#pragma once

#include "../../include/exact_runtime.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
// Header presence is not debugger availability: no-debugger Hermes installs
// the same public header with inert declarations but omits the implementation.
// @ref LLP 0029#2-executable-layout-stub-envelope-footer — release stubs bind a lean/static engine profile without inheriting debugger linkage
#if !defined(EXACT_HAS_HERMES_ASYNC_DEBUGGER) && defined(HERMES_ENABLE_DEBUGGER) && \
    defined(__has_include)
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
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <cmath>
#include <functional>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <tuple>
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
  uint64_t associatedEvaluation;
  std::vector<uint64_t> principalStack;
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

struct NextTickEntry {
  uint64_t id;
  uint64_t principal;
  uint64_t associatedEvaluation;
  std::vector<uint64_t> principalStack;
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
// Heap-owned state for one debugger command admitted from a non-runtime
// thread. App-bundle begin cancels every registered command while closing the
// debugger gate, waking its caller even when Hermes never services the queued
// interrupt. A late interrupt checks `cancelled` before touching the runtime.
struct ExactPendingDebuggerCommand {
  std::mutex mutex;
  std::condition_variable cv;
  bool cancelled{false};
  bool settled{false};
  std::string result;
};
#endif

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

enum class StructuredAsyncPrincipalStatus : uint32_t {
  Authenticated = 1,
  Unavailable = 2,
  Ambiguous = 3,
};

struct StructuredAsyncFailureContext {
  uint32_t kind{0};
  StructuredAsyncPrincipalStatus principalStatus{
      StructuredAsyncPrincipalStatus::Unavailable};
  uint64_t principal{0};
  uint64_t eventId{0};
  uint64_t associatedEvaluation{0};
};

struct StructuredAsyncFailureEvent {
  uint64_t runtimeNonce{0};
  uint64_t handleId{0};
  uint64_t hostContextId{0};
  uint64_t principal{0};
  uint64_t eventId{0};
  uint64_t associatedEvaluation{0};
  uint32_t kind{0};
  StructuredAsyncPrincipalStatus principalStatus{
      StructuredAsyncPrincipalStatus::Unavailable};
};

struct StructuredPendingPromiseRejection {
  std::unique_ptr<facebook::jsi::Object> promise;
  std::unique_ptr<facebook::jsi::Value> reason;
  StructuredAsyncFailureContext failureContext{};
  uint32_t safeMetadataFields{0};
  uint32_t safeErrorClass{0};
  std::string safeMessage;
  std::string safeStack;
};

struct StructuredSafeThrowMetadata {
  uint32_t fields{0};
  uint32_t errorClass{0};
  std::string message;
  std::string stack;
};

// Native work-unit events cross to the authenticated session controller
// through a bounded, any-thread queue. Keep this internal representation
// independent of the public C layout so the queue never owns caller memory.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
struct StructuredWorkUnitEvent {
  uint32_t kind{0};
  uint32_t phase{0};
  uint64_t targetId{0};
  uint64_t schedulingId{0};
};

// Terminal cancellation publication is separate from the work-unit stream:
// request delivery is nonterminal, while this record is emitted only after
// the exact target has returned and the owner has checked runtime reuse.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
struct StructuredCancellationEvent {
  uint32_t resolution{0};
  uint64_t targetId{0};
};

enum class StructuredSessionCellKind : uint32_t {
  Let = 3,
  Const = 4,
  Class = 5,
  Import = 6,
};

struct StructuredSessionCell {
  StructuredSessionCellKind kind{StructuredSessionCellKind::Let};
  bool initialized{false};
  std::unique_ptr<facebook::jsi::Value> value;
};

struct StructuredSessionJournalEntry {
  std::string name;
  bool initialized{false};
  bool restoresLastValueAutoUpdate{false};
  bool priorLastValueAutoUpdateEnabled{false};
  uint64_t lastValueMutationGenerationAtInstantiation{0};
  std::unique_ptr<StructuredSessionCell> displaced;
};

// Pending promise for the dedicated Exact embedder ingress.  This is kept
// separate from HostCallAsyncEntry storage so an armed runtime can accept
// typed Exact completions without making the diagnostic string bridge
// reachable again. @ref LLP 0002#the-exact-embedder-ingress
struct ExactHostCallAsyncEntry {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

struct ExactHermesRuntime;
struct ExactGpuRuntimeBinding;
struct ExactGpuRuntimeBindingV2;
struct ExactGpuDecodedImageRuntimeBindingV1;

enum class EmbedderCapabilityState : uint8_t {
  LegacyAutoFinalize,
  Configuring,
  Finalized,
  Failed,
};

struct ModuleFactoryEntry {
  uint64_t graph_generation{0};
  uint8_t source_goal{0};
  uint32_t principal_id{0};
  std::string compartment_identity;
  std::string semantic_digest;
  std::string source_id;
  std::shared_ptr<facebook::jsi::Function> factory;
};

struct GraphContextEntry {
  uint64_t graph_generation{0};
  std::string requesting_source_id;
  uint32_t effect_owner{0};
  uint32_t schedule_owner{0};
  std::vector<uint32_t> constrained_principals;
  uint32_t references{1};
};

enum class NativeModuleRecordState : uint8_t {
  New,
  Instantiated,
  Declared,
  Evaluating,
  Evaluated,
  Errored,
};

struct NativeModuleBindingCell {
  bool initialized{false};
  std::shared_ptr<facebook::jsi::Value> value;
  uint64_t alias_record_id{0};
  std::string alias_export;
};

struct NativeModuleImportBinding {
  uint64_t target_record_id{0};
  std::string target_export;
};

struct NativeModuleRecordEntry {
  uint64_t graph_generation{0};
  uint8_t source_goal{0};
  bool published{false};
  std::string source_id;
  uint64_t context_handle_id{0};
  std::shared_ptr<facebook::jsi::Function> factory;
  NativeModuleRecordState state{NativeModuleRecordState::New};
  std::map<std::string, NativeModuleBindingCell> export_cells;
  std::map<std::pair<std::string, std::string>, NativeModuleImportBinding>
      import_bindings;
  std::set<uint64_t> evaluation_dependencies;
  std::map<std::string, uint64_t> dynamic_import_bindings;
  std::map<std::pair<uint32_t, std::string>, uint64_t>
      computed_dynamic_import_bindings;
  std::set<std::string> deferred_dynamic_imports;
  std::set<std::pair<uint32_t, std::string>>
      deferred_computed_dynamic_imports;
  std::shared_ptr<facebook::jsi::Object> namespace_object;
  std::shared_ptr<facebook::jsi::Function> declare_function;
  std::shared_ptr<facebook::jsi::Function> execute_function;
  // A TLA record owns exactly one internal evaluation promise. Both
  // settlement handlers are attached synchronously before control returns to
  // Rust; the retained promise keeps suspended work live without making an
  // individual dynamic-import waiter its cancellation target.
  // @ref LLP 0026#6-top-level-await-and-dynamic-import
  std::shared_ptr<facebook::jsi::Object> evaluation_promise;
  std::string error_message;
  uint64_t error_token{0};
};

enum class NativeCommonJsRecordState : uint8_t {
  New,
  Evaluating,
  Evaluated,
};

enum class NativeCommonJsRequireTargetKind : uint8_t {
  CommonJs,
  Esm,
};

struct NativeCommonJsRequireBinding {
  NativeCommonJsRequireTargetKind kind{NativeCommonJsRequireTargetKind::CommonJs};
  uint64_t record_id{0};
  bool esm_synchronous_eligible{false};
};

struct NativeCommonJsRequireProviderEntry {
  ExactCommonJsRequireProviderCallback provider{nullptr};
  void* context{nullptr};
};

struct NativeCommonJsRecordEntry {
  uint64_t graph_generation{0};
  uint8_t source_goal{0};
  bool published{false};
  std::string source_id;
  uint64_t context_handle_id{0};
  std::shared_ptr<facebook::jsi::Function> factory;
  NativeCommonJsRecordState state{NativeCommonJsRecordState::New};
  std::map<std::string, NativeCommonJsRequireBinding> require_bindings;
  std::set<std::string> deferred_commonjs_requires;
  std::set<std::string> bootstrap_internal_commonjs_requires;
  std::map<std::string, uint64_t> dynamic_import_bindings;
  std::map<std::pair<uint32_t, std::string>, uint64_t>
      computed_dynamic_import_bindings;
  std::set<std::string> deferred_dynamic_imports;
  std::set<std::pair<uint32_t, std::string>>
      deferred_computed_dynamic_imports;
  std::set<std::string> detected_exports;
  std::string filename;
  std::string dirname;
  std::shared_ptr<facebook::jsi::Object> module_object;
  std::shared_ptr<facebook::jsi::Value> exports_value;
  uint64_t adapter_record_id{0};
};

struct NativeModuleDynamicActivationEntry {
  uint64_t graph_generation{0};
  uint64_t requester_record_id{0};
  bool requester_is_commonjs{false};
  bool computed{false};
  uint32_t site{0};
  std::string requester_source_id;
  std::string specifier;
  bool taken{false};
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

// A runtime address is not an identity: allocators routinely reuse the same
// address after destroy/recreate. Every asynchronous producer therefore
// carries the creation nonce it observed while the handle was live, and the
// registry validates the pair atomically before any handle dereference.
// @ref LLP 0003#the-event-loop — callback delivery is runtime-generation scoped.
struct RuntimeCallbackTarget {
  ExactHermesRuntime* runtime{nullptr};
  uint64_t nonce{0};
  StructuredAsyncFailureContext failureContext{};

  explicit operator bool() const {
    return runtime != nullptr && nonce != 0;
  }
};

inline void exactTestDelayRuntimeProducer() {
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
  const char* value = std::getenv("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS");
  if (!value || !*value) return;
  char* end = nullptr;
  auto milliseconds = std::strtoull(value, &end, 10);
  if (end == value || *end != '\0') return;
  milliseconds = std::min<unsigned long long>(milliseconds, 2000);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
#endif
}

// Test-only: parks a cross-thread producer after pushRuntimeCallback has
// published (and notified) its completion, so the runtime thread executes and
// releases the queued callback before the producer returns. Counterpart of
// exactTestDelayRuntimeProducer, which delays before target acquisition.
inline void exactTestHoldRuntimeProducerAfterEnqueue() {
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
  const char* value = std::getenv("IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS");
  if (!value || !*value) return;
  char* end = nullptr;
  auto milliseconds = std::strtoull(value, &end, 10);
  if (end == value || *end != '\0') return;
  milliseconds = std::min<unsigned long long>(milliseconds, 2000);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
#endif
}

#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
extern std::atomic<uint64_t> g_trackedJsiOwnerFinalReleasesOnOwnerThread;
extern std::atomic<uint64_t> g_trackedJsiOwnerFinalReleasesOffOwnerThread;
#endif

// Wrap a JSI promise callback destined for a cross-thread completion so
// observer builds record which thread ran the FINAL owner release. JSI values
// may only be destroyed on the runtime owner thread; a nonzero off-owner
// count is always a bug (the producer-side copy became the last owner).
// Ordinary builds compile to a plain make_shared.
inline std::shared_ptr<facebook::jsi::Function> exactMakeTrackedJsiCallbackOwner(
    std::thread::id ownerThread, facebook::jsi::Function&& fn) {
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
  return std::shared_ptr<facebook::jsi::Function>(
      new facebook::jsi::Function(std::move(fn)),
      [ownerThread](facebook::jsi::Function* owned) {
        auto& counter = std::this_thread::get_id() == ownerThread
            ? g_trackedJsiOwnerFinalReleasesOnOwnerThread
            : g_trackedJsiOwnerFinalReleasesOffOwnerThread;
        counter.fetch_add(1, std::memory_order_seq_cst);
        delete owned;
      });
#else
  (void)ownerThread;
  return std::make_shared<facebook::jsi::Function>(std::move(fn));
#endif
}

struct ExactHermesRuntime {
  std::unique_ptr<facebook::hermes::HermesRuntime> runtime;
  uint64_t host_context_id{0};
  uint64_t runtime_nonce{0};
  // Armed runtimes bind their authenticated `/project` namespace before any
  // bootstrap code runs. This bit makes partial construction and normal
  // teardown idempotently close the exact generation.
  // @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
  bool vfs_runtime_bound{false};
  // Structured-evaluation handles are owner-thread-only roots. IDs are
  // monotonic and never reused within this runtime generation.
  // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
  uint64_t next_structured_value_handle_id{1};
  std::unordered_map<uint64_t, std::unique_ptr<facebook::jsi::Value>>
      structured_value_handles;
  std::unordered_map<uint64_t, StructuredSafeThrowMetadata>
      structured_value_safe_throw_metadata;
  uint64_t next_structured_async_event_id{1};
  std::deque<StructuredAsyncFailureEvent> structured_async_failure_events;
  std::deque<StructuredPendingPromiseRejection>
      structured_pending_promise_rejections;
  // Loss discovered while collecting the current checkpoint is held
  // separately so the older retained records can publish before its marker.
  uint64_t structured_pending_promise_rejection_dropped{0};
  std::unique_ptr<facebook::jsi::Function>
      structured_unhandled_rejection_handler;
  std::unique_ptr<facebook::jsi::Function>
      structured_rejection_handled_handler;
  bool structured_promise_rejection_tracker_configured{false};
  // Nonzero opens a sticky coalescing window: publication counts every later
  // failure until the owner takes the marker, preserving pre-receipt order.
  uint64_t structured_async_failure_dropped{0};
  bool structured_async_failure_failed{false};
  StructuredAsyncFailureContext structured_active_async_failure_context{};
  bool structured_active_async_failure_context_set{false};
  uint64_t structured_vm_job_associated_evaluation{0};
  // Hermes' no-embedder-scheduler sentinel; kept equal to the runtime
  // principal/no-job value used by the carried patch.
  uint32_t structured_vm_job_scheduler_principal{0xFFFFFFFFu};
  uint64_t next_structured_work_target_id{1};
  uint64_t structured_pending_display_work_target_id{0};
  uint64_t structured_pending_display_handle_id{0};
  std::unique_ptr<facebook::jsi::Value> structured_last_displayed_value;
  std::unique_ptr<facebook::jsi::Function> structured_last_value_getter;
  std::unique_ptr<facebook::jsi::Function> structured_last_value_setter;
  bool structured_last_value_auto_update_enabled{true};
  uint64_t structured_last_value_mutation_generation{0};
  // The authenticated session identity is native-only and bound exactly once
  // to an armed runtime. Submission ordinals are consumed monotonically after
  // every accepted request, including JavaScript throws.
  // @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
  std::array<uint8_t, 32> structured_session_token{};
  bool structured_session_bound{false};
  bool structured_evaluation_in_flight{false};
  uint64_t next_structured_submission_ordinal{1};
  // A submission is admitted before Rust syntax/lowering begins. Keeping its
  // exact credential binding and work target native-side prevents either a
  // skipped continuation or a different request from consuming the ticket.
  // @ref LLP 0024#2-source-identity-and-reserved-schemes
  uint64_t structured_admitted_submission_ordinal{0};
  std::array<uint8_t, 32> structured_admitted_request_binding{};
  uint64_t structured_admitted_work_target_id{0};
  // The native module graph is orchestrated in Rust. Raw JS values are retained
  // per failing runner operation and selected by an exact nonzero token; a
  // handled or later failure can never overwrite the foreground outcome.
  bool structured_module_graph_in_flight{false};
  bool structured_module_graph_suspended{false};
  uint64_t structured_module_graph_work_target_id{0};
  uint64_t next_structured_module_error_token{1};
  std::unordered_map<uint64_t, std::unique_ptr<facebook::jsi::Value>>
      structured_module_error_values;
  // Exact, any-thread cancellation is paired with the native-published unit
  // that is executing now. The mutex closes the query -> cancel -> successor
  // race: a cancellation can only arm the target that is still current while
  // holding this lock, and the owner clears that target under the same lock
  // before a successor may be published.
  // @ref LLP 0025#6-interruption-and-cancellation
  std::mutex structured_cancel_mutex;
  uint64_t structured_active_work_target_id{0};
  uint64_t structured_cancel_requested_work_target_id{0};
  uint64_t structured_cancellation_critical_work_target_id{0};
  bool structured_vm_work_active{false};
  // Compiled before project code is admitted. Besides proving that a runtime
  // which observed a break can execute again, this inert unit consumes a late
  // Hermes timeout before any successor target is published.
  std::shared_ptr<const facebook::jsi::PreparedJavaScript>
      structured_cancellation_consistency_probe;
  // Publication is enabled by the authenticated session bind. Events are
  // bounded and loss is fail-loud: once overflowed, the any-thread consumer
  // receives the overflow state instead of a silently incomplete live set.
  std::mutex structured_work_event_mutex;
  std::deque<StructuredWorkUnitEvent> structured_work_events;
  std::deque<StructuredCancellationEvent> structured_cancellation_events;
  bool structured_work_event_overflow{false};
  bool structured_cancellation_event_overflow{false};
  bool structured_work_event_failed{false};
  std::unordered_set<uint64_t> structured_published_due_timers;
  uint64_t structured_evaluation_scheduling_id{0};
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
  // Test-only record of the four fixed native-freeze calls performed while
  // their patched Hermes globals are still reachable, immediately before the
  // production bootstrap deletes those globals. Four bits represent the
  // identity/semantics checks and one proves the fixed observer completed; no
  // callable authority is retained.
  uint32_t capsec_native_freeze_observation{0};
  // One-shot, runtime-owned proof that the trusted loader crossed an
  // authenticated builtin cache miss and completed the exact source body.
  // The loader reports through its already-captured module-attribution
  // HostFunction; project code cannot reach that closure after bootstrap.
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
  bool capsec_builtin_source_observer_armed{false};
  bool capsec_builtin_source_observer_completed{false};
  bool capsec_builtin_source_observer_duplicate{false};
  std::string capsec_builtin_source_observation_id;
  std::string capsec_builtin_source_expected_alias;
  std::string capsec_builtin_source_id;
  // Deterministic conformance seam for the normal-return cancellation race.
  // The queued native task never enters JS, so a delivered Hermes break must
  // be drained by the consistency probe and resolve Defeated.
  std::mutex structured_test_work_mutex;
  std::condition_variable structured_test_work_cv;
  bool structured_test_work_released{false};
  // Deterministically inject the controller-cancel -> Begin-publication-fail
  // interleaving so rollback proves it consumes the armed Hermes break.
  bool structured_test_fail_next_begin_after_cancellation{false};
#endif
  // Persistent checked-cell session record. JSI roots are native-only and are
  // destroyed on the owner thread before `runtime` (declared above) is torn
  // down. The journal contains only declarative replacements because rollback
  // never mutates the realm-global object record.
  // @ref LLP 0024#71-the-environment-a-modified-globalenvironmentrecord
  std::unordered_map<std::string, std::unique_ptr<StructuredSessionCell>>
      structured_session_cells;
  std::unordered_set<std::string> structured_session_var_declared_names;
  std::unordered_set<std::string> structured_session_created_vars;
  std::vector<StructuredSessionJournalEntry> structured_session_journal;
  bool structured_session_transaction_active{false};
  bool structured_session_completion_has_value{false};
  std::unique_ptr<facebook::jsi::Value> structured_session_completion_value;
  // A top-level-await wrapper may outlive the native call which started it.
  // Keep both the driving Promise and its settlement payload rooted until the
  // owner resumes the exact work target through the continuation ABI. The
  // callback checks the target id before publishing, so a stale Promise can
  // never settle a successor submission.
  // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
  uint64_t structured_async_work_target_id{0};
  uint32_t structured_async_capability_flags{0};
  bool structured_async_settled{false};
  bool structured_async_rejected{false};
  std::unique_ptr<facebook::jsi::Value> structured_async_invocation;
  std::unique_ptr<facebook::jsi::Value> structured_async_settlement_value;
  // Captured before the bare bootstrap evaluator is sealed. Later user writes
  // cannot redirect declaration feasibility, property definition, Promise
  // settlement, or delete/assignment operations through mutable globals.
  std::unique_ptr<facebook::jsi::Function> structured_object_get_own_descriptor;
  std::unique_ptr<facebook::jsi::Function> structured_object_define_property;
  std::unique_ptr<facebook::jsi::Function> structured_object_is_extensible;
  std::unique_ptr<facebook::jsi::Function> structured_reflect_set;
  std::unique_ptr<facebook::jsi::Function> structured_reflect_delete_property;
  std::unique_ptr<facebook::jsi::Function> structured_promise_then;
  std::unique_ptr<facebook::jsi::Function> structured_number;
  std::unique_ptr<facebook::jsi::Object> structured_process;
  // `process.env` is one shared facade, but its armed mutable state is not.
  // Native frame attribution selects the exact principal bucket for every
  // read, write, delete, and enumeration after the corresponding typed gate.
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  std::unordered_map<
      uint64_t,
      std::unordered_map<std::string, std::string>>
      environment_principal_overlays;
  // Captured from pristine Hermes before any Ibex bootstrap script can replace
  // Object's reflection intrinsics. The armed finalizer uses only these roots
  // for its getter-free disposition sweep. Baseline keys distinguish engine
  // primordials from globals installed by Ibex.
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  std::unique_ptr<facebook::jsi::Function>
      root_global_get_own_property_names;
  std::unique_ptr<facebook::jsi::Function>
      root_global_get_own_property_symbols;
  std::unique_ptr<facebook::jsi::Function>
      root_global_get_own_property_descriptor;
  std::unique_ptr<facebook::jsi::Function> root_global_get_prototype_of;
  std::unique_ptr<facebook::jsi::Function> root_global_object_is_frozen;
  std::unique_ptr<facebook::jsi::Function> root_global_reflect_delete_property;
  std::vector<std::string> root_global_baseline_keys;
  // Armed user execution opens only after the descriptor-only sweep has run
  // against the final authenticated embedder capability projection. A
  // transaction begun after ordinary bootstrap invalidates the earlier base
  // sweep until its provider globals are published, sealed, and reverified.
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  bool root_global_disposition_verified_for_user_execution{false};
  // Captured exactly once by the trusted loader bootstrap through a temporary
  // host-only rendezvous global. Project code never receives the closure and
  // cannot replace it after bootstrap deletes the rendezvous property.
  // @ref LLP 0024#73-evaluation-phases-collisions-and-the-cross-kind-matrix
  std::unique_ptr<facebook::jsi::Function>
      structured_session_import_materializer;
  // A reserved entry spans top-level-await suspension. Cancellation must
  // commit/abort this trusted cache state before it can publish Accepted;
  // otherwise cleanup could fail after the terminal record is observable.
  // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
  bool structured_module_cache_entry_pending{false};
  // Cooperative lifecycle is recorded out of band before an uncatchable
  // engine interrupt stops the currently executing unit.
  bool structured_lifecycle_pending{false};
  int32_t structured_lifecycle_exit_code{0};
  bool structured_session_terminated{false};
  // The historical bare evaluator is restricted to trusted bootstrap on an
  // armed runtime and irreversibly sealed before project source is admitted.
  // @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
  bool armed_bootstrap_eval_open{true};
  // Set only by the named, owner-thread trusted seal after the reviewed
  // shared-runtime ambient/global closure program completes without throwing.
  // finish_bootstrap requires this witness instead of duplicating or
  // implicitly running that program.
  bool armed_shared_runtime_globals_sealed{false};
  // Immutable constructor-selected posture. Bootstrap must never consult
  // process-global environment toggles that other threads can observe/race.
  bool armed{false};
  bool bootstrap_bun_compat{false};
  bool bootstrap_fixture_compat{false};
  bool bootstrap_bun_fixture{false};
  bool bootstrap_dev_served{false};
  std::unique_ptr<facebook::jsi::Function>
      dev_served_module_table_lifecycle;
  // The legacy lazy-bootstrap callbacks can execute after diagnostic package
  // code begins. Their source/HBC choices are therefore captured during the
  // native bootstrap and never re-read from the process environment.
  // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
  bool legacy_stream_enhance_source{false};
  bool legacy_stream_enhance_hbc{true};
  bool legacy_web_crypto_source{false};
  bool legacy_web_crypto_hbc{true};
  bool legacy_web_storage_source{false};
  bool legacy_web_storage_hbc{true};
  bool legacy_form_data_source{false};
  bool legacy_form_data_hbc{true};
  // One-shot, context-bound child-process bootstrap state captured by the Rust
  // Host handoff before this engine exists.  It is projected only through the
  // temporary trusted-bootstrap carrier, never through `process.env`.
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
  int process_ipc_fd{-1};
  bool process_ipc_advanced_serialization{false};
  bool structural_lockdown{false};
  // Multi-capability embedders opt into an explicit construction transaction.
  // Legacy Exact-only callers remain on the historical auto-finalize path.
  // Only the runtime owner thread mutates this state.
  EmbedderCapabilityState embedder_capability_state{
      EmbedderCapabilityState::LegacyAutoFinalize};
  // WebGPU registration authenticates and retains native service state, but
  // activation may happen after ordinary project execution has begun. While
  // this owner-thread transaction is open, every other runtime-driving ingress
  // remains closed until the new roots have been swept and the debugger gate
  // has been restored.
  // @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
  bool webgpu_runtime_activation_in_progress{false};
  bool webgpu_runtime_bundle_evaluated{false};
  // Trusted bootstrap scripts run before the handle is published to an
  // embedder. They do not close the construction-only capability window.
  bool trusted_bootstrap_in_progress{false};
  // The explicit embedder-capability transaction is a construction-only
  // operation. Once any externally driven user-code entry point has run, a
  // later transaction cannot publish provisional capabilities into that realm.
  // Owner-thread only, like embedder_capability_state.
  bool user_execution_started{false};
  bool shared_runtime_bundle_installed{false};
  // The public one-shot baseline hook is deleted at the initial seal. Native
  // retains the trusted closure so a later WebGPU activation can copy only the
  // newly authenticated conditional roots into package baselines.
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  std::shared_ptr<facebook::jsi::Function> compartment_baseline_refresher;
  // Strict JSON [{locator,endowments}] projection copied from the immutable
  // armed Host context. Locator punctuation is data, never bootstrap syntax.
  std::string snapshot_endowments_json;
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
  // A successful GPU Canvas app-bundle begin excludes every debugger ingress
  // until finish has proved the temporary capture root closed. The atomic is
  // checked both before an off-thread interrupt is queued and again when that
  // interrupt reaches the runtime thread; debug_mutex linearizes the gate with
  // event publication/consumption and debugger snapshots.
  // @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
  std::atomic<bool> gpu_canvas_app_bundle_debugger_blocked{false};
  // Owner-thread-only companion state. An attached debugger is temporarily
  // detached at begin so a pre-existing breakpoint cannot pause trusted
  // capture source, then restored before the gate opens after finish.
  bool gpu_canvas_app_bundle_debugger_was_attached{false};
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
  std::unordered_set<std::shared_ptr<ExactPendingDebuggerCommand>>
      pending_debugger_commands;
#endif
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  std::atomic<bool> test_pause_debugger_after_interrupt_enqueue{false};
  std::atomic<bool> test_debugger_interrupt_enqueue_paused{false};
#endif
  // An owner-thread protocol failure can quarantine a live runtime before its
  // embedder is able to schedule physical destruction. Quarantine is
  // irreversible and closes every later drive/callback/debugger ingress while
  // still permitting transaction cleanup and owner-thread destruction.
  // @ref LLP 0002#runtime-driving-thread-contract
  std::atomic<bool> runtime_quarantined{false};
  // The additive outer app-bundle transaction closes every ordinary runtime
  // drive before generated preparation publishes its carrier and remains
  // closed through Canvas capture, runApp, and native absence verification.
  std::atomic<bool> app_bundle_evaluation_open{false};
  uint32_t app_bundle_expected_prepared_disposition{0};
  bool app_bundle_immediate_evaluation_completed{false};
  bool app_bundle_immediate_source_fallback_allowed{false};
  bool app_bundle_prepared_classified{false};
  bool app_bundle_prepared_staged{false};
  bool app_bundle_prepared_invoked{false};
  std::unique_ptr<facebook::jsi::Function>
      app_bundle_prepared_consume_gpu_integration;
  std::unique_ptr<facebook::jsi::Function> app_bundle_prepared_run_app;
  std::atomic<bool> gpu_canvas_app_bundle_transaction_open{false};
  bool gpu_canvas_app_bundle_owns_debugger_exclusion{false};
  std::mutex debug_mutex;
  std::deque<std::string> debug_events;
  std::unordered_set<uint32_t> known_scripts;
  std::unordered_map<uint32_t, std::string> script_id_to_name;
  std::unordered_map<std::string, std::string> sources_by_name;
  std::unordered_map<std::string, std::string> source_maps_by_name;
  std::thread::id runtime_thread;
  // Trusted bootstrap scripts execute before this handle is published in the
  // live runtime registry. Only the constructing owner thread may use that
  // narrow pre-publication evaluation window.
  bool bootstrap_in_progress{true};
  // Private evaluator capabilities captured before lockdown deletes/tames the
  // corresponding globals. They are reachable only through the native module
  // ABI and are released on the runtime owner thread during teardown.
  std::shared_ptr<facebook::jsi::Function> module_function_constructor;
  std::shared_ptr<facebook::jsi::Function> module_compartment_binder;
  // Exact bootstrap-internal object resolver captured from the trusted module
  // loader and removed from the root global before package evaluation.
  std::shared_ptr<facebook::jsi::Function> module_bootstrap_internal_resolver;
  uint64_t next_module_handle_id{1};
  std::unordered_map<uint64_t, ModuleFactoryEntry> module_factories;
  std::unordered_map<uint64_t, GraphContextEntry> graph_contexts;
  std::unordered_map<uint64_t, NativeModuleRecordEntry> module_records;
  std::unordered_map<uint64_t, NativeCommonJsRecordEntry> commonjs_records;
  std::map<uint64_t, NativeCommonJsRequireProviderEntry>
      commonjs_require_providers;
  bool commonjs_require_provider_call_active{false};
  uint64_t commonjs_require_provider_call_generation{0};
  std::set<uint64_t> pinned_module_generations;
  uint64_t next_module_dynamic_activation_request_id{1};
  std::unordered_map<uint64_t, NativeModuleDynamicActivationEntry>
      module_dynamic_activation_requests;
  std::deque<uint64_t> module_dynamic_activation_queue;
  // One evaluated prepared carrier table per authenticated principal/content
  // pair. Individual module handles select factories from this retained table.
  std::map<std::tuple<uint32_t, std::string, std::string>,
           std::shared_ptr<facebook::jsi::Object>>
      prepared_carrier_tables;
  uint64_t next_timer_id{1};
  std::unordered_map<uint64_t, TimerEntry> timers;
  std::deque<NextTickEntry> next_tick;
  // One Canvas acquisition epoch spans the complete outer runtime-owner task,
  // including nextTick and every microtask slice. Windows can bound one drain
  // to 1024 jobs, so the active identity survives between poll calls until a
  // slice reports completion. These fields are owner-thread-only.
  uint64_t next_gpu_host_task_id{1};
  uint64_t active_gpu_host_task_id{0};
  uint32_t gpu_host_task_depth{0};
  std::atomic<bool> gpu_host_task_microtask_continuation{false};
  std::atomic<bool> gpu_host_task_checkpoint_failed{false};
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
  // Pins held by native workers and generation-bearing any-thread controls
  // that may dereference this handle outside the runtime thread. Destroy enters
  // Closing (refusing new pins), cancels source work, and keeps the exact
  // registry generation until this reaches zero.
  std::atomic<uint32_t> native_worker_pins{0};
  std::mutex native_worker_mutex;
  std::condition_variable native_worker_cv;
  std::mutex fetchMutex;
  std::unordered_map<uint32_t, FetchCallbackEntry> fetchCallbacks;
  std::mutex hostCallAsyncMutex;
  std::unordered_map<uint64_t, HostCallAsyncEntry> hostCallAsyncCallbacks;
  std::mutex exactHostCallAsyncMutex;
  std::unordered_map<uint64_t, ExactHostCallAsyncEntry>
      exactHostCallAsyncCallbacks;
  std::mutex callbackMutex;
  struct QueuedRuntimeCallback {
    StructuredAsyncFailureContext failureContext;
    std::function<void(facebook::jsi::Runtime&)> callback;
  };
  std::deque<QueuedRuntimeCallback> callbackQueue;
  // Finalizers are admitted from native producer threads but always executed
  // by poll/destroy on the owning runtime thread. Unlike callbackQueue, these
  // run during teardown: they exist for native contexts whose final release
  // owns a JSI value (notably WebSocket callback contexts).
  std::mutex finalizerMutex;
  std::deque<std::function<void()>> finalizerQueue;
  // Legacy-runtime fail-loud marker for async callbacks with no consuming
  // uncaughtException handler. Authenticated runtimes publish the rooted
  // structured event instead and never set this flag. One-shot and owner-
  // thread-only for the legacy poll contract.
  // @ref LLP 0003#the-event-loop — async failures are fatal (ENG-23130)
  // @ref LLP 0024#9-asynchronous-failures — structured engines report, not decide.
  bool fatal_async_error = false;
  bool typed_authority_generations_initialized = false;
  uint64_t typed_negative_generation = 0;
  uint64_t typed_dynamic_generation = 0;
  uint64_t typed_handle_generation = 0;
  // Legacy host policy for JS errors escaping drained async callbacks. The
  // CLI default is the fatal_async_error / poll -1 contract above; embedded
  // app hosts may retain raw reporting and keep pumping. Authenticated
  // structured publication bypasses both legacy branches. Set during engine
  // construction and read only on the runtime thread.
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

  // Dedicated Exact app/agent endowment. The operation domain is a canonical
  // sorted set of numeric IDs selected once by the native embedder. JS can
  // send only bytes for one of those IDs; it cannot name a new host operation.
  uint32_t exact_host_context = 0;
  std::unordered_set<uint32_t> exact_host_operations;
  void (*exact_host_call_async_fn)(ExactHermesRuntime* runtime,
                                   uint64_t call_id,
                                   uint32_t operation_id,
                                   const uint8_t* payload,
                                   size_t payload_len,
                                   void* context) = nullptr;
  void* exact_host_call_async_context = nullptr;
  // The shared runtime's one-shot GPU construction handoff is removed from
  // globalThis at the armed bootstrap seal. Native retains it only until a
  // late provider transaction consumes it or user execution closes it.
  std::shared_ptr<facebook::jsi::Function> gpu_construction_capture;
  // Optional provider-independent Exact GPU service registration. The binding
  // owns the native mailbox plus owner-thread-only JSI bridge/Promise roots;
  // no physical WGPU handle crosses this boundary. Runtime-js captures the
  // bridge only in its private construction module and revokes it on teardown.
  std::shared_ptr<ExactGpuRuntimeBinding> gpu_binding;
  // Additive full-identity carrier. Exactly one of gpu_binding/gpu_binding_v2
  // may be populated; keeping distinct types makes the V1 ABI and behavior
  // mechanically unchanged while V2 is staged behind the same feature gate.
  std::shared_ptr<ExactGpuRuntimeBindingV2> gpu_binding_v2;
  // Construction-private, subordinate decoded-image callback. It contributes
  // no capability-set bit and is consumed only while publishing a live V2
  // private bridge. Teardown generation-fences and cancels it independently.
  std::shared_ptr<ExactGpuDecodedImageRuntimeBindingV1>
      gpu_decoded_image_binding_v1;
};

// Replace the captured typed-filesystem principal constraint for the current
// thread and return the previous scope. The implementation is platform-local
// because the typed filesystem bridge owns this TLS on both POSIX and Windows.
// Runtime-drive entry uses a null replacement to prevent an outer runtime's
// captured principals from becoming authority in a nested different-runtime
// drive; the returned pointer remains owned by the still-live outer scope.
const std::vector<uint64_t>* exactSwapTypedPrincipalStackForRuntimeDrive(
    const std::vector<uint64_t>* replacement);

/// Common owner-thread, liveness, generation, and non-reentrancy gate for
/// every entry point that drives JSI or module-runner state. A successful
/// guard also selects this runtime's exact Host/VFS and frame-attribution
/// contexts for the complete drive, restoring any outer runtime on unwind.
/// @ref LLP 0002#runtime-driving-thread-contract
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
/// @ref LLP 0013#mechanism-3
class ExactRuntimeDriveGuard {
 public:
  ExactRuntimeDriveGuard(
      ExactHermesRuntime* runtime,
      uint64_t expectedNonce = 0,
      bool allowQuarantined = false,
      bool allowAppBundleEvaluation = false,
      bool allowCommonJsRequireMutation = false);
  ~ExactRuntimeDriveGuard();
  ExactRuntimeDriveGuard(const ExactRuntimeDriveGuard&) = delete;
  ExactRuntimeDriveGuard& operator=(const ExactRuntimeDriveGuard&) = delete;

  int32_t status() const { return status_; }
  explicit operator bool() const { return status_ == EXACT_RUNTIME_DRIVE_OK; }

 private:
  ExactHermesRuntime* runtime_{nullptr};
  uint64_t nonce_{0};
  uint64_t previous_runtime_nonce_{0};
  uint64_t previous_host_context_{UINT64_MAX};
  uint64_t previous_module_id_{0};
  uint64_t previous_native_principal_{UINT64_MAX};
  const std::vector<uint64_t>* previous_typed_principal_stack_{nullptr};
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  void* previous_attribution_runtime_{nullptr};
#endif
  bool principal_scope_active_{false};
  bool dynamic_scope_active_{false};
  bool nested_commonjs_require_mutation_{false};
  int32_t status_{EXACT_RUNTIME_DRIVE_INVALID};
};

/// Outermost runtime-owner user-code scope used by the typed Canvas current-
/// texture lifetime. Destruction is the finally path: it drains nextTick and
/// microtasks, retaining the same task identity across a bounded Windows
/// continuation, then invokes the construction-captured GPU checkpoint once.
/// Nested coercions/callbacks join the existing scope.
/// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
class ScopedGpuHostTask {
 public:
  explicit ScopedGpuHostTask(ExactHermesRuntime* runtime) noexcept;
  ~ScopedGpuHostTask();
  ScopedGpuHostTask(const ScopedGpuHostTask&) = delete;
  ScopedGpuHostTask& operator=(const ScopedGpuHostTask&) = delete;

  explicit operator bool() const { return active_; }
  bool finish() noexcept;

 private:
  ExactHermesRuntime* runtime_{nullptr};
  bool active_{false};
};

/// Resume a bounded microtask continuation before admitting a new outer task.
/// Returns false while another slice is still required or after checkpoint
/// quarantine. A true result means a fresh task may begin.
bool exactResumeGpuHostTaskContinuation(ExactHermesRuntime* runtime) noexcept;

/// Irreversibly close all ordinary runtime drive and producer ingress while
/// retaining only cleanup/query/destruction access to the exact generation.
/// The caller must hold a successful owner-thread ExactRuntimeDriveGuard.
bool exactRuntimeQuarantine(ExactHermesRuntime* runtime) noexcept;

bool exactGpuCloseConstructionCapture(ExactHermesRuntime* runtime);
bool exactGpuRetainConstructionCaptureForBootstrapSeal(
    ExactHermesRuntime* runtime);

inline bool exactRuntimeEnterUserExecution(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime) {
    return false;
  }
  if (runtime->runtime_quarantined.load(std::memory_order_acquire)) {
    return false;
  }
  if (runtime->app_bundle_evaluation_open.load(std::memory_order_acquire)) {
    return false;
  }
  if (runtime->webgpu_runtime_activation_in_progress) {
    return false;
  }
  // A provisional or failed native capability transaction outranks every
  // evaluator posture, including trusted construction. Native finalizers use
  // direct owner-thread JSI and do not need this project-execution gate.
  if (runtime->embedder_capability_state ==
          EmbedderCapabilityState::Configuring ||
      runtime->embedder_capability_state == EmbedderCapabilityState::Failed) {
    return false;
  }
  if (runtime->trusted_bootstrap_in_progress) {
    return true;
  }
  // The host-controlled bare evaluator remains the phase-limited trusted
  // loader while armed_bootstrap_eval_open is true. It must neither close the
  // provider rendezvous nor count as project execution; structured/project
  // ingress independently refuses until finish_bootstrap closes this phase.
  if (runtime->armed && runtime->armed_bootstrap_eval_open) {
    return true;
  }
  if (runtime->armed &&
      !runtime->root_global_disposition_verified_for_user_execution) {
    runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
    return false;
  }
  // The runtime-js handoff callback is construction-only. Closing it here is
  // the final common fence for legacy/feature-off runtimes that never run a
  // multi-capability finalizer; user code can never enumerate or call it.
  if (!runtime->user_execution_started) {
    if (!exactGpuCloseConstructionCapture(runtime)) {
      runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
      return false;
    }
  }
  runtime->user_execution_started = true;
  return true;
}

/// Construction-only evaluator used before registerRuntime publishes the
/// generation. Public embedders must use ex_hermes_eval, whose drive guard can
/// therefore reject every stale/off-owner/reentrant caller before dereference.
/// @ref LLP 0002#runtime-driving-thread-contract
int exactHermesBootstrapEval(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* sourceUrl,
    int isBytecode,
    char** outValue);

/// Perform one owner-thread Hermes source/bytecode evaluation, optionally
/// preceded by one trusted source prelude, and discard both results. Bytecode
/// sanity is proven before the optional prelude executes. This internal
/// primitive intentionally performs no nextTick or microtask drain, debugger
/// script publication, thenable inspection/poll, result coercion, or mutable
/// uncaught-exception hook between or after evaluations. The public GPU Canvas
/// transaction wrappers are its only embedder ingress.
int exactHermesEvalImmediateNoJobs(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* sourceUrl,
    int isBytecode,
    char** outError,
    const uint8_t* preludeData = nullptr,
    size_t preludeLen = 0,
    const char* preludeSourceUrl = nullptr);

struct NativeWebSocketCallbackContext {
  RuntimeCallbackTarget target;
  std::shared_ptr<facebook::jsi::Object> ws_instance;
  uint64_t runtime_nonce;
  uint64_t principal;
  std::string capability;
  std::atomic<uint32_t> ref_count{1};
  // One producer pin spans native connect through the backend's final context
  // release. It keeps teardown in its closing phase until every native callback
  // has stopped touching this context and its JSI owner has been marshalled.
  bool runtime_pin_held{false};
  // Guarded by g_websocket_mutex in hermes_runtime_websocket.cc. Keeping the
  // pre-registration terminal state on the exact per-runtime callback
  // context avoids process-global missing-ID tombstones.
  bool websocket_registered{false};
  bool websocket_terminal{false};
};

extern "C" int32_t ex_host_is_allow_all(void);
extern "C" int32_t ex_host_is_armed(void);
extern "C" uint32_t ex_host_armed_bootstrap_compatibility_flags(void);
extern "C" int32_t ibex_private_take_process_ipc_bootstrap(
    uint64_t host_context_id,
    int32_t* out_fd,
    uint32_t* out_serialization);
extern "C" uint64_t ibex_private_claim_restricted_host_context();
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
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
extern thread_local void* g_vm_runtime;
#endif

extern "C" uint64_t ex_host_enter_context(uint64_t context_id);
extern "C" void ex_host_restore_context(uint64_t previous);
extern "C" void ex_host_release_context(uint64_t context_id);
extern "C" uint32_t ex_host_vfs_bind_runtime(
    uint64_t context_id, uint64_t runtime_nonce);
extern "C" uint32_t ex_host_vfs_unbind_runtime(uint64_t runtime_nonce);
extern "C" uint32_t ex_host_vfs_get_cwd(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
extern "C" uint32_t ex_host_vfs_chdir(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
extern "C" uint32_t ex_host_vfs_resolve_path(
    uint64_t runtime_nonce,
    const uint8_t* input,
    uint64_t input_len,
    uint8_t** out_backing,
    uint64_t* out_backing_len,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
// Private retained-object read-only descriptor open. The returned opaque file
// handle is released with ex_host_fs_close and carries its original occurrence
// and bearer for later descriptor Repeat operations.
extern "C" uint32_t ibex_private_vfs_open_read_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    void** out_file,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
// Private retained-object existing-file append open. It never creates an
// absent path and carries the exact occurrence and bearer into later writes.
extern "C" uint32_t ibex_private_vfs_open_append_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    void** out_file,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
// Private retained-object whole-file read. The engine supplies its native
// runtime generation and frame-derived constrained principal stack; output is
// explicit-length and released with ex_host_free_buffer.
extern "C" uint32_t ibex_private_vfs_read_file_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Worker-backed whole-file read using the async readFile coverage contract.
// Inputs and output ownership match ibex_private_vfs_read_file_typed.
extern "C" uint32_t ibex_private_vfs_read_file_async_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-object stat. Output is explicit-length Node-shaped JSON and
// is released with ex_host_free_buffer.
extern "C" uint32_t ibex_private_vfs_stat_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    uint8_t** out_json,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-object lstat. The final link object is opened no-follow;
// output ownership matches ibex_private_vfs_stat_typed.
extern "C" uint32_t ibex_private_vfs_lstat_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    uint8_t** out_json,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-descriptor metadata Repeat. Output ownership matches
// ibex_private_vfs_stat_typed.
extern "C" uint32_t ibex_private_vfs_fstat_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint8_t** out_json,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-descriptor byte-read Repeat. Output is explicit-length and
// released with ex_host_free_buffer; positioned reads preserve the cursor.
extern "C" uint32_t ibex_private_vfs_read_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint32_t length,
    uint8_t positioned,
    uint64_t position,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Worker-backed scalar descriptor read. Authorization and acquisition share
// the async scalar-read coverage edge on the worker.
extern "C" uint32_t ibex_private_vfs_read_async_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint32_t length,
    uint8_t positioned,
    uint64_t position,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-descriptor whole-file read Repeat. Each call advances the
// descriptor by at most `length` bytes and attributes the decision to the
// readFile surface rather than the scalar read surface.
extern "C" uint32_t ibex_private_vfs_read_file_descriptor_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint32_t length,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained-descriptor vector-read Repeat. The caller supplies the
// aggregate destination length and scatters the explicit-length result only
// after the object-bound decision succeeds.
extern "C" uint32_t ibex_private_vfs_readv_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint32_t length,
    uint8_t positioned,
    uint64_t position,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Worker-backed aggregate descriptor vector read using the async readv edge.
extern "C" uint32_t ibex_private_vfs_readv_async_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    uint32_t length,
    uint8_t positioned,
    uint64_t position,
    uint8_t** out_data,
    uint64_t* out_len,
    int32_t* out_errno);
// Private retained append-descriptor write Repeat. The caller-owned input
// remains borrowed only for this synchronous call.
extern "C" uint32_t ibex_private_vfs_write_append_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    const uint8_t* data,
    uint32_t data_len,
    uint32_t* out_written,
    int32_t* out_errno);
// Worker-backed retained append writes. Each bridge binds its Repeat to the
// corresponding async scalar/vector coverage edge.
extern "C" uint32_t ibex_private_vfs_write_async_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    const uint8_t* data,
    uint32_t data_len,
    uint32_t* out_written,
    int32_t* out_errno);
extern "C" uint32_t ibex_private_vfs_writev_async_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    const uint8_t* data,
    uint32_t data_len,
    uint32_t* out_written,
    int32_t* out_errno);
// Retained writable-descriptor durability repeats. These do not mutate file
// contents and intentionally have separate surface identities from writes.
extern "C" uint32_t ibex_private_vfs_fsync_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    int32_t* out_errno);
extern "C" uint32_t ibex_private_vfs_fdatasync_typed(
    uint64_t runtime_nonce,
    uint64_t descriptor_owner,
    const uint64_t* module_ids,
    size_t module_ids_len,
    void* file,
    int32_t* out_errno);
// Private retained-object directory enumeration. Output is explicit-length
// JSON; every member is authorized at Repeat before disclosure.
extern "C" uint32_t ibex_private_vfs_readdir_typed(
    uint64_t runtime_nonce,
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const uint8_t* input,
    uint64_t input_len,
    const uint8_t* presented_handle_id,
    uint64_t presented_handle_id_len,
    uint8_t** out_json,
    uint64_t* out_len,
    int32_t* out_errno);
// Private native adapter: project an already-authenticated canonical backing
// identity through one exact runtime VFS session. Success returns only an
// explicit-length virtual spelling; the caller frees it with
// ex_host_free_buffer. This is intentionally not part of exact_runtime.h.
extern "C" uint32_t ibex_private_vfs_project_realpath(
    uint64_t runtime_nonce,
    const uint8_t* requested_virtual,
    uint64_t requested_virtual_len,
    const uint8_t* canonical_backing,
    uint64_t canonical_backing_len,
    uint8_t** out_virtual,
    uint64_t* out_virtual_len,
    int32_t* out_errno);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint64_t len);

[[noreturn]] void exactThrowVfsError(
    facebook::jsi::Runtime& runtime,
    uint32_t result,
    int32_t hostErrno,
    const char* operation,
    const std::string& path = "");

inline uint64_t exactCurrentRuntimeNonce() {
  return g_active_runtime_nonce;
}

// Select one runtime's Host/generation boundary for internal work that cannot
// use the registered drive guard (construction, Closing teardown, and pinned
// worker operations). Crossing generations also isolates every principal TLS;
// same-runtime helper nesting preserves the caller's active JS/callback scope.
// Off-owner worker scopes deliberately leave g_vm_runtime null and must install
// any captured typed-principal constraint explicitly after construction.
// @ref LLP 0002#runtime-driving-thread-contract
class ScopedRuntimeSecurityContext {
 public:
  explicit ScopedRuntimeSecurityContext(const ExactHermesRuntime* runtime)
      : previousRuntime_(g_active_runtime_nonce), previousHost_(UINT64_MAX) {
    if (runtime != nullptr) {
      g_active_runtime_nonce = runtime->runtime_nonce;
      previousHost_ = ex_host_enter_context(runtime->host_context_id);
      if (previousRuntime_ != runtime->runtime_nonce) {
        previousModule_ = g_active_module_id;
        previousNativePrincipal_ = g_native_callback_principal_id;
        previousTypedPrincipalStack_ =
            exactSwapTypedPrincipalStackForRuntimeDrive(nullptr);
        g_active_module_id = 0;
        g_native_callback_principal_id = kNoNativePrincipalOverride;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
        previousAttributionRuntime_ = g_vm_runtime;
        g_vm_runtime = runtime->runtime_thread == std::this_thread::get_id()
            ? runtime->attribution_runtime
            : nullptr;
#endif
        principalBoundary_ = true;
      }
    }
  }
  ~ScopedRuntimeSecurityContext() {
    if (principalBoundary_) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
      g_vm_runtime = previousAttributionRuntime_;
#endif
      exactSwapTypedPrincipalStackForRuntimeDrive(
          previousTypedPrincipalStack_);
      g_native_callback_principal_id = previousNativePrincipal_;
      g_active_module_id = previousModule_;
    }
    if (previousHost_ != UINT64_MAX) ex_host_restore_context(previousHost_);
    g_active_runtime_nonce = previousRuntime_;
  }
  ScopedRuntimeSecurityContext(const ScopedRuntimeSecurityContext&) = delete;
  ScopedRuntimeSecurityContext& operator=(const ScopedRuntimeSecurityContext&) = delete;

 private:
  uint64_t previousRuntime_;
  uint64_t previousHost_;
  uint64_t previousModule_{0};
  uint64_t previousNativePrincipal_{kNoNativePrincipalOverride};
  const std::vector<uint64_t>* previousTypedPrincipalStack_{nullptr};
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  void* previousAttributionRuntime_{nullptr};
#endif
  bool principalBoundary_{false};
};

struct ExactResolvedVfsPath {
  std::string backing;
  std::string virtualPath;
};

// File-backed SQLite shares the filesystem adapter's checked-object path. The
// public spelling remains virtual while the retained descriptors and backing
// spelling never cross into JavaScript. The descriptor is kept alive for the
// whole SQLite handle lifetime so the Host opens the exact object authorized at
// commit rather than re-resolving a pathname.
// @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
// @ref LLP 0023#6-path-bearing-observables
struct ExactArmedSqliteFile {
  std::shared_ptr<int> parent;
  std::shared_ptr<int> target;
  std::string authorizationBackingPath;
  std::string virtualPath;
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
  bool needsWrite = false;
};

// These helpers are private native adapters. In an armed runtime they accept
// virtual UTF-8 bytes and keep the backing spelling entirely native; unarmed
// diagnostic runtimes retain their historical host-path behavior.
ExactResolvedVfsPath exactResolveVfsPath(
    facebook::jsi::Runtime& runtime, const std::string& input);
ExactArmedSqliteFile exactOpenArmedSqliteFile(
    facebook::jsi::Runtime& runtime,
    const ExactResolvedVfsPath& path,
    bool needsWrite,
    bool mayCreate);
void exactRequireArmedSqliteFile(
    facebook::jsi::Runtime& runtime,
    const ExactArmedSqliteFile& file,
    const char* syscall,
    uint32_t surface,
    bool needsRead,
    bool needsWrite);
std::string exactGetVfsCwd(facebook::jsi::Runtime& runtime);
std::string exactSetVfsCwd(
    facebook::jsi::Runtime& runtime, const std::string& input);

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
extern "C" int32_t ex_host_authorize_typed_listen_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t operation_kind,
    const char* host,
    uint16_t port,
    int32_t dual_stack,
    uint32_t stage,
    const char* bound_address,
    uint16_t bound_port,
    const char* listener_id,
    const char* accepted_address,
    uint16_t accepted_port);
extern "C" int32_t ex_host_has_deputy_classes(void);
extern "C" int32_t ex_host_check_import(uint64_t module_id,
                                        const char* specifier,
                                        const char* target_source_id,
                                        uint32_t resolution_kind);
// @ref LLP 0013#delegation-and-authority-flow — authority-bearing capability handles.
extern "C" uint64_t ex_host_handle_create(const char* capability);
extern "C" uint64_t ex_host_handle_scoped(uint64_t parent, const char* narrower);
extern "C" int32_t ex_host_handle_check(uint64_t id, const char* capability);
extern "C" void ex_host_handle_revoke(uint64_t id);
// @ref LLP 0013 — §dynamic permissions — runtime root-grant mutation (tri-state).
extern "C" int32_t ex_host_permission_request(const char* capability);
extern "C" void ex_host_permission_revoke(const char* capability);
extern "C" int32_t ex_host_permission_status(const char* capability);
extern "C" int32_t ex_host_authorize_typed_environment_read_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t stage,
    uint32_t read_surface,
    const uint8_t* name,
    size_t name_len);
extern "C" int32_t ex_host_authorize_typed_environment_write_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t stage,
    const uint8_t* name,
    size_t name_len);
extern "C" int32_t ex_host_authorize_typed_print_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t stage);

// Reserved principals are part of the runtime's fallback attribution contract
// too, so they must remain available when an embedder uses an unpatched Hermes
// without frame-attribution symbols. Keep these values in sync with Hermes'
// kRuntimePackageId and the Rust NO_USER_PRINCIPAL constant.
constexpr uint32_t kRuntimePrincipalId = 0xFFFFFFFFu;
constexpr uint32_t kNoUserPrincipalId = 0xFFFFFFFEu;

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
#ifdef EXACT_HAVE_STRUCTURED_ASYNC_PROVENANCE
extern "C" uint32_t ex_hermes_vm_current_job_scheduler_principal(
    void* vm_runtime);
extern "C" uint64_t ex_hermes_vm_current_job_identity(void* vm_runtime);
extern "C" uint64_t ex_hermes_vm_current_job_associated_evaluation(
    void* vm_runtime);
extern "C" void ex_hermes_vm_set_job_associated_evaluation(
    void* vm_runtime,
    uint64_t associated_evaluation);
extern "C" void ex_hermes_vm_set_embedder_job_scheduler_principal(
    void* vm_runtime,
    uint32_t principal);
extern "C" int ex_hermes_vm_take_failed_job_context(
    void* vm_runtime,
    uint32_t* principal,
    uint64_t* identity,
    uint64_t* associated_evaluation);
#endif
// The vm::Runtime pointer (HermesRuntime::getVMRuntimeUnsafe()), cached at
// runtime creation. Null on unpatched engines and until the runtime is created.
// THREAD-LOCAL: names the runtime the current thread created and drives, so
// concurrent runtimes on other threads (unit-test harness, worklets) can't
// clobber or free the pointer this thread's attribution walk reads. The extern
// is declared above with the other runtime-bound TLS so construction and
// teardown scopes can select it too. (ENG-23011)
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
bool exactRegisterProcessIpcFd(int fd);
bool exactCloseProcessIpcFd(uint64_t runtimeNonce, int fd);
bool exactRegisterReceivedFdForCurrentPrincipal(int fd);
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
enum class ExactEnvironmentOverlayAccess : uint32_t {
  ScalarRead = 0,
  EnumerationRead = 1,
  Write = 2,
};

inline bool typedEnvironmentOverlayAccessAllowed(
    const std::string& name,
    ExactEnvironmentOverlayAccess access) {
  if (ex_host_is_armed() != 1) return true;
  auto principal = currentPrincipalId();
  auto principals = exactCollectTypedPrincipalStack();
  for (uint32_t stage = 0; stage <= 1; ++stage) {
    auto result = access == ExactEnvironmentOverlayAccess::Write
        ? ex_host_authorize_typed_environment_write_stack(
              principal,
              principals.data(),
              principals.size(),
              stage,
              reinterpret_cast<const uint8_t*>(name.data()),
              name.size())
        : ex_host_authorize_typed_environment_read_stack(
              principal,
              principals.data(),
              principals.size(),
              stage,
              access == ExactEnvironmentOverlayAccess::EnumerationRead ? 1u : 0u,
              reinterpret_cast<const uint8_t*>(name.data()),
              name.size());
    if (result != 1) return false;
  }
  return true;
}

// @ref LLP 0022#7-capabilities-principals-and-affordance-parity — an armed
// environment read authorizes the current principal's exact overlay name and
// never falls through to the host process environment.
inline void authorizeTypedEnvironmentRead(
    facebook::jsi::Runtime& runtime,
    const std::string& name) {
  if (!typedEnvironmentOverlayAccessAllowed(
          name, ExactEnvironmentOverlayAccess::ScalarRead)) {
    throw facebook::jsi::JSError(
        runtime, "Permission denied: env:read authority required");
  }
}

// @ref LLP 0021#typed-resources-and-initial-vocabulary — overlay mutation is
// independently authorized by env:write at requested and commit.
inline void authorizeTypedEnvironmentWrite(
    facebook::jsi::Runtime& runtime,
    const std::string& name) {
  if (!typedEnvironmentOverlayAccessAllowed(
          name, ExactEnvironmentOverlayAccess::Write)) {
    throw facebook::jsi::JSError(
        runtime, "Permission denied: env:write authority required");
  }
}
// @ref LLP 0021#decision-staging-and-principal-semantics — direct print
// authorizes every generated stage before the line enters the stdout broker.
inline void authorizeTypedPrint(facebook::jsi::Runtime& runtime) {
  if (ex_host_is_armed() != 1) return;
  auto principal = currentPrincipalId();
  auto principals = exactCollectTypedPrincipalStack();
  for (uint32_t stage : {0u, 2u, 4u}) {
    if (ex_host_authorize_typed_print_stack(
            principal, principals.data(), principals.size(), stage) != 1) {
      throw facebook::jsi::JSError(
          runtime, "Permission denied: stdio:write authority required");
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
RuntimeCallbackTarget exactRuntimeCallbackTarget(ExactHermesRuntime* runtime);
uint64_t exactAllocateAsyncEventIdentity(ExactHermesRuntime* runtime);
uint64_t exactCurrentAsyncEvaluationAssociation(ExactHermesRuntime* runtime);
uint64_t exactAllocateRuntimeNonce();
bool exactPinRuntimeNativeWorker(RuntimeCallbackTarget target);
void exactUnpinRuntimeNativeWorker(RuntimeCallbackTarget target);
// Remove only filesystem work that is still queued for this exact runtime
// generation. A worker atomically commits its operation while holding the
// pool mutex before it can run an effect, so teardown never reports a
// committed effect as canceled.
// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
void exactCancelQueuedFsOperations(RuntimeCallbackTarget target);
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
// Private test controls for executable no-oracle and queue-cancellation
// evidence. They are deliberately absent from exact_runtime.h and production
// artifacts.
extern "C" void ibex_private_test_reset_fs_conformance_observer();
extern "C" void ibex_private_test_set_requested_fs_authorization_result(
    int32_t result);
extern "C" void
ibex_private_test_set_requested_fs_authorization_result_for_path(
    int32_t result,
    const char* path);
extern "C" uint64_t ibex_private_test_armed_path_lookup_count();
extern "C" uint64_t
ibex_private_test_armed_path_lookup_after_refusal_count();
extern "C" uint64_t ibex_private_test_cancel_queued_fs_operations(
    ExactHermesRuntime* runtime);
#endif

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
inline bool ibexHermesES6BlockScopingEnabled() {
  // @ref LLP 0034#decision — Ibex enables Hermes's existing correct lexical
  // scope implementation by default. This opt-out is a migration control and
  // must be resolved identically by the compiler and both runtime kinds.
  return !env_flag_enabled("IBEX_LEGACY_HERMES_BLOCK_SCOPING");
}
void requireArmedStartupStage(ExactHermesRuntime* handle, const char* stage);
void requireDiagnosticStartupStage(ExactHermesRuntime* handle, const char* stage);
void reportStartupFailure(ExactHermesRuntime* handle,
                          const char* stage,
                          const std::string& detail);
std::string valueToString(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);
uint64_t nowMs();
double processUptimeSeconds();
facebook::jsi::Function makeProcessExitFn(
    ExactHermesRuntime* handle,
    facebook::jsi::Runtime& rt);
void cleanupFetchCallbacks(ExactHermesRuntime* runtime);
void exactForgetNativeFetchTarget(uint32_t requestId, uint64_t runtimeNonce);

// Retain one exact raw JavaScript failure value and return its graph-local
// nonzero token. No property access or coercion is performed here.
uint64_t exactRetainStructuredModuleGraphError(
    ExactHermesRuntime* runtime,
    const facebook::jsi::JSError& error) noexcept;
uint64_t exactRetainStructuredModuleGraphError(
    ExactHermesRuntime* runtime,
    const facebook::jsi::Value& value) noexcept;

bool eval_bootstrap_script(ExactHermesRuntime* handle,
                           const char* source,
                           const uint8_t* hbc,
                           size_t hbcLen,
                           const char* sourceUrl,
                           bool preferSource,
                           bool allowHbc);

bool installModuleLoader(ExactHermesRuntime* handle);
void captureLegacyBootstrapEnvironment(ExactHermesRuntime* handle);
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
void unregisterSignalRuntime(ExactHermesRuntime* handle);
void installFsMutationGuardHostFunction(ExactHermesRuntime* handle);
void installFsHostFunctions(ExactHermesRuntime* handle);
void installChildProcessHostFunctions(ExactHermesRuntime* handle);
// Install only the runtime/principal-bound retained-wrapper owner primitive.
// Full socket and TLS host functions remain behind __exactEnsureNet.
void installNetOwnerHostFunction(ExactHermesRuntime* handle);
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
extern "C" void ex_host_console_log_bytes(
    int32_t level,
    const uint8_t* message,
    size_t length);
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
bool exactRuntimeDebuggerIngressAllowed(
    const ExactHermesRuntime* runtime) noexcept;
bool exactRuntimeBeginGpuCanvasDebuggerExclusion(
    ExactHermesRuntime* runtime) noexcept;
bool exactRuntimeFinishGpuCanvasDebuggerExclusion(
    ExactHermesRuntime* runtime) noexcept;
void pushDebugEvent(ExactHermesRuntime* runtime, const std::string& event);
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> snapshotDebugger(
    ExactHermesRuntime* runtime);
std::shared_ptr<ExactPendingDebuggerCommand> exactRuntimeAdmitDebuggerCommand(
    ExactHermesRuntime* runtime,
    std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI>* debugger);
void exactRuntimeCancelPendingDebuggerCommands(
    ExactHermesRuntime* runtime) noexcept;
bool exactRuntimeDebuggerCommandCancelled(
    const std::shared_ptr<ExactPendingDebuggerCommand>& command) noexcept;
void exactRuntimeSettleDebuggerCommand(
    ExactHermesRuntime* runtime,
    const std::shared_ptr<ExactPendingDebuggerCommand>& command,
    std::string result = {}) noexcept;
std::string exactRuntimeWaitDebuggerCommand(
    ExactHermesRuntime* runtime,
    const std::shared_ptr<ExactPendingDebuggerCommand>& command,
    bool* cancelled = nullptr) noexcept;
void exactRuntimeDebuggerInterruptQueuedTestPause(
    ExactHermesRuntime* runtime,
    const std::shared_ptr<ExactPendingDebuggerCommand>& command) noexcept;
#endif
void clearDebugger(ExactHermesRuntime* runtime);
void disableDebugger(ExactHermesRuntime* runtime);
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
std::string buildPausedEvent(facebook::hermes::debugger::Debugger& debugger);
#endif
bool runtimeIsAlive(RuntimeCallbackTarget target);

// ENG-22925/ENG-23028: run `body` with the runtime pinned alive. Holds
// g_runtimeRegistryMutex across a generation test AND the synchronous execution
// of `body`, so a caller on any thread can safely dereference runtime-owned
// state (per-runtime mutexes/maps) that would otherwise race a concurrent
// ex_hermes_destroy entering Closing. Returns
// true iff the runtime was alive and `body` ran. `body` MUST be short and MUST
// NOT re-enter the runtime registry (no ex_hermes_destroy / pushRuntimeCallback /
// runtimeIsAlive). If it takes a per-runtime lock, that lock must follow the
// registry in the global lock order; destroy-side cleanup that needs the same
// lock must also happen under the registry. This is the cross-translation-unit
// form of the resolve_host_call pin so sibling completion paths (fetch,
// debugger, etc.) can close the same check-then-lock TOCTOU without exposing the
// registry internals.
bool withRuntimePinned(RuntimeCallbackTarget target,
                       const std::function<void()>& body);

#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
void emitNewScripts(ExactHermesRuntime* runtime,
                    facebook::hermes::debugger::Debugger& debugger);
#endif

void pushRuntimeCallback(RuntimeCallbackTarget target,
                         std::function<void(facebook::jsi::Runtime&)> fn,
                         bool* accepted = nullptr);
extern "C" void ex_hermes_notify_callback();

// Enqueue a native-resource finalizer without transferring ownership on
// failure. A successful enqueue guarantees `fn` runs on the runtime thread,
// including while destroy waits for native producer pins to drain.
bool pushRuntimeFinalizer(RuntimeCallbackTarget target,
                          std::function<void()> fn);

bool exactGpuBindingInstalled(const ExactHermesRuntime* runtime);
bool exactGpuAuthenticatedV2ProviderGlobalsActive(
    const ExactHermesRuntime* runtime);
bool exactGpuAuthenticatedDecodedImageGlobalActive(
    const ExactHermesRuntime* runtime);
bool exactGpuRuntimeActivated(const ExactHermesRuntime* runtime);
bool exactGpuCheckpointHostTask(ExactHermesRuntime* runtime);
bool exactGpuOwnerDrainPending(const ExactHermesRuntime* runtime);
int exactGpuDrainOwnerFallback(ExactHermesRuntime* runtime);
int32_t exactGpuActivateInstall(ExactHermesRuntime* runtime);
bool exactGpuPublishPrivateBridge(ExactHermesRuntime* runtime);
bool exactGpuSealPrivateBridge(ExactHermesRuntime* runtime);
void exactGpuRollbackInstall(ExactHermesRuntime* runtime);
void exactGpuBeginRuntimeTeardown(ExactHermesRuntime* runtime);

// Additive V2 implementation hooks, composed by the version-neutral lifecycle
// helpers above. These stay engine-internal; the public surface is the C ABI in
// exact_runtime.h plus the one-shot runtime-js construction capture.
int32_t exactGpuV2ActivateInstall(ExactHermesRuntime* runtime);
bool exactGpuV2PublishPrivateBridge(ExactHermesRuntime* runtime);
bool exactGpuV2SealPrivateBridge(ExactHermesRuntime* runtime);
bool exactGpuV2CheckpointHostTask(ExactHermesRuntime* runtime);
bool exactGpuV2OwnerDrainPending(const ExactHermesRuntime* runtime);
int exactGpuV2DrainOwnerFallback(ExactHermesRuntime* runtime);
void exactGpuV2RollbackInstall(ExactHermesRuntime* runtime);
void exactGpuV2BeginRuntimeTeardown(ExactHermesRuntime* runtime);

bool exactGpuDecodedImageAttachAuthorityV1(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& bridge);
void exactGpuDecodedImageDiscardIfUnusedV1(ExactHermesRuntime* runtime);
void exactGpuDecodedImageRollbackInstallV1(ExactHermesRuntime* runtime);
void exactGpuDecodedImageBeginRuntimeTeardownV1(ExactHermesRuntime* runtime);
bool exactGpuDecodedImageOwnerDrainPendingV1(
    const ExactHermesRuntime* runtime);
int exactGpuDecodedImageDrainOwnerFallbackV1(ExactHermesRuntime* runtime);

void exactRequireFdReadable(facebook::jsi::Runtime& runtime, int fd, const char* syscall);
void exactRequireFdWritable(facebook::jsi::Runtime& runtime, int fd, const char* syscall);
extern "C" int32_t ex_host_session_descriptor_is_protected(int32_t fd);
extern "C" int32_t ex_host_session_descriptor_read_route(int32_t fd);
extern "C" int32_t ex_host_session_descriptor_write_route(int32_t fd);
extern "C" int32_t ex_host_session_descriptor_close_route(int32_t fd);
extern "C" int32_t ex_host_session_descriptor_alias_source_route(int32_t fd);
extern "C" int32_t ex_host_session_descriptor_alias_target_route(int32_t fd);
extern "C" int32_t ex_host_terminal_session_stdio_query(
    int32_t fd,
    int32_t* out_is_tty,
    uint16_t* out_columns,
    uint16_t* out_rows);

extern const char* g_streamEnhanceJS;
extern const char* g_webCryptoJS;
extern const char* g_webStorageJS;
extern const char* g_formDataJS;
