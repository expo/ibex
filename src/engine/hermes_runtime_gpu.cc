// @system @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Optional provider-independent Exact GPU service registration and the private
// construction-time binary bridge used by a future generated WebGPU wrapper.
// This file deliberately publishes no navigator.gpu value and contains no
// wgpu-native dependency.

#include "hermes_runtime_internal.h"
#include "../../include/exact_runtime.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" int32_t ex_host_authorize_exact_gpu_provider(
    uint64_t context_id,
    uint32_t abi_version,
    const uint8_t* profile_id,
    size_t profile_id_len,
    const uint8_t* profile_digest,
    const uint8_t* webgpu_c_vocabulary_digest,
    const uint8_t* operation_set_digest,
    const uint8_t* semantic_program_digest,
    const uint32_t* operation_ids,
    size_t operation_count,
    uint32_t topology_id);

namespace {

constexpr char kGpuCaptureGlobalName[] = "__ibexCaptureGpuNativeBridge";

bool closeGpuConstructionCaptureImpl(ExactHermesRuntime* runtime) noexcept {
  // This name is meaningful only during the trusted construction window.
  // Once app execution starts it may legitimately be rebound by untrusted JS;
  // teardown must neither invoke nor delete that unrelated lookalike.
  if (!runtime || !runtime->runtime || runtime->user_execution_started) {
    return true;
  }
  auto& rt = *runtime->runtime;
  bool invocationSucceeded = true;
  try {
    if (rt.global().hasProperty(rt, kGpuCaptureGlobalName)) {
      auto capture = rt.global().getProperty(rt, kGpuCaptureGlobalName);
      if (!capture.isObject() || !capture.getObject(rt).isFunction(rt)) {
        invocationSucceeded = false;
      } else {
        capture.getObject(rt).asFunction(rt).call(rt);
      }
    }
  } catch (...) {
    invocationSucceeded = false;
  }

  bool absent = false;
  try {
    absent = !rt.global().hasProperty(rt, kGpuCaptureGlobalName);
  } catch (...) {
    absent = false;
  }
  if (!absent) {
    // Deletion is an independent fail-closed step. A malformed or replaced
    // construction callback must not keep the handoff enumerable/callable just
    // because invoking it failed.
    try {
      auto deleted = rt.global()
                         .getPropertyAsObject(rt, "Reflect")
                         .getPropertyAsFunction(rt, "deleteProperty")
                         .call(
                             rt,
                             rt.global(),
                             facebook::jsi::String::createFromAscii(
                                 rt, kGpuCaptureGlobalName));
      absent = deleted.isBool() && deleted.getBool() &&
          !rt.global().hasProperty(rt, kGpuCaptureGlobalName);
    } catch (...) {
      absent = false;
    }
  }
  return invocationSucceeded && absent;
}

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
constexpr size_t kMaxGpuOperationCount = 4096;
constexpr size_t kMaxGpuProfileIdBytes = 256;
constexpr size_t kMaxGpuPayloadBytes = 16 * 1024 * 1024;
constexpr size_t kMaxGpuPendingReceipts = 1024;
constexpr size_t kMaxGpuQueuedEvents = 1024;
constexpr size_t kMaxGpuRecentTerminals = 2048;
constexpr size_t kMaxGpuRetireHandles = 4096;

#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
std::atomic<uint64_t> gGpuTestResolveCalls{0};
std::atomic<uint64_t> gGpuTestRejectCalls{0};
std::atomic<uint32_t> gGpuTestLastSettlementKind{0};
std::atomic<int32_t> gGpuTestLastSettlementStatus{0};
std::atomic<uint32_t> gGpuTestDrainFailurePoint{0};
std::atomic<uint64_t> gGpuTestOwnerFallbackDrainCalls{0};
std::atomic<uint64_t> gGpuTestDiagnosticBackingCount{0};
std::atomic<uint64_t> gGpuTestDiagnosticBackingBytes{0};
std::atomic<uint64_t> gGpuTestDiagnosticAttachmentCount{0};
std::atomic<uint32_t> gGpuTestActivationPauseState{0};
std::atomic<uint32_t> gGpuTestResultPublicationFailurePoint{0};
std::atomic<bool> gGpuTestSuccessCarrierReady{false};
std::atomic<uint64_t> gGpuTestAuthorityReductionCalls{0};
#endif

enum class GpuMailboxPhase : uint8_t {
  Installing,
  Activating,
  Live,
  ProtocolViolation,
  Closing,
  Detached,
};

struct CopiedGpuEvent {
  uint32_t kind{0};
  uint32_t operation_id{0};
  uint64_t completion_id{0};
  int32_t status{0};
  std::vector<uint8_t> payload;
};

struct GpuSubmissionState {
  uint32_t operation_id{0};
  bool event_queued{false};
};

struct ExactGpuClientMailbox {
  explicit ExactGpuClientMailbox(RuntimeCallbackTarget target)
      : target(target) {}

  std::atomic<uint32_t> references{1};
  std::atomic<GpuMailboxPhase> phase{GpuMailboxPhase::Installing};
  std::atomic<uint64_t> accepted_events{0};
  RuntimeCallbackTarget target;
  std::atomic<ExactGpuRealmTokenV1> realm{0};
  std::atomic<bool> owner_drain_required{false};

  // Service threads touch only this plain-native state. JSI resolve/reject
  // functions remain owner-thread-only in ExactGpuRuntimeBinding.
  std::mutex mutex;
  std::unordered_map<uint64_t, GpuSubmissionState> submissions;
  std::deque<CopiedGpuEvent> events;
  size_t queued_payload_bytes{0};
  uint64_t highest_completion_id{0};
  std::array<uint64_t, kMaxGpuRecentTerminals> recent_terminals{};
  size_t recent_terminal_count{0};
  size_t recent_terminal_cursor{0};
  bool drain_scheduled{false};
  bool authority_reduced{false};
  bool authority_reduction_applied{false};
  bool terminal_event_queued{false};
};

struct PendingGpuReceipt {
  uint32_t operation_id{0};
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

struct GpuPromiseResolvers {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

void retainGpuClient(void* context) {
  if (!context) return;
  static_cast<ExactGpuClientMailbox*>(context)->references.fetch_add(
      1, std::memory_order_relaxed);
}

void releaseGpuClient(void* context) {
  if (!context) return;
  auto* mailbox = static_cast<ExactGpuClientMailbox*>(context);
  if (mailbox->references.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    delete mailbox;
  }
}

struct RetainedGpuMailbox {
  explicit RetainedGpuMailbox(ExactGpuClientMailbox* mailbox)
      : mailbox(mailbox) {
    retainGpuClient(mailbox);
  }

  ~RetainedGpuMailbox() {
    releaseGpuClient(mailbox);
  }

  RetainedGpuMailbox(const RetainedGpuMailbox&) = delete;
  RetainedGpuMailbox& operator=(const RetainedGpuMailbox&) = delete;

  ExactGpuClientMailbox* mailbox;
};

bool validProfileId(const char* data, size_t length) {
  if (!data || length == 0 || length > kMaxGpuProfileIdBytes) return false;
  for (size_t index = 0; index < length; ++index) {
    unsigned char byte = static_cast<unsigned char>(data[index]);
    if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
          byte == '.' || byte == '_' || byte == '/' || byte == '-')) {
      return false;
    }
  }
  return (data[0] >= 'a' && data[0] <= 'z') ||
      (data[0] >= '0' && data[0] <= '9');
}

bool validOperationIds(const uint32_t* operations, size_t count) {
  if (!operations || count == 0 || count > kMaxGpuOperationCount) return false;
  uint32_t previous = 0;
  for (size_t index = 0; index < count; ++index) {
    if (operations[index] == 0 || (index > 0 && operations[index] <= previous)) {
      return false;
    }
    previous = operations[index];
  }
  return true;
}

bool validServiceApi(const ExactGpuServiceApiV1* api) {
  return api->feature_bits == 0 && api->retain_service &&
      api->release_service && api->open_realm && api->activate_realm &&
      api->submit && api->retire && api->cancel && api->close_realm;
}

bool isGpuTerminalLocked(
    const ExactGpuClientMailbox& mailbox,
    uint64_t completion) {
  if (completion == 0) return false;
  for (size_t index = 0; index < mailbox.recent_terminal_count; ++index) {
    if (mailbox.recent_terminals[index] == completion) return true;
  }
  return false;
}

void markGpuTerminalLocked(ExactGpuClientMailbox& mailbox, uint64_t completion) {
  if (completion == 0 || isGpuTerminalLocked(mailbox, completion)) return;
  mailbox.recent_terminals[mailbox.recent_terminal_cursor] = completion;
  mailbox.recent_terminal_cursor =
      (mailbox.recent_terminal_cursor + 1) % kMaxGpuRecentTerminals;
  mailbox.recent_terminal_count = std::min(
      mailbox.recent_terminal_count + 1, kMaxGpuRecentTerminals);
}

#endif

}  // namespace

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
struct ExactGpuRuntimeBinding {
  ExactGpuServiceApiV1 api{};
  ExactGpuClientMailbox* mailbox{nullptr};
  ExactGpuRealmTokenV1 realm{0};
  ExactGpuAccountTokenV1 account{0};
  std::unordered_set<uint32_t> allowed_operations;
  std::unordered_map<uint64_t, PendingGpuReceipt> pending_receipts;
  uint64_t next_completion_id{1};
  std::shared_ptr<facebook::jsi::Object> private_bridge;
  std::shared_ptr<facebook::jsi::Function> revoke_capture;
  bool service_retained{false};
  bool realm_open{false};
  bool bridge_captured{false};
  bool bridge_sealed{false};
  bool detached{false};

  ~ExactGpuRuntimeBinding();
  void detach(ExactHermesRuntime* runtime, const char* reason) noexcept;
};
#else
struct ExactGpuRuntimeBinding {
  void detach(ExactHermesRuntime*, const char*) noexcept {}
};
#endif

namespace {

#if defined(IBEX_ENABLE_WEBGPU_BINDING)

GpuMailboxPhase markGpuMailboxProtocolViolation(
    ExactGpuClientMailbox* mailbox) noexcept;
void publishGpuOwnerDrainFallback(ExactGpuClientMailbox* mailbox) noexcept;

bool parseCanonicalGpuUint64(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* name,
    bool allowZero,
    uint64_t& out) {
  if (!value.isString()) {
    throw facebook::jsi::JSError(
        rt,
        std::string(name) +
            " must be a canonical decimal string (JS numbers are not accepted)");
  }
  auto text = value.asString(rt).utf8(rt);
  if (text.empty() || text.size() > 20 ||
      (text.size() > 1 && text.front() == '0')) {
    throw facebook::jsi::JSError(
        rt, std::string(name) + " must be a canonical uint64 decimal string");
  }
  uint64_t parsed = 0;
  for (char byte : text) {
    if (byte < '0' || byte > '9') {
      throw facebook::jsi::JSError(
          rt, std::string(name) + " must be a canonical uint64 decimal string");
    }
    uint64_t digit = static_cast<uint64_t>(byte - '0');
    if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
      throw facebook::jsi::JSError(
          rt, std::string(name) + " exceeds the uint64 range");
    }
    parsed = parsed * 10 + digit;
  }
  if (!allowZero && parsed == 0) {
    throw facebook::jsi::JSError(rt, std::string(name) + " must be nonzero");
  }
  out = parsed;
  return true;
}

uint32_t parseGpuOperationId(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(rt, "GPU operation ID must be a uint32");
  }
  double raw = value.asNumber();
  if (!std::isfinite(raw) || raw < 1.0 ||
      raw > static_cast<double>(UINT32_MAX) || std::floor(raw) != raw) {
    throw facebook::jsi::JSError(rt, "GPU operation ID must be a uint32");
  }
  return static_cast<uint32_t>(raw);
}

facebook::jsi::String gpuUint64String(
    facebook::jsi::Runtime& rt,
    uint64_t value) {
  return facebook::jsi::String::createFromAscii(rt, std::to_string(value));
}

void defineGpuProperty(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& target,
    const char* name,
    facebook::jsi::Value value,
    bool configurable) {
  auto objectConstructor = rt.global().getPropertyAsObject(rt, "Object");
  auto defineProperty =
      objectConstructor.getPropertyAsFunction(rt, "defineProperty");
  facebook::jsi::Object descriptor(rt);
  descriptor.setProperty(rt, "value", std::move(value));
  descriptor.setProperty(rt, "writable", false);
  descriptor.setProperty(rt, "enumerable", false);
  descriptor.setProperty(rt, "configurable", configurable);
  defineProperty.call(
      rt,
      target,
      facebook::jsi::String::createFromAscii(rt, name),
      descriptor);
}

std::shared_ptr<facebook::jsi::Object> tryMakeGpuDiagnosticPayload(
    facebook::jsi::Runtime& rt,
    const std::vector<uint8_t>& payload) noexcept {
  try {
    auto value = makeUint8Array(rt, payload);
    auto object = value.asObject(rt);
    auto shared =
        std::make_shared<facebook::jsi::Object>(std::move(object));
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    gGpuTestDiagnosticBackingCount.fetch_add(1, std::memory_order_seq_cst);
    gGpuTestDiagnosticBackingBytes.fetch_add(
        payload.size(), std::memory_order_seq_cst);
#endif
    return shared;
  } catch (...) {
    // Diagnostic bytes are optional under allocation pressure. The receipt
    // itself must still reject exactly once, so callers share one successful
    // backing or attach `undefined`; they never retry a large allocation once
    // per pending receipt.
    return nullptr;
  }
}

std::shared_ptr<facebook::jsi::Object> tryMakeEmptyGpuDiagnosticPayload(
    facebook::jsi::Runtime& rt) noexcept {
  static const std::vector<uint8_t> empty;
  return tryMakeGpuDiagnosticPayload(rt, empty);
}

facebook::jsi::Object makeGpuError(
    facebook::jsi::Runtime& rt,
    const char* kind,
    int32_t status,
    uint32_t operation,
    uint64_t completion,
    const std::shared_ptr<facebook::jsi::Object>& payload,
    const char* fallbackMessage) {
  // Payload is opaque binary diagnostic data, not implicitly trusted UTF-8.
  // Preserve it separately and keep the public error message deterministic.
  const char* message = fallbackMessage ? fallbackMessage : "Exact GPU error";
  auto error = rt.global()
                   .getPropertyAsFunction(rt, "Error")
                   .callAsConstructor(
                       rt, facebook::jsi::String::createFromUtf8(rt, message))
                   .getObject(rt);
  error.setProperty(
      rt, "kind", facebook::jsi::String::createFromAscii(rt, kind));
  error.setProperty(rt, "status", status);
  error.setProperty(rt, "operationId", static_cast<double>(operation));
  error.setProperty(rt, "completionId", gpuUint64String(rt, completion));
  if (payload) {
    error.setProperty(rt, "payload", facebook::jsi::Value(rt, *payload));
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    gGpuTestDiagnosticAttachmentCount.fetch_add(
        1, std::memory_order_seq_cst);
#endif
  } else {
    error.setProperty(rt, "payload", facebook::jsi::Value::undefined());
  }
  return error;
}

facebook::jsi::Object makeGpuReceipt(
    facebook::jsi::Runtime& rt,
    CopiedGpuEvent event) {
  const char* kind = "operation-complete";
  if (event.kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR) {
    kind = "device-error";
  } else if (event.kind == EXACT_GPU_SERVICE_EVENT_DEVICE_LOST) {
    kind = "device-lost";
  } else if (event.kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED) {
    kind = "realm-closed";
  }
  facebook::jsi::Object receipt(rt);
  receipt.setProperty(
      rt, "kind", facebook::jsi::String::createFromAscii(rt, kind));
  receipt.setProperty(rt, "status", event.status);
  receipt.setProperty(
      rt, "operationId", static_cast<double>(event.operation_id));
  receipt.setProperty(
      rt, "completionId", gpuUint64String(rt, event.completion_id));
  receipt.setProperty(
      rt, "payload", makeUint8Array(rt, std::move(event.payload)));
  return receipt;
}

void rejectGpuReceipt(
    facebook::jsi::Runtime& rt,
    PendingGpuReceipt receipt,
    const char* kind,
    int32_t status,
    uint64_t completion,
    const std::shared_ptr<facebook::jsi::Object>& payload,
    const char* message) noexcept {
  if (!receipt.reject) return;
  try {
    auto error = makeGpuError(
        rt,
        kind,
        status,
        receipt.operation_id,
        completion,
        payload,
        message);
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    uint32_t settlementKind = 9;
    if (std::strcmp(kind, "operation-error") == 0) settlementKind = 2;
    else if (std::strcmp(kind, "device-error") == 0) settlementKind = 3;
    else if (std::strcmp(kind, "device-lost") == 0) settlementKind = 4;
    else if (std::strcmp(kind, "realm-closed") == 0) settlementKind = 5;
    else if (std::strcmp(kind, "protocol-violation") == 0) settlementKind = 6;
    else if (std::strcmp(kind, "cancelled") == 0) settlementKind = 7;
    else if (std::strcmp(kind, "admission-rejected") == 0) settlementKind = 8;
    gGpuTestLastSettlementKind.store(settlementKind, std::memory_order_seq_cst);
    gGpuTestLastSettlementStatus.store(status, std::memory_order_seq_cst);
    gGpuTestRejectCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
    receipt.reject->call(rt, error);
  } catch (...) {
    // Constructing a structured Error is diagnostic, not settlement-critical.
    // Under VM allocation pressure, make one allocation-minimal rejection
    // attempt so the Promise is not left pending solely because its metadata
    // could not be materialized.
    try {
      receipt.reject->call(rt, facebook::jsi::Value::undefined());
    } catch (...) {
    }
  }
}

std::unordered_map<uint64_t, PendingGpuReceipt> takeAllGpuReceipts(
    ExactGpuRuntimeBinding& binding) noexcept {
  auto receipts = std::move(binding.pending_receipts);
  binding.pending_receipts.clear();
  return receipts;
}

void cancelGpuCompletionsOutsideLocks(
    ExactGpuRuntimeBinding& binding,
    const uint64_t* completions,
    size_t completionCount) noexcept {
  if (!binding.realm_open || !binding.api.cancel) return;
  for (size_t index = 0; index < completionCount; ++index) {
    try {
      (void)binding.api.cancel(
          binding.api.service_context, binding.realm, completions[index]);
    } catch (...) {
      ex_host_console_log(1, "Exact GPU service cancel threw across its C ABI");
    }
  }
}

void reduceGpuAuthority(
    ExactGpuRuntimeBinding& binding,
    facebook::jsi::Runtime& rt,
    const char* kind,
    int32_t status,
    const std::vector<uint8_t>& payload,
    const char* message,
    bool cancelProviderWork) noexcept {
  std::array<uint64_t, kMaxGpuPendingReceipts> completions{};
  size_t completionCount = 0;
  if (binding.mailbox) {
    try {
      std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
      if (binding.mailbox->authority_reduction_applied) return;
      binding.mailbox->authority_reduction_applied = true;
      binding.mailbox->authority_reduced = true;
      for (const auto& entry : binding.mailbox->submissions) {
        if (completionCount < completions.size()) {
          completions[completionCount++] = entry.first;
        }
        markGpuTerminalLocked(*binding.mailbox, entry.first);
      }
      binding.mailbox->submissions.clear();
    } catch (...) {
      (void)markGpuMailboxProtocolViolation(binding.mailbox);
      publishGpuOwnerDrainFallback(binding.mailbox);
      return;
    }
  }
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  gGpuTestAuthorityReductionCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
  auto receipts = takeAllGpuReceipts(binding);
  if (cancelProviderWork) {
    cancelGpuCompletionsOutsideLocks(
        binding, completions.data(), completionCount);
  }
  // Terminal events fan out to as many as kMaxGpuPendingReceipts Promises.
  // Materialize their opaque diagnostic bytes once and attach that same JSI
  // value to every Error. This keeps a maximum-size terminal payload O(bytes +
  // receipts), rather than copying 16 MiB once per receipt.
  auto diagnosticPayload = tryMakeGpuDiagnosticPayload(rt, payload);
  for (auto& entry : receipts) {
    rejectGpuReceipt(
        rt,
        std::move(entry.second),
        kind,
        status,
        entry.first,
        diagnosticPayload,
        message);
  }
  if (std::strcmp(kind, "protocol-violation") == 0 && binding.realm_open &&
      binding.api.close_realm) {
    try {
      (void)binding.api.close_realm(
          binding.api.service_context, binding.realm, 1);
    } catch (...) {
      ex_host_console_log(
          1, "Exact GPU service close_realm threw during protocol quarantine");
    }
    binding.realm_open = false;
  }
}

void drainGpuMailbox(
    ExactGpuClientMailbox* mailbox,
    facebook::jsi::Runtime& rt) noexcept {
  if (!mailbox) return;
  while (true) {
    std::optional<CopiedGpuEvent> event;
    bool protocolViolation = false;
    try {
      std::lock_guard<std::mutex> lock(mailbox->mutex);
      protocolViolation = mailbox->phase.load(std::memory_order_acquire) ==
          GpuMailboxPhase::ProtocolViolation;
      if (protocolViolation) {
        mailbox->events.clear();
        mailbox->queued_payload_bytes = 0;
        mailbox->drain_scheduled = false;
      } else if (!mailbox->events.empty()) {
        mailbox->queued_payload_bytes -=
            mailbox->events.front().payload.size();
        event.emplace(std::move(mailbox->events.front()));
        mailbox->events.pop_front();
      } else {
        mailbox->drain_scheduled = false;
      }
    } catch (...) {
      (void)markGpuMailboxProtocolViolation(mailbox);
      publishGpuOwnerDrainFallback(mailbox);
      return;
    }

    auto* runtime = mailbox->target.runtime;
    if (!runtime || !runtime->gpu_binding ||
        runtime->gpu_binding->mailbox != mailbox) {
      return;
    }
    auto& binding = *runtime->gpu_binding;
    if (protocolViolation) {
      reduceGpuAuthority(
          binding,
          rt,
          "protocol-violation",
          EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION,
          {},
          "Exact GPU provider violated the service event protocol",
          true);
      return;
    }
    if (!event) return;

    if (event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_LOST ||
        event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED) {
      const bool realmClosed =
          event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED;
      reduceGpuAuthority(
          binding,
          rt,
          realmClosed ? "realm-closed" : "device-lost",
          event->status,
          event->payload,
          realmClosed ? "Exact GPU realm closed" : "Exact GPU device lost",
          !realmClosed);
      if (realmClosed) binding.realm_open = false;
      continue;
    }

    bool current = false;
    try {
      {
        std::lock_guard<std::mutex> lock(mailbox->mutex);
        auto iterator = mailbox->submissions.find(event->completion_id);
        if (iterator != mailbox->submissions.end() &&
            iterator->second.event_queued &&
            iterator->second.operation_id == event->operation_id) {
          mailbox->submissions.erase(iterator);
          markGpuTerminalLocked(*mailbox, event->completion_id);
          current = true;
        }
      }
    } catch (...) {
      (void)markGpuMailboxProtocolViolation(mailbox);
      publishGpuOwnerDrainFallback(mailbox);
      return;
    }
    if (!current) continue;

    auto pending = binding.pending_receipts.find(event->completion_id);
    if (pending == binding.pending_receipts.end() ||
        pending->second.operation_id != event->operation_id) {
      continue;
    }
    auto receipt = std::move(pending->second);
    binding.pending_receipts.erase(pending);
    try {
      if (event->kind == EXACT_GPU_SERVICE_EVENT_OPERATION_COMPLETE &&
          event->status == 0) {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
        gGpuTestLastSettlementKind.store(1, std::memory_order_seq_cst);
        gGpuTestLastSettlementStatus.store(
            event->status, std::memory_order_seq_cst);
        gGpuTestResolveCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
        receipt.resolve->call(rt, makeGpuReceipt(rt, std::move(*event)));
      } else {
        auto diagnosticPayload =
            tryMakeGpuDiagnosticPayload(rt, event->payload);
        rejectGpuReceipt(
            rt,
            std::move(receipt),
            event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR
                ? "device-error"
                : "operation-error",
            event->status,
            event->completion_id,
            diagnosticPayload,
            event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR
                ? "Exact GPU device error"
                : "Exact GPU operation failed");
      }
    } catch (...) {
      rejectGpuReceipt(
          rt,
          std::move(receipt),
          "delivery-error",
          -1,
          event->completion_id,
          tryMakeEmptyGpuDiagnosticPayload(rt),
          "Exact GPU receipt delivery failed");
    }
  }
}

bool scheduleGpuMailboxDrain(ExactGpuClientMailbox* mailbox) noexcept {
  if (!mailbox) return false;
  std::shared_ptr<RetainedGpuMailbox> retained;
  try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (gGpuTestDrainFailurePoint.load(std::memory_order_seq_cst) == 1) {
      throw std::bad_alloc();
    }
#endif
    // make_shared allocates its control block before constructing the retain
    // token. Allocation failure therefore cannot leave an unmatched retain or
    // enter the pointer+deleter shared_ptr double-release trap.
    retained = std::make_shared<RetainedGpuMailbox>(mailbox);
  } catch (...) {
    return false;
  }

  bool pinned = false;
  try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (gGpuTestDrainFailurePoint.load(std::memory_order_seq_cst) == 2) {
      throw std::bad_alloc();
    }
#endif
    pinned = exactPinRuntimeNativeWorker(mailbox->target);
  } catch (...) {
    return false;
  }
  if (!pinned) return false;

  bool accepted = false;
  try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (gGpuTestDrainFailurePoint.load(std::memory_order_seq_cst) == 3) {
      throw std::bad_alloc();
    }
#endif
    std::function<void(facebook::jsi::Runtime&)> callback =
        [retained = std::move(retained)](facebook::jsi::Runtime& rt) {
          drainGpuMailbox(retained->mailbox, rt);
        };
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (gGpuTestDrainFailurePoint.load(std::memory_order_seq_cst) == 4) {
      throw std::bad_alloc();
    }
#endif
    pushRuntimeCallback(mailbox->target, std::move(callback), &accepted);
  } catch (...) {
    accepted = false;
  }
  try {
    exactUnpinRuntimeNativeWorker(mailbox->target);
  } catch (...) {
    // This boundary is noexcept because providers may call it from arbitrary
    // native threads. A lock-system exception must not escape the C callback.
  }
  return accepted;
}

GpuMailboxPhase markGpuMailboxProtocolViolation(
    ExactGpuClientMailbox* mailbox) noexcept {
  auto phase = mailbox->phase.load(std::memory_order_acquire);
  while (phase != GpuMailboxPhase::ProtocolViolation &&
         phase != GpuMailboxPhase::Closing &&
         phase != GpuMailboxPhase::Detached) {
    if (mailbox->phase.compare_exchange_weak(
            phase,
            GpuMailboxPhase::ProtocolViolation,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      return GpuMailboxPhase::ProtocolViolation;
    }
  }
  return phase;
}

bool requestGpuMailboxDrain(ExactGpuClientMailbox* mailbox) noexcept {
  bool shouldSchedule = false;
  try {
    std::lock_guard<std::mutex> lock(mailbox->mutex);
    if (!mailbox->drain_scheduled) {
      mailbox->drain_scheduled = true;
      shouldSchedule = true;
    }
  } catch (...) {
    return false;
  }
  if (!shouldSchedule) return true;
  if (scheduleGpuMailboxDrain(mailbox)) return true;
  try {
    std::lock_guard<std::mutex> lock(mailbox->mutex);
    mailbox->drain_scheduled = false;
  } catch (...) {
    // Leaving drain_scheduled set is conservative: later ingress cannot
    // incorrectly claim it published a second ordinary callback. The durable
    // owner flag below independently guarantees progress.
  }
  // Publish the authority reduction before the fallback flag. Otherwise an
  // owner poll could consume the copied event as a normal completion in the
  // narrow interval between failed callback publication and poisoning.
  (void)markGpuMailboxProtocolViolation(mailbox);
  publishGpuOwnerDrainFallback(mailbox);
  return false;
}

void publishGpuOwnerDrainFallback(ExactGpuClientMailbox* mailbox) noexcept {
  if (!mailbox) return;
  // Allocation-free durable state makes a failed callback publication visible
  // to owner-thread polling. Teardown also observes the queued receipts, so no
  // accepted submission can be stranded even if the host wake hook fails.
  mailbox->owner_drain_required.store(true, std::memory_order_release);
  try {
    ex_hermes_notify_callback();
  } catch (...) {
  }
}

int32_t poisonGpuMailbox(ExactGpuClientMailbox* mailbox) noexcept {
  auto phase = markGpuMailboxProtocolViolation(mailbox);
  if (phase == GpuMailboxPhase::Closing ||
      phase == GpuMailboxPhase::Detached) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  if (!mailbox->owner_drain_required.load(std::memory_order_acquire) &&
      !requestGpuMailboxDrain(mailbox)) {
    publishGpuOwnerDrainFallback(mailbox);
  }
  return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
}

bool validGpuEventPrefix(const ExactGpuServiceEventV1* event) {
  return event && event->struct_size >= sizeof(ExactGpuServiceEventV1) &&
      event->abi_version == EXACT_GPU_SERVICE_ABI_VERSION_V1 &&
      event->flags == 0 && event->reserved == 0 &&
      event->kind >= EXACT_GPU_SERVICE_EVENT_OPERATION_COMPLETE &&
      event->kind <= EXACT_GPU_SERVICE_EVENT_REALM_CLOSED &&
      event->payload_len <= kMaxGpuPayloadBytes &&
      (event->payload_len == 0 || event->payload != nullptr);
}

int32_t receiveGpuEventImpl(
    void* context,
    const ExactGpuServiceEventV1* event) {
  if (!context) return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  auto* mailbox = static_cast<ExactGpuClientMailbox*>(context);
  auto phase = mailbox->phase.load(std::memory_order_acquire);
  if (phase == GpuMailboxPhase::Installing) {
    return poisonGpuMailbox(mailbox);
  }
  if (phase == GpuMailboxPhase::ProtocolViolation) {
    if (validGpuEventPrefix(event) && event->completion_id != 0 &&
        (event->kind == EXACT_GPU_SERVICE_EVENT_OPERATION_COMPLETE ||
         event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR)) {
      try {
        std::lock_guard<std::mutex> lock(mailbox->mutex);
        if (isGpuTerminalLocked(*mailbox, event->completion_id)) {
          return EXACT_GPU_CLIENT_EVENT_DISCARDED;
        }
      } catch (...) {
      }
    }
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  // Publishing Activating is the provider-visible admission point. The
  // mailbox is already completely native and synchronized, so callbacks from
  // any provider thread are safe from this point forward. A thread-affinity
  // check would leave an unobservable race between activate_realm returning
  // and Ibex's subsequent Live transition.
  if (phase != GpuMailboxPhase::Live &&
      phase != GpuMailboxPhase::Activating) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  if (!validGpuEventPrefix(event)) return poisonGpuMailbox(mailbox);
  if (!runtimeIsAlive(mailbox->target) ||
      event->realm_token != mailbox->realm.load(std::memory_order_acquire)) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }

  bool malformed = false;
  bool discarded = false;
  try {
    std::lock_guard<std::mutex> lock(mailbox->mutex);
    phase = mailbox->phase.load(std::memory_order_acquire);
    if (phase != GpuMailboxPhase::Live &&
        phase != GpuMailboxPhase::Activating) {
      return phase == GpuMailboxPhase::ProtocolViolation
          ? EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION
          : EXACT_GPU_CLIENT_EVENT_DISCARDED;
    }

    const bool operationEvent =
        event->kind == EXACT_GPU_SERVICE_EVENT_OPERATION_COMPLETE ||
        event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR;
    if (operationEvent) {
      if (event->completion_id == 0 || event->operation_id == 0 ||
          event->operation_id > UINT32_MAX) {
        malformed = true;
      } else {
        auto submission = mailbox->submissions.find(event->completion_id);
        if (submission == mailbox->submissions.end()) {
          if (event->completion_id <= mailbox->highest_completion_id) {
            discarded = true;
          } else {
            malformed = true;
          }
        } else if (submission->second.operation_id != event->operation_id) {
          malformed = true;
        } else if (submission->second.event_queued) {
          discarded = true;
        } else {
          submission->second.event_queued = true;
        }
      }
    } else {
      if (event->operation_id != 0 || event->completion_id != 0) {
        malformed = true;
      } else if (mailbox->terminal_event_queued ||
                 mailbox->authority_reduced) {
        discarded = true;
      } else {
        mailbox->terminal_event_queued = true;
        mailbox->authority_reduced = true;
      }
    }
    if (discarded) return EXACT_GPU_CLIENT_EVENT_DISCARDED;
    if (malformed || mailbox->events.size() >= kMaxGpuQueuedEvents ||
        event->payload_len >
            kMaxGpuPayloadBytes - mailbox->queued_payload_bytes) {
      malformed = true;
    } else {
      CopiedGpuEvent copied;
      copied.kind = event->kind;
      copied.operation_id = static_cast<uint32_t>(event->operation_id);
      copied.completion_id = event->completion_id;
      copied.status = event->status;
      if (event->payload_len > 0) {
        copied.payload.assign(event->payload, event->payload + event->payload_len);
      }
      mailbox->queued_payload_bytes += copied.payload.size();
      mailbox->events.push_back(std::move(copied));
    }
  } catch (...) {
    malformed = true;
  }
  if (malformed) return poisonGpuMailbox(mailbox);
  if (!requestGpuMailboxDrain(mailbox)) {
    // Losing an accepted event would strand its Promise permanently. Treat a
    // drain-publication failure as authority-fatal and make one best-effort
    // protocol-violation drain attempt; teardown remains the final settler if
    // the runtime generation is already closing.
    return poisonGpuMailbox(mailbox);
  }
  mailbox->accepted_events.fetch_add(1, std::memory_order_relaxed);
  return EXACT_GPU_CLIENT_EVENT_ACCEPTED;
}

#if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS) || \
    defined(receiveGpuEvent)
#error "Ibex CapSec GPU callback identifiers must not be preprocessor macros"
#endif

int32_t receiveGpuEvent(
    void* context,
    const ExactGpuServiceEventV1* event) noexcept {
  try {
    return receiveGpuEventImpl(context, event);
  } catch (...) {
    // The service owns this C ABI call stack. Even an unexpected lock-system
    // failure must become durable owner-observable state, never a C++ unwind
    // (or noexcept termination) across the provider boundary.
    if (!context) return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
    auto* mailbox = static_cast<ExactGpuClientMailbox*>(context);
    auto phase = markGpuMailboxProtocolViolation(mailbox);
    if (phase == GpuMailboxPhase::Closing ||
        phase == GpuMailboxPhase::Detached) {
      return EXACT_GPU_CLIENT_EVENT_DISCARDED;
    }
    publishGpuOwnerDrainFallback(mailbox);
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
}

// The value remains the callback expression seen by C++. The structural CapSec
// scanner binds this exact identity macro (definition, direct replacement, and
// undef lifetime) to the versioned table's named ingress field.
#define IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(table_type, field_name, callback) \
  callback
const ExactGpuClientSinkV1 kGpuClientSink = {
    sizeof(ExactGpuClientSinkV1),
    EXACT_GPU_SERVICE_ABI_VERSION_V1,
    retainGpuClient,
    releaseGpuClient,
    IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
        ExactGpuClientSinkV1, on_event, receiveGpuEvent),
};
#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS

facebook::jsi::Object makeGpuPromise(
    facebook::jsi::Runtime& rt,
    const std::shared_ptr<GpuPromiseResolvers>& resolvers) {
  auto promiseConstructor = rt.global().getPropertyAsFunction(rt, "Promise");
  auto executor = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "executor"),
      2,
      [resolvers](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isObject() || !args[1].isObject()) {
          throw facebook::jsi::JSError(rt, "Malformed GPU Promise executor");
        }
        resolvers->resolve = std::make_shared<facebook::jsi::Function>(
            args[0].asObject(rt).asFunction(rt));
        resolvers->reject = std::make_shared<facebook::jsi::Function>(
            args[1].asObject(rt).asFunction(rt));
        return facebook::jsi::Value::undefined();
      });
  auto promise = promiseConstructor.callAsConstructor(rt, executor).getObject(rt);
  if (!resolvers->resolve || !resolvers->reject) {
    throw facebook::jsi::JSError(rt, "GPU Promise executor did not initialize");
  }
  return promise;
}

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value submitGpuBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding || count != 5) {
    throw facebook::jsi::JSError(
        rt,
        "GPU bridge submit requires operationId, deviceOrdinal, queueOrdinal, accountToken, and payload");
  }
  auto& binding = *runtime->gpu_binding;
  uint32_t operation = parseGpuOperationId(rt, args[0]);
  if (binding.allowed_operations.count(operation) == 0) {
    throw facebook::jsi::JSError(rt, "GPU operation is not in the authenticated profile");
  }
  uint64_t device = 0;
  uint64_t queue = 0;
  uint64_t account = 0;
  parseCanonicalGpuUint64(rt, args[1], "deviceOrdinal", true, device);
  parseCanonicalGpuUint64(rt, args[2], "queueOrdinal", true, queue);
  parseCanonicalGpuUint64(rt, args[3], "accountToken", false, account);
  if (account != binding.account) {
    throw facebook::jsi::JSError(rt, "GPU account token does not name this realm account");
  }
  if (!args[4].isObject()) {
    throw facebook::jsi::JSError(rt, "GPU payload must be an ArrayBuffer or view");
  }
  auto payloadObject = args[4].asObject(rt);
  if (!payloadObject.isArrayBuffer(rt)) {
    auto arrayBuffer = rt.global().getPropertyAsObject(rt, "ArrayBuffer");
    auto isView = arrayBuffer.getPropertyAsFunction(rt, "isView");
    auto isViewResult = isView.callWithThis(rt, arrayBuffer, payloadObject);
    if (!isViewResult.isBool() || !isViewResult.getBool()) {
      throw facebook::jsi::JSError(rt, "GPU payload must be an ArrayBuffer or view");
    }
  }
  const uint8_t* payloadData = nullptr;
  size_t payloadLength = 0;
  if (!extractArrayBufferView(rt, payloadObject, payloadData, payloadLength)) {
    throw facebook::jsi::JSError(rt, "GPU payload must be an ArrayBuffer or view");
  }
  if (payloadLength > kMaxGpuPayloadBytes) {
    throw facebook::jsi::JSError(rt, "GPU payload exceeds 16 MiB");
  }
  std::vector<uint8_t> payload;
  if (payloadLength > 0) {
    payload.assign(payloadData, payloadData + payloadLength);
  }

  if (binding.pending_receipts.size() >= kMaxGpuPendingReceipts) {
    throw facebook::jsi::JSError(rt, "GPU pending-receipt budget exhausted");
  }
  if (binding.next_completion_id == 0 ||
      binding.next_completion_id == std::numeric_limits<uint64_t>::max()) {
    throw facebook::jsi::JSError(rt, "GPU completion ID space exhausted");
  }
  const uint64_t completion = binding.next_completion_id;
  auto resolvers = std::make_shared<GpuPromiseResolvers>();
  auto promise = makeGpuPromise(rt, resolvers);

#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  gGpuTestSuccessCarrierReady.store(false, std::memory_order_seq_cst);
  if (gGpuTestResultPublicationFailurePoint.load(std::memory_order_seq_cst) ==
      1) {
    throw std::bad_alloc();
  }
#endif
  // Complete every fallible JSI operation for the accepted result before the
  // completion becomes visible to either native map or the provider. Once
  // submit returns success, returning this already-rooted carrier is a move-only
  // operation and cannot turn an accepted semantic call into a JS exception.
  facebook::jsi::Object successResultObject(rt);
  successResultObject.setProperty(
      rt, "completionId", gpuUint64String(rt, completion));
  successResultObject.setProperty(rt, "admissionStatus", 0);
  successResultObject.setProperty(
      rt, "receipt", facebook::jsi::Value(rt, promise));
  // Convert Object -> Value before admission too. Returning the Value below
  // uses JSI's noexcept Value move constructor and performs no VM operation.
  facebook::jsi::Value successResult(std::move(successResultObject));
  facebook::jsi::Object protocolResultObject(rt);
  protocolResultObject.setProperty(
      rt, "completionId", gpuUint64String(rt, completion));
  protocolResultObject.setProperty(
      rt,
      "admissionStatus",
      static_cast<int32_t>(EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION));
  protocolResultObject.setProperty(
      rt, "receipt", facebook::jsi::Value(rt, promise));
  facebook::jsi::Value protocolResult(std::move(protocolResultObject));
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  gGpuTestSuccessCarrierReady.store(true, std::memory_order_seq_cst);
#endif

  auto [pendingIterator, pendingInserted] = binding.pending_receipts.emplace(
      completion,
      PendingGpuReceipt{operation, resolvers->resolve, resolvers->reject});
  if (!pendingInserted) {
    throw facebook::jsi::JSError(rt, "GPU completion ID is already pending");
  }
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    if (binding.mailbox->phase.load(std::memory_order_acquire) !=
            GpuMailboxPhase::Live ||
        binding.mailbox->authority_reduced ||
        binding.mailbox->submissions.size() >= kMaxGpuPendingReceipts) {
      throw facebook::jsi::JSError(rt, "GPU realm no longer admits submissions");
    }
    auto [submissionIterator, submissionInserted] =
        binding.mailbox->submissions.emplace(
            completion, GpuSubmissionState{operation, false});
    (void)submissionIterator;
    if (!submissionInserted) {
      throw facebook::jsi::JSError(rt, "GPU completion ID is already submitted");
    }
    binding.mailbox->highest_completion_id = completion;
    binding.next_completion_id = completion + 1;
  } catch (...) {
    binding.pending_receipts.erase(pendingIterator);
    throw;
  }

  ExactGpuSemanticCallV1 call = {
      sizeof(ExactGpuSemanticCallV1),
      EXACT_GPU_SERVICE_ABI_VERSION_V1,
      operation,
      0,
      completion,
      device,
      queue,
      account,
      payload.empty() ? nullptr : payload.data(),
      payload.size(),
  };
  auto rollbackSubmission = [&](int32_t status, bool cancelProvider) noexcept {
    try {
      std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
      binding.mailbox->submissions.erase(completion);
      markGpuTerminalLocked(*binding.mailbox, completion);
    } catch (...) {
      (void)markGpuMailboxProtocolViolation(binding.mailbox);
      publishGpuOwnerDrainFallback(binding.mailbox);
    }
    if (cancelProvider) {
      try {
        (void)binding.api.cancel(
            binding.api.service_context, binding.realm, completion);
      } catch (...) {
        ex_host_console_log(
            1, "Exact GPU service cancel threw during submit rollback");
      }
    }
    auto pending = binding.pending_receipts.find(completion);
    if (pending == binding.pending_receipts.end()) return;
    auto receipt = std::move(pending->second);
    binding.pending_receipts.erase(pending);
    rejectGpuReceipt(
        rt,
        std::move(receipt),
        cancelProvider ? "delivery-error" : "admission-rejected",
        status,
        completion,
        tryMakeEmptyGpuDiagnosticPayload(rt),
        cancelProvider
            ? "Exact GPU accepted a call whose result could not be returned"
            : "Exact GPU service rejected the semantic call");
  };
  int32_t admission = -1;
  try {
    // Provider entry is deliberately outside both the mailbox mutex and the
    // owner-thread pending-receipt map mutation. A synchronous on_event call
    // copies into the mailbox and schedules a later drain; it never reenters
    // JSI while submit is on the stack.
    admission = binding.api.submit(
        binding.api.service_context, binding.realm, &call);
  } catch (...) {
    ex_host_console_log(1, "Exact GPU service submit threw across its C ABI");
    admission = -1;
  }

  if (admission == 0) {
    return successResult;
  }

  bool callbackThenRejection = false;
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    auto submission = binding.mailbox->submissions.find(completion);
    if (submission != binding.mailbox->submissions.end() &&
        submission->second.event_queued) {
      callbackThenRejection = true;
      binding.mailbox->authority_reduced = true;
      markGpuTerminalLocked(*binding.mailbox, completion);
      (void)markGpuMailboxProtocolViolation(binding.mailbox);
    }
  } catch (...) {
    // Failing to determine whether provider work escaped a claimed rejection
    // is itself authority-fatal. The poison path publishes an allocation-free
    // owner drain; returning the prebuilt protocol carrier remains non-fallible.
    callbackThenRejection = true;
    (void)poisonGpuMailbox(binding.mailbox);
  }
  if (callbackThenRejection) {
    // The callback proves the provider accepted work despite its return code.
    // Keep the pending receipt/submission for the already-scheduled protocol
    // drain, which cancels work, closes the realm, and rejects exactly once.
    return protocolResult;
  }

  rollbackSubmission(admission, false);
  // No provider work was accepted, so constructing an admission-failure
  // carrier here cannot create an accepted-call/throw ambiguity.
  facebook::jsi::Object failureResult(rt);
  failureResult.setProperty(
      rt, "completionId", gpuUint64String(rt, completion));
  failureResult.setProperty(rt, "admissionStatus", admission);
  failureResult.setProperty(
      rt, "receipt", facebook::jsi::Value(rt, promise));
  return failureResult;
}

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value cancelGpuBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding || count != 1) {
    throw facebook::jsi::JSError(rt, "GPU bridge cancel requires a completion ID");
  }
  auto& binding = *runtime->gpu_binding;
  uint64_t completion = 0;
  parseCanonicalGpuUint64(rt, args[0], "completionId", false, completion);
  auto pending = binding.pending_receipts.find(completion);
  if (pending == binding.pending_receipts.end()) return -1;
  auto receipt = std::move(pending->second);
  binding.pending_receipts.erase(pending);
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    binding.mailbox->submissions.erase(completion);
    markGpuTerminalLocked(*binding.mailbox, completion);
  } catch (...) {
    (void)markGpuMailboxProtocolViolation(binding.mailbox);
    publishGpuOwnerDrainFallback(binding.mailbox);
  }
  int32_t status = -1;
  try {
    status = binding.api.cancel(
        binding.api.service_context, binding.realm, completion);
  } catch (...) {
    ex_host_console_log(1, "Exact GPU service cancel threw across its C ABI");
  }
  rejectGpuReceipt(
      rt,
      std::move(receipt),
      "cancelled",
      status,
      completion,
      tryMakeEmptyGpuDiagnosticPayload(rt),
      "Exact GPU operation was cancelled");
  return status;
}

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value retireGpuBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding || count != 1 ||
      !args[0].isObject() || !args[0].asObject(rt).isArray(rt)) {
    throw facebook::jsi::JSError(
        rt, "GPU bridge retire requires an array of logical-handle strings");
  }
  auto handlesArray = args[0].asObject(rt).asArray(rt);
  size_t handleCount = handlesArray.size(rt);
  if (handleCount == 0 || handleCount > kMaxGpuRetireHandles) {
    throw facebook::jsi::JSError(rt, "GPU retire batch is empty or too large");
  }
  std::vector<uint64_t> handles;
  handles.reserve(handleCount);
  std::unordered_set<uint64_t> unique;
  for (size_t index = 0; index < handleCount; ++index) {
    uint64_t handle = 0;
    auto value = handlesArray.getValueAtIndex(rt, index);
    parseCanonicalGpuUint64(rt, value, "logicalHandle", false, handle);
    if (!unique.insert(handle).second) {
      throw facebook::jsi::JSError(rt, "GPU retire batch contains a duplicate handle");
    }
    handles.push_back(handle);
  }
  ExactGpuRetireBatchV1 batch = {
      sizeof(ExactGpuRetireBatchV1),
      EXACT_GPU_SERVICE_ABI_VERSION_V1,
      handles.data(),
      handles.size(),
  };
  int32_t status = -1;
  try {
    status = runtime->gpu_binding->api.retire(
        runtime->gpu_binding->api.service_context,
        runtime->gpu_binding->realm,
        &batch);
  } catch (...) {
    ex_host_console_log(1, "Exact GPU service retire threw across its C ABI");
  }
  return status;
}

#endif

}  // namespace

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
ExactGpuRuntimeBinding::~ExactGpuRuntimeBinding() {
  detach(nullptr, "Exact GPU runtime binding destroyed");
}

void ExactGpuRuntimeBinding::detach(
    ExactHermesRuntime* runtime,
    const char* reason) noexcept {
  if (detached) return;
  detached = true;
  if (runtime && runtime->runtime && revoke_capture) {
    try {
      revoke_capture->call(*runtime->runtime);
    } catch (...) {
    }
  }
  revoke_capture.reset();
  private_bridge.reset();
  bridge_captured = false;
  if (!closeGpuConstructionCaptureImpl(runtime) && runtime &&
      !runtime->user_execution_started) {
    runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
  }

  std::array<uint64_t, kMaxGpuPendingReceipts> completions{};
  size_t completionCount = 0;
  if (mailbox) {
    mailbox->phase.store(GpuMailboxPhase::Closing, std::memory_order_release);
    try {
      std::lock_guard<std::mutex> lock(mailbox->mutex);
      mailbox->authority_reduced = true;
      for (const auto& entry : mailbox->submissions) {
        if (completionCount < completions.size()) {
          completions[completionCount++] = entry.first;
        }
        markGpuTerminalLocked(*mailbox, entry.first);
      }
      mailbox->submissions.clear();
      mailbox->events.clear();
      mailbox->queued_payload_bytes = 0;
    } catch (...) {
      // Closing is already atomically visible, so provider ingress is fenced.
      // close_realm remains the final backend cancellation even if the
      // best-effort per-completion snapshot cannot acquire its native mutex.
    }
  }
  auto receipts = takeAllGpuReceipts(*this);
  cancelGpuCompletionsOutsideLocks(
      *this, completions.data(), completionCount);
  if (runtime && runtime->runtime) {
    auto& rt = *runtime->runtime;
    auto diagnosticPayload = tryMakeEmptyGpuDiagnosticPayload(rt);
    for (auto& entry : receipts) {
      rejectGpuReceipt(
          rt,
          std::move(entry.second),
          "realm-closed",
          -1,
          entry.first,
          diagnosticPayload,
          reason ? reason : "Exact GPU realm closed");
    }
  }

  if (realm_open && api.close_realm) {
    try {
      (void)api.close_realm(api.service_context, realm, 1);
    } catch (...) {
      ex_host_console_log(1, "Exact GPU service close_realm threw across its C ABI");
    }
    realm_open = false;
  }
  if (mailbox) {
    mailbox->phase.store(GpuMailboxPhase::Detached, std::memory_order_release);
  }
  if (service_retained && api.release_service) {
    try {
      api.release_service(api.service_context);
    } catch (...) {
      ex_host_console_log(1, "Exact GPU service release_service threw across its C ABI");
    }
    service_retained = false;
  }
  if (mailbox) {
    releaseGpuClient(mailbox);
    mailbox = nullptr;
  }
}
#endif

extern "C" uint32_t ex_hermes_gpu_provider_abi_version(void) {
  return EXACT_GPU_SERVICE_ABI_VERSION_V1;
}

extern "C" size_t ex_hermes_gpu_provider_descriptor_size_v1(void) {
  return sizeof(ExactHermesGpuProviderDescriptorV1);
}

extern "C" int32_t ex_hermes_set_gpu_provider_v1(
    ExactHermesRuntime* runtime,
    const ExactHermesGpuProviderDescriptorV1* descriptor) {
  // @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — owner
  // affinity and restricted-runtime refusal precede all provider interaction.
  if (!runtime || !runtime->runtime) return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  if (runtime->runtime_thread != std::this_thread::get_id()) {
    return EXACT_GPU_PROVIDER_WRONG_THREAD;
  }
  if (runtime->restricted) return EXACT_GPU_PROVIDER_RESTRICTED_RUNTIME;
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)descriptor;
  return EXACT_GPU_PROVIDER_UNSUPPORTED;
#else
  if (runtime->embedder_capability_state !=
      EmbedderCapabilityState::Configuring) {
    return EXACT_GPU_PROVIDER_INVALID_STATE;
  }
  if (runtime->gpu_binding || runtime->gpu_binding_v2) {
    return EXACT_GPU_PROVIDER_ALREADY_INSTALLED;
  }
  if (!descriptor) return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  if (descriptor->struct_size < sizeof(ExactHermesGpuProviderDescriptorV1)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  if (descriptor->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V1) {
    return EXACT_GPU_PROVIDER_ABI_MISMATCH;
  }
  if (!descriptor->api) return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  if (descriptor->api->struct_size < sizeof(ExactGpuServiceApiV1)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  if (descriptor->api->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V1) {
    return EXACT_GPU_PROVIDER_ABI_MISMATCH;
  }
  if (descriptor->flags != 0 || descriptor->reserved != 0 ||
      descriptor->topology_id !=
          EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_V1 ||
      !validProfileId(descriptor->profile_id, descriptor->profile_id_len) ||
      !validOperationIds(
          descriptor->sorted_operation_ids, descriptor->operation_id_count) ||
      !validServiceApi(descriptor->api)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }

  if (ex_host_authorize_exact_gpu_provider(
          runtime->host_context_id,
          descriptor->abi_version,
          reinterpret_cast<const uint8_t*>(descriptor->profile_id),
          descriptor->profile_id_len,
          descriptor->profile_digest,
          descriptor->webgpu_c_vocabulary_digest,
          descriptor->operation_set_digest,
          descriptor->semantic_program_digest,
          descriptor->sorted_operation_ids,
          descriptor->operation_id_count,
          descriptor->topology_id) != 1) {
    return EXACT_GPU_PROVIDER_AUTHENTICATION_FAILED;
  }

  std::shared_ptr<ExactGpuRuntimeBinding> binding;
  try {
    binding = std::make_shared<ExactGpuRuntimeBinding>();
    binding->api = *descriptor->api;
    binding->allowed_operations.insert(
        descriptor->sorted_operation_ids,
        descriptor->sorted_operation_ids + descriptor->operation_id_count);
    binding->mailbox =
        new ExactGpuClientMailbox(exactRuntimeCallbackTarget(runtime));
  } catch (...) {
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  try {
    binding->api.retain_service(binding->api.service_context);
    binding->service_retained = true;
  } catch (...) {
    runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }

  // Registration remains provisional: it copies the allowlist/table and owns
  // no JSI property. Realm creation and bridge publication are both deferred to
  // the one-shot transaction finalizer.
  runtime->gpu_binding = std::move(binding);
  return EXACT_GPU_PROVIDER_OK;
#endif
}

int32_t exactGpuActivateInstall(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return EXACT_GPU_PROVIDER_OK;
#else
  if (runtime && runtime->gpu_binding_v2) {
    return exactGpuV2ActivateInstall(runtime);
  }
  if (!runtime || !runtime->gpu_binding) return EXACT_GPU_PROVIDER_OK;
  auto& binding = runtime->gpu_binding;
  if (binding->realm_open) return EXACT_GPU_PROVIDER_OK;

  ExactGpuRealmOpenV1 open = {
      sizeof(ExactGpuRealmOpenV1),
      EXACT_GPU_SERVICE_ABI_VERSION_V1,
      runtime->exact_host_context == 0
          ? static_cast<uint32_t>(EXACT_EMBEDDER_CONTEXT_APP)
          : runtime->exact_host_context,
      0,
      runtime->runtime_nonce,
  };
  int32_t status = EXACT_GPU_PROVIDER_OPEN_FAILED;
  try {
    status = binding->api.open_realm(
        binding->api.service_context,
        &open,
        &kGpuClientSink,
        binding->mailbox,
        &binding->realm,
        &binding->account);
  } catch (...) {
    status = EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  bool activated = false;
  if (status == 0 && binding->realm != 0 && binding->account != 0) {
    binding->mailbox->realm.store(binding->realm, std::memory_order_release);
    auto expected = GpuMailboxPhase::Installing;
    activated = binding->mailbox->phase.compare_exchange_strong(
        expected,
        GpuMailboxPhase::Activating,
        std::memory_order_acq_rel,
        std::memory_order_acquire);
  }
  if (!activated) {
    const bool protocolViolation =
        binding->mailbox->phase.load(std::memory_order_acquire) ==
        GpuMailboxPhase::ProtocolViolation;
    if (binding->realm != 0) binding->realm_open = true;
    return protocolViolation ? EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION
                             : EXACT_GPU_PROVIDER_OPEN_FAILED;
  }

  binding->realm_open = true;
  try {
    binding->api.activate_realm(binding->api.service_context, binding->realm);
  } catch (...) {
    binding->mailbox->phase.store(
        GpuMailboxPhase::ProtocolViolation, std::memory_order_release);
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  uint32_t pauseExpected = 1;
  if (gGpuTestActivationPauseState.compare_exchange_strong(
          pauseExpected, 2, std::memory_order_seq_cst)) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (gGpuTestActivationPauseState.load(std::memory_order_seq_cst) == 2 &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::yield();
    }
    if (gGpuTestActivationPauseState.load(std::memory_order_seq_cst) == 2) {
      gGpuTestActivationPauseState.store(0, std::memory_order_seq_cst);
      binding->mailbox->phase.store(
          GpuMailboxPhase::ProtocolViolation, std::memory_order_release);
      return EXACT_GPU_PROVIDER_OPEN_FAILED;
    }
    gGpuTestActivationPauseState.store(0, std::memory_order_seq_cst);
  }
#endif
  auto expected = GpuMailboxPhase::Activating;
  if (!binding->mailbox->phase.compare_exchange_strong(
          expected,
          GpuMailboxPhase::Live,
          std::memory_order_acq_rel,
          std::memory_order_acquire)) {
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  return EXACT_GPU_PROVIDER_OK;
#endif
}

bool exactGpuPublishPrivateBridge(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return true;
#else
  exactGpuDecodedImageDiscardIfUnusedV1(runtime);
  if (runtime && runtime->gpu_binding_v2) {
    return exactGpuV2PublishPrivateBridge(runtime);
  }
  if (!runtime || !runtime->runtime || !runtime->gpu_binding) return true;
  auto& binding = *runtime->gpu_binding;
  if (binding.bridge_captured) return true;
  if (!binding.realm_open || !binding.mailbox ||
      binding.mailbox->phase.load(std::memory_order_acquire) !=
          GpuMailboxPhase::Live) {
    return false;
  }
#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Object gpuNativeBridge(rt);
    auto submit = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "submit"),
        5,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return submitGpuBridgeCall(runtime, rt, args, count);
        });
    auto cancel = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "cancel"),
        1,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return cancelGpuBridgeCall(runtime, rt, args, count);
        });
    auto retire = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "retire"),
        1,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return retireGpuBridgeCall(runtime, rt, args, count);
        });
    defineGpuProperty(
        rt, gpuNativeBridge, "submit", std::move(submit), false);
    defineGpuProperty(
        rt, gpuNativeBridge, "cancel", std::move(cancel), false);
    defineGpuProperty(
        rt, gpuNativeBridge, "retire", std::move(retire), false);
    defineGpuProperty(
        rt,
        gpuNativeBridge,
        "realmToken",
        gpuUint64String(rt, binding.realm),
        false);
    defineGpuProperty(
        rt,
        gpuNativeBridge,
        "accountToken",
        gpuUint64String(rt, binding.account),
        false);
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "preventExtensions")
        .call(rt, gpuNativeBridge);
    auto captureValue = rt.global().getProperty(rt, kGpuCaptureGlobalName);
    if (!captureValue.isObject() ||
        !captureValue.getObject(rt).isFunction(rt)) {
      return false;
    }
    auto capture = captureValue.getObject(rt).asFunction(rt);
    auto privateGpuNativeBridge =
        std::make_shared<facebook::jsi::Object>(std::move(gpuNativeBridge));
    auto revokeValue = capture.call(rt, *privateGpuNativeBridge);
    if (!closeGpuConstructionCaptureImpl(runtime)) return false;
    if (!revokeValue.isObject() ||
        !revokeValue.getObject(rt).isFunction(rt) ||
        rt.global().hasProperty(rt, kGpuCaptureGlobalName)) {
      return false;
    }
    auto revoke = revokeValue.getObject(rt).asFunction(rt);
    try {
      binding.revoke_capture =
          std::make_shared<facebook::jsi::Function>(std::move(revoke));
    } catch (...) {
      try {
        revokeValue.getObject(rt).asFunction(rt).call(rt);
      } catch (...) {
      }
      throw;
    }
    binding.private_bridge = std::move(privateGpuNativeBridge);
    binding.bridge_captured = true;
    return true;
  } catch (...) {
    closeGpuConstructionCaptureImpl(runtime);
    return false;
  }
#endif
}

bool exactGpuSealPrivateBridge(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  return closeGpuConstructionCaptureImpl(runtime);
#else
  if (!runtime || !runtime->runtime) return false;
  if (runtime->gpu_binding_v2) {
    return exactGpuV2SealPrivateBridge(runtime);
  }
  if (!closeGpuConstructionCaptureImpl(runtime)) return false;
  if (!runtime->gpu_binding) return true;
  auto& binding = *runtime->gpu_binding;
  if (!binding.bridge_captured || !binding.private_bridge ||
      !binding.revoke_capture) {
    return false;
  }
  if (binding.bridge_sealed) return true;
  binding.bridge_sealed = true;
  return true;
#endif
}

bool exactGpuCloseConstructionCapture(ExactHermesRuntime* runtime) {
  return closeGpuConstructionCaptureImpl(runtime);
}

bool exactGpuBindingInstalled(const ExactHermesRuntime* runtime) {
  return runtime &&
      (runtime->gpu_binding != nullptr || runtime->gpu_binding_v2 != nullptr);
}

bool exactGpuOwnerDrainPending(const ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return false;
#else
  const bool v1Pending = runtime && runtime->gpu_binding &&
      runtime->gpu_binding->mailbox &&
      runtime->gpu_binding->mailbox->owner_drain_required.load(
          std::memory_order_acquire);
  return v1Pending || exactGpuV2OwnerDrainPending(runtime);
#endif
}

int exactGpuDrainOwnerFallback(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return 0;
#else
  int drained = exactGpuV2DrainOwnerFallback(runtime);
  if (!runtime || !runtime->runtime || !runtime->gpu_binding ||
      !runtime->gpu_binding->mailbox) {
    return drained;
  }
  auto* mailbox = runtime->gpu_binding->mailbox;
  if (!mailbox->owner_drain_required.exchange(
          false, std::memory_order_acq_rel)) {
    return drained;
  }
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  gGpuTestOwnerFallbackDrainCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
  drainGpuMailbox(mailbox, *runtime->runtime);
  return drained + 1;
#endif
}

void exactGpuRollbackInstall(ExactHermesRuntime* runtime) {
  if (!runtime) return;
  exactGpuDecodedImageRollbackInstallV1(runtime);
  if (runtime->gpu_binding_v2) {
    exactGpuV2RollbackInstall(runtime);
  }
  if (!runtime->gpu_binding) {
    if (!closeGpuConstructionCaptureImpl(runtime)) {
      runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
    }
    return;
  }
  runtime->gpu_binding->detach(runtime, "Exact GPU capability installation rolled back");
  runtime->gpu_binding.reset();
}

void exactGpuBeginRuntimeTeardown(ExactHermesRuntime* runtime) {
  if (!runtime) return;
  exactGpuDecodedImageBeginRuntimeTeardownV1(runtime);
  if (runtime->gpu_binding_v2) {
    exactGpuV2BeginRuntimeTeardown(runtime);
  }
  if (!runtime->gpu_binding) {
    closeGpuConstructionCaptureImpl(runtime);
    return;
  }
  runtime->gpu_binding->detach(runtime, "Exact GPU runtime was destroyed");
  runtime->gpu_binding.reset();
}

#if defined(IBEX_ENABLE_WEBGPU_BINDING) && \
    defined(IBEX_GPU_BRIDGE_TEST_HOOKS)
extern "C" void ibex_test_gpu_reset_bridge_observer(void) {
  gGpuTestResolveCalls.store(0, std::memory_order_seq_cst);
  gGpuTestRejectCalls.store(0, std::memory_order_seq_cst);
  gGpuTestLastSettlementKind.store(0, std::memory_order_seq_cst);
  gGpuTestLastSettlementStatus.store(0, std::memory_order_seq_cst);
  gGpuTestDrainFailurePoint.store(0, std::memory_order_seq_cst);
  gGpuTestOwnerFallbackDrainCalls.store(0, std::memory_order_seq_cst);
  gGpuTestDiagnosticBackingCount.store(0, std::memory_order_seq_cst);
  gGpuTestDiagnosticBackingBytes.store(0, std::memory_order_seq_cst);
  gGpuTestDiagnosticAttachmentCount.store(0, std::memory_order_seq_cst);
  gGpuTestActivationPauseState.store(0, std::memory_order_seq_cst);
  gGpuTestResultPublicationFailurePoint.store(0, std::memory_order_seq_cst);
  gGpuTestSuccessCarrierReady.store(false, std::memory_order_seq_cst);
  gGpuTestAuthorityReductionCalls.store(0, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_set_drain_failure_point(uint32_t point) {
  gGpuTestDrainFailurePoint.store(point, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_pause_after_activate_return(void) {
  gGpuTestActivationPauseState.store(1, std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_activation_pause_state(void) {
  return gGpuTestActivationPauseState.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_resume_after_activate_return(void) {
  gGpuTestActivationPauseState.store(3, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_set_result_publication_failure_point(
    uint32_t point) {
  gGpuTestResultPublicationFailurePoint.store(point, std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_success_carrier_ready(void) {
  return gGpuTestSuccessCarrierReady.load(std::memory_order_seq_cst) ? 1 : 0;
}

extern "C" uint64_t ibex_test_gpu_authority_reduction_calls(void) {
  return gGpuTestAuthorityReductionCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_owner_fallback_drain_calls(void) {
  return gGpuTestOwnerFallbackDrainCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_diagnostic_backing_count(void) {
  return gGpuTestDiagnosticBackingCount.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_diagnostic_backing_bytes(void) {
  return gGpuTestDiagnosticBackingBytes.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_diagnostic_attachment_count(void) {
  return gGpuTestDiagnosticAttachmentCount.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_bridge_resolve_calls(void) {
  return gGpuTestResolveCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_bridge_reject_calls(void) {
  return gGpuTestRejectCalls.load(std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_last_settlement_kind(void) {
  return gGpuTestLastSettlementKind.load(std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_last_settlement_status(void) {
  return gGpuTestLastSettlementStatus.load(std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_private_bridge_present(
    ExactHermesRuntime* runtime) {
  return runtime && runtime->runtime_thread == std::this_thread::get_id() &&
          runtime->gpu_binding && runtime->gpu_binding->private_bridge &&
          runtime->gpu_binding->bridge_captured
      ? 1
      : 0;
}

extern "C" size_t ibex_test_gpu_pending_receipts(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding) {
    return 0;
  }
  return runtime->gpu_binding->pending_receipts.size();
}

extern "C" size_t ibex_test_gpu_mailbox_submissions(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding->mailbox->mutex);
    return runtime->gpu_binding->mailbox->submissions.size();
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_mailbox_events(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding->mailbox->mutex);
    return runtime->gpu_binding->mailbox->events.size();
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_mailbox_payload_bytes(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding->mailbox->mutex);
    return runtime->gpu_binding->mailbox->queued_payload_bytes;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_private_bridge_submit(
    ExactHermesRuntime* runtime,
    uint32_t operation_id,
    const char* device_ordinal,
    const char* queue_ordinal,
    const char* account_token,
    const uint8_t* payload,
    size_t payload_len,
    uint64_t* out_completion_id) {
  if (out_completion_id) *out_completion_id = 0;
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->private_bridge ||
      payload_len > kMaxGpuPayloadBytes ||
      (payload_len > 0 && !payload)) {
    return -1000;
  }
  try {
    auto& rt = *runtime->runtime;
    auto submit = runtime->gpu_binding->private_bridge->getPropertyAsFunction(
        rt, "submit");
    std::vector<uint8_t> payloadCopy;
    if (payload_len > 0) payloadCopy.assign(payload, payload + payload_len);
    auto result = submit.call(
        rt,
        facebook::jsi::Value(static_cast<double>(operation_id)),
        facebook::jsi::String::createFromAscii(
            rt, device_ordinal ? device_ordinal : ""),
        facebook::jsi::String::createFromAscii(
            rt, queue_ordinal ? queue_ordinal : ""),
        facebook::jsi::String::createFromAscii(
            rt, account_token ? account_token : ""),
        makeUint8Array(rt, std::move(payloadCopy)));
    if (!result.isObject()) return -1000;
    auto object = result.getObject(rt);
    auto admission = object.getProperty(rt, "admissionStatus");
    auto completion = object.getProperty(rt, "completionId");
    if (!admission.isNumber() || !completion.isString()) return -1000;
    auto receipt = object.getProperty(rt, "receipt");
    if (receipt.isObject()) {
      auto promise = receipt.getObject(rt);
      auto ignoreRejection = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(rt, "ignoreGpuTestRejection"),
          1,
          [](facebook::jsi::Runtime&,
             const facebook::jsi::Value&,
             const facebook::jsi::Value*,
             size_t) { return facebook::jsi::Value::undefined(); });
      promise.getPropertyAsFunction(rt, "catch")
          .callWithThis(rt, promise, ignoreRejection);
    }
    uint64_t parsedCompletion = 0;
    if (!parseCanonicalGpuUint64(
            rt, completion, "completionId", false, parsedCompletion)) {
      return -1000;
    }
    if (out_completion_id) *out_completion_id = parsedCompletion;
    return static_cast<int32_t>(admission.asNumber());
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_private_bridge_cancel(
    ExactHermesRuntime* runtime,
    const char* completion_id) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->private_bridge) {
    return -1000;
  }
  try {
    auto& rt = *runtime->runtime;
    auto cancel = runtime->gpu_binding->private_bridge->getPropertyAsFunction(
        rt, "cancel");
    auto result = cancel.call(
        rt,
        facebook::jsi::String::createFromAscii(
            rt, completion_id ? completion_id : ""));
    return result.isNumber() ? static_cast<int32_t>(result.asNumber()) : -1000;
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_private_bridge_submit_plain_object(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->private_bridge) {
    return -1000;
  }
  try {
    auto& rt = *runtime->runtime;
    auto submit = runtime->gpu_binding->private_bridge->getPropertyAsFunction(
        rt, "submit");
    facebook::jsi::Object duckTypedPayload(rt);
    auto buffer = rt.global()
                      .getPropertyAsFunction(rt, "ArrayBuffer")
                      .callAsConstructor(rt, 4);
    duckTypedPayload.setProperty(rt, "buffer", std::move(buffer));
    duckTypedPayload.setProperty(rt, "byteOffset", 0);
    duckTypedPayload.setProperty(rt, "byteLength", 4);
    (void)submit.call(
        rt,
        7,
        facebook::jsi::String::createFromAscii(rt, "0"),
        facebook::jsi::String::createFromAscii(rt, "0"),
        facebook::jsi::String::createFromAscii(rt, "42"),
        duckTypedPayload);
    return 0;
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_private_bridge_retire(
    ExactHermesRuntime* runtime,
    const uint64_t* handles,
    size_t handle_count) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding || !runtime->gpu_binding->private_bridge ||
      !handles || handle_count == 0 || handle_count > kMaxGpuRetireHandles) {
    return -1000;
  }
  try {
    auto& rt = *runtime->runtime;
    auto retire = runtime->gpu_binding->private_bridge->getPropertyAsFunction(
        rt, "retire");
    facebook::jsi::Array array(rt, handle_count);
    for (size_t index = 0; index < handle_count; ++index) {
      array.setValueAtIndex(rt, index, gpuUint64String(rt, handles[index]));
    }
    auto result = retire.call(rt, array);
    return result.isNumber() ? static_cast<int32_t>(result.asNumber()) : -1000;
  } catch (...) {
    return -1000;
  }
}
#endif

#if defined(IBEX_GPU_BRIDGE_TEST_HOOKS)
extern "C" int32_t ibex_test_gpu_capture_present(
    ExactHermesRuntime* runtime) noexcept {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id()) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    return rt.global().hasProperty(rt, kGpuCaptureGlobalName) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_install_nonconfigurable_capture(
    ExactHermesRuntime* runtime) noexcept {
  if (!runtime || !runtime->runtime || runtime->user_execution_started ||
      runtime->runtime_thread != std::this_thread::get_id()) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Object descriptor(rt);
    descriptor.setProperty(rt, "value", 17);
    descriptor.setProperty(rt, "writable", false);
    descriptor.setProperty(rt, "enumerable", false);
    descriptor.setProperty(rt, "configurable", false);
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "defineProperty")
        .call(
            rt,
            rt.global(),
            facebook::jsi::String::createFromAscii(
                rt, kGpuCaptureGlobalName),
            descriptor);
    return rt.global().hasProperty(rt, kGpuCaptureGlobalName) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_user_execution_started(
    ExactHermesRuntime* runtime) noexcept {
  return runtime && runtime->runtime_thread == std::this_thread::get_id() &&
          runtime->user_execution_started
      ? 1
      : 0;
}
#endif
