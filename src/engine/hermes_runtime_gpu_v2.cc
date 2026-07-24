// @system @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Additive full-identity Exact GPU carrier. V1 remains implemented in
// hermes_runtime_gpu.cc; this file deliberately publishes no navigator.gpu and
// contains no physical-provider ABI dependency.

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

extern "C" int32_t ex_host_authorize_exact_gpu_provider_v2(
    uint64_t context_id,
    uint32_t abi_version,
    const uint8_t* profile_id,
    size_t profile_id_len,
    const uint8_t* profile_digest,
    const uint8_t* webgpu_c_vocabulary_digest,
    const uint8_t* operation_set_digest,
    const uint8_t* semantic_program_digest,
    const uint8_t* runtime_routing_digest,
    const uint32_t* operation_ids,
    size_t operation_count,
    uint32_t topology_id,
    uint8_t* out_authority_digest);
extern "C" int32_t ex_host_capture_exact_gpu_authority_context_v2(
    uint64_t context_id,
    uint64_t runtime_address,
    uint64_t runtime_nonce,
    uint32_t context_kind,
    uint64_t actor_principal,
    uint64_t effect_owner_principal,
    uint64_t scheduler_principal,
    uint32_t has_scheduler_principal,
    const uint64_t* principals,
    size_t principal_count,
    const ExactGpuAuthoritySessionFactsV2* facts,
    uint8_t* out_digest,
    uint64_t* out_authority_session_id);
extern "C" int32_t ex_host_capture_exact_gpu_presentation_authority_v2(
    uint64_t context_id,
    uint64_t runtime_address,
    uint64_t runtime_nonce,
    uint32_t context_kind,
    uint64_t actor_principal,
    uint64_t effect_owner_principal,
    uint64_t scheduler_principal,
    uint32_t has_scheduler_principal,
    const uint64_t* principals,
    size_t principal_count,
    const ExactGpuAuthoritySessionFactsV2* facts,
    uint8_t* out_digest,
    uint64_t* out_acquire_authority_session_id,
    uint64_t* out_present_authority_session_id);
extern "C" int32_t ex_host_recheck_exact_gpu_presentation_authority_v2(
    uint64_t context_id,
    uint64_t runtime_address,
    uint64_t runtime_nonce,
    uint32_t context_kind,
    uint64_t actor_principal,
    uint64_t effect_owner_principal,
    uint64_t scheduler_principal,
    uint32_t has_scheduler_principal,
    const uint64_t* principals,
    size_t principal_count,
    const ExactGpuAuthoritySessionFactsV2* facts,
    uint64_t retained_acquire_authority_session_id,
    uint64_t retained_present_authority_session_id,
    const uint8_t* retained_authority_context_digest,
    uint8_t* out_recheck_digest);
extern "C" int32_t ex_host_retire_exact_gpu_presentation_authority_v2(
    uint64_t context_id,
    uint64_t acquire_authority_session_id,
    uint64_t present_authority_session_id,
    const uint8_t* authority_context_digest);
extern "C" int32_t ex_host_exact_gpu_authority_session_requested_v2(
    uint64_t context_id,
    uint64_t authority_session_id);
extern "C" int32_t ex_host_force_retire_exact_gpu_authority_session_v2(
    uint64_t context_id,
    uint64_t authority_session_id);
extern "C" const ExactGpuAuthoritySessionApiV2*
ex_host_exact_gpu_authority_session_api_v2(void);

namespace {

bool closeGpuV2ConstructionCapture(ExactHermesRuntime* runtime) noexcept {
  try {
    return exactGpuCloseConstructionCapture(runtime);
  } catch (...) {
    return false;
  }
}

bool nonzeroCanvasReceiptDigestV1(const uint8_t digest[32]) noexcept {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < 32; ++index) aggregate |= digest[index];
  return aggregate != 0;
}

bool zeroCanvasReceiptDigestV1(const uint8_t digest[32]) noexcept {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < 32; ++index) aggregate |= digest[index];
  return aggregate == 0;
}

bool validCanvasAttachmentFailureV1(uint32_t failure) noexcept {
  switch (failure) {
    case EXACT_GPU_CANVAS_ATTACHMENT_STALE_GENERATION_V1:
    case EXACT_GPU_CANVAS_ATTACHMENT_AUTHORITY_DENIED_V1:
    case EXACT_GPU_CANVAS_ATTACHMENT_PROVIDER_LOST_V1:
    case EXACT_GPU_CANVAS_ATTACHMENT_SUPERSEDED_BEFORE_ATTACH_V1:
    case EXACT_GPU_CANVAS_ATTACHMENT_ROOT_GENERATION_CLOSED_V1:
    case EXACT_GPU_CANVAS_ATTACHMENT_INTERNAL_V1:
      return true;
    default:
      return false;
  }
}

bool validCanvasAttachmentReceiptV1(
    const ExactGpuCanvasAttachmentReceiptV1& receipt) noexcept {
  if (receipt.struct_size != sizeof(ExactGpuCanvasAttachmentReceiptV1) ||
      receipt.abi_version !=
          EXACT_GPU_CANVAS_ATTACHMENT_RECEIPT_ABI_VERSION_V1 ||
      receipt.runtime_generation == 0 || receipt.root_instance_id == 0 ||
      receipt.root_generation == 0 || receipt.commit_sequence == 0 ||
      receipt.view_id == 0 || receipt.view_generation == 0 ||
      receipt.handle_id == 0 || receipt.handle_generation == 0 ||
      receipt.attachment_id == 0 || receipt.attachment_generation == 0) {
    return false;
  }
  if (receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1) {
    return receipt.failure == 0 && receipt.context_id != 0 &&
        receipt.context_generation != 0 &&
        receipt.drawing_buffer_width != 0 &&
        receipt.drawing_buffer_height != 0 &&
        nonzeroCanvasReceiptDigestV1(receipt.target_authority_digest) &&
        receipt.surface_account_token != 0 &&
        receipt.surface_account_generation != 0;
  }
  if (receipt.outcome != EXACT_GPU_CANVAS_ATTACHMENT_REJECTED_V1 ||
      !validCanvasAttachmentFailureV1(receipt.failure)) {
    return false;
  }
  return receipt.context_id == 0 && receipt.context_generation == 0 &&
      receipt.drawing_buffer_width == 0 &&
      receipt.drawing_buffer_height == 0 &&
      zeroCanvasReceiptDigestV1(receipt.target_authority_digest) &&
      receipt.surface_account_token == 0 &&
      receipt.surface_account_generation == 0;
}

#if defined(IBEX_ENABLE_WEBGPU_BINDING)

constexpr char kGpuCaptureGlobalNameV2[] = "__ibexCaptureGpuNativeBridge";
constexpr char kGpuCanvasAppBundleCaptureGlobalNameV1[] =
    "__ibexCaptureGpuCanvasRuntimeIntegration";
constexpr size_t kMaxGpuOperationCountV2 = 4096;
constexpr size_t kMaxGpuProfileIdBytesV2 = 256;
constexpr size_t kMaxGpuPayloadBytesV2 = 16 * 1024 * 1024;
constexpr size_t kMaxGpuDiagnosticBytesV2 = 4096;
constexpr size_t kMaxGpuPendingOperationsV2 = 1024;
// One ordinary terminal plus the separately-budgeted sealed-child terminals
// may coexist before the owner drain.
constexpr size_t kMaxGpuQueuedEventsV2 = 2048;
constexpr size_t kMaxGpuRecentTerminalsV2 = 2048;
constexpr size_t kMaxGpuRetireObjectsV2 = 4096;
constexpr size_t kMaxGpuLifecycleTombstonesV2 =
    EXACT_GPU_MAX_LIFECYCLE_TERMINALS_PER_REALM_V2;
constexpr size_t kMaxGpuLifecycleTombstoneBytesV2 = 16 * 1024 * 1024;

enum class GpuMailboxPhaseV2 : uint8_t {
  Installing,
  Activating,
  Live,
  ProtocolViolation,
  Closing,
  Detached,
};

bool equalRuntimeV2(
    const ExactGpuRuntimeIdentityV2& left,
    const ExactGpuRuntimeIdentityV2& right) {
  return left.runtime_address == right.runtime_address &&
      left.runtime_nonce == right.runtime_nonce;
}

bool equalRealmV2(
    const ExactGpuRealmIdentityV2& left,
    const ExactGpuRealmIdentityV2& right) {
  return equalRuntimeV2(left.runtime, right.runtime) &&
      left.realm_id == right.realm_id &&
      left.realm_generation == right.realm_generation;
}

bool equalAccountV2(
    const ExactGpuAccountIdentityV2& left,
    const ExactGpuAccountIdentityV2& right) {
  return left.account_id == right.account_id &&
      left.account_generation == right.account_generation &&
      std::memcmp(
          left.authority_digest,
          right.authority_digest,
          EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2) == 0;
}

bool equalDeviceV2(
    const ExactGpuDeviceIdentityV2& left,
    const ExactGpuDeviceIdentityV2& right) {
  return left.logical_device_id == right.logical_device_id &&
      left.logical_device_generation == right.logical_device_generation &&
      left.provider_generation == right.provider_generation;
}

bool equalObjectV2(
    const ExactGpuObjectRefV2& left,
    const ExactGpuObjectRefV2& right) {
  return left.kind == right.kind && left.flags == right.flags &&
      left.object_id == right.object_id &&
      left.object_generation == right.object_generation;
}

bool nonzeroDigestV2(const uint8_t* digest) {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2;
       ++index) {
    aggregate |= digest[index];
  }
  return aggregate != 0;
}

bool validRealmV2(const ExactGpuRealmIdentityV2& realm) {
  return realm.runtime.runtime_address != 0 && realm.runtime.runtime_nonce != 0 &&
      realm.realm_id != 0 && realm.realm_generation != 0;
}

bool validAccountV2(const ExactGpuAccountIdentityV2& account) {
  return account.account_id != 0 && account.account_generation != 0 &&
      nonzeroDigestV2(account.authority_digest);
}

bool deviceAbsentV2(const ExactGpuDeviceIdentityV2& device) {
  return device.logical_device_id == 0 &&
      device.logical_device_generation == 0 && device.provider_generation == 0;
}

bool validDeviceV2(const ExactGpuDeviceIdentityV2& device) {
  return deviceAbsentV2(device) ||
      (device.logical_device_id != 0 &&
       device.logical_device_generation != 0 &&
       device.provider_generation != 0);
}

bool objectAbsentV2(const ExactGpuObjectRefV2& object) {
  return object.kind == EXACT_GPU_OBJECT_NONE_V2 && object.flags == 0 &&
      object.object_id == 0 && object.object_generation == 0;
}

bool validObjectV2(const ExactGpuObjectRefV2& object, bool allowAbsent) {
  if (objectAbsentV2(object)) return allowAbsent;
  return object.kind >= EXACT_GPU_OBJECT_GPU_V2 &&
      object.kind <= EXACT_GPU_OBJECT_CANVAS_CONTEXT_V2 && object.flags == 0 &&
      object.object_id != 0 && object.object_generation != 0;
}

bool validRedactedGpuDiagnosticV2(
    const uint8_t* bytes,
    size_t byteLength) noexcept {
  size_t index = 0;
  while (index < byteLength) {
    const uint8_t first = bytes[index++];
    uint32_t codePoint = 0;
    uint32_t minimum = 0;
    size_t remaining = 0;
    if (first <= 0x7f) {
      codePoint = first;
    } else if (first >= 0xc2 && first <= 0xdf) {
      codePoint = first & 0x1f;
      minimum = 0x80;
      remaining = 1;
    } else if (first >= 0xe0 && first <= 0xef) {
      codePoint = first & 0x0f;
      minimum = 0x800;
      remaining = 2;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codePoint = first & 0x07;
      minimum = 0x10000;
      remaining = 3;
    } else {
      return false;
    }
    for (size_t part = 0; part < remaining; ++part) {
      if (index >= byteLength) return false;
      const uint8_t continuation = bytes[index++];
      if ((continuation & 0xc0) != 0x80) return false;
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    if (codePoint < minimum || codePoint > 0x10ffff ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
      return false;
    }
    const bool forbiddenControl =
        (codePoint <= 0x1f && codePoint != 0x09 && codePoint != 0x0a &&
         codePoint != 0x0d) ||
        (codePoint >= 0x7f && codePoint <= 0x9f);
    if (forbiddenControl) return false;
  }
  return true;
}

struct CopiedGpuEventV2 {
  ExactGpuServiceEventV2 event{};
  std::vector<uint8_t> payload;
};

struct GpuLifecycleTombstoneV2 {
  uint32_t kind{0};
  uint32_t flags{0};
  ExactGpuServiceEventRecordV2 record{};
  std::vector<uint8_t> payload;
};

struct GpuSubmissionStateV2 {
  ExactGpuSemanticCallV2 call{};
  bool event_queued{false};
  ExactGpuOperationProvenanceV2 queued_terminal_provenance{};
  bool initiating_observed{false};
  ExactGpuOperationProvenanceV2 initiating_provenance{};
};

enum class GpuSealedAuthorityContextSourceV2 : uint8_t {
  CommandProgram,
  EnclosingCarrier,
  StagedRecord,
};

struct ParsedGpuSealedOperationV2 {
  ExactGpuSemanticCallV2 call{};
  bool staged_local{false};
  GpuSealedAuthorityContextSourceV2 authority_context_source{
      GpuSealedAuthorityContextSourceV2::EnclosingCarrier};
};

struct GpuSealedSubmissionStateV2 {
  GpuSubmissionStateV2 submission{};
  uint64_t parent_operation_instance_id{0};
  size_t batch_index{0};
  bool staged_local{false};
};

struct GpuSealedBatchStateV2 {
  std::vector<uint64_t> child_operation_instance_ids;
  size_t next_callback_index{0};
  uint64_t previous_highest_operation_instance_id{0};
};

enum class GpuTerminalCauseV2 : uint8_t {
  None,
  CallbackAccepted,
  CancelWon,
  ServiceRejected,
  Quarantine,
  Teardown,
};

struct ExactGpuClientMailboxV2 {
  explicit ExactGpuClientMailboxV2(RuntimeCallbackTarget target)
      : target(target) {}

  std::atomic<uint32_t> references{1};
  std::atomic<GpuMailboxPhaseV2> phase{GpuMailboxPhaseV2::Installing};
  std::atomic<bool> realm_terminal_accepted{false};
  RuntimeCallbackTarget target;
  std::atomic<bool> owner_drain_required{false};
  std::mutex mutex;
  ExactGpuRealmIdentityV2 realm{};
  std::unordered_set<uint32_t> allowed_operations;
  uint64_t next_service_entry_reservation{1};
  std::unordered_map<uint64_t, uint32_t> service_entry_reservations;
  std::unordered_map<uint64_t, GpuSubmissionStateV2> submissions;
  std::unordered_map<uint64_t, GpuSealedSubmissionStateV2>
      sealed_submissions;
  std::unordered_map<uint64_t, GpuSealedBatchStateV2> sealed_batches;
  std::deque<CopiedGpuEventV2> events;
  size_t queued_payload_bytes{0};
  uint64_t highest_operation_instance_id{0};
  uint64_t highest_sealed_operation_instance_id{0};
  std::array<uint64_t, kMaxGpuRecentTerminalsV2> recent_terminals{};
  std::array<ExactGpuSemanticCallV2, kMaxGpuRecentTerminalsV2>
      recent_terminal_calls{};
  std::array<GpuTerminalCauseV2, kMaxGpuRecentTerminalsV2>
      recent_terminal_causes{};
  std::array<uint32_t, kMaxGpuRecentTerminalsV2>
      recent_terminal_event_kinds{};
  std::array<uint32_t, kMaxGpuRecentTerminalsV2>
      recent_terminal_event_flags{};
  std::array<ExactGpuServiceEventRecordV2, kMaxGpuRecentTerminalsV2>
      recent_terminal_event_records{};
  std::array<std::vector<uint8_t>, kMaxGpuRecentTerminalsV2>
      recent_terminal_event_payloads{};
  std::array<bool, kMaxGpuRecentTerminalsV2>
      recent_terminal_initiating_observed{};
  std::array<ExactGpuOperationProvenanceV2, kMaxGpuRecentTerminalsV2>
      recent_terminal_initiating_provenance{};
  size_t recent_terminal_payload_bytes{0};
  size_t recent_terminal_head{0};
  size_t recent_terminal_count{0};
  // Lifecycle exactly-once history is deliberately bounded. A new distinct
  // terminal beyond either budget is a protocol violation and closes the
  // realm; silently evicting an old key would permit a replay to settle twice.
  std::array<GpuLifecycleTombstoneV2, kMaxGpuLifecycleTombstonesV2>
      lifecycle_tombstones{};
  size_t lifecycle_tombstone_count{0};
  size_t lifecycle_tombstone_payload_bytes{0};
  bool protocol_applied{false};
};

struct PendingGpuReceiptV2 {
  uint32_t operation_id{0};
  uint64_t operation_instance_id{0};
  uint64_t promise_id{0};
  ExactGpuAccountIdentityV2 account{};
  ExactGpuDeviceIdentityV2 device{};
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

bool canRetainGpuPayloadV2(
    const ExactGpuClientMailboxV2& mailbox,
    size_t additionalBytes) noexcept {
  size_t remaining = kMaxGpuPayloadBytesV2;
  if (mailbox.queued_payload_bytes > remaining) return false;
  remaining -= mailbox.queued_payload_bytes;
  if (mailbox.recent_terminal_payload_bytes > remaining) return false;
  remaining -= mailbox.recent_terminal_payload_bytes;
  if (mailbox.lifecycle_tombstone_payload_bytes > remaining) return false;
  remaining -= mailbox.lifecycle_tombstone_payload_bytes;
  return additionalBytes <= remaining;
}

enum class GpuServiceEntryKindV2 : uint32_t {
  Submit = 1,
  Cancel = 2,
  Retire = 3,
};

uint64_t reserveGpuServiceEntryLockedV2(
    ExactGpuClientMailboxV2& mailbox,
    GpuServiceEntryKindV2 kind) {
  if (mailbox.phase.load(std::memory_order_acquire) !=
          GpuMailboxPhaseV2::Live ||
      mailbox.next_service_entry_reservation == 0 ||
      mailbox.next_service_entry_reservation ==
          std::numeric_limits<uint64_t>::max() ||
      mailbox.service_entry_reservations.size() >=
          kMaxGpuPendingOperationsV2) {
    return 0;
  }
  const uint64_t reservation = mailbox.next_service_entry_reservation++;
  if (!mailbox.service_entry_reservations
           .emplace(reservation, static_cast<uint32_t>(kind))
           .second) {
    return 0;
  }
  return reservation;
}

void releaseGpuServiceEntryV2(
    ExactGpuClientMailboxV2& mailbox,
    uint64_t reservation) noexcept {
  if (reservation == 0) return;
  try {
    std::lock_guard<std::mutex> lock(mailbox.mutex);
    mailbox.service_entry_reservations.erase(reservation);
  } catch (...) {
  }
}

struct GpuPromiseResolversV2 {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

void retainGpuClientV2(void* context) {
  if (!context) return;
  static_cast<ExactGpuClientMailboxV2*>(context)->references.fetch_add(
      1, std::memory_order_relaxed);
}

void releaseGpuClientV2(void* context) {
  if (!context) return;
  auto* mailbox = static_cast<ExactGpuClientMailboxV2*>(context);
  if (mailbox->references.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    delete mailbox;
  }
}

bool validProfileIdV2(const char* data, size_t length) {
  if (!data || length == 0 || length > kMaxGpuProfileIdBytesV2) return false;
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

bool validOperationIdsV2(const uint32_t* operations, size_t count) {
  if (!operations || count == 0 || count > kMaxGpuOperationCountV2) {
    return false;
  }
  uint32_t previous = 0;
  for (size_t index = 0; index < count; ++index) {
    if (operations[index] == 0 || (index > 0 && operations[index] <= previous)) {
      return false;
    }
    previous = operations[index];
  }
  return true;
}

bool validServiceApiV2(const ExactGpuServiceApiV2* api) {
  return api && api->struct_size == sizeof(ExactGpuServiceApiV2) &&
      api->abi_version == EXACT_GPU_SERVICE_ABI_VERSION_V2 &&
      api->feature_bits == 0 && api->retain_service && api->release_service &&
      api->open_realm && api->activate_realm && api->submit && api->retire &&
      api->cancel && api->close_realm;
}

int32_t captureGpuAuthorityContextV2(
    ExactHermesRuntime* runtime,
    const ExactGpuSemanticCallV2& call,
    uint8_t outDigest[32],
    uint64_t* outAuthoritySessionId,
    uint64_t* outPresentAuthoritySessionId = nullptr,
    uint64_t retainedAcquireAuthoritySessionId = 0,
    uint64_t retainedPresentAuthoritySessionId = 0,
    const uint8_t* retainedAuthorityContextDigest = nullptr) {
  const bool recheck =
      retainedAcquireAuthoritySessionId != 0 ||
      retainedPresentAuthoritySessionId != 0 ||
      retainedAuthorityContextDigest != nullptr;
  const bool presentationCapture =
      !recheck && outAuthoritySessionId && outPresentAuthoritySessionId;
  const bool operationCapture =
      !recheck && outAuthoritySessionId && !outPresentAuthoritySessionId;
  const bool presentationRecheck =
      recheck && !outAuthoritySessionId && !outPresentAuthoritySessionId &&
      retainedAcquireAuthoritySessionId != 0 &&
      retainedPresentAuthoritySessionId != 0 &&
      retainedAcquireAuthoritySessionId !=
          retainedPresentAuthoritySessionId &&
      retainedAuthorityContextDigest;
  const int32_t captureFailureStatus = presentationRecheck
      ? EXACT_GPU_AUTHORITY_INVALID_V2
      : EXACT_GPU_AUTHORITY_DENIED_V2;
  if (!runtime || !runtime->armed ||
      !runtime->typed_authority_generations_initialized ||
      runtime->runtime_nonce == 0 || call.operation_id == 0 || !outDigest ||
      (!operationCapture && !presentationCapture && !presentationRecheck)) {
    return captureFailureStatus;
  }
  if (outAuthoritySessionId) *outAuthoritySessionId = 0;
  if (outPresentAuthoritySessionId) *outPresentAuthoritySessionId = 0;
  auto collectedPrincipals = exactCollectTypedPrincipalStack();
  const uint64_t actor = currentPrincipalId();
  // These values mirror Hermes' reserved package-domain IDs even when this
  // build lacks the optional frame-attribution patch (and therefore does not
  // declare the helper constants in hermes_runtime_internal.h).
  const uint64_t noUser = static_cast<uint64_t>(UINT32_MAX - 1u);
  const uint64_t runtimeOnly = static_cast<uint64_t>(UINT32_MAX);
  // This checkpoint's digest is deliberately caller attribution rather than
  // the complete positive authority decision. At direct API ingress the actor
  // owns the caller-side effect; the semantic service must later join the
  // operation-selected effect/stage/target/handle facts before admission.
  const uint64_t effectOwner = actor;
  const bool hasScheduler =
      g_native_callback_principal_id != kNoNativePrincipalOverride;
  const uint64_t scheduler = hasScheduler
      ? g_native_callback_principal_id
      : UINT64_C(0);
  const auto invalidPrincipal = [&](uint64_t principal) {
    return principal > UINT32_MAX || principal == noUser ||
        principal == runtimeOnly;
  };
  // The shared collector preserves repeated A -> B -> A live frames on POSIX
  // while Windows already deduplicates globally. Canonicalize locally in
  // innermost-first order so the digest is platform-independent. Inspect the
  // raw collection first: its appended NoUser value is the fail-closed witness
  // that the 256-frame walk truncated and must never be normalized away.
  if (collectedPrincipals.empty() ||
      std::any_of(
          collectedPrincipals.begin(),
          collectedPrincipals.end(),
          invalidPrincipal)) {
    return captureFailureStatus;
  }
  std::vector<uint64_t> principals;
  principals.reserve(collectedPrincipals.size());
  for (uint64_t principal : collectedPrincipals) {
    if (std::find(principals.begin(), principals.end(), principal) ==
        principals.end()) {
      principals.push_back(principal);
    }
  }
  if (principals.empty() || invalidPrincipal(actor) ||
      invalidPrincipal(effectOwner) ||
      (hasScheduler && invalidPrincipal(scheduler)) ||
      principals.front() != actor ||
      std::find(principals.begin(), principals.end(), actor) ==
          principals.end() ||
      (hasScheduler &&
       std::find(principals.begin(), principals.end(), scheduler) ==
           principals.end())) {
    return captureFailureStatus;
  }
  const uint32_t contextKind = runtime->exact_host_context == 0
      ? static_cast<uint32_t>(EXACT_EMBEDDER_CONTEXT_APP)
      : runtime->exact_host_context;
  ExactGpuAuthoritySessionFactsV2 facts{};
  facts.struct_size = sizeof(facts);
  facts.abi_version = EXACT_GPU_SERVICE_ABI_VERSION_V2;
  facts.operation_id = call.operation_id;
  facts.topology_id = call.topology_id;
  facts.realm = call.realm;
  facts.account = call.account;
  facts.ingress_device = call.ingress_device;
  facts.provider_generation = call.provider_generation;
  facts.operation_instance_id = call.operation_instance_id;
  facts.promise_id = call.promise_id;
  facts.captured_scope_id = call.captured_scope_id;
  facts.adapter_ordinal = call.adapter_ordinal;
  facts.device_ingress_ordinal = call.device_ingress_ordinal;
  facts.queue_ingress_ordinal = call.queue_ingress_ordinal;
  facts.receiver = call.receiver;
  facts.target = call.target;
  if (presentationCapture) {
    return ex_host_capture_exact_gpu_presentation_authority_v2(
               runtime->host_context_id,
               static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime)),
               runtime->runtime_nonce,
               contextKind,
               actor,
               effectOwner,
               scheduler,
               hasScheduler ? 1u : 0u,
               principals.data(),
               principals.size(),
               &facts,
               outDigest,
        outAuthoritySessionId,
        outPresentAuthoritySessionId);
  }
  if (presentationRecheck) {
    return ex_host_recheck_exact_gpu_presentation_authority_v2(
               runtime->host_context_id,
               static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime)),
               runtime->runtime_nonce,
               contextKind,
               actor,
               effectOwner,
               scheduler,
               hasScheduler ? 1u : 0u,
               principals.data(),
               principals.size(),
               &facts,
               retainedAcquireAuthoritySessionId,
        retainedPresentAuthoritySessionId,
        retainedAuthorityContextDigest,
        outDigest);
  }
  return ex_host_capture_exact_gpu_authority_context_v2(
             runtime->host_context_id,
             static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime)),
             runtime->runtime_nonce,
             contextKind,
             actor,
             effectOwner,
             scheduler,
             hasScheduler ? 1u : 0u,
             principals.data(),
             principals.size(),
             &facts,
      outDigest,
      outAuthoritySessionId);
}

size_t terminalSlotV2(
    const ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance) {
  if (operationInstance == 0) return kMaxGpuRecentTerminalsV2;
  for (size_t offset = 0; offset < mailbox.recent_terminal_count; ++offset) {
    const size_t slot =
        (mailbox.recent_terminal_head + offset) % kMaxGpuRecentTerminalsV2;
    if (mailbox.recent_terminals[slot] == operationInstance) return slot;
  }
  return kMaxGpuRecentTerminalsV2;
}

bool terminalSeenV2(
    const ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance) {
  return terminalSlotV2(mailbox, operationInstance) !=
      kMaxGpuRecentTerminalsV2;
}

void markTerminalV2(
    ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance,
    const ExactGpuSemanticCallV2* retainedCall,
    GpuTerminalCauseV2 cause,
    const ExactGpuServiceEventV2* terminalEvent,
    const std::vector<uint8_t>* terminalPayload,
    const ExactGpuOperationProvenanceV2* initiatingProvenance = nullptr) {
  if (operationInstance == 0 || terminalSeenV2(mailbox, operationInstance)) {
    return;
  }
  const size_t payloadBytes = terminalPayload ? terminalPayload->size() : 0;
  while (
      mailbox.recent_terminal_count == kMaxGpuRecentTerminalsV2 ||
      (mailbox.recent_terminal_count != 0 &&
       !canRetainGpuPayloadV2(mailbox, payloadBytes))) {
    const size_t oldest = mailbox.recent_terminal_head;
    mailbox.recent_terminal_payload_bytes -=
        mailbox.recent_terminal_event_payloads[oldest].size();
    // `clear()` preserves capacity and would let a provider rotate one large
    // terminal through every ring slot while the logical byte accounting says
    // zero. Swap with an empty vector so eviction releases the backing store.
    std::vector<uint8_t>().swap(
        mailbox.recent_terminal_event_payloads[oldest]);
    mailbox.recent_terminals[oldest] = 0;
    mailbox.recent_terminal_causes[oldest] = GpuTerminalCauseV2::None;
    mailbox.recent_terminal_event_kinds[oldest] = 0;
    mailbox.recent_terminal_event_flags[oldest] = 0;
    mailbox.recent_terminal_initiating_observed[oldest] = false;
    mailbox.recent_terminal_head =
        (mailbox.recent_terminal_head + 1) % kMaxGpuRecentTerminalsV2;
    --mailbox.recent_terminal_count;
  }
  if (!canRetainGpuPayloadV2(mailbox, payloadBytes)) {
    throw std::bad_alloc();
  }
  const size_t slot =
      (mailbox.recent_terminal_head + mailbox.recent_terminal_count) %
      kMaxGpuRecentTerminalsV2;
  mailbox.recent_terminals[slot] = operationInstance;
  mailbox.recent_terminal_calls[slot] = retainedCall
      ? *retainedCall
      : ExactGpuSemanticCallV2{};
  mailbox.recent_terminal_calls[slot].payload = nullptr;
  mailbox.recent_terminal_calls[slot].payload_len = 0;
  mailbox.recent_terminal_causes[slot] = cause;
  if (terminalEvent) {
    mailbox.recent_terminal_event_kinds[slot] = terminalEvent->kind;
    mailbox.recent_terminal_event_flags[slot] = terminalEvent->flags;
    mailbox.recent_terminal_event_records[slot] = terminalEvent->record;
  }
  if (terminalPayload && !terminalPayload->empty()) {
    mailbox.recent_terminal_event_payloads[slot] = *terminalPayload;
    mailbox.recent_terminal_payload_bytes += terminalPayload->size();
  }
  if (initiatingProvenance) {
    mailbox.recent_terminal_initiating_observed[slot] = true;
    mailbox.recent_terminal_initiating_provenance[slot] =
        *initiatingProvenance;
  }
  ++mailbox.recent_terminal_count;
}

const ExactGpuSemanticCallV2* terminalCallV2(
    const ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance) {
  if (operationInstance == 0) return nullptr;
  const size_t slot = terminalSlotV2(mailbox, operationInstance);
  if (slot != kMaxGpuRecentTerminalsV2 &&
      mailbox.recent_terminal_calls[slot].operation_instance_id ==
            operationInstance) {
    return &mailbox.recent_terminal_calls[slot];
  }
  return nullptr;
}

bool equalProvenanceToSubmissionV2(
    const ExactGpuOperationProvenanceV2& event,
    const ExactGpuSemanticCallV2& call) {
  return event.operation_id == call.operation_id &&
      event.topology_id == call.topology_id &&
      equalRealmV2(event.realm, call.realm) &&
      equalAccountV2(event.account, call.account) &&
      equalDeviceV2(event.ingress_device, call.ingress_device) &&
      (call.provider_generation == 0
           ? (event.provider_admission == EXACT_GPU_PROVIDER_NOT_ADMITTED_V2
                  ? event.provider_generation == 0
                  : event.provider_generation != 0)
           : event.provider_generation == call.provider_generation) &&
      event.operation_instance_id == call.operation_instance_id &&
      event.promise_id == call.promise_id &&
      event.captured_scope_id == call.captured_scope_id &&
      event.adapter_ordinal == call.adapter_ordinal &&
      event.device_ingress_ordinal == call.device_ingress_ordinal &&
      event.queue_ingress_ordinal == call.queue_ingress_ordinal &&
      std::memcmp(
          event.authority_context_digest,
          call.authority_context_digest,
          sizeof(call.authority_context_digest)) == 0 &&
      event.authority_session_id == call.authority_session_id &&
      equalObjectV2(event.receiver, call.receiver) &&
      equalObjectV2(event.target, call.target);
}

GpuSubmissionStateV2* pendingOperationStateV2(
    ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance,
    bool* sealedChild = nullptr) {
  auto ordinary = mailbox.submissions.find(operationInstance);
  if (ordinary != mailbox.submissions.end()) {
    if (sealedChild) *sealedChild = false;
    return &ordinary->second;
  }
  auto sealed = mailbox.sealed_submissions.find(operationInstance);
  if (sealed != mailbox.sealed_submissions.end()) {
    if (sealedChild) *sealedChild = true;
    return &sealed->second.submission;
  }
  return nullptr;
}

bool sealedIdentityFallsWithinLiveBatchV2(
    const ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance) {
  for (const auto& entry : mailbox.sealed_batches) {
    const auto& batch = entry.second;
    if (
        !batch.child_operation_instance_ids.empty() &&
        operationInstance >
            batch.previous_highest_operation_instance_id &&
        operationInstance <= batch.child_operation_instance_ids.back()) {
      return true;
    }
  }
  return false;
}

bool emptyOperationProvenanceV2(
    const ExactGpuOperationProvenanceV2& operation) {
  const bool zeroRealm = operation.realm.runtime.runtime_address == 0 &&
      operation.realm.runtime.runtime_nonce == 0 &&
      operation.realm.realm_id == 0 && operation.realm.realm_generation == 0;
  uint8_t accountDigest = 0;
  uint8_t contextDigest = 0;
  for (size_t index = 0; index < 32; ++index) {
    accountDigest |= operation.account.authority_digest[index];
    contextDigest |= operation.authority_context_digest[index];
  }
  return zeroRealm && operation.account.account_id == 0 &&
      operation.account.account_generation == 0 && accountDigest == 0 &&
      deviceAbsentV2(operation.ingress_device) &&
      deviceAbsentV2(operation.result_device) &&
      operation.provider_generation == 0 &&
      operation.topology_id == 0 &&
      operation.operation_id == 0 && operation.operation_instance_id == 0 &&
      operation.promise_id == 0 && operation.provider_admission == 0 &&
      operation.device_transition == 0 && operation.reserved == 0 &&
      operation.reserved2 == 0 && operation.physical_sequence == 0 &&
      operation.captured_scope_id == 0 && operation.adapter_ordinal == 0 &&
      operation.device_ingress_ordinal == 0 &&
      operation.queue_ingress_ordinal == 0 && contextDigest == 0 &&
      operation.authority_session_id == 0 &&
      objectAbsentV2(operation.receiver) && objectAbsentV2(operation.target);
}

bool validOperationProvenanceV2(
    const ExactGpuOperationProvenanceV2& operation) {
  const bool requestDeviceClassAssignment =
      operation.promise_id != 0 &&
      deviceAbsentV2(operation.ingress_device) &&
      !deviceAbsentV2(operation.result_device) &&
      operation.provider_generation != 0 &&
      operation.result_device.provider_generation ==
          operation.provider_generation &&
      operation.captured_scope_id == 0 && operation.adapter_ordinal != 0 &&
      operation.device_ingress_ordinal == 0 &&
      operation.queue_ingress_ordinal == 0 &&
      operation.receiver.kind == EXACT_GPU_OBJECT_ADAPTER_V2 &&
      operation.receiver.flags == 0 && operation.receiver.object_id != 0 &&
      operation.receiver.object_generation != 0 &&
      objectAbsentV2(operation.target);
  return validRealmV2(operation.realm) && validAccountV2(operation.account) &&
      validDeviceV2(operation.ingress_device) &&
      validDeviceV2(operation.result_device) &&
      operation.topology_id ==
          EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_V2 &&
      operation.operation_id != 0 && operation.operation_instance_id != 0 &&
      operation.reserved == 0 && operation.reserved2 == 0 &&
      ((operation.device_transition == EXACT_GPU_DEVICE_UNCHANGED_V2 &&
        equalDeviceV2(operation.ingress_device, operation.result_device)) ||
       (operation.device_transition == EXACT_GPU_DEVICE_ASSIGNED_V2 &&
        requestDeviceClassAssignment &&
        operation.provider_admission == EXACT_GPU_PROVIDER_ADMITTED_V2) ||
       (operation.device_transition ==
            EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2 &&
        requestDeviceClassAssignment)) &&
      ((operation.provider_admission == EXACT_GPU_PROVIDER_NOT_ADMITTED_V2 &&
        operation.physical_sequence == 0) ||
       (operation.provider_admission == EXACT_GPU_PROVIDER_ADMITTED_V2 &&
        operation.provider_generation != 0 &&
        operation.physical_sequence != 0)) &&
      (operation.provider_generation == 0 ||
       deviceAbsentV2(operation.ingress_device) ||
       operation.provider_generation ==
           operation.ingress_device.provider_generation) &&
      (operation.provider_generation == 0 ||
       deviceAbsentV2(operation.result_device) ||
       operation.provider_generation ==
           operation.result_device.provider_generation) &&
      nonzeroDigestV2(operation.authority_context_digest) &&
      operation.authority_session_id != 0 &&
      validObjectV2(operation.receiver, false) &&
      validObjectV2(operation.target, true);
}

bool equalOperationProvenanceRecordV2(
    const ExactGpuOperationProvenanceV2& left,
    const ExactGpuOperationProvenanceV2& right) {
  return equalRealmV2(left.realm, right.realm) &&
      equalAccountV2(left.account, right.account) &&
      equalDeviceV2(left.ingress_device, right.ingress_device) &&
      equalDeviceV2(left.result_device, right.result_device) &&
      left.provider_generation == right.provider_generation &&
      left.topology_id == right.topology_id &&
      left.operation_id == right.operation_id &&
      left.operation_instance_id == right.operation_instance_id &&
      left.promise_id == right.promise_id &&
      left.provider_admission == right.provider_admission &&
      left.device_transition == right.device_transition &&
      left.reserved == right.reserved &&
      left.reserved2 == right.reserved2 &&
      left.physical_sequence == right.physical_sequence &&
      left.captured_scope_id == right.captured_scope_id &&
      left.adapter_ordinal == right.adapter_ordinal &&
      left.device_ingress_ordinal == right.device_ingress_ordinal &&
      left.queue_ingress_ordinal == right.queue_ingress_ordinal &&
      std::memcmp(
          left.authority_context_digest,
          right.authority_context_digest,
          sizeof(left.authority_context_digest)) == 0 &&
      left.authority_session_id == right.authority_session_id &&
      equalObjectV2(left.receiver, right.receiver) &&
      equalObjectV2(left.target, right.target);
}

bool equalOperationTerminalEventV2(
    uint32_t retainedKind,
    uint32_t retainedFlags,
    const ExactGpuServiceEventRecordV2& retainedRecord,
    const std::vector<uint8_t>& retainedPayload,
    const ExactGpuServiceEventV2& incoming) {
  if (retainedKind != incoming.kind || retainedFlags != incoming.flags ||
      retainedPayload.size() != incoming.payload_len ||
      (incoming.payload_len != 0 &&
       std::memcmp(
           retainedPayload.data(), incoming.payload, incoming.payload_len) !=
           0)) {
    return false;
  }
  if (incoming.kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
    const auto& a = retainedRecord.operation_result;
    const auto& b = incoming.record.operation_result;
    return equalOperationProvenanceRecordV2(a.operation, b.operation) &&
        a.result_kind == b.result_kind && a.status == b.status;
  }
  if (incoming.kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2) {
    const auto& a = retainedRecord.device_error;
    const auto& b = incoming.record.device_error;
    return equalOperationProvenanceRecordV2(a.operation, b.operation) &&
        a.error_kind == b.error_kind &&
        a.backend_class == b.backend_class && a.status == b.status &&
        a.reserved == b.reserved;
  }
  return false;
}

bool sameLifecycleKeyV2(
    uint32_t kind,
    const ExactGpuServiceEventRecordV2& left,
    const ExactGpuServiceEventRecordV2& right) {
  switch (kind) {
    case EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2:
      return equalRealmV2(left.provider_loss.realm, right.provider_loss.realm) &&
          equalDeviceV2(left.provider_loss.device, right.provider_loss.device);
    case EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2:
      return equalRealmV2(
                 left.logical_device_lost.realm,
                 right.logical_device_lost.realm) &&
          equalDeviceV2(
              left.logical_device_lost.device,
              right.logical_device_lost.device);
    case EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2:
      return equalRealmV2(
                 left.account_closed.realm, right.account_closed.realm) &&
          equalAccountV2(
              left.account_closed.account, right.account_closed.account);
    case EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2:
      return equalRealmV2(left.realm_closed.realm, right.realm_closed.realm);
    default:
      return false;
  }
}

bool equalLifecycleRecordV2(
    uint32_t kind,
    const ExactGpuServiceEventRecordV2& left,
    const ExactGpuServiceEventRecordV2& right) {
  switch (kind) {
    case EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2: {
      const auto& a = left.provider_loss;
      const auto& b = right.provider_loss;
      return equalRealmV2(a.realm, b.realm) &&
          equalDeviceV2(a.device, b.device) && a.topology_id == b.topology_id &&
          a.backend_class == b.backend_class && a.loss_reason == b.loss_reason &&
          a.has_initiating_operation == b.has_initiating_operation &&
          a.last_accepted_physical_sequence ==
              b.last_accepted_physical_sequence &&
          equalOperationProvenanceRecordV2(
              a.initiating_operation, b.initiating_operation);
    }
    case EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2: {
      const auto& a = left.logical_device_lost;
      const auto& b = right.logical_device_lost;
      return equalRealmV2(a.realm, b.realm) &&
          equalAccountV2(a.account, b.account) &&
          equalDeviceV2(a.device, b.device) && a.topology_id == b.topology_id &&
          a.backend_class == b.backend_class && a.loss_reason == b.loss_reason &&
          a.has_initiating_operation == b.has_initiating_operation &&
          a.logical_loss_ordinal == b.logical_loss_ordinal &&
          a.last_accepted_physical_sequence ==
              b.last_accepted_physical_sequence &&
          equalOperationProvenanceRecordV2(
              a.initiating_operation, b.initiating_operation);
    }
    case EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2: {
      const auto& a = left.account_closed;
      const auto& b = right.account_closed;
      return equalRealmV2(a.realm, b.realm) &&
          equalAccountV2(a.account, b.account) &&
          a.close_ordinal == b.close_ordinal &&
          a.close_reason == b.close_reason && a.reserved == b.reserved;
    }
    case EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2: {
      const auto& a = left.realm_closed;
      const auto& b = right.realm_closed;
      return equalRealmV2(a.realm, b.realm) &&
          a.close_ordinal == b.close_ordinal &&
          a.close_reason == b.close_reason && a.reserved == b.reserved;
    }
    default:
      return false;
  }
}

enum class GpuLifecycleReplayV2 : uint8_t {
  New,
  IdenticalReplay,
  ContradictionOrOverflow,
};

bool isLifecycleEventV2(uint32_t kind) {
  return kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2 ||
      kind == EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2 ||
      kind == EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2 ||
      kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2;
}

bool realmTerminalRememberedV2(const ExactGpuClientMailboxV2& mailbox) {
  for (size_t index = 0; index < mailbox.lifecycle_tombstone_count; ++index) {
    if (mailbox.lifecycle_tombstones[index].kind ==
        EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2) {
      return true;
    }
  }
  return false;
}

GpuLifecycleReplayV2 classifyLifecycleReplayV2(
    const ExactGpuClientMailboxV2& mailbox,
    const ExactGpuServiceEventV2& event) {
  for (size_t index = 0; index < mailbox.lifecycle_tombstone_count; ++index) {
    const auto& retained = mailbox.lifecycle_tombstones[index];
    if (retained.kind != event.kind ||
        !sameLifecycleKeyV2(event.kind, retained.record, event.record)) {
      continue;
    }
    const bool samePayload = retained.payload.size() == event.payload_len &&
        (event.payload_len == 0 ||
         std::memcmp(
             retained.payload.data(), event.payload, event.payload_len) == 0);
    return retained.flags == event.flags &&
            equalLifecycleRecordV2(event.kind, retained.record, event.record) &&
            samePayload
        ? GpuLifecycleReplayV2::IdenticalReplay
        : GpuLifecycleReplayV2::ContradictionOrOverflow;
  }
  return GpuLifecycleReplayV2::New;
}

GpuLifecycleReplayV2 rememberLifecycleEventV2(
    ExactGpuClientMailboxV2& mailbox,
    const ExactGpuServiceEventV2& event) {
  const auto replay = classifyLifecycleReplayV2(mailbox, event);
  if (replay != GpuLifecycleReplayV2::New) return replay;
  if (mailbox.lifecycle_tombstone_count >= kMaxGpuLifecycleTombstonesV2 ||
      event.payload_len > kMaxGpuLifecycleTombstoneBytesV2 -
              mailbox.lifecycle_tombstone_payload_bytes ||
      !canRetainGpuPayloadV2(mailbox, event.payload_len)) {
    return GpuLifecycleReplayV2::ContradictionOrOverflow;
  }
  auto& retained =
      mailbox.lifecycle_tombstones[mailbox.lifecycle_tombstone_count];
  retained.kind = event.kind;
  retained.flags = event.flags;
  retained.record = event.record;
  if (event.payload_len != 0) {
    retained.payload.assign(
        event.payload, event.payload + event.payload_len);
  }
  mailbox.lifecycle_tombstone_payload_bytes += retained.payload.size();
  ++mailbox.lifecycle_tombstone_count;
  return GpuLifecycleReplayV2::New;
}

bool isServiceDetachedAssignedV2(
    const ExactGpuOperationProvenanceV2& operation) {
  return operation.device_transition ==
      EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2;
}

const ExactGpuRealmIdentityV2* eventRealmV2(
    const ExactGpuServiceEventV2& event) {
  switch (event.kind) {
    case EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2:
      return &event.record.operation_result.operation.realm;
    case EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2:
      return &event.record.device_error.operation.realm;
    case EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2:
      return &event.record.provider_loss.realm;
    case EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2:
      return &event.record.logical_device_lost.realm;
    case EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2:
      return &event.record.account_closed.realm;
    case EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2:
      return &event.record.realm_closed.realm;
    default:
      return nullptr;
  }
}

const ExactGpuOperationProvenanceV2* eventOperationV2(
    const ExactGpuServiceEventV2& event) {
  if (event.kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
    return &event.record.operation_result.operation;
  }
  if (event.kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2) {
    return &event.record.device_error.operation;
  }
  return nullptr;
}

const ExactGpuOperationProvenanceV2* operationFromRecordV2(
    uint32_t kind,
    const ExactGpuServiceEventRecordV2& record) {
  if (kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
    return &record.operation_result.operation;
  }
  if (kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2) {
    return &record.device_error.operation;
  }
  return nullptr;
}

const CopiedGpuEventV2* queuedOperationEventV2(
    const ExactGpuClientMailboxV2& mailbox,
    uint64_t operationInstance) {
  for (const auto& queued : mailbox.events) {
    const auto* operation = eventOperationV2(queued.event);
    if (operation && operation->operation_instance_id == operationInstance) {
      return &queued;
    }
  }
  return nullptr;
}

template <typename Visitor>
void forEachObservedPhysicalOperationV2(
    const ExactGpuClientMailboxV2& mailbox,
    Visitor&& visitor) {
  for (const auto& entry : mailbox.submissions) {
    const auto& state = entry.second;
    if (state.event_queued) {
      visitor(state.queued_terminal_provenance);
    } else if (state.initiating_observed) {
      visitor(state.initiating_provenance);
    }
  }
  for (size_t offset = 0; offset < mailbox.recent_terminal_count; ++offset) {
    const size_t slot =
        (mailbox.recent_terminal_head + offset) % kMaxGpuRecentTerminalsV2;
    if (mailbox.recent_terminal_causes[slot] ==
        GpuTerminalCauseV2::CallbackAccepted) {
      if (const auto* operation = operationFromRecordV2(
              mailbox.recent_terminal_event_kinds[slot],
              mailbox.recent_terminal_event_records[slot])) {
        visitor(*operation);
      }
    } else if (mailbox.recent_terminal_initiating_observed[slot]) {
      visitor(mailbox.recent_terminal_initiating_provenance[slot]);
    }
  }
  // Lifecycle tombstones outlive the bounded recent-operation ring. Their
  // full initiating keys therefore remain sequence-ledger evidence until the
  // realm ends; omitting them would permit reuse after operation aging.
  for (size_t index = 0; index < mailbox.lifecycle_tombstone_count; ++index) {
    const auto& retained = mailbox.lifecycle_tombstones[index];
    if (retained.kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2 &&
        retained.record.provider_loss.has_initiating_operation == 1) {
      visitor(retained.record.provider_loss.initiating_operation);
    } else if (
        retained.kind == EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2 &&
        retained.record.logical_device_lost.has_initiating_operation == 1) {
      visitor(retained.record.logical_device_lost.initiating_operation);
    }
  }
}

bool physicalSequenceConflictsV2(
    const ExactGpuClientMailboxV2& mailbox,
    const ExactGpuOperationProvenanceV2& candidate) {
  if (candidate.physical_sequence == 0) return false;
  bool conflict = false;
  forEachObservedPhysicalOperationV2(
      mailbox, [&](const ExactGpuOperationProvenanceV2& observed) {
        if (observed.physical_sequence == candidate.physical_sequence &&
            !equalOperationProvenanceRecordV2(observed, candidate)) {
          conflict = true;
        }
      });
  if (conflict) return true;
  if (candidate.provider_admission != EXACT_GPU_PROVIDER_ADMITTED_V2) {
    return false;
  }
  for (size_t index = 0; index < mailbox.lifecycle_tombstone_count; ++index) {
    const auto& retained = mailbox.lifecycle_tombstones[index];
    if (retained.kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2) {
      const auto& loss = retained.record.provider_loss;
      if (candidate.provider_generation == loss.device.provider_generation &&
          candidate.physical_sequence >
              loss.last_accepted_physical_sequence) {
        return true;
      }
    }
  }
  return false;
}

bool providerLossContradictsObservedV2(
    const ExactGpuClientMailboxV2& mailbox,
    const ExactGpuProviderLossRecordV2& loss) {
  bool conflict = false;
  forEachObservedPhysicalOperationV2(
      mailbox, [&](const ExactGpuOperationProvenanceV2& observed) {
        if (observed.provider_admission == EXACT_GPU_PROVIDER_ADMITTED_V2 &&
            observed.provider_generation == loss.device.provider_generation &&
            observed.physical_sequence >
                loss.last_accepted_physical_sequence) {
          conflict = true;
        }
      });
  return conflict;
}

const ExactGpuOperationProvenanceV2* eventInitiatingOperationV2(
    const ExactGpuServiceEventV2& event) {
  if (event.kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2 &&
      event.record.provider_loss.has_initiating_operation == 1) {
    return &event.record.provider_loss.initiating_operation;
  }
  if (event.kind == EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2 &&
      event.record.logical_device_lost.has_initiating_operation == 1) {
    return &event.record.logical_device_lost.initiating_operation;
  }
  return nullptr;
}

enum class GpuPreliminaryAdmissionV2 : uint8_t {
  Proceed,
  Discard,
  ProtocolViolation,
};

GpuPreliminaryAdmissionV2 preliminaryEventAdmissionV2(
    ExactGpuClientMailboxV2& mailbox,
    const ExactGpuServiceEventV2& event) {
  // Lifecycle tombstones are realm-lifetime replay authority. Consult them
  // before reconciling an initiating operation against the bounded recent
  // operation ring: an exact lifecycle replay remains an exact replay even
  // after its initiating operation ages out of that shorter ring.
  if (isLifecycleEventV2(event.kind)) {
    const auto replay = classifyLifecycleReplayV2(mailbox, event);
    if (replay == GpuLifecycleReplayV2::IdenticalReplay) {
      return GpuPreliminaryAdmissionV2::Discard;
    }
    if (replay == GpuLifecycleReplayV2::ContradictionOrOverflow) {
      return GpuPreliminaryAdmissionV2::ProtocolViolation;
    }
  }

  const auto* initiating = eventInitiatingOperationV2(event);
  if (!initiating) return GpuPreliminaryAdmissionV2::Proceed;
  bool sealedChild = false;
  auto* retainedState = pendingOperationStateV2(
      mailbox, initiating->operation_instance_id, &sealedChild);
  const bool sealedNamespace =
      initiating->operation_instance_id >= (uint64_t{1} << 63);
  // Sealed local pseudo-calls are terminal children of their enclosing
  // carrier. They never acquire independent lifecycle authority, including
  // after their terminal moves into the recent-operation ring.
  if (sealedNamespace && isLifecycleEventV2(event.kind)) {
    return GpuPreliminaryAdmissionV2::ProtocolViolation;
  }
  if ((retainedState && sealedNamespace != sealedChild) ||
      (!sealedNamespace &&
       mailbox.allowed_operations.count(initiating->operation_id) == 0)) {
    return GpuPreliminaryAdmissionV2::ProtocolViolation;
  }
  const uint64_t highWater = sealedNamespace
      ? mailbox.highest_sealed_operation_instance_id
      : mailbox.highest_operation_instance_id;
  if (initiating->operation_instance_id > highWater) {
    return GpuPreliminaryAdmissionV2::ProtocolViolation;
  }

  if (retainedState) {
    auto& state = *retainedState;
    if (!equalProvenanceToSubmissionV2(*initiating, state.call)) {
      return GpuPreliminaryAdmissionV2::ProtocolViolation;
    }
    if (state.event_queued) {
      return equalOperationProvenanceRecordV2(
                 *initiating, state.queued_terminal_provenance)
          ? GpuPreliminaryAdmissionV2::Proceed
          : GpuPreliminaryAdmissionV2::ProtocolViolation;
    }
    if (state.initiating_observed) {
      return equalOperationProvenanceRecordV2(
                 *initiating, state.initiating_provenance)
          ? GpuPreliminaryAdmissionV2::Proceed
          : GpuPreliminaryAdmissionV2::ProtocolViolation;
    }
    state.initiating_observed = true;
    state.initiating_provenance = *initiating;
    return GpuPreliminaryAdmissionV2::Proceed;
  }

  const size_t terminalSlot =
      terminalSlotV2(mailbox, initiating->operation_instance_id);
  if (terminalSlot == kMaxGpuRecentTerminalsV2 ||
      mailbox.recent_terminal_causes[terminalSlot] ==
          GpuTerminalCauseV2::ServiceRejected ||
      !equalProvenanceToSubmissionV2(
          *initiating, mailbox.recent_terminal_calls[terminalSlot])) {
    return GpuPreliminaryAdmissionV2::ProtocolViolation;
  }

  const auto cause = mailbox.recent_terminal_causes[terminalSlot];
  const ExactGpuOperationProvenanceV2* observed = nullptr;
  if (cause == GpuTerminalCauseV2::CallbackAccepted) {
    observed = operationFromRecordV2(
        mailbox.recent_terminal_event_kinds[terminalSlot],
        mailbox.recent_terminal_event_records[terminalSlot]);
  } else if (mailbox.recent_terminal_initiating_observed[terminalSlot]) {
    observed = &mailbox.recent_terminal_initiating_provenance[terminalSlot];
  }
  if (observed) {
    return equalOperationProvenanceRecordV2(*initiating, *observed)
        ? GpuPreliminaryAdmissionV2::Proceed
        : GpuPreliminaryAdmissionV2::ProtocolViolation;
  }
  if (cause == GpuTerminalCauseV2::CancelWon) {
    mailbox.recent_terminal_initiating_observed[terminalSlot] = true;
    mailbox.recent_terminal_initiating_provenance[terminalSlot] = *initiating;
    return GpuPreliminaryAdmissionV2::Proceed;
  }
  return GpuPreliminaryAdmissionV2::ProtocolViolation;
}

bool validEventPrefixV2(const ExactGpuServiceEventV2* event) {
  if (!event || event->struct_size != sizeof(ExactGpuServiceEventV2) ||
      event->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V2 ||
      event->reserved != 0 ||
      event->kind < EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2 ||
      event->kind > EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2 ||
      event->payload_len > kMaxGpuPayloadBytesV2 ||
      (event->payload_len != 0 && event->payload == nullptr)) {
    return false;
  }
  const bool flagsValid =
      event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2
      ? (event->flags == EXACT_GPU_SERVICE_EVENT_FLAG_NONE_V2 ||
         event->flags ==
             EXACT_GPU_SERVICE_EVENT_FLAG_UNCAPTURED_ERROR_V2)
      : event->flags == EXACT_GPU_SERVICE_EVENT_FLAG_NONE_V2;
  if (!flagsValid) return false;
  switch (event->kind) {
    case EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2: {
      const auto& record = event->record.operation_result;
      const bool payloadShapeValid =
          ((record.result_kind == EXACT_GPU_RESULT_NONE_V2 ||
            record.result_kind == EXACT_GPU_RESULT_UNDEFINED_V2 ||
            record.result_kind == EXACT_GPU_RESULT_NULL_V2) &&
           event->payload_len == 0) ||
          (record.result_kind == EXACT_GPU_RESULT_OBJECT_V2 &&
           event->payload_len != 0) ||
          record.result_kind == EXACT_GPU_RESULT_BYTES_V2;
      return event->record_size == sizeof(record) &&
          validOperationProvenanceV2(record.operation) &&
          record.result_kind >= EXACT_GPU_RESULT_NONE_V2 &&
          record.result_kind <= EXACT_GPU_RESULT_BYTES_V2 &&
          payloadShapeValid &&
          ((record.operation.device_transition !=
                EXACT_GPU_DEVICE_ASSIGNED_V2 &&
            record.operation.device_transition !=
                EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2) ||
           record.result_kind == EXACT_GPU_RESULT_OBJECT_V2) &&
          record.status == 0;
    }
    case EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2: {
      const auto& record = event->record.device_error;
      const bool uncaptured =
          event->flags ==
          EXACT_GPU_SERVICE_EVENT_FLAG_UNCAPTURED_ERROR_V2;
      return event->record_size == sizeof(record) && record.reserved == 0 &&
          (!uncaptured ||
           (event->payload_len <= kMaxGpuDiagnosticBytesV2 &&
            validRedactedGpuDiagnosticV2(
                event->payload, event->payload_len) &&
            !deviceAbsentV2(record.operation.result_device) &&
            record.error_kind >= EXACT_GPU_ERROR_VALIDATION_V2 &&
            record.error_kind <= EXACT_GPU_ERROR_INTERNAL_V2)) &&
          validOperationProvenanceV2(record.operation) &&
          record.operation.device_transition ==
              EXACT_GPU_DEVICE_UNCHANGED_V2 &&
          record.error_kind >= EXACT_GPU_ERROR_VALIDATION_V2 &&
          record.error_kind <= EXACT_GPU_ERROR_INVALID_STATE_V2 &&
          record.status != 0 &&
          ((record.operation.provider_admission ==
                EXACT_GPU_PROVIDER_NOT_ADMITTED_V2 &&
            record.backend_class == EXACT_GPU_BACKEND_NONE_V2) ||
           (record.operation.provider_admission ==
                EXACT_GPU_PROVIDER_ADMITTED_V2 &&
            record.backend_class >= EXACT_GPU_BACKEND_VALIDATION_V2 &&
            record.backend_class <= EXACT_GPU_BACKEND_PROVIDER_FAILURE_V2));
    }
    case EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2: {
      const auto& record = event->record.provider_loss;
      if (event->record_size != sizeof(record) || !validRealmV2(record.realm) ||
          deviceAbsentV2(record.device) || !validDeviceV2(record.device) ||
          record.topology_id !=
              EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_V2 ||
          record.backend_class < EXACT_GPU_BACKEND_DEVICE_REMOVED_V2 ||
          record.backend_class > EXACT_GPU_BACKEND_PROVIDER_FAILURE_V2 ||
          !(record.loss_reason == EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2 ||
            record.loss_reason == EXACT_GPU_DEVICE_LOSS_PHYSICAL_DEVICE_V2 ||
            record.loss_reason == EXACT_GPU_DEVICE_LOSS_PROVIDER_RESTART_V2) ||
          (record.loss_reason == EXACT_GPU_DEVICE_LOSS_PHYSICAL_DEVICE_V2 &&
           record.backend_class != EXACT_GPU_BACKEND_DEVICE_REMOVED_V2) ||
          (record.loss_reason == EXACT_GPU_DEVICE_LOSS_PROVIDER_RESTART_V2 &&
           record.backend_class != EXACT_GPU_BACKEND_PROVIDER_FAILURE_V2) ||
          record.has_initiating_operation > 1) {
        return false;
      }
      if (record.has_initiating_operation == 0) {
        return emptyOperationProvenanceV2(record.initiating_operation);
      }
      return validOperationProvenanceV2(record.initiating_operation) &&
          record.initiating_operation.provider_admission ==
              EXACT_GPU_PROVIDER_ADMITTED_V2 &&
          equalRealmV2(record.initiating_operation.realm, record.realm) &&
          equalDeviceV2(
              record.initiating_operation.result_device, record.device) &&
          record.initiating_operation.topology_id == record.topology_id &&
          record.initiating_operation.physical_sequence <=
              record.last_accepted_physical_sequence;
    }
    case EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2: {
      const auto& record = event->record.logical_device_lost;
      if (event->record_size != sizeof(record) || !validRealmV2(record.realm) ||
          !validAccountV2(record.account) || deviceAbsentV2(record.device) ||
          !validDeviceV2(record.device) ||
          record.topology_id !=
              EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_V2 ||
          record.backend_class > EXACT_GPU_BACKEND_PROVIDER_FAILURE_V2 ||
          record.loss_reason < EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2 ||
          record.loss_reason > EXACT_GPU_DEVICE_LOSS_ACCOUNT_CLOSED_V2 ||
          ((record.loss_reason == EXACT_GPU_DEVICE_LOSS_DESTROYED_V2 ||
            record.loss_reason == EXACT_GPU_DEVICE_LOSS_ACCOUNT_CLOSED_V2) &&
           record.backend_class != EXACT_GPU_BACKEND_NONE_V2) ||
          (record.loss_reason == EXACT_GPU_DEVICE_LOSS_PHYSICAL_DEVICE_V2 &&
           record.backend_class != EXACT_GPU_BACKEND_DEVICE_REMOVED_V2) ||
          (record.loss_reason == EXACT_GPU_DEVICE_LOSS_PROVIDER_RESTART_V2 &&
           record.backend_class != EXACT_GPU_BACKEND_PROVIDER_FAILURE_V2) ||
          record.has_initiating_operation > 1 ||
          record.logical_loss_ordinal == 0) {
        return false;
      }
      if (record.has_initiating_operation == 0) {
        return emptyOperationProvenanceV2(record.initiating_operation);
      }
      const bool serviceDetachedAssigned =
          isServiceDetachedAssignedV2(record.initiating_operation);
      return validOperationProvenanceV2(record.initiating_operation) &&
          !serviceDetachedAssigned &&
          equalRealmV2(record.initiating_operation.realm, record.realm) &&
          equalAccountV2(record.initiating_operation.account, record.account) &&
          equalDeviceV2(
              record.initiating_operation.result_device, record.device) &&
          record.initiating_operation.topology_id == record.topology_id &&
          (record.initiating_operation.physical_sequence == 0 ||
           record.initiating_operation.physical_sequence <=
               record.last_accepted_physical_sequence);
    }
    case EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2: {
      const auto& record = event->record.account_closed;
      return event->record_size == sizeof(record) && record.reserved == 0 &&
          validRealmV2(record.realm) && validAccountV2(record.account) &&
          record.close_ordinal != 0 &&
          record.close_reason >= EXACT_GPU_CLOSE_EXPLICIT_V2 &&
          record.close_reason <= EXACT_GPU_CLOSE_PROVIDER_FAILURE_V2;
    }
    case EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2: {
      const auto& record = event->record.realm_closed;
      return event->record_size == sizeof(record) && record.reserved == 0 &&
          validRealmV2(record.realm) && record.close_ordinal != 0 &&
          record.close_reason >= EXACT_GPU_CLOSE_EXPLICIT_V2 &&
          record.close_reason <= EXACT_GPU_CLOSE_PROVIDER_FAILURE_V2;
    }
    default:
      return false;
  }
}

#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
std::atomic<uint32_t> gGpuV2RealmCloseAdmissionPauseState{0};
std::atomic<uint32_t> gGpuV2DetachLockAttempted{0};
std::atomic<uint32_t> gGpuV2DetachCleanupPauseState{0};
#endif

GpuMailboxPhaseV2 poisonGpuMailboxV2(
    ExactGpuClientMailboxV2* mailbox) noexcept {
  auto phase = mailbox->phase.load(std::memory_order_acquire);
  while (phase != GpuMailboxPhaseV2::ProtocolViolation &&
         phase != GpuMailboxPhaseV2::Closing &&
         phase != GpuMailboxPhaseV2::Detached) {
    if (mailbox->phase.compare_exchange_weak(
            phase,
            GpuMailboxPhaseV2::ProtocolViolation,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      break;
    }
  }
  mailbox->owner_drain_required.store(true, std::memory_order_release);
  try {
    ex_hermes_notify_callback();
  } catch (...) {
  }
  return mailbox->phase.load(std::memory_order_acquire);
}

void quarantineAcceptedRealmCloseV2(ExactGpuClientMailboxV2* mailbox) noexcept {
  auto expected = GpuMailboxPhaseV2::Closing;
  (void)mailbox->phase.compare_exchange_strong(
      expected,
      GpuMailboxPhaseV2::ProtocolViolation,
      std::memory_order_acq_rel,
      std::memory_order_acquire);
  mailbox->owner_drain_required.store(true, std::memory_order_release);
  try {
    ex_hermes_notify_callback();
  } catch (...) {
  }
}

bool pauseRealmCloseAdmissionForTest() noexcept {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  uint32_t expected = 1;
  if (!gGpuV2RealmCloseAdmissionPauseState.compare_exchange_strong(
          expected, 2, std::memory_order_seq_cst)) {
    return true;
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (gGpuV2RealmCloseAdmissionPauseState.load(std::memory_order_seq_cst) ==
             2 &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
  const bool resumed = gGpuV2RealmCloseAdmissionPauseState.load(
                           std::memory_order_seq_cst) == 3;
  gGpuV2RealmCloseAdmissionPauseState.store(0, std::memory_order_seq_cst);
  return resumed;
#else
  return true;
#endif
}

int32_t receiveGpuEventV2Impl(
    void* context,
    const ExactGpuServiceEventV2* event) {
  if (!context) return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  auto* mailbox = static_cast<ExactGpuClientMailboxV2*>(context);
  auto phase = mailbox->phase.load(std::memory_order_acquire);
  if (phase == GpuMailboxPhaseV2::Installing) {
    (void)poisonGpuMailboxV2(mailbox);
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  if (phase == GpuMailboxPhaseV2::ProtocolViolation) {
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  const bool acceptedClosePhase =
      phase == GpuMailboxPhaseV2::Closing &&
      mailbox->realm_terminal_accepted.load(std::memory_order_acquire);
  if (phase != GpuMailboxPhaseV2::Activating &&
      phase != GpuMailboxPhaseV2::Live && !acceptedClosePhase) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  if (!validEventPrefixV2(event)) {
    if (acceptedClosePhase) {
      quarantineAcceptedRealmCloseV2(mailbox);
    } else {
      (void)poisonGpuMailboxV2(mailbox);
    }
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  const bool closingRealmReplay = acceptedClosePhase &&
      event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2;
  if (acceptedClosePhase && !closingRealmReplay) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  const auto* eventRealm = eventRealmV2(*event);
  if (!eventRealm || !runtimeIsAlive(mailbox->target)) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  if (!equalRealmV2(*eventRealm, mailbox->realm)) {
    // While this retained sink is live, a different realm is a provider
    // misroute, not a stale callback. Silent discard could strand the real
    // realm's receipts, so quarantine the binding on the owner drain.
    if (closingRealmReplay) {
      quarantineAcceptedRealmCloseV2(mailbox);
    } else {
      (void)poisonGpuMailboxV2(mailbox);
    }
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }

  bool malformed = false;
  bool discarded = false;
  try {
    std::lock_guard<std::mutex> lock(mailbox->mutex);
    phase = mailbox->phase.load(std::memory_order_acquire);
    const bool lockedClosingRealmReplay =
        phase == GpuMailboxPhaseV2::Closing &&
        mailbox->realm_terminal_accepted.load(std::memory_order_acquire) &&
        event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2;
    if (phase != GpuMailboxPhaseV2::Activating &&
        phase != GpuMailboxPhaseV2::Live && !lockedClosingRealmReplay) {
      return phase == GpuMailboxPhaseV2::ProtocolViolation
          ? EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION
          : EXACT_GPU_CLIENT_EVENT_DISCARDED;
    }

    if (event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2 &&
        !pauseRealmCloseAdmissionForTest()) {
      malformed = true;
    }
    if (!malformed) {
      const auto preliminary = preliminaryEventAdmissionV2(*mailbox, *event);
      if (preliminary == GpuPreliminaryAdmissionV2::Discard) {
        return EXACT_GPU_CLIENT_EVENT_DISCARDED;
      }
      malformed =
          preliminary == GpuPreliminaryAdmissionV2::ProtocolViolation;
    }

    if (!malformed) {
      if (const auto* initiating = eventInitiatingOperationV2(*event)) {
        malformed = physicalSequenceConflictsV2(*mailbox, *initiating);
      }
    }
    if (!malformed) {
      if (const auto* operation = eventOperationV2(*event)) {
        // ASSIGNED_DETACHED is a self-contained operation terminal for a fresh
        // service-detached already-lost device, preserving either admission
        // relation. It intentionally does not consume realm-lifetime lifecycle
        // replay authority. Attached device loss still arrives through the
        // typed lifecycle path below.
        malformed = physicalSequenceConflictsV2(*mailbox, *operation);
      } else if (event->kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2) {
        malformed = providerLossContradictsObservedV2(
            *mailbox, event->record.provider_loss);
      }
    }

    if (malformed) {
      // Skip variant bookkeeping and quarantine after releasing the mutex.
    } else if (
        realmTerminalRememberedV2(*mailbox) &&
        event->kind != EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2) {
      // Once the realm terminal is accepted, later records cannot mutate that
      // realm. They are stale delivery rather than a second settlement.
      discarded = true;
    } else if (const auto* operation = eventOperationV2(*event)) {
      auto ordinary =
          mailbox->submissions.find(operation->operation_instance_id);
      auto sealed =
          mailbox->sealed_submissions.find(operation->operation_instance_id);
      GpuSubmissionStateV2* submission = nullptr;
      if (ordinary != mailbox->submissions.end()) {
        submission = &ordinary->second;
      } else if (sealed != mailbox->sealed_submissions.end()) {
        submission = &sealed->second.submission;
      }
      if (!submission) {
        const size_t terminalSlot =
            terminalSlotV2(*mailbox, operation->operation_instance_id);
        if (terminalSlot != kMaxGpuRecentTerminalsV2) {
          const auto& call = mailbox->recent_terminal_calls[terminalSlot];
          const auto cause = mailbox->recent_terminal_causes[terminalSlot];
          if (!equalProvenanceToSubmissionV2(*operation, call) ||
              cause == GpuTerminalCauseV2::ServiceRejected ||
              (mailbox->recent_terminal_initiating_observed[terminalSlot] &&
               !equalOperationProvenanceRecordV2(
                   *operation,
                   mailbox->recent_terminal_initiating_provenance
                       [terminalSlot]))) {
            // A service-rejected call was never owned by the service; any
            // later callback contradicts the submit return. Other retained
            // terminals must still carry the exact authenticated full key.
            malformed = true;
          } else if (cause == GpuTerminalCauseV2::CallbackAccepted) {
            const bool exactReplay = equalOperationTerminalEventV2(
                mailbox->recent_terminal_event_kinds[terminalSlot],
                mailbox->recent_terminal_event_flags[terminalSlot],
                mailbox->recent_terminal_event_records[terminalSlot],
                mailbox->recent_terminal_event_payloads[terminalSlot],
                *event);
            discarded = exactReplay;
            malformed = !exactReplay;
          } else {
            // Cancellation won before provider delivery; a late terminal with
            // the exact retained key is an allowed stale callback.
            discarded = true;
          }
        } else {
          // Full-key tombstones are retained under explicit count/byte
          // budgets. Once an older instance ages out, a callback at or below
          // the monotonic high-water mark is stale and cannot be re-associated
          // with a newer operation; future IDs remain a protocol violation.
          const bool sealedNamespace =
              operation->operation_instance_id >= (uint64_t{1} << 63);
          const bool liveSealedBatchGap =
              sealedNamespace &&
              sealedIdentityFallsWithinLiveBatchV2(
                  *mailbox, operation->operation_instance_id);
          discarded =
              !liveSealedBatchGap &&
              operation->operation_instance_id <=
                  (sealedNamespace
                       ? mailbox->highest_sealed_operation_instance_id
                       : mailbox->highest_operation_instance_id);
          malformed = !discarded;
        }
      } else if (!equalProvenanceToSubmissionV2(
                     *operation, submission->call)) {
        malformed = true;
      } else if (
          submission->initiating_observed &&
          !equalOperationProvenanceRecordV2(
              *operation, submission->initiating_provenance)) {
        malformed = true;
      } else if (submission->event_queued) {
        const auto* queued = queuedOperationEventV2(
            *mailbox, operation->operation_instance_id);
        const bool exactReplay = queued && equalOperationTerminalEventV2(
            queued->event.kind,
            queued->event.flags,
            queued->event.record,
            queued->payload,
            *event);
        discarded = exactReplay;
        malformed = !exactReplay;
      } else {
        if (sealed != mailbox->sealed_submissions.end()) {
          auto batch = mailbox->sealed_batches.find(
              sealed->second.parent_operation_instance_id);
          const bool successTerminal =
              event->kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2 &&
              event->flags == EXACT_GPU_SERVICE_EVENT_FLAG_NONE_V2 &&
              event->record.operation_result.result_kind ==
                  EXACT_GPU_RESULT_NONE_V2 &&
              event->record.operation_result.status == 0 &&
              event->payload_len == 0;
          const bool errorTerminal =
              event->kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2 &&
              event->record.device_error.status != 0 &&
              event->record.device_error.error_kind >=
                  EXACT_GPU_ERROR_VALIDATION_V2 &&
              event->record.device_error.error_kind <=
                  EXACT_GPU_ERROR_INTERNAL_V2 &&
              event->payload_len <= kMaxGpuDiagnosticBytesV2 &&
              validRedactedGpuDiagnosticV2(
                  event->payload, event->payload_len);
          if (
              batch == mailbox->sealed_batches.end() ||
              batch->second.next_callback_index !=
                  sealed->second.batch_index ||
              sealed->second.batch_index >=
                  batch->second.child_operation_instance_ids.size() ||
              batch->second.child_operation_instance_ids
                      [sealed->second.batch_index] !=
                  operation->operation_instance_id ||
              operation->provider_admission !=
                  EXACT_GPU_PROVIDER_NOT_ADMITTED_V2 ||
              operation->physical_sequence != 0 ||
              (!successTerminal && !errorTerminal) ||
              (errorTerminal &&
               event->record.device_error.backend_class != 0)) {
            malformed = true;
          } else {
            ++batch->second.next_callback_index;
          }
        } else {
          auto batch =
              mailbox->sealed_batches.find(operation->operation_instance_id);
          if (
              batch != mailbox->sealed_batches.end() &&
              batch->second.next_callback_index !=
                  batch->second.child_operation_instance_ids.size()) {
            malformed = true;
          }
        }
        if (!malformed) {
          submission->event_queued = true;
          submission->queued_terminal_provenance = *operation;
        }
      }
    } else if (isLifecycleEventV2(event->kind)) {
      const auto replay = rememberLifecycleEventV2(*mailbox, *event);
      discarded = replay == GpuLifecycleReplayV2::IdenticalReplay;
      malformed = replay == GpuLifecycleReplayV2::ContradictionOrOverflow;
    } else {
      malformed = true;
    }
    if (discarded) return EXACT_GPU_CLIENT_EVENT_DISCARDED;
    if (!malformed &&
        (mailbox->events.size() >= kMaxGpuQueuedEventsV2 ||
         !canRetainGpuPayloadV2(*mailbox, event->payload_len))) {
      malformed = true;
    }
    if (!malformed) {
      CopiedGpuEventV2 copied;
      copied.event = *event;
      copied.event.payload = nullptr;
      copied.event.payload_len = 0;
      if (event->payload_len > 0) {
        copied.payload.assign(
            event->payload, event->payload + event->payload_len);
      }
      mailbox->queued_payload_bytes += copied.payload.size();
      mailbox->events.push_back(std::move(copied));
      if (event->kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2) {
        // Realm-close admission linearizes with submit under this mutex. The
        // Closing phase rejects new submissions immediately, while the owner
        // drain is still allowed to deliver the already-queued terminal.
        mailbox->realm_terminal_accepted.store(true, std::memory_order_release);
        mailbox->phase.store(
            GpuMailboxPhaseV2::Closing, std::memory_order_release);
      }
    }
  } catch (...) {
    malformed = true;
  }
  if (malformed) {
    if (mailbox->realm_terminal_accepted.load(std::memory_order_acquire) &&
        mailbox->phase.load(std::memory_order_acquire) ==
            GpuMailboxPhaseV2::Closing) {
      quarantineAcceptedRealmCloseV2(mailbox);
    } else {
      (void)poisonGpuMailboxV2(mailbox);
    }
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  mailbox->owner_drain_required.store(true, std::memory_order_release);
  try {
    ex_hermes_notify_callback();
  } catch (...) {
  }
  return EXACT_GPU_CLIENT_EVENT_ACCEPTED;
}

#if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS) || \
    defined(receiveGpuEvent)
#error "Ibex CapSec GPU callback identifiers must not be preprocessor macros"
#endif

int32_t receiveGpuEvent(
    void* context,
    const ExactGpuServiceEventV2* event) noexcept {
  try {
    return receiveGpuEventV2Impl(context, event);
  } catch (...) {
    if (!context) return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
    auto* mailbox = static_cast<ExactGpuClientMailboxV2*>(context);
    auto phase = poisonGpuMailboxV2(mailbox);
    return phase == GpuMailboxPhaseV2::Closing ||
            phase == GpuMailboxPhaseV2::Detached
        ? EXACT_GPU_CLIENT_EVENT_DISCARDED
        : EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
}

#define IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(table_type, field_name, callback) \
  callback
const ExactGpuClientSinkV2 kGpuClientSinkV2 = {
    sizeof(ExactGpuClientSinkV2),
    EXACT_GPU_SERVICE_ABI_VERSION_V2,
    retainGpuClientV2,
    releaseGpuClientV2,
    IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
        ExactGpuClientSinkV2, on_event, receiveGpuEvent),
};
#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS

#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
std::atomic<uint64_t> gGpuV2ResolveCalls{0};
std::atomic<uint64_t> gGpuV2RejectCalls{0};
std::atomic<uint64_t> gGpuV2DeviceLossCalls{0};
std::atomic<uint64_t> gGpuV2RealmReductionCalls{0};
std::atomic<uint64_t> gGpuV2WrapperEventCalls{0};
std::atomic<uint64_t> gGpuV2CanvasReceiptObserverCalls{0};
std::atomic<uint64_t> gGpuV2HostTaskCheckpointCalls{0};
std::atomic<uint64_t> gGpuV2LastRejectedPromiseId{0};
std::atomic<uint64_t> gGpuV2ObserverOrderClock{0};
std::atomic<uint64_t> gGpuV2LastRawEventOrder{0};
std::atomic<uint64_t> gGpuV2LastLogicalLossOrder{0};
std::atomic<uint64_t> gGpuV2LastDetachedLossOrder{0};
std::atomic<uint64_t> gGpuV2LastDeviceLostReactionOrder{0};
std::atomic<uint64_t> gGpuV2LastPromiseReactionOrder{0};
std::atomic<uint32_t> gGpuV2LastUncapturedProjectionValid{0};
std::atomic<uint64_t> gGpuV2OperationResultPayloadMaterializations{0};
std::atomic<uint32_t> gGpuV2OperationResultReusedMailboxBacking{0};
std::atomic<uint32_t> gGpuV2LastReceiptResolvedUndefined{0};
// 0 = use the compiled/live engine capability, 1 = simulate an artifact
// without the interface declaration, 2 = simulate a failed live UUID cast.
// Both negative legs run through the same publication gate used in production.
std::atomic<uint32_t> gGpuV2MappedArrayBufferGateFailure{0};
std::atomic<uint32_t> gGpuV2DrainPauseState{0};
std::atomic<uint32_t> gGpuV2ServiceEntryPauseKind{0};
std::atomic<uint32_t> gGpuV2ServiceEntryPauseState{0};
#endif

#endif

}  // namespace

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
struct DecodedImagePromiseResolversV1 {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

struct PendingDecodedImageV1 {
  uint64_t request_id{0};
  ExactGpuDecodedImageIdentityV1 identity{};
  std::vector<uint8_t> encoded;
  std::shared_ptr<DecodedImagePromiseResolversV1> resolvers;
  bool completion_queued{false};
  bool owner_fallback_required{false};
  size_t queued_decoded_bytes{0};
};

struct ExactGpuDecodedImageRuntimeBindingV1 {
  ExactGpuDecodedImageHostApiV1 api{};
  RuntimeCallbackTarget target{};
  std::mutex mutex;
  std::unordered_map<uint64_t, PendingDecodedImageV1> pending;
  size_t pending_encoded_bytes{0};
  size_t queued_decoded_bytes{0};
  std::atomic<bool> owner_drain_required{false};
  bool context_retained{false};
  bool active{true};

  ~ExactGpuDecodedImageRuntimeBindingV1();
  void detach(ExactHermesRuntime* runtime, const char* reason) noexcept;
};

struct ExactGpuRuntimeBindingV2 {
  ExactGpuServiceApiV2 api{};
  ExactGpuClientMailboxV2* mailbox{nullptr};
  ExactGpuRealmIdentityV2 realm{};
  ExactGpuAccountIdentityV2 root_account{};
  std::array<uint8_t, EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2> authority_digest{};
  std::array<uint8_t, 32> runtime_routing_digest{};
  uint32_t topology_id{0};
  std::unordered_set<uint32_t> allowed_operations;
  std::unordered_map<uint64_t, PendingGpuReceiptV2> pending_receipts;
  // Owner-thread-only bounded delivery queue for spontaneous errors/loss and
  // non-Promise terminals until the generated wrapper installs its private
  // sink. It is never exposed on globalThis.
  std::deque<CopiedGpuEventV2> deferred_wrapper_events;
  size_t deferred_wrapper_payload_bytes{0};
  std::shared_ptr<facebook::jsi::Function> wrapper_event_sink;
  bool wrapper_event_sink_set{false};
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  // Tests observe the exact event object delivered to the production wrapper
  // without competing for its one-shot construction-private sink.
  std::shared_ptr<facebook::jsi::Function> test_event_observer;
#endif
  uint64_t next_operation_instance_id{1};
  uint64_t next_promise_id{1};
  std::shared_ptr<facebook::jsi::Object> private_bridge;
  std::shared_ptr<facebook::jsi::Function> revoke_capture;
  // Optional typed Exact Canvas terminal sink returned together with the
  // revoker by runtime-js. Like every JSI root here it is realm-bound,
  // owner-thread-only, and cleared before Hermes teardown.
  std::shared_ptr<facebook::jsi::Function> canvas_receipt_sink;
  // Construction-captured, owner-thread-only host-task checkpoint. This is
  // invoked only after the outer user task and its nextTick/microtask closure
  // have drained; runtime-js uses it to expire current Canvas textures.
  std::shared_ptr<facebook::jsi::Function> host_task_checkpoint;
  // Frozen construction-result identities which native invokes around each
  // host-controlled Exact app-bundle evaluation. The temporary root capture
  // itself exists only between those two calls.
  std::shared_ptr<facebook::jsi::Function> canvas_app_bundle_begin;
  std::shared_ptr<facebook::jsi::Function> canvas_app_bundle_finish;
  std::shared_ptr<facebook::jsi::Function> canvas_app_bundle_capture;
  uint64_t canvas_app_bundle_generation{0};
  uint32_t canvas_app_bundle_expectation{0};
  bool canvas_app_bundle_prepared{false};
  bool canvas_app_bundle_open{false};
  bool canvas_app_bundle_committed{false};
  bool service_retained{false};
  bool realm_open{false};
  bool bridge_captured{false};
  bool bridge_sealed{false};
  bool decoded_image_authority_attached{false};
  bool detached{false};

  ~ExactGpuRuntimeBindingV2();
  void detach(ExactHermesRuntime* runtime, const char* reason) noexcept;
};
#else
struct ExactGpuDecodedImageRuntimeBindingV1 {};
struct ExactGpuRuntimeBindingV2 {};
#endif

namespace {

#if defined(IBEX_ENABLE_WEBGPU_BINDING)

constexpr size_t kMaxDecodedImageEncodedBytesV1 = 16 * 1024 * 1024;
constexpr size_t kMaxDecodedImageBytesV1 = 64 * 1024 * 1024;
constexpr size_t kMaxDecodedImageDimensionV1 = 8192;
constexpr size_t kMaxPendingDecodedImagesV1 = 8;
constexpr size_t kMaxPendingDecodedImageEncodedBytesV1 = 32 * 1024 * 1024;
constexpr size_t kMaxQueuedDecodedImageBytesV1 = 64 * 1024 * 1024;

struct DecodedImageRequestTargetV1 {
  RuntimeCallbackTarget target{};
  std::weak_ptr<ExactGpuDecodedImageRuntimeBindingV1> binding;
};

struct CopiedDecodedImagePlaneV1 {
  uint32_t width{0};
  uint32_t height{0};
  uint32_t bytes_per_row{0};
  std::vector<uint8_t> encoded;
  std::vector<uint8_t> decoded;
  std::array<uint8_t, 32> encoded_sha256{};
  std::array<uint8_t, 32> decoded_sha256{};
};

std::atomic<uint64_t> gNextDecodedImageRequestIdV1{1};
std::mutex gDecodedImageRequestTargetsMutexV1;
std::unordered_map<uint64_t, DecodedImageRequestTargetV1>
    gDecodedImageRequestTargetsV1;

uint64_t nextDecodedImageRequestIdV1() {
  uint64_t current =
      gNextDecodedImageRequestIdV1.load(std::memory_order_relaxed);
  while (current != 0) {
    const uint64_t next = current + 1;
    if (gNextDecodedImageRequestIdV1.compare_exchange_weak(
            current, next, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      return current;
    }
  }
  return 0;
}

bool equalDecodedImageIdentityV1(const ExactGpuDecodedImageIdentityV1 &left,
                                 const ExactGpuDecodedImageIdentityV1 &right) {
  return left.runtime_address == right.runtime_address &&
         left.runtime_nonce == right.runtime_nonce &&
         left.source_id == right.source_id &&
         left.source_generation == right.source_generation;
}

bool validDecodedImageIdentityV1(
    const ExactGpuDecodedImageIdentityV1 &identity) {
  return identity.runtime_address != 0 && identity.runtime_nonce != 0 &&
         identity.source_id != 0 && identity.source_generation != 0;
}

void forgetDecodedImageRequestTargetV1(uint64_t requestId) {
  std::lock_guard<std::mutex> lock(gDecodedImageRequestTargetsMutexV1);
  gDecodedImageRequestTargetsV1.erase(requestId);
}

std::optional<DecodedImageRequestTargetV1>
takeDecodedImageRequestTargetV1(uint64_t requestId) {
  std::lock_guard<std::mutex> lock(gDecodedImageRequestTargetsMutexV1);
  auto found = gDecodedImageRequestTargetsV1.find(requestId);
  if (found == gDecodedImageRequestTargetsV1.end())
    return std::nullopt;
  auto target = found->second;
  gDecodedImageRequestTargetsV1.erase(found);
  return target;
}

class ScopedDecodedImageRuntimePinV1 {
 public:
  explicit ScopedDecodedImageRuntimePinV1(RuntimeCallbackTarget target)
      : target_(target), acquired_(exactPinRuntimeNativeWorker(target_)) {}

  ~ScopedDecodedImageRuntimePinV1() {
    if (!acquired_)
      return;
    try {
      exactUnpinRuntimeNativeWorker(target_);
    } catch (...) {
    }
  }

  ScopedDecodedImageRuntimePinV1(const ScopedDecodedImageRuntimePinV1 &) =
      delete;
  ScopedDecodedImageRuntimePinV1 &operator=(
      const ScopedDecodedImageRuntimePinV1 &) = delete;

  explicit operator bool() const { return acquired_; }

 private:
  RuntimeCallbackTarget target_{};
  bool acquired_{false};
};

void publishDecodedImageOwnerFallbackV1(
    const std::shared_ptr<ExactGpuDecodedImageRuntimeBindingV1> &binding,
    uint64_t requestId) noexcept {
  if (!binding)
    return;
  try {
    std::lock_guard<std::mutex> lock(binding->mutex);
    auto found = binding->pending.find(requestId);
    if (found != binding->pending.end()) {
      binding->queued_decoded_bytes -= found->second.queued_decoded_bytes;
      found->second.queued_decoded_bytes = 0;
      found->second.completion_queued = true;
      found->second.owner_fallback_required = true;
    }
  } catch (...) {
  }
  binding->owner_drain_required.store(true, std::memory_order_release);
  try {
    ex_hermes_notify_callback();
  } catch (...) {
  }
}

facebook::jsi::Object makeDecodedImagePromiseV1(
    facebook::jsi::Runtime &rt,
    const std::shared_ptr<DecodedImagePromiseResolversV1> &resolvers) {
  auto executor = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "decodedImagePromiseExecutor"), 2,
      [resolvers](facebook::jsi::Runtime &rt, const facebook::jsi::Value &,
                  const facebook::jsi::Value *args,
                  size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isObject() || !args[1].isObject() ||
            !args[0].asObject(rt).isFunction(rt) ||
            !args[1].asObject(rt).isFunction(rt)) {
          throw facebook::jsi::JSError(
              rt, "Malformed decoded-image Promise executor");
        }
        resolvers->resolve = std::make_shared<facebook::jsi::Function>(
            args[0].asObject(rt).asFunction(rt));
        resolvers->reject = std::make_shared<facebook::jsi::Function>(
            args[1].asObject(rt).asFunction(rt));
        return facebook::jsi::Value::undefined();
      });
  auto promise = rt.global()
                     .getPropertyAsFunction(rt, "Promise")
                     .callAsConstructor(rt, executor)
                     .getObject(rt);
  if (!resolvers->resolve || !resolvers->reject) {
    throw facebook::jsi::JSError(
        rt, "Decoded-image Promise executor did not initialize");
  }
  return promise;
}

facebook::jsi::Object makeDecodedImageErrorV1(facebook::jsi::Runtime &rt,
                                              const char *message) {
  auto error = rt.global()
                   .getPropertyAsFunction(rt, "Error")
                   .callAsConstructor(
                       rt, facebook::jsi::String::createFromUtf8(rt, message))
                   .getObject(rt);
  error.setProperty(
      rt, "name", facebook::jsi::String::createFromAscii(rt, "OperationError"));
  return error;
}

void rejectDecodedImageV1(
    facebook::jsi::Runtime &rt,
    const std::shared_ptr<DecodedImagePromiseResolversV1> &resolvers,
    const char *message) noexcept {
  if (!resolvers || !resolvers->reject)
    return;
  try {
    resolvers->reject->call(rt, makeDecodedImageErrorV1(rt, message));
  } catch (...) {
    try {
      resolvers->reject->call(rt, facebook::jsi::Value::undefined());
    } catch (...) {
    }
  }
}

std::string decodedImageDigestHexV1(const std::array<uint8_t, 32> &digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result(64, '0');
  for (size_t index = 0; index < digest.size(); ++index) {
    result[index * 2] = kHex[digest[index] >> 4];
    result[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  return result;
}

void settleDecodedImageV1(
    const std::shared_ptr<ExactGpuDecodedImageRuntimeBindingV1> &binding,
    facebook::jsi::Runtime &rt, uint64_t requestId, uint32_t status,
    std::shared_ptr<CopiedDecodedImagePlaneV1> plane) noexcept {
  std::shared_ptr<DecodedImagePromiseResolversV1> resolvers;
  ExactGpuDecodedImageIdentityV1 identity{};
  {
    std::lock_guard<std::mutex> lock(binding->mutex);
    auto found = binding->pending.find(requestId);
    if (found == binding->pending.end() || !found->second.completion_queued) {
      return;
    }
    identity = found->second.identity;
    resolvers = std::move(found->second.resolvers);
    binding->pending_encoded_bytes -= found->second.encoded.size();
    binding->queued_decoded_bytes -= found->second.queued_decoded_bytes;
    binding->pending.erase(found);
  }
  if (status != EXACT_GPU_DECODED_IMAGE_COMPLETE_V1 || !plane) {
    rejectDecodedImageV1(rt, resolvers,
                         status == EXACT_GPU_DECODED_IMAGE_CANCELLED_V1
                             ? "Decoded-image request was cancelled"
                             : "Native PNG decode failed");
    return;
  }
  try {
    facebook::jsi::Object result(rt);
    result.setProperty(rt, "runtimeAddress",
                       facebook::jsi::String::createFromAscii(
                           rt, std::to_string(identity.runtime_address)));
    result.setProperty(rt, "runtimeNonce",
                       facebook::jsi::String::createFromAscii(
                           rt, std::to_string(identity.runtime_nonce)));
    result.setProperty(rt, "sourceId",
                       facebook::jsi::String::createFromAscii(
                           rt, std::to_string(identity.source_id)));
    result.setProperty(rt, "sourceGeneration",
                       facebook::jsi::String::createFromAscii(
                           rt, std::to_string(identity.source_generation)));
    result.setProperty(rt, "width", static_cast<double>(plane->width));
    result.setProperty(rt, "height", static_cast<double>(plane->height));
    result.setProperty(rt, "bytesPerRow",
                       static_cast<double>(plane->bytes_per_row));
    result.setProperty(rt, "encodedBytes",
                       makeUint8Array(rt, std::move(plane->encoded)));
    result.setProperty(rt, "decodedPremultipliedRgba8",
                       makeUint8Array(rt, std::move(plane->decoded)));
    result.setProperty(rt, "encodedContentSha256",
                       facebook::jsi::String::createFromAscii(
                           rt, decodedImageDigestHexV1(plane->encoded_sha256)));
    result.setProperty(rt, "decodedContentSha256",
                       facebook::jsi::String::createFromAscii(
                           rt, decodedImageDigestHexV1(plane->decoded_sha256)));
    result.setProperty(rt, "originClean", true);
    result.setProperty(rt, "colorSpace",
                       facebook::jsi::String::createFromAscii(rt, "srgb"));
    result.setProperty(
        rt, "alphaMode",
        facebook::jsi::String::createFromAscii(rt, "premultiplied"));
    result.setProperty(rt, "orientation",
                       facebook::jsi::String::createFromAscii(rt, "top-left"));
    resolvers->resolve->call(rt, std::move(result));
  } catch (...) {
    rejectDecodedImageV1(rt, resolvers,
                         "Decoded-image result materialization failed");
  }
}

bool pauseReservedGpuV2ServiceEntryForTest(
    ExactGpuClientMailboxV2* mailbox,
    GpuServiceEntryKindV2 kind) noexcept {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  if (gGpuV2ServiceEntryPauseKind.load(std::memory_order_seq_cst) !=
      static_cast<uint32_t>(kind)) {
    return true;
  }
  uint32_t expected = 1;
  if (!gGpuV2ServiceEntryPauseState.compare_exchange_strong(
          expected, 2, std::memory_order_seq_cst)) {
    return true;
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (gGpuV2ServiceEntryPauseState.load(std::memory_order_seq_cst) == 2 &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
  if (gGpuV2ServiceEntryPauseState.load(std::memory_order_seq_cst) != 3) {
    gGpuV2ServiceEntryPauseState.store(0, std::memory_order_seq_cst);
    (void)poisonGpuMailboxV2(mailbox);
    return false;
  }
  gGpuV2ServiceEntryPauseState.store(0, std::memory_order_seq_cst);
  gGpuV2ServiceEntryPauseKind.store(0, std::memory_order_seq_cst);
#else
  (void)mailbox;
  (void)kind;
#endif
  return true;
}

bool pauseGpuV2DetachCleanupForTest() noexcept {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  uint32_t expected = 1;
  if (!gGpuV2DetachCleanupPauseState.compare_exchange_strong(
          expected, 2, std::memory_order_seq_cst)) {
    return true;
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (gGpuV2DetachCleanupPauseState.load(std::memory_order_seq_cst) == 2 &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
  const bool resumed =
      gGpuV2DetachCleanupPauseState.load(std::memory_order_seq_cst) == 3;
  gGpuV2DetachCleanupPauseState.store(0, std::memory_order_seq_cst);
  return resumed;
#else
  return true;
#endif
}

facebook::jsi::String gpuV2Uint64String(
    facebook::jsi::Runtime& rt,
    uint64_t value) {
  return facebook::jsi::String::createFromAscii(rt, std::to_string(value));
}

uint64_t parseCanonicalGpuV2Uint64(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* name,
    bool allowZero) {
  if (!value.isString()) {
    throw facebook::jsi::JSError(
        rt, std::string(name) + " must be a canonical decimal string");
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
    const uint64_t digit = static_cast<uint64_t>(byte - '0');
    if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
      throw facebook::jsi::JSError(rt, std::string(name) + " exceeds uint64");
    }
    parsed = parsed * 10 + digit;
  }
  if (!allowZero && parsed == 0) {
    throw facebook::jsi::JSError(rt, std::string(name) + " must be nonzero");
  }
  return parsed;
}

uint32_t parseGpuV2Uint32(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* name,
    uint32_t minimum,
    uint32_t maximum) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(rt, std::string(name) + " must be a uint32");
  }
  const double raw = value.asNumber();
  if (!std::isfinite(raw) || std::floor(raw) != raw ||
      raw < static_cast<double>(minimum) || raw > static_cast<double>(maximum)) {
    throw facebook::jsi::JSError(rt, std::string(name) + " must be a uint32");
  }
  return static_cast<uint32_t>(raw);
}

void defineGpuV2Property(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& target,
    const char* name,
    facebook::jsi::Value value) {
  facebook::jsi::Object descriptor(rt);
  descriptor.setProperty(rt, "value", std::move(value));
  descriptor.setProperty(rt, "writable", false);
  descriptor.setProperty(rt, "enumerable", false);
  descriptor.setProperty(rt, "configurable", false);
  rt.global()
      .getPropertyAsObject(rt, "Object")
      .getPropertyAsFunction(rt, "defineProperty")
      .call(
          rt,
          target,
          facebook::jsi::String::createFromAscii(rt, name),
          descriptor);
}

const char* canvasAttachmentFailureStringV1(uint32_t failure) noexcept {
  switch (failure) {
    case EXACT_GPU_CANVAS_ATTACHMENT_STALE_GENERATION_V1:
      return "stale-generation";
    case EXACT_GPU_CANVAS_ATTACHMENT_AUTHORITY_DENIED_V1:
      return "authority-denied";
    case EXACT_GPU_CANVAS_ATTACHMENT_PROVIDER_LOST_V1:
      return "provider-lost";
    case EXACT_GPU_CANVAS_ATTACHMENT_SUPERSEDED_BEFORE_ATTACH_V1:
      return "superseded-before-attach";
    case EXACT_GPU_CANVAS_ATTACHMENT_ROOT_GENERATION_CLOSED_V1:
      return "root-generation-closed";
    case EXACT_GPU_CANVAS_ATTACHMENT_INTERNAL_V1:
      return "internal";
    default:
      return nullptr;
  }
}

std::string canvasAuthorityDigestHexV1(const uint8_t digest[32]) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result(64, '0');
  for (size_t index = 0; index < 32; ++index) {
    result[index * 2] = kHex[digest[index] >> 4];
    result[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  return result;
}

facebook::jsi::Object makeCanvasAttachmentReceiptValueV1(
    facebook::jsi::Runtime& rt,
    const ExactGpuCanvasAttachmentReceiptV1& receipt) {
  facebook::jsi::Object value(rt);
  value.setProperty(
      rt,
      "kind",
      facebook::jsi::String::createFromAscii(
          rt, "exact-gpu-canvas-attachment-v1"));
  value.setProperty(
      rt,
      "outcome",
      facebook::jsi::String::createFromAscii(
          rt,
          receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1
              ? "attached"
              : "rejected"));
  value.setProperty(
      rt, "protocolRootId", static_cast<double>(receipt.protocol_root_id));
  value.setProperty(
      rt,
      "runtimeGeneration",
      gpuV2Uint64String(rt, receipt.runtime_generation));
  value.setProperty(
      rt, "rootInstanceId", gpuV2Uint64String(rt, receipt.root_instance_id));
  value.setProperty(
      rt, "rootGeneration", gpuV2Uint64String(rt, receipt.root_generation));
  value.setProperty(
      rt, "commitSequence", gpuV2Uint64String(rt, receipt.commit_sequence));
  value.setProperty(rt, "viewId", static_cast<double>(receipt.view_id));
  value.setProperty(
      rt, "viewGeneration", gpuV2Uint64String(rt, receipt.view_generation));
  value.setProperty(rt, "handleId", gpuV2Uint64String(rt, receipt.handle_id));
  value.setProperty(
      rt,
      "handleGeneration",
      gpuV2Uint64String(rt, receipt.handle_generation));
  value.setProperty(
      rt, "attachmentId", gpuV2Uint64String(rt, receipt.attachment_id));
  value.setProperty(
      rt,
      "attachmentGeneration",
      gpuV2Uint64String(rt, receipt.attachment_generation));
  if (receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1) {
    value.setProperty(
        rt, "contextId", gpuV2Uint64String(rt, receipt.context_id));
    value.setProperty(
        rt,
        "contextGeneration",
        gpuV2Uint64String(rt, receipt.context_generation));
    value.setProperty(
        rt,
        "drawingBufferWidth",
        static_cast<double>(receipt.drawing_buffer_width));
    value.setProperty(
        rt,
        "drawingBufferHeight",
        static_cast<double>(receipt.drawing_buffer_height));
    value.setProperty(
        rt,
        "targetAuthorityDigest",
        facebook::jsi::String::createFromAscii(
            rt,
            canvasAuthorityDigestHexV1(receipt.target_authority_digest)));
    value.setProperty(
        rt,
        "surfaceAccountToken",
        gpuV2Uint64String(rt, receipt.surface_account_token));
    value.setProperty(
        rt,
        "surfaceAccountGeneration",
        gpuV2Uint64String(rt, receipt.surface_account_generation));
  } else {
    value.setProperty(
        rt,
        "failure",
        facebook::jsi::String::createFromAscii(
            rt, canvasAttachmentFailureStringV1(receipt.failure)));
  }
  rt.global()
      .getPropertyAsObject(rt, "Object")
      .getPropertyAsFunction(rt, "freeze")
      .call(rt, value);
  return value;
}

#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
bool canvasReceiptValueMatchesV1(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const ExactGpuCanvasAttachmentReceiptV1& receipt) {
  if (!runtime || !value.isObject() ||
      !runtime->root_global_get_own_property_names ||
      !runtime->root_global_get_own_property_symbols ||
      !runtime->root_global_get_own_property_descriptor ||
      !runtime->root_global_get_prototype_of) {
    return false;
  }
  auto object = value.asObject(rt);
  if (object.isFunction(rt)) return false;

  std::unordered_set<std::string> expectedNames = {
      "kind",
      "outcome",
      "protocolRootId",
      "runtimeGeneration",
      "rootInstanceId",
      "rootGeneration",
      "commitSequence",
      "viewId",
      "viewGeneration",
      "handleId",
      "handleGeneration",
      "attachmentId",
      "attachmentGeneration",
  };
  if (receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1) {
    expectedNames.insert("contextId");
    expectedNames.insert("contextGeneration");
    expectedNames.insert("drawingBufferWidth");
    expectedNames.insert("drawingBufferHeight");
    expectedNames.insert("targetAuthorityDigest");
    expectedNames.insert("surfaceAccountToken");
    expectedNames.insert("surfaceAccountGeneration");
  } else {
    expectedNames.insert("failure");
  }

  auto namesValue = runtime->root_global_get_own_property_names->call(
      rt, object);
  auto symbolsValue = runtime->root_global_get_own_property_symbols->call(
      rt, object);
  if (!namesValue.isObject() || !namesValue.asObject(rt).isArray(rt) ||
      !symbolsValue.isObject() || !symbolsValue.asObject(rt).isArray(rt)) {
    return false;
  }
  auto names = namesValue.asObject(rt).asArray(rt);
  auto symbols = symbolsValue.asObject(rt).asArray(rt);
  if (names.size(rt) != expectedNames.size() || symbols.size(rt) != 0) {
    return false;
  }
  for (size_t index = 0; index < names.size(rt); ++index) {
    auto nameValue = names.getValueAtIndex(rt, index);
    if (!nameValue.isString()) return false;
    auto name = nameValue.asString(rt).utf8(rt);
    if (expectedNames.erase(name) != 1) return false;

    auto key = facebook::jsi::String::createFromUtf8(rt, name);
    auto descriptorValue =
        runtime->root_global_get_own_property_descriptor->call(
            rt, object, key);
    if (!descriptorValue.isObject()) return false;
    auto descriptor = descriptorValue.asObject(rt);
    auto writable = descriptor.getProperty(rt, "writable");
    auto enumerable = descriptor.getProperty(rt, "enumerable");
    auto configurable = descriptor.getProperty(rt, "configurable");
    auto getter = descriptor.getProperty(rt, "get");
    auto setter = descriptor.getProperty(rt, "set");
    if (!writable.isBool() || writable.getBool() ||
        !enumerable.isBool() || !enumerable.getBool() ||
        !configurable.isBool() || configurable.getBool() ||
        !getter.isUndefined() || !setter.isUndefined()) {
      return false;
    }
  }
  if (!expectedNames.empty()) return false;

  auto frozen = rt.global()
                    .getPropertyAsObject(rt, "Object")
                    .getPropertyAsFunction(rt, "isFrozen")
                    .call(rt, object);
  if (!frozen.isBool() || !frozen.getBool()) return false;
  auto prototypeValue = runtime->root_global_get_prototype_of->call(
      rt, object);
  if (!prototypeValue.isObject()) return false;
  auto expectedPrototype = rt.global()
                               .getPropertyAsObject(rt, "Object")
                               .getPropertyAsObject(rt, "prototype");
  if (!facebook::jsi::Object::strictEquals(
          rt, prototypeValue.asObject(rt), expectedPrototype)) {
    return false;
  }

  auto stringProperty = [&](const char* name, const std::string& expected) {
    auto property = object.getProperty(rt, name);
    return property.isString() &&
        property.asString(rt).utf8(rt) == expected;
  };
  auto numberProperty = [&](const char* name, uint32_t expected) {
    auto property = object.getProperty(rt, name);
    return property.isNumber() &&
        property.asNumber() == static_cast<double>(expected);
  };
  if (!stringProperty("kind", "exact-gpu-canvas-attachment-v1") ||
      !stringProperty(
          "outcome",
          receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1
              ? "attached"
              : "rejected") ||
      !numberProperty("protocolRootId", receipt.protocol_root_id) ||
      !stringProperty(
          "runtimeGeneration", std::to_string(receipt.runtime_generation)) ||
      !stringProperty(
          "rootInstanceId", std::to_string(receipt.root_instance_id)) ||
      !stringProperty(
          "rootGeneration", std::to_string(receipt.root_generation)) ||
      !stringProperty(
          "commitSequence", std::to_string(receipt.commit_sequence)) ||
      !numberProperty("viewId", receipt.view_id) ||
      !stringProperty(
          "viewGeneration", std::to_string(receipt.view_generation)) ||
      !stringProperty("handleId", std::to_string(receipt.handle_id)) ||
      !stringProperty(
          "handleGeneration", std::to_string(receipt.handle_generation)) ||
      !stringProperty(
          "attachmentId", std::to_string(receipt.attachment_id)) ||
      !stringProperty(
          "attachmentGeneration",
          std::to_string(receipt.attachment_generation))) {
    return false;
  }
  if (receipt.outcome == EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1) {
    return stringProperty("contextId", std::to_string(receipt.context_id)) &&
        stringProperty(
            "contextGeneration", std::to_string(receipt.context_generation)) &&
        numberProperty(
            "drawingBufferWidth", receipt.drawing_buffer_width) &&
        numberProperty(
            "drawingBufferHeight", receipt.drawing_buffer_height) &&
        stringProperty(
            "targetAuthorityDigest",
            canvasAuthorityDigestHexV1(receipt.target_authority_digest)) &&
        stringProperty(
            "surfaceAccountToken",
            std::to_string(receipt.surface_account_token)) &&
        stringProperty(
            "surfaceAccountGeneration",
            std::to_string(receipt.surface_account_generation));
  }
  const char* failure = canvasAttachmentFailureStringV1(receipt.failure);
  return failure && stringProperty("failure", failure);
}
#endif

std::vector<uint8_t> parseGpuV2Bytes(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* name,
    size_t maximum,
    size_t exactLength = 0) {
  if (!value.isObject()) {
    throw facebook::jsi::JSError(
        rt, std::string(name) + " must be an ArrayBuffer or view");
  }
  auto object = value.asObject(rt);
  if (!object.isArrayBuffer(rt)) {
    auto arrayBuffer = rt.global().getPropertyAsObject(rt, "ArrayBuffer");
    auto isView = arrayBuffer.getPropertyAsFunction(rt, "isView");
    auto result = isView.callWithThis(rt, arrayBuffer, object);
    if (!result.isBool() || !result.getBool()) {
      throw facebook::jsi::JSError(
          rt, std::string(name) + " must be an ArrayBuffer or view");
    }
  }
  const uint8_t* data = nullptr;
  size_t length = 0;
  if (!extractArrayBufferView(rt, object, data, length) || length > maximum ||
      (exactLength != 0 && length != exactLength)) {
    throw facebook::jsi::JSError(rt, std::string(name) + " has an invalid size");
  }
  return length == 0 ? std::vector<uint8_t>()
                     : std::vector<uint8_t>(data, data + length);
}

facebook::jsi::Value
decodeGpuImageV1BridgeCall(ExactHermesRuntime *runtime,
                           facebook::jsi::Runtime &rt,
                           const facebook::jsi::Value *args, size_t count) {
  if (!runtime || !runtime->gpu_decoded_image_binding_v1 || count != 1 ||
      !args[0].isObject()) {
    throw facebook::jsi::JSError(
        rt, "Decoded-image authority requires one canonical request");
  }
  auto binding = runtime->gpu_decoded_image_binding_v1;
  auto requestObject = args[0].asObject(rt);
  ExactGpuDecodedImageIdentityV1 identity{};
  identity.runtime_address = parseCanonicalGpuV2Uint64(
      rt, requestObject.getProperty(rt, "runtimeAddress"), "runtimeAddress",
      false);
  identity.runtime_nonce = parseCanonicalGpuV2Uint64(
      rt, requestObject.getProperty(rt, "runtimeNonce"), "runtimeNonce", false);
  identity.source_id = parseCanonicalGpuV2Uint64(
      rt, requestObject.getProperty(rt, "sourceId"), "sourceId", false);
  identity.source_generation = parseCanonicalGpuV2Uint64(
      rt, requestObject.getProperty(rt, "sourceGeneration"), "sourceGeneration",
      false);
  auto mimeValue = requestObject.getProperty(rt, "mimeType");
  if (!mimeValue.isString() || mimeValue.asString(rt).utf8(rt) != "image/png") {
    throw facebook::jsi::JSError(rt, "Decoded-image source must be PNG");
  }
  auto encoded =
      parseGpuV2Bytes(rt, requestObject.getProperty(rt, "encodedBytes"),
                      "encodedBytes", kMaxDecodedImageEncodedBytesV1);
  if (encoded.empty() ||
      identity.runtime_address !=
          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime)) ||
      identity.runtime_nonce != runtime->runtime_nonce) {
    throw facebook::jsi::JSError(
        rt, "Decoded-image request has stale runtime identity");
  }
  const uint64_t requestId = nextDecodedImageRequestIdV1();
  if (requestId == 0) {
    throw facebook::jsi::JSError(
        rt, "Decoded-image request identity space is exhausted");
  }
  auto resolvers = std::make_shared<DecodedImagePromiseResolversV1>();
  auto promise = makeDecodedImagePromiseV1(rt, resolvers);
  {
    std::lock_guard<std::mutex> lock(binding->mutex);
    if (!binding->active) {
      throw facebook::jsi::JSError(rt, "Decoded-image authority is revoked");
    }
    if (binding->pending.size() >= kMaxPendingDecodedImagesV1 ||
        encoded.size() > kMaxPendingDecodedImageEncodedBytesV1 -
                             binding->pending_encoded_bytes) {
      throw facebook::jsi::JSError(rt,
                                   "Decoded-image pending budget is exhausted");
    }
    PendingDecodedImageV1 pending;
    pending.request_id = requestId;
    pending.identity = identity;
    pending.encoded = std::move(encoded);
    pending.resolvers = resolvers;
    binding->pending_encoded_bytes += pending.encoded.size();
    binding->pending.emplace(requestId, std::move(pending));
  }
  try {
    std::lock_guard<std::mutex> lock(gDecodedImageRequestTargetsMutexV1);
    auto inserted = gDecodedImageRequestTargetsV1.emplace(
        requestId, DecodedImageRequestTargetV1{binding->target, binding});
    if (!inserted.second)
      throw std::bad_alloc();
  } catch (...) {
    std::lock_guard<std::mutex> lock(binding->mutex);
    auto found = binding->pending.find(requestId);
    if (found != binding->pending.end()) {
      binding->pending_encoded_bytes -= found->second.encoded.size();
      binding->pending.erase(found);
    }
    throw facebook::jsi::JSError(
        rt, "Decoded-image request registry is unavailable");
  }

  ExactGpuDecodedImageRequestV1 request{};
  request.struct_size = sizeof(request);
  request.abi_version = EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1;
  request.mime_type = EXACT_GPU_DECODED_IMAGE_MIME_PNG_V1;
  request.request_id = requestId;
  request.identity = identity;
  {
    std::lock_guard<std::mutex> lock(binding->mutex);
    auto found = binding->pending.find(requestId);
    request.encoded_bytes = found->second.encoded.data();
    request.encoded_len = found->second.encoded.size();
  }
  int32_t admission = EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  try {
    admission = binding->api.begin_decode(binding->api.host_context, &request);
  } catch (...) {
    admission = EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  if (admission != 0) {
    forgetDecodedImageRequestTargetV1(requestId);
    std::shared_ptr<DecodedImagePromiseResolversV1> rejected;
    {
      std::lock_guard<std::mutex> lock(binding->mutex);
      auto found = binding->pending.find(requestId);
      if (found != binding->pending.end() && !found->second.completion_queued) {
        rejected = std::move(found->second.resolvers);
        binding->pending_encoded_bytes -= found->second.encoded.size();
        binding->pending.erase(found);
      }
    }
    if (rejected) {
      rejectDecodedImageV1(rt, rejected,
                           "Native decoded-image queue rejected the request");
    }
  }
  return facebook::jsi::Value(rt, std::move(promise));
}

facebook::jsi::Value revokeGpuImageV1BridgeCall(ExactHermesRuntime *runtime,
                                                facebook::jsi::Runtime &,
                                                size_t count) {
  if (!runtime || count != 0)
    return facebook::jsi::Value::undefined();
  auto binding = runtime->gpu_decoded_image_binding_v1;
  if (binding) {
    binding->detach(runtime, "Decoded-image authority was revoked");
    if (runtime->gpu_decoded_image_binding_v1 == binding) {
      runtime->gpu_decoded_image_binding_v1.reset();
    }
  }
  return facebook::jsi::Value::undefined();
}

facebook::jsi::Object makeGpuV2Promise(
    facebook::jsi::Runtime& rt,
    const std::shared_ptr<GpuPromiseResolversV2>& resolvers) {
  auto executor = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "gpuV2PromiseExecutor"),
      2,
      [resolvers](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isObject() || !args[1].isObject()) {
          throw facebook::jsi::JSError(rt, "Malformed GPU V2 Promise executor");
        }
        resolvers->resolve = std::make_shared<facebook::jsi::Function>(
            args[0].asObject(rt).asFunction(rt));
        resolvers->reject = std::make_shared<facebook::jsi::Function>(
            args[1].asObject(rt).asFunction(rt));
        return facebook::jsi::Value::undefined();
      });
  auto promise = rt.global()
                     .getPropertyAsFunction(rt, "Promise")
                     .callAsConstructor(rt, executor)
                     .getObject(rt);
  if (!resolvers->resolve || !resolvers->reject) {
    throw facebook::jsi::JSError(rt, "GPU V2 Promise executor did not initialize");
  }
  return promise;
}

std::shared_ptr<facebook::jsi::Object> tryMakeGpuV2DiagnosticPayload(
    facebook::jsi::Runtime& rt,
    const std::vector<uint8_t>& payload) noexcept {
  try {
    auto value = makeUint8Array(rt, payload);
    return std::make_shared<facebook::jsi::Object>(value.asObject(rt));
  } catch (...) {
    // Diagnostic bytes are optional under allocation pressure. Settlement is
    // still exactly once and never retries one large allocation per receipt.
    return nullptr;
  }
}

facebook::jsi::Object makeGpuV2Error(
    facebook::jsi::Runtime& rt,
    const char* kind,
    int32_t status,
    uint64_t operationInstance,
    uint64_t promiseId,
    uint32_t typedKind,
    const std::shared_ptr<facebook::jsi::Object>& payload,
    const char* message) {
  auto error = rt.global()
                   .getPropertyAsFunction(rt, "Error")
                   .callAsConstructor(
                       rt,
                       facebook::jsi::String::createFromUtf8(rt, message))
                   .getObject(rt);
  error.setProperty(
      rt, "kind", facebook::jsi::String::createFromAscii(rt, kind));
  error.setProperty(rt, "status", status);
  error.setProperty(
      rt, "operationInstanceId", gpuV2Uint64String(rt, operationInstance));
  error.setProperty(rt, "promiseId", gpuV2Uint64String(rt, promiseId));
  error.setProperty(rt, "typedKind", static_cast<double>(typedKind));
  if (payload) {
    error.setProperty(rt, "payload", facebook::jsi::Value(rt, *payload));
  } else {
    error.setProperty(rt, "payload", facebook::jsi::Value::undefined());
  }
  return error;
}

void rejectGpuV2Receipt(
    facebook::jsi::Runtime& rt,
    PendingGpuReceiptV2 receipt,
    const char* kind,
    int32_t status,
    uint32_t typedKind,
    const std::shared_ptr<facebook::jsi::Object>& payload,
    const char* message) noexcept {
  if (!receipt.reject) return;
  try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    gGpuV2RejectCalls.fetch_add(1, std::memory_order_seq_cst);
    gGpuV2LastRejectedPromiseId.store(
        receipt.promise_id, std::memory_order_seq_cst);
#endif
    receipt.reject->call(
        rt,
        makeGpuV2Error(
            rt,
            kind,
            status,
            receipt.operation_instance_id,
            receipt.promise_id,
            typedKind,
            payload,
            message));
  } catch (...) {
    try {
      receipt.reject->call(rt, facebook::jsi::Value::undefined());
    } catch (...) {
    }
  }
}

ExactGpuCancelV2 makeGpuCancelV2(const ExactGpuSemanticCallV2& call) {
  ExactGpuCancelV2 cancel{};
  cancel.struct_size = sizeof(cancel);
  cancel.abi_version = EXACT_GPU_SERVICE_ABI_VERSION_V2;
  cancel.realm = call.realm;
  cancel.account = call.account;
  cancel.ingress_device = call.ingress_device;
  cancel.provider_generation = call.provider_generation;
  cancel.topology_id = call.topology_id;
  cancel.operation_id = call.operation_id;
  cancel.operation_instance_id = call.operation_instance_id;
  cancel.promise_id = call.promise_id;
  cancel.captured_scope_id = call.captured_scope_id;
  cancel.adapter_ordinal = call.adapter_ordinal;
  cancel.device_ingress_ordinal = call.device_ingress_ordinal;
  cancel.queue_ingress_ordinal = call.queue_ingress_ordinal;
  std::copy(
      std::begin(call.authority_context_digest),
      std::end(call.authority_context_digest),
      cancel.authority_context_digest);
  cancel.authority_session_id = call.authority_session_id;
  cancel.receiver = call.receiver;
  cancel.target = call.target;
  return cancel;
}

void cancelGpuV2OutsideLocks(
    ExactGpuRuntimeBindingV2& binding,
    const ExactGpuSemanticCallV2& call) noexcept {
  if (!binding.realm_open || !binding.api.cancel ||
      (binding.mailbox && binding.mailbox->realm_terminal_accepted.load(
                              std::memory_order_acquire))) {
    return;
  }
  auto cancel = makeGpuCancelV2(call);
  try {
    (void)binding.api.cancel(binding.api.service_context, &cancel);
  } catch (...) {
    ex_host_console_log(1, "Exact GPU V2 service cancel threw across its C ABI");
  }
}

void revokeGpuV2BridgeCapture(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt) noexcept {
  if (binding.revoke_capture) {
    try {
      binding.revoke_capture->call(rt);
    } catch (...) {
    }
  }
  binding.revoke_capture.reset();
  binding.canvas_receipt_sink.reset();
  binding.host_task_checkpoint.reset();
  binding.canvas_app_bundle_begin.reset();
  binding.canvas_app_bundle_finish.reset();
  binding.canvas_app_bundle_capture.reset();
  binding.canvas_app_bundle_expectation = 0;
  binding.canvas_app_bundle_prepared = false;
  binding.canvas_app_bundle_open = false;
  binding.canvas_app_bundle_committed = false;
  binding.private_bridge.reset();
  binding.bridge_captured = false;
}

void reduceGpuV2Realm(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    const char* kind,
    int32_t status,
    const std::vector<uint8_t>& payload,
    const char* message,
  bool cancelProviderWork) noexcept {
  revokeGpuV2BridgeCapture(binding, rt);
  std::vector<ExactGpuSemanticCallV2> cancellations;
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    if (binding.mailbox->protocol_applied) return;
    binding.mailbox->protocol_applied = true;
    cancellations.reserve(binding.mailbox->submissions.size());
    for (const auto& entry : binding.mailbox->submissions) {
      cancellations.push_back(entry.second.call);
      markTerminalV2(
          *binding.mailbox,
          entry.first,
          &entry.second.call,
          GpuTerminalCauseV2::Quarantine,
          nullptr,
          nullptr);
    }
    binding.mailbox->submissions.clear();
    for (const auto& entry : binding.mailbox->sealed_submissions) {
      markTerminalV2(
          *binding.mailbox,
          entry.first,
          &entry.second.submission.call,
          GpuTerminalCauseV2::Quarantine,
          nullptr,
          nullptr);
    }
    binding.mailbox->sealed_submissions.clear();
    binding.mailbox->sealed_batches.clear();
    if (cancelProviderWork) {
      binding.mailbox->events.clear();
      binding.mailbox->queued_payload_bytes = 0;
    }
  } catch (...) {
  }
  auto receipts = std::move(binding.pending_receipts);
  binding.pending_receipts.clear();
  // One optional JSI backing is shared by every rejection in this fanout.
  // Never allocate payload.size() once per pending Promise.
  auto diagnosticPayload = tryMakeGpuV2DiagnosticPayload(rt, payload);
  if (cancelProviderWork) {
    for (const auto& cancellation : cancellations) {
      cancelGpuV2OutsideLocks(binding, cancellation);
    }
    if (binding.realm_open && binding.api.close_realm &&
        !binding.mailbox->realm_terminal_accepted.load(
            std::memory_order_acquire)) {
      try {
        (void)binding.api.close_realm(
            binding.api.service_context, &binding.realm, 1);
      } catch (...) {
        ex_host_console_log(
            1, "Exact GPU V2 close_realm threw during quarantine");
      }
      binding.realm_open = false;
    }
    binding.mailbox->phase.store(
        GpuMailboxPhaseV2::Closing, std::memory_order_release);
  }
  for (auto& entry : receipts) {
    rejectGpuV2Receipt(
        rt,
        std::move(entry.second),
        kind,
        status,
        0,
        diagnosticPayload,
        message);
  }
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  gGpuV2RealmReductionCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
}

void setGpuV2ObjectRefProperties(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& target,
    const char* prefix,
    const ExactGpuObjectRefV2& object) {
  target.setProperty(
      rt,
      (std::string(prefix) + "Kind").c_str(),
      static_cast<double>(object.kind));
  target.setProperty(
      rt,
      (std::string(prefix) + "Flags").c_str(),
      static_cast<double>(object.flags));
  target.setProperty(
      rt,
      (std::string(prefix) + "Id").c_str(),
      gpuV2Uint64String(rt, object.object_id));
  target.setProperty(
      rt,
      (std::string(prefix) + "Generation").c_str(),
      gpuV2Uint64String(rt, object.object_generation));
}

void setGpuV2OperationProperties(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& target,
    const ExactGpuOperationProvenanceV2& operation) {
  target.setProperty(
      rt, "operationId", static_cast<double>(operation.operation_id));
  target.setProperty(
      rt, "topologyId", static_cast<double>(operation.topology_id));
  target.setProperty(
      rt,
      "runtimeAddress",
      gpuV2Uint64String(rt, operation.realm.runtime.runtime_address));
  target.setProperty(
      rt,
      "runtimeNonce",
      gpuV2Uint64String(rt, operation.realm.runtime.runtime_nonce));
  target.setProperty(
      rt,
      "operationInstanceId",
      gpuV2Uint64String(rt, operation.operation_instance_id));
  target.setProperty(
      rt, "promiseId", gpuV2Uint64String(rt, operation.promise_id));
  target.setProperty(
      rt,
      "providerAdmission",
      static_cast<double>(operation.provider_admission));
  target.setProperty(
      rt,
      "physicalSequence",
      gpuV2Uint64String(rt, operation.physical_sequence));
  target.setProperty(
      rt,
      "capturedScopeId",
      gpuV2Uint64String(rt, operation.captured_scope_id));
  target.setProperty(
      rt, "realmId", gpuV2Uint64String(rt, operation.realm.realm_id));
  target.setProperty(
      rt,
      "realmGeneration",
      gpuV2Uint64String(rt, operation.realm.realm_generation));
  target.setProperty(
      rt, "accountId", gpuV2Uint64String(rt, operation.account.account_id));
  target.setProperty(
      rt,
      "accountGeneration",
      gpuV2Uint64String(rt, operation.account.account_generation));
  std::vector<uint8_t> accountDigest(
      operation.account.authority_digest,
      operation.account.authority_digest +
          EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
  target.setProperty(
      rt,
      "accountAuthorityDigest",
      makeUint8Array(rt, std::move(accountDigest)));
  target.setProperty(
      rt,
      "logicalDeviceId",
      gpuV2Uint64String(rt, operation.result_device.logical_device_id));
  target.setProperty(
      rt,
      "logicalDeviceGeneration",
      gpuV2Uint64String(rt, operation.result_device.logical_device_generation));
  target.setProperty(
      rt,
      "providerGeneration",
      gpuV2Uint64String(rt, operation.result_device.provider_generation));
  target.setProperty(
      rt,
      "ingressLogicalDeviceId",
      gpuV2Uint64String(rt, operation.ingress_device.logical_device_id));
  target.setProperty(
      rt,
      "ingressLogicalDeviceGeneration",
      gpuV2Uint64String(
          rt, operation.ingress_device.logical_device_generation));
  target.setProperty(
      rt,
      "ingressProviderGeneration",
      gpuV2Uint64String(rt, operation.ingress_device.provider_generation));
  target.setProperty(
      rt,
      "deviceTransition",
      static_cast<double>(operation.device_transition));
  target.setProperty(
      rt,
      "operationProviderGeneration",
      gpuV2Uint64String(rt, operation.provider_generation));
  target.setProperty(
      rt,
      "adapterOrdinal",
      gpuV2Uint64String(rt, operation.adapter_ordinal));
  target.setProperty(
      rt,
      "deviceIngressOrdinal",
      gpuV2Uint64String(rt, operation.device_ingress_ordinal));
  target.setProperty(
      rt,
      "queueIngressOrdinal",
      gpuV2Uint64String(rt, operation.queue_ingress_ordinal));
  std::vector<uint8_t> contextDigest(
      operation.authority_context_digest,
      operation.authority_context_digest + 32);
  target.setProperty(
      rt,
      "authorityContextDigest",
      makeUint8Array(rt, std::move(contextDigest)));
  setGpuV2ObjectRefProperties(rt, target, "receiver", operation.receiver);
  setGpuV2ObjectRefProperties(rt, target, "target", operation.target);
}

facebook::jsi::Object makeGpuV2WrapperEvent(
    facebook::jsi::Runtime& rt,
    const ExactGpuServiceEventV2& event,
    std::vector<uint8_t> payload) {
  facebook::jsi::Object value(rt);
  value.setProperty(rt, "kind", static_cast<double>(event.kind));
  const auto* payloadData = payload.data();
  const size_t payloadSize = payload.size();
  auto payloadValue = makeUint8Array(rt, std::move(payload));
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  if (event.kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
    gGpuV2OperationResultPayloadMaterializations.fetch_add(
        1, std::memory_order_seq_cst);
    const uint8_t* exposedData = nullptr;
    size_t exposedSize = 0;
    const auto payloadObject = payloadValue.asObject(rt);
    gGpuV2OperationResultReusedMailboxBacking.store(
        extractArrayBufferView(rt, payloadObject, exposedData, exposedSize) &&
                exposedSize == payloadSize &&
                (payloadSize == 0 || exposedData == payloadData)
            ? 1
            : 0,
        std::memory_order_seq_cst);
  }
#endif
  value.setProperty(rt, "payload", std::move(payloadValue));
  switch (event.kind) {
    case EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2: {
      const auto& record = event.record.operation_result;
      setGpuV2OperationProperties(rt, value, record.operation);
      value.setProperty(
          rt, "resultKind", static_cast<double>(record.result_kind));
      value.setProperty(rt, "status", record.status);
      const bool detachedAlreadyLost =
          isServiceDetachedAssignedV2(record.operation);
      value.setProperty(rt, "detachedAlreadyLost", detachedAlreadyLost);
      if (detachedAlreadyLost) {
        value.setProperty(
            rt,
            "lossReason",
            static_cast<double>(EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2));
        value.setProperty(
            rt,
            "backendClass",
            static_cast<double>(EXACT_GPU_BACKEND_NONE_V2));
      }
      break;
    }
    case EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2: {
      const auto& record = event.record.device_error;
      setGpuV2OperationProperties(rt, value, record.operation);
      value.setProperty(
          rt,
          "uncapturedError",
          event.flags ==
              EXACT_GPU_SERVICE_EVENT_FLAG_UNCAPTURED_ERROR_V2);
      value.setProperty(
          rt, "errorKind", static_cast<double>(record.error_kind));
      value.setProperty(
          rt, "backendClass", static_cast<double>(record.backend_class));
      value.setProperty(rt, "status", record.status);
      break;
    }
    case EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2: {
      const auto& record = event.record.provider_loss;
      value.setProperty(
          rt,
          "runtimeAddress",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_address));
      value.setProperty(
          rt,
          "runtimeNonce",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_nonce));
      value.setProperty(
          rt, "topologyId", static_cast<double>(record.topology_id));
      value.setProperty(
          rt, "realmId", gpuV2Uint64String(rt, record.realm.realm_id));
      value.setProperty(
          rt,
          "realmGeneration",
          gpuV2Uint64String(rt, record.realm.realm_generation));
      value.setProperty(
          rt,
          "logicalDeviceId",
          gpuV2Uint64String(rt, record.device.logical_device_id));
      value.setProperty(
          rt,
          "logicalDeviceGeneration",
          gpuV2Uint64String(rt, record.device.logical_device_generation));
      value.setProperty(
          rt,
          "providerGeneration",
          gpuV2Uint64String(rt, record.device.provider_generation));
      value.setProperty(
          rt,
          "lastAcceptedPhysicalSequence",
          gpuV2Uint64String(rt, record.last_accepted_physical_sequence));
      value.setProperty(
          rt, "backendClass", static_cast<double>(record.backend_class));
      value.setProperty(
          rt, "lossReason", static_cast<double>(record.loss_reason));
      value.setProperty(
          rt,
          "hasInitiatingOperation",
          record.has_initiating_operation == 1);
      if (record.has_initiating_operation == 1) {
        facebook::jsi::Object initiating(rt);
        setGpuV2OperationProperties(
            rt, initiating, record.initiating_operation);
        value.setProperty(rt, "initiatingOperation", std::move(initiating));
      }
      break;
    }
    case EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2: {
      const auto& record = event.record.logical_device_lost;
      value.setProperty(
          rt,
          "runtimeAddress",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_address));
      value.setProperty(
          rt,
          "runtimeNonce",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_nonce));
      value.setProperty(
          rt, "topologyId", static_cast<double>(record.topology_id));
      value.setProperty(
          rt, "realmId", gpuV2Uint64String(rt, record.realm.realm_id));
      value.setProperty(
          rt,
          "realmGeneration",
          gpuV2Uint64String(rt, record.realm.realm_generation));
      value.setProperty(
          rt, "accountId", gpuV2Uint64String(rt, record.account.account_id));
      value.setProperty(
          rt,
          "accountGeneration",
          gpuV2Uint64String(rt, record.account.account_generation));
      std::vector<uint8_t> accountDigest(
          record.account.authority_digest,
          record.account.authority_digest +
              EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
      value.setProperty(
          rt,
          "accountAuthorityDigest",
          makeUint8Array(rt, std::move(accountDigest)));
      value.setProperty(
          rt,
          "logicalDeviceId",
          gpuV2Uint64String(rt, record.device.logical_device_id));
      value.setProperty(
          rt,
          "logicalDeviceGeneration",
          gpuV2Uint64String(rt, record.device.logical_device_generation));
      value.setProperty(
          rt,
          "providerGeneration",
          gpuV2Uint64String(rt, record.device.provider_generation));
      value.setProperty(
          rt,
          "logicalLossOrdinal",
          gpuV2Uint64String(rt, record.logical_loss_ordinal));
      value.setProperty(
          rt,
          "lastAcceptedPhysicalSequence",
          gpuV2Uint64String(rt, record.last_accepted_physical_sequence));
      value.setProperty(
          rt, "backendClass", static_cast<double>(record.backend_class));
      value.setProperty(
          rt, "lossReason", static_cast<double>(record.loss_reason));
      value.setProperty(
          rt,
          "hasInitiatingOperation",
          record.has_initiating_operation == 1);
      if (record.has_initiating_operation == 1) {
        facebook::jsi::Object initiating(rt);
        setGpuV2OperationProperties(
            rt, initiating, record.initiating_operation);
        value.setProperty(rt, "initiatingOperation", std::move(initiating));
      }
      break;
    }
    case EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2: {
      const auto& record = event.record.account_closed;
      value.setProperty(
          rt,
          "runtimeAddress",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_address));
      value.setProperty(
          rt,
          "runtimeNonce",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_nonce));
      value.setProperty(
          rt, "realmId", gpuV2Uint64String(rt, record.realm.realm_id));
      value.setProperty(
          rt,
          "realmGeneration",
          gpuV2Uint64String(rt, record.realm.realm_generation));
      value.setProperty(
          rt, "accountId", gpuV2Uint64String(rt, record.account.account_id));
      value.setProperty(
          rt,
          "accountGeneration",
          gpuV2Uint64String(rt, record.account.account_generation));
      std::vector<uint8_t> accountDigest(
          record.account.authority_digest,
          record.account.authority_digest +
              EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
      value.setProperty(
          rt,
          "accountAuthorityDigest",
          makeUint8Array(rt, std::move(accountDigest)));
      value.setProperty(
          rt, "closeOrdinal", gpuV2Uint64String(rt, record.close_ordinal));
      value.setProperty(
          rt, "closeReason", static_cast<double>(record.close_reason));
      break;
    }
    case EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2: {
      const auto& record = event.record.realm_closed;
      value.setProperty(
          rt,
          "runtimeAddress",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_address));
      value.setProperty(
          rt,
          "runtimeNonce",
          gpuV2Uint64String(rt, record.realm.runtime.runtime_nonce));
      value.setProperty(
          rt, "realmId", gpuV2Uint64String(rt, record.realm.realm_id));
      value.setProperty(
          rt,
          "realmGeneration",
          gpuV2Uint64String(rt, record.realm.realm_generation));
      value.setProperty(
          rt, "closeOrdinal", gpuV2Uint64String(rt, record.close_ordinal));
      value.setProperty(
          rt, "closeReason", static_cast<double>(record.close_reason));
      break;
    }
    default:
      break;
  }
  return value;
}

bool deliverGpuV2WrapperEvent(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    CopiedGpuEventV2& copied,
    bool retainPayloadForCaller = false) noexcept {
  if (!binding.wrapper_event_sink) {
    try {
      if (binding.deferred_wrapper_events.size() >= kMaxGpuQueuedEventsV2 ||
          copied.payload.size() >
              kMaxGpuPayloadBytesV2 - binding.deferred_wrapper_payload_bytes) {
        return false;
      }
      binding.deferred_wrapper_payload_bytes += copied.payload.size();
      if (retainPayloadForCaller) {
        binding.deferred_wrapper_events.push_back(copied);
      } else {
        CopiedGpuEventV2 deferred;
        deferred.event = copied.event;
        deferred.payload = std::move(copied.payload);
        binding.deferred_wrapper_events.push_back(std::move(deferred));
      }
      return true;
    } catch (...) {
      return false;
    }
  }
  try {
    auto event = retainPayloadForCaller
        ? makeGpuV2WrapperEvent(rt, copied.event, copied.payload)
        : makeGpuV2WrapperEvent(
              rt, copied.event, std::move(copied.payload));
    binding.wrapper_event_sink->call(rt, event);
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (binding.test_event_observer) {
      binding.test_event_observer->call(rt, event);
    }
#endif
    return true;
  } catch (...) {
    return false;
  }
}

bool flushGpuV2WrapperEvents(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt) noexcept {
  while (!binding.deferred_wrapper_events.empty()) {
    auto copied = std::move(binding.deferred_wrapper_events.front());
    binding.deferred_wrapper_events.pop_front();
    binding.deferred_wrapper_payload_bytes -= copied.payload.size();
    if (!deliverGpuV2WrapperEvent(binding, rt, copied)) {
      return false;
    }
  }
  return true;
}

void drainGpuMailboxV2(
    ExactGpuClientMailboxV2* mailbox,
    facebook::jsi::Runtime& rt) noexcept {
  if (!mailbox) return;
  auto* runtime = mailbox->target.runtime;
  if (!runtime || !runtime->gpu_binding_v2 ||
      runtime->gpu_binding_v2->mailbox != mailbox) {
    return;
  }
  auto& binding = *runtime->gpu_binding_v2;
  auto quarantineProtocolViolation = [&]() noexcept {
    (void)poisonGpuMailboxV2(mailbox);
    reduceGpuV2Realm(
        binding,
        rt,
        "protocol-violation",
        EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION,
        {},
        "Exact GPU V2 provider violated the event protocol",
        true);
  };
  if (mailbox->phase.load(std::memory_order_acquire) ==
      GpuMailboxPhaseV2::ProtocolViolation) {
    reduceGpuV2Realm(
        binding,
        rt,
        "protocol-violation",
        EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION,
        {},
        "Exact GPU V2 provider violated the event protocol",
        true);
    return;
  }

  for (;;) {
    CopiedGpuEventV2 copied;
    bool hasEvent = false;
    bool currentOperation = false;
    try {
      std::lock_guard<std::mutex> lock(mailbox->mutex);
      if (!mailbox->events.empty()) {
        copied = std::move(mailbox->events.front());
        mailbox->events.pop_front();
        mailbox->queued_payload_bytes -= copied.payload.size();
        hasEvent = true;
        if (const auto* operation = eventOperationV2(copied.event)) {
          auto ordinary =
              mailbox->submissions.find(operation->operation_instance_id);
          auto sealed = mailbox->sealed_submissions.find(
              operation->operation_instance_id);
          GpuSubmissionStateV2* submission = nullptr;
          if (ordinary != mailbox->submissions.end()) {
            submission = &ordinary->second;
          } else if (sealed != mailbox->sealed_submissions.end()) {
            submission = &sealed->second.submission;
          }
          if (submission && submission->event_queued &&
              equalProvenanceToSubmissionV2(
                  *operation, submission->call)) {
            auto retainedCall = submission->call;
            if (sealed != mailbox->sealed_submissions.end()) {
              mailbox->sealed_submissions.erase(sealed);
            } else {
              auto batch = mailbox->sealed_batches.find(
                  operation->operation_instance_id);
              if (batch != mailbox->sealed_batches.end()) {
                if (
                    batch->second.next_callback_index !=
                        batch->second.child_operation_instance_ids.size()) {
                  throw std::runtime_error(
                      "outer GPU terminal drained before sealed children");
                }
                for (const auto childId :
                     batch->second.child_operation_instance_ids) {
                  if (mailbox->sealed_submissions.count(childId) != 0) {
                    throw std::runtime_error(
                        "outer GPU terminal retained a sealed child");
                  }
                }
                mailbox->sealed_batches.erase(batch);
              }
              mailbox->submissions.erase(ordinary);
            }
            markTerminalV2(
                *mailbox,
                operation->operation_instance_id,
                &retainedCall,
                GpuTerminalCauseV2::CallbackAccepted,
                &copied.event,
                &copied.payload);
            currentOperation = true;
          }
        }
      }
    } catch (...) {
      quarantineProtocolViolation();
      return;
    }
    if (!hasEvent) return;
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    if (currentOperation) {
      uint32_t pauseExpected = 1;
      if (gGpuV2DrainPauseState.compare_exchange_strong(
              pauseExpected, 2, std::memory_order_seq_cst)) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (gGpuV2DrainPauseState.load(std::memory_order_seq_cst) == 2 &&
               std::chrono::steady_clock::now() < deadline) {
          std::this_thread::yield();
        }
        if (gGpuV2DrainPauseState.load(std::memory_order_seq_cst) == 2) {
          gGpuV2DrainPauseState.store(0, std::memory_order_seq_cst);
          quarantineProtocolViolation();
          return;
        }
        gGpuV2DrainPauseState.store(0, std::memory_order_seq_cst);
      }
    }
#endif
    if (mailbox->phase.load(std::memory_order_acquire) ==
        GpuMailboxPhaseV2::ProtocolViolation) {
      reduceGpuV2Realm(
          binding,
          rt,
          "protocol-violation",
          EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION,
          {},
          "Exact GPU V2 provider violated the event protocol",
          true);
      return;
    }
    auto& event = copied.event;

    if (event.kind == EXACT_GPU_SERVICE_EVENT_REALM_CLOSED_V2) {
      const auto record = event.record.realm_closed;
      binding.realm_open = false;
      reduceGpuV2Realm(
          binding,
          rt,
          "realm-closed",
          -static_cast<int32_t>(record.close_reason),
          copied.payload,
          "Exact GPU V2 realm closed",
          false);
      try {
        std::lock_guard<std::mutex> lock(mailbox->mutex);
        mailbox->events.clear();
        mailbox->queued_payload_bytes = 0;
      } catch (...) {
      }
      mailbox->phase.store(
          GpuMailboxPhaseV2::Closing, std::memory_order_release);
      if (!deliverGpuV2WrapperEvent(binding, rt, copied)) {
        return;
      }
      return;
    }

    // Provider loss is a physical cause/fanout input, not the logical
    // GPUDevice.lost settlement. Keep it observable by the private wrapper,
    // but do not terminalize any logical device or its pending operations.
    if (event.kind == EXACT_GPU_SERVICE_EVENT_PROVIDER_LOSS_V2) {
      if (!deliverGpuV2WrapperEvent(binding, rt, copied)) {
        quarantineProtocolViolation();
        return;
      }
      continue;
    }

    if (event.kind == EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2 ||
        event.kind == EXACT_GPU_SERVICE_EVENT_ACCOUNT_CLOSED_V2) {
      const bool deviceLost =
          event.kind == EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2;
      if (deviceLost) {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
        gGpuV2DeviceLossCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
      }
      // Lifecycle settlement is distinct from operation settlement. The
      // authenticated semantic service emits one typed terminal for each
      // affected positive operation while cleanup operations remain pending.
      if (!deliverGpuV2WrapperEvent(binding, rt, copied)) {
        quarantineProtocolViolation();
        return;
      }
      continue;
    }

    const auto* operation = eventOperationV2(event);
    if (!operation) {
      quarantineProtocolViolation();
      return;
    }
    if (!currentOperation) continue;
    // The generated wrapper owns the operation-specific typed result (for
    // example the adapter/device reference). Publish that full record before
    // settling the correlated Promise so a reaction can never observe a
    // carrier result whose object identity is still deferred. A throwing sink
    // quarantines while the receipt remains pending for realm reduction.
    const bool retainPayloadForReceipt =
        event.kind == EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2 &&
        operation->promise_id != 0;
    if (!deliverGpuV2WrapperEvent(
            binding, rt, copied, retainPayloadForReceipt)) {
      quarantineProtocolViolation();
      return;
    }
    if (operation->promise_id != 0) {
      auto pending = binding.pending_receipts.find(operation->promise_id);
      if (pending == binding.pending_receipts.end() ||
          pending->second.operation_instance_id !=
              operation->operation_instance_id) {
        quarantineProtocolViolation();
        return;
      }
      auto receipt = std::move(pending->second);
      binding.pending_receipts.erase(pending);
      if (event.kind == EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
        try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
          gGpuV2ResolveCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
          // The raw wrapper event is the sole typed result carrier. Promise
          // fulfillment is only an ordering signal, so mapped payload bytes
          // have exactly one external ArrayBuffer backing and are never
          // materialized a second time for an ignored receipt value.
          receipt.resolve->call(rt, facebook::jsi::Value::undefined());
        } catch (...) {
          rejectGpuV2Receipt(
              rt,
              std::move(receipt),
              "delivery-error",
              -1,
              0,
              {},
              "Exact GPU V2 result delivery failed");
        }
      } else {
        const auto& errorRecord = event.record.device_error;
        auto diagnosticPayload =
            tryMakeGpuV2DiagnosticPayload(rt, copied.payload);
        rejectGpuV2Receipt(
            rt,
            std::move(receipt),
            "device-error",
            errorRecord.status,
            errorRecord.error_kind,
            diagnosticPayload,
            "Exact GPU V2 device error");
      }
    }
  }
}

ExactGpuObjectRefV2 parseGpuV2Object(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& metadata,
    const char* prefix,
    bool allowAbsent) {
  const std::string kindName = std::string(prefix) + "Kind";
  const std::string idName = std::string(prefix) + "Id";
  const std::string generationName = std::string(prefix) + "Generation";
  ExactGpuObjectRefV2 object{};
  object.kind = parseGpuV2Uint32(
      rt,
      metadata.getProperty(rt, kindName.c_str()),
      kindName.c_str(),
      allowAbsent ? EXACT_GPU_OBJECT_NONE_V2 : EXACT_GPU_OBJECT_GPU_V2,
      EXACT_GPU_OBJECT_CANVAS_CONTEXT_V2);
  object.object_id = parseCanonicalGpuV2Uint64(
      rt, metadata.getProperty(rt, idName.c_str()), idName.c_str(), allowAbsent);
  object.object_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, generationName.c_str()),
      generationName.c_str(),
      allowAbsent);
  if (!validObjectV2(object, allowAbsent)) {
    throw facebook::jsi::JSError(rt, std::string(prefix) + " is not a full typed reference");
  }
  return object;
}

ExactGpuObjectRefV2 parseGpuV2NestedObject(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object object,
    const char* label) {
  ExactGpuObjectRefV2 result{};
  result.kind = parseGpuV2Uint32(
      rt,
      object.getProperty(rt, "kind"),
      label,
      EXACT_GPU_OBJECT_GPU_V2,
      EXACT_GPU_OBJECT_CANVAS_CONTEXT_V2);
  result.object_id = parseCanonicalGpuV2Uint64(
      rt, object.getProperty(rt, "id"), label, false);
  result.object_generation = parseCanonicalGpuV2Uint64(
      rt, object.getProperty(rt, "generation"), label, false);
  if (!validObjectV2(result, false)) {
    throw facebook::jsi::JSError(
        rt, std::string(label) + " is not a full typed reference");
  }
  return result;
}

std::string parseGpuV2Literal(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* label) {
  if (!value.isString()) {
    throw facebook::jsi::JSError(
        rt, std::string(label) + " must be a string");
  }
  return value.asString(rt).utf8(rt);
}

std::vector<ParsedGpuSealedOperationV2> parseGpuV2SealedOperations(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& metadata,
    const ExactGpuSemanticCallV2& parent) {
  auto value = metadata.getProperty(rt, "sealedOperations");
  if (!value.isObject() || !value.asObject(rt).isArray(rt)) {
    throw facebook::jsi::JSError(
        rt, "sealedOperations must be a bounded array");
  }
  auto array = value.asObject(rt).asArray(rt);
  const size_t count = array.size(rt);
  if (count > kMaxGpuPendingOperationsV2) {
    throw facebook::jsi::JSError(
        rt, "sealedOperations exceeds its reviewed bound");
  }
  std::vector<ParsedGpuSealedOperationV2> operations;
  operations.reserve(count);
  uint64_t previousOperationInstance = 0;
  uint64_t previousDeviceIngress = 0;
  for (size_t index = 0; index < count; ++index) {
    auto entryValue = array.getValueAtIndex(rt, index);
    if (!entryValue.isObject()) {
      throw facebook::jsi::JSError(
          rt, "sealedOperations entry must be an object");
    }
    auto entry = entryValue.asObject(rt);
    ParsedGpuSealedOperationV2 parsed;
    parsed.call = parent;
    parsed.call.operation_id = parseGpuV2Uint32(
        rt,
        entry.getProperty(rt, "operationId"),
        "sealed operationId",
        1,
        UINT32_MAX);
    parsed.call.operation_instance_id = parseCanonicalGpuV2Uint64(
        rt,
        entry.getProperty(rt, "operationInstanceId"),
        "sealed operationInstanceId",
        false);
    parsed.call.device_ingress_ordinal = parseCanonicalGpuV2Uint64(
        rt,
        entry.getProperty(rt, "deviceIngressOrdinal"),
        "sealed deviceIngressOrdinal",
        false);
    parsed.call.captured_scope_id = parseCanonicalGpuV2Uint64(
        rt,
        entry.getProperty(rt, "capturedScopeId"),
        "sealed capturedScopeId",
        true);
    parsed.call.promise_id = 0;
    parsed.call.adapter_ordinal = 0;
    parsed.call.queue_ingress_ordinal = 0;
    parsed.call.receiver = parseGpuV2NestedObject(
        rt,
        entry.getPropertyAsObject(rt, "receiver"),
        "sealed receiver");
    if (entry.hasProperty(rt, "target")) {
      parsed.call.target = parseGpuV2NestedObject(
          rt,
          entry.getPropertyAsObject(rt, "target"),
          "sealed target");
    } else {
      parsed.call.target = ExactGpuObjectRefV2{};
    }
    parsed.call.payload = nullptr;
    parsed.call.payload_len = 0;
    const auto identityClass = parseGpuV2Literal(
        rt, entry.getProperty(rt, "identityClass"), "sealed identityClass");
    const auto contextSource = parseGpuV2Literal(
        rt,
        entry.getProperty(rt, "authorityContextSource"),
        "sealed authorityContextSource");
    parsed.staged_local = identityClass == "staged-local";
    if (!parsed.staged_local && identityClass != "active-route") {
      throw facebook::jsi::JSError(
          rt, "sealed identityClass is not closed");
    }
    if (contextSource == "command-program") {
      parsed.authority_context_source =
          GpuSealedAuthorityContextSourceV2::CommandProgram;
    } else if (contextSource == "enclosing-carrier") {
      parsed.authority_context_source =
          GpuSealedAuthorityContextSourceV2::EnclosingCarrier;
    } else if (contextSource == "staged-record") {
      parsed.authority_context_source =
          GpuSealedAuthorityContextSourceV2::StagedRecord;
    } else {
      throw facebook::jsi::JSError(
          rt, "sealed authorityContextSource is not closed");
    }
    const bool enclosing =
        parsed.authority_context_source ==
        GpuSealedAuthorityContextSourceV2::EnclosingCarrier;
    if (enclosing) {
      if (entry.hasProperty(rt, "authorityContextDigest")) {
        throw facebook::jsi::JSError(
            rt, "enclosing-carrier child must omit its context digest");
      }
      std::fill(
          std::begin(parsed.call.authority_context_digest),
          std::end(parsed.call.authority_context_digest),
          0);
    } else {
      auto digest = parseGpuV2Bytes(
          rt,
          entry.getProperty(rt, "authorityContextDigest"),
          "sealed authorityContextDigest",
          EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2,
          EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
      std::copy(
          digest.begin(),
          digest.end(),
          parsed.call.authority_context_digest);
      if (!nonzeroDigestV2(parsed.call.authority_context_digest)) {
        throw facebook::jsi::JSError(
            rt, "sealed authorityContextDigest is zero");
      }
    }
    const bool routeAllowed =
        binding.allowed_operations.count(parsed.call.operation_id) != 0;
    if (
        parsed.call.operation_instance_id < (uint64_t{1} << 63) ||
        parsed.call.operation_instance_id <= previousOperationInstance ||
        parsed.call.device_ingress_ordinal <= previousDeviceIngress ||
        parsed.call.device_ingress_ordinal >= parent.device_ingress_ordinal ||
        (parsed.staged_local
             ? routeAllowed ||
                 parsed.authority_context_source !=
                     GpuSealedAuthorityContextSourceV2::StagedRecord
             : !routeAllowed ||
                 parsed.authority_context_source ==
                     GpuSealedAuthorityContextSourceV2::StagedRecord) ||
        !validObjectV2(parsed.call.receiver, false) ||
        !validObjectV2(parsed.call.target, true)) {
      throw facebook::jsi::JSError(
          rt, "sealed operation authority is malformed");
    }
    previousOperationInstance = parsed.call.operation_instance_id;
    previousDeviceIngress = parsed.call.device_ingress_ordinal;
    operations.push_back(std::move(parsed));
  }
  return operations;
}

ExactGpuSemanticCallV2 parseGpuV2Call(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    uint32_t operation,
    facebook::jsi::Object& metadata,
    std::vector<uint8_t>& authority,
    std::vector<uint8_t>& payload) {
  ExactGpuSemanticCallV2 call{};
  call.struct_size = sizeof(call);
  call.abi_version = EXACT_GPU_SERVICE_ABI_VERSION_V2;
  call.operation_id = operation;
  call.realm = binding.realm;
  call.account.account_id = parseCanonicalGpuV2Uint64(
      rt, metadata.getProperty(rt, "accountId"), "accountId", false);
  call.account.account_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "accountGeneration"),
      "accountGeneration",
      false);
  authority = parseGpuV2Bytes(
      rt,
      metadata.getProperty(rt, "authorityDigest"),
      "authorityDigest",
      EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2,
      EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
  std::copy(authority.begin(), authority.end(), call.account.authority_digest);
  call.ingress_device.logical_device_id = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "logicalDeviceId"),
      "logicalDeviceId",
      true);
  call.ingress_device.logical_device_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "logicalDeviceGeneration"),
      "logicalDeviceGeneration",
      true);
  call.ingress_device.provider_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "providerGeneration"),
      "providerGeneration",
      true);
  call.provider_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "operationProviderGeneration"),
      "operationProviderGeneration",
      true);
  call.captured_scope_id = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "capturedScopeId"),
      "capturedScopeId",
      true);
  call.adapter_ordinal = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "adapterOrdinal"),
      "adapterOrdinal",
      true);
  call.device_ingress_ordinal = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "deviceIngressOrdinal"),
      "deviceIngressOrdinal",
      true);
  call.queue_ingress_ordinal = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "queueIngressOrdinal"),
      "queueIngressOrdinal",
      true);
  call.receiver = parseGpuV2Object(rt, metadata, "receiver", false);
  call.target = parseGpuV2Object(rt, metadata, "target", true);
  call.topology_id = binding.topology_id;
  if (!validAccountV2(call.account) ||
      !validDeviceV2(call.ingress_device) ||
      (!deviceAbsentV2(call.ingress_device) &&
       (call.provider_generation == 0 ||
        call.provider_generation !=
            call.ingress_device.provider_generation))) {
    throw facebook::jsi::JSError(rt, "GPU V2 metadata identity is malformed");
  }
  call.payload = payload.empty() ? nullptr : payload.data();
  call.payload_len = payload.size();
  return call;
}

struct GpuPresentationAuthorityCarrierV2 {
  uint64_t acquire_session_id{0};
  uint64_t present_session_id{0};
  std::array<uint8_t, 32> authority_context_digest{};
};

GpuPresentationAuthorityCarrierV2 parseGpuPresentationAuthorityCarrierV2(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value) {
  if (!value.isObject()) {
    throw facebook::jsi::JSError(
        rt, "GPU presentation authority carrier must be an object");
  }
  auto object = value.asObject(rt);
  GpuPresentationAuthorityCarrierV2 carrier;
  carrier.acquire_session_id = parseCanonicalGpuV2Uint64(
      rt,
      object.getProperty(rt, "acquireSessionId"),
      "acquireSessionId",
      false);
  carrier.present_session_id = parseCanonicalGpuV2Uint64(
      rt,
      object.getProperty(rt, "presentSessionId"),
      "presentSessionId",
      false);
  auto digest = parseGpuV2Bytes(
      rt,
      object.getProperty(rt, "authorityContextDigest"),
      "authorityContextDigest",
      32,
      32);
  std::copy(
      digest.begin(),
      digest.end(),
      carrier.authority_context_digest.begin());
  if (carrier.acquire_session_id == carrier.present_session_id ||
      !nonzeroDigestV2(carrier.authority_context_digest.data())) {
    throw facebook::jsi::JSError(
        rt, "GPU presentation authority carrier is malformed");
  }
  return carrier;
}

ExactGpuSemanticCallV2 parseGpuPresentationAuthorityCallV2(
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    uint32_t operation,
    facebook::jsi::Object& metadata) {
  std::vector<uint8_t> authority;
  std::vector<uint8_t> payload;
  auto call =
      parseGpuV2Call(binding, rt, operation, metadata, authority, payload);
  call.operation_instance_id = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "operationInstanceId"),
      "operationInstanceId",
      false);
  call.promise_id = 0;
  if (!validRealmV2(call.realm) ||
      !equalRealmV2(call.realm, binding.realm) ||
      binding.allowed_operations.count(operation) == 0 ||
      call.operation_instance_id == 0 ||
      call.adapter_ordinal != 0 || call.queue_ingress_ordinal != 0 ||
      !validObjectV2(call.receiver, false) ||
      call.receiver.kind != EXACT_GPU_OBJECT_CANVAS_CONTEXT_V2 ||
      !validObjectV2(call.target, false) ||
      call.target.kind != EXACT_GPU_OBJECT_TEXTURE_V2) {
    throw facebook::jsi::JSError(
        rt, "GPU presentation authority metadata is malformed");
  }
  return call;
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value captureGpuPresentationAuthorityBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 2 ||
      !args[0].isNumber() || !args[1].isObject()) {
    throw facebook::jsi::JSError(
        rt, "capturePresentationAuthority requires operation and metadata");
  }
  auto& binding = *runtime->gpu_binding_v2;
  const auto operation = parseGpuV2Uint32(
      rt, args[0], "operationId", 1, std::numeric_limits<uint32_t>::max());
  auto metadata = args[1].asObject(rt);
  auto call =
      parseGpuPresentationAuthorityCallV2(binding, rt, operation, metadata);
  std::array<uint8_t, 32> digest{};
  uint64_t acquireSessionId = 0;
  uint64_t presentSessionId = 0;
  if (captureGpuAuthorityContextV2(
          runtime,
          call,
          digest.data(),
          &acquireSessionId,
          &presentSessionId) != EXACT_GPU_AUTHORITY_ALLOWED_V2) {
    return facebook::jsi::Value::null();
  }
  try {
    facebook::jsi::Object result(rt);
    defineGpuV2Property(
        rt,
        result,
        "acquireSessionId",
        gpuV2Uint64String(rt, acquireSessionId));
    defineGpuV2Property(
        rt,
        result,
        "presentSessionId",
        gpuV2Uint64String(rt, presentSessionId));
    std::vector<uint8_t> digestBytes(digest.begin(), digest.end());
    defineGpuV2Property(
        rt,
        result,
        "authorityContextDigest",
        makeUint8Array(rt, std::move(digestBytes)));
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "preventExtensions")
        .call(rt, result);
    return facebook::jsi::Value(std::move(result));
  } catch (...) {
    (void)ex_host_retire_exact_gpu_presentation_authority_v2(
        runtime->host_context_id,
        acquireSessionId,
        presentSessionId,
        digest.data());
    throw;
  }
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value recheckGpuPresentationAuthorityBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 3 ||
      !args[0].isNumber() || !args[1].isObject()) {
    throw facebook::jsi::JSError(
        rt,
        "recheckPresentationAuthority requires operation, metadata, and retained authority");
  }
  auto& binding = *runtime->gpu_binding_v2;
  const auto operation = parseGpuV2Uint32(
      rt, args[0], "operationId", 1, std::numeric_limits<uint32_t>::max());
  auto metadata = args[1].asObject(rt);
  auto call =
      parseGpuPresentationAuthorityCallV2(binding, rt, operation, metadata);
  const auto retained =
      parseGpuPresentationAuthorityCarrierV2(rt, args[2]);
  std::array<uint8_t, 32> recheckDigest{};
  const int32_t status = captureGpuAuthorityContextV2(
      runtime,
      call,
      recheckDigest.data(),
      nullptr,
      nullptr,
      retained.acquire_session_id,
      retained.present_session_id,
      retained.authority_context_digest.data());
  if (status == EXACT_GPU_AUTHORITY_ALLOWED_V2) {
    return facebook::jsi::Value(true);
  }
  if (status == EXACT_GPU_AUTHORITY_DENIED_V2) {
    return facebook::jsi::Value(false);
  }
  throw facebook::jsi::JSError(
      rt, "GPU presentation authority recheck failed structurally");
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value retireGpuPresentationAuthorityBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || count != 1) {
    throw facebook::jsi::JSError(
        rt, "retirePresentationAuthority requires retained authority");
  }
  const auto retained =
      parseGpuPresentationAuthorityCarrierV2(rt, args[0]);
  return facebook::jsi::Value(static_cast<double>(
      ex_host_retire_exact_gpu_presentation_authority_v2(
          runtime->host_context_id,
          retained.acquire_session_id,
          retained.present_session_id,
          retained.authority_context_digest.data())));
}

facebook::jsi::Value submitGpuV2Carrier(
    ExactHermesRuntime* runtime,
    ExactGpuRuntimeBindingV2& binding,
    facebook::jsi::Runtime& rt,
    ExactGpuSemanticCallV2 call,
    bool wantsPromise,
    std::vector<ParsedGpuSealedOperationV2> sealedOperations = {}) {
  if (!binding.wrapper_event_sink_set || !binding.wrapper_event_sink) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 requires its typed event sink before submit");
  }
  std::fill(
      std::begin(call.authority_context_digest),
      std::end(call.authority_context_digest),
      0);
  call.authority_session_id = 0;
  if (binding.allowed_operations.count(call.operation_id) == 0) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 operation is not in the authenticated profile");
  }
  if (!validRealmV2(call.realm) || !equalRealmV2(call.realm, binding.realm) ||
      !validAccountV2(call.account) ||
      !validDeviceV2(call.ingress_device) ||
      (!deviceAbsentV2(call.ingress_device) &&
       (call.provider_generation == 0 ||
        call.provider_generation !=
            call.ingress_device.provider_generation)) ||
      !validObjectV2(call.receiver, false) ||
      !validObjectV2(call.target, true) || call.flags != 0 ||
      call.reserved != 0 || call.topology_id != binding.topology_id ||
      call.payload_len > kMaxGpuPayloadBytesV2 ||
      (call.payload_len > 0 && !call.payload)) {
    throw facebook::jsi::JSError(rt, "GPU V2 call carrier is malformed");
  }
  // Do not blanket-reject calls after logical loss/account close. The
  // authenticated operation routing plan (known to the semantic service, but
  // represented here only by its digest) distinguishes forbidden positive
  // work from required release-after-revocation operations such as destroy,
  // unmap, cancel, and sweep. The service must make that per-operation decision
  // before provider admission; the carrier continues to enforce identities,
  // bounds, and provenance without guessing from an opaque operation ID.
  if (binding.next_operation_instance_id == 0 ||
      binding.next_operation_instance_id >= (uint64_t{1} << 63) ||
      (wantsPromise &&
       (binding.next_promise_id == 0 ||
        binding.next_promise_id == std::numeric_limits<uint64_t>::max()))) {
    throw facebook::jsi::JSError(rt, "GPU V2 identity space exhausted");
  }
  if (wantsPromise &&
      binding.pending_receipts.size() >= kMaxGpuPendingOperationsV2) {
    throw facebook::jsi::JSError(rt, "GPU V2 pending-operation budget exhausted");
  }

  call.operation_instance_id = binding.next_operation_instance_id;
  call.promise_id = wantsPromise ? binding.next_promise_id : 0;
  std::shared_ptr<GpuPromiseResolversV2> resolvers;
  facebook::jsi::Value receipt = facebook::jsi::Value::undefined();
  if (wantsPromise) {
    resolvers = std::make_shared<GpuPromiseResolversV2>();
    receipt = facebook::jsi::Value(rt, makeGpuV2Promise(rt, resolvers));
  }

  auto makeCarrier = [&](int32_t status) {
    facebook::jsi::Object carrier(rt);
    carrier.setProperty(
        rt,
        "operationInstanceId",
        gpuV2Uint64String(rt, call.operation_instance_id));
    carrier.setProperty(rt, "promiseId", gpuV2Uint64String(rt, call.promise_id));
    // This is semantic-service acceptance/tracking, not provider admission.
    // providerAdmission/physicalSequence arrive only in a typed terminal.
    carrier.setProperty(rt, "submissionStatus", status);
    carrier.setProperty(rt, "receipt", facebook::jsi::Value(rt, receipt));
    return facebook::jsi::Value(std::move(carrier));
  };
  // Build both non-fallible post-admission return carriers before publishing
  // the operation to provider code.
  auto successCarrier = makeCarrier(EXACT_GPU_PROVIDER_OK);
  auto protocolCarrier = makeCarrier(EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION);
  uint64_t serviceEntryReservation = 0;
  // Finish all batch-vector allocation before capturing the authority
  // session or publishing a Promise receipt. From that point onward every
  // potentially throwing insertion is covered by the rollback guard below.
  std::vector<uint64_t> insertedChildIds;
  insertedChildIds.reserve(sealedOperations.size());
  GpuSealedBatchStateV2 sealedBatch;
  sealedBatch.child_operation_instance_ids.reserve(sealedOperations.size());
  for (const auto& sealed : sealedOperations) {
    sealedBatch.child_operation_instance_ids.push_back(
        sealed.call.operation_instance_id);
  }

  if (captureGpuAuthorityContextV2(
          runtime,
          call,
          call.authority_context_digest,
          &call.authority_session_id) != EXACT_GPU_AUTHORITY_ALLOWED_V2 ||
      !nonzeroDigestV2(call.authority_context_digest) ||
      call.authority_session_id == 0) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 native authority-session capture failed closed");
  }
  for (auto& sealed : sealedOperations) {
    sealed.call.authority_session_id = call.authority_session_id;
    if (
        sealed.authority_context_source ==
        GpuSealedAuthorityContextSourceV2::EnclosingCarrier) {
      std::copy(
          std::begin(call.authority_context_digest),
          std::end(call.authority_context_digest),
          sealed.call.authority_context_digest);
    }
    if (
        !nonzeroDigestV2(sealed.call.authority_context_digest) ||
        sealed.call.authority_session_id == 0) {
      (void)ex_host_force_retire_exact_gpu_authority_session_v2(
          runtime->host_context_id, call.authority_session_id);
      throw facebook::jsi::JSError(
          rt, "GPU V2 sealed-operation authority stamping failed closed");
    }
  }

  if (wantsPromise) {
    try {
      auto [iterator, inserted] = binding.pending_receipts.emplace(
          call.promise_id,
          PendingGpuReceiptV2{
              call.operation_id,
              call.operation_instance_id,
              call.promise_id,
              call.account,
              call.ingress_device,
              resolvers->resolve,
              resolvers->reject});
      (void)iterator;
      if (!inserted) {
        (void)ex_host_force_retire_exact_gpu_authority_session_v2(
            runtime->host_context_id, call.authority_session_id);
        throw facebook::jsi::JSError(rt, "GPU V2 Promise ID is already pending");
      }
    } catch (...) {
      (void)ex_host_force_retire_exact_gpu_authority_session_v2(
          runtime->host_context_id, call.authority_session_id);
      throw;
    }
  }
  bool outerInserted = false;
  bool batchInserted = false;
  uint64_t previousSealedHighWater = 0;
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    previousSealedHighWater =
        binding.mailbox->highest_sealed_operation_instance_id;
    if (binding.mailbox->phase.load(std::memory_order_acquire) !=
            GpuMailboxPhaseV2::Live ||
        binding.mailbox->submissions.size() >= kMaxGpuPendingOperationsV2 ||
        sealedOperations.size() >
            kMaxGpuPendingOperationsV2 -
                binding.mailbox->sealed_submissions.size() ||
        (!sealedOperations.empty() &&
         binding.mailbox->sealed_batches.size() >=
             kMaxGpuPendingOperationsV2)) {
      throw facebook::jsi::JSError(rt, "GPU V2 realm no longer admits calls");
    }
    if (
        !sealedOperations.empty() &&
        sealedOperations.front().call.operation_instance_id <=
            previousSealedHighWater) {
      throw facebook::jsi::JSError(
          rt, "GPU V2 sealed-operation identity is stale");
    }
    for (const auto& sealed : sealedOperations) {
      if (
          binding.mailbox->sealed_submissions.count(
              sealed.call.operation_instance_id) != 0 ||
          terminalSlotV2(
              *binding.mailbox, sealed.call.operation_instance_id) !=
              kMaxGpuRecentTerminalsV2) {
        throw facebook::jsi::JSError(
            rt, "GPU V2 sealed-operation identity is already retained");
      }
    }
    serviceEntryReservation = reserveGpuServiceEntryLockedV2(
        *binding.mailbox, GpuServiceEntryKindV2::Submit);
    if (serviceEntryReservation == 0) {
      throw facebook::jsi::JSError(
          rt, "GPU V2 service-entry reservation failed closed");
    }
    GpuSubmissionStateV2 submission;
    submission.call = call;
    submission.call.payload = nullptr;
    submission.call.payload_len = 0;
    if (!binding.mailbox->submissions
             .emplace(call.operation_instance_id, submission)
             .second) {
      throw facebook::jsi::JSError(
          rt, "GPU V2 operation instance is already pending");
    }
    outerInserted = true;
    for (size_t index = 0; index < sealedOperations.size(); ++index) {
      GpuSealedSubmissionStateV2 child;
      child.submission.call = sealedOperations[index].call;
      child.parent_operation_instance_id = call.operation_instance_id;
      child.batch_index = index;
      child.staged_local = sealedOperations[index].staged_local;
      if (!binding.mailbox->sealed_submissions
               .emplace(
                   child.submission.call.operation_instance_id,
                   child)
               .second) {
        throw facebook::jsi::JSError(
            rt, "GPU V2 sealed-operation identity is already pending");
      }
      insertedChildIds.push_back(
          child.submission.call.operation_instance_id);
    }
    if (!sealedOperations.empty()) {
      sealedBatch.previous_highest_operation_instance_id =
          previousSealedHighWater;
      if (!binding.mailbox->sealed_batches
               .emplace(call.operation_instance_id, std::move(sealedBatch))
               .second) {
        throw facebook::jsi::JSError(
            rt, "GPU V2 sealed-operation batch is already pending");
      }
      batchInserted = true;
      binding.mailbox->highest_sealed_operation_instance_id =
          sealedOperations.back().call.operation_instance_id;
    }
    binding.mailbox->highest_operation_instance_id =
        call.operation_instance_id;
    ++binding.next_operation_instance_id;
    if (wantsPromise) ++binding.next_promise_id;
  } catch (...) {
    try {
      std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
      if (batchInserted) {
        binding.mailbox->sealed_batches.erase(call.operation_instance_id);
      }
      for (const auto childId : insertedChildIds) {
        binding.mailbox->sealed_submissions.erase(childId);
      }
      if (outerInserted) {
        binding.mailbox->submissions.erase(call.operation_instance_id);
      }
      binding.mailbox->highest_sealed_operation_instance_id =
          previousSealedHighWater;
    } catch (...) {
      (void)poisonGpuMailboxV2(binding.mailbox);
    }
    releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
    if (wantsPromise) binding.pending_receipts.erase(call.promise_id);
    (void)ex_host_force_retire_exact_gpu_authority_session_v2(
        runtime->host_context_id, call.authority_session_id);
    throw;
  }

  int32_t admission = -1;
  if (pauseReservedGpuV2ServiceEntryForTest(
          binding.mailbox, GpuServiceEntryKindV2::Submit)) {
    try {
      admission = binding.api.submit(binding.api.service_context, &call);
    } catch (...) {
      ex_host_console_log(
          1, "Exact GPU V2 service submit threw across its C ABI");
    }
  }
  releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
  if (binding.mailbox->phase.load(std::memory_order_acquire) ==
      GpuMailboxPhaseV2::ProtocolViolation) {
    // A synchronous callback is part of the service call. Its protocol
    // violation dominates both an acceptance and a service rejection; retain
    // the Promise/submission so the owner drain settles it as a realm failure.
    (void)ex_host_force_retire_exact_gpu_authority_session_v2(
        runtime->host_context_id, call.authority_session_id);
    return protocolCarrier;
  }
  if (admission == 0 &&
      ex_host_exact_gpu_authority_session_requested_v2(
          runtime->host_context_id, call.authority_session_id) != 1) {
    (void)ex_host_force_retire_exact_gpu_authority_session_v2(
        runtime->host_context_id, call.authority_session_id);
    (void)poisonGpuMailboxV2(binding.mailbox);
    return protocolCarrier;
  }
  if (admission == 0) return successCarrier;

  (void)ex_host_force_retire_exact_gpu_authority_session_v2(
      runtime->host_context_id, call.authority_session_id);

  bool callbackThenRejection = false;
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    auto submission =
        binding.mailbox->submissions.find(call.operation_instance_id);
    auto batch =
        binding.mailbox->sealed_batches.find(call.operation_instance_id);
    if (submission == binding.mailbox->submissions.end()) {
      callbackThenRejection = true;
    } else if (
        submission->second.event_queued ||
        submission->second.initiating_observed) {
      callbackThenRejection = true;
    } else if (batch != binding.mailbox->sealed_batches.end()) {
      for (const auto childId :
           batch->second.child_operation_instance_ids) {
        auto child = binding.mailbox->sealed_submissions.find(childId);
        if (
            child == binding.mailbox->sealed_submissions.end() ||
            child->second.submission.event_queued ||
            child->second.submission.initiating_observed) {
          callbackThenRejection = true;
          break;
        }
      }
    }
    if (!callbackThenRejection) {
      binding.mailbox->submissions.erase(submission);
      markTerminalV2(
          *binding.mailbox,
          call.operation_instance_id,
          &call,
          GpuTerminalCauseV2::ServiceRejected,
          nullptr,
          nullptr);
      if (batch != binding.mailbox->sealed_batches.end()) {
        const auto childIds = batch->second.child_operation_instance_ids;
        const auto previousHigh =
            batch->second.previous_highest_operation_instance_id;
        const auto batchLast = childIds.empty() ? 0 : childIds.back();
        for (const auto childId : childIds) {
          binding.mailbox->sealed_submissions.erase(childId);
        }
        binding.mailbox->sealed_batches.erase(batch);
        if (
            batchLast != 0 &&
            binding.mailbox->highest_sealed_operation_instance_id ==
                batchLast) {
          binding.mailbox->highest_sealed_operation_instance_id =
              previousHigh;
        } else if (batchLast != 0) {
          callbackThenRejection = true;
        }
      }
    }
  } catch (...) {
    callbackThenRejection = true;
  }
  if (callbackThenRejection) {
    (void)poisonGpuMailboxV2(binding.mailbox);
    return protocolCarrier;
  }
  if (wantsPromise) {
    auto pending = binding.pending_receipts.find(call.promise_id);
    if (pending != binding.pending_receipts.end()) {
      auto receiptValue = std::move(pending->second);
      binding.pending_receipts.erase(pending);
      rejectGpuV2Receipt(
          rt,
          std::move(receiptValue),
          "admission-rejected",
          admission,
          0,
          {},
          "Exact GPU V2 service rejected the semantic call");
    }
  }
  return makeCarrier(admission);
}

size_t parseGpuV2MappedArrayBufferIndex(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value,
    const char* label) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(rt, std::string(label) + " must be a number");
  }
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 0 || std::floor(number) != number ||
      number > static_cast<double>(std::numeric_limits<uint32_t>::max())) {
    throw facebook::jsi::JSError(
        rt, std::string(label) + " must be an unsigned 32-bit integer");
  }
  return static_cast<size_t>(number);
}

bool hasGpuV2MappedArrayBufferApi(facebook::jsi::Runtime& rt) noexcept {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  if (gGpuV2MappedArrayBufferGateFailure.load(std::memory_order_seq_cst) == 1) {
    return false;
  }
#endif
#if !defined(EXACT_HAVE_WEBGPU_MAPPED_ARRAY_BUFFER)
  (void)rt;
  return false;
#else
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  if (gGpuV2MappedArrayBufferGateFailure.load(std::memory_order_seq_cst) == 2) {
    return false;
  }
#endif
  return facebook::jsi::castInterface<
             facebook::hermes::IExactWebGpuArrayBuffer>(&rt) != nullptr;
#endif
}

#if defined(EXACT_HAVE_WEBGPU_MAPPED_ARRAY_BUFFER)
facebook::hermes::IExactWebGpuArrayBuffer* requireGpuV2MappedArrayBufferApi(
    facebook::jsi::Runtime& rt) {
  auto* api = facebook::jsi::castInterface<
      facebook::hermes::IExactWebGpuArrayBuffer>(&rt);
  if (!api) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 mapped ArrayBuffer engine capability is unavailable");
  }
  return api;
}
#endif

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value submitGpuV2BridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 4 ||
      !args[1].isBool() || !args[2].isObject()) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 submit requires operationId, wantsPromise, metadata, payload");
  }
  auto& binding = *runtime->gpu_binding_v2;
  const uint32_t operation = parseGpuV2Uint32(
      rt, args[0], "operationId", 1, UINT32_MAX);
  auto metadata = args[2].asObject(rt);
  auto payload = parseGpuV2Bytes(
      rt, args[3], "payload", kMaxGpuPayloadBytesV2);
  std::vector<uint8_t> authority;
  auto call = parseGpuV2Call(
      binding, rt, operation, metadata, authority, payload);
  auto sealedOperations = parseGpuV2SealedOperations(
      binding, rt, metadata, call);
  return submitGpuV2Carrier(
      runtime,
      binding,
      rt,
      call,
      args[1].getBool(),
      std::move(sealedOperations));
}

facebook::jsi::Value cancelGpuV2CarrierCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 2) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 cancel requires operationInstanceId and promiseId");
  }
  auto& binding = *runtime->gpu_binding_v2;
  const uint64_t operationInstance = parseCanonicalGpuV2Uint64(
      rt, args[0], "operationInstanceId", false);
  const uint64_t promiseId =
      parseCanonicalGpuV2Uint64(rt, args[1], "promiseId", true);
  if (promiseId != 0) {
    auto pending = binding.pending_receipts.find(promiseId);
    if (pending != binding.pending_receipts.end() &&
        pending->second.operation_instance_id != operationInstance) {
      (void)poisonGpuMailboxV2(binding.mailbox);
      return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    }
  }
  ExactGpuSemanticCallV2 retainedCall{};
  ExactGpuOperationProvenanceV2 retainedInitiating{};
  bool initiatingObserved = false;
  bool cancellationWon = false;
  uint64_t serviceEntryReservation = 0;
  try {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    if (binding.mailbox->phase.load(std::memory_order_acquire) !=
        GpuMailboxPhaseV2::Live) {
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    }
    auto submission = binding.mailbox->submissions.find(operationInstance);
    if (submission == binding.mailbox->submissions.end()) {
      const auto* terminal = terminalCallV2(*binding.mailbox, operationInstance);
      return terminal && terminal->promise_id == promiseId ? 0 : -1;
    }
    if (submission->second.call.promise_id != promiseId) return -1;
    // Linearize the race while holding the one mailbox lock. A terminal that
    // was already accepted wins and cancellation is an idempotent no-op.
    // Otherwise cancellation removes the live key and installs its full
    // tombstone before calling service code, so every later callback loses.
    if (submission->second.event_queued) return 0;
    serviceEntryReservation = reserveGpuServiceEntryLockedV2(
        *binding.mailbox, GpuServiceEntryKindV2::Cancel);
    if (serviceEntryReservation == 0) {
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    }
    retainedCall = submission->second.call;
    initiatingObserved = submission->second.initiating_observed;
    if (initiatingObserved) {
      retainedInitiating = submission->second.initiating_provenance;
    }
    binding.mailbox->submissions.erase(submission);
    markTerminalV2(
        *binding.mailbox,
        operationInstance,
        &retainedCall,
        GpuTerminalCauseV2::CancelWon,
        nullptr,
        nullptr,
        initiatingObserved ? &retainedInitiating : nullptr);
    cancellationWon = true;
  } catch (...) {
    releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
    (void)poisonGpuMailboxV2(binding.mailbox);
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  if (!cancellationWon) return -1;
  if (promiseId != 0) {
    auto pending = binding.pending_receipts.find(promiseId);
    if (pending == binding.pending_receipts.end() ||
        pending->second.operation_instance_id != operationInstance) {
      releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
      (void)poisonGpuMailboxV2(binding.mailbox);
      return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    }
  }
  auto cancel = makeGpuCancelV2(retainedCall);
  int32_t status = -1;
  if (pauseReservedGpuV2ServiceEntryForTest(
          binding.mailbox, GpuServiceEntryKindV2::Cancel)) {
    try {
      status = binding.api.cancel(binding.api.service_context, &cancel);
    } catch (...) {
      ex_host_console_log(
          1, "Exact GPU V2 service cancel threw across its C ABI");
    }
  }
  releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
  if (binding.mailbox->phase.load(std::memory_order_acquire) ==
      GpuMailboxPhaseV2::ProtocolViolation) {
    // Leave the pending receipt for realm reduction. Cancellation already won
    // its operation key, but it must not publicly settle as `cancelled` after
    // a synchronous provider callback quarantined the realm.
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  if (status != 0) {
    // A valid full-key cancellation is an infallible semantic acknowledgement;
    // hardware may continue cleanup, but the service cannot refuse ownership.
    (void)poisonGpuMailboxV2(binding.mailbox);
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }

  if (promiseId != 0) {
    auto pending = binding.pending_receipts.find(promiseId);
    if (pending == binding.pending_receipts.end() ||
        pending->second.operation_instance_id != operationInstance) {
      (void)poisonGpuMailboxV2(binding.mailbox);
      return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    }
    auto receipt = std::move(pending->second);
    binding.pending_receipts.erase(pending);
    rejectGpuV2Receipt(
        rt,
        std::move(receipt),
        "cancelled",
        0,
        0,
        {},
        "Exact GPU V2 operation was cancelled");
  }
  return 0;
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value cancelGpuV2BridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  return cancelGpuV2CarrierCall(runtime, rt, args, count);
}

int32_t retireGpuV2Carrier(
    ExactGpuRuntimeBindingV2& binding,
    const ExactGpuRetireBatchV2& batch) noexcept {
  uint64_t serviceEntryReservation = 0;
  try {
    {
      std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
      if (binding.mailbox->phase.load(std::memory_order_acquire) !=
              GpuMailboxPhaseV2::Live ||
          !binding.realm_open) {
        return EXACT_GPU_PROVIDER_INVALID_STATE;
      }
      serviceEntryReservation = reserveGpuServiceEntryLockedV2(
          *binding.mailbox, GpuServiceEntryKindV2::Retire);
      if (serviceEntryReservation == 0) {
        return EXACT_GPU_PROVIDER_INVALID_STATE;
      }
      // The reservation under the callback-admission mutex is the exact
      // service-entry linearization point. A realm terminal accepted first
      // closes this gate; a retire reserved first may finish without holding
      // the mutex across reentrant provider code.
    }
    int32_t status = EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    if (pauseReservedGpuV2ServiceEntryForTest(
            binding.mailbox, GpuServiceEntryKindV2::Retire)) {
      status = binding.api.retire(
          binding.api.service_context, &binding.realm, &batch);
    }
    releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
    if (binding.mailbox->phase.load(std::memory_order_acquire) ==
        GpuMailboxPhaseV2::ProtocolViolation) {
      return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    }
    return status;
  } catch (...) {
    releaseGpuServiceEntryV2(*binding.mailbox, serviceEntryReservation);
    ex_host_console_log(1, "Exact GPU V2 service retire threw across its C ABI");
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
}

ExactGpuOwnedObjectRefV2 parseGpuV2OwnedObject(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object& metadata) {
  ExactGpuOwnedObjectRefV2 owned{};
  owned.account.account_id = parseCanonicalGpuV2Uint64(
      rt, metadata.getProperty(rt, "accountId"), "accountId", false);
  owned.account.account_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "accountGeneration"),
      "accountGeneration",
      false);
  auto digest = parseGpuV2Bytes(
      rt,
      metadata.getProperty(rt, "authorityDigest"),
      "authorityDigest",
      EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2,
      EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
  std::copy(digest.begin(), digest.end(), owned.account.authority_digest);
  owned.device.logical_device_id = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "logicalDeviceId"),
      "logicalDeviceId",
      true);
  owned.device.logical_device_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "logicalDeviceGeneration"),
      "logicalDeviceGeneration",
      true);
  owned.device.provider_generation = parseCanonicalGpuV2Uint64(
      rt,
      metadata.getProperty(rt, "providerGeneration"),
      "providerGeneration",
      true);
  owned.object = parseGpuV2Object(rt, metadata, "object", false);
  if (!validAccountV2(owned.account) || !validDeviceV2(owned.device)) {
    throw facebook::jsi::JSError(rt, "GPU V2 retire identity is malformed");
  }
  return owned;
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value retireGpuV2BridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 1 ||
      !args[0].isObject() || !args[0].asObject(rt).isArray(rt)) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 retire requires an array of full typed references");
  }
  auto array = args[0].asObject(rt).asArray(rt);
  const size_t objectCount = array.size(rt);
  if (objectCount == 0 || objectCount > kMaxGpuRetireObjectsV2) {
    throw facebook::jsi::JSError(rt, "GPU V2 retire batch is empty or too large");
  }
  std::vector<ExactGpuOwnedObjectRefV2> objects;
  objects.reserve(objectCount);
  for (size_t index = 0; index < objectCount; ++index) {
    auto value = array.getValueAtIndex(rt, index);
    if (!value.isObject()) {
      throw facebook::jsi::JSError(rt, "GPU V2 retire entry must be an object");
    }
    auto metadata = value.asObject(rt);
    auto owned = parseGpuV2OwnedObject(rt, metadata);
    const bool duplicate = std::any_of(
        objects.begin(),
        objects.end(),
        [&](const ExactGpuOwnedObjectRefV2& prior) {
          return equalAccountV2(prior.account, owned.account) &&
              equalDeviceV2(prior.device, owned.device) &&
              equalObjectV2(prior.object, owned.object);
        });
    if (duplicate) {
      throw facebook::jsi::JSError(rt, "GPU V2 retire batch contains a duplicate");
    }
    objects.push_back(owned);
  }
  ExactGpuRetireBatchV2 batch = {
      sizeof(ExactGpuRetireBatchV2),
      EXACT_GPU_SERVICE_ABI_VERSION_V2,
      0,
      0,
      objects.data(),
      objects.size(),
  };
  return retireGpuV2Carrier(*runtime->gpu_binding_v2, batch);
}

facebook::jsi::Value setGpuV2EventSinkCarrierCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (!runtime || !runtime->gpu_binding_v2 || count != 1 ||
      !args[0].isObject() || !args[0].asObject(rt).isFunction(rt)) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 setEventSink requires one function");
  }
  auto& binding = *runtime->gpu_binding_v2;
  auto sink = std::make_shared<facebook::jsi::Function>(
      args[0].asObject(rt).asFunction(rt));
  {
    std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
    if (binding.mailbox->phase.load(std::memory_order_acquire) !=
            GpuMailboxPhaseV2::Live ||
        !binding.realm_open) {
      throw facebook::jsi::JSError(
          rt, "GPU V2 realm no longer admits an event sink");
    }
    if (binding.wrapper_event_sink_set) {
      throw facebook::jsi::JSError(
          rt, "GPU V2 event sink is already installed");
    }
    binding.wrapper_event_sink = std::move(sink);
    binding.wrapper_event_sink_set = true;
  }
  if (!flushGpuV2WrapperEvents(binding, rt)) {
    (void)poisonGpuMailboxV2(binding.mailbox);
    throw facebook::jsi::JSError(
        rt, "GPU V2 event sink failed during bounded backlog delivery");
  }
  return facebook::jsi::Value::undefined();
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value setGpuV2EventSinkBridgeCall(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  return setGpuV2EventSinkCarrierCall(runtime, rt, args, count);
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value createGpuV2MappedRangeAliasBridgeCall(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (count != 3 || !args[0].isObject()) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 createMappedRangeAlias requires an ArrayBuffer and range");
  }
#if !defined(EXACT_HAVE_WEBGPU_MAPPED_ARRAY_BUFFER)
  (void)args;
  throw facebook::jsi::JSError(
      rt, "GPU V2 mapped ArrayBuffer engine capability is unavailable");
#else
  auto sourceObject = args[0].asObject(rt);
  if (!sourceObject.isArrayBuffer(rt)) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 mapped range source must be an ArrayBuffer");
  }
  const size_t byteOffset = parseGpuV2MappedArrayBufferIndex(
      rt, args[1], "GPU V2 mapped range byteOffset");
  const size_t byteLength = parseGpuV2MappedArrayBufferIndex(
      rt, args[2], "GPU V2 mapped range byteLength");
  auto source = sourceObject.getArrayBuffer(rt);
  auto alias = requireGpuV2MappedArrayBufferApi(rt)
                   ->createWebGpuMappedRangeAlias(
                       source, byteOffset, byteLength);
  return facebook::jsi::Value(rt, std::move(alias));
#endif
}

#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif

facebook::jsi::Value detachGpuV2MappedRangeBridgeCall(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value* args,
    size_t count) {
  if (count != 1 || !args[0].isObject()) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 detachMappedRange requires one ArrayBuffer");
  }
#if !defined(EXACT_HAVE_WEBGPU_MAPPED_ARRAY_BUFFER)
  (void)args;
  throw facebook::jsi::JSError(
      rt, "GPU V2 mapped ArrayBuffer engine capability is unavailable");
#else
  auto bufferObject = args[0].asObject(rt);
  if (!bufferObject.isArrayBuffer(rt)) {
    throw facebook::jsi::JSError(
        rt, "GPU V2 mapped range detach target must be an ArrayBuffer");
  }
  auto buffer = bufferObject.getArrayBuffer(rt);
  return facebook::jsi::Value(
      requireGpuV2MappedArrayBufferApi(rt)->detachWebGpuMappedRange(buffer));
#endif
}

#endif

}  // namespace

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
ExactGpuDecodedImageRuntimeBindingV1::~ExactGpuDecodedImageRuntimeBindingV1() {
  detach(nullptr, "Decoded-image binding destroyed");
}

void ExactGpuDecodedImageRuntimeBindingV1::detach(ExactHermesRuntime *runtime,
                                                  const char *reason) noexcept {
  std::vector<std::pair<ExactGpuDecodedImageIdentityV1, uint64_t>>
      cancellations;
  std::vector<std::shared_ptr<DecodedImagePromiseResolversV1>> rejections;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (!active && !context_retained)
      return;
    active = false;
    cancellations.reserve(pending.size());
    rejections.reserve(pending.size());
    for (auto &entry : pending) {
      if (!entry.second.completion_queued) {
        cancellations.emplace_back(entry.second.identity, entry.first);
      }
      rejections.push_back(std::move(entry.second.resolvers));
    }
    pending.clear();
    pending_encoded_bytes = 0;
    queued_decoded_bytes = 0;
    owner_drain_required.store(false, std::memory_order_release);
  }
  for (const auto &cancellation : cancellations) {
    forgetDecodedImageRequestTargetV1(cancellation.second);
    try {
      api.cancel_decode(api.host_context, &cancellation.first,
                        cancellation.second);
    } catch (...) {
      ex_host_console_log(1,
                          "Decoded-image host cancel threw across its C ABI");
    }
  }
  if (runtime && runtime->runtime) {
    for (const auto &resolvers : rejections) {
      rejectDecodedImageV1(*runtime->runtime, resolvers, reason);
    }
  }
  if (context_retained && api.release_context) {
    try {
      api.release_context(api.host_context);
    } catch (...) {
      ex_host_console_log(1,
                          "Decoded-image host release threw across its C ABI");
    }
    context_retained = false;
  }
}

ExactGpuRuntimeBindingV2::~ExactGpuRuntimeBindingV2() {
  detach(nullptr, "Exact GPU V2 binding destroyed");
}

void ExactGpuRuntimeBindingV2::detach(
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
  canvas_receipt_sink.reset();
  host_task_checkpoint.reset();
  canvas_app_bundle_begin.reset();
  canvas_app_bundle_finish.reset();
  canvas_app_bundle_capture.reset();
  canvas_app_bundle_expectation = 0;
  canvas_app_bundle_prepared = false;
  canvas_app_bundle_open = false;
  canvas_app_bundle_committed = false;
  private_bridge.reset();
  wrapper_event_sink.reset();
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
  test_event_observer.reset();
#endif
  deferred_wrapper_events.clear();
  deferred_wrapper_payload_bytes = 0;
  bridge_captured = false;
  decoded_image_authority_attached = false;
  if (!closeGpuV2ConstructionCapture(runtime) && runtime &&
      !runtime->user_execution_started) {
    runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
  }

  std::vector<ExactGpuSemanticCallV2> cancellations;
  bool realmTerminalAccepted = false;
  if (mailbox) {
    try {
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
      if (gGpuV2RealmCloseAdmissionPauseState.load(
              std::memory_order_seq_cst) == 2) {
        gGpuV2DetachLockAttempted.store(1, std::memory_order_seq_cst);
      }
#endif
      std::lock_guard<std::mutex> lock(mailbox->mutex);
      // This mutex is also the callback-admission linearization point. If the
      // service terminal won it, teardown must not echo cancellation/close;
      // if teardown wins it, Closing fences the callback before it can admit.
      realmTerminalAccepted = mailbox->realm_terminal_accepted.load(
          std::memory_order_acquire);
      mailbox->phase.store(
          GpuMailboxPhaseV2::Closing, std::memory_order_release);
      cancellations.reserve(mailbox->submissions.size());
      for (const auto& entry : mailbox->submissions) {
        if (!realmTerminalAccepted) {
          cancellations.push_back(entry.second.call);
        }
        markTerminalV2(
            *mailbox,
            entry.first,
            &entry.second.call,
            GpuTerminalCauseV2::Teardown,
            nullptr,
            nullptr);
      }
      mailbox->submissions.clear();
      for (const auto& entry : mailbox->sealed_submissions) {
        markTerminalV2(
            *mailbox,
            entry.first,
            &entry.second.submission.call,
            GpuTerminalCauseV2::Teardown,
            nullptr,
            nullptr);
      }
      mailbox->sealed_submissions.clear();
      mailbox->sealed_batches.clear();
      mailbox->events.clear();
      mailbox->queued_payload_bytes = 0;
    } catch (...) {
    }
  }
  (void)pauseGpuV2DetachCleanupForTest();
  auto receipts = std::move(pending_receipts);
  pending_receipts.clear();
  for (const auto& cancellation : cancellations) {
    cancelGpuV2OutsideLocks(*this, cancellation);
  }
  if (runtime && runtime->runtime) {
    for (auto& entry : receipts) {
      rejectGpuV2Receipt(
          *runtime->runtime,
          std::move(entry.second),
          "realm-closed",
          -1,
          0,
          {},
          reason ? reason : "Exact GPU V2 realm closed");
    }
  }
  if (realm_open && api.close_realm && !realmTerminalAccepted) {
    try {
      (void)api.close_realm(api.service_context, &realm, 1);
    } catch (...) {
      ex_host_console_log(1, "Exact GPU V2 close_realm threw across its C ABI");
    }
  }
  realm_open = false;
  if (mailbox) {
    mailbox->phase.store(GpuMailboxPhaseV2::Detached, std::memory_order_release);
  }
  if (service_retained && api.release_service) {
    try {
      api.release_service(api.service_context);
    } catch (...) {
      ex_host_console_log(1, "Exact GPU V2 release_service threw across its C ABI");
    }
    service_retained = false;
  }
  if (mailbox) {
    releaseGpuClientV2(mailbox);
    mailbox = nullptr;
  }
}
#endif

extern "C" uint32_t ex_hermes_gpu_decoded_image_abi_version_v1(void) {
  return EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1;
}

extern "C" size_t ex_hermes_gpu_decoded_image_descriptor_size_v1(void) {
  return sizeof(ExactHermesGpuDecodedImageDescriptorV1);
}

extern "C" int32_t ex_hermes_set_gpu_decoded_image_provider_v1(
    ExactHermesRuntime *runtime,
    const ExactHermesGpuDecodedImageDescriptorV1 *descriptor) {
  if (!runtime || !runtime->runtime)
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  if (runtime->runtime_thread != std::this_thread::get_id()) {
    return EXACT_GPU_PROVIDER_WRONG_THREAD;
  }
  if (runtime->restricted)
    return EXACT_GPU_PROVIDER_RESTRICTED_RUNTIME;
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)descriptor;
  return EXACT_GPU_PROVIDER_UNSUPPORTED;
#else
  if (runtime->embedder_capability_state !=
      EmbedderCapabilityState::Configuring) {
    return EXACT_GPU_PROVIDER_INVALID_STATE;
  }
  if (runtime->gpu_decoded_image_binding_v1) {
    return EXACT_GPU_PROVIDER_ALREADY_INSTALLED;
  }
  if (!descriptor || descriptor->struct_size !=
                         sizeof(ExactHermesGpuDecodedImageDescriptorV1)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  if (descriptor->abi_version != EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1) {
    return EXACT_GPU_PROVIDER_ABI_MISMATCH;
  }
  if (descriptor->flags != 0 || !descriptor->api ||
      descriptor->api->struct_size != sizeof(ExactGpuDecodedImageHostApiV1) ||
      descriptor->api->abi_version != EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1 ||
      !descriptor->api->host_context || !descriptor->api->retain_context ||
      !descriptor->api->release_context || !descriptor->api->begin_decode ||
      !descriptor->api->cancel_decode) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  try {
    auto binding = std::make_shared<ExactGpuDecodedImageRuntimeBindingV1>();
    binding->api = *descriptor->api;
    binding->target = exactRuntimeCallbackTarget(runtime);
    binding->api.retain_context(binding->api.host_context);
    binding->context_retained = true;
    runtime->gpu_decoded_image_binding_v1 = std::move(binding);
  } catch (...) {
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  return EXACT_GPU_PROVIDER_OK;
#endif
}

extern "C" int32_t ex_hermes_complete_gpu_decoded_image_v1(
    uint64_t request_id, uint32_t status,
    const ExactGpuDecodedImagePlaneV1 *plane) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)request_id;
  (void)status;
  (void)plane;
  return EXACT_GPU_PROVIDER_UNSUPPORTED;
#else
  std::shared_ptr<ExactGpuDecodedImageRuntimeBindingV1> fallbackBinding;
  try {
    if (request_id == 0 ||
        (status != EXACT_GPU_DECODED_IMAGE_COMPLETE_V1 &&
         status != EXACT_GPU_DECODED_IMAGE_DECODE_FAILED_V1 &&
         status != EXACT_GPU_DECODED_IMAGE_CANCELLED_V1)) {
      return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
    }
    auto targetEntry = takeDecodedImageRequestTargetV1(request_id);
    if (!targetEntry)
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    auto binding = targetEntry->binding.lock();
    if (!binding)
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    fallbackBinding = binding;
    ScopedDecodedImageRuntimePinV1 runtimePin(targetEntry->target);
    if (!runtimePin) {
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    }

    uint32_t terminalStatus = status;
    size_t decodedLength = 0;
    bool protocolViolation = false;
    bool structurallyValid = status != EXACT_GPU_DECODED_IMAGE_COMPLETE_V1;
    if (status == EXACT_GPU_DECODED_IMAGE_COMPLETE_V1 && plane &&
        plane->struct_size == sizeof(ExactGpuDecodedImagePlaneV1) &&
        plane->abi_version == EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1 &&
        plane->reserved == 0 && plane->request_id == request_id &&
        validDecodedImageIdentityV1(plane->identity) && plane->width != 0 &&
        plane->height != 0 && plane->width <= kMaxDecodedImageDimensionV1 &&
        plane->height <= kMaxDecodedImageDimensionV1 &&
        plane->bytes_per_row == plane->width * 4 &&
        plane->color_space == EXACT_GPU_DECODED_IMAGE_COLOR_SPACE_SRGB_V1 &&
        plane->alpha_mode == EXACT_GPU_DECODED_IMAGE_ALPHA_PREMULTIPLIED_V1 &&
        plane->orientation == EXACT_GPU_DECODED_IMAGE_ORIENTATION_TOP_LEFT_V1 &&
        plane->origin_clean_class ==
            EXACT_GPU_DECODED_IMAGE_ORIGIN_SCRIPT_OWNED_BLOB_V1 &&
        plane->encoded_bytes && plane->encoded_len != 0 &&
        plane->encoded_len <= kMaxDecodedImageEncodedBytesV1 &&
        plane->decoded_bytes) {
      decodedLength = static_cast<size_t>(plane->bytes_per_row) * plane->height;
      structurallyValid = decodedLength != 0 &&
                          decodedLength <= kMaxDecodedImageBytesV1 &&
                          plane->decoded_len == decodedLength;
    }

    bool admitted = false;
    {
      std::lock_guard<std::mutex> lock(binding->mutex);
      auto found = binding->pending.find(request_id);
      if (found != binding->pending.end() && binding->active &&
          !found->second.completion_queued) {
        if (status == EXACT_GPU_DECODED_IMAGE_COMPLETE_V1 &&
            (!structurallyValid || !plane ||
             !equalDecodedImageIdentityV1(found->second.identity,
                                          plane->identity) ||
             found->second.encoded.size() != plane->encoded_len ||
             decodedLength > kMaxQueuedDecodedImageBytesV1 -
                                 binding->queued_decoded_bytes)) {
          terminalStatus = EXACT_GPU_DECODED_IMAGE_DECODE_FAILED_V1;
          decodedLength = 0;
          protocolViolation = true;
        }
        found->second.completion_queued = true;
        found->second.queued_decoded_bytes =
            terminalStatus == EXACT_GPU_DECODED_IMAGE_COMPLETE_V1
                ? decodedLength
                : 0;
        binding->queued_decoded_bytes += found->second.queued_decoded_bytes;
        admitted = true;
      }
    }
    if (!admitted) {
      return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
    }

    std::shared_ptr<CopiedDecodedImagePlaneV1> copied;
    if (terminalStatus == EXACT_GPU_DECODED_IMAGE_COMPLETE_V1) {
      try {
        copied = std::make_shared<CopiedDecodedImagePlaneV1>();
        copied->width = plane->width;
        copied->height = plane->height;
        copied->bytes_per_row = plane->bytes_per_row;
        copied->encoded.assign(plane->encoded_bytes,
                               plane->encoded_bytes + plane->encoded_len);
        copied->decoded.assign(plane->decoded_bytes,
                               plane->decoded_bytes + plane->decoded_len);
        std::copy(std::begin(plane->encoded_sha256),
                  std::end(plane->encoded_sha256),
                  copied->encoded_sha256.begin());
        std::copy(std::begin(plane->decoded_sha256),
                  std::end(plane->decoded_sha256),
                  copied->decoded_sha256.begin());
        std::lock_guard<std::mutex> lock(binding->mutex);
        auto found = binding->pending.find(request_id);
        if (found == binding->pending.end() ||
            found->second.encoded != copied->encoded) {
          terminalStatus = EXACT_GPU_DECODED_IMAGE_DECODE_FAILED_V1;
          copied.reset();
          if (found != binding->pending.end()) {
            binding->queued_decoded_bytes -= found->second.queued_decoded_bytes;
            found->second.queued_decoded_bytes = 0;
          }
        }
      } catch (...) {
        terminalStatus = EXACT_GPU_DECODED_IMAGE_DECODE_FAILED_V1;
        copied.reset();
        std::lock_guard<std::mutex> lock(binding->mutex);
        auto found = binding->pending.find(request_id);
        if (found != binding->pending.end()) {
          binding->queued_decoded_bytes -= found->second.queued_decoded_bytes;
          found->second.queued_decoded_bytes = 0;
        }
      }
    }

    bool accepted = false;
    try {
      pushRuntimeCallback(
          targetEntry->target,
          [binding, request_id, terminalStatus,
           copied](facebook::jsi::Runtime &rt) mutable {
            settleDecodedImageV1(binding, rt, request_id, terminalStatus,
                                 std::move(copied));
          },
          &accepted);
    } catch (...) {
      accepted = false;
    }
    if (!accepted) {
      publishDecodedImageOwnerFallbackV1(binding, request_id);
    }
    if (!accepted)
      return EXACT_GPU_PROVIDER_INVALID_STATE;
    return protocolViolation ? EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION
                             : EXACT_GPU_PROVIDER_OK;
  } catch (...) {
    publishDecodedImageOwnerFallbackV1(fallbackBinding, request_id);
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
#endif
}

bool exactGpuDecodedImageAttachAuthorityV1(ExactHermesRuntime *runtime,
                                           facebook::jsi::Runtime &rt,
                                           facebook::jsi::Object &bridge) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  (void)rt;
  (void)bridge;
  return true;
#else
  if (!runtime || !runtime->gpu_decoded_image_binding_v1)
    return true;
  auto binding = runtime->gpu_decoded_image_binding_v1;
  {
    std::lock_guard<std::mutex> lock(binding->mutex);
    if (!binding->active)
      return false;
  }
  try {
    facebook::jsi::Object authority(rt);
    auto decode = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "decodePng"), 1,
        [runtime](facebook::jsi::Runtime &rt, const facebook::jsi::Value &,
                  const facebook::jsi::Value *args,
                  size_t count) -> facebook::jsi::Value {
          return decodeGpuImageV1BridgeCall(runtime, rt, args, count);
        });
    auto revoke = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "revoke"), 0,
        [runtime](facebook::jsi::Runtime &rt, const facebook::jsi::Value &,
                  const facebook::jsi::Value *,
                  size_t count) -> facebook::jsi::Value {
          return revokeGpuImageV1BridgeCall(runtime, rt, count);
        });
    authority.setProperty(rt, "decodePng", std::move(decode));
    authority.setProperty(rt, "revoke", std::move(revoke));
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "freeze")
        .call(rt, authority);
    defineGpuV2Property(rt, bridge, "decodedImageAuthority",
                        std::move(authority));
    return true;
  } catch (...) {
    return false;
  }
#endif
}

void exactGpuDecodedImageDiscardIfUnusedV1(ExactHermesRuntime *runtime) {
  if (!runtime || runtime->gpu_binding_v2 ||
      !runtime->gpu_decoded_image_binding_v1) {
    return;
  }
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  runtime->gpu_decoded_image_binding_v1->detach(
      runtime, "Decoded-image authority had no authenticated V2 consumer");
#endif
  runtime->gpu_decoded_image_binding_v1.reset();
}

void exactGpuDecodedImageRollbackInstallV1(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->gpu_decoded_image_binding_v1)
    return;
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  runtime->gpu_decoded_image_binding_v1->detach(
      runtime, "Decoded-image capability installation rolled back");
#endif
  runtime->gpu_decoded_image_binding_v1.reset();
}

void exactGpuDecodedImageBeginRuntimeTeardownV1(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->gpu_decoded_image_binding_v1)
    return;
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  runtime->gpu_decoded_image_binding_v1->detach(
      runtime, "Decoded-image runtime was destroyed");
#endif
  runtime->gpu_decoded_image_binding_v1.reset();
}

bool exactGpuDecodedImageOwnerDrainPendingV1(
    const ExactHermesRuntime *runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return false;
#else
  return runtime && runtime->gpu_decoded_image_binding_v1 &&
      runtime->gpu_decoded_image_binding_v1->owner_drain_required.load(
          std::memory_order_acquire);
#endif
}

int exactGpuDecodedImageDrainOwnerFallbackV1(ExactHermesRuntime *runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return 0;
#else
  if (!runtime || !runtime->runtime ||
      !runtime->gpu_decoded_image_binding_v1) {
    return 0;
  }
  auto binding = runtime->gpu_decoded_image_binding_v1;
  if (!binding->owner_drain_required.exchange(false,
                                               std::memory_order_acq_rel)) {
    return 0;
  }
  std::vector<uint64_t> rejected;
  {
    std::lock_guard<std::mutex> lock(binding->mutex);
    rejected.reserve(binding->pending.size());
    for (const auto &entry : binding->pending) {
      if (entry.second.owner_fallback_required) {
        rejected.push_back(entry.first);
      }
    }
  }
  for (uint64_t requestId : rejected) {
    settleDecodedImageV1(binding, *runtime->runtime, requestId,
                         EXACT_GPU_DECODED_IMAGE_DECODE_FAILED_V1, nullptr);
  }
  return rejected.empty() ? 0 : 1;
#endif
}

extern "C" uint32_t ex_hermes_gpu_provider_abi_version_v2(void) {
  return EXACT_GPU_SERVICE_ABI_VERSION_V2;
}

extern "C" size_t ex_hermes_gpu_provider_descriptor_size_v2(void) {
  return sizeof(ExactHermesGpuProviderDescriptorV2);
}

extern "C" int32_t ex_hermes_set_gpu_provider_v2(
    ExactHermesRuntime* runtime,
    const ExactHermesGpuProviderDescriptorV2* descriptor) {
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
  // V2 caller-attribution provenance is meaningful only for a positively
  // armed runtime with initialized typed-authority generations. Diagnostic
  // and partially constructed runtimes fail closed before native retention.
  if (!runtime->armed || !runtime->typed_authority_generations_initialized) {
    return EXACT_GPU_PROVIDER_AUTHENTICATION_FAILED;
  }
  // Read no descriptor field beyond the caller-declared prefix until the
  // exact-size check succeeds. In particular, an undersized prefix cannot
  // trigger the ABI-mismatch branch by reading abi_version out of bounds.
  if (!descriptor) return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  if (descriptor->struct_size != sizeof(ExactHermesGpuProviderDescriptorV2)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  if (descriptor->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V2) {
    return EXACT_GPU_PROVIDER_ABI_MISMATCH;
  }
  if (descriptor->flags != 0 || descriptor->reserved != 0 ||
      descriptor->topology_id !=
          EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_V2 ||
      !nonzeroDigestV2(descriptor->profile_digest) ||
      !nonzeroDigestV2(descriptor->runtime_routing_digest) ||
      !validProfileIdV2(descriptor->profile_id, descriptor->profile_id_len) ||
      !validOperationIdsV2(
          descriptor->sorted_operation_ids, descriptor->operation_id_count) ||
      !validServiceApiV2(descriptor->api)) {
    return EXACT_GPU_PROVIDER_INVALID_ARGUMENT;
  }
  std::array<uint8_t, EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2>
      providerAuthority{};
  if (ex_host_authorize_exact_gpu_provider_v2(
          runtime->host_context_id,
          descriptor->abi_version,
          reinterpret_cast<const uint8_t*>(descriptor->profile_id),
          descriptor->profile_id_len,
          descriptor->profile_digest,
          descriptor->webgpu_c_vocabulary_digest,
          descriptor->operation_set_digest,
          descriptor->semantic_program_digest,
          descriptor->runtime_routing_digest,
          descriptor->sorted_operation_ids,
          descriptor->operation_id_count,
          descriptor->topology_id,
          providerAuthority.data()) != 1 ||
      !nonzeroDigestV2(providerAuthority.data())) {
    return EXACT_GPU_PROVIDER_AUTHENTICATION_FAILED;
  }
  std::shared_ptr<ExactGpuRuntimeBindingV2> binding;
  try {
    binding = std::make_shared<ExactGpuRuntimeBindingV2>();
    binding->api = *descriptor->api;
    binding->allowed_operations.insert(
        descriptor->sorted_operation_ids,
        descriptor->sorted_operation_ids + descriptor->operation_id_count);
    binding->authority_digest = providerAuthority;
    std::copy(
        descriptor->runtime_routing_digest,
        descriptor->runtime_routing_digest + 32,
        binding->runtime_routing_digest.begin());
    binding->topology_id = descriptor->topology_id;
    binding->mailbox =
        new ExactGpuClientMailboxV2(exactRuntimeCallbackTarget(runtime));
    binding->mailbox->allowed_operations = binding->allowed_operations;
    binding->api.retain_service(binding->api.service_context);
    binding->service_retained = true;
  } catch (...) {
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  runtime->gpu_binding_v2 = std::move(binding);
  return EXACT_GPU_PROVIDER_OK;
#endif
}

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
namespace {

facebook::jsi::Value gpuCanvasDescriptorFieldV1(
    ExactHermesRuntime* runtime,
    const facebook::jsi::Object& descriptor,
    const char* field) {
  auto& rt = *runtime->runtime;
  auto namesValue = runtime->root_global_get_own_property_names->call(
      rt, descriptor);
  if (!namesValue.isObject() || !namesValue.asObject(rt).isArray(rt)) {
    throw std::runtime_error(
        "GPU Canvas descriptor reflection returned a non-array");
  }
  auto names = namesValue.asObject(rt).asArray(rt);
  for (size_t index = 0; index < names.size(rt); ++index) {
    auto name = names.getValueAtIndex(rt, index);
    if (!name.isString()) {
      throw std::runtime_error(
          "GPU Canvas descriptor reflection returned a non-string");
    }
    if (name.asString(rt).utf8(rt) == field) {
      return descriptor.getProperty(rt, field);
    }
  }
  return facebook::jsi::Value::undefined();
}

facebook::jsi::Value gpuCanvasAppBundleCaptureDescriptorV1(
    ExactHermesRuntime* runtime) {
  auto& rt = *runtime->runtime;
  return runtime->root_global_get_own_property_descriptor->call(
      rt,
      rt.global(),
      facebook::jsi::String::createFromAscii(
          rt, kGpuCanvasAppBundleCaptureGlobalNameV1));
}

bool gpuCanvasAppBundleCaptureAbsentV1(ExactHermesRuntime* runtime) {
  return gpuCanvasAppBundleCaptureDescriptorV1(runtime).isUndefined();
}

bool gpuCanvasAppBundleCaptureMatchesV1(
    ExactHermesRuntime* runtime,
    const facebook::jsi::Function& expected) {
  auto& rt = *runtime->runtime;
  auto descriptorValue = gpuCanvasAppBundleCaptureDescriptorV1(runtime);
  if (!descriptorValue.isObject()) return false;
  auto descriptor = descriptorValue.asObject(rt);
  auto value = gpuCanvasDescriptorFieldV1(runtime, descriptor, "value");
  auto writable = gpuCanvasDescriptorFieldV1(
      runtime, descriptor, "writable");
  auto enumerable = gpuCanvasDescriptorFieldV1(
      runtime, descriptor, "enumerable");
  auto configurable = gpuCanvasDescriptorFieldV1(
      runtime, descriptor, "configurable");
  auto getter = gpuCanvasDescriptorFieldV1(runtime, descriptor, "get");
  auto setter = gpuCanvasDescriptorFieldV1(runtime, descriptor, "set");
  return value.isObject() && value.asObject(rt).isFunction(rt) &&
      facebook::jsi::Object::strictEquals(
          rt, value.asObject(rt), expected) &&
      writable.isBool() && !writable.getBool() && enumerable.isBool() &&
      !enumerable.getBool() && configurable.isBool() &&
      configurable.getBool() && getter.isUndefined() && setter.isUndefined();
}

bool closeGpuCanvasAppBundleCaptureRootV1(
    ExactHermesRuntime* runtime) noexcept {
  try {
    auto descriptor = gpuCanvasAppBundleCaptureDescriptorV1(runtime);
    if (descriptor.isUndefined()) return true;
    auto& rt = *runtime->runtime;
    auto deleted = runtime->root_global_reflect_delete_property->call(
        rt,
        rt.global(),
        facebook::jsi::String::createFromAscii(
            rt, kGpuCanvasAppBundleCaptureGlobalNameV1));
    return deleted.isBool() && deleted.getBool() &&
        gpuCanvasAppBundleCaptureAbsentV1(runtime);
  } catch (...) {
    return false;
  }
}

void failGpuCanvasAppBundleCleanupV1(ExactHermesRuntime* runtime) noexcept {
  if (!runtime) return;
  runtime->root_global_disposition_verified_for_user_execution = false;
  runtime->embedder_capability_state = EmbedderCapabilityState::Failed;
  exactGpuRollbackInstall(runtime);
}

bool gpuCanvasAppBundleControllerAvailableV1(
    ExactHermesRuntime* runtime,
    const std::shared_ptr<ExactGpuRuntimeBindingV2>& binding) {
  return runtime && runtime->runtime && !runtime->restricted &&
         runtime->exact_host_context != EXACT_EMBEDDER_CONTEXT_AGENT &&
         binding && !binding->detached && binding->realm_open &&
         binding->bridge_captured && binding->bridge_sealed &&
         binding->canvas_receipt_sink && binding->host_task_checkpoint &&
         binding->canvas_app_bundle_begin && binding->canvas_app_bundle_finish;
}

}  // namespace
#endif

extern "C" int32_t ex_hermes_begin_gpu_canvas_app_bundle_v1(
    ExactHermesRuntime* runtime,
    uint32_t expectation) {
  if (!runtime ||
      (expectation != EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
       expectation != EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_VALID_V1)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ExactRuntimeDriveGuard drive(runtime, 0, false, true);
  if (!drive) return drive.status();
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  return EXACT_GPU_CANVAS_APP_BUNDLE_UNAVAILABLE_V1;
#else
  auto binding = runtime->gpu_binding_v2;
  if (!gpuCanvasAppBundleControllerAvailableV1(runtime, binding)) {
    return EXACT_GPU_CANVAS_APP_BUNDLE_UNAVAILABLE_V1;
  }
  if (binding->canvas_app_bundle_open ||
      binding->canvas_app_bundle_generation == UINT64_MAX) {
    return EXACT_GPU_CANVAS_APP_BUNDLE_INVALID_STATE_V1;
  }
  try {
    if (!gpuCanvasAppBundleCaptureAbsentV1(runtime)) {
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
  } catch (...) {
    (void)exactRuntimeQuarantine(runtime);
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }

  if (!binding->canvas_app_bundle_prepared) {
    const bool outerEvaluationOpen =
        runtime->app_bundle_evaluation_open.load(std::memory_order_acquire);
    if (outerEvaluationOpen) {
      const uint32_t preparedDisposition =
          runtime->app_bundle_expected_prepared_disposition;
      if (!runtime->gpu_canvas_app_bundle_debugger_blocked.load(
              std::memory_order_acquire) ||
          (preparedDisposition != 0 &&
           (preparedDisposition != expectation ||
            !runtime->app_bundle_prepared_classified ||
            runtime->app_bundle_prepared_staged ||
            runtime->app_bundle_prepared_invoked ||
            !runtime->app_bundle_prepared_consume_gpu_integration ||
            !runtime->app_bundle_prepared_run_app))) {
        (void)exactRuntimeQuarantine(runtime);
        return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
      }
      runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = false;
    } else {
      runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = true;
      runtime->app_bundle_immediate_evaluation_completed = false;
      runtime->app_bundle_immediate_source_fallback_allowed = false;
    }

    // A legacy standalone transaction closes debugger ingress here. The
    // staged protocol arrives with the stronger outer exclusion already held.
    // @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
    if (!outerEvaluationOpen &&
        !exactRuntimeBeginGpuCanvasDebuggerExclusion(runtime)) {
      runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = false;
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
    if (!outerEvaluationOpen && (!exactRuntimeEnterUserExecution(runtime) ||
                                 !runtime->user_execution_started)) {
      runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = false;
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }

    // Phase 0 invokes any app-owned release from G(n-1) while the reserved
    // root is absent. A bounded Windows drain retains this prepared state and
    // requires the host to poll/retry before phase 1/2 can publish G(n).
    ScopedGpuHostTask cleanupTask(runtime);
    if (!cleanupTask) {
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
    try {
      auto prepared =
          binding->canvas_app_bundle_begin->call(*runtime->runtime, 0.0);
      if (!prepared.isUndefined() || !cleanupTask.finish()) {
        (void)exactRuntimeQuarantine(runtime);
        return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
      }
      binding->canvas_app_bundle_prepared = true;
      binding->canvas_app_bundle_expectation = expectation;
      if (runtime->gpu_host_task_microtask_continuation.load(
              std::memory_order_acquire)) {
        return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_PENDING_V1;
      }
    } catch (...) {
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
  } else {
    if (binding->canvas_app_bundle_expectation != expectation) {
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
    if (runtime->gpu_host_task_microtask_continuation.load(
            std::memory_order_acquire) &&
        !exactResumeGpuHostTaskContinuation(runtime)) {
      if (runtime->gpu_host_task_microtask_continuation.load(
              std::memory_order_acquire) &&
          !runtime->gpu_host_task_checkpoint_failed.load(
              std::memory_order_acquire)) {
        return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_PENDING_V1;
      }
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
    }
  }

  binding->canvas_app_bundle_committed = false;
  binding->canvas_app_bundle_prepared = false;
  try {
    auto captureValue = binding->canvas_app_bundle_begin->call(
        *runtime->runtime, static_cast<double>(expectation));
    binding->canvas_app_bundle_open = true;
    runtime->gpu_canvas_app_bundle_transaction_open.store(
        true, std::memory_order_release);
    if (expectation == EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1) {
      if (!captureValue.isObject() ||
          !captureValue.asObject(*runtime->runtime).isFunction(
              *runtime->runtime)) {
        throw std::runtime_error(
            "GPU Canvas app-bundle begin returned no capture function");
      }
      auto capture = std::make_shared<facebook::jsi::Function>(
          captureValue.asObject(*runtime->runtime).asFunction(
              *runtime->runtime));
      if (!gpuCanvasAppBundleCaptureMatchesV1(runtime, *capture)) {
        throw std::runtime_error(
            "GPU Canvas app-bundle capture descriptor mismatch");
      }
      binding->canvas_app_bundle_capture = std::move(capture);
    } else {
      if (!captureValue.isUndefined() ||
          !gpuCanvasAppBundleCaptureAbsentV1(runtime)) {
        throw std::runtime_error(
            "GPU Canvas unused app-bundle transaction exposed a capture");
      }
      binding->canvas_app_bundle_capture.reset();
    }
    binding->canvas_app_bundle_generation += 1;
    return EXACT_GPU_CANVAS_APP_BUNDLE_OK_V1;
  } catch (...) {
    if (binding->canvas_app_bundle_open) {
      try {
        binding->canvas_app_bundle_finish->call(
            *runtime->runtime, false);
      } catch (...) {
      }
    }
    binding->canvas_app_bundle_capture.reset();
    binding->canvas_app_bundle_expectation = 0;
    binding->canvas_app_bundle_open = false;
    runtime->gpu_canvas_app_bundle_transaction_open.store(
        false, std::memory_order_release);
    binding->canvas_app_bundle_committed = false;
    if (!closeGpuCanvasAppBundleCaptureRootV1(runtime)) {
      failGpuCanvasAppBundleCleanupV1(runtime);
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1;
    }
    const bool ownsDebuggerExclusion =
        runtime->gpu_canvas_app_bundle_owns_debugger_exclusion;
    runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = false;
    if (ownsDebuggerExclusion &&
        !exactRuntimeFinishGpuCanvasDebuggerExclusion(runtime)) {
      failGpuCanvasAppBundleCleanupV1(runtime);
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1;
    }
    (void)exactRuntimeQuarantine(runtime);
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }
#endif
}

namespace {

void writeGpuCanvasImmediateEvalRefusal(
    char** outError,
    const char* message) noexcept {
  if (outError == nullptr) return;
  if (*outError != nullptr) {
    std::free(*outError);
  }
  *outError = nullptr;
  *outError = copyMallocString(message);
}

}  // namespace

static int32_t evalGpuCanvasAppBundleImmediateV1(
    ExactHermesRuntime* runtime,
    const uint8_t* prelude_data,
    size_t prelude_len,
    const char* prelude_source_url,
    const uint8_t* data,
    size_t len,
    const char* source_url,
    int is_bytecode,
    char** out_error) {
  if (out_error != nullptr) *out_error = nullptr;
  if (runtime == nullptr || data == nullptr || len == 0 ||
      (is_bytecode != 0 && is_bytecode != 1) ||
      ((prelude_data == nullptr) != (prelude_len == 0))) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error, "GPU Canvas immediate eval received invalid input");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ExactRuntimeDriveGuard drive(runtime, 0, false, true);
  if (!drive) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error, "GPU Canvas immediate eval refused by the runtime drive gate");
    return drive.status();
  }
  const bool outerOpen = runtime->app_bundle_evaluation_open.load(
      std::memory_order_acquire);
  const bool canvasOpen =
      runtime->gpu_canvas_app_bundle_transaction_open.load(
          std::memory_order_acquire);
  const uint32_t preparedDisposition =
      runtime->app_bundle_expected_prepared_disposition;
  const bool stagedPrepare = outerOpen && preparedDisposition != 0 &&
      !canvasOpen && !runtime->app_bundle_prepared_classified;
  const bool stagedLegacyEval =
      outerOpen && preparedDisposition == 0;
  const bool standaloneCanvasEval = !outerOpen && canvasOpen;
  if ((!stagedPrepare && !stagedLegacyEval && !standaloneCanvasEval) ||
      !runtime->gpu_canvas_app_bundle_debugger_blocked.load(
          std::memory_order_acquire)) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error,
        "GPU Canvas immediate eval requires an open app-bundle transaction");
    return EXACT_GPU_CANVAS_APP_BUNDLE_INVALID_STATE_V1;
  }
  if (runtime->app_bundle_immediate_evaluation_completed ||
      (runtime->app_bundle_immediate_source_fallback_allowed &&
       is_bytecode != 0)) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error,
        "GPU Canvas immediate eval already ran or requires source fallback");
    return EXACT_GPU_CANVAS_APP_BUNDLE_INVALID_STATE_V1;
  }

  ScopedGpuHostTask hostTask(runtime);
  if (!hostTask) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error,
        "GPU Canvas immediate eval host-task boundary is unavailable");
    (void)exactRuntimeQuarantine(runtime);
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  int32_t status = exactHermesEvalImmediateNoJobs(
      runtime, data, len, source_url, is_bytecode, out_error, prelude_data,
      prelude_len, prelude_source_url);
  if (status == 2 && is_bytecode != 0) {
    runtime->app_bundle_immediate_source_fallback_allowed = true;
  } else {
    runtime->app_bundle_immediate_source_fallback_allowed = false;
    runtime->app_bundle_immediate_evaluation_completed = true;
  }
  if (status != 0 && status != 2) {
    // Source/HBC execution may have partially mutated the world before
    // throwing. Quarantine before returning so the embedder's idle loop cannot
    // pump callbacks while physical retirement is merely queued. Status 2 is
    // the sole pre-instruction bytecode rejection and may retry source.
    (void)exactRuntimeQuarantine(runtime);
  }
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  if (status == 0 && canvasOpen) {
    auto binding = runtime->gpu_binding_v2;
    if (binding &&
        binding->canvas_app_bundle_expectation ==
            EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
        !gpuCanvasAppBundleCaptureAbsentV1(runtime)) {
      // A consume-required bundle must take and delete the one-shot handoff
      // synchronously. Never drain app jobs while that root is exposed: a
      // queued callback could otherwise steal it after evaluation returns.
      writeGpuCanvasImmediateEvalRefusal(
          out_error,
          "GPU Canvas app bundle did not consume its capture synchronously");
      (void)exactRuntimeQuarantine(runtime);
      status = EXACT_GPU_CANVAS_APP_BUNDLE_REQUIRED_NOT_CONSUMED_V1;
    }
  }
#endif
  if (!hostTask.finish()) {
    writeGpuCanvasImmediateEvalRefusal(
        out_error, "GPU Canvas immediate eval host-task checkpoint failed");
    (void)exactRuntimeQuarantine(runtime);
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  return status;
}

// @abi-output ex_hermes_eval_gpu_canvas_app_bundle_immediate_v1 out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
extern "C" int32_t ex_hermes_eval_gpu_canvas_app_bundle_immediate_v1(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* source_url,
    int is_bytecode,
    char** out_error) {
  return evalGpuCanvasAppBundleImmediateV1(
      runtime,
      nullptr,
      0,
      nullptr,
      data,
      len,
      source_url,
      is_bytecode,
      out_error);
}

// @abi-output ex_hermes_eval_gpu_canvas_app_bundle_with_prelude_immediate_v1 out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
extern "C" int32_t
ex_hermes_eval_gpu_canvas_app_bundle_with_prelude_immediate_v1(
    ExactHermesRuntime* runtime,
    const uint8_t* prelude_data,
    size_t prelude_len,
    const char* prelude_source_url,
    const uint8_t* artifact_data,
    size_t artifact_len,
    const char* artifact_source_url,
    int artifact_is_bytecode,
    char** out_error) {
  return evalGpuCanvasAppBundleImmediateV1(
      runtime,
      prelude_data,
      prelude_len,
      prelude_source_url,
      artifact_data,
      artifact_len,
      artifact_source_url,
      artifact_is_bytecode,
      out_error);
}

extern "C" int32_t ex_hermes_finish_gpu_canvas_app_bundle_v1(
    ExactHermesRuntime* runtime,
    uint32_t evaluation_succeeded) {
  if (!runtime || evaluation_succeeded > 1) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ExactRuntimeDriveGuard drive(runtime, 0, true, true);
  if (!drive) return drive.status();
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  return EXACT_GPU_CANVAS_APP_BUNDLE_UNAVAILABLE_V1;
#else
  auto binding = runtime->gpu_binding_v2;
  if (!gpuCanvasAppBundleControllerAvailableV1(runtime, binding)) {
    if (binding && binding->canvas_app_bundle_open) {
      failGpuCanvasAppBundleCleanupV1(runtime);
      (void)exactRuntimeQuarantine(runtime);
      return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1;
    }
    return EXACT_GPU_CANVAS_APP_BUNDLE_UNAVAILABLE_V1;
  }
  if (!binding->canvas_app_bundle_open ||
      (binding->canvas_app_bundle_expectation !=
           EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
       binding->canvas_app_bundle_expectation !=
           EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_VALID_V1) ||
      (binding->canvas_app_bundle_expectation ==
           EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
       !binding->canvas_app_bundle_capture)) {
    return EXACT_GPU_CANVAS_APP_BUNDLE_INVALID_STATE_V1;
  }

  ScopedGpuHostTask hostTask(runtime);
  if (!hostTask) {
    (void)exactRuntimeQuarantine(runtime);
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }
  auto finishHostTask = [&]() noexcept {
    if (hostTask.finish()) return true;
    (void)exactRuntimeQuarantine(runtime);
    return false;
  };

  if (evaluation_succeeded == 0) {
    // Legacy raw evaluators may report failure here without having used the
    // immediate ABI. Close their world before invoking even trusted controller
    // cleanup so the host cannot pump it while retirement is scheduled.
    (void)exactRuntimeQuarantine(runtime);
  }

  const uint32_t expectation = binding->canvas_app_bundle_expectation;
  bool consumed = false;
  bool controllerFailed = false;
  try {
    auto result = binding->canvas_app_bundle_finish->call(
        *runtime->runtime, evaluation_succeeded != 0);
    if (!result.isBool()) {
      throw std::runtime_error(
          "GPU Canvas app-bundle finish returned a non-boolean result");
    }
    consumed = result.getBool();
  } catch (...) {
    controllerFailed = true;
  }
  binding->canvas_app_bundle_capture.reset();
  binding->canvas_app_bundle_expectation = 0;
  binding->canvas_app_bundle_open = false;
  runtime->gpu_canvas_app_bundle_transaction_open.store(
      false, std::memory_order_release);
  if (!runtime->app_bundle_evaluation_open.load(std::memory_order_acquire)) {
    runtime->app_bundle_immediate_evaluation_completed = false;
    runtime->app_bundle_immediate_source_fallback_allowed = false;
  }
  binding->canvas_app_bundle_committed =
      !controllerFailed && evaluation_succeeded != 0 &&
      expectation == EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
      consumed;

  if (!closeGpuCanvasAppBundleCaptureRootV1(runtime)) {
    binding->canvas_app_bundle_committed = false;
    failGpuCanvasAppBundleCleanupV1(runtime);
    (void)exactRuntimeQuarantine(runtime);
    (void)finishHostTask();
    return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1;
  }
  const bool ownsDebuggerExclusion =
      runtime->gpu_canvas_app_bundle_owns_debugger_exclusion;
  runtime->gpu_canvas_app_bundle_owns_debugger_exclusion = false;
  if (ownsDebuggerExclusion &&
      !exactRuntimeFinishGpuCanvasDebuggerExclusion(runtime)) {
    binding->canvas_app_bundle_committed = false;
    failGpuCanvasAppBundleCleanupV1(runtime);
    (void)exactRuntimeQuarantine(runtime);
    (void)finishHostTask();
    return EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1;
  }
  if (controllerFailed) {
    binding->canvas_app_bundle_committed = false;
    (void)exactRuntimeQuarantine(runtime);
    (void)finishHostTask();
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }
  if (evaluation_succeeded != 0 &&
      expectation == EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 &&
      !consumed) {
    (void)exactRuntimeQuarantine(runtime);
    (void)finishHostTask();
    return EXACT_GPU_CANVAS_APP_BUNDLE_REQUIRED_NOT_CONSUMED_V1;
  }
  if (evaluation_succeeded != 0 &&
      expectation == EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_VALID_V1 &&
      consumed) {
    (void)exactRuntimeQuarantine(runtime);
    (void)finishHostTask();
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }
  if (!finishHostTask()) {
    return EXACT_GPU_CANVAS_APP_BUNDLE_HANDOFF_FAILED_V1;
  }
  return consumed ? EXACT_GPU_CANVAS_APP_BUNDLE_OK_V1
                  : EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_V1;
#endif
}

extern "C" int32_t ex_hermes_deliver_gpu_canvas_attachment_receipt_v1(
    ExactHermesRuntime* runtime,
    const ExactGpuCanvasAttachmentReceiptV1* receipt) {
  // No malformed caller input is allowed to enter a runtime drive. In
  // particular the nonce is trusted by the registry gate only after the
  // complete exact-size discriminant has been validated.
  if (!runtime || !receipt || !validCanvasAttachmentReceiptV1(*receipt)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ExactRuntimeDriveGuard drive(runtime, receipt->runtime_generation);
  if (!drive) return drive.status();
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  return EXACT_GPU_CANVAS_RECEIPT_SINK_UNAVAILABLE_V1;
#else
  auto binding = runtime->gpu_binding_v2;
  if (!binding || binding->detached || !binding->realm_open ||
      !binding->bridge_captured || !binding->bridge_sealed ||
      !binding->canvas_receipt_sink || binding->canvas_app_bundle_open ||
      !binding->canvas_app_bundle_committed) {
    return EXACT_GPU_CANVAS_RECEIPT_SINK_UNAVAILABLE_V1;
  }
  if (binding->realm.runtime.runtime_address !=
          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime)) ||
      binding->realm.runtime.runtime_nonce != receipt->runtime_generation) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  ScopedGpuHostTask hostTask(runtime);
  if (!hostTask) return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  try {
    auto value = makeCanvasAttachmentReceiptValueV1(
        *runtime->runtime, *receipt);
    binding->canvas_receipt_sink->call(*runtime->runtime, value);
    if (!hostTask.finish()) return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (...) {
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
#endif
}

int32_t exactGpuV2ActivateInstall(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return EXACT_GPU_PROVIDER_OK;
#else
  if (!runtime || !runtime->gpu_binding_v2) return EXACT_GPU_PROVIDER_OK;
  auto& binding = *runtime->gpu_binding_v2;
  if (binding.realm_open) return EXACT_GPU_PROVIDER_OK;
  ExactGpuRealmOpenV2 open{};
  open.struct_size = sizeof(open);
  open.abi_version = EXACT_GPU_SERVICE_ABI_VERSION_V2;
  open.context_kind = runtime->exact_host_context == 0
      ? static_cast<uint32_t>(EXACT_EMBEDDER_CONTEXT_APP)
      : runtime->exact_host_context;
  open.runtime.runtime_address = static_cast<uint64_t>(
      reinterpret_cast<uintptr_t>(runtime));
  open.runtime.runtime_nonce = runtime->runtime_nonce;
  std::copy(
      binding.authority_digest.begin(),
      binding.authority_digest.end(),
      open.authority_digest);
  std::copy(
      binding.runtime_routing_digest.begin(),
      binding.runtime_routing_digest.end(),
      open.runtime_routing_digest);
  open.authority_session_api = ex_host_exact_gpu_authority_session_api_v2();
  if (!open.authority_session_api ||
      open.authority_session_api->struct_size !=
          sizeof(ExactGpuAuthoritySessionApiV2) ||
      open.authority_session_api->abi_version !=
          EXACT_GPU_SERVICE_ABI_VERSION_V2 ||
      open.authority_session_api->authority_context != nullptr ||
      !open.authority_session_api->evaluate ||
      !open.authority_session_api->retire ||
      !open.authority_session_api->evaluate_batch_and_then) {
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  int32_t status = EXACT_GPU_PROVIDER_OPEN_FAILED;
  try {
    status = binding.api.open_realm(
        binding.api.service_context,
        &open,
        &kGpuClientSinkV2,
        binding.mailbox,
        &binding.realm,
        &binding.root_account);
  } catch (...) {
    status = EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  const bool realmValid = validRealmV2(binding.realm) &&
      equalRuntimeV2(binding.realm.runtime, open.runtime);
  // A service may return a valid allocated realm together with a failed status
  // or malformed root account. Retain that realm identity so transaction
  // rollback can close it; otherwise the provider-side realm leaks.
  if (realmValid) {
    binding.mailbox->realm = binding.realm;
    binding.realm_open = true;
  }
  const bool identityValid = status == 0 && realmValid &&
      validAccountV2(binding.root_account) &&
      std::memcmp(
          binding.root_account.authority_digest,
          open.authority_digest,
          EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2) == 0;
  if (!identityValid) return EXACT_GPU_PROVIDER_OPEN_FAILED;
  auto expected = GpuMailboxPhaseV2::Installing;
  if (!binding.mailbox->phase.compare_exchange_strong(
          expected,
          GpuMailboxPhaseV2::Activating,
          std::memory_order_acq_rel,
          std::memory_order_acquire)) {
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  try {
    binding.api.activate_realm(binding.api.service_context, &binding.realm);
  } catch (...) {
    (void)poisonGpuMailboxV2(binding.mailbox);
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  expected = GpuMailboxPhaseV2::Activating;
  if (!binding.mailbox->phase.compare_exchange_strong(
          expected,
          GpuMailboxPhaseV2::Live,
          std::memory_order_acq_rel,
          std::memory_order_acquire)) {
    return EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION;
  }
  return EXACT_GPU_PROVIDER_OK;
#endif
}

bool exactGpuV2CaptureResultFunctions(
    ExactHermesRuntime* runtime,
    const facebook::jsi::Value& result,
    std::shared_ptr<facebook::jsi::Function>* outRevoke,
    std::shared_ptr<facebook::jsi::Function>* outCanvasReceiptSink,
    std::shared_ptr<facebook::jsi::Function>* outHostTaskCheckpoint,
    std::shared_ptr<facebook::jsi::Function>* outCanvasAppBundleBegin,
    std::shared_ptr<facebook::jsi::Function>* outCanvasAppBundleFinish) {
  if (!runtime || !runtime->runtime || !outRevoke || !outCanvasReceiptSink ||
      !outHostTaskCheckpoint || !outCanvasAppBundleBegin ||
      !outCanvasAppBundleFinish || !result.isObject() ||
      !runtime->root_global_get_own_property_names ||
      !runtime->root_global_get_own_property_symbols ||
      !runtime->root_global_get_own_property_descriptor ||
      !runtime->root_global_get_prototype_of) {
    return false;
  }
  auto& rt = *runtime->runtime;
  auto object = result.asObject(rt);
  if (object.isFunction(rt)) return false;

  auto frozen = rt.global()
                    .getPropertyAsObject(rt, "Object")
                    .getPropertyAsFunction(rt, "isFrozen")
                    .call(rt, object);
  if (!frozen.isBool() || !frozen.getBool()) return false;

  auto namesValue = runtime->root_global_get_own_property_names->call(
      rt, object);
  auto symbolsValue = runtime->root_global_get_own_property_symbols->call(
      rt, object);
  if (!namesValue.isObject() || !namesValue.asObject(rt).isArray(rt) ||
      !symbolsValue.isObject() || !symbolsValue.asObject(rt).isArray(rt)) {
    return false;
  }
  auto names = namesValue.asObject(rt).asArray(rt);
  auto symbols = symbolsValue.asObject(rt).asArray(rt);
  if (names.size(rt) != 5 || symbols.size(rt) != 0) return false;
  bool sawRevoke = false;
  bool sawCanvasReceiptSink = false;
  bool sawHostTaskCheckpoint = false;
  bool sawCanvasAppBundleBegin = false;
  bool sawCanvasAppBundleFinish = false;
  for (size_t index = 0; index < names.size(rt); ++index) {
    auto name = names.getValueAtIndex(rt, index);
    if (!name.isString()) return false;
    const auto text = name.asString(rt).utf8(rt);
    if (text == "revoke" && !sawRevoke) {
      sawRevoke = true;
    } else if (text == "canvasReceiptSink" && !sawCanvasReceiptSink) {
      sawCanvasReceiptSink = true;
    } else if (text == "checkpointHostTask" && !sawHostTaskCheckpoint) {
      sawHostTaskCheckpoint = true;
    } else if (text == "beginCanvasAppBundle" && !sawCanvasAppBundleBegin) {
      sawCanvasAppBundleBegin = true;
    } else if (text == "finishCanvasAppBundle" &&
               !sawCanvasAppBundleFinish) {
      sawCanvasAppBundleFinish = true;
    } else {
      return false;
    }
  }
  if (!sawRevoke || !sawCanvasReceiptSink || !sawHostTaskCheckpoint ||
      !sawCanvasAppBundleBegin || !sawCanvasAppBundleFinish) {
    return false;
  }

  auto prototypeValue = runtime->root_global_get_prototype_of->call(
      rt, object);
  if (!prototypeValue.isObject()) return false;
  auto expectedPrototype = rt.global()
                               .getPropertyAsObject(rt, "Object")
                               .getPropertyAsObject(rt, "prototype");
  if (!facebook::jsi::Object::strictEquals(
          rt, prototypeValue.asObject(rt), expectedPrototype)) {
    return false;
  }

  auto readFrozenFunction = [&](const char* name)
      -> std::shared_ptr<facebook::jsi::Function> {
    auto key = facebook::jsi::String::createFromAscii(rt, name);
    auto descriptorValue =
        runtime->root_global_get_own_property_descriptor->call(
            rt, object, key);
    if (!descriptorValue.isObject()) return nullptr;
    auto descriptor = descriptorValue.asObject(rt);
    auto value = descriptor.getProperty(rt, "value");
    auto writable = descriptor.getProperty(rt, "writable");
    auto enumerable = descriptor.getProperty(rt, "enumerable");
    auto configurable = descriptor.getProperty(rt, "configurable");
    auto getter = descriptor.getProperty(rt, "get");
    auto setter = descriptor.getProperty(rt, "set");
    if (!value.isObject() || !value.asObject(rt).isFunction(rt) ||
        !writable.isBool() || writable.getBool() ||
        !enumerable.isBool() || !enumerable.getBool() ||
        !configurable.isBool() || configurable.getBool() ||
        !getter.isUndefined() || !setter.isUndefined()) {
      return nullptr;
    }
    return std::make_shared<facebook::jsi::Function>(
        value.asObject(rt).asFunction(rt));
  };

  auto revoke = readFrozenFunction("revoke");
  auto canvasReceiptSink = readFrozenFunction("canvasReceiptSink");
  auto hostTaskCheckpoint = readFrozenFunction("checkpointHostTask");
  auto canvasAppBundleBegin = readFrozenFunction("beginCanvasAppBundle");
  auto canvasAppBundleFinish = readFrozenFunction("finishCanvasAppBundle");
  if (!revoke || !canvasReceiptSink || !hostTaskCheckpoint ||
      !canvasAppBundleBegin || !canvasAppBundleFinish) {
    return false;
  }
  *outRevoke = std::move(revoke);
  *outCanvasReceiptSink = std::move(canvasReceiptSink);
  *outHostTaskCheckpoint = std::move(hostTaskCheckpoint);
  *outCanvasAppBundleBegin = std::move(canvasAppBundleBegin);
  *outCanvasAppBundleFinish = std::move(canvasAppBundleFinish);
  return true;
}

bool exactGpuV2PublishPrivateBridge(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return true;
#else
  if (!runtime || !runtime->runtime || !runtime->gpu_binding_v2) return true;
  auto& binding = *runtime->gpu_binding_v2;
  if (binding.bridge_captured) return true;
  if (!binding.realm_open || !binding.mailbox ||
      binding.mailbox->phase.load(std::memory_order_acquire) !=
          GpuMailboxPhaseV2::Live) {
    return false;
  }
  // The construction-private wrapper includes GPUBuffer mapping methods only
  // when Hermes can mint true aliases and honor WebGPUBufferMapping's detach
  // key. Never substitute copy-and-shadow semantics.
  auto& rt = *runtime->runtime;
  if (!hasGpuV2MappedArrayBufferApi(rt)) return false;
#if defined(captureGpuPresentationAuthorityBridgeCall) || \
    defined(recheckGpuPresentationAuthorityBridgeCall) || \
    defined(retireGpuPresentationAuthorityBridgeCall) || \
    defined(submitGpuV2BridgeCall) || defined(cancelGpuV2BridgeCall) || \
    defined(retireGpuV2BridgeCall) || defined(setGpuV2EventSinkBridgeCall) || \
    defined(createGpuV2MappedRangeAliasBridgeCall) || \
    defined(detachGpuV2MappedRangeBridgeCall)
#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"
#endif
  try {
    facebook::jsi::Object gpuNativeBridgeV2(rt);
    auto submit = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "submit"),
        4,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return submitGpuV2BridgeCall(runtime, rt, args, count);
        });
    auto cancel = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "cancel"),
        2,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return cancelGpuV2BridgeCall(runtime, rt, args, count);
        });
    auto retire = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "retire"),
        1,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return retireGpuV2BridgeCall(runtime, rt, args, count);
        });
    auto capturePresentationAuthority =
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "capturePresentationAuthority"),
            2,
            [runtime](facebook::jsi::Runtime& rt,
                      const facebook::jsi::Value&,
                      const facebook::jsi::Value* args,
                      size_t count) -> facebook::jsi::Value {
              return captureGpuPresentationAuthorityBridgeCall(
                  runtime, rt, args, count);
            });
    auto recheckPresentationAuthority =
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "recheckPresentationAuthority"),
            3,
            [runtime](facebook::jsi::Runtime& rt,
                      const facebook::jsi::Value&,
                      const facebook::jsi::Value* args,
                      size_t count) -> facebook::jsi::Value {
              return recheckGpuPresentationAuthorityBridgeCall(
                  runtime, rt, args, count);
            });
    auto retirePresentationAuthority =
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "retirePresentationAuthority"),
            1,
            [runtime](facebook::jsi::Runtime& rt,
                      const facebook::jsi::Value&,
                      const facebook::jsi::Value* args,
                      size_t count) -> facebook::jsi::Value {
              return retireGpuPresentationAuthorityBridgeCall(
                  runtime, rt, args, count);
            });
    auto setEventSink = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "setEventSink"),
        1,
        [runtime](facebook::jsi::Runtime& rt,
                  const facebook::jsi::Value&,
                  const facebook::jsi::Value* args,
                  size_t count) -> facebook::jsi::Value {
          return setGpuV2EventSinkBridgeCall(runtime, rt, args, count);
        });
    auto createMappedRangeAlias =
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "createMappedRangeAlias"),
            3,
            [](facebook::jsi::Runtime& rt,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
              return createGpuV2MappedRangeAliasBridgeCall(rt, args, count);
            });
    auto detachMappedRange = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "detachMappedRange"),
        1,
        [](facebook::jsi::Runtime& rt,
           const facebook::jsi::Value&,
           const facebook::jsi::Value* args,
           size_t count) -> facebook::jsi::Value {
          return detachGpuV2MappedRangeBridgeCall(rt, args, count);
        });
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "abiVersion",
        static_cast<double>(EXACT_GPU_SERVICE_ABI_VERSION_V2));
    defineGpuV2Property(
        rt, gpuNativeBridgeV2, "submit", std::move(submit));
    defineGpuV2Property(
        rt, gpuNativeBridgeV2, "cancel", std::move(cancel));
    defineGpuV2Property(
        rt, gpuNativeBridgeV2, "retire", std::move(retire));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "capturePresentationAuthority",
        std::move(capturePresentationAuthority));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "recheckPresentationAuthority",
        std::move(recheckPresentationAuthority));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "retirePresentationAuthority",
        std::move(retirePresentationAuthority));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "createMappedRangeAlias",
        std::move(createMappedRangeAlias));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "detachMappedRange",
        std::move(detachMappedRange));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "setEventSink",
        std::move(setEventSink));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "runtimeAddress",
        gpuV2Uint64String(rt, binding.realm.runtime.runtime_address));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "runtimeNonce",
        gpuV2Uint64String(rt, binding.realm.runtime.runtime_nonce));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "realmId",
        gpuV2Uint64String(rt, binding.realm.realm_id));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "realmGeneration",
        gpuV2Uint64String(rt, binding.realm.realm_generation));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "rootAccountId",
        gpuV2Uint64String(rt, binding.root_account.account_id));
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "rootAccountGeneration",
        gpuV2Uint64String(rt, binding.root_account.account_generation));
    std::vector<uint8_t> digest(
        binding.root_account.authority_digest,
        binding.root_account.authority_digest +
            EXACT_GPU_AUTHORITY_DIGEST_SIZE_V2);
    defineGpuV2Property(
        rt,
        gpuNativeBridgeV2,
        "rootAuthorityDigest",
        makeUint8Array(rt, std::move(digest)));
    binding.decoded_image_authority_attached =
        runtime->gpu_decoded_image_binding_v1 != nullptr;
    if (!exactGpuDecodedImageAttachAuthorityV1(runtime, rt,
                                               gpuNativeBridgeV2)) {
      binding.decoded_image_authority_attached = false;
      return false;
    }
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "preventExtensions")
        .call(rt, gpuNativeBridgeV2);
    std::shared_ptr<facebook::jsi::Function> captureHolder;
    if (runtime->gpu_construction_capture) {
      captureHolder = runtime->gpu_construction_capture;
    } else {
      auto captureValue = rt.global().getProperty(rt, kGpuCaptureGlobalNameV2);
      if (!captureValue.isObject() ||
          !captureValue.getObject(rt).isFunction(rt)) {
        return false;
      }
      captureHolder = std::make_shared<facebook::jsi::Function>(
          captureValue.getObject(rt).asFunction(rt));
    }
    auto& capture = *captureHolder;
    auto captured = std::make_shared<facebook::jsi::Object>(
        std::move(gpuNativeBridgeV2));
    auto revokeValue = capture.call(rt, *captured);
    runtime->gpu_construction_capture.reset();
    if (!closeGpuV2ConstructionCapture(runtime) ||
        rt.global().hasProperty(rt, kGpuCaptureGlobalNameV2)) {
      return false;
    }
    std::shared_ptr<facebook::jsi::Function> revokeCapture;
    std::shared_ptr<facebook::jsi::Function> canvasReceiptSink;
    std::shared_ptr<facebook::jsi::Function> hostTaskCheckpoint;
    std::shared_ptr<facebook::jsi::Function> canvasAppBundleBegin;
    std::shared_ptr<facebook::jsi::Function> canvasAppBundleFinish;
    if (revokeValue.isObject() &&
        revokeValue.getObject(rt).isFunction(rt)) {
      // Compatibility with the original construction capture. It remains
      // revocable but deliberately has no typed Canvas delivery route.
      revokeCapture = std::make_shared<facebook::jsi::Function>(
          revokeValue.getObject(rt).asFunction(rt));
    } else if (!exactGpuV2CaptureResultFunctions(
                   runtime, revokeValue, &revokeCapture, &canvasReceiptSink,
                   &hostTaskCheckpoint, &canvasAppBundleBegin,
                   &canvasAppBundleFinish)) {
      return false;
    }
    binding.revoke_capture = std::move(revokeCapture);
    binding.canvas_receipt_sink = std::move(canvasReceiptSink);
    binding.host_task_checkpoint = std::move(hostTaskCheckpoint);
    binding.canvas_app_bundle_begin = std::move(canvasAppBundleBegin);
    binding.canvas_app_bundle_finish = std::move(canvasAppBundleFinish);
    binding.private_bridge = std::move(captured);
    binding.bridge_captured = true;
    return true;
  } catch (...) {
    closeGpuV2ConstructionCapture(runtime);
    return false;
  }
#endif
}

bool exactGpuV2SealPrivateBridge(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  return closeGpuV2ConstructionCapture(runtime);
#else
  if (!runtime || !runtime->runtime) return false;
  if (!closeGpuV2ConstructionCapture(runtime)) return false;
  if (!runtime->gpu_binding_v2) return true;
  auto& binding = *runtime->gpu_binding_v2;
  if (!binding.bridge_captured || !binding.private_bridge ||
      !binding.revoke_capture) {
    return false;
  }
  binding.bridge_sealed = true;
  return true;
#endif
}

bool exactGpuAuthenticatedV2ProviderGlobalsActive(
    const ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return false;
#else
  return runtime && runtime->gpu_binding_v2 &&
      runtime->gpu_binding_v2->realm_open &&
      runtime->gpu_binding_v2->bridge_captured &&
      runtime->gpu_binding_v2->bridge_sealed &&
      !runtime->gpu_binding_v2->detached;
#endif
}

bool exactGpuAuthenticatedDecodedImageGlobalActive(
    const ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return false;
#else
  return exactGpuAuthenticatedV2ProviderGlobalsActive(runtime) &&
      runtime->gpu_binding_v2->decoded_image_authority_attached;
#endif
}

bool exactGpuV2CheckpointHostTask(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return true;
#else
  if (!runtime || !runtime->runtime || !runtime->gpu_binding_v2) return true;
  auto binding = runtime->gpu_binding_v2;
  if (binding->detached || !binding->realm_open || !binding->bridge_captured ||
      !binding->bridge_sealed) {
    return true;
  }

  // The legacy function-only construction capture has neither typed Canvas
  // sink nor task checkpoint. It cannot mint a Canvas current texture, so it
  // remains a valid no-op compatibility path. A partial typed result is an
  // invariant failure and must reduce the realm before more user code runs.
  if (!binding->canvas_receipt_sink && !binding->host_task_checkpoint) {
    return true;
  }
  if (!binding->canvas_receipt_sink || !binding->host_task_checkpoint) {
    reduceGpuV2Realm(
        *binding, *runtime->runtime, "protocol-violation",
        EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION, {},
        "Exact GPU V2 typed Canvas checkpoint capture is incomplete", true);
    return false;
  }

  auto checkpoint = binding->host_task_checkpoint;
  try {
    checkpoint->call(*runtime->runtime);
#ifdef IBEX_GPU_BRIDGE_TEST_HOOKS
    gGpuV2HostTaskCheckpointCalls.fetch_add(1, std::memory_order_seq_cst);
#endif
    return true;
  } catch (...) {
    // The wrapper closes its realm when a checkpoint control submission is
    // rejected. Reduce the native realm too so no later task can retain or
    // reuse a current texture whose expiry outcome is ambiguous.
    if (!binding->detached) {
      reduceGpuV2Realm(*binding, *runtime->runtime,
                       "host-task-checkpoint-failed",
                       EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION, {},
                       "Exact GPU V2 host-task checkpoint failed", true);
    }
    return false;
  }
#endif
}

bool exactGpuV2OwnerDrainPending(const ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return false;
#else
  return runtime && runtime->gpu_binding_v2 && runtime->gpu_binding_v2->mailbox &&
      runtime->gpu_binding_v2->mailbox->owner_drain_required.load(
          std::memory_order_acquire);
#endif
}

int exactGpuV2DrainOwnerFallback(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return 0;
#else
  if (!runtime || !runtime->runtime || !runtime->gpu_binding_v2 ||
      !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  auto* mailbox = runtime->gpu_binding_v2->mailbox;
  if (!mailbox->owner_drain_required.exchange(
          false, std::memory_order_acq_rel)) {
    return 0;
  }
  drainGpuMailboxV2(mailbox, *runtime->runtime);
  return 1;
#endif
}

void exactGpuV2RollbackInstall(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->gpu_binding_v2) return;
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  runtime->gpu_binding_v2->detach(
      runtime, "Exact GPU V2 capability installation rolled back");
#endif
  runtime->gpu_binding_v2.reset();
}

void exactGpuV2BeginRuntimeTeardown(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->gpu_binding_v2) return;
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
  runtime->gpu_binding_v2->detach(runtime, "Exact GPU V2 runtime was destroyed");
#endif
  runtime->gpu_binding_v2.reset();
}

#if defined(IBEX_ENABLE_WEBGPU_BINDING) && \
    defined(IBEX_GPU_BRIDGE_TEST_HOOKS)
extern "C" void ibex_test_gpu_v2_reset_observer(void) {
  gGpuV2ResolveCalls.store(0, std::memory_order_seq_cst);
  gGpuV2RejectCalls.store(0, std::memory_order_seq_cst);
  gGpuV2DeviceLossCalls.store(0, std::memory_order_seq_cst);
  gGpuV2RealmReductionCalls.store(0, std::memory_order_seq_cst);
  gGpuV2WrapperEventCalls.store(0, std::memory_order_seq_cst);
  gGpuV2CanvasReceiptObserverCalls.store(0, std::memory_order_seq_cst);
  gGpuV2HostTaskCheckpointCalls.store(0, std::memory_order_seq_cst);
  gGpuV2LastRejectedPromiseId.store(0, std::memory_order_seq_cst);
  gGpuV2ObserverOrderClock.store(0, std::memory_order_seq_cst);
  gGpuV2LastRawEventOrder.store(0, std::memory_order_seq_cst);
  gGpuV2LastLogicalLossOrder.store(0, std::memory_order_seq_cst);
  gGpuV2LastDetachedLossOrder.store(0, std::memory_order_seq_cst);
  gGpuV2LastDeviceLostReactionOrder.store(0, std::memory_order_seq_cst);
  gGpuV2LastPromiseReactionOrder.store(0, std::memory_order_seq_cst);
  gGpuV2LastUncapturedProjectionValid.store(0, std::memory_order_seq_cst);
  gGpuV2OperationResultPayloadMaterializations.store(
      0, std::memory_order_seq_cst);
  gGpuV2OperationResultReusedMailboxBacking.store(
      0, std::memory_order_seq_cst);
  gGpuV2LastReceiptResolvedUndefined.store(0, std::memory_order_seq_cst);
  gGpuV2MappedArrayBufferGateFailure.store(0, std::memory_order_seq_cst);
  gGpuV2DrainPauseState.store(0, std::memory_order_seq_cst);
  gGpuV2ServiceEntryPauseKind.store(0, std::memory_order_seq_cst);
  gGpuV2ServiceEntryPauseState.store(0, std::memory_order_seq_cst);
  gGpuV2RealmCloseAdmissionPauseState.store(0, std::memory_order_seq_cst);
  gGpuV2DetachLockAttempted.store(0, std::memory_order_seq_cst);
  gGpuV2DetachCleanupPauseState.store(0, std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_v2_validate_event(
    const ExactGpuServiceEventV2* event) {
  return validEventPrefixV2(event) ? 1 : 0;
}

extern "C" int32_t ibex_test_gpu_v2_operation_terminal_flags_are_replay_authority(
    const ExactGpuServiceEventV2* event) {
  if (!validEventPrefixV2(event) ||
      event->kind != EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2 ||
      event->flags != EXACT_GPU_SERVICE_EVENT_FLAG_UNCAPTURED_ERROR_V2) {
    return 0;
  }
  try {
    auto mailbox =
        std::make_unique<ExactGpuClientMailboxV2>(RuntimeCallbackTarget{});
    std::vector<uint8_t> payload;
    if (event->payload_len != 0) {
      payload.assign(event->payload, event->payload + event->payload_len);
    }
    markTerminalV2(
        *mailbox,
        event->record.device_error.operation.operation_instance_id,
        nullptr,
        GpuTerminalCauseV2::CallbackAccepted,
        event,
        &payload);
    const size_t slot = terminalSlotV2(
        *mailbox,
        event->record.device_error.operation.operation_instance_id);
    if (slot == kMaxGpuRecentTerminalsV2 ||
        !equalOperationTerminalEventV2(
            mailbox->recent_terminal_event_kinds[slot],
            mailbox->recent_terminal_event_flags[slot],
            mailbox->recent_terminal_event_records[slot],
            mailbox->recent_terminal_event_payloads[slot],
            *event)) {
      return 0;
    }
    ExactGpuServiceEventV2 mutated = *event;
    mutated.flags = EXACT_GPU_SERVICE_EVENT_FLAG_NONE_V2;
    const bool trueToFalseContradicts = !equalOperationTerminalEventV2(
        mailbox->recent_terminal_event_kinds[slot],
        mailbox->recent_terminal_event_flags[slot],
        mailbox->recent_terminal_event_records[slot],
        mailbox->recent_terminal_event_payloads[slot],
        mutated);
    const bool falseToTrueContradicts = !equalOperationTerminalEventV2(
        mailbox->recent_terminal_event_kinds[slot],
        EXACT_GPU_SERVICE_EVENT_FLAG_NONE_V2,
        mailbox->recent_terminal_event_records[slot],
        mailbox->recent_terminal_event_payloads[slot],
        *event);
    return trueToFalseContradicts && falseToTrueContradicts ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" uint64_t ibex_test_gpu_v2_host_task_checkpoint_calls() {
  return gGpuV2HostTaskCheckpointCalls.load(std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_v2_recent_terminal_rotation_releases_payloads(
    void) {
  try {
    auto mailbox =
        std::make_unique<ExactGpuClientMailboxV2>(RuntimeCallbackTarget{});
    std::vector<uint8_t> largePayload(1024 * 1024, 0xa5);
    uint64_t operationInstance = 1;
    for (size_t cycle = 0; cycle < 4; ++cycle) {
      markTerminalV2(
          *mailbox,
          operationInstance++,
          nullptr,
          GpuTerminalCauseV2::CallbackAccepted,
          nullptr,
          &largePayload);
      for (size_t index = 0; index < kMaxGpuRecentTerminalsV2; ++index) {
        markTerminalV2(
            *mailbox,
            operationInstance++,
            nullptr,
            GpuTerminalCauseV2::CallbackAccepted,
            nullptr,
            nullptr);
      }
      size_t retainedCapacity = 0;
      for (const auto& payload : mailbox->recent_terminal_event_payloads) {
        retainedCapacity += payload.capacity();
      }
      if (mailbox->recent_terminal_payload_bytes != 0 ||
          retainedCapacity != 0) {
        return 0;
      }
    }
    return 1;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_lifecycle_replay_survives_recent_aging(
    const ExactGpuServiceEventV2* event) {
  if (!validEventPrefixV2(event) ||
      event->kind != EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2 ||
      !eventInitiatingOperationV2(*event)) {
    return 0;
  }
  try {
    auto mailbox =
        std::make_unique<ExactGpuClientMailboxV2>(RuntimeCallbackTarget{});
    if (rememberLifecycleEventV2(*mailbox, *event) !=
        GpuLifecycleReplayV2::New) {
      return 0;
    }
    const auto* initiating = eventInitiatingOperationV2(*event);
    markTerminalV2(
        *mailbox,
        initiating->operation_instance_id,
        nullptr,
        GpuTerminalCauseV2::CallbackAccepted,
        nullptr,
        nullptr);
    uint64_t operationInstance = initiating->operation_instance_id + 1;
    for (size_t index = 0; index < kMaxGpuRecentTerminalsV2 + 32; ++index) {
      markTerminalV2(
          *mailbox,
          operationInstance++,
          nullptr,
          GpuTerminalCauseV2::CallbackAccepted,
          nullptr,
          nullptr);
    }
    if (terminalSeenV2(*mailbox, initiating->operation_instance_id) ||
        preliminaryEventAdmissionV2(*mailbox, *event) !=
            GpuPreliminaryAdmissionV2::Discard) {
      return 0;
    }

    // Keep the lifecycle key and structural validity unchanged while mutating
    // a canonical field. The production preliminary admission helper must
    // classify this as a contradiction even though its initiating operation
    // has aged out of the bounded operation-terminal ring.
    ExactGpuServiceEventV2 mutated = *event;
    auto& ordinal = mutated.record.logical_device_lost.logical_loss_ordinal;
    ordinal = ordinal == std::numeric_limits<uint64_t>::max()
        ? ordinal - 1
        : ordinal + 1;
    if (!validEventPrefixV2(&mutated) ||
        preliminaryEventAdmissionV2(*mailbox, mutated) !=
            GpuPreliminaryAdmissionV2::ProtocolViolation) {
      return 0;
    }
    return 1;
  } catch (...) {
    return 0;
  }
}

extern "C" uint64_t ibex_test_gpu_v2_resolve_calls(void) {
  return gGpuV2ResolveCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_reject_calls(void) {
  return gGpuV2RejectCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_device_loss_calls(void) {
  return gGpuV2DeviceLossCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_realm_reduction_calls(void) {
  return gGpuV2RealmReductionCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_wrapper_event_calls(void) {
  return gGpuV2WrapperEventCalls.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_rejected_promise_id(void) {
  return gGpuV2LastRejectedPromiseId.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_raw_event_order(void) {
  return gGpuV2LastRawEventOrder.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_logical_loss_order(void) {
  return gGpuV2LastLogicalLossOrder.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_detached_loss_order(void) {
  return gGpuV2LastDetachedLossOrder.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_device_lost_reaction_order(void) {
  return gGpuV2LastDeviceLostReactionOrder.load(std::memory_order_seq_cst);
}

extern "C" uint64_t ibex_test_gpu_v2_last_promise_reaction_order(void) {
  return gGpuV2LastPromiseReactionOrder.load(std::memory_order_seq_cst);
}

extern "C" uint32_t
ibex_test_gpu_v2_last_uncaptured_projection_valid(void) {
  return gGpuV2LastUncapturedProjectionValid.load(
      std::memory_order_seq_cst);
}

extern "C" uint64_t
ibex_test_gpu_v2_operation_result_payload_materializations(void) {
  return gGpuV2OperationResultPayloadMaterializations.load(
      std::memory_order_seq_cst);
}

extern "C" uint32_t
ibex_test_gpu_v2_operation_result_reused_mailbox_backing(void) {
  return gGpuV2OperationResultReusedMailboxBacking.load(
      std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_last_receipt_resolved_undefined(void) {
  return gGpuV2LastReceiptResolvedUndefined.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_pause_after_terminal_pop(void) {
  gGpuV2DrainPauseState.store(1, std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_terminal_pop_pause_state(void) {
  return gGpuV2DrainPauseState.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_resume_after_terminal_pop(void) {
  gGpuV2DrainPauseState.store(3, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_pause_reserved_service_entry(
    uint32_t kind) {
  gGpuV2ServiceEntryPauseKind.store(kind, std::memory_order_seq_cst);
  gGpuV2ServiceEntryPauseState.store(1, std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_service_entry_pause_state(void) {
  return gGpuV2ServiceEntryPauseState.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_resume_reserved_service_entry(void) {
  gGpuV2ServiceEntryPauseState.store(3, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_pause_realm_close_admission(void) {
  gGpuV2DetachLockAttempted.store(0, std::memory_order_seq_cst);
  gGpuV2RealmCloseAdmissionPauseState.store(1, std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_realm_close_admission_pause_state(void) {
  return gGpuV2RealmCloseAdmissionPauseState.load(std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_detach_lock_attempted(void) {
  return gGpuV2DetachLockAttempted.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_resume_realm_close_admission(void) {
  gGpuV2RealmCloseAdmissionPauseState.store(3, std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_pause_detach_cleanup(void) {
  gGpuV2DetachCleanupPauseState.store(1, std::memory_order_seq_cst);
}

extern "C" uint32_t ibex_test_gpu_v2_detach_cleanup_pause_state(void) {
  return gGpuV2DetachCleanupPauseState.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_resume_detach_cleanup(void) {
  gGpuV2DetachCleanupPauseState.store(3, std::memory_order_seq_cst);
}

extern "C" int32_t ibex_test_gpu_v2_install_canvas_receipt_observer(
    ExactHermesRuntime* runtime,
    const ExactGpuCanvasAttachmentReceiptV1* expected_receipt) {
  if (!runtime || !runtime->runtime || !expected_receipt ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !validCanvasAttachmentReceiptV1(*expected_receipt) ||
      !runtime->gpu_binding_v2 || runtime->gpu_binding_v2->detached ||
      !runtime->gpu_binding_v2->realm_open ||
      !runtime->gpu_binding_v2->bridge_captured ||
      !runtime->gpu_binding_v2->bridge_sealed ||
      !runtime->gpu_binding_v2->canvas_receipt_sink ||
      runtime->gpu_binding_v2->realm.runtime.runtime_nonce !=
          expected_receipt->runtime_generation) {
    return 0;
  }
  try {
    const auto expected = *expected_receipt;
    auto observer = facebook::jsi::Function::createFromHostFunction(
        *runtime->runtime,
        facebook::jsi::PropNameID::forAscii(
            *runtime->runtime, "observeGpuCanvasAttachmentReceipt"),
        1,
        [runtime, expected](facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          gGpuV2CanvasReceiptObserverCalls.fetch_add(
              1, std::memory_order_seq_cst);
          if (count != 1 ||
              !canvasReceiptValueMatchesV1(
                  runtime, rt, args[0], expected)) {
            throw facebook::jsi::JSError(
                rt, "GPU Canvas attachment receipt shape mismatch");
          }
          return facebook::jsi::Value::undefined();
        });
    runtime->gpu_binding_v2->canvas_receipt_sink =
        std::make_shared<facebook::jsi::Function>(std::move(observer));
    return 1;
  } catch (...) {
    return 0;
  }
}

extern "C" uint64_t ibex_test_gpu_v2_canvas_receipt_observer_calls(void) {
  return gGpuV2CanvasReceiptObserverCalls.load(std::memory_order_seq_cst);
}

extern "C" void ibex_test_gpu_v2_queue_debugger_event(
    ExactHermesRuntime* runtime) {
  pushDebugEvent(
      runtime,
      "{\"method\":\"Ibex.testDebuggerGate\",\"params\":{}}");
}

extern "C" void ibex_test_gpu_v2_pause_next_debugger_interrupt_after_enqueue(
    ExactHermesRuntime* runtime) {
  if (!runtime) return;
  runtime->test_debugger_interrupt_enqueue_paused.store(
      false, std::memory_order_release);
  runtime->test_pause_debugger_after_interrupt_enqueue.store(
      true, std::memory_order_release);
}

extern "C" uint32_t ibex_test_gpu_v2_debugger_interrupt_enqueue_paused(
    ExactHermesRuntime* runtime) {
  return runtime && runtime->test_debugger_interrupt_enqueue_paused.load(
                        std::memory_order_acquire)
      ? 1
      : 0;
}

extern "C" uint32_t ibex_test_gpu_v2_immediate_eval_markers(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->root_global_get_own_property_descriptor) {
    return UINT32_MAX;
  }
  try {
    auto& rt = *runtime->runtime;
    auto marker = [&](const char* name) -> bool {
      auto descriptor = runtime->root_global_get_own_property_descriptor->call(
          rt,
          rt.global(),
          facebook::jsi::String::createFromAscii(rt, name));
      if (descriptor.isUndefined()) return false;
      if (!descriptor.isObject()) {
        throw std::runtime_error("immediate-eval marker descriptor invalid");
      }
      auto value = gpuCanvasDescriptorFieldV1(
          runtime, descriptor.asObject(rt), "value");
      return value.isBool() && value.getBool();
    };
    uint32_t bits = 0;
    if (marker("__ibexImmediateNextTickRan")) bits |= 1u << 0;
    if (marker("__ibexImmediateMicrotaskRan")) bits |= 1u << 1;
    if (marker("__ibexImmediateThenInspected")) bits |= 1u << 2;
    if (marker("__ibexImmediateResultCoerced")) bits |= 1u << 3;
    if (marker("__ibexImmediateHandlerCalled")) bits |= 1u << 4;
    return bits;
  } catch (...) {
    return UINT32_MAX;
  }
}

extern "C" int32_t
ibex_test_gpu_v2_consume_canvas_app_bundle_integration(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 ||
      !runtime->gpu_binding_v2->canvas_app_bundle_open ||
      runtime->gpu_binding_v2->canvas_app_bundle_expectation !=
          EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 ||
      !runtime->gpu_binding_v2->canvas_app_bundle_capture) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Object integration(rt);
    auto install = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(
            rt, "installCanvasContextMinter"),
        1,
        [](facebook::jsi::Runtime& rt,
           const facebook::jsi::Value&,
           const facebook::jsi::Value* args,
           size_t count) -> facebook::jsi::Value {
          if (count != 1 || !args[0].isObject()) {
            throw facebook::jsi::JSError(
                rt, "Canvas minter test integration received no object");
          }
          auto minter = args[0].asObject(rt);
          auto mint = minter.getProperty(rt, "mintCanvasContext");
          if (!mint.isObject() || !mint.asObject(rt).isFunction(rt)) {
            throw facebook::jsi::JSError(
                rt, "Canvas minter test integration received no mint function");
          }
          return facebook::jsi::Function::createFromHostFunction(
              rt,
              facebook::jsi::PropNameID::forAscii(
                  rt, "releaseCanvasContextMinter"),
              0,
              [](facebook::jsi::Runtime&,
                 const facebook::jsi::Value&,
                 const facebook::jsi::Value*,
                 size_t) -> facebook::jsi::Value {
                return facebook::jsi::Value::undefined();
              });
        });
    auto deliver = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(
            rt, "deliverCanvasAttachmentReceipt"),
        1,
        [](facebook::jsi::Runtime&,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) -> facebook::jsi::Value {
          return facebook::jsi::Value::undefined();
        });
    integration.setProperty(
        rt, "installCanvasContextMinter", std::move(install));
    integration.setProperty(
        rt, "deliverCanvasAttachmentReceipt", std::move(deliver));
    rt.global()
        .getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "freeze")
        .call(rt, integration);
    runtime->gpu_binding_v2->canvas_app_bundle_capture->call(
        rt, integration);
    return 1;
  } catch (...) {
    return 0;
  }
}

static bool attachGpuV2TestEventObserver(
    ExactHermesRuntime* runtime,
    facebook::jsi::Runtime& rt,
    facebook::jsi::Value& argument) {
  auto& binding = *runtime->gpu_binding_v2;
  if (!binding.wrapper_event_sink_set) {
    (void)setGpuV2EventSinkCarrierCall(runtime, rt, &argument, 1);
    return true;
  }

  // Authenticated provider publication installs the production wrapper's
  // one-shot sink. A test build observes that exact delivered object through a
  // separate close-gated slot instead of weakening or replacing the sink.
  auto observer = std::make_shared<facebook::jsi::Function>(
      argument.asObject(rt).asFunction(rt));
  if (!binding.mailbox) return false;
  std::lock_guard<std::mutex> lock(binding.mailbox->mutex);
  if (binding.mailbox->phase.load(std::memory_order_acquire) !=
          GpuMailboxPhaseV2::Live ||
      !binding.realm_open || binding.test_event_observer) {
    return false;
  }
  binding.test_event_observer = std::move(observer);
  return true;
}

extern "C" int32_t ibex_test_gpu_v2_install_mailbox_only_event_sink(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    auto sink = std::make_shared<facebook::jsi::Function>(
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "observeGpuV2MailboxOnlyEvent"),
            1,
            [](facebook::jsi::Runtime&,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) {
              return facebook::jsi::Value::undefined();
            }));
    std::lock_guard<std::mutex> lock(
        runtime->gpu_binding_v2->mailbox->mutex);
    if (
        runtime->gpu_binding_v2->mailbox->phase.load(
            std::memory_order_acquire) != GpuMailboxPhaseV2::Live ||
        !runtime->gpu_binding_v2->realm_open) {
      return 0;
    }
    runtime->gpu_binding_v2->wrapper_event_sink = std::move(sink);
    runtime->gpu_binding_v2->wrapper_event_sink_set = true;
    return 1;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_install_event_observer(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    auto lossResolvers = std::make_shared<GpuPromiseResolversV2>();
    auto lossPromise = makeGpuV2Promise(rt, lossResolvers);
    auto observeLossReaction = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(
            rt, "observeGpuV2DeviceLostReaction"),
        1,
        [](facebook::jsi::Runtime&,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) {
          const uint64_t order =
              gGpuV2ObserverOrderClock.fetch_add(
                  1, std::memory_order_seq_cst) +
              1;
          gGpuV2LastDeviceLostReactionOrder.store(
              order, std::memory_order_seq_cst);
          return facebook::jsi::Value::undefined();
        });
    lossPromise.getPropertyAsFunction(rt, "then").callWithThis(
        rt, lossPromise, observeLossReaction);
    auto lossResolved = std::make_shared<bool>(false);
    facebook::jsi::Value argument(
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(rt, "observeGpuV2Event"),
            1,
            [lossResolvers, lossResolved](facebook::jsi::Runtime& rt,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) {
              gGpuV2WrapperEventCalls.fetch_add(
                  1, std::memory_order_seq_cst);
              const uint64_t order =
                  gGpuV2ObserverOrderClock.fetch_add(
                      1, std::memory_order_seq_cst) +
                  1;
              gGpuV2LastRawEventOrder.store(order, std::memory_order_seq_cst);
              if (count == 1 && args[0].isObject()) {
                auto event = args[0].getObject(rt);
                auto kind = event.getProperty(rt, "kind");
                if (kind.isNumber() &&
                    static_cast<uint32_t>(kind.asNumber()) ==
                        EXACT_GPU_SERVICE_EVENT_LOGICAL_DEVICE_LOST_V2) {
                  gGpuV2LastLogicalLossOrder.store(
                      order, std::memory_order_seq_cst);
                  if (!*lossResolved) {
                    *lossResolved = true;
                    lossResolvers->resolve->call(
                        rt, facebook::jsi::Value::undefined());
                  }
                } else if (
                    kind.isNumber() &&
                    static_cast<uint32_t>(kind.asNumber()) ==
                        EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2) {
                  const auto uncaptured =
                      event.getProperty(rt, "uncapturedError");
                  gGpuV2LastUncapturedProjectionValid.store(
                      uncaptured.isBool() && !uncaptured.getBool() &&
                              !event.hasProperty(rt, "flags")
                          ? 1
                          : 2,
                      std::memory_order_seq_cst);
                } else if (
                    kind.isNumber() &&
                    static_cast<uint32_t>(kind.asNumber()) ==
                        EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2) {
                  auto detached =
                      event.getProperty(rt, "detachedAlreadyLost");
                  if (detached.isBool() && detached.getBool()) {
                    gGpuV2LastDetachedLossOrder.store(
                        order, std::memory_order_seq_cst);
                    if (!*lossResolved) {
                      *lossResolved = true;
                      lossResolvers->resolve->call(
                          rt, facebook::jsi::Value::undefined());
                    }
                  }
                }
              }
              return facebook::jsi::Value::undefined();
            }));
    return attachGpuV2TestEventObserver(runtime, rt, argument) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_install_throwing_event_observer(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Value argument(
        facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(
                rt, "throwFromGpuV2EventObserver"),
            1,
            [](facebook::jsi::Runtime& rt,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
              gGpuV2WrapperEventCalls.fetch_add(
                  1, std::memory_order_seq_cst);
              throw facebook::jsi::JSError(
                  rt, "intentional GPU V2 event observer failure");
            }));
    return attachGpuV2TestEventObserver(runtime, rt, argument) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_cancel(
    ExactHermesRuntime* runtime,
    uint64_t operation_instance_id,
    uint64_t promise_id) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || operation_instance_id == 0) {
    return -1000;
  }
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Value arguments[] = {
        gpuV2Uint64String(rt, operation_instance_id),
        gpuV2Uint64String(rt, promise_id),
    };
    auto result = cancelGpuV2CarrierCall(runtime, rt, arguments, 2);
    return result.isNumber()
        ? static_cast<int32_t>(result.asNumber())
        : -1000;
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_v2_private_bridge_present(
    ExactHermesRuntime* runtime) {
  return runtime && runtime->runtime_thread == std::this_thread::get_id() &&
          runtime->gpu_binding_v2 && runtime->gpu_binding_v2->private_bridge &&
          runtime->gpu_binding_v2->bridge_captured
      ? 1
      : 0;
}

extern "C" int32_t ibex_test_gpu_v2_canvas_receipt_sink_present(
    ExactHermesRuntime* runtime) {
  return runtime && runtime->runtime_thread == std::this_thread::get_id() &&
          runtime->gpu_binding_v2 &&
          runtime->gpu_binding_v2->canvas_receipt_sink
      ? 1
      : 0;
}

extern "C" int32_t ibex_test_gpu_v2_mapped_array_buffer_gate(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id()) {
    return -1;
  }
  return hasGpuV2MappedArrayBufferApi(*runtime->runtime) ? 1 : 0;
}

extern "C" int32_t ibex_test_gpu_v2_force_mapped_array_buffer_gate_failure(
    uint32_t failure) {
  if (failure > 2) return -1;
  gGpuV2MappedArrayBufferGateFailure.store(failure, std::memory_order_seq_cst);
  return 0;
}

extern "C" int32_t ibex_test_gpu_v2_mapped_range_bridge_roundtrip(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->private_bridge ||
      !hasGpuV2MappedArrayBufferApi(*runtime->runtime)) {
    return 0;
  }
  try {
    auto& rt = *runtime->runtime;
    auto& bridge = *runtime->gpu_binding_v2->private_bridge;
    auto createAlias =
        bridge.getPropertyAsFunction(rt, "createMappedRangeAlias");
    auto detachAlias = bridge.getPropertyAsFunction(rt, "detachMappedRange");
    auto sourceObject = rt.global()
                            .getPropertyAsFunction(rt, "ArrayBuffer")
                            .callAsConstructor(rt, 16)
                            .getObject(rt);
    auto source = sourceObject.getArrayBuffer(rt);
    source.data(rt)[5] = 17;
    auto aliasObject = createAlias
                           .callWithThis(rt, bridge, sourceObject, 4, 6)
                           .getObject(rt);
    if (!aliasObject.isArrayBuffer(rt)) return 0;
    auto alias = aliasObject.getArrayBuffer(rt);
    if (alias.size(rt) != 6 || alias.data(rt)[1] != 17) return 0;
    alias.data(rt)[2] = 29;
    if (source.data(rt)[6] != 29) return 0;

    // Exercise composition through the construction-private HostFunction,
    // rather than only calling Hermes' engine interface directly: overlapping
    // aliases share the source, while OOB and alias-as-source requests reject.
    auto overlappingObject = createAlias
                                 .callWithThis(rt, bridge, sourceObject, 5, 3)
                                 .getObject(rt);
    if (!overlappingObject.isArrayBuffer(rt)) return 0;
    auto overlapping = overlappingObject.getArrayBuffer(rt);
    if (overlapping.size(rt) != 3 || overlapping.data(rt)[1] != 29) return 0;
    overlapping.data(rt)[0] = 37;
    if (source.data(rt)[5] != 37 || alias.data(rt)[1] != 37) return 0;

    bool outOfBoundsRejected = false;
    try {
      (void)createAlias.callWithThis(rt, bridge, sourceObject, 15, 2);
    } catch (...) {
      outOfBoundsRejected = true;
    }
    bool aliasSourceRejected = false;
    try {
      (void)createAlias.callWithThis(rt, bridge, aliasObject, 0, 1);
    } catch (...) {
      aliasSourceRejected = true;
    }

#if defined(JSI_UNSTABLE)
    bool transferRejected = false;
    auto* serialization =
        facebook::jsi::castInterface<facebook::jsi::ISerialization>(&rt);
    if (!serialization) return 0;
    auto transfers = facebook::jsi::Array::createWithElements(
        rt, facebook::jsi::Value(rt, alias));
    auto transferValue = facebook::jsi::Value(rt, alias);
    try {
      (void)serialization->serializeWithTransfer(
          transferValue, transfers);
    } catch (...) {
      transferRejected = true;
    }
#else
    const bool transferRejected = false;
#endif

    const auto detached =
        detachAlias.callWithThis(rt, bridge, aliasObject);
    const auto duplicate =
        detachAlias.callWithThis(rt, bridge, aliasObject);
    const auto wrongSource =
        detachAlias.callWithThis(rt, bridge, sourceObject);
    const auto overlappingDetached =
        detachAlias.callWithThis(rt, bridge, overlappingObject);
    return detached.isBool() && detached.getBool() && duplicate.isBool() &&
            !duplicate.getBool() && wrongSource.isBool() &&
            !wrongSource.getBool() && overlappingDetached.isBool() &&
            overlappingDetached.getBool() && outOfBoundsRejected &&
            aliasSourceRejected && transferRejected && source.size(rt) == 16 &&
            source.data(rt)[5] == 37 && source.data(rt)[6] == 29
        ? 1
        : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_v2_pending_receipts(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2) {
    return 0;
  }
  return runtime->gpu_binding_v2->pending_receipts.size();
}

extern "C" size_t ibex_test_gpu_v2_mailbox_submissions(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding_v2->mailbox->mutex);
    return runtime->gpu_binding_v2->mailbox->submissions.size();
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_v2_mailbox_sealed_submissions(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding_v2->mailbox->mutex);
    return runtime->gpu_binding_v2->mailbox->sealed_submissions.size();
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_v2_mailbox_sealed_batches(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding_v2->mailbox->mutex);
    return runtime->gpu_binding_v2->mailbox->sealed_batches.size();
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_copy_sealed_submission(
    ExactHermesRuntime* runtime,
    uint64_t operation_instance_id,
    ExactGpuSemanticCallV2* out_call) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox ||
      !out_call) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding_v2->mailbox->mutex);
    auto child = runtime->gpu_binding_v2->mailbox->sealed_submissions.find(
        operation_instance_id);
    if (
        child ==
        runtime->gpu_binding_v2->mailbox->sealed_submissions.end()) {
      return 0;
    }
    *out_call = child->second.submission.call;
    return 1;
  } catch (...) {
    return 0;
  }
}

extern "C" size_t ibex_test_gpu_v2_lifecycle_tombstones(
    ExactHermesRuntime* runtime) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !runtime->gpu_binding_v2->mailbox) {
    return 0;
  }
  try {
    std::lock_guard<std::mutex> lock(runtime->gpu_binding_v2->mailbox->mutex);
    return runtime->gpu_binding_v2->mailbox->lifecycle_tombstone_count;
  } catch (...) {
    return 0;
  }
}

extern "C" int32_t ibex_test_gpu_v2_submit(
    ExactHermesRuntime* runtime,
    const ExactGpuSemanticCallV2* template_call,
    int32_t wants_promise,
    uint64_t* out_operation_instance_id,
    uint64_t* out_promise_id) {
  if (out_operation_instance_id) *out_operation_instance_id = 0;
  if (out_promise_id) *out_promise_id = 0;
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !template_call ||
      template_call->struct_size != sizeof(ExactGpuSemanticCallV2) ||
      template_call->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V2 ||
      (wants_promise != 0 && wants_promise != 1)) {
    return -1000;
  }
  try {
    auto call = *template_call;
    call.realm = runtime->gpu_binding_v2->realm;
    call.operation_instance_id = 0;
    call.promise_id = 0;
    auto result = submitGpuV2Carrier(
        runtime,
        *runtime->gpu_binding_v2,
        *runtime->runtime,
        call,
        wants_promise == 1);
    if (!result.isObject()) return -1000;
    auto object = result.getObject(*runtime->runtime);
    auto operation = object.getProperty(*runtime->runtime, "operationInstanceId");
    auto promise = object.getProperty(*runtime->runtime, "promiseId");
    auto admission = object.getProperty(*runtime->runtime, "submissionStatus");
    if (!operation.isString() || !promise.isString() || !admission.isNumber()) {
      return -1000;
    }
    const uint64_t parsedOperation = parseCanonicalGpuV2Uint64(
        *runtime->runtime, operation, "operationInstanceId", false);
    const uint64_t parsedPromise = parseCanonicalGpuV2Uint64(
        *runtime->runtime, promise, "promiseId", true);
    if (out_operation_instance_id) *out_operation_instance_id = parsedOperation;
    if (out_promise_id) *out_promise_id = parsedPromise;
    auto receipt = object.getProperty(*runtime->runtime, "receipt");
    if (receipt.isObject()) {
      auto promiseObject = receipt.getObject(*runtime->runtime);
      auto observeSettlement = facebook::jsi::Function::createFromHostFunction(
          *runtime->runtime,
          facebook::jsi::PropNameID::forAscii(
              *runtime->runtime, "observeGpuV2TestSettlement"),
          1,
          [](facebook::jsi::Runtime&,
             const facebook::jsi::Value&,
             const facebook::jsi::Value* args,
             size_t count) {
            const uint64_t order =
                gGpuV2ObserverOrderClock.fetch_add(
                    1, std::memory_order_seq_cst) +
                1;
            gGpuV2LastPromiseReactionOrder.store(
                order, std::memory_order_seq_cst);
            gGpuV2LastReceiptResolvedUndefined.store(
                count == 1 && args[0].isUndefined() ? 1 : 0,
                std::memory_order_seq_cst);
            return facebook::jsi::Value::undefined();
          });
      auto then = promiseObject.getPropertyAsFunction(*runtime->runtime, "then");
      then.callWithThis(
          *runtime->runtime,
          promiseObject,
          observeSettlement,
          observeSettlement);
    }
    return static_cast<int32_t>(admission.asNumber());
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_v2_submit_sealed(
    ExactHermesRuntime* runtime,
    const ExactGpuSemanticCallV2* template_call,
    int32_t wants_promise,
    const ExactGpuSemanticCallV2* child_templates,
    const uint32_t* authority_sources,
    size_t child_count,
    uint64_t* out_operation_instance_id,
    uint64_t* out_promise_id) {
  if (out_operation_instance_id) *out_operation_instance_id = 0;
  if (out_promise_id) *out_promise_id = 0;
  if (!runtime || !runtime->runtime ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !template_call ||
      template_call->struct_size != sizeof(ExactGpuSemanticCallV2) ||
      template_call->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V2 ||
      (wants_promise != 0 && wants_promise != 1) ||
      child_count == 0 || child_count > kMaxGpuPendingOperationsV2 ||
      !child_templates || !authority_sources) {
    return -1000;
  }
  try {
    auto call = *template_call;
    call.realm = runtime->gpu_binding_v2->realm;
    call.operation_instance_id = 0;
    call.promise_id = 0;
    std::vector<ParsedGpuSealedOperationV2> sealed;
    sealed.reserve(child_count);
    uint64_t previousOperationInstance = 0;
    uint64_t previousDeviceIngress = 0;
    for (size_t index = 0; index < child_count; ++index) {
      const auto& descriptor = child_templates[index];
      if (
          descriptor.struct_size != sizeof(ExactGpuSemanticCallV2) ||
          descriptor.abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V2 ||
          descriptor.operation_id == 0 ||
          descriptor.operation_instance_id < (uint64_t{1} << 63) ||
          descriptor.operation_instance_id <= previousOperationInstance ||
          descriptor.device_ingress_ordinal == 0 ||
          descriptor.device_ingress_ordinal <= previousDeviceIngress ||
          descriptor.device_ingress_ordinal >=
              call.device_ingress_ordinal ||
          !validObjectV2(descriptor.receiver, false) ||
          !validObjectV2(descriptor.target, true)) {
        return -1000;
      }
      ParsedGpuSealedOperationV2 child;
      child.call = call;
      child.call.operation_id = descriptor.operation_id;
      child.call.operation_instance_id =
          descriptor.operation_instance_id;
      child.call.promise_id = 0;
      child.call.captured_scope_id = descriptor.captured_scope_id;
      child.call.adapter_ordinal = 0;
      child.call.device_ingress_ordinal =
          descriptor.device_ingress_ordinal;
      child.call.queue_ingress_ordinal = 0;
      child.call.receiver = descriptor.receiver;
      child.call.target = descriptor.target;
      child.call.payload = nullptr;
      child.call.payload_len = 0;
      std::copy(
          std::begin(descriptor.authority_context_digest),
          std::end(descriptor.authority_context_digest),
          std::begin(child.call.authority_context_digest));
      child.call.authority_session_id = 0;
      const bool active =
          runtime->gpu_binding_v2->allowed_operations.count(
              child.call.operation_id) != 0;
      switch (authority_sources[index]) {
        case 1:
          if (!active ||
              !nonzeroDigestV2(child.call.authority_context_digest)) {
            return -1000;
          }
          child.authority_context_source =
              GpuSealedAuthorityContextSourceV2::CommandProgram;
          break;
        case 2:
          if (active &&
              !nonzeroDigestV2(child.call.authority_context_digest)) {
            child.authority_context_source =
                GpuSealedAuthorityContextSourceV2::EnclosingCarrier;
            break;
          }
          return -1000;
        case 3:
          if (active ||
              !nonzeroDigestV2(child.call.authority_context_digest)) {
            return -1000;
          }
          child.staged_local = true;
          child.authority_context_source =
              GpuSealedAuthorityContextSourceV2::StagedRecord;
          break;
        default:
          return -1000;
      }
      previousOperationInstance = child.call.operation_instance_id;
      previousDeviceIngress = child.call.device_ingress_ordinal;
      sealed.push_back(std::move(child));
    }
    auto result = submitGpuV2Carrier(
        runtime,
        *runtime->gpu_binding_v2,
        *runtime->runtime,
        call,
        wants_promise == 1,
        std::move(sealed));
    if (!result.isObject()) return -1000;
    auto object = result.getObject(*runtime->runtime);
    auto operation =
        object.getProperty(*runtime->runtime, "operationInstanceId");
    auto promise = object.getProperty(*runtime->runtime, "promiseId");
    auto admission =
        object.getProperty(*runtime->runtime, "submissionStatus");
    if (!operation.isString() || !promise.isString() ||
        !admission.isNumber()) {
      return -1000;
    }
    const uint64_t parsedOperation = parseCanonicalGpuV2Uint64(
        *runtime->runtime, operation, "operationInstanceId", false);
    const uint64_t parsedPromise = parseCanonicalGpuV2Uint64(
        *runtime->runtime, promise, "promiseId", true);
    if (out_operation_instance_id) {
      *out_operation_instance_id = parsedOperation;
    }
    if (out_promise_id) *out_promise_id = parsedPromise;
    return static_cast<int32_t>(admission.asNumber());
  } catch (...) {
    return -1000;
  }
}

extern "C" int32_t ibex_test_gpu_v2_retire(
    ExactHermesRuntime* runtime,
    const ExactGpuOwnedObjectRefV2* objects,
    size_t object_count) {
  if (!runtime || runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->gpu_binding_v2 || !objects || object_count == 0 ||
      object_count > kMaxGpuRetireObjectsV2) {
    return -1000;
  }
  for (size_t index = 0; index < object_count; ++index) {
    if (!validAccountV2(objects[index].account) ||
        !validDeviceV2(objects[index].device) ||
        !validObjectV2(objects[index].object, false)) {
      return -1000;
    }
  }
  ExactGpuRetireBatchV2 batch = {
      sizeof(ExactGpuRetireBatchV2),
      EXACT_GPU_SERVICE_ABI_VERSION_V2,
      0,
      0,
      objects,
      object_count,
  };
  return retireGpuV2Carrier(*runtime->gpu_binding_v2, batch);
}
#endif
