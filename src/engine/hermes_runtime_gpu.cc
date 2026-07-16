// @system @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Optional provider-independent Exact GPU service registration. This file
// intentionally installs no JSI value and contains no wgpu-native dependency.

#include "hermes_runtime_internal.h"
#include "../../include/exact_runtime.h"

#include <atomic>
#include <cstring>
#include <memory>
#include <string>

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

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
constexpr size_t kMaxGpuOperationCount = 4096;
constexpr size_t kMaxGpuProfileIdBytes = 256;
constexpr size_t kMaxGpuEventPayloadBytes = 16 * 1024 * 1024;

enum class GpuMailboxPhase : uint8_t {
  Installing,
  Live,
  ProtocolViolation,
  Closing,
  Detached,
};

struct ExactGpuClientMailbox {
  explicit ExactGpuClientMailbox(RuntimeCallbackTarget target) : target(target) {}

  std::atomic<uint32_t> references{1};
  std::atomic<GpuMailboxPhase> phase{GpuMailboxPhase::Installing};
  std::atomic<uint64_t> accepted_events{0};
  RuntimeCallbackTarget target;
  std::atomic<ExactGpuRealmTokenV1> realm{0};
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

bool validGpuEvent(const ExactGpuServiceEventV1* event) {
  if (!event || event->struct_size < sizeof(ExactGpuServiceEventV1) ||
      event->abi_version != EXACT_GPU_SERVICE_ABI_VERSION_V1 ||
      event->flags != 0 || event->reserved != 0 ||
      event->kind < EXACT_GPU_SERVICE_EVENT_OPERATION_COMPLETE ||
      event->kind > EXACT_GPU_SERVICE_EVENT_REALM_CLOSED ||
      event->payload_len > kMaxGpuEventPayloadBytes ||
      (event->payload_len > 0 && event->payload == nullptr)) {
    return false;
  }
  return true;
}

int32_t receiveGpuEvent(
    void* context,
    const ExactGpuServiceEventV1* event) {
  if (!context) {
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  auto* mailbox = static_cast<ExactGpuClientMailbox*>(context);
  auto phase = mailbox->phase.load(std::memory_order_acquire);
  if (phase == GpuMailboxPhase::Installing) {
    auto expected = GpuMailboxPhase::Installing;
    if (mailbox->phase.compare_exchange_strong(
            expected,
            GpuMailboxPhase::ProtocolViolation,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
    }
    phase = expected;
  }
  if (phase == GpuMailboxPhase::ProtocolViolation) {
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  if (phase != GpuMailboxPhase::Live) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }
  if (!validGpuEvent(event)) {
    return EXACT_GPU_CLIENT_EVENT_PROTOCOL_VIOLATION;
  }
  if (!runtimeIsAlive(mailbox->target) ||
      event->realm_token != mailbox->realm.load(std::memory_order_acquire)) {
    return EXACT_GPU_CLIENT_EVENT_DISCARDED;
  }

  // Foundation checkpoint only: prove the service-thread mailbox contract but
  // publish no JSI work. A later generated binding may schedule one bounded
  // owner-thread drain after taking a short runtime-generation pin.
  mailbox->accepted_events.fetch_add(1, std::memory_order_relaxed);
  return EXACT_GPU_CLIENT_EVENT_ACCEPTED;
}

const ExactGpuClientSinkV1 kGpuClientSink = {
    sizeof(ExactGpuClientSinkV1),
    EXACT_GPU_SERVICE_ABI_VERSION_V1,
    retainGpuClient,
    releaseGpuClient,
    receiveGpuEvent,
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
#endif

}  // namespace

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
struct ExactGpuRuntimeBinding {
  ExactGpuServiceApiV1 api{};
  ExactGpuClientMailbox* mailbox{nullptr};
  ExactGpuRealmTokenV1 realm{0};
  ExactGpuAccountTokenV1 account{0};
  bool service_retained{false};
  bool realm_open{false};
  bool detached{false};

  ~ExactGpuRuntimeBinding() {
    detach();
  }

  void detach() noexcept {
    if (detached) return;
    detached = true;
    if (mailbox) {
      mailbox->phase.store(GpuMailboxPhase::Closing, std::memory_order_release);
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
};
#else
struct ExactGpuRuntimeBinding {
  void detach() noexcept {}
};
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
  if (runtime->gpu_binding) return EXACT_GPU_PROVIDER_ALREADY_INSTALLED;
  // Each size/version gate precedes every later-field read. A caller may pass
  // only the prefix it advertises; never inspect abi_version (or the nested
  // function table) after a short-size rejection.
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
          EXACT_GPU_SERVICE_TOPOLOGY_ISOLATED_PER_LOGICAL_DEVICE_V1 ||
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

  // Registration is provisional. Realm creation is deliberately deferred to
  // the one-shot transaction finalizer, after every setter has run, so an
  // app/agent context installed by the Exact ingress cannot depend on setter
  // order. The mailbox stays Installing and has not been shared with the
  // provider yet.
  runtime->gpu_binding = std::move(binding);
  return EXACT_GPU_PROVIDER_OK;
#endif
}

int32_t exactGpuActivateInstall(ExactHermesRuntime* runtime) {
#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
  (void)runtime;
  return EXACT_GPU_PROVIDER_OK;
#else
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
    // The provider may retain the plain-native sink during open_realm, but it
    // is forbidden to call on_event or publish an event producer until
    // activate_realm. An event callback that wins this competing transition
    // is therefore unambiguously early.
    auto expected = GpuMailboxPhase::Installing;
    activated = binding->mailbox->phase.compare_exchange_strong(
        expected,
        GpuMailboxPhase::Live,
        std::memory_order_acq_rel,
        std::memory_order_acquire);
  }
  if (!activated) {
    const bool protocolViolation =
        binding->mailbox->phase.load(std::memory_order_acquire) ==
        GpuMailboxPhase::ProtocolViolation;
    // A provider that allocated a realm before reporting failure still owes a
    // close; treating every returned nonzero realm as live prevents a partial
    // open from leaking backend state.
    if (binding->realm != 0) binding->realm_open = true;
    return protocolViolation ? EXACT_GPU_PROVIDER_PROTOCOL_VIOLATION
                             : EXACT_GPU_PROVIDER_OPEN_FAILED;
  }

  binding->realm_open = true;
  // Activation invocation, not open_realm return, is the service-visible
  // callback-admission linearization point. Live is published first so a
  // conforming provider may deliver synchronously from this one-way hook.
  try {
    binding->api.activate_realm(binding->api.service_context, binding->realm);
  } catch (...) {
    binding->mailbox->phase.store(
        GpuMailboxPhase::ProtocolViolation, std::memory_order_release);
    return EXACT_GPU_PROVIDER_OPEN_FAILED;
  }
  return EXACT_GPU_PROVIDER_OK;
#endif
}

bool exactGpuBindingInstalled(const ExactHermesRuntime* runtime) {
  return runtime && runtime->gpu_binding != nullptr;
}

void exactGpuRollbackInstall(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->gpu_binding) return;
  runtime->gpu_binding->detach();
  runtime->gpu_binding.reset();
}

void exactGpuBeginRuntimeTeardown(ExactHermesRuntime* runtime) {
  exactGpuRollbackInstall(runtime);
}
