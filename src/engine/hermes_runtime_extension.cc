#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../include/ibex/runtime_extension.hpp"
#include "hermes_runtime_extension_internal.h"
#include "hermes_runtime_internal.h"

#if defined(_WIN32)
#include <malloc.h>
#endif

#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
#include <jsi/hermes-interfaces.h>
#endif

namespace ibex::runtime_extension::internal {
struct Instance;
}

namespace ibex::runtime_extension::v1 {
struct RuntimeStateAccess {
  static std::unique_ptr<InstallContextV1>
  makeInstallContext(ExactHermesRuntime *runtime, internal::Instance *instance);
};
} // namespace ibex::runtime_extension::v1

extern "C" int32_t
ex_host_matches_runtime_extension_authority_digest(uint64_t context_id,
                                                   const char *digest);
extern "C" int32_t ex_host_runtime_extension_bootstrap_digest_matches_v1(
    const uint8_t *bytes, size_t byte_length, const char *digest);
extern "C" int32_t ex_host_matches_runtime_extension_registry_projection_v1(
    uint64_t context_id, const char *projection_json);
extern "C" int32_t ex_host_authorize_runtime_extension_operation_v1(
    uint64_t context_id, uint64_t runtime_nonce, uint64_t extension_generation,
    const char *extension_id, const char *operation_id,
    const char *authority_class, const char *semantics, const char *stage,
    const char *atomicity_group, const char *const *resource_kinds,
    size_t resource_kind_count, const char *resource_json,
    const uint64_t *constrained_principals, size_t constrained_principal_count,
    const uint64_t *presented_leases, size_t presented_lease_count,
    uint64_t *out_lease);
extern "C" int32_t
ex_host_revoke_runtime_extension_lease_v1(uint64_t context_id, uint64_t lease);
extern "C" int32_t ex_host_check_runtime_extension_lease_binding_v1(
    uint64_t context_id, uint64_t lease, uint64_t runtime_nonce,
    uint64_t extension_generation, const char *extension_id,
    const char *operation_id);
extern "C" int32_t ex_host_check_runtime_extension_lease_binding_owner_v1(
    uint64_t context_id, uint64_t lease, uint64_t runtime_nonce,
    uint64_t extension_generation, const char *extension_id,
    const char *operation_id);

namespace ibex::runtime_extension::internal {

#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
namespace test_fault {
constexpr uint32_t kTokenImplAllocation = 1u << 0;
constexpr uint32_t kPostDispositionAllocation = 1u << 1;
constexpr uint32_t kPostCallbackAllocation = 1u << 2;
constexpr uint32_t kKeyedExternalDetachException = 1u << 3;

std::atomic<uint32_t> g_armed{0};
std::atomic<bool> g_hold_next_accepted_post{false};
std::atomic<bool> g_accepted_post_held{false};
std::atomic<bool> g_release_accepted_post{true};

bool consume(uint32_t fault) {
  return (g_armed.fetch_and(~fault, std::memory_order_acq_rel) & fault) != 0;
}

void holdAcceptedPostBeforeReturnIfArmed() noexcept {
  if (!g_hold_next_accepted_post.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  g_accepted_post_held.store(true, std::memory_order_release);
  while (!g_release_accepted_post.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  g_accepted_post_held.store(false, std::memory_order_release);
}
} // namespace test_fault
#endif

namespace {

constexpr uint64_t kSupportedFeatures =
    IBEX_RUNTIME_EXTENSION_FEATURE_OWNER_EXECUTOR |
    IBEX_RUNTIME_EXTENSION_FEATURE_OPERATION_MEMBRANE |
    IBEX_RUNTIME_EXTENSION_FEATURE_COPIED_BUFFERS |
    IBEX_RUNTIME_EXTENSION_FEATURE_NATIVE_MODULES |
    IBEX_RUNTIME_EXTENSION_FEATURE_INTROSPECTION
#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
    | IBEX_RUNTIME_EXTENSION_FEATURE_KEYED_EXTERNAL_BUFFERS
#endif
    ;
constexpr size_t kMaxExtensions = 256;
constexpr size_t kMaxStringBytes = 4096;
constexpr size_t kMaxListItems = 4096;
constexpr size_t kMaxCopiedPayloadBytes = 16 * 1024 * 1024;
constexpr size_t kMaxBootstrapBytes = 64 * 1024 * 1024;
constexpr size_t kMaxGlobalSnapshotObjects = 8192;
constexpr size_t kMaxGlobalSnapshotProperties = 131072;
constexpr size_t kMaxGlobalSnapshotKeyBytes = 16 * 1024 * 1024;
constexpr size_t kMaxGlobalSnapshotStabilizationPasses = 4;

std::atomic<uint64_t> g_nextExtensionGeneration{1};

bool validCString(const char *value, size_t maximum = kMaxStringBytes) {
  if (value == nullptr || *value == '\0')
    return false;
  return std::memchr(value, '\0', maximum + 1) != nullptr;
}

bool validDigest(const char *value) {
  if (!validCString(value, 96))
    return false;
  std::string digest(value);
  if (digest.rfind("sha256-", 0) == 0) {
    digest.erase(0, 7);
    return digest.size() == 43 &&
           std::all_of(digest.begin(), digest.end(), [](unsigned char byte) {
             return std::isalnum(byte) || byte == '_' || byte == '-';
           });
  }
  if (digest.rfind("sha256:", 0) == 0)
    digest.erase(0, 7);
  if (digest.size() != 64)
    return false;
  return std::all_of(digest.begin(), digest.end(), [](unsigned char byte) {
    return std::isxdigit(byte) != 0;
  });
}

bool validStableId(const char *value) {
  if (!validCString(value, 128) ||
      !std::islower(static_cast<unsigned char>(value[0]))) {
    return false;
  }
  for (const unsigned char byte : std::string(value)) {
    if (!(std::islower(byte) || std::isdigit(byte) || byte == '.' ||
          byte == '-')) {
      return false;
    }
  }
  return true;
}

bool validIdentifierSegment(const std::string &segment) {
  if (segment.empty())
    return false;
  const auto first = static_cast<unsigned char>(segment.front());
  if (!(std::isalpha(first) || first == '_' || first == '$'))
    return false;
  return std::all_of(segment.begin() + 1, segment.end(),
                     [](unsigned char byte) {
                       return std::isalnum(byte) || byte == '_' || byte == '$';
                     });
}

std::vector<std::string> splitPath(const std::string &path) {
  std::vector<std::string> segments;
  size_t start = 0;
  while (start <= path.size()) {
    const size_t separator = path.find('.', start);
    auto segment =
        path.substr(start, separator == std::string::npos ? std::string::npos
                                                          : separator - start);
    if (!validIdentifierSegment(segment))
      return {};
    segments.push_back(std::move(segment));
    if (separator == std::string::npos)
      break;
    start = separator + 1;
  }
  return segments;
}

bool validOperationEntryPath(
    const std::string &path,
    const std::set<std::string> &declared_global_paths,
    const std::vector<std::string> &declared_module_specifiers) {
  const size_t export_separator = path.find('#');
  if (export_separator == std::string::npos) {
    if (std::binary_search(declared_module_specifiers.begin(),
                           declared_module_specifiers.end(), path)) {
      return true;
    }
    if (splitPath(path).empty())
      return false;
    return std::any_of(
        declared_global_paths.begin(), declared_global_paths.end(),
        [&path](const std::string &owner) {
          return path == owner ||
                 (path.size() > owner.size() &&
                  path.compare(0, owner.size(), owner) == 0 &&
                  path[owner.size()] == '.');
        });
  }
  if (export_separator == 0 || export_separator + 1 >= path.size() ||
      path.find('#', export_separator + 1) != std::string::npos) {
    return false;
  }

  const std::string owner = path.substr(0, export_separator);
  const std::string export_path = path.substr(export_separator + 1);
  if (splitPath(export_path).empty())
    return false;

  return declared_global_paths.count(owner) != 0 ||
         std::binary_search(declared_module_specifiers.begin(),
                            declared_module_specifiers.end(), owner);
}

bool pathOverlaps(const std::string &left, const std::string &right) {
  if (left == right)
    return true;
  const auto prefix = [](const std::string &parent, const std::string &child) {
    return child.size() > parent.size() &&
           child.compare(0, parent.size(), parent) == 0 &&
           child[parent.size()] == '.';
  };
  return prefix(left, right) || prefix(right, left);
}

uint64_t allocateGeneration() {
  uint64_t current = g_nextExtensionGeneration.load(std::memory_order_relaxed);
  for (;;) {
    if (current == 0 || current == std::numeric_limits<uint64_t>::max()) {
      return 0;
    }
    if (g_nextExtensionGeneration.compare_exchange_weak(
            current, current + 1, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      return current;
    }
  }
}

std::string jsonEscape(const std::string &input) {
  std::string result;
  result.reserve(input.size() + 8);
  for (unsigned char byte : input) {
    switch (byte) {
    case '"':
      result += "\\\"";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    default:
      if (byte < 0x20) {
        static constexpr char kHex[] = "0123456789abcdef";
        result += "\\u00";
        result.push_back(kHex[(byte >> 4) & 0x0f]);
        result.push_back(kHex[byte & 0x0f]);
      } else {
        result.push_back(static_cast<char>(byte));
      }
    }
  }
  return result;
}

} // namespace

struct OwnedOperation {
  std::string id;
  std::string authority_class;
  std::string semantics;
  std::string stage;
  std::string atomicity_group;
  std::vector<std::string> resource_kinds;
  std::string js_entry_path;
  uint32_t flags{0};
};

struct OwnedCallback {
  std::string id;
  std::string operation_id;
  uint32_t producer_affinity{0};
  uint32_t delivery{0};
  uint32_t max_pending{0};
};

struct OwnedGlobal {
  std::string path;
  uint32_t kind{0};
};

struct OwnedBootstrap {
  std::string id;
  uint32_t format{0};
  uint32_t evaluation_mode{0};
  std::string content_digest;
  std::string source_url;
  std::vector<uint8_t> bytes;
};

struct OwnedProvider {
  std::string abi_id;
  uint32_t minimum_version{0};
  uint32_t abi_version{0};
  uint32_t provider_struct_size{0};
  std::string identity_digest;
  const void *vtable{nullptr};
  void *context{nullptr};
};

// Public completion handles may die on arbitrary producer threads, but the
// callback they retire is JSI-bearing and must remain owner-thread-owned.
// Keep the producer-visible retirement state separate from CallbackSlot so a
// producer never needs a strong reference to the callback merely to request
// retirement.
// @ref LLP 0040#5-owner-executor-and-completion-tokens
struct CallbackRetirementState {
  uint32_t max_pending{0};
  bool repeating{false};
  std::atomic<uint32_t> pending{0};
  std::atomic<bool> terminal_admitted{false};
  std::atomic<bool> retirement_requested{false};
  std::atomic<bool> published{false};
  std::atomic<bool> retired{false};
};

// Operation leases may be retained by provider-owned asynchronous sessions.
// Their last public copy can therefore die on any producer thread. The
// producer publishes retirement through this independently retained state;
// only the runtime-owner slot below touches Host state.
// @ref LLP 0040#5-owner-executor-and-completion-tokens
struct OperationLeaseRetirementState {
  std::atomic<bool> retirement_requested{false};
  std::atomic<bool> published{false};
  std::atomic<bool> revoked{false};
};

// Tokens outlive the runtime they were minted from. Keep every field a
// producer may touch in independently retained, allocation-free state so an
// arbitrary producer never dereferences a possibly-reused runtime/Instance
// address. Runtime identity is still admitted by the pointer+nonce registry
// immediately before enqueue.
// @ref LLP 0040#5-owner-executor-and-completion-tokens
struct RuntimeProducerState {
  std::atomic<bool> accepting{false};
  std::atomic<bool> callback_retirement_pending{false};
  std::atomic<bool> operation_lease_retirement_pending{false};
};

struct InstanceProducerState {
  std::atomic<uint32_t> lifecycle{IBEX_RUNTIME_EXTENSION_DECLARED};
  std::atomic<uint64_t> callbacks_admitted{0};
  std::atomic<uint64_t> callbacks_rejected{0};
};

struct CompletionAuthorityState {
  uint64_t host_context_id{0};
  uint64_t lease{0};
  uint64_t runtime_nonce{0};
  uint64_t extension_generation{0};
  std::string extension_id;
  std::string operation_id;

  int32_t currentStatus() const noexcept {
    if (lease == 0)
      return 0;
    return ex_host_check_runtime_extension_lease_binding_v1(
        host_context_id, lease, runtime_nonce, extension_generation,
        extension_id.c_str(), operation_id.c_str());
  }

  int32_t currentOwnerStatus() const noexcept {
    if (lease == 0)
      return 0;
    // This path is invoked only from a callback already admitted to the
    // runtime-owner queue. The Host check below may wait for its own immutable
    // policy/generation snapshot, but performs no provider callback, worker
    // dispatch, or external effect while holding that guard. Producer and
    // cross-thread paths use currentStatus() above and remain try-lock-only.
    return ex_host_check_runtime_extension_lease_binding_owner_v1(
        host_context_id, lease, runtime_nonce, extension_generation,
        extension_id.c_str(), operation_id.c_str());
  }
};

struct CallbackSlot {
  uint64_t token_id{0};
  std::shared_ptr<CallbackRetirementState> retirement;
  // The owner-thread slot, not the public producer token, owns the authority
  // lease. Last-token destruction can therefore remain an atomics-only
  // operation; lease revocation and its Host locks happen on the owner when
  // this slot is retired or the runtime closes.
  std::shared_ptr<void> operation_lease;
  v1::CompletionTokenV1::OwnerCallback callback;
};

struct OperationLeaseSlot {
  uint64_t host_context_id{0};
  uint64_t lease{0};
  std::shared_ptr<OperationLeaseRetirementState> retirement;
};

struct KeyedExternalAlias {
  uint64_t revocation_key{0};
  std::unique_ptr<facebook::jsi::ArrayBuffer> buffer;
};

struct Instance {
  std::string id;
  std::string version;
  std::string manifest_digest;
  std::string authority_capsule_digest;
  uint32_t realm_mask{0};
  uint64_t required_features{0};
  std::vector<OwnedGlobal> globals;
  std::vector<std::string> module_specifiers;
  std::vector<OwnedBootstrap> bootstraps;
  std::set<std::string> published_modules;
  std::vector<OwnedOperation> operations;
  std::vector<OwnedCallback> callbacks;
  std::unique_ptr<OwnedProvider> provider;
  IbexRuntimeExtensionProviderBindingV1 provider_view{};
  IbexRuntimeExtensionLifecycleVTableV1 lifecycle{};
  std::shared_ptr<InstanceProducerState> producer_state{
      std::make_shared<InstanceProducerState>()};
  uint64_t generation{0};
  void *extension_instance{nullptr};
  std::unique_ptr<v1::InstallContextV1> install_context;
  mutable std::mutex callback_slots_mutex;
  std::vector<std::shared_ptr<CallbackSlot>> callback_slots;
  // Owner-only. Public/provider lease copies retain only the retirement state
  // and copied authority facts, never this slot or Instance.
  std::vector<OperationLeaseSlot> operation_lease_slots;
  std::vector<KeyedExternalAlias> keyed_external_aliases;
  std::set<uint64_t> revoking_external_keys;
  std::set<uint64_t> retired_external_keys;
  uint64_t next_callback_token_id{1};

  const OwnedOperation *operation(const std::string &operation_id) const {
    auto found = std::find_if(operations.begin(), operations.end(),
                              [&](const OwnedOperation &candidate) {
                                return candidate.id == operation_id;
                              });
    return found == operations.end() ? nullptr : &*found;
  }

  const OwnedCallback *callback(const std::string &callback_id) const {
    auto found = std::find_if(callbacks.begin(), callbacks.end(),
                              [&](const OwnedCallback &candidate) {
                                return candidate.id == callback_id;
                              });
    return found == callbacks.end() ? nullptr : &*found;
  }

  const OwnedGlobal *global(const std::string &path) const {
    auto found = std::lower_bound(
        globals.begin(), globals.end(), path,
        [](const OwnedGlobal &candidate, const std::string &key) {
          return candidate.path < key;
        });
    return found == globals.end() || found->path != path ? nullptr : &*found;
  }

  std::shared_ptr<CallbackSlot> callbackSlot(uint64_t token_id) const {
    std::lock_guard<std::mutex> lock(callback_slots_mutex);
    auto found =
        std::find_if(callback_slots.begin(), callback_slots.end(),
                     [&](const std::shared_ptr<CallbackSlot> &candidate) {
                       return candidate->token_id == token_id;
                     });
    return found == callback_slots.end() ? nullptr : *found;
  }

  void eraseCallbackSlot(uint64_t token_id) {
    std::shared_ptr<CallbackSlot> retired;
    {
      std::lock_guard<std::mutex> lock(callback_slots_mutex);
      auto found = std::find_if(
          callback_slots.begin(), callback_slots.end(),
          [token_id](const std::shared_ptr<CallbackSlot> &candidate) {
            return candidate->token_id == token_id;
          });
      if (found != callback_slots.end()) {
        if ((*found)->retirement) {
          (*found)->retirement->retired.store(true, std::memory_order_release);
        }
        retired = std::move(*found);
        callback_slots.erase(found);
      }
    }
    // Callback captures may retire other tokens. Destroy them after releasing
    // the slot mutex so owner-thread retirement cannot recursively deadlock.
    retired.reset();
  }

  size_t callbackSlotCount() const {
    std::lock_guard<std::mutex> lock(callback_slots_mutex);
    return callback_slots.size();
  }

  void addCallbackSlot(std::shared_ptr<CallbackSlot> slot) {
    std::lock_guard<std::mutex> lock(callback_slots_mutex);
    callback_slots.push_back(std::move(slot));
  }

  void retireRequestedCallbackSlots() {
    for (;;) {
      uint64_t token_id = 0;
      {
        std::lock_guard<std::mutex> lock(callback_slots_mutex);
        const auto found = std::find_if(
            callback_slots.begin(), callback_slots.end(),
            [](const std::shared_ptr<CallbackSlot> &candidate) {
              return candidate->retirement &&
                     candidate->retirement->retirement_requested.load(
                         std::memory_order_acquire) &&
                     candidate->retirement->pending.load(
                         std::memory_order_acquire) == 0;
            });
        if (found == callback_slots.end())
          return;
        token_id = (*found)->token_id;
      }
      // eraseCallbackSlot drops the JSI-bearing callback after releasing the
      // mutex and this method is called only on the runtime owner.
      eraseCallbackSlot(token_id);
    }
  }

  void clearCallbackSlots() {
    std::vector<std::shared_ptr<CallbackSlot>> retired;
    {
      std::lock_guard<std::mutex> lock(callback_slots_mutex);
      for (const auto &slot : callback_slots) {
        if (slot->retirement) {
          slot->retirement->retired.store(true, std::memory_order_release);
        }
      }
      retired.swap(callback_slots);
    }
    retired.clear();
  }

  void addOperationLeaseSlot(OperationLeaseSlot slot) {
    if (operation_lease_slots.size() >= kMaxListItems) {
      throw std::runtime_error(
          "runtime extension operation lease slot budget is exhausted");
    }
    operation_lease_slots.push_back(std::move(slot));
  }

  void retireRequestedOperationLeaseSlots() noexcept {
    auto iterator = operation_lease_slots.begin();
    while (iterator != operation_lease_slots.end()) {
      if (!iterator->retirement ||
          !iterator->retirement->retirement_requested.load(
              std::memory_order_acquire)) {
        ++iterator;
        continue;
      }
      iterator->retirement->revoked.store(true, std::memory_order_release);
      if (iterator->lease != 0) {
        (void)ex_host_revoke_runtime_extension_lease_v1(
            iterator->host_context_id, iterator->lease);
      }
      iterator = operation_lease_slots.erase(iterator);
    }
  }

  void clearOperationLeaseSlots() noexcept {
    for (auto &slot : operation_lease_slots) {
      if (slot.retirement) {
        slot.retirement->retirement_requested.store(true,
                                                     std::memory_order_release);
        slot.retirement->revoked.store(true, std::memory_order_release);
      }
      if (slot.lease != 0) {
        (void)ex_host_revoke_runtime_extension_lease_v1(slot.host_context_id,
                                                        slot.lease);
      }
    }
    operation_lease_slots.clear();
  }

  size_t operationLeaseSlotCount() const noexcept {
    return operation_lease_slots.size();
  }

  bool hasActiveExternalKey(uint64_t key) const {
    return std::any_of(keyed_external_aliases.begin(),
                       keyed_external_aliases.end(),
                       [key](const KeyedExternalAlias &alias) {
                         return alias.revocation_key == key;
                       });
  }
};

struct RuntimeState {
  uint64_t host_context_id{0};
  bool registry_authenticated{false};
  std::string report_mode{"diagnostic"};
  std::string extension_set_digest;
  std::string authority_capsule_digest;
  std::string executable_selection_identity;
  ExactHermesRuntime *runtime{nullptr};
  std::vector<std::unique_ptr<Instance>> instances;
  bool installed{false};
  bool activated{false};
  bool closed{false};
  std::shared_ptr<RuntimeProducerState> producer_state{
      std::make_shared<RuntimeProducerState>()};

  Instance *find(const std::string &extension_id, uint64_t generation) const {
    auto found = std::find_if(instances.begin(), instances.end(),
                              [&](const std::unique_ptr<Instance> &candidate) {
                                return candidate->id == extension_id &&
                                       candidate->generation == generation;
                              });
    return found == instances.end() ? nullptr : found->get();
  }
};

namespace {

void wakeRuntimeOwnerAfterRetirementRequest() noexcept {
  // Producer handles retain their state independently. No runtime, Instance,
  // or owner-slot pointer is consulted here: the owner observes the durable
  // bit on its next drive, while a handle that outlives teardown merely wakes
  // a now-empty owner.
  try {
    ex_hermes_notify_callback();
  } catch (...) {
    // The durable bit remains visible to the next owner drive even if a
    // non-conforming embedder wake hook throws across its C boundary.
  }
}

void markCallbackRetirementPendingAndWake(
    const std::shared_ptr<RuntimeProducerState> &producer_state) noexcept {
  if (producer_state) {
    producer_state->callback_retirement_pending.store(
        true, std::memory_order_release);
  }
  wakeRuntimeOwnerAfterRetirementRequest();
}

void markOperationLeaseRetirementPendingAndWake(
    const std::shared_ptr<RuntimeProducerState> &producer_state) noexcept {
  if (producer_state) {
    producer_state->operation_lease_retirement_pending.store(
        true, std::memory_order_release);
  }
  wakeRuntimeOwnerAfterRetirementRequest();
}

struct PendingCallbackDispositionV1 {
  Instance *instance{nullptr};
  uint64_t token_id{0};
  bool terminal{false};
  std::shared_ptr<CallbackRetirementState> retirement;
  std::atomic<bool> settled{false};

  ~PendingCallbackDispositionV1() { finishWithoutOwner(); }

  void finishOnOwner(bool request_retirement) noexcept {
    finish(request_retirement, true);
  }

  void finishWithoutOwner() noexcept { finish(false, false); }

 private:
  void finish(bool request_retirement, bool on_owner) noexcept {
    if (settled.exchange(true, std::memory_order_acq_rel))
      return;

    auto owned_retirement = std::move(retirement);
    if (!owned_retirement)
      return;

    if (request_retirement) {
      owned_retirement->retirement_requested.store(true,
                                                   std::memory_order_release);
    }

    const auto previous =
        owned_retirement->pending.fetch_sub(1, std::memory_order_acq_rel);
    if (previous == 0) {
      // Defensive saturation for a malformed internal disposition. Never let
      // an underflow turn the bounded callback budget into an unbounded one.
      owned_retirement->pending.store(0, std::memory_order_release);
    } else if (previous == 1 &&
               on_owner && instance &&
               owned_retirement->retirement_requested.load(
                   std::memory_order_acquire)) {
      // Only the queue-owned disposition reaches this branch. Producer
      // destruction may decrement the producer-only accounting above, but
      // never consults Instance or releases JSI/Host-owned state.
      instance->eraseCallbackSlot(token_id);
    }

    owned_retirement.reset();
  }
};

const IbexRuntimeExtensionProviderBindingV1 *
providerFor(const IbexRuntimeExtensionRegistryV1 *registry,
            const std::string &extension_id) {
  if (registry == nullptr)
    return nullptr;
  for (size_t index = 0; index < registry->provider_binding_count; ++index) {
    const auto &binding = registry->provider_bindings[index];
    if (validCString(binding.extension_id, 128) &&
        extension_id == binding.extension_id) {
      return &binding;
    }
  }
  return nullptr;
}

bool copyStringList(const char *const *input, size_t count, bool paths,
                    std::vector<std::string> *output, std::string *error) {
  if (output == nullptr || count > kMaxListItems ||
      (count != 0 && input == nullptr)) {
    if (error)
      *error = "invalid descriptor string list";
    return false;
  }
  std::set<std::string> seen;
  output->reserve(count);
  for (size_t index = 0; index < count; ++index) {
    if (!validCString(input[index])) {
      if (error)
        *error = "descriptor contains an invalid string";
      return false;
    }
    std::string value(input[index]);
    if (paths && splitPath(value).empty()) {
      if (error)
        *error = "descriptor contains an invalid logical path";
      return false;
    }
    if (!seen.insert(value).second) {
      if (error)
        *error = "descriptor contains a duplicate string";
      return false;
    }
    output->push_back(std::move(value));
  }
  std::sort(output->begin(), output->end());
  return true;
}

bool copyDescriptor(const IbexRuntimeExtensionRegistryV1 *registry,
                    const IbexRuntimeExtensionDescriptorV1 &descriptor,
                    std::unique_ptr<Instance> *output, std::string *error) {
  if (output == nullptr ||
      descriptor.struct_size != sizeof(IbexRuntimeExtensionDescriptorV1) ||
      descriptor.sdk_version != IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1 ||
      !validStableId(descriptor.id) || !validCString(descriptor.version, 128) ||
      !validDigest(descriptor.manifest_digest) ||
      !validDigest(descriptor.authority_capsule_digest) ||
      descriptor.realm_mask != IBEX_RUNTIME_EXTENSION_REALM_MAIN ||
      descriptor.install_phase !=
          IBEX_RUNTIME_EXTENSION_INSTALL_BEFORE_USER_CODE ||
      (descriptor.required_features & ~kSupportedFeatures) != 0 ||
      descriptor.lifecycle == nullptr ||
      descriptor.lifecycle->struct_size !=
          sizeof(IbexRuntimeExtensionLifecycleVTableV1) ||
      descriptor.lifecycle->install == nullptr ||
      descriptor.lifecycle->checkpoint == nullptr ||
      descriptor.lifecycle->quiesce == nullptr ||
      descriptor.lifecycle->close == nullptr) {
    if (error)
      *error = "malformed or unsupported extension descriptor";
    return false;
  }
  if (std::strcmp(descriptor.authority_capsule_digest,
                  registry->authority_capsule_digest) != 0) {
    if (error) {
      *error =
          "runtime extension descriptor authority capsule digest differs "
          "from registry";
    }
    return false;
  }

  auto instance = std::make_unique<Instance>();
  instance->id = descriptor.id;
  instance->version = descriptor.version;
  instance->manifest_digest = descriptor.manifest_digest;
  instance->authority_capsule_digest = descriptor.authority_capsule_digest;
  instance->realm_mask = descriptor.realm_mask;
  instance->required_features = descriptor.required_features;
  instance->lifecycle = *descriptor.lifecycle;
  instance->generation = allocateGeneration();
  if (instance->generation == 0) {
    if (error)
      *error = "extension generation namespace exhausted";
    return false;
  }
  if (!copyStringList(descriptor.module_specifiers,
                      descriptor.module_specifier_count, false,
                      &instance->module_specifiers, error)) {
    return false;
  }
  if (descriptor.bootstrap_count > kMaxListItems ||
      (descriptor.bootstrap_count != 0 && descriptor.bootstraps == nullptr)) {
    if (error)
      *error = "invalid runtime extension bootstrap inventory";
    return false;
  }
  std::set<std::string> bootstrap_ids;
  size_t total_bootstrap_bytes = 0;
  instance->bootstraps.reserve(descriptor.bootstrap_count);
  for (size_t index = 0; index < descriptor.bootstrap_count; ++index) {
    const auto &bootstrap = descriptor.bootstraps[index];
    if (bootstrap.struct_size != sizeof(IbexRuntimeExtensionBootstrapV1) ||
        !validStableId(bootstrap.id) ||
        (bootstrap.format != IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SOURCE &&
         bootstrap.format !=
             IBEX_RUNTIME_EXTENSION_BOOTSTRAP_HERMES_BYTECODE) ||
        bootstrap.evaluation_mode !=
            IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SCRIPT_GLOBAL ||
        !validDigest(bootstrap.content_digest) ||
        !validCString(bootstrap.source_url) || bootstrap.bytes == nullptr ||
        bootstrap.byte_length == 0 ||
        bootstrap.byte_length > kMaxBootstrapBytes ||
        total_bootstrap_bytes > kMaxBootstrapBytes - bootstrap.byte_length ||
        !bootstrap_ids.insert(bootstrap.id).second) {
      if (error)
        *error = "invalid runtime extension bootstrap inventory";
      return false;
    }
    total_bootstrap_bytes += bootstrap.byte_length;
    OwnedBootstrap copied;
    copied.id = bootstrap.id;
    copied.format = bootstrap.format;
    copied.evaluation_mode = bootstrap.evaluation_mode;
    copied.content_digest = bootstrap.content_digest;
    copied.source_url = bootstrap.source_url;
    copied.bytes.assign(bootstrap.bytes,
                        bootstrap.bytes + bootstrap.byte_length);
    if (ex_host_runtime_extension_bootstrap_digest_matches_v1(
            copied.bytes.data(), copied.bytes.size(),
            copied.content_digest.c_str()) != 1) {
      if (error)
        *error = "runtime extension bootstrap digest mismatch";
      return false;
    }
    instance->bootstraps.push_back(std::move(copied));
  }
  std::sort(instance->bootstraps.begin(), instance->bootstraps.end(),
            [](const OwnedBootstrap &left, const OwnedBootstrap &right) {
              return left.id < right.id;
            });
  if (descriptor.global_count > kMaxListItems ||
      (descriptor.global_count != 0 && descriptor.globals == nullptr)) {
    if (error)
      *error = "invalid runtime extension global inventory";
    return false;
  }
  std::set<std::string> global_paths;
  for (size_t index = 0; index < descriptor.global_count; ++index) {
    const auto &global = descriptor.globals[index];
    if (global.struct_size != sizeof(IbexRuntimeExtensionGlobalV1) ||
        !validCString(global.path) || splitPath(global.path).empty() ||
        (global.kind != IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT &&
         global.kind != IBEX_RUNTIME_EXTENSION_GLOBAL_FUNCTION) ||
        !global_paths.insert(global.path).second) {
      if (error)
        *error = "invalid runtime extension global inventory";
      return false;
    }
    instance->globals.push_back(OwnedGlobal{global.path, global.kind});
  }
  std::sort(instance->globals.begin(), instance->globals.end(),
            [](const OwnedGlobal &left, const OwnedGlobal &right) {
              return left.path < right.path;
            });
  if (!instance->module_specifiers.empty() &&
      (instance->required_features &
       IBEX_RUNTIME_EXTENSION_FEATURE_NATIVE_MODULES) == 0) {
    if (error)
      *error = "module declarations require native-modules feature";
    return false;
  }

  if (descriptor.operation_count > kMaxListItems ||
      (descriptor.operation_count != 0 && descriptor.operations == nullptr)) {
    if (error)
      *error = "invalid extension operation inventory";
    return false;
  }
  std::set<std::string> operation_ids;
  for (size_t index = 0; index < descriptor.operation_count; ++index) {
    const auto &operation = descriptor.operations[index];
    if (operation.struct_size != sizeof(IbexRuntimeExtensionOperationV1) ||
        !validCString(operation.id, 128) ||
        !validCString(operation.authority_class, 256) ||
        !validCString(operation.semantics, 256) ||
        !validCString(operation.stage, 64) ||
        !validCString(operation.atomicity_group, 256) ||
        operation.resource_kind_count == 0 ||
        operation.resource_kind_count > kMaxListItems ||
        operation.resource_kinds == nullptr ||
        !validCString(operation.js_entry_path) ||
        !validOperationEntryPath(operation.js_entry_path, global_paths,
                                 instance->module_specifiers) ||
        !operation_ids.insert(operation.id).second) {
      if (error)
        *error = "invalid extension operation inventory";
      return false;
    }
    std::vector<std::string> resource_kinds;
    resource_kinds.reserve(operation.resource_kind_count);
    for (size_t resource_index = 0;
         resource_index < operation.resource_kind_count; ++resource_index) {
      const char *resource_kind = operation.resource_kinds[resource_index];
      if (!validCString(resource_kind, 128) ||
          (!resource_kinds.empty() && resource_kinds.back() >= resource_kind)) {
        if (error) {
          *error = "extension operation resource kinds are not canonical";
        }
        return false;
      }
      resource_kinds.emplace_back(resource_kind);
    }
    instance->operations.push_back(OwnedOperation{
        operation.id, operation.authority_class, operation.semantics,
        operation.stage, operation.atomicity_group, std::move(resource_kinds),
        operation.js_entry_path, operation.flags});
  }
  std::sort(instance->operations.begin(), instance->operations.end(),
            [](const OwnedOperation &left, const OwnedOperation &right) {
              return left.id < right.id;
            });

  if (descriptor.callback_count > kMaxListItems ||
      (descriptor.callback_count != 0 && descriptor.callbacks == nullptr)) {
    if (error)
      *error = "invalid extension callback inventory";
    return false;
  }
  std::set<std::string> callback_ids;
  for (size_t index = 0; index < descriptor.callback_count; ++index) {
    const auto &callback = descriptor.callbacks[index];
    if (callback.struct_size != sizeof(IbexRuntimeExtensionCallbackV1) ||
        !validCString(callback.id, 128) ||
        !validCString(callback.operation_id, 128) ||
        operation_ids.count(callback.operation_id) == 0 ||
        callback.producer_affinity <
            IBEX_RUNTIME_EXTENSION_CALLBACK_RUNTIME_OWNER ||
        callback.producer_affinity >
            IBEX_RUNTIME_EXTENSION_CALLBACK_PROVIDER_THREAD ||
        callback.delivery !=
            IBEX_RUNTIME_EXTENSION_CALLBACK_DELIVERY_RUNTIME_OWNER ||
        callback.max_pending == 0 || callback.max_pending > 65536 ||
        !callback_ids.insert(callback.id).second) {
      if (error)
        *error = "invalid extension callback inventory";
      return false;
    }
    instance->callbacks.push_back(OwnedCallback{
        callback.id, callback.operation_id, callback.producer_affinity,
        callback.delivery, callback.max_pending});
  }
  std::sort(instance->callbacks.begin(), instance->callbacks.end(),
            [](const OwnedCallback &left, const OwnedCallback &right) {
              return left.id < right.id;
            });

  const bool requires_provider = descriptor.provider_abi_id != nullptr &&
                                 *descriptor.provider_abi_id != '\0';
  const auto *provider = providerFor(registry, instance->id);
  if (requires_provider) {
    if (!validCString(descriptor.provider_abi_id, 256) ||
        descriptor.provider_abi_min_version == 0 ||
        descriptor.provider_struct_size == 0 || provider == nullptr ||
        provider->struct_size !=
            sizeof(IbexRuntimeExtensionProviderBindingV1) ||
        !validCString(provider->abi_id, 256) ||
        std::string(descriptor.provider_abi_id) != provider->abi_id ||
        provider->abi_version < descriptor.provider_abi_min_version ||
        provider->provider_struct_size != descriptor.provider_struct_size ||
        !validDigest(provider->identity_digest) ||
        provider->vtable == nullptr) {
      if (error)
        *error = "runtime extension provider ABI mismatch";
      return false;
    }
    instance->provider = std::make_unique<OwnedProvider>();
    instance->provider->abi_id = provider->abi_id;
    instance->provider->minimum_version = descriptor.provider_abi_min_version;
    instance->provider->abi_version = provider->abi_version;
    instance->provider->provider_struct_size = provider->provider_struct_size;
    instance->provider->identity_digest = provider->identity_digest;
    instance->provider->vtable = provider->vtable;
    instance->provider->context = provider->context;
    instance->provider_view.struct_size = sizeof(instance->provider_view);
    instance->provider_view.extension_id = instance->id.c_str();
    instance->provider_view.abi_id = instance->provider->abi_id.c_str();
    instance->provider_view.abi_version = instance->provider->abi_version;
    instance->provider_view.provider_struct_size =
        instance->provider->provider_struct_size;
    instance->provider_view.identity_digest =
        instance->provider->identity_digest.c_str();
    instance->provider_view.vtable = instance->provider->vtable;
    instance->provider_view.context = instance->provider->context;
  } else if (provider != nullptr) {
    if (error)
      *error = "undeclared runtime extension provider binding";
    return false;
  }

  *output = std::move(instance);
  return true;
}

void appendJsonString(std::string &output, const std::string &value) {
  static constexpr char kHex[] = "0123456789abcdef";
  output.push_back('"');
  for (const unsigned char byte : value) {
    switch (byte) {
    case '"':
      output += "\\\"";
      break;
    case '\\':
      output += "\\\\";
      break;
    case '\b':
      output += "\\b";
      break;
    case '\f':
      output += "\\f";
      break;
    case '\n':
      output += "\\n";
      break;
    case '\r':
      output += "\\r";
      break;
    case '\t':
      output += "\\t";
      break;
    default:
      if (byte < 0x20) {
        output += "\\u00";
        output.push_back(kHex[byte >> 4]);
        output.push_back(kHex[byte & 0x0f]);
      } else {
        output.push_back(static_cast<char>(byte));
      }
    }
  }
  output.push_back('"');
}

const char *globalKindName(uint32_t kind) {
  return kind == IBEX_RUNTIME_EXTENSION_GLOBAL_FUNCTION ? "function" : "object";
}

const char *callbackAffinityName(uint32_t affinity) {
  switch (affinity) {
  case IBEX_RUNTIME_EXTENSION_CALLBACK_RUNTIME_OWNER:
    return "runtime-owner";
  case IBEX_RUNTIME_EXTENSION_CALLBACK_BACKGROUND_PRODUCER:
    return "background-producer";
  default:
    return "provider-thread";
  }
}

const char *bootstrapFormatName(uint32_t format) {
  return format == IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SOURCE ? "source"
                                                           : "hermes-bytecode";
}

std::string registryProjectionJson(const RuntimeState &state) {
  std::string output;
  output.reserve(4096);
  output += "{\"schema\":\"ibex/runtime-extension-registry-projection/1\","
            "\"extensionSetDigest\":";
  appendJsonString(output, state.extension_set_digest);
  output += ",\"authorityCapsuleDigest\":";
  appendJsonString(output, state.authority_capsule_digest);
  output += ",\"executableSelectionIdentity\":";
  appendJsonString(output, state.executable_selection_identity);
  output += ",\"descriptors\":[";
  bool first_descriptor = true;
  for (const auto &owned : state.instances) {
    const auto &descriptor = *owned;
    if (!first_descriptor)
      output.push_back(',');
    first_descriptor = false;
    output += "{\"id\":";
    appendJsonString(output, descriptor.id);
    output += ",\"version\":";
    appendJsonString(output, descriptor.version);
    output += ",\"sdkVersion\":\"1\",\"manifestDigest\":";
    appendJsonString(output, descriptor.manifest_digest);
    output += ",\"authorityCapsuleDigest\":";
    appendJsonString(output, descriptor.authority_capsule_digest);
    output += ",\"trustedBootstrap\":{\"realm\":\"app\","
              "\"installPhase\":\"pre-user-code\"},\"bootstrap\":[";
    bool first = true;
    for (const auto &bootstrap : descriptor.bootstraps) {
      if (!first)
        output.push_back(',');
      first = false;
      output += "{\"id\":";
      appendJsonString(output, bootstrap.id);
      output += ",\"format\":";
      appendJsonString(output, bootstrapFormatName(bootstrap.format));
      output += ",\"evaluationMode\":\"script-global\",\"contentDigest\":";
      appendJsonString(output, bootstrap.content_digest);
      output += ",\"sourceUrl\":";
      appendJsonString(output, bootstrap.source_url);
      output += ",\"byteLength\":";
      output += std::to_string(bootstrap.bytes.size());
      output.push_back('}');
    }
    output += "],\"requiredFeatureBits\":";
    output += std::to_string(descriptor.required_features);
    output += ",\"globals\":[";
    first = true;
    for (const auto &global : descriptor.globals) {
      if (!first)
        output.push_back(',');
      first = false;
      output += "{\"name\":";
      appendJsonString(output, global.path);
      output += ",\"kind\":";
      appendJsonString(output, globalKindName(global.kind));
      output.push_back('}');
    }
    output += "],\"modules\":[";
    first = true;
    for (const auto &module : descriptor.module_specifiers) {
      if (!first)
        output.push_back(',');
      first = false;
      output += "{\"specifier\":";
      appendJsonString(output, module);
      output.push_back('}');
    }
    output += "],\"callbacks\":[";
    first = true;
    for (const auto &callback : descriptor.callbacks) {
      if (!first)
        output.push_back(',');
      first = false;
      output += "{\"id\":";
      appendJsonString(output, callback.id);
      output += ",\"operationId\":";
      appendJsonString(output, callback.operation_id);
      output += ",\"producerAffinity\":";
      appendJsonString(output,
                       callbackAffinityName(callback.producer_affinity));
      output += ",\"delivery\":\"runtime-thread\",\"maxPending\":";
      output += std::to_string(callback.max_pending);
      output.push_back('}');
    }
    output.push_back(']');
    if (descriptor.provider) {
      output += ",\"providerAbi\":{\"id\":";
      appendJsonString(output, descriptor.provider->abi_id);
      output += ",\"minVersion\":";
      output += std::to_string(descriptor.provider->minimum_version);
      output += ",\"selectedVersion\":";
      output += std::to_string(descriptor.provider->abi_version);
      output += ",\"structSize\":";
      output += std::to_string(descriptor.provider->provider_struct_size);
      output += ",\"identityDigest\":";
      appendJsonString(output, descriptor.provider->identity_digest);
      output.push_back('}');
    }
    output += ",\"authorityFragment\":{\"schema\":"
              "\"ibex/runtime-extension-authority-fragment/1\",\"namespace\":";
    appendJsonString(output, descriptor.id);
    output += ",\"operations\":[";
    first = true;
    for (const auto &operation : descriptor.operations) {
      if (!first)
        output.push_back(',');
      first = false;
      output += "{\"operationId\":";
      appendJsonString(output, operation.id);
      output += ",\"authorityClass\":";
      appendJsonString(output, operation.authority_class);
      output += ",\"semantics\":";
      appendJsonString(output, operation.semantics);
      output += ",\"stage\":";
      appendJsonString(output, operation.stage);
      output += ",\"atomicityGroup\":";
      appendJsonString(output, operation.atomicity_group);
      output += ",\"resourceKinds\":[";
      bool first_resource_kind = true;
      for (const auto &resource_kind : operation.resource_kinds) {
        if (!first_resource_kind)
          output.push_back(',');
        first_resource_kind = false;
        appendJsonString(output, resource_kind);
      }
      output.push_back(']');
      output += ",\"jsEntryPath\":";
      appendJsonString(output, operation.js_entry_path);
      output += ",\"flags\":";
      output += std::to_string(operation.flags);
      output.push_back('}');
    }
    output += "]}}";
  }
  output += "]}";
  return output;
}

facebook::jsi::Function objectFunction(facebook::jsi::Runtime &runtime,
                                       const char *name) {
  return runtime.global()
      .getPropertyAsObject(runtime, "Object")
      .getPropertyAsFunction(runtime, name);
}

struct TrustedReflection {
  facebook::jsi::Function get_own_property_names;
  facebook::jsi::Function get_own_property_symbols;
  facebook::jsi::Function get_own_property_descriptor;
  facebook::jsi::Function get_prototype_of;
};

TrustedReflection captureTrustedReflection(facebook::jsi::Runtime &runtime) {
  return {
      objectFunction(runtime, "getOwnPropertyNames"),
      objectFunction(runtime, "getOwnPropertySymbols"),
      objectFunction(runtime, "getOwnPropertyDescriptor"),
      objectFunction(runtime, "getPrototypeOf"),
  };
}

class AlignedBootstrapBuffer final : public facebook::jsi::Buffer {
public:
  explicit AlignedBootstrapBuffer(const std::vector<uint8_t> &bytes)
      : size_(bytes.size()) {
    if (bytes.empty())
      return;
    const size_t alignment = alignof(std::max_align_t);
    const size_t padded = (bytes.size() + alignment - 1) & ~(alignment - 1);
#if defined(_WIN32)
    data_ = static_cast<uint8_t *>(_aligned_malloc(padded, alignment));
    if (data_ == nullptr)
      throw std::bad_alloc();
#else
    if (posix_memalign(reinterpret_cast<void **>(&data_), alignment, padded) !=
        0) {
      data_ = nullptr;
      throw std::bad_alloc();
    }
#endif
    std::memcpy(data_, bytes.data(), bytes.size());
  }

  ~AlignedBootstrapBuffer() override {
#if defined(_WIN32)
    _aligned_free(data_);
#else
    std::free(data_);
#endif
  }

  size_t size() const override { return size_; }

  const uint8_t *data() const override { return data_; }

private:
  size_t size_{0};
  uint8_t *data_{nullptr};
};

void evaluateBootstrap(facebook::jsi::Runtime &runtime,
                       const OwnedBootstrap &bootstrap) {
  std::shared_ptr<facebook::jsi::Buffer> buffer;
  if (bootstrap.format == IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SOURCE) {
    buffer = std::make_shared<facebook::jsi::StringBuffer>(
        std::string(reinterpret_cast<const char *>(bootstrap.bytes.data()),
                    bootstrap.bytes.size()));
  } else {
    buffer = std::make_shared<AlignedBootstrapBuffer>(bootstrap.bytes);
  }
  (void)runtime.evaluateJavaScript(buffer, bootstrap.source_url);
}

struct PropertySnapshot {
  std::unique_ptr<facebook::jsi::Value> value;
  std::unique_ptr<facebook::jsi::Value> getter;
  std::unique_ptr<facebook::jsi::Value> setter;
  bool data{false};
  bool enumerable{false};
  bool configurable{false};
  bool writable{false};
};

struct ObjectSnapshot {
  bool present{false};
  std::map<std::string, PropertySnapshot> properties;
  size_t symbol_count{0};
};

facebook::jsi::Value descriptorOwnField(facebook::jsi::Runtime &runtime,
                                        const TrustedReflection &reflection,
                                        const facebook::jsi::Object &descriptor,
                                        const char *field);

std::set<std::string>
descriptorOwnFieldNames(facebook::jsi::Runtime &runtime,
                        const TrustedReflection &reflection,
                        const facebook::jsi::Object &descriptor);

std::unique_ptr<facebook::jsi::Object>
ownDataObjectAtPath(facebook::jsi::Runtime &runtime,
                    const TrustedReflection &reflection,
                    const std::string &path) {
  auto current = std::make_unique<facebook::jsi::Object>(runtime.global());
  if (path.empty())
    return current;
  for (const auto &segment : splitPath(path)) {
    auto descriptor_value = reflection.get_own_property_descriptor.call(
        runtime, *current,
        facebook::jsi::String::createFromUtf8(runtime, segment));
    if (descriptor_value.isUndefined())
      return nullptr;
    if (!descriptor_value.isObject()) {
      throw std::runtime_error("invalid property descriptor");
    }
    auto descriptor = descriptor_value.asObject(runtime);
    const auto fields =
        descriptorOwnFieldNames(runtime, reflection, descriptor);
    const auto own_field = [&](const char *field) {
      return fields.count(field) == 0 ? facebook::jsi::Value::undefined()
                                      : descriptor.getProperty(runtime, field);
    };
    auto getter = own_field("get");
    auto setter = own_field("set");
    auto value = own_field("value");
    if (!getter.isUndefined() || !setter.isUndefined() || !value.isObject()) {
      throw std::runtime_error(
          "runtime extension global parent is not a data object");
    }
    auto object = value.asObject(runtime);
    if (object.isHostObject(runtime)) {
      throw std::runtime_error(
          "runtime extension global parent may not be a HostObject");
    }
    current = std::make_unique<facebook::jsi::Object>(std::move(object));
  }
  return current;
}

facebook::jsi::Array reflectionArray(facebook::jsi::Runtime &runtime,
                                     const facebook::jsi::Function &function,
                                     const facebook::jsi::Object &object,
                                     const char *operation) {
  auto value = function.call(runtime, object);
  if (!value.isObject() || !value.asObject(runtime).isArray(runtime)) {
    throw std::runtime_error(std::string("Object.") + operation +
                             " returned invalid data");
  }
  auto result = value.asObject(runtime).asArray(runtime);
  if (result.length(runtime) > kMaxListItems) {
    throw std::runtime_error(std::string("Object.") + operation +
                             " exceeded snapshot bounds");
  }
  return result;
}

std::set<std::string>
descriptorOwnFieldNames(facebook::jsi::Runtime &runtime,
                        const TrustedReflection &reflection,
                        const facebook::jsi::Object &descriptor) {
  std::set<std::string> result;
  auto names = reflectionArray(runtime, reflection.get_own_property_names,
                               descriptor, "getOwnPropertyNames");
  for (size_t index = 0; index < names.length(runtime); ++index) {
    auto name = names.getValueAtIndex(runtime, index);
    if (!name.isString()) {
      throw std::runtime_error(
          "property descriptor field name was not a string");
    }
    result.insert(name.asString(runtime).utf8(runtime));
  }
  return result;
}

facebook::jsi::Value descriptorOwnField(facebook::jsi::Runtime &runtime,
                                        const TrustedReflection &reflection,
                                        const facebook::jsi::Object &descriptor,
                                        const char *field) {
  const auto fields = descriptorOwnFieldNames(runtime, reflection, descriptor);
  if (fields.count(field) != 0) {
    // The intrinsic creates a fresh ordinary descriptor record. Requiring
    // the field to be own before reading prevents a missing field from
    // reaching a hostile inherited accessor.
    return descriptor.getProperty(runtime, field);
  }
  return facebook::jsi::Value::undefined();
}

PropertySnapshot snapshotPropertyDescriptor(facebook::jsi::Runtime &runtime,
                                            const TrustedReflection &reflection,
                                            const facebook::jsi::Object &object,
                                            const facebook::jsi::Value &key) {
  auto descriptor_value =
      reflection.get_own_property_descriptor.call(runtime, object, key);
  if (!descriptor_value.isObject()) {
    throw std::runtime_error("own property descriptor disappeared");
  }
  auto descriptor = descriptor_value.asObject(runtime);
  const auto fields = descriptorOwnFieldNames(runtime, reflection, descriptor);
  const auto own_field = [&](const char *field) {
    return fields.count(field) == 0 ? facebook::jsi::Value::undefined()
                                    : descriptor.getProperty(runtime, field);
  };
  auto value = own_field("value");
  auto getter = own_field("get");
  auto setter = own_field("set");
  auto enumerable = own_field("enumerable");
  auto configurable = own_field("configurable");
  auto writable = own_field("writable");
  if (!enumerable.isBool() || !configurable.isBool()) {
    throw std::runtime_error("own property descriptor has invalid flags");
  }
  const bool is_data = writable.isBool();
  const auto valid_accessor = [&](const facebook::jsi::Value &accessor) {
    return accessor.isUndefined() ||
           (accessor.isObject() &&
            accessor.asObject(runtime).isFunction(runtime));
  };
  if ((is_data && (!getter.isUndefined() || !setter.isUndefined())) ||
      (!is_data && (!writable.isUndefined() || !valid_accessor(getter) ||
                    !valid_accessor(setter)))) {
    throw std::runtime_error("own property descriptor has invalid shape");
  }
  PropertySnapshot property;
  property.value = std::make_unique<facebook::jsi::Value>(runtime, value);
  property.getter = std::make_unique<facebook::jsi::Value>(runtime, getter);
  property.setter = std::make_unique<facebook::jsi::Value>(runtime, setter);
  property.data = is_data;
  property.enumerable = enumerable.getBool();
  property.configurable = configurable.getBool();
  property.writable = is_data && writable.getBool();
  return property;
}

ObjectSnapshot snapshotObject(facebook::jsi::Runtime &runtime,
                              const TrustedReflection &reflection,
                              const std::string &path) {
  ObjectSnapshot result;
  auto object = ownDataObjectAtPath(runtime, reflection, path);
  if (!object)
    return result;
  result.present = true;
  auto names = reflectionArray(runtime, reflection.get_own_property_names,
                               *object, "getOwnPropertyNames");
  const size_t length = names.length(runtime);
  for (size_t index = 0; index < length; ++index) {
    auto name_value = names.getValueAtIndex(runtime, index);
    if (!name_value.isString()) {
      throw std::runtime_error("own property name was not a string");
    }
    auto name = name_value.asString(runtime).utf8(runtime);
    if (name.size() > kMaxStringBytes) {
      throw std::runtime_error("own property name exceeded snapshot bounds");
    }
    result.properties.emplace(
        std::move(name),
        snapshotPropertyDescriptor(runtime, reflection, *object, name_value));
  }
  result.symbol_count =
      reflectionArray(runtime, reflection.get_own_property_symbols, *object,
                      "getOwnPropertySymbols")
          .length(runtime);
  return result;
}

using AllowedChildren = std::map<std::string, std::set<std::string>>;

AllowedChildren allowedChildrenFor(const Instance &instance) {
  AllowedChildren result;
  for (const auto &global : instance.globals) {
    const auto &path = global.path;
    const auto segments = splitPath(path);
    std::string parent;
    for (const auto &segment : segments) {
      result[parent].insert(segment);
      parent = parent.empty() ? segment : parent + "." + segment;
    }
  }
  return result;
}

bool sameValue(facebook::jsi::Runtime &runtime,
               const facebook::jsi::Value &left,
               const facebook::jsi::Value &right) {
  if (left.isNumber() && right.isNumber()) {
    const double left_number = left.getNumber();
    const double right_number = right.getNumber();
    if (std::isnan(left_number) && std::isnan(right_number))
      return true;
    if (left_number == 0 && right_number == 0) {
      return std::signbit(left_number) == std::signbit(right_number);
    }
  }
  return facebook::jsi::Value::strictEquals(runtime, left, right);
}

bool samePropertyDescriptor(facebook::jsi::Runtime &runtime,
                            const PropertySnapshot &left,
                            const PropertySnapshot &right) {
  return left.data == right.data &&
         sameValue(runtime, *left.value, *right.value) &&
         sameValue(runtime, *left.getter, *right.getter) &&
         sameValue(runtime, *left.setter, *right.setter) &&
         left.enumerable == right.enumerable &&
         left.configurable == right.configurable &&
         left.writable == right.writable;
}

struct GraphPropertySnapshot {
  std::unique_ptr<facebook::jsi::Value> key;
  std::string string_key;
  bool is_string{false};
  PropertySnapshot descriptor;
};

struct GraphObjectSnapshot {
  std::unique_ptr<facebook::jsi::Value> identity;
  std::unique_ptr<facebook::jsi::Value> prototype;
  std::vector<GraphPropertySnapshot> properties;
  std::string debug_path;
};

struct AllowedAddition {
  std::unique_ptr<facebook::jsi::Value> object;
  std::string property;
};

struct GlobalSnapshot {
  std::map<std::string, ObjectSnapshot> declared_parents;
  std::vector<GraphObjectSnapshot> graph;
  std::vector<AllowedAddition> allowed_additions;
};

// @ref LLP 0040#verification
// Retain pristine reflection functions and walk only own data-descriptor
// values plus prototypes. Accessor bodies are identities to compare, never
// traversal edges to invoke.
std::vector<GraphPropertySnapshot>
snapshotOwnPropertyTable(facebook::jsi::Runtime &runtime,
                         const TrustedReflection &reflection,
                         const facebook::jsi::Object &object,
                         size_t *total_properties, size_t *total_key_bytes) {
  auto names = reflectionArray(runtime, reflection.get_own_property_names,
                               object, "getOwnPropertyNames");
  auto symbols = reflectionArray(runtime, reflection.get_own_property_symbols,
                                 object, "getOwnPropertySymbols");
  const auto name_count = names.length(runtime);
  const auto symbol_count = symbols.length(runtime);
  if (name_count > kMaxListItems - symbol_count ||
      *total_properties >
          kMaxGlobalSnapshotProperties - name_count - symbol_count) {
    throw std::runtime_error(
        "runtime extension global descriptor graph exceeded property bounds");
  }
  *total_properties += name_count + symbol_count;

  std::vector<GraphPropertySnapshot> result;
  result.reserve(name_count + symbol_count);
  const auto append = [&](facebook::jsi::Value key, bool expect_string) {
    if ((expect_string && !key.isString()) ||
        (!expect_string && !key.isSymbol())) {
      throw std::runtime_error(
          "runtime extension global descriptor graph returned an invalid key");
    }
    GraphPropertySnapshot property;
    property.is_string = expect_string;
    if (expect_string) {
      property.string_key = key.asString(runtime).utf8(runtime);
      if (property.string_key.size() > kMaxStringBytes ||
          *total_key_bytes >
              kMaxGlobalSnapshotKeyBytes - property.string_key.size()) {
        throw std::runtime_error(
            "runtime extension global descriptor graph exceeded key bounds");
      }
      *total_key_bytes += property.string_key.size();
    }
    property.descriptor =
        snapshotPropertyDescriptor(runtime, reflection, object, key);
    property.key = std::make_unique<facebook::jsi::Value>(runtime, key);
    result.push_back(std::move(property));
  };
  for (size_t index = 0; index < name_count; ++index) {
    append(names.getValueAtIndex(runtime, index), true);
  }
  for (size_t index = 0; index < symbol_count; ++index) {
    append(symbols.getValueAtIndex(runtime, index), false);
  }
  return result;
}

void enqueueGraphObject(facebook::jsi::Runtime &runtime,
                        const facebook::jsi::Value &value,
                        std::string debug_path,
                        std::vector<GraphObjectSnapshot> *graph) {
  if (!value.isObject())
    return;
  for (const auto &existing : *graph) {
    if (sameValue(runtime, *existing.identity, value))
      return;
  }
  if (graph->size() >= kMaxGlobalSnapshotObjects) {
    throw std::runtime_error(
        "runtime extension global descriptor graph exceeded object bounds");
  }
  GraphObjectSnapshot snapshot;
  snapshot.identity = std::make_unique<facebook::jsi::Value>(runtime, value);
  snapshot.debug_path = std::move(debug_path);
  graph->push_back(std::move(snapshot));
}

std::vector<GraphObjectSnapshot>
captureDescriptorGraphPass(facebook::jsi::Runtime &runtime,
                           const TrustedReflection &reflection) {
  std::vector<GraphObjectSnapshot> graph;
  auto global = facebook::jsi::Value(runtime, runtime.global());
  enqueueGraphObject(runtime, global, "[[Global]]", &graph);
  size_t total_properties = 0;
  size_t total_key_bytes = 0;
  for (size_t index = 0; index < graph.size(); ++index) {
    auto object = graph[index].identity->asObject(runtime);
    auto prototype = reflection.get_prototype_of.call(runtime, object);
    if (!prototype.isNull() && !prototype.isObject()) {
      throw std::runtime_error("Object.getPrototypeOf returned invalid data");
    }
    auto properties = snapshotOwnPropertyTable(
        runtime, reflection, object, &total_properties, &total_key_bytes);
    std::vector<std::pair<std::unique_ptr<facebook::jsi::Value>, std::string>>
        children;
    if (prototype.isObject()) {
      children.emplace_back(
          std::make_unique<facebook::jsi::Value>(runtime, prototype),
          graph[index].debug_path + ".[[Prototype]]");
    }
    for (const auto &property : properties) {
      if (property.descriptor.data && property.descriptor.value->isObject()) {
        children.emplace_back(
            std::make_unique<facebook::jsi::Value>(runtime,
                                                   *property.descriptor.value),
            graph[index].debug_path + "." +
                (property.is_string ? property.string_key : "[[Symbol]]"));
      }
    }
    graph[index].prototype =
        std::make_unique<facebook::jsi::Value>(runtime, prototype);
    graph[index].properties = std::move(properties);
    for (auto &[child, path] : children) {
      enqueueGraphObject(runtime, *child, std::move(path), &graph);
    }
  }
  return graph;
}

const GraphObjectSnapshot *
findGraphObject(facebook::jsi::Runtime &runtime,
                const std::vector<GraphObjectSnapshot> &graph,
                const facebook::jsi::Value &identity) {
  auto found = std::find_if(
      graph.begin(), graph.end(), [&](const GraphObjectSnapshot &object) {
        return sameValue(runtime, *object.identity, identity);
      });
  return found == graph.end() ? nullptr : &*found;
}

bool sameDescriptorGraph(facebook::jsi::Runtime &runtime,
                         const std::vector<GraphObjectSnapshot> &left,
                         const std::vector<GraphObjectSnapshot> &right) {
  if (left.size() != right.size())
    return false;
  for (const auto &left_object : left) {
    const auto *right_object =
        findGraphObject(runtime, right, *left_object.identity);
    if (right_object == nullptr ||
        !sameValue(runtime, *left_object.prototype, *right_object->prototype) ||
        left_object.properties.size() != right_object->properties.size()) {
      return false;
    }
    for (const auto &left_property : left_object.properties) {
      auto right_property = std::find_if(
          right_object->properties.begin(), right_object->properties.end(),
          [&](const GraphPropertySnapshot &candidate) {
            return sameValue(runtime, *left_property.key, *candidate.key);
          });
      if (right_property == right_object->properties.end() ||
          !samePropertyDescriptor(runtime, left_property.descriptor,
                                  right_property->descriptor)) {
        return false;
      }
    }
  }
  return true;
}

std::vector<GraphObjectSnapshot>
captureDescriptorGraph(facebook::jsi::Runtime &runtime,
                       const TrustedReflection &reflection) {
  auto prior = captureDescriptorGraphPass(runtime, reflection);
  for (size_t pass = 1; pass < kMaxGlobalSnapshotStabilizationPasses; ++pass) {
    auto current = captureDescriptorGraphPass(runtime, reflection);
    if (sameDescriptorGraph(runtime, prior, current)) {
      return current;
    }
    prior = std::move(current);
  }
  throw std::runtime_error(
      "runtime extension global descriptor graph did not stabilize");
}

std::vector<AllowedAddition>
captureAllowedAdditions(facebook::jsi::Runtime &runtime,
                        const TrustedReflection &reflection,
                        const Instance &instance) {
  std::vector<AllowedAddition> result;
  for (const auto &[parent, children] : allowedChildrenFor(instance)) {
    auto object = ownDataObjectAtPath(runtime, reflection, parent);
    if (!object)
      continue;
    auto object_value = facebook::jsi::Value(runtime, *object);
    for (const auto &child : children) {
      const auto duplicate = std::any_of(
          result.begin(), result.end(), [&](const AllowedAddition &existing) {
            return existing.property == child &&
                   sameValue(runtime, *existing.object, object_value);
          });
      if (duplicate)
        continue;
      AllowedAddition addition;
      addition.object =
          std::make_unique<facebook::jsi::Value>(runtime, object_value);
      addition.property = child;
      result.push_back(std::move(addition));
    }
  }
  return result;
}

GlobalSnapshot captureGlobalSnapshot(facebook::jsi::Runtime &runtime,
                                     const TrustedReflection &reflection,
                                     const Instance &instance) {
  GlobalSnapshot result;
  // Some trusted bootstrap facades are deliberately lazy Proxies. Reflection
  // can materialize their pre-user-code backing graph, so establish a bounded
  // fixed point before recording declaration-parent tables. A graph that does
  // not converge is an uninspectable construction failure.
  result.graph = captureDescriptorGraph(runtime, reflection);
  for (const auto &[parent, _] : allowedChildrenFor(instance)) {
    result.declared_parents.emplace(
        parent, snapshotObject(runtime, reflection, parent));
  }
  result.allowed_additions =
      captureAllowedAdditions(runtime, reflection, instance);
  return result;
}

const GraphPropertySnapshot *
findGraphProperty(facebook::jsi::Runtime &runtime,
                  const std::vector<GraphPropertySnapshot> &properties,
                  const facebook::jsi::Value &key) {
  auto found = std::find_if(properties.begin(), properties.end(),
                            [&](const GraphPropertySnapshot &property) {
                              return sameValue(runtime, *property.key, key);
                            });
  return found == properties.end() ? nullptr : &*found;
}

bool isAllowedAddition(facebook::jsi::Runtime &runtime,
                       const GlobalSnapshot &before,
                       const facebook::jsi::Value &object,
                       const GraphPropertySnapshot &property) {
  if (!property.is_string)
    return false;
  return std::any_of(before.allowed_additions.begin(),
                     before.allowed_additions.end(),
                     [&](const AllowedAddition &allowed) {
                       return allowed.property == property.string_key &&
                              sameValue(runtime, *allowed.object, object);
                     });
}

std::string graphPropertyLabel(const GraphPropertySnapshot &property) {
  return property.is_string ? property.string_key : "[[Symbol]]";
}

void verifyDescriptorGraph(facebook::jsi::Runtime &runtime,
                           const TrustedReflection &reflection,
                           const GlobalSnapshot &before) {
  size_t total_properties = 0;
  size_t total_key_bytes = 0;
  for (const auto &prior_object : before.graph) {
    auto object = prior_object.identity->asObject(runtime);
    auto prototype = reflection.get_prototype_of.call(runtime, object);
    if ((!prototype.isNull() && !prototype.isObject()) ||
        !sameValue(runtime, *prior_object.prototype, prototype)) {
      throw std::runtime_error(
          "runtime extension mutated a pre-existing global prototype");
    }
    auto after_properties = snapshotOwnPropertyTable(
        runtime, reflection, object, &total_properties, &total_key_bytes);
    for (const auto &property : prior_object.properties) {
      const auto *current =
          findGraphProperty(runtime, after_properties, *property.key);
      if (current == nullptr) {
        throw std::runtime_error(
            "runtime extension removed pre-existing global property " +
            graphPropertyLabel(property));
      }
      if (!samePropertyDescriptor(runtime, property.descriptor,
                                  current->descriptor)) {
        throw std::runtime_error(
            "runtime extension mutated pre-existing global property " +
            graphPropertyLabel(property));
      }
    }
    for (const auto &property : after_properties) {
      if (findGraphProperty(runtime, prior_object.properties, *property.key) ==
              nullptr &&
          !isAllowedAddition(runtime, before, *prior_object.identity,
                             property)) {
        throw std::runtime_error(
            "runtime extension published undeclared nested global property " +
            graphPropertyLabel(property));
      }
    }
  }
}

void verifyGlobalDelta(facebook::jsi::Runtime &runtime,
                       const TrustedReflection &reflection,
                       const Instance &instance, const GlobalSnapshot &before) {
  verifyDescriptorGraph(runtime, reflection, before);
  const auto allowed = allowedChildrenFor(instance);
  for (const auto &[parent, allowed_children] : allowed) {
    const auto before_it = before.declared_parents.find(parent);
    if (before_it == before.declared_parents.end()) {
      throw std::runtime_error("missing pre-install global snapshot");
    }
    auto after = snapshotObject(runtime, reflection, parent);
    if (!after.present) {
      throw std::runtime_error(
          "runtime extension did not publish declared global parent " + parent);
    }
    const auto &prior = before_it->second;
    if (prior.present) {
      for (const auto &[name, property] : prior.properties) {
        auto found = after.properties.find(name);
        if (found == after.properties.end()) {
          throw std::runtime_error(
              "runtime extension removed undeclared global property " +
              (parent.empty() ? name : parent + "." + name));
        }
        const auto &current = found->second;
        if (!samePropertyDescriptor(runtime, property, current)) {
          throw std::runtime_error(
              "runtime extension replaced existing global property " +
              (parent.empty() ? name : parent + "." + name));
        }
      }
    }
    for (const auto &[name, _] : after.properties) {
      if ((!prior.present || prior.properties.count(name) == 0) &&
          allowed_children.count(name) == 0) {
        throw std::runtime_error(
            "runtime extension published undeclared global property " +
            (parent.empty() ? name : parent + "." + name));
      }
    }
    if (!prior.present && after.symbol_count != 0) {
      throw std::runtime_error(
          "runtime extension published an undeclared symbol on global parent " +
          parent);
    }
  }
  for (const auto &global : instance.globals) {
    const auto &path = global.path;
    const auto segments = splitPath(path);
    std::string parent;
    for (size_t index = 0; index + 1 < segments.size(); ++index) {
      parent =
          parent.empty() ? segments[index] : parent + "." + segments[index];
    }
    auto object = ownDataObjectAtPath(runtime, reflection, parent);
    if (!object) {
      throw std::runtime_error(
          "runtime extension declared global is missing: " + path);
    }
    auto descriptor = reflection.get_own_property_descriptor.call(
        runtime, *object,
        facebook::jsi::String::createFromUtf8(runtime, segments.back()));
    if (!descriptor.isObject()) {
      throw std::runtime_error(
          "runtime extension declared global is missing: " + path);
    }
    auto declared_value = descriptorOwnField(
        runtime, reflection, descriptor.asObject(runtime), "value");
    if (!declared_value.isObject() ||
        (global.kind == IBEX_RUNTIME_EXTENSION_GLOBAL_FUNCTION &&
         !declared_value.asObject(runtime).isFunction(runtime)) ||
        (global.kind == IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT &&
         declared_value.asObject(runtime).isFunction(runtime))) {
      throw std::runtime_error(
          "runtime extension global kind does not match declaration: " + path);
    }
  }
}

#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
facebook::hermes::IKeyedExternalArrayBuffer *
keyedExternalApi(facebook::jsi::Runtime &runtime) {
  return facebook::jsi::castInterface<
      facebook::hermes::IKeyedExternalArrayBuffer>(&runtime);
}

bool revokeKeyedExternalAliases(ExactHermesRuntime *runtime, Instance &instance,
                                uint64_t key, bool all) noexcept {
  if (!runtime || !runtime->runtime)
    return false;
  auto *api = keyedExternalApi(*runtime->runtime);
  if (!api)
    return false;
  bool revoked = false;
  bool detach_failed = false;
  std::set<uint64_t> attempted_keys;
  auto iterator = instance.keyed_external_aliases.begin();
  while (iterator != instance.keyed_external_aliases.end()) {
    if (!all && iterator->revocation_key != key) {
      ++iterator;
      continue;
    }
    const auto revocation_key = iterator->revocation_key;
    attempted_keys.insert(revocation_key);
    instance.revoking_external_keys.insert(revocation_key);
    try {
#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
      if (test_fault::consume(test_fault::kKeyedExternalDetachException)) {
        throw std::runtime_error(
            "injected runtime extension keyed external detach failure");
      }
#endif
      revoked = api->detachKeyedExternalRange(*iterator->buffer) || revoked;
      iterator = instance.keyed_external_aliases.erase(iterator);
    } catch (...) {
      ex_host_console_log(1, "Runtime extension keyed external detach threw");
      // Retain both the alias object and its non-reusable key. A later
      // explicit revoke or the teardown pass can retry without allowing
      // provider storage to be reclaimed under a still-attached JS view.
      detach_failed = true;
      ++iterator;
    }
  }
  for (const auto attempted_key : attempted_keys) {
    if (!instance.hasActiveExternalKey(attempted_key)) {
      instance.revoking_external_keys.erase(attempted_key);
      instance.retired_external_keys.insert(attempted_key);
    }
  }
  return revoked && !detach_failed;
}
#else
bool revokeKeyedExternalAliases(ExactHermesRuntime *, Instance &, uint64_t,
                                bool) noexcept {
  return false;
}
#endif

void rollbackInstalled(RuntimeState &state) noexcept {
  state.producer_state->accepting.store(false, std::memory_order_release);
  for (auto it = state.instances.rbegin(); it != state.instances.rend(); ++it) {
    auto &instance = **it;
    const auto lifecycle =
        instance.producer_state->lifecycle.load(std::memory_order_acquire);
    if (lifecycle != IBEX_RUNTIME_EXTENSION_INSTALLING &&
        lifecycle != IBEX_RUNTIME_EXTENSION_ACTIVE &&
        lifecycle != IBEX_RUNTIME_EXTENSION_QUIESCING_STATE) {
      continue;
    }
    instance.producer_state->lifecycle.store(
        IBEX_RUNTIME_EXTENSION_QUIESCING_STATE, std::memory_order_release);
    if (lifecycle != IBEX_RUNTIME_EXTENSION_QUIESCING_STATE) {
      try {
        instance.lifecycle.quiesce(instance.install_context.get(),
                                   instance.extension_instance);
      } catch (...) {
        ex_host_console_log(1, "Runtime extension quiesce callback threw");
      }
    }
    (void)revokeKeyedExternalAliases(state.runtime, instance, 0, true);
    if (!instance.keyed_external_aliases.empty()) {
      // A detach exception is treated as retryable and teardown performs one
      // additional bounded pass. If the engine keeps throwing, fail closed
      // below by retaining the provider instance rather than reclaiming its
      // storage while an alias might still be attached.
      (void)revokeKeyedExternalAliases(state.runtime, instance, 0, true);
    }
    const bool external_aliases_detached =
        instance.keyed_external_aliases.empty();
    if (!external_aliases_detached) {
      ex_host_console_log(
          1, "Runtime extension keyed external detach remained incomplete; "
             "provider close was suppressed");
    }
    if (external_aliases_detached) {
      try {
        instance.lifecycle.close(instance.install_context.get(),
                                 instance.extension_instance);
      } catch (...) {
        ex_host_console_log(1, "Runtime extension close callback threw");
      }
      instance.extension_instance = nullptr;
    }
    instance.clearCallbackSlots();
    instance.clearOperationLeaseSlots();
    instance.producer_state->lifecycle.store(
        IBEX_RUNTIME_EXTENSION_CLOSED, std::memory_order_release);
  }
  state.producer_state->callback_retirement_pending.store(
      false, std::memory_order_release);
  state.producer_state->operation_lease_retirement_pending.store(
      false, std::memory_order_release);
}

} // namespace

std::shared_ptr<RuntimeState>
prepare(uint64_t host_context_id, bool authenticate_registry,
        const char *report_mode, const IbexRuntimeExtensionRegistryV1 *registry,
        std::string *error) {
  auto state = std::make_shared<RuntimeState>();
  state->host_context_id = host_context_id;
  state->registry_authenticated = authenticate_registry;
  state->report_mode =
      report_mode == nullptr ? "unknown" : std::string(report_mode);
  if (registry == nullptr)
    return state;
  if (registry->struct_size != sizeof(IbexRuntimeExtensionRegistryV1) ||
      registry->sdk_version != IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1 ||
      registry->descriptor_count > kMaxExtensions ||
      (registry->descriptor_count != 0 && registry->descriptors == nullptr) ||
      registry->provider_binding_count > kMaxExtensions ||
      (registry->provider_binding_count != 0 &&
       registry->provider_bindings == nullptr) ||
      !validDigest(registry->extension_set_digest) ||
      !validDigest(registry->authority_capsule_digest) ||
      !validDigest(registry->executable_selection_identity)) {
    if (error)
      *error = "malformed runtime extension registry";
    return nullptr;
  }
#if defined(EXACT_HAVE_FRAME_ATTRIBUTION) && \
    !defined(EXACT_HAVE_JOB_CONSTRAINED_PRINCIPALS)
  if (registry->descriptor_count != 0) {
    if (error) {
      *error =
          "runtime extensions require Hermes constrained-principal job "
          "propagation";
    }
    return nullptr;
  }
#endif
#if !defined(EXACT_HAVE_HERMES_MICROTASK_CONFIG)
  if (registry->descriptor_count != 0) {
    if (error) {
      *error =
          "runtime extensions require the Hermes engine microtask queue";
    }
    return nullptr;
  }
#endif
  state->extension_set_digest = registry->extension_set_digest;
  state->authority_capsule_digest = registry->authority_capsule_digest;
  state->executable_selection_identity =
      registry->executable_selection_identity;
  if (authenticate_registry &&
      ex_host_matches_runtime_extension_authority_digest(
          host_context_id, state->authority_capsule_digest.c_str()) != 1) {
    if (error) {
      *error =
          "runtime extension authority capsule does not match armed context";
    }
    return nullptr;
  }

  std::set<std::string> ids;
  std::set<std::string> modules;
  std::vector<std::pair<std::string, std::string>> globals;
  for (size_t index = 0; index < registry->descriptor_count; ++index) {
    std::unique_ptr<Instance> instance;
    if (!copyDescriptor(registry, registry->descriptors[index], &instance,
                        error)) {
      return nullptr;
    }
    if (!ids.insert(instance->id).second) {
      if (error)
        *error = "duplicate runtime extension ID";
      return nullptr;
    }
    for (const auto &module : instance->module_specifiers) {
      if (!modules.insert(module).second) {
        if (error)
          *error = "duplicate runtime extension module specifier";
        return nullptr;
      }
    }
    for (const auto &global : instance->globals) {
      const auto &path = global.path;
      for (const auto &[existing_path, existing_owner] : globals) {
        if (pathOverlaps(path, existing_path)) {
          if (error) {
            *error =
                "overlapping runtime extension globals: " + existing_owner +
                " and " + instance->id;
          }
          return nullptr;
        }
      }
      globals.emplace_back(path, instance->id);
    }
    state->instances.push_back(std::move(instance));
  }
  for (size_t index = 0; index < registry->provider_binding_count; ++index) {
    const auto &provider = registry->provider_bindings[index];
    if (provider.struct_size != sizeof(IbexRuntimeExtensionProviderBindingV1) ||
        !validStableId(provider.extension_id) ||
        ids.count(provider.extension_id) == 0) {
      if (error)
        *error = "orphaned runtime extension provider binding";
      return nullptr;
    }
    for (size_t prior = 0; prior < index; ++prior) {
      if (std::strcmp(registry->provider_bindings[prior].extension_id,
                      provider.extension_id) == 0) {
        if (error)
          *error = "duplicate runtime extension provider binding";
        return nullptr;
      }
    }
  }
  std::sort(state->instances.begin(), state->instances.end(),
            [](const std::unique_ptr<Instance> &left,
               const std::unique_ptr<Instance> &right) {
              return left->id < right->id;
            });
  if (authenticate_registry) {
    const auto projection = registryProjectionJson(*state);
    if (projection.size() > 4 * 1024 * 1024 ||
        ex_host_matches_runtime_extension_registry_projection_v1(
            host_context_id, projection.c_str()) != 1) {
      if (error) {
        *error =
            "runtime extension registry does not match authenticated capsule";
      }
      return nullptr;
    }
  }
  return state;
}

void bind(const std::shared_ptr<RuntimeState> &state,
          ExactHermesRuntime *runtime) {
  if (!state || !runtime || state->runtime != nullptr) {
    throw std::runtime_error("runtime extension state bind is invalid");
  }
  state->runtime = runtime;
  runtime->runtime_extensions = state;
}

std::set<std::string>
inspectLoaderModuleRegistry(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->runtime ||
      !runtime->runtime_extension_module_inspector) {
    throw std::runtime_error(
        "runtime extension loader inspector is unavailable");
  }
  auto &rt = *runtime->runtime;
  auto value = runtime->runtime_extension_module_inspector->call(rt);
  if (!value.isObject() || !value.asObject(rt).isArray(rt)) {
    throw std::runtime_error(
        "runtime extension loader inspector returned invalid data");
  }
  auto names = value.asObject(rt).asArray(rt);
  const auto length = names.length(rt);
  if (length > kMaxListItems) {
    throw std::runtime_error(
        "runtime extension loader registry exceeds SDK bounds");
  }
  std::set<std::string> result;
  for (size_t index = 0; index < length; ++index) {
    auto name = names.getValueAtIndex(rt, index);
    if (!name.isString()) {
      throw std::runtime_error(
          "runtime extension loader registry contains a non-string key");
    }
    auto inserted = result.insert(name.getString(rt).utf8(rt));
    if (!inserted.second) {
      throw std::runtime_error(
          "runtime extension loader registry contains a duplicate key");
    }
  }
  return result;
}

void install(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->runtime || !runtime->runtime_extensions)
    return;
  auto &state = *runtime->runtime_extensions;
  if (state.installed || state.closed ||
      runtime->runtime_thread != std::this_thread::get_id()) {
    throw std::runtime_error("runtime extension install is out of sequence");
  }
  auto reflection = captureTrustedReflection(*runtime->runtime);
  auto loader_modules = inspectLoaderModuleRegistry(runtime);
  for (auto &owned : state.instances) {
    auto &instance = *owned;
    GlobalSnapshot before;
    try {
      before = captureGlobalSnapshot(*runtime->runtime, reflection, instance);
    } catch (...) {
      rollbackInstalled(state);
      throw;
    }
    instance.producer_state->lifecycle.store(
        IBEX_RUNTIME_EXTENSION_INSTALLING, std::memory_order_release);
    instance.install_context =
        v1::RuntimeStateAccess::makeInstallContext(runtime, &instance);
    void *extension_instance = nullptr;
    int32_t status = IBEX_RUNTIME_EXTENSION_INSTALL_FAILED;
    try {
      for (const auto &bootstrap : instance.bootstraps) {
        evaluateBootstrap(*runtime->runtime, bootstrap);
      }
      status = instance.lifecycle.install(instance.install_context.get(),
                                          &extension_instance);
    } catch (const std::exception &exception) {
      ex_host_console_log(1, exception.what());
    } catch (...) {
      ex_host_console_log(1, "Runtime extension installer threw");
    }
    instance.extension_instance = extension_instance;
    if (status != IBEX_RUNTIME_EXTENSION_OK) {
      rollbackInstalled(state);
      throw std::runtime_error("runtime extension install failed: " +
                               instance.id);
    }
    try {
      verifyGlobalDelta(*runtime->runtime, reflection, instance, before);
      const std::set<std::string> declared_modules(
          instance.module_specifiers.begin(), instance.module_specifiers.end());
      if (instance.published_modules != declared_modules) {
        throw std::runtime_error(
            "runtime extension did not publish its exact module set: " +
            instance.id);
      }
      auto expected_loader_modules = loader_modules;
      expected_loader_modules.insert(
          declared_modules.begin(), declared_modules.end());
      auto actual_loader_modules = inspectLoaderModuleRegistry(runtime);
      if (actual_loader_modules != expected_loader_modules) {
        throw std::runtime_error(
            "runtime extension changed the loader registry outside its "
            "declared module set: " +
            instance.id);
      }
      loader_modules = std::move(actual_loader_modules);
    } catch (...) {
      rollbackInstalled(state);
      throw;
    }
  }
  state.installed = true;
}

void activate(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->runtime_extensions)
    return;
  auto &state = *runtime->runtime_extensions;
  if (state.activated || state.closed || !state.installed ||
      runtime->runtime_thread != std::this_thread::get_id()) {
    throw std::runtime_error("runtime extension activation is out of sequence");
  }
  for (auto &instance : state.instances) {
    if (instance->producer_state->lifecycle.load(std::memory_order_acquire) !=
        IBEX_RUNTIME_EXTENSION_INSTALLING) {
      rollbackInstalled(state);
      throw std::runtime_error("runtime extension lifecycle state is invalid");
    }
    instance->producer_state->lifecycle.store(
        IBEX_RUNTIME_EXTENSION_ACTIVE, std::memory_order_release);
  }
  state.activated = true;
  state.producer_state->accepting.store(true, std::memory_order_release);
}

bool checkpoint(ExactHermesRuntime *runtime) noexcept {
  if (!runtime || !runtime->runtime_extensions)
    return true;
  auto &state = *runtime->runtime_extensions;
  if (state.closed || runtime->runtime_thread != std::this_thread::get_id()) {
    return false;
  }
  if (state.producer_state->callback_retirement_pending.exchange(
          false, std::memory_order_acq_rel)) {
    try {
      for (auto &instance : state.instances) {
        instance->retireRequestedCallbackSlots();
      }
    } catch (...) {
      // Preserve the keepalive bit so a transient native failure cannot turn a
      // durable retirement request into teardown-only cleanup.
      state.producer_state->callback_retirement_pending.store(
          true, std::memory_order_release);
      return false;
    }
  }
  if (state.producer_state->operation_lease_retirement_pending.exchange(
          false, std::memory_order_acq_rel)) {
    try {
      for (auto &instance : state.instances) {
        instance->retireRequestedOperationLeaseSlots();
      }
    } catch (...) {
      // Host revocation is owner-only. Preserve the durable bit if a
      // non-conforming foreign boundary throws so the owner retries instead
      // of silently retaining live authority.
      state.producer_state->operation_lease_retirement_pending.store(
          true, std::memory_order_release);
      return false;
    }
  }
  // Ibex bootstrap itself runs inside host-task boundaries before the fixed
  // extension install/activation window. There is no extension work to
  // advance yet, so these checkpoints are intentional no-ops. Once activated,
  // every selected lifecycle callback below remains mandatory and fail-closed.
  if (!state.activated)
    return true;
  for (auto &owned : state.instances) {
    auto &instance = *owned;
    if (instance.producer_state->lifecycle.load(std::memory_order_acquire) !=
        IBEX_RUNTIME_EXTENSION_ACTIVE) {
      return false;
    }
    try {
      if (instance.lifecycle.checkpoint(instance.install_context.get(),
                                        instance.extension_instance) !=
          IBEX_RUNTIME_EXTENSION_OK) {
        return false;
      }
    } catch (...) {
      ex_host_console_log(1, "Runtime extension checkpoint callback threw");
      return false;
    }
  }
  return true;
}

bool hasPendingOwnerRetirements(const ExactHermesRuntime *runtime) noexcept {
  return runtime && runtime->runtime_extensions &&
         !runtime->runtime_extensions->closed &&
         (runtime->runtime_extensions->producer_state
              ->callback_retirement_pending.load(std::memory_order_acquire) ||
          runtime->runtime_extensions->producer_state
              ->operation_lease_retirement_pending.load(
                  std::memory_order_acquire));
}

void quiesce(ExactHermesRuntime *runtime) noexcept {
  if (!runtime || !runtime->runtime_extensions)
    return;
  auto &state = *runtime->runtime_extensions;
  if (state.closed)
    return;
  state.producer_state->accepting.store(false, std::memory_order_release);
  for (auto it = state.instances.rbegin(); it != state.instances.rend(); ++it) {
    auto &instance = **it;
    if (instance.producer_state->lifecycle.exchange(
            IBEX_RUNTIME_EXTENSION_QUIESCING_STATE,
            std::memory_order_acq_rel) !=
        IBEX_RUNTIME_EXTENSION_ACTIVE) {
      continue;
    }
    try {
      instance.lifecycle.quiesce(instance.install_context.get(),
                                 instance.extension_instance);
    } catch (...) {
      ex_host_console_log(1, "Runtime extension quiesce callback threw");
    }
  }
}

void close(ExactHermesRuntime *runtime) noexcept {
  if (!runtime || !runtime->runtime_extensions)
    return;
  auto &state = *runtime->runtime_extensions;
  if (state.closed)
    return;
  rollbackInstalled(state);
  state.closed = true;
}

#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
extern "C" int32_t ibex_test_runtime_extension_with_callback_slot_lock_v1(
    ExactHermesRuntime *runtime, void (*body)(void *), void *context) {
  if (!runtime || !body || !runtime->runtime_extensions ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      runtime->runtime_extensions->instances.empty()) {
    return 0;
  }
  auto &instance = *runtime->runtime_extensions->instances.front();
  std::lock_guard<std::mutex> lock(instance.callback_slots_mutex);
  body(context);
  return 1;
}

void armAcceptedPostReturnHoldForTest(bool armed) noexcept {
  test_fault::g_accepted_post_held.store(false, std::memory_order_release);
  test_fault::g_release_accepted_post.store(!armed, std::memory_order_release);
  test_fault::g_hold_next_accepted_post.store(armed,
                                              std::memory_order_release);
}

bool acceptedPostReturnHeldForTest() noexcept {
  return test_fault::g_accepted_post_held.load(std::memory_order_acquire);
}

size_t callbackSlotCountForTest(ExactHermesRuntime *runtime) noexcept {
  if (!runtime || !runtime->runtime_extensions ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      runtime->runtime_extensions->instances.empty()) {
    return std::numeric_limits<size_t>::max();
  }
  return runtime->runtime_extensions->instances.front()->callbackSlotCount();
}

size_t operationLeaseSlotCountForTest(ExactHermesRuntime *runtime) noexcept {
  if (!runtime || !runtime->runtime_extensions ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      runtime->runtime_extensions->instances.empty()) {
    return std::numeric_limits<size_t>::max();
  }
  return runtime->runtime_extensions->instances.front()
      ->operationLeaseSlotCount();
}
#endif

std::unordered_set<std::string>
declaredRootKeys(const ExactHermesRuntime *runtime) {
  std::unordered_set<std::string> result;
  if (!runtime || !runtime->runtime_extensions)
    return result;
  for (const auto &instance : runtime->runtime_extensions->instances) {
    for (const auto &global : instance->globals) {
      const auto separator = global.path.find('.');
      result.insert(global.path.substr(0, separator));
    }
  }
  return result;
}

std::unordered_set<std::string>
declaredNativeKeyPairs(const ExactHermesRuntime *runtime) {
  std::unordered_set<std::string> result;
  if (!runtime || !runtime->runtime_extensions)
    return result;
  for (const auto &instance : runtime->runtime_extensions->instances) {
    for (const auto &operation : instance->operations) {
      const auto segments = splitPath(operation.js_entry_path);
      if (segments.empty())
        continue;
      const auto &root = segments.front();
      if (segments.size() == 1) {
        result.insert(root + std::string(1, '\0') + root);
      } else {
        for (size_t index = 1; index < segments.size(); ++index) {
          result.insert(root + std::string(1, '\0') + segments[index]);
        }
      }
    }
  }
  return result;
}

std::vector<std::string>
declaredGlobalPaths(const ExactHermesRuntime *runtime) {
  std::vector<std::string> result;
  if (!runtime || !runtime->runtime_extensions)
    return result;
  for (const auto &instance : runtime->runtime_extensions->instances) {
    for (const auto &global : instance->globals) {
      result.push_back(global.path);
    }
  }
  std::sort(result.begin(), result.end());
  return result;
}

bool declaredLogicalPath(const ExactHermesRuntime *runtime,
                         const std::string &path) {
  if (!runtime || !runtime->runtime_extensions)
    return false;
  for (const auto &instance : runtime->runtime_extensions->instances) {
    if (instance->global(path) != nullptr) {
      return true;
    }
  }
  return false;
}

} // namespace ibex::runtime_extension::internal

namespace ibex::runtime_extension::v1 {

struct OperationLeaseV1::Impl {
  uint64_t host_context_id{0};
  uint64_t lease{0};
  uint64_t runtime_nonce{0};
  uint64_t extension_generation{0};
  std::string extension_id;
  std::string operation_id;
  std::shared_ptr<internal::RuntimeProducerState> runtime_producer_state;
  std::shared_ptr<internal::OperationLeaseRetirementState> retirement;

  ~Impl() {
    if (!retirement || !retirement->published.load(std::memory_order_acquire)) {
      return;
    }
    retirement->retirement_requested.store(true, std::memory_order_release);
    // Provider-retained leases may reach their last copy on arbitrary worker
    // threads. Destruction is therefore atomics plus wake only; the owner-held
    // slot performs the Host revocation at checkpoint or teardown.
    internal::markOperationLeaseRetirementPendingAndWake(
        runtime_producer_state);
  }

  bool retirementIsLive() const noexcept {
    return retirement &&
           retirement->published.load(std::memory_order_acquire) &&
           !retirement->retirement_requested.load(std::memory_order_acquire) &&
           !retirement->revoked.load(std::memory_order_acquire);
  }

  int32_t currentStatus() const noexcept {
    if (lease == 0 || !retirementIsLive())
      return 0;
    const auto status = ex_host_check_runtime_extension_lease_binding_v1(
        host_context_id, lease, runtime_nonce, extension_generation,
        extension_id.c_str(), operation_id.c_str());
    return status == 1 && retirementIsLive() ? 1 : 0;
  }

  bool isCurrent() const {
    return currentStatus() == 1;
  }
};

struct CompletionTokenV1::Impl {
  RuntimeCallbackTarget target;
  internal::Instance *instance{nullptr};
  std::shared_ptr<internal::RuntimeProducerState> runtime_producer_state;
  std::shared_ptr<internal::InstanceProducerState> instance_producer_state;
  std::string extension_id;
  uint64_t generation{0};
  uint64_t token_id{0};
  uint64_t acquisition_principal{0};
  std::vector<uint64_t> acquisition_principals;
  std::shared_ptr<internal::CompletionAuthorityState> authority;
  std::shared_ptr<internal::CallbackRetirementState> retirement;

  ~Impl() {
    if (!retirement || !retirement->published.load(std::memory_order_acquire)) {
      return;
    }
    retirement->retirement_requested.store(true, std::memory_order_release);
    // This destructor may run on a provider callback thread after the runtime
    // address has been freed and reused. It therefore performs exactly two
    // producer-safe actions: publish durable atomics and wake the owner. It
    // never looks up a slot, Host lease, registry entry, or runtime pointer.
    internal::markCallbackRetirementPendingAndWake(runtime_producer_state);
  }
};

struct InstallContextV1::Impl {
  ExactHermesRuntime *runtime{nullptr};
  internal::Instance *instance{nullptr};
};

thread_local const InstallContextV1 *g_activeOperationContext = nullptr;
thread_local const char *g_activeOperationId = nullptr;

class ScopedExtensionOperationV1 {
public:
  ScopedExtensionOperationV1(const InstallContextV1 *context,
                             const char *operation_id)
      : previous_context_(g_activeOperationContext),
        previous_operation_(g_activeOperationId) {
    g_activeOperationContext = context;
    g_activeOperationId = operation_id;
  }

  ~ScopedExtensionOperationV1() {
    g_activeOperationContext = previous_context_;
    g_activeOperationId = previous_operation_;
  }

private:
  const InstallContextV1 *previous_context_;
  const char *previous_operation_;
};

std::unique_ptr<InstallContextV1>
RuntimeStateAccess::makeInstallContext(ExactHermesRuntime *runtime,
                                       internal::Instance *instance) {
  auto impl = std::make_unique<InstallContextV1::Impl>();
  impl->runtime = runtime;
  impl->instance = instance;
  return std::unique_ptr<InstallContextV1>(
      new InstallContextV1(std::move(impl)));
}

CompletionTokenV1::CompletionTokenV1() = default;
CompletionTokenV1::CompletionTokenV1(std::shared_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
CompletionTokenV1::CompletionTokenV1(const CompletionTokenV1 &) = default;
CompletionTokenV1::CompletionTokenV1(CompletionTokenV1 &&) noexcept = default;
CompletionTokenV1 &
CompletionTokenV1::operator=(const CompletionTokenV1 &) = default;
CompletionTokenV1 &
CompletionTokenV1::operator=(CompletionTokenV1 &&) noexcept = default;
CompletionTokenV1::~CompletionTokenV1() = default;

CompletionTokenV1::operator bool() const {
  return impl_ && static_cast<bool>(impl_->target) &&
         impl_->runtime_producer_state && impl_->instance_producer_state &&
         impl_->runtime_producer_state->accepting.load(
             std::memory_order_acquire) &&
         impl_->instance_producer_state->lifecycle.load(
             std::memory_order_acquire) ==
             IBEX_RUNTIME_EXTENSION_ACTIVE &&
         impl_->retirement &&
         impl_->retirement->published.load(std::memory_order_acquire) &&
         !impl_->retirement->retired.load(std::memory_order_acquire);
}

ScheduleResult CompletionTokenV1::post(const uint8_t *bytes,
                                       size_t length) const {
  if ((length != 0 && bytes == nullptr) ||
      length > internal::kMaxCopiedPayloadBytes) {
    return ScheduleResult::Invalid;
  }
  std::vector<uint8_t> copy;
  try {
    if (length != 0)
      copy.assign(bytes, bytes + length);
  } catch (...) {
    return ScheduleResult::QueueFull;
  }
  return post(std::move(copy));
}

ScheduleResult CompletionTokenV1::post(std::vector<uint8_t> bytes) const {
  if (!impl_ || bytes.size() > internal::kMaxCopiedPayloadBytes) {
    return ScheduleResult::Invalid;
  }
  const auto runtime_producer_state = impl_->runtime_producer_state;
  const auto instance_producer_state = impl_->instance_producer_state;
  if (!runtime_producer_state || !instance_producer_state ||
      !runtime_producer_state->accepting.load(std::memory_order_acquire)) {
    return ScheduleResult::StaleGeneration;
  }
  if (instance_producer_state->lifecycle.load(std::memory_order_acquire) !=
      IBEX_RUNTIME_EXTENSION_ACTIVE) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::Quiescing;
  }
  const auto authority = impl_->authority;
  if (!authority) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::StaleAuthority;
  }
  const auto lease_status = authority->currentStatus();
  if (lease_status < 0) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::QueueFull;
  }
  if (lease_status != 1) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::StaleAuthority;
  }
  auto retirement = impl_->retirement;
  if (!retirement || !retirement->published.load(std::memory_order_acquire) ||
      retirement->retired.load(std::memory_order_acquire)) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::Invalid;
  }
  const auto target = impl_->target;
  auto *instance = impl_->instance;
  const auto token_id = impl_->token_id;
  const auto acquisition_principal = impl_->acquisition_principal;
  std::vector<uint64_t> acquisition_principals;
  try {
    acquisition_principals = impl_->acquisition_principals;
  } catch (...) {
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::QueueFull;
  }
  if (!retirement->repeating) {
    bool expected = false;
    if (!retirement->terminal_admitted.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel,
            std::memory_order_relaxed)) {
      instance_producer_state->callbacks_rejected.fetch_add(
          1, std::memory_order_relaxed);
      return ScheduleResult::Invalid;
    }
  }
  uint32_t pending = retirement->pending.load(std::memory_order_relaxed);
  for (;;) {
    if (pending >= retirement->max_pending) {
      instance_producer_state->callbacks_rejected.fetch_add(
          1, std::memory_order_relaxed);
      if (!retirement->repeating) {
        retirement->terminal_admitted.store(false, std::memory_order_release);
      }
      return ScheduleResult::QueueFull;
    }
    if (retirement->pending.compare_exchange_weak(pending, pending + 1,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_relaxed)) {
      break;
    }
  }

  std::shared_ptr<internal::PendingCallbackDispositionV1> disposition;
  try {
#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
    if (internal::test_fault::consume(
            internal::test_fault::kPostDispositionAllocation)) {
      throw std::bad_alloc();
    }
#endif
    disposition = std::make_shared<internal::PendingCallbackDispositionV1>();
    disposition->instance = instance;
    disposition->token_id = impl_->token_id;
    disposition->terminal = !retirement->repeating;
    disposition->retirement = retirement;
  } catch (...) {
    retirement->pending.fetch_sub(1, std::memory_order_acq_rel);
    if (!retirement->repeating) {
      retirement->terminal_admitted.store(false, std::memory_order_release);
    }
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::QueueFull;
  }

  TryRuntimeCallbackResult enqueue_result = TryRuntimeCallbackResult::Busy;
  try {
#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
    if (internal::test_fault::consume(
            internal::test_fault::kPostCallbackAllocation)) {
      throw std::bad_alloc();
    }
#endif
    enqueue_result = tryPushRuntimeExtensionCallback(
        target,
        [instance, instance_producer_state, token_id, authority,
         acquisition_principal,
         acquisition_principals = std::move(acquisition_principals),
         retire_after_delivery = disposition->terminal,
         payload = std::move(bytes)](facebook::jsi::Runtime &runtime) {
          auto slot = instance ? instance->callbackSlot(token_id) : nullptr;
          if (!instance || !slot) {
            return;
          }

          v1::CompletionTokenV1::OwnerCallback terminal_callback;
          if (retire_after_delivery) {
            terminal_callback = std::move(slot->callback);
          }
          if (instance_producer_state->lifecycle.load(
                  std::memory_order_acquire) ==
                  IBEX_RUNTIME_EXTENSION_ACTIVE &&
              authority && authority->currentOwnerStatus() == 1) {
            ScopedNativePrincipal principal(acquisition_principal);
            ScopedTypedPrincipalStack principals(acquisition_principals);
            auto &callback =
                retire_after_delivery ? terminal_callback : slot->callback;
            callback(runtime, payload);
            instance_producer_state->callbacks_admitted.fetch_add(
                1, std::memory_order_relaxed);
          } else {
            instance_producer_state->callbacks_rejected.fetch_add(
                1, std::memory_order_relaxed);
          }
        },
        [disposition]() noexcept {
          disposition->finishOnOwner(disposition->terminal);
        });
  } catch (...) {
    disposition->finishWithoutOwner();
    if (!retirement->repeating) {
      retirement->terminal_admitted.store(false, std::memory_order_release);
    }
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return ScheduleResult::QueueFull;
  }
  const bool accepted =
      enqueue_result == TryRuntimeCallbackResult::Accepted;
#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
  if (accepted) {
    internal::test_fault::holdAcceptedPostBeforeReturnIfArmed();
  }
#endif
  if (!accepted) {
    // Busy/Stale means tryPushRuntimeExtensionCallback did not transfer the
    // callback, so no owner can race this rollback.
    disposition->finishWithoutOwner();
    if (!retirement->repeating) {
      retirement->terminal_admitted.store(false, std::memory_order_release);
    }
    instance_producer_state->callbacks_rejected.fetch_add(
        1, std::memory_order_relaxed);
    return enqueue_result == TryRuntimeCallbackResult::Stale
               ? ScheduleResult::StaleGeneration
               : ScheduleResult::QueueFull;
  }
  return ScheduleResult::Accepted;
}

OperationLeaseV1::OperationLeaseV1() = default;
OperationLeaseV1::OperationLeaseV1(std::shared_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
OperationLeaseV1::OperationLeaseV1(OperationLeaseV1 &&) noexcept = default;
OperationLeaseV1 &
OperationLeaseV1::operator=(OperationLeaseV1 &&) noexcept = default;
OperationLeaseV1::~OperationLeaseV1() = default;

OperationLeaseV1::operator bool() const { return impl_ && impl_->isCurrent(); }

uint64_t OperationLeaseV1::opaqueId() const {
  return impl_ && impl_->retirementIsLive() ? impl_->lease : 0;
}

InstallContextV1::InstallContextV1(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
InstallContextV1::~InstallContextV1() = default;

InstallContextV1 &InstallContextV1::fromOpaque(void *opaque) {
  if (!opaque)
    throw std::invalid_argument("null runtime extension context");
  return *static_cast<InstallContextV1 *>(opaque);
}

facebook::jsi::Runtime &InstallContextV1::runtime() const {
  if (!impl_ || !impl_->runtime || !impl_->runtime->runtime ||
      !impl_->instance) {
    throw std::runtime_error("runtime extension context is closed");
  }
  const auto lifecycle = impl_->instance->producer_state->lifecycle.load(
      std::memory_order_acquire);
  if (lifecycle == IBEX_RUNTIME_EXTENSION_DECLARED ||
      lifecycle == IBEX_RUNTIME_EXTENSION_CLOSED) {
    throw std::runtime_error("runtime extension context is closed");
  }
  if (impl_->runtime->runtime_thread != std::this_thread::get_id()) {
    throw std::runtime_error(
        "runtime extension JSI access requires the runtime owner");
  }
  return *impl_->runtime->runtime;
}

uint64_t InstallContextV1::runtimeNonce() const {
  return impl_ && impl_->runtime ? impl_->runtime->runtime_nonce : 0;
}

uint64_t InstallContextV1::generation() const {
  return impl_ && impl_->instance ? impl_->instance->generation : 0;
}

const std::string &InstallContextV1::extensionId() const {
  if (!impl_ || !impl_->instance) {
    throw std::runtime_error("runtime extension context is closed");
  }
  return impl_->instance->id;
}

uint64_t InstallContextV1::supportedFeatures() const {
  return internal::kSupportedFeatures;
}

const RuntimeExtensionProviderBindingV1 *InstallContextV1::provider() const {
  if (!impl_ || !impl_->instance || !impl_->instance->provider)
    return nullptr;
  (void)runtime();
  // The view and all strings it references are owned by this immutable
  // Instance. A later provider() call for another context cannot overwrite it.
  // @ref LLP 0040#1-source-linked-sdk-and-immutable-descriptor-table
  return &impl_->instance->provider_view;
}

void InstallContextV1::defineGlobal(const std::string &path,
                                    facebook::jsi::Value value, bool writable,
                                    bool enumerable) {
  if (!impl_ || !impl_->instance ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_INSTALLING) {
    throw std::runtime_error("runtime extension globals are construction-only");
  }
  const auto *declaration = impl_->instance->global(path);
  if (!declaration) {
    throw std::runtime_error(
        "runtime extension attempted an undeclared global: " + path);
  }
  auto segments = internal::splitPath(path);
  if (segments.empty()) {
    throw std::runtime_error("runtime extension global path is invalid");
  }
  auto &rt = runtime();
  if (!value.isObject() ||
      (declaration->kind == IBEX_RUNTIME_EXTENSION_GLOBAL_FUNCTION &&
       !value.asObject(rt).isFunction(rt)) ||
      (declaration->kind == IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT &&
       value.asObject(rt).isFunction(rt))) {
    throw std::runtime_error(
        "runtime extension global kind does not match declaration: " + path);
  }
  auto define_property = internal::objectFunction(rt, "defineProperty");
  auto get_descriptor =
      internal::objectFunction(rt, "getOwnPropertyDescriptor");
  auto current = facebook::jsi::Object(rt.global());
  for (size_t index = 0; index + 1 < segments.size(); ++index) {
    auto descriptor_value = get_descriptor.call(
        rt, current,
        facebook::jsi::String::createFromUtf8(rt, segments[index]));
    if (descriptor_value.isUndefined()) {
      facebook::jsi::Object child(rt);
      facebook::jsi::Object descriptor(rt);
      descriptor.setProperty(rt, "value", child);
      descriptor.setProperty(rt, "writable", false);
      descriptor.setProperty(rt, "enumerable", false);
      descriptor.setProperty(rt, "configurable", false);
      define_property.call(
          rt, current,
          facebook::jsi::String::createFromUtf8(rt, segments[index]),
          descriptor);
      current = std::move(child);
      continue;
    }
    if (!descriptor_value.isObject()) {
      throw std::runtime_error("runtime extension global parent is invalid");
    }
    auto descriptor = descriptor_value.asObject(rt);
    auto getter = descriptor.getProperty(rt, "get");
    auto setter = descriptor.getProperty(rt, "set");
    auto parent_value = descriptor.getProperty(rt, "value");
    if (!getter.isUndefined() || !setter.isUndefined() ||
        !parent_value.isObject()) {
      throw std::runtime_error(
          "runtime extension global parent is not a data object");
    }
    auto parent = parent_value.asObject(rt);
    if (parent.isHostObject(rt)) {
      throw std::runtime_error(
          "runtime extension global parent may not be a HostObject");
    }
    current = std::move(parent);
  }
  auto existing = get_descriptor.call(
      rt, current, facebook::jsi::String::createFromUtf8(rt, segments.back()));
  if (!existing.isUndefined()) {
    throw std::runtime_error(
        "runtime extension may not replace an existing global: " + path);
  }
  facebook::jsi::Object descriptor(rt);
  descriptor.setProperty(rt, "value", std::move(value));
  descriptor.setProperty(rt, "writable", writable);
  descriptor.setProperty(rt, "enumerable", enumerable);
  descriptor.setProperty(rt, "configurable", false);
  define_property.call(
      rt, current, facebook::jsi::String::createFromUtf8(rt, segments.back()),
      descriptor);
}

void InstallContextV1::defineModule(const std::string &specifier,
                                    facebook::jsi::Value exports) {
  if (!impl_ || !impl_->instance ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_INSTALLING ||
      !std::binary_search(impl_->instance->module_specifiers.begin(),
                          impl_->instance->module_specifiers.end(),
                          specifier) ||
      impl_->instance->published_modules.count(specifier) != 0) {
    throw std::runtime_error(
        "runtime extension attempted an undeclared or duplicate module: " +
        specifier);
  }
  auto &rt = runtime();
  if (!impl_->runtime ||
      !impl_->runtime->runtime_extension_module_registrar) {
    throw std::runtime_error(
        "runtime extension module registrar is unavailable");
  }
  auto result = impl_->runtime->runtime_extension_module_registrar->call(
      rt, facebook::jsi::String::createFromUtf8(rt, specifier),
      std::move(exports));
  if (!result.isBool() || !result.getBool()) {
    throw std::runtime_error("runtime extension module registrar refused: " +
                             specifier);
  }
  impl_->instance->published_modules.insert(specifier);
}

OperationLeaseV1 InstallContextV1::authorize(
    const std::string &operationId, const std::string &resourceJson,
    const std::vector<const OperationLeaseV1 *> &presentedLeases) {
  if (!impl_ || !impl_->runtime || !impl_->instance ||
      impl_->runtime->runtime_thread != std::this_thread::get_id() ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_ACTIVE ||
      g_activeOperationContext != this || g_activeOperationId == nullptr ||
      operationId != g_activeOperationId) {
    return {};
  }
  // Consecutive effectful calls can occur within one JavaScript host task,
  // before its boundary checkpoint. Reap prior owner-requested leases here so
  // the bounded owner slot table cannot be exhausted by already-retired
  // synchronous calls.
  impl_->instance->retireRequestedOperationLeaseSlots();
  const auto *operation = impl_->instance->operation(operationId);
  if (!operation)
    return {};
  auto principals = exactCollectTypedPrincipalStack();
  std::vector<uint64_t> presented_lease_ids;
  presented_lease_ids.reserve(presentedLeases.size());
  for (const auto *presented : presentedLeases) {
    if (presented == nullptr || !*presented ||
        presented->impl_->host_context_id != impl_->runtime->host_context_id ||
        presented->impl_->runtime_nonce != impl_->runtime->runtime_nonce ||
        presented->impl_->extension_generation != impl_->instance->generation ||
        presented->impl_->extension_id != impl_->instance->id) {
      return {};
    }
    presented_lease_ids.push_back(presented->impl_->lease);
  }
  std::sort(presented_lease_ids.begin(), presented_lease_ids.end());
  if (std::adjacent_find(presented_lease_ids.begin(),
                         presented_lease_ids.end()) !=
      presented_lease_ids.end()) {
    return {};
  }
  std::vector<const char *> resource_kinds;
  resource_kinds.reserve(operation->resource_kinds.size());
  for (const auto &resource_kind : operation->resource_kinds) {
    resource_kinds.push_back(resource_kind.c_str());
  }
  uint64_t lease = 0;
  if (ex_host_authorize_runtime_extension_operation_v1(
          impl_->runtime->host_context_id, impl_->runtime->runtime_nonce,
          impl_->instance->generation, impl_->instance->id.c_str(),
          operation->id.c_str(), operation->authority_class.c_str(),
          operation->semantics.c_str(), operation->stage.c_str(),
          operation->atomicity_group.c_str(), resource_kinds.data(),
          resource_kinds.size(), resourceJson.c_str(), principals.data(),
          principals.size(),
          presented_lease_ids.empty() ? nullptr : presented_lease_ids.data(),
          presented_lease_ids.size(), &lease) != 1 ||
      lease == 0) {
    return {};
  }
  struct OwnerLeaseRollback {
    uint64_t host_context_id{0};
    uint64_t lease{0};
    ~OwnerLeaseRollback() {
      if (lease != 0) {
        (void)ex_host_revoke_runtime_extension_lease_v1(host_context_id, lease);
      }
    }
  } rollback{impl_->runtime->host_context_id, lease};

  auto retirement =
      std::make_shared<internal::OperationLeaseRetirementState>();
  auto lease_impl = std::make_shared<OperationLeaseV1::Impl>();
  lease_impl->host_context_id = impl_->runtime->host_context_id;
  lease_impl->lease = lease;
  lease_impl->runtime_nonce = impl_->runtime->runtime_nonce;
  lease_impl->extension_generation = impl_->instance->generation;
  lease_impl->extension_id = impl_->instance->id;
  lease_impl->operation_id = operationId;
  lease_impl->runtime_producer_state =
      impl_->runtime->runtime_extensions->producer_state;
  lease_impl->retirement = retirement;
  impl_->instance->addOperationLeaseSlot(
      internal::OperationLeaseSlot{impl_->runtime->host_context_id, lease,
                                   retirement});
  retirement->published.store(true, std::memory_order_release);
  rollback.lease = 0;
  return OperationLeaseV1(std::move(lease_impl));
}

facebook::jsi::Function InstallContextV1::makeEffectfulHostFunction(
    const std::string &operationId, const std::string &functionName,
    unsigned int parameterCount, EffectfulHostFunction callback,
    ResourceNormalizer resourceNormalizer,
    PresentedLeaseCollector presentedLeaseCollector) {
  if (!impl_ || !impl_->instance ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_INSTALLING ||
      impl_->instance->operation(operationId) == nullptr || !callback) {
    throw std::runtime_error(
        "effectful runtime extension function is not declared");
  }
  auto &rt = runtime();
  return facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forUtf8(rt, functionName), parameterCount,
      [this, operationId, callback = std::move(callback),
       resourceNormalizer = std::move(resourceNormalizer),
       presentedLeaseCollector = std::move(presentedLeaseCollector)](
          facebook::jsi::Runtime &callback_runtime,
          const facebook::jsi::Value &receiver,
          const facebook::jsi::Value *arguments,
          size_t count) mutable -> facebook::jsi::Value {
        const auto resource_json =
            resourceNormalizer ? resourceNormalizer(callback_runtime, receiver,
                                                    arguments, count)
                               : std::string("{}");
        const auto presented_leases =
            presentedLeaseCollector
                ? presentedLeaseCollector(callback_runtime, receiver, arguments,
                                          count)
                : std::vector<const OperationLeaseV1 *>{};
        ScopedExtensionOperationV1 operation_scope(this, operationId.c_str());
        auto lease = authorize(operationId, resource_json, presented_leases);
        if (!lease) {
          throw facebook::jsi::JSError(
              callback_runtime,
              "Permission denied: runtime extension operation");
        }
        return callback(callback_runtime, lease, receiver, arguments, count);
      });
}

CompletionTokenV1 InstallContextV1::makeCompletionToken(
    OperationLeaseV1 &lease, const std::string &callbackId,
    CompletionTokenV1::OwnerCallback callback, CompletionMode mode) {
  if (!impl_ || !impl_->runtime || !impl_->instance || !callback || !lease ||
      !lease.impl_) {
    return {};
  }
  const auto *declaration = impl_->instance->callback(callbackId);
  if (!declaration ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_ACTIVE ||
      g_activeOperationContext != this || g_activeOperationId == nullptr ||
      declaration->operation_id != g_activeOperationId ||
      lease.impl_->host_context_id != impl_->runtime->host_context_id ||
      lease.impl_->runtime_nonce != impl_->runtime->runtime_nonce ||
      lease.impl_->extension_generation != impl_->instance->generation ||
      lease.impl_->extension_id != impl_->instance->id ||
      lease.impl_->operation_id != declaration->operation_id ||
      (mode != CompletionMode::Once && mode != CompletionMode::Repeating) ||
      impl_->instance->next_callback_token_id == 0 ||
      impl_->instance->next_callback_token_id ==
          std::numeric_limits<uint64_t>::max()) {
    return {};
  }

  // A producer may have requested retirement since the preceding owner task.
  // Reap those zero-pending slots before applying the bounded slot budget.
  impl_->instance->retireRequestedCallbackSlots();
  if (impl_->instance->callbackSlotCount() >= internal::kMaxListItems) {
    return {};
  }

  auto retirement = std::make_shared<internal::CallbackRetirementState>();
  auto slot = std::make_shared<internal::CallbackSlot>();
  auto authority = std::make_shared<internal::CompletionAuthorityState>();
  const uint64_t token_id = impl_->instance->next_callback_token_id;
  slot->token_id = token_id;
  slot->retirement = retirement;
  slot->operation_lease = lease.impl_;
  slot->callback = std::move(callback);
  authority->host_context_id = lease.impl_->host_context_id;
  authority->lease = lease.impl_->lease;
  authority->runtime_nonce = lease.impl_->runtime_nonce;
  authority->extension_generation = lease.impl_->extension_generation;
  authority->extension_id = lease.impl_->extension_id;
  authority->operation_id = lease.impl_->operation_id;
  retirement->max_pending = declaration->max_pending;
  retirement->repeating = mode == CompletionMode::Repeating;

#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
  if (internal::test_fault::consume(
          internal::test_fault::kTokenImplAllocation)) {
    throw std::bad_alloc();
  }
#endif
  auto token = std::make_shared<CompletionTokenV1::Impl>();
  token->target = exactRuntimeCallbackTarget(impl_->runtime);
  token->instance = impl_->instance;
  token->runtime_producer_state =
      impl_->runtime->runtime_extensions->producer_state;
  token->instance_producer_state = impl_->instance->producer_state;
  token->extension_id = impl_->instance->id;
  token->generation = impl_->instance->generation;
  token->token_id = token_id;
  token->acquisition_principal = currentPrincipalId();
  token->acquisition_principals = exactCollectTypedPrincipalStack();
  token->authority = std::move(authority);
  token->retirement = retirement;
  CompletionTokenV1 result(std::move(token));

  // All potentially throwing token state exists before publication. If the
  // vector insertion itself throws, both the local slot and its JSI callback
  // unwind on this owner thread and `result` observes published=false.
  impl_->instance->next_callback_token_id++;
  impl_->instance->addCallbackSlot(std::move(slot));
  retirement->published.store(true, std::memory_order_release);
  return result;
}

std::vector<uint8_t> InstallContextV1::copyBytes(const uint8_t *bytes,
                                                 size_t length) const {
  if ((length != 0 && bytes == nullptr) ||
      length > internal::kMaxCopiedPayloadBytes) {
    throw std::invalid_argument("runtime extension copy exceeds SDK limit");
  }
  return length == 0 ? std::vector<uint8_t>()
                     : std::vector<uint8_t>(bytes, bytes + length);
}

facebook::jsi::ArrayBuffer InstallContextV1::createKeyedExternalRange(
    OperationLeaseV1 &lease, const facebook::jsi::ArrayBuffer &source,
    size_t byteOffset, size_t byteLength, uint64_t revocationKey) {
#if !defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
  (void)lease;
  (void)source;
  (void)byteOffset;
  (void)byteLength;
  (void)revocationKey;
  throw std::runtime_error(
      "keyed external buffers are unavailable in this Hermes build");
#else
  if (!impl_ || !impl_->runtime || !impl_->instance || !lease || !lease.impl_ ||
      lease.impl_->runtime_nonce != impl_->runtime->runtime_nonce ||
      lease.impl_->extension_generation != impl_->instance->generation ||
      lease.impl_->extension_id != impl_->instance->id ||
      g_activeOperationContext != this || g_activeOperationId == nullptr ||
      lease.impl_->operation_id != g_activeOperationId || revocationKey == 0 ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_ACTIVE ||
      (impl_->instance->required_features &
       IBEX_RUNTIME_EXTENSION_FEATURE_KEYED_EXTERNAL_BUFFERS) == 0 ||
      impl_->instance->revoking_external_keys.count(revocationKey) != 0 ||
      impl_->instance->retired_external_keys.count(revocationKey) != 0) {
    throw std::runtime_error("keyed external buffer creation was not admitted");
  }
  auto &owner = runtime();
  auto *api = internal::keyedExternalApi(owner);
  if (!api) {
    throw std::runtime_error(
        "keyed external buffer feature was negotiated but disappeared");
  }
  auto alias =
      api->createKeyedExternalRangeAlias(source, byteOffset, byteLength);
  auto retained =
      facebook::jsi::Value(owner, alias).asObject(owner).getArrayBuffer(owner);
  impl_->instance->keyed_external_aliases.push_back(
      internal::KeyedExternalAlias{
          revocationKey,
          std::make_unique<facebook::jsi::ArrayBuffer>(std::move(retained)),
      });
  return alias;
#endif
}

bool InstallContextV1::revokeKeyedExternalKey(OperationLeaseV1 &lease,
                                              uint64_t revocationKey) {
  if (!impl_ || !impl_->runtime || !impl_->instance || !lease || !lease.impl_ ||
      lease.impl_->runtime_nonce != impl_->runtime->runtime_nonce ||
      lease.impl_->extension_generation != impl_->instance->generation ||
      lease.impl_->extension_id != impl_->instance->id ||
      g_activeOperationContext != this || g_activeOperationId == nullptr ||
      lease.impl_->operation_id != g_activeOperationId || revocationKey == 0 ||
      impl_->instance->producer_state->lifecycle.load(
          std::memory_order_acquire) !=
          IBEX_RUNTIME_EXTENSION_ACTIVE ||
      !impl_->instance->hasActiveExternalKey(revocationKey)) {
    return false;
  }
  return internal::revokeKeyedExternalAliases(impl_->runtime, *impl_->instance,
                                              revocationKey, false);
}

} // namespace ibex::runtime_extension::v1

#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
extern "C" void
ibex_test_runtime_extension_arm_completion_fault_v1(uint32_t fault_mask) {
  constexpr uint32_t kSupported =
      ibex::runtime_extension::internal::test_fault::kTokenImplAllocation |
      ibex::runtime_extension::internal::test_fault::
          kPostDispositionAllocation |
      ibex::runtime_extension::internal::test_fault::
          kPostCallbackAllocation;
  if (fault_mask == 0) {
    ibex::runtime_extension::internal::test_fault::g_armed.store(
        0, std::memory_order_release);
    return;
  }
  ibex::runtime_extension::internal::test_fault::g_armed.fetch_or(
      fault_mask & kSupported, std::memory_order_acq_rel);
}

extern "C" void
ibex_test_runtime_extension_arm_keyed_external_detach_fault_v1() {
  ibex::runtime_extension::internal::test_fault::g_armed.fetch_or(
      ibex::runtime_extension::internal::test_fault::
          kKeyedExternalDetachException,
      std::memory_order_acq_rel);
}
#endif

extern "C" uint32_t ibex_runtime_extension_sdk_version_v1() {
  return IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1;
}

extern "C" uint64_t ibex_runtime_extension_supported_features_v1() {
  return ibex::runtime_extension::internal::kSupportedFeatures;
}

extern "C" size_t ibex_runtime_extension_count_v1(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->runtime_extensions)
    return 0;
  return runtime->runtime_extensions->instances.size();
}

extern "C" int32_t
ibex_runtime_extension_inspect_v1(ExactHermesRuntime *runtime, size_t index,
                                  IbexRuntimeExtensionInspectionV1 *output) {
  if (!runtime || !runtime->runtime_extensions || !output ||
      output->struct_size != sizeof(IbexRuntimeExtensionInspectionV1) ||
      index >= runtime->runtime_extensions->instances.size()) {
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  }
  const auto &instance = *runtime->runtime_extensions->instances[index];
  output->id = instance.id.c_str();
  output->version = instance.version.c_str();
  output->manifest_digest = instance.manifest_digest.c_str();
  output->generation = instance.generation;
  output->lifecycle_state =
      instance.producer_state->lifecycle.load(std::memory_order_acquire);
  output->callbacks_admitted =
      instance.producer_state->callbacks_admitted.load(
          std::memory_order_relaxed);
  output->callbacks_rejected =
      instance.producer_state->callbacks_rejected.load(
          std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

static const char *runtimeExtensionLifecycleStateName(uint32_t state) {
  switch (state) {
  case IBEX_RUNTIME_EXTENSION_DECLARED:
    // A selected instance which never advanced into installation represents
    // a failed construction. Such a runtime is normally destroyed before it
    // can be observed, but retain an explicit data-only name for diagnostics.
    return "failed";
  case IBEX_RUNTIME_EXTENSION_INSTALLING:
    return "installing";
  case IBEX_RUNTIME_EXTENSION_ACTIVE:
    return "active";
  case IBEX_RUNTIME_EXTENSION_QUIESCING_STATE:
    return "quiescing";
  case IBEX_RUNTIME_EXTENSION_CLOSED:
    return "closed";
  default:
    return "unknown";
  }
}

extern "C" char *
ibex_runtime_extension_report_json_v1(ExactHermesRuntime *runtime) {
  if (!runtime || !runtime->runtime_extensions)
    return nullptr;
  const auto &state = *runtime->runtime_extensions;
  std::ostringstream report;
  report << "{\"schema\":\"ibex.runtime-extension-report/v1\","
            "\"mode\":\""
         << ibex::runtime_extension::internal::jsonEscape(state.report_mode)
         << "\",\"registryAuthenticated\":"
         << (state.registry_authenticated ? "true" : "false")
         << ",\"sdkVersion\":1,\"extensionSetDigest\":\""
         << ibex::runtime_extension::internal::jsonEscape(
                state.extension_set_digest)
         << "\",\"authorityCapsuleDigest\":\""
         << ibex::runtime_extension::internal::jsonEscape(
                state.authority_capsule_digest)
         << "\",\"executableSelectionIdentity\":\""
         << ibex::runtime_extension::internal::jsonEscape(
                state.executable_selection_identity)
         << "\",\"extensions\":[";
  for (size_t index = 0; index < state.instances.size(); ++index) {
    if (index != 0)
      report << ',';
    const auto &instance = *state.instances[index];
    const auto lifecycle_state =
        instance.producer_state->lifecycle.load(std::memory_order_acquire);
    report << "{\"id\":\""
           << ibex::runtime_extension::internal::jsonEscape(instance.id)
           << "\",\"version\":\""
           << ibex::runtime_extension::internal::jsonEscape(instance.version)
           << "\",\"manifestDigest\":\""
           << ibex::runtime_extension::internal::jsonEscape(
                  instance.manifest_digest)
           << "\",\"generation\":" << instance.generation
           << ",\"state\":" << lifecycle_state << ",\"stateName\":\""
           << runtimeExtensionLifecycleStateName(lifecycle_state) << '"'
           << ",\"requiredFeatureBits\":" << instance.required_features
           << ",\"providerAbi\":";
    if (instance.provider) {
      report << "{\"id\":\""
             << ibex::runtime_extension::internal::jsonEscape(
                    instance.provider->abi_id)
             << "\",\"minVersion\":" << instance.provider->minimum_version
             << ",\"selectedVersion\":" << instance.provider->abi_version
             << ",\"structSize\":" << instance.provider->provider_struct_size
             << ",\"identityDigest\":\""
             << ibex::runtime_extension::internal::jsonEscape(
                    instance.provider->identity_digest)
             << "\"}";
    } else {
      report << "null";
    }
    report << ",\"callbacksAdmitted\":"
           << instance.producer_state->callbacks_admitted.load(
                  std::memory_order_relaxed)
           << ",\"callbacksRejected\":"
           << instance.producer_state->callbacks_rejected.load(
                  std::memory_order_relaxed)
           << '}';
  }
  report << "]}";
  const auto text = report.str();
  auto *output = static_cast<char *>(std::malloc(text.size() + 1));
  if (!output)
    return nullptr;
  std::memcpy(output, text.data(), text.size());
  output[text.size()] = '\0';
  return output;
}
