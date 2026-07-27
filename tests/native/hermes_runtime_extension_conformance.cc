#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../../include/ibex/runtime_extension.hpp"
#include "../../src/engine/hermes_runtime_extension_internal.h"

namespace {

namespace ext = ibex::runtime_extension::v1;

constexpr char kManifestDigest[] =
    "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
constexpr char kCapsuleDigest[] =
    "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
constexpr char kSetDigest[] =
    "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
constexpr char kSelectionDigest[] =
    "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
constexpr char kUndeclaredModuleBootstrapSource[] =
    "globalThis.__ibexRegisterRuntimeExtensionModule("
    "\"ibex:undeclared-bootstrap\", Object.freeze({marker: 1}));";
constexpr char kUndeclaredModuleBootstrapDigest[] =
    "sha256-azE-F512727VJChByuLh3AnpE0_jRYmiwROA4By3BJI";
constexpr char kProviderAbiId[] = "ibex.conformance.provider";
constexpr uint64_t kProviderMarker = 4242;

struct FixtureProviderVTableV1 {
  uint64_t marker;
};

constexpr FixtureProviderVTableV1 kFixtureProviderVTable = {
    kProviderMarker,
};
uint64_t g_fixtureProviderContext = kProviderMarker;

constexpr IbexRuntimeExtensionProviderBindingV1 kFixtureProviderBinding = {
    sizeof(IbexRuntimeExtensionProviderBindingV1),
    "ibex.conformance",
    kProviderAbiId,
    1,
    sizeof(FixtureProviderVTableV1),
    kManifestDigest,
    &kFixtureProviderVTable,
    &g_fixtureProviderContext,
};
constexpr uint64_t kSecondaryProviderMarker = 4343;
uint64_t g_secondaryProviderContext = kSecondaryProviderMarker;
constexpr IbexRuntimeExtensionProviderBindingV1 kSecondaryProviderBinding = {
    sizeof(IbexRuntimeExtensionProviderBindingV1),
    "ibex.conformance.secondary",
    kProviderAbiId,
    1,
    sizeof(FixtureProviderVTableV1),
    kManifestDigest,
    &kFixtureProviderVTable,
    &g_secondaryProviderContext,
};

std::atomic<uint64_t> g_installCount{0};
std::atomic<uint64_t> g_quiesceCount{0};
std::atomic<uint64_t> g_closeCount{0};
std::atomic<uint64_t> g_enqueuedCount{0};
std::atomic<uint64_t> g_postAcceptedCount{0};
std::atomic<uint64_t> g_postRejectedCount{0};
std::atomic<uint64_t> g_ownerDeliveryMismatchCount{0};
std::atomic<uint64_t> g_ownerCaptureDestroyedCount{0};
std::atomic<uint64_t> g_ownerCaptureMismatchCount{0};
std::atomic<uint64_t> g_closeSequence{0};
std::atomic<uint64_t> g_teardownScheduleRejectedCount{0};
std::atomic<uint64_t> g_providerViewStableCount{0};
std::atomic<uint64_t> g_offOwnerTokenRetiredCount{0};
std::atomic<uint64_t> g_offOwnerLeaseRetiredCount{0};
std::atomic<int32_t> g_lastPostResult{
    static_cast<int32_t>(ext::ScheduleResult::Invalid)};
std::atomic<uint32_t> g_offOwnerRetireDelayMs{0};
std::atomic<bool> g_retireNextSubscriptionOffOwner{false};
std::atomic<bool> g_holdNextOperationLeaseRetirement{false};
std::atomic<bool> g_operationLeaseRetirementHeld{false};
std::atomic<bool> g_releaseOperationLeaseRetirement{true};
const IbexRuntimeExtensionProviderBindingV1 *g_primaryProviderView{nullptr};

void recordClose(uint64_t marker) {
  auto current = g_closeSequence.load(std::memory_order_relaxed);
  while (!g_closeSequence.compare_exchange_weak(current, current * 10 + marker,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
  }
}

struct OwnerCaptureWitness {
  explicit OwnerCaptureWitness(std::thread::id owner) : owner_(owner) {}

  ~OwnerCaptureWitness() {
    g_ownerCaptureDestroyedCount.fetch_add(1, std::memory_order_relaxed);
    if (std::this_thread::get_id() != owner_) {
      g_ownerCaptureMismatchCount.fetch_add(1, std::memory_order_relaxed);
    }
  }

private:
  std::thread::id owner_;
};

class FixtureHostObject final : public facebook::jsi::HostObject {
public:
  explicit FixtureHostObject(uint64_t identity) : identity_(identity) {}

  facebook::jsi::Value get(facebook::jsi::Runtime &runtime,
                           const facebook::jsi::PropNameID &property) override {
    if (property.utf8(runtime) == "identity") {
      return facebook::jsi::Value(static_cast<double>(identity_));
    }
    return facebook::jsi::Value::undefined();
  }

  std::vector<facebook::jsi::PropNameID>
  getPropertyNames(facebook::jsi::Runtime &runtime) override {
    std::vector<facebook::jsi::PropNameID> names;
    names.push_back(facebook::jsi::PropNameID::forAscii(runtime, "identity"));
    return names;
  }

private:
  uint64_t identity_;
};

class VectorBuffer final : public facebook::jsi::MutableBuffer {
public:
  explicit VectorBuffer(std::vector<uint8_t> bytes)
      : bytes_(std::move(bytes)) {}

  size_t size() const override { return bytes_.size(); }

  uint8_t *data() override { return bytes_.data(); }

private:
  std::vector<uint8_t> bytes_;
};

struct FixtureInstance {
  std::thread::id owner_thread;
  ext::CompletionTokenV1 event_token;
  bool has_event_token{false};
};

struct PromiseResolvers {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

facebook::jsi::Object
makePromise(facebook::jsi::Runtime &runtime,
            const std::shared_ptr<PromiseResolvers> &resolvers) {
  auto executor = facebook::jsi::Function::createFromHostFunction(
      runtime,
      facebook::jsi::PropNameID::forAscii(runtime,
                                          "runtimeExtensionFixtureExecutor"),
      2,
      [resolvers](facebook::jsi::Runtime &callback_runtime,
                  const facebook::jsi::Value &,
                  const facebook::jsi::Value *arguments,
                  size_t count) -> facebook::jsi::Value {
        if (count < 2 || !arguments[0].isObject() || !arguments[1].isObject() ||
            !arguments[0]
                 .asObject(callback_runtime)
                 .isFunction(callback_runtime) ||
            !arguments[1]
                 .asObject(callback_runtime)
                 .isFunction(callback_runtime)) {
          throw facebook::jsi::JSError(
              callback_runtime, "malformed conformance Promise executor");
        }
        resolvers->resolve = std::make_shared<facebook::jsi::Function>(
            arguments[0]
                .asObject(callback_runtime)
                .asFunction(callback_runtime));
        resolvers->reject = std::make_shared<facebook::jsi::Function>(
            arguments[1]
                .asObject(callback_runtime)
                .asFunction(callback_runtime));
        return facebook::jsi::Value::undefined();
      });
  auto promise = runtime.global()
                     .getPropertyAsFunction(runtime, "Promise")
                     .callAsConstructor(runtime, executor)
                     .getObject(runtime);
  if (!resolvers->resolve || !resolvers->reject) {
    throw facebook::jsi::JSError(
        runtime, "conformance Promise executor did not initialize");
  }
  return promise;
}

void recordPost(ext::ScheduleResult result) {
  g_lastPostResult.store(static_cast<int32_t>(result),
                         std::memory_order_release);
  if (result == ext::ScheduleResult::Accepted) {
    g_postAcceptedCount.fetch_add(1, std::memory_order_relaxed);
  } else {
    g_postRejectedCount.fetch_add(1, std::memory_order_relaxed);
  }
}

int32_t installFixture(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &context = ext::InstallContextV1::fromOpaque(opaque_context);
  auto &runtime = context.runtime();
  const auto *provider = context.provider();
  if (provider == nullptr || provider->extension_id == nullptr ||
      provider->abi_id == nullptr || provider->identity_digest == nullptr ||
      std::string(provider->extension_id) != "ibex.conformance" ||
      std::string(provider->abi_id) != kProviderAbiId ||
      provider->abi_version != 1 ||
      provider->provider_struct_size != sizeof(FixtureProviderVTableV1) ||
      std::string(provider->identity_digest) != kManifestDigest ||
      provider->vtable == nullptr || provider->context == nullptr) {
    return IBEX_RUNTIME_EXTENSION_AUTHENTICATION_FAILED;
  }
  const auto *provider_vtable =
      static_cast<const FixtureProviderVTableV1 *>(provider->vtable);
  const auto *provider_context =
      static_cast<const uint64_t *>(provider->context);
  if (provider_vtable->marker != kProviderMarker ||
      *provider_context != kProviderMarker) {
    return IBEX_RUNTIME_EXTENSION_AUTHENTICATION_FAILED;
  }
  g_primaryProviderView = provider;
  auto instance = std::make_unique<FixtureInstance>();
  instance->owner_thread = std::this_thread::get_id();
  auto api = facebook::jsi::Object(runtime);
  api.setProperty(runtime, "providerMarker",
                  static_cast<double>(provider_vtable->marker));

  auto prototype = facebook::jsi::Object(runtime);
  prototype.setProperty(
      runtime, "kind",
      facebook::jsi::String::createFromAscii(runtime, "native-fixture"));
  auto native_object = facebook::jsi::Object::createFromHostObject(
      runtime, std::make_shared<FixtureHostObject>(context.generation()));
  runtime.global()
      .getPropertyAsObject(runtime, "Object")
      .getPropertyAsFunction(runtime, "setPrototypeOf")
      .call(runtime, native_object, prototype);
  api.setProperty(runtime, "prototype", prototype);
  api.setProperty(runtime, "nativeObject", native_object);
  auto retained_native_object = std::make_shared<facebook::jsi::Object>(
      facebook::jsi::Value(runtime, native_object).asObject(runtime));

  api.setProperty(
      runtime, "getNativeObject",
      facebook::jsi::Function::createFromHostFunction(
          runtime,
          facebook::jsi::PropNameID::forAscii(runtime, "getNativeObject"), 0,
          [retained_native_object](facebook::jsi::Runtime &callback_runtime,
                                   const facebook::jsi::Value &,
                                   const facebook::jsi::Value *,
                                   size_t) mutable -> facebook::jsi::Value {
            return facebook::jsi::Value(callback_runtime,
                                        *retained_native_object);
          }));

  api.setProperty(
      runtime, "enqueue",
      context.makeEffectfulHostFunction(
          "enqueue", "enqueue", 1,
          [](facebook::jsi::Runtime &callback_runtime, ext::OperationLeaseV1 &,
             const facebook::jsi::Value &,
             const facebook::jsi::Value *arguments,
             size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isNumber()) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "enqueue requires one number");
            }
            const auto sequence =
                g_enqueuedCount.fetch_add(1, std::memory_order_relaxed) + 1;
            return facebook::jsi::Value(static_cast<double>(sequence));
          }));

  api.setProperty(
      runtime, "retireLeaseOffOwner",
      context.makeEffectfulHostFunction(
          "retire-lease", "retireLeaseOffOwner", 0,
          [](facebook::jsi::Runtime &callback_runtime,
             ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
             const facebook::jsi::Value *, size_t count)
              -> facebook::jsi::Value {
            if (count != 0 ||
                !g_holdNextOperationLeaseRetirement.exchange(
                    false, std::memory_order_acq_rel)) {
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "off-owner lease retirement fixture was not armed");
            }
            auto retained =
                std::make_unique<ext::OperationLeaseV1>(std::move(lease));
            std::thread([retained = std::move(retained)]() mutable {
              g_operationLeaseRetirementHeld.store(true,
                                                   std::memory_order_release);
              while (!g_releaseOperationLeaseRetirement.load(
                  std::memory_order_acquire)) {
                std::this_thread::yield();
              }
              retained.reset();
              g_offOwnerLeaseRetiredCount.fetch_add(1,
                                                    std::memory_order_release);
            }).detach();
            return facebook::jsi::Value::undefined();
          }));

  api.setProperty(
      runtime, "complete",
      context.makeEffectfulHostFunction(
          "complete", "complete", 1,
          [&context, instance_ptr = instance.get()](
              facebook::jsi::Runtime &callback_runtime,
              ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
              const facebook::jsi::Value *arguments,
              size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isString()) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "complete requires one string");
            }
            const auto payload =
                arguments[0].asString(callback_runtime).utf8(callback_runtime);
            auto resolvers = std::make_shared<PromiseResolvers>();
            auto owner_witness = std::make_shared<OwnerCaptureWitness>(
                instance_ptr->owner_thread);
            const auto owner_thread = instance_ptr->owner_thread;
            auto promise = makePromise(callback_runtime, resolvers);
            auto token = context.makeCompletionToken(
                lease, "promise",
                [resolvers, owner_witness,
                 owner_thread](facebook::jsi::Runtime &owner_runtime,
                               const std::vector<uint8_t> &bytes) {
                  (void)owner_witness;
                  if (std::this_thread::get_id() != owner_thread) {
                    g_ownerDeliveryMismatchCount.fetch_add(
                        1, std::memory_order_relaxed);
                  }
                  resolvers->resolve->call(
                      owner_runtime,
                      facebook::jsi::String::createFromUtf8(
                          owner_runtime, bytes.data(), bytes.size()));
                });
            if (!token) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "completion token unavailable");
            }
            std::thread([token = std::move(token), payload]() mutable {
              std::this_thread::sleep_for(std::chrono::milliseconds(2));
              recordPost(
                  token.post(reinterpret_cast<const uint8_t *>(payload.data()),
                             payload.size()));
            }).detach();
            return promise;
          }));

  api.setProperty(
      runtime, "completeAfter",
      context.makeEffectfulHostFunction(
          "complete-after", "completeAfter", 2,
          [&context, instance_ptr = instance.get()](
              facebook::jsi::Runtime &callback_runtime,
              ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
              const facebook::jsi::Value *arguments,
              size_t count) -> facebook::jsi::Value {
            if (count != 2 || !arguments[0].isString() ||
                !arguments[1].isNumber()) {
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "completeAfter requires a string and delay");
            }
            const double delay_value = arguments[1].asNumber();
            if (!std::isfinite(delay_value) || delay_value < 0 ||
                delay_value > 10'000 ||
                delay_value !=
                    static_cast<double>(static_cast<uint32_t>(delay_value))) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "completeAfter delay must be an "
                                           "integer from 0 through 10000");
            }
            const auto payload =
                arguments[0].asString(callback_runtime).utf8(callback_runtime);
            auto resolvers = std::make_shared<PromiseResolvers>();
            auto owner_witness = std::make_shared<OwnerCaptureWitness>(
                instance_ptr->owner_thread);
            const auto owner_thread = instance_ptr->owner_thread;
            auto promise = makePromise(callback_runtime, resolvers);
            auto token = context.makeCompletionToken(
                lease, "delayed",
                [resolvers, owner_witness,
                 owner_thread](facebook::jsi::Runtime &owner_runtime,
                               const std::vector<uint8_t> &bytes) {
                  (void)owner_witness;
                  if (std::this_thread::get_id() != owner_thread) {
                    g_ownerDeliveryMismatchCount.fetch_add(
                        1, std::memory_order_relaxed);
                  }
                  resolvers->resolve->call(
                      owner_runtime,
                      facebook::jsi::String::createFromUtf8(
                          owner_runtime, bytes.data(), bytes.size()));
                });
            if (!token) {
              throw facebook::jsi::JSError(
                  callback_runtime, "delayed completion token unavailable");
            }
            const auto delay =
                std::chrono::milliseconds(static_cast<uint32_t>(delay_value));
            std::thread([token = std::move(token), payload, delay]() mutable {
              std::this_thread::sleep_for(delay);
              recordPost(
                  token.post(reinterpret_cast<const uint8_t *>(payload.data()),
                             payload.size()));
            }).detach();
            return promise;
          }));

  api.setProperty(
      runtime, "subscribe",
      context.makeEffectfulHostFunction(
          "subscribe", "subscribe", 1,
          [&context, instance_ptr = instance.get()](
              facebook::jsi::Runtime &callback_runtime,
              ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
              const facebook::jsi::Value *arguments,
              size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isObject() ||
                !arguments[0]
                     .asObject(callback_runtime)
                     .isFunction(callback_runtime)) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "subscribe requires one function");
            }
            auto listener = std::make_shared<facebook::jsi::Function>(
                arguments[0]
                    .asObject(callback_runtime)
                    .asFunction(callback_runtime));
            auto owner_witness = std::make_shared<OwnerCaptureWitness>(
                instance_ptr->owner_thread);
            const auto owner_thread = instance_ptr->owner_thread;
            auto next_token = context.makeCompletionToken(
                lease, "event",
                [listener, owner_witness,
                 owner_thread](facebook::jsi::Runtime &owner_runtime,
                               const std::vector<uint8_t> &bytes) {
                  (void)owner_witness;
                  if (std::this_thread::get_id() != owner_thread) {
                    g_ownerDeliveryMismatchCount.fetch_add(
                        1, std::memory_order_relaxed);
                  }
                  listener->call(
                      owner_runtime,
                      facebook::jsi::String::createFromUtf8(
                          owner_runtime, bytes.data(), bytes.size()));
                },
                ext::CompletionMode::Repeating);
            if (!next_token) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "event token unavailable");
            }
            if (g_retireNextSubscriptionOffOwner.exchange(
                    false, std::memory_order_acq_rel)) {
              std::thread([token = std::move(next_token)]() mutable {
                const auto delay = g_offOwnerRetireDelayMs.load(
                    std::memory_order_acquire);
                if (delay != 0) {
                  std::this_thread::sleep_for(
                      std::chrono::milliseconds(delay));
                }
                token = {};
                g_offOwnerTokenRetiredCount.fetch_add(
                    1, std::memory_order_release);
              }).detach();
              return facebook::jsi::Value::undefined();
            }
            // Keep one extra public copy alive while assigning the retained
            // subscription. Dropping this copy must not retire the shared
            // callback slot; replacing the retained last copy must.
            auto copy = next_token;
            instance_ptr->event_token = std::move(next_token);
            if (!copy) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "copied event token became stale");
            }
            instance_ptr->has_event_token = true;
            return facebook::jsi::Value::undefined();
          }));

  api.setProperty(
      runtime, "emit",
      context.makeEffectfulHostFunction(
          "emit", "emit", 1,
          [instance_ptr = instance.get()](
              facebook::jsi::Runtime &callback_runtime, ext::OperationLeaseV1 &,
              const facebook::jsi::Value &,
              const facebook::jsi::Value *arguments,
              size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isString() ||
                !instance_ptr->event_token) {
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "emit requires one string and an active subscription");
            }
            const auto payload =
                arguments[0].asString(callback_runtime).utf8(callback_runtime);
            auto token = instance_ptr->event_token;
            std::thread([token = std::move(token), payload]() mutable {
              std::this_thread::sleep_for(std::chrono::milliseconds(2));
              recordPost(
                  token.post(reinterpret_cast<const uint8_t *>(payload.data()),
                             payload.size()));
            }).detach();
            return facebook::jsi::Value::undefined();
          }));

  api.setProperty(
      runtime, "copyBuffer",
      context.makeEffectfulHostFunction(
          "copy-buffer", "copyBuffer", 1,
          [&context](facebook::jsi::Runtime &callback_runtime,
                     ext::OperationLeaseV1 &, const facebook::jsi::Value &,
                     const facebook::jsi::Value *arguments,
                     size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isString()) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "copyBuffer requires one string");
            }
            const auto input =
                arguments[0].asString(callback_runtime).utf8(callback_runtime);
            auto copied = context.copyBytes(
                reinterpret_cast<const uint8_t *>(input.data()), input.size());
            auto buffer = std::make_shared<VectorBuffer>(std::move(copied));
            facebook::jsi::ArrayBuffer array_buffer(callback_runtime,
                                                    std::move(buffer));
            return callback_runtime.global()
                .getPropertyAsFunction(callback_runtime, "Uint8Array")
                .callAsConstructor(callback_runtime, array_buffer)
                .getObject(callback_runtime);
          }));

#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
  api.setProperty(
      runtime, "externalRange",
      context.makeEffectfulHostFunction(
          "external-range", "externalRange", 4,
          [&context](facebook::jsi::Runtime &callback_runtime,
                     ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
                     const facebook::jsi::Value *arguments,
                     size_t count) -> facebook::jsi::Value {
            if (count != 4 || !arguments[0].isObject() ||
                !arguments[0]
                     .asObject(callback_runtime)
                     .isArrayBuffer(callback_runtime) ||
                !arguments[1].isNumber() || !arguments[2].isNumber() ||
                !arguments[3].isNumber()) {
              throw facebook::jsi::JSError(
                  callback_runtime, "externalRange requires ArrayBuffer, "
                                    "offset, length, and key");
            }
            auto checked_size = [&](double value, const char *label) -> size_t {
              if (!std::isfinite(value) || value < 0 ||
                  value > 9'007'199'254'740'991.0 ||
                  value >
                      static_cast<double>(std::numeric_limits<size_t>::max()) ||
                  value != static_cast<double>(static_cast<size_t>(value))) {
                throw facebook::jsi::JSError(
                    callback_runtime,
                    std::string(label) + " must be a nonnegative integer");
              }
              return static_cast<size_t>(value);
            };
            const auto offset = checked_size(arguments[1].asNumber(), "offset");
            const auto length = checked_size(arguments[2].asNumber(), "length");
            const auto key_value = arguments[3].asNumber();
            if (!std::isfinite(key_value) || key_value < 1 ||
                key_value > 9'007'199'254'740'991.0 ||
                key_value !=
                    static_cast<double>(static_cast<uint64_t>(key_value))) {
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "externalRange key must be a positive safe integer");
            }
            auto source = arguments[0]
                              .asObject(callback_runtime)
                              .getArrayBuffer(callback_runtime);
            auto alias = context.createKeyedExternalRange(
                lease, source, offset, length,
                static_cast<uint64_t>(key_value));
            return facebook::jsi::Value(std::move(alias));
          }));

  api.setProperty(
      runtime, "revokeExternal",
      context.makeEffectfulHostFunction(
          "revoke-external", "revokeExternal", 1,
          [&context](facebook::jsi::Runtime &callback_runtime,
                     ext::OperationLeaseV1 &lease, const facebook::jsi::Value &,
                     const facebook::jsi::Value *arguments,
                     size_t count) -> facebook::jsi::Value {
            if (count != 1 || !arguments[0].isNumber()) {
              throw facebook::jsi::JSError(callback_runtime,
                                           "revokeExternal requires one key");
            }
            const auto key_value = arguments[0].asNumber();
            if (!std::isfinite(key_value) || key_value < 1 ||
                key_value > 9'007'199'254'740'991.0 ||
                key_value !=
                    static_cast<double>(static_cast<uint64_t>(key_value))) {
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "revokeExternal key must be a positive safe integer");
            }
            return facebook::jsi::Value(context.revokeKeyedExternalKey(
                lease, static_cast<uint64_t>(key_value)));
          }));
#endif

  auto module_exports = facebook::jsi::Value(runtime, api);
  context.defineModule("@ibex/conformance", std::move(module_exports));
  context.defineGlobal("__ibexRuntimeExtensionFixture", std::move(api), false,
                       false);
  *output = instance.release();
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installFailure(void *, void **) {
  return IBEX_RUNTIME_EXTENSION_INSTALL_FAILED;
}

int32_t installBootstrapInjectionWitness(void *, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installUndeclaredGlobal(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &context = ext::InstallContextV1::fromOpaque(opaque_context);
  context.defineGlobal("__ibexUndeclaredRuntimeExtensionFixture",
                       facebook::jsi::Object(context.runtime()), false, false);
  *output = nullptr;
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installUndeclaredEffect(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &context = ext::InstallContextV1::fromOpaque(opaque_context);
  (void)context.makeEffectfulHostFunction(
      "not-declared", "notDeclared", 0,
      [](facebook::jsi::Runtime &, ext::OperationLeaseV1 &,
         const facebook::jsi::Value &, const facebook::jsi::Value *,
         size_t) { return facebook::jsi::Value::undefined(); });
  *output = nullptr;
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installNestedMutation(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &runtime = ext::InstallContextV1::fromOpaque(opaque_context).runtime();
  runtime.global()
      .getPropertyAsObject(runtime, "Math")
      .setProperty(runtime, "__ibexUndeclaredNestedMutation",
                   facebook::jsi::Object(runtime));
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installPrototypeMutation(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &runtime = ext::InstallContextV1::fromOpaque(opaque_context).runtime();
  runtime.global()
      .getPropertyAsObject(runtime, "Math")
      .setPrototype(runtime, facebook::jsi::Value::null());
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installReflectionReplacement(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &runtime = ext::InstallContextV1::fromOpaque(opaque_context).runtime();
  auto object = runtime.global().getPropertyAsObject(runtime, "Object");
  auto original = std::make_shared<facebook::jsi::Function>(
      object.getPropertyAsFunction(runtime, "getOwnPropertyDescriptor"));
  object.setProperty(runtime, "getOwnPropertyDescriptor",
                     facebook::jsi::Function::createFromHostFunction(
                         runtime,
                         facebook::jsi::PropNameID::forAscii(
                             runtime, "replacementGetOwnPropertyDescriptor"),
                         2,
                         [original](facebook::jsi::Runtime &callback_runtime,
                                    const facebook::jsi::Value &,
                                    const facebook::jsi::Value *arguments,
                                    size_t count) -> facebook::jsi::Value {
                           return original->call(callback_runtime, arguments,
                                                 count);
                         }));
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installDeclaredNested(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &runtime = ext::InstallContextV1::fromOpaque(opaque_context).runtime();
  auto nested = facebook::jsi::Object(runtime);
  nested.setProperty(runtime, "marker", 393.0);
  runtime.global()
      .getPropertyAsObject(runtime, "Object")
      .setProperty(runtime, "__ibexDeclaredNestedFixture", std::move(nested));
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

int32_t installModuleEntry(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &context = ext::InstallContextV1::fromOpaque(opaque_context);
  auto &runtime = context.runtime();
  auto exports = facebook::jsi::Object(runtime);
  exports.setProperty(runtime, "fixtureModuleExport", 1.0);
  context.defineModule("@ibex/conformance", std::move(exports));
  *output = nullptr;
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

void quiesceFixture(void *, void *opaque_instance) {
  g_quiesceCount.fetch_add(1, std::memory_order_relaxed);
  auto *instance = static_cast<FixtureInstance *>(opaque_instance);
  if (instance != nullptr && instance->has_event_token) {
    constexpr uint8_t kTeardownPayload[] = {'t', 'e', 'a', 'r',
                                            'd', 'o', 'w', 'n'};
    const auto result =
        instance->event_token.post(kTeardownPayload, sizeof(kTeardownPayload));
    recordPost(result);
    // The runtime registry may close producer admission before extension
    // quiesce runs, so either StaleGeneration or Quiescing is the expected
    // fail-closed result. Acceptance is the forbidden outcome.
    if (result != ext::ScheduleResult::Accepted) {
      g_teardownScheduleRejectedCount.fetch_add(1, std::memory_order_relaxed);
    }
  }
}

int32_t checkpointFixture(void *, void *) { return IBEX_RUNTIME_EXTENSION_OK; }

void closeFixture(void *, void *instance) {
  delete static_cast<FixtureInstance *>(instance);
  g_closeCount.fetch_add(1, std::memory_order_relaxed);
  recordClose(1);
}

void closeFailure(void *, void *) {
  g_closeCount.fetch_add(1, std::memory_order_relaxed);
  recordClose(3);
}

int32_t installSecondary(void *opaque_context, void **output) {
  if (!output)
    return IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT;
  auto &context = ext::InstallContextV1::fromOpaque(opaque_context);
  const auto *provider = context.provider();
  if (provider == nullptr || g_primaryProviderView == nullptr ||
      provider == g_primaryProviderView || provider->extension_id == nullptr ||
      std::string(provider->extension_id) != "ibex.conformance.secondary" ||
      provider->context != &g_secondaryProviderContext ||
      g_primaryProviderView->extension_id == nullptr ||
      std::string(g_primaryProviderView->extension_id) != "ibex.conformance" ||
      g_primaryProviderView->context != &g_fixtureProviderContext) {
    return IBEX_RUNTIME_EXTENSION_AUTHENTICATION_FAILED;
  }
  g_providerViewStableCount.fetch_add(1, std::memory_order_relaxed);
  *output = new uint64_t(2);
  g_installCount.fetch_add(1, std::memory_order_relaxed);
  return IBEX_RUNTIME_EXTENSION_OK;
}

void closeSecondary(void *, void *instance) {
  delete static_cast<uint64_t *>(instance);
  g_closeCount.fetch_add(1, std::memory_order_relaxed);
  recordClose(2);
}

constexpr IbexRuntimeExtensionGlobalV1 kGlobals[] = {
    {
        sizeof(IbexRuntimeExtensionGlobalV1),
        "__ibexRuntimeExtensionFixture",
        IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT,
    },
};

constexpr IbexRuntimeExtensionGlobalV1 kOverlappingGlobals[] = {
    {
        sizeof(IbexRuntimeExtensionGlobalV1),
        "__ibexRuntimeExtensionFixture.child",
        IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT,
    },
};

constexpr IbexRuntimeExtensionGlobalV1 kDeclaredNestedGlobals[] = {
    {
        sizeof(IbexRuntimeExtensionGlobalV1),
        "Object.__ibexDeclaredNestedFixture",
        IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT,
    },
};

constexpr const char *kOperationResourceKinds[] = {
    "runtime-extension",
};

#define IBEX_CONFORMANCE_OPERATION(operation_id, authority, entry_path)        \
  {sizeof(IbexRuntimeExtensionOperationV1),                                    \
   operation_id,                                                               \
   authority,                                                                  \
   "runtime-extension.invoke.authenticated-v1",                                \
   "requested",                                                                \
   "fixture.operation.decision",                                               \
   kOperationResourceKinds,                                                    \
   sizeof(kOperationResourceKinds) / sizeof(kOperationResourceKinds[0]),       \
   entry_path,                                                                 \
   0}

constexpr IbexRuntimeExtensionOperationV1 kOperations[] = {
    IBEX_CONFORMANCE_OPERATION("complete", "fixture.complete",
                               "__ibexRuntimeExtensionFixture.complete"),
    IBEX_CONFORMANCE_OPERATION("complete-after", "fixture.complete-after",
                               "__ibexRuntimeExtensionFixture.completeAfter"),
    IBEX_CONFORMANCE_OPERATION("copy-buffer", "fixture.copy-buffer",
                               "__ibexRuntimeExtensionFixture.copyBuffer"),
    IBEX_CONFORMANCE_OPERATION("emit", "fixture.emit",
                               "__ibexRuntimeExtensionFixture.emit"),
    IBEX_CONFORMANCE_OPERATION("enqueue", "fixture.enqueue",
                               "__ibexRuntimeExtensionFixture.enqueue"),
#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
    IBEX_CONFORMANCE_OPERATION("external-range", "fixture.external-range",
                               "__ibexRuntimeExtensionFixture.externalRange"),
#endif
    IBEX_CONFORMANCE_OPERATION(
        "retire-lease", "fixture.retire-lease",
        "__ibexRuntimeExtensionFixture.retireLeaseOffOwner"),
#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
    IBEX_CONFORMANCE_OPERATION("revoke-external", "fixture.revoke-external",
                               "__ibexRuntimeExtensionFixture.revokeExternal"),
#endif
    IBEX_CONFORMANCE_OPERATION("subscribe", "fixture.subscribe",
                               "__ibexRuntimeExtensionFixture.subscribe"),
};

constexpr IbexRuntimeExtensionOperationV1 kDeclaredModuleEntryOperations[] = {
    IBEX_CONFORMANCE_OPERATION("module-export", "fixture.module-export",
                               "@ibex/conformance#fixtureModuleExport"),
};

constexpr IbexRuntimeExtensionOperationV1 kUndeclaredModuleEntryOperations[] = {
    IBEX_CONFORMANCE_OPERATION("module-export", "fixture.module-export",
                               "undeclared/module#fixtureModuleExport"),
};

constexpr IbexRuntimeExtensionOperationV1 kMalformedModuleEntryOperations[] = {
    IBEX_CONFORMANCE_OPERATION("module-export", "fixture.module-export",
                               "@ibex/conformance#fixture..moduleExport"),
};

#undef IBEX_CONFORMANCE_OPERATION

constexpr IbexRuntimeExtensionCallbackV1 kCallbacks[] = {
    {
        sizeof(IbexRuntimeExtensionCallbackV1),
        "delayed",
        "complete-after",
        IBEX_RUNTIME_EXTENSION_CALLBACK_BACKGROUND_PRODUCER,
        IBEX_RUNTIME_EXTENSION_CALLBACK_DELIVERY_RUNTIME_OWNER,
        8,
    },
    {
        sizeof(IbexRuntimeExtensionCallbackV1),
        "event",
        "subscribe",
        IBEX_RUNTIME_EXTENSION_CALLBACK_BACKGROUND_PRODUCER,
        IBEX_RUNTIME_EXTENSION_CALLBACK_DELIVERY_RUNTIME_OWNER,
        8,
    },
    {
        sizeof(IbexRuntimeExtensionCallbackV1),
        "promise",
        "complete",
        IBEX_RUNTIME_EXTENSION_CALLBACK_BACKGROUND_PRODUCER,
        IBEX_RUNTIME_EXTENSION_CALLBACK_DELIVERY_RUNTIME_OWNER,
        8,
    },
};

constexpr const char *kModules[] = {
    "@ibex/conformance",
};

constexpr const char *kReservedSeparatorModules[] = {
    "@ibex/conformance#fixture",
};

constexpr const char *kInvalidGrammarModules[] = {
    "bad module",
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installFixture,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kFailureLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installFailure,
    checkpointFixture,
    quiesceFixture,
    closeFailure,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1
    kBootstrapInjectionWitnessLifecycle = {
        sizeof(IbexRuntimeExtensionLifecycleVTableV1),
        installBootstrapInjectionWitness,
        checkpointFixture,
        quiesceFixture,
        closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kUndeclaredGlobalLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installUndeclaredGlobal,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kUndeclaredEffectLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installUndeclaredEffect,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kNestedMutationLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installNestedMutation,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kPrototypeMutationLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installPrototypeMutation,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1
    kReflectionReplacementLifecycle = {
        sizeof(IbexRuntimeExtensionLifecycleVTableV1),
        installReflectionReplacement,
        checkpointFixture,
        quiesceFixture,
        closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kDeclaredNestedLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installDeclaredNested,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kModuleEntryLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installModuleEntry,
    checkpointFixture,
    quiesceFixture,
    closeFixture,
};

constexpr IbexRuntimeExtensionLifecycleVTableV1 kSecondaryLifecycle = {
    sizeof(IbexRuntimeExtensionLifecycleVTableV1),
    installSecondary,
    checkpointFixture,
    quiesceFixture,
    closeSecondary,
};

constexpr uint64_t kFixtureRequiredFeatures =
    IBEX_RUNTIME_EXTENSION_FEATURE_OWNER_EXECUTOR |
    IBEX_RUNTIME_EXTENSION_FEATURE_OPERATION_MEMBRANE |
    IBEX_RUNTIME_EXTENSION_FEATURE_COPIED_BUFFERS |
    IBEX_RUNTIME_EXTENSION_FEATURE_NATIVE_MODULES |
    IBEX_RUNTIME_EXTENSION_FEATURE_INTROSPECTION
#if defined(IBEX_HAVE_KEYED_EXTERNAL_ARRAY_BUFFER)
    | IBEX_RUNTIME_EXTENSION_FEATURE_KEYED_EXTERNAL_BUFFERS
#endif
    ;

constexpr IbexRuntimeExtensionDescriptorV1 kDescriptor = {
    sizeof(IbexRuntimeExtensionDescriptorV1),
    IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
    "ibex.conformance",
    "1",
    kManifestDigest,
    kCapsuleDigest,
    IBEX_RUNTIME_EXTENSION_REALM_MAIN,
    IBEX_RUNTIME_EXTENSION_INSTALL_BEFORE_USER_CODE,
    kFixtureRequiredFeatures,
    kProviderAbiId,
    1,
    sizeof(FixtureProviderVTableV1),
    kGlobals,
    sizeof(kGlobals) / sizeof(kGlobals[0]),
    kModules,
    sizeof(kModules) / sizeof(kModules[0]),
    nullptr,
    0,
    kOperations,
    sizeof(kOperations) / sizeof(kOperations[0]),
    kCallbacks,
    sizeof(kCallbacks) / sizeof(kCallbacks[0]),
    &kLifecycle,
};

constexpr IbexRuntimeExtensionDescriptorV1
makeBareDescriptor(const char *id, uint32_t sdk_version,
                   const IbexRuntimeExtensionGlobalV1 *globals,
                   size_t global_count,
                   const IbexRuntimeExtensionLifecycleVTableV1 *lifecycle) {
  return {
      sizeof(IbexRuntimeExtensionDescriptorV1),
      sdk_version,
      id,
      "1",
      kManifestDigest,
      kCapsuleDigest,
      IBEX_RUNTIME_EXTENSION_REALM_MAIN,
      IBEX_RUNTIME_EXTENSION_INSTALL_BEFORE_USER_CODE,
      IBEX_RUNTIME_EXTENSION_FEATURE_OWNER_EXECUTOR,
      nullptr,
      0,
      0,
      globals,
      global_count,
      nullptr,
      0,
      nullptr,
      0,
      nullptr,
      0,
      nullptr,
      0,
      lifecycle,
  };
}

constexpr IbexRuntimeExtensionDescriptorV1 kFailureDescriptor =
    makeBareDescriptor("ibex.conformance.failure",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kFailureLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 makeModuleEntryDescriptor(
    const char *id, const IbexRuntimeExtensionOperationV1 *operations) {
  auto descriptor =
      makeBareDescriptor(id, IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                         &kModuleEntryLifecycle);
  descriptor.required_features =
      IBEX_RUNTIME_EXTENSION_FEATURE_OWNER_EXECUTOR |
      IBEX_RUNTIME_EXTENSION_FEATURE_OPERATION_MEMBRANE |
      IBEX_RUNTIME_EXTENSION_FEATURE_NATIVE_MODULES |
      IBEX_RUNTIME_EXTENSION_FEATURE_INTROSPECTION;
  descriptor.module_specifiers = kModules;
  descriptor.module_specifier_count = sizeof(kModules) / sizeof(kModules[0]);
  descriptor.operations = operations;
  descriptor.operation_count = 1;
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1 kDeclaredModuleEntryDescriptor =
    makeModuleEntryDescriptor("ibex.conformance.module-entry",
                              kDeclaredModuleEntryOperations);

constexpr IbexRuntimeExtensionDescriptorV1 kUndeclaredModuleEntryDescriptor =
    makeModuleEntryDescriptor("ibex.conformance.undeclared-module-entry",
                              kUndeclaredModuleEntryOperations);

constexpr IbexRuntimeExtensionDescriptorV1 kMalformedModuleEntryDescriptor =
    makeModuleEntryDescriptor("ibex.conformance.malformed-module-entry",
                              kMalformedModuleEntryOperations);

constexpr IbexRuntimeExtensionDescriptorV1
makeReservedModuleSeparatorDescriptor() {
  auto descriptor = makeModuleEntryDescriptor(
      "ibex.conformance.reserved-module-separator",
      kDeclaredModuleEntryOperations);
  descriptor.module_specifiers = kReservedSeparatorModules;
  descriptor.module_specifier_count =
      sizeof(kReservedSeparatorModules) / sizeof(kReservedSeparatorModules[0]);
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1
    kReservedModuleSeparatorDescriptor =
        makeReservedModuleSeparatorDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1
makeInvalidModuleGrammarDescriptor() {
  auto descriptor = makeModuleEntryDescriptor(
      "ibex.conformance.invalid-module-grammar",
      kDeclaredModuleEntryOperations);
  descriptor.module_specifiers = kInvalidGrammarModules;
  descriptor.module_specifier_count =
      sizeof(kInvalidGrammarModules) / sizeof(kInvalidGrammarModules[0]);
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1 kInvalidModuleGrammarDescriptor =
    makeInvalidModuleGrammarDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1 kOverlapDescriptor =
    makeBareDescriptor(
        "ibex.conformance.overlap", IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
        kOverlappingGlobals,
        sizeof(kOverlappingGlobals) / sizeof(kOverlappingGlobals[0]),
        &kFailureLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kAbiMismatchDescriptor =
    makeBareDescriptor("ibex.conformance.abi-mismatch",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1 + 1, nullptr, 0,
                       &kFailureLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kUndeclaredGlobalDescriptor =
    makeBareDescriptor("ibex.conformance.undeclared-global",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kUndeclaredGlobalLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kUndeclaredEffectDescriptor =
    makeBareDescriptor("ibex.conformance.undeclared-effect",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kUndeclaredEffectLifecycle);

const IbexRuntimeExtensionBootstrapV1 kUndeclaredModuleBootstraps[] = {
    {
        sizeof(IbexRuntimeExtensionBootstrapV1),
        "undeclared-module-injection",
        IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SOURCE,
        IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SCRIPT_GLOBAL,
        kUndeclaredModuleBootstrapDigest,
        "<runtime-extension-undeclared-module-bootstrap>",
        reinterpret_cast<const uint8_t *>(kUndeclaredModuleBootstrapSource),
        sizeof(kUndeclaredModuleBootstrapSource) - 1,
    },
};

IbexRuntimeExtensionDescriptorV1
makeUndeclaredModuleBootstrapDescriptor() {
  auto descriptor = makeBareDescriptor(
      "ibex.conformance.undeclared-bootstrap-module",
      IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
      &kBootstrapInjectionWitnessLifecycle);
  descriptor.bootstraps = kUndeclaredModuleBootstraps;
  descriptor.bootstrap_count =
      sizeof(kUndeclaredModuleBootstraps) /
      sizeof(kUndeclaredModuleBootstraps[0]);
  return descriptor;
}

const IbexRuntimeExtensionDescriptorV1
    kUndeclaredModuleBootstrapDescriptor =
        makeUndeclaredModuleBootstrapDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1 kNestedMutationDescriptor =
    makeBareDescriptor("ibex.conformance.nested-mutation",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kNestedMutationLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kPrototypeMutationDescriptor =
    makeBareDescriptor("ibex.conformance.prototype-mutation",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kPrototypeMutationLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kReflectionReplacementDescriptor =
    makeBareDescriptor("ibex.conformance.reflection-replacement",
                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, nullptr, 0,
                       &kReflectionReplacementLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 kDeclaredNestedDescriptor =
    makeBareDescriptor(
        "ibex.conformance.declared-nested",
        IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1, kDeclaredNestedGlobals,
        sizeof(kDeclaredNestedGlobals) / sizeof(kDeclaredNestedGlobals[0]),
        &kDeclaredNestedLifecycle);

constexpr IbexRuntimeExtensionDescriptorV1 makeSecondaryDescriptor() {
  auto descriptor = makeBareDescriptor("ibex.conformance.secondary",
                                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
                                       nullptr, 0, &kSecondaryLifecycle);
  descriptor.provider_abi_id = kProviderAbiId;
  descriptor.provider_abi_min_version = 1;
  descriptor.provider_struct_size = sizeof(FixtureProviderVTableV1);
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1 kSecondaryDescriptor =
    makeSecondaryDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1 makeUnsupportedFeatureDescriptor() {
  auto descriptor = makeBareDescriptor("ibex.conformance.unsupported-feature",
                                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
                                       nullptr, 0, &kFailureLifecycle);
  descriptor.required_features = UINT64_C(1) << 63;
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1 kUnsupportedFeatureDescriptor =
    makeUnsupportedFeatureDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1 makeProviderMismatchDescriptor() {
  auto descriptor = makeBareDescriptor("ibex.conformance.provider-mismatch",
                                       IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
                                       nullptr, 0, &kFailureLifecycle);
  descriptor.provider_abi_id = "ibex.conformance.provider";
  descriptor.provider_abi_min_version = 1;
  descriptor.provider_struct_size = sizeof(uint64_t);
  return descriptor;
}

constexpr IbexRuntimeExtensionDescriptorV1 kProviderMismatchDescriptor =
    makeProviderMismatchDescriptor();

constexpr IbexRuntimeExtensionDescriptorV1 kDuplicateIdDescriptors[] = {
    kDescriptor,
    kDescriptor,
};

constexpr IbexRuntimeExtensionDescriptorV1 kOverlappingGlobalDescriptors[] = {
    kDescriptor,
    kOverlapDescriptor,
};

constexpr IbexRuntimeExtensionDescriptorV1 kFailingDescriptors[] = {
    kDescriptor,
    kFailureDescriptor,
};

constexpr IbexRuntimeExtensionDescriptorV1 kSuccessfulDescriptors[] = {
    kDescriptor,
    kSecondaryDescriptor,
};

constexpr IbexRuntimeExtensionProviderBindingV1 kSuccessfulProviderBindings[] =
    {
        kFixtureProviderBinding,
        kSecondaryProviderBinding,
};

constexpr IbexRuntimeExtensionRegistryV1 kRegistry = {
    sizeof(IbexRuntimeExtensionRegistryV1),
    IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
    kSetDigest,
    kCapsuleDigest,
    kSelectionDigest,
    &kDescriptor,
    1,
    &kFixtureProviderBinding,
    1,
};

constexpr IbexRuntimeExtensionRegistryV1 kFailingRegistry = {
    sizeof(IbexRuntimeExtensionRegistryV1),
    IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
    kSetDigest,
    kCapsuleDigest,
    kSelectionDigest,
    kFailingDescriptors,
    sizeof(kFailingDescriptors) / sizeof(kFailingDescriptors[0]),
    &kFixtureProviderBinding,
    1,
};

constexpr IbexRuntimeExtensionRegistryV1
makeRegistry(const IbexRuntimeExtensionDescriptorV1 *descriptors,
             size_t descriptor_count) {
  return {
      sizeof(IbexRuntimeExtensionRegistryV1),
      IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
      kSetDigest,
      kCapsuleDigest,
      kSelectionDigest,
      descriptors,
      descriptor_count,
      nullptr,
      0,
  };
}

constexpr IbexRuntimeExtensionRegistryV1
makeFixtureRegistry(const IbexRuntimeExtensionDescriptorV1 *descriptors,
                    size_t descriptor_count) {
  auto registry = makeRegistry(descriptors, descriptor_count);
  registry.provider_bindings = &kFixtureProviderBinding;
  registry.provider_binding_count = 1;
  return registry;
}

constexpr IbexRuntimeExtensionRegistryV1 kDuplicateIdRegistry =
    makeFixtureRegistry(kDuplicateIdDescriptors,
                        sizeof(kDuplicateIdDescriptors) /
                            sizeof(kDuplicateIdDescriptors[0]));

constexpr IbexRuntimeExtensionRegistryV1 kOverlappingGlobalRegistry =
    makeFixtureRegistry(kOverlappingGlobalDescriptors,
                        sizeof(kOverlappingGlobalDescriptors) /
                            sizeof(kOverlappingGlobalDescriptors[0]));

constexpr IbexRuntimeExtensionRegistryV1 kAbiMismatchRegistry =
    makeRegistry(&kAbiMismatchDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kUndeclaredGlobalRegistry =
    makeRegistry(&kUndeclaredGlobalDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kUndeclaredEffectRegistry =
    makeRegistry(&kUndeclaredEffectDescriptor, 1);

const IbexRuntimeExtensionRegistryV1 kUndeclaredModuleBootstrapRegistry =
    makeRegistry(&kUndeclaredModuleBootstrapDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kNestedMutationRegistry =
    makeRegistry(&kNestedMutationDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kPrototypeMutationRegistry =
    makeRegistry(&kPrototypeMutationDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kReflectionReplacementRegistry =
    makeRegistry(&kReflectionReplacementDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kDeclaredNestedRegistry =
    makeRegistry(&kDeclaredNestedDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kMalformedDigestRegistry = {
    sizeof(IbexRuntimeExtensionRegistryV1),
    IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1,
    "not-a-digest",
    kCapsuleDigest,
    kSelectionDigest,
    &kDescriptor,
    1,
    &kFixtureProviderBinding,
    1,
};

constexpr IbexRuntimeExtensionRegistryV1 kUnsupportedFeatureRegistry =
    makeRegistry(&kUnsupportedFeatureDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kProviderMismatchRegistry =
    makeRegistry(&kProviderMismatchDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kDeclaredModuleEntryRegistry =
    makeRegistry(&kDeclaredModuleEntryDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kUndeclaredModuleEntryRegistry =
    makeRegistry(&kUndeclaredModuleEntryDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kMalformedModuleEntryRegistry =
    makeRegistry(&kMalformedModuleEntryDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kReservedModuleSeparatorRegistry =
    makeRegistry(&kReservedModuleSeparatorDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 kInvalidModuleGrammarRegistry =
    makeRegistry(&kInvalidModuleGrammarDescriptor, 1);

constexpr IbexRuntimeExtensionRegistryV1 makeSuccessfulRegistry() {
  auto registry = makeRegistry(kSuccessfulDescriptors,
                               sizeof(kSuccessfulDescriptors) /
                                   sizeof(kSuccessfulDescriptors[0]));
  registry.provider_bindings = kSuccessfulProviderBindings;
  registry.provider_binding_count = sizeof(kSuccessfulProviderBindings) /
                                    sizeof(kSuccessfulProviderBindings[0]);
  return registry;
}

constexpr IbexRuntimeExtensionRegistryV1 kSuccessfulRegistry =
    makeSuccessfulRegistry();

const IbexRuntimeExtensionRegistryV1 *bindFixtureRegistry(
    const char *extension_set_digest, const char *authority_capsule_digest,
    const char *executable_selection_identity,
    bool mismatch_descriptor_capsule_digest) {
  if (extension_set_digest == nullptr || authority_capsule_digest == nullptr ||
      executable_selection_identity == nullptr) {
    return nullptr;
  }
  static thread_local std::string bound_set_digest;
  static thread_local std::string bound_capsule_digest;
  static thread_local std::string bound_selection_identity;
  static thread_local std::vector<IbexRuntimeExtensionDescriptorV1>
      bound_descriptors;
  static thread_local IbexRuntimeExtensionRegistryV1 bound_registry;
  bound_set_digest = extension_set_digest;
  bound_capsule_digest = authority_capsule_digest;
  bound_selection_identity = executable_selection_identity;
  bound_descriptors.assign(kRegistry.descriptors,
                           kRegistry.descriptors + kRegistry.descriptor_count);
  for (auto &descriptor : bound_descriptors) {
    const char *mismatched_digest =
        std::strcmp(authority_capsule_digest, kManifestDigest) == 0
            ? kSetDigest
            : kManifestDigest;
    descriptor.authority_capsule_digest = mismatch_descriptor_capsule_digest
                                              ? mismatched_digest
                                              : bound_capsule_digest.c_str();
  }
  bound_registry = kRegistry;
  bound_registry.extension_set_digest = bound_set_digest.c_str();
  bound_registry.authority_capsule_digest = bound_capsule_digest.c_str();
  bound_registry.executable_selection_identity =
      bound_selection_identity.c_str();
  bound_registry.descriptors = bound_descriptors.data();
  return &bound_registry;
}

} // namespace

extern "C" const IbexRuntimeExtensionRegistryV1 *
ibex_runtime_extension_conformance_registry_v1() {
  return &kRegistry;
}

extern "C" const IbexRuntimeExtensionRegistryV1 *
ibex_runtime_extension_conformance_failing_registry_v1() {
  return &kFailingRegistry;
}

extern "C" const IbexRuntimeExtensionRegistryV1 *
ibex_runtime_extension_conformance_bound_registry_v1(
    const char *extension_set_digest, const char *authority_capsule_digest,
    const char *executable_selection_identity) {
  return bindFixtureRegistry(extension_set_digest, authority_capsule_digest,
                             executable_selection_identity, false);
}

extern "C" const IbexRuntimeExtensionRegistryV1 *
ibex_runtime_extension_conformance_bound_registry_descriptor_digest_mismatch_v1(
    const char *extension_set_digest, const char *authority_capsule_digest,
    const char *executable_selection_identity) {
  return bindFixtureRegistry(extension_set_digest, authority_capsule_digest,
                             executable_selection_identity, true);
}

extern "C" const IbexRuntimeExtensionRegistryV1 *
ibex_runtime_extension_conformance_registry_variant_v1(uint32_t variant) {
  switch (variant) {
  case 1:
    return &kDuplicateIdRegistry;
  case 2:
    return &kOverlappingGlobalRegistry;
  case 3:
    return &kAbiMismatchRegistry;
  case 4:
    return &kUndeclaredGlobalRegistry;
  case 5:
    return &kUndeclaredEffectRegistry;
  case 6:
    return &kFailingRegistry;
  case 7:
    return &kMalformedDigestRegistry;
  case 8:
    return &kUnsupportedFeatureRegistry;
  case 9:
    return &kProviderMismatchRegistry;
  case 10:
    return &kSuccessfulRegistry;
  case 11:
    return &kNestedMutationRegistry;
  case 12:
    return &kPrototypeMutationRegistry;
  case 13:
    return &kReflectionReplacementRegistry;
  case 14:
    return &kDeclaredNestedRegistry;
  case 15:
    return &kUndeclaredModuleBootstrapRegistry;
  case 16:
    return &kDeclaredModuleEntryRegistry;
  case 17:
    return &kUndeclaredModuleEntryRegistry;
  case 18:
    return &kMalformedModuleEntryRegistry;
  case 19:
    return &kReservedModuleSeparatorRegistry;
  case 20:
    return &kInvalidModuleGrammarRegistry;
  default:
    return nullptr;
  }
}

extern "C" uint64_t
ibex_runtime_extension_conformance_counter_v1(uint32_t counter) {
  switch (counter) {
  case 0:
    return g_installCount.load(std::memory_order_relaxed);
  case 1:
    return g_quiesceCount.load(std::memory_order_relaxed);
  case 2:
    return g_closeCount.load(std::memory_order_relaxed);
  case 3:
    return g_enqueuedCount.load(std::memory_order_relaxed);
  case 4:
    return g_postAcceptedCount.load(std::memory_order_relaxed);
  case 5:
    return g_postRejectedCount.load(std::memory_order_relaxed);
  case 6:
    return g_ownerDeliveryMismatchCount.load(std::memory_order_relaxed);
  case 7:
    return g_ownerCaptureDestroyedCount.load(std::memory_order_relaxed);
  case 8:
    return g_ownerCaptureMismatchCount.load(std::memory_order_relaxed);
  case 9:
    return g_closeSequence.load(std::memory_order_relaxed);
  case 10:
    return g_teardownScheduleRejectedCount.load(std::memory_order_relaxed);
  case 11:
    return g_providerViewStableCount.load(std::memory_order_relaxed);
  case 12:
    return g_offOwnerTokenRetiredCount.load(std::memory_order_acquire);
  case 13:
    return static_cast<uint64_t>(
        g_lastPostResult.load(std::memory_order_acquire));
  case 14:
    return g_offOwnerLeaseRetiredCount.load(std::memory_order_acquire);
  default:
    return 0;
  }
}

extern "C" void
ibex_runtime_extension_conformance_hold_next_accepted_post_v1() {
  ibex::runtime_extension::internal::armAcceptedPostReturnHoldForTest(true);
}

extern "C" int32_t
ibex_runtime_extension_conformance_accepted_post_is_held_v1() {
  return ibex::runtime_extension::internal::acceptedPostReturnHeldForTest()
             ? 1
             : 0;
}

extern "C" void ibex_runtime_extension_conformance_release_accepted_post_v1() {
  ibex::runtime_extension::internal::armAcceptedPostReturnHoldForTest(false);
}

extern "C" size_t ibex_runtime_extension_conformance_callback_slot_count_v1(
    ExactHermesRuntime *runtime) {
  return ibex::runtime_extension::internal::callbackSlotCountForTest(runtime);
}

extern "C" size_t
ibex_runtime_extension_conformance_operation_lease_slot_count_v1(
    ExactHermesRuntime *runtime) {
  return ibex::runtime_extension::internal::operationLeaseSlotCountForTest(
      runtime);
}

extern "C" void ibex_runtime_extension_conformance_reset_v1() {
  ibex::runtime_extension::internal::armAcceptedPostReturnHoldForTest(false);
  g_installCount.store(0, std::memory_order_relaxed);
  g_quiesceCount.store(0, std::memory_order_relaxed);
  g_closeCount.store(0, std::memory_order_relaxed);
  g_enqueuedCount.store(0, std::memory_order_relaxed);
  g_postAcceptedCount.store(0, std::memory_order_relaxed);
  g_postRejectedCount.store(0, std::memory_order_relaxed);
  g_ownerDeliveryMismatchCount.store(0, std::memory_order_relaxed);
  g_ownerCaptureDestroyedCount.store(0, std::memory_order_relaxed);
  g_ownerCaptureMismatchCount.store(0, std::memory_order_relaxed);
  g_closeSequence.store(0, std::memory_order_relaxed);
  g_teardownScheduleRejectedCount.store(0, std::memory_order_relaxed);
  g_providerViewStableCount.store(0, std::memory_order_relaxed);
  g_offOwnerTokenRetiredCount.store(0, std::memory_order_relaxed);
  g_offOwnerLeaseRetiredCount.store(0, std::memory_order_relaxed);
  g_lastPostResult.store(static_cast<int32_t>(ext::ScheduleResult::Invalid),
                         std::memory_order_relaxed);
  g_offOwnerRetireDelayMs.store(0, std::memory_order_relaxed);
  g_retireNextSubscriptionOffOwner.store(false, std::memory_order_relaxed);
  g_holdNextOperationLeaseRetirement.store(false,
                                           std::memory_order_relaxed);
  g_operationLeaseRetirementHeld.store(false, std::memory_order_relaxed);
  g_releaseOperationLeaseRetirement.store(true, std::memory_order_relaxed);
  g_primaryProviderView = nullptr;
}

extern "C" void
ibex_runtime_extension_conformance_retire_next_subscription_off_owner_v1() {
  g_retireNextSubscriptionOffOwner.store(true, std::memory_order_release);
}

extern "C" void
ibex_runtime_extension_conformance_set_off_owner_retire_delay_v1(
    uint32_t delay_ms) {
  g_offOwnerRetireDelayMs.store(delay_ms, std::memory_order_release);
}

extern "C" void
ibex_runtime_extension_conformance_hold_next_operation_lease_retirement_v1() {
  g_operationLeaseRetirementHeld.store(false, std::memory_order_release);
  g_releaseOperationLeaseRetirement.store(false, std::memory_order_release);
  g_holdNextOperationLeaseRetirement.store(true, std::memory_order_release);
}

extern "C" int32_t
ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() {
  return g_operationLeaseRetirementHeld.load(std::memory_order_acquire) ? 1
                                                                        : 0;
}

extern "C" void
ibex_runtime_extension_conformance_release_operation_lease_retirement_v1() {
  g_releaseOperationLeaseRetirement.store(true, std::memory_order_release);
}
