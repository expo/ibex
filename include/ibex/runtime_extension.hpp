/*
 * ibex/runtime_extension.hpp
 *
 * C++17 authoring facade for the source-linked runtime-extension ABI.
 *
 * @ref LLP 0040
 */

#ifndef IBEX_RUNTIME_EXTENSION_HPP
#define IBEX_RUNTIME_EXTENSION_HPP

#include "../ibex_runtime_extension.h"

#include <jsi/jsi.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ibex::runtime_extension::v1 {

using RuntimeExtensionOperationV1 = ::IbexRuntimeExtensionOperationV1;
using RuntimeExtensionCallbackV1 = ::IbexRuntimeExtensionCallbackV1;
using RuntimeExtensionBootstrapV1 = ::IbexRuntimeExtensionBootstrapV1;
using RuntimeExtensionGlobalV1 = ::IbexRuntimeExtensionGlobalV1;
using RuntimeExtensionProviderBindingV1 =
    ::IbexRuntimeExtensionProviderBindingV1;
using RuntimeExtensionLifecycleVTableV1 =
    ::IbexRuntimeExtensionLifecycleVTableV1;
using RuntimeExtensionDescriptorV1 = ::IbexRuntimeExtensionDescriptorV1;
using RuntimeExtensionRegistryV1 = ::IbexRuntimeExtensionRegistryV1;

enum class ScheduleResult : int32_t {
  Accepted = IBEX_RUNTIME_EXTENSION_OK,
  StaleAuthority = IBEX_RUNTIME_EXTENSION_AUTHENTICATION_FAILED,
  StaleGeneration = IBEX_RUNTIME_EXTENSION_STALE_GENERATION,
  Quiescing = IBEX_RUNTIME_EXTENSION_QUIESCING,
  QueueFull = IBEX_RUNTIME_EXTENSION_QUEUE_FULL,
  Invalid = IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT
};

enum class CompletionMode : uint8_t {
  Once = 1,
  Repeating = 2,
};

class CompletionTokenV1 {
public:
  using OwnerCallback = std::function<void(facebook::jsi::Runtime &,
                                           const std::vector<uint8_t> &)>;

  CompletionTokenV1();
  CompletionTokenV1(const CompletionTokenV1 &);
  CompletionTokenV1(CompletionTokenV1 &&) noexcept;
  CompletionTokenV1 &operator=(const CompletionTokenV1 &);
  CompletionTokenV1 &operator=(CompletionTokenV1 &&) noexcept;
  ~CompletionTokenV1();

  explicit operator bool() const;

  /*
   * Copies bytes before returning. Producer admission is fail-fast and never
   * waits for runtime, callback-queue, Host-context, or typed-generation
   * locks. Only Accepted transfers the copied payload to the owner queue;
   * other dispositions reclaim producer-safe bytes on the caller. Copies share
   * one owner-only callback slot; destroying the last copy publishes an
   * atomics-only retirement request after already-admitted posts reach a
   * terminal disposition. Once transferred, owner delivery may begin or finish
   * before post() returns; publish every completion-visible producer state
   * before calling post().
   */
  ScheduleResult post(const uint8_t *bytes, size_t length) const;
  ScheduleResult post(std::vector<uint8_t> bytes) const;

private:
  struct Impl;
  explicit CompletionTokenV1(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
  friend class InstallContextV1;
};

class OperationLeaseV1 {
public:
  OperationLeaseV1();
  OperationLeaseV1(OperationLeaseV1 &&) noexcept;
  OperationLeaseV1 &operator=(OperationLeaseV1 &&) noexcept;
  ~OperationLeaseV1();
  OperationLeaseV1(const OperationLeaseV1 &) = delete;
  OperationLeaseV1 &operator=(const OperationLeaseV1 &) = delete;

  /*
   * Provider retention may move this lease across threads. Last-copy
   * destruction is always nonblocking: it publishes an atomic retirement
   * request and wakes the runtime owner, whose independently owned slot
   * performs Host revocation. It never touches Host, JSI, the runtime, or an
   * extension Instance. Currentness remains a fail-fast Host binding check.
   */
  explicit operator bool() const;
  uint64_t opaqueId() const;

private:
  struct Impl;
  explicit OperationLeaseV1(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
  friend class CompletionTokenV1;
  friend class InstallContextV1;
};

class InstallContextV1 {
public:
  using EffectfulHostFunction = std::function<facebook::jsi::Value(
      facebook::jsi::Runtime &, OperationLeaseV1 &,
      const facebook::jsi::Value &, const facebook::jsi::Value *, size_t)>;
  using ResourceNormalizer = std::function<std::string(
      facebook::jsi::Runtime &, const facebook::jsi::Value &,
      const facebook::jsi::Value *, size_t)>;
  using PresentedLeaseCollector =
      std::function<std::vector<const OperationLeaseV1 *>(
          facebook::jsi::Runtime &, const facebook::jsi::Value &,
          const facebook::jsi::Value *, size_t)>;

  InstallContextV1(const InstallContextV1 &) = delete;
  InstallContextV1 &operator=(const InstallContextV1 &) = delete;
  ~InstallContextV1();

  static InstallContextV1 &fromOpaque(void *opaque);

  facebook::jsi::Runtime &runtime() const;
  uint64_t runtimeNonce() const;
  uint64_t generation() const;
  const std::string &extensionId() const;
  uint64_t supportedFeatures() const;

  /*
   * Returns an immutable per-instance view which remains stable through the
   * close callback. A provider() call on another context cannot overwrite it.
   */
  const RuntimeExtensionProviderBindingV1 *provider() const;

  /*
   * The only supported publication path. `path` must exactly match one
   * descriptor-declared path. Parent objects may already exist but may not be
   * accessors or HostObjects. Publication is non-enumerable and
   * non-configurable by default.
   */
  void defineGlobal(const std::string &path, facebook::jsi::Value value,
                    bool writable = false, bool enumerable = false);

  /*
   * Publish one descriptor-declared module export into the trusted module
   * loader. The construction-only registrar is deleted before user code.
   */
  void defineModule(const std::string &specifier, facebook::jsi::Value exports);

  /*
   * Every effectful JS-triggerable native callable must be minted here. Raw
   * JSI remains available for pure branded object/prototype construction; the
   * source contract forbids raw effectful HostFunctions, HostObject traps,
   * accessors, finalizers, or external-buffer hooks.
   */
  facebook::jsi::Function makeEffectfulHostFunction(
      const std::string &operationId, const std::string &functionName,
      unsigned int parameterCount, EffectfulHostFunction callback,
      ResourceNormalizer resourceNormalizer = {},
      PresentedLeaseCollector presentedLeaseCollector = {});

  /*
   * Mint a background-delivery token for the exact currently executing
   * operation. The owner-side callback slot retains `lease`; public token
   * copies retain only producer-safe binding facts and atomics, so last-copy
   * destruction never revokes a Host lease or destroys JSI off owner. The
   * authenticated binding/currentness is rechecked both before enqueue and on
   * owner-thread delivery. The admitted owner check may wait only for a stable
   * context-local Host policy/generation snapshot; it invokes no provider,
   * external callback, worker, runtime drive, or effectful Host API under that
   * guard.
   */
  CompletionTokenV1
  makeCompletionToken(OperationLeaseV1 &lease, const std::string &callbackId,
                      CompletionTokenV1::OwnerCallback callback,
                      CompletionMode mode = CompletionMode::Once);

  OperationLeaseV1
  authorize(const std::string &operationId, const std::string &resourceJson,
            const std::vector<const OperationLeaseV1 *> &presentedLeases = {});

  std::vector<uint8_t> copyBytes(const uint8_t *bytes, size_t length) const;

  /*
   * Optional keyed-external-buffer profile. The lease must belong to the
   * generated operation currently executing. A nonzero revocation key is
   * extension-local and may name multiple overlapping aliases; revoking it
   * detaches every alias exactly once and permanently retires the key for this
   * runtime generation. If engine detach throws, the alias and key remain
   * strongly retained and non-reusable so an explicit retry or teardown can
   * safely finish before provider storage is reclaimed.
   */
  facebook::jsi::ArrayBuffer createKeyedExternalRange(
      OperationLeaseV1 &lease, const facebook::jsi::ArrayBuffer &source,
      size_t byteOffset, size_t byteLength, uint64_t revocationKey);

  bool revokeKeyedExternalKey(OperationLeaseV1 &lease, uint64_t revocationKey);

private:
  struct Impl;
  explicit InstallContextV1(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
  friend struct RuntimeStateAccess;
};

} // namespace ibex::runtime_extension::v1

#endif /* IBEX_RUNTIME_EXTENSION_HPP */
