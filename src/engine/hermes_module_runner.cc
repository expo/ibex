// Native-only Hermes factory compiler for the authenticated module graph.
// @ref LLP 0026#4-native-graph-owner-and-hermes-runner — identity and
// compartment are selected before package factory compilation, and package JS
// never receives the compiler capability.

#include "hermes_runtime_internal.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>

namespace {

struct ActiveCommonJsEvaluation {
  ExactHermesRuntime* runtime;
  uint64_t record_id;
};

thread_local std::vector<ActiveCommonJsEvaluation>
    activeCommonJsEvaluations;

class ScopedActiveCommonJsEvaluation {
 public:
  ScopedActiveCommonJsEvaluation(
      ExactHermesRuntime* runtime, uint64_t recordId) {
    activeCommonJsEvaluations.push_back({runtime, recordId});
  }

  ScopedActiveCommonJsEvaluation(const ScopedActiveCommonJsEvaluation&) = delete;
  ScopedActiveCommonJsEvaluation& operator=(
      const ScopedActiveCommonJsEvaluation&) = delete;

  ~ScopedActiveCommonJsEvaluation() {
    activeCommonJsEvaluations.pop_back();
  }
};

class ScopedCommonJsRequireProviderCall {
 public:
  ScopedCommonJsRequireProviderCall(
      ExactHermesRuntime* runtime, uint64_t graphGeneration)
      : runtime_(runtime) {
    if (runtime_ == nullptr ||
        runtime_->commonjs_require_provider_call_active) {
      return;
    }
    runtime_->commonjs_require_provider_call_active = true;
    runtime_->commonjs_require_provider_call_generation = graphGeneration;
    active_ = true;
  }

  ScopedCommonJsRequireProviderCall(
      const ScopedCommonJsRequireProviderCall&) = delete;
  ScopedCommonJsRequireProviderCall& operator=(
      const ScopedCommonJsRequireProviderCall&) = delete;

  ~ScopedCommonJsRequireProviderCall() {
    if (!active_) return;
    runtime_->commonjs_require_provider_call_generation = 0;
    runtime_->commonjs_require_provider_call_active = false;
  }

  explicit operator bool() const { return active_; }

 private:
  ExactHermesRuntime* runtime_{nullptr};
  bool active_{false};
};

bool isActiveCommonJsEvaluationOwner(
    ExactHermesRuntime* runtime, uint64_t recordId) {
  return !activeCommonJsEvaluations.empty() &&
      activeCommonJsEvaluations.back().runtime == runtime &&
      activeCommonJsEvaluations.back().record_id == recordId;
}

bool finiteIntegerInRange(double value, double minimum, double maximum) {
  return std::isfinite(value) && value >= minimum && value <= maximum &&
      std::trunc(value) == value;
}

#ifdef IBEX_CAPSEC_CONFORMANCE_OBSERVER
thread_local std::set<std::string> moduleRunnerAbiObservations;

void observeModuleRunnerAbi(const char* functionName) {
  moduleRunnerAbiObservations.emplace(functionName);
}
#else
void observeModuleRunnerAbi(const char*) {}
#endif

void writeError(char** out, const std::string& message) {
  if (out == nullptr) return;
  if (*out != nullptr) {
    std::free(*out);
    *out = nullptr;
  }
  *out = static_cast<char*>(std::malloc(message.size() + 1));
  if (*out == nullptr) return;
  std::memcpy(*out, message.data(), message.size());
  (*out)[message.size()] = '\0';
}

bool validDigest(const std::string& digest) {
  if (digest.size() != 50 || digest.compare(0, 7, "sha256-") != 0) {
    return false;
  }
  for (size_t i = 7; i < digest.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(digest[i]);
    if (!(std::isalnum(c) || c == '_' || c == '-')) return false;
  }
  return true;
}

std::string safeSourceLabel(const uint8_t* bytes, size_t length) {
  std::string label(reinterpret_cast<const char*>(bytes), length);
  for (char& c : label) {
    if (c == '\r' || c == '\n') c = '_';
  }
  return label.empty() ? std::string("ibex-module-factory") : label;
}

class CarrierMemoryBuffer : public facebook::jsi::Buffer {
 public:
  CarrierMemoryBuffer(const uint8_t* data, size_t length)
      : bytes_(data, data + length) {}
  size_t size() const override { return bytes_.size(); }
  const uint8_t* data() const override { return bytes_.data(); }

 private:
  std::vector<uint8_t> bytes_;
};

class CarrierAlignedBytecodeBuffer : public facebook::jsi::Buffer {
 public:
  CarrierAlignedBytecodeBuffer(const uint8_t* data, size_t length)
      : size_(length), storage_(length + alignof(std::max_align_t)) {
    const auto address = reinterpret_cast<uintptr_t>(storage_.data());
    const auto alignment = alignof(std::max_align_t);
    const auto aligned = (address + alignment - 1) & ~(alignment - 1);
    data_ = reinterpret_cast<uint8_t*>(aligned);
    std::memcpy(data_, data, length);
  }
  size_t size() const override { return size_; }
  const uint8_t* data() const override { return data_; }

 private:
  size_t size_;
  std::vector<uint8_t> storage_;
  uint8_t* data_{nullptr};
};

bool carrierBytecodeSanityCheck(
    const uint8_t* bytes, size_t length, std::string& reason) {
  CarrierAlignedBytecodeBuffer buffer(bytes, length);
  const auto* alignedData = buffer.data();
#if defined(EXACT_HAVE_HERMES_RUNTIME_BYTECODE_SANITY_CHECK)
  return facebook::hermes::HermesRuntime::hermesBytecodeSanityCheck(
      alignedData, length, &reason);
#elif defined(EXACT_HAVE_HERMES_ROOT_BYTECODE_SANITY_CHECK)
  auto* root = facebook::jsi::castInterface<facebook::hermes::IHermesRootAPI>(
      facebook::hermes::makeHermesRootAPI());
  if (root == nullptr) {
    reason = "Hermes root API unavailable";
    return false;
  }
  return root->hermesBytecodeSanityCheck(alignedData, length, &reason);
#else
  (void)alignedData;
  reason = "linked Hermes exposes no bytecode sanity-check API";
  return false;
#endif
}

facebook::jsi::Object compartmentFor(
    facebook::jsi::Runtime& rt, const std::string& identity) {
  auto registryValue = rt.global().getProperty(rt, "__compartments");
  if (!registryValue.isObject()) {
    throw facebook::jsi::JSError(rt, "module compartment registry is unavailable");
  }
  // The authenticated identity crosses FFI as pointer+length. Preserve that
  // boundary here too: a C-string lookup would collapse an embedded NUL onto
  // a different compartment even if an upstream identity type regressed.
  // @ref LLP 0013#mechanism-2-per-package-compartment-globals — package compartments are keyed by the complete authenticated locator
  const auto property = facebook::jsi::PropNameID::forUtf8(rt, identity);
  auto compartment = registryValue.asObject(rt).getProperty(rt, property);
  if (!compartment.isObject()) {
    throw facebook::jsi::JSError(rt, "authenticated module compartment is unavailable");
  }
  return compartment.asObject(rt);
}

facebook::jsi::PropNameID moduleExportPropertyName(
    facebook::jsi::Runtime& rt, const std::string& name) {
  // ModuleExportName is a length-bearing JavaScript string and may contain an
  // embedded NUL. Never route it through the const-char JSI convenience
  // overload, which would silently address a different property.
  // @ref LLP 0027#esmcommonjs-interop-matrix
  return facebook::jsi::PropNameID::forUtf8(rt, name);
}

bool commonJsRequireMutationTargetsGeneration(
    ExactHermesRuntime* runtime, uint64_t graphGeneration) {
  return runtime != nullptr &&
      (!runtime->commonjs_require_provider_call_active ||
       runtime->commonjs_require_provider_call_generation ==
           graphGeneration);
}

uint64_t nextHandleId(ExactHermesRuntime* runtime) {
  const uint64_t id = runtime->next_module_handle_id++;
  if (id == 0 || runtime->next_module_handle_id == 0) {
    throw std::runtime_error("module-runner handle space exhausted");
  }
  return id;
}

void releaseContextReference(ExactHermesRuntime* runtime, uint64_t contextId) {
  auto context = runtime->graph_contexts.find(contextId);
  if (context != runtime->graph_contexts.end() &&
      --context->second.references == 0) {
    runtime->graph_contexts.erase(context);
  }
}

void eraseDynamicActivationsForRequester(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t requesterRecordId,
    bool requesterIsCommonJs) {
  for (auto it =
           runtime->module_dynamic_activation_requests.begin();
       it != runtime->module_dynamic_activation_requests.end();) {
    const auto& request = it->second;
    if (request.graph_generation == graphGeneration &&
        request.requester_record_id == requesterRecordId &&
        request.requester_is_commonjs == requesterIsCommonJs) {
      it = runtime->module_dynamic_activation_requests.erase(it);
    } else {
      ++it;
    }
  }
  runtime->module_dynamic_activation_queue.erase(
      std::remove_if(
          runtime->module_dynamic_activation_queue.begin(),
          runtime->module_dynamic_activation_queue.end(),
          [&](uint64_t requestId) {
            return runtime->module_dynamic_activation_requests.count(
                       requestId) == 0;
          }),
      runtime->module_dynamic_activation_queue.end());
}

NativeModuleRecordEntry* recordFor(
    ExactHermesRuntime* runtime, ExactModuleRunnerHandle handle) {
  if (runtime == nullptr || handle.opaque[0] != runtime->runtime_nonce ||
      handle.opaque[1] == 0 || handle.opaque[2] == 0) {
    return nullptr;
  }
  auto it = runtime->module_records.find(handle.opaque[2]);
  if (it == runtime->module_records.end() ||
      it->second.graph_generation != handle.opaque[1]) {
    return nullptr;
  }
  return &it->second;
}

struct ResolvedModuleRecord {
  NativeModuleRecordEntry* record{nullptr};
  uint64_t record_id{0};
};

ResolvedModuleRecord resolveLiveModuleRecord(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t recordId) {
  if (runtime == nullptr) return {};
  // Cross-module reads resolve one slot-forwarding hop. Writes and completion
  // callbacks deliberately remain exact-record-bound: erasing a retired entry
  // fences stale publication instead of redirecting it into the successor.
  // @ref LLP 0055#23-stable-logical-slots-every-cross-module-use-resolves-through-the-slot
  auto forwarding = runtime->module_record_forwarding.find(recordId);
  uint64_t resolvedId = recordId;
  if (forwarding != runtime->module_record_forwarding.end()) {
    resolvedId = forwarding->second;
  }
  auto record = runtime->module_records.find(resolvedId);
  if (record == runtime->module_records.end() ||
      record->second.graph_generation != graphGeneration) {
    return {};
  }
  return {&record->second, resolvedId};
}

void eraseModuleSourceSlotIfOwned(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    const std::string& sourceId,
    uint64_t recordId) {
  for (auto slot = runtime->module_source_slots.begin();
       slot != runtime->module_source_slots.end(); ++slot) {
    if (slot->first.first == graphGeneration &&
        slot->first.second == sourceId && slot->second == recordId) {
      runtime->module_source_slots.erase(slot);
      return;
    }
  }
}

NativeCommonJsRecordEntry* commonJsRecordFor(
    ExactHermesRuntime* runtime, ExactModuleRunnerHandle handle) {
  if (runtime == nullptr || handle.opaque[0] != runtime->runtime_nonce ||
      handle.opaque[1] == 0 || handle.opaque[2] == 0) {
    return nullptr;
  }
  auto it = runtime->commonjs_records.find(handle.opaque[2]);
  if (it == runtime->commonjs_records.end() ||
      it->second.graph_generation != handle.opaque[1]) {
    return nullptr;
  }
  return &it->second;
}

facebook::jsi::Value rejectedPromise(
    facebook::jsi::Runtime& rt, const std::string& message);

facebook::jsi::Object dynamicEvaluationPromise(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t requesterRecordId,
    uint64_t targetRecordId);

facebook::jsi::Object pendingDynamicActivationPromise(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t requesterRecordId,
    bool requesterIsCommonJs,
    const std::string& requesterSourceId,
    bool computed,
    uint32_t site,
    const std::string& specifier);

void evaluateSynchronousRequiredEsm(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t targetRecordId);

facebook::jsi::Value readBinding(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t recordId,
    NativeModuleRecordEntry& record,
    const std::string& exportName);

facebook::jsi::Value requireEsmRecord(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t recordId,
    bool synchronousEligible);

void finalizeCommonJsAdapter(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    NativeCommonJsRecordEntry& commonjs) {
  if (commonjs.adapter_record_id == 0) return;
  auto found = runtime->module_records.find(commonjs.adapter_record_id);
  if (found == runtime->module_records.end() ||
      found->second.graph_generation != commonjs.graph_generation) {
    throw facebook::jsi::JSError(rt, "CommonJS ESM adapter is stale");
  }
  if (!commonjs.exports_value) {
    throw facebook::jsi::JSError(rt, "CommonJS exports are unavailable");
  }
  auto& adapter = found->second;
  for (auto& [name, cell] : adapter.export_cells) {
    facebook::jsi::Value snapshot = facebook::jsi::Value::undefined();
    if (name == "default" || name == "module.exports") {
      snapshot = facebook::jsi::Value(rt, *commonjs.exports_value);
    } else if (commonjs.exports_value->isObject()) {
      snapshot = commonjs.exports_value->asObject(rt).getProperty(
          rt, moduleExportPropertyName(rt, name));
    }
    cell.initialized = true;
    cell.value = std::make_shared<facebook::jsi::Value>(rt, snapshot);
  }
  auto objectConstructor = rt.global().getPropertyAsObject(rt, "Object");
  auto create = objectConstructor.getPropertyAsFunction(rt, "create");
  auto defineProperty =
      objectConstructor.getPropertyAsFunction(rt, "defineProperty");
  auto preventExtensions =
      objectConstructor.getPropertyAsFunction(rt, "preventExtensions");
  auto namespaceObject =
      create.call(rt, facebook::jsi::Value::null()).asObject(rt);
  for (const auto& [name, cell] : adapter.export_cells) {
    facebook::jsi::Object descriptor(rt);
    descriptor.setProperty(rt, "enumerable", true);
    descriptor.setProperty(rt, "configurable", false);
    descriptor.setProperty(rt, "writable", false);
    descriptor.setProperty(rt, "value", *cell.value);
    defineProperty.call(
        rt,
        namespaceObject,
        facebook::jsi::String::createFromUtf8(rt, name),
        descriptor);
  }
  preventExtensions.call(rt, namespaceObject);
  adapter.namespace_object =
      std::make_shared<facebook::jsi::Object>(std::move(namespaceObject));
  adapter.state = NativeModuleRecordState::Evaluated;
}

void rememberCommonJsAdapterError(
    ExactHermesRuntime* runtime,
    const NativeCommonJsRecordEntry& commonjs,
    const std::string& message) {
  if (commonjs.adapter_record_id == 0) return;
  auto found = runtime->module_records.find(commonjs.adapter_record_id);
  if (found == runtime->module_records.end() ||
      found->second.graph_generation != commonjs.graph_generation) {
    return;
  }
  found->second.state = NativeModuleRecordState::Errored;
  if (found->second.error_message.empty()) {
    found->second.error_message = message;
  }
}

// @ref LLP 0026#7-commonjs-interop — publish before execution, expose current
// partial exports to cycles, and evict every throwing record.
facebook::jsi::Value evaluateCommonJsRecord(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t recordId) {
  auto found = runtime->commonjs_records.find(recordId);
  if (found == runtime->commonjs_records.end()) {
    throw facebook::jsi::JSError(rt, "CommonJS record is stale");
  }
  auto& record = found->second;
  if (record.state == NativeCommonJsRecordState::Evaluating) {
    if (!record.module_object) {
      throw facebook::jsi::JSError(rt, "CommonJS module object is unavailable");
    }
    auto currentExports = record.module_object->getProperty(rt, "exports");
    record.exports_value =
        std::make_shared<facebook::jsi::Value>(rt, currentExports);
    return facebook::jsi::Value(rt, *record.exports_value);
  }
  if (record.state == NativeCommonJsRecordState::Evaluated) {
    if (!record.exports_value) {
      throw facebook::jsi::JSError(rt, "CommonJS exports are unavailable");
    }
    return facebook::jsi::Value(rt, *record.exports_value);
  }
  if (!record.factory || !record.module_object || !record.exports_value) {
    throw facebook::jsi::JSError(rt, "CommonJS record is incomplete");
  }

  const uint64_t graphGeneration = record.graph_generation;
  const auto target = exactRuntimeCallbackTarget(runtime);
  record.state = NativeCommonJsRecordState::Evaluating;
  ScopedActiveCommonJsEvaluation activeEvaluation(runtime, recordId);
  try {
    auto requireFunction = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "commonJsRequire"),
        1,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          if (!runtimeIsAlive(target) ||
              target.runtime->runtime_thread != std::this_thread::get_id()) {
            throw facebook::jsi::JSError(rt, "stale CommonJS require callback");
          }
          auto current = target.runtime->commonjs_records.find(recordId);
          if (current == target.runtime->commonjs_records.end() ||
              current->second.graph_generation != graphGeneration) {
            throw facebook::jsi::JSError(rt, "stale CommonJS require owner");
          }
          // Manifest-builtin fan-out is a private exception only while the
          // exact generated body is synchronously initializing. A builtin may
          // not export/capture this closure and later launder root loader
          // authority for a package caller.
          // @ref LLP 0021#module-initialization-and-trusted-source-acquisition
          if (current->second.source_goal == 3 &&
              (current->second.state != NativeCommonJsRecordState::Evaluating ||
               !isActiveCommonJsEvaluationOwner(target.runtime, recordId))) {
            throw facebook::jsi::JSError(
                rt,
                "manifest builtin require is unavailable outside synchronous initialization");
          }
          if (count != 1 || !args[0].isString()) {
            throw facebook::jsi::JSError(
                rt, "CommonJS require expects one string specifier");
          }
          const std::string specifier = args[0].asString(rt).utf8(rt);
          auto binding = current->second.require_bindings.find(specifier);
          if (binding == current->second.require_bindings.end()) {
            if (current->second.bootstrap_internal_commonjs_requires.count(
                    specifier) != 0) {
              if (current->second.source_goal != 3 ||
                  !target.runtime->module_bootstrap_internal_resolver) {
                throw facebook::jsi::JSError(
                    rt, "bootstrap-internal CommonJS require is unavailable");
              }
              auto internal =
                  target.runtime->module_bootstrap_internal_resolver->call(
                      rt,
                      facebook::jsi::String::createFromUtf8(rt, specifier));
              if (internal.isNull() || internal.isUndefined()) {
                throw facebook::jsi::JSError(
                    rt, "bootstrap-internal CommonJS require is stale");
              }
              return internal;
            }
            if (current->second.deferred_commonjs_requires.count(specifier) ==
                0) {
              throw facebook::jsi::JSError(
                  rt, "CommonJS require target is not linked");
            }
            auto provider =
                target.runtime->commonjs_require_providers.find(
                    graphGeneration);
            if (provider ==
                    target.runtime->commonjs_require_providers.end() ||
                provider->second.provider == nullptr) {
              throw facebook::jsi::JSError(
                  rt, "CommonJS require activation provider is unavailable");
            }
            const std::string requesterSourceId = current->second.source_id;
            const NativeCommonJsRequireProviderEntry providerEntry =
                provider->second;
            ExactModuleRunnerHandle requesterHandle{{
                target.runtime->runtime_nonce,
                graphGeneration,
                recordId,
            }};
            ExactModuleRunnerHandle targetHandle{{0, 0, 0}};
            uint32_t targetKind = UINT32_MAX;
            uint8_t errorBuffer[1024] = {};
            size_t errorLength = 0;
            int32_t providerStatus = EXACT_RUNTIME_DRIVE_INVALID;
            {
              ScopedCommonJsRequireProviderCall providerCall(
                  target.runtime, graphGeneration);
              if (!providerCall) {
                throw facebook::jsi::JSError(
                    rt, "CommonJS require activation is already active");
              }
              providerStatus = providerEntry.provider(
                  providerEntry.context,
                  target.runtime->runtime_nonce,
                  graphGeneration,
                  requesterHandle,
                  reinterpret_cast<const uint8_t*>(
                      requesterSourceId.data()),
                  requesterSourceId.size(),
                  reinterpret_cast<const uint8_t*>(specifier.data()),
                  specifier.size(),
                  &targetHandle,
                  &targetKind,
                  errorBuffer,
                  sizeof(errorBuffer),
                  &errorLength);
            }
            if (providerStatus != EXACT_RUNTIME_DRIVE_OK) {
              const size_t boundedLength =
                  std::min(errorLength, sizeof(errorBuffer));
              const std::string detail(
                  reinterpret_cast<const char*>(errorBuffer),
                  boundedLength);
              throw facebook::jsi::JSError(
                  rt,
                  detail.empty()
                      ? "CommonJS require activation was refused"
                      : detail);
            }
            current = target.runtime->commonjs_records.find(recordId);
            if (current == target.runtime->commonjs_records.end() ||
                current->second.graph_generation != graphGeneration ||
                current->second.source_id != requesterSourceId ||
                current->second.state !=
                    NativeCommonJsRecordState::Evaluating ||
                current->second.deferred_commonjs_requires.count(specifier) ==
                    0 ||
                targetHandle.opaque[0] != target.runtime->runtime_nonce ||
                targetHandle.opaque[1] != graphGeneration ||
                (targetKind != 0 && targetKind != 1)) {
              throw facebook::jsi::JSError(
                  rt, "CommonJS require activation returned a stale target");
            }
            NativeCommonJsRequireBinding activatedBinding;
            activatedBinding.kind =
                targetKind == 0
                ? NativeCommonJsRequireTargetKind::CommonJs
                : NativeCommonJsRequireTargetKind::Esm;
            activatedBinding.record_id = targetHandle.opaque[2];
            // The provider publishes an ESM target only after the host has
            // checked its complete static closure for synchronous eligibility.
            // Preserve that successful gate on the binding; async-tainted
            // targets are refused by the provider before they reach here.
            // @ref LLP 0026#7-commonjs-interop
            activatedBinding.esm_synchronous_eligible = targetKind == 1;
            if (targetKind == 0) {
              auto* activated =
                  commonJsRecordFor(target.runtime, targetHandle);
              if (activated == nullptr || !activated->published) {
                throw facebook::jsi::JSError(
                    rt,
                    "CommonJS require activation returned an unpublished CommonJS target");
              }
            } else {
              auto* activated = recordFor(target.runtime, targetHandle);
              if (activated == nullptr || !activated->published) {
                throw facebook::jsi::JSError(
                    rt,
                    "CommonJS require activation returned an unpublished ESM target");
              }
            }
            auto [inserted, unique] =
                current->second.require_bindings.emplace(
                    specifier, activatedBinding);
            if (!unique) {
              throw facebook::jsi::JSError(
                  rt, "CommonJS require activation raced an existing target");
            }
            binding = inserted;
          }
          if (binding->second.kind ==
              NativeCommonJsRequireTargetKind::Esm) {
            // Refuse an async-tainted target closure BEFORE any member body
            // runs. The prelinked eligibility bit is the host's TLA
            // classification for this exact edge; evaluating first and
            // detecting the returned promise afterwards would execute the
            // target as a side effect of a refusal.
            // @ref LLP 0026#7-commonjs-interop
            if (!binding->second.esm_synchronous_eligible) {
              throw facebook::jsi::JSError(
                  rt,
                  "ERR_REQUIRE_ASYNC_MODULE: require() target graph contains top-level await");
            }
            evaluateSynchronousRequiredEsm(
                rt,
                target.runtime,
                graphGeneration,
                binding->second.record_id);
            return requireEsmRecord(
                rt,
                target.runtime,
                graphGeneration,
                binding->second.record_id,
                binding->second.esm_synchronous_eligible);
          }
          auto dependency = target.runtime->commonjs_records.find(
              binding->second.record_id);
          if (dependency == target.runtime->commonjs_records.end() ||
              dependency->second.graph_generation != graphGeneration) {
            throw facebook::jsi::JSError(rt, "CommonJS require target is stale");
          }
          return evaluateCommonJsRecord(
              rt, target.runtime, binding->second.record_id);
        });
    auto dynamicImport = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "commonJsDynamicImport"),
        1,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          // Producer-owned metadata keeps guarded failures at invocation while
          // naming the authenticated requester and original authored span.
          // @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
          const bool siteBearing = count >= 5 && args[0].isNumber() &&
              args[1].isNumber() && args[2].isNumber() && args[3].isNumber();
          const bool legacyComputed =
              !siteBearing && count >= 2 && args[0].isNumber();
          const size_t specifierIndex = siteBearing ? 4 : (legacyComputed ? 1 : 0);
          if (count < specifierIndex + 1 || count > specifierIndex + 2) {
            return rejectedPromise(rt, "CommonJS dynamic import arguments are invalid");
          }
          if (!runtimeIsAlive(target) ||
              target.runtime->runtime_thread != std::this_thread::get_id()) {
            return rejectedPromise(rt, "stale CommonJS dynamic import callback");
          }
          auto current = target.runtime->commonjs_records.find(recordId);
          if (current == target.runtime->commonjs_records.end() ||
              current->second.graph_generation != graphGeneration) {
            return rejectedPromise(rt, "stale CommonJS dynamic import owner");
          }
          if (current->second.source_goal == 3 &&
              (current->second.state != NativeCommonJsRecordState::Evaluating ||
               !isActiveCommonJsEvaluationOwner(target.runtime, recordId))) {
            return rejectedPromise(
                rt,
                "manifest builtin dynamic import is unavailable outside synchronous initialization");
          }
          try {
            const std::string specifier =
                args[specifierIndex].toString(rt).utf8(rt);
            bool computed = legacyComputed;
            uint32_t site = 0;
            std::string siteDiagnostic;
            if (siteBearing) {
              const double rawKind = args[0].asNumber();
              const double rawStart = args[1].asNumber();
              const double rawEnd = args[2].asNumber();
              const double rawOptionsGuard = args[3].asNumber();
              if (!finiteIntegerInRange(rawKind, -1, UINT32_MAX) ||
                  !finiteIntegerInRange(rawStart, 0, UINT32_MAX) ||
                  !finiteIntegerInRange(rawEnd, 0, UINT32_MAX) ||
                  rawEnd < rawStart ||
                  (rawOptionsGuard != 0 && rawOptionsGuard != 1)) {
                return rejectedPromise(rt, "dynamic import site metadata is invalid");
              }
              computed = rawKind >= 0;
              if (computed) site = static_cast<uint32_t>(rawKind);
              siteDiagnostic = current->second.source_id +
                  " at original-source bytes " +
                  std::to_string(static_cast<uint32_t>(rawStart)) + ".." +
                  std::to_string(static_cast<uint32_t>(rawEnd));
              if (rawOptionsGuard != 0) {
                return rejectedPromise(
                    rt, "unsupported dynamic import options in " + siteDiagnostic);
              }
            }
            uint64_t targetRecordId = 0;
            if (computed) {
              if (!siteBearing) {
                const double rawSite = args[0].asNumber();
                if (!finiteIntegerInRange(rawSite, 0, UINT32_MAX)) {
                  return rejectedPromise(rt, "computed dynamic import site is invalid");
                }
                site = static_cast<uint32_t>(rawSite);
              }
              auto binding = current->second.computed_dynamic_import_bindings.find(
                  std::make_pair(site, specifier));
              if (binding == current->second.computed_dynamic_import_bindings.end()) {
                if (current->second.deferred_computed_dynamic_imports.count(
                        std::make_pair(site, specifier)) != 0) {
                  auto promise = pendingDynamicActivationPromise(
                      rt,
                      target.runtime,
                      graphGeneration,
                      recordId,
                      true,
                      current->second.source_id,
                      true,
                      site,
                      specifier);
                  return facebook::jsi::Value(rt, promise);
                }
                return rejectedPromise(
                    rt,
                    "computed dynamic import candidate is not authorized for this site" +
                        (siteDiagnostic.empty() ? std::string() :
                                                  " in " + siteDiagnostic));
              }
              targetRecordId = binding->second;
            } else {
              auto binding = current->second.dynamic_import_bindings.find(specifier);
              if (binding == current->second.dynamic_import_bindings.end()) {
                if (current->second.deferred_dynamic_imports.count(specifier) != 0) {
                  auto promise = pendingDynamicActivationPromise(
                      rt,
                      target.runtime,
                      graphGeneration,
                      recordId,
                      true,
                      current->second.source_id,
                      false,
                      0,
                      specifier);
                  return facebook::jsi::Value(rt, promise);
                }
                return rejectedPromise(
                    rt, "CommonJS dynamic import target is not authorized and linked");
              }
              targetRecordId = binding->second;
            }
            auto promise = dynamicEvaluationPromise(
                rt,
                target.runtime,
                graphGeneration,
                recordId,
                targetRecordId);
            return facebook::jsi::Value(rt, promise);
          } catch (const facebook::jsi::JSError& error) {
            // Keep the engine-side reason: a swallowed generic label made
            // real linkage faults (e.g. a missing adapter record) look like
            // application bugs (LLP 0413 Phase 2 integration finding).
            return rejectedPromise(
                rt, "CommonJS dynamic import failed: " + error.getMessage());
          } catch (const std::exception& error) {
            return rejectedPromise(rt, error.what());
          } catch (...) {
            return rejectedPromise(
                rt, "unknown CommonJS dynamic import failure");
          }
        });
    auto computedRequire = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "commonJsComputedRequire"),
        2,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          // The producer supplies original-source coordinates as hidden
          // arguments. Authored arguments have already evaluated before this
          // callback throws, preserving reached-site CommonJS ordering without
          // granting a runtime resolver.
          // @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
          if (!runtimeIsAlive(target) ||
              target.runtime->runtime_thread != std::this_thread::get_id()) {
            throw facebook::jsi::JSError(
                rt, "stale computed CommonJS require callback");
          }
          auto current = target.runtime->commonjs_records.find(recordId);
          if (current == target.runtime->commonjs_records.end() ||
              current->second.graph_generation != graphGeneration) {
            throw facebook::jsi::JSError(
                rt, "stale computed CommonJS require owner");
          }
          if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
            throw facebook::jsi::JSError(
                rt, "computed CommonJS require site metadata is invalid");
          }
          const double rawStart = args[0].asNumber();
          const double rawEnd = args[1].asNumber();
          if (!finiteIntegerInRange(rawStart, 0, UINT32_MAX) ||
              !finiteIntegerInRange(rawEnd, 0, UINT32_MAX) ||
              rawEnd < rawStart) {
            throw facebook::jsi::JSError(
                rt, "computed CommonJS require site metadata is invalid");
          }
          throw facebook::jsi::JSError(
              rt,
              "IBEX_LEGACY_COMPUTED_REQUIRE: computed CommonJS require is "
              "unsupported in " + current->second.source_id +
                  " at original-source bytes " +
                  std::to_string(static_cast<uint32_t>(rawStart)) + ".." +
                  std::to_string(static_cast<uint32_t>(rawEnd)));
        });
    auto graphContext = runtime->graph_contexts.find(record.context_handle_id);
    if (graphContext == runtime->graph_contexts.end()) {
      throw facebook::jsi::JSError(rt, "CommonJS graph context is stale");
    }
    std::vector<uint64_t> constrained(
        graphContext->second.constrained_principals.begin(),
        graphContext->second.constrained_principals.end());
    ScopedNativePrincipal scheduledPrincipal(
        graphContext->second.schedule_owner);
    ScopedTypedPrincipalStack constrainedScope(constrained);
    auto result = record.factory->call(
        rt,
        requireFunction,
        *record.module_object,
        *record.exports_value,
        facebook::jsi::String::createFromUtf8(rt, record.filename),
        facebook::jsi::String::createFromUtf8(rt, record.dirname),
        dynamicImport,
        computedRequire);
    (void)result;
    auto finalExports = record.module_object->getProperty(rt, "exports");
    record.exports_value =
        std::make_shared<facebook::jsi::Value>(rt, finalExports);
    record.state = NativeCommonJsRecordState::Evaluated;
    finalizeCommonJsAdapter(rt, runtime, record);
    return facebook::jsi::Value(rt, *record.exports_value);
  } catch (const facebook::jsi::JSError& error) {
    const uint64_t contextId = record.context_handle_id;
    rememberCommonJsAdapterError(
        runtime, record, "CommonJS record evaluation threw");
    eraseDynamicActivationsForRequester(
        runtime, graphGeneration, recordId, true);
    runtime->commonjs_records.erase(recordId);
    releaseContextReference(runtime, contextId);
    throw;
  } catch (const std::exception& error) {
    const uint64_t contextId = record.context_handle_id;
    rememberCommonJsAdapterError(runtime, record, error.what());
    eraseDynamicActivationsForRequester(
        runtime, graphGeneration, recordId, true);
    runtime->commonjs_records.erase(recordId);
    releaseContextReference(runtime, contextId);
    throw;
  } catch (...) {
    const uint64_t contextId = record.context_handle_id;
    rememberCommonJsAdapterError(
        runtime, record, "unknown CommonJS evaluation failure");
    eraseDynamicActivationsForRequester(
        runtime, graphGeneration, recordId, true);
    runtime->commonjs_records.erase(recordId);
    releaseContextReference(runtime, contextId);
    throw;
  }
}

NativeModuleRecordEntry* callbackRecordFor(
    RuntimeCallbackTarget target, uint64_t graphGeneration, uint64_t recordId) {
  if (!runtimeIsAlive(target) ||
      target.runtime->runtime_thread != std::this_thread::get_id()) {
    return nullptr;
  }
  auto it = target.runtime->module_records.find(recordId);
  if (it == target.runtime->module_records.end() ||
      it->second.graph_generation != graphGeneration) {
    return nullptr;
  }
  return &it->second;
}

facebook::jsi::Value readBinding(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t recordId,
    NativeModuleRecordEntry& record,
    const std::string& exportName) {
  auto* current = &record;
  uint64_t currentId = recordId;
  std::string currentName = exportName;
  std::set<std::pair<uint64_t, std::string>> visited;
  while (true) {
    if (!visited.emplace(currentId, currentName).second) {
      throw facebook::jsi::JSError(rt, "cyclic module export alias");
    }
    if (current->state == NativeModuleRecordState::Errored) {
      throw facebook::jsi::JSError(
          rt,
          current->error_message.empty() ? "module record is errored"
                                         : current->error_message);
    }
    if (currentName == "*") {
      if (!current->namespace_object) {
        throw facebook::jsi::JSError(
            rt, "module namespace is not instantiated");
      }
      return facebook::jsi::Value(rt, *current->namespace_object);
    }
    auto cell = current->export_cells.find(currentName);
    if (cell == current->export_cells.end()) {
      throw facebook::jsi::JSError(
          rt, "module does not export '" + currentName + "'");
    }
    if (cell->second.alias_record_id != 0) {
      auto target = resolveLiveModuleRecord(
          runtime,
          current->graph_generation,
          cell->second.alias_record_id);
      if (target.record == nullptr) {
        throw facebook::jsi::JSError(rt, "module export alias is stale");
      }
      currentId = target.record_id;
      currentName = cell->second.alias_export;
      current = target.record;
      continue;
    }
    if (!cell->second.initialized || !cell->second.value) {
      throw facebook::jsi::JSError(
          rt, "Cannot access '" + currentName + "' before initialization");
    }
    return facebook::jsi::Value(rt, *cell->second.value);
  }
}

void rememberRecordError(
    NativeModuleRecordEntry& record,
    const std::string& message,
    uint64_t errorToken = 0) {
  record.state = NativeModuleRecordState::Errored;
  if (record.error_message.empty()) {
    record.error_message = message;
    record.error_token = errorToken;
  }
}

int32_t reportRecordError(
    NativeModuleRecordEntry& record,
    char** outError,
    uint64_t* outErrorToken) {
  if (outErrorToken) *outErrorToken = record.error_token;
  writeError(
      outError,
      record.error_message.empty() ? "module record is errored"
                                   : record.error_message);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

bool beginRecordExecute(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t recordId,
    NativeModuleRecordEntry& entry) {
  if (entry.state == NativeModuleRecordState::Evaluating) return true;
  if (entry.state == NativeModuleRecordState::Evaluated) return false;
  if (entry.state != NativeModuleRecordState::Declared ||
      !entry.execute_function) {
    const char* state = "unknown";
    switch (entry.state) {
      case NativeModuleRecordState::New:
        state = "new";
        break;
      case NativeModuleRecordState::Instantiated:
        state = "instantiated";
        break;
      case NativeModuleRecordState::Declared:
        state = "declared";
        break;
      case NativeModuleRecordState::Evaluating:
        state = "evaluating";
        break;
      case NativeModuleRecordState::Evaluated:
        state = "evaluated";
        break;
      case NativeModuleRecordState::Errored:
        state = "errored";
        break;
    }
    throw facebook::jsi::JSError(
        rt,
        "module record is not ready to execute (state=" +
            std::string(state) + ", execute=" +
            (entry.execute_function ? "present" : "absent") +
            ", source=" + entry.source_id + ")");
  }
  auto graphContext = runtime->graph_contexts.find(entry.context_handle_id);
  if (graphContext == runtime->graph_contexts.end()) {
    throw facebook::jsi::JSError(rt, "module graph context is stale");
  }
  std::vector<uint64_t> constrained(
      graphContext->second.constrained_principals.begin(),
      graphContext->second.constrained_principals.end());
  ScopedNativePrincipal scheduledPrincipal(graphContext->second.schedule_owner);
  ScopedTypedPrincipalStack constrainedScope(constrained);
  // Publish the evaluating state before entering authored code. A synchronous
  // CJS→ESM→CJS re-entry can otherwise observe this record as merely declared
  // while its execute function is already on the stack and recursively run it.
  // @ref LLP 0026#6-top-level-await-and-dynamic-import
  entry.state = NativeModuleRecordState::Evaluating;
  facebook::jsi::Value result;
  try {
    result = entry.execute_function->call(rt);
  } catch (...) {
    entry.state = NativeModuleRecordState::Declared;
    throw;
  }
  if (result.isObject()) {
    auto object = result.asObject(rt);
    auto thenValue = object.getProperty(rt, "then");
    if (thenValue.isObject() && thenValue.asObject(rt).isFunction(rt)) {
      const uint64_t graphGeneration = entry.graph_generation;
      const auto target = exactRuntimeCallbackTarget(runtime);
      auto fulfilled = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(rt, "moduleEvaluationFulfilled"),
          1,
          [target, graphGeneration, recordId](
              facebook::jsi::Runtime&,
              const facebook::jsi::Value&,
              const facebook::jsi::Value*,
              size_t) -> facebook::jsi::Value {
            auto* current =
                callbackRecordFor(target, graphGeneration, recordId);
            if (current != nullptr &&
                current->state == NativeModuleRecordState::Evaluating) {
              current->state = NativeModuleRecordState::Evaluated;
              current->evaluation_promise.reset();
            }
            return facebook::jsi::Value::undefined();
          });
      auto rejected = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(rt, "moduleEvaluationRejected"),
          1,
          [target, graphGeneration, recordId](
              facebook::jsi::Runtime&,
              const facebook::jsi::Value&,
              const facebook::jsi::Value* args,
              size_t count) -> facebook::jsi::Value {
            auto* current =
                callbackRecordFor(target, graphGeneration, recordId);
            if (current != nullptr &&
                current->state == NativeModuleRecordState::Evaluating) {
              std::string message = "module evaluation promise rejected";
              uint64_t errorToken = 0;
              if (count != 0) {
                errorToken = exactRetainStructuredModuleGraphError(
                    target.runtime, args[0]);
              }
              rememberRecordError(*current, message, errorToken);
              current->evaluation_promise.reset();
            }
            return facebook::jsi::Value::undefined();
          });
      auto thenFunction = thenValue.asObject(rt).asFunction(rt);
      auto retainedPromise = facebook::jsi::Value(rt, object).asObject(rt);
      entry.evaluation_promise =
          std::make_shared<facebook::jsi::Object>(std::move(retainedPromise));
      try {
        thenFunction.callWithThis(rt, object, fulfilled, rejected);
      } catch (...) {
        entry.evaluation_promise.reset();
        entry.state = NativeModuleRecordState::Declared;
        throw;
      }
      return true;
    }
  }
  entry.state = NativeModuleRecordState::Evaluated;
  return false;
}

void collectDynamicEvaluationOrder(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t recordId,
    std::set<uint64_t>& visiting,
    std::set<uint64_t>& visited,
    std::vector<uint64_t>& order) {
  if (visited.count(recordId) != 0 || !visiting.insert(recordId).second) return;
  auto record = runtime->module_records.find(recordId);
  if (record == runtime->module_records.end() ||
      record->second.graph_generation != graphGeneration) {
    throw std::runtime_error("dynamic import graph contains a stale record");
  }
  for (uint64_t dependency : record->second.evaluation_dependencies) {
    collectDynamicEvaluationOrder(
        runtime,
        graphGeneration,
        dependency,
        visiting,
        visited,
        order);
  }
  visiting.erase(recordId);
  if (visited.insert(recordId).second) order.push_back(recordId);
}

uint64_t commonJsOwnerForAdapter(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t adapterRecordId) {
  for (const auto& [recordId, record] : runtime->commonjs_records) {
    if (record.graph_generation == graphGeneration &&
        record.adapter_record_id == adapterRecordId) {
      return recordId;
    }
  }
  return 0;
}

facebook::jsi::Value requireEsmRecord(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t recordId,
    bool synchronousEligible) {
  if (!synchronousEligible) {
    throw facebook::jsi::JSError(
        rt,
        "ERR_REQUIRE_ASYNC_MODULE: require() target graph contains top-level await");
  }

  std::set<uint64_t> visiting;
  std::set<uint64_t> visited;
  std::vector<uint64_t> order;
  collectDynamicEvaluationOrder(
      runtime, graphGeneration, recordId, visiting, visited, order);

  // Refuse every async/cyclic/incomplete closure before starting a new body.
  // Literal require edges are linked eagerly, but their records remain lazy
  // until this reached invocation.
  // @ref LLP 0027#esmcommonjs-interop-matrix
  for (uint64_t memberId : order) {
    auto found = runtime->module_records.find(memberId);
    if (found == runtime->module_records.end() ||
        found->second.graph_generation != graphGeneration) {
      throw facebook::jsi::JSError(
          rt, "CommonJS require ESM closure contains a stale record");
    }
    auto& member = found->second;
    if (member.state == NativeModuleRecordState::Errored) {
      throw facebook::jsi::JSError(
          rt,
          member.error_message.empty() ? "module record is errored"
                                       : member.error_message);
    }
    if (member.state == NativeModuleRecordState::Evaluating) {
      throw facebook::jsi::JSError(
          rt,
          "ERR_REQUIRE_CYCLE_MODULE: require() encountered an evaluating ES module");
    }
    if (member.state == NativeModuleRecordState::Instantiated) {
      const uint64_t ownerId =
          commonJsOwnerForAdapter(runtime, graphGeneration, memberId);
      auto owner = runtime->commonjs_records.find(ownerId);
      if (ownerId == 0 || owner == runtime->commonjs_records.end()) {
        throw facebook::jsi::JSError(
            rt, "CommonJS require ESM closure contains an undeclared record");
      }
      if (owner->second.state == NativeCommonJsRecordState::Evaluating) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_REQUIRE_CYCLE_MODULE: require() encountered an evaluating CommonJS adapter");
      }
      continue;
    }
    if (member.state != NativeModuleRecordState::Declared &&
        member.state != NativeModuleRecordState::Evaluated) {
      throw facebook::jsi::JSError(
          rt, "CommonJS require ESM closure is not ready to evaluate");
    }
  }

  for (uint64_t memberId : order) {
    auto found = runtime->module_records.find(memberId);
    if (found == runtime->module_records.end() ||
        found->second.graph_generation != graphGeneration) {
      throw facebook::jsi::JSError(
          rt, "CommonJS require ESM closure became stale");
    }
    if (found->second.state == NativeModuleRecordState::Evaluated) continue;
    if (found->second.state == NativeModuleRecordState::Instantiated) {
      const uint64_t ownerId =
          commonJsOwnerForAdapter(runtime, graphGeneration, memberId);
      if (ownerId == 0) {
        throw facebook::jsi::JSError(
            rt, "CommonJS require ESM adapter owner became stale");
      }
      evaluateCommonJsRecord(rt, runtime, ownerId);
      auto adapter = runtime->module_records.find(memberId);
      if (adapter == runtime->module_records.end() ||
          adapter->second.state != NativeModuleRecordState::Evaluated) {
        throw facebook::jsi::JSError(
            rt, "CommonJS require ESM adapter did not evaluate");
      }
      continue;
    }

    auto& member = found->second;
    try {
      if (beginRecordExecute(rt, runtime, memberId, member)) {
        member.evaluation_promise.reset();
        rememberRecordError(
            member,
            "ERR_REQUIRE_ASYNC_MODULE: synchronous artifact returned a promise");
        throw facebook::jsi::JSError(
            rt,
            "ERR_REQUIRE_ASYNC_MODULE: synchronous artifact returned a promise");
      }
    } catch (const facebook::jsi::JSError& error) {
      if (member.state != NativeModuleRecordState::Errored) {
        rememberRecordError(
            member,
            "module evaluation threw",
            exactRetainStructuredModuleGraphError(runtime, error));
      }
      throw;
    } catch (const std::exception& error) {
      rememberRecordError(member, error.what());
      throw;
    } catch (...) {
      rememberRecordError(member, "unknown module evaluation failure");
      throw;
    }
  }

  auto found = runtime->module_records.find(recordId);
  if (found == runtime->module_records.end() ||
      found->second.graph_generation != graphGeneration ||
      found->second.state != NativeModuleRecordState::Evaluated) {
    throw facebook::jsi::JSError(
        rt, "CommonJS require ESM target did not evaluate synchronously");
  }
  auto& record = found->second;
  if (record.export_cells.count("module.exports") != 0) {
    return readBinding(rt, runtime, recordId, record, "module.exports");
  }
  if (record.source_goal == 2) {
    return readBinding(rt, runtime, recordId, record, "default");
  }
  if (!record.namespace_object) {
    throw facebook::jsi::JSError(rt, "required ES module namespace is unavailable");
  }
  if (record.export_cells.count("default") == 0) {
    return facebook::jsi::Value(rt, *record.namespace_object);
  }

  // Node's synchronous require(ESM) surface adds the compatibility marker
  // when a default export is present. The module has completed evaluation, so
  // this deterministic snapshot cannot expose partially initialized cells.
  facebook::jsi::Object result(rt);
  for (const auto& [name, cell] : record.export_cells) {
    (void)cell;
    result.setProperty(
        rt,
        moduleExportPropertyName(rt, name),
        readBinding(rt, runtime, recordId, record, name));
  }
  result.setProperty(rt, "__esModule", true);
  return result;
}

bool dynamicRecordReaches(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t fromRecordId,
    uint64_t targetRecordId,
    std::set<uint64_t>& visited) {
  if (fromRecordId == targetRecordId) return true;
  if (!visited.insert(fromRecordId).second) return false;
  auto record = runtime->module_records.find(fromRecordId);
  if (record == runtime->module_records.end() ||
      record->second.graph_generation != graphGeneration) {
    throw std::runtime_error("dynamic import graph contains a stale record");
  }
  for (uint64_t dependency : record->second.evaluation_dependencies) {
    if (dynamicRecordReaches(
            runtime,
            graphGeneration,
            dependency,
            targetRecordId,
            visited)) {
      return true;
    }
  }
  return false;
}

std::vector<std::vector<uint64_t>> dynamicEvaluationSccs(
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    const std::vector<uint64_t>& evaluationOrder) {
  std::set<uint64_t> assigned;
  std::vector<std::vector<uint64_t>> components;
  for (uint64_t root : evaluationOrder) {
    if (assigned.count(root) != 0) continue;
    std::vector<uint64_t> component;
    for (uint64_t candidate : evaluationOrder) {
      if (assigned.count(candidate) != 0) continue;
      std::set<uint64_t> forwardVisited;
      std::set<uint64_t> reverseVisited;
      if (dynamicRecordReaches(
              runtime,
              graphGeneration,
              root,
              candidate,
              forwardVisited) &&
          dynamicRecordReaches(
              runtime,
              graphGeneration,
              candidate,
              root,
              reverseVisited)) {
        component.push_back(candidate);
      }
    }
    for (uint64_t member : component) assigned.insert(member);
    components.push_back(std::move(component));
  }
  return components;
}

void evaluateSynchronousRequiredEsm(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t targetRecordId) {
  std::set<uint64_t> visiting;
  std::set<uint64_t> visited;
  std::vector<uint64_t> order;
  collectDynamicEvaluationOrder(
      runtime,
      graphGeneration,
      targetRecordId,
      visiting,
      visited,
      order);
  for (uint64_t recordId : order) {
    auto commonjs = std::find_if(
        runtime->commonjs_records.begin(),
        runtime->commonjs_records.end(),
        [recordId](const auto& entry) {
          return entry.second.adapter_record_id == recordId;
        });
    if (commonjs != runtime->commonjs_records.end()) {
      if (commonjs->second.graph_generation != graphGeneration ||
          !commonjs->second.published) {
        throw facebook::jsi::JSError(
            rt, "CommonJS require ESM closure contains a stale CJS adapter");
      }
      if (commonjs->second.state == NativeCommonJsRecordState::Evaluating) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_REQUIRE_CYCLE_MODULE: require() encountered a CommonJS/ESM cycle");
      }
      evaluateCommonJsRecord(rt, runtime, commonjs->first);
      auto adapter = runtime->module_records.find(recordId);
      if (adapter == runtime->module_records.end() ||
          adapter->second.graph_generation != graphGeneration ||
          adapter->second.state != NativeModuleRecordState::Evaluated) {
        throw facebook::jsi::JSError(
            rt, "CommonJS require ESM dependency adapter did not evaluate");
      }
      continue;
    }
    auto found = runtime->module_records.find(recordId);
    if (found == runtime->module_records.end() ||
        found->second.graph_generation != graphGeneration ||
        !found->second.published) {
      throw facebook::jsi::JSError(
          rt, "CommonJS require ESM closure contains a stale record");
    }
    auto& record = found->second;
    if (record.state == NativeModuleRecordState::Evaluated) continue;
    if (record.state == NativeModuleRecordState::Errored) {
      throw facebook::jsi::JSError(
          rt,
          record.error_message.empty() ? "module record is errored"
                                       : record.error_message);
    }
    if (record.state == NativeModuleRecordState::Evaluating) {
      throw facebook::jsi::JSError(
          rt,
          "ERR_REQUIRE_CYCLE_MODULE: require() encountered an evaluating ES module");
    }
    try {
      if (beginRecordExecute(rt, runtime, recordId, record)) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_REQUIRE_ASYNC_MODULE: require() target graph is asynchronous");
      }
    } catch (const facebook::jsi::JSError& error) {
      rememberRecordError(
          record,
          "required ES module evaluation threw",
          exactRetainStructuredModuleGraphError(runtime, error));
      throw;
    } catch (const std::exception& error) {
      rememberRecordError(record, error.what());
      throw;
    } catch (...) {
      rememberRecordError(
          record, "unknown required ES module evaluation failure");
      throw;
    }
  }
}

facebook::jsi::Object appendPromiseThen(
    facebook::jsi::Runtime& rt,
    facebook::jsi::Object chain,
    facebook::jsi::Function fulfilled) {
  auto then = chain.getPropertyAsFunction(rt, "then");
  auto next = then.callWithThis(rt, chain, fulfilled);
  if (!next.isObject()) {
    throw facebook::jsi::JSError(rt, "Promise.then did not return an object");
  }
  return next.asObject(rt);
}

facebook::jsi::Value rejectedPromise(
    facebook::jsi::Runtime& rt, const std::string& message) {
  auto promiseConstructor = rt.global().getPropertyAsObject(rt, "Promise");
  auto reject = promiseConstructor.getPropertyAsFunction(rt, "reject");
  return reject.callWithThis(
      rt, promiseConstructor, facebook::jsi::JSError(rt, message).value());
}

facebook::jsi::Object pendingDynamicActivationPromise(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t requesterRecordId,
    bool requesterIsCommonJs,
    const std::string& requesterSourceId,
    bool computed,
    uint32_t site,
    const std::string& specifier) {
  constexpr size_t kMaximumPendingDynamicActivations = 1024;
  if (runtime->module_dynamic_activation_requests.size() >=
      kMaximumPendingDynamicActivations) {
    throw facebook::jsi::JSError(
        rt, "dynamic module activation request budget exhausted");
  }
  const uint64_t requestId =
      runtime->next_module_dynamic_activation_request_id++;
  if (requestId == 0 ||
      runtime->next_module_dynamic_activation_request_id == 0) {
    throw facebook::jsi::JSError(
        rt, "dynamic module activation request id space exhausted");
  }

  const auto target = exactRuntimeCallbackTarget(runtime);
  auto executor = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(
          rt, "dynamicModuleActivationExecutor"),
      2,
      [target,
       requestId,
       graphGeneration,
       requesterRecordId,
       requesterIsCommonJs,
       requesterSourceId,
       computed,
       site,
       specifier](
          facebook::jsi::Runtime& rt,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        if (!runtimeIsAlive(target) ||
            target.runtime->runtime_thread != std::this_thread::get_id()) {
          throw facebook::jsi::JSError(
              rt, "stale dynamic module activation executor");
        }
        if (count < 2 || !args[0].isObject() ||
            !args[0].asObject(rt).isFunction(rt) || !args[1].isObject() ||
            !args[1].asObject(rt).isFunction(rt)) {
          throw facebook::jsi::JSError(
              rt, "malformed dynamic module activation executor");
        }
        NativeModuleDynamicActivationEntry entry;
        entry.graph_generation = graphGeneration;
        entry.requester_record_id = requesterRecordId;
        entry.requester_is_commonjs = requesterIsCommonJs;
        entry.computed = computed;
        entry.site = site;
        entry.requester_source_id = requesterSourceId;
        entry.specifier = specifier;
        entry.resolve = std::make_shared<facebook::jsi::Function>(
            args[0].asObject(rt).asFunction(rt));
        entry.reject = std::make_shared<facebook::jsi::Function>(
            args[1].asObject(rt).asFunction(rt));
        if (!target.runtime->module_dynamic_activation_requests
                 .emplace(requestId, std::move(entry))
                 .second) {
          throw facebook::jsi::JSError(
              rt, "duplicate dynamic module activation request");
        }
        target.runtime->module_dynamic_activation_queue.push_back(requestId);
        return facebook::jsi::Value::undefined();
      });
  auto promiseConstructor =
      rt.global().getPropertyAsFunction(rt, "Promise");
  auto promise =
      promiseConstructor.callAsConstructor(rt, executor);
  if (!promise.isObject() ||
      runtime->module_dynamic_activation_requests.count(requestId) != 1) {
    runtime->module_dynamic_activation_requests.erase(requestId);
    throw facebook::jsi::JSError(
        rt, "dynamic module activation Promise did not initialize");
  }
  return promise.asObject(rt);
}

facebook::jsi::Object dynamicEvaluationPromise(
    facebook::jsi::Runtime& rt,
    ExactHermesRuntime* runtime,
    uint64_t graphGeneration,
    uint64_t requesterRecordId,
    uint64_t targetRecordId) {
  auto promiseConstructor = rt.global().getPropertyAsObject(rt, "Promise");
  auto resolve = promiseConstructor.getPropertyAsFunction(rt, "resolve");
  auto targetResolution =
      resolveLiveModuleRecord(runtime, graphGeneration, targetRecordId);
  if (targetResolution.record == nullptr) {
    throw facebook::jsi::JSError(rt, "stale dynamic import target");
  }
  targetRecordId = targetResolution.record_id;
  auto* targetRecord = targetResolution.record;
  // A link-time dynamic-import binding may target the ESM adapter of a
  // CommonJS record that has never evaluated (a dynamic-only member of a
  // fully-linked prepared graph — the LLP 0413 Phase 2 committed shape).
  // The adapter sits in Instantiated state until finalizeCommonJsAdapter
  // runs, so the ESM state machine below cannot drive it. Mirror the
  // require()-of-ESM-closure path: evaluate the backing CommonJS record
  // lazily through a chained promise step (ordered after the current job),
  // which finalizes the adapter to Evaluated for the namespace step.
  if (targetRecord->state == NativeModuleRecordState::Instantiated) {
    auto backing = std::find_if(
        runtime->commonjs_records.begin(),
        runtime->commonjs_records.end(),
        [targetRecordId](const auto& entry) {
          return entry.second.adapter_record_id == targetRecordId;
        });
    if (backing != runtime->commonjs_records.end()) {
      if (backing->second.graph_generation != graphGeneration) {
        throw facebook::jsi::JSError(
            rt, "stale CommonJS dynamic import adapter");
      }
      if (backing->second.state == NativeCommonJsRecordState::Evaluating) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_ASYNC_MODULE_CYCLE: dynamic import re-enters an evaluating "
            "CommonJS module");
      }
      const uint64_t backingRecordId = backing->first;
      const auto callbackTarget = exactRuntimeCallbackTarget(runtime);
      auto initialValue = resolve.callWithThis(
          rt, promiseConstructor, facebook::jsi::Value::undefined());
      if (!initialValue.isObject()) {
        throw facebook::jsi::JSError(
            rt, "Promise operation did not return an object");
      }
      auto evaluateStep = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(
              rt, "dynamicCommonJsAdapterEvaluation"),
          0,
          [callbackTarget, graphGeneration, backingRecordId](
              facebook::jsi::Runtime& rt,
              const facebook::jsi::Value&,
              const facebook::jsi::Value*,
              size_t) -> facebook::jsi::Value {
            if (!runtimeIsAlive(callbackTarget) ||
                callbackTarget.runtime->runtime_thread !=
                    std::this_thread::get_id()) {
              throw facebook::jsi::JSError(
                  rt, "stale CommonJS dynamic import evaluation");
            }
            auto current = callbackTarget.runtime->commonjs_records.find(
                backingRecordId);
            if (current == callbackTarget.runtime->commonjs_records.end() ||
                current->second.graph_generation != graphGeneration) {
              throw facebook::jsi::JSError(
                  rt, "stale CommonJS dynamic import evaluation owner");
            }
            if (current->second.state ==
                NativeCommonJsRecordState::Evaluating) {
              throw facebook::jsi::JSError(
                  rt,
                  "ERR_ASYNC_MODULE_CYCLE: dynamic import re-enters an "
                  "evaluating CommonJS module");
            }
            evaluateCommonJsRecord(rt, callbackTarget.runtime, backingRecordId);
            return facebook::jsi::Value::undefined();
          });
      auto chained = appendPromiseThen(
          rt, initialValue.asObject(rt), std::move(evaluateStep));
      auto namespaceStep = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(
              rt, "dynamicCommonJsAdapterNamespace"),
          0,
          [callbackTarget, graphGeneration, targetRecordId](
              facebook::jsi::Runtime& rt,
              const facebook::jsi::Value&,
              const facebook::jsi::Value*,
              size_t) -> facebook::jsi::Value {
            if (!runtimeIsAlive(callbackTarget) ||
                callbackTarget.runtime->runtime_thread !=
                    std::this_thread::get_id()) {
              throw facebook::jsi::JSError(
                  rt, "stale CommonJS dynamic import namespace");
            }
            auto resolved = resolveLiveModuleRecord(
                callbackTarget.runtime, graphGeneration, targetRecordId);
            auto* record = resolved.record == nullptr
                ? nullptr
                : callbackRecordFor(
                      callbackTarget, graphGeneration, resolved.record_id);
            if (record == nullptr || !record->namespace_object ||
                record->state != NativeModuleRecordState::Evaluated) {
              throw facebook::jsi::JSError(
                  rt, "dynamic import target did not evaluate");
            }
            return facebook::jsi::Value(rt, *record->namespace_object);
          });
      return appendPromiseThen(rt, std::move(chained), std::move(namespaceStep));
    }
  }
  facebook::jsi::Value initial;
  bool needsEvaluation = false;
  switch (targetRecord->state) {
    case NativeModuleRecordState::Evaluating:
      if (!targetRecord->evaluation_promise) {
        throw facebook::jsi::JSError(
            rt, "async module has no retained evaluation promise");
      }
      initial = resolve.callWithThis(
          rt,
          promiseConstructor,
          facebook::jsi::Value(rt, *targetRecord->evaluation_promise));
      break;
    case NativeModuleRecordState::Evaluated:
      initial = resolve.callWithThis(
          rt, promiseConstructor, facebook::jsi::Value::undefined());
      break;
    case NativeModuleRecordState::Errored: {
      auto reject = promiseConstructor.getPropertyAsFunction(rt, "reject");
      initial = reject.callWithThis(
          rt,
          promiseConstructor,
          facebook::jsi::JSError(
              rt,
              targetRecord->error_message.empty()
                  ? "module record is errored"
                  : targetRecord->error_message)
              .value());
      break;
    }
    case NativeModuleRecordState::Declared:
      needsEvaluation = true;
      initial = resolve.callWithThis(
          rt, promiseConstructor, facebook::jsi::Value::undefined());
      break;
    default:
      throw facebook::jsi::JSError(
          rt, "dynamic import target is not linked and declared");
  }
  if (!initial.isObject()) {
    throw facebook::jsi::JSError(rt, "Promise operation did not return an object");
  }
  auto chain = initial.asObject(rt);
  std::vector<uint64_t> order;
  std::vector<std::vector<uint64_t>> components;
  if (needsEvaluation) {
    std::set<uint64_t> visiting;
    std::set<uint64_t> visited;
    collectDynamicEvaluationOrder(
        runtime,
        graphGeneration,
        targetRecordId,
        visiting,
        visited,
        order);
    for (uint64_t recordId : order) {
      if (recordId == requesterRecordId) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_ASYNC_MODULE_CYCLE: dynamic target statically re-enters its requester");
      }
      auto record = runtime->module_records.find(recordId);
      if (record != runtime->module_records.end() &&
          recordId != targetRecordId &&
          record->second.state == NativeModuleRecordState::Evaluating) {
        throw facebook::jsi::JSError(
            rt,
            "ERR_ASYNC_MODULE_CYCLE: dynamic target overlaps an evaluating dependency");
      }
    }
    components = dynamicEvaluationSccs(runtime, graphGeneration, order);
  }
  const auto target = exactRuntimeCallbackTarget(runtime);
  for (auto component : components) {
    auto step = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "dynamicModuleEvaluationScc"),
        0,
        [target, graphGeneration, component = std::move(component)](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value*,
            size_t) -> facebook::jsi::Value {
          facebook::jsi::Array pending(rt, component.size());
          size_t pendingCount = 0;
          for (uint64_t recordId : component) {
            auto* record =
                callbackRecordFor(target, graphGeneration, recordId);
            if (record == nullptr) {
              throw facebook::jsi::JSError(rt, "stale dynamic import record");
            }
            if (record->state == NativeModuleRecordState::Errored) {
              throw facebook::jsi::JSError(
                  rt,
                  record->error_message.empty() ? "module record is errored"
                                                : record->error_message);
            }
            bool asynchronous = false;
            try {
              asynchronous =
                  beginRecordExecute(rt, target.runtime, recordId, *record);
            } catch (const facebook::jsi::JSError& error) {
              rememberRecordError(
                  *record,
                  "dynamic module evaluation threw",
                  exactRetainStructuredModuleGraphError(
                      target.runtime, error));
              throw;
            } catch (const std::exception& error) {
              rememberRecordError(*record, error.what());
              throw;
            } catch (...) {
              rememberRecordError(
                  *record, "unknown dynamic module evaluation failure");
              throw;
            }
            if (asynchronous) {
              if (!record->evaluation_promise) {
                throw facebook::jsi::JSError(
                    rt, "async module has no retained evaluation promise");
              }
              pending.setValueAtIndex(
                  rt,
                  pendingCount++,
                  facebook::jsi::Value(rt, *record->evaluation_promise));
            }
          }
          if (pendingCount == 0) return facebook::jsi::Value::undefined();
          auto promises = facebook::jsi::Array(rt, pendingCount);
          for (size_t index = 0; index < pendingCount; ++index) {
            promises.setValueAtIndex(
                rt, index, pending.getValueAtIndex(rt, index));
          }
          auto promiseConstructor =
              rt.global().getPropertyAsObject(rt, "Promise");
          auto all = promiseConstructor.getPropertyAsFunction(rt, "all");
          return all.callWithThis(rt, promiseConstructor, promises);
        });
    chain = appendPromiseThen(rt, std::move(chain), std::move(step));
  }
  auto namespaceStep = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "dynamicModuleNamespace"),
      0,
      [target, graphGeneration, targetRecordId](
          facebook::jsi::Runtime& rt,
          const facebook::jsi::Value&,
          const facebook::jsi::Value*,
          size_t) -> facebook::jsi::Value {
        if (!runtimeIsAlive(target) ||
            target.runtime->runtime_thread != std::this_thread::get_id()) {
          throw facebook::jsi::JSError(
              rt, "stale dynamic import namespace");
        }
        auto resolved = resolveLiveModuleRecord(
            target.runtime, graphGeneration, targetRecordId);
        auto* record = resolved.record == nullptr
            ? nullptr
            : callbackRecordFor(
                  target, graphGeneration, resolved.record_id);
        if (record == nullptr || !record->namespace_object ||
            record->state != NativeModuleRecordState::Evaluated) {
          throw facebook::jsi::JSError(
              rt, "dynamic import target did not evaluate");
        }
        return facebook::jsi::Value(rt, *record->namespace_object);
      });
  return appendPromiseThen(rt, std::move(chain), std::move(namespaceStep));
}

}  // namespace

// @abi-output ex_hermes_module_compile_factory out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_compile_factory out_error_token role=output kind=scalar ownership=caller-storage
#ifdef IBEX_CAPSEC_CONFORMANCE_OBSERVER
extern "C" void ibex_test_begin_module_runner_abi_observation() {
  moduleRunnerAbiObservations.clear();
}

extern "C" char* ibex_test_take_module_runner_abi_observation() {
  std::string json = "[";
  bool first = true;
  for (const auto& name : moduleRunnerAbiObservations) {
    if (!first) json += ',';
    first = false;
    json += '"';
    json += name;
    json += '"';
  }
  json += ']';
  moduleRunnerAbiObservations.clear();
  auto* result = static_cast<char*>(std::malloc(json.size() + 1));
  if (result == nullptr) return nullptr;
  std::memcpy(result, json.data(), json.size());
  result[json.size()] = '\0';
  return result;
}
#endif
extern "C" int32_t ex_hermes_module_compile_factory(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint32_t source_goal,
    uint32_t principal_id,
    uint64_t graph_generation,
    const uint8_t* compartment_identity,
    size_t compartment_identity_len,
    const uint8_t* semantic_digest,
    size_t semantic_digest_len,
    const uint8_t* source_id,
    size_t source_id_len,
    const uint8_t* factory_source,
    size_t factory_source_len,
    const uint8_t* source_label,
    size_t source_label_len,
    ExactModuleRunnerHandle* out_factory,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  if (out_factory) *out_factory = ExactModuleRunnerHandle{{0, 0, 0}};

  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!commonJsRequireMutationTargetsGeneration(
          runtime, graph_generation)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(out_error,
               "module factory compile refused before embedder "
               "capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (runtime_nonce == 0 || graph_generation == 0 || source_goal > 3 ||
      out_factory == nullptr ||
      semantic_digest == nullptr || factory_source == nullptr ||
      source_id == nullptr || source_id_len == 0 || factory_source_len == 0 ||
      source_label == nullptr ||
      (compartment_identity_len != 0 && compartment_identity == nullptr)) {
    writeError(out_error, "module factory compile received invalid input");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (!runtime->module_function_constructor ||
      !runtime->module_compartment_binder) {
    writeError(out_error, "native module evaluator capability is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  const std::string digest(
      reinterpret_cast<const char*>(semantic_digest), semantic_digest_len);
  if (!validDigest(digest)) {
    writeError(out_error, "module artifact semantic digest is not canonical");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string compartment(
      reinterpret_cast<const char*>(compartment_identity),
      compartment_identity_len);
  if (principal_id != 0 && compartment.empty()) {
    writeError(out_error, "non-root module factory requires a compartment identity");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "module factory host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  ScopedRuntimeSecurityContext securityContext(runtime);
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  ScopedActiveAttributionRuntime activeAttributionRuntime(
      runtime->attribution_runtime);
#endif

  uint64_t pendingErrorToken = 0;
  std::string pendingError;
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Object targetCompartment(rt);
    bool bindCompartment = !compartment.empty();
    if (bindCompartment) {
      targetCompartment = compartmentFor(rt, compartment);
    }

#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime == nullptr) {
      throw facebook::jsi::JSError(rt, "module factory attribution VM is unavailable");
    }
    ex_hermes_vm_set_pending_package_id(runtime->attribution_runtime, principal_id);
#else
    if (principal_id != 0 || bindCompartment) {
      throw facebook::jsi::JSError(
          rt, "non-root module factory requires the attributed Hermes build");
    }
#endif

    // The first compilation creates a tiny trusted trampoline stamped with the
    // authenticated principal. Binding its Domain to the authenticated
    // compartment before invocation makes Hermes patch 0006 carry both values
    // into the actual Function compilation. The package factory's Domain is
    // therefore selected before its bytes are compiled, not repaired later.
    static const char* kTrampolineBody =
        "\"use strict\";return function(__ibexCtor,__ibexSource,__ibexLabel){"
        "return __ibexCtor(\"\\\"use strict\\\";return (\"+__ibexSource+"
        "\");\\n//# sourceURL=\"+__ibexLabel)();};";
    auto trampolineConstructorValue = runtime->module_function_constructor->call(
        rt, facebook::jsi::String::createFromUtf8(rt, kTrampolineBody));
    if (!trampolineConstructorValue.isObject() ||
        !trampolineConstructorValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(
          rt, "module compiler did not return a trampoline constructor");
    }
    auto trampolineValue =
        trampolineConstructorValue.asObject(rt).asFunction(rt).call(rt);
    if (!trampolineValue.isObject() ||
        !trampolineValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(rt, "module compiler did not create a trampoline");
    }
    auto trampoline = trampolineValue.asObject(rt).asFunction(rt);
    if (bindCompartment) {
      runtime->module_compartment_binder->call(
          rt, trampoline, targetCompartment);
    }

    const std::string source(
        reinterpret_cast<const char*>(factory_source), factory_source_len);
    const std::string label = safeSourceLabel(source_label, source_label_len);
    auto factoryValue = trampoline.call(
        rt,
        *runtime->module_function_constructor,
        facebook::jsi::String::createFromUtf8(rt, source),
        facebook::jsi::String::createFromUtf8(rt, label));
    if (!factoryValue.isObject() || !factoryValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(rt, "module artifact did not compile to a factory");
    }

    uint64_t id = nextHandleId(runtime);
    ModuleFactoryEntry entry;
    entry.graph_generation = graph_generation;
    entry.source_goal = static_cast<uint8_t>(source_goal);
    entry.principal_id = principal_id;
    entry.compartment_identity = compartment;
    entry.semantic_digest = digest;
    entry.source_id.assign(
        reinterpret_cast<const char*>(source_id), source_id_len);
    entry.factory = std::make_shared<facebook::jsi::Function>(
        factoryValue.asObject(rt).asFunction(rt));
    runtime->module_factories.emplace(id, std::move(entry));
    if (!hostTask.finish()) {
      runtime->module_factories.erase(id);
      writeError(out_error, "module factory host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    out_factory->opaque[0] = runtime_nonce;
    out_factory->opaque[1] = graph_generation;
    out_factory->opaque[2] = id;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    pendingErrorToken = exactRetainStructuredModuleGraphError(runtime, error);
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    pendingError = "module factory compilation threw";
  } catch (const std::exception& error) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    pendingError = error.what();
  } catch (...) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    pendingError = "unknown module factory compilation failure";
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module factory host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  if (out_error_token) *out_error_token = pendingErrorToken;
  writeError(out_error, pendingError);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

// Carrier bytes have already passed Rust manifest, digest, producer, graph,
// principal, and engine admission. Native code evaluates the authenticated
// per-principal table and selects exactly one original-module factory.
// @ref LLP 0026#9-production-artifacts-and-bytecode
// @abi-output ex_hermes_module_load_carrier_factory out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_load_carrier_factory out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_load_carrier_factory(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint32_t source_goal,
    uint32_t principal_id,
    uint64_t graph_generation,
    const uint8_t* compartment_identity,
    size_t compartment_identity_len,
    const uint8_t* semantic_digest,
    size_t semantic_digest_len,
    const uint8_t* source_id,
    size_t source_id_len,
    const uint8_t* carrier_digest,
    size_t carrier_digest_len,
    const uint8_t* carrier_bytes,
    size_t carrier_bytes_len,
    uint32_t carrier_encoding,
    const uint8_t* entry_id,
    size_t entry_id_len,
    const uint8_t* source_label,
    size_t source_label_len,
    ExactModuleRunnerHandle* out_factory,
    char** out_error,
    uint64_t* out_error_token) {
  if (out_error_token) *out_error_token = 0;
  observeModuleRunnerAbi(__func__);
  if (out_error) *out_error = nullptr;
  if (out_factory) *out_factory = ExactModuleRunnerHandle{{0, 0, 0}};

  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!commonJsRequireMutationTargetsGeneration(
          runtime, graph_generation)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "module carrier load refused before embedder capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (runtime_nonce == 0 || graph_generation == 0 || source_goal > 3 ||
      carrier_encoding > 1 || out_factory == nullptr ||
      semantic_digest == nullptr || source_id == nullptr || source_id_len == 0 ||
      carrier_digest == nullptr ||
      carrier_bytes == nullptr || carrier_bytes_len == 0 || entry_id == nullptr ||
      entry_id_len == 0 || source_label == nullptr ||
      (compartment_identity_len != 0 && compartment_identity == nullptr)) {
    writeError(out_error, "prepared carrier load received invalid input");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (!runtime->module_compartment_binder) {
    writeError(out_error, "native module compartment binder is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  const std::string digest(
      reinterpret_cast<const char*>(semantic_digest), semantic_digest_len);
  if (!validDigest(digest)) {
    writeError(out_error, "module artifact semantic digest is not canonical");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string admittedCarrierDigest(
      reinterpret_cast<const char*>(carrier_digest), carrier_digest_len);
  if (!validDigest(admittedCarrierDigest)) {
    writeError(out_error, "prepared carrier digest is not canonical");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string compartment(
      reinterpret_cast<const char*>(compartment_identity),
      compartment_identity_len);
  if (principal_id != 0 && compartment.empty()) {
    writeError(out_error, "non-root module factory requires a compartment identity");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "module carrier host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  ScopedRuntimeSecurityContext securityContext(runtime);
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  ScopedActiveAttributionRuntime activeAttributionRuntime(
      runtime->attribution_runtime);
#endif

  uint64_t pendingErrorToken = 0;
  std::string pendingError;
  try {
    auto& rt = *runtime->runtime;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime == nullptr) {
      throw facebook::jsi::JSError(
          rt, "prepared carrier attribution VM is unavailable");
    }
    ex_hermes_vm_set_pending_package_id(runtime->attribution_runtime, principal_id);
#else
    if (principal_id != 0 || !compartment.empty()) {
      throw facebook::jsi::JSError(
          rt, "non-root prepared carrier requires the attributed Hermes build");
    }
#endif

    const auto cacheKey =
        std::make_tuple(principal_id, compartment, admittedCarrierDigest);
    std::shared_ptr<facebook::jsi::Object> table;
    auto cached = runtime->prepared_carrier_tables.find(cacheKey);
    if (cached != runtime->prepared_carrier_tables.end()) {
      table = cached->second;
    } else {
      std::shared_ptr<facebook::jsi::Buffer> buffer;
      if (carrier_encoding == 1) {
        buffer = std::make_shared<CarrierAlignedBytecodeBuffer>(
            carrier_bytes, carrier_bytes_len);
        std::string reason;
        if (!carrierBytecodeSanityCheck(carrier_bytes, carrier_bytes_len, reason)) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
          ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
#endif
          if (!hostTask.finish()) {
            writeError(out_error, "module carrier host-task checkpoint failed");
            return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
          }
          writeError(out_error, "Bytecode sanity check failed: " + reason);
          return 2;
        }
      } else {
        buffer = std::make_shared<CarrierMemoryBuffer>(
            carrier_bytes, carrier_bytes_len);
      }

      const std::string label = safeSourceLabel(source_label, source_label_len);
      auto tableValue = rt.evaluateJavaScript(buffer, label);
      if (!tableValue.isObject()) {
        throw facebook::jsi::JSError(
            rt, "prepared carrier did not evaluate to a factory table");
      }
      table = std::make_shared<facebook::jsi::Object>(tableValue.asObject(rt));
      runtime->prepared_carrier_tables.emplace(cacheKey, table);
    }
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
#endif
    const std::string entry(
        reinterpret_cast<const char*>(entry_id), entry_id_len);
    auto property = facebook::jsi::PropNameID::forUtf8(rt, entry);
    if (!table->hasProperty(rt, property)) {
      throw facebook::jsi::JSError(rt, "prepared carrier entry is absent");
    }
    auto factoryValue = table->getProperty(rt, property);
    if (!factoryValue.isObject() ||
        !factoryValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(
          rt, "prepared carrier entry is not a module factory");
    }
    auto factory = factoryValue.asObject(rt).asFunction(rt);
    if (!compartment.empty()) {
      auto targetCompartment = compartmentFor(rt, compartment);
      runtime->module_compartment_binder->call(
          rt, factory, targetCompartment);
    }

    const uint64_t id = nextHandleId(runtime);
    ModuleFactoryEntry stored;
    stored.graph_generation = graph_generation;
    stored.source_goal = static_cast<uint8_t>(source_goal);
    stored.principal_id = principal_id;
    stored.compartment_identity = compartment;
    stored.semantic_digest = digest;
    stored.source_id.assign(
        reinterpret_cast<const char*>(source_id), source_id_len);
    stored.factory = std::make_shared<facebook::jsi::Function>(
        std::move(factory));
    runtime->module_factories.emplace(id, std::move(stored));
    if (!hostTask.finish()) {
      runtime->module_factories.erase(id);
      writeError(out_error, "module carrier host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    out_factory->opaque[0] = runtime_nonce;
    out_factory->opaque[1] = graph_generation;
    out_factory->opaque[2] = id;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    pendingErrorToken = exactRetainStructuredModuleGraphError(runtime, error);
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    // Keep the engine-side reason: the generic label hid real load faults
    // (e.g. the unattributed-build compartment refusal) behind an
    // application-shaped message (LLP 0413 Phase 2 integration finding).
    pendingError = "prepared module factory load threw: " + error.getMessage();
  } catch (const std::exception& error) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    pendingError = error.what();
  } catch (...) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    pendingError = "unknown prepared carrier load failure";
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module carrier host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  if (out_error_token) *out_error_token = pendingErrorToken;
  writeError(out_error, pendingError);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

// Bulk envelope admission invokes this for every HBC carrier before any table
// is evaluated. Header inspection remains in Rust; this check uses the exact
// linked Hermes decoder and therefore catches engine-specific structural
// rejection eagerly. @ref LLP 0029#1-command-surface-and-producer-pipeline
// @abi-output ex_hermes_module_preflight_bytecode out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
extern "C" int32_t ex_hermes_module_preflight_bytecode(
    const uint8_t* bytes,
    size_t length,
    char** out_error) {
  observeModuleRunnerAbi(__func__);
  if (out_error) *out_error = nullptr;
  if (bytes == nullptr || length == 0) {
    writeError(out_error, "prepared bytecode preflight received invalid input");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  std::string reason;
  if (!carrierBytecodeSanityCheck(bytes, length, reason)) {
    writeError(out_error, "Bytecode sanity check failed: " + reason);
    return 2;
  }
  return 0;
}

extern "C" int32_t ex_hermes_commonjs_create_record(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle factory,
    ExactModuleRunnerHandle context,
    const uint8_t* source_id,
    size_t source_id_len,
    const uint8_t* filename,
    size_t filename_len,
    const uint8_t* dirname,
    size_t dirname_len,
    ExactModuleRunnerHandle* out_record) {
  observeModuleRunnerAbi(__func__);
  if (out_record) *out_record = ExactModuleRunnerHandle{{0, 0, 0}};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (out_record == nullptr || source_id == nullptr || source_id_len == 0 ||
      filename == nullptr || filename_len == 0 || dirname == nullptr ||
      factory.opaque[0] != runtime_nonce || context.opaque[0] != runtime_nonce ||
      factory.opaque[1] == 0 || factory.opaque[1] != context.opaque[1]) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto factoryIt = runtime->module_factories.find(factory.opaque[2]);
  auto contextIt = runtime->graph_contexts.find(context.opaque[2]);
  if (factoryIt == runtime->module_factories.end() ||
      contextIt == runtime->graph_contexts.end() ||
      (factoryIt->second.source_goal != 1 &&
       factoryIt->second.source_goal != 3) ||
      factoryIt->second.graph_generation != factory.opaque[1] ||
      contextIt->second.graph_generation != context.opaque[1] ||
      factoryIt->second.source_id !=
          std::string(reinterpret_cast<const char*>(source_id), source_id_len) ||
      contextIt->second.references == std::numeric_limits<uint32_t>::max()) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  try {
    auto& rt = *runtime->runtime;
    facebook::jsi::Object initialExports(rt);
    facebook::jsi::Object module(rt);
    module.setProperty(rt, "exports", initialExports);
    NativeCommonJsRecordEntry entry;
    entry.graph_generation = factory.opaque[1];
    entry.source_goal = factoryIt->second.source_goal;
    entry.source_id.assign(
        reinterpret_cast<const char*>(source_id), source_id_len);
    entry.context_handle_id = context.opaque[2];
    entry.factory = factoryIt->second.factory;
    entry.filename.assign(reinterpret_cast<const char*>(filename), filename_len);
    entry.dirname.assign(reinterpret_cast<const char*>(dirname), dirname_len);
    entry.module_object =
        std::make_shared<facebook::jsi::Object>(std::move(module));
    entry.exports_value =
        std::make_shared<facebook::jsi::Value>(rt, initialExports);
    const uint64_t id = nextHandleId(runtime);
    ++contextIt->second.references;
    runtime->commonjs_records.emplace(id, std::move(entry));
    out_record->opaque[0] = runtime_nonce;
    out_record->opaque[1] = factory.opaque[1];
    out_record->opaque[2] = id;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (...) {
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
}

extern "C" int32_t ex_hermes_commonjs_record_declare_export(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* export_name,
    size_t export_name_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New ||
      export_name == nullptr || export_name_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string name(
      reinterpret_cast<const char*>(export_name), export_name_len);
  if (name == "default" || name == "module.exports" ||
      !entry->detected_exports.insert(name).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_link_require(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  auto* target = commonJsRecordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New || specifier == nullptr ||
      specifier_len == 0 ||
      entry->graph_generation != target->graph_generation ||
      (entry->source_goal == 3 && target->source_goal != 3)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string name(
      reinterpret_cast<const char*>(specifier), specifier_len);
  NativeCommonJsRequireBinding binding;
  binding.kind = NativeCommonJsRequireTargetKind::CommonJs;
  binding.record_id = target_record.opaque[2];
  if (!entry->require_bindings.emplace(name, binding).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_link_require_esm(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record,
    int32_t synchronous_eligible) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New || specifier == nullptr ||
      specifier_len == 0 ||
      entry->graph_generation != target->graph_generation ||
      entry->source_goal == 3 ||
      (synchronous_eligible != 0 && synchronous_eligible != 1)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string name(
      reinterpret_cast<const char*>(specifier), specifier_len);
  NativeCommonJsRequireBinding binding;
  binding.kind = NativeCommonJsRequireTargetKind::Esm;
  binding.record_id = target_record.opaque[2];
  binding.esm_synchronous_eligible = synchronous_eligible != 0;
  if (!entry->require_bindings.emplace(name, binding).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_defer_require(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New ||
      entry->source_goal == 3 || specifier == nullptr ||
      specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (entry->require_bindings.count(spelling) != 0 ||
      !entry->deferred_commonjs_requires.insert(spelling).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t
ex_hermes_commonjs_record_link_bootstrap_internal_require(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New ||
      entry->source_goal != 3 || specifier == nullptr || specifier_len == 0 ||
      runtime->module_bootstrap_internal_resolver == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (entry->require_bindings.count(spelling) != 0 ||
      entry->deferred_commonjs_requires.count(spelling) != 0 ||
      !entry->bootstrap_internal_commonjs_requires.insert(spelling).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_set_commonjs_require_provider(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation,
    ExactCommonJsRequireProviderCallback provider,
    void* context) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (graph_generation == 0 || provider == nullptr ||
      context == nullptr ||
      runtime->commonjs_require_provider_call_active ||
      runtime->pinned_module_generations.count(graph_generation) == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  NativeCommonJsRequireProviderEntry entry;
  entry.provider = provider;
  entry.context = context;
  if (!runtime->commonjs_require_providers
           .emplace(graph_generation, entry)
           .second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_clear_commonjs_require_provider(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, true);
  if (!drive) return drive.status();
  if (graph_generation == 0 ||
      (runtime->commonjs_require_provider_call_active &&
       runtime->commonjs_require_provider_call_generation ==
           graph_generation)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  runtime->commonjs_require_providers.erase(graph_generation);
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_link_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New || specifier == nullptr ||
      specifier_len == 0 ||
      entry->graph_generation != target->graph_generation ||
      entry->source_goal == 3) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (!entry->dynamic_import_bindings
           .emplace(spelling, target_record.opaque[2])
           .second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_link_computed_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    uint32_t site,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New || specifier == nullptr ||
      specifier_len == 0 ||
      entry->graph_generation != target->graph_generation) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (!entry->computed_dynamic_import_bindings
           .emplace(std::make_pair(site, spelling), target_record.opaque[2])
           .second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_commonjs_record_defer_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New ||
      entry->source_goal == 3 || specifier == nullptr ||
      specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (entry->dynamic_import_bindings.count(spelling) != 0 ||
      !entry->deferred_dynamic_imports.insert(spelling).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t
ex_hermes_commonjs_record_defer_computed_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    uint32_t site,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeCommonJsRecordState::New ||
      entry->source_goal == 3 || specifier == nullptr ||
      specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const auto key = std::make_pair(
      site,
      std::string(
          reinterpret_cast<const char*>(specifier), specifier_len));
  if (entry->computed_dynamic_import_bindings.count(key) != 0 ||
      !entry->deferred_computed_dynamic_imports.insert(key).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

// @abi-output ex_hermes_commonjs_record_evaluate out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_commonjs_record_evaluate out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_commonjs_record_evaluate(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    int32_t* out_evicted,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_evicted) *out_evicted = 0;
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "CommonJS evaluation refused before embedder capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (out_evicted == nullptr) return EXACT_RUNTIME_DRIVE_INVALID;
  auto* entry = commonJsRecordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  const std::string sourceId = entry->source_id;
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "CommonJS host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  uint64_t pendingErrorToken = 0;
  std::string pendingError;
  try {
    evaluateCommonJsRecord(*runtime->runtime, runtime, record.opaque[2]);
    if (!hostTask.finish()) {
      writeError(out_error, "CommonJS host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    pendingErrorToken = exactRetainStructuredModuleGraphError(runtime, error);
    // Keep the engine-side reason (LLP 0413 Phase 2 integration finding):
    // the retained token names the structured value, but embedders reading
    // only the error string got an application-shaped generic label.
    const auto message = error.getMessage();
    const auto stack = error.getStack();
    pendingError = "CommonJS record evaluation threw in " + sourceId + ": " +
        (stack.empty() ? message : message + "\n" + stack);
  } catch (const std::exception& error) {
    pendingError = error.what();
  } catch (...) {
    pendingError = "unknown CommonJS evaluation failure";
  }
  if (!hostTask.finish()) {
    writeError(out_error, "CommonJS host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  *out_evicted = 1;
  if (out_error_token) *out_error_token = pendingErrorToken;
  writeError(out_error, pendingError);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

// @abi-output ex_hermes_commonjs_record_create_esm_adapter out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_commonjs_record_create_esm_adapter out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_commonjs_record_create_esm_adapter(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    ExactModuleRunnerHandle* out_adapter,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_adapter) *out_adapter = ExactModuleRunnerHandle{{0, 0, 0}};
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "CommonJS adapter creation refused before embedder capability "
        "finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto* commonjs = commonJsRecordFor(runtime, record);
  if (commonjs == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (out_adapter == nullptr ||
      (commonjs->state != NativeCommonJsRecordState::New &&
       commonjs->state != NativeCommonJsRecordState::Evaluated) ||
      commonjs->adapter_record_id != 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto context = runtime->graph_contexts.find(commonjs->context_handle_id);
  if (context == runtime->graph_contexts.end() ||
      context->second.references == std::numeric_limits<uint32_t>::max()) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "CommonJS adapter host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  ExactModuleRunnerHandle pendingAdapter{{0, 0, 0}};
  uint64_t pendingErrorToken = 0;
  std::string pendingError;
  bool created = false;
  try {
    auto& rt = *runtime->runtime;
    NativeModuleRecordEntry adapter;
    adapter.graph_generation = commonjs->graph_generation;
    adapter.source_id = commonjs->source_id;
    adapter.context_handle_id = commonjs->context_handle_id;
    adapter.state = NativeModuleRecordState::Instantiated;
    for (const auto& name : commonjs->detected_exports) {
      NativeModuleBindingCell cell;
      adapter.export_cells.emplace(name, std::move(cell));
    }
    for (const std::string name : {"default", "module.exports"}) {
      NativeModuleBindingCell cell;
      adapter.export_cells.emplace(name, std::move(cell));
    }
    const uint64_t id = nextHandleId(runtime);
    ++context->second.references;
    runtime->module_records.emplace(id, std::move(adapter));
    commonjs->adapter_record_id = id;
    if (commonjs->state == NativeCommonJsRecordState::Evaluated) {
      finalizeCommonJsAdapter(rt, runtime, *commonjs);
    }
    pendingAdapter.opaque[0] = runtime_nonce;
    pendingAdapter.opaque[1] = commonjs->graph_generation;
    pendingAdapter.opaque[2] = id;
    created = true;
  } catch (const facebook::jsi::JSError& error) {
    pendingErrorToken = exactRetainStructuredModuleGraphError(runtime, error);
    pendingError = "CommonJS adapter creation threw";
  } catch (const std::exception& error) {
    pendingError = error.what();
  } catch (...) {
    pendingError = "unknown CommonJS adapter failure";
  }
  if (!hostTask.finish()) {
    writeError(out_error, "CommonJS adapter host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  if (created) {
    *out_adapter = pendingAdapter;
    return EXACT_RUNTIME_DRIVE_OK;
  }
  if (out_error_token) *out_error_token = pendingErrorToken;
  writeError(out_error, pendingError);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

extern "C" int32_t ex_hermes_module_pin_generation(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (graph_generation == 0 ||
      !runtime->pinned_module_generations.insert(graph_generation).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_unpin_generation(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (runtime->commonjs_require_provider_call_active &&
      runtime->commonjs_require_provider_call_generation ==
          graph_generation) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (runtime->pinned_module_generations.erase(graph_generation) != 1) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  runtime->commonjs_require_providers.erase(graph_generation);
  for (auto it =
           runtime->module_dynamic_activation_requests.begin();
       it != runtime->module_dynamic_activation_requests.end();) {
    if (it->second.graph_generation == graph_generation) {
      it = runtime->module_dynamic_activation_requests.erase(it);
    } else {
      ++it;
    }
  }
  runtime->module_dynamic_activation_queue.erase(
      std::remove_if(
          runtime->module_dynamic_activation_queue.begin(),
          runtime->module_dynamic_activation_queue.end(),
          [&](uint64_t requestId) {
            return runtime->module_dynamic_activation_requests.count(
                       requestId) == 0;
          }),
      runtime->module_dynamic_activation_queue.end());
  for (auto slot = runtime->module_source_slots.begin();
       slot != runtime->module_source_slots.end();) {
    if (slot->first.first == graph_generation) {
      slot = runtime->module_source_slots.erase(slot);
    } else {
      ++slot;
    }
  }
  for (auto forwarding = runtime->module_record_forwarding.begin();
       forwarding != runtime->module_record_forwarding.end();) {
    auto target = runtime->module_records.find(forwarding->second);
    if (target == runtime->module_records.end() ||
        target->second.graph_generation == graph_generation) {
      forwarding = runtime->module_record_forwarding.erase(forwarding);
    } else {
      ++forwarding;
    }
  }
  for (auto it = runtime->commonjs_records.begin();
       it != runtime->commonjs_records.end();) {
    if (it->second.graph_generation != graph_generation) {
      ++it;
      continue;
    }
    const uint64_t contextId = it->second.context_handle_id;
    it = runtime->commonjs_records.erase(it);
    releaseContextReference(runtime, contextId);
  }
  for (auto it = runtime->module_records.begin();
       it != runtime->module_records.end();) {
    if (it->second.graph_generation != graph_generation) {
      ++it;
      continue;
    }
    const uint64_t contextId = it->second.context_handle_id;
    it = runtime->module_records.erase(it);
    releaseContextReference(runtime, contextId);
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_release_handle(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle handle) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (handle.opaque[0] != runtime_nonce || handle.opaque[1] == 0 ||
      handle.opaque[2] == 0) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  auto it = runtime->module_factories.find(handle.opaque[2]);
  if (it != runtime->module_factories.end() &&
      it->second.graph_generation == handle.opaque[1]) {
    runtime->module_factories.erase(it);
    return EXACT_RUNTIME_DRIVE_OK;
  }
  auto record = runtime->module_records.find(handle.opaque[2]);
  if (record != runtime->module_records.end() &&
      record->second.graph_generation == handle.opaque[1]) {
    if (runtime->pinned_module_generations.count(handle.opaque[1]) != 0) {
      return EXACT_RUNTIME_DRIVE_OK;
    }
    for (auto& [_, commonjs] : runtime->commonjs_records) {
      if (commonjs.adapter_record_id == handle.opaque[2]) {
        commonjs.adapter_record_id = 0;
        break;
      }
    }
    eraseDynamicActivationsForRequester(
        runtime, handle.opaque[1], handle.opaque[2], false);
    eraseModuleSourceSlotIfOwned(
        runtime,
        handle.opaque[1],
        record->second.source_id,
        handle.opaque[2]);
    releaseContextReference(runtime, record->second.context_handle_id);
    runtime->module_records.erase(record);
    return EXACT_RUNTIME_DRIVE_OK;
  }
  auto commonjs = runtime->commonjs_records.find(handle.opaque[2]);
  if (commonjs != runtime->commonjs_records.end() &&
      commonjs->second.graph_generation == handle.opaque[1]) {
    if (runtime->pinned_module_generations.count(handle.opaque[1]) != 0) {
      return EXACT_RUNTIME_DRIVE_OK;
    }
    eraseDynamicActivationsForRequester(
        runtime, handle.opaque[1], handle.opaque[2], true);
    releaseContextReference(runtime, commonjs->second.context_handle_id);
    runtime->commonjs_records.erase(commonjs);
    return EXACT_RUNTIME_DRIVE_OK;
  }
  auto context = runtime->graph_contexts.find(handle.opaque[2]);
  if (context != runtime->graph_contexts.end() &&
      context->second.graph_generation == handle.opaque[1]) {
    if (--context->second.references == 0) {
      runtime->graph_contexts.erase(context);
    }
    return EXACT_RUNTIME_DRIVE_OK;
  }
  return EXACT_RUNTIME_DRIVE_STALE;
}

extern "C" int32_t ex_hermes_module_publish_records(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    const ExactModuleRunnerHandle* handles,
    size_t handles_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (handles == nullptr || handles_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  try {
    std::set<std::pair<bool, uint64_t>> selected;
    auto sourceSlots = runtime->module_source_slots;
    for (size_t index = 0; index < handles_len; ++index) {
      const auto handle = handles[index];
      if (handle.opaque[0] != runtime_nonce ||
          handle.opaque[1] == 0 || handle.opaque[2] == 0) {
        return EXACT_RUNTIME_DRIVE_STALE;
      }
      auto module = runtime->module_records.find(handle.opaque[2]);
      if (module != runtime->module_records.end() &&
          module->second.graph_generation == handle.opaque[1]) {
        if (module->second.published ||
            module->second.state != NativeModuleRecordState::Declared) {
          return EXACT_RUNTIME_DRIVE_INVALID;
        }
        for (const auto& [_, commonjs] : runtime->commonjs_records) {
          if (commonjs.adapter_record_id == handle.opaque[2]) {
            return EXACT_RUNTIME_DRIVE_INVALID;
          }
        }
        const auto slot =
            std::make_pair(handle.opaque[1], module->second.source_id);
        auto occupied = sourceSlots.find(slot);
        if (occupied != sourceSlots.end() &&
            occupied->second != handle.opaque[2]) {
          return EXACT_RUNTIME_DRIVE_INVALID;
        }
        sourceSlots[slot] = handle.opaque[2];
        if (!selected.emplace(false, handle.opaque[2]).second) {
          return EXACT_RUNTIME_DRIVE_INVALID;
        }
        continue;
      }
      auto commonjs = runtime->commonjs_records.find(handle.opaque[2]);
      if (commonjs == runtime->commonjs_records.end() ||
          commonjs->second.graph_generation != handle.opaque[1]) {
        return EXACT_RUNTIME_DRIVE_STALE;
      }
      auto adapter =
          runtime->module_records.find(commonjs->second.adapter_record_id);
      if (commonjs->second.published ||
          commonjs->second.state != NativeCommonJsRecordState::New ||
          adapter == runtime->module_records.end() ||
          adapter->second.published ||
          adapter->second.graph_generation != handle.opaque[1] ||
          adapter->second.state != NativeModuleRecordState::Instantiated ||
          adapter->second.source_id != commonjs->second.source_id ||
          !selected.emplace(true, handle.opaque[2]).second) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
      const auto slot =
          std::make_pair(handle.opaque[1], commonjs->second.source_id);
      auto occupied = sourceSlots.find(slot);
      if (occupied != sourceSlots.end() &&
          occupied->second != commonjs->second.adapter_record_id) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
      sourceSlots[slot] = commonjs->second.adapter_record_id;
    }
    for (const auto& [isCommonJs, recordId] : selected) {
      if (isCommonJs) {
        auto& commonjs = runtime->commonjs_records.at(recordId);
        runtime->module_records.at(commonjs.adapter_record_id).published = true;
        commonjs.published = true;
      } else {
        runtime->module_records.at(recordId).published = true;
      }
    }
    runtime->module_source_slots.swap(sourceSlots);
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (...) {
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
}

extern "C" int32_t ex_hermes_module_commit_hot_revision(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation,
    uint32_t pair_count,
    const uint64_t* prior_record_ids,
    const uint64_t* successor_record_ids) {
  observeModuleRunnerAbi(__func__);
  // @ref LLP 0055#53-the-commit-bundle-atomic-owner-thread-no-fail
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (graph_generation == 0 || pair_count == 0 ||
      prior_record_ids == nullptr || successor_record_ids == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (runtime->pinned_module_generations.count(graph_generation) == 0) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }

  struct HotRevisionCommitPair {
    uint64_t prior_record_id{0};
    uint64_t successor_record_id{0};
    NativeModuleRecordEntry* prior{nullptr};
    NativeModuleRecordEntry* successor{nullptr};
    uint64_t* slot_record_id{nullptr};
  };

  std::vector<HotRevisionCommitPair> pairs;
  std::unordered_map<uint64_t, uint64_t> forwardingNodes;
  try {
    pairs.reserve(pair_count);
    forwardingNodes.reserve(pair_count);
    std::set<uint64_t> priorIds;
    std::set<uint64_t> successorIds;
    std::set<std::string> sourceIds;
    for (uint32_t index = 0; index < pair_count; ++index) {
      const uint64_t priorId = prior_record_ids[index];
      const uint64_t successorId = successor_record_ids[index];
      if (priorId == 0 || successorId == 0 || priorId == successorId ||
          !priorIds.insert(priorId).second ||
          !successorIds.insert(successorId).second) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
      auto prior = runtime->module_records.find(priorId);
      auto successor = runtime->module_records.find(successorId);
      if (prior == runtime->module_records.end() ||
          successor == runtime->module_records.end() ||
          prior->second.graph_generation != graph_generation ||
          successor->second.graph_generation != graph_generation) {
        return EXACT_RUNTIME_DRIVE_STALE;
      }
      if (!prior->second.published || successor->second.published ||
          successor->second.state < NativeModuleRecordState::Instantiated ||
          prior->second.source_id != successor->second.source_id ||
          !sourceIds.insert(prior->second.source_id).second ||
          (prior->second.namespace_object &&
           successor->second.namespace_object)) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
      auto slot = runtime->module_source_slots.find(
          std::make_pair(graph_generation, prior->second.source_id));
      if (slot == runtime->module_source_slots.end() ||
          slot->second != priorId) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
      if (runtime->module_record_forwarding.count(priorId) == 0) {
        forwardingNodes.emplace(priorId, successorId);
      }
      pairs.push_back({
          priorId,
          successorId,
          &prior->second,
          &successor->second,
          &slot->second});
    }
    for (const auto& [_, request] :
         runtime->module_dynamic_activation_requests) {
      if (request.graph_generation == graph_generation &&
          priorIds.count(request.requester_record_id) != 0) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
    }
    if (forwardingNodes.size() >
        runtime->module_record_forwarding.max_size() -
            runtime->module_record_forwarding.size()) {
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    runtime->module_record_forwarding.reserve(
        runtime->module_record_forwarding.size() + forwardingNodes.size());
  } catch (...) {
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  for (const auto& pair : pairs) {
    pair.successor->published = true;
    *pair.slot_record_id = pair.successor_record_id;
    for (auto& [_, targetRecordId] : runtime->module_record_forwarding) {
      if (targetRecordId == pair.prior_record_id) {
        targetRecordId = pair.successor_record_id;
      }
    }
    auto forwarding = runtime->module_record_forwarding.find(
        pair.prior_record_id);
    if (forwarding != runtime->module_record_forwarding.end()) {
      forwarding->second = pair.successor_record_id;
    } else {
      auto node = forwardingNodes.extract(pair.prior_record_id);
      runtime->module_record_forwarding.insert(std::move(node));
    }
    if (pair.prior->namespace_object) {
      pair.successor->namespace_object =
          std::move(pair.prior->namespace_object);
    }
    const uint64_t contextId = pair.prior->context_handle_id;
    releaseContextReference(runtime, contextId);
    runtime->module_records.erase(pair.prior_record_id);
    // D2: loader invalidator + carrier occupancy mount here.
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_discard_unpublished_record(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle handle) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto module = runtime->module_records.find(handle.opaque[2]);
  if (module != runtime->module_records.end() &&
      handle.opaque[0] == runtime_nonce &&
      module->second.graph_generation == handle.opaque[1]) {
    if (module->second.published ||
        module->second.state == NativeModuleRecordState::Evaluating ||
        module->second.state == NativeModuleRecordState::Evaluated) {
      return EXACT_RUNTIME_DRIVE_INVALID;
    }
    for (const auto& [_, commonjs] : runtime->commonjs_records) {
      if (commonjs.adapter_record_id == handle.opaque[2]) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
    }
    eraseDynamicActivationsForRequester(
        runtime, handle.opaque[1], handle.opaque[2], false);
    const uint64_t contextId = module->second.context_handle_id;
    runtime->module_records.erase(module);
    releaseContextReference(runtime, contextId);
    return EXACT_RUNTIME_DRIVE_OK;
  }
  auto commonjs = runtime->commonjs_records.find(handle.opaque[2]);
  if (commonjs == runtime->commonjs_records.end() ||
      handle.opaque[0] != runtime_nonce ||
      commonjs->second.graph_generation != handle.opaque[1]) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  if (commonjs->second.published ||
      commonjs->second.state != NativeCommonJsRecordState::New) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (commonjs->second.adapter_record_id != 0) {
    auto adapter =
        runtime->module_records.find(commonjs->second.adapter_record_id);
    if (adapter == runtime->module_records.end() ||
        adapter->second.published ||
        adapter->second.graph_generation != handle.opaque[1] ||
        adapter->second.state == NativeModuleRecordState::Evaluating ||
        adapter->second.state == NativeModuleRecordState::Evaluated) {
      return EXACT_RUNTIME_DRIVE_INVALID;
    }
    const uint64_t adapterContextId = adapter->second.context_handle_id;
    runtime->module_records.erase(adapter);
    releaseContextReference(runtime, adapterContextId);
  }
  eraseDynamicActivationsForRequester(
      runtime, handle.opaque[1], handle.opaque[2], true);
  const uint64_t contextId = commonjs->second.context_handle_id;
  runtime->commonjs_records.erase(commonjs);
  releaseContextReference(runtime, contextId);
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_graph_context_create(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation,
    const uint8_t* requesting_source_id,
    size_t requesting_source_id_len,
    uint32_t effect_owner,
    uint32_t schedule_owner,
    const uint32_t* constrained_principals,
    size_t constrained_principals_len,
    ExactModuleRunnerHandle* out_context) {
  observeModuleRunnerAbi(__func__);
  if (out_context) *out_context = ExactModuleRunnerHandle{{0, 0, 0}};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!commonJsRequireMutationTargetsGeneration(
          runtime, graph_generation)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  if (runtime_nonce == 0 || graph_generation == 0 || out_context == nullptr ||
      requesting_source_id == nullptr || requesting_source_id_len == 0 ||
      (constrained_principals_len != 0 && constrained_principals == nullptr) ||
      constrained_principals_len > 256) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  for (size_t i = 1; i < constrained_principals_len; ++i) {
    if (constrained_principals[i - 1] >= constrained_principals[i]) {
      return EXACT_RUNTIME_DRIVE_INVALID;
    }
  }
  GraphContextEntry entry;
  entry.graph_generation = graph_generation;
  entry.requesting_source_id.assign(
      reinterpret_cast<const char*>(requesting_source_id),
      requesting_source_id_len);
  entry.effect_owner = effect_owner;
  entry.schedule_owner = schedule_owner;
  if (constrained_principals_len != 0) {
    entry.constrained_principals.assign(
        constrained_principals,
        constrained_principals + constrained_principals_len);
  }
  const uint64_t id = nextHandleId(runtime);
  runtime->graph_contexts.emplace(id, std::move(entry));
  out_context->opaque[0] = runtime_nonce;
  out_context->opaque[1] = graph_generation;
  out_context->opaque[2] = id;
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_graph_context_retain(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle context) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (context.opaque[0] != runtime_nonce || context.opaque[1] == 0 ||
      context.opaque[2] == 0) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  auto it = runtime->graph_contexts.find(context.opaque[2]);
  if (it == runtime->graph_contexts.end() ||
      it->second.graph_generation != context.opaque[1] ||
      it->second.references == std::numeric_limits<uint32_t>::max()) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  ++it->second.references;
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_create_record(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle factory,
    ExactModuleRunnerHandle context,
    const uint8_t* source_id,
    size_t source_id_len,
    ExactModuleRunnerHandle* out_record) {
  observeModuleRunnerAbi(__func__);
  if (out_record) *out_record = ExactModuleRunnerHandle{{0, 0, 0}};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (out_record == nullptr || source_id == nullptr || source_id_len == 0 ||
      factory.opaque[0] != runtime_nonce || context.opaque[0] != runtime_nonce ||
      factory.opaque[1] == 0 || factory.opaque[1] != context.opaque[1]) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto factoryIt = runtime->module_factories.find(factory.opaque[2]);
  auto contextIt = runtime->graph_contexts.find(context.opaque[2]);
  if (factoryIt == runtime->module_factories.end() ||
      contextIt == runtime->graph_contexts.end() ||
      (factoryIt->second.source_goal != 0 &&
       factoryIt->second.source_goal != 2) ||
      factoryIt->second.graph_generation != factory.opaque[1] ||
      contextIt->second.graph_generation != context.opaque[1] ||
      factoryIt->second.source_id !=
          std::string(reinterpret_cast<const char*>(source_id), source_id_len)) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  NativeModuleRecordEntry entry;
  entry.graph_generation = factory.opaque[1];
  entry.source_goal = factoryIt->second.source_goal;
  entry.source_id.assign(reinterpret_cast<const char*>(source_id), source_id_len);
  entry.context_handle_id = context.opaque[2];
  entry.factory = factoryIt->second.factory;
  if (contextIt->second.references == std::numeric_limits<uint32_t>::max()) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  const uint64_t id = nextHandleId(runtime);
  ++contextIt->second.references;
  runtime->module_records.emplace(id, std::move(entry));
  out_record->opaque[0] = runtime_nonce;
  out_record->opaque[1] = factory.opaque[1];
  out_record->opaque[2] = id;
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_declare_export(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* export_name,
    size_t export_name_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New || export_name == nullptr ||
      export_name_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  std::string name(reinterpret_cast<const char*>(export_name), export_name_len);
  if (!entry->export_cells.emplace(name, NativeModuleBindingCell{}).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_link_export(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* export_name,
    size_t export_name_len,
    ExactModuleRunnerHandle target_record,
    const uint8_t* target_export,
    size_t target_export_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      entry->graph_generation != target->graph_generation ||
      export_name == nullptr || export_name_len == 0 ||
      target_export == nullptr || target_export_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string name(
      reinterpret_cast<const char*>(export_name), export_name_len);
  const std::string targetName(
      reinterpret_cast<const char*>(target_export), target_export_len);
  auto cell = entry->export_cells.find(name);
  if (cell == entry->export_cells.end() || cell->second.initialized ||
      cell->second.alias_record_id != 0 ||
      (targetName != "*" && target->export_cells.find(targetName) ==
                                target->export_cells.end())) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  cell->second.alias_record_id = target_record.opaque[2];
  cell->second.alias_export = targetName;
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_link_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len,
    const uint8_t* imported_name,
    size_t imported_name_len,
    ExactModuleRunnerHandle target_record,
    const uint8_t* target_export,
    size_t target_export_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      entry->graph_generation != target->graph_generation ||
      specifier == nullptr || specifier_len == 0 || imported_name == nullptr ||
      imported_name_len == 0 || target_export == nullptr ||
      target_export_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  std::string targetName(
      reinterpret_cast<const char*>(target_export), target_export_len);
  if (targetName != "*" && target->export_cells.find(targetName) ==
                               target->export_cells.end()) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto key = std::make_pair(
      std::string(reinterpret_cast<const char*>(specifier), specifier_len),
      std::string(
          reinterpret_cast<const char*>(imported_name), imported_name_len));
  NativeModuleImportBinding binding;
  binding.target_record_id = target_record.opaque[2];
  binding.target_export = std::move(targetName);
  if (!entry->import_bindings.emplace(std::move(key), std::move(binding)).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_link_dependency(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      entry->graph_generation != target->graph_generation) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  entry->evaluation_dependencies.insert(target_record.opaque[2]);
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_link_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      entry->graph_generation != target->graph_generation ||
      specifier == nullptr || specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (!entry->dynamic_import_bindings
           .emplace(spelling, target_record.opaque[2])
           .second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_link_computed_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    uint32_t site,
    const uint8_t* specifier,
    size_t specifier_len,
    ExactModuleRunnerHandle target_record) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  auto* target = recordFor(runtime, target_record);
  if (entry == nullptr || target == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      entry->graph_generation != target->graph_generation ||
      specifier == nullptr || specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (!entry->computed_dynamic_import_bindings
           .emplace(std::make_pair(site, spelling), target_record.opaque[2])
           .second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_defer_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      specifier == nullptr || specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string spelling(
      reinterpret_cast<const char*>(specifier), specifier_len);
  if (entry->dynamic_import_bindings.count(spelling) != 0 ||
      !entry->deferred_dynamic_imports.insert(spelling).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

extern "C" int32_t ex_hermes_module_record_defer_computed_dynamic_import(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    uint32_t site,
    const uint8_t* specifier,
    size_t specifier_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state != NativeModuleRecordState::New ||
      specifier == nullptr || specifier_len == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const auto key = std::make_pair(
      site,
      std::string(
          reinterpret_cast<const char*>(specifier), specifier_len));
  if (entry->computed_dynamic_import_bindings.count(key) != 0 ||
      !entry->deferred_computed_dynamic_imports.insert(key).second) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  return EXACT_RUNTIME_DRIVE_OK;
}

// @abi-output ex_hermes_module_take_dynamic_activation_request out_request role=output kind=aggregate schema=ExHermesModuleDynamicActivationRequest members=* ownership=caller-storage member-ownership=caller-frees:ex_hermes_module_dynamic_activation_request_dispose
extern "C" int32_t ex_hermes_module_take_dynamic_activation_request(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t graph_generation,
    ExHermesModuleDynamicActivationRequest* out_request) {
  observeModuleRunnerAbi(__func__);
  if (out_request == nullptr) return EXACT_RUNTIME_DRIVE_INVALID;
  *out_request = ExHermesModuleDynamicActivationRequest{};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (graph_generation == 0) return EXACT_RUNTIME_DRIVE_INVALID;

  auto selected = runtime->module_dynamic_activation_queue.end();
  NativeModuleDynamicActivationEntry* entry = nullptr;
  for (auto it = runtime->module_dynamic_activation_queue.begin();
       it != runtime->module_dynamic_activation_queue.end();) {
    auto found =
        runtime->module_dynamic_activation_requests.find(*it);
    if (found == runtime->module_dynamic_activation_requests.end() ||
        found->second.taken) {
      it = runtime->module_dynamic_activation_queue.erase(it);
      continue;
    }
    if (found->second.graph_generation == graph_generation) {
      selected = it;
      entry = &found->second;
      break;
    }
    ++it;
  }
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_OK;

  auto copyBytes = [](const std::string& source) -> uint8_t* {
    if (source.empty()) return nullptr;
    auto* copy = static_cast<uint8_t*>(std::malloc(source.size()));
    if (copy != nullptr) {
      std::memcpy(copy, source.data(), source.size());
    }
    return copy;
  };
  auto* requester = copyBytes(entry->requester_source_id);
  auto* specifierCopy = copyBytes(entry->specifier);
  if ((requester == nullptr && !entry->requester_source_id.empty()) ||
      (specifierCopy == nullptr && !entry->specifier.empty())) {
    std::free(requester);
    std::free(specifierCopy);
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  const uint64_t requestId = *selected;
  entry->taken = true;
  runtime->module_dynamic_activation_queue.erase(selected);
  out_request->runtime_nonce = runtime_nonce;
  out_request->request_id = requestId;
  out_request->graph_generation = entry->graph_generation;
  out_request->requester_record = ExactModuleRunnerHandle{{
      runtime_nonce,
      entry->graph_generation,
      entry->requester_record_id}};
  out_request->kind = entry->computed ? 1u : 0u;
  out_request->site = entry->site;
  out_request->requester_source_id = requester;
  out_request->requester_source_id_len =
      entry->requester_source_id.size();
  out_request->specifier = specifierCopy;
  out_request->specifier_len = entry->specifier.size();
  return EXACT_RUNTIME_DRIVE_OK;
}

// @abi-output ex_hermes_module_dynamic_activation_request_dispose request role=inout kind=aggregate schema=ExHermesModuleDynamicActivationRequest members=* ownership=caller-storage member-ownership=caller-frees:ex_hermes_module_dynamic_activation_request_dispose
extern "C" void ex_hermes_module_dynamic_activation_request_dispose(
    ExHermesModuleDynamicActivationRequest* request) {
  if (request == nullptr) return;
  std::free(request->requester_source_id);
  std::free(request->specifier);
  *request = ExHermesModuleDynamicActivationRequest{};
}

extern "C" int32_t ex_hermes_module_complete_dynamic_activation(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t request_id,
    ExactModuleRunnerHandle target_record,
    const uint8_t* error,
    size_t error_len) {
  observeModuleRunnerAbi(__func__);
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime) || request_id == 0 ||
      (error_len != 0 && error == nullptr)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto pending =
      runtime->module_dynamic_activation_requests.find(request_id);
  if (pending == runtime->module_dynamic_activation_requests.end()) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  auto& request = pending->second;
  if (!request.taken || !request.resolve || !request.reject) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const bool success = error_len == 0;
  if (success) {
    if (target_record.opaque[0] != runtime_nonce ||
        target_record.opaque[1] != request.graph_generation ||
        target_record.opaque[2] == 0 ||
        recordFor(runtime, target_record) == nullptr) {
      return EXACT_RUNTIME_DRIVE_STALE;
    }
  } else if (target_record.opaque[0] != 0 ||
             target_record.opaque[1] != 0 ||
             target_record.opaque[2] != 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  NativeModuleRecordEntry* moduleRequester = nullptr;
  NativeCommonJsRecordEntry* commonJsRequester = nullptr;
  uint64_t requesterContextId = 0;
  if (request.requester_is_commonjs) {
    auto requester =
        runtime->commonjs_records.find(request.requester_record_id);
    if (requester == runtime->commonjs_records.end() ||
        requester->second.graph_generation != request.graph_generation ||
        requester->second.source_id != request.requester_source_id) {
      return EXACT_RUNTIME_DRIVE_STALE;
    }
    commonJsRequester = &requester->second;
    requesterContextId = requester->second.context_handle_id;
  } else {
    auto requester =
        runtime->module_records.find(request.requester_record_id);
    if (requester == runtime->module_records.end() ||
        requester->second.graph_generation != request.graph_generation ||
        requester->second.source_id != request.requester_source_id) {
      return EXACT_RUNTIME_DRIVE_STALE;
    }
    moduleRequester = &requester->second;
    requesterContextId = requester->second.context_handle_id;
  }
  auto requesterContext = runtime->graph_contexts.find(requesterContextId);
  if (requesterContext == runtime->graph_contexts.end() ||
      requesterContext->second.graph_generation != request.graph_generation) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  if (success) {
    const uint64_t targetId = target_record.opaque[2];
    const auto bindingConflict = [&](const auto& requester) {
      if (request.computed) {
        auto existing =
            requester.computed_dynamic_import_bindings.find(
                std::make_pair(request.site, request.specifier));
        return existing !=
                requester.computed_dynamic_import_bindings.end() &&
            existing->second != targetId;
      }
      auto existing =
          requester.dynamic_import_bindings.find(request.specifier);
      return existing != requester.dynamic_import_bindings.end() &&
          existing->second != targetId;
    };
    if ((moduleRequester != nullptr &&
         bindingConflict(*moduleRequester)) ||
        (commonJsRequester != nullptr &&
         bindingConflict(*commonJsRequester))) {
      return EXACT_RUNTIME_DRIVE_INVALID;
    }
  }

  auto resolve = request.resolve;
  auto reject = request.reject;
  const uint64_t graphGeneration = request.graph_generation;
  const uint64_t requesterRecordId = request.requester_record_id;
  const bool computed = request.computed;
  const uint32_t site = request.site;
  const std::string specifier = request.specifier;
  std::vector<uint64_t> constrained(
      requesterContext->second.constrained_principals.begin(),
      requesterContext->second.constrained_principals.end());
  // The mailbox completion is a fresh native drive with no live requester
  // frame. Restore the requester's authenticated graph carrier while settling
  // its public Promise and draining the resulting continuation; otherwise an
  // `await import()` continuation would resume as no-user authority.
  // @ref LLP 0026#6-top-level-await-and-dynamic-import
  ScopedNativePrincipal scheduledPrincipal(
      requesterContext->second.schedule_owner);
  ScopedTypedPrincipalStack constrainedScope(constrained);
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  bool completed = false;
  try {
    auto& rt = *runtime->runtime;
    if (!success) {
      const std::string message(
          reinterpret_cast<const char*>(error), error_len);
      reject->call(
          rt,
          facebook::jsi::JSError(
              rt,
              message.empty() ? "dynamic module activation refused"
                              : message)
              .value());
    } else {
      auto chain = dynamicEvaluationPromise(
          rt,
          runtime,
          graphGeneration,
          requesterRecordId,
          target_record.opaque[2]);
      resolve->call(rt, facebook::jsi::Value(rt, chain));
      auto bindTarget = [&](auto& requester) {
        if (computed) {
          requester.computed_dynamic_import_bindings
              [std::make_pair(site, specifier)] =
              target_record.opaque[2];
        } else {
          requester.dynamic_import_bindings[specifier] =
              target_record.opaque[2];
        }
      };
      if (moduleRequester != nullptr) {
        bindTarget(*moduleRequester);
      } else {
        bindTarget(*commonJsRequester);
      }
    }
    completed = true;
  } catch (const facebook::jsi::JSError& completionError) {
    try {
      reject->call(*runtime->runtime, completionError.value());
    } catch (...) {
    }
  } catch (const std::exception& completionError) {
    try {
      reject->call(
          *runtime->runtime,
          facebook::jsi::JSError(
              *runtime->runtime, completionError.what())
              .value());
    } catch (...) {
    }
  } catch (...) {
    try {
      reject->call(
          *runtime->runtime,
          facebook::jsi::JSError(
              *runtime->runtime,
              "unknown dynamic module activation completion failure")
              .value());
    } catch (...) {
    }
  }
  runtime->module_dynamic_activation_requests.erase(request_id);
  if (!hostTask.finish()) return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  return completed ? EXACT_RUNTIME_DRIVE_OK
                   : EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

// @abi-output ex_hermes_module_record_instantiate out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_instantiate out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_record_instantiate(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* meta_url,
    size_t meta_url_len,
    const uint8_t* virtual_path,
    size_t virtual_path_len,
    int32_t is_main,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "module instantiate refused before embedder capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error, out_error_token);
  }
  if (entry->state != NativeModuleRecordState::New || meta_url == nullptr ||
      meta_url_len == 0 ||
      (virtual_path_len != 0 && virtual_path == nullptr) ||
      (is_main != 0 && is_main != 1)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const std::string virtualPath(
      virtual_path_len == 0 ? "" : reinterpret_cast<const char*>(virtual_path),
      virtual_path_len);
  if (!virtualPath.empty() &&
      (virtualPath.rfind("/project/", 0) != 0 ||
       virtualPath.find('\0') != std::string::npos ||
       virtualPath.back() == '/')) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error,
               "module instantiate host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }

  try {
    auto& rt = *runtime->runtime;
    auto objectConstructor = rt.global().getPropertyAsObject(rt, "Object");
    auto create = objectConstructor.getPropertyAsFunction(rt, "create");
    auto defineProperty =
        objectConstructor.getPropertyAsFunction(rt, "defineProperty");
    auto preventExtensions =
        objectConstructor.getPropertyAsFunction(rt, "preventExtensions");
    auto namespaceValue = create.call(rt, facebook::jsi::Value::null());
    if (!namespaceValue.isObject()) {
      throw facebook::jsi::JSError(rt, "failed to create module namespace");
    }
    auto namespaceObject = namespaceValue.asObject(rt);
    const auto target = exactRuntimeCallbackTarget(runtime);
    const uint64_t graphGeneration = entry->graph_generation;
    const uint64_t recordId = record.opaque[2];
    const auto occupiedSlot = runtime->module_source_slots.find(
        std::make_pair(graphGeneration, entry->source_id));
    // A staged successor must not retain a second namespace facade. Commit
    // moves the already-exposed slot-owned object from the prior incarnation.
    // @ref LLP 0055#23-stable-logical-slots-every-cross-module-use-resolves-through-the-slot
    const bool retainNamespace =
        occupiedSlot == runtime->module_source_slots.end() ||
        occupiedSlot->second == recordId;

    for (const auto& exportCell : entry->export_cells) {
      const std::string name = exportCell.first;
      auto getter = facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(rt, "moduleNamespaceGetter"),
          0,
          [target, graphGeneration, recordId, name](
              facebook::jsi::Runtime& rt,
              const facebook::jsi::Value&,
              const facebook::jsi::Value*,
              size_t) -> facebook::jsi::Value {
            if (!runtimeIsAlive(target) ||
                target.runtime->runtime_thread != std::this_thread::get_id()) {
              throw facebook::jsi::JSError(rt, "stale module namespace");
            }
            auto resolved = resolveLiveModuleRecord(
                target.runtime, graphGeneration, recordId);
            auto* current = resolved.record == nullptr
                ? nullptr
                : callbackRecordFor(
                      target, graphGeneration, resolved.record_id);
            if (current == nullptr) {
              throw facebook::jsi::JSError(rt, "stale module namespace");
            }
            return readBinding(
                rt, target.runtime, resolved.record_id, *current, name);
          });
      facebook::jsi::Object descriptor(rt);
      descriptor.setProperty(rt, "enumerable", true);
      descriptor.setProperty(rt, "configurable", false);
      descriptor.setProperty(rt, "get", std::move(getter));
      defineProperty.call(
          rt,
          namespaceObject,
          facebook::jsi::String::createFromUtf8(rt, name),
          descriptor);
    }
    preventExtensions.call(rt, namespaceObject);
    if (retainNamespace) {
      entry->namespace_object =
          std::make_shared<facebook::jsi::Object>(std::move(namespaceObject));
    }

    auto exportFunction = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "moduleExport"),
        2,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          auto* current = callbackRecordFor(target, graphGeneration, recordId);
          if (current == nullptr) {
            throw facebook::jsi::JSError(rt, "stale module export callback");
          }
          if (count != 2 || !args[0].isString()) {
            throw facebook::jsi::JSError(rt, "module export requires name and value");
          }
          const std::string name = args[0].asString(rt).utf8(rt);
          auto cell = current->export_cells.find(name);
          if (cell == current->export_cells.end()) {
            throw facebook::jsi::JSError(
                rt, "module attempted to publish undeclared export '" + name + "'");
          }
          if (cell->second.alias_record_id != 0) {
            throw facebook::jsi::JSError(
                rt, "module attempted to publish indirect export '" + name + "'");
          }
          cell->second.value =
              std::make_shared<facebook::jsi::Value>(rt, args[1]);
          cell->second.initialized = true;
          return facebook::jsi::Value::undefined();
        });

    facebook::jsi::Object context(rt);
    auto importValue = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "moduleImportValue"),
        2,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          auto* current = callbackRecordFor(target, graphGeneration, recordId);
          if (current == nullptr) {
            throw facebook::jsi::JSError(rt, "stale module import context");
          }
          if (count != 2 || !args[0].isString() || !args[1].isString()) {
            throw facebook::jsi::JSError(
                rt, "module importValue requires specifier and import name");
          }
          auto key = std::make_pair(
              args[0].asString(rt).utf8(rt), args[1].asString(rt).utf8(rt));
          auto binding = current->import_bindings.find(key);
          if (binding == current->import_bindings.end()) {
            throw facebook::jsi::JSError(rt, "module import binding is not linked");
          }
          auto targetRecord = resolveLiveModuleRecord(
              target.runtime,
              graphGeneration,
              binding->second.target_record_id);
          if (targetRecord.record == nullptr) {
            throw facebook::jsi::JSError(rt, "module import target is stale");
          }
          return readBinding(
              rt,
              target.runtime,
              targetRecord.record_id,
              *targetRecord.record,
              binding->second.target_export);
        });
    context.setProperty(rt, "importValue", std::move(importValue));
    auto dynamicImport = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "moduleDynamicImport"),
        1,
        [target, graphGeneration, recordId](
            facebook::jsi::Runtime& rt,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          // import() never throws synchronously: malformed, denied, stale,
          // and cyclic requests all become fresh rejected public promises.
          // @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
          const bool siteBearing = count >= 5 && args[0].isNumber() &&
              args[1].isNumber() && args[2].isNumber() && args[3].isNumber();
          const bool legacyComputed =
              !siteBearing && count >= 2 && args[0].isNumber();
          const size_t specifierIndex = siteBearing ? 4 : (legacyComputed ? 1 : 0);
          if (count < specifierIndex + 1 || count > specifierIndex + 2) {
            return rejectedPromise(rt, "dynamic import arguments are invalid");
          }
          auto* current = callbackRecordFor(target, graphGeneration, recordId);
          if (current == nullptr) {
            return rejectedPromise(rt, "stale dynamic import requester");
          }
          try {
            const std::string specifier =
                args[specifierIndex].toString(rt).utf8(rt);
            bool computed = legacyComputed;
            uint32_t site = 0;
            std::string siteDiagnostic;
            if (siteBearing) {
              const double rawKind = args[0].asNumber();
              const double rawStart = args[1].asNumber();
              const double rawEnd = args[2].asNumber();
              const double rawOptionsGuard = args[3].asNumber();
              if (!finiteIntegerInRange(rawKind, -1, UINT32_MAX) ||
                  !finiteIntegerInRange(rawStart, 0, UINT32_MAX) ||
                  !finiteIntegerInRange(rawEnd, 0, UINT32_MAX) ||
                  rawEnd < rawStart ||
                  (rawOptionsGuard != 0 && rawOptionsGuard != 1)) {
                return rejectedPromise(rt, "dynamic import site metadata is invalid");
              }
              computed = rawKind >= 0;
              if (computed) site = static_cast<uint32_t>(rawKind);
              siteDiagnostic = current->source_id + " at original-source bytes " +
                  std::to_string(static_cast<uint32_t>(rawStart)) + ".." +
                  std::to_string(static_cast<uint32_t>(rawEnd));
              if (rawOptionsGuard != 0) {
                return rejectedPromise(
                    rt, "unsupported dynamic import options in " + siteDiagnostic);
              }
            }
            uint64_t targetRecordId = 0;
            if (computed) {
              if (!siteBearing) {
                const double rawSite = args[0].asNumber();
                if (!finiteIntegerInRange(rawSite, 0, UINT32_MAX)) {
                  return rejectedPromise(rt, "computed dynamic import site is invalid");
                }
                site = static_cast<uint32_t>(rawSite);
              }
              auto binding = current->computed_dynamic_import_bindings.find(
                  std::make_pair(site, specifier));
              if (binding == current->computed_dynamic_import_bindings.end()) {
                if (current->deferred_computed_dynamic_imports.count(
                        std::make_pair(site, specifier)) != 0) {
                  auto promise = pendingDynamicActivationPromise(
                      rt,
                      target.runtime,
                      graphGeneration,
                      recordId,
                      false,
                      current->source_id,
                      true,
                      site,
                      specifier);
                  return facebook::jsi::Value(rt, promise);
                }
                return rejectedPromise(
                    rt,
                    "computed dynamic import candidate is not authorized for this site" +
                        (siteDiagnostic.empty() ? std::string() :
                                                  " in " + siteDiagnostic));
              }
              targetRecordId = binding->second;
            } else {
              auto binding = current->dynamic_import_bindings.find(specifier);
              if (binding == current->dynamic_import_bindings.end()) {
                if (current->deferred_dynamic_imports.count(specifier) != 0) {
                  auto promise = pendingDynamicActivationPromise(
                      rt,
                      target.runtime,
                      graphGeneration,
                      recordId,
                      false,
                      current->source_id,
                      false,
                      0,
                      specifier);
                  return facebook::jsi::Value(rt, promise);
                }
                return rejectedPromise(
                    rt, "dynamic import target is not authorized and linked");
              }
              targetRecordId = binding->second;
            }
            auto resolvedTarget = resolveLiveModuleRecord(
                target.runtime, graphGeneration, targetRecordId);
            if (resolvedTarget.record == nullptr) {
              return rejectedPromise(rt, "stale dynamic import target");
            }
            targetRecordId = resolvedTarget.record_id;
            if (targetRecordId == recordId &&
                current->state != NativeModuleRecordState::Evaluated) {
              return rejectedPromise(
                  rt, "ERR_ASYNC_MODULE_CYCLE: dynamic import re-entered its evaluating record");
            }
            auto promise = dynamicEvaluationPromise(
                rt,
                target.runtime,
                graphGeneration,
                recordId,
                targetRecordId);
            return facebook::jsi::Value(rt, promise);
          } catch (const facebook::jsi::JSError& error) {
            return rejectedPromise(rt, "dynamic import failed");
          } catch (const std::exception& error) {
            return rejectedPromise(rt, error.what());
          } catch (...) {
            return rejectedPromise(rt, "unknown dynamic import failure");
          }
        });
    context.setProperty(rt, "dynamicImport", std::move(dynamicImport));
    facebook::jsi::Object meta(rt);
    meta.setProperty(
        rt,
        "url",
        facebook::jsi::String::createFromUtf8(
            rt,
            std::string(reinterpret_cast<const char*>(meta_url), meta_url_len)));
    meta.setProperty(rt, "main", is_main == 1);
    if (!virtualPath.empty()) {
      const size_t separator = virtualPath.rfind('/');
      const std::string dirname =
          separator == 0 ? std::string("/") : virtualPath.substr(0, separator);
      const std::string basename = virtualPath.substr(separator + 1);
      auto pathValue = facebook::jsi::String::createFromUtf8(rt, virtualPath);
      meta.setProperty(rt, "path", pathValue);
      meta.setProperty(rt, "filename", pathValue);
      auto dirnameValue = facebook::jsi::String::createFromUtf8(rt, dirname);
      meta.setProperty(rt, "dirname", dirnameValue);
      meta.setProperty(rt, "dir", dirnameValue);
      meta.setProperty(
          rt,
          "file",
          facebook::jsi::String::createFromUtf8(rt, basename));
    }
    auto metaResolve = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "importMetaResolveRefusal"),
        1,
        [](facebook::jsi::Runtime& rt,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) -> facebook::jsi::Value {
          throw facebook::jsi::JSError(
              rt,
              "ERR_IMPORT_META_RESOLVE_UNAVAILABLE: native resolution-only gate is unavailable");
        });
    meta.setProperty(rt, "resolve", std::move(metaResolve));
    context.setProperty(rt, "meta", std::move(meta));

    auto instanceValue = entry->factory->call(rt, exportFunction, context);
    if (!instanceValue.isObject()) {
      throw facebook::jsi::JSError(rt, "module factory did not return an object");
    }
    auto instance = instanceValue.asObject(rt);
    auto declareValue = instance.getProperty(rt, "declare");
    auto executeValue = instance.getProperty(rt, "execute");
    if (!declareValue.isObject() ||
        !declareValue.asObject(rt).isFunction(rt) || !executeValue.isObject() ||
        !executeValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(
          rt, "module factory result requires declare and execute functions");
    }
    entry->declare_function = std::make_shared<facebook::jsi::Function>(
        declareValue.asObject(rt).asFunction(rt));
    entry->execute_function = std::make_shared<facebook::jsi::Function>(
        executeValue.asObject(rt).asFunction(rt));
    entry->state = NativeModuleRecordState::Instantiated;
    if (!hostTask.finish()) {
      writeError(out_error, "module instantiate host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(
        *entry,
        "module instantiation threw",
        exactRetainStructuredModuleGraphError(runtime, error));
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module instantiation failure");
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module instantiate host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  return reportRecordError(*entry, out_error, out_error_token);
}

// @abi-output ex_hermes_module_record_run_declare out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_run_declare out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_record_run_declare(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce, false, false, true);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "module declaration refused before embedder capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error, out_error_token);
  }
  if (entry->state != NativeModuleRecordState::Instantiated ||
      !entry->declare_function) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error,
               "module declaration host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  try {
    entry->declare_function->call(*runtime->runtime);
    entry->state = NativeModuleRecordState::Declared;
    if (!hostTask.finish()) {
      writeError(out_error, "module declaration host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(
        *entry,
        "module declaration threw",
        exactRetainStructuredModuleGraphError(runtime, error));
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module declaration failure");
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module declaration host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  return reportRecordError(*entry, out_error, out_error_token);
}

// @abi-output ex_hermes_module_record_run_execute out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_run_execute out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_record_run_execute(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    int32_t* out_async,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_async) *out_async = 0;
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (!exactRuntimeEnterUserExecution(runtime)) {
    writeError(
        out_error,
        "module evaluation refused before embedder capability finalization");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error, out_error_token);
  }
  if (entry->state != NativeModuleRecordState::Declared ||
      !entry->execute_function || out_async == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "module execution host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  try {
    const int32_t async =
        beginRecordExecute(*runtime->runtime, runtime, record.opaque[2], *entry)
            ? 1
            : 0;
    if (!hostTask.finish()) {
      writeError(out_error, "module execution host-task checkpoint failed");
      return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
    }
    *out_async = async;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(
        *entry,
        "module execution threw",
        exactRetainStructuredModuleGraphError(runtime, error));
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module evaluation failure");
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module execution host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  return reportRecordError(*entry, out_error, out_error_token);
}

// @abi-output ex_hermes_module_record_poll_evaluation out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_poll_evaluation out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_record_poll_evaluation(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    int32_t* out_state,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_state) *out_state = -1;
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (out_state == nullptr) return EXACT_RUNTIME_DRIVE_INVALID;
  switch (entry->state) {
    case NativeModuleRecordState::Evaluating:
      *out_state = 0;
      return EXACT_RUNTIME_DRIVE_OK;
    case NativeModuleRecordState::Evaluated:
      *out_state = 1;
      return EXACT_RUNTIME_DRIVE_OK;
    case NativeModuleRecordState::Errored:
      *out_state = 2;
      return reportRecordError(*entry, out_error, out_error_token);
    default:
      return EXACT_RUNTIME_DRIVE_INVALID;
  }
}

// @abi-output ex_hermes_module_record_namespace_json out_json role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_namespace_json out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
// @abi-output ex_hermes_module_record_namespace_json out_error_token role=output kind=scalar ownership=caller-storage
extern "C" int32_t ex_hermes_module_record_namespace_json(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    char** out_json,
    char** out_error,
    uint64_t* out_error_token) {
  observeModuleRunnerAbi(__func__);
  if (out_json) *out_json = nullptr;
  if (out_error) *out_error = nullptr;
  if (out_error_token) *out_error_token = 0;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
  // Namespace serialization is diagnostic runtime inspection. Production
  // module execution never needs it and armed runtimes reject it before
  // reading a record or evaluating a namespace getter.
  if (runtime->armed) {
    writeError(out_error,
               "module namespace inspection is closed under armed startup");
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error, out_error_token);
  }
  if (!entry->namespace_object || out_json == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) {
    writeError(out_error, "module namespace host-task boundary is unavailable");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  uint64_t pendingErrorToken = 0;
  std::string pendingError;
  std::string text;
  try {
    auto& rt = *runtime->runtime;
    auto json = rt.global().getPropertyAsObject(rt, "JSON");
    auto stringify = json.getPropertyAsFunction(rt, "stringify");
    auto value = stringify.call(rt, *entry->namespace_object);
    if (!value.isString()) {
      throw facebook::jsi::JSError(rt, "module namespace is not serializable");
    }
    text = value.asString(rt).utf8(rt);
  } catch (const facebook::jsi::JSError& error) {
    pendingErrorToken = exactRetainStructuredModuleGraphError(runtime, error);
    pendingError = "module namespace serialization threw";
  } catch (const std::exception& error) {
    pendingError = error.what();
  } catch (...) {
    pendingError = "unknown module namespace serialization failure";
  }
  if (!hostTask.finish()) {
    writeError(out_error, "module namespace host-task checkpoint failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  if (!pendingError.empty()) {
    if (out_error_token) *out_error_token = pendingErrorToken;
    writeError(out_error, pendingError);
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  *out_json = static_cast<char*>(std::malloc(text.size() + 1));
  if (*out_json == nullptr) {
    writeError(out_error, "module namespace result allocation failed");
    return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
  }
  std::memcpy(*out_json, text.data(), text.size());
  (*out_json)[text.size()] = '\0';
  return EXACT_RUNTIME_DRIVE_OK;
}
