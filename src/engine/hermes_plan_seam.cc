// Restricted Hermes provider for Exact's native Contract plan evaluator.
//
// This file deliberately does not include or mirror Contract's generated C
// result ABI. It transports the generated outcome discriminant and payload as
// opaque values; Swift projects those into CnHostPlanSeamResultV1 using the
// generated WP5 constants. There is no source-eval, module-loader, timer,
// fetch, native-module, or app-host surface on this opaque runtime.
//
// The synchronous entry points comply with LLP 0297 §4.2/B2 because they are
// callable only by the already-owning plan/Hermes executor. They never hop to
// another queue, wait, use a semaphore, or bounce through the main thread.
// @ref https://github.com/expo/exact/blob/main/docs/design/0514-m1-native-plan-host-and-ts-seam.md — Exact 0514 M1 §3

#include "../../include/exact_runtime.h"
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
#include "../../include/exact_runtime_plan_seam_benchmark.h"
#endif
#include "hermes_runtime_internal.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

using facebook::jsi::Function;
using facebook::jsi::Object;
using facebook::jsi::PropNameID;
using facebook::jsi::Runtime;
using facebook::jsi::String;
using facebook::jsi::Value;

void registerRuntime(ExactHermesRuntime* runtime);

namespace {

constexpr uint64_t kDefaultHeapBytes = 16ull << 20;
constexpr uint64_t kMaximumHeapBytes = 128ull << 20;
constexpr size_t kMaximumTransportBytes = 16ull << 20;
constexpr uint32_t kBindingKindHostImport = 1;
constexpr uint32_t kBindingKindCapability = 2;

#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
uint64_t continuousNanoseconds() {
#if defined(__APPLE__)
  static mach_timebase_info_data_t timebase = [] {
    mach_timebase_info_data_t value{};
    if (mach_timebase_info(&value) != KERN_SUCCESS || value.denom == 0) {
      value.numer = 1;
      value.denom = 1;
    }
    return value;
  }();
  const uint64_t ticks = mach_continuous_time();
  const uint64_t quotient = ticks / timebase.denom;
  const uint64_t remainder = ticks % timebase.denom;
  return quotient * timebase.numer +
      (remainder * timebase.numer) / timebase.denom;
#else
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
#endif
}

uint64_t elapsedNanoseconds(uint64_t start, uint64_t end) {
  return end >= start ? end - start : 0;
}

void clearBenchmarkCreateTiming(
    ExHermesPlanSeamBenchmarkCreateTimingV1* timing) {
  if (timing == nullptr) return;
  std::memset(timing, 0, sizeof(*timing));
  timing->abi_version = EX_HERMES_PLAN_SEAM_BENCHMARK_ABI_VERSION_V1;
  timing->struct_size = sizeof(*timing);
}

void clearBenchmarkDirectBatchResult(
    ExHermesPlanSeamBenchmarkDirectBatchResultV1* result) {
  if (result == nullptr) return;
  std::memset(result, 0, sizeof(*result));
  result->abi_version = EX_HERMES_PLAN_SEAM_BENCHMARK_ABI_VERSION_V1;
  result->struct_size = sizeof(*result);
}
#endif

void writeCreateDiagnostic(
    ExHermesPlanSeamCreateDiagnosticV1* out,
    int32_t transportStatus,
    uint32_t code,
    const std::string& message) {
  if (out == nullptr) return;
  std::memset(out, 0, sizeof(*out));
  out->abi_version = EX_HERMES_PLAN_SEAM_ABI_VERSION_V1;
  out->struct_size = sizeof(*out);
  out->transport_status = transportStatus;
  out->code = code;
  const size_t length = std::min(
      message.size(),
      static_cast<size_t>(
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_MESSAGE_CAPACITY_V1));
  if (length != 0) std::memcpy(out->message, message.data(), length);
  out->message_len = static_cast<uint32_t>(length);
}

int32_t refuseCreate(
    ExHermesPlanSeamCreateDiagnosticV1* out,
    int32_t transportStatus,
    uint32_t code,
    const std::string& message) {
  writeCreateDiagnostic(out, transportStatus, code, message);
  return transportStatus;
}

class PlanSeamAlignedBytecodeBuffer final : public facebook::jsi::Buffer {
 public:
  PlanSeamAlignedBytecodeBuffer(const uint8_t* data, size_t length)
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
  size_t size_{0};
  std::vector<uint8_t> storage_;
  uint8_t* data_{nullptr};
};

bool planSeamBytecodeSanityCheck(
    const uint8_t* bytes, size_t length, std::string& reason) {
  PlanSeamAlignedBytecodeBuffer buffer(bytes, length);
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

bool validFacetInputs(const ExHermesPlanSeamFacetHostInputsV1& inputs) {
  return inputs.abi_version == EX_HERMES_PLAN_SEAM_ABI_VERSION_V1 &&
      inputs.struct_size == sizeof(ExHermesPlanSeamFacetHostInputsV1) &&
      (inputs.system_appearance == EX_HERMES_PLAN_SEAM_APPEARANCE_LIGHT_V1 ||
       inputs.system_appearance == EX_HERMES_PLAN_SEAM_APPEARANCE_DARK_V1) &&
      inputs.reduced_motion <= 1 &&
      inputs.native_control_presentation <= 1 &&
      inputs.reserved == 0 && std::isfinite(inputs.viewport_width) &&
      inputs.viewport_width > 0;
}

bool parseNonzeroU64(const std::string& text, uint64_t& out) {
  if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
  uint64_t value = 0;
  for (char character : text) {
    if (character < '0' || character > '9') return false;
    const uint64_t digit = static_cast<uint64_t>(character - '0');
    if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  if (value == 0) return false;
  out = value;
  return true;
}

std::string u64Text(uint64_t value) { return std::to_string(value); }

Object facetInputsObject(
    Runtime& runtime, const ExHermesPlanSeamFacetHostInputsV1& inputs) {
  Object object(runtime);
  object.setProperty(
      runtime,
      "systemAppearance",
      String::createFromAscii(
          runtime,
          inputs.system_appearance == EX_HERMES_PLAN_SEAM_APPEARANCE_DARK_V1
              ? "dark"
              : "light"));
  object.setProperty(
      runtime, "reducedMotion", inputs.reduced_motion != 0);
  object.setProperty(runtime, "viewportWidth", inputs.viewport_width);
  object.setProperty(
      runtime,
      "nativeControlPresentation",
      inputs.native_control_presentation != 0);
  return object;
}

bool validateReducedHermesInternalSurface(
    Runtime& runtime, std::string& reason) {
  // This linked Hermes profile retains the immutable HermesInternal object
  // when EnableHermesInternal=false, but publishes no own members at all. Pin
  // that observed disabled profile exactly: a future engine/test/queue member
  // is a create refusal. Microtasks are independently disabled at RuntimeConfig
  // construction, so no callable useEngineQueue hook is expected or needed.
  auto global = runtime.global();
  auto internalValue = global.getProperty(runtime, "HermesInternal");
  if (!internalValue.isObject()) {
    reason = "HermesInternal is absent or not an object";
    return false;
  }
  auto internal = internalValue.asObject(runtime);
  auto objectValue = global.getProperty(runtime, "Object");
  if (!objectValue.isObject()) {
    reason = "HermesInternal own-property introspection is unavailable";
    return false;
  }
  auto object = objectValue.asObject(runtime);
  auto getOwnPropertyNamesValue =
      object.getProperty(runtime, "getOwnPropertyNames");
  if (!getOwnPropertyNamesValue.isObject() ||
      !getOwnPropertyNamesValue.asObject(runtime).isFunction(runtime)) {
    reason = "HermesInternal own-property introspection is unavailable";
    return false;
  }
  auto propertiesValue = getOwnPropertyNamesValue.asObject(runtime)
                             .asFunction(runtime)
                             .call(runtime, internal);
  if (!propertiesValue.isObject() ||
      !propertiesValue.asObject(runtime).isArray(runtime)) {
    reason = "HermesInternal own-property introspection returned invalid data";
    return false;
  }
  auto properties = propertiesValue.asObject(runtime).asArray(runtime);
  std::vector<std::string> actualProperties;
  actualProperties.reserve(properties.size(runtime));
  for (size_t index = 0; index < properties.size(runtime); ++index) {
    auto propertyValue = properties.getValueAtIndex(runtime, index);
    if (!propertyValue.isString()) {
      reason = "HermesInternal property name is not a string";
      return false;
    }
    const std::string property =
        propertyValue.asString(runtime).utf8(runtime);
    actualProperties.push_back(property);
  }
  if (!actualProperties.empty()) {
    reason = "HermesInternal exact-shape mismatch; actual=[";
    for (size_t index = 0; index < actualProperties.size(); ++index) {
      if (index != 0) reason += ",";
      reason += actualProperties[index];
    }
    reason += "]; expected=[]";
    return false;
  }
  return true;
}

bool closeAmbientSurface(Runtime& runtime, std::string& reason) {
  auto global = runtime.global();
  static constexpr const char* kClosedGlobals[] = {
      "Date",       "eval",       "Function",   "Proxy",
      "WebAssembly", "Intl",       "fetch",      "XMLHttpRequest",
      "WebSocket",  "setTimeout", "setInterval", "queueMicrotask",
      "requestAnimationFrame", "process", "require", "exact",
      "print", "gc"};
  for (const char* name : kClosedGlobals) {
    global.deleteProperty(runtime, name);
    if (global.hasProperty(runtime, name)) {
      reason = std::string("ambient global could not be removed: ") + name;
      return false;
    }
  }
  auto mathValue = global.getProperty(runtime, "Math");
  if (mathValue.isObject()) {
    auto math = mathValue.asObject(runtime);
    math.deleteProperty(runtime, "random");
    if (math.hasProperty(runtime, "random")) {
      reason = "ambient Math.random could not be removed";
      return false;
    }
  }
  return validateReducedHermesInternalSurface(runtime, reason);
}

struct PlanSeamReply {
  uint8_t outcomeDiscriminant{0};
  std::vector<uint8_t> payload;
  uint64_t reactiveVersion{0};
};

struct PlanSeamLease {
  explicit PlanSeamLease(std::vector<uint8_t> bytes)
      : payload(std::move(bytes)) {}
  std::vector<uint8_t> payload;
};

class RestrictedHostContextLease {
 public:
  explicit RestrictedHostContextLease(uint64_t context) : context_(context) {}
  ~RestrictedHostContextLease() {
    if (context_ != 0) ex_host_release_context(context_);
  }
  RestrictedHostContextLease(const RestrictedHostContextLease&) = delete;
  RestrictedHostContextLease& operator=(const RestrictedHostContextLease&) = delete;
  void disarm() { context_ = 0; }

 private:
  uint64_t context_;
};

}  // namespace

struct ExactHermesPlanSeamRuntimeV1 {
  ExactHermesRuntime* handle{nullptr};
  uint64_t generation{0};
  uint64_t executorIdentity{0};
  std::thread::id owner;
  ExHermesPlanSeamInvalidationCallbackV1 invalidationCallback{nullptr};
  void* invalidationContext{nullptr};
  bool stopping{false};
  bool stopped{false};
  bool fenced{false};
  bool callbackActive{false};
  uint64_t nextLeaseToken{1};
  std::unordered_map<uint64_t, std::unique_ptr<PlanSeamLease>> leases;
  std::vector<uint8_t> registryReceipt;
  std::unique_ptr<Function> isProxy;
  std::unique_ptr<Function> captureThrown;
  std::unique_ptr<Function> recordInvalidation;
  std::unique_ptr<Function> callSync;
  std::unique_ptr<Function> callCapabilitySync;
  std::unique_ptr<Function> readReactiveSync;
  std::unique_ptr<Function> applyFacetHostInputs;
  std::unique_ptr<Function> providerFault;
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  std::unique_ptr<Function> benchmarkDirectProvider;
  std::unique_ptr<Function> benchmarkAssertDirectProvider;
  std::unique_ptr<Function> benchmarkProjectTick;
  std::unique_ptr<Function> benchmarkAssertTickProjection;
  std::unique_ptr<Function> benchmarkResetAdapterCounters;
  std::unique_ptr<Function> benchmarkTakeAdapterCounters;
  bool benchmarkCountersArmed{false};
  bool benchmarkCountersOverflowed{false};
  uint64_t benchmarkArgumentBytesCopied{0};
  uint64_t benchmarkResultBytesCopied{0};
  uint64_t benchmarkAdapterAllocations{0};
#endif
  std::unique_ptr<Function> dispose;
};

namespace {

class CallbackActiveScope {
 public:
  explicit CallbackActiveScope(ExactHermesPlanSeamRuntimeV1* seam)
      : seam_(seam) {
    seam_->callbackActive = true;
  }
  ~CallbackActiveScope() { seam_->callbackActive = false; }
  CallbackActiveScope(const CallbackActiveScope&) = delete;
  CallbackActiveScope& operator=(const CallbackActiveScope&) = delete;

 private:
  ExactHermesPlanSeamRuntimeV1* seam_;
};

#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
bool addBenchmarkCounter(uint64_t& target, size_t amount) {
  if (amount > std::numeric_limits<uint64_t>::max() - target) return false;
  target += static_cast<uint64_t>(amount);
  return true;
}

void recordBenchmarkAdapter(
    ExactHermesPlanSeamRuntimeV1* seam,
    size_t argumentBytes,
    size_t resultBytes,
    size_t allocations) {
  if (!seam->benchmarkCountersArmed || seam->benchmarkCountersOverflowed) return;
  seam->benchmarkCountersOverflowed =
      !addBenchmarkCounter(seam->benchmarkArgumentBytesCopied, argumentBytes) ||
      !addBenchmarkCounter(seam->benchmarkResultBytesCopied, resultBytes) ||
      !addBenchmarkCounter(seam->benchmarkAdapterAllocations, allocations);
}

void recordBenchmarkArrayBoundaryAllocation(void* context) {
  recordBenchmarkAdapter(
      static_cast<ExactHermesPlanSeamRuntimeV1*>(context), 0, 0, 1);
}
#endif

bool readReply(
    ExactHermesPlanSeamRuntimeV1* seam,
    Runtime& runtime,
    const Value& value,
    PlanSeamReply& out) {
#if !defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  (void)seam;
#endif
  if (!value.isObject()) return false;
  auto object = value.asObject(runtime);
  auto discriminant = object.getProperty(runtime, "outcomeDiscriminant");
  auto payload = object.getProperty(runtime, "payload");
  auto version = object.getProperty(runtime, "reactiveVersion");
  if (!discriminant.isNumber() || !payload.isObject() ||
      !version.isString()) {
    return false;
  }
  const double numericDiscriminant = discriminant.asNumber();
  if (!std::isfinite(numericDiscriminant) || numericDiscriminant < 0 ||
      numericDiscriminant > std::numeric_limits<uint8_t>::max() ||
      std::floor(numericDiscriminant) != numericDiscriminant) {
    return false;
  }
  const uint8_t* bytes = nullptr;
  size_t length = 0;
  if (!extractArrayBufferView(
          runtime, payload.asObject(runtime), bytes, length) ||
      length > kMaximumTransportBytes || (length != 0 && bytes == nullptr)) {
    return false;
  }
  const std::string versionText = version.asString(runtime).utf8(runtime);
  uint64_t reactiveVersion = 0;
  if (versionText != "0" && !parseNonzeroU64(versionText, reactiveVersion)) {
    return false;
  }
  out.outcomeDiscriminant = static_cast<uint8_t>(numericDiscriminant);
  out.payload.clear();
  if (length != 0) {
    out.payload.assign(bytes, bytes + length);
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
    recordBenchmarkAdapter(seam, 0, length, 1);
#endif
  }
  out.reactiveVersion = reactiveVersion;
  return true;
}

bool hasRequiredReactiveVersion(
    const PlanSeamReply& reply, bool reactiveRead) {
  return !reactiveRead || reply.outcomeDiscriminant != 0 ||
      reply.reactiveVersion != 0;
}

int32_t prepareOutputs(
    uint8_t* outOutcomeDiscriminant,
    const uint8_t** outPayload,
    size_t* outPayloadLen,
    uint64_t* outReactiveVersion,
    uint64_t* outLeaseGeneration,
    uint64_t* outLeaseToken) {
  if (outOutcomeDiscriminant == nullptr || outPayload == nullptr ||
      outPayloadLen == nullptr || outReactiveVersion == nullptr ||
      outLeaseGeneration == nullptr || outLeaseToken == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  *outOutcomeDiscriminant = 0;
  *outPayload = nullptr;
  *outPayloadLen = 0;
  *outReactiveVersion = 0;
  *outLeaseGeneration = 0;
  *outLeaseToken = 0;
  return EX_HERMES_PLAN_SEAM_OK_V1;
}

int32_t mintReply(
    ExactHermesPlanSeamRuntimeV1* seam,
    PlanSeamReply reply,
    uint8_t* outOutcomeDiscriminant,
    const uint8_t** outPayload,
    size_t* outPayloadLen,
    uint64_t* outReactiveVersion,
    uint64_t* outLeaseGeneration,
    uint64_t* outLeaseToken) {
  if (seam->fenced) {
    return EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  if (seam->nextLeaseToken == 0) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_LEASE_V1;
  }
  const uint64_t token = seam->nextLeaseToken++;
  auto lease = std::make_unique<PlanSeamLease>(std::move(reply.payload));
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  recordBenchmarkAdapter(seam, 0, 0, 1);
#endif
  const uint8_t* pointer = lease->payload.empty() ? nullptr : lease->payload.data();
  const size_t length = lease->payload.size();
  if (!seam->leases.emplace(token, std::move(lease)).second) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_LEASE_V1;
  }
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  recordBenchmarkAdapter(seam, 0, 0, 1);
#endif
  *outOutcomeDiscriminant = reply.outcomeDiscriminant;
  *outPayload = pointer;
  *outPayloadLen = length;
  *outReactiveVersion = reply.reactiveVersion;
  *outLeaseGeneration = seam->generation;
  *outLeaseToken = token;
  return EX_HERMES_PLAN_SEAM_OK_V1;
}

int32_t ownerDriveStatus(ExactHermesPlanSeamRuntimeV1* seam) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->owner != std::this_thread::get_id()) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  if (seam->handle == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->callbackActive) {
    return EX_HERMES_PLAN_SEAM_REENTRANT_V1;
  }
  if (seam->fenced || seam->stopping || seam->stopped) {
    return EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  return EX_HERMES_PLAN_SEAM_OK_V1;
}

int32_t mapDriveGuardFailure(
    ExactHermesPlanSeamRuntimeV1* seam, int32_t status) {
  if (status == EXACT_RUNTIME_DRIVE_OFF_OWNER) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  if (status == EXACT_RUNTIME_DRIVE_REENTRANT) {
    return EX_HERMES_PLAN_SEAM_REENTRANT_V1;
  }
  seam->fenced = true;
  return EX_HERMES_PLAN_SEAM_FENCED_V1;
}

bool copyRegistryFunction(
    Runtime& runtime,
    const Object& registry,
    const char* name,
    std::unique_ptr<Function>& out) {
  auto value = registry.getProperty(runtime, name);
  if (!value.isObject() || !value.asObject(runtime).isFunction(runtime)) {
    return false;
  }
  out = std::make_unique<Function>(
      value.asObject(runtime).asFunction(runtime));
  return true;
}

std::unique_ptr<Function> makeIsProxyFunction(Runtime& runtime) {
  // This realm is constructed with ES6Proxy disabled and the Proxy constructor
  // removed before its only HBC is evaluated. Therefore `false` is an
  // engine-enforced predicate here, not the unsound userland approximation
  // used by generic compatibility shims.
  return std::make_unique<Function>(Function::createFromHostFunction(
      runtime,
      PropNameID::forAscii(runtime, "planSeamIsProxy"),
      1,
      [](Runtime&, const Value&, const Value*, size_t count) -> Value {
        if (count != 1) return Value(true);
        return Value(false);
      }));
}

std::unique_ptr<Function> makeSafeThrowFunction(
    ExactHermesPlanSeamRuntimeV1* seam, Runtime& runtime) {
  return std::make_unique<Function>(Function::createFromHostFunction(
      runtime,
      PropNameID::forAscii(runtime, "planSeamCaptureThrown"),
      1,
      [seam](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
        Object result(rt);
        std::string message;
        std::string stack;
#ifdef HERMES_HAS_BOUNDED_SAFE_TEXT_METADATA
        if (count == 1) {
          bool messageTruncated = false;
          bool stackTruncated = false;
          (void)seam->handle->runtime->getSafeJSErrorMetadata(
              args[0], message, stack, messageTruncated, stackTruncated);
        }
#else
        (void)seam;
        (void)args;
        (void)count;
#endif
        result.setProperty(
            rt, "message", String::createFromUtf8(rt, message));
        result.setProperty(rt, "stack", String::createFromUtf8(rt, stack));
        return result;
      }));
}

std::unique_ptr<Function> makeInvalidationFunction(
    ExactHermesPlanSeamRuntimeV1* seam, Runtime& runtime) {
  return std::make_unique<Function>(Function::createFromHostFunction(
      runtime,
      PropNameID::forAscii(runtime, "planSeamRecordInvalidation"),
      3,
      [seam](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
        if (seam->stopping || seam->stopped || seam->fenced ||
            seam->invalidationCallback == nullptr) {
          return Value(-1.0);
        }
        if (count != 3 || !args[0].isString() || !args[1].isNumber() ||
            !args[2].isString()) {
          seam->fenced = true;
          return Value(-1.0);
        }
        uint64_t generation = 0;
        uint64_t version = 0;
        const double reference = args[1].asNumber();
        if (!parseNonzeroU64(args[0].asString(rt).utf8(rt), generation) ||
            !parseNonzeroU64(args[2].asString(rt).utf8(rt), version) ||
            generation != seam->generation || !std::isfinite(reference) ||
            reference < 0 ||
            reference > std::numeric_limits<uint32_t>::max() ||
            std::floor(reference) != reference) {
          seam->fenced = true;
          return Value(-1.0);
        }
        // LLP 0297 W0: this callback only records/coalesces. Swift must enqueue
        // a fresh top-level physical-owner job before any read/publication.
        const int32_t status = seam->invalidationCallback(
            seam->invalidationContext,
            generation,
            static_cast<uint32_t>(reference),
            version);
        if (status != 0) seam->fenced = true;
        // The generated registry treats this as the narrow native transport
        // status (0 accepted, nonzero refused), not a JavaScript predicate.
        return Value(static_cast<double>(status));
      }));
}

bool installEndowment(
    ExactHermesPlanSeamRuntimeV1* seam,
    const ExHermesPlanSeamFacetHostInputsV1& inputs,
    std::unique_ptr<Function>& isProxy,
    std::unique_ptr<Function>& captureThrown,
    std::unique_ptr<Function>& recordInvalidation,
    std::string& reason) {
  auto& runtime = *seam->handle->runtime;
  if (!closeAmbientSurface(runtime, reason)) return false;
  isProxy = makeIsProxyFunction(runtime);
  captureThrown = makeSafeThrowFunction(seam, runtime);
  recordInvalidation = makeInvalidationFunction(seam, runtime);

  auto freeze = runtime.global()
                    .getPropertyAsObject(runtime, "Object")
                    .getPropertyAsFunction(runtime, "freeze");
  auto inputsObject = facetInputsObject(runtime, inputs);
  auto frozenInputs = freeze.call(runtime, inputsObject);

  Object native(runtime);
  native.setProperty(
      runtime,
      "generation",
      String::createFromUtf8(runtime, u64Text(seam->generation)));
  native.setProperty(runtime, "isProxy", *isProxy);
  native.setProperty(runtime, "captureThrown", *captureThrown);
  native.setProperty(runtime, "recordInvalidation", *recordInvalidation);
  native.setProperty(runtime, "facetHostInputs", std::move(frozenInputs));
  auto frozen = freeze.call(runtime, native);
  runtime.global().setProperty(
      runtime, "__exactPlanHermesSeamNativeV1", std::move(frozen));
  return true;
}

bool clearBootstrapGlobals(Runtime& runtime) {
  auto global = runtime.global();
  global.deleteProperty(runtime, "__exactPlanHermesSeamNativeV1");
  global.deleteProperty(runtime, "__exactPlanHermesSeamRegistryV1");
  return !global.hasProperty(runtime, "__exactPlanHermesSeamNativeV1") &&
      !global.hasProperty(runtime, "__exactPlanHermesSeamRegistryV1");
}

template <typename Invoke>
int32_t invokeAndLease(
    ExactHermesPlanSeamRuntimeV1* seam,
    bool capabilityScope,
    bool reactiveRead,
    Invoke&& invoke,
    uint8_t* outOutcomeDiscriminant,
    const uint8_t** outPayload,
    size_t* outPayloadLen,
    uint64_t* outReactiveVersion,
    uint64_t* outLeaseGeneration,
    uint64_t* outLeaseToken) {
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  ExactRuntimeDriveGuard guard(seam->handle, seam->handle->runtime_nonce);
  if (!guard) {
    return mapDriveGuardFailure(seam, guard.status());
  }
  CallbackActiveScope callbackScope(seam);
  try {
    PlanSeamReply reply;
    auto result = invoke(*seam->handle->runtime);
    if (!readReply(seam, *seam->handle->runtime, result, reply) ||
        !hasRequiredReactiveVersion(reply, reactiveRead)) {
      seam->fenced = true;
      return EX_HERMES_PLAN_SEAM_REGISTRY_V1;
    }
    return mintReply(
        seam,
        std::move(reply),
        outOutcomeDiscriminant,
        outPayload,
        outPayloadLen,
        outReactiveVersion,
        outLeaseGeneration,
        outLeaseToken);
  } catch (...) {
    if (seam->fenced) {
      return EX_HERMES_PLAN_SEAM_FENCED_V1;
    }
    if (!seam->providerFault) {
      seam->fenced = true;
      return EX_HERMES_PLAN_SEAM_ENGINE_V1;
    }
    try {
      PlanSeamReply reply;
      auto& runtime = *seam->handle->runtime;
      Value faultArguments[] = {
          String::createFromAscii(runtime, "native-wrapper"),
          String::createFromAscii(
              runtime, capabilityScope ? "capability" : "pure")};
      auto result = seam->providerFault->call(
          runtime,
          static_cast<const Value*>(faultArguments),
          static_cast<size_t>(2));
      if (!readReply(seam, *seam->handle->runtime, result, reply) ||
          !hasRequiredReactiveVersion(reply, reactiveRead)) {
        seam->fenced = true;
        return EX_HERMES_PLAN_SEAM_ENGINE_V1;
      }
      return mintReply(
          seam,
          std::move(reply),
          outOutcomeDiscriminant,
          outPayload,
          outPayloadLen,
          outReactiveVersion,
          outLeaseGeneration,
          outLeaseToken);
    } catch (...) {
      seam->fenced = true;
      return EX_HERMES_PLAN_SEAM_ENGINE_V1;
    }
  }
}

void dropRoots(ExactHermesPlanSeamRuntimeV1* seam) {
  seam->isProxy.reset();
  seam->captureThrown.reset();
  seam->recordInvalidation.reset();
  seam->callSync.reset();
  seam->callCapabilitySync.reset();
  seam->readReactiveSync.reset();
  seam->applyFacetHostInputs.reset();
  seam->providerFault.reset();
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  seam->benchmarkDirectProvider.reset();
  seam->benchmarkAssertDirectProvider.reset();
  seam->benchmarkProjectTick.reset();
  seam->benchmarkAssertTickProjection.reset();
  seam->benchmarkResetAdapterCounters.reset();
  seam->benchmarkTakeAdapterCounters.reset();
#endif
  seam->dispose.reset();
}

void retainFailedCreateQuarantine(
    std::unique_ptr<ExactHermesPlanSeamRuntimeV1> seam) {
  // A refused owner-affine destroy cannot return a usable handle to Swift,
  // but freeing only the wrapper would leave native host functions with a
  // dangling capture. Keep the fenced graph for process lifetime. The heap
  // allocation deliberately has no static destructor, which could otherwise
  // release JSI roots on an arbitrary process-exit thread.
  try {
    static auto* lock = new std::mutex();
    static auto* quarantined =
        new std::vector<std::unique_ptr<ExactHermesPlanSeamRuntimeV1>>();
    std::lock_guard<std::mutex> guard(*lock);
    quarantined->push_back(std::move(seam));
  } catch (...) {
    // The wrapper is captured by realm-owned host functions. If quarantine
    // bookkeeping cannot allocate, leaking the graph is the only safe
    // fail-closed outcome; deleting only the wrapper would leave a UAF.
    (void)seam.release();
  }
}

void destroyFailedCreate(ExactHermesPlanSeamRuntimeV1* seam) {
  if (seam == nullptr) return;
  std::unique_ptr<ExactHermesPlanSeamRuntimeV1> owned(seam);
  if (owned->handle != nullptr) {
    owned->stopping = true;
    owned->fenced = true;
    owned->invalidationCallback = nullptr;
    owned->invalidationContext = nullptr;
    dropRoots(owned.get());
    const int32_t status = ex_hermes_try_destroy(
        owned->handle, owned->handle->runtime_nonce);
    if (status != EXACT_RUNTIME_DRIVE_OK) {
      retainFailedCreateQuarantine(std::move(owned));
      return;
    }
    owned->handle = nullptr;
  }
}

}  // namespace

static int32_t createPlanSeamRuntimeV1(
    const ExHermesPlanSeamOptionsV1* options,
    ExactHermesPlanSeamRuntimeV1** outRuntime,
    ExHermesPlanSeamCreateDiagnosticV1* outDiagnostic
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
    ,
    ExHermesPlanSeamBenchmarkCreateTimingV1* outBenchmarkTiming,
    bool requireBenchmarkRoots
#endif
    ) {
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
  clearBenchmarkCreateTiming(outBenchmarkTiming);
#endif
  if (outRuntime != nullptr) *outRuntime = nullptr;
  if (options == nullptr || outRuntime == nullptr ||
      options->abi_version != EX_HERMES_PLAN_SEAM_ABI_VERSION_V1 ||
      options->struct_size != sizeof(ExHermesPlanSeamOptionsV1) ||
      options->generation == 0 || options->executor_identity == 0 ||
      options->hbc_bytes == nullptr || options->hbc_len == 0 ||
      options->hbc_len > kMaximumTransportBytes ||
      options->expected_registry_receipt == nullptr ||
      options->expected_registry_receipt_len == 0 ||
      options->expected_registry_receipt_len > kMaximumTransportBytes ||
      !validFacetInputs(options->facet_host_inputs)) {
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_INVALID_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_ARGUMENTS_V1,
        "plan seam create options are invalid");
  }
  const uint64_t heapBytes = options->heap_bytes == 0
      ? kDefaultHeapBytes
      : options->heap_bytes;
  if (heapBytes > kMaximumHeapBytes) {
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_INVALID_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_HEAP_LIMIT_V1,
        "plan seam heap limit exceeds the maximum");
  }
  std::string bytecodeReason;
  if (!planSeamBytecodeSanityCheck(
          options->hbc_bytes, options->hbc_len, bytecodeReason)) {
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_INVALID_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_BYTECODE_V1,
        "plan seam HBC sanity check failed: " + bytecodeReason);
  }
  const uint64_t hostContext = ibex_private_claim_restricted_host_context();
  if (hostContext == 0) {
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_HOST_CONTEXT_V1,
        "plan seam restricted host context is unavailable");
  }
  RestrictedHostContextLease hostContextLease(hostContext);

  auto gc = ::hermes::vm::GCConfig::Builder()
                .withShouldRecordStats(true)
                .withName("exact-plan-hermes-seam")
                .withInitHeapSize(1 << 20)
                .withMaxHeapSize(heapBytes)
                .build();
  auto builder = ::hermes::vm::RuntimeConfig::Builder()
                     .withGCConfig(gc)
                     .withMicrotaskQueue(false)
                     .withEnableHermesInternal(false)
                     .withES6Proxy(false);
#if defined(EXACT_HAVE_HERMES_ES6_BLOCK_SCOPING_CONFIG)
  builder.withES6BlockScoping(ibexHermesES6BlockScopingEnabled());
#elif defined(EXACT_HAVE_HERMES_ENABLE_BLOCK_SCOPING_CONFIG)
  builder.withEnableBlockScoping(ibexHermesES6BlockScopingEnabled());
#endif
  auto hermes = facebook::hermes::makeHermesRuntime(
      builder.withEnableEval(true).build());
  if (!hermes) {
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_RUNTIME_V1,
        "plan seam Hermes runtime creation failed");
  }

  auto seam = std::make_unique<ExactHermesPlanSeamRuntimeV1>();
  // Keep the one-live-lease map's bucket allocation outside retained
  // telemetry; every successful emplace still allocates its observable node.
  seam->leases.reserve(1);
  seam->generation = options->generation;
  seam->executorIdentity = options->executor_identity;
  seam->owner = std::this_thread::get_id();
  seam->invalidationCallback = options->invalidation_callback;
  seam->invalidationContext = options->invalidation_context;
  seam->handle = new ExactHermesRuntime();
  seam->handle->runtime = std::move(hermes);
  seam->handle->runtime_thread = seam->owner;
  seam->handle->host_context_id = hostContext;
  seam->handle->restricted = true;
  seam->handle->structural_lockdown = true;
  seam->handle->runtime_nonce = exactAllocateRuntimeNonce();
  if (seam->handle->runtime_nonce == 0) {
    delete seam->handle;
    seam->handle = nullptr;
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_NONCE_V1,
        "plan seam runtime nonce allocation failed");
  }
  bool registrationFailed = false;
  std::string registrationReason = "plan seam runtime registration failed";
  try {
    disableDebugger(seam->handle);
    registerRuntime(seam->handle);
  } catch (const std::exception& error) {
    // A JSError retains a realm-owned Value. Copy only its bounded native
    // diagnostic before the catch ends; destroy the runtime afterward.
    registrationReason += ": ";
    registrationReason += error.what();
    registrationFailed = true;
  } catch (...) {
    // A JSError retains a realm-owned Value. Do not delete the runtime until
    // the caught exception has left scope and its destructor has run.
    registrationFailed = true;
  }
  if (registrationFailed) {
    delete seam->handle;
    seam->handle = nullptr;
    return refuseCreate(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_REGISTRATION_V1,
        registrationReason);
  }
  hostContextLease.disarm();

  int32_t createFailure = EX_HERMES_PLAN_SEAM_ENGINE_V1;
  uint32_t createDiagnosticCode =
      EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1;
  std::string createDiagnosticReason =
      "plan seam create failed unexpectedly";
  try {
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_DRIVE_GUARD_V1;
    createDiagnosticReason = "plan seam create drive was refused";
    ExactRuntimeDriveGuard guard(
        seam->handle, seam->handle->runtime_nonce);
    if (!guard) {
      createFailure = mapDriveGuardFailure(seam.get(), guard.status());
      createDiagnosticReason += " (drive status " +
          std::to_string(guard.status()) + ")";
      throw std::runtime_error(createDiagnosticReason);
    }
    CallbackActiveScope callbackScope(seam.get());
    auto& runtime = *seam->handle->runtime;
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_ENDOWMENT_V1;
    createDiagnosticReason = "plan seam endowment installation failed";
    std::string endowmentReason;
    if (!installEndowment(
            seam.get(),
            options->facet_host_inputs,
            seam->isProxy,
            seam->captureThrown,
            seam->recordInvalidation,
            endowmentReason)) {
      if (endowmentReason.rfind("HermesInternal", 0) == 0) {
        createDiagnosticCode =
            EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_HERMES_INTERNAL_V1;
      } else if (endowmentReason.rfind("ambient", 0) == 0) {
        createDiagnosticCode =
            EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_AMBIENT_SURFACE_V1;
      }
      if (!endowmentReason.empty()) {
        createDiagnosticReason += ": " + endowmentReason;
      }
      throw std::runtime_error(createDiagnosticReason);
    }

#ifdef EXACT_HAVE_HERMES_DYNAMIC_CODE_LATCH
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_VM_RUNTIME_V1;
    createDiagnosticReason = "plan seam VM runtime is unavailable";
    auto* vm = seam->handle->runtime->getVMRuntimeUnsafe();
    if (vm == nullptr) {
      throw std::runtime_error(createDiagnosticReason);
    }
    // Host-selected HBC evaluation remains available after this one-way VM
    // latch. Apply it before provider bytecode executes so no intrinsic
    // Function-constructor path can compile and retain source-created code.
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_DYNAMIC_CODE_LATCH_V1;
    createDiagnosticReason = "plan seam dynamic-code latch failed";
    ex_hermes_vm_disable_eval(vm);
#else
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_DYNAMIC_CODE_LATCH_V1;
    createDiagnosticReason = "plan seam dynamic-code latch is unavailable";
    throw std::runtime_error(createDiagnosticReason);
#endif

    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_HBC_EVALUATION_V1;
    createDiagnosticReason = "plan seam HBC evaluation failed";
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
    // The cold artifact phase is intentionally narrower than restricted-realm
    // construction: it measures loading/copying the already-compiled HBC and
    // Hermes evaluation/instantiation only.
    const uint64_t artifactPhaseStart = outBenchmarkTiming != nullptr
        ? continuousNanoseconds()
        : 0;
#endif
    auto hbc = std::make_shared<PlanSeamAlignedBytecodeBuffer>(
        options->hbc_bytes, options->hbc_len);
    auto evaluated = runtime.evaluateJavaScript(
        hbc, "exact:plan-hermes-seam-registry.hbc");
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
    const uint64_t artifactPhaseEnd = outBenchmarkTiming != nullptr
        ? continuousNanoseconds()
        : 0;
#endif
    Value registryValue = std::move(evaluated);
    if (!registryValue.isObject()) {
      registryValue = runtime.global().getProperty(
          runtime, "__exactPlanHermesSeamRegistryV1");
    }
    if (!registryValue.isObject()) {
      createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      createDiagnosticCode =
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_REGISTRY_ABSENT_V1;
      createDiagnosticReason = "plan seam registry object is absent";
      throw std::runtime_error(createDiagnosticReason);
    }
    auto registry = registryValue.asObject(runtime);
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_RECEIPT_MALFORMED_V1;
    createDiagnosticReason = "plan seam registry receipt is malformed";
    auto receipt = registry.getProperty(runtime, "receipt");
    if (receipt.isString()) {
      const std::string receiptText = receipt.asString(runtime).utf8(runtime);
      seam->registryReceipt.assign(receiptText.begin(), receiptText.end());
    } else if (receipt.isObject()) {
      const uint8_t* receiptBytes = nullptr;
      size_t receiptLength = 0;
      if (!extractArrayBufferView(
              runtime,
              receipt.asObject(runtime),
              receiptBytes,
              receiptLength) ||
          receiptLength == 0 || receiptLength > kMaximumTransportBytes ||
          receiptBytes == nullptr) {
        createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
        throw std::runtime_error(createDiagnosticReason);
      }
      seam->registryReceipt.assign(
          receiptBytes, receiptBytes + receiptLength);
    } else {
      createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      createDiagnosticReason = "plan seam registry receipt is absent";
      throw std::runtime_error(createDiagnosticReason);
    }
    if (seam->registryReceipt.size() !=
            options->expected_registry_receipt_len ||
        std::memcmp(
            seam->registryReceipt.data(),
            options->expected_registry_receipt,
            seam->registryReceipt.size()) != 0) {
      createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      createDiagnosticCode =
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_RECEIPT_MISMATCH_V1;
      createDiagnosticReason = "plan seam registry receipt does not match";
      throw std::runtime_error(createDiagnosticReason);
    }
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_REGISTRY_INCOMPLETE_V1;
    createDiagnosticReason = "plan seam rooted registry is incomplete";
    if (!copyRegistryFunction(
            runtime, registry, "callSync", seam->callSync) ||
        !copyRegistryFunction(
            runtime,
            registry,
            "callCapabilitySync",
            seam->callCapabilitySync) ||
        !copyRegistryFunction(
            runtime,
            registry,
            "readReactiveSync",
            seam->readReactiveSync) ||
        !copyRegistryFunction(
            runtime,
            registry,
            "applyFacetHostInputsV1",
            seam->applyFacetHostInputs) ||
        !copyRegistryFunction(
            runtime, registry, "providerFault", seam->providerFault) ||
        !copyRegistryFunction(runtime, registry, "dispose", seam->dispose)) {
      createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      throw std::runtime_error(createDiagnosticReason);
    }
    createDiagnosticCode =
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_BOOTSTRAP_CLEANUP_V1;
    createDiagnosticReason =
        "plan seam bootstrap globals could not be removed";
    if (!clearBootstrapGlobals(runtime)) {
      createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      throw std::runtime_error(createDiagnosticReason);
    }
    if (seam->fenced) {
      createFailure = EX_HERMES_PLAN_SEAM_FENCED_V1;
      createDiagnosticCode =
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_FENCED_V1;
      createDiagnosticReason = "plan seam fenced during registry creation";
      throw std::runtime_error(createDiagnosticReason);
    }
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
    // Stop the production-comparable registry-admission phase before copying
    // any benchmark-only roots. The local registry Object remains rooted after
    // its bootstrap global is removed, so benchmark setup can safely follow.
    const uint64_t registryPhaseEnd = outBenchmarkTiming != nullptr
        ? continuousNanoseconds()
        : 0;
    if (requireBenchmarkRoots) {
      createDiagnosticCode =
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_REGISTRY_INCOMPLETE_V1;
      createDiagnosticReason =
          "plan seam benchmark comparator roots are incomplete";
      if (!copyRegistryFunction(
              runtime,
              registry,
              "benchmarkDirectProvider",
              seam->benchmarkDirectProvider) ||
          !copyRegistryFunction(
              runtime,
              registry,
              "benchmarkAssertDirectProvider",
              seam->benchmarkAssertDirectProvider) ||
          !copyRegistryFunction(
              runtime,
              registry,
              "benchmarkProjectTick",
              seam->benchmarkProjectTick) ||
          !copyRegistryFunction(
              runtime,
              registry,
              "benchmarkAssertTickProjection",
              seam->benchmarkAssertTickProjection) ||
          !copyRegistryFunction(
              runtime,
              registry,
              "benchmarkResetAdapterCounters",
              seam->benchmarkResetAdapterCounters) ||
          !copyRegistryFunction(
              runtime,
              registry,
              "benchmarkTakeAdapterCounters",
              seam->benchmarkTakeAdapterCounters)) {
        createFailure = EX_HERMES_PLAN_SEAM_REGISTRY_V1;
        throw std::runtime_error(createDiagnosticReason);
      }
    }
    if (seam->fenced) {
      createFailure = EX_HERMES_PLAN_SEAM_FENCED_V1;
      createDiagnosticCode =
          EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_FENCED_V1;
      createDiagnosticReason =
          "plan seam fenced during benchmark root setup";
      throw std::runtime_error(createDiagnosticReason);
    }
    if (outBenchmarkTiming != nullptr) {
      outBenchmarkTiming->artifact_load_compile_instantiate_ns =
          elapsedNanoseconds(artifactPhaseStart, artifactPhaseEnd);
      outBenchmarkTiming->registry_admission_ns =
          elapsedNanoseconds(artifactPhaseEnd, registryPhaseEnd);
    }
#endif
    *outRuntime = seam.release();
    writeCreateDiagnostic(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_OK_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_NONE_V1,
        "plan seam create succeeded");
    return EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (const std::exception&) {
    // A JSError owns a realm Value. Let the caught object die at the end of
    // this catch before owner-affine cleanup begins. The stage-specific reason
    // is retained instead of reflecting an authored thrown value across the
    // restricted-realm boundary.
  } catch (...) {
    createDiagnosticReason += ": non-standard native exception";
  }
  writeCreateDiagnostic(
      outDiagnostic,
      createFailure,
      createDiagnosticCode,
      createDiagnosticReason);
  destroyFailedCreate(seam.release());
  return createFailure;
}

extern "C" int32_t ex_hermes_plan_seam_create_v1(
    const ExHermesPlanSeamOptionsV1* options,
    ExactHermesPlanSeamRuntimeV1** outRuntime,
    ExHermesPlanSeamCreateDiagnosticV1* outDiagnostic) {
  if (outRuntime != nullptr) *outRuntime = nullptr;
  if (outDiagnostic == nullptr) return EX_HERMES_PLAN_SEAM_INVALID_V1;
  writeCreateDiagnostic(
      outDiagnostic,
      EX_HERMES_PLAN_SEAM_ENGINE_V1,
      EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
      "plan seam create did not reach a classified result");
  try {
    return createPlanSeamRuntimeV1(
        options,
        outRuntime,
        outDiagnostic
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
        ,
        nullptr,
        false
#endif
        );
  } catch (const std::exception& error) {
    if (outRuntime != nullptr) *outRuntime = nullptr;
    writeCreateDiagnostic(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
        std::string("plan seam create escaped its stage: ") + error.what());
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  } catch (...) {
    if (outRuntime != nullptr) *outRuntime = nullptr;
    writeCreateDiagnostic(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
        "plan seam create escaped its stage with a non-standard exception");
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
extern "C" int32_t ex_hermes_plan_seam_create_benchmark_v1(
    const ExHermesPlanSeamOptionsV1* options,
    ExactHermesPlanSeamRuntimeV1** outRuntime,
    ExHermesPlanSeamCreateDiagnosticV1* outDiagnostic,
    ExHermesPlanSeamBenchmarkCreateTimingV1* outTiming) {
  if (outRuntime != nullptr) *outRuntime = nullptr;
  clearBenchmarkCreateTiming(outTiming);
  if (outDiagnostic == nullptr || outTiming == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  writeCreateDiagnostic(
      outDiagnostic,
      EX_HERMES_PLAN_SEAM_ENGINE_V1,
      EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
      "plan seam benchmark create did not reach a classified result");
  try {
    return createPlanSeamRuntimeV1(
        options, outRuntime, outDiagnostic, outTiming, true);
  } catch (const std::exception& error) {
    if (outRuntime != nullptr) *outRuntime = nullptr;
    clearBenchmarkCreateTiming(outTiming);
    writeCreateDiagnostic(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
        std::string("plan seam benchmark create escaped its stage: ") +
            error.what());
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  } catch (...) {
    if (outRuntime != nullptr) *outRuntime = nullptr;
    clearBenchmarkCreateTiming(outTiming);
    writeCreateDiagnostic(
        outDiagnostic,
        EX_HERMES_PLAN_SEAM_ENGINE_V1,
        EX_HERMES_PLAN_SEAM_CREATE_DIAGNOSTIC_UNEXPECTED_V1,
        "plan seam benchmark create escaped with a non-standard exception");
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_benchmark_direct_batch_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    const uint32_t* caseIds,
    size_t caseCount,
    uint8_t projectTick,
    uint64_t* outCallLatencyNs,
    ExHermesPlanSeamBenchmarkDirectBatchResultV1* outResult) {
  clearBenchmarkDirectBatchResult(outResult);
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  if (caseIds == nullptr || caseCount == 0 || projectTick > 1 ||
      caseCount > kMaximumTransportBytes / sizeof(uint32_t) ||
      outCallLatencyNs == nullptr || outResult == nullptr ||
      seam->benchmarkDirectProvider == nullptr ||
      seam->benchmarkAssertDirectProvider == nullptr ||
      (projectTick != 0 &&
       (seam->benchmarkProjectTick == nullptr ||
        seam->benchmarkAssertTickProjection == nullptr))) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  std::fill(outCallLatencyNs, outCallLatencyNs + caseCount, 0);
  try {
    ExactRuntimeDriveGuard guard(
        seam->handle, seam->handle->runtime_nonce);
    if (!guard) return mapDriveGuardFailure(seam, guard.status());
    CallbackActiveScope callbackScope(seam);
    auto& runtime = *seam->handle->runtime;
    std::vector<std::pair<uint32_t, Value>> results;
    results.reserve(caseCount);
    Value tickProjection;
    const uint64_t batchStart = continuousNanoseconds();
    for (size_t index = 0; index < caseCount; ++index) {
      const uint32_t caseId = caseIds[index];
      if (caseId == 0) return EX_HERMES_PLAN_SEAM_INVALID_V1;
      const uint64_t callStart = continuousNanoseconds();
      Value result = seam->benchmarkDirectProvider->call(
          runtime,
          Value(static_cast<double>(caseId)),
          Value(static_cast<double>(index)));
      const uint64_t callEnd = continuousNanoseconds();
      outCallLatencyNs[index] = elapsedNanoseconds(callStart, callEnd);
      results.emplace_back(caseId, std::move(result));
    }
    if (projectTick != 0) {
      // LLP 0517 section 10.1 requires the tick comparator to include the
      // same two-board and visible-row formatting/style projection as the
      // native/runner lanes. Keep that work inside the containing batch
      // interval while retaining provider-only per-call samples.
      tickProjection = seam->benchmarkProjectTick->call(runtime);
    }
    const uint64_t batchEnd = continuousNanoseconds();
    // Result encoding/assertion is deliberately outside every retained timing
    // interval. It proves identical semantics without charging the direct
    // comparator for a boundary codec it does not traverse.
    for (auto& entry : results) {
      Value assertion = seam->benchmarkAssertDirectProvider->call(
          runtime,
          Value(static_cast<double>(entry.first)),
          std::move(entry.second));
      if (!assertion.isBool() || !assertion.getBool()) {
        seam->fenced = true;
        return EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      }
    }
    if (projectTick != 0) {
      Value assertion = seam->benchmarkAssertTickProjection->call(
          runtime, std::move(tickProjection));
      if (!assertion.isBool() || !assertion.getBool()) {
        seam->fenced = true;
        return EX_HERMES_PLAN_SEAM_REGISTRY_V1;
      }
    }
    outResult->batch_latency_ns =
        elapsedNanoseconds(batchStart, batchEnd);
    outResult->actual_calls = caseCount;
    return EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (...) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_benchmark_reset_adapter_counters_v1(
    ExactHermesPlanSeamRuntimeV1* seam) {
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  if (seam->benchmarkResetAdapterCounters == nullptr ||
      seam->benchmarkTakeAdapterCounters == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  try {
    ExactRuntimeDriveGuard guard(seam->handle, seam->handle->runtime_nonce);
    if (!guard) return mapDriveGuardFailure(seam, guard.status());
    CallbackActiveScope callbackScope(seam);
    seam->benchmarkArgumentBytesCopied = 0;
    seam->benchmarkResultBytesCopied = 0;
    seam->benchmarkAdapterAllocations = 0;
    seam->benchmarkCountersOverflowed = false;
    seam->benchmarkResetAdapterCounters->call(*seam->handle->runtime);
    seam->benchmarkCountersArmed = true;
    return EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (...) {
    seam->benchmarkCountersArmed = false;
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_benchmark_take_adapter_counters_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    ExHermesPlanSeamBenchmarkAdapterCountersV1* outCounters) {
  if (outCounters == nullptr) return EX_HERMES_PLAN_SEAM_INVALID_V1;
  *outCounters = {};
  outCounters->abi_version = 1;
  outCounters->struct_size =
      static_cast<uint32_t>(sizeof(ExHermesPlanSeamBenchmarkAdapterCountersV1));
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  if (!seam->benchmarkCountersArmed ||
      seam->benchmarkTakeAdapterCounters == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  try {
    ExactRuntimeDriveGuard guard(seam->handle, seam->handle->runtime_nonce);
    if (!guard) return mapDriveGuardFailure(seam, guard.status());
    CallbackActiveScope callbackScope(seam);
    auto& runtime = *seam->handle->runtime;
    Value value = seam->benchmarkTakeAdapterCounters->call(runtime);
    seam->benchmarkCountersArmed = false;
    if (!value.isObject() || seam->benchmarkCountersOverflowed) {
      seam->fenced = true;
      return EX_HERMES_PLAN_SEAM_REGISTRY_V1;
    }
    auto object = value.asObject(runtime);
    auto readCounter = [&runtime, &object](
                           const char* name,
                           uint64_t& output) -> bool {
      Value property = object.getProperty(runtime, name);
      if (!property.isNumber()) return false;
      const double number = property.asNumber();
      if (!std::isfinite(number) || number < 0 ||
          number > 9007199254740991.0 || std::floor(number) != number) {
        return false;
      }
      output = static_cast<uint64_t>(number);
      return true;
    };
    uint64_t tsArgumentBytes = 0;
    uint64_t tsResultBytes = 0;
    uint64_t tsAllocations = 0;
    if (!readCounter("argumentBytesCopied", tsArgumentBytes) ||
        !readCounter("resultBytesCopied", tsResultBytes) ||
        !readCounter("adapterAllocations", tsAllocations) ||
        !addBenchmarkCounter(
            seam->benchmarkArgumentBytesCopied, tsArgumentBytes) ||
        !addBenchmarkCounter(seam->benchmarkResultBytesCopied, tsResultBytes) ||
        !addBenchmarkCounter(seam->benchmarkAdapterAllocations, tsAllocations)) {
      seam->fenced = true;
      return EX_HERMES_PLAN_SEAM_REGISTRY_V1;
    }
    outCounters->argument_bytes_copied =
        seam->benchmarkArgumentBytesCopied;
    outCounters->result_bytes_copied = seam->benchmarkResultBytesCopied;
    outCounters->adapter_allocations = seam->benchmarkAdapterAllocations;
    return EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (...) {
    seam->benchmarkCountersArmed = false;
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}
#endif

extern "C" int32_t ex_hermes_plan_seam_call_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    uint32_t bindingKind,
    uint32_t bindingRef,
    uint64_t callId,
    const uint8_t* arguments,
    size_t argumentsLen,
    uint8_t* outOutcomeDiscriminant,
    const uint8_t** outPayload,
    size_t* outPayloadLen,
    uint64_t* outReactiveVersion,
    uint64_t* outLeaseGeneration,
    uint64_t* outLeaseToken) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  // Owner/re-entry/fence admission precedes inspection of every caller-owned
  // argument or output location.
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  const int32_t outputStatus = prepareOutputs(
      outOutcomeDiscriminant,
      outPayload,
      outPayloadLen,
      outReactiveVersion,
      outLeaseGeneration,
      outLeaseToken);
  if (outputStatus != EX_HERMES_PLAN_SEAM_OK_V1 ||
      argumentsLen > kMaximumTransportBytes ||
      (argumentsLen != 0 && arguments == nullptr)) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  const bool pureCall =
      bindingKind == kBindingKindHostImport && callId == 0;
  const bool capabilityCall =
      bindingKind == kBindingKindCapability && callId != 0;
  if (!pureCall && !capabilityCall) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  try {
    if (pureCall) {
      return invokeAndLease(
          seam,
          false,
          false,
          [seam, bindingRef, arguments, argumentsLen](Runtime& runtime) {
            if (!seam->callSync) {
              throw std::runtime_error("plan seam call root is absent");
            }
            // Copy only after owner/re-entry admission. A wrong-owner caller
            // must be refused before native argument memory is inspected or
            // seam state is mutated.
            std::vector<uint8_t> copiedArguments;
            if (argumentsLen != 0) {
              copiedArguments.assign(arguments, arguments + argumentsLen);
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
              recordBenchmarkAdapter(seam, argumentsLen, 0, 1);
#endif
            }
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
            auto argumentBytes =
                makeUint8Array(
                    runtime,
                    std::move(copiedArguments),
                    recordBenchmarkArrayBoundaryAllocation,
                    seam);
#else
            auto argumentBytes =
                makeUint8Array(runtime, std::move(copiedArguments));
#endif
            Value values[] = {Value(static_cast<double>(bindingRef)),
                              std::move(argumentBytes)};
            return seam->callSync->call(
                runtime,
                static_cast<const Value*>(values),
                static_cast<size_t>(2));
          },
          outOutcomeDiscriminant,
          outPayload,
          outPayloadLen,
          outReactiveVersion,
          outLeaseGeneration,
          outLeaseToken);
    }
    return invokeAndLease(
        seam,
        true,
        false,
        [seam,
         bindingRef,
         callId,
         arguments,
         argumentsLen](Runtime& runtime) {
          if (!seam->callCapabilitySync) {
            throw std::runtime_error("plan seam capability root is absent");
          }
          std::vector<uint8_t> copiedArguments;
          if (argumentsLen != 0) {
            copiedArguments.assign(arguments, arguments + argumentsLen);
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
            recordBenchmarkAdapter(seam, argumentsLen, 0, 1);
#endif
          }
#if defined(IBEX_PLAN_SEAM_BENCHMARK_ABI)
          auto argumentBytes =
              makeUint8Array(
                  runtime,
                  std::move(copiedArguments),
                  recordBenchmarkArrayBoundaryAllocation,
                  seam);
#else
          auto argumentBytes =
              makeUint8Array(runtime, std::move(copiedArguments));
#endif
          Value values[] = {
              Value(static_cast<double>(bindingRef)),
              String::createFromUtf8(runtime, u64Text(callId)),
              std::move(argumentBytes)};
          return seam->callCapabilitySync->call(
              runtime,
              static_cast<const Value*>(values),
              static_cast<size_t>(3));
        },
        outOutcomeDiscriminant,
        outPayload,
        outPayloadLen,
        outReactiveVersion,
        outLeaseGeneration,
        outLeaseToken);
  } catch (...) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_read_reactive_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    uint32_t hostImportRef,
    uint8_t* outOutcomeDiscriminant,
    const uint8_t** outPayload,
    size_t* outPayloadLen,
    uint64_t* outReactiveVersion,
    uint64_t* outLeaseGeneration,
    uint64_t* outLeaseToken) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  // Preserve the same owner-before-caller-memory admission law as call_v1.
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  const int32_t outputStatus = prepareOutputs(
      outOutcomeDiscriminant,
      outPayload,
      outPayloadLen,
      outReactiveVersion,
      outLeaseGeneration,
      outLeaseToken);
  if (outputStatus != EX_HERMES_PLAN_SEAM_OK_V1) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  return invokeAndLease(
      seam,
      false,
      true,
      [seam, hostImportRef](Runtime& runtime) {
        if (!seam->readReactiveSync) {
          throw std::runtime_error("plan seam reactive root is absent");
        }
        Value argument(static_cast<double>(hostImportRef));
        return seam->readReactiveSync->call(
            runtime,
            static_cast<const Value*>(&argument),
            static_cast<size_t>(1));
      },
      outOutcomeDiscriminant,
      outPayload,
      outPayloadLen,
      outReactiveVersion,
      outLeaseGeneration,
      outLeaseToken);
}

extern "C" int32_t ex_hermes_plan_seam_release_result_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    uint64_t leaseGeneration,
    uint64_t leaseToken,
    const uint8_t* payload,
    size_t payloadLen) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->owner != std::this_thread::get_id()) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  if (seam->handle == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->callbackActive) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_LEASE_V1;
  }
  if (leaseToken == 0) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  auto found = seam->leases.find(leaseToken);
  if (leaseGeneration != seam->generation || found == seam->leases.end()) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_LEASE_V1;
  }
  const auto& bytes = found->second->payload;
  const uint8_t* expected = bytes.empty() ? nullptr : bytes.data();
  if (payload != expected || payloadLen != bytes.size()) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_LEASE_V1;
  }
  seam->leases.erase(found);
  return EX_HERMES_PLAN_SEAM_OK_V1;
}

extern "C" int32_t ex_hermes_plan_seam_apply_facet_host_inputs_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    const ExHermesPlanSeamFacetHostInputsV1* inputs) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  const int32_t ownerStatus = ownerDriveStatus(seam);
  if (ownerStatus != EX_HERMES_PLAN_SEAM_OK_V1) return ownerStatus;
  // Admit the physical owner before reading any caller-owned bytes. This is
  // the LLP 0297 §4.2 same-owner seam, not a cross-queue sync surface.
  if (inputs == nullptr || !validFacetInputs(*inputs)) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  ExactRuntimeDriveGuard guard(seam->handle, seam->handle->runtime_nonce);
  if (!guard) {
    return mapDriveGuardFailure(seam, guard.status());
  }
  if (!seam->applyFacetHostInputs) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  CallbackActiveScope callbackScope(seam);
  try {
    auto& runtime = *seam->handle->runtime;
    auto object = facetInputsObject(runtime, *inputs);
    seam->applyFacetHostInputs->call(runtime, object);
    return seam->fenced ? EX_HERMES_PLAN_SEAM_FENCED_V1
                        : EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (...) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_registry_receipt_v1(
    ExactHermesPlanSeamRuntimeV1* seam,
    const uint8_t** outBytes,
    size_t* outLen) {
  if (outBytes != nullptr) *outBytes = nullptr;
  if (outLen != nullptr) *outLen = 0;
  if (seam == nullptr || outBytes == nullptr || outLen == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->owner != std::this_thread::get_id()) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  *outBytes = seam->registryReceipt.empty()
      ? nullptr
      : seam->registryReceipt.data();
  *outLen = seam->registryReceipt.size();
  return EX_HERMES_PLAN_SEAM_OK_V1;
}

extern "C" uint64_t ex_hermes_plan_seam_executor_identity_v1(
    const ExactHermesPlanSeamRuntimeV1* seam) {
  return seam == nullptr ? 0 : seam->executorIdentity;
}

extern "C" int32_t ex_hermes_plan_seam_shutdown_v1(
    ExactHermesPlanSeamRuntimeV1* seam) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->owner != std::this_thread::get_id()) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  if (seam->handle == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->callbackActive) {
    return EX_HERMES_PLAN_SEAM_REENTRANT_V1;
  }
  if (seam->stopped) return EX_HERMES_PLAN_SEAM_OK_V1;
  seam->stopping = true;
  seam->invalidationCallback = nullptr;
  seam->invalidationContext = nullptr;
  ExactRuntimeDriveGuard guard(seam->handle, seam->handle->runtime_nonce);
  if (!guard) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  try {
    if (seam->dispose) seam->dispose->call(*seam->handle->runtime);
    dropRoots(seam);
    seam->stopped = true;
    return EX_HERMES_PLAN_SEAM_OK_V1;
  } catch (...) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_ENGINE_V1;
  }
}

extern "C" int32_t ex_hermes_plan_seam_destroy_v1(
    ExactHermesPlanSeamRuntimeV1* seam) {
  if (seam == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->owner != std::this_thread::get_id()) {
    return EX_HERMES_PLAN_SEAM_OFF_OWNER_V1;
  }
  if (seam->handle == nullptr) {
    return EX_HERMES_PLAN_SEAM_INVALID_V1;
  }
  if (seam->callbackActive) {
    return EX_HERMES_PLAN_SEAM_REENTRANT_V1;
  }
  if (!seam->stopped || !seam->leases.empty()) {
    seam->fenced = true;
    return EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  auto* handle = seam->handle;
  const uint64_t nonce = handle->runtime_nonce;
  const int32_t status = ex_hermes_try_destroy(handle, nonce);
  if (status != EXACT_RUNTIME_DRIVE_OK) {
    seam->fenced = true;
    return status == EXACT_RUNTIME_DRIVE_OFF_OWNER
        ? EX_HERMES_PLAN_SEAM_OFF_OWNER_V1
        : EX_HERMES_PLAN_SEAM_FENCED_V1;
  }
  seam->handle = nullptr;
  delete seam;
  return EX_HERMES_PLAN_SEAM_OK_V1;
}
