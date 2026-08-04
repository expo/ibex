// Dedicated engine half of the restricted external-script worker.
//
// This file intentionally exposes only private C symbols consumed by the Rust
// owner-thread queue. Public embedders receive ExactRestrictedWorkerV1 and can
// never obtain this ExactHermesRuntime pointer.
// @ref LLP 0048#61-native-construction-and-ownership-seam

#include "../../include/exact_runtime.h"
#include "hermes_runtime_internal.h"

#include <cstring>
#include <algorithm>
#include <memory>
#include <string>

using facebook::jsi::Function;
using facebook::jsi::Array;
using facebook::jsi::Object;
using facebook::jsi::PropNameID;
using facebook::jsi::Value;

void registerRuntime(ExactHermesRuntime* runtime);

namespace {
using EmitCallback = int32_t (*)(void*, const uint8_t*, size_t);
using DigestCallback = int32_t (*)(const uint8_t*, size_t, uint8_t*, size_t);
using FaultCallback = int32_t (*)(void*, uint32_t);

struct RestrictedEngine {
  ExactHermesRuntime* handle = nullptr;
  EmitCallback emit = nullptr;
  FaultCallback fault = nullptr;
  void* context = nullptr;
  bool started = false;
  std::unique_ptr<Function> emit_function;
  std::unique_ptr<Function> receiver;
  std::unique_ptr<Function> broker_factory;
  std::unique_ptr<Function> settlement_codec;
};

std::string base64url(const uint8_t* bytes, size_t length) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string output;
  output.reserve((length * 4 + 2) / 3);
  for (size_t index = 0; index < length; index += 3) {
    uint32_t value = static_cast<uint32_t>(bytes[index]) << 16;
    if (index + 1 < length) value |= static_cast<uint32_t>(bytes[index + 1]) << 8;
    if (index + 2 < length) value |= bytes[index + 2];
    output.push_back(alphabet[(value >> 18) & 63]);
    output.push_back(alphabet[(value >> 12) & 63]);
    if (index + 1 < length) output.push_back(alphabet[(value >> 6) & 63]);
    if (index + 2 < length) output.push_back(alphabet[value & 63]);
  }
  return output;
}

bool drain(ExactHermesRuntime* handle) {
#if defined(_WIN32)
  return handle->runtime->drainMicrotasks(1024);
#else
  return handle->runtime->drainMicrotasks(-1);
#endif
}

void installSurface(RestrictedEngine* engine, DigestCallback digest) {
  auto& rt = *engine->handle->runtime;
  auto emit = Function::createFromHostFunction(
      rt,
      PropNameID::forAscii(rt, "__ibexRestrictedEmit"),
      1,
      [engine](facebook::jsi::Runtime& runtime,
               const Value&,
               const Value* args,
               size_t count) -> Value {
        if (count != 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime, "restricted broker emission must be one string");
        }
        const std::string bytes = args[0].asString(runtime).utf8(runtime);
        if (bytes.empty() || engine->emit == nullptr ||
            engine->emit(
                engine->context,
                reinterpret_cast<const uint8_t*>(bytes.data()),
                bytes.size()) != 0) {
          throw facebook::jsi::JSError(runtime, "restricted broker queue refused");
        }
        return Value::undefined();
      });
  engine->emit_function = std::make_unique<Function>(std::move(emit));
  auto codec = Function::createFromHostFunction(
      rt,
      PropNameID::forAscii(rt, "restrictedSettlementCodec"),
      3,
      [engine, digest](facebook::jsi::Runtime& runtime,
               const Value&,
               const Value* args,
               size_t count) -> Value {
        if (count != 3 || !args[0].isString() || !args[1].isNumber() ||
            !args[2].isNumber()) {
          throw facebook::jsi::JSError(runtime, "invalid settlement codec input");
        }
        const std::string bytes = args[0].asString(runtime).utf8(runtime);
        const double chunk_number = args[1].asNumber();
        const double result_number = args[2].asNumber();
        if (chunk_number < 1 || chunk_number > 4 * 1024 * 1024 ||
            result_number < 1 || result_number > 16 * 1024 * 1024 ||
            chunk_number != static_cast<size_t>(chunk_number) ||
            result_number != static_cast<size_t>(result_number)) {
          throw facebook::jsi::JSError(runtime, "invalid settlement codec input");
        }
        if (bytes.size() > static_cast<size_t>(result_number)) {
          if (engine->fault != nullptr) engine->fault(engine->context, 1);
          throw facebook::jsi::JSError(runtime, "settlement resource ceiling");
        }
        uint8_t hash[32];
        if (digest == nullptr || digest(
                reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), hash,
                sizeof(hash)) != 0) {
          throw facebook::jsi::JSError(runtime, "settlement digest failed");
        }
        const size_t chunk_size = static_cast<size_t>(chunk_number);
        const size_t chunk_count = (bytes.size() + chunk_size - 1) / chunk_size;
        Array chunks(runtime, chunk_count);
        for (size_t index = 0; index < chunk_count; ++index) {
          const size_t start = index * chunk_size;
          const size_t length = std::min(chunk_size, bytes.size() - start);
          chunks.setValueAtIndex(
              runtime, index,
              facebook::jsi::String::createFromUtf8(
                  runtime,
                  base64url(
                      reinterpret_cast<const uint8_t*>(bytes.data()) + start,
                      length)));
        }
        Object result(runtime);
        result.setProperty(runtime, "byteLength", static_cast<double>(bytes.size()));
        result.setProperty(
            runtime, "digest",
            facebook::jsi::String::createFromUtf8(
                runtime, std::string("sha256-") + base64url(hash, sizeof(hash))));
        result.setProperty(runtime, "chunks", std::move(chunks));
        return result;
      });
  engine->settlement_codec = std::make_unique<Function>(std::move(codec));

  // Bare Hermes has no Ibex host globals. Close the remaining standard clock,
  // entropy, and dynamic-code spellings before authored code is evaluated.
  // The engine latch below is the non-bypassable dynamic-code enforcement;
  // deletion is also required for the authenticated global inventory.
  static const char* kLockdown = R"JS(
(function () {
  "use strict";
  var g = globalThis;
  try { delete g.Date; } catch (_) {}
  try { delete g.eval; } catch (_) {}
  try { delete g.Function; } catch (_) {}
  try { delete g.WebAssembly; } catch (_) {}
  try { delete g.Intl; } catch (_) {}
  if (g.Math && Object.prototype.hasOwnProperty.call(g.Math, "random")) {
    try { delete g.Math.random; } catch (_) {}
  }
})();
)JS";
  rt.evaluateJavaScript(
      std::make_shared<facebook::jsi::StringBuffer>(kLockdown),
      "ibex:restricted-worker-lockdown");
#ifdef EXACT_HAVE_HERMES_DYNAMIC_CODE_LATCH
  auto* vm = engine->handle->runtime->getVMRuntimeUnsafe();
  if (vm == nullptr) throw std::runtime_error("restricted worker VM unavailable");
  ex_hermes_vm_disable_eval(vm);
#else
  throw std::runtime_error("restricted worker dynamic-code latch unavailable");
#endif
  static const char* kBrokerWrapper =
#include "restricted_worker_wrapper.inc"
  ;
  auto wrapper = rt.evaluateJavaScript(
      std::make_shared<facebook::jsi::StringBuffer>(kBrokerWrapper),
      "ibex:restricted-worker-wrapper");
  if (!wrapper.isObject() || !wrapper.asObject(rt).isFunction(rt)) {
    throw std::runtime_error("restricted worker wrapper is not callable");
  }
  engine->broker_factory = std::make_unique<Function>(
      wrapper.asObject(rt).asFunction(rt));
}

int32_t deliver(RestrictedEngine* engine, const uint8_t* bytes, size_t len) {
  if (engine == nullptr || engine->handle == nullptr || bytes == nullptr ||
      len == 0 || engine->handle->runtime_thread != std::this_thread::get_id()) {
    return -1;
  }
  try {
    auto& rt = *engine->handle->runtime;
    if (!engine->receiver) {
      return -2;
    }
    engine->receiver->call(
        rt,
        facebook::jsi::String::createFromUtf8(
            rt, bytes, len));
    return drain(engine->handle) ? 0 : -5;
  } catch (...) {
    return -4;
  }
}
}  // namespace

extern "C" void* ibex_private_restricted_engine_create_v1(
    uint64_t heap_bytes,
    EmitCallback emit,
    FaultCallback fault,
    DigestCallback digest,
    void* context) {
  if (heap_bytes == 0 || heap_bytes > (512ull << 20) || emit == nullptr || fault == nullptr || digest == nullptr) return nullptr;
  const uint64_t hostContext = ibex_private_claim_restricted_host_context();
  if (hostContext == 0) return nullptr;
  auto gc = ::hermes::vm::GCConfig::Builder()
                .withShouldRecordStats(true)
                .withName("ibex-restricted-worker")
                .withInitHeapSize(1 << 20)
                .withMaxHeapSize(heap_bytes)
                .build();
  auto builder = ::hermes::vm::RuntimeConfig::Builder()
                     .withGCConfig(gc)
                     .withMicrotaskQueue(true);
#if defined(EXACT_HAVE_HERMES_ES6_BLOCK_SCOPING_CONFIG)
  builder.withES6BlockScoping(ibexHermesES6BlockScopingEnabled());
#elif defined(EXACT_HAVE_HERMES_ENABLE_BLOCK_SCOPING_CONFIG)
  builder.withEnableBlockScoping(ibexHermesES6BlockScopingEnabled());
#endif
  auto runtime = facebook::hermes::makeHermesRuntime(
      builder.withEnableEval(true).build());
  if (!runtime) { ex_host_release_context(hostContext); return nullptr; }
  auto* handle = new ExactHermesRuntime();
  handle->runtime = std::move(runtime);
  handle->runtime_thread = std::this_thread::get_id();
  handle->host_context_id = hostContext;
  handle->restricted = true;
  handle->structural_lockdown = true;
  handle->runtime_nonce = exactAllocateRuntimeNonce();
  if (handle->runtime_nonce == 0) { delete handle; ex_host_release_context(hostContext); return nullptr; }
  disableDebugger(handle);
  auto* engine = new RestrictedEngine{handle, emit, fault, context, false, nullptr, nullptr, nullptr, nullptr};
  try { installSurface(engine, digest); } catch (...) { delete engine; ex_hermes_destroy(handle); return nullptr; }
  registerRuntime(handle);
  return engine;
}

extern "C" int32_t ibex_private_restricted_engine_start_v1(
    void* opaque,
    const uint8_t* source,
    size_t source_len,
    const uint8_t* start_frame,
    size_t start_frame_len) {
  auto* engine = static_cast<RestrictedEngine*>(opaque);
  if (engine == nullptr || engine->started || source == nullptr || source_len == 0) return -1;
  try {
    auto& runtime = *engine->handle->runtime;
    auto authored_value = runtime.evaluateJavaScript(
        std::make_shared<facebook::jsi::StringBuffer>(std::string(
            reinterpret_cast<const char*>(source), source_len)),
        "ibex:external-script");
    if (!authored_value.isObject() ||
        !authored_value.asObject(runtime).isFunction(runtime) ||
        !engine->emit_function || !engine->broker_factory ||
        !engine->settlement_codec) {
      return -2;
    }
    auto authored = authored_value.asObject(runtime).asFunction(runtime);
    auto receiver_value = engine->broker_factory->call(
        runtime, authored, *engine->emit_function, *engine->settlement_codec);
    if (!receiver_value.isObject() ||
        !receiver_value.asObject(runtime).isFunction(runtime)) {
      return -2;
    }
    engine->receiver = std::make_unique<Function>(
        receiver_value.asObject(runtime).asFunction(runtime));
    engine->started = true;
  } catch (...) { return -3; }
  return deliver(engine, start_frame, start_frame_len);
}

extern "C" int32_t ibex_private_restricted_engine_submit_v1(
    void* opaque, const uint8_t* frame, size_t frame_len) {
  auto* engine = static_cast<RestrictedEngine*>(opaque);
  return engine != nullptr && engine->started ? deliver(engine, frame, frame_len) : -1;
}

extern "C" int32_t ibex_private_restricted_engine_interrupt_v1(void* opaque) {
  auto* engine = static_cast<RestrictedEngine*>(opaque);
  return engine == nullptr ? -1 : ex_hermes_interrupt_eval(
      engine->handle, engine->handle->runtime_nonce);
}

extern "C" void ibex_private_restricted_engine_destroy_v1(void* opaque) {
  auto* engine = static_cast<RestrictedEngine*>(opaque);
  if (engine == nullptr) return;
  auto* handle = engine->handle;
  delete engine;
  ex_hermes_destroy(handle);
}
