#include "../../include/exact_runtime.h"
#include "hermes_runtime_internal.h"

#include <memory>
#include <string>

using facebook::jsi::Function;
using facebook::jsi::Object;
using facebook::jsi::PropNameID;
using facebook::jsi::Runtime;
using facebook::jsi::String;
using facebook::jsi::Value;

extern "C" int32_t ibex_private_external_script_transform_v1(
    const uint8_t*, size_t, const uint8_t*, size_t, uint8_t**, size_t*);
extern "C" void ibex_private_external_script_transform_dispose_v1(uint8_t*);
extern "C" int32_t ibex_private_restricted_limits_digest_v1(
    const uint8_t*, size_t, uint8_t*, size_t, size_t*);

namespace {
struct WorkerBridgeState {
  ExactRestrictedWorkerV1* worker = nullptr;
  uint64_t nonce = 0;
  bool destroyed = false;

  ~WorkerBridgeState() {
    if (worker != nullptr && !destroyed) {
      ex_restricted_worker_destroy_v1(worker, nonce);
    }
  }
};

std::string requiredString(
    Runtime& runtime, const Value* args, size_t count, size_t index,
    const char* label) {
  if (index >= count || !args[index].isString()) {
    throw facebook::jsi::JSError(runtime, std::string(label) + " must be a string");
  }
  return args[index].asString(runtime).utf8(runtime);
}

void requireLive(Runtime& runtime, const std::shared_ptr<WorkerBridgeState>& state) {
  if (state->worker == nullptr || state->destroyed) {
    throw facebook::jsi::JSError(runtime, "restricted worker handle is closed");
  }
}

Value statusResult(Runtime& runtime, int32_t status) {
  if (status != 0) {
    throw facebook::jsi::JSError(
        runtime, "restricted worker operation refused with status " +
                     std::to_string(status));
  }
  return Value::undefined();
}

Object workerObject(Runtime& runtime, std::shared_ptr<WorkerBridgeState> state) {
  Object object(runtime);
  auto start = Function::createFromHostFunction(
      runtime, PropNameID::forAscii(runtime, "start"), 3,
      [state](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
        requireLive(rt, state);
        auto source = requiredString(rt, args, count, 0, "transformed source");
        auto map = requiredString(rt, args, count, 1, "source map");
        auto frame = requiredString(rt, args, count, 2, "start frame");
        return statusResult(
            rt, ex_restricted_worker_start_v1(
                    state->worker,
                    reinterpret_cast<const uint8_t*>(source.data()), source.size(),
                    reinterpret_cast<const uint8_t*>(map.data()), map.size(),
                    reinterpret_cast<const uint8_t*>(frame.data()), frame.size()));
      });
  auto submit = Function::createFromHostFunction(
      runtime, PropNameID::forAscii(runtime, "submit"), 1,
      [state](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
        requireLive(rt, state);
        auto frame = requiredString(rt, args, count, 0, "broker frame");
        return statusResult(
            rt, ex_restricted_worker_submit_frame_v1(
                    state->worker,
                    reinterpret_cast<const uint8_t*>(frame.data()), frame.size()));
      });
  auto take = Function::createFromHostFunction(
      runtime, PropNameID::forAscii(runtime, "take"), 1,
      [state](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
        requireLive(rt, state);
        uint32_t wait = 0;
        if (count == 1) {
          if (!args[0].isNumber() || args[0].asNumber() < 0 ||
              args[0].asNumber() > 1000 ||
              args[0].asNumber() != static_cast<uint32_t>(args[0].asNumber())) {
            throw facebook::jsi::JSError(rt, "worker wait must be an integer from 0 through 1000");
          }
          wait = static_cast<uint32_t>(args[0].asNumber());
        } else if (count != 0) {
          throw facebook::jsi::JSError(rt, "worker take accepts at most one argument");
        }
        ExRestrictedWorkerEventV1 event{};
        int32_t status = ex_restricted_worker_take_event_v1(state->worker, wait, &event);
        if (status == 1) return Value::undefined();
        if (status != 0) return statusResult(rt, status);
        Object result(rt);
        result.setProperty(rt, "tag", static_cast<double>(event.tag));
        result.setProperty(rt, "fault", static_cast<double>(event.fault));
        result.setProperty(rt, "runtimeNonce", static_cast<double>(event.runtime_nonce));
        if (event.bytes != nullptr && event.bytes_len != 0) {
          result.setProperty(
              rt, "frame",
              String::createFromUtf8(rt, event.bytes, event.bytes_len));
        }
        ex_restricted_worker_event_dispose_v1(&event);
        return result;
      });
  auto interrupt = Function::createFromHostFunction(
      runtime, PropNameID::forAscii(runtime, "interrupt"), 0,
      [state](Runtime& rt, const Value&, const Value*, size_t count) -> Value {
        if (count != 0) throw facebook::jsi::JSError(rt, "interrupt accepts no arguments");
        requireLive(rt, state);
        return statusResult(rt, ex_restricted_worker_interrupt_v1(state->worker, state->nonce));
      });
  auto destroy = Function::createFromHostFunction(
      runtime, PropNameID::forAscii(runtime, "destroy"), 0,
      [state](Runtime& rt, const Value&, const Value*, size_t count) -> Value {
        if (count != 0) throw facebook::jsi::JSError(rt, "destroy accepts no arguments");
        if (state->destroyed) return Value::undefined();
        requireLive(rt, state);
        int32_t status = ex_restricted_worker_destroy_v1(state->worker, state->nonce);
        if (status == 0) {
          state->destroyed = true;
          state->worker = nullptr;
        }
        return statusResult(rt, status);
      });
  object.setProperty(runtime, "start", std::move(start));
  object.setProperty(runtime, "submit", std::move(submit));
  object.setProperty(runtime, "take", std::move(take));
  object.setProperty(runtime, "interrupt", std::move(interrupt));
  object.setProperty(runtime, "destroy", std::move(destroy));
  return object;
}
}  // namespace

extern "C" int32_t ibex_private_install_app_bound_worker_bridge_v1(
    ExactHermesRuntime* handle, const uint8_t* contract, size_t contract_len) {
  if (handle == nullptr || handle->runtime == nullptr || handle->restricted ||
      handle->runtime_thread != std::this_thread::get_id() || contract == nullptr ||
      contract_len == 0) {
    return -1;
  }
  try {
    auto& runtime = *handle->runtime;
    if (!runtime.global().getProperty(runtime, "__ibexAppBoundWorkerV1").isUndefined()) {
      return -2;
    }
    Object bridge(runtime);
    auto transform = Function::createFromHostFunction(
        runtime, PropNameID::forAscii(runtime, "transformExternalScript"), 2,
        [](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
          auto path = requiredString(rt, args, count, 0, "external script path");
          auto source = requiredString(rt, args, count, 1, "external script source");
          uint8_t* output = nullptr;
          size_t output_len = 0;
          int32_t status = ibex_private_external_script_transform_v1(
              reinterpret_cast<const uint8_t*>(path.data()), path.size(),
              reinterpret_cast<const uint8_t*>(source.data()), source.size(),
              &output, &output_len);
          if (status != 0 || output == nullptr) return statusResult(rt, status);
          auto value = String::createFromUtf8(rt, output, output_len);
          ibex_private_external_script_transform_dispose_v1(output);
          return value;
        });
    auto create = Function::createFromHostFunction(
        runtime, PropNameID::forAscii(runtime, "create"), 2,
        [](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
          auto arming = requiredString(rt, args, count, 0, "arming receipt");
          auto limits = requiredString(rt, args, count, 1, "worker limits");
          ExRestrictedWorkerOptionsV1 options{
              EX_RESTRICTED_WORKER_ABI_VERSION_V1,
              sizeof(ExRestrictedWorkerOptionsV1),
              reinterpret_cast<const uint8_t*>(arming.data()), arming.size(),
              reinterpret_cast<const uint8_t*>(limits.data()), limits.size()};
          auto state = std::make_shared<WorkerBridgeState>();
          int32_t status = ex_restricted_worker_create_v1(
              &options, &state->worker, &state->nonce);
          if (status != 0) return statusResult(rt, status);
          return workerObject(rt, std::move(state));
        });
    auto digestLimits = Function::createFromHostFunction(
        runtime, PropNameID::forAscii(runtime, "digestLimits"), 1,
        [](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
          auto limits = requiredString(rt, args, count, 0, "worker limits");
          uint8_t output[128];
          size_t output_len = 0;
          int32_t status = ibex_private_restricted_limits_digest_v1(
              reinterpret_cast<const uint8_t*>(limits.data()), limits.size(),
              output, sizeof(output), &output_len);
          if (status != 0) return statusResult(rt, status);
          return String::createFromUtf8(rt, output, output_len);
        });
    bridge.setProperty(runtime, "transformExternalScript", std::move(transform));
    bridge.setProperty(runtime, "create", std::move(create));
    bridge.setProperty(runtime, "digestLimits", std::move(digestLimits));
    bridge.setProperty(
        runtime, "contract", String::createFromUtf8(runtime, contract, contract_len));
    auto freeze = runtime.global()
                      .getPropertyAsObject(runtime, "Object")
                      .getPropertyAsFunction(runtime, "freeze");
    auto frozen = freeze.call(runtime, bridge);
    Object descriptor(runtime);
    descriptor.setProperty(runtime, "value", std::move(frozen));
    descriptor.setProperty(runtime, "writable", false);
    descriptor.setProperty(runtime, "enumerable", false);
    descriptor.setProperty(runtime, "configurable", false);
    runtime.global()
        .getPropertyAsObject(runtime, "Object")
        .getPropertyAsFunction(runtime, "defineProperty")
        .call(
            runtime, runtime.global(),
            String::createFromAscii(runtime, "__ibexAppBoundWorkerV1"),
            descriptor);
    return 0;
  } catch (...) {
    return -3;
  }
}
