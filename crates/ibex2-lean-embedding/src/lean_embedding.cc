#include <hermes/hermes.h>
#include "ibex2_jsi.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace facebook;

namespace {
struct Bytes final : jsi::Buffer {
  std::vector<uint8_t> bytes;
  Bytes(const uint8_t *data, size_t size) : bytes(data, data + size) {}
  size_t size() const override { return bytes.size(); }
  const uint8_t *data() const override { return bytes.data(); }
};

struct Consumer {
  std::unique_ptr<jsi::Runtime> runtime;
  std::unique_ptr<ibex2::jsi_adapter::Adapter> adapter;
};

char *copy(const std::string &value) {
  auto *result = static_cast<char *>(std::malloc(value.size() + 1));
  if (result != nullptr) std::memcpy(result, value.c_str(), value.size() + 1);
  return result;
}

uint32_t bytecode_version() {
  auto *root = jsi::castInterface<facebook::hermes::IHermesRootAPI>(
      facebook::hermes::makeHermesRootAPI());
  return root == nullptr ? 0 : root->getBytecodeVersion();
}
}  // namespace

extern "C" {
uint32_t ibex2_lean_bytecode_version() { return bytecode_version(); }

void *ibex2_lean_create(const void *queue, const Ibex2Bindings *bindings,
                        uint16_t groups,
                        const ibex2::jsi_adapter::CompiledScript *scripts,
                        size_t script_count, char **error) {
  try {
    auto consumer = std::make_unique<Consumer>();
    auto config = ::hermes::vm::RuntimeConfig::Builder()
                      .withMicrotaskQueue(true)
                      .build();
    consumer->runtime = facebook::hermes::makeHermesRuntimeNoThrow(config);
    if (!consumer->runtime) throw std::runtime_error("cannot create lean Hermes runtime");
    consumer->adapter = std::make_unique<ibex2::jsi_adapter::Adapter>(
        *consumer->runtime, queue, bytecode_version());
    consumer->adapter->install(groups, bindings, scripts, script_count);
    return consumer.release();
  } catch (const std::exception &exception) {
    if (error != nullptr) *error = copy(exception.what());
    return nullptr;
  }
}

int ibex2_lean_evaluate(void *handle, const uint8_t *bytes, size_t size,
                        const char *source_url, char **result) {
  try {
    auto &runtime = *static_cast<Consumer *>(handle)->runtime;
    auto value = runtime.evaluateJavaScript(
        std::make_shared<Bytes>(bytes, size), source_url);
    if (result != nullptr) *result = copy(value.toString(runtime).utf8(runtime));
    return 0;
  } catch (const std::exception &exception) {
    if (result != nullptr) *result = copy(exception.what());
    return 1;
  }
}

void ibex2_lean_destroy(void *handle) {
  delete static_cast<Consumer *>(handle);
}

void ibex2_lean_free(char *value) { std::free(value); }
}
