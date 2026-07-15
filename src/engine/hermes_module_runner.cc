// Native-only Hermes factory compiler for the authenticated module graph.
// @ref LLP 0026#4-native-graph-owner-and-hermes-runner — identity and
// compartment are selected before package factory compilation, and package JS
// never receives the compiler capability.

#include "hermes_runtime_internal.h"

#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

void writeError(char** out, const std::string& message) {
  if (out == nullptr) return;
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

facebook::jsi::Object compartmentFor(
    facebook::jsi::Runtime& rt, const std::string& identity) {
  auto registryValue = rt.global().getProperty(rt, "__compartments");
  if (!registryValue.isObject()) {
    throw facebook::jsi::JSError(rt, "module compartment registry is unavailable");
  }
  auto compartment = registryValue.asObject(rt).getProperty(rt, identity.c_str());
  if (!compartment.isObject()) {
    throw facebook::jsi::JSError(rt, "authenticated module compartment is unavailable");
  }
  return compartment.asObject(rt);
}

uint64_t nextHandleId(ExactHermesRuntime* runtime) {
  const uint64_t id = runtime->next_module_handle_id++;
  if (id == 0 || runtime->next_module_handle_id == 0) {
    throw std::runtime_error("module-runner handle space exhausted");
  }
  return id;
}

}  // namespace

extern "C" int32_t ex_hermes_module_compile_factory(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
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
    char** out_error) {
  if (out_error) *out_error = nullptr;
  if (out_factory) *out_factory = ExactModuleRunnerHandle{{0, 0, 0}};

  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  if (runtime_nonce == 0 || graph_generation == 0 || out_factory == nullptr ||
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

  ScopedRuntimeSecurityContext securityContext(runtime);
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  ScopedActiveAttributionRuntime activeAttributionRuntime(
      runtime->attribution_runtime);
#endif

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
    auto trampolineValue = runtime->module_function_constructor->call(
        rt, facebook::jsi::String::createFromUtf8(rt, kTrampolineBody));
    if (!trampolineValue.isObject() ||
        !trampolineValue.asObject(rt).isFunction(rt)) {
      throw facebook::jsi::JSError(rt, "module compiler did not return a trampoline");
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
    entry.principal_id = principal_id;
    entry.compartment_identity = compartment;
    entry.semantic_digest = digest;
    entry.source_id.assign(
        reinterpret_cast<const char*>(source_id), source_id_len);
    entry.factory = std::make_shared<facebook::jsi::Function>(
        factoryValue.asObject(rt).asFunction(rt));
    runtime->module_factories.emplace(id, std::move(entry));
    out_factory->opaque[0] = runtime_nonce;
    out_factory->opaque[1] = graph_generation;
    out_factory->opaque[2] = id;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    writeError(out_error, error.getMessage());
  } catch (const std::exception& error) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    writeError(out_error, error.what());
  } catch (...) {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
    if (runtime->attribution_runtime != nullptr) {
      ex_hermes_vm_clear_pending_package_id(runtime->attribution_runtime);
    }
#endif
    writeError(out_error, "unknown module factory compilation failure");
  }
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}

extern "C" int32_t ex_hermes_module_release_handle(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle handle) {
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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
    auto retainedContext =
        runtime->graph_contexts.find(record->second.context_handle_id);
    if (retainedContext != runtime->graph_contexts.end() &&
        --retainedContext->second.references == 0) {
      runtime->graph_contexts.erase(retainedContext);
    }
    runtime->module_records.erase(record);
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
  if (out_context) *out_context = ExactModuleRunnerHandle{{0, 0, 0}};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
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
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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
  if (out_record) *out_record = ExactModuleRunnerHandle{{0, 0, 0}};
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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
      factoryIt->second.graph_generation != factory.opaque[1] ||
      contextIt->second.graph_generation != context.opaque[1] ||
      factoryIt->second.source_id !=
          std::string(reinterpret_cast<const char*>(source_id), source_id_len)) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }
  NativeModuleRecordEntry entry;
  entry.graph_generation = factory.opaque[1];
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
