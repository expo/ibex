// Native-only Hermes factory compiler for the authenticated module graph.
// @ref LLP 0026#4-native-graph-owner-and-hermes-runner — identity and
// compartment are selected before package factory compilation, and package JS
// never receives the compiler capability.

#include "hermes_runtime_internal.h"

#include <cstring>
#include <limits>
#include <set>
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
      auto target = runtime->module_records.find(cell->second.alias_record_id);
      if (target == runtime->module_records.end() ||
          target->second.graph_generation != current->graph_generation) {
        throw facebook::jsi::JSError(rt, "module export alias is stale");
      }
      currentId = cell->second.alias_record_id;
      currentName = cell->second.alias_export;
      current = &target->second;
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
    NativeModuleRecordEntry& record, const std::string& message) {
  record.state = NativeModuleRecordState::Errored;
  if (record.error_message.empty()) {
    record.error_message = message;
  }
}

int32_t reportRecordError(
    NativeModuleRecordEntry& record, char** outError) {
  writeError(
      outError,
      record.error_message.empty() ? "module record is errored"
                                   : record.error_message);
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
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

extern "C" int32_t ex_hermes_module_record_declare_export(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* export_name,
    size_t export_name_len) {
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
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

extern "C" int32_t ex_hermes_module_record_instantiate(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    const uint8_t* meta_url,
    size_t meta_url_len,
    int32_t is_main,
    char** out_error) {
  if (out_error) *out_error = nullptr;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error);
  }
  if (entry->state != NativeModuleRecordState::New || meta_url == nullptr ||
      meta_url_len == 0 || (is_main != 0 && is_main != 1)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
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
            auto* current =
                callbackRecordFor(target, graphGeneration, recordId);
            if (current == nullptr) {
              throw facebook::jsi::JSError(rt, "stale module namespace");
            }
            return readBinding(
                rt, target.runtime, recordId, *current, name);
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
    entry->namespace_object =
        std::make_shared<facebook::jsi::Object>(std::move(namespaceObject));

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
          auto targetRecord =
              target.runtime->module_records.find(binding->second.target_record_id);
          if (targetRecord == target.runtime->module_records.end() ||
              targetRecord->second.graph_generation != graphGeneration) {
            throw facebook::jsi::JSError(rt, "module import target is stale");
          }
          return readBinding(
              rt,
              target.runtime,
              binding->second.target_record_id,
              targetRecord->second,
              binding->second.target_export);
        });
    context.setProperty(rt, "importValue", std::move(importValue));
    facebook::jsi::Object meta(rt);
    meta.setProperty(
        rt,
        "url",
        facebook::jsi::String::createFromUtf8(
            rt,
            std::string(reinterpret_cast<const char*>(meta_url), meta_url_len)));
    meta.setProperty(rt, "main", is_main == 1);
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
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(*entry, error.getMessage());
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module instantiation failure");
  }
  return reportRecordError(*entry, out_error);
}

extern "C" int32_t ex_hermes_module_record_run_declare(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    char** out_error) {
  if (out_error) *out_error = nullptr;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error);
  }
  if (entry->state != NativeModuleRecordState::Instantiated ||
      !entry->declare_function) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  try {
    entry->declare_function->call(*runtime->runtime);
    entry->state = NativeModuleRecordState::Declared;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(*entry, error.getMessage());
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module declaration failure");
  }
  return reportRecordError(*entry, out_error);
}

extern "C" int32_t ex_hermes_module_record_run_execute(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    int32_t* out_async,
    char** out_error) {
  if (out_async) *out_async = 0;
  if (out_error) *out_error = nullptr;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error);
  }
  if (entry->state != NativeModuleRecordState::Declared ||
      !entry->execute_function || out_async == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  try {
    auto& rt = *runtime->runtime;
    auto result = entry->execute_function->call(rt);
    if (result.isObject()) {
      auto object = result.asObject(rt);
      auto thenValue = object.getProperty(rt, "then");
      if (thenValue.isObject() && thenValue.asObject(rt).isFunction(rt)) {
        *out_async = 1;
      }
    }
    entry->state = NativeModuleRecordState::Evaluated;
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    rememberRecordError(*entry, error.getMessage());
  } catch (const std::exception& error) {
    rememberRecordError(*entry, error.what());
  } catch (...) {
    rememberRecordError(*entry, "unknown module evaluation failure");
  }
  return reportRecordError(*entry, out_error);
}

extern "C" int32_t ex_hermes_module_record_namespace_json(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    ExactModuleRunnerHandle record,
    char** out_json,
    char** out_error) {
  if (out_json) *out_json = nullptr;
  if (out_error) *out_error = nullptr;
  ExactRuntimeDriveGuard drive(runtime, runtime_nonce);
  if (!drive) return drive.status();
  auto* entry = recordFor(runtime, record);
  if (entry == nullptr) return EXACT_RUNTIME_DRIVE_STALE;
  if (entry->state == NativeModuleRecordState::Errored) {
    return reportRecordError(*entry, out_error);
  }
  if (!entry->namespace_object || out_json == nullptr) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  try {
    auto& rt = *runtime->runtime;
    auto json = rt.global().getPropertyAsObject(rt, "JSON");
    auto stringify = json.getPropertyAsFunction(rt, "stringify");
    auto value = stringify.call(rt, *entry->namespace_object);
    if (!value.isString()) {
      throw facebook::jsi::JSError(rt, "module namespace is not serializable");
    }
    const std::string text = value.asString(rt).utf8(rt);
    *out_json = static_cast<char*>(std::malloc(text.size() + 1));
    if (*out_json == nullptr) {
      throw std::bad_alloc();
    }
    std::memcpy(*out_json, text.data(), text.size());
    (*out_json)[text.size()] = '\0';
    return EXACT_RUNTIME_DRIVE_OK;
  } catch (const facebook::jsi::JSError& error) {
    writeError(out_error, error.getMessage());
  } catch (const std::exception& error) {
    writeError(out_error, error.what());
  } catch (...) {
    writeError(out_error, "unknown module namespace serialization failure");
  }
  return EXACT_RUNTIME_DRIVE_ENGINE_ERROR;
}
