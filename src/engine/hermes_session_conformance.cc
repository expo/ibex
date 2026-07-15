#include "hermes_runtime_internal.h"

#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

const char* sessionCellKindName(StructuredSessionCellKind kind) {
  switch (kind) {
    case StructuredSessionCellKind::Let:
      return "let";
    case StructuredSessionCellKind::Const:
      return "const";
    case StructuredSessionCellKind::Class:
      return "class";
    case StructuredSessionCellKind::Import:
      return "import";
  }
  return "unknown";
}

void appendJsonString(std::ostringstream& out, const std::string& value) {
  out << '"' << escapeJson(value) << '"';
}

template <typename Set>
void appendSortedStringSet(std::ostringstream& out, const Set& values) {
  std::vector<std::string> sorted(values.begin(), values.end());
  std::sort(sorted.begin(), sorted.end());
  out << '[';
  for (size_t index = 0; index < sorted.size(); ++index) {
    if (index != 0) out << ',';
    appendJsonString(out, sorted[index]);
  }
  out << ']';
}

bool appendOwnDescriptor(
    std::ostringstream& out,
    ExactHermesRuntime* handle,
    const std::string& name) {
  auto& rt = *handle->runtime;
  auto descriptorValue = handle->structured_object_get_own_descriptor->call(
      rt,
      rt.global(),
      facebook::jsi::String::createFromUtf8(rt, name));
  if (descriptorValue.isUndefined()) return false;
  if (!descriptorValue.isObject()) return false;

  auto descriptor = descriptorValue.asObject(rt);
  const bool data = descriptor.hasProperty(rt, "value");
  out << "{\"type\":\"" << (data ? "data" : "accessor") << "\"";
  if (data) {
    out << ",\"writable\":"
        << (descriptor.getProperty(rt, "writable").getBool() ? "true" : "false");
  } else {
    out << ",\"hasGetter\":"
        << (!descriptor.getProperty(rt, "get").isUndefined() ? "true" : "false")
        << ",\"hasSetter\":"
        << (!descriptor.getProperty(rt, "set").isUndefined() ? "true" : "false");
  }
  out << ",\"enumerable\":"
      << (descriptor.getProperty(rt, "enumerable").getBool() ? "true" : "false")
      << ",\"configurable\":"
      << (descriptor.getProperty(rt, "configurable").getBool() ? "true" : "false")
      << '}';
  return true;
}

}  // namespace

// Test-only, read-only session metadata used by LLP 0024 conformance gates.
// This source file is omitted from ordinary builds, and every Rust caller is
// additionally cfg(test). The function cannot evaluate source, return live
// values, or mutate the runtime; it exposes only declarative metadata,
// provenance sets, and own-descriptor flags for names selected by the harness.
// @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them
extern "C" char* ibex_test_observe_session_metadata(
    ExactHermesRuntime* runtime,
    const char* const* requested_names,
    size_t requested_name_count) {
  if (!runtime || !runtime->armed || !runtime->structured_session_bound ||
      runtime->runtime_thread != std::this_thread::get_id() ||
      !runtime->structured_object_get_own_descriptor ||
      (requested_name_count != 0 && !requested_names) ||
      requested_name_count > 1024) {
    return nullptr;
  }

  try {
    std::vector<std::string> names;
    names.reserve(requested_name_count);
    for (size_t index = 0; index < requested_name_count; ++index) {
      if (!requested_names[index]) return nullptr;
      const size_t length = std::strlen(requested_names[index]);
      if (length > 4096) return nullptr;
      names.emplace_back(requested_names[index], length);
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());

    std::vector<std::string> cellNames;
    cellNames.reserve(runtime->structured_session_cells.size());
    for (const auto& entry : runtime->structured_session_cells) {
      cellNames.push_back(entry.first);
    }
    std::sort(cellNames.begin(), cellNames.end());

    std::ostringstream out;
    out << "{\"declarativeRecord\":{";
    for (size_t index = 0; index < cellNames.size(); ++index) {
      if (index != 0) out << ',';
      const auto& name = cellNames[index];
      const auto& cell = runtime->structured_session_cells.at(name);
      appendJsonString(out, name);
      out << ":{\"kind\":\"" << sessionCellKindName(cell->kind)
          << "\",\"initialized\":" << (cell->initialized ? "true" : "false")
          << '}';
    }
    out << "},\"varDeclaredNames\":";
    appendSortedStringSet(out, runtime->structured_session_var_declared_names);
    out << ",\"sessionCreatedVars\":";
    appendSortedStringSet(out, runtime->structured_session_created_vars);
    out << ",\"own\":{";
    bool firstDescriptor = true;
    for (const auto& name : names) {
      std::ostringstream descriptor;
      if (!appendOwnDescriptor(descriptor, runtime, name)) continue;
      if (!firstDescriptor) out << ',';
      firstDescriptor = false;
      appendJsonString(out, name);
      out << ':' << descriptor.str();
    }
    out << "}}";

    const std::string json = out.str();
    auto* result = static_cast<char*>(std::malloc(json.size() + 1));
    if (!result) return nullptr;
    std::memcpy(result, json.data(), json.size());
    result[json.size()] = '\0';
    return result;
  } catch (const std::bad_alloc&) {
    return nullptr;
  } catch (const facebook::jsi::JSIException&) {
    return nullptr;
  } catch (...) {
    return nullptr;
  }
}

#endif
