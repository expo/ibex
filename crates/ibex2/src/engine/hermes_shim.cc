// Minimal C ABI over stock JSI for the Ibex 2 spike.
//
// This file deliberately uses ONLY the public Hermes/JSI embedding surface —
// makeHermesRuntime, RuntimeConfig, evaluateJavaScript, and host functions. If
// anything here ever needs a symbol the carried patch series adds, that is the
// signal LLP 0060 D3 has been broken and the fork has grown back.
//
// @ref LLP 0060#1-the-decision — D4: eval is closed at construction, not latched after boot
// @ref LLP 0058#1-what-an-engine-must-provide — requirement 2, host functions over primitives

#include <hermes/hermes.h>
#include <jsi/jsi.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace facebook;

namespace {

struct Ibex2Runtime {
  std::unique_ptr<jsi::Runtime> runtime;
};

// Copy a std::string out to a malloc'd C string the Rust side owns and frees
// through ibex2_hermes_free_string.
char *dup_c_string(const std::string &value) {
  char *out = static_cast<char *>(std::malloc(value.size() + 1));
  if (out == nullptr) {
    return nullptr;
  }
  std::memcpy(out, value.c_str(), value.size() + 1);
  return out;
}

} // namespace

extern "C" {

/// Create a runtime. `enable_eval == 0` closes JavaScript `eval` and the
/// Function constructor at construction time — LLP 0060 D4. Host-driven
/// evaluation through ibex2_hermes_eval is a separate path and stays available,
/// which is the whole point: the runtime can still run prepared code while
/// JavaScript cannot compile source of its own.
void *ibex2_hermes_create(int enable_eval) {
  auto config = ::hermes::vm::RuntimeConfig::Builder()
                    .withEnableEval(enable_eval != 0)
                    .build();
  // Fully qualified: `using namespace facebook` makes bare `hermes` ambiguous
  // between ::hermes (the VM namespace) and facebook::hermes (the JSI one).
  auto runtime = facebook::hermes::makeHermesRuntimeNoThrow(config);
  if (!runtime) {
    return nullptr;
  }
  auto *handle = new Ibex2Runtime();
  handle->runtime = std::move(runtime);
  return handle;
}

void ibex2_hermes_destroy(void *handle) {
  delete static_cast<Ibex2Runtime *>(handle);
}

/// Evaluate `source` as the host. Returns 0 on success and 1 if JavaScript
/// threw; `*out` receives the result (or the error message) either way.
int ibex2_hermes_eval(void *handle, const char *source, char **out) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr || source == nullptr) {
    return -1;
  }
  try {
    auto buffer = std::make_shared<jsi::StringBuffer>(std::string(source));
    jsi::Value value = rt->runtime->evaluateJavaScript(buffer, "<spike>");
    if (out != nullptr) {
      *out = dup_c_string(value.toString(*rt->runtime).utf8(*rt->runtime));
    }
    return 0;
  } catch (const jsi::JSError &err) {
    if (out != nullptr) {
      *out = dup_c_string(err.getMessage());
    }
    return 1;
  } catch (const std::exception &err) {
    if (out != nullptr) {
      *out = dup_c_string(std::string(err.what()));
    }
    return 1;
  }
}

/// Install a host function that takes no arguments and returns a fixed string,
/// so the spike can prove the LLP 0058 requirement-2 path works on stock JSI
/// before any real capability is built on it.
int ibex2_hermes_install_probe(void *handle, const char *name,
                               const char *value) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr || name == nullptr ||
      value == nullptr) {
    return -1;
  }
  try {
    jsi::Runtime &runtime = *rt->runtime;
    std::string owned_value(value);
    auto prop = jsi::PropNameID::forUtf8(runtime, std::string(name));
    auto fn = jsi::Function::createFromHostFunction(
        runtime, prop, 0,
        [owned_value](jsi::Runtime &rt, const jsi::Value &,
                      const jsi::Value *, size_t) -> jsi::Value {
          return jsi::String::createFromUtf8(rt, owned_value);
        });
    runtime.global().setProperty(runtime, prop, std::move(fn));
    return 0;
  } catch (const std::exception &) {
    return 1;
  }
}

void ibex2_hermes_free_string(char *value) { std::free(value); }

} // extern "C"
