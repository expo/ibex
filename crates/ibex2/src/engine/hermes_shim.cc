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

// ---------------------------------------------------------------------------
// The host-call boundary (LLP 0059.000 §1), bridged onto stock JSI.
// ---------------------------------------------------------------------------

// Mirrors ibex2::boundary_abi::AbiValue. Kept in lockstep by the round-trip
// tests: any drift shows up as a wrong tag rather than silent corruption.
struct Ibex2AbiValue {
  int32_t tag;
  double number;
  const unsigned char *data;
  size_t len;
};

enum : int32_t {
  IBEX2_TAG_UNDEFINED = 0,
  IBEX2_TAG_NULL = 1,
  IBEX2_TAG_BOOL = 2,
  IBEX2_TAG_NUMBER = 3,
  IBEX2_TAG_STRING = 4,
  IBEX2_TAG_BYTES = 5,
};

extern "C" int ibex2_host_call(uint32_t op, const Ibex2AbiValue *argv,
                               size_t argc, Ibex2AbiValue *out);
extern "C" void ibex2_host_release(Ibex2AbiValue *value);

namespace {

// Convert a JS argument. Strings are decoded into `owned`, which the caller
// keeps alive for the duration of the host call so the span stays valid.
Ibex2AbiValue to_abi(jsi::Runtime &rt, const jsi::Value &value,
                     std::vector<std::string> &owned) {
  Ibex2AbiValue out{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
  if (value.isUndefined()) {
    return out;
  }
  if (value.isNull()) {
    out.tag = IBEX2_TAG_NULL;
    return out;
  }
  if (value.isBool()) {
    out.tag = IBEX2_TAG_BOOL;
    out.number = value.getBool() ? 1.0 : 0.0;
    return out;
  }
  if (value.isNumber()) {
    out.tag = IBEX2_TAG_NUMBER;
    out.number = value.getNumber();
    return out;
  }
  if (value.isObject() && value.getObject(rt).isArrayBuffer(rt)) {
    auto buffer = value.getObject(rt).getArrayBuffer(rt);
    out.tag = IBEX2_TAG_BYTES;
    out.data = buffer.data(rt);
    out.len = buffer.size(rt);
    return out;
  }
  // Everything else stringifies, which is what console does with its arguments.
  owned.push_back(value.toString(rt).utf8(rt));
  const std::string &text = owned.back();
  out.tag = IBEX2_TAG_STRING;
  out.data = reinterpret_cast<const unsigned char *>(text.data());
  out.len = text.size();
  return out;
}

// A byte result IS the JavaScript ArrayBuffer's storage — no copy, no second
// allocation. Rust allocated it, ownership transfers here, and the engine frees
// it back through the boundary when the ArrayBuffer is collected. That is the
// outbound half of LLP 0059.000 §1.2.
//
// The destructor is the whole mechanism: Hermes holds this shared_ptr for as
// long as the ArrayBuffer is reachable, so the Rust allocation outlives every
// JavaScript reference to it and is released exactly once.
class RustBytes : public jsi::MutableBuffer {
public:
  explicit RustBytes(Ibex2AbiValue value) : value_(value) {}
  ~RustBytes() override { ibex2_host_release(&value_); }

  RustBytes(const RustBytes &) = delete;
  RustBytes &operator=(const RustBytes &) = delete;

  size_t size() const override { return value_.len; }
  uint8_t *data() override {
    return const_cast<uint8_t *>(value_.data);
  }

private:
  Ibex2AbiValue value_;
};

// Convert a result. For bytes this TAKES OWNERSHIP and clears `value`, so the
// caller's release becomes a no-op — the RustBytes destructor releases instead,
// when the engine is done with the buffer. Strings still copy: Hermes owns its
// own string representation and there is no way to hand it one (§1.2).
jsi::Value from_abi(jsi::Runtime &rt, Ibex2AbiValue &value) {
  switch (value.tag) {
  case IBEX2_TAG_NULL:
    return jsi::Value::null();
  case IBEX2_TAG_BOOL:
    return jsi::Value(value.number != 0.0);
  case IBEX2_TAG_NUMBER:
    return jsi::Value(value.number);
  case IBEX2_TAG_STRING: {
    std::string text(reinterpret_cast<const char *>(value.data), value.len);
    return jsi::String::createFromUtf8(rt, text);
  }
  case IBEX2_TAG_BYTES: {
    Ibex2AbiValue owned = value;
    value = Ibex2AbiValue{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
    return jsi::Value(rt,
                      jsi::ArrayBuffer(rt, std::make_shared<RustBytes>(owned)));
  }
  default:
    return jsi::Value::undefined();
  }
}

// One host function per op, so JavaScript sees ordinary callables while every
// one of them funnels through the single ibex2_host_call surface.
jsi::Function make_host_binding(jsi::Runtime &runtime, const char *name,
                                uint32_t op) {
  auto prop = jsi::PropNameID::forUtf8(runtime, std::string(name));
  return jsi::Function::createFromHostFunction(
      runtime, prop, 1,
      [op](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
        std::vector<std::string> owned;
        owned.reserve(count);
        std::vector<Ibex2AbiValue> abi;
        abi.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          abi.push_back(to_abi(rt, args[i], owned));
        }
        Ibex2AbiValue out{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
        int status = ibex2_host_call(op, abi.empty() ? nullptr : abi.data(),
                                     abi.size(), &out);
        jsi::Value result = from_abi(rt, out);
        ibex2_host_release(&out);
        if (status != 0) {
          // The Rust error taxonomy becomes a JS throw here, so failures are
          // identical on every platform (LLP 0057 §3).
          throw jsi::JSError(rt, result.isString()
                                     ? result.getString(rt).utf8(rt)
                                     : std::string("host call failed"));
        }
        return result;
      });
}

void set_binding(jsi::Runtime &rt, jsi::Object &target, const char *name,
                 uint32_t op) {
  target.setProperty(rt, jsi::PropNameID::forUtf8(rt, std::string(name)),
                     make_host_binding(rt, name, op));
}

} // namespace

extern "C" {

/// Install the pure tier: console, btoa/atob, and a raw host-call escape hatch.
int ibex2_hermes_install_stdlib(void *handle) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr) {
    return -1;
  }
  try {
    jsi::Runtime &runtime = *rt->runtime;
    jsi::Object global = runtime.global();

    jsi::Object console(runtime);
    set_binding(runtime, console, "log", 1);
    set_binding(runtime, console, "info", 2);
    set_binding(runtime, console, "debug", 3);
    set_binding(runtime, console, "warn", 4);
    set_binding(runtime, console, "error", 5);
    global.setProperty(runtime, jsi::PropNameID::forAscii(runtime, "console"),
                       std::move(console));

    set_binding(runtime, global, "btoa", 10);
    set_binding(runtime, global, "atob", 11);
    set_binding(runtime, global, "__ibex2_text_encode", 20);
    set_binding(runtime, global, "__ibex2_text_decode", 21);
    set_binding(runtime, global, "__ibex2_text_encode_into", 22);
    set_binding(runtime, global, "__ibex2_url_parse", 30);
    set_binding(runtime, global, "__ibex2_search_params_get", 31);
    return 0;
  } catch (const std::exception &) {
    return 1;
  }
}

} // extern "C"
