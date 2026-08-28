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
#include <unordered_map>
#include <vector>
#include <cstring>
#include <memory>
#include <string>

using namespace facebook;

extern "C" const void *ibex2_queue_create();
extern "C" void ibex2_queue_destroy(const void *queue);
extern "C" void ibex2_grants_destroy(const void *grants);

namespace {

struct PendingPromise {
  std::shared_ptr<jsi::Function> resolve;
  std::shared_ptr<jsi::Function> reject;
};

struct Ibex2Runtime {
  std::unique_ptr<jsi::Runtime> runtime;
  // Promises awaiting an off-thread completion. Keyed by task id, and touched
  // ONLY on the JavaScript thread — jsi values are not thread-safe and nothing
  // here may be reached from a worker.
  std::unordered_map<uint64_t, PendingPromise> pending;
  uint64_t next_task_id = 1;
  // This runtime's own completion queue. Per-runtime so two runtimes in one
  // process cannot take each other's completions (task::Pump C5).
  const void *queue = nullptr;
  // Loaded modules, by resolved specifier. Held here rather than on the global
  // object: a module registry reachable from JavaScript would let any module
  // read any other's exports without requiring it (LLP 0062 R1).
  std::unordered_map<std::string, std::shared_ptr<jsi::Object>> modules;
  // Grant sets handed to module bindings, released when the runtime is.
  std::vector<const void *> module_grants;
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
  // The engine microtask queue is OFF by default in stock Hermes. Ibex 2 needs
  // it on: it is what makes the job queue explicit and drainable, which is the
  // whole basis of the LLP 0058 §3 adapter. Without it there is no defined
  // point at which "microtasks have finished" is true.
  auto config = ::hermes::vm::RuntimeConfig::Builder()
                    .withEnableEval(enable_eval != 0)
                    .withMicrotaskQueue(true)
                    .build();
  // Fully qualified: `using namespace facebook` makes bare `hermes` ambiguous
  // between ::hermes (the VM namespace) and facebook::hermes (the JSI one).
  auto runtime = facebook::hermes::makeHermesRuntimeNoThrow(config);
  if (!runtime) {
    return nullptr;
  }
  auto *handle = new Ibex2Runtime();
  handle->runtime = std::move(runtime);
  handle->queue = ibex2_queue_create();
  return handle;
}

void ibex2_hermes_destroy(void *handle) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt != nullptr) {
    // Workers may still hold the queue; releasing our reference is enough,
    // and the last holder frees it.
    for (const void *grants : rt->module_grants) {
      ibex2_grants_destroy(grants);
    }
    ibex2_queue_destroy(rt->queue);
  }
  delete rt;
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

extern "C" int ibex2_host_call(const void *state, uint32_t op,
                               const Ibex2AbiValue *argv, size_t argc,
                               Ibex2AbiValue *out);
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
                                uint32_t op, const void *state) {
  auto prop = jsi::PropNameID::forUtf8(runtime, std::string(name));
  return jsi::Function::createFromHostFunction(
      runtime, prop, 1,
      [op, state](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
                  size_t count) -> jsi::Value {
        std::vector<std::string> owned;
        owned.reserve(count);
        std::vector<Ibex2AbiValue> abi;
        abi.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          abi.push_back(to_abi(rt, args[i], owned));
        }
        Ibex2AbiValue out{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
        int status = ibex2_host_call(state, op,
                                     abi.empty() ? nullptr : abi.data(),
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
                 uint32_t op, const void *state) {
  target.setProperty(rt, jsi::PropNameID::forUtf8(rt, std::string(name)),
                     make_host_binding(rt, name, op, state));
}

} // namespace

extern "C" int ibex2_async_begin(const void *queue, const void *grants,
                                 uint32_t op, const Ibex2AbiValue *argv,
                                 size_t argc, uint64_t task_id);
extern "C" int ibex2_wait_for_completion(const void *queue,
                                         unsigned long long timeout_ms);
extern "C" double ibex2_take_due_timer(const void *queue);
extern "C" int ibex2_loader_load(const void *state, const char *from,
                                 const char *specifier,
                                 Ibex2AbiValue *out_resolved,
                                 Ibex2AbiValue *out_source);
extern "C" const void *ibex2_loader_grants_for(const void *state,
                                               const char *specifier);
extern "C" double ibex2_millis_until_next_timer(const void *queue);
extern "C" int ibex2_response_field(const void *queue, double handle,
                                    uint32_t field, const Ibex2AbiValue *name,
                                    Ibex2AbiValue *out);
extern "C" int ibex2_take_completion(const void *queue, uint64_t *task_id,
                                     Ibex2AbiValue *out, int *is_error);

// ---------------------------------------------------------------------------
// The job-queue adapter (LLP 0058 §3 / OQ1).
//
// A delegating op returns a promise immediately, the work happens on another
// thread, and the completion is delivered here — on the JavaScript thread —
// by resolving the stored promise and then draining microtasks. The ordering
// contract is stated in Rust, in task::Pump::CONTRACT, and the tests hold this
// implementation to it.
// ---------------------------------------------------------------------------


namespace {

// Build a promise and stash its resolve/reject under `id`.
//
// The executor runs synchronously inside the Promise constructor, so the
// functions are captured before this returns and a completion can never arrive
// to find the table empty.
jsi::Value make_pending_promise(jsi::Runtime &rt, Ibex2Runtime *owner,
                                uint64_t id) {
  auto ctor = rt.global().getPropertyAsFunction(rt, "Promise");
  auto executor = jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, "executor"), 2,
      [owner, id](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
                  size_t count) -> jsi::Value {
        if (count < 2) {
          throw jsi::JSError(rt, "promise executor needs resolve and reject");
        }
        owner->pending[id] = PendingPromise{
            std::make_shared<jsi::Function>(
                args[0].getObject(rt).getFunction(rt)),
            std::make_shared<jsi::Function>(
                args[1].getObject(rt).getFunction(rt))};
        return jsi::Value::undefined();
      });
  return ctor.callAsConstructor(rt, executor);
}

jsi::Function make_async_binding(jsi::Runtime &runtime, const char *name,
                                 uint32_t op, Ibex2Runtime *owner,
                                 const void *grants) {
  auto prop = jsi::PropNameID::forUtf8(runtime, std::string(name));
  return jsi::Function::createFromHostFunction(
      runtime, prop, 1,
      [op, owner, grants](jsi::Runtime &rt, const jsi::Value &,
                          const jsi::Value *args, size_t count) -> jsi::Value {
        std::vector<std::string> owned;
        owned.reserve(count);
        std::vector<Ibex2AbiValue> abi;
        abi.reserve(count);
        for (size_t i = 0; i < count; ++i) {
          abi.push_back(to_abi(rt, args[i], owned));
        }

        uint64_t id = owner->next_task_id++;
        jsi::Value promise = make_pending_promise(rt, owner, id);

        // The work starts only after the promise exists, so there is no window
        // in which a completion could arrive for an unknown task.
        if (ibex2_async_begin(owner->queue, grants, op,
                              abi.empty() ? nullptr : abi.data(), abi.size(),
                              id) != 0) {
          owner->pending.erase(id);
          throw jsi::JSError(rt, "could not start the async operation");
        }
        return promise;
      });
}

} // namespace

extern "C" {

/// Deliver every ready completion, then drain microtasks. Returns how many
/// completions were delivered.
///
/// This is the entire adapter. The order of the two steps is the contract:
/// resolving only ENQUEUES continuations (C1), and draining afterwards runs
/// them to quiescence before the caller regains control (C2).
int ibex2_hermes_pump(void *handle) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr) {
    return -1;
  }
  jsi::Runtime &runtime = *rt->runtime;
  int delivered = 0;

  uint64_t id = 0;
  Ibex2AbiValue value{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
  int is_error = 0;
  while (ibex2_take_completion(rt->queue, &id, &value, &is_error) != 0) {
    auto found = rt->pending.find(id);
    if (found == rt->pending.end()) {
      // Nothing is waiting for it; release the payload rather than leak it.
      ibex2_host_release(&value);
      continue;
    }
    PendingPromise promise = found->second;
    rt->pending.erase(found);

    jsi::Value payload = from_abi(runtime, value);
    ibex2_host_release(&value);
    try {
      if (is_error != 0) {
        // Reject with a real Error so `catch (e) { e.message }` works.
        auto error_ctor = runtime.global().getPropertyAsFunction(runtime, "Error");
        jsi::Value err = error_ctor.callAsConstructor(runtime, payload);
        promise.reject->call(runtime, err);
      } else {
        promise.resolve->call(runtime, payload);
      }
    } catch (const jsi::JSError &) {
      // A throwing resolve must not abort the pump; the remaining completions
      // are still owed delivery.
    }
    delivered += 1;
  }

  // C2: drain to quiescence, including microtasks enqueued by the microtasks
  // we just ran.
  runtime.drainMicrotasks();

  // Then timers. Each fired timer is a separate TASK, so the microtask queue is
  // drained after each one rather than once at the end — that is the HTML
  // microtask checkpoint, and batching it would let a later timer's
  // continuation run before an earlier timer's.
  jsi::Value fire = runtime.global().getProperty(runtime, "__ibex2_fire_timer");
  while (true) {
    double handle = ibex2_take_due_timer(rt->queue);
    if (handle == 0.0) {
      break;
    }
    if (fire.isObject() && fire.getObject(runtime).isFunction(runtime)) {
      try {
        fire.getObject(runtime).getFunction(runtime).call(runtime, handle);
      } catch (const jsi::JSError &) {
        // A throwing timer callback must not stop the other timers that are
        // already due, exactly as an unhandled error in one task does not
        // cancel the next.
      }
    }
    runtime.drainMicrotasks();
    delivered += 1;
  }
  return delivered;
}

/// Block until a completion is ready, or the timeout elapses.
///
/// A real embedder calls this instead of spinning: it wakes exactly when there
/// is work rather than burning a core to discover there is none.
int ibex2_hermes_wait(void *handle, unsigned long long timeout_ms) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr) {
    return 0;
  }
  return ibex2_wait_for_completion(rt->queue, timeout_ms);
}

/// Drain microtasks without delivering completions — the "JavaScript ran and
/// then yielded" step, used by the tests to observe ordering.
int ibex2_hermes_drain_microtasks(void *handle) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr) {
    return -1;
  }
  rt->runtime->drainMicrotasks();
  return 0;
}

} // extern "C"

namespace {

std::shared_ptr<jsi::Object> load_module(jsi::Runtime &rt, Ibex2Runtime *owner,
                                         const std::string &from,
                                         const std::string &specifier);

// `require`, closed over the specifier of the module that holds it — so a
// relative path resolves against the right file, and a module cannot claim to
// be somewhere else to change what it can reach.
jsi::Function make_require(jsi::Runtime &runtime, Ibex2Runtime *owner,
                           const std::string &self) {
  return jsi::Function::createFromHostFunction(
      runtime, jsi::PropNameID::forAscii(runtime, "require"), 1,
      [owner, self](jsi::Runtime &rt, const jsi::Value &,
                    const jsi::Value *args, size_t count) -> jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw jsi::JSError(rt, "require expects a specifier");
        }
        auto exports =
            load_module(rt, owner, self, args[0].getString(rt).utf8(rt));
        return jsi::Value(rt, *exports);
      });
}

std::shared_ptr<jsi::Object> load_module(jsi::Runtime &rt, Ibex2Runtime *owner,
                                         const std::string &from,
                                         const std::string &specifier) {
  Ibex2AbiValue resolved{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
  Ibex2AbiValue source{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
  int status = ibex2_loader_load(owner->queue, from.c_str(), specifier.c_str(),
                                 &resolved, &source);
  std::string resolved_name(reinterpret_cast<const char *>(resolved.data),
                            resolved.len);
  if (status != 0) {
    ibex2_host_release(&resolved);
    ibex2_host_release(&source);
    throw jsi::JSError(rt, resolved_name);
  }
  std::string source_text(reinterpret_cast<const char *>(source.data),
                          source.len);
  ibex2_host_release(&resolved);
  ibex2_host_release(&source);

  // A cycle returns the partial exports rather than recursing forever, which
  // is what CommonJS does and what makes mutually-importing modules terminate.
  auto existing = owner->modules.find(resolved_name);
  if (existing != owner->modules.end()) {
    return existing->second;
  }

  auto module = std::make_shared<jsi::Object>(rt);
  auto exports = std::make_shared<jsi::Object>(rt);
  module->setProperty(rt, "exports", jsi::Value(rt, *exports));
  // Registered BEFORE evaluation, so a cycle finds this entry.
  owner->modules[resolved_name] = exports;

  // The wrapper is a function EXPRESSION evaluated by the host. new Function
  // cannot be used — dynamic code is closed at construction (LLP 0060 D4) —
  // which is precisely why the loader lives here and not in JavaScript.
  std::string wrapped =
      "(function (module, exports, require, fetch) {\n" + source_text + "\n})";
  auto buffer = std::make_shared<jsi::StringBuffer>(wrapped);
  jsi::Value fn_value = rt.evaluateJavaScript(buffer, resolved_name);
  if (!fn_value.isObject() || !fn_value.getObject(rt).isFunction(rt)) {
    owner->modules.erase(resolved_name);
    throw jsi::JSError(rt, "module wrapper did not evaluate to a function");
  }

  // This module's own authority, captured now and carried by its binding for
  // the binding's whole life (LLP 0060 D1). A module granted nothing receives
  // a fetch that refuses everything — not an absent fetch, so the failure is a
  // denial rather than a TypeError.
  const void *grants =
      ibex2_loader_grants_for(owner->queue, resolved_name.c_str());
  if (grants != nullptr) {
    owner->module_grants.push_back(grants);
  }

  jsi::Value fetch_binding = jsi::Value(
      rt, make_async_binding(rt, "fetch", 101, owner, grants));

  fn_value.getObject(rt).getFunction(rt).call(
      rt, jsi::Value(rt, *module), jsi::Value(rt, *exports),
      jsi::Value(rt, make_require(rt, owner, resolved_name)),
      std::move(fetch_binding));

  // `module.exports = ...` replaces the object, so re-read it after running.
  jsi::Value final_exports = module->getProperty(rt, "exports");
  if (final_exports.isObject()) {
    auto replaced = std::make_shared<jsi::Object>(final_exports.getObject(rt));
    owner->modules[resolved_name] = replaced;
    return replaced;
  }
  return exports;
}

} // namespace

extern "C" {

/// Evaluate a buffer that may contain Hermes bytecode.
///
/// Hermes detects the HBC magic and takes the bytecode path, so this is the
/// same entry point as source with a different payload — which is exactly what
/// makes the comparison between them fair.
int ibex2_hermes_eval_bytes(void *handle, const unsigned char *data, size_t len,
                            char **out) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr || data == nullptr) {
    return -1;
  }

  // A Buffer over bytes the caller owns for the duration of the call.
  class BorrowedBuffer : public jsi::Buffer {
  public:
    BorrowedBuffer(const unsigned char *data, size_t len)
        : data_(data), len_(len) {}
    size_t size() const override { return len_; }
    const uint8_t *data() const override { return data_; }

  private:
    const unsigned char *data_;
    size_t len_;
  };

  try {
    auto buffer = std::make_shared<BorrowedBuffer>(data, len);
    jsi::Value value = rt->runtime->evaluateJavaScript(buffer, "<hbc>");
    if (out != nullptr) {
      *out = dup_c_string(value.isUndefined()
                              ? std::string("undefined")
                              : value.toString(*rt->runtime).utf8(*rt->runtime));
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

/// This runtime's Rust-side state, for callers that need it directly.
const void *ibex2_hermes_state(void *handle) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  return rt == nullptr ? nullptr : rt->queue;
}

/// Load and run an entry module. Returns 0 on success.
///
/// `out_error` receives the message on failure and is Rust-released.
int ibex2_hermes_run_entry(void *handle, const char *specifier,
                           char **out_error) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr) {
    return -1;
  }
  try {
    load_module(*rt->runtime, rt, "./", specifier);
    rt->runtime->drainMicrotasks();
    return 0;
  } catch (const jsi::JSError &e) {
    if (out_error != nullptr) {
      *out_error = dup_c_string(e.getMessage());
    }
    return 1;
  } catch (const std::exception &e) {
    if (out_error != nullptr) {
      *out_error = dup_c_string(std::string(e.what()));
    }
    return 1;
  }
}

} // extern "C"

extern "C" {

/// Install `fetch`, bound to the grants it will carry for its whole lifetime.
///
/// The grants are captured HERE, at install time, and handed back on every
/// call. That is LLP 0060 D1 made concrete: two runtimes — or two bindings —
/// can be given different authority for identical JavaScript, and neither can
/// reach the other's.
int ibex2_hermes_install_fetch(void *handle, const void *grants) {
  auto *rt = static_cast<Ibex2Runtime *>(handle);
  if (rt == nullptr || rt->runtime == nullptr) {
    return -1;
  }
  try {
    jsi::Runtime &runtime = *rt->runtime;
    jsi::Object global = runtime.global();
    global.setProperty(
        runtime, jsi::PropNameID::forAscii(runtime, "__ibex2_fetch"),
        make_async_binding(runtime, "__ibex2_fetch", 101, rt, grants));

    // Response accessors. A response crosses as a handle; these read it.
    auto field_fn = jsi::Function::createFromHostFunction(
        runtime, jsi::PropNameID::forAscii(runtime, "__ibex2_response_field"), 3,
        [rt](jsi::Runtime &r, const jsi::Value &, const jsi::Value *args,
             size_t count) -> jsi::Value {
          if (count < 2) {
            throw jsi::JSError(r, "response field needs a handle and a field id");
          }
          std::vector<std::string> owned;
          Ibex2AbiValue name{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
          if (count >= 3) {
            name = to_abi(r, args[2], owned);
          }
          Ibex2AbiValue out{IBEX2_TAG_UNDEFINED, 0.0, nullptr, 0};
          int status = ibex2_response_field(
              rt->queue, args[0].asNumber(),
              static_cast<uint32_t>(args[1].asNumber()),
              count >= 3 ? &name : nullptr, &out);
          jsi::Value result = from_abi(r, out);
          ibex2_host_release(&out);
          if (status != 0) {
            throw jsi::JSError(r, result.isString()
                                      ? result.getString(r).utf8(r)
                                      : std::string("response read failed"));
          }
          return result;
        });
    global.setProperty(runtime,
                       jsi::PropNameID::forAscii(runtime, "__ibex2_response_field"),
                       std::move(field_fn));
    return 0;
  } catch (const std::exception &) {
    return 1;
  }
}

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
    set_binding(runtime, console, "log", 1, rt->queue);
    set_binding(runtime, console, "info", 2, rt->queue);
    set_binding(runtime, console, "debug", 3, rt->queue);
    set_binding(runtime, console, "warn", 4, rt->queue);
    set_binding(runtime, console, "error", 5, rt->queue);
    global.setProperty(runtime, jsi::PropNameID::forAscii(runtime, "console"),
                       std::move(console));

    set_binding(runtime, global, "btoa", 10, rt->queue);
    set_binding(runtime, global, "atob", 11, rt->queue);
    set_binding(runtime, global, "__ibex2_text_encode", 20, rt->queue);
    set_binding(runtime, global, "__ibex2_text_decode", 21, rt->queue);
    set_binding(runtime, global, "__ibex2_text_encode_into", 22, rt->queue);
    set_binding(runtime, global, "__ibex2_url_parse", 30, rt->queue);
    set_binding(runtime, global, "__ibex2_search_params_get", 31, rt->queue);

    // The ops behind the Headers class. Rust owns the semantics; the class
    // shape is in bindings/headers.js.
    jsi::Object headers(runtime);
    set_binding(runtime, headers, "create", 40, rt->queue);
    set_binding(runtime, headers, "append", 41, rt->queue);
    set_binding(runtime, headers, "set", 42, rt->queue);
    set_binding(runtime, headers, "get", 43, rt->queue);
    set_binding(runtime, headers, "has", 44, rt->queue);
    set_binding(runtime, headers, "remove", 45, rt->queue);
    set_binding(runtime, headers, "count", 46, rt->queue);
    set_binding(runtime, headers, "nameAt", 47, rt->queue);
    set_binding(runtime, headers, "valueAt", 48, rt->queue);
    set_binding(runtime, headers, "validName", 49, rt->queue);
    set_binding(runtime, headers, "validValue", 50, rt->queue);
    set_binding(runtime, headers, "free", 51, rt->queue);
    global.setProperty(runtime,
                       jsi::PropNameID::forAscii(runtime, "__ibex2_headers"),
                       std::move(headers));

    set_binding(runtime, global, "__ibex2_timer_set", 60, rt->queue);
    set_binding(runtime, global, "__ibex2_timer_set_repeating", 61, rt->queue);
    set_binding(runtime, global, "__ibex2_timer_clear", 62, rt->queue);
    set_binding(runtime, global, "__ibex2_performance_now", 63, rt->queue);

    // The delegating tier. One op for now — enough to hold the adapter to its
    // ordering contract before any transport exists.
    global.setProperty(runtime,
                       jsi::PropNameID::forAscii(runtime, "__ibex2_async_echo"),
                       make_async_binding(runtime, "__ibex2_async_echo", 100, rt, nullptr));
    return 0;
  } catch (const std::exception &) {
    return 1;
  }
}

} // extern "C"
