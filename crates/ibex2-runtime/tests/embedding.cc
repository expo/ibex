// A caller-owned runtime: no ibex2 Hermes owner, loader, or pump.
#include <hermes/hermes.h>
#include <jsi/instrumentation.h>
#include "ibex2_jsi.h"
#include <cstdlib>
#include <cstring>
#include <type_traits>

using namespace facebook;
namespace ibex2::jsi_adapter {
struct AdapterTestAccess {
  static jsi::Object websocket_hooks(Adapter &adapter, const void *grants) {
    return adapter.websocket_hooks(grants);
  }
};
} // namespace ibex2::jsi_adapter

namespace {
struct Bytes : jsi::Buffer {
  std::vector<uint8_t> bytes;
  Bytes(const uint8_t *p, size_t n) : bytes(p, p + n) {}
  size_t size() const override { return bytes.size(); }
  const uint8_t *data() const override { return bytes.data(); }
};
struct Consumer {
  std::unique_ptr<jsi::Runtime> runtime;
  std::unique_ptr<ibex2::jsi_adapter::Adapter> adapter;
  const void *queue = nullptr;
  std::shared_ptr<size_t> promise_probe_roots = std::make_shared<size_t>(0);
};
struct PromiseProbeRoot final : jsi::NativeState {
  std::shared_ptr<size_t> count;
  explicit PromiseProbeRoot(std::shared_ptr<size_t> value) : count(std::move(value)) {
    ++*count;
  }
  ~PromiseProbeRoot() override { --*count; }
};
uint32_t bytecode_version() {
  auto *root = jsi::castInterface<facebook::hermes::IHermesRootAPI>(
      facebook::hermes::makeHermesRootAPI());
  return root == nullptr ? 0 : root->getBytecodeVersion();
}
char *copy(const std::string &s) {
  auto *p = static_cast<char *>(std::malloc(s.size() + 1));
  std::memcpy(p, s.c_str(), s.size() + 1);
  return p;
}
}

using InstallMethod = void (ibex2::jsi_adapter::Adapter::*)(
    ibex2::jsi_adapter::Groups, const Ibex2Bindings*,
    const ibex2::jsi_adapter::CompiledScript*, size_t);
static_assert(std::is_same_v<decltype(&ibex2::jsi_adapter::Adapter::install),
                             InstallMethod>);
using InstallWithMethod = void (ibex2::jsi_adapter::Adapter::*)(
    ibex2::jsi_adapter::Groups, const Ibex2Bindings*,
    const ibex2::jsi_adapter::CompiledScript*, size_t,
    const ibex2::jsi_adapter::InstallOptions&);
static_assert(std::is_same_v<decltype(&ibex2::jsi_adapter::Adapter::install_with),
                             InstallWithMethod>);
using HardenMethod = void (ibex2::jsi_adapter::Adapter::*)(
    const ibex2::jsi_adapter::CompiledScript&);
static_assert(std::is_same_v<decltype(&ibex2::jsi_adapter::Adapter::harden),
                             HardenMethod>);
using CaptureIntrinsicsMethod = void (ibex2::jsi_adapter::Adapter::*)();
static_assert(std::is_same_v<
    decltype(&ibex2::jsi_adapter::Adapter::capture_intrinsics),
    CaptureIntrinsicsMethod>);
static_assert(!std::is_convertible_v<const void*, const Ibex2Bindings*>);

extern "C" {
int bindings_validate_groups(uint16_t groups, char **error) {
  try {
    ibex2::jsi_adapter::validate_groups(groups);
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
char *bindings_expected_scripts(uint16_t groups, char **error) {
  try {
    const auto scripts = ibex2::jsi_adapter::expected_scripts(groups);
    std::string joined;
    for (const char *script : scripts) {
      if (!joined.empty()) joined.push_back('\n');
      joined.append(script);
    }
    return copy(joined);
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return nullptr;
  }
}
void *bindings_consumer_create_uninstalled(const void *queue) {
  try {
    auto c = std::make_unique<Consumer>();
    c->queue = queue;
    auto config = ::hermes::vm::RuntimeConfig::Builder()
        .withEnableEval(false).withMicrotaskQueue(true).build();
    c->runtime = facebook::hermes::makeHermesRuntimeNoThrow(config);
    if (!c->runtime) return nullptr;
    c->adapter = std::make_unique<ibex2::jsi_adapter::Adapter>(
        *c->runtime, queue, bytecode_version());
    return c.release();
  } catch (const std::exception &) {
    return nullptr;
  }
}
int bindings_consumer_install(
    void *handle, const Ibex2Bindings *bindings, uint16_t groups,
    const ibex2::jsi_adapter::CompiledScript *scripts, size_t script_count,
    char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr) return 0;
    c->adapter->install(groups, bindings, scripts, script_count);
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_install_with_fetch_primitives(
    void *handle, const Ibex2Bindings *bindings, uint16_t groups,
    const ibex2::jsi_adapter::CompiledScript *scripts, size_t script_count,
    const char *fetch_primitives, char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr) return 0;
    ibex2::jsi_adapter::InstallOptions options;
    options.fetch_primitives = fetch_primitives;
    c->adapter->install_with(groups, bindings, scripts, script_count, options);
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_install_with_options(
    void *handle, const Ibex2Bindings *bindings, uint16_t groups,
    const ibex2::jsi_adapter::CompiledScript *scripts, size_t script_count,
    const char *fetch_primitives, const char *abort_hooks,
    bool defer_intrinsic_snapshot, char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr) return 0;
    ibex2::jsi_adapter::InstallOptions options;
    options.fetch_primitives = fetch_primitives;
    options.abort_hooks = abort_hooks;
    options.defer_intrinsic_snapshot = defer_intrinsic_snapshot;
    c->adapter->install_with(groups, bindings, scripts, script_count, options);
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_capture_intrinsics(void *handle, char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr) return 0;
    c->adapter->capture_intrinsics();
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_install_storage(
    void *handle, const void *grants, const uint8_t *factory, size_t len,
    char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr || c->runtime == nullptr) return 0;
    auto &rt = *c->runtime;
    auto sqlite_factory = rt.evaluateJavaScript(
        std::make_shared<Bytes>(factory, len), "sqlite.hbc")
        .getObject(rt).getFunction(rt);
    rt.global().setProperty(
        rt, "storage", c->adapter->storage(grants, sqlite_factory));
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_publish_websocket_numeric_probe(
    void *handle, const void *grants, char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr || c->runtime == nullptr) return 0;
    auto &rt = *c->runtime;
    auto websocket =
        ibex2::jsi_adapter::AdapterTestAccess::websocket_hooks(
            *c->adapter, grants);
    rt.global().setProperty(
        rt, "__test_websocket_close",
        websocket.getProperty(rt, "close"));

    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}

int bindings_consumer_publish_sqlite_numeric_probe(
    void *handle, const void *grants, char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr || c->runtime == nullptr) return 0;
    auto &rt = *c->runtime;

    auto factory = jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "numericProbeSqliteFactory"), 2,
        [](jsi::Runtime &r, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          if (count != 2 || !args[1].isObject() ||
              !args[1].getObject(r).isFunction(r))
            throw jsi::JSError(r, "SQLite retain probe was not supplied");
          r.global().setProperty(r, "__test_sqlite_own",
                                 jsi::Value(r, args[1]));
          auto make_sqlite = jsi::Function::createFromHostFunction(
              r, jsi::PropNameID::forAscii(r, "numericProbeMakeSqlite"), 1,
              [](jsi::Runtime &, const jsi::Value &, const jsi::Value *,
                 size_t) -> jsi::Value { return jsi::Value::undefined(); });
          return jsi::Value(r, std::move(make_sqlite));
        });
    c->adapter->storage(grants, factory);
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
int bindings_consumer_harden(void *handle, const uint8_t *bytes, size_t len,
                             char **error) {
  try {
    auto *c = static_cast<Consumer *>(handle);
    if (c == nullptr || c->adapter == nullptr) return 0;
    c->adapter->harden(ibex2::jsi_adapter::CompiledScript{"harden", bytes, len});
    return 1;
  } catch (const std::exception &e) {
    if (error != nullptr) *error = copy(e.what());
    return 0;
  }
}
void *bindings_consumer_create(const void *queue, const Ibex2Bindings *bindings,
                               uint16_t groups,
                               const ibex2::jsi_adapter::CompiledScript *scripts,
                               size_t script_count, char **error) {
  void *consumer = bindings_consumer_create_uninstalled(queue);
  if (consumer == nullptr) return nullptr;
  if (bindings_consumer_install(consumer, bindings, groups, scripts,
                                script_count, error) == 1)
    return consumer;
  delete static_cast<Consumer *>(consumer);
  return nullptr;
}
void *storage_consumer_create(const void *queue, const void *grants,
                              const uint8_t *factory, size_t len,
                              const uint8_t *harden, size_t harden_len, char **error) {
  try {
    auto c = std::make_unique<Consumer>();
    c->queue = queue;
    auto config = ::hermes::vm::RuntimeConfig::Builder()
        .withEnableEval(false).withMicrotaskQueue(true).build();
    c->runtime = facebook::hermes::makeHermesRuntimeNoThrow(config);
    if (!c->runtime) return nullptr;
    auto &rt = *c->runtime;
    auto names = rt.global().getPropertyAsObject(rt, "Object")
        .getPropertyAsFunction(rt, "getOwnPropertyNames");
    auto stringify = rt.global().getPropertyAsObject(rt, "JSON")
        .getPropertyAsFunction(rt, "stringify");
    auto before = stringify.call(rt, names.call(rt, rt.global())).getString(rt).utf8(rt);
    auto f = rt.evaluateJavaScript(std::make_shared<Bytes>(factory, len), "sqlite.hbc")
        .getObject(rt).getFunction(rt);
    c->adapter = std::make_unique<ibex2::jsi_adapter::Adapter>(
        rt, queue, bytecode_version());
    if (harden_len) rt.evaluateJavaScript(std::make_shared<Bytes>(harden, harden_len), "harden.hbc");
    auto storage = c->adapter->storage(grants, f);
    auto after = stringify.call(rt, names.call(rt, rt.global())).getString(rt).utf8(rt);
    if (before != after) throw jsi::JSError(rt, "installer mutated caller globals");
    // The caller deliberately passes its capability to the test application.
    rt.global().setProperty(rt, "storage", storage);
    return c.release();
  } catch (const std::exception &e) { *error = copy(e.what()); return nullptr; }
}
// Trusted host lookup: the value is retrieved with the runtime that owns it.
uint64_t storage_consumer_image_task_id(void *owner, void *value_owner, const char *name) {
  auto *c = static_cast<Consumer *>(owner);
  auto *source = static_cast<Consumer *>(value_owner);
  if (!c || !c->adapter || !source || !source->runtime) return 0;
  auto &rt = *source->runtime;
  return c->adapter->image_task_id(rt, rt.global().getProperty(rt, name));
}
// Same runtime, independently branded adapter: checks owner identity separately
// from the runtime check without ever passing a foreign value to a JSI engine.
uint64_t storage_consumer_foreign_adapter_image_task_id(void *value_owner, const char *name) {
  auto *c = static_cast<Consumer *>(value_owner);
  auto &rt = *c->runtime;
  ibex2::jsi_adapter::Adapter other(rt, c->queue, bytecode_version());
  return other.image_task_id(rt, rt.global().getProperty(rt, name));
}
// Detach without destroying the adapter so the production stale-owner refusal
// is exercised while the Promise remains alive in its own runtime.
uint64_t storage_consumer_detached_image_task_id(void *value_owner, const char *name) {
  auto *c = static_cast<Consumer *>(value_owner);
  auto &rt = *c->runtime;
  auto value = rt.global().getProperty(rt, name);
  c->adapter->detach();
  return c->adapter->image_task_id(rt, value);
}
// Unhardened fault-injection only: count actual native owners attached to the
// replacement constructor's callbacks and returned object across collection.
int storage_consumer_install_promise_root_probe(void *value_owner) {
  auto *c = static_cast<Consumer *>(value_owner);
  auto &rt = *c->runtime;
  try {
    auto probe = jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "promiseRootProbe"), 1,
        [count = c->promise_probe_roots](jsi::Runtime &r, const jsi::Value &,
                                       const jsi::Value *args, size_t argc) {
          if (argc != 1 || !args[0].isObject())
            throw jsi::JSError(r, "promise probe requires an object");
          ibex2::jsi_adapter::set_native_state_once(
              r, args[0].getObject(r), std::make_shared<PromiseProbeRoot>(count),
              "Promise root probe");
          return jsi::Value::undefined();
        });
    rt.global().setProperty(rt, "promiseRootProbe", std::move(probe));
    return 1;
  } catch (...) {
    return 0;
  }
}
size_t storage_consumer_promise_probe_roots(void *value_owner) {
  return *static_cast<Consumer *>(value_owner)->promise_probe_roots;
}

int storage_consumer_eval(void *h, const uint8_t *bytes, size_t len, char **out) {
  auto &rt = *static_cast<Consumer *>(h)->runtime;
  try {
    auto v = rt.evaluateJavaScript(std::make_shared<Bytes>(bytes, len), "test.hbc");
    *out = copy(v.toString(rt).utf8(rt));
    return 0;
  } catch (const std::exception &e) { *out = copy(e.what()); return 1; }
}
int storage_consumer_step(void *h, bool deliver, char **out) {
  auto *c = static_cast<Consumer *>(h);
  try {
    if (deliver) return c->adapter->deliver_one() ? 1 : 0;
    c->runtime->drainMicrotasks();
    return 0;
  } catch (const std::exception &e) { *out = copy(e.what()); return -1; }
}
int storage_consumer_collect_garbage(void *h) {
  auto *c = static_cast<Consumer *>(h);
  try {
    // LLP 0071 D7: a borrowed owner reconciles keepalive roots first, as the
    // owning runtime does.
    if (c->adapter) c->adapter->prepare_garbage_collection();
    c->runtime->instrumentation().collectGarbage("embedding test collection");
    return 1;
  } catch (...) {
    return 0;
  }
}
unsigned long long storage_consumer_subscribe(void *h, const char *callback_name) {
  auto *c = static_cast<Consumer *>(h);
  try {
    auto callback = c->runtime->global().getPropertyAsFunction(
        *c->runtime, callback_name);
    return c->adapter->subscribe(std::move(callback));
  } catch (...) {
    return 0;
  }
}
unsigned long long storage_consumer_subscribe_native_throw(void *h) {
  auto *c = static_cast<Consumer *>(h);
  try {
    auto callback = jsi::Function::createFromHostFunction(
        *c->runtime,
        jsi::PropNameID::forAscii(*c->runtime, "throwNativeEvent"), 1,
        [](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t)
            -> jsi::Value { throw std::runtime_error("native callback boom"); });
    return c->adapter->subscribe(std::move(callback));
  } catch (...) {
    return 0;
  }
}
// LLP 0071 D5: one cycle. 0 idle, 1 delivered, 2 nested, -1 failed.
int storage_consumer_cycle(void *h, char **out) {
  auto *c = static_cast<Consumer *>(h);
  try {
    switch (c->adapter->cycle()) {
      case ibex2::jsi_adapter::Adapter::Cycle::Delivered: return 1;
      case ibex2::jsi_adapter::Adapter::Cycle::Nested: return 2;
      default: return 0;
    }
  } catch (const std::exception &e) { *out = copy(e.what()); return -1; }
}
// LLP 0071 D5: globals through which JavaScript reaches the caller's loop, as
// an embedder's native function might -- cycleFromJs() and deliverFromJs().
int storage_consumer_install_loop_probe(void *h) {
  auto *c = static_cast<Consumer *>(h);
  auto &rt = *c->runtime;
  try {
    rt.global().setProperty(rt, "cycleFromJs", jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "cycleFromJs"), 0,
        [c](jsi::Runtime &r, const jsi::Value &, const jsi::Value *, size_t) -> jsi::Value {
          switch (c->adapter->cycle()) {
            case ibex2::jsi_adapter::Adapter::Cycle::Delivered: return jsi::String::createFromAscii(r, "delivered");
            case ibex2::jsi_adapter::Adapter::Cycle::Nested: return jsi::String::createFromAscii(r, "nested");
            default: return jsi::String::createFromAscii(r, "idle");
          }
        }));
    rt.global().setProperty(rt, "detachFromJs", jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "detachFromJs"), 0,
        [c](jsi::Runtime &, const jsi::Value &, const jsi::Value *, size_t) -> jsi::Value {
          c->adapter->detach();
          return jsi::Value::undefined();
        }));
    rt.global().setProperty(rt, "deliverFromJs", jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "deliverFromJs"), 0,
        [c](jsi::Runtime &r, const jsi::Value &, const jsi::Value *, size_t) -> jsi::Value {
          try {
            return jsi::String::createFromAscii(r, c->adapter->deliver_one() ? "delivered" : "idle");
          } catch (const std::logic_error &e) {
            return jsi::String::createFromUtf8(r, std::string("refused: ") + e.what());
          }
        }));
    return 1;
  } catch (...) { return 0; }
}
void storage_consumer_detach(void *h) { static_cast<Consumer *>(h)->adapter.reset(); }
void storage_consumer_destroy(void *h) { delete static_cast<Consumer *>(h); }
void storage_consumer_free(char *s) { std::free(s); }
}
