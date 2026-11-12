// Exercise the real collector and JSI exception boundary with a small heap.
#include <hermes/hermes.h>
#include <hermes/Public/JSOutOfMemoryError.h>
#include <cstring>
#include <iostream>
#ifndef IBEX2_OOM_STANDALONE
#include "ibex2_jsi.h"
extern "C" int ibex2_test_publish_event(const void *, uint64_t);
#endif

using namespace facebook;

namespace {
const char *exhaust_heap = R"JS(
  var held = [];
  try {
    for (var i = 0; i < 1000000; ++i) held.push({id: i, title: 'task', done: false});
  } catch (error) {
    // A heap OOM must leave JavaScript, including its catch clauses.
    held = [];
  }
)JS";

auto make_small_runtime() {
  auto config = ::hermes::vm::RuntimeConfig::Builder()
      .withGCConfig(::hermes::vm::GCConfig::Builder()
          .withInitHeapSize(4 << 20).withMaxHeapSize(8 << 20).build())
      .withMicrotaskQueue(true).build();
  return facebook::hermes::makeHermesRuntime(config);
}

jsi::Value eval(jsi::Runtime &runtime, const std::string &source) {
  return runtime.evaluateJavaScript(std::make_shared<jsi::StringBuffer>(source), "oom-test.js");
}
}

extern "C" int bindings_test_oom(const void *queue, int path) {
  // EH with hidden, RTTI-disabled standard-library typeinfo can break ordinary
  // exception matching in the final executable, even outside the engine.
  try {
    throw std::invalid_argument("embedding exception");
  } catch (const std::exception &) {
  } catch (...) {
    std::cerr << "std::invalid_argument did not match std::exception\n";
    return 0;
  }
  bool caught = false;
  {
    auto runtime = make_small_runtime();
#ifndef IBEX2_OOM_STANDALONE
    ibex2::jsi_adapter::Adapter adapter(*runtime, queue);
#else
    (void)queue;
#endif
    try {
      if (path == 0) {
        eval(*runtime, exhaust_heap);
      } else if (path == 1) {
        runtime->global().setProperty(*runtime, "allocate",
            jsi::Function::createFromHostFunction(*runtime,
                jsi::PropNameID::forAscii(*runtime, "allocate"), 0,
                [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *, size_t) {
                  return eval(rt, exhaust_heap);
                }));
        eval(*runtime, "allocate()");
#ifndef IBEX2_OOM_STANDALONE
      } else if (path == 2) {
        eval(*runtime, std::string("HermesInternal.enqueueJob(function () {") + exhaust_heap + "})");
        adapter.cycle();
      } else if (path == 3) {
        auto callback = eval(*runtime, std::string("(function () {") + exhaust_heap + "})")
            .getObject(*runtime).getFunction(*runtime);
        auto id = adapter.subscribe(std::move(callback));
        if (!ibex2_test_publish_event(queue, id)) return 0;
        adapter.deliver_one();
#endif
      } else {
        return 0;
      }
    } catch (const ::hermes::vm::JSOutOfMemoryError &error) {
      caught = std::strstr(error.what(), "Max heap size") != nullptr;
    } catch (const std::exception &error) {
      std::cerr << "wrong exception: " << error.what() << '\n';
      return 0;
    }
    // Destruction only: the interpreter register stack was not unwound.
    // The adapter and its JSI roots must go before the runtime.
  }
  auto replacement = make_small_runtime();
  return caught && eval(*replacement, "1 + 1").getNumber() == 2;
}

#ifdef IBEX2_OOM_STANDALONE
int main() {
  for (int path : {0, 1}) {
    if (!bindings_test_oom(nullptr, path)) return 1;
    std::cout << "JSOutOfMemoryError escaped path " << path
              << "; destroyed runtime and evaluated in a replacement\n";
  }
#if defined(__APPLE__) || defined(__ANDROID__)
  auto runtime = make_small_runtime();
  const auto intl = eval(*runtime, R"JS(
    JSON.stringify([
      typeof Intl.DateTimeFormat, typeof Intl.NumberFormat, typeof Intl.Collator,
      new Intl.DateTimeFormat('en-US', {timeZone: 'UTC', year: 'numeric',
        month: 'short', day: 'numeric'}).format(1577966400000),
      typeof new Intl.NumberFormat('en-US').format(1234.5),
      new Intl.Collator('en-US').compare('a', 'b') < 0
    ])
  )JS").getString(*runtime).utf8(*runtime);
  const char *expected = R"(["function","function","function","Jan 2, 2020","string",true])";
  std::cout << "Intl constructors/date/collation: " << intl << '\n';
  // The ICU backend's incomplete NumberFormat is completed by Exact's Ibex
  // projection; this standalone probe checks the engine constructor only.
  return intl == expected ? 0 : 1;
#else
  return 0;
#endif
}
#endif
