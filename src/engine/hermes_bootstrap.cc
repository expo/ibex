#include "hermes_runtime_internal.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#if __has_include("bootstrap_bytecode.h")
#include "bootstrap_bytecode.h"
#define HAS_PRECOMPILED_BOOTSTRAP 1
#endif

#if __has_include("bootstrap_source.h")
#include "bootstrap_source.h"
#endif

#if __has_include("runtime_bundle_source.h")
#include "runtime_bundle_source.h"
#define HAS_SHARED_RUNTIME_BUNDLE 1
#endif

#if __has_include("runtime_bundle_bytecode.h")
#include "runtime_bundle_bytecode.h"
#define HAS_SHARED_RUNTIME_BUNDLE_HBC 1
#endif

extern "C" void ex_host_console_log(int32_t level, const char* message);
extern "C" int ex_hermes_eval(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* source_url,
    int is_bytecode,
    char** out_value);
extern "C" void ex_hermes_free_string(char* value);

const char* g_streamEnhanceJS = nullptr;
const char* g_webCryptoJS = nullptr;
const char* g_webStorageJS = nullptr;
const char* g_formDataJS = nullptr;

bool eval_bootstrap_script(
    ExactHermesRuntime* handle,
    const char* source,
    const uint8_t* hbc,
    size_t hbcLen,
    const char* sourceUrl,
    bool preferSource,
    bool allowHbc) {
  if (!handle || !source || !sourceUrl) {
    return false;
  }

#ifdef HAS_PRECOMPILED_BOOTSTRAP
  if (!preferSource && allowHbc && hbc != nullptr && hbcLen > 0) {
    if (ex_hermes_eval(handle, hbc, hbcLen, sourceUrl, 1, nullptr) == 0) {
      return true;
    }
  }
#endif
  return ex_hermes_eval(handle,
                        reinterpret_cast<const uint8_t*>(source),
                        std::strlen(source),
                        sourceUrl,
                        0,
                        nullptr) == 0;
}

static bool installSharedRuntimeBundle(ExactHermesRuntime* handle) {
#ifdef HAS_SHARED_RUNTIME_BUNDLE
  if (!handle || !handle->runtime || SHARED_RUNTIME_BUNDLE_SRC[0] == '\0') {
    return false;
  }

  if (env_flag_enabled("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE")) {
    if (startup_trace_enabled()) {
      fprintf(
          stderr,
          "[startup]   shared_runtime_bundle skipped (set "
          "EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE=0 to re-enable)\n");
    }
    return false;
  }

  auto& rt = *handle->runtime;
  try {
    rt.global().setProperty(rt, "__exactSuppressRuntimeBanner", true);
  } catch (...) {
  }

  bool sourceSharedRuntimeBundle = env_flag_enabled("EX_SHARED_RUNTIME_BUNDLE_SOURCE");
#ifdef HAS_SHARED_RUNTIME_BUNDLE_HBC
  const uint8_t* sharedRuntimeBundleHbc =
      reinterpret_cast<const uint8_t*>(SHARED_RUNTIME_BUNDLE_HBC);
  size_t sharedRuntimeBundleHbcLen = SHARED_RUNTIME_BUNDLE_HBC_LEN;
#else
  const uint8_t* sharedRuntimeBundleHbc = nullptr;
  size_t sharedRuntimeBundleHbcLen = 0;
#endif

  char* error = nullptr;
  bool evaluated = false;
  if (!sourceSharedRuntimeBundle &&
      sharedRuntimeBundleHbc != nullptr &&
      sharedRuntimeBundleHbcLen > 0) {
    evaluated = ex_hermes_eval(handle,
                               sharedRuntimeBundleHbc,
                               sharedRuntimeBundleHbcLen,
                               "<shared-runtime-bundle>",
                               1,
                               &error) == 0;
    if (!evaluated && error != nullptr) {
      ex_hermes_free_string(error);
      error = nullptr;
    }
  }
  if (!evaluated) {
    evaluated = ex_hermes_eval(handle,
                               reinterpret_cast<const uint8_t*>(SHARED_RUNTIME_BUNDLE_SRC),
                               std::strlen(SHARED_RUNTIME_BUNDLE_SRC),
                               "<shared-runtime-bundle>",
                               0,
                               &error) == 0;
  }
  if (!evaluated) {
    if (error != nullptr) {
      ex_host_console_log(1, error);
      ex_hermes_free_string(error);
    }
    return false;
  }

  try {
    auto loaded = rt.global().getProperty(rt, "__exactRuntimeLoaded");
    return loaded.isBool() && loaded.getBool();
  } catch (...) {
    return false;
  }
#else
  (void)handle;
  return false;
#endif
}

bool installModuleLoader(ExactHermesRuntime* handle) {
  bool skip_module_loader = env_flag_enabled("EX_SKIP_STARTUP_MODULE_LOADER");
  bool skip_module_loader_script = env_flag_enabled("EX_SKIP_STARTUP_MODULE_LOADER_SCRIPT");
  if (skip_module_loader) {
    if (startup_trace_enabled()) {
      fprintf(stderr,
              "[startup]   module_loader skipped (set EX_SKIP_STARTUP_MODULE_LOADER=0 to "
              "re-enable)\n");
    }
    return false;
  }

  static const char* loader = MODULE_LOADER_SRC;

  // Signal to the module loader that a shared runtime bundle will be loaded
  // after it, so it can skip eager Buffer/timer installation.
#ifdef HAS_SHARED_RUNTIME_BUNDLE
  if (!env_flag_enabled("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE")) {
    try {
      handle->runtime->global().setProperty(
          *handle->runtime, "__exactHasSharedRuntimeBundle", true);
    } catch (...) {}
  }
#endif

  auto t0 = std::chrono::steady_clock::now();
  if (skip_module_loader_script) {
    if (startup_trace_enabled()) {
      fprintf(stderr,
              "[startup]   module_loader_script skipped (set "
              "EX_SKIP_STARTUP_MODULE_LOADER_SCRIPT=0 to re-enable)\n");
    }
  } else {
    bool source_module_loader = env_flag_enabled("EX_MODULE_LOADER_SOURCE");
    bool module_loader_hbc =
        env_flag_enabled("EX_MODULE_LOADER_HBC") || !source_module_loader;
    try {
#ifdef HAS_PRECOMPILED_BOOTSTRAP
      bool moduleLoaderEvaluated = eval_bootstrap_script(
          handle,
          loader,
          reinterpret_cast<const uint8_t*>(MODULE_LOADER_HBC),
          MODULE_LOADER_HBC_LEN,
          "<module-loader>",
          source_module_loader || !module_loader_hbc,
          module_loader_hbc);
#else
      bool moduleLoaderEvaluated =
          eval_bootstrap_script(handle, loader, nullptr, 0, "<module-loader>", true, false);
#endif
      if (!moduleLoaderEvaluated) {
        throw std::runtime_error("Module loader failed to evaluate");
      }
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, err.getMessage().c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
    }
  }
  if (startup_trace_enabled()) {
    auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              t0)
            .count();
    fprintf(stderr,
            "[startup]   %-28s %6lld us (%5.1f ms)\n",
            "module_loader",
            static_cast<long long>(elapsed),
            elapsed / 1000.0);
  }

  auto t_srb = std::chrono::steady_clock::now();
  bool sharedRuntimeInstalled = installSharedRuntimeBundle(handle);
  if (startup_trace_enabled()) {
    auto srb_elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              t_srb)
            .count();
    fprintf(stderr,
            "[startup]   %-28s %6lld us (%5.1f ms)\n",
            "shared_runtime_bundle",
            static_cast<long long>(srb_elapsed),
            srb_elapsed / 1000.0);
  }
  if (sharedRuntimeInstalled) {
    if (startup_trace_enabled()) {
      fprintf(stderr,
              "[startup]   shared_runtime_bundle installed; skipping legacy bootstrap_globals\n");
    }
    return true;
  }

  t0 = std::chrono::steady_clock::now();
  if (env_flag_enabled("EX_SKIP_STARTUP_BOOTSTRAP_GLOBALS")) {
    if (startup_trace_enabled()) {
      fprintf(stderr,
              "[startup]   bootstrap_globals skipped (set "
              "EX_SKIP_STARTUP_BOOTSTRAP_GLOBALS=0 to re-enable)\n");
    }
  } else {
    bool source_bootstrap_globals = env_flag_enabled("EX_BOOTSTRAP_GLOBALS_SOURCE");
    bool bootstrap_globals_hbc =
        env_flag_enabled("EX_BOOTSTRAP_GLOBALS_HBC") || !source_bootstrap_globals;
    try {
      const char* globals = BOOTSTRAP_GLOBALS_SRC;
#ifdef HAS_PRECOMPILED_BOOTSTRAP
      bool bootstrapGlobalsEvaluated = eval_bootstrap_script(
          handle,
          globals,
          reinterpret_cast<const uint8_t*>(BOOTSTRAP_GLOBALS_HBC),
          BOOTSTRAP_GLOBALS_HBC_LEN,
          "<bootstrap>",
          source_bootstrap_globals || !bootstrap_globals_hbc,
          bootstrap_globals_hbc);
#else
      bool bootstrapGlobalsEvaluated =
          eval_bootstrap_script(handle, globals, nullptr, 0, "<bootstrap>", true, false);
#endif
      if (!bootstrapGlobalsEvaluated) {
        throw std::runtime_error("Bootstrap globals failed to evaluate");
      }
    } catch (...) {
    }
    if (startup_trace_enabled()) {
      auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::steady_clock::now() - t0)
                         .count();
      fprintf(stderr,
              "[startup]   %-28s %6lld us (%5.1f ms)\n",
              "bootstrap_globals",
              static_cast<long long>(elapsed),
              elapsed / 1000.0);
    }
  }

  return false;
}

void ensureStreamEnhance(ExactHermesRuntime* handle) {
  if (handle->stream_enhance_loaded) return;
  handle->stream_enhance_loaded = true;
  if (!g_streamEnhanceJS) {
    return;
  }
  try {
    bool sourceStreamEnhance = env_flag_enabled("EX_STREAM_ENHANCE_SOURCE");
    bool streamEnhanceHbc =
        env_flag_enabled("EX_STREAM_ENHANCE_HBC") || !sourceStreamEnhance;
    if (!eval_bootstrap_script(
            handle,
            g_streamEnhanceJS,
            reinterpret_cast<const uint8_t*>(STREAM_ENHANCE_HBC),
            STREAM_ENHANCE_HBC_LEN,
            "<stream-enhance>",
            sourceStreamEnhance,
            streamEnhanceHbc)) {
      throw std::runtime_error("Stream enhance failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, (std::string("Stream enhance error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("Stream enhance error: ") + err.what()).c_str());
  } catch (...) {
  }
}

void ensureWebCrypto(ExactHermesRuntime* handle) {
  if (handle->web_crypto_loaded) return;
  handle->web_crypto_loaded = true;
  if (!g_webCryptoJS) {
    return;
  }
  try {
    bool source_preferred = env_flag_enabled("EX_WEB_CRYPTO_SOURCE");
    bool hbc_enabled = env_flag_enabled("EX_WEB_CRYPTO_HBC") || !source_preferred;
    if (!eval_bootstrap_script(
            handle,
            g_webCryptoJS,
            reinterpret_cast<const uint8_t*>(WEB_CRYPTO_HBC),
            WEB_CRYPTO_HBC_LEN,
            "<web-crypto>",
            source_preferred,
            hbc_enabled)) {
      throw std::runtime_error("Web Crypto failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, (std::string("Web Crypto error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("Web Crypto error: ") + err.what()).c_str());
  } catch (...) {
  }
}

void ensureWebStorage(ExactHermesRuntime* handle) {
  if (handle->web_storage_loaded) return;
  handle->web_storage_loaded = true;
  if (!g_webStorageJS) {
    return;
  }
  try {
    bool source_preferred = env_flag_enabled("EX_WEB_STORAGE_SOURCE");
    bool hbc_enabled = env_flag_enabled("EX_WEB_STORAGE_HBC") || !source_preferred;
    if (!eval_bootstrap_script(
            handle,
            g_webStorageJS,
            reinterpret_cast<const uint8_t*>(WEB_STORAGE_HBC),
            WEB_STORAGE_HBC_LEN,
            "<web-storage>",
            source_preferred,
            hbc_enabled)) {
      throw std::runtime_error("Storage failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, (std::string("Storage error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("Storage error: ") + err.what()).c_str());
  } catch (...) {
  }
}

void ensureFormData(ExactHermesRuntime* handle) {
  if (handle->form_data_loaded) return;
  handle->form_data_loaded = true;
  if (!g_formDataJS) {
    return;
  }
  try {
    bool source_preferred = env_flag_enabled("EX_FORM_DATA_SOURCE");
    bool hbc_enabled = env_flag_enabled("EX_FORM_DATA_HBC") || !source_preferred;
    if (!eval_bootstrap_script(
            handle,
            g_formDataJS,
            reinterpret_cast<const uint8_t*>(FORM_DATA_HBC),
            FORM_DATA_HBC_LEN,
            "<form-data>",
            source_preferred,
            hbc_enabled)) {
      throw std::runtime_error("FormData failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, (std::string("FormData error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("FormData error: ") + err.what()).c_str());
  } catch (...) {
  }
}

void installLegacyLazyBootstrapGetters(ExactHermesRuntime* handle, bool sharedRuntimeInstalled) {
#ifdef HAS_PRECOMPILED_BOOTSTRAP
  if (!handle || !handle->runtime) {
    return;
  }

  bool tracing = startup_trace_enabled();
  if (sharedRuntimeInstalled) {
    if (tracing) {
      fprintf(stderr, "[startup]   legacy_lazy_getters skipped (shared runtime bundle)\n");
    }
    return;
  }
  if (env_flag_enabled("EX_SKIP_STARTUP_LAZY_GETTERS")) {
    if (tracing) {
      fprintf(stderr,
              "[startup]   lazy_getters skipped (set EX_SKIP_STARTUP_LAZY_GETTERS=0 to re-enable)\n");
    }
    return;
  }

  auto& rt = *handle->runtime;
  auto ensureStreamFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEnsureStreamEnhance"),
      0,
      [handle](facebook::jsi::Runtime&, const facebook::jsi::Value&, const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        ensureStreamEnhance(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactEnsureStreamEnhance", std::move(ensureStreamFn));

  auto ensureCryptoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEnsureWebCrypto"),
      0,
      [handle](facebook::jsi::Runtime&, const facebook::jsi::Value&, const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        ensureWebCrypto(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactEnsureWebCrypto", std::move(ensureCryptoFn));

  auto ensureStorageFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEnsureWebStorage"),
      0,
      [handle](facebook::jsi::Runtime&, const facebook::jsi::Value&, const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        ensureWebStorage(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactEnsureWebStorage", std::move(ensureStorageFn));

  auto ensureFormDataFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEnsureFormData"),
      0,
      [handle](facebook::jsi::Runtime&, const facebook::jsi::Value&, const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        ensureFormData(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactEnsureFormData", std::move(ensureFormDataFn));

  try {
    bool sourceLazyGetters = env_flag_enabled("EX_LAZY_GETTERS_SOURCE");
    bool lazyGettersHbc = env_flag_enabled("EX_LAZY_GETTERS_HBC") || !sourceLazyGetters;
    if (!eval_bootstrap_script(handle,
                               LAZY_GETTERS_SRC,
                               reinterpret_cast<const uint8_t*>(LAZY_GETTERS_HBC),
                               LAZY_GETTERS_HBC_LEN,
                               "<lazy-getters>",
                               sourceLazyGetters,
                               lazyGettersHbc)) {
      throw std::runtime_error("Lazy getters failed to evaluate");
    }
  } catch (...) {
  }
#else
  (void)handle;
  (void)sharedRuntimeInstalled;
#endif
}

void runLegacyProcessCompatFix(ExactHermesRuntime* handle, bool sharedRuntimeInstalled) {
  if (!handle || !handle->runtime) {
    return;
  }

  if (sharedRuntimeInstalled) {
    if (startup_trace_enabled()) {
      fprintf(stderr, "[startup]   process_compat_fix skipped (shared runtime bundle)\n");
    }
    return;
  }

  try {
    bool sourceProcessCompatFix = env_flag_enabled("EX_PROCESS_COMPAT_FIX_SOURCE");
    bool processCompatFixHbc =
        env_flag_enabled("EX_PROCESS_COMPAT_FIX_HBC") || !sourceProcessCompatFix;
    if (!eval_bootstrap_script(handle,
                               PROCESS_COMPAT_FIX_SRC,
                               reinterpret_cast<const uint8_t*>(PROCESS_COMPAT_FIX_HBC),
                               PROCESS_COMPAT_FIX_HBC_LEN,
                               "<process-compat-fix>",
                               sourceProcessCompatFix,
                               processCompatFixHbc)) {
      throw std::runtime_error("Process compatibility fix failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(
        1, (std::string("Process compatibility fix error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(
        1, (std::string("Process compatibility fix error: ") + err.what()).c_str());
  }
}

void runLegacyCompatPolyfills(ExactHermesRuntime* handle, bool sharedRuntimeInstalled) {
  if (!handle || !handle->runtime) {
    return;
  }

  bool tracing = startup_trace_enabled();
  if (sharedRuntimeInstalled) {
    if (tracing) {
      fprintf(stderr, "[startup]   compat_polyfills skipped (shared runtime bundle)\n");
    }
    return;
  }
  if (env_flag_enabled("EX_SKIP_STARTUP_COMPAT_POLYFILLS")) {
    if (tracing) {
      fprintf(stderr,
              "[startup]   compat_polyfills skipped (set EX_SKIP_STARTUP_COMPAT_POLYFILLS=0 to re-enable)\n");
    }
    return;
  }

  auto start = std::chrono::steady_clock::now();
  bool compatEvaluated = false;
  try {
    bool sourceCompatPolyfills = env_flag_enabled("EX_COMPAT_POLYFILLS_SOURCE");
    bool compatPolyfillsHbc =
        env_flag_enabled("EX_COMPAT_POLYFILLS_HBC") || !sourceCompatPolyfills;
    compatEvaluated = eval_bootstrap_script(handle,
                                            COMPAT_POLYFILLS_SRC,
                                            reinterpret_cast<const uint8_t*>(COMPAT_POLYFILLS_HBC),
                                            COMPAT_POLYFILLS_HBC_LEN,
                                            "<compat-polyfills>",
                                            sourceCompatPolyfills || !compatPolyfillsHbc,
                                            compatPolyfillsHbc);
    if (!compatEvaluated) {
      throw std::runtime_error("Compatibility polyfills failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(
        1, (std::string("Compatibility polyfill error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("Compatibility polyfill error: ") + err.what()).c_str());
  }

  if (compatEvaluated) {
    handle->runtime->drainMicrotasks(-1);
  }
  if (tracing) {
    auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              start)
            .count();
    fprintf(stderr,
            "[startup]   %-28s %6lld us (%5.1f ms)\n",
            "compat_polyfills",
            static_cast<long long>(elapsed),
            elapsed / 1000.0);
  }
}

void runLegacyExactGlobal(ExactHermesRuntime* handle, bool sharedRuntimeInstalled) {
  if (!handle || !handle->runtime) {
    return;
  }

  bool tracing = startup_trace_enabled();
  if (sharedRuntimeInstalled) {
    if (tracing) {
      fprintf(stderr, "[startup]   exact_global skipped (shared runtime bundle)\n");
    }
    return;
  }
  if (env_flag_enabled("EX_SKIP_STARTUP_EXACT_GLOBAL")) {
    if (tracing) {
      fprintf(stderr,
              "[startup]   exact_global skipped (set EX_SKIP_STARTUP_EXACT_GLOBAL=0 to re-enable)\n");
    }
    return;
  }

  auto start = std::chrono::steady_clock::now();
  bool exactEvaluated = false;
  try {
    bool sourceExactGlobal = env_flag_enabled("EX_EXACT_GLOBAL_SOURCE");
    bool exactGlobalHbc = env_flag_enabled("EX_EXACT_GLOBAL_HBC") || !sourceExactGlobal;
#ifdef HAS_PRECOMPILED_BOOTSTRAP
    exactEvaluated = eval_bootstrap_script(handle,
                                           EXACT_GLOBAL_SRC,
                                           reinterpret_cast<const uint8_t*>(EXACT_GLOBAL_HBC),
                                           EXACT_GLOBAL_HBC_LEN,
                                           "<exact-global>",
                                           sourceExactGlobal || !exactGlobalHbc,
                                           exactGlobalHbc && !sourceExactGlobal);
#else
    exactEvaluated =
        eval_bootstrap_script(handle, EXACT_GLOBAL_SRC, nullptr, 0, "<exact-global>", true, false);
#endif
    if (!exactEvaluated) {
      throw std::runtime_error("Exact global script failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  }

  if (exactEvaluated) {
    handle->runtime->drainMicrotasks(-1);
  }
  if (tracing) {
    auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              start)
            .count();
    fprintf(stderr,
            "[startup]   %-28s %6lld us (%5.1f ms)\n",
            "exact_global",
            static_cast<long long>(elapsed),
            elapsed / 1000.0);
  }
}

// Version entries installed on process.versions via direct JSI property
// setting instead of evaluating a JS script at runtime.  The previous
// implementation evaluated ~70 lines of raw JS source every startup,
// which cost ~19ms due to JS parsing, Object.defineProperty overhead,
// and a require('events') call.  Direct C++ property setting is ~100x
// faster.
static void setVersionProp(facebook::jsi::Runtime& rt,
                           facebook::jsi::Object& obj,
                           const char* key, const char* value) {
  obj.setProperty(rt,
    facebook::jsi::PropNameID::forAscii(rt, key),
    facebook::jsi::String::createFromUtf8(rt, value));
}

void runFinalProcessVersionsFix(ExactHermesRuntime* handle) {
  if (!handle || !handle->runtime) {
    return;
  }

  auto& rt = *handle->runtime;
  try {
    auto processVal = rt.global().getProperty(rt, "process");
    if (!processVal.isObject()) return;
    auto processObj = processVal.asObject(rt);

    // Build versions object with direct property setting
    facebook::jsi::Object versions(rt);
    setVersionProp(rt, versions, "node", "24.13.1");
    setVersionProp(rt, versions, "acorn", "8.15.0");
    setVersionProp(rt, versions, "ada", "2.9.2");
    setVersionProp(rt, versions, "ares", "1.34.4");
    setVersionProp(rt, versions, "brotli", "1.1.0");
    setVersionProp(rt, versions, "cjs_module_lexer", "2.1.0");
    setVersionProp(rt, versions, "cldr", "46.0");
    setVersionProp(rt, versions, "icu", "76.1");
    setVersionProp(rt, versions, "llhttp", "9.3.0");
    setVersionProp(rt, versions, "modules", "131");
    setVersionProp(rt, versions, "napi", "9");
    setVersionProp(rt, versions, "nbytes", "0.1.1");
    setVersionProp(rt, versions, "ncrypto", "0.0.1");
    setVersionProp(rt, versions, "nghttp2", "1.64.0");
    setVersionProp(rt, versions, "openssl", "3.4.1");
    setVersionProp(rt, versions, "simdjson", "3.13.0");
    setVersionProp(rt, versions, "simdutf", "6.4.2");
    setVersionProp(rt, versions, "tz", "2025a");
    setVersionProp(rt, versions, "unicode", "16.0");
    setVersionProp(rt, versions, "uv", "1.50.0");
    setVersionProp(rt, versions, "uvwasi", "0.0.21");
    setVersionProp(rt, versions, "v8", "13.6.233.8-node.26");
    setVersionProp(rt, versions, "zlib", "1.3.1.1-motley-82a5fec");
    setVersionProp(rt, versions, "zstd", "1.5.7");
    setVersionProp(rt, versions, "hermes", "0.12.0");
    setVersionProp(rt, versions, "exact", "0.1.0");

    processObj.setProperty(rt, "versions", std::move(versions));

    // Set process.version
    processObj.setProperty(rt, "version",
      facebook::jsi::String::createFromUtf8(rt, "v24.13.1"));

    // Set process.release
    facebook::jsi::Object release(rt);
    // Preserve any existing release properties
    try {
      auto existingRelease = processObj.getProperty(rt, "release");
      if (existingRelease.isObject()) {
        auto existingObj = existingRelease.asObject(rt);
        auto names = existingObj.getPropertyNames(rt);
        auto len = names.size(rt);
        for (size_t i = 0; i < len; i++) {
          auto name = names.getValueAtIndex(rt, i).getString(rt).utf8(rt);
          if (name != "name" && name != "lts") {
            release.setProperty(rt,
              facebook::jsi::PropNameID::forUtf8(rt, name),
              existingObj.getProperty(rt,
                facebook::jsi::PropNameID::forUtf8(rt, name)));
          }
        }
      }
    } catch (...) {}
    setVersionProp(rt, release, "name", "node");
    setVersionProp(rt, release, "lts", "Krypton");
    processObj.setProperty(rt, "release", std::move(release));
  } catch (...) {
  }
}

void installWebStreamsPolyfill(ExactHermesRuntime* handle) {
  if (!handle || !handle->runtime) {
    return;
  }

  try {
#ifdef HAS_PRECOMPILED_BOOTSTRAP
    bool sourceWebStreamsPolyfill = env_flag_enabled("EX_WEB_STREAMS_POLYFILL_SOURCE");
    bool webStreamsPolyfillHbc =
        env_flag_enabled("EX_WEB_STREAMS_POLYFILL_HBC") || !sourceWebStreamsPolyfill;
    bool webStreamsPolyfillEvaluated = eval_bootstrap_script(
        handle,
        WEB_STREAMS_POLYFILL_SRC,
        reinterpret_cast<const uint8_t*>(WEB_STREAMS_POLYFILL_HBC),
        WEB_STREAMS_POLYFILL_HBC_LEN,
        "<web-streams-polyfill>",
        sourceWebStreamsPolyfill,
        webStreamsPolyfillHbc);
#else
    bool webStreamsPolyfillEvaluated = eval_bootstrap_script(
        handle, WEB_STREAMS_POLYFILL_SRC, nullptr, 0, "<web-streams-polyfill>", true, false);
#endif
    if (!webStreamsPolyfillEvaluated) {
      throw std::runtime_error("Web Streams polyfill failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, (std::string("Web Streams polyfill error: ") + err.getMessage()).c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, (std::string("Web Streams polyfill error: ") + err.what()).c_str());
  }
}
