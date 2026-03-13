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

  auto& rt = *handle->runtime;
  try {
    rt.global().setProperty(rt, "__exactSuppressRuntimeBanner", true);
  } catch (...) {
  }

  char* error = nullptr;
  bool evaluated = ex_hermes_eval(
                       handle,
                       reinterpret_cast<const uint8_t*>(SHARED_RUNTIME_BUNDLE_SRC),
                       std::strlen(SHARED_RUNTIME_BUNDLE_SRC),
                       "<shared-runtime-bundle>",
                       0,
                       &error) == 0;
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

  auto t0 = std::chrono::steady_clock::now();
  if (skip_module_loader_script) {
    if (startup_trace_enabled()) {
      fprintf(stderr,
              "[startup]   module_loader_script skipped (set "
              "EX_SKIP_STARTUP_MODULE_LOADER_SCRIPT=0 to re-enable)\n");
    }
  } else {
    bool source_module_loader = env_flag_enabled("EX_MODULE_LOADER_SOURCE");
    bool module_loader_hbc = env_flag_enabled("EX_MODULE_LOADER_HBC");
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

  bool sharedRuntimeInstalled = installSharedRuntimeBundle(handle);
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
    bool bootstrap_globals_hbc = env_flag_enabled("EX_BOOTSTRAP_GLOBALS_HBC");
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
    if (!eval_bootstrap_script(
            handle,
            g_streamEnhanceJS,
            reinterpret_cast<const uint8_t*>(STREAM_ENHANCE_HBC),
            STREAM_ENHANCE_HBC_LEN,
            "<stream-enhance>",
            true,
            env_flag_enabled("EX_STREAM_ENHANCE_HBC"))) {
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
    bool source_preferred = !env_flag_enabled("EX_WEB_CRYPTO_HBC");
    bool hbc_enabled = env_flag_enabled("EX_WEB_CRYPTO_HBC");
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
    bool source_preferred = !env_flag_enabled("EX_WEB_STORAGE_HBC");
    bool hbc_enabled = env_flag_enabled("EX_WEB_STORAGE_HBC");
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
    bool source_preferred = !env_flag_enabled("EX_FORM_DATA_HBC");
    bool hbc_enabled = env_flag_enabled("EX_FORM_DATA_HBC");
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
