#include "hermes_runtime_internal.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <limits.h>
#include <memory>
#include <string>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#if defined(__APPLE__)
#include <crt_externs.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach-o/dyld.h>
#endif

#if !defined(__APPLE__)
extern "C" char** environ;
#endif

#if __has_include("bootstrap_bytecode.h")
#include "bootstrap_bytecode.h"
#define HAS_PRECOMPILED_BOOTSTRAP 1
#endif

#if __has_include("bootstrap_source.h")
#include "bootstrap_source.h"
#endif

void installProcessSetup(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  const auto performanceStart = std::chrono::steady_clock::now();
  const double performanceTimeOriginMs =
      std::chrono::duration<double, std::milli>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  facebook::jsi::Object processObj(rt);
  if (rt.global().hasProperty(rt, "process")) {
    auto existing = rt.global().getProperty(rt, "process");
    if (existing.isObject()) {
      processObj = existing.asObject(rt);
    }
  }

  auto nextTickFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "nextTick"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        std::vector<facebook::jsi::Value> callbackArgs;
        if (count > 1) {
          callbackArgs.reserve(count - 1);
          for (size_t i = 1; i < count; i++) {
            callbackArgs.emplace_back(runtime, args[i]);
          }
        }
        handle->next_tick.push_back(
            NextTickEntry{currentPrincipalId(), std::move(callback), std::move(callbackArgs)});
        return facebook::jsi::Value::undefined();
      });
  processObj.setProperty(rt, "nextTick", std::move(nextTickFn));

  // When the shared runtime bundle is compiled in, skip eager env var
  // copying.  The shared bundle creates a Proxy-based process.env that
  // lazily reads from the native __exactGetEnv/__exactGetAllEnv host
  // functions, making this eager copy (~0.6ms for ~40 env vars) wasted.
  {
    auto hasShared = rt.global().getProperty(rt, "__exactHasSharedRuntimeBundle");
    bool skipEnvCopy = hasShared.isBool() && hasShared.getBool();
    if (!skipEnvCopy) {
      facebook::jsi::Object envObj(rt);
#if defined(__APPLE__)
      char** envp = *_NSGetEnviron();
#else
      char** envp = ::environ;
#endif
      if (envp) {
        for (char** ep = envp; *ep; ++ep) {
          std::string entry(*ep);
          auto eq = entry.find('=');
          if (eq != std::string::npos) {
            auto key = entry.substr(0, eq);
            auto val = entry.substr(eq + 1);
            envObj.setProperty(rt,
                               facebook::jsi::PropNameID::forUtf8(rt, key),
                               facebook::jsi::String::createFromUtf8(rt, val));
          }
        }
      }
      processObj.setProperty(rt, "env", std::move(envObj));
    }
  }

  std::string exact_platform = "unknown";
#if defined(__APPLE__)
  exact_platform = "darwin";
  processObj.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "darwin"));
#elif defined(EXACT_PLATFORM_ANDROID)
  exact_platform = "android";
  processObj.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "android"));
#elif defined(__linux__)
  exact_platform = "linux";
  processObj.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "linux"));
#elif defined(_WIN32)
  exact_platform = "win32";
  processObj.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "win32"));
#else
  processObj.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "unknown"));
#endif

  std::string exact_arch = "unknown";
#if defined(__aarch64__) || defined(_M_ARM64)
  exact_arch = "arm64";
  processObj.setProperty(rt, "arch", facebook::jsi::String::createFromUtf8(rt, "arm64"));
#elif defined(__x86_64__) || defined(_M_X64)
  exact_arch = "x64";
  processObj.setProperty(rt, "arch", facebook::jsi::String::createFromUtf8(rt, "x64"));
#else
  processObj.setProperty(rt, "arch", facebook::jsi::String::createFromUtf8(rt, "unknown"));
#endif
  rt.global().setProperty(
      rt, "__exactPlatform", facebook::jsi::String::createFromUtf8(rt, exact_platform));
  rt.global().setProperty(rt, "__exactArch", facebook::jsi::String::createFromUtf8(rt, exact_arch));

  auto performanceNowFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPerformanceNow"),
      0,
      [performanceStart](facebook::jsi::Runtime&,
                         const facebook::jsi::Value&,
                         const facebook::jsi::Value*,
                         size_t) -> facebook::jsi::Value {
        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - performanceStart);
        return facebook::jsi::Value(elapsed.count());
      });
  rt.global().setProperty(rt, "__exactPerformanceNow", std::move(performanceNowFn));

  auto performanceTimeOriginFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPerformanceTimeOrigin"),
      0,
      [performanceTimeOriginMs](facebook::jsi::Runtime&,
                                const facebook::jsi::Value&,
                                const facebook::jsi::Value*,
                                size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(performanceTimeOriginMs);
      });
  rt.global().setProperty(
      rt, "__exactPerformanceTimeOrigin", std::move(performanceTimeOriginFn));

  // process.version and process.versions are set by runFinalProcessVersionsFix()
  // after all globals are installed.  Skip the redundant setup here.

  {
    auto configId = facebook::jsi::PropNameID::forAscii(rt, "config");
    auto configValue = processObj.getProperty(rt, configId);
    if (configValue.isUndefined() || configValue.isNull()) {
      facebook::jsi::Object configObj(rt);
      facebook::jsi::Object targetDefaultsObj(rt);
      facebook::jsi::Object variablesObj(rt);
      configObj.setProperty(rt, "target_defaults", std::move(targetDefaultsObj));
      configObj.setProperty(rt, "variables", std::move(variablesObj));
      processObj.setProperty(rt, "config", std::move(configObj));
    }
  }

  auto cwdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "cwd"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char buffer[PATH_MAX];
        if (getcwd(buffer, sizeof(buffer))) {
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, buffer));
        }
        return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, "/"));
      });
  processObj.setProperty(rt, "cwd", std::move(cwdFn));

  auto chdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "chdir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "The first argument must be of type string");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        // @ref LLP 0013#policy — process-global cwd mutation is ambient host
        // authority; enforce the canonical process:cwd gate before chdir().
        if (!checkCapability("process:cwd")) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: process:cwd capability required");
        }
        if (chdir(path.c_str()) != 0) {
          throw facebook::jsi::JSError(
              runtime, "Failed to change directory: " + std::string(strerror(errno)));
        }
        return facebook::jsi::Value::undefined();
      });
  processObj.setProperty(rt, "chdir", std::move(chdirFn));

  auto exitFn = makeHardExitFn(rt);
  processObj.setProperty(rt, "exit", std::move(exitFn));
  try {
    auto markerBuffer = std::make_shared<facebook::jsi::StringBuffer>(
        R"EXACT_MARKER_JS(
(function() {
  if (typeof process !== 'object' || process === null) return;
  if (process.exit) {
    try { process.exit.__exactHostExit = true; } catch (_) {}
  }
})();
)EXACT_MARKER_JS");
    rt.evaluateJavaScript(markerBuffer, "<process-exit-marker>");
  } catch (...) {
  }

  auto makeStream = [&rt](int fd) {
    facebook::jsi::Object stream(rt);
    auto writeFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "write"),
        3,
        [fd](facebook::jsi::Runtime& runtime,
             const facebook::jsi::Value&,
             const facebook::jsi::Value* args,
             size_t count) -> facebook::jsi::Value {
          if (count > 0) {
            auto data = extractBytes(runtime, args[0]);
            size_t written = 0;
            while (written < data.size()) {
              ssize_t bytes =
                  ::write(fd, data.data() + written, static_cast<size_t>(data.size() - written));
              if (bytes < 0) {
                if (errno == EINTR) {
                  continue;
                }
                throw facebook::jsi::JSError(
                    runtime, std::string("write failed: ") + std::strerror(errno));
              }
              if (bytes == 0) {
                break;
              }
              written += static_cast<size_t>(bytes);
            }
          }
          for (size_t i = 1; i < count; i++) {
            if (args[i].isObject() && args[i].asObject(runtime).isFunction(runtime)) {
              args[i].asObject(runtime).asFunction(runtime).call(runtime);
              break;
            }
          }
          return facebook::jsi::Value(true);
        });
    stream.setProperty(rt, "write", std::move(writeFn));

    bool isTTY = ::isatty(fd) != 0;
    stream.setProperty(rt, "isTTY", facebook::jsi::Value(isTTY));
    stream.setProperty(rt, "fd", facebook::jsi::Value(fd));

    if (isTTY) {
      struct winsize ws;
      if (::ioctl(fd, TIOCGWINSZ, &ws) == 0) {
        stream.setProperty(rt, "columns", facebook::jsi::Value(static_cast<int>(ws.ws_col)));
        stream.setProperty(rt, "rows", facebook::jsi::Value(static_cast<int>(ws.ws_row)));
      }
    }

    stream.setProperty(rt, "writable", facebook::jsi::Value(true));
    stream.setProperty(rt, "writableEnded", facebook::jsi::Value(false));
    stream.setProperty(rt, "writableFinished", facebook::jsi::Value(false));
    stream.setProperty(rt, "writableHighWaterMark", facebook::jsi::Value(16384));
    stream.setProperty(rt, "writableLength", facebook::jsi::Value(0));
    stream.setProperty(rt, "writableObjectMode", facebook::jsi::Value(false));
    stream.setProperty(rt, "destroyed", facebook::jsi::Value(false));

    return stream;
  };
  processObj.setProperty(rt, "stdout", makeStream(1));
  processObj.setProperty(rt, "stderr", makeStream(2));

  {
    facebook::jsi::Object stdinObj(rt);
    stdinObj.setProperty(rt, "readable", facebook::jsi::Value(true));
    stdinObj.setProperty(rt, "isTTY", facebook::jsi::Value(::isatty(0) != 0));
    stdinObj.setProperty(rt, "fd", facebook::jsi::Value(0));
    auto stdinDestroyFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "destroy"),
        1,
        [](facebook::jsi::Runtime&,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) -> facebook::jsi::Value { return facebook::jsi::Value::undefined(); });
    stdinObj.setProperty(rt, "destroy", std::move(stdinDestroyFn));
    processObj.setProperty(rt, "stdin", std::move(stdinObj));
  }

  processObj.setProperty(rt, "pid", facebook::jsi::Value(static_cast<int>(getpid())));
  processObj.setProperty(rt, "ppid", facebook::jsi::Value(static_cast<int>(getppid())));

  {
    std::string execPathStr;
#if defined(__APPLE__)
    char execPathBuf[PATH_MAX];
    uint32_t epSize = sizeof(execPathBuf);
    if (_NSGetExecutablePath(execPathBuf, &epSize) == 0) {
      char realExecPath[PATH_MAX];
      if (realpath(execPathBuf, realExecPath)) {
        execPathStr = realExecPath;
      } else {
        execPathStr = execPathBuf;
      }
    }
#elif defined(__linux__)
    char execPathBuf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", execPathBuf, sizeof(execPathBuf) - 1);
    if (len > 0) {
      execPathBuf[len] = '\0';
      execPathStr = execPathBuf;
    }
#endif
    if (execPathStr.empty()) {
      execPathStr = "ibex";
    }
    processObj.setProperty(
        rt, "execPath", facebook::jsi::String::createFromUtf8(rt, execPathStr));
  }

  processObj.setProperty(rt, "title", facebook::jsi::String::createFromUtf8(rt, "ibex"));

  auto uptimeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "uptime"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(processUptimeSeconds());
      });
  processObj.setProperty(rt, "uptime", std::move(uptimeFn));

  {
    auto hrtimeFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "hrtime"),
        1,
        [](facebook::jsi::Runtime& runtime,
           const facebook::jsi::Value&,
           const facebook::jsi::Value* args,
           size_t count) -> facebook::jsi::Value {
          auto now = std::chrono::steady_clock::now().time_since_epoch();
          auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

          int64_t prevSec = 0, prevNs = 0;
          if (count > 0 && args[0].isObject()) {
            auto arr = args[0].asObject(runtime).asArray(runtime);
            auto sVal = arr.getValueAtIndex(runtime, 0);
            auto nVal = arr.getValueAtIndex(runtime, 1);
            if (sVal.isNumber()) prevSec = static_cast<int64_t>(sVal.asNumber());
            if (nVal.isNumber()) prevNs = static_cast<int64_t>(nVal.asNumber());
          }

          int64_t sec = ns / 1000000000LL;
          int64_t rem = ns % 1000000000LL;

          if (count > 0 && args[0].isObject()) {
            sec -= prevSec;
            rem -= prevNs;
            if (rem < 0) {
              sec -= 1;
              rem += 1000000000LL;
            }
          }

          auto result = facebook::jsi::Array(runtime, 2);
          result.setValueAtIndex(runtime, 0, facebook::jsi::Value(static_cast<double>(sec)));
          result.setValueAtIndex(runtime, 1, facebook::jsi::Value(static_cast<double>(rem)));
          return result;
        });

    auto hrtimeBigintFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "bigint"),
        0,
        [](facebook::jsi::Runtime& runtime,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) -> facebook::jsi::Value {
          auto now = std::chrono::steady_clock::now().time_since_epoch();
          auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
          auto nsStr = std::to_string(ns);
          auto bigintCtor = runtime.global().getPropertyAsFunction(runtime, "BigInt");
          return bigintCtor.call(runtime, facebook::jsi::String::createFromUtf8(runtime, nsStr));
        });

    hrtimeFn.setProperty(rt, "bigint", std::move(hrtimeBigintFn));
    processObj.setProperty(rt, "hrtime", std::move(hrtimeFn));
  }

  auto getResidentSetSize = []() -> size_t {
    size_t rss = 0;
#if defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &infoCount) ==
        KERN_SUCCESS) {
      rss = info.resident_size;
    }
#elif defined(__linux__)
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
      rss = static_cast<size_t>(usage.ru_maxrss) * 1024;
    }
#endif
    if (rss == 0) {
      rss = 1024 * 1024;
    }
    return rss;
  };

  auto heapInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetHeapInfo"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        bool includeExpensive = false;
        if (count > 0) {
          if (args[0].isBool()) {
            includeExpensive = args[0].getBool();
          } else if (args[0].isNumber()) {
            includeExpensive = args[0].asNumber() != 0;
          }
        }

        auto heapInfo = captureHeapInfo(handle, includeExpensive);
        return makeHeapInfoObject(runtime, heapInfo);
      });
  rt.global().setProperty(rt, "__exactGetHeapInfo", std::move(heapInfoFn));

  auto gcStatsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetGCStats"),
      0,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        if (!handle || !handle->runtime) {
          return facebook::jsi::Value::null();
        }

        try {
          auto stats = handle->runtime->instrumentation().getRecordedGCStats();
          return facebook::jsi::String::createFromUtf8(runtime, stats);
        } catch (...) {
          return facebook::jsi::Value::null();
        }
      });
  rt.global().setProperty(rt, "__exactGetGCStats", std::move(gcStatsFn));

  auto sourceCacheStatsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetSourceCacheStats"),
      0,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        facebook::jsi::Object result(runtime);
        if (!handle) {
          result.setProperty(runtime, "count", facebook::jsi::Value(0));
          result.setProperty(runtime, "totalBytes", facebook::jsi::Value(0));
          result.setProperty(runtime, "largestBytes", facebook::jsi::Value(0));
          return result;
        }

        size_t totalBytes = 0;
        size_t largestBytes = 0;
        std::string largestName;
        for (const auto& entry : handle->sources_by_name) {
          totalBytes += entry.second.size();
          if (entry.second.size() > largestBytes) {
            largestBytes = entry.second.size();
            largestName = entry.first;
          }
        }

        result.setProperty(
            runtime, "count", facebook::jsi::Value(static_cast<double>(handle->sources_by_name.size())));
        result.setProperty(
            runtime, "totalBytes", facebook::jsi::Value(static_cast<double>(totalBytes)));
        result.setProperty(
            runtime, "largestBytes", facebook::jsi::Value(static_cast<double>(largestBytes)));
        if (!largestName.empty()) {
          result.setProperty(
              runtime,
              "largestName",
              facebook::jsi::String::createFromUtf8(runtime, largestName));
        }
        return result;
      });
  rt.global().setProperty(rt, "__exactGetSourceCacheStats", std::move(sourceCacheStatsFn));

  auto rssFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetProcessRSS"),
      0,
      [getResidentSetSize](facebook::jsi::Runtime&,
                           const facebook::jsi::Value&,
                           const facebook::jsi::Value*,
                           size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<double>(getResidentSetSize()));
      });
  rt.global().setProperty(rt, "__exactGetProcessRSS", std::move(rssFn));

  auto memoryUsageFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "memoryUsage"),
      0,
      [handle, getResidentSetSize](facebook::jsi::Runtime& runtime,
                                   const facebook::jsi::Value&,
                                   const facebook::jsi::Value*,
                                   size_t) -> facebook::jsi::Value {
        auto heapInfo = captureHeapInfo(handle, false);
        int64_t heapTotal =
            lookupHeapInfoValue(heapInfo, {"hermes_heapSize", "heapSize"}, 0);
        int64_t heapUsed = lookupHeapInfoValue(
            heapInfo, {"hermes_allocatedBytes", "allocatedBytes"}, 0);
        int64_t external = lookupHeapInfoValue(
            heapInfo, {"hermes_externalBytes", "externalBytes"}, 0);
        int64_t arrayBuffers = lookupHeapInfoValue(
            heapInfo,
            {"hermes_arrayBufferBytes", "arrayBufferBytes", "hermes_arrayBuffers", "arrayBuffers"},
            0);

        facebook::jsi::Object result(runtime);
        size_t rss = getResidentSetSize();
        result.setProperty(runtime, "rss", facebook::jsi::Value(static_cast<double>(rss)));
        result.setProperty(runtime, "heapTotal", facebook::jsi::Value(static_cast<double>(heapTotal)));
        result.setProperty(runtime, "heapUsed", facebook::jsi::Value(static_cast<double>(heapUsed)));
        result.setProperty(runtime, "external", facebook::jsi::Value(static_cast<double>(external)));
        result.setProperty(
            runtime,
            "arrayBuffers",
            facebook::jsi::Value(static_cast<double>(arrayBuffers)));
        return result;
      });
  auto memoryUsageRssFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "rss"),
      0,
      [getResidentSetSize](facebook::jsi::Runtime&,
                           const facebook::jsi::Value&,
                           const facebook::jsi::Value*,
                           size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<double>(getResidentSetSize()));
      });
  memoryUsageFn.setProperty(rt, "rss", std::move(memoryUsageRssFn));
  processObj.setProperty(rt, "memoryUsage", std::move(memoryUsageFn));

  auto cpuUsageFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "cpuUsage"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
        int64_t userUsec =
            static_cast<int64_t>(usage.ru_utime.tv_sec) * 1000000LL + usage.ru_utime.tv_usec;
        int64_t sysUsec =
            static_cast<int64_t>(usage.ru_stime.tv_sec) * 1000000LL + usage.ru_stime.tv_usec;

        if (count > 0 && args[0].isObject()) {
          auto prev = args[0].asObject(runtime);
          auto prevUser = prev.getProperty(runtime, "user");
          auto prevSystem = prev.getProperty(runtime, "system");
          if (prevUser.isNumber()) {
            userUsec -= static_cast<int64_t>(prevUser.asNumber());
          }
          if (prevSystem.isNumber()) {
            sysUsec -= static_cast<int64_t>(prevSystem.asNumber());
          }
        }

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "user", facebook::jsi::Value(static_cast<double>(userUsec)));
        result.setProperty(runtime, "system", facebook::jsi::Value(static_cast<double>(sysUsec)));
        return result;
      });
  processObj.setProperty(rt, "cpuUsage", std::move(cpuUsageFn));

  auto getuidFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getuid"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<int>(getuid()));
      });
  processObj.setProperty(rt, "getuid", std::move(getuidFn));

  auto getgidFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getgid"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<int>(getgid()));
      });
  processObj.setProperty(rt, "getgid", std::move(getgidFn));

  auto getgroupsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getgroups"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        int ngroups = getgroups(0, nullptr);
        if (ngroups < 0) {
          return facebook::jsi::Value::undefined();
        }
        std::vector<gid_t> groups(ngroups);
        if (getgroups(ngroups, groups.data()) < 0) {
          return facebook::jsi::Value::undefined();
        }
        auto arr = facebook::jsi::Array(runtime, ngroups);
        for (int i = 0; i < ngroups; i++) {
          arr.setValueAtIndex(runtime, i, facebook::jsi::Value(static_cast<int>(groups[i])));
        }
        return std::move(arr);
      });
  processObj.setProperty(rt, "getgroups", std::move(getgroupsFn));

  auto killFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "kill"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "process.kill requires a pid");
        }
        pid_t targetPid = static_cast<pid_t>(args[0].asNumber());
        int sig = SIGTERM;
        if (count > 1) {
          if (args[1].isNumber()) {
            sig = static_cast<int>(args[1].asNumber());
          } else if (args[1].isString()) {
            auto sigName = args[1].asString(runtime).utf8(runtime);
            if (sigName == "SIGTERM") sig = SIGTERM;
            else if (sigName == "SIGKILL") sig = SIGKILL;
            else if (sigName == "SIGINT") sig = SIGINT;
            else if (sigName == "SIGHUP") sig = SIGHUP;
            else if (sigName == "SIGUSR1") sig = SIGUSR1;
            else if (sigName == "SIGUSR2") sig = SIGUSR2;
            else if (sigName == "SIGSTOP") sig = SIGSTOP;
            else if (sigName == "SIGCONT") sig = SIGCONT;
            else if (sigName == "SIGQUIT") sig = SIGQUIT;
            else {
              throw facebook::jsi::JSError(
                  runtime, std::string("Unknown signal: ") + sigName);
            }
          }
        }
        // @ref LLP 0013#policy — process.kill crosses the host process boundary;
        // require the canonical signal capability before any kill(2) syscall.
        if (!checkCapability("process:signal")) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: process:signal capability required");
        }
        int result = kill(targetPid, sig);
        if (result != 0) {
          throw facebook::jsi::JSError(runtime, std::string("kill failed: ") + strerror(errno));
        }
        return facebook::jsi::Value(true);
      });
  processObj.setProperty(rt, "kill", std::move(killFn));

  {
    facebook::jsi::Object releaseObj(rt);
    releaseObj.setProperty(rt, "name", facebook::jsi::String::createFromUtf8(rt, "node"));
    processObj.setProperty(rt, "release", std::move(releaseObj));
  }

  rt.global().setProperty(rt, "process", std::move(processObj));

  {
    static const char* streamEnhanceJS = STREAM_ENHANCE_SRC;
#ifdef HAS_PRECOMPILED_BOOTSTRAP
    g_streamEnhanceJS = streamEnhanceJS;
    handle->stream_enhance_loaded = false;
    ensureStreamEnhance(handle);
#else
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(streamEnhanceJS);
      rt.evaluateJavaScript(buffer, "<stream-enhance>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("Stream enhance error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("Stream enhance error: ") + err.what()).c_str());
    }
#endif
  }

  {
    static const char* streamStabilityPatchJS = R"JS(
(function() {
  'use strict';
  var p = globalThis.process;
  if (!p || p.__exactStreamStabilityPatched) return;

  function createWritableProxy(stream) {
    if (!stream) return stream;
    var writeFn = stream.write;
    var proxy = Object.create(stream);
    Object.defineProperty(proxy, 'write', {
      configurable: true,
      enumerable: true,
      get: function() { return writeFn; },
      set: function(value) { writeFn = value; },
    });
    return proxy;
  }

  function pinStream(name, stream, transform) {
    var value = transform ? transform(stream) : stream;
    if (name === 'stdout' || name === 'stderr') {
      if (value && value.writable === undefined) {
        value.writable = true;
      }
    }
    try {
      Object.defineProperty(p, name, {
        value: value,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch (_) {
      try {
        p[name] = value;
      } catch (_) {}
    }
  }

  pinStream('stdout', p.stdout, createWritableProxy);
  pinStream('stderr', p.stderr, createWritableProxy);
  pinStream('stdin', p.stdin);
  if (p.stdin && typeof p.stdin.destroy !== 'function') {
    p.stdin.destroy = function(err) {
      this.destroyed = true;
      this.readable = false;
      if (typeof this.emit === 'function') {
        if (err) this.emit('error', err);
        this.emit('close');
      }
      return this;
    };
  }
  p.__exactStreamStabilityPatched = true;
})();
)JS";
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(streamStabilityPatchJS);
      rt.evaluateJavaScript(buffer, "<stream-stability-patch>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(
          1, (std::string("Stream stability patch error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(
          1, (std::string("Stream stability patch error: ") + err.what()).c_str());
    }
  }
}
