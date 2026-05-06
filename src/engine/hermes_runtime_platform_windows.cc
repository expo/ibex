#include "hermes_runtime_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdlib>
#include <initializer_list>
#include <string>
#include <vector>

namespace {

std::string getenvString(const char* key) {
  char* value = nullptr;
  size_t len = 0;
  if (_dupenv_s(&value, &len, key) != 0 || !value) {
    return std::string();
  }
  std::string result(value, len > 0 ? len - 1 : 0);
  free(value);
  return result;
}

facebook::jsi::Function unsupportedFunction(facebook::jsi::Runtime& rt, const char* name) {
  return facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, name),
      0,
      [name](facebook::jsi::Runtime& runtime,
             const facebook::jsi::Value&,
             const facebook::jsi::Value*,
             size_t) -> facebook::jsi::Value {
        throw facebook::jsi::JSError(runtime, std::string(name) + " is not available on Windows yet");
      });
}

void installUnsupportedGlobal(ExactHermesRuntime* handle, const char* name) {
  auto& rt = *handle->runtime;
  rt.global().setProperty(rt, name, unsupportedFunction(rt, name));
}

void installUnsupportedModule(ExactHermesRuntime* handle, std::initializer_list<const char*> names) {
  for (const char* name : names) {
    installUnsupportedGlobal(handle, name);
  }
}

} // namespace

void installOsInfoGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto hostnameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetHostname"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD len = sizeof(name);
        if (!GetComputerNameA(name, &len)) {
          return facebook::jsi::String::createFromUtf8(runtime, "localhost");
        }
        return facebook::jsi::String::createFromUtf8(runtime, name);
      });
  rt.global().setProperty(rt, "__exactGetHostname", std::move(hostnameFn));

  auto cpuCountFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetCpuCount"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return facebook::jsi::Value(static_cast<double>(info.dwNumberOfProcessors));
      });
  rt.global().setProperty(rt, "__exactGetCpuCount", std::move(cpuCountFn));

  auto totalMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetTotalMem"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        if (!GlobalMemoryStatusEx(&status)) return facebook::jsi::Value(0.0);
        return facebook::jsi::Value(static_cast<double>(status.ullTotalPhys));
      });
  rt.global().setProperty(rt, "__exactGetTotalMem", std::move(totalMemFn));

  auto freeMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetFreeMem"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        if (!GlobalMemoryStatusEx(&status)) return facebook::jsi::Value(0.0);
        return facebook::jsi::Value(static_cast<double>(status.ullAvailPhys));
      });
  rt.global().setProperty(rt, "__exactGetFreeMem", std::move(freeMemFn));

  auto uptimeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUptime"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<double>(GetTickCount64()) / 1000.0);
      });
  rt.global().setProperty(rt, "__exactGetUptime", std::move(uptimeFn));

  auto userInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUserInfo"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        facebook::jsi::Object info(runtime);
        auto username = getenvString("USERNAME");
        auto homedir = getenvString("USERPROFILE");
        info.setProperty(runtime, "uid", facebook::jsi::Value(-1.0));
        info.setProperty(runtime, "gid", facebook::jsi::Value(-1.0));
        info.setProperty(runtime, "username", facebook::jsi::String::createFromUtf8(runtime, username));
        info.setProperty(runtime, "homedir", facebook::jsi::String::createFromUtf8(runtime, homedir));
        info.setProperty(runtime, "shell", facebook::jsi::Value::null());
        return info;
      });
  rt.global().setProperty(rt, "__exactGetUserInfo", std::move(userInfoFn));

  auto loadAvgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetLoadAvg"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        facebook::jsi::Array result(runtime, 3);
        result.setValueAtIndex(runtime, 0, facebook::jsi::Value(0.0));
        result.setValueAtIndex(runtime, 1, facebook::jsi::Value(0.0));
        result.setValueAtIndex(runtime, 2, facebook::jsi::Value(0.0));
        return result;
      });
  rt.global().setProperty(rt, "__exactGetLoadAvg", std::move(loadAvgFn));

  auto networkInterfacesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetNetworkInterfaces"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Object(runtime);
      });
  rt.global().setProperty(rt, "__exactGetNetworkInterfaces", std::move(networkInterfacesFn));
}

void installProcessSetup(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  facebook::jsi::Object process(rt);
  if (rt.global().hasProperty(rt, "process")) {
    auto existing = rt.global().getProperty(rt, "process");
    if (existing.isObject()) {
      process = existing.asObject(rt);
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
        std::vector<facebook::jsi::Value> callback_args;
        for (size_t i = 1; i < count; i++) {
          callback_args.emplace_back(runtime, args[i]);
        }
        handle->next_tick.push_back(NextTickEntry{std::move(callback), std::move(callback_args)});
        return facebook::jsi::Value::undefined();
      });
  process.setProperty(rt, "nextTick", std::move(nextTickFn));
  process.setProperty(rt, "platform", facebook::jsi::String::createFromUtf8(rt, "win32"));
#if defined(_M_ARM64)
  process.setProperty(rt, "arch", facebook::jsi::String::createFromUtf8(rt, "arm64"));
  rt.global().setProperty(rt, "__exactArch", facebook::jsi::String::createFromUtf8(rt, "arm64"));
#else
  process.setProperty(rt, "arch", facebook::jsi::String::createFromUtf8(rt, "x64"));
  rt.global().setProperty(rt, "__exactArch", facebook::jsi::String::createFromUtf8(rt, "x64"));
#endif
  if (!process.hasProperty(rt, "env")) {
    process.setProperty(rt, "env", facebook::jsi::Object(rt));
  }
  rt.global().setProperty(rt, "process", std::move(process));
  rt.global().setProperty(rt, "__exactPlatform", facebook::jsi::String::createFromUtf8(rt, "win32"));
}

void installDnsHostFunctions(ExactHermesRuntime* handle) {
  installUnsupportedModule(handle, {"__exactDnsLookup", "__exactDnsResolve", "__exactDnsReverse"});
}

void installChildProcessHostFunctions(ExactHermesRuntime* handle) {
  installUnsupportedModule(handle, {"__exactSpawn", "__exactSpawnRead", "__exactSpawnWrite", "__exactSpawnKill"});
}

void installNetHostFunctions(ExactHermesRuntime* handle) {
  installUnsupportedModule(handle, {"__exactTcpConnect", "__exactTcpRead", "__exactTcpWrite"});
}

void installHttpHostFunctions(ExactHermesRuntime* handle) {
  installUnsupportedModule(handle, {"__exactHttpServe", "__exactHttpWait", "__exactHttpRespond"});
}

extern "C" int ex_hermes_debugger_enable(ExactHermesRuntime* runtime) {
  (void)runtime;
  return 0;
}

extern "C" char* ex_hermes_debugger_get_scripts(ExactHermesRuntime* runtime) {
  (void)runtime;
  return copyMallocString("[]");
}

extern "C" char* ex_hermes_debugger_get_script_source(
    ExactHermesRuntime* runtime,
    uint32_t script_id) {
  (void)runtime;
  (void)script_id;
  return nullptr;
}

extern "C" char* ex_hermes_debugger_set_breakpoint(
    ExactHermesRuntime* runtime,
    uint32_t script_id,
    uint32_t line_number,
    uint32_t column_number,
    const char* condition) {
  (void)runtime;
  (void)script_id;
  (void)line_number;
  (void)column_number;
  (void)condition;
  return nullptr;
}

extern "C" void ex_hermes_debugger_remove_breakpoint(
    ExactHermesRuntime* runtime,
    uint64_t breakpoint_id) {
  (void)runtime;
  (void)breakpoint_id;
}

extern "C" void ex_hermes_debugger_pause(ExactHermesRuntime* runtime) {
  (void)runtime;
}

extern "C" void ex_hermes_debugger_resume(ExactHermesRuntime* runtime, int command) {
  (void)runtime;
  (void)command;
}

extern "C" char* ex_hermes_debugger_next_event(ExactHermesRuntime* runtime) {
  (void)runtime;
  return nullptr;
}

extern "C" char* ex_hermes_debugger_eval(
    ExactHermesRuntime* runtime,
    const char* expression,
    uint32_t frame_index) {
  (void)runtime;
  (void)expression;
  (void)frame_index;
  return nullptr;
}
