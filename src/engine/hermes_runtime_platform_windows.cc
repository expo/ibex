#include "hermes_runtime_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
// @ref LLP 0003#the-platform-shims-map — Windows platform shims call Win32 and
// Winsock directly for process, DNS, TCP, and OS information.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

extern "C" void ex_host_free_string(char* value);

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

void ensureWinsock() {
  static std::once_flag once;
  std::call_once(once, []() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  });
}

std::string winsockErrorString(const char* prefix, int error = WSAGetLastError()) {
  char* message = nullptr;
  DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
      FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD len = FormatMessageA(
      flags,
      nullptr,
      static_cast<DWORD>(error),
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&message),
      0,
      nullptr);
  std::string result = prefix ? prefix : "Winsock";
  result += " failed";
  result += " (";
  result += std::to_string(error);
  result += ")";
  if (len && message) {
    result += ": ";
    result.append(message, len);
    while (!result.empty() &&
           (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
      result.pop_back();
    }
  }
  if (message) LocalFree(message);
  return result;
}

std::string networkEndpointCapability(const char* base, const std::string& host, int port) {
  return std::string(base) + ":" + host + ":" + std::to_string(port);
}

void requireNetworkCapability(
    facebook::jsi::Runtime& runtime,
    const std::string& capability,
    const char* description) {
  if (!checkCapability(capability)) {
    std::string message =
        std::string("Permission denied: ") + description + " capability required";
    throw facebook::jsi::JSError(runtime, message.c_str());
  }
}

bool setSocketNonBlocking(SOCKET socket) {
  u_long mode = 1;
  return ioctlsocket(socket, FIONBIO, &mode) == 0;
}

struct WindowsSocketEntry {
  SOCKET socket;
  uint64_t owner;
  std::string capability;
};

std::unordered_map<int, WindowsSocketEntry> g_windows_sockets;
int g_windows_next_socket_handle = 1;
std::mutex g_windows_sockets_mutex;

int registerWindowsSocket(
    SOCKET socket,
    const std::string& capability,
    uint64_t owner = currentPrincipalId()) {
  std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
  int handle = g_windows_next_socket_handle++;
  g_windows_sockets[handle] = WindowsSocketEntry{socket, owner, capability};
  return handle;
}

WindowsSocketEntry requireWindowsSocket(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation) {
  WindowsSocketEntry entry{};
  {
    std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
    auto it = g_windows_sockets.find(handle);
    if (it == g_windows_sockets.end()) {
      throw facebook::jsi::JSError(
          runtime, std::string(operation) + ": invalid handle");
    }
    entry = it->second;
  }
  if (!isAllowAll()) {
    if (entry.owner != currentPrincipalId()) {
      throw facebook::jsi::JSError(
          runtime, std::string(operation) + ": handle belongs to a different principal");
    }
    if (!entry.capability.empty() && !checkCapability(entry.capability)) {
      throw facebook::jsi::JSError(
          runtime, "Permission denied: network capability required");
    }
  }
  return entry;
}

bool tryWindowsSocket(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation,
    WindowsSocketEntry& entry) {
  try {
    entry = requireWindowsSocket(runtime, handle, operation);
    return true;
  } catch (const facebook::jsi::JSError&) {
    return false;
  }
}

SOCKET removeWindowsSocket(facebook::jsi::Runtime& runtime, int handle, const char* operation) {
  (void)requireWindowsSocket(runtime, handle, operation);
  std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
  auto it = g_windows_sockets.find(handle);
  if (it == g_windows_sockets.end()) return INVALID_SOCKET;
  SOCKET socket = it->second.socket;
  g_windows_sockets.erase(it);
  return socket;
}

std::vector<uint8_t> jsiValueToBytes(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (value.isString()) {
    std::string data = value.toString(runtime).utf8(runtime);
    return std::vector<uint8_t>(data.begin(), data.end());
  }
  if (value.isObject()) {
    auto obj = value.asObject(runtime);
    if (obj.isArrayBuffer(runtime)) {
      auto ab = obj.getArrayBuffer(runtime);
      const uint8_t* data = ab.data(runtime);
      return std::vector<uint8_t>(data, data + ab.size(runtime));
    }
    auto bufferProp = obj.getProperty(runtime, "buffer");
    auto byteLengthProp = obj.getProperty(runtime, "byteLength");
    auto byteOffsetProp = obj.getProperty(runtime, "byteOffset");
    if (bufferProp.isObject() &&
        bufferProp.asObject(runtime).isArrayBuffer(runtime) &&
        byteLengthProp.isNumber()) {
      auto ab = bufferProp.asObject(runtime).getArrayBuffer(runtime);
      size_t offset = byteOffsetProp.isNumber()
          ? static_cast<size_t>(byteOffsetProp.asNumber())
          : 0;
      size_t length = static_cast<size_t>(byteLengthProp.asNumber());
      if (offset > ab.size(runtime)) {
        throw facebook::jsi::JSError(runtime, "invalid byteOffset");
      }
      if (offset + length > ab.size(runtime)) {
        length = ab.size(runtime) - offset;
      }
      const uint8_t* data = ab.data(runtime) + offset;
      return std::vector<uint8_t>(data, data + length);
    }
  }
  std::string data = value.toString(runtime).utf8(runtime);
  return std::vector<uint8_t>(data.begin(), data.end());
}

std::string socketAddressJson(const sockaddr_storage& addr) {
  char ip[INET6_ADDRSTRLEN] = {};
  int port = 0;
  std::string family;
  if (addr.ss_family == AF_INET) {
    auto* sa = reinterpret_cast<const sockaddr_in*>(&addr);
    InetNtopA(AF_INET, const_cast<IN_ADDR*>(&sa->sin_addr), ip, sizeof(ip));
    port = ntohs(sa->sin_port);
    family = "IPv4";
  } else if (addr.ss_family == AF_INET6) {
    auto* sa = reinterpret_cast<const sockaddr_in6*>(&addr);
    InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&sa->sin6_addr), ip, sizeof(ip));
    port = ntohs(sa->sin6_port);
    family = "IPv6";
  } else {
    return std::string();
  }
  return "{\"address\":\"" + std::string(ip) + "\",\"port\":" + std::to_string(port) +
      ",\"family\":\"" + family + "\"}";
}

std::wstring utf8ToWide(const std::string& value) {
  if (value.empty()) return std::wstring();
  int needed = MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      value.data(),
      static_cast<int>(value.size()),
      nullptr,
      0);
  if (needed <= 0) {
    needed = MultiByteToWideChar(
        CP_ACP,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(
        CP_ACP,
        0,
        value.data(),
        static_cast<int>(value.size()),
        out.data(),
        needed);
    return out;
  }
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      value.data(),
      static_cast<int>(value.size()),
      out.data(),
      needed);
  return out;
}

std::string wideToUtf8(const std::wstring& value) {
  if (value.empty()) return std::string();
  int needed = WideCharToMultiByte(
      CP_UTF8,
      0,
      value.data(),
      static_cast<int>(value.size()),
      nullptr,
      0,
      nullptr,
      nullptr);
  if (needed <= 0) return std::string();
  std::string out(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(
      CP_UTF8,
      0,
      value.data(),
      static_cast<int>(value.size()),
      out.data(),
      needed,
      nullptr,
      nullptr);
  return out;
}

std::string jsonEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 16);
  for (unsigned char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

std::string parseJsonString(const std::string& value, size_t& pos) {
  std::string out;
  if (pos >= value.size() || value[pos] != '"') return out;
  ++pos;
  while (pos < value.size()) {
    char ch = value[pos++];
    if (ch == '"') break;
    if (ch == '\\' && pos < value.size()) {
      char escaped = value[pos++];
      switch (escaped) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: out.push_back(escaped); break;
      }
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

void skipJsonWhitespace(const std::string& value, size_t& pos) {
  while (pos < value.size() &&
         (value[pos] == ' ' || value[pos] == '\n' || value[pos] == '\r' || value[pos] == '\t')) {
    ++pos;
  }
}

bool parseJsonStringProperty(const std::string& json, const char* key, std::string& out) {
  std::string pattern = std::string("\"") + key + "\":";
  size_t pos = json.find(pattern);
  if (pos == std::string::npos) return false;
  pos += pattern.size();
  skipJsonWhitespace(json, pos);
  if (pos >= json.size() || json[pos] != '"') return false;
  out = parseJsonString(json, pos);
  return true;
}

uint32_t parseJsonUintProperty(const std::string& json, const char* key, uint32_t fallback) {
  std::string pattern = std::string("\"") + key + "\":";
  size_t pos = json.find(pattern);
  if (pos == std::string::npos) return fallback;
  pos += pattern.size();
  skipJsonWhitespace(json, pos);
  try {
    return static_cast<uint32_t>(std::stoul(json.substr(pos)));
  } catch (...) {
    return fallback;
  }
}

std::vector<std::string> parseEnvFromOptionsJson(const std::string& optsJson) {
  std::vector<std::string> env;
  size_t pos = optsJson.find("\"env\":{");
  if (pos == std::string::npos) return env;
  pos += 7;
  while (pos < optsJson.size()) {
    skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos >= optsJson.size() || optsJson[pos] == '}') break;
    if (optsJson[pos] != '"') break;
    std::string key = parseJsonString(optsJson, pos);
    skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] != ':') break;
    ++pos;
    skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == '"') {
      std::string val = parseJsonString(optsJson, pos);
      env.push_back(key + "=" + val);
    } else {
      while (pos < optsJson.size() && optsJson[pos] != ',' && optsJson[pos] != '}') ++pos;
    }
  }
  return env;
}

std::vector<std::string> parseArgsJson(const std::string& argsJson) {
  std::vector<std::string> args;
  size_t pos = 0;
  skipJsonWhitespace(argsJson, pos);
  if (pos >= argsJson.size() || argsJson[pos] != '[') return args;
  ++pos;
  while (pos < argsJson.size()) {
    skipJsonWhitespace(argsJson, pos);
    if (pos < argsJson.size() && argsJson[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos >= argsJson.size() || argsJson[pos] == ']') break;
    if (argsJson[pos] == '"') {
      args.push_back(parseJsonString(argsJson, pos));
    } else {
      while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') ++pos;
    }
  }
  return args;
}

std::wstring normalizeExecutablePath(std::string file) {
  for (char& ch : file) {
    if (ch == '/') ch = '\\';
  }
  return utf8ToWide(file);
}

std::wstring quoteWindowsArg(const std::wstring& arg) {
  if (arg.empty()) return L"\"\"";
  bool needsQuotes = false;
  for (wchar_t ch : arg) {
    if (ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\v' || ch == L'"') {
      needsQuotes = true;
      break;
    }
  }
  if (!needsQuotes) return arg;

  std::wstring out = L"\"";
  size_t backslashes = 0;
  for (wchar_t ch : arg) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    if (ch == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(ch);
      backslashes = 0;
      continue;
    }
    if (backslashes > 0) {
      out.append(backslashes, L'\\');
      backslashes = 0;
    }
    out.push_back(ch);
  }
  if (backslashes > 0) out.append(backslashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

std::wstring buildCommandLine(
    const std::string& file,
    const std::vector<std::string>& args,
    const std::string& argv0) {
  std::wstring commandLine = quoteWindowsArg(
      argv0.empty() ? normalizeExecutablePath(file) : utf8ToWide(argv0));
  for (const auto& arg : args) {
    commandLine.push_back(L' ');
    commandLine += quoteWindowsArg(utf8ToWide(arg));
  }
  return commandLine;
}

std::wstring buildEnvironmentBlock(std::vector<std::string> envEntries) {
  if (envEntries.empty()) return std::wstring();
  bool hasQuiet = false;
  for (const auto& entry : envEntries) {
    if (_strnicmp(entry.c_str(), "EXACT_QUIET=", 12) == 0) {
      hasQuiet = true;
      break;
    }
  }
  if (!hasQuiet) {
    envEntries.push_back("EXACT_QUIET=1");
  }
  std::sort(envEntries.begin(), envEntries.end(), [](const std::string& a, const std::string& b) {
    return _stricmp(a.c_str(), b.c_str()) < 0;
  });
  std::wstring block;
  for (const auto& entry : envEntries) {
    block += utf8ToWide(entry);
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

std::string windowsErrorMessage(DWORD error) {
  LPWSTR message = nullptr;
  DWORD len = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&message),
      0,
      nullptr);
  std::string out = "CreateProcessW failed: " + std::to_string(error);
  if (len > 0 && message) {
    out = wideToUtf8(std::wstring(message, message + len));
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
      out.pop_back();
    }
  }
  if (message) LocalFree(message);
  return out;
}

void readPipeToString(HANDLE readHandle, std::string* out, uint32_t maxBuffer) {
  char buffer[4096];
  DWORD bytesRead = 0;
  while (ReadFile(readHandle, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
    if (out->size() < maxBuffer) {
      size_t remaining = static_cast<size_t>(maxBuffer) - out->size();
      out->append(buffer, buffer + std::min<size_t>(remaining, bytesRead));
    }
  }
  CloseHandle(readHandle);
}

std::string spawnSyncWindowsJson(
    const std::string& file,
    const std::vector<std::string>& spawnArgs,
    const std::string& optsJson) {
  std::string cwd;
  std::string input;
  std::string argv0;
  std::string stdioMode = "pipe";
  parseJsonStringProperty(optsJson, "cwd", cwd);
  parseJsonStringProperty(optsJson, "input", input);
  parseJsonStringProperty(optsJson, "argv0", argv0);
  parseJsonStringProperty(optsJson, "stdio", stdioMode);
  uint32_t timeoutMs = parseJsonUintProperty(optsJson, "timeout", 0);
  uint32_t maxBuffer = parseJsonUintProperty(optsJson, "maxBuffer", 1024 * 1024);
  auto envEntries = parseEnvFromOptionsJson(optsJson);

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  const bool usePipe = stdioMode == "pipe";
  const bool useIgnore = stdioMode == "ignore";

  HANDLE childStdIn = nullptr;
  HANDLE childStdOut = nullptr;
  HANDLE childStdErr = nullptr;
  HANDLE parentStdInWrite = nullptr;
  HANDLE parentStdOutRead = nullptr;
  HANDLE parentStdErrRead = nullptr;
  HANDLE nullRead = nullptr;
  HANDLE nullWriteOut = nullptr;
  HANDLE nullWriteErr = nullptr;

  auto failJson = [&](const std::string& message) {
    if (parentStdInWrite && parentStdInWrite != INVALID_HANDLE_VALUE) CloseHandle(parentStdInWrite);
    if (parentStdOutRead && parentStdOutRead != INVALID_HANDLE_VALUE) CloseHandle(parentStdOutRead);
    if (parentStdErrRead && parentStdErrRead != INVALID_HANDLE_VALUE) CloseHandle(parentStdErrRead);
    if (childStdIn && childStdIn != INVALID_HANDLE_VALUE && childStdIn != GetStdHandle(STD_INPUT_HANDLE)) CloseHandle(childStdIn);
    if (childStdOut && childStdOut != INVALID_HANDLE_VALUE && childStdOut != GetStdHandle(STD_OUTPUT_HANDLE)) CloseHandle(childStdOut);
    if (childStdErr && childStdErr != INVALID_HANDLE_VALUE && childStdErr != GetStdHandle(STD_ERROR_HANDLE)) CloseHandle(childStdErr);
    if (nullRead && nullRead != INVALID_HANDLE_VALUE) CloseHandle(nullRead);
    if (nullWriteOut && nullWriteOut != INVALID_HANDLE_VALUE) CloseHandle(nullWriteOut);
    if (nullWriteErr && nullWriteErr != INVALID_HANDLE_VALUE) CloseHandle(nullWriteErr);
    return std::string("{\"stdout\":\"\",\"stderr\":\"\",\"status\":127,\"pid\":0,\"error\":\"") +
        jsonEscape(message) + "\"}";
  };

  if (usePipe) {
    HANDLE stdinRead = nullptr;
    HANDLE stdinWrite = nullptr;
    if (!CreatePipe(&stdinRead, &stdinWrite, &sa, 0)) {
      return failJson("Failed to create stdin pipe");
    }
    SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0);
    childStdIn = stdinRead;
    parentStdInWrite = stdinWrite;

    HANDLE stdoutRead = nullptr;
    HANDLE stdoutWrite = nullptr;
    if (!CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0)) {
      CloseHandle(stdinRead);
      CloseHandle(stdinWrite);
      return failJson("Failed to create stdout pipe");
    }
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
    parentStdOutRead = stdoutRead;
    childStdOut = stdoutWrite;

    HANDLE stderrRead = nullptr;
    HANDLE stderrWrite = nullptr;
    if (!CreatePipe(&stderrRead, &stderrWrite, &sa, 0)) {
      return failJson("Failed to create stderr pipe");
    }
    SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);
    parentStdErrRead = stderrRead;
    childStdErr = stderrWrite;
  } else if (useIgnore) {
    nullRead = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    nullWriteOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    nullWriteErr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullRead == INVALID_HANDLE_VALUE || nullWriteOut == INVALID_HANDLE_VALUE || nullWriteErr == INVALID_HANDLE_VALUE) {
      return failJson("Failed to open NUL for ignored stdio");
    }
    childStdIn = nullRead;
    childStdOut = nullWriteOut;
    childStdErr = nullWriteErr;
  } else {
    childStdIn = GetStdHandle(STD_INPUT_HANDLE);
    childStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    childStdErr = GetStdHandle(STD_ERROR_HANDLE);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = childStdIn;
  startup.hStdOutput = childStdOut;
  startup.hStdError = childStdErr;

  PROCESS_INFORMATION processInfo{};
  std::wstring commandLine = buildCommandLine(file, spawnArgs, argv0);
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');
  std::wstring wideCwd = cwd.empty() ? std::wstring() : utf8ToWide(cwd);
  std::wstring envBlock = buildEnvironmentBlock(envEntries);

  DWORD flags = CREATE_NO_WINDOW;
  if (!envBlock.empty()) flags |= CREATE_UNICODE_ENVIRONMENT;
  BOOL created = CreateProcessW(
      nullptr,
      mutableCommandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      flags,
      envBlock.empty() ? nullptr : const_cast<wchar_t*>(envBlock.data()),
      wideCwd.empty() ? nullptr : wideCwd.c_str(),
      &startup,
      &processInfo);

  if (childStdIn && childStdIn != GetStdHandle(STD_INPUT_HANDLE)) {
    CloseHandle(childStdIn);
    childStdIn = nullptr;
  }
  if (childStdOut && childStdOut != GetStdHandle(STD_OUTPUT_HANDLE)) {
    CloseHandle(childStdOut);
    childStdOut = nullptr;
  }
  if (childStdErr && childStdErr != GetStdHandle(STD_ERROR_HANDLE)) {
    CloseHandle(childStdErr);
    childStdErr = nullptr;
  }
  nullRead = nullptr;
  nullWriteOut = nullptr;
  nullWriteErr = nullptr;

  if (!created) {
    DWORD err = GetLastError();
    return failJson(windowsErrorMessage(err) + ": " + file);
  }

  if (parentStdInWrite) {
    if (!input.empty()) {
      DWORD written = 0;
      WriteFile(
          parentStdInWrite,
          input.data(),
          static_cast<DWORD>(input.size()),
          &written,
          nullptr);
    }
    CloseHandle(parentStdInWrite);
    parentStdInWrite = nullptr;
  }

  std::string stdoutStr;
  std::string stderrStr;
  std::thread stdoutThread;
  std::thread stderrThread;
  if (parentStdOutRead) {
    stdoutThread = std::thread(readPipeToString, parentStdOutRead, &stdoutStr, maxBuffer);
    parentStdOutRead = nullptr;
  }
  if (parentStdErrRead) {
    stderrThread = std::thread(readPipeToString, parentStdErrRead, &stderrStr, maxBuffer);
    parentStdErrRead = nullptr;
  }

  DWORD waitMs = timeoutMs == 0 ? INFINITE : timeoutMs;
  DWORD waitResult = WaitForSingleObject(processInfo.hProcess, waitMs);
  bool timedOut = waitResult == WAIT_TIMEOUT;
  if (timedOut) {
    TerminateProcess(processInfo.hProcess, 1);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
  }

  DWORD exitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);

  if (stdoutThread.joinable()) stdoutThread.join();
  if (stderrThread.joinable()) stderrThread.join();

  int status = timedOut ? -1 : static_cast<int>(exitCode);
  std::string result = "{\"stdout\":\"" + jsonEscape(stdoutStr)
      + "\",\"stderr\":\"" + jsonEscape(stderrStr)
      + "\",\"status\":" + std::to_string(status)
      + ",\"pid\":" + std::to_string(static_cast<int>(processInfo.dwProcessId));
  if (timedOut) {
    result += ",\"error\":\"Command timed out\"";
  }
  result += "}";
  return result;
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
  auto& rt = *handle->runtime;
  auto dnsLookupFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsLookup"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsLookup: hostname required");
        }
        ensureWinsock();
        std::string hostname = args[0].toString(runtime).utf8(runtime);
        int family = 0;
        if (count > 1 && args[1].isNumber()) {
          family = static_cast<int>(args[1].asNumber());
        }
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = family == 4 ? AF_INET : (family == 6 ? AF_INET6 : AF_UNSPEC);
        addrinfo* result = nullptr;
        int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        if (rc != 0 || !result) {
          if (result) freeaddrinfo(result);
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactDnsLookup", rc));
        }
        std::ostringstream json;
        json << '[';
        bool first = true;
        for (addrinfo* item = result; item; item = item->ai_next) {
          sockaddr_storage storage{};
          if (item->ai_addrlen > sizeof(storage)) continue;
          std::memcpy(&storage, item->ai_addr, item->ai_addrlen);
          std::string address = socketAddressJson(storage);
          if (address.empty()) continue;
          size_t portPos = address.find(",\"port\":");
          if (portPos != std::string::npos) {
            size_t familyPos = address.find(",\"family\":", portPos + 1);
            if (familyPos != std::string::npos) {
              address.erase(portPos, familyPos - portPos);
            }
          }
          if (!first) json << ',';
          first = false;
          json << address;
        }
        freeaddrinfo(result);
        json << ']';
        return facebook::jsi::String::createFromUtf8(runtime, json.str());
      });
  rt.global().setProperty(rt, "__exactDnsLookup", std::move(dnsLookupFn));

  auto dnsResolveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsResolve"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsResolve: hostname required");
        }
        ensureWinsock();
        std::string hostname = args[0].toString(runtime).utf8(runtime);
        std::string rrtype = "A";
        if (count > 1 && args[1].isString()) {
          rrtype = args[1].toString(runtime).utf8(runtime);
        }
        int family = rrtype == "AAAA" ? 6 : 4;
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = family == 6 ? AF_INET6 : AF_INET;
        addrinfo* result = nullptr;
        int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        if (rc != 0 || !result) {
          if (result) freeaddrinfo(result);
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactDnsResolve", rc));
        }
        std::ostringstream json;
        json << '[';
        bool first = true;
        for (addrinfo* item = result; item; item = item->ai_next) {
          sockaddr_storage storage{};
          if (item->ai_addrlen > sizeof(storage)) continue;
          std::memcpy(&storage, item->ai_addr, item->ai_addrlen);
          char ip[INET6_ADDRSTRLEN] = {};
          bool ok = false;
          if (storage.ss_family == AF_INET) {
            auto* sa = reinterpret_cast<sockaddr_in*>(&storage);
            ok = InetNtopA(AF_INET, &sa->sin_addr, ip, sizeof(ip)) != nullptr;
          } else if (storage.ss_family == AF_INET6) {
            auto* sa = reinterpret_cast<sockaddr_in6*>(&storage);
            ok = InetNtopA(AF_INET6, &sa->sin6_addr, ip, sizeof(ip)) != nullptr;
          }
          if (!ok) continue;
          std::string escaped;
          appendEscapedJsonText(escaped, reinterpret_cast<const uint8_t*>(ip), std::strlen(ip));
          if (!first) json << ',';
          first = false;
          json << escaped;
        }
        freeaddrinfo(result);
        json << ']';
        return facebook::jsi::String::createFromUtf8(runtime, json.str());
      });
  rt.global().setProperty(rt, "__exactDnsResolve", std::move(dnsResolveFn));

  installUnsupportedGlobal(handle, "__exactDnsReverse");
}

void installChildProcessHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto spawnSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawnSync: file path required");
        }
        std::string file = args[0].toString(runtime).utf8(runtime);
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          spawnArgs = parseArgsJson(args[1].toString(runtime).utf8(runtime));
        }
        std::string optsJson = "{}";
        if (count > 2 && args[2].isString()) {
          optsJson = args[2].toString(runtime).utf8(runtime);
        }
        std::string resultJson = spawnSyncWindowsJson(file, spawnArgs, optsJson);
        return facebook::jsi::String::createFromUtf8(runtime, resultJson);
      });
  rt.global().setProperty(rt, "__exactSpawnSync", std::move(spawnSyncFn));
  installUnsupportedModule(handle, {
      "__exactSpawn",
      "__exactSpawnRead",
      "__exactSpawnWrite",
      "__exactSpawnKill",
      "__exactSpawnCloseStdin",
      "__exactSpawnPoll",
      "__exactSpawnGetFd",
      "__exactSpawnSendMsg",
      "__exactSpawnRecvMsg"});
}

void installNetHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  ensureWinsock();

  auto stringToUtf8BytesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStringToUtf8Bytes"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactStringToUtf8Bytes: string required");
        }
        std::string data = args[0].toString(runtime).utf8(runtime);
        return makeUint8Array(runtime, std::vector<uint8_t>(data.begin(), data.end()));
      });
  rt.global().setProperty(rt, "__exactStringToUtf8Bytes", std::move(stringToUtf8BytesFn));

  auto tcpConnectFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpConnect"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpConnect: host and port required");
        }
        ensureWinsock();
        std::string host = args[0].toString(runtime).utf8(runtime);
        int port = static_cast<int>(args[1].asNumber());
        std::string connectCapability = networkEndpointCapability("network:connect", host, port);
        requireNetworkCapability(runtime, connectCapability, "network:connect");
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* result = nullptr;
        std::string portString = std::to_string(port);
        int rc = getaddrinfo(host.c_str(), portString.c_str(), &hints, &result);
        if (rc != 0 || !result) {
          if (result) freeaddrinfo(result);
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpConnect getaddrinfo", rc));
        }
        SOCKET socket = INVALID_SOCKET;
        int lastError = 0;
        for (addrinfo* item = result; item; item = item->ai_next) {
          socket = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
          if (socket == INVALID_SOCKET) {
            lastError = WSAGetLastError();
            continue;
          }
          if (::connect(socket, item->ai_addr, static_cast<int>(item->ai_addrlen)) == 0) {
            break;
          }
          lastError = WSAGetLastError();
          closesocket(socket);
          socket = INVALID_SOCKET;
        }
        freeaddrinfo(result);
        if (socket == INVALID_SOCKET) {
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpConnect", lastError));
        }
        setSocketNonBlocking(socket);
        return facebook::jsi::Value(registerWindowsSocket(socket, connectCapability));
      });
  rt.global().setProperty(rt, "__exactTcpConnect", std::move(tcpConnectFn));

  auto tcpReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpRead: handle required");
        }
        SOCKET socket = requireWindowsSocket(
            runtime, static_cast<int>(args[0].asNumber()), "__exactTcpRead").socket;
        int maxBytes = 65536;
        if (count > 1 && args[1].isNumber()) {
          maxBytes = std::max(1, static_cast<int>(args[1].asNumber()));
        }
        std::vector<uint8_t> buffer(static_cast<size_t>(maxBytes));
        int read = recv(socket, reinterpret_cast<char*>(buffer.data()), maxBytes, 0);
        if (read > 0) {
          buffer.resize(static_cast<size_t>(read));
          return makeUint8Array(runtime, std::move(buffer));
        }
        if (read == 0) {
          return facebook::jsi::Value::null();
        }
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpRead", error));
      });
  rt.global().setProperty(rt, "__exactTcpRead", std::move(tcpReadFn));

  auto tcpWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpWrite"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpWrite: handle and data required");
        }
        SOCKET socket = requireWindowsSocket(
            runtime, static_cast<int>(args[0].asNumber()), "__exactTcpWrite").socket;
        std::vector<uint8_t> data = jsiValueToBytes(runtime, args[1]);
        if (data.empty()) return facebook::jsi::Value(0);
        int written = send(
            socket,
            reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()),
            0);
        if (written < 0) {
          int error = WSAGetLastError();
          if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
            return facebook::jsi::Value(0);
          }
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpWrite", error));
        }
        return facebook::jsi::Value(written);
      });
  rt.global().setProperty(rt, "__exactTcpWrite", std::move(tcpWriteFn));

  auto tcpCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpClose: handle required");
        }
        SOCKET socket =
            removeWindowsSocket(runtime, static_cast<int>(args[0].asNumber()), "__exactTcpClose");
        if (socket != INVALID_SOCKET) {
          closesocket(socket);
        }
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactTcpClose", std::move(tcpCloseFn));

  auto tcpShutdownFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpShutdown"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpShutdown: handle required");
        }
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpShutdown", entry)) {
          return facebook::jsi::Value(0);
        }
        SOCKET socket = entry.socket;
        int how = SD_SEND;
        if (count > 1 && args[1].isNumber()) {
          int value = static_cast<int>(args[1].asNumber());
          if (value == 0) how = SD_RECEIVE;
          if (value == 2) how = SD_BOTH;
        }
        shutdown(socket, how);
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactTcpShutdown", std::move(tcpShutdownFn));

  auto tcpResetFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpReset"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpReset: handle required");
        }
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpReset", entry)) {
          return facebook::jsi::Value(0);
        }
        SOCKET socket = entry.socket;
        linger option{};
        option.l_onoff = 1;
        option.l_linger = 0;
        setsockopt(socket, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&option), sizeof(option));
        shutdown(socket, SD_BOTH);
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactTcpReset", std::move(tcpResetFn));

  auto tcpSetNoDelayFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetNoDelay"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpSetNoDelay: handle required");
        }
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpSetNoDelay", entry)) {
          return facebook::jsi::Value(-1);
        }
        SOCKET socket = entry.socket;
        BOOL flag = !(count > 1 && args[1].isNumber() && args[1].asNumber() == 0);
        setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag));
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactTcpSetNoDelay", std::move(tcpSetNoDelayFn));

  auto tcpSetKeepAliveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetKeepAlive"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpSetKeepAlive: handle required");
        }
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpSetKeepAlive", entry)) {
          return facebook::jsi::Value(-1);
        }
        SOCKET socket = entry.socket;
        BOOL flag = !(count > 1 && args[1].isNumber() && args[1].asNumber() == 0);
        setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&flag), sizeof(flag));
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactTcpSetKeepAlive", std::move(tcpSetKeepAliveFn));

  auto tcpListenFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpListen"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        ensureWinsock();
        std::string host = "0.0.0.0";
        if (count > 0 && args[0].isString()) host = args[0].toString(runtime).utf8(runtime);
        int port = count > 1 && args[1].isNumber() ? static_cast<int>(args[1].asNumber()) : 0;
        int backlog = count > 2 && args[2].isNumber() ? static_cast<int>(args[2].asNumber()) : 128;
        int ipv6Only = count > 3 && args[3].isNumber() ? static_cast<int>(args[3].asNumber()) : 0;
        std::string listenCapability = networkEndpointCapability("network:listen", host, port);
        requireNetworkCapability(runtime, listenCapability, "network:listen");

        addrinfo hints{};
        hints.ai_family = (ipv6Only || host.find(':') != std::string::npos) ? AF_INET6 : AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;
        std::string portString = std::to_string(port);
        const char* node = (host == "0.0.0.0" || host.empty()) ? nullptr : host.c_str();
        addrinfo* result = nullptr;
        int rc = getaddrinfo(node, portString.c_str(), &hints, &result);
        if (rc != 0 || !result) {
          if (result) freeaddrinfo(result);
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpListen getaddrinfo", rc));
        }
        SOCKET socket = INVALID_SOCKET;
        int lastError = 0;
        for (addrinfo* item = result; item; item = item->ai_next) {
          socket = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
          if (socket == INVALID_SOCKET) {
            lastError = WSAGetLastError();
            continue;
          }
          BOOL reuse = TRUE;
          setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
          if (item->ai_family == AF_INET6 && ipv6Only) {
            DWORD only = 1;
            setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&only), sizeof(only));
          }
          if (bind(socket, item->ai_addr, static_cast<int>(item->ai_addrlen)) == 0 &&
              listen(socket, backlog) == 0) {
            break;
          }
          lastError = WSAGetLastError();
          closesocket(socket);
          socket = INVALID_SOCKET;
        }
        freeaddrinfo(result);
        if (socket == INVALID_SOCKET) {
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpListen", lastError));
        }
        setSocketNonBlocking(socket);
        return facebook::jsi::Value(registerWindowsSocket(socket, listenCapability));
      });
  rt.global().setProperty(rt, "__exactTcpListen", std::move(tcpListenFn));

  auto tcpAcceptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpAccept"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTcpAccept: handle required");
        }
        auto serverEntry = requireWindowsSocket(
            runtime, static_cast<int>(args[0].asNumber()), "__exactTcpAccept");
        SOCKET server = serverEntry.socket;
        sockaddr_storage clientAddr{};
        int clientLen = sizeof(clientAddr);
        SOCKET client = accept(server, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (client == INVALID_SOCKET) {
          int error = WSAGetLastError();
          if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
            return facebook::jsi::Value(-1);
          }
          throw facebook::jsi::JSError(runtime, winsockErrorString("__exactTcpAccept", error));
        }
        setSocketNonBlocking(client);
        return facebook::jsi::Value(
            registerWindowsSocket(client, serverEntry.capability, serverEntry.owner));
      });
  rt.global().setProperty(rt, "__exactTcpAccept", std::move(tcpAcceptFn));

  auto tcpLocalAddrFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpLocalAddr"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpLocalAddr", entry)) {
          return facebook::jsi::Value::null();
        }
        SOCKET socket = entry.socket;
        sockaddr_storage addr{};
        int addrLen = sizeof(addr);
        if (getsockname(socket, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) return facebook::jsi::Value::null();
        std::string json = socketAddressJson(addr);
        if (json.empty()) return facebook::jsi::Value::null();
        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactTcpLocalAddr", std::move(tcpLocalAddrFn));

  auto tcpRemoteAddrFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRemoteAddr"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
        WindowsSocketEntry entry{};
        if (!tryWindowsSocket(
                runtime, static_cast<int>(args[0].asNumber()), "__exactTcpRemoteAddr", entry)) {
          return facebook::jsi::Value::null();
        }
        SOCKET socket = entry.socket;
        sockaddr_storage addr{};
        int addrLen = sizeof(addr);
        if (getpeername(socket, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) return facebook::jsi::Value::null();
        std::string json = socketAddressJson(addr);
        if (json.empty()) return facebook::jsi::Value::null();
        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactTcpRemoteAddr", std::move(tcpRemoteAddrFn));

  auto tcpFromFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpFromFd"),
      1,
      [](facebook::jsi::Runtime&, const facebook::jsi::Value&,
         const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactTcpFromFd", std::move(tcpFromFdFn));

  auto tcpGetFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTcpGetFd"),
      1,
      [](facebook::jsi::Runtime&, const facebook::jsi::Value&,
         const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactTcpGetFd", std::move(tcpGetFdFn));

  installUnsupportedModule(handle, {
      "__exactUnixConnect",
      "__exactUnixListen",
      "__exactUnixAccept",
      "__exactUdpSocket",
      "__exactUdpBind",
      "__exactUdpSend",
      "__exactUdpRecv",
      "__exactUdpClose",
      "__exactUdpAddress"});
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
