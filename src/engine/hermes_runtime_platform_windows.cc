#include "hermes_runtime_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
// @ref LLP 0003#the-platform-shims-map — Windows platform shims call Win32 and
// Winsock directly for process, DNS, TCP, and OS information.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

extern "C" void ex_host_free_string(char* value);
extern "C" uint64_t ex_hermes_current_runtime_nonce();

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
  return std::string(base) + ":" + formatNetworkEndpoint(host, port);
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
  uint64_t runtimeNonce;
  uint64_t owner;
  std::string capability;
};

std::unordered_map<int, WindowsSocketEntry> g_windows_sockets;
int g_windows_next_socket_handle = 1;
std::mutex g_windows_sockets_mutex;

struct WindowsNetOwnerStampEntry {
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
};

std::unordered_map<uint64_t, WindowsNetOwnerStampEntry> g_windows_net_owner_stamps;
std::mutex g_windows_net_owner_stamp_mutex;

uint64_t windowsNetOwnerStampForCurrentPrincipal() {
  const uint64_t runtimeNonce = exactCurrentRuntimeNonce();
  const uint64_t owner = currentPrincipalId();
  if (runtimeNonce == 0) return 0;
  std::lock_guard<std::mutex> lock(g_windows_net_owner_stamp_mutex);
  for (const auto& item : g_windows_net_owner_stamps) {
    if (item.second.runtimeNonce == runtimeNonce && item.second.owner == owner) {
      return item.first;
    }
  }
  static std::random_device randomDevice;
  constexpr uint64_t kJsSafeMask = (uint64_t{1} << 53) - 1;
  for (size_t attempt = 0; attempt < 128; ++attempt) {
    uint64_t stamp =
        ((static_cast<uint64_t>(randomDevice()) << 32) ^
         static_cast<uint64_t>(randomDevice())) &
        kJsSafeMask;
    if (stamp == 0 || g_windows_net_owner_stamps.count(stamp) != 0) continue;
    g_windows_net_owner_stamps.emplace(
        stamp, WindowsNetOwnerStampEntry{runtimeNonce, owner});
    return stamp;
  }
  return 0;
}

void requireWindowsNetOwnerStamp(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: numeric stamp required");
  }
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 1.0 || number > kMaxSafeInteger ||
      std::floor(number) != number) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: invalid stamp");
  }
  const uint64_t stamp = static_cast<uint64_t>(number);
  std::lock_guard<std::mutex> lock(g_windows_net_owner_stamp_mutex);
  auto item = g_windows_net_owner_stamps.find(stamp);
  if (item == g_windows_net_owner_stamps.end() ||
      item->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      item->second.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, "__exactNetOwner: stamp belongs to another runtime or principal");
  }
}

int requireWindowsNetOwnerSocketHandle(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(
        runtime, "__exactNetOwner: numeric handle required");
  }
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 1.0 ||
      number > kMaxSafeInteger || std::floor(number) != number ||
      number > static_cast<double>(std::numeric_limits<int>::max())) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: invalid handle");
  }
  return static_cast<int>(number);
}

int registerWindowsSocket(
    SOCKET socket,
    const std::string& capability,
    uint64_t owner = currentPrincipalId()) {
  std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
  int handle = g_windows_next_socket_handle++;
  g_windows_sockets[handle] = WindowsSocketEntry{
      socket, exactCurrentRuntimeNonce(), owner, capability};
  return handle;
}

WindowsSocketEntry requireWindowsSocket(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation,
    bool requireLiveAuthority = true) {
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
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(
        runtime, std::string(operation) + ": handle belongs to a different runtime");
  }
  // Permissive capability policy does not make numeric handles ambient.
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(operation) + ": handle belongs to a different principal");
  }
  if (!isAllowAll()) {
    if (requireLiveAuthority && !entry.capability.empty() &&
        !checkCapability(entry.capability)) {
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
    WindowsSocketEntry& entry,
    bool requireLiveAuthority = true) {
  try {
    entry = requireWindowsSocket(runtime, handle, operation, requireLiveAuthority);
    return true;
  } catch (const facebook::jsi::JSError&) {
    return false;
  }
}

SOCKET removeWindowsSocket(facebook::jsi::Runtime& runtime, int handle, const char* operation) {
  // @ref LLP 0021#handles-dynamic-authority-and-generations — release checks
  // ownership and runtime identity, never a positive grant that may already
  // have been revoked.
  auto expected = requireWindowsSocket(runtime, handle, operation, false);
  std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
  auto it = g_windows_sockets.find(handle);
  if (it == g_windows_sockets.end()) return INVALID_SOCKET;
  if (it->second.runtimeNonce != expected.runtimeNonce ||
      it->second.owner != expected.owner ||
      it->second.socket != expected.socket) {
    throw facebook::jsi::JSError(
        runtime, std::string(operation) + ": handle identity changed during release");
  }
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
    const uint8_t* data = nullptr;
    size_t length = 0;
    if (extractArrayBufferView(runtime, obj, data, length)) {
      return data ? std::vector<uint8_t>(data, data + length) : std::vector<uint8_t>();
    }
  }
  std::string data = value.toString(runtime).utf8(runtime);
  return std::vector<uint8_t>(data.begin(), data.end());
}

bool isIpv4MappedAddress(const IN6_ADDR& address) {
  return IN6_IS_ADDR_V4MAPPED(&address) != 0;
}

bool isIpv4MappedLiteral(const std::string& host) {
  IN6_ADDR address{};
  return InetPtonA(AF_INET6, host.c_str(), &address) == 1 &&
      isIpv4MappedAddress(address);
}

std::string socketAddressText(const sockaddr_storage& addr) {
  char ip[INET6_ADDRSTRLEN] = {};
  if (addr.ss_family == AF_INET) {
    auto* sa = reinterpret_cast<const sockaddr_in*>(&addr);
    if (!InetNtopA(AF_INET, const_cast<IN_ADDR*>(&sa->sin_addr), ip, sizeof(ip))) {
      return std::string();
    }
  } else if (addr.ss_family == AF_INET6) {
    auto* sa = reinterpret_cast<const sockaddr_in6*>(&addr);
    if (isIpv4MappedAddress(sa->sin6_addr)) {
      IN_ADDR embedded{};
      std::memcpy(&embedded, &sa->sin6_addr.u.Byte[12], sizeof(embedded));
      if (!InetNtopA(AF_INET, &embedded, ip, sizeof(ip))) return std::string();
    } else if (!InetNtopA(
                   AF_INET6,
                   const_cast<IN6_ADDR*>(&sa->sin6_addr),
                   ip,
                   sizeof(ip))) {
      return std::string();
    }
  } else {
    return std::string();
  }
  return std::string(ip);
}

std::string socketAddressJson(const sockaddr_storage& addr) {
  std::string ip = socketAddressText(addr);
  if (ip.empty()) return std::string();
  int port = 0;
  std::string family;
  if (addr.ss_family == AF_INET) {
    auto* sa = reinterpret_cast<const sockaddr_in*>(&addr);
    port = ntohs(sa->sin_port);
    family = "IPv4";
  } else if (addr.ss_family == AF_INET6) {
    auto* sa = reinterpret_cast<const sockaddr_in6*>(&addr);
    port = ntohs(sa->sin6_port);
    family = isIpv4MappedAddress(sa->sin6_addr) ? "IPv4" : "IPv6";
  }
  return "{\"address\":\"" + ip + "\",\"port\":" + std::to_string(port) +
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
        case 'u': {
          auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
          };
          auto readUnit = [&](size_t& at, uint32_t& unit) -> bool {
            if (at + 4 > value.size()) return false;
            unit = 0;
            for (int i = 0; i < 4; ++i) {
              int n = hex(value[at++]);
              if (n < 0) return false;
              unit = (unit << 4) | static_cast<uint32_t>(n);
            }
            return true;
          };
          auto append = [&](uint32_t cp) {
            if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
            else if (cp <= 0x7ff) {
              out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
              out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else if (cp <= 0xffff) {
              out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
              out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
              out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else {
              out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
              out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
              out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
              out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            }
          };
          uint32_t code = 0;
          if (!readUnit(pos, code)) append(0xfffd);
          else if (code >= 0xd800 && code <= 0xdbff &&
                   pos + 6 <= value.size() && value[pos] == '\\' && value[pos + 1] == 'u') {
            size_t lowPos = pos + 2;
            uint32_t low = 0;
            if (readUnit(lowPos, low) && low >= 0xdc00 && low <= 0xdfff) {
              pos = lowPos;
              append(0x10000 + ((code - 0xd800) << 10) + low - 0xdc00);
            } else append(0xfffd);
          } else if (code >= 0xd800 && code <= 0xdfff) append(0xfffd);
          else append(code);
          break;
        }
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

bool skipJsonValue(const std::string& value, size_t& pos) {
  skipJsonWhitespace(value, pos);
  if (pos >= value.size()) return false;
  if (value[pos] == '"') {
    parseJsonString(value, pos);
    return true;
  }
  if (value[pos] == '{' || value[pos] == '[') {
    int depth = 0;
    while (pos < value.size()) {
      if (value[pos] == '"') {
        parseJsonString(value, pos);
        continue;
      }
      if (value[pos] == '{' || value[pos] == '[') ++depth;
      else if (value[pos] == '}' || value[pos] == ']') {
        --depth;
        ++pos;
        if (depth == 0) return true;
        continue;
      }
      ++pos;
    }
    return false;
  }
  while (pos < value.size() && value[pos] != ',' && value[pos] != '}' && value[pos] != ']') ++pos;
  return true;
}

bool findTopLevelJsonValue(const std::string& json, const char* key, size_t& valuePos) {
  size_t pos = 0;
  skipJsonWhitespace(json, pos);
  if (pos >= json.size() || json[pos++] != '{') return false;
  while (pos < json.size()) {
    skipJsonWhitespace(json, pos);
    if (pos >= json.size() || json[pos] == '}') return false;
    if (json[pos] != '"') return false;
    std::string parsedKey = parseJsonString(json, pos);
    skipJsonWhitespace(json, pos);
    if (pos >= json.size() || json[pos++] != ':') return false;
    skipJsonWhitespace(json, pos);
    if (parsedKey == key) {
      valuePos = pos;
      return true;
    }
    if (!skipJsonValue(json, pos)) return false;
    skipJsonWhitespace(json, pos);
    if (pos < json.size() && json[pos] == ',') ++pos;
  }
  return false;
}

bool parseJsonStringProperty(const std::string& json, const char* key, std::string& out) {
  size_t pos = 0;
  if (!findTopLevelJsonValue(json, key, pos)) return false;
  if (pos >= json.size() || json[pos] != '"') return false;
  out = parseJsonString(json, pos);
  return true;
}

uint32_t parseJsonUintProperty(const std::string& json, const char* key, uint32_t fallback) {
  size_t pos = 0;
  if (!findTopLevelJsonValue(json, key, pos)) return fallback;
  try {
    return static_cast<uint32_t>(std::stoul(json.substr(pos)));
  } catch (...) {
    return fallback;
  }
}

struct WindowsEnvironmentOptions {
  bool present = false;
  std::vector<std::string> entries;
};

WindowsEnvironmentOptions parseEnvFromOptionsJson(
    const std::string& optsJson) {
  WindowsEnvironmentOptions env;
  size_t pos = 0;
  env.present = findTopLevelJsonValue(optsJson, "env", pos);
  if (!env.present || pos >= optsJson.size() || optsJson[pos] != '{') {
    return env;
  }
  ++pos;
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
      env.entries.push_back(key + "=" + val);
    } else {
      while (pos < optsJson.size() && optsJson[pos] != ',' && optsJson[pos] != '}') ++pos;
    }
  }
  return env;
}

std::optional<std::string> windowsEnvironmentValue(
    const std::vector<std::string>& entries,
    const char* key) {
  for (const auto& entry : entries) {
    const size_t equals = entry.find('=');
    if (equals != std::string::npos &&
        _stricmp(entry.substr(0, equals).c_str(), key) == 0) {
      return entry.substr(equals + 1);
    }
  }
  return std::nullopt;
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

std::wstring buildEnvironmentBlock(
    std::vector<std::string> envEntries,
    bool envPresent) {
  if (!envPresent) return std::wstring();
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

bool windowsRegularFileExists(const std::wstring& path) {
  DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
      (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring windowsJoinPath(
    const std::wstring& directory,
    const std::wstring& leaf) {
  if (directory.empty()) return leaf;
  std::wstring joined = directory;
  if (joined.back() != L'\\' && joined.back() != L'/') joined.push_back(L'\\');
  joined += leaf;
  return joined;
}

std::wstring windowsChildCwd(const std::string& cwd) {
  if (!cwd.empty()) return utf8ToWide(cwd);
  DWORD required = GetCurrentDirectoryW(0, nullptr);
  if (required == 0) return std::wstring();
  std::vector<wchar_t> buffer(required);
  DWORD written = GetCurrentDirectoryW(required, buffer.data());
  if (written == 0 || written >= required) return std::wstring();
  return std::wstring(buffer.data(), written);
}

std::wstring resolveWindowsExecutableForEnvironment(
    const std::string& file,
    const std::string& cwd,
    const WindowsEnvironmentOptions& environment) {
  if (!environment.present) return std::wstring();

  const std::wstring wideFile = utf8ToWide(file);
  const std::wstring childCwd = windowsChildCwd(cwd);
  const bool hasDirectory = file.find('/') != std::string::npos ||
      file.find('\\') != std::string::npos || file.find(':') != std::string::npos;
  if (hasDirectory) {
    if (wideFile.size() >= 2 && wideFile[1] == L':') return wideFile;
    if (!wideFile.empty() && (wideFile[0] == L'\\' || wideFile[0] == L'/')) {
      return wideFile;
    }
    return windowsJoinPath(childCwd, wideFile);
  }

  // Node resolves through the supplied environment's PATH when present. A
  // missing PATH falls back to the parent search path; an explicitly empty
  // PATH searches only the child cwd. Keeping those states distinct prevents
  // `env: { PATH: '' }` from accidentally executing a parent-installed tool.
  auto configuredPath = windowsEnvironmentValue(environment.entries, "PATH");
  std::string search = configuredPath.value_or(getenvString("PATH"));
  std::vector<std::wstring> directories;
  directories.push_back(childCwd);
  size_t start = 0;
  while (start <= search.size()) {
    size_t end = search.find(';', start);
    if (end == std::string::npos) end = search.size();
    std::string component = search.substr(start, end - start);
    if (!component.empty()) directories.push_back(utf8ToWide(component));
    start = end + 1;
  }

  std::vector<std::wstring> names = {wideFile};
  if (file.find('.') == std::string::npos) {
    names.push_back(wideFile + L".com");
    names.push_back(wideFile + L".exe");
  }
  for (const auto& directory : directories) {
    for (const auto& name : names) {
      std::wstring candidate = windowsJoinPath(directory, name);
      if (windowsRegularFileExists(candidate)) return candidate;
    }
  }
  // Supplying a concrete, not-found application path makes CreateProcessW
  // fail instead of silently repeating its parent-environment search.
  return windowsJoinPath(childCwd, wideFile);
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

// ENG-23115 (mirrors the POSIX helpers in hermes_runtime_process.cc) — the
// spawnSync stdio channel is base64 end-to-end (ENG-23009) so binary stdin/stdout
// round-trips byte-accurately. The Windows native never adopted it, so stdin was
// WriteFile'd raw (the literal base64 text the JS builtin sends) and stdout/stderr
// were returned as a lossy UTF-8 string. These give it the same base64 channel.
std::string base64Encode(const std::string& in) {
  static const char* tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 2 < in.size()) {
    uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                 (static_cast<uint8_t>(in[i + 1]) << 8) |
                 static_cast<uint8_t>(in[i + 2]);
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back(tbl[(n >> 6) & 63]);
    out.push_back(tbl[n & 63]);
    i += 3;
  }
  size_t rem = in.size() - i;
  if (rem == 1) {
    uint32_t n = static_cast<uint8_t>(in[i]) << 16;
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2) {
    uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                 (static_cast<uint8_t>(in[i + 1]) << 8);
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back(tbl[(n >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

std::string base64Decode(const std::string& in) {
  auto dec = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  std::string out;
  out.reserve((in.size() / 4) * 3);
  int buffer = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    int v = dec(c);
    if (v < 0) continue;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buffer >> bits) & 0xff));
    }
  }
  return out;
}

std::vector<std::string> parseWindowsStdioModes(const std::string& optsJson);

void readPipeToString(HANDLE readHandle, std::string* out, uint32_t maxBuffer) {
  char buffer[4096];
  DWORD bytesRead = 0;
  while (ReadFile(readHandle, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
    // ENG-23115 — maxBuffer == 0 means UNLIMITED (the JS builtin encodes
    // Infinity that way, honored by the POSIX native). The old `out->size() <
    // maxBuffer` guard is `size_t < 0` when maxBuffer == 0, which is never true,
    // so it drained the pipe but captured nothing -> empty stdout/stderr.
    if (maxBuffer == 0) {
      out->append(buffer, buffer + bytesRead);
    } else if (out->size() < maxBuffer) {
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
  parseJsonStringProperty(optsJson, "cwd", cwd);
  parseJsonStringProperty(optsJson, "input", input);
  parseJsonStringProperty(optsJson, "argv0", argv0);
  // ENG-23115 — the JS builtin base64-encodes stdin and sets
  // "inputEncoding":"base64" (ENG-23009). Decode it back to raw bytes before
  // WriteFile, mirroring the POSIX native; without this the child received the
  // literal base64 text ("aGVsbG8=" instead of "hello").
  std::string inputEncoding;
  if (parseJsonStringProperty(optsJson, "inputEncoding", inputEncoding) &&
      inputEncoding == "base64") {
    input = base64Decode(input);
  }
  uint32_t timeoutMs = parseJsonUintProperty(optsJson, "timeout", 0);
  uint32_t maxBuffer = parseJsonUintProperty(optsJson, "maxBuffer", 1024 * 1024);
  auto environment = parseEnvFromOptionsJson(optsJson);
  auto stdioModes = parseWindowsStdioModes(optsJson);

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  const bool pipeStdin = stdioModes[0] == "pipe";
  const bool pipeStdout = stdioModes[1] == "pipe";
  const bool pipeStderr = stdioModes[2] == "pipe";
  const bool ignoreStdin = stdioModes[0] == "ignore";
  const bool ignoreStdout = stdioModes[1] == "ignore";
  const bool ignoreStderr = stdioModes[2] == "ignore";

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

  // This backend implements neither IPC nor descriptor duplication. Treating
  // either mode as the generic fallback below silently inherited the parent's
  // console for slots 0-2 or ignored later slots. Reject every occurrence
  // before creating or selecting any handles, matching the async Windows
  // backend's fail-closed behavior.
  for (const auto& mode : stdioModes) {
    if (mode == "ipc") {
      return failJson(
          "child_process IPC is not supported by the Windows sync spawn backend");
    }
    if (mode.size() > 3 && mode.substr(0, 3) == "fd:") {
      return failJson(
          "child_process fd:N stdio is not supported by the Windows sync spawn backend");
    }
  }

  for (size_t i = 3; i < stdioModes.size(); ++i) {
    if (stdioModes[i] != "ignore") {
      return failJson(
          "child_process extra stdio is not supported by the Windows sync spawn backend");
    }
  }

  if (pipeStdin) {
    HANDLE stdinRead = nullptr;
    HANDLE stdinWrite = nullptr;
    if (!CreatePipe(&stdinRead, &stdinWrite, &sa, 0)) {
      return failJson("Failed to create stdin pipe");
    }
    SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0);
    childStdIn = stdinRead;
    parentStdInWrite = stdinWrite;
  } else if (ignoreStdin) {
    nullRead = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullRead == INVALID_HANDLE_VALUE) return failJson("Failed to open NUL for ignored stdin");
    childStdIn = nullRead;
  } else {
    childStdIn = GetStdHandle(STD_INPUT_HANDLE);
  }

  if (pipeStdout) {
    HANDLE stdoutRead = nullptr;
    HANDLE stdoutWrite = nullptr;
    if (!CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0)) {
      return failJson("Failed to create stdout pipe");
    }
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
    parentStdOutRead = stdoutRead;
    childStdOut = stdoutWrite;
  } else if (ignoreStdout) {
    nullWriteOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullWriteOut == INVALID_HANDLE_VALUE) return failJson("Failed to open NUL for ignored stdout");
    childStdOut = nullWriteOut;
  } else {
    childStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  }

  if (pipeStderr) {
    HANDLE stderrRead = nullptr;
    HANDLE stderrWrite = nullptr;
    if (!CreatePipe(&stderrRead, &stderrWrite, &sa, 0)) {
      return failJson("Failed to create stderr pipe");
    }
    SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);
    parentStdErrRead = stderrRead;
    childStdErr = stderrWrite;
  } else if (ignoreStderr) {
    nullWriteErr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullWriteErr == INVALID_HANDLE_VALUE) return failJson("Failed to open NUL for ignored stderr");
    childStdErr = nullWriteErr;
  } else {
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
  std::wstring envBlock =
      buildEnvironmentBlock(environment.entries, environment.present);
  std::wstring applicationName =
      resolveWindowsExecutableForEnvironment(file, cwd, environment);

  DWORD flags = CREATE_NO_WINDOW;
  if (environment.present) flags |= CREATE_UNICODE_ENVIRONMENT;
  BOOL created = CreateProcessW(
      environment.present ? applicationName.c_str() : nullptr,
      mutableCommandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      flags,
      environment.present ? const_cast<wchar_t*>(envBlock.data()) : nullptr,
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
  // ENG-23115 — return stdout/stderr base64-encoded and flag
  // "stdioEncoding":"base64" so the JS builtin decodes them to byte-accurate
  // Buffers (ENG-23009). The old raw jsonEscape'd string turned bytes >= 0x80
  // into U+FFFD and yielded a JS string, not a Buffer. base64 output is pure
  // [A-Za-z0-9+/=], none of which needs JSON escaping.
  std::string result = "{\"stdout\":\"" + base64Encode(stdoutStr)
      + "\",\"stderr\":\"" + base64Encode(stderrStr)
      + "\",\"stdioEncoding\":\"base64\",\"status\":" + std::to_string(status)
      + ",\"pid\":" + std::to_string(static_cast<int>(processInfo.dwProcessId));
  if (timedOut) {
    result += ",\"error\":\"Command timed out\"";
  }
  result += "}";
  return result;
}

struct WindowsSpawnPipeBuffer {
  std::mutex mutex;
  std::deque<std::vector<uint8_t>> chunks;
  bool closed = false;
};

bool isValidHandle(HANDLE handle);
void closeHandleIfValid(HANDLE& handle);

struct WindowsSpawnedProcess {
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
  std::string capability;
  HANDLE process = nullptr;
  HANDLE stdinWrite = nullptr;
  HANDLE stdinWriterThread = nullptr;
  std::mutex stdinMutex;
  std::condition_variable stdinCv;
  std::deque<std::vector<uint8_t>> stdinQueue;
  size_t stdinQueuedBytes = 0;
  bool stdinCloseRequested = false;
  bool stdinWriterStopped = false;
  DWORD pid = 0;
  std::shared_ptr<WindowsSpawnPipeBuffer> stdoutBuffer;
  std::shared_ptr<WindowsSpawnPipeBuffer> stderrBuffer;
  bool exited = false;
  // @ref LLP 0008#sockets-dns-and-process — explicit ChildProcess.unref()
  // transfers lifetime out of the owning Hermes runtime. Closing our HANDLE at
  // teardown must not terminate that child.
  bool referenced = true;
  int exitCode = -1;
  int killedSignal = 0;
};

constexpr size_t kWindowsSpawnStdinQueueBytes = 256 * 1024;

void runWindowsStdinWriter(const std::shared_ptr<WindowsSpawnedProcess>& proc) {
  HANDLE writerThread = nullptr;
  BOOL duplicated = DuplicateHandle(
      GetCurrentProcess(),
      GetCurrentThread(),
      GetCurrentProcess(),
      &writerThread,
      0,
      FALSE,
      DUPLICATE_SAME_ACCESS);
  {
    std::lock_guard<std::mutex> lock(proc->stdinMutex);
    if (!duplicated || !isValidHandle(writerThread)) {
      proc->stdinCloseRequested = true;
      proc->stdinQueue.clear();
      proc->stdinQueuedBytes = 0;
      closeHandleIfValid(proc->stdinWrite);
      proc->stdinWriterStopped = true;
    } else {
      proc->stdinWriterThread = writerThread;
    }
  }
  proc->stdinCv.notify_all();
  if (!duplicated || !isValidHandle(writerThread)) return;

  for (;;) {
    std::vector<uint8_t> chunk;
    HANDLE handle = nullptr;
    {
      std::unique_lock<std::mutex> lock(proc->stdinMutex);
      proc->stdinCv.wait(lock, [&] {
        return proc->stdinCloseRequested || !proc->stdinQueue.empty();
      });
      if (proc->stdinQueue.empty()) {
        if (proc->stdinCloseRequested) {
          closeHandleIfValid(proc->stdinWrite);
          closeHandleIfValid(proc->stdinWriterThread);
          proc->stdinWriterStopped = true;
          lock.unlock();
          proc->stdinCv.notify_all();
          return;
        }
        continue;
      }
      chunk = std::move(proc->stdinQueue.front());
      proc->stdinQueue.pop_front();
      handle = proc->stdinWrite;
    }

    size_t offset = 0;
    bool failed = !isValidHandle(handle);
    while (!failed && offset < chunk.size()) {
      DWORD written = 0;
      DWORD request = static_cast<DWORD>(std::min<size_t>(
          chunk.size() - offset, std::numeric_limits<DWORD>::max()));
      if (!WriteFile(handle, chunk.data() + offset, request, &written, nullptr) || written == 0) {
        failed = true;
        break;
      }
      offset += written;
    }

    {
      std::lock_guard<std::mutex> lock(proc->stdinMutex);
      proc->stdinQueuedBytes = proc->stdinQueuedBytes > chunk.size()
          ? proc->stdinQueuedBytes - chunk.size()
          : 0;
      if (failed) {
        proc->stdinCloseRequested = true;
        proc->stdinQueue.clear();
        proc->stdinQueuedBytes = 0;
        closeHandleIfValid(proc->stdinWrite);
        closeHandleIfValid(proc->stdinWriterThread);
        proc->stdinWriterStopped = true;
      }
    }
    proc->stdinCv.notify_all();
    if (failed) return;
  }
}

std::unordered_map<int, std::shared_ptr<WindowsSpawnedProcess>> g_windows_spawned_processes;
uint64_t g_windows_next_spawn_handle = 1;
std::mutex g_windows_spawn_mutex;

bool allocateWindowsSpawnHandleLocked(int& handle) {
  if (g_windows_next_spawn_handle == 0 ||
      g_windows_next_spawn_handle > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  handle = static_cast<int>(g_windows_next_spawn_handle++);
  return true;
}

bool isValidHandle(HANDLE handle) {
  return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

void closeHandleIfValid(HANDLE& handle) {
  if (isValidHandle(handle)) {
    CloseHandle(handle);
  }
  handle = nullptr;
}

// Graceful stdin close drains bytes already accepted into stdinQueue. Dispose
// and kill use `discard=true`: cancel a synchronous WriteFile by its writer
// thread handle, discard queued bytes, and optionally wait for deterministic
// writer teardown. stdinWrite is only closed while stdinMutex is held (by the
// writer or the not-yet-started fallback), so it cannot race an in-flight copy
// of that handle.
void requestWindowsStdinClose(
    const std::shared_ptr<WindowsSpawnedProcess>& proc,
    bool discard,
    bool waitForWriter) {
  if (!proc) return;
  std::unique_lock<std::mutex> lock(proc->stdinMutex);
  proc->stdinCloseRequested = true;
  if (discard) {
    proc->stdinQueue.clear();
    proc->stdinQueuedBytes = 0;
  }
  if (waitForWriter && !isValidHandle(proc->stdinWriterThread) && !proc->stdinWriterStopped) {
    // Dispose can win the race immediately after spawn. Wait for the detached
    // thread either to publish its cancelable handle or to report that handle
    // duplication failed and close the pipe itself.
    proc->stdinCv.wait_for(lock, std::chrono::seconds(1), [&] {
      return isValidHandle(proc->stdinWriterThread) || proc->stdinWriterStopped;
    });
  }
  if (!isValidHandle(proc->stdinWriterThread) && proc->stdinWriterStopped) {
    closeHandleIfValid(proc->stdinWrite);
  }
  proc->stdinCv.notify_all();
  if (waitForWriter && !proc->stdinWriterStopped) {
    // Cancel repeatedly across the pop->WriteFile race: a cancellation issued
    // just before the syscall reports no pending I/O and would otherwise let
    // the writer enter an uncancelled blocking write immediately afterwards.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!proc->stdinWriterStopped && std::chrono::steady_clock::now() < deadline) {
      if (discard && isValidHandle(proc->stdinWriterThread)) {
        CancelSynchronousIo(proc->stdinWriterThread);
      }
      proc->stdinCv.notify_all();
      proc->stdinCv.wait_for(lock, std::chrono::milliseconds(10));
    }
  } else if (discard && isValidHandle(proc->stdinWriterThread)) {
    CancelSynchronousIo(proc->stdinWriterThread);
  }
}

std::string normalizeWindowsStdioMode(const std::string& value) {
  if (value == "ignore") return "ignore";
  if (value == "inherit") return "inherit";
  if (value == "pipe") return "pipe";
  if (value == "overlapped") return "pipe";
  if (value == "ipc") return "ipc";
  if (value.size() > 3 && value.substr(0, 3) == "fd:") return value;
  return "pipe";
}

std::vector<std::string> parseWindowsStdioModes(const std::string& optsJson) {
  std::vector<std::string> modes = {"pipe", "pipe", "pipe"};
  size_t pos = 0;
  if (!findTopLevelJsonValue(optsJson, "stdio", pos)) return modes;
  if (pos >= optsJson.size()) return modes;
  if (optsJson[pos] == '"') {
    std::string mode = normalizeWindowsStdioMode(parseJsonString(optsJson, pos));
    modes[0] = mode;
    modes[1] = mode;
    modes[2] = mode;
    return modes;
  }
  if (optsJson[pos] != '[') return modes;
  ++pos;
  size_t slot = 0;
  while (pos < optsJson.size()) {
    skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] == ']') break;
    std::string parsed;
    if (optsJson[pos] == '"') {
      parsed = parseJsonString(optsJson, pos);
    } else {
      while (pos < optsJson.size() && optsJson[pos] != ',' && optsJson[pos] != ']') {
        parsed.push_back(optsJson[pos++]);
      }
    }
    if (slot >= modes.size()) modes.resize(slot + 1, "ignore");
    modes[slot++] = normalizeWindowsStdioMode(parsed);
    skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == ',') ++pos;
  }
  return modes;
}

bool parseJsonBoolProperty(const std::string& json, const char* key, bool fallback) {
  size_t pos = 0;
  if (!findTopLevelJsonValue(json, key, pos)) return fallback;
  if (json.compare(pos, 4, "true") == 0) return true;
  if (json.compare(pos, 5, "false") == 0) return false;
  return fallback;
}

std::string spawnErrorJson(
    const std::string& code,
    int errnoValue,
    const std::string& message) {
  return "{\"error\":\"" + jsonEscape(message)
      + "\",\"code\":\"" + jsonEscape(code)
      + "\",\"errno\":" + std::to_string(errnoValue)
      + ",\"message\":\"" + jsonEscape(message) + "\"}";
}

void readWindowsPipeToBuffer(
    HANDLE readHandle,
    std::shared_ptr<WindowsSpawnPipeBuffer> output) {
  char buffer[4096];
  DWORD bytesRead = 0;
  while (ReadFile(readHandle, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
    std::vector<uint8_t> chunk(
        reinterpret_cast<uint8_t*>(buffer),
        reinterpret_cast<uint8_t*>(buffer) + bytesRead);
    std::lock_guard<std::mutex> lock(output->mutex);
    output->chunks.push_back(std::move(chunk));
  }
  CloseHandle(readHandle);
  std::lock_guard<std::mutex> lock(output->mutex);
  output->closed = true;
}

std::vector<uint8_t> drainWindowsPipeBuffer(
    const std::shared_ptr<WindowsSpawnPipeBuffer>& buffer) {
  std::vector<uint8_t> out;
  if (!buffer) return out;
  std::lock_guard<std::mutex> lock(buffer->mutex);
  size_t total = 0;
  for (const auto& chunk : buffer->chunks) total += chunk.size();
  out.reserve(total);
  while (!buffer->chunks.empty()) {
    auto chunk = std::move(buffer->chunks.front());
    buffer->chunks.pop_front();
    out.insert(out.end(), chunk.begin(), chunk.end());
  }
  return out;
}

std::shared_ptr<WindowsSpawnedProcess> requireWindowsSpawnProcessOwnership(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation) {
  std::shared_ptr<WindowsSpawnedProcess> proc;
  {
    std::lock_guard<std::mutex> lock(g_windows_spawn_mutex);
    auto it = g_windows_spawned_processes.find(handle);
    if (it == g_windows_spawned_processes.end()) {
      throw facebook::jsi::JSError(runtime, std::string(operation) + ": invalid handle");
    }
    proc = it->second;
  }
  if (proc->runtimeNonce != ex_hermes_current_runtime_nonce()) {
    throw facebook::jsi::JSError(
        runtime, std::string(operation) + ": handle belongs to a different runtime");
  }
  // Permissive capability policy never turns a forgeable numeric handle into
  // ambient object authority.
  if (proc->owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(operation) + ": handle belongs to a different principal");
  }
  return proc;
}

std::shared_ptr<WindowsSpawnedProcess> requireWindowsSpawnProcess(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation) {
  auto proc = requireWindowsSpawnProcessOwnership(runtime, handle, operation);
  if (!proc->capability.empty() && !checkCapability(proc->capability)) {
    throw facebook::jsi::JSError(
        runtime, "Permission denied: process:spawn capability required");
  }
  return proc;
}

std::shared_ptr<WindowsSpawnedProcess> tryWindowsSpawnProcess(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* operation) {
  try {
    return requireWindowsSpawnProcess(runtime, handle, operation);
  } catch (const facebook::jsi::JSError&) {
    return nullptr;
  }
}

std::string buildWindowsSpawnCommandLine(
    const std::string& file,
    const std::vector<std::string>& spawnArgs,
    const std::string& optsJson,
    const std::string& launchFile) {
  std::string argv0;
  parseJsonStringProperty(optsJson, "argv0", argv0);

  bool useShell = parseJsonBoolProperty(optsJson, "shell", false);
  std::string shellPath;
  if (parseJsonStringProperty(optsJson, "shell", shellPath)) {
    useShell = true;
  }
  if (!useShell) {
    return wideToUtf8(buildCommandLine(file, spawnArgs, argv0));
  }

  std::string shell = launchFile;
  std::wstring childCommand = buildCommandLine(file, spawnArgs, argv0);
  std::wstring commandLine = quoteWindowsArg(utf8ToWide(shell));
  std::string lowerShell = shell;
  std::transform(lowerShell.begin(), lowerShell.end(), lowerShell.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  auto hasSuffix = [&](const char* suffix) {
    size_t length = std::strlen(suffix);
    return lowerShell.size() >= length &&
        lowerShell.compare(lowerShell.size() - length, length, suffix) == 0;
  };
  bool isCmd = hasSuffix("cmd") || hasSuffix("cmd.exe");
  commandLine += isCmd ? L" /d /s /c " : L" -c ";
  commandLine += quoteWindowsArg(childCommand);
  return wideToUtf8(commandLine);
}

std::string windowsSpawnLaunchFile(
    const std::string& file,
    const std::string& optsJson,
    const WindowsEnvironmentOptions& environment) {
  bool useShell = parseJsonBoolProperty(optsJson, "shell", false);
  std::string shell;
  if (parseJsonStringProperty(optsJson, "shell", shell)) useShell = true;
  if (!useShell) return file;
  if (!shell.empty()) return shell;
  auto configured = windowsEnvironmentValue(environment.entries, "ComSpec");
  if (configured && !configured->empty()) return *configured;
  if (!configured) {
    shell = getenvString("ComSpec");
    if (!shell.empty()) return shell;
  }
  return "cmd.exe";
}

std::string spawnAsyncWindowsJson(
    const std::string& file,
    const std::vector<std::string>& spawnArgs,
    const std::string& optsJson) {
  std::string cwd;
  parseJsonStringProperty(optsJson, "cwd", cwd);
  auto environment = parseEnvFromOptionsJson(optsJson);
  auto stdioModes = parseWindowsStdioModes(optsJson);
  for (const auto& mode : stdioModes) {
    if (mode == "ipc") {
      return spawnErrorJson(
          "ENOTSUP",
          -1,
          "child_process IPC is not supported by the Windows async spawn backend");
    }
    if (mode.size() > 3 && mode.substr(0, 3) == "fd:") {
      return spawnErrorJson(
          "ENOTSUP",
          -1,
          "child_process fd:N stdio is not supported by the Windows async spawn backend");
    }
  }
  for (size_t i = 3; i < stdioModes.size(); ++i) {
    if (stdioModes[i] != "ignore") {
      return spawnErrorJson(
          "ENOTSUP",
          -1,
          "child_process extra stdio is not supported by the Windows async spawn backend");
    }
  }

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE childStdIn = nullptr;
  HANDLE childStdOut = nullptr;
  HANDLE childStdErr = nullptr;
  HANDLE parentStdInWrite = nullptr;
  HANDLE parentStdOutRead = nullptr;
  HANDLE parentStdErrRead = nullptr;
  std::vector<HANDLE> childOwnedHandles;

  auto fail = [&](const std::string& code, int errnoValue, const std::string& message) {
    closeHandleIfValid(parentStdInWrite);
    closeHandleIfValid(parentStdOutRead);
    closeHandleIfValid(parentStdErrRead);
    for (HANDLE& handle : childOwnedHandles) {
      closeHandleIfValid(handle);
    }
    return spawnErrorJson(code, errnoValue, message);
  };

  auto openNul = [&](DWORD access) -> HANDLE {
    HANDLE handle = CreateFileW(
        L"NUL",
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    return handle == INVALID_HANDLE_VALUE ? nullptr : handle;
  };

  auto setupStdin = [&]() -> bool {
    const std::string& mode = stdioModes.size() > 0 ? stdioModes[0] : std::string("pipe");
    if (mode == "pipe") {
      HANDLE readHandle = nullptr;
      HANDLE writeHandle = nullptr;
      if (!CreatePipe(&readHandle, &writeHandle, &sa, 0)) return false;
      SetHandleInformation(writeHandle, HANDLE_FLAG_INHERIT, 0);
      childStdIn = readHandle;
      parentStdInWrite = writeHandle;
      childOwnedHandles.push_back(readHandle);
      return true;
    }
    if (mode == "ignore") {
      childStdIn = openNul(GENERIC_READ);
      if (!childStdIn) return false;
      childOwnedHandles.push_back(childStdIn);
      return true;
    }
    childStdIn = GetStdHandle(STD_INPUT_HANDLE);
    return true;
  };

  auto setupStdout = [&]() -> bool {
    const std::string& mode = stdioModes.size() > 1 ? stdioModes[1] : std::string("pipe");
    if (mode == "pipe") {
      HANDLE readHandle = nullptr;
      HANDLE writeHandle = nullptr;
      if (!CreatePipe(&readHandle, &writeHandle, &sa, 0)) return false;
      SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);
      parentStdOutRead = readHandle;
      childStdOut = writeHandle;
      childOwnedHandles.push_back(writeHandle);
      return true;
    }
    if (mode == "ignore") {
      childStdOut = openNul(GENERIC_WRITE);
      if (!childStdOut) return false;
      childOwnedHandles.push_back(childStdOut);
      return true;
    }
    childStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    return true;
  };

  auto setupStderr = [&]() -> bool {
    const std::string& mode = stdioModes.size() > 2 ? stdioModes[2] : std::string("pipe");
    if (mode == "pipe") {
      HANDLE readHandle = nullptr;
      HANDLE writeHandle = nullptr;
      if (!CreatePipe(&readHandle, &writeHandle, &sa, 0)) return false;
      SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);
      parentStdErrRead = readHandle;
      childStdErr = writeHandle;
      childOwnedHandles.push_back(writeHandle);
      return true;
    }
    if (mode == "ignore") {
      childStdErr = openNul(GENERIC_WRITE);
      if (!childStdErr) return false;
      childOwnedHandles.push_back(childStdErr);
      return true;
    }
    childStdErr = GetStdHandle(STD_ERROR_HANDLE);
    return true;
  };

  if (!setupStdin()) {
    return fail("EMFILE", -24, "Failed to create stdin handle");
  }
  if (!setupStdout()) {
    return fail("EMFILE", -24, "Failed to create stdout handle");
  }
  if (!setupStderr()) {
    return fail("EMFILE", -24, "Failed to create stderr handle");
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = childStdIn;
  startup.hStdOutput = childStdOut;
  startup.hStdError = childStdErr;

  PROCESS_INFORMATION processInfo{};
  std::string launchFile = windowsSpawnLaunchFile(file, optsJson, environment);
  std::string commandLineUtf8 =
      buildWindowsSpawnCommandLine(file, spawnArgs, optsJson, launchFile);
  std::wstring commandLine = utf8ToWide(commandLineUtf8);
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');
  std::wstring wideCwd = cwd.empty() ? std::wstring() : utf8ToWide(cwd);
  std::wstring envBlock =
      buildEnvironmentBlock(environment.entries, environment.present);
  std::wstring applicationName =
      resolveWindowsExecutableForEnvironment(launchFile, cwd, environment);

  DWORD flags = CREATE_NO_WINDOW;
  if (parseJsonBoolProperty(optsJson, "detached", false)) {
    flags |= CREATE_NEW_PROCESS_GROUP;
  }
  if (environment.present) flags |= CREATE_UNICODE_ENVIRONMENT;
  BOOL created = CreateProcessW(
      environment.present ? applicationName.c_str() : nullptr,
      mutableCommandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      flags,
      environment.present ? const_cast<wchar_t*>(envBlock.data()) : nullptr,
      wideCwd.empty() ? nullptr : wideCwd.c_str(),
      &startup,
      &processInfo);

  for (HANDLE& handle : childOwnedHandles) {
    closeHandleIfValid(handle);
  }

  if (!created) {
    DWORD err = GetLastError();
    closeHandleIfValid(parentStdInWrite);
    closeHandleIfValid(parentStdOutRead);
    closeHandleIfValid(parentStdErrRead);
    std::string code = err == ERROR_ACCESS_DENIED ? "EACCES" : "ENOENT";
    int errnoValue = err == ERROR_ACCESS_DENIED ? -13 : -2;
    return spawnErrorJson(code, errnoValue, windowsErrorMessage(err) + ": " + file);
  }

  CloseHandle(processInfo.hThread);

  auto proc = std::make_shared<WindowsSpawnedProcess>();
  proc->runtimeNonce = ex_hermes_current_runtime_nonce();
  proc->owner = currentPrincipalId();
  proc->capability = "process:spawn";
  proc->process = processInfo.hProcess;
  proc->stdinWrite = parentStdInWrite;
  proc->pid = processInfo.dwProcessId;
  parentStdInWrite = nullptr;
  if (isValidHandle(proc->stdinWrite)) {
    std::thread(runWindowsStdinWriter, proc).detach();
  } else {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // ignore/inherit stdin has no parent writer thread. Mark that terminal
    // state explicitly so disposal cannot wait six seconds for a thread that
    // was never created.
    proc->stdinWriterStopped = true;
  }

  if (parentStdOutRead) {
    proc->stdoutBuffer = std::make_shared<WindowsSpawnPipeBuffer>();
    std::thread(readWindowsPipeToBuffer, parentStdOutRead, proc->stdoutBuffer).detach();
    parentStdOutRead = nullptr;
  }
  if (parentStdErrRead) {
    proc->stderrBuffer = std::make_shared<WindowsSpawnPipeBuffer>();
    std::thread(readWindowsPipeToBuffer, parentStdErrRead, proc->stderrBuffer).detach();
    parentStdErrRead = nullptr;
  }

  int handle = 0;
  bool registered = false;
  {
    std::lock_guard<std::mutex> lock(g_windows_spawn_mutex);
    if (allocateWindowsSpawnHandleLocked(handle)) {
      registered = g_windows_spawned_processes.emplace(handle, proc).second;
    }
  }
  if (!registered) {
    TerminateProcess(proc->process, 1);
    WaitForSingleObject(proc->process, INFINITE);
    requestWindowsStdinClose(proc, true, true);
    closeHandleIfValid(proc->process);
    return spawnErrorJson(
        "ERR_OUT_OF_RANGE", -1, "spawn handle space exhausted");
  }

  return "{\"handle\":" + std::to_string(handle)
      + ",\"pid\":" + std::to_string(static_cast<unsigned long>(processInfo.dwProcessId))
      + "}";
}

} // namespace

void exactCleanupRuntimeSockets(uint64_t runtimeNonce) {
  {
    std::lock_guard<std::mutex> lock(g_windows_sockets_mutex);
    for (auto it = g_windows_sockets.begin(); it != g_windows_sockets.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        closesocket(it->second.socket);
        it = g_windows_sockets.erase(it);
      } else {
        ++it;
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(g_windows_net_owner_stamp_mutex);
    for (auto it = g_windows_net_owner_stamps.begin();
         it != g_windows_net_owner_stamps.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        it = g_windows_net_owner_stamps.erase(it);
      } else {
        ++it;
      }
    }
  }
}

extern "C" void exactCleanupRuntimeSpawnedProcesses(uint64_t runtimeNonce) {
  if (runtimeNonce == 0) return;

  std::vector<std::shared_ptr<WindowsSpawnedProcess>> owned;
  {
    std::lock_guard<std::mutex> lock(g_windows_spawn_mutex);
    for (auto it = g_windows_spawned_processes.begin();
         it != g_windows_spawned_processes.end();) {
      if (it->second && it->second->runtimeNonce == runtimeNonce) {
        owned.push_back(it->second);
        it = g_windows_spawned_processes.erase(it);
      } else {
        ++it;
      }
    }
  }

  for (const auto& proc : owned) {
    if (isValidHandle(proc->process)) {
      DWORD exitCode = 0;
      if (proc->referenced &&
          GetExitCodeProcess(proc->process, &exitCode) &&
          exitCode == STILL_ACTIVE) {
        TerminateProcess(proc->process, 1);
      }
      if (proc->referenced) {
        WaitForSingleObject(proc->process, INFINITE);
      }
    }
    requestWindowsStdinClose(proc, true, true);
    // Closing a process HANDLE does not terminate the process. In particular,
    // unref'ed detached children continue independently after runtime teardown.
    closeHandleIfValid(proc->process);
  }
}

void installOsInfoGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto authorizeSystemInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAuthorizeSystemInfo"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactAuthorizeSystemInfo: information kind required");
        }
        double raw = args[0].asNumber();
        if (!std::isfinite(raw) || raw < 0 || raw > 15 || std::floor(raw) != raw) {
          throw facebook::jsi::JSError(
              runtime, "__exactAuthorizeSystemInfo: invalid information kind");
        }
        auto name =
            static_cast<ExactSystemInfoName>(static_cast<uint32_t>(raw));
        exactRequireTypedSystemInfo(
            runtime,
            ExactSystemInfoSurface::CachedValue,
            name);
        // @ref LLP 0021#typed-resources-and-initial-vocabulary — return host
        // storage paths only after the sys:read decision instead of re-entering
        // the separately gated process.env compatibility facade.
        if (name == ExactSystemInfoName::StoragePaths) {
          auto home = getenvString("HOME");
          if (home.empty()) home = getenvString("USERPROFILE");
          if (home.empty()) home = "/";
          auto temporary = getenvString("TMPDIR");
          if (temporary.empty()) temporary = getenvString("TMP");
          if (temporary.empty()) temporary = getenvString("TEMP");
          if (temporary.empty()) temporary = "/tmp";
          facebook::jsi::Object paths(runtime);
          paths.setProperty(runtime, "home", home);
          paths.setProperty(runtime, "temporary", temporary);
          return paths;
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(
      rt, "__exactAuthorizeSystemInfo", std::move(authorizeSystemInfoFn));

  auto hostnameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetHostname"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::Hostname, ExactSystemInfoName::Hostname);
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::CpuCount, ExactSystemInfoName::Cpus);
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return facebook::jsi::Value(static_cast<double>(info.dwNumberOfProcessors));
      });
  rt.global().setProperty(rt, "__exactGetCpuCount", std::move(cpuCountFn));

  auto totalMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetTotalMem"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::TotalMemory, ExactSystemInfoName::Memory);
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::FreeMemory, ExactSystemInfoName::Memory);
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::Uptime, ExactSystemInfoName::Uptime);
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
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::UserInfo, ExactSystemInfoName::User);
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
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::LoadAverage, ExactSystemInfoName::LoadAverage);
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
        exactRequireTypedSystemInfo(
            runtime,
            ExactSystemInfoSurface::NetworkInterfaces,
            ExactSystemInfoName::NetworkInterfaces);
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
        handle->next_tick.push_back(
            NextTickEntry{currentPrincipalId(), exactCollectTypedPrincipalStack(),
                          std::move(callback), std::move(callback_args)});
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

// @ref LLP 0008#sockets-dns-and-process — Windows default-path record queries
// preserve resolver rcodes through a bounded raw UDP transport instead of
// flattening them through getaddrinfo.
struct WindowsDnsResult {
  bool ok = false;
  std::string payload;
  std::string error;
  std::string code;
};

uint16_t readDnsU16(const uint8_t* bytes) {
  return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

uint32_t readDnsU32(const uint8_t* bytes) {
  return (static_cast<uint32_t>(bytes[0]) << 24) |
      (static_cast<uint32_t>(bytes[1]) << 16) |
      (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
}

const char* windowsDnsRcodeToErrorCode(int rcode) {
  switch (rcode) {
    case 1: return "EFORMERR";
    case 2: return "ESERVFAIL";
    case 3: return "ENOTFOUND";
    case 4: return "ENOTIMP";
    case 5: return "EREFUSED";
    default: return "EBADRESP";
  }
}

int windowsDnsRrtypeToQtype(const std::string& rrtype) {
  if (rrtype == "A") return 1;
  if (rrtype == "NS") return 2;
  if (rrtype == "CNAME") return 5;
  if (rrtype == "SOA") return 6;
  if (rrtype == "PTR") return 12;
  if (rrtype == "MX") return 15;
  if (rrtype == "TXT") return 16;
  if (rrtype == "AAAA") return 28;
  if (rrtype == "SRV") return 33;
  if (rrtype == "NAPTR") return 35;
  if (rrtype == "ANY") return 255;
  if (rrtype == "CAA") return 257;
  return -1;
}

void applyWindowsDnsTiming(int& timeoutSeconds, int& attempts) {
  const std::string options = getenvString("RES_OPTIONS");
  std::istringstream tokens(options);
  std::string token;
  while (tokens >> token) {
    if (token.rfind("timeout:", 0) == 0) {
      int value = std::atoi(token.c_str() + 8);
      if (value > 0 && value <= 30) timeoutSeconds = value;
    } else if (token.rfind("attempts:", 0) == 0) {
      int value = std::atoi(token.c_str() + 9);
      if (value > 0 && value <= 5) attempts = value;
    }
  }
}

void loadWindowsDnsServers(
    std::vector<sockaddr_in>& servers,
    int& timeoutSeconds,
    int& attempts) {
  timeoutSeconds = 5;
  attempts = 2;
  const std::string overrideSpec = getenvString("IBEX_DNS_SERVER");
  if (!overrideSpec.empty()) {
    std::string address = overrideSpec;
    int port = 53;
    const size_t colon = address.rfind(':');
    if (colon != std::string::npos) {
      port = std::atoi(address.substr(colon + 1).c_str());
      address.resize(colon);
    }
    sockaddr_in server{};
    if (port > 0 && port <= 65535 &&
        InetPtonA(AF_INET, address.c_str(), &server.sin_addr) == 1) {
      server.sin_family = AF_INET;
      server.sin_port = htons(static_cast<uint16_t>(port));
      servers.push_back(server);
    }
  }

  if (servers.empty()) {
    ULONG size = 0;
    if (GetNetworkParams(nullptr, &size) == ERROR_BUFFER_OVERFLOW && size > 0) {
      std::vector<uint8_t> storage(size);
      auto* info = reinterpret_cast<FIXED_INFO*>(storage.data());
      if (GetNetworkParams(info, &size) == NO_ERROR) {
        for (IP_ADDR_STRING* item = &info->DnsServerList; item; item = item->Next) {
          sockaddr_in server{};
          if (InetPtonA(AF_INET, item->IpAddress.String, &server.sin_addr) != 1) continue;
          server.sin_family = AF_INET;
          server.sin_port = htons(53);
          servers.push_back(server);
        }
      }
    }
  }
  applyWindowsDnsTiming(timeoutSeconds, attempts);
}

std::string windowsDnsServersJson() {
  std::vector<sockaddr_in> servers;
  int timeoutSeconds = 0;
  int attempts = 0;
  loadWindowsDnsServers(servers, timeoutSeconds, attempts);
  std::ostringstream json;
  json << '[';
  bool first = true;
  for (const auto& server : servers) {
    char address[INET_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET, const_cast<IN_ADDR*>(&server.sin_addr), address, sizeof(address))) {
      continue;
    }
    if (!first) json << ',';
    first = false;
    json << '"' << address;
    const uint16_t port = ntohs(server.sin_port);
    if (port != 0 && port != 53) json << ':' << port;
    json << '"';
  }
  json << ']';
  return json.str();
}

bool buildWindowsDnsQuery(
    const std::string& hostname,
    int qtype,
    uint16_t id,
    std::vector<uint8_t>& query) {
  query.clear();
  query.reserve(hostname.size() + 18);
  query.push_back(static_cast<uint8_t>(id >> 8));
  query.push_back(static_cast<uint8_t>(id));
  query.push_back(0x01);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x01);
  query.insert(query.end(), 6, 0x00);
  size_t labelStart = 0;
  size_t encodedLength = 0;
  for (size_t index = 0; index <= hostname.size(); ++index) {
    if (index != hostname.size() && hostname[index] != '.') continue;
    const size_t labelLength = index - labelStart;
    if (labelLength == 0) {
      if (index == hostname.size() && index > 0) break;
      return false;
    }
    encodedLength += labelLength + 1;
    if (labelLength > 63 || encodedLength > 255) return false;
    query.push_back(static_cast<uint8_t>(labelLength));
    query.insert(query.end(), hostname.begin() + labelStart, hostname.begin() + index);
    labelStart = index + 1;
  }
  query.push_back(0x00);
  query.push_back(static_cast<uint8_t>((qtype >> 8) & 0xff));
  query.push_back(static_cast<uint8_t>(qtype & 0xff));
  query.push_back(0x00);
  query.push_back(0x01);
  return true;
}

struct WindowsRawDnsOutcome {
  std::vector<uint8_t> response;
  int rcode = -1;
  bool truncated = false;
  bool connectionRefused = false;
};

WindowsRawDnsOutcome sendWindowsDnsQuery(
    const std::vector<sockaddr_in>& servers,
    int timeoutSeconds,
    int attempts,
    const std::vector<uint8_t>& query) {
  WindowsRawDnsOutcome outcome;
  const uint16_t queryId = readDnsU16(query.data());
  std::vector<uint8_t> response(4096);
  for (int attempt = 0; attempt < attempts; ++attempt) {
    for (const auto& server : servers) {
      SOCKET socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (socketHandle == INVALID_SOCKET) continue;
      if (connect(
              socketHandle,
              reinterpret_cast<const sockaddr*>(&server),
              sizeof(server)) == SOCKET_ERROR ||
          send(
              socketHandle,
              reinterpret_cast<const char*>(query.data()),
              static_cast<int>(query.size()),
              0) != static_cast<int>(query.size())) {
        if (WSAGetLastError() == WSAECONNREFUSED) outcome.connectionRefused = true;
        closesocket(socketHandle);
        continue;
      }
      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
      bool receivedFinal = false;
      while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - std::chrono::steady_clock::now());
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(remaining.count() / 1000000);
        timeout.tv_usec = static_cast<long>(remaining.count() % 1000000);
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(socketHandle, &readable);
        const int selected = select(0, &readable, nullptr, nullptr, &timeout);
        if (selected <= 0) break;
        const int received = recv(
            socketHandle,
            reinterpret_cast<char*>(response.data()),
            static_cast<int>(response.size()),
            0);
        if (received == SOCKET_ERROR) {
          if (WSAGetLastError() == WSAECONNREFUSED) outcome.connectionRefused = true;
          break;
        }
        if (received < 12 || readDnsU16(response.data()) != queryId ||
            (response[2] & 0x80) == 0) {
          continue;
        }
        outcome.rcode = response[3] & 0x0f;
        if ((response[2] & 0x02) != 0) {
          outcome.truncated = true;
          receivedFinal = true;
        } else if (outcome.rcode == 0 || outcome.rcode == 3) {
          response.resize(static_cast<size_t>(received));
          outcome.response = response;
          receivedFinal = true;
        }
        break;
      }
      closesocket(socketHandle);
      if (receivedFinal) return outcome;
    }
  }
  return outcome;
}

bool readWindowsDnsName(
    const std::vector<uint8_t>& packet,
    size_t offset,
    std::string& name,
    size_t& nextOffset) {
  name.clear();
  bool jumped = false;
  size_t cursor = offset;
  nextOffset = offset;
  for (size_t steps = 0; steps <= packet.size(); ++steps) {
    if (cursor >= packet.size()) return false;
    const uint8_t length = packet[cursor];
    if ((length & 0xc0) == 0xc0) {
      if (cursor + 1 >= packet.size()) return false;
      const size_t pointer =
          (static_cast<size_t>(length & 0x3f) << 8) | packet[cursor + 1];
      if (pointer >= packet.size()) return false;
      if (!jumped) nextOffset = cursor + 2;
      cursor = pointer;
      jumped = true;
      continue;
    }
    if ((length & 0xc0) != 0 || length > 63) return false;
    ++cursor;
    if (length == 0) {
      if (!jumped) nextOffset = cursor;
      return true;
    }
    if (cursor + length > packet.size()) return false;
    if (!name.empty()) name.push_back('.');
    name.append(reinterpret_cast<const char*>(packet.data() + cursor), length);
    cursor += length;
    if (!jumped) nextOffset = cursor;
  }
  return false;
}

bool appendWindowsDnsText(
    const std::vector<uint8_t>& packet,
    size_t end,
    size_t& offset,
    std::string& json) {
  if (offset >= end) return false;
  const size_t length = packet[offset++];
  if (offset + length > end) return false;
  if (!appendEscapedJsonText(json, packet.data() + offset, length)) return false;
  offset += length;
  return true;
}

WindowsDnsResult parseWindowsDnsResponse(
    const std::vector<uint8_t>& packet,
    const std::string& hostname,
    int qtype,
    const std::string& rrtype) {
  if (packet.size() < 12 || readDnsU16(packet.data() + 4) != 1) {
    return {false, "", "Invalid DNS response (EBADRESP)", "EBADRESP"};
  }
  const uint16_t flags = readDnsU16(packet.data() + 2);
  if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0 || (flags & 0x0200) != 0) {
    return {false, "", "Invalid DNS response flags (EBADRESP)", "EBADRESP"};
  }
  const int rcode = packet[3] & 0x0f;
  if (rcode != 0) {
    const std::string code = windowsDnsRcodeToErrorCode(rcode);
    return {false, "", "DNS query failed (" + code + ")", code};
  }
  size_t offset = 12;
  std::string questionName;
  size_t nextOffset = 0;
  if (!readWindowsDnsName(packet, offset, questionName, nextOffset) ||
      nextOffset + 4 > packet.size() || readDnsU16(packet.data() + nextOffset) != qtype ||
      readDnsU16(packet.data() + nextOffset + 2) != 1) {
    return {false, "", "Invalid DNS question (EBADRESP)", "EBADRESP"};
  }
  auto normalizeName = [](std::string value) {
    if (!value.empty() && value.back() == '.') value.pop_back();
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
      return static_cast<char>(std::tolower(byte));
    });
    return value;
  };
  if (normalizeName(questionName) != normalizeName(hostname)) {
    return {false, "", "DNS response question mismatch (EBADRESP)", "EBADRESP"};
  }
  offset = nextOffset + 4;
  const uint16_t answerCount = readDnsU16(packet.data() + 6);
  std::ostringstream json;
  json << '[';
  bool first = true;
  auto appendRecord = [&](const std::string& record) {
    if (!first) json << ',';
    first = false;
    json << record;
  };
  (void)rrtype;
  for (uint16_t index = 0; index < answerCount; ++index) {
    std::string owner;
    if (!readWindowsDnsName(packet, offset, owner, nextOffset) ||
        nextOffset + 10 > packet.size()) {
      return {false, "", "Truncated DNS record (EBADRESP)", "EBADRESP"};
    }
    const int recordType = readDnsU16(packet.data() + nextOffset);
    const uint16_t recordClass = readDnsU16(packet.data() + nextOffset + 2);
    const uint32_t ttl = readDnsU32(packet.data() + nextOffset + 4);
    const size_t dataLength = readDnsU16(packet.data() + nextOffset + 8);
    const size_t dataOffset = nextOffset + 10;
    const size_t dataEnd = dataOffset + dataLength;
    if (dataEnd > packet.size()) {
      return {false, "", "Truncated DNS record data (EBADRESP)", "EBADRESP"};
    }
    offset = dataEnd;
    if (recordClass != 1 || (qtype != 255 && recordType != qtype)) continue;
    if (recordType == 1 && dataLength == 4) {
      char address[INET_ADDRSTRLEN]{};
      IN_ADDR parsed{};
      std::memcpy(&parsed, packet.data() + dataOffset, 4);
      if (InetNtopA(AF_INET, &parsed, address, sizeof(address))) {
        std::string addressJson;
        appendEscapedJsonText(
            addressJson, reinterpret_cast<const uint8_t*>(address), std::strlen(address));
        appendRecord(addressJson);
      }
    } else if (recordType == 28 && dataLength == 16) {
      char address[INET6_ADDRSTRLEN]{};
      IN6_ADDR parsed{};
      std::memcpy(&parsed, packet.data() + dataOffset, 16);
      if (InetNtopA(AF_INET6, &parsed, address, sizeof(address))) {
        std::string addressJson;
        appendEscapedJsonText(
            addressJson, reinterpret_cast<const uint8_t*>(address), std::strlen(address));
        appendRecord(addressJson);
      }
    } else if (recordType == 15 && dataLength >= 3) {
      std::string exchange;
      size_t ignored = 0;
      if (!readWindowsDnsName(packet, dataOffset + 2, exchange, ignored)) continue;
      std::string exchangeJson;
      if (!appendEscapedJsonText(
              exchangeJson,
              reinterpret_cast<const uint8_t*>(exchange.data()),
              exchange.size())) continue;
      appendRecord(
          "{\"priority\":" + std::to_string(readDnsU16(packet.data() + dataOffset)) +
          ",\"exchange\":" + exchangeJson + "}");
    } else if (recordType == 16) {
      size_t textOffset = dataOffset;
      std::ostringstream texts;
      texts << '[';
      bool firstText = true;
      bool valid = true;
      while (textOffset < dataEnd) {
        std::string textJson;
        if (!appendWindowsDnsText(packet, dataEnd, textOffset, textJson)) {
          valid = false;
          break;
        }
        if (!firstText) texts << ',';
        firstText = false;
        texts << textJson;
      }
      if (valid) {
        texts << ']';
        appendRecord(texts.str());
      }
    } else if (recordType == 2 || recordType == 5 || recordType == 12) {
      std::string value;
      size_t ignored = 0;
      if (!readWindowsDnsName(packet, dataOffset, value, ignored)) continue;
      std::string valueJson;
      if (appendEscapedJsonText(
              valueJson,
              reinterpret_cast<const uint8_t*>(value.data()),
              value.size())) appendRecord(valueJson);
    } else if (recordType == 33 && dataLength >= 7) {
      std::string target;
      size_t ignored = 0;
      if (!readWindowsDnsName(packet, dataOffset + 6, target, ignored)) continue;
      std::string targetJson;
      if (!appendEscapedJsonText(
              targetJson,
              reinterpret_cast<const uint8_t*>(target.data()),
              target.size())) continue;
      appendRecord(
          "{\"priority\":" + std::to_string(readDnsU16(packet.data() + dataOffset)) +
          ",\"weight\":" + std::to_string(readDnsU16(packet.data() + dataOffset + 2)) +
          ",\"port\":" + std::to_string(readDnsU16(packet.data() + dataOffset + 4)) +
          ",\"name\":" + targetJson + "}");
    } else if (recordType == 6) {
      std::string nsname;
      std::string hostmaster;
      size_t soaOffset = 0;
      if (!readWindowsDnsName(packet, dataOffset, nsname, soaOffset) ||
          !readWindowsDnsName(packet, soaOffset, hostmaster, soaOffset) ||
          soaOffset + 20 != dataEnd) continue;
      std::string nsnameJson;
      std::string hostmasterJson;
      if (!appendEscapedJsonText(
              nsnameJson,
              reinterpret_cast<const uint8_t*>(nsname.data()),
              nsname.size()) ||
          !appendEscapedJsonText(
              hostmasterJson,
              reinterpret_cast<const uint8_t*>(hostmaster.data()),
              hostmaster.size())) continue;
      appendRecord(
          "{\"nsname\":" + nsnameJson + ",\"hostmaster\":" + hostmasterJson +
          ",\"serial\":" + std::to_string(readDnsU32(packet.data() + soaOffset)) +
          ",\"refresh\":" + std::to_string(readDnsU32(packet.data() + soaOffset + 4)) +
          ",\"retry\":" + std::to_string(readDnsU32(packet.data() + soaOffset + 8)) +
          ",\"expire\":" + std::to_string(readDnsU32(packet.data() + soaOffset + 12)) +
          ",\"minttl\":" + std::to_string(readDnsU32(packet.data() + soaOffset + 16)) + "}");
    } else if (recordType == 257 && dataLength >= 2) {
      const size_t tagLength = packet[dataOffset + 1];
      if (dataOffset + 2 + tagLength > dataEnd) continue;
      std::string tagJson;
      std::string valueJson;
      if (!appendEscapedJsonText(tagJson, packet.data() + dataOffset + 2, tagLength) ||
          !appendEscapedJsonText(
              valueJson,
              packet.data() + dataOffset + 2 + tagLength,
              dataEnd - dataOffset - 2 - tagLength)) continue;
      appendRecord(
          "{\"critical\":" + std::to_string(packet[dataOffset]) + "," + tagJson + ":" +
          valueJson + "}");
    } else if (recordType == 35 && dataLength >= 5) {
      size_t naptrOffset = dataOffset + 4;
      std::string flagsJson;
      std::string serviceJson;
      std::string regexpJson;
      if (!appendWindowsDnsText(packet, dataEnd, naptrOffset, flagsJson) ||
          !appendWindowsDnsText(packet, dataEnd, naptrOffset, serviceJson) ||
          !appendWindowsDnsText(packet, dataEnd, naptrOffset, regexpJson)) continue;
      std::string replacement;
      size_t ignored = 0;
      if (!readWindowsDnsName(packet, naptrOffset, replacement, ignored)) continue;
      std::string replacementJson;
      if (!appendEscapedJsonText(
              replacementJson,
              reinterpret_cast<const uint8_t*>(replacement.data()),
              replacement.size())) continue;
      appendRecord(
          "{\"flags\":" + flagsJson + ",\"service\":" + serviceJson +
          ",\"regexp\":" + regexpJson + ",\"replacement\":" + replacementJson +
          ",\"order\":" + std::to_string(readDnsU16(packet.data() + dataOffset)) +
          ",\"preference\":" + std::to_string(readDnsU16(packet.data() + dataOffset + 2)) +
          "}");
    }
    (void)ttl;
  }
  json << ']';
  return {true, json.str(), "", ""};
}

WindowsDnsResult resolveWindowsDnsRecords(
    const std::string& hostname,
    const std::string& rrtype) {
  ensureWinsock();
  const int qtype = windowsDnsRrtypeToQtype(rrtype);
  if (qtype < 0) {
    return {false, "", "Unsupported DNS record type (ENOTIMP)", "ENOTIMP"};
  }
  std::vector<sockaddr_in> servers;
  int timeoutSeconds = 5;
  int attempts = 2;
  loadWindowsDnsServers(servers, timeoutSeconds, attempts);
  if (servers.empty()) {
    return {false, "", "No usable DNS servers (ENOTFOUND)", "ENOTFOUND"};
  }
  static std::random_device randomDevice;
  const uint16_t id = static_cast<uint16_t>(randomDevice());
  std::vector<uint8_t> query;
  if (!buildWindowsDnsQuery(hostname, qtype, id, query)) {
    return {false, "", "Invalid DNS name (EBADNAME)", "EBADNAME"};
  }
  WindowsRawDnsOutcome outcome =
      sendWindowsDnsQuery(servers, timeoutSeconds, attempts, query);
  if (!outcome.response.empty()) {
    return parseWindowsDnsResponse(outcome.response, hostname, qtype, rrtype);
  }
  if (outcome.truncated) {
    return {false, "", "Truncated DNS response (EBADRESP)", "EBADRESP"};
  }
  if (outcome.rcode > 0) {
    const std::string code = windowsDnsRcodeToErrorCode(outcome.rcode);
    return {false, "", "DNS query failed (" + code + ")", code};
  }
  if (outcome.connectionRefused) {
    return {false, "", "DNS server refused connection (ECONNREFUSED)", "ECONNREFUSED"};
  }
  return {false, "", "DNS query timed out (ETIMEOUT)", "ETIMEOUT"};
}

void installDnsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto dnsGetServersFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsGetServers"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::String::createFromUtf8(runtime, windowsDnsServersJson());
      });
  rt.global().setProperty(rt, "__exactDnsGetServers", std::move(dnsGetServersFn));

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
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsLookup");
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
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsResolve");
        std::string rrtype = "A";
        if (count > 1 && args[1].isString()) {
          rrtype = args[1].toString(runtime).utf8(runtime);
        }
        if (rrtype != "A" && rrtype != "AAAA") {
          WindowsDnsResult resolved = resolveWindowsDnsRecords(hostname, rrtype);
          if (!resolved.ok) {
            throw facebook::jsi::JSError(runtime, resolved.error);
          }
          return facebook::jsi::String::createFromUtf8(runtime, resolved.payload);
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
          std::string ip = socketAddressText(storage);
          if (ip.empty()) continue;
          std::string escaped;
          appendEscapedJsonText(
              escaped,
              reinterpret_cast<const uint8_t*>(ip.data()),
              ip.size());
          if (!first) json << ',';
          first = false;
          json << escaped;
        }
        freeaddrinfo(result);
        json << ']';
        return facebook::jsi::String::createFromUtf8(runtime, json.str());
      });
  rt.global().setProperty(rt, "__exactDnsResolve", std::move(dnsResolveFn));

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // reverse DNS is target-absent on Windows. Do not publish a throw-only
  // callable: builtin feature detection would treat that as an available
  // backend, and branchless target evidence requires the global to be missing.
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

  auto spawnFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawn"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawn: file path required");
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
        std::string resultJson = spawnAsyncWindowsJson(file, spawnArgs, optsJson);
        return facebook::jsi::String::createFromUtf8(runtime, resultJson);
      });
  rt.global().setProperty(rt, "__exactSpawn", std::move(spawnFn));

  auto spawnReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return makeUint8Array(runtime, std::vector<uint8_t>());
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnRead");
        if (!proc) {
          return makeUint8Array(runtime, std::vector<uint8_t>());
        }

        std::string streamName;
        if (args[1].isNumber()) {
          int stream = static_cast<int>(args[1].asNumber());
          if (stream == 1) streamName = "stdout";
          else if (stream == 2) streamName = "stderr";
        } else if (args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        }

        if (streamName == "stdout") {
          return makeUint8Array(runtime, drainWindowsPipeBuffer(proc->stdoutBuffer));
        }
        if (streamName == "stderr") {
          return makeUint8Array(runtime, drainWindowsPipeBuffer(proc->stderrBuffer));
        }
        return makeUint8Array(runtime, std::vector<uint8_t>());
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(spawnReadFn));

  auto spawnWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnWrite");
        if (!proc) {
          return facebook::jsi::Value(-1);
        }
        std::string streamName = "stdin";
        if (count > 2 && args[2].isString()) {
          streamName = args[2].toString(runtime).utf8(runtime);
        }
        if (streamName != "stdin") {
          return facebook::jsi::Value(-1);
        }
        std::vector<uint8_t> bytes = jsiValueToBytes(runtime, args[1]);
        if (bytes.empty()) {
          return facebook::jsi::Value(0);
        }

        size_t accepted = 0;
        {
          std::lock_guard<std::mutex> lock(proc->stdinMutex);
          if (proc->stdinCloseRequested || !isValidHandle(proc->stdinWrite)) {
            return facebook::jsi::Value(-1);
          }
          size_t available = kWindowsSpawnStdinQueueBytes > proc->stdinQueuedBytes
              ? kWindowsSpawnStdinQueueBytes - proc->stdinQueuedBytes
              : 0;
          accepted = std::min(available, bytes.size());
          if (accepted > 0) {
            proc->stdinQueue.emplace_back(bytes.begin(), bytes.begin() + accepted);
            proc->stdinQueuedBytes += accepted;
          }
        }
        if (accepted > 0) proc->stdinCv.notify_one();
        // Zero is the same retry/backpressure contract as POSIX EAGAIN.
        return facebook::jsi::Value(static_cast<double>(accepted));
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(spawnWriteFn));

  auto spawnPollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::String::createFromUtf8(
              runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}");
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnPoll");
        if (!proc) {
          return facebook::jsi::String::createFromUtf8(
              runtime, "{\"exited\":true,\"exitCode\":-1,\"signal\":0}");
        }

        if (!proc->exited && isValidHandle(proc->process)) {
          DWORD wait = WaitForSingleObject(proc->process, 0);
          if (wait == WAIT_OBJECT_0) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(proc->process, &exitCode)) {
              proc->exitCode = static_cast<int>(exitCode);
            } else {
              proc->exitCode = -1;
            }
            proc->exited = true;
            requestWindowsStdinClose(proc, true, false);
          }
        }
        if (!proc->exited) {
          return facebook::jsi::String::createFromUtf8(
              runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}");
        }
        int reportedExit = proc->killedSignal ? -1 : proc->exitCode;
        std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(reportedExit)
            + ",\"signal\":" + std::to_string(proc->killedSignal) + "}";
        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(spawnPollFn));

  auto spawnKillFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnKill");
        if (!proc || !isValidHandle(proc->process)) {
          return facebook::jsi::Value(false);
        }
        int sig = count > 1 && args[1].isNumber() ? static_cast<int>(args[1].asNumber()) : 15;
        DWORD wait = WaitForSingleObject(proc->process, 0);
        if (wait == WAIT_OBJECT_0) {
          return facebook::jsi::Value(false);
        }
        if (sig == 0) {
          return facebook::jsi::Value(true);
        }
        BOOL ok = TerminateProcess(proc->process, 1);
        if (ok) {
          proc->killedSignal = sig;
          requestWindowsStdinClose(proc, true, false);
        }
        return facebook::jsi::Value(ok != FALSE);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(spawnKillFn));

  auto spawnSetReferencedFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSetReferenced"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isBool()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactSpawnSetReferenced: numeric handle and boolean state required");
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = requireWindowsSpawnProcessOwnership(
            runtime, handle, "__exactSpawnSetReferenced");
        bool updated = false;
        {
          std::lock_guard<std::mutex> lock(g_windows_spawn_mutex);
          auto it = g_windows_spawned_processes.find(handle);
          if (it != g_windows_spawned_processes.end() && it->second == proc) {
            proc->referenced = args[1].getBool();
            updated = true;
          }
        }
        return facebook::jsi::Value(updated);
      });
  rt.global().setProperty(
      rt, "__exactSpawnSetReferenced", std::move(spawnSetReferencedFn));

  auto spawnCloseStdinFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnCloseStdin");
        if (!proc) {
          return facebook::jsi::Value::undefined();
        }
        std::string streamName = "stdin";
        if (count > 1 && args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        }
        if (streamName == "stdin") {
          requestWindowsStdinClose(proc, false, false);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(spawnCloseStdinFn));

  auto spawnGetFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactSpawnGetFd", std::move(spawnGetFdFn));

  auto spawnDisposeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnDispose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = tryWindowsSpawnProcess(runtime, handle, "__exactSpawnDispose");
        if (!proc) {
          return facebook::jsi::Value::undefined();
        }
        {
          std::lock_guard<std::mutex> lock(g_windows_spawn_mutex);
          auto it = g_windows_spawned_processes.find(handle);
          if (it != g_windows_spawned_processes.end() && it->second == proc) {
            g_windows_spawned_processes.erase(it);
          } else {
            return facebook::jsi::Value::undefined();
          }
        }
        requestWindowsStdinClose(proc, true, true);
        closeHandleIfValid(proc->process);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnDispose", std::move(spawnDisposeFn));
}

void installNetOwnerHostFunction(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto netOwnerFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactNetOwner"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactNetOwner: action required");
        }
        const std::string action = args[0].asString(runtime).utf8(runtime);
        if (action == "new") {
          const uint64_t stamp = windowsNetOwnerStampForCurrentPrincipal();
          if (stamp == 0) {
            throw facebook::jsi::JSError(
                runtime, "__exactNetOwner: stamp allocation failed");
          }
          return facebook::jsi::Value(static_cast<double>(stamp));
        }
        if (action != "assert" || count < 2) {
          throw facebook::jsi::JSError(
              runtime, "__exactNetOwner: unsupported action");
        }
        requireWindowsNetOwnerStamp(runtime, args[1]);
        if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
          requireWindowsSocket(
              runtime, requireWindowsNetOwnerSocketHandle(runtime, args[2]),
              "__exactNetOwner", false);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactNetOwner", std::move(netOwnerFn));
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
        if (isIpv4MappedLiteral(host)) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactTcpConnect: IPv4-mapped IPv6 literals are not canonical; use IPv4");
        }
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
                runtime,
                static_cast<int>(args[0].asNumber()),
                "__exactTcpShutdown",
                entry,
                false)) {
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
                runtime,
                static_cast<int>(args[0].asNumber()),
                "__exactTcpReset",
                entry,
                false)) {
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
        if (isIpv4MappedLiteral(host)) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactTcpListen: IPv4-mapped IPv6 literals are not canonical; use IPv4");
        }
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
          if (item->ai_family == AF_INET6) {
            DWORD only = ipv6Only ? 1 : 0;
            if (setsockopt(
                    socket,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    reinterpret_cast<const char*>(&only),
                    sizeof(only)) != 0) {
              lastError = WSAGetLastError();
              closesocket(socket);
              socket = INVALID_SOCKET;
              continue;
            }
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

  // Unix-domain and UDP backends are likewise target-absent on Windows.
  // Publishing callable error stubs would defeat the builtins' feature
  // detection and cannot satisfy an absent CapSec target cell.

  // Native TLS bridge (ENG-23526): these shims ride the Windows TCP globals
  // above and are driven from src/builtins/tls.js just like the Unix bridge.
  installTlsHostFunctions(handle);
}

extern "C" int ex_hermes_debugger_enable(ExactHermesRuntime* runtime) {
  (void)runtime;
  return 0;
}

extern "C" char* ex_hermes_debugger_get_scripts(ExactHermesRuntime* runtime) {
  (void)runtime;
  // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
  // the no-debugger target must not return even an empty debugger data shape.
  return nullptr;
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
