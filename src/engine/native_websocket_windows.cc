#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

typedef void (*NativeWsOpenCallback)(
    uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(
    uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(
    uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

extern "C" void native_ws_retain_context(void* context);
extern "C" void native_ws_release_context(void* context);

namespace {

struct WebSocketEntry {
  uint32_t ws_id = 0;
  HINTERNET session = nullptr;
  HINTERNET connect = nullptr;
  HINTERNET request = nullptr;
  HINTERNET websocket = nullptr;

  NativeWsOpenCallback open_cb = nullptr;
  NativeWsMessageCallback message_cb = nullptr;
  NativeWsCloseCallback close_cb = nullptr;
  NativeWsErrorCallback error_cb = nullptr;
  NativeWsBytesSentCallback bytes_sent_cb = nullptr;
  void* context = nullptr;

  std::mutex handle_mutex;
  std::mutex send_mutex;
  std::atomic<bool> closed{false};
  std::atomic<bool> receive_paused{false};
  std::atomic<bool> flow_controlled_receive{false};
};

std::mutex g_ws_mutex;
std::unordered_map<uint32_t, std::shared_ptr<WebSocketEntry>> g_ws_connections;
std::atomic<uint32_t> g_next_ws_id{1};

std::wstring utf8ToWide(const std::string& input) {
  if (input.empty()) return std::wstring();
  int len = MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
  if (len <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), len);
  return out;
}

std::string lastErrorString(const char* operation, DWORD error = GetLastError()) {
  return std::string(operation) + " failed with Windows error " + std::to_string(error);
}

bool hasPrefix(const std::string& value, const char* prefix) {
  const size_t len = std::strlen(prefix);
  return value.size() >= len && value.compare(0, len, prefix) == 0;
}

std::string websocketUrlToHttpUrl(const char* raw_url) {
  if (!raw_url) return std::string();
  std::string url(raw_url);
  if (hasPrefix(url, "ws://")) {
    return "http://" + url.substr(5);
  }
  if (hasPrefix(url, "wss://")) {
    return "https://" + url.substr(6);
  }
  return std::string();
}

bool parseUrl(
    const std::string& url,
    std::wstring& host,
    INTERNET_PORT& port,
    std::wstring& path,
    bool& secure) {
  std::wstring wide_url = utf8ToWide(url);
  if (wide_url.empty()) return false;

  URL_COMPONENTS components = {};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  if (!WinHttpCrackUrl(wide_url.c_str(), static_cast<DWORD>(wide_url.size()), 0, &components)) {
    return false;
  }
  if (components.nScheme != INTERNET_SCHEME_HTTP && components.nScheme != INTERNET_SCHEME_HTTPS) {
    return false;
  }

  host.assign(components.lpszHostName, components.dwHostNameLength);
  port = components.nPort;
  secure = components.nScheme == INTERNET_SCHEME_HTTPS;
  path.assign(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.lpszExtraInfo && components.dwExtraInfoLength > 0) {
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
  }
  if (path.empty()) path = L"/";
  return !host.empty();
}

bool isLoopbackHost(const std::wstring& host) {
  return host == L"localhost" || host == L"127.0.0.1" || host == L"::1" || host == L"[::1]";
}

void closeHandles(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return;
  std::lock_guard<std::mutex> lock(entry->handle_mutex);
  HINTERNET websocket = entry->websocket;
  HINTERNET request = entry->request;
  HINTERNET connect = entry->connect;
  HINTERNET session = entry->session;
  entry->websocket = nullptr;
  entry->request = nullptr;
  entry->connect = nullptr;
  entry->session = nullptr;
  if (websocket) WinHttpCloseHandle(websocket);
  if (request) WinHttpCloseHandle(request);
  if (connect) WinHttpCloseHandle(connect);
  if (session) WinHttpCloseHandle(session);
}

void call_error(const std::shared_ptr<WebSocketEntry>& entry, const char* message) {
  if (!entry || !entry->error_cb || !entry->context) return;
  native_ws_retain_context(entry->context);
  entry->error_cb(entry->ws_id, message ? message : "WebSocket error", entry->context);
  native_ws_release_context(entry->context);
}

void call_open(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry || !entry->open_cb || !entry->context) return;
  native_ws_retain_context(entry->context);
  entry->open_cb(entry->ws_id, "", "", entry->context);
  native_ws_release_context(entry->context);
}

void call_message(
    const std::shared_ptr<WebSocketEntry>& entry,
    const uint8_t* data,
    size_t len,
    bool is_text) {
  if (!entry || !entry->message_cb || !entry->context) return;
  native_ws_retain_context(entry->context);
  entry->message_cb(entry->ws_id, data, len, is_text ? 1 : 0, entry->context);
  native_ws_release_context(entry->context);
}

void call_close(
    const std::shared_ptr<WebSocketEntry>& entry,
    uint16_t code,
    const char* reason,
    int was_clean) {
  if (!entry || !entry->close_cb || !entry->context) return;
  native_ws_retain_context(entry->context);
  entry->close_cb(entry->ws_id, code, reason ? reason : "", was_clean, entry->context);
  native_ws_release_context(entry->context);
}

void call_bytes_sent(const std::shared_ptr<WebSocketEntry>& entry, size_t bytes_sent) {
  if (!entry || !entry->bytes_sent_cb || !entry->context) return;
  native_ws_retain_context(entry->context);
  entry->bytes_sent_cb(entry->ws_id, bytes_sent, entry->context);
  native_ws_release_context(entry->context);
}

void releaseContext(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry || !entry->context) return;
  native_ws_release_context(entry->context);
  entry->context = nullptr;
}

void remove_connection(uint32_t ws_id) {
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
    g_ws_connections.erase(it);
  }
  if (!entry) return;
  entry->closed.store(true, std::memory_order_relaxed);
  closeHandles(entry);
  releaseContext(entry);
}

HINTERNET entryWebSocket(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return nullptr;
  std::lock_guard<std::mutex> lock(entry->handle_mutex);
  return entry->websocket;
}

void receive_loop(const std::shared_ptr<WebSocketEntry>& entry) {
  call_open(entry);

  std::vector<uint8_t> message;
  bool message_is_text = false;

  while (entry && !entry->closed.load(std::memory_order_relaxed)) {
    if (entry->receive_paused.load(std::memory_order_relaxed)) {
      Sleep(10);
      continue;
    }

    HINTERNET websocket = entryWebSocket(entry);
    if (!websocket) break;

    uint8_t buffer[64 * 1024];
    DWORD bytes_read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    DWORD rc = WinHttpWebSocketReceive(
        websocket,
        buffer,
        static_cast<DWORD>(sizeof(buffer)),
        &bytes_read,
        &buffer_type);

    if (rc != NO_ERROR) {
      if (!entry->closed.load(std::memory_order_relaxed)) {
        auto message_text = lastErrorString("WinHttpWebSocketReceive", rc);
        call_error(entry, message_text.c_str());
        call_close(entry, 1006, "Connection error", 0);
      }
      break;
    }

    if (buffer_type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
      USHORT status = 1005;
      char reason[256] = {};
      DWORD reason_used = 0;
      DWORD close_rc = WinHttpWebSocketQueryCloseStatus(
          websocket,
          &status,
          reason,
          sizeof(reason) - 1,
          &reason_used);
      if (close_rc != NO_ERROR) {
        status = 1005;
        reason[0] = '\0';
      } else if (reason_used < sizeof(reason)) {
        reason[reason_used] = '\0';
      } else {
        reason[sizeof(reason) - 1] = '\0';
      }
      call_close(entry, status, reason, 1);
      break;
    }

    const bool is_text =
        buffer_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
        buffer_type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE;
    const bool is_fragment =
        buffer_type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE ||
        buffer_type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE;

    if (message.empty()) {
      message_is_text = is_text;
    }
    if (bytes_read > 0) {
      message.insert(message.end(), buffer, buffer + bytes_read);
    }
    if (is_fragment) {
      continue;
    }

    if (entry->flow_controlled_receive.load(std::memory_order_relaxed)) {
      entry->receive_paused.store(true, std::memory_order_relaxed);
    }
    call_message(entry, message.data(), message.size(), message_is_text);
    message.clear();
  }

  remove_connection(entry->ws_id);
}

void send_initial_error(
    NativeWsErrorCallback error_cb,
    void* context,
    const char* message) {
  if (!error_cb || !context) return;
  native_ws_retain_context(context);
  error_cb(0, message ? message : "WebSocket connection failed", context);
  native_ws_release_context(context);
}

} // namespace

extern "C" uint32_t native_ws_connect(
    const char* url,
    const char* protocols,
    NativeWsOpenCallback open_cb,
    NativeWsMessageCallback message_cb,
    NativeWsCloseCallback close_cb,
    NativeWsErrorCallback error_cb,
    NativeWsBytesSentCallback bytes_sent_cb,
    void* context) {
  if (!url || !open_cb || !message_cb || !close_cb || !error_cb) {
    return 0;
  }

  std::string http_url = websocketUrlToHttpUrl(url);
  if (http_url.empty()) {
    send_initial_error(error_cb, context, "Invalid WebSocket URL");
    return 0;
  }

  std::wstring host;
  INTERNET_PORT port = 0;
  std::wstring path;
  bool secure = false;
  if (!parseUrl(http_url, host, port, path, secure)) {
    send_initial_error(error_cb, context, "Invalid WebSocket URL");
    return 0;
  }

  auto entry = std::make_shared<WebSocketEntry>();
  entry->ws_id = g_next_ws_id.fetch_add(1, std::memory_order_relaxed);
  entry->open_cb = open_cb;
  entry->message_cb = message_cb;
  entry->close_cb = close_cb;
  entry->error_cb = error_cb;
  entry->bytes_sent_cb = bytes_sent_cb;
  entry->context = context;
  if (entry->context) {
    native_ws_retain_context(entry->context);
  }

  DWORD access_type =
      isLoopbackHost(host) ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
  entry->session = WinHttpOpen(
      L"Exact/0.1",
      access_type,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS,
      0);
  if (!entry->session) {
    auto msg = lastErrorString("WinHttpOpen");
    send_initial_error(error_cb, context, msg.c_str());
    releaseContext(entry);
    return 0;
  }
  WinHttpSetTimeouts(entry->session, 30000, 30000, 30000, 300000);

  std::wstring connect_host = host == L"127.0.0.1" ? L"localhost" : host;
  entry->connect = WinHttpConnect(entry->session, connect_host.c_str(), port, 0);
  if (!entry->connect) {
    auto msg = lastErrorString("WinHttpConnect");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  DWORD request_flags = secure ? WINHTTP_FLAG_SECURE : 0;
  entry->request = WinHttpOpenRequest(
      entry->connect,
      L"GET",
      path.c_str(),
      nullptr,
      WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      request_flags);
  if (!entry->request) {
    auto msg = lastErrorString("WinHttpOpenRequest");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  if (protocols && *protocols) {
    std::wstring header = L"Sec-WebSocket-Protocol: ";
    header += utf8ToWide(protocols);
    header += L"\r\n";
    WinHttpAddRequestHeaders(
        entry->request,
        header.c_str(),
        static_cast<DWORD>(-1),
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
  }

  if (!WinHttpSetOption(entry->request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
    auto msg = lastErrorString("WinHttpSetOption(UPGRADE_TO_WEB_SOCKET)");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  if (!WinHttpSendRequest(
          entry->request,
          WINHTTP_NO_ADDITIONAL_HEADERS,
          0,
          WINHTTP_NO_REQUEST_DATA,
          0,
          0,
          0)) {
    auto msg = lastErrorString("WinHttpSendRequest");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  if (!WinHttpReceiveResponse(entry->request, nullptr)) {
    auto msg = lastErrorString("WinHttpReceiveResponse");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  DWORD status_code = 0;
  DWORD status_size = sizeof(status_code);
  if (WinHttpQueryHeaders(
          entry->request,
          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
          WINHTTP_HEADER_NAME_BY_INDEX,
          &status_code,
          &status_size,
          WINHTTP_NO_HEADER_INDEX) &&
      status_code != 101) {
    std::string msg = "WebSocket upgrade failed with HTTP status " + std::to_string(status_code);
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }

  entry->websocket = WinHttpWebSocketCompleteUpgrade(entry->request, 0);
  if (!entry->websocket) {
    auto msg = lastErrorString("WinHttpWebSocketCompleteUpgrade");
    send_initial_error(error_cb, context, msg.c_str());
    closeHandles(entry);
    releaseContext(entry);
    return 0;
  }
  WinHttpCloseHandle(entry->request);
  entry->request = nullptr;

  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    g_ws_connections[entry->ws_id] = entry;
  }

  std::thread([entry]() { receive_loop(entry); }).detach();
  return entry->ws_id;
}

extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text) {
  if (!data || length == 0) return;
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (!entry || entry->closed.load(std::memory_order_relaxed)) return;

  HINTERNET websocket = entryWebSocket(entry);
  if (!websocket) return;

  std::lock_guard<std::mutex> lock(entry->send_mutex);
  WINHTTP_WEB_SOCKET_BUFFER_TYPE type = is_text
      ? WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE
      : WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
  DWORD rc = WinHttpWebSocketSend(
      websocket,
      type,
      const_cast<uint8_t*>(data),
      static_cast<DWORD>(length));
  if (rc != NO_ERROR) {
    auto msg = lastErrorString("WinHttpWebSocketSend", rc);
    call_error(entry, msg.c_str());
    return;
  }
  call_bytes_sent(entry, length);
}

extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason) {
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (!entry || entry->closed.exchange(true, std::memory_order_relaxed)) return;

  HINTERNET websocket = entryWebSocket(entry);
  if (websocket) {
    std::lock_guard<std::mutex> lock(entry->send_mutex);
    WinHttpWebSocketClose(
        websocket,
        code == 1005 ? WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS : code,
        const_cast<char*>(reason ? reason : ""),
        reason ? static_cast<DWORD>(std::strlen(reason)) : 0);
  }
  call_close(entry, code == 1005 ? 1000 : code, reason ? reason : "", 1);
  remove_connection(ws_id);
}

extern "C" void native_ws_pause(uint32_t ws_id) {
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (entry) entry->receive_paused.store(true, std::memory_order_relaxed);
}

extern "C" void native_ws_resume(uint32_t ws_id) {
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (entry) entry->receive_paused.store(false, std::memory_order_relaxed);
}

extern "C" void native_ws_set_flow_controlled(uint32_t ws_id, int enabled) {
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (entry) entry->flow_controlled_receive.store(enabled != 0, std::memory_order_relaxed);
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
  remove_connection(ws_id);
}

extern "C" int native_ws_has_active(void) {
  std::lock_guard<std::mutex> lock(g_ws_mutex);
  for (const auto& pair : g_ws_connections) {
    const auto& entry = pair.second;
    if (entry && !entry->closed.load(std::memory_order_relaxed)) {
      return 1;
    }
  }
  return 0;
}
