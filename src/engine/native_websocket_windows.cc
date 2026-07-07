#ifndef NOMINMAX
#define NOMINMAX
#endif
// @ref LLP 0003#the-platform-shims-map — Windows WebSocket uses WinHTTP's
// native HTTP upgrade/WebSocket API.
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
  // Guards reads/nulling of `context` so a callback's snapshot+retain is
  // atomic against the teardown release; without it a receive-thread
  // callback can retain a context whose final release (and scheduled
  // delete) already happened on the closing thread.
  std::mutex context_mutex;
  std::atomic<bool> close_requested{false};
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
  // Serialize with in-flight WinHttpWebSocketSend/Close (send_mutex before
  // handle_mutex everywhere): a handle must not be closed -- and its value
  // possibly recycled by an unrelated connection -- under a live send.
  std::lock_guard<std::mutex> send_lock(entry->send_mutex);
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

// Snapshots and retains the callback context atomically against the
// teardown release in releaseContext. The caller must balance a non-null
// return with native_ws_release_context.
void* acquireContext(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return nullptr;
  std::lock_guard<std::mutex> lock(entry->context_mutex);
  if (!entry->context) return nullptr;
  native_ws_retain_context(entry->context);
  return entry->context;
}

void call_error(const std::shared_ptr<WebSocketEntry>& entry, const char* message) {
  if (!entry || !entry->error_cb) return;
  void* ctx = acquireContext(entry);
  if (!ctx) return;
  entry->error_cb(entry->ws_id, message ? message : "WebSocket error", ctx);
  native_ws_release_context(ctx);
}

void call_open(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry || !entry->open_cb) return;
  void* ctx = acquireContext(entry);
  if (!ctx) return;
  entry->open_cb(entry->ws_id, "", "", ctx);
  native_ws_release_context(ctx);
}

void call_message(
    const std::shared_ptr<WebSocketEntry>& entry,
    const uint8_t* data,
    size_t len,
    bool is_text) {
  if (!entry || !entry->message_cb) return;
  void* ctx = acquireContext(entry);
  if (!ctx) return;
  entry->message_cb(entry->ws_id, data, len, is_text ? 1 : 0, ctx);
  native_ws_release_context(ctx);
}

void call_close(
    const std::shared_ptr<WebSocketEntry>& entry,
    uint16_t code,
    const char* reason,
    int was_clean) {
  if (!entry || !entry->close_cb) return;
  void* ctx = acquireContext(entry);
  if (!ctx) return;
  entry->close_cb(entry->ws_id, code, reason ? reason : "", was_clean, ctx);
  native_ws_release_context(ctx);
}

void call_bytes_sent(const std::shared_ptr<WebSocketEntry>& entry, size_t bytes_sent) {
  if (!entry || !entry->bytes_sent_cb) return;
  void* ctx = acquireContext(entry);
  if (!ctx) return;
  entry->bytes_sent_cb(entry->ws_id, bytes_sent, ctx);
  native_ws_release_context(ctx);
}

void releaseContext(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return;
  void* ctx = nullptr;
  {
    std::lock_guard<std::mutex> lock(entry->context_mutex);
    ctx = entry->context;
    entry->context = nullptr;
  }
  if (ctx) native_ws_release_context(ctx);
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
  bool upgraded = false;
  {
    std::lock_guard<std::mutex> lock(entry->handle_mutex);
    upgraded = entry->websocket != nullptr;
  }
  if (upgraded) {
    closeHandles(entry);
  }
  // Not upgraded: the handshake thread still owns session/connect/request
  // and closes them itself once it observes `closed` -- closing them here
  // would yank handles out from under its blocking synchronous WinHTTP
  // calls (documented as unpredictable) and risk the OS recycling the
  // handle values into an unrelated connection.
  releaseContext(entry);
}

HINTERNET entryWebSocket(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return nullptr;
  std::lock_guard<std::mutex> lock(entry->handle_mutex);
  return entry->websocket;
}

void receive_loop(const std::shared_ptr<WebSocketEntry>& entry) {
  if (!entry) return;
  if (entry->closed.load(std::memory_order_relaxed)) {
    // A concurrent close()/destroy raced the end of the handshake; it
    // already reported closure, so deliver no open event.
    remove_connection(entry->ws_id);
    closeHandles(entry);
    return;
  }
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
      if (!entry->closed.load(std::memory_order_relaxed) &&
          !entry->close_requested.load(std::memory_order_relaxed)) {
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
    call_message(
        entry,
        message.empty() ? reinterpret_cast<const uint8_t*>("") : message.data(),
        message.size(),
        message_is_text);
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

// Reports an async connect failure (mirroring the macOS delegate's
// connection-failure path: error callback, then close with 1006/unclean),
// unless a concurrent close()/destroy already reported closure.
void fail_connect(const std::shared_ptr<WebSocketEntry>& entry, const std::string& message) {
  if (!entry->closed.exchange(true, std::memory_order_relaxed)) {
    call_error(entry, message.c_str());
    call_close(entry, 1006, message.c_str(), 0);
  }
  remove_connection(entry->ws_id);
  // Pre-upgrade handles belong to this (handshake) thread; remove_connection
  // intentionally leaves them alone, so dispose of them here.
  closeHandles(entry);
}

// Stores a handle produced during the async handshake into the entry unless
// the socket was concurrently closed/destroyed. On false the caller must
// dispose of the handle and abandon the handshake (the closer already fired
// the close callback and cleaned up).
bool adopt_handshake_handle(
    const std::shared_ptr<WebSocketEntry>& entry,
    HINTERNET WebSocketEntry::*slot,
    HINTERNET value) {
  std::lock_guard<std::mutex> lock(entry->handle_mutex);
  if (entry->closed.load(std::memory_order_relaxed)) {
    return false;
  }
  (*entry).*slot = value;
  return true;
}

// Runs on a detached thread: the WinHTTP connect/upgrade handshake is fully
// synchronous (this session has no WINHTTP_FLAG_ASYNC), so running it on the
// JS thread stalled the entire event loop for the handshake RTT -- ~30s for
// an unreachable host. WHATWG requires connection establishment to run "in
// parallel"; macOS is fully async already. Handles are published to the
// entry as they are created so a concurrent close()/destroy can cancel the
// blocking WinHTTP calls by closing them.
// @ref LLP 0003#websocket-bridge-threading-and-context-ownership — connect
// returns immediately; the handshake must not block the JS thread
void run_connect_handshake(
    const std::shared_ptr<WebSocketEntry>& entry,
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    bool secure,
    const std::string& protocols) {
  DWORD access_type =
      isLoopbackHost(host) ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
  HINTERNET session = WinHttpOpen(
      L"Exact/0.1",
      access_type,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS,
      0);
  if (!session) {
    fail_connect(entry, lastErrorString("WinHttpOpen"));
    return;
  }
  if (!adopt_handshake_handle(entry, &WebSocketEntry::session, session)) {
    WinHttpCloseHandle(session);
    closeHandles(entry);
    return;
  }
  WinHttpSetTimeouts(session, 30000, 30000, 30000, 300000);

  std::wstring connect_host = host == L"127.0.0.1" ? L"localhost" : host;
  HINTERNET connect = WinHttpConnect(session, connect_host.c_str(), port, 0);
  if (!connect) {
    fail_connect(entry, lastErrorString("WinHttpConnect"));
    return;
  }
  if (!adopt_handshake_handle(entry, &WebSocketEntry::connect, connect)) {
    WinHttpCloseHandle(connect);
    closeHandles(entry);
    return;
  }

  DWORD request_flags = secure ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET request = WinHttpOpenRequest(
      connect,
      L"GET",
      path.c_str(),
      nullptr,
      WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      request_flags);
  if (!request) {
    fail_connect(entry, lastErrorString("WinHttpOpenRequest"));
    return;
  }
  if (!adopt_handshake_handle(entry, &WebSocketEntry::request, request)) {
    WinHttpCloseHandle(request);
    closeHandles(entry);
    return;
  }

  if (!protocols.empty()) {
    std::wstring header = L"Sec-WebSocket-Protocol: ";
    header += utf8ToWide(protocols);
    header += L"\r\n";
    WinHttpAddRequestHeaders(
        request,
        header.c_str(),
        static_cast<DWORD>(-1),
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
  }

  if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
    fail_connect(entry, lastErrorString("WinHttpSetOption(UPGRADE_TO_WEB_SOCKET)"));
    return;
  }

  if (!WinHttpSendRequest(
          request,
          WINHTTP_NO_ADDITIONAL_HEADERS,
          0,
          WINHTTP_NO_REQUEST_DATA,
          0,
          0,
          0)) {
    fail_connect(entry, lastErrorString("WinHttpSendRequest"));
    return;
  }

  if (!WinHttpReceiveResponse(request, nullptr)) {
    fail_connect(entry, lastErrorString("WinHttpReceiveResponse"));
    return;
  }

  DWORD status_code = 0;
  DWORD status_size = sizeof(status_code);
  if (WinHttpQueryHeaders(
          request,
          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
          WINHTTP_HEADER_NAME_BY_INDEX,
          &status_code,
          &status_size,
          WINHTTP_NO_HEADER_INDEX) &&
      status_code != 101) {
    fail_connect(
        entry, "WebSocket upgrade failed with HTTP status " + std::to_string(status_code));
    return;
  }

  HINTERNET websocket = WinHttpWebSocketCompleteUpgrade(request, 0);
  if (!websocket) {
    fail_connect(entry, lastErrorString("WinHttpWebSocketCompleteUpgrade"));
    return;
  }
  if (!adopt_handshake_handle(entry, &WebSocketEntry::websocket, websocket)) {
    WinHttpCloseHandle(websocket);
    closeHandles(entry);
    return;
  }
  {
    std::lock_guard<std::mutex> lock(entry->handle_mutex);
    if (entry->request) {
      WinHttpCloseHandle(entry->request);
      entry->request = nullptr;
    }
  }

  receive_loop(entry);
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
  // Adopt the caller's reference: the bridge creates the context with
  // ref_count == 1 and transfers ownership when a nonzero ws_id is returned
  // (remove_connection performs the balancing release). An extra retain here
  // leaked the context -- and the JS WebSocket instance it pins -- on every
  // successful connection.
  // @ref LLP 0003#websocket-bridge-threading-and-context-ownership — ownership
  // transfers on nonzero ws_id; never retain at connect
  entry->context = context;

  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    g_ws_connections[entry->ws_id] = entry;
  }

  std::string protocol_list = protocols ? protocols : "";
  std::thread([entry, host, port, path, secure, protocol_list]() {
    run_connect_handshake(entry, host, port, path, secure, protocol_list);
  }).detach();
  return entry->ws_id;
}

extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text) {
  // Zero-length payloads are valid WebSocket frames (WHATWG: send('') and
  // send(new Uint8Array(0)) transmit empty frames the peer observes).
  // WinHttpWebSocketSend accepts a null buffer only when the length is 0.
  if (!data && length > 0) return;
  std::shared_ptr<WebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) return;
    entry = it->second;
  }
  if (!entry || entry->closed.load(std::memory_order_relaxed) ||
      entry->close_requested.load(std::memory_order_relaxed)) {
    return;
  }

  // Hold send_mutex across the handle read AND the send: closeHandles
  // acquires send_mutex before closing, so the handle cannot be closed (and
  // its value recycled) while WinHttpWebSocketSend is using it.
  std::lock_guard<std::mutex> lock(entry->send_mutex);
  HINTERNET websocket = nullptr;
  {
    std::lock_guard<std::mutex> handle_lock(entry->handle_mutex);
    websocket = entry->websocket;
  }
  if (!websocket) return;

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
  if (!entry || entry->closed.load(std::memory_order_relaxed) ||
      entry->close_requested.exchange(true, std::memory_order_relaxed)) {
    return;
  }

  HINTERNET websocket = entryWebSocket(entry);
  if (websocket) {
    const uint16_t close_code = code;
    const std::string reason_copy = reason ? reason : "";
    NativeWsCloseCallback close_cb = entry->close_cb;
    void* close_context = acquireContext(entry);
    std::thread([entry, close_code, reason_copy, close_cb, close_context]() {
      // WinHttpWebSocketClose is synchronous for this session and can wait
      // for the peer close frame. Run it off the JS thread while preserving
      // send/close serialization against handle teardown.
      // @ref LLP 0003#websocket-bridge-threading-and-context-ownership — native
      // close handshakes must not block the runtime thread
      const bool already_closed = entry->closed.exchange(true, std::memory_order_relaxed);
      if (!already_closed) {
        HINTERNET active_websocket = entryWebSocket(entry);
        if (active_websocket) {
          std::lock_guard<std::mutex> lock(entry->send_mutex);
          WinHttpWebSocketClose(
              active_websocket,
              close_code == 1005 ? WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS : close_code,
              const_cast<char*>(reason_copy.c_str()),
              static_cast<DWORD>(reason_copy.size()));
        }
      }
      if (close_cb && close_context) {
        close_cb(
            entry->ws_id,
            close_code == 1005 ? 1000 : close_code,
            reason_copy.c_str(),
            1,
            close_context);
      }
      if (close_context) {
        native_ws_release_context(close_context);
      }
      remove_connection(entry->ws_id);
    }).detach();
    return;
  } else {
    // close() while still CONNECTING: fail the connection per WHATWG --
    // error event, then an unclean 1006 close. The handshake thread
    // observes `closed`, abandons the upgrade, and disposes of its own
    // handles.
    entry->closed.store(true, std::memory_order_relaxed);
    call_error(entry, "WebSocket was closed before the connection was established");
    call_close(entry, 1006, "", 0);
  }
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
