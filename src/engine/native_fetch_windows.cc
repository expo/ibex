#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

typedef void (*NativeFetchResponseCallback)(
    uint32_t request_id,
    int status,
    const char* status_text,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    void* context);

namespace {

struct RequestState {
  uint32_t request_id = 0;
  HINTERNET session = nullptr;
  HINTERNET connect = nullptr;
  HINTERNET request = nullptr;
  std::atomic<bool> cancelled{false};
};

std::mutex g_requests_mutex;
std::unordered_map<uint32_t, std::shared_ptr<RequestState>> g_requests;

std::wstring utf8ToWide(const std::string& input) {
  if (input.empty()) return std::wstring();
  int len = MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
  if (len <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), len);
  return out;
}

std::string wideToUtf8(const wchar_t* data, size_t len) {
  if (!data || len == 0) return std::string();
  int out_len = WideCharToMultiByte(CP_UTF8, 0, data, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
  if (out_len <= 0) return std::string();
  std::string out(static_cast<size_t>(out_len), '\0');
  WideCharToMultiByte(CP_UTF8, 0, data, static_cast<int>(len), out.data(), out_len, nullptr, nullptr);
  return out;
}

std::string lastErrorString(const char* operation) {
  std::ostringstream out;
  out << operation << " failed with Windows error " << GetLastError();
  return out.str();
}

void closeHandles(const std::shared_ptr<RequestState>& state) {
  if (!state) return;
  HINTERNET request = state->request;
  HINTERNET connect = state->connect;
  HINTERNET session = state->session;
  state->request = nullptr;
  state->connect = nullptr;
  state->session = nullptr;
  if (request) WinHttpCloseHandle(request);
  if (connect) WinHttpCloseHandle(connect);
  if (session) WinHttpCloseHandle(session);
}

void removeRequest(uint32_t request_id) {
  std::lock_guard<std::mutex> lock(g_requests_mutex);
  g_requests.erase(request_id);
}

void sendError(
    const std::shared_ptr<RequestState>& state,
    const std::string& message,
    NativeFetchResponseCallback callback,
    void* context) {
  if (!state || state->cancelled.load(std::memory_order_relaxed) || !callback) {
    return;
  }
  callback(state->request_id, 0, message.c_str(), nullptr, nullptr, 0, context);
}

bool parseUrl(
    const std::string& url,
    std::wstring& host,
    INTERNET_PORT& port,
    std::wstring& path,
    bool& secure) {
  std::wstring wide_url = utf8ToWide(url);
  if (wide_url.empty()) {
    return false;
  }

  URL_COMPONENTS components = {};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  if (!WinHttpCrackUrl(
          wide_url.c_str(),
          static_cast<DWORD>(wide_url.size()),
          0,
          &components)) {
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
  if (path.empty()) {
    path = L"/";
  }
  return !host.empty();
}

std::string queryHeaders(HINTERNET request, DWORD query) {
  DWORD size = 0;
  WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
    return std::string();
  }
  std::vector<wchar_t> buffer((size / sizeof(wchar_t)) + 1);
  if (!WinHttpQueryHeaders(
          request,
          query,
          WINHTTP_HEADER_NAME_BY_INDEX,
          buffer.data(),
          &size,
          WINHTTP_NO_HEADER_INDEX)) {
    return std::string();
  }
  return wideToUtf8(buffer.data(), size / sizeof(wchar_t));
}

void performFetch(
    std::shared_ptr<RequestState> state,
    std::string method,
    std::string url,
    std::string headers,
    int decompress,
    std::vector<uint8_t> body,
    NativeFetchResponseCallback callback,
    void* context) {
  (void)decompress;

  auto finish = [&]() {
    closeHandles(state);
    removeRequest(state->request_id);
  };

  std::wstring host;
  INTERNET_PORT port = 0;
  std::wstring path;
  bool secure = false;
  if (!parseUrl(url, host, port, path, secure)) {
    sendError(state, "Invalid URL", callback, context);
    finish();
    return;
  }

  state->session = WinHttpOpen(
      L"Exact/0.1",
      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS,
      0);
  if (!state->session) {
    sendError(state, lastErrorString("WinHttpOpen"), callback, context);
    finish();
    return;
  }
  WinHttpSetTimeouts(state->session, 30000, 30000, 30000, 300000);

  state->connect = WinHttpConnect(state->session, host.c_str(), port, 0);
  if (!state->connect) {
    sendError(state, lastErrorString("WinHttpConnect"), callback, context);
    finish();
    return;
  }

  std::wstring wide_method = utf8ToWide(method.empty() ? "GET" : method);
  DWORD request_flags = secure ? WINHTTP_FLAG_SECURE : 0;
  state->request = WinHttpOpenRequest(
      state->connect,
      wide_method.c_str(),
      path.c_str(),
      nullptr,
      WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      request_flags);
  if (!state->request) {
    sendError(state, lastErrorString("WinHttpOpenRequest"), callback, context);
    finish();
    return;
  }

  DWORD disabled_features = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
  WinHttpSetOption(
      state->request,
      WINHTTP_OPTION_DISABLE_FEATURE,
      &disabled_features,
      sizeof(disabled_features));

#if defined(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL) && defined(WINHTTP_PROTOCOL_FLAG_HTTP2)
  DWORD protocols = WINHTTP_PROTOCOL_FLAG_HTTP2;
  WinHttpSetOption(
      state->request,
      WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
      &protocols,
      sizeof(protocols));
#endif

  std::wstring wide_headers = utf8ToWide(headers);
  LPCWSTR header_ptr = wide_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wide_headers.c_str();
  DWORD header_len = wide_headers.empty() ? 0 : static_cast<DWORD>(wide_headers.size());
  LPVOID body_ptr = body.empty() ? WINHTTP_NO_REQUEST_DATA : body.data();
  DWORD body_len = static_cast<DWORD>(body.size());
  if (!WinHttpSendRequest(state->request, header_ptr, header_len, body_ptr, body_len, body_len, 0)) {
    sendError(state, lastErrorString("WinHttpSendRequest"), callback, context);
    finish();
    return;
  }

  if (!WinHttpReceiveResponse(state->request, nullptr)) {
    sendError(state, lastErrorString("WinHttpReceiveResponse"), callback, context);
    finish();
    return;
  }

  DWORD status_code = 0;
  DWORD status_code_size = sizeof(status_code);
  if (!WinHttpQueryHeaders(
          state->request,
          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
          WINHTTP_HEADER_NAME_BY_INDEX,
          &status_code,
          &status_code_size,
          WINHTTP_NO_HEADER_INDEX)) {
    sendError(state, lastErrorString("WinHttpQueryHeaders(status)"), callback, context);
    finish();
    return;
  }

  std::string status_text = queryHeaders(state->request, WINHTTP_QUERY_STATUS_TEXT);
  std::string response_headers = queryHeaders(state->request, WINHTTP_QUERY_RAW_HEADERS_CRLF);

  std::vector<uint8_t> response_body;
  for (;;) {
    if (state->cancelled.load(std::memory_order_relaxed)) {
      finish();
      return;
    }
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(state->request, &available)) {
      sendError(state, lastErrorString("WinHttpQueryDataAvailable"), callback, context);
      finish();
      return;
    }
    if (available == 0) {
      break;
    }
    std::vector<uint8_t> chunk(available);
    DWORD read = 0;
    if (!WinHttpReadData(state->request, chunk.data(), available, &read)) {
      sendError(state, lastErrorString("WinHttpReadData"), callback, context);
      finish();
      return;
    }
    response_body.insert(response_body.end(), chunk.begin(), chunk.begin() + read);
  }

  if (!state->cancelled.load(std::memory_order_relaxed) && callback) {
    callback(
        state->request_id,
        static_cast<int>(status_code),
        status_text.empty() ? "OK" : status_text.c_str(),
        response_headers.empty() ? nullptr : response_headers.c_str(),
        response_body.empty() ? nullptr : response_body.data(),
        response_body.size(),
        context);
  }
  finish();
}

} // namespace

extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    int decompress,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context) {
  if (!url || !response_callback) {
    return;
  }

  auto state = std::make_shared<RequestState>();
  state->request_id = request_id;
  {
    std::lock_guard<std::mutex> lock(g_requests_mutex);
    g_requests[request_id] = state;
  }

  std::vector<uint8_t> body_copy;
  if (body && body_length > 0) {
    body_copy.assign(body, body + body_length);
  }

  std::thread(
      performFetch,
      state,
      std::string(method ? method : "GET"),
      std::string(url),
      std::string(headers ? headers : ""),
      decompress,
      std::move(body_copy),
      response_callback,
      context)
      .detach();
}

extern "C" void native_fetch_cancel(uint32_t request_id) {
  std::shared_ptr<RequestState> state;
  {
    std::lock_guard<std::mutex> lock(g_requests_mutex);
    auto it = g_requests.find(request_id);
    if (it == g_requests.end()) {
      return;
    }
    state = it->second;
  }
  if (state) {
    state->cancelled.store(true, std::memory_order_relaxed);
    closeHandles(state);
  }
}
