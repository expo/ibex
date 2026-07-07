/**
 * native_websocket_linux.cc
 *
 * Linux WebSocket implementation.
 *
 * The supported Linux networking profile uses libcurl's websocket API. A
 * degraded fetch-only fallback can be enabled from build.rs for constrained
 * local builds; WebSocket remains unavailable in that profile.
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#ifdef EXACT_HAS_CURL
#include <curl/curl.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#endif

typedef void (*NativeWsOpenCallback)(uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

extern "C" void native_ws_retain_context(void* context);
extern "C" void native_ws_release_context(void* context);

#ifdef EXACT_HAS_CURL

struct OutboundMessage {
    std::vector<uint8_t> bytes;
    bool is_text = false;
};

struct WebSocketEntry {
    uint32_t ws_id = 0;
    CURL* curl = nullptr;
    curl_slist* headers = nullptr;

    NativeWsOpenCallback open_cb = nullptr;
    NativeWsMessageCallback message_cb = nullptr;
    NativeWsCloseCallback close_cb = nullptr;
    NativeWsErrorCallback error_cb = nullptr;
    NativeWsBytesSentCallback bytes_sent_cb = nullptr;
    void* context = nullptr;

    std::mutex io_mutex;
    std::queue<OutboundMessage> outbound;
    std::atomic<bool> closed{false};
    std::atomic<bool> receive_paused{false};
    std::atomic<bool> flow_controlled_receive{false};
    std::thread io_thread;
};

static std::mutex g_ws_mutex;
static std::unordered_map<uint32_t, std::shared_ptr<WebSocketEntry>> g_ws_connections;
static std::atomic<uint32_t> g_next_ws_id{1};
static std::once_flag g_curl_global_init_once;

static void ensure_curl_global_init() {
    std::call_once(g_curl_global_init_once, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

static bool should_trust_loopback_tls() {
    const char* value = std::getenv("EXACT_WPT_TRUST_LOOPBACK_TLS");
    if (!value || !*value) {
        return false;
    }
    return std::string(value) != "0";
}

static std::string extract_url_host(const char* url) {
    if (!url || !*url) {
        return "";
    }

    std::string value(url);
    const auto scheme_sep = value.find("://");
    if (scheme_sep == std::string::npos) {
        return "";
    }

    auto authority_start = scheme_sep + 3;
    auto authority_end = value.find_first_of("/?#", authority_start);
    std::string authority = value.substr(authority_start, authority_end - authority_start);
    if (authority.empty()) {
        return "";
    }

    const auto userinfo_sep = authority.rfind('@');
    if (userinfo_sep != std::string::npos) {
        authority.erase(0, userinfo_sep + 1);
    }

    if (!authority.empty() && authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string::npos) {
            return "";
        }
        return authority.substr(1, closing - 1);
    }

    const auto port_sep = authority.rfind(':');
    if (port_sep != std::string::npos) {
        authority.resize(port_sep);
    }

    return authority;
}

static bool is_loopback_host(const std::string& host) {
    return host == "localhost" || host == "127.0.0.1" || host == "::1";
}

static bool should_disable_tls_verification_for_url(const char* url) {
    if (!should_trust_loopback_tls()) {
        return false;
    }
    return is_loopback_host(extract_url_host(url));
}

static void call_error(const std::shared_ptr<WebSocketEntry>& entry, const char* message) {
    if (!entry || !entry->error_cb || !entry->context) {
        return;
    }
    native_ws_retain_context(entry->context);
    entry->error_cb(entry->ws_id, message ? message : "WebSocket error", entry->context);
    native_ws_release_context(entry->context);
}

static void call_open(const std::shared_ptr<WebSocketEntry>& entry) {
    if (!entry || !entry->open_cb || !entry->context) {
        return;
    }
    native_ws_retain_context(entry->context);
    entry->open_cb(entry->ws_id, "", "", entry->context);
    native_ws_release_context(entry->context);
}

static void call_message(
    const std::shared_ptr<WebSocketEntry>& entry,
    const uint8_t* data,
    size_t len,
    bool is_text
) {
    if (!entry || !entry->message_cb || !entry->context) {
        return;
    }
    native_ws_retain_context(entry->context);
    entry->message_cb(entry->ws_id, data, len, is_text ? 1 : 0, entry->context);
    native_ws_release_context(entry->context);
}

static void call_bytes_sent(const std::shared_ptr<WebSocketEntry>& entry, size_t bytes_sent) {
    if (!entry || !entry->bytes_sent_cb || !entry->context) {
        return;
    }
    native_ws_retain_context(entry->context);
    entry->bytes_sent_cb(entry->ws_id, bytes_sent, entry->context);
    native_ws_release_context(entry->context);
}

static void call_close(const std::shared_ptr<WebSocketEntry>& entry, uint16_t code, const char* reason, int was_clean) {
    if (!entry || !entry->close_cb || !entry->context) {
        return;
    }
    native_ws_retain_context(entry->context);
    entry->close_cb(entry->ws_id, code, reason ? reason : "", was_clean, entry->context);
    native_ws_release_context(entry->context);
}

static void remove_connection(uint32_t ws_id) {
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
        g_ws_connections.erase(it);
    }

    if (!entry) {
        return;
    }
    entry->closed.store(true, std::memory_order_relaxed);
    if (entry->context) {
        native_ws_release_context(entry->context);
        entry->context = nullptr;
    }
}

static void run_io_loop(const std::shared_ptr<WebSocketEntry>& entry) {
    call_open(entry);

    // Message reassembly state. curl_ws_recv returns at most one buffer's
    // worth of a single frame per call (meta->bytesleft > 0 while the frame
    // continues) and fragmented messages arrive as CURLWS_CONT frames, so a
    // message event may only fire once the final chunk of the final frame
    // has been appended. The text/binary type is latched from the first
    // frame: continuation frames do not carry CURLWS_TEXT.
    std::vector<uint8_t> message;
    bool message_is_text = false;
    bool message_in_progress = false;

    while (!entry->closed.load(std::memory_order_relaxed)) {
        // Drain outbound messages first.
        for (;;) {
            OutboundMessage msg;
            {
                std::lock_guard<std::mutex> lock(entry->io_mutex);
                if (entry->outbound.empty()) {
                    break;
                }
                msg = std::move(entry->outbound.front());
                entry->outbound.pop();
            }

            size_t sent = 0;
            const unsigned int flags = msg.is_text ? CURLWS_TEXT : CURLWS_BINARY;
            const CURLcode send_rc = curl_ws_send(
                entry->curl,
                msg.bytes.data(),
                msg.bytes.size(),
                &sent,
                0,
                flags
            );
            if (send_rc != CURLE_OK) {
                call_error(entry, curl_easy_strerror(send_rc));
                entry->closed.store(true, std::memory_order_relaxed);
                break;
            }
            call_bytes_sent(entry, sent);
        }

        if (entry->closed.load(std::memory_order_relaxed)) {
            break;
        }

        if (entry->receive_paused.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        uint8_t buffer[64 * 1024];
        size_t nrecv = 0;
        const struct curl_ws_frame* meta = nullptr;
        const CURLcode recv_rc = curl_ws_recv(entry->curl, buffer, sizeof(buffer), &nrecv, &meta);
        if (recv_rc == CURLE_OK) {
            const unsigned int frame_flags = meta ? static_cast<unsigned int>(meta->flags) : 0u;
            if (frame_flags & (CURLWS_PING | CURLWS_PONG)) {
                // curl answers pings itself but still surfaces the frames;
                // control frames must never become JS message events.
                continue;
            }
            if (frame_flags & CURLWS_CLOSE) {
                // RFC 6455 5.5.1: the first two payload bytes are the status
                // code (big-endian) and the rest is a UTF-8 reason. Report
                // 1005 ("no status") when the peer sent no code.
                uint16_t close_code = 1005;
                std::string close_reason;
                if (nrecv >= 2) {
                    close_code = static_cast<uint16_t>((buffer[0] << 8) | buffer[1]);
                    close_reason.assign(reinterpret_cast<const char*>(buffer) + 2, nrecv - 2);
                }
                call_close(entry, close_code, close_reason.c_str(), 1);
                entry->closed.store(true, std::memory_order_relaxed);
                break;
            }
            if (message_in_progress ||
                (frame_flags & (CURLWS_TEXT | CURLWS_BINARY | CURLWS_CONT)) != 0) {
                if (!message_in_progress) {
                    message_is_text = (frame_flags & CURLWS_TEXT) != 0;
                    message_in_progress = true;
                }
                if (nrecv > 0) {
                    message.insert(message.end(), buffer, buffer + nrecv);
                }
                const bool frame_complete = !meta || meta->bytesleft == 0;
                const bool final_fragment = (frame_flags & CURLWS_CONT) == 0;
                if (frame_complete && final_fragment) {
                    if (entry->flow_controlled_receive.load(std::memory_order_relaxed)) {
                        entry->receive_paused.store(true, std::memory_order_relaxed);
                    }
                    call_message(
                        entry,
                        message.empty() ? reinterpret_cast<const uint8_t*>("") : message.data(),
                        message.size(),
                        message_is_text);
                    message.clear();
                    message_in_progress = false;
                }
                continue;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        if (recv_rc == CURLE_AGAIN) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        call_error(entry, curl_easy_strerror(recv_rc));
        call_close(entry, 1006, "Connection error", 0);
        entry->closed.store(true, std::memory_order_relaxed);
        break;
    }

    if (entry->headers) {
        curl_slist_free_all(entry->headers);
        entry->headers = nullptr;
    }
    if (entry->curl) {
        curl_easy_cleanup(entry->curl);
        entry->curl = nullptr;
    }

    remove_connection(entry->ws_id);
}

#endif // EXACT_HAS_CURL

extern "C" uint32_t native_ws_connect(
    const char* url,
    const char* protocols,
    NativeWsOpenCallback open_cb,
    NativeWsMessageCallback message_cb,
    NativeWsCloseCallback close_cb,
    NativeWsErrorCallback error_cb,
    NativeWsBytesSentCallback bytes_sent_cb,
    void* context
) {
#ifdef EXACT_HAS_CURL
    if (!url || !open_cb || !message_cb || !close_cb || !error_cb) {
        return 0;
    }

    ensure_curl_global_init();

    CURL* curl = curl_easy_init();
    if (!curl) {
        if (error_cb && context) {
            native_ws_retain_context(context);
            error_cb(0, "Failed to initialize libcurl", context);
            native_ws_release_context(context);
        }
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); // websocket mode
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (should_disable_tls_verification_for_url(url)) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_slist* headers = nullptr;
    if (protocols && *protocols) {
        std::string proto_header = "Sec-WebSocket-Protocol: ";
        proto_header += protocols;
        headers = curl_slist_append(headers, proto_header.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        if (headers) {
            curl_slist_free_all(headers);
        }
        const char* msg = curl_easy_strerror(rc);
        if (error_cb && context) {
            native_ws_retain_context(context);
            error_cb(0, msg ? msg : "WebSocket connect failed", context);
            native_ws_release_context(context);
        }
        curl_easy_cleanup(curl);
        return 0;
    }

    auto entry = std::make_shared<WebSocketEntry>();
    entry->ws_id = g_next_ws_id.fetch_add(1, std::memory_order_relaxed);
    entry->curl = curl;
    entry->headers = headers;
    entry->open_cb = open_cb;
    entry->message_cb = message_cb;
    entry->close_cb = close_cb;
    entry->error_cb = error_cb;
    entry->bytes_sent_cb = bytes_sent_cb;
    entry->context = context;
    if (entry->context) {
        native_ws_retain_context(entry->context);
    }

    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        g_ws_connections[entry->ws_id] = entry;
    }

    entry->io_thread = std::thread([entry]() { run_io_loop(entry); });
    entry->io_thread.detach();

    return entry->ws_id;
#else
    (void)url;
    (void)protocols;
    (void)open_cb;
    (void)message_cb;
    (void)close_cb;
    (void)bytes_sent_cb;
    if (error_cb) {
        error_cb(0, "native WebSocket requires Linux native networking with libcurl >= 7.86", context);
    }
    return 0;
#endif
}

extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text) {
#ifdef EXACT_HAS_CURL
    if (!data || length == 0) {
        return;
    }
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
    }
    if (!entry || entry->closed.load(std::memory_order_relaxed)) {
        return;
    }

    OutboundMessage msg;
    msg.bytes.assign(data, data + length);
    msg.is_text = is_text != 0;
    {
        std::lock_guard<std::mutex> lock(entry->io_mutex);
        entry->outbound.push(std::move(msg));
    }
#else
    (void)ws_id;
    (void)data;
    (void)length;
    (void)is_text;
#endif
}

extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason) {
#ifdef EXACT_HAS_CURL
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
    }
    if (!entry) {
        return;
    }

    entry->closed.store(true, std::memory_order_relaxed);
    (void)reason;

    size_t sent = 0;
    if (code == 1005) {
        curl_ws_send(
            entry->curl,
            nullptr,
            0,
            &sent,
            0,
            CURLWS_CLOSE
        );
    } else {
        const uint8_t close_payload[2] = {
            static_cast<uint8_t>((code >> 8) & 0xFF),
            static_cast<uint8_t>(code & 0xFF)
        };
        curl_ws_send(
            entry->curl,
            close_payload,
            sizeof(close_payload),
            &sent,
            0,
            CURLWS_CLOSE
        );
    }
#else
    (void)ws_id;
    (void)code;
    (void)reason;
#endif
}

extern "C" void native_ws_pause(uint32_t ws_id) {
#ifdef EXACT_HAS_CURL
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
    }
    if (!entry) {
        return;
    }
    entry->receive_paused.store(true, std::memory_order_relaxed);
#else
    (void)ws_id;
#endif
}

extern "C" void native_ws_resume(uint32_t ws_id) {
#ifdef EXACT_HAS_CURL
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
    }
    if (!entry) {
        return;
    }
    entry->receive_paused.store(false, std::memory_order_relaxed);
#else
    (void)ws_id;
#endif
}

extern "C" void native_ws_set_flow_controlled(uint32_t ws_id, int enabled) {
#ifdef EXACT_HAS_CURL
    std::shared_ptr<WebSocketEntry> entry;
    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        auto it = g_ws_connections.find(ws_id);
        if (it == g_ws_connections.end()) {
            return;
        }
        entry = it->second;
    }
    if (!entry) {
        return;
    }
    entry->flow_controlled_receive.store(enabled != 0, std::memory_order_relaxed);
#else
    (void)ws_id;
    (void)enabled;
#endif
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
#ifdef EXACT_HAS_CURL
    remove_connection(ws_id);
#else
    (void)ws_id;
#endif
}

extern "C" int native_ws_has_active(void) {
#ifdef EXACT_HAS_CURL
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    for (const auto& pair : g_ws_connections) {
        const auto& entry = pair.second;
        if (entry && !entry->closed.load(std::memory_order_relaxed)) {
            return 1;
        }
    }
    return 0;
#else
    return 0;
#endif
}
