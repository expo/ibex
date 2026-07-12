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
    // curl/headers are created and used exclusively by the io thread (the
    // handshake runs there too); no other thread may touch them.
    CURL* curl = nullptr;
    curl_slist* headers = nullptr;
    std::string url;
    std::string protocols;
    std::string selected_protocol;
    std::string extensions;

    NativeWsOpenCallback open_cb = nullptr;
    NativeWsMessageCallback message_cb = nullptr;
    NativeWsCloseCallback close_cb = nullptr;
    NativeWsErrorCallback error_cb = nullptr;
    NativeWsBytesSentCallback bytes_sent_cb = nullptr;
    void* context = nullptr;

    std::mutex io_mutex;
    std::queue<OutboundMessage> outbound;
    // Client close request, written by the JS thread under io_mutex and
    // consumed by the io thread once close_requested is observed.
    uint16_t close_code = 1005;
    std::string close_reason;
    std::atomic<bool> close_requested{false};
    std::atomic<bool> closed{false};
    std::atomic<bool> receive_paused{false};
    std::atomic<bool> flow_controlled_receive{false};
};

static std::mutex g_ws_mutex;
static std::unordered_map<uint32_t, std::shared_ptr<WebSocketEntry>> g_ws_connections;
static std::atomic<uint32_t> g_next_ws_id{1};

static uint32_t allocate_ws_id() {
    uint32_t next = g_next_ws_id.load(std::memory_order_relaxed);
    while (next != 0) {
        const uint32_t successor = next + 1; // unsigned wrap yields terminal 0
        if (g_next_ws_id.compare_exchange_weak(
                next, successor, std::memory_order_relaxed, std::memory_order_relaxed)) {
            return next;
        }
    }
    return 0;
}
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

static int connect_progress_callback(
    void* clientp,
    curl_off_t,
    curl_off_t,
    curl_off_t,
    curl_off_t
) {
    auto* entry = static_cast<WebSocketEntry*>(clientp);
    if (!entry) {
        return 0;
    }
    return entry->closed.load(std::memory_order_relaxed) ||
            entry->close_requested.load(std::memory_order_relaxed)
        ? 1
        : 0;
}

static char ascii_lower(char value) {
    return (value >= 'A' && value <= 'Z') ? static_cast<char>(value - 'A' + 'a') : value;
}

static bool ascii_equals_ignore_case(const std::string& left, const char* right) {
    if (!right) {
        return false;
    }
    size_t i = 0;
    for (; i < left.size() && right[i] != '\0'; ++i) {
        if (ascii_lower(left[i]) != ascii_lower(right[i])) {
            return false;
        }
    }
    return i == left.size() && right[i] == '\0';
}

static std::string trim_header_value(std::string value) {
    size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
        ++start;
    }

    size_t end = value.size();
    while (end > start) {
        const char ch = value[end - 1];
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            break;
        }
        --end;
    }

    return value.substr(start, end - start);
}

static void capture_handshake_header(WebSocketEntry* entry, const char* data, size_t length) {
    if (!entry || !data || length == 0) {
        return;
    }

    std::string line(data, length);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }
    if (line.empty()) {
        return;
    }

    if (line.rfind("HTTP/", 0) == 0) {
        entry->selected_protocol.clear();
        entry->extensions.clear();
        return;
    }

    const auto colon = line.find(':');
    if (colon == std::string::npos) {
        return;
    }

    const std::string name = line.substr(0, colon);
    const std::string value = trim_header_value(line.substr(colon + 1));
    if (ascii_equals_ignore_case(name, "Sec-WebSocket-Protocol")) {
        entry->selected_protocol = value;
    } else if (ascii_equals_ignore_case(name, "Sec-WebSocket-Extensions")) {
        entry->extensions = value;
    }
}

static size_t handshake_header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    const size_t length = size * nitems;
    capture_handshake_header(static_cast<WebSocketEntry*>(userdata), buffer, length);
    return length;
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
    entry->open_cb(
        entry->ws_id,
        entry->selected_protocol.c_str(),
        entry->extensions.c_str(),
        entry->context
    );
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

// Builds the RFC 6455 5.5.1 CLOSE payload: 2-byte big-endian status code
// followed by the UTF-8 reason bytes; empty when there is no code (1005
// means "no status" and must never appear on the wire).
static std::vector<uint8_t> build_close_payload(uint16_t code, const std::string& reason) {
    std::vector<uint8_t> payload;
    if (code != 1005) {
        payload.push_back(static_cast<uint8_t>((code >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(code & 0xFF));
        payload.insert(payload.end(), reason.begin(), reason.end());
    }
    return payload;
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

// Runs on the io thread. Performs the blocking DNS/TCP/TLS/upgrade
// handshake; on success entry->curl is ready for curl_ws_recv/curl_ws_send.
// On failure the error and close callbacks fire (mirroring the macOS
// delegate's connection-failure path) and false is returned.
static bool perform_handshake(const std::shared_ptr<WebSocketEntry>& entry) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        call_error(entry, "Failed to initialize libcurl");
        call_close(entry, 1006, "Failed to initialize libcurl", 0);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, entry->url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); // websocket mode
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, handshake_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, entry.get());
    // close()/destroy during CONNECTING must not keep the runtime alive until
    // libcurl's 30s timeout. The progress callback is the documented,
    // same-thread way to abort curl_easy_perform without touching the easy
    // handle from the JS thread.
    // @ref LLP 0003#websocket-bridge-threading-and-context-ownership — native
    // close during CONNECTING must fail the connection promptly
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, connect_progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, entry.get());
    if (should_disable_tls_verification_for_url(entry->url.c_str())) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_slist* headers = nullptr;
    if (!entry->protocols.empty()) {
        std::string proto_header = "Sec-WebSocket-Protocol: ";
        proto_header += entry->protocols;
        headers = curl_slist_append(headers, proto_header.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        const bool aborted_for_close =
            rc == CURLE_ABORTED_BY_CALLBACK &&
            (entry->closed.load(std::memory_order_relaxed) ||
             entry->close_requested.load(std::memory_order_relaxed));
        if (headers) {
            curl_slist_free_all(headers);
        }
        curl_easy_cleanup(curl);
        if (aborted_for_close) {
            if (entry->close_requested.load(std::memory_order_relaxed) &&
                !entry->closed.exchange(true, std::memory_order_relaxed)) {
                call_error(entry, "WebSocket was closed before the connection was established");
                call_close(entry, 1006, "", 0);
            }
            return false;
        }
        const char* msg = curl_easy_strerror(rc);
        if (!msg) {
            msg = "WebSocket connect failed";
        }
        call_error(entry, msg);
        call_close(entry, 1006, msg, 0);
        return false;
    }

    if (entry->close_requested.load(std::memory_order_relaxed) ||
        entry->closed.load(std::memory_order_relaxed)) {
        if (headers) {
            curl_slist_free_all(headers);
        }
        curl_easy_cleanup(curl);
        if (entry->close_requested.load(std::memory_order_relaxed) &&
            !entry->closed.exchange(true, std::memory_order_relaxed)) {
            call_error(entry, "WebSocket was closed before the connection was established");
            call_close(entry, 1006, "", 0);
        }
        return false;
    }

    entry->curl = curl;
    entry->headers = headers;
    return true;
}

static void run_io_loop(const std::shared_ptr<WebSocketEntry>& entry) {
    if (entry->close_requested.load(std::memory_order_relaxed)) {
        if (!entry->closed.exchange(true, std::memory_order_relaxed)) {
            call_error(entry, "WebSocket was closed before the connection was established");
            call_close(entry, 1006, "", 0);
        }
        remove_connection(entry->ws_id);
        return;
    }
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

    // Client-initiated close handshake state. The io thread is the only
    // thread that ever touches entry->curl: the JS thread just records the
    // requested code/reason and sets close_requested. The give-up deadline
    // arms the moment the request is observed -- not when the CLOSE frame
    // finally goes out -- so a frame that can never be written (peer not
    // reading, send buffer full) still cannot park readyState at CLOSING
    // forever. After the CLOSE frame goes out we keep reading until the
    // peer's CLOSE arrives (or the deadline expires) so the close callback
    // always fires.
    constexpr auto kCloseHandshakeTimeout = std::chrono::seconds(5);
    // Bound for retrying CURLE_AGAIN on outbound data frames: a peer that
    // stops reading must not wedge the io thread forever, but a transiently
    // full socket buffer must not tear down a healthy connection either.
    constexpr auto kSendStallTimeout = std::chrono::seconds(10);
    bool closing = false;
    bool close_sent = false;
    uint16_t requested_close_code = 1005;
    std::string requested_close_reason;
    std::chrono::steady_clock::time_point close_deadline_start{};

    while (!entry->closed.load(std::memory_order_relaxed)) {
        if (!closing && entry->close_requested.load(std::memory_order_acquire)) {
            {
                std::lock_guard<std::mutex> lock(entry->io_mutex);
                requested_close_code = entry->close_code;
                requested_close_reason = entry->close_reason;
            }
            closing = true;
            close_deadline_start = std::chrono::steady_clock::now();
        }

        if (closing &&
            std::chrono::steady_clock::now() - close_deadline_start > kCloseHandshakeTimeout) {
            // Peer never acknowledged our CLOSE frame (or it could never be
            // sent); complete the client close anyway so readyState cannot
            // stay CLOSING forever.
            call_close(entry, requested_close_code, requested_close_reason.c_str(), 1);
            entry->closed.store(true, std::memory_order_relaxed);
            break;
        }

        // Drain outbound messages first (data frames must not follow a
        // CLOSE frame, RFC 6455 5.5.1).
        if (!close_sent) {
            bool send_failed = false;
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

                const unsigned int flags = msg.is_text ? CURLWS_TEXT : CURLWS_BINARY;
                // The CONNECT_ONLY socket is non-blocking, so curl_ws_send
                // returns CURLE_AGAIN with *sent updated when the kernel
                // buffer fills mid-frame; retry with the remaining payload
                // (per curl_ws_send docs) instead of tearing the connection
                // down, bounded by kSendStallTimeout.
                size_t total_sent = 0;
                CURLcode send_rc = CURLE_OK;
                const auto send_start = std::chrono::steady_clock::now();
                for (;;) {
                    size_t sent = 0;
                    send_rc = curl_ws_send(
                        entry->curl,
                        msg.bytes.data() + total_sent,
                        msg.bytes.size() - total_sent,
                        &sent,
                        0,
                        flags
                    );
                    total_sent += sent;
                    if (send_rc != CURLE_AGAIN) {
                        break;
                    }
                    if (total_sent >= msg.bytes.size() && !msg.bytes.empty()) {
                        // curl accepted the whole payload but has not
                        // flushed it yet; later curl_ws_* calls flush.
                        send_rc = CURLE_OK;
                        break;
                    }
                    if (entry->closed.load(std::memory_order_relaxed) ||
                        std::chrono::steady_clock::now() - send_start > kSendStallTimeout) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                if (send_rc != CURLE_OK) {
                    call_error(entry, curl_easy_strerror(send_rc));
                    call_close(entry, 1006, "Connection error", 0);
                    entry->closed.store(true, std::memory_order_relaxed);
                    send_failed = true;
                    break;
                }
                call_bytes_sent(entry, total_sent);
            }
            if (send_failed) {
                break;
            }
        }

        if (closing && !close_sent) {
            const std::vector<uint8_t> payload =
                build_close_payload(requested_close_code, requested_close_reason);
            size_t sent = 0;
            const CURLcode close_rc = curl_ws_send(
                entry->curl,
                payload.data(),
                payload.size(),
                &sent,
                0,
                CURLWS_CLOSE
            );
            if (close_rc == CURLE_OK) {
                close_sent = true;
            } else if (close_rc != CURLE_AGAIN) {
                call_close(entry, 1006, "Connection error", 0);
                entry->closed.store(true, std::memory_order_relaxed);
                break;
            }
            // CURLE_AGAIN: fall through and keep reading; the deadline armed
            // above guarantees forward progress.
        }

        if (entry->closed.load(std::memory_order_relaxed)) {
            break;
        }

        // Keep reading while flow-control-paused once closing: incoming data
        // frames are discarded below anyway, but the peer's CLOSE ack must
        // still be seen or every flow-controlled close would burn the full
        // handshake timeout.
        if (entry->receive_paused.load(std::memory_order_relaxed) && !closing) {
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
                if (!close_sent) {
                    // Server-initiated close: echo a CLOSE frame back
                    // (best-effort) to complete the closing handshake.
                    const std::vector<uint8_t> ack = build_close_payload(close_code, "");
                    size_t ack_sent = 0;
                    curl_ws_send(entry->curl, ack.data(), ack.size(), &ack_sent, 0, CURLWS_CLOSE);
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
                    if (closing) {
                        // WHATWG: message events only fire while OPEN.
                        // Frames still in flight when close() was called are
                        // discarded (matching the pre-async behavior), but
                        // reading continues so the CLOSE ack is seen.
                        message.clear();
                        message_in_progress = false;
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

        if (closing) {
            // The client requested a close and the peer tore the connection
            // down (with or without acknowledging our CLOSE frame). The
            // client close still completed, so report the requested code
            // rather than an error.
            call_close(entry, requested_close_code, requested_close_reason.c_str(), 1);
            entry->closed.store(true, std::memory_order_relaxed);
            break;
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

    auto entry = std::make_shared<WebSocketEntry>();
    entry->ws_id = allocate_ws_id();
    if (entry->ws_id == 0) {
        return 0;
    }
    entry->url = url;
    entry->protocols = protocols ? protocols : "";
    entry->open_cb = open_cb;
    entry->message_cb = message_cb;
    entry->close_cb = close_cb;
    entry->error_cb = error_cb;
    entry->bytes_sent_cb = bytes_sent_cb;
    // Adopt the caller's reference: the bridge creates the context with
    // ref_count == 1 and transfers ownership when a nonzero ws_id is
    // returned (remove_connection performs the balancing release). An extra
    // retain here leaked the context -- and the JS WebSocket instance it
    // pins -- on every successful connection.
    // @ref LLP 0003#websocket-bridge-threading-and-context-ownership — ownership
    // transfers on nonzero ws_id; never retain at connect
    entry->context = context;

    {
        std::lock_guard<std::mutex> lock(g_ws_mutex);
        if (!g_ws_connections.emplace(entry->ws_id, entry).second) {
            return 0;
        }
    }

    // Run the blocking DNS/TCP/TLS/upgrade handshake on the io thread and
    // return immediately: a synchronous curl_easy_perform here would stall
    // the whole JS event loop for the handshake RTT (up to CURLOPT_TIMEOUT,
    // 30s, for an unreachable host). WHATWG requires connection
    // establishment to run "in parallel"; macOS is fully async already.
    std::thread io_thread([entry]() {
        if (!perform_handshake(entry)) {
            remove_connection(entry->ws_id);
            return;
        }
        run_io_loop(entry);
    });
    io_thread.detach();

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
    // Zero-length payloads are valid WebSocket frames (WHATWG: send('') and
    // send(new Uint8Array(0)) transmit empty frames the peer observes).
    if (!data && length > 0) {
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
    if (!entry || entry->closed.load(std::memory_order_relaxed) ||
        entry->close_requested.load(std::memory_order_relaxed)) {
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

    // Never touch the CURL easy handle from the JS thread: the io thread is
    // concurrently inside curl_ws_recv/curl_ws_send on the same handle (a
    // libcurl handle must not be used from two threads) and frees it on
    // exit. Record the requested code/reason and let the io thread send the
    // CLOSE frame and complete the closing handshake.
    // @ref LLP 0003#websocket-bridge-threading-and-context-ownership — the io
    // thread exclusively owns the CURL handle
    {
        std::lock_guard<std::mutex> lock(entry->io_mutex);
        entry->close_code = code;
        entry->close_reason = reason ? reason : "";
    }
    entry->close_requested.store(true, std::memory_order_release);
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
