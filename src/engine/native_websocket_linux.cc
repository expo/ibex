/**
 * native_websocket_linux.cc
 *
 * Temporary Linux WebSocket stubs. They preserve ABI compatibility with
 * hermes_runtime.cc so non-network CLI flows can run while Linux networking
 * implementation is completed.
 */

#include <cstddef>
#include <cstdint>

typedef void (*NativeWsOpenCallback)(uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

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
    (void)url;
    (void)protocols;
    (void)open_cb;
    (void)message_cb;
    (void)close_cb;
    (void)bytes_sent_cb;
    if (error_cb) {
        error_cb(0, "native_ws_connect is not implemented on Linux yet", context);
    }
    return 0;
}

extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text) {
    (void)ws_id;
    (void)data;
    (void)length;
    (void)is_text;
}

extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason) {
    (void)ws_id;
    (void)code;
    (void)reason;
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
    (void)ws_id;
}

extern "C" int native_ws_has_active(void) {
    return 0;
}
