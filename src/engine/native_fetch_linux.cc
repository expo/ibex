/**
 * native_fetch_linux.cc
 *
 * Temporary Linux fetch stub. It preserves ABI compatibility with
 * hermes_runtime.cc so non-network CLI flows can run while Linux networking
 * implementation is completed.
 */

#include <cstddef>
#include <cstdint>

typedef void (*NativeFetchResponseCallback)(
    uint32_t request_id,
    int status,
    const char* status_text,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    void* context
);

extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context
) {
    (void)method;
    (void)url;
    (void)headers;
    (void)body;
    (void)body_length;
    if (!response_callback) {
        return;
    }
    response_callback(
        request_id,
        0,
        "native_fetch_perform is not implemented on Linux yet",
        nullptr,
        nullptr,
        0,
        context
    );
}
