/**
 * native_fetch_linux.cc
 *
 * Linux fetch implementation.
 *
 * If libcurl headers are available (EXACT_HAS_CURL), this uses libcurl.
 * Otherwise it falls back to a stub so non-network flows still compile/run.
 */

#include <cstddef>
#include <cstdint>

#ifdef EXACT_HAS_CURL
#include <curl/curl.h>
#include <cstring>
#include <string>
#include <vector>
#endif

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
#ifdef EXACT_HAS_CURL
    if (!method || !url || !response_callback) {
        return;
    }

    struct FetchResult {
        long status = 0;
        std::string status_text;
        std::string response_headers;
        std::vector<uint8_t> response_body;
    } result;

    auto write_body = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* vec = static_cast<std::vector<uint8_t>*>(userdata);
        const size_t total = size * nmemb;
        vec->insert(vec->end(), reinterpret_cast<uint8_t*>(ptr), reinterpret_cast<uint8_t*>(ptr) + total);
        return total;
    };

    auto write_headers = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* headers_out = static_cast<std::string*>(userdata);
        const size_t total = size * nmemb;
        headers_out->append(ptr, total);
        return total;
    };

    CURL* curl = curl_easy_init();
    if (!curl) {
        response_callback(request_id, 0, "Failed to initialize libcurl", nullptr, nullptr, 0, context);
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.response_body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_headers);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result.response_headers);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);

    if (body && body_length > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body_length));
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }

    curl_slist* curl_headers = nullptr;
    if (headers && *headers) {
        const char* line_start = headers;
        const char* p = headers;
        while (*p) {
            if (*p == '\r' && *(p + 1) == '\n') {
                if (p > line_start) {
                    std::string line(line_start, static_cast<size_t>(p - line_start));
                    curl_headers = curl_slist_append(curl_headers, line.c_str());
                }
                p += 2;
                line_start = p;
                continue;
            }
            p++;
        }
        if (p > line_start) {
            std::string line(line_start, static_cast<size_t>(p - line_start));
            curl_headers = curl_slist_append(curl_headers, line.c_str());
        }
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }

    char error_buffer[CURL_ERROR_SIZE];
    std::memset(error_buffer, 0, sizeof(error_buffer));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        const char* msg = error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(rc);
        response_callback(request_id, 0, msg, nullptr, nullptr, 0, context);
        if (curl_headers) {
            curl_slist_free_all(curl_headers);
        }
        curl_easy_cleanup(curl);
        return;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    result.status_text = "OK";

    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);

    const char* status_text = result.status_text.empty() ? "OK" : result.status_text.c_str();
    const char* response_headers = result.response_headers.empty() ? nullptr : result.response_headers.c_str();
    const uint8_t* body_ptr = result.response_body.empty() ? nullptr : result.response_body.data();
    response_callback(
        request_id,
        static_cast<int>(result.status),
        status_text,
        response_headers,
        body_ptr,
        result.response_body.size(),
        context
    );
#else
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
#endif
}
