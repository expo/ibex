/**
 * native_fetch_linux.cc
 *
 * Linux fetch implementation.
 *
 * The supported Linux networking profile uses libcurl. A degraded curl CLI
 * fallback can be enabled from build.rs for constrained local builds.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unistd.h>

#ifdef EXACT_HAS_CURL
#include <curl/curl.h>
#include <cstring>
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

namespace {

struct LinuxFetchRequest {
    std::atomic<bool> cancelled{false};
};

std::mutex g_fetch_requests_mutex;
std::unordered_map<uint32_t, std::shared_ptr<LinuxFetchRequest>> g_fetch_requests;

void register_fetch_request(
    uint32_t request_id,
    const std::shared_ptr<LinuxFetchRequest>& request
) {
    std::lock_guard<std::mutex> lock(g_fetch_requests_mutex);
    g_fetch_requests[request_id] = request;
}

void remove_fetch_request(uint32_t request_id) {
    std::lock_guard<std::mutex> lock(g_fetch_requests_mutex);
    g_fetch_requests.erase(request_id);
}

bool request_cancelled(const std::shared_ptr<LinuxFetchRequest>& request) {
    return request && request->cancelled.load(std::memory_order_relaxed);
}

#ifdef EXACT_HAS_CURL
std::once_flag g_curl_global_init_once;

void ensure_curl_global_init() {
    std::call_once(g_curl_global_init_once, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

int linux_fetch_progress_callback(
    void* clientp,
    curl_off_t,
    curl_off_t,
    curl_off_t,
    curl_off_t
) {
    auto* request = static_cast<LinuxFetchRequest*>(clientp);
    return request && request->cancelled.load(std::memory_order_relaxed) ? 1 : 0;
}
#endif

} // namespace

static void native_fetch_perform_async(
    uint32_t request_id,
    std::shared_ptr<LinuxFetchRequest> request_state,
    std::string method,
    std::string url,
    std::string headers,
    int decompress,
    std::vector<uint8_t> body,
    NativeFetchResponseCallback response_callback,
    void* context
) {
#ifdef EXACT_HAS_CURL
    if (method.empty() || url.empty() || !response_callback) {
        remove_fetch_request(request_id);
        return;
    }
    if (request_cancelled(request_state)) {
        remove_fetch_request(request_id);
        return;
    }

    ensure_curl_global_init();

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
        remove_fetch_request(request_id);
        if (!request_cancelled(request_state)) {
            response_callback(request_id, 0, "Failed to initialize libcurl", nullptr, nullptr, 0, context);
        }
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    // Don't auto-follow redirects — let JS handle redirect logic
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (decompress) {
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    } else {
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "identity");
        curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.response_body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_headers);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result.response_headers);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, linux_fetch_progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, request_state.get());

    if (!body.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }

    curl_slist* curl_headers = nullptr;
    if (!headers.empty()) {
        const char* line_start = headers.c_str();
        const char* p = headers.c_str();
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
    const bool cancelled = request_cancelled(request_state);
    if (rc != CURLE_OK) {
        const char* msg = error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(rc);
        if (curl_headers) {
            curl_slist_free_all(curl_headers);
        }
        curl_easy_cleanup(curl);
        remove_fetch_request(request_id);
        if (!cancelled && !request_cancelled(request_state) && rc != CURLE_ABORTED_BY_CALLBACK) {
            response_callback(request_id, 0, msg, nullptr, nullptr, 0, context);
        }
        return;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    result.status_text = "OK";

    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);
    remove_fetch_request(request_id);

    if (cancelled || request_cancelled(request_state)) {
        return;
    }
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
    if (!response_callback) {
        remove_fetch_request(request_id);
        return;
    }
    if (method.empty() || url.empty()) {
        remove_fetch_request(request_id);
        response_callback(request_id, 0, "Invalid request", nullptr, nullptr, 0, context);
        return;
    }
    if (request_cancelled(request_state)) {
        remove_fetch_request(request_id);
        return;
    }

    auto shell_quote = [](const std::string& input) -> std::string {
        std::string out = "'";
        for (char c : input) {
            if (c == '\'') {
                out += "'\"'\"'";
            } else {
                out.push_back(c);
            }
        }
        out.push_back('\'');
        return out;
    };

    auto make_temp_path = [](const char* tmpl) -> std::string {
        char path[256];
        std::snprintf(path, sizeof(path), "/tmp/%s", tmpl);
        int fd = mkstemp(path);
        if (fd >= 0) {
            close(fd);
        }
        return std::string(path);
    };

    const std::string header_path = make_temp_path("exact_fetch_headers_XXXXXX");
    const std::string body_path = make_temp_path("exact_fetch_body_XXXXXX");
    const std::string code_path = make_temp_path("exact_fetch_code_XXXXXX");
    std::string req_body_path;

    if (!body.empty()) {
        req_body_path = make_temp_path("exact_fetch_req_XXXXXX");
        std::ofstream req_out(req_body_path, std::ios::binary);
        req_out.write(
            reinterpret_cast<const char*>(body.data()),
            static_cast<std::streamsize>(body.size())
        );
        req_out.close();
    }

    std::ostringstream cmd;
    // No -L flag: don't auto-follow redirects — let JS handle redirect logic
    cmd << "curl -sS --connect-timeout 30 --max-time 300 "
        << "-X " << shell_quote(method)
        << " -D " << shell_quote(header_path)
        << " -o " << shell_quote(body_path)
        << " -w '%{http_code}' ";

    if (!headers.empty()) {
        const char* line_start = headers.c_str();
        const char* p = headers.c_str();
        while (*p) {
            if (*p == '\r' && *(p + 1) == '\n') {
                if (p > line_start) {
                    std::string line(line_start, static_cast<size_t>(p - line_start));
                    cmd << "-H " << shell_quote(line) << " ";
                }
                p += 2;
                line_start = p;
                continue;
            }
            p++;
        }
        if (p > line_start) {
            std::string line(line_start, static_cast<size_t>(p - line_start));
            cmd << "-H " << shell_quote(line) << " ";
        }
    }

    if (!req_body_path.empty()) {
        cmd << "--data-binary @" << shell_quote(req_body_path) << " ";
    }

    cmd << shell_quote(url) << " > " << shell_quote(code_path) << " 2>/dev/null";

    const int rc = std::system(cmd.str().c_str());
    const bool cancelled = request_cancelled(request_state);
    if (rc != 0) {
        if (!header_path.empty()) std::remove(header_path.c_str());
        if (!body_path.empty()) std::remove(body_path.c_str());
        if (!code_path.empty()) std::remove(code_path.c_str());
        if (!req_body_path.empty()) std::remove(req_body_path.c_str());
        remove_fetch_request(request_id);
        if (!cancelled && !request_cancelled(request_state)) {
            response_callback(request_id, 0, "curl command failed", nullptr, nullptr, 0, context);
        }
        return;
    }

    std::ifstream code_in(code_path);
    std::string code_text;
    std::getline(code_in, code_text);
    code_in.close();
    int status_code = 0;
    try {
        status_code = std::stoi(code_text);
    } catch (...) {
        status_code = 0;
    }

    std::ifstream headers_in(header_path, std::ios::binary);
    std::string response_headers((std::istreambuf_iterator<char>(headers_in)),
                                 std::istreambuf_iterator<char>());
    headers_in.close();

    std::ifstream body_in(body_path, std::ios::binary);
    std::vector<uint8_t> response_body((std::istreambuf_iterator<char>(body_in)),
                                       std::istreambuf_iterator<char>());
    body_in.close();

    if (!header_path.empty()) std::remove(header_path.c_str());
    if (!body_path.empty()) std::remove(body_path.c_str());
    if (!code_path.empty()) std::remove(code_path.c_str());
    if (!req_body_path.empty()) std::remove(req_body_path.c_str());
    remove_fetch_request(request_id);

    if (cancelled || request_cancelled(request_state)) {
        return;
    }
    const char* headers_ptr = response_headers.empty() ? nullptr : response_headers.c_str();
    const uint8_t* body_ptr = response_body.empty() ? nullptr : response_body.data();
    response_callback(
        request_id,
        status_code,
        status_code > 0 ? "OK" : "Network Error",
        headers_ptr,
        body_ptr,
        response_body.size(),
        context
    );
#endif
}

extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    int decompress,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context
) {
    if (!response_callback) {
        return;
    }
    if (!method || !url) {
        response_callback(request_id, 0, "Invalid request", nullptr, nullptr, 0, context);
        return;
    }

    std::string method_copy(method);
    std::string url_copy(url);
    std::string headers_copy = headers ? headers : "";
    std::vector<uint8_t> body_copy;
    if (body && body_length > 0) {
        body_copy.assign(body, body + body_length);
    }

    auto request_state = std::make_shared<LinuxFetchRequest>();
    register_fetch_request(request_id, request_state);

    std::thread(
        [request_id,
         request_state,
         method_copy = std::move(method_copy),
         url_copy = std::move(url_copy),
         headers_copy = std::move(headers_copy),
         decompress,
         body_copy = std::move(body_copy),
         response_callback,
         context]() mutable {
            native_fetch_perform_async(
                request_id,
                request_state,
                std::move(method_copy),
                std::move(url_copy),
                std::move(headers_copy),
                decompress,
                std::move(body_copy),
                response_callback,
                context
            );
        }
    ).detach();
}

extern "C" void native_fetch_cancel(uint32_t request_id) {
    std::shared_ptr<LinuxFetchRequest> request;
    {
        std::lock_guard<std::mutex> lock(g_fetch_requests_mutex);
        auto it = g_fetch_requests.find(request_id);
        if (it == g_fetch_requests.end()) {
            return;
        }
        request = it->second;
        g_fetch_requests.erase(it);
    }
    if (request) {
        request->cancelled.store(true, std::memory_order_relaxed);
    }
}
