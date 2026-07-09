/**
 * native_fetch_linux.cc
 *
 * Linux fetch implementation.
 *
 * The supported Linux networking profile uses libcurl. A degraded curl CLI
 * fallback can be enabled from build.rs for constrained local builds.
 */

#include <atomic>
#include <cctype>
#include <cerrno>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef EXACT_HAS_CURL
#include <curl/curl.h>
#include <cstring>
#endif

// ENG-23874 — the degraded curl CLI fallback spawns via posix_spawnp with the
// caller's environment (PATH lookup for `curl` is intentional: this fallback
// exists only for constrained dev builds, opted into by
// IBEX_ALLOW_CURL_CLI_FALLBACK=1 at build time; supported builds use libcurl
// in-process and never take this path).
extern char** environ;

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

// ENG-23471 — bounded worker pool so N concurrent fetches can't spawn N OS
// threads (a Promise.all over hundreds of URLs used to create hundreds of
// detached threads). Same discipline as hermes_runtime_dns.cc's DnsWorkerPool
// and hermes_runtime_http.cc's WaitWorkerPool: lazily spawn workers up to a
// cap, bound the backlog, park idle workers on a condvar. Fetch jobs block in
// curl_easy_perform, so the cap matches the HTTP wait pools (16) rather than
// DNS's 8; excess work queues, and overflow past the queue bound fails the
// fetch loudly instead of growing without bound.
class FetchWorkerPool {
public:
    static FetchWorkerPool& instance() {
        // Intentionally leaked: a function-local `static FetchWorkerPool` is
        // destructed during exit() while workers are still parked in
        // cv_.wait(), and destroying a mutex/condvar with waiters is UB that
        // deadlocks the process inside glibc's pthread destructors (run-
        // verified on Linux: `process.exit(0)` after any fetch hung forever
        // with a static instance; macOS never reproduces it). Workers are
        // detached, so leaking the pool lets exit() proceed normally.
        static FetchWorkerPool* pool = new FetchWorkerPool();
        return *pool;
    }

    bool enqueue(std::function<void()> job, std::string& error) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.size() >= kMaxQueue) {
                error = "Fetch worker queue full";
                return false;
            }
            spawn_worker_if_needed_locked();
            queue_.push_back(std::move(job));
        }
        cv_.notify_one();
        return true;
    }

private:
    static constexpr size_t kMaxWorkers = 16;
    static constexpr size_t kMaxQueue = 512;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> queue_;
    size_t idle_ = 0;
    size_t total_ = 0;

    void spawn_worker_if_needed_locked() {
        if (idle_ > 0 || total_ >= kMaxWorkers) {
            return;
        }
        total_ += 1;
        std::thread([this]() {
            for (;;) {
                std::function<void()> job;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    idle_ += 1;
                    cv_.wait(lock, [this] { return !queue_.empty(); });
                    idle_ -= 1;
                    job = std::move(queue_.front());
                    queue_.pop_front();
                }
                job();
            }
        }).detach();
    }
};

// ENG-23471 — extract the reason phrase from the captured raw status line(s)
// so Response.statusText reports what the server actually said ("Not Found")
// instead of a hardcoded "OK". The header capture can contain several status
// lines (1xx interim responses); the LAST one belongs to the final response.
// HTTP/2+ status lines carry no reason phrase — return "" for those, which is
// the fetch-spec default statusText.
std::string parse_status_reason(const std::string& raw_headers) {
    std::string reason;
    size_t pos = 0;
    while (pos < raw_headers.size()) {
        size_t eol = raw_headers.find("\r\n", pos);
        size_t end = eol == std::string::npos ? raw_headers.size() : eol;
        if (raw_headers.compare(pos, 5, "HTTP/") == 0) {
            reason.clear();
            // Status line: HTTP/<version> SP <code> [SP <reason>]
            size_t sp1 = raw_headers.find(' ', pos);
            if (sp1 != std::string::npos && sp1 < end) {
                size_t code = raw_headers.find_first_not_of(' ', sp1);
                if (code != std::string::npos && code < end) {
                    size_t sp2 = raw_headers.find(' ', code);
                    if (sp2 != std::string::npos && sp2 < end) {
                        size_t phrase = raw_headers.find_first_not_of(' ', sp2);
                        if (phrase != std::string::npos && phrase < end) {
                            reason = raw_headers.substr(phrase, end - phrase);
                            while (!reason.empty() &&
                                   (reason.back() == '\r' || reason.back() == '\n' ||
                                    reason.back() == ' ' || reason.back() == '\t')) {
                                reason.pop_back();
                            }
                        }
                    }
                }
            }
        }
        if (eol == std::string::npos) {
            break;
        }
        pos = eol + 2;
    }
    return reason;
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

    // ENG-23471 — CURLOPT_POSTFIELDS switches curl's *internal* method to POST
    // even when the fields are null/empty (CURLOPT_CUSTOMREQUEST only rewrites
    // the request-line verb), so every body-less request — notably plain GETs —
    // used to carry `Content-Length: 0` plus curl's default
    // `Content-Type: application/x-www-form-urlencoded`, headers the
    // macOS/Windows backends never send. Only opt into POST framing when the
    // request actually carries (or should advertise) a body.
    std::string method_upper = method;
    for (char& mc : method_upper) {
        mc = static_cast<char>(std::toupper(static_cast<unsigned char>(mc)));
    }
    bool suppress_default_content_type = false;
    if (!body.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method_upper == "HEAD") {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (method_upper == "POST" || method_upper == "PUT" || method_upper == "PATCH") {
        // Body-carrying methods with an empty body still advertise
        // `Content-Length: 0` (matching undici and the macOS/Windows
        // backends), but must not inherit curl's default form Content-Type.
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
        suppress_default_content_type = true;
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
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
    if (suppress_default_content_type) {
        bool has_content_type = false;
        static const char kContentType[] = "content-type:";
        for (size_t line = 0; line < headers.size();) {
            size_t eol = headers.find("\r\n", line);
            size_t line_end = eol == std::string::npos ? headers.size() : eol;
            size_t i = 0;
            while (kContentType[i] != '\0' && line + i < line_end &&
                   std::tolower(static_cast<unsigned char>(headers[line + i])) == kContentType[i]) {
                i++;
            }
            if (kContentType[i] == '\0') {
                has_content_type = true;
                break;
            }
            if (eol == std::string::npos) break;
            line = eol + 2;
        }
        if (!has_content_type) {
            // A valueless header tells curl to drop its internally generated one.
            curl_headers = curl_slist_append(curl_headers, "Content-Type:");
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
    // ENG-23471 — surface the server's real reason phrase (empty for HTTP/2+)
    // instead of hardcoding "OK" for every status code.
    result.status_text = parse_status_reason(result.response_headers);

    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);
    remove_fetch_request(request_id);

    if (cancelled || request_cancelled(request_state)) {
        return;
    }
    const char* status_text = result.status_text.c_str();
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

    // @ref LLP 0008#linux-networking — ENG-23874: the degraded CLI fallback
    // must not route request data through a shell: build an argv array and
    // posix_spawnp it directly, so there is no quoting layer whose correctness
    // every future flag has to preserve. The URL is bound to --url (not
    // positional) so a URL beginning with `-` cannot be parsed as a curl
    // option.
    // No -L flag: don't auto-follow redirects — let JS handle redirect logic.
    std::vector<std::string> args = {
        "curl", "-sS",
        "--connect-timeout", "30",
        "--max-time", "300",
        "-X", method,
        "-D", header_path,
        "-o", body_path,
        "-w", "%{http_code}",
    };

    if (!headers.empty()) {
        const char* line_start = headers.c_str();
        const char* p = headers.c_str();
        while (*p) {
            if (*p == '\r' && *(p + 1) == '\n') {
                if (p > line_start) {
                    args.emplace_back("-H");
                    args.emplace_back(line_start, static_cast<size_t>(p - line_start));
                }
                p += 2;
                line_start = p;
                continue;
            }
            p++;
        }
        if (p > line_start) {
            args.emplace_back("-H");
            args.emplace_back(line_start, static_cast<size_t>(p - line_start));
        }
    }

    if (!req_body_path.empty()) {
        args.emplace_back("--data-binary");
        args.emplace_back("@" + req_body_path);
    }

    args.emplace_back("--url");
    args.emplace_back(url);

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (std::string& arg : args) {
        argv.push_back(&arg[0]);
    }
    argv.push_back(nullptr);

    // stdout carries only curl's `-w %{http_code}` output; capture it in the
    // mkstemp-created (0600) status file. stdin/stderr go to /dev/null, as the
    // shell redirection used to do.
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(
        &actions, STDOUT_FILENO, code_path.c_str(), O_WRONLY | O_TRUNC, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    pid_t curl_pid = 0;
    const int spawn_rc =
        posix_spawnp(&curl_pid, "curl", &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);

    int rc = -1;
    if (spawn_rc == 0) {
        int wait_status = 0;
        pid_t waited;
        do {
            waited = waitpid(curl_pid, &wait_status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited == curl_pid && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0) {
            rc = 0;
        }
    }
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
    // ENG-23471 — report the server's real reason phrase, not a hardcoded "OK".
    const std::string reason = parse_status_reason(response_headers);
    response_callback(
        request_id,
        status_code,
        status_code > 0 ? reason.c_str() : "Network Error",
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

    // ENG-23471 — run the blocking transfer on the bounded FetchWorkerPool
    // instead of a fresh detached thread per request.
    std::string pool_error;
    const bool queued = FetchWorkerPool::instance().enqueue(
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
        },
        pool_error
    );
    if (!queued) {
        remove_fetch_request(request_id);
        response_callback(request_id, 0, pool_error.c_str(), nullptr, nullptr, 0, context);
    }
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
