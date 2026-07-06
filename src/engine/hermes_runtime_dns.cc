#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <condition_variable>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sstream>
#include <sys/socket.h>

#include "hermes_runtime_internal.h"

#if defined(EXACT_PLATFORM_ANDROID)
extern "C" int android_dns_query(
    const char* hostname,
    int qtype,
    uint8_t* answer,
    size_t answer_capacity,
    size_t* answer_length,
    char* error,
    size_t error_capacity);
#endif

namespace {

// Result of a blocking resolver call performed off the JS thread. Carries only
// plain data (JSON payload / error message) so it can cross the worker→runtime
// thread boundary without touching JSI (which is single-threaded). (ENG-22995)
struct DnsResult {
  bool ok = false;
  std::string payload;  // JSON string on success
  std::string error;    // error message on failure
};

// getaddrinfo + JSON serialization. No JSI: safe to run on a worker thread.
// Mirrors the historical synchronous __exactDnsLookup body. (ENG-22995)
DnsResult doDnsLookup(const std::string& hostname, int family) {
  struct addrinfo hints = {};
  hints.ai_socktype = SOCK_STREAM;
  if (family == 4) {
    hints.ai_family = AF_INET;
  } else if (family == 6) {
    hints.ai_family = AF_INET6;
  } else {
    hints.ai_family = AF_UNSPEC;
  }

  struct addrinfo* result = nullptr;
  int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
  if (ret != 0 || !result) {
    if (result) {
      freeaddrinfo(result);
    }
    return {false, "",
            std::string("getaddrinfo failed for ") + hostname + ": " + gai_strerror(ret)};
  }

  // Stream JSON output to avoid quadratic reallocations as records accumulate.
  std::ostringstream json;
  json << '[';
  bool first = true;
  for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
    char addr[INET6_ADDRSTRLEN] = {};
    int fam = 4;
    if (p->ai_family == AF_INET) {
      auto* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
      inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));
      fam = 4;
    } else if (p->ai_family == AF_INET6) {
      auto* sa = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
      inet_ntop(AF_INET6, &sa->sin6_addr, addr, sizeof(addr));
      fam = 6;
    } else {
      continue;
    }
    if (!first) {
      json << ',';
    }
    json << "{\"address\":\"" << addr << "\",\"family\":" << fam << '}';
    first = false;
  }
  json << ']';
  freeaddrinfo(result);

  DnsResult out;
  out.ok = true;
  out.payload = json.str();
  return out;
}

// Map a JS rrtype string to a resolver query type. Returns -1 for unsupported
// types. Pure/non-blocking, so callers run it on the JS thread. (ENG-22995)
int dnsRrtypeToQtype(const std::string& rrtype) {
  if (rrtype == "MX") return ns_t_mx;
  if (rrtype == "TXT") return ns_t_txt;
  if (rrtype == "SRV") return ns_t_srv;
  if (rrtype == "NS") return ns_t_ns;
  if (rrtype == "CNAME") return ns_t_cname;
  if (rrtype == "SOA") return ns_t_soa;
  if (rrtype == "PTR") return ns_t_ptr;
  if (rrtype == "CAA") return 257;
  if (rrtype == "NAPTR") return ns_t_naptr;
  return -1;
}

// res_query + record parsing. No JSI: safe to run on a worker thread. `qtype`
// is already mapped (see dnsRrtypeToQtype); `rrtype` is carried for error
// text. Mirrors the historical synchronous __exactDnsResolve body. (ENG-22995)
DnsResult doDnsResolve(const std::string& hostname, int qtype, const std::string& rrtype) {
  unsigned char answer[4096];
  int len = -1;
#if defined(EXACT_PLATFORM_ANDROID)
  // @ref LLP 0008#android-backend-matrix — Android raw DNS record
  // queries use DnsResolver when available, with the POSIX resolver as
  // the API-level fallback.
  size_t androidAnswerLength = 0;
  char androidDnsError[256] = {};
  int androidDnsResult = android_dns_query(
      hostname.c_str(),
      qtype,
      answer,
      sizeof(answer),
      &androidAnswerLength,
      androidDnsError,
      sizeof(androidDnsError));
  if (androidDnsResult > 0) {
    len = static_cast<int>(androidAnswerLength);
  }
#endif
  if (len < 0) {
    len = res_query(hostname.c_str(), ns_c_in, qtype, answer, sizeof(answer));
  }
  if (len < 0) {
    return {false, "", "DNS query failed for " + hostname + " type " + rrtype};
  }
  ns_msg msg;
  if (ns_initparse(answer, len, &msg) < 0) {
    return {false, "", "Failed to parse DNS response"};
  }
  int rrCount = ns_msg_count(msg, ns_s_an);
  // Stream JSON output to avoid quadratic string growth when a response contains many
  // records.
  std::ostringstream json;
  json << '[';
  bool first = true;
  auto appendRecord = [&json, &first](const std::string& record) {
    if (!first) {
      json << ',';
    }
    first = false;
    json << record;
  };
  for (int i = 0; i < rrCount; i++) {
    ns_rr rr;
    if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) {
      continue;
    }
    if (ns_rr_type(rr) != qtype) {
      continue;
    }
    const unsigned char* rdata = ns_rr_rdata(rr);
    int rdlen = ns_rr_rdlen(rr);
    if (qtype == ns_t_mx) {
      if (rdlen < 3) {
        continue;
      }
      uint32_t prio = (static_cast<uint32_t>(rdata[0]) << 8) |
                      static_cast<uint32_t>(rdata[1]);
      char ex[NS_MAXDNAME];
      if (ns_name_uncompress(
              ns_msg_base(msg), ns_msg_end(msg), rdata + 2, ex, sizeof(ex)) < 0) {
        continue;
      }
      std::string exchange(ex);
      if (!exchange.empty() && exchange.back() == '.') {
        exchange.pop_back();
      }
      std::string exJson;
      if (!appendEscapedJsonText(
              exJson,
              reinterpret_cast<const uint8_t*>(exchange.c_str()),
              exchange.size())) {
        continue;
      }
      appendRecord(
          "{\"priority\":" + std::to_string(prio) + ",\"exchange\":" + exJson + "}");
    } else if (qtype == ns_t_txt) {
      int p = 0;
      bool valid = true;
      bool firstText = true;
      std::ostringstream texts;
      texts << '[';
      while (p < rdlen) {
        uint8_t sl = static_cast<uint8_t>(rdata[p]);
        p++;
        if (p + static_cast<int>(sl) > rdlen) {
          valid = false;
          break;
        }
        std::string textJson;
        if (!appendEscapedJsonText(textJson, rdata + p, sl)) {
          valid = false;
          break;
        }
        if (!firstText) {
          texts << ',';
        }
        firstText = false;
        texts << textJson;
        p += sl;
      }
      if (!valid) {
        continue;
      }
      texts << ']';
      appendRecord(texts.str());
    } else if (qtype == ns_t_srv) {
      if (rdlen < 7) {
        continue;
      }
      uint32_t prio = (static_cast<uint32_t>(rdata[0]) << 8) |
                      static_cast<uint32_t>(rdata[1]);
      uint32_t weight = (static_cast<uint32_t>(rdata[2]) << 8) |
                        static_cast<uint32_t>(rdata[3]);
      uint32_t port = (static_cast<uint32_t>(rdata[4]) << 8) |
                      static_cast<uint32_t>(rdata[5]);
      char target[NS_MAXDNAME];
      if (ns_name_uncompress(
              ns_msg_base(msg), ns_msg_end(msg), rdata + 6, target, sizeof(target)) < 0) {
        continue;
      }
      std::string targetName(target);
      if (!targetName.empty() && targetName.back() == '.') {
        targetName.pop_back();
      }
      std::string targetJson;
      if (!appendEscapedJsonText(
              targetJson,
              reinterpret_cast<const uint8_t*>(targetName.c_str()),
              targetName.size())) {
        continue;
      }
      appendRecord(
          "{\"priority\":" + std::to_string(prio) + ",\"weight\":" +
          std::to_string(weight) + ",\"port\":" + std::to_string(port) +
          ",\"name\":" + targetJson + "}");
    } else if (qtype == ns_t_ns) {
      char name[NS_MAXDNAME];
      if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, name, sizeof(name)) <
          0) {
        continue;
      }
      std::string nsName(name);
      if (!nsName.empty() && nsName.back() == '.') {
        nsName.pop_back();
      }
      std::string nsJson;
      if (!appendEscapedJsonText(
              nsJson,
              reinterpret_cast<const uint8_t*>(nsName.c_str()),
              nsName.size())) {
        continue;
      }
      appendRecord(nsJson);
    } else if (qtype == ns_t_cname) {
      char cname[NS_MAXDNAME];
      if (ns_name_uncompress(
              ns_msg_base(msg), ns_msg_end(msg), rdata, cname, sizeof(cname)) < 0) {
        continue;
      }
      std::string alias(cname);
      if (!alias.empty() && alias.back() == '.') {
        alias.pop_back();
      }
      std::string aliasJson;
      if (!appendEscapedJsonText(
              aliasJson,
              reinterpret_cast<const uint8_t*>(alias.c_str()),
              alias.size())) {
        continue;
      }
      appendRecord(aliasJson);
    } else if (qtype == ns_t_soa) {
      char mname[NS_MAXDNAME];
      int offset1 = ns_name_uncompress(
          ns_msg_base(msg), ns_msg_end(msg), rdata, mname, sizeof(mname));
      if (offset1 < 0) {
        continue;
      }
      std::string nsname(mname);
      if (!nsname.empty() && nsname.back() == '.') {
        nsname.pop_back();
      }
      char rname[NS_MAXDNAME];
      int offset2 = ns_name_uncompress(
          ns_msg_base(msg), ns_msg_end(msg), rdata + offset1, rname, sizeof(rname));
      if (offset2 < 0) {
        continue;
      }
      std::string hostmaster(rname);
      if (!hostmaster.empty() && hostmaster.back() == '.') {
        hostmaster.pop_back();
      }
      const unsigned char* soaData = rdata + offset1 + offset2;
      if (offset1 + offset2 + 20 > rdlen) {
        continue;
      }
      uint32_t serial = (uint32_t(soaData[0]) << 24) | (uint32_t(soaData[1]) << 16) |
                        (uint32_t(soaData[2]) << 8) | soaData[3];
      int32_t refresh = static_cast<int32_t>(
          (uint32_t(soaData[4]) << 24) | (uint32_t(soaData[5]) << 16) |
          (uint32_t(soaData[6]) << 8) | uint32_t(soaData[7]));
      int32_t retry = static_cast<int32_t>(
          (uint32_t(soaData[8]) << 24) | (uint32_t(soaData[9]) << 16) |
          (uint32_t(soaData[10]) << 8) | uint32_t(soaData[11]));
      int32_t expire = static_cast<int32_t>(
          (uint32_t(soaData[12]) << 24) | (uint32_t(soaData[13]) << 16) |
          (uint32_t(soaData[14]) << 8) | uint32_t(soaData[15]));
      uint32_t minTtl = (uint32_t(soaData[16]) << 24) |
                        (uint32_t(soaData[17]) << 16) |
                        (uint32_t(soaData[18]) << 8) | soaData[19];
      std::string nsnameJson;
      std::string hostmasterJson;
      if (!appendEscapedJsonText(
              nsnameJson,
              reinterpret_cast<const uint8_t*>(nsname.c_str()),
              nsname.size())) {
        continue;
      }
      if (!appendEscapedJsonText(
              hostmasterJson,
              reinterpret_cast<const uint8_t*>(hostmaster.c_str()),
              hostmaster.size())) {
        continue;
      }
      appendRecord(
          "{\"nsname\":" + nsnameJson + ",\"hostmaster\":" + hostmasterJson +
          ",\"serial\":" + std::to_string(serial) + ",\"refresh\":" +
          std::to_string(refresh) + ",\"retry\":" + std::to_string(retry) +
          ",\"expire\":" + std::to_string(expire) + ",\"minttl\":" +
          std::to_string(minTtl) + "}");
    } else if (qtype == ns_t_ptr) {
      char ptrName[NS_MAXDNAME];
      if (ns_name_uncompress(
              ns_msg_base(msg), ns_msg_end(msg), rdata, ptrName, sizeof(ptrName)) < 0) {
        continue;
      }
      std::string reverseName(ptrName);
      if (!reverseName.empty() && reverseName.back() == '.') {
        reverseName.pop_back();
      }
      std::string reverseJson;
      if (!appendEscapedJsonText(
              reverseJson,
              reinterpret_cast<const uint8_t*>(reverseName.c_str()),
              reverseName.size())) {
        continue;
      }
      appendRecord(reverseJson);
    } else if (qtype == 257) {
      if (rdlen < 2) {
        continue;
      }
      uint8_t flags = rdata[0];
      uint8_t tagLen = rdata[1];
      if (static_cast<size_t>(2 + tagLen) > static_cast<size_t>(rdlen)) {
        continue;
      }
      size_t offset = static_cast<size_t>(2 + tagLen);
      size_t valueLen = static_cast<size_t>(rdlen) - offset;
      std::string tag;
      if (!appendEscapedJsonText(tag, rdata + 2, static_cast<size_t>(tagLen))) {
        continue;
      }
      std::string value;
      if (!appendEscapedJsonText(value, rdata + 2 + tagLen, valueLen)) {
        continue;
      }
      appendRecord(
          "{\"critical\":" + std::to_string(static_cast<uint32_t>(flags)) + "," + tag +
          ":" + value + "}");
    }
  }
  json << ']';

  DnsResult out;
  out.ok = true;
  out.payload = json.str();
  return out;
}

// getnameinfo. No JSI: safe to run on a worker thread. `ip` has already been
// validated (see the host-function entry) but is re-parsed here so the worker
// is self-contained. Mirrors the historical synchronous __exactDnsReverse
// body. (ENG-22995)
DnsResult doDnsReverse(const std::string& ip) {
  struct sockaddr_storage sa;
  socklen_t salen = 0;
  memset(&sa, 0, sizeof(sa));
  auto* sa4 = reinterpret_cast<struct sockaddr_in*>(&sa);
  auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(&sa);
  if (inet_pton(AF_INET, ip.c_str(), &sa4->sin_addr) == 1) {
    sa4->sin_family = AF_INET;
    salen = sizeof(struct sockaddr_in);
  } else if (inet_pton(AF_INET6, ip.c_str(), &sa6->sin6_addr) == 1) {
    sa6->sin6_family = AF_INET6;
    salen = sizeof(struct sockaddr_in6);
  } else {
    return {false, "", "invalid IP address: " + ip};
  }
  char host[NI_MAXHOST];
  int ret = getnameinfo(
      reinterpret_cast<struct sockaddr*>(&sa),
      salen,
      host,
      sizeof(host),
      nullptr,
      0,
      NI_NAMEREQD);
  if (ret != 0) {
    return {false, "", "getnameinfo failed for " + ip + ": " + gai_strerror(ret)};
  }

  DnsResult out;
  out.ok = true;
  out.payload = std::string("[") + jsonString(host) + "]";
  return out;
}

// Bounded worker pool that runs the blocking resolver calls off the JS thread.
// Same discipline as hermes_runtime_http.cc's WaitWorkerPool: lazily spawn
// workers up to a cap, bound the backlog, and block workers on a condvar when
// idle. Process-global; each job carries its own runtime handle. (ENG-22995)
class DnsWorkerPool {
 public:
  static DnsWorkerPool& instance() {
    static DnsWorkerPool pool;
    return pool;
  }

  bool enqueue(std::function<void()> job, std::string& error) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (idle_ == 0 && total_ >= kMaxWorkers) {
        error = "DNS worker pool exhausted";
        return false;
      }
      if (queue_.size() >= kMaxQueue) {
        error = "DNS worker queue full";
        return false;
      }
      spawnWorkerIfNeededLocked();
      queue_.push_back(std::move(job));
    }
    cv_.notify_one();
    return true;
  }

 private:
  static constexpr size_t kMaxWorkers = 8;
  static constexpr size_t kMaxQueue = 512;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  size_t idle_ = 0;
  size_t total_ = 0;

  void spawnWorkerIfNeededLocked() {
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

// Build a Promise whose resolution runs `work` on a DNS worker thread and
// delivers the DnsResult back on the runtime thread via pushRuntimeCallback —
// the same wake-driven discipline as __hostCallAsync / fetch. The caller must
// have already validated arguments and enforced capabilities on the JS thread.
// (ENG-22995)
facebook::jsi::Value startDnsAsync(
    ExactHermesRuntime* handle,
    facebook::jsi::Runtime& runtime,
    std::function<DnsResult()> work) {
  // Capture the scheduling principal on the JS thread so the resolved
  // continuation is attributed to the caller, not a bare native frame.
  uint64_t principal = currentPrincipalId();
  auto workPtr = std::make_shared<std::function<DnsResult()>>(std::move(work));
  auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
  auto executor = facebook::jsi::Function::createFromHostFunction(
      runtime,
      facebook::jsi::PropNameID::forAscii(runtime, "executor"),
      2,
      [handle, principal, workPtr](
          facebook::jsi::Runtime& rt,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isObject() || !args[1].isObject()) {
          throw facebook::jsi::JSError(rt, "DNS async: malformed executor invocation");
        }
        auto resolve =
            std::make_shared<facebook::jsi::Function>(args[0].asObject(rt).asFunction(rt));
        auto reject =
            std::make_shared<facebook::jsi::Function>(args[1].asObject(rt).asFunction(rt));

        // Mark the lookup in flight before dispatching so the event loop stays
        // alive across the resolver call even with no other pending work.
        handle->pending_dns_lookups.fetch_add(1, std::memory_order_relaxed);

        std::string enqueueError;
        bool queued = DnsWorkerPool::instance().enqueue(
            [handle, principal, workPtr, resolve, reject]() {
              DnsResult result = (*workPtr)();
              pushRuntimeCallback(
                  handle,
                  [handle, principal, resolve, reject, result](
                      facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    handle->pending_dns_lookups.fetch_sub(1, std::memory_order_relaxed);
                    try {
                      if (result.ok) {
                        resolve->call(
                            rt, facebook::jsi::String::createFromUtf8(rt, result.payload));
                      } else {
                        reject->call(rt, facebook::jsi::JSError(rt, result.error).value());
                      }
                    } catch (...) {
                    }
                  });
            },
            enqueueError);
        if (!queued) {
          handle->pending_dns_lookups.fetch_sub(1, std::memory_order_relaxed);
          reject->call(rt, facebook::jsi::JSError(rt, enqueueError).value());
        }
        return facebook::jsi::Value::undefined();
      });
  return promiseCtor.callAsConstructor(runtime, executor);
}

}  // namespace

void installDnsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  // --- DNS lookup ---
  // __exactDnsLookup(hostname, family) -> JSON string { address, family }
  // Synchronous/blocking. Retained for backward compatibility and as the
  // fallback path in dns.js; new call sites use __exactDnsLookupAsync. (ENG-22995)
  auto dnsLookupFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsLookup"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsLookup: hostname required");
        }
        auto hostname = args[0].asString(runtime).utf8(runtime);
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsLookup");
        int family = 0;  // 0 = any, 4 = IPv4, 6 = IPv6
        if (count > 1 && args[1].isNumber()) {
          family = static_cast<int>(args[1].asNumber());
        }
        DnsResult result = doDnsLookup(hostname, family);
        if (!result.ok) {
          throw facebook::jsi::JSError(runtime, result.error);
        }
        return facebook::jsi::String::createFromUtf8(runtime, result.payload);
      });
  rt.global().setProperty(rt, "__exactDnsLookup", std::move(dnsLookupFn));

  // __exactDnsLookupAsync(hostname, family) -> Promise<JSON string>
  // Non-blocking: getaddrinfo runs on the DNS worker pool and the Promise is
  // resolved on the runtime thread, so a slow resolver never freezes timers or
  // other I/O. Capability + arg checks stay synchronous on the JS thread so
  // frame attribution sees the real caller. (ENG-22995)
  auto dnsLookupAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsLookupAsync"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsLookupAsync: hostname required");
        }
        auto hostname = args[0].asString(runtime).utf8(runtime);
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsLookupAsync");
        int family = 0;
        if (count > 1 && args[1].isNumber()) {
          family = static_cast<int>(args[1].asNumber());
        }
        return startDnsAsync(handle, runtime, [hostname, family]() -> DnsResult {
          return doDnsLookup(hostname, family);
        });
      });
  rt.global().setProperty(rt, "__exactDnsLookupAsync", std::move(dnsLookupAsyncFn));

  // __exactDnsResolve(hostname, rrtype) -> JSON array via res_query
  // Synchronous/blocking fallback; new call sites use __exactDnsResolveAsync.
  auto dnsResolveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsResolve"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsResolve requires hostname and rrtype");
        }
        auto hostname = args[0].asString(runtime).utf8(runtime);
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsResolve");
        auto rrtype = args[1].asString(runtime).utf8(runtime);
        int qtype = dnsRrtypeToQtype(rrtype);
        if (qtype < 0) {
          throw facebook::jsi::JSError(runtime, ("unsupported record type: " + rrtype).c_str());
        }
        DnsResult result = doDnsResolve(hostname, qtype, rrtype);
        if (!result.ok) {
          throw facebook::jsi::JSError(runtime, result.error);
        }
        return facebook::jsi::String::createFromUtf8(runtime, result.payload);
      });
  rt.global().setProperty(rt, "__exactDnsResolve", std::move(dnsResolveFn));

  // __exactDnsResolveAsync(hostname, rrtype) -> Promise<JSON array>. (ENG-22995)
  auto dnsResolveAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsResolveAsync"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactDnsResolveAsync requires hostname and rrtype");
        }
        auto hostname = args[0].asString(runtime).utf8(runtime);
        requireNetworkResolveCapability(runtime, hostname, "__exactDnsResolveAsync");
        auto rrtype = args[1].asString(runtime).utf8(runtime);
        int qtype = dnsRrtypeToQtype(rrtype);
        if (qtype < 0) {
          throw facebook::jsi::JSError(runtime, ("unsupported record type: " + rrtype).c_str());
        }
        return startDnsAsync(handle, runtime, [hostname, qtype, rrtype]() -> DnsResult {
          return doDnsResolve(hostname, qtype, rrtype);
        });
      });
  rt.global().setProperty(rt, "__exactDnsResolveAsync", std::move(dnsResolveAsyncFn));

  // __exactDnsReverse(ip) -> JSON array of hostnames via getnameinfo
  // Synchronous/blocking fallback; new call sites use __exactDnsReverseAsync.
  auto dnsReverseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsReverse"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsReverse: ip address required");
        }
        auto ip = args[0].asString(runtime).utf8(runtime);
        // Validate the address up front so an invalid IP fails synchronously,
        // as before, and only a real reverse query reaches the resolver.
        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET, ip.c_str(), &addr4) != 1 &&
            inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) {
          throw facebook::jsi::JSError(runtime, ("invalid IP address: " + ip).c_str());
        }
        requireNetworkResolveCapability(runtime, ip, "__exactDnsReverse");
        DnsResult result = doDnsReverse(ip);
        if (!result.ok) {
          throw facebook::jsi::JSError(runtime, result.error);
        }
        return facebook::jsi::String::createFromUtf8(runtime, result.payload);
      });
  rt.global().setProperty(rt, "__exactDnsReverse", std::move(dnsReverseFn));

  // __exactDnsReverseAsync(ip) -> Promise<JSON array of hostnames>. (ENG-22995)
  auto dnsReverseAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsReverseAsync"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsReverseAsync: ip address required");
        }
        auto ip = args[0].asString(runtime).utf8(runtime);
        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET, ip.c_str(), &addr4) != 1 &&
            inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) {
          throw facebook::jsi::JSError(runtime, ("invalid IP address: " + ip).c_str());
        }
        requireNetworkResolveCapability(runtime, ip, "__exactDnsReverseAsync");
        return startDnsAsync(handle, runtime, [ip]() -> DnsResult {
          return doDnsReverse(ip);
        });
      });
  rt.global().setProperty(rt, "__exactDnsReverseAsync", std::move(dnsReverseAsyncFn));
}
