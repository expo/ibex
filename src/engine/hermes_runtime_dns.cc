#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <resolv.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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
  // Node-style dns error code ("ESERVFAIL", "EREFUSED", "ETIMEOUT", ...) when
  // the failure cause is known. Attached as `.code` on the JS error and echoed
  // in the message so dns.js can map resolver failures with fidelity instead
  // of flattening everything to ENOTFOUND. Empty = unknown cause. (ENG-23506)
  std::string code;
};

// DNS response rcode -> Node-compatible dns error code (c-ares naming).
const char* dnsRcodeToErrorCode(int rcode) {
  switch (rcode) {
    case 1: return "EFORMERR";
    case 2: return "ESERVFAIL";
    case 3: return "ENOTFOUND";
    case 4: return "ENOTIMP";
    case 5: return "EREFUSED";
    default: return "EBADRESP";
  }
}

// getaddrinfo/getnameinfo EAI_* -> the code Node's dns.lookup surfaces for the
// same condition (libuv maps EAI_NONAME/EAI_NODATA to ENOTFOUND and passes
// other EAI_* names through). (ENG-23506)
std::string gaiErrorToCode(int err) {
  switch (err) {
    case EAI_AGAIN: return "EAI_AGAIN";
    case EAI_FAIL: return "EAI_FAIL";
    case EAI_MEMORY: return "ENOMEM";
#if defined(EAI_NODATA)
    case EAI_NODATA: return "ENOTFOUND";
#endif
    case EAI_NONAME: return "ENOTFOUND";
    default: return "ENOTFOUND";
  }
}

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
    DnsResult out;
    out.code = ret != 0 ? gaiErrorToCode(ret) : "ENOTFOUND";
    out.error = std::string("getaddrinfo failed for ") + hostname + ": " + gai_strerror(ret) +
        " (" + out.code + ")";
    return out;
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

bool readDnsTextField(
    const unsigned char* rdata,
    int rdlen,
    int& offset,
    std::string& out) {
  if (offset >= rdlen) {
    return false;
  }
  uint8_t length = static_cast<uint8_t>(rdata[offset++]);
  if (offset + static_cast<int>(length) > rdlen) {
    return false;
  }
  if (!appendEscapedJsonText(out, rdata + offset, static_cast<size_t>(length))) {
    return false;
  }
  offset += length;
  return true;
}

#if !defined(EXACT_PLATFORM_ANDROID)

// --- Raw UDP DNS transport with rcode preservation (ENG-23506) ---
//
// libresolv flattens resolver failures: res_nsend treats SERVFAIL/NOTIMP/
// REFUSED responses as "try the next server" and, once every server has been
// skipped, fails with a generic timeout (verified empirically on macOS
// libresolv; glibc's send_dg has the same next_ns skip). Only NXDOMAIN and
// NOERROR rcodes ever reach the caller, so res_query can never distinguish
// ESERVFAIL/EREFUSED/ETIMEOUT the way Node's c-ares resolver does. To preserve
// rcode fidelity the default resolver path sends the query on its own UDP
// socket against the system-configured nameservers and inspects the rcode
// itself, mirroring c-ares. Truncated (TC) responses and configurations with
// no usable IPv4 nameserver fall back to the legacy res_query path.
// @ref LLP 0008#sockets-dns-and-process — default-path DNS rcode fidelity.

// Parse "timeout:N" / "attempts:N" tokens from the standard RES_OPTIONS env
// variable. glibc's res_ninit honors these natively but macOS libresolv
// ignores them (verified: retrans stays 30 regardless), so the raw transport
// applies them itself for uniform, test-controllable timing. (ENG-23506)
void applyResOptionsTiming(int& retransSec, int& retries) {
  const char* resOptions = std::getenv("RES_OPTIONS");
  if (!resOptions || !*resOptions) {
    return;
  }
  std::istringstream tokens(resOptions);
  std::string token;
  while (tokens >> token) {
    if (token.rfind("timeout:", 0) == 0) {
      int value = atoi(token.c_str() + 8);
      if (value > 0 && value <= 30) {
        retransSec = value;
      }
    } else if (token.rfind("attempts:", 0) == 0) {
      int value = atoi(token.c_str() + 9);
      if (value > 0 && value <= 5) {
        retries = value;
      }
    }
  }
}

// Load the resolver target list + timing. `IBEX_DNS_SERVER` ("a.b.c.d" or
// "a.b.c.d:port") overrides the system nameservers so tests can point the
// DEFAULT resolver path at a loopback mock server without touching
// /etc/resolv.conf (see tests/native_dns_rcode.rs); res_ninit supplies
// retrans/retry, then RES_OPTIONS "timeout:"/"attempts:" are applied on top
// for platforms whose res_ninit ignores them. (ENG-23506)
void loadDnsServers(std::vector<struct sockaddr_in>& servers, int& retransSec, int& retries) {
  retransSec = 5;
  retries = 2;
  const char* overrideSpec = std::getenv("IBEX_DNS_SERVER");
  if (overrideSpec && *overrideSpec) {
    std::string spec(overrideSpec);
    int port = 53;
    auto colon = spec.rfind(':');
    if (colon != std::string::npos) {
      port = atoi(spec.substr(colon + 1).c_str());
      spec = spec.substr(0, colon);
    }
    struct sockaddr_in sa = {};
    if (port > 0 && port <= 65535 && inet_pton(AF_INET, spec.c_str(), &sa.sin_addr) == 1) {
      sa.sin_family = AF_INET;
      sa.sin_port = htons(static_cast<uint16_t>(port));
      servers.push_back(sa);
    }
  }
  struct __res_state state;
  memset(&state, 0, sizeof(state));
  if (res_ninit(&state) == 0) {
    if (state.retrans > 0 && state.retrans <= 30) {
      retransSec = state.retrans;
    }
    if (state.retry > 0 && state.retry <= 5) {
      retries = state.retry;
    }
    if (servers.empty()) {
      for (int i = 0; i < state.nscount && i < MAXNS; ++i) {
        const struct sockaddr_in& sa = state.nsaddr_list[i];
        if (sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0) {
          servers.push_back(sa);
        }
      }
    }
    res_nclose(&state);
  }
  applyResOptionsTiming(retransSec, retries);
}

std::string systemDnsServersJson() {
  std::vector<struct sockaddr_in> servers;
  int retransSec = 0;
  int retries = 0;
  loadDnsServers(servers, retransSec, retries);
  std::ostringstream json;
  json << '[';
  bool first = true;
  for (const auto& server : servers) {
    char address[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &server.sin_addr, address, sizeof(address))) continue;
    if (!first) json << ',';
    first = false;
    json << '"' << address;
    uint16_t port = ntohs(server.sin_port);
    if (port != 0 && port != 53) json << ':' << port;
    json << '"';
  }
  json << ']';
  return json.str();
}

// Encode a standard recursive query (header + single QD). Returns false for
// names that cannot be encoded (empty/oversized labels). No search-domain
// semantics — res_query (the previous transport) never applied them either.
bool buildRawDnsQuery(
    const std::string& hostname,
    int qtype,
    uint16_t id,
    std::vector<unsigned char>& out) {
  out.clear();
  out.reserve(hostname.size() + 18);
  out.push_back(static_cast<unsigned char>(id >> 8));
  out.push_back(static_cast<unsigned char>(id & 0xFF));
  out.push_back(0x01);  // RD
  out.push_back(0x00);
  out.push_back(0x00);
  out.push_back(0x01);  // QDCOUNT = 1
  for (int i = 0; i < 6; ++i) {
    out.push_back(0x00);  // AN/NS/AR counts
  }
  size_t labelStart = 0;
  size_t nameLength = 0;
  const std::string& name = hostname;
  for (size_t i = 0; i <= name.size(); ++i) {
    if (i == name.size() || name[i] == '.') {
      size_t labelLen = i - labelStart;
      if (labelLen == 0) {
        // Allow a single trailing dot; reject empty labels elsewhere.
        if (i == name.size() && i > 0) {
          break;
        }
        return false;
      }
      if (labelLen > 63) {
        return false;
      }
      nameLength += labelLen + 1;
      if (nameLength > 255) {
        return false;
      }
      out.push_back(static_cast<unsigned char>(labelLen));
      out.insert(out.end(), name.begin() + labelStart, name.begin() + i);
      labelStart = i + 1;
    }
  }
  out.push_back(0x00);
  out.push_back(static_cast<unsigned char>((qtype >> 8) & 0xFF));
  out.push_back(static_cast<unsigned char>(qtype & 0xFF));
  out.push_back(0x00);
  out.push_back(0x01);  // class IN
  return true;
}

struct RawDnsOutcome {
  int len = -1;              // >= 0: usable response bytes written into `answer`
  int rcode = -1;            // rcode of the last received response, -1 if none
  bool truncated = false;    // TC bit seen: caller should retry via res_query (TCP)
  bool connRefused = false;  // ICMP port unreachable observed
};

// Send the query to each configured server with per-attempt timeout
// `retransSec`, `retries` passes. NOERROR/NXDOMAIN responses finish the query;
// other rcodes are remembered and the next server is tried (like c-ares), so
// a SERVFAIL from every server reports ESERVFAIL rather than a fake timeout.
RawDnsOutcome sendRawDnsQuery(
    const std::vector<struct sockaddr_in>& servers,
    int retransSec,
    int retries,
    const std::vector<unsigned char>& query,
    unsigned char* answer,
    size_t answerCapacity) {
  RawDnsOutcome outcome;
  const uint16_t queryId =
      static_cast<uint16_t>((static_cast<uint16_t>(query[0]) << 8) | query[1]);
  for (int attempt = 0; attempt < retries && outcome.len < 0; ++attempt) {
    for (const auto& server : servers) {
      int fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (fd < 0) {
        continue;
      }
      fcntl(fd, F_SETFD, FD_CLOEXEC);
      // connect() so an ICMP port-unreachable surfaces as ECONNREFUSED on
      // recv, which maps to Node's ECONNREFUSED "could not contact server".
      if (connect(fd, reinterpret_cast<const struct sockaddr*>(&server), sizeof(server)) != 0 ||
          send(fd, query.data(), query.size(), 0) != static_cast<ssize_t>(query.size())) {
        if (errno == ECONNREFUSED) {
          outcome.connRefused = true;
        }
        close(fd);
        continue;
      }
      auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(retransSec);
      bool gotFinalAnswer = false;
      for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - std::chrono::steady_clock::now())
                             .count();
        if (remaining <= 0) {
          break;
        }
        struct pollfd pfd = {fd, POLLIN, 0};
        int pollResult = poll(&pfd, 1, static_cast<int>(remaining));
        if (pollResult <= 0) {
          break;  // timeout (or poll error): next server / next attempt
        }
        ssize_t got = recv(fd, answer, answerCapacity, 0);
        if (got < 0) {
          if (errno == ECONNREFUSED) {
            outcome.connRefused = true;
          }
          break;
        }
        if (got < NS_HFIXEDSZ) {
          continue;  // runt datagram: keep waiting for a real response
        }
        uint16_t responseId =
            static_cast<uint16_t>((static_cast<uint16_t>(answer[0]) << 8) | answer[1]);
        if (responseId != queryId || (answer[2] & 0x80) == 0) {
          continue;  // not our response: keep waiting
        }
        outcome.rcode = answer[3] & 0x0F;
        if ((answer[2] & 0x02) != 0) {
          outcome.truncated = true;
          gotFinalAnswer = true;
          break;
        }
        if (outcome.rcode == 0 || outcome.rcode == 3 /* NXDOMAIN */) {
          outcome.len = static_cast<int>(got);
          gotFinalAnswer = true;
        }
        // Other rcodes (SERVFAIL/REFUSED/...): remembered in outcome.rcode;
        // fall through to the next server in case another one can answer.
        break;
      }
      close(fd);
      if (gotFinalAnswer || outcome.truncated) {
        return outcome;
      }
    }
  }
  return outcome;
}

#endif  // !EXACT_PLATFORM_ANDROID

// Default-path record query + parsing. No JSI: safe to run on a worker thread.
// `qtype` is already mapped (see dnsRrtypeToQtype); `rrtype` is carried for
// error text. The transport preserves resolver rcodes (see the raw UDP block
// above) so failures carry Node-compatible codes; parsing mirrors the
// historical synchronous __exactDnsResolve body. (ENG-22995 / ENG-23506)
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
#else
  // Raw UDP transport first so resolver rcodes survive; res_query only as the
  // fallback for truncated responses (it retries over TCP) or configurations
  // without a usable IPv4 nameserver. (ENG-23506)
  std::vector<struct sockaddr_in> servers;
  int retransSec = 5;
  int retries = 2;
  loadDnsServers(servers, retransSec, retries);
  if (!servers.empty()) {
    std::random_device randomDevice;
    uint16_t queryId = static_cast<uint16_t>(randomDevice());
    std::vector<unsigned char> query;
    if (!buildRawDnsQuery(hostname, qtype, queryId, query)) {
      DnsResult out;
      out.code = "EBADNAME";
      out.error = "DNS query failed for " + hostname + " type " + rrtype + " (EBADNAME)";
      return out;
    }
    RawDnsOutcome outcome =
        sendRawDnsQuery(servers, retransSec, retries, query, answer, sizeof(answer));
    if (outcome.len >= 0) {
      len = outcome.len;
    } else if (!outcome.truncated) {
      DnsResult out;
      if (outcome.rcode > 0) {
        out.code = dnsRcodeToErrorCode(outcome.rcode);
      } else if (outcome.connRefused) {
        out.code = "ECONNREFUSED";
      } else {
        out.code = "ETIMEOUT";
      }
      out.error =
          "DNS query failed for " + hostname + " type " + rrtype + " (" + out.code + ")";
      return out;
    }
    // Truncated: fall through to res_query below for the TCP retry.
  }
#endif
  if (len < 0) {
    len = res_query(hostname.c_str(), ns_c_in, qtype, answer, sizeof(answer));
  }
  if (len < 0) {
    return {false, "", "DNS query failed for " + hostname + " type " + rrtype, ""};
  }
  // Any transport can hand back a non-NOERROR packet (NXDOMAIN from the raw
  // UDP path, or whatever the Android DnsResolver returned): map its rcode
  // before parsing so the JS layer sees ENOTFOUND/ESERVFAIL/... instead of an
  // empty record set. (ENG-23506)
  if (len >= NS_HFIXEDSZ) {
    int responseRcode = answer[3] & 0x0F;
    if (responseRcode != 0) {
      DnsResult out;
      out.code = dnsRcodeToErrorCode(responseRcode);
      out.error =
          "DNS query failed for " + hostname + " type " + rrtype + " (" + out.code + ")";
      return out;
    }
  }
  ns_msg msg;
  if (ns_initparse(answer, len, &msg) < 0) {
    return {false, "", "Failed to parse DNS response", ""};
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
    } else if (qtype == ns_t_naptr) {
      if (rdlen < 5) {
        continue;
      }
      uint32_t order = (static_cast<uint32_t>(rdata[0]) << 8) |
                       static_cast<uint32_t>(rdata[1]);
      uint32_t preference = (static_cast<uint32_t>(rdata[2]) << 8) |
                            static_cast<uint32_t>(rdata[3]);
      int offset = 4;
      std::string flagsJson;
      std::string serviceJson;
      std::string regexpJson;
      if (!readDnsTextField(rdata, rdlen, offset, flagsJson) ||
          !readDnsTextField(rdata, rdlen, offset, serviceJson) ||
          !readDnsTextField(rdata, rdlen, offset, regexpJson)) {
        continue;
      }
      char replacement[NS_MAXDNAME];
      int consumed = ns_name_uncompress(
          ns_msg_base(msg), ns_msg_end(msg), rdata + offset, replacement, sizeof(replacement));
      if (consumed < 0 || offset + consumed != rdlen) {
        continue;
      }
      std::string replacementName(replacement);
      if (!replacementName.empty() && replacementName.back() == '.') {
        replacementName.pop_back();
      }
      std::string replacementJson;
      if (!appendEscapedJsonText(
              replacementJson,
              reinterpret_cast<const uint8_t*>(replacementName.c_str()),
              replacementName.size())) {
        continue;
      }
      appendRecord(
          "{\"flags\":" + flagsJson + ",\"service\":" + serviceJson +
          ",\"regexp\":" + regexpJson + ",\"replacement\":" + replacementJson +
          ",\"order\":" + std::to_string(order) + ",\"preference\":" +
          std::to_string(preference) + "}");
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
    return {false, "", "invalid IP address: " + ip, ""};
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
    DnsResult out;
    out.code = gaiErrorToCode(ret);
    out.error = "getnameinfo failed for " + ip + ": " + gai_strerror(ret) +
        " (" + out.code + ")";
    return out;
  }

  DnsResult out;
  out.ok = true;
  out.payload = std::string("[") + jsonString(host) + "]";
  return out;
}

// Build the JS Error for a failed DnsResult, attaching the Node-style dns
// `code` when known so dns.js can map the failure without message scraping
// (the code token is also embedded in the message as a fallback). (ENG-23506)
facebook::jsi::Value dnsErrorValue(facebook::jsi::Runtime& rt, const DnsResult& result) {
  facebook::jsi::JSError jsError(rt, result.error);
  facebook::jsi::Value errValue(rt, jsError.value());
  if (!result.code.empty() && errValue.isObject()) {
    errValue.asObject(rt).setProperty(
        rt, "code", facebook::jsi::String::createFromUtf8(rt, result.code));
  }
  return errValue;
}

// Throw a failed DnsResult from a synchronous host function, preserving the
// dns `code` property on the thrown error. (ENG-23506)
[[noreturn]] void throwDnsError(facebook::jsi::Runtime& rt, const DnsResult& result) {
  facebook::jsi::JSError jsError(rt, result.error);
  if (!result.code.empty()) {
    facebook::jsi::Value errValue(rt, jsError.value());
    if (errValue.isObject()) {
      errValue.asObject(rt).setProperty(
          rt, "code", facebook::jsi::String::createFromUtf8(rt, result.code));
    }
  }
  throw jsError;
}

// Bounded worker pool that runs the blocking resolver calls off the JS thread.
// Same discipline as hermes_runtime_http.cc's WaitWorkerPool: lazily spawn
// workers up to a cap, bound the backlog, and block workers on a condvar when
// idle. Process-global; each job carries its own runtime handle. (ENG-22995)
class DnsWorkerPool {
 public:
  static DnsWorkerPool& instance() {
    // ENG-23498 — intentionally leaked (same fix as FetchWorkerPool in
    // native_fetch_linux.cc, ENG-23471): a function-local
    // `static DnsWorkerPool` is destructed during exit() while detached
    // workers are still parked in cv_.wait(), and destroying a mutex/condvar
    // with waiters is UB that deadlocks the process inside glibc's pthread
    // destructors (run-verified on Linux: one dns.lookup followed by
    // `process.exit(0)` hung forever with a by-value static; macOS never
    // reproduces it). Workers are detached, so leaking the pool lets exit()
    // proceed normally.
    static DnsWorkerPool* pool = new DnsWorkerPool();
    return *pool;
  }

  bool enqueue(std::function<void()> job, std::string& error) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      // ENG-23022: reject ONLY when the backlog is genuinely full. The old
      // `idle_ == 0 && total_ >= kMaxWorkers` early-reject fired before the
      // queue-full check, so once all kMaxWorkers workers were busy in
      // getaddrinfo the kMaxQueue backlog was never used — the 9th+ concurrent
      // lookup rejected with "DNS worker pool exhausted", which every
      // lookup/resolve/reverse caller (and net.Socket.connect, which resolves
      // via dns.lookup) maps to a spurious getaddrinfo ENOTFOUND. That pattern
      // was borrowed from HTTP's WaitWorkerPool, whose one-wait-per-server
      // profile makes it harmless; DNS is high fan-out, so a single
      // Promise.all over >8 distinct hosts issues all enqueues in one JS tick
      // and hits the early-reject. Excess work now queues; a busy worker drains
      // it on its next loop iteration (spawnWorkerIfNeededLocked still caps the
      // thread count, and cv_.wait re-checks the predicate so no wakeup is lost).
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

class DnsAsyncLifetime {
 public:
  explicit DnsAsyncLifetime(RuntimeCallbackTarget target) : target_(target) {}
  void activate() noexcept { active_ = true; }
  ~DnsAsyncLifetime() {
    if (!active_) return;
    target_.runtime->pending_dns_lookups.fetch_sub(1, std::memory_order_relaxed);
    exactUnpinRuntimeNativeWorker(target_);
  }

 private:
  RuntimeCallbackTarget target_;
  bool active_{false};
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

        auto target = exactRuntimeCallbackTarget(handle);
        auto lifetime = std::make_shared<DnsAsyncLifetime>(target);
        if (!exactPinRuntimeNativeWorker(target)) {
          throw facebook::jsi::JSError(rt, "DNS async: runtime is shutting down");
        }

        // Mark the lookup in flight before dispatching so the event loop stays
        // alive across the resolver call even with no other pending work.
        handle->pending_dns_lookups.fetch_add(1, std::memory_order_relaxed);
        lifetime->activate();

        std::string enqueueError;
        bool queued = DnsWorkerPool::instance().enqueue(
            [target, principal, workPtr, resolve, reject,
             lifetime]() mutable {
              exactTestDelayRuntimeProducer();
              DnsResult result;
              try {
                result = (*workPtr)();
              } catch (const std::exception& error) {
                result.error = std::string("DNS worker failed: ") + error.what();
                result.code = "EAI_FAIL";
              } catch (...) {
                result.error = "DNS worker failed";
                result.code = "EAI_FAIL";
              }
              *workPtr = {};
              auto runtimeResolve = std::move(resolve);
              auto runtimeReject = std::move(reject);
              pushRuntimeCallback(
                  target,
                  [principal, resolve = std::move(runtimeResolve),
                   reject = std::move(runtimeReject), result = std::move(result)](
                      facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    try {
                      if (result.ok) {
                        resolve->call(
                            rt, facebook::jsi::String::createFromUtf8(rt, result.payload));
                      } else {
                        reject->call(rt, dnsErrorValue(rt, result));
                      }
                    } catch (...) {
                    }
                  });
            },
            enqueueError);
        if (!queued) {
          *workPtr = {};
          reject->call(rt, facebook::jsi::JSError(rt, enqueueError).value());
        }
        return facebook::jsi::Value::undefined();
      });
  return promiseCtor.callAsConstructor(runtime, executor);
}

}  // namespace

void installDnsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto dnsGetServersFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsGetServers"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
#if defined(EXACT_PLATFORM_ANDROID)
        // Android's resolver is network-scoped and intentionally does not
        // expose nameserver addresses through the NDK resolver API. Return an
        // explicit empty diagnostic list; resolution itself uses the platform
        // android_dns_query bridge and never treats this as custom authority.
        const std::string servers = "[]";
#else
        const std::string servers = systemDnsServersJson();
#endif
        return facebook::jsi::String::createFromUtf8(runtime, servers);
      });
  rt.global().setProperty(rt, "__exactDnsGetServers", std::move(dnsGetServersFn));

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
          throwDnsError(runtime, result);
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
          throwDnsError(runtime, result);
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
          throwDnsError(runtime, result);
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
