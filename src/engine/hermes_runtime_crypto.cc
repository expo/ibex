#include "hermes_runtime_internal.h"
#include "hermes_runtime_zlib_streams.h"

#include <atomic>
#include <cctype>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
// fcntl/F_GETFL/F_SETFL/O_NONBLOCK for the stdin entropy fallback. On Apple
// these arrive transitively through the Security framework headers; Linux needs
// them spelled out. (This file is not compiled on Windows — see build.rs.)
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHmac.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/SecRandom.h>
#include <Security/Security.h>
#include <zlib.h>
#if !defined(EXACT_NO_BROTLI)
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif
#if !defined(EXACT_NO_OPENSSL)
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif
extern "C" {
  CCCryptorStatus CCCryptorGCMOneshotEncrypt(
      CCAlgorithm alg, const void* key, size_t keyLength,
      const void* iv, size_t ivLength,
      const void* aData, size_t aDataLength,
      const void* dataIn, size_t dataInLength,
      void* cipherOut,
      void* tagOut, size_t tagLength);
  CCCryptorStatus CCCryptorGCMOneshotDecrypt(
      CCAlgorithm alg, const void* key, size_t keyLength,
      const void* iv, size_t ivLength,
      const void* aData, size_t aDataLength,
      const void* cipherIn, size_t dataInLength,
      void* dataOut,
      const void* tagIn, size_t tagLength);
}
#else
#if !defined(EXACT_NO_OPENSSL)
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif
#include <zlib.h>
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

extern "C" void ex_host_grant_capability(uint64_t module_id, const char* capability);

namespace {

// --- Signal trap machinery (ENG-23234) ---
// The async-signal-safe half of Node-style signal dispatch. A sigaction
// handler may only touch lock-free atomics and async-signal-safe syscalls,
// so delivery is split in three stages:
//   1. signal_handler marks the signal pending (per-signal counter — the old
//      single shared slot lost distinct signals that coalesced between
//      polls) and writes one doorbell byte to a self-pipe.
//   2. A detached watcher thread blocks on the pipe's read end (no polling)
//      and, outside signal context, pushes a runtime callback — the same
//      cross-thread wake path fetch/WS/HTTP completions use — so a runtime
//      parked in wait_for_callback_or_sleep wakes immediately. SA_RESTART
//      stays on (other native code relies on uninterrupted syscalls); the
//      pipe makes the wake-up independent of EINTR semantics.
//   3. The callback invokes globalThis.__exactDispatchPendingSignals()
//      (installed by stream-enhance.js), which drains __exactPollSignal()
//      and emits on the *current* process object.
static constexpr int kMaxTrappedSignal = 63;
static std::atomic<unsigned> g_pending_signal_counts[kMaxTrappedSignal + 1];
static int g_signal_wake_pipe[2] = {-1, -1};
static std::mutex g_signal_runtime_mutex;
static RuntimeCallbackTarget g_signal_runtime;
static std::once_flag g_signal_watcher_once;

static void signal_handler(int sig) {
  if (sig <= 0 || sig > kMaxTrappedSignal) return;
  int saved_errno = errno;
  g_pending_signal_counts[sig].fetch_add(1, std::memory_order_relaxed);
  int fd = g_signal_wake_pipe[1];
  if (fd >= 0) {
    unsigned char byte = static_cast<unsigned char>(sig);
    ssize_t ignored = write(fd, &byte, 1);
    (void)ignored;  // a full pipe still wakes the watcher; counters carry the data
  }
  errno = saved_errno;
}

static void signalWatcherThreadMain() {
  for (;;) {
    unsigned char buf[64];
    ssize_t n = read(g_signal_wake_pipe[0], buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (n == 0) return;  // write end closed (does not happen today)
    RuntimeCallbackTarget target;
    {
      std::lock_guard<std::mutex> lock(g_signal_runtime_mutex);
      target = g_signal_runtime;
    }
    if (!target) continue;
    pushRuntimeCallback(target, [](facebook::jsi::Runtime& rt) {
      auto dispatch =
          rt.global().getProperty(rt, "__exactDispatchPendingSignals");
      if (dispatch.isObject()) {
        auto obj = dispatch.asObject(rt);
        if (obj.isFunction(rt)) {
          obj.asFunction(rt).call(rt);
        }
      }
    });
  }
}

// Lazily create the self-pipe + watcher thread on first trap. The watcher is
// a detached native thread parked in read(); it holds no JS state and does
// not count toward ex_hermes_has_pending_tasks, so watching a signal never
// keeps the event loop alive (ENG-23132 semantics).
static bool ensureSignalWatcher() {
  std::call_once(g_signal_watcher_once, []() {
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0) return;
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    // Write end nonblocking: the signal handler must never block on a full
    // pipe (the byte is only a doorbell).
    int wflags = fcntl(fds[1], F_GETFL, 0);
    if (wflags >= 0) fcntl(fds[1], F_SETFL, wflags | O_NONBLOCK);
    g_signal_wake_pipe[0] = fds[0];
    g_signal_wake_pipe[1] = fds[1];
    std::thread(signalWatcherThreadMain).detach();
  });
  return g_signal_wake_pipe[1] >= 0;
}

struct CFUniqueReleaser {
  void operator()(const void* ptr) const {
    if (ptr) {
#if defined(__APPLE__)
      CFRelease(ptr);
#endif
    }
  }
};

using CFUniquePtr = std::unique_ptr<const void, CFUniqueReleaser>;

template <typename T>
using CFRefPtr = std::unique_ptr<std::remove_pointer_t<T>, CFUniqueReleaser>;

template <typename T>
CFRefPtr<T> adoptCF(T ptr) {
  return CFRefPtr<T>(ptr);
}

// Parse the optional RSA scheme + salt-length trailing arguments shared by the
// __exactSignSync/__exactVerifySync bridges (ENG-23002). The scheme argument
// selects RSA-PSS ("pss"/"rsa-pss") vs PKCS#1 v1.5; the salt argument is the PSS
// salt length in bytes. Negative values are modes, mirroring Node's constants:
// -1 = digest length (RSA_PSS_SALTLEN_DIGEST), -2 = maximum on sign / recover
// from the signature on verify (RSA_PSS_SALTLEN_MAX_SIGN / RSA_PSS_SALTLEN_AUTO,
// ENG-23129). Both are optional so legacy 3/4-argument callers keep PKCS#1 v1.5
// behavior.
#if (defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)) || \
    (!defined(__APPLE__) && !defined(EXACT_NO_OPENSSL))
static void parseRsaSignScheme(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    size_t schemeIndex,
    size_t saltIndex,
    bool& usePss,
    int& saltLen) {
  usePss = false;
  saltLen = -1;
  if (count > schemeIndex && args[schemeIndex].isString()) {
    auto s = args[schemeIndex].asString(runtime).utf8(runtime);
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    usePss = (s == "pss" || s == "rsa-pss");
  }
  if (count > saltIndex && args[saltIndex].isNumber()) {
    saltLen = static_cast<int>(args[saltIndex].asNumber());
  }
}
#endif

#if defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)
// @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
static std::string normalizeHashForNodeCrypto(const std::string& algorithm) {
  auto lowered = algorithm;
  for (auto& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  // Dash/underscore-stripped copy so a hyphenated WebCrypto hash name such as
  // "SHA-384" matches the "sha384" tokens below. The substring fallbacks used to
  // test `lowered` directly, but "sha-384" contains no "sha384" substring, so a
  // dashed name missed every branch and silently fell through to the sha256
  // default — SHA-1/SHA-384/SHA-512 were all computed over SHA-256 on-device
  // (ENG-23024). Matching against the compact form fixes the digest selection.
  std::string compact;
  compact.reserve(lowered.size());
  for (char ch : lowered) {
    if (ch != '-' && ch != '_') compact.push_back(ch);
  }

  if (lowered == "ecdsa" || lowered == "ecdsa-with-sha1") return "sha1";
  if (lowered == "ecdsa-with-sha256" || lowered == "rsa-sha256" || lowered == "sha256") return "sha256";
  if (lowered == "ecdsa-with-sha384" || lowered == "rsa-sha384" || lowered == "sha384") return "sha384";
  if (lowered == "ecdsa-with-sha512" || lowered == "rsa-sha512" || lowered == "sha512") return "sha512";
  // Multi-part digest names must match before the plain shaNNN substring
  // checks: "sha512-256" contains "sha512" and would select the wrong digest,
  // and sha224/sha3-* had no tokens at all (ENG-23129).
  if (compact.find("sha512224") != std::string::npos) return "sha512-224";
  if (compact.find("sha512256") != std::string::npos) return "sha512-256";
  if (compact.find("sha3224") != std::string::npos) return "sha3-224";
  if (compact.find("sha3256") != std::string::npos) return "sha3-256";
  if (compact.find("sha3384") != std::string::npos) return "sha3-384";
  if (compact.find("sha3512") != std::string::npos) return "sha3-512";
  if (compact.find("sha224") != std::string::npos) return "sha224";
  if (compact.find("sha256") != std::string::npos) return "sha256";
  if (compact.find("sha384") != std::string::npos) return "sha384";
  if (compact.find("sha512") != std::string::npos) return "sha512";
  if (compact.find("sha1") != std::string::npos) return "sha1";
  if (compact.find("md5") != std::string::npos) return "md5";
  // Unknown: return the lowered name unchanged so the caller's algorithm
  // lookup misses and it throws "unsupported algorithm" instead of silently
  // signing with SHA-256 (ENG-23129 — the old `return "sha256"` default
  // signed the wrong hash for sha224/sha3-*/anything unrecognized).
  return lowered;
}

// Digest output size in bytes for the hash names we support. Used to validate
// the RSA-PSS salt length on the SecKey path, whose message-PSS algorithms fix
// the salt length at the digest size (ENG-23002).
static size_t rsaHashDigestSize(const std::string& hashName) {
  if (hashName == "sha1") return 20;
  if (hashName == "sha224") return 28;
  if (hashName == "sha256") return 32;
  if (hashName == "sha384") return 48;
  if (hashName == "sha512") return 64;
  return 0;
}

// @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
// When usePss is set for an RSA key, select the SecKey RSA-PSS message
// algorithms instead of PKCS#1 v1.5 so RSA-PSS signatures actually use PSS
// padding (ENG-23002 — previously RSA always mapped to v1.5).
static SecKeyAlgorithm pickSecKeySignAlgorithm(const std::string& hashName, bool isRsa, bool usePss) {
  if (isRsa) {
    if (usePss) {
      if (hashName == "sha1") return kSecKeyAlgorithmRSASignatureMessagePSSSHA1;
      if (hashName == "sha256") return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;
      if (hashName == "sha384") return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;
      if (hashName == "sha512") return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;
      return nullptr;
    }
    if (hashName == "sha1") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
    if (hashName == "sha256") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    if (hashName == "sha384") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
    if (hashName == "sha512") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    return nullptr;
  }

  if (hashName == "sha1") return kSecKeyAlgorithmECDSASignatureMessageX962SHA1;
  if (hashName == "sha256") return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
  if (hashName == "sha384") return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
  if (hashName == "sha512") return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
  return nullptr;
}

static bool isRsaSecKey(SecKeyRef key) {
  bool isRsa = false;
  CFUniquePtr attrs(static_cast<const void*>(SecKeyCopyAttributes(key)));
  if (attrs.get()) {
    auto type = CFDictionaryGetValue(
        static_cast<CFDictionaryRef>(attrs.get()), kSecAttrKeyType);
    if (type != nullptr) {
      isRsa = CFEqual(type, kSecAttrKeyTypeRSA);
    }
  }
  return isRsa;
}

static std::string dataToString(CFDataRef data) {
  if (!data) return {};
  const auto bytes = CFDataGetBytePtr(data);
  const auto len = CFDataGetLength(data);
  return std::string(reinterpret_cast<const char*>(bytes), static_cast<size_t>(len));
}
#endif // defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)

// @ref LLP 0001#21-crypto-profile-the-axis-that-caused-the-original-break — Linux has both a reduced no-OpenSSL profile and a full OpenSSL profile.
#if defined(EXACT_NO_OPENSSL)
static uint32_t rotateLeft32(uint32_t value, uint32_t shift) {
  return (value << shift) | (value >> (32 - shift));
}

static uint32_t rotateRight32(uint32_t value, uint32_t shift) {
  return (value >> shift) | (value << (32 - shift));
}

static uint64_t rotateRight64(uint64_t value, uint64_t shift) {
  return (value >> shift) | (value << (64 - shift));
}

static std::string normalizeDigestName(std::string algorithm) {
  std::string normalized;
  normalized.reserve(algorithm.size());
  for (char ch : algorithm) {
    if (ch != '-' && ch != '_') {
      normalized.push_back(static_cast<char>(
          std::tolower(static_cast<unsigned char>(ch))));
    }
  }
  return normalized;
}

enum class PortableDigestKind {
  Md5,
  Sha1,
  Sha224,
  Sha256,
  Sha384,
  Sha512,
};

struct PortableDigestSpec {
  PortableDigestKind kind;
  size_t block_size;
  size_t output_size;
};

[[maybe_unused]] static std::optional<PortableDigestSpec> portableDigestSpecForAlgorithm(
    const std::string& algorithm) {
  const auto normalized = normalizeDigestName(algorithm);
  if (normalized == "md5") {
    return PortableDigestSpec{PortableDigestKind::Md5, 64, 16};
  }
  if (normalized == "sha1") {
    return PortableDigestSpec{PortableDigestKind::Sha1, 64, 20};
  }
  if (normalized == "sha224") {
    return PortableDigestSpec{PortableDigestKind::Sha224, 64, 28};
  }
  if (normalized == "sha256") {
    return PortableDigestSpec{PortableDigestKind::Sha256, 64, 32};
  }
  if (normalized == "sha384") {
    return PortableDigestSpec{PortableDigestKind::Sha384, 128, 48};
  }
  if (normalized == "sha512") {
    return PortableDigestSpec{PortableDigestKind::Sha512, 128, 64};
  }
  return std::nullopt;
}

static void appendBigEndian32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<uint8_t>(value & 0xff));
}

static void appendBigEndian64(std::vector<uint8_t>& out, uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
  }
}

static std::vector<uint8_t> md5Digest(const std::vector<uint8_t>& input) {
  static constexpr uint32_t shifts[64] = {
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  };
  static constexpr uint32_t constants[64] = {
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
      0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
      0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
      0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
      0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
      0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  };

  uint32_t a0 = 0x67452301;
  uint32_t b0 = 0xefcdab89;
  uint32_t c0 = 0x98badcfe;
  uint32_t d0 = 0x10325476;

  std::vector<uint8_t> message(input);
  const uint64_t bitLength = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(0x80);
  while ((message.size() % 64) != 56) {
    message.push_back(0);
  }
  for (int i = 0; i < 8; ++i) {
    message.push_back(static_cast<uint8_t>((bitLength >> (8 * i)) & 0xff));
  }

  for (size_t offset = 0; offset < message.size(); offset += 64) {
    uint32_t words[16];
    for (size_t i = 0; i < 16; ++i) {
      const size_t wordOffset = offset + i * 4;
      words[i] = static_cast<uint32_t>(message[wordOffset]) |
          (static_cast<uint32_t>(message[wordOffset + 1]) << 8) |
          (static_cast<uint32_t>(message[wordOffset + 2]) << 16) |
          (static_cast<uint32_t>(message[wordOffset + 3]) << 24);
    }

    uint32_t a = a0;
    uint32_t b = b0;
    uint32_t c = c0;
    uint32_t d = d0;

    for (uint32_t i = 0; i < 64; ++i) {
      uint32_t f;
      uint32_t g;
      if (i < 16) {
        f = (b & c) | ((~b) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * i) % 16;
      }

      const uint32_t next = d;
      d = c;
      c = b;
      b += rotateLeft32(a + f + constants[i] + words[g], shifts[i]);
      a = next;
    }

    a0 += a;
    b0 += b;
    c0 += c;
    d0 += d;
  }

  std::vector<uint8_t> digest(16);
  const uint32_t state[4] = {a0, b0, c0, d0};
  for (size_t i = 0; i < 4; ++i) {
    digest[i * 4] = static_cast<uint8_t>(state[i] & 0xff);
    digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
    digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
    digest[i * 4 + 3] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
  }
  return digest;
}

static std::vector<uint8_t> sha1Digest(const std::vector<uint8_t>& input) {
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xefcdab89;
  uint32_t h2 = 0x98badcfe;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xc3d2e1f0;

  std::vector<uint8_t> message(input);
  const uint64_t bitLength = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(0x80);
  while ((message.size() % 64) != 56) {
    message.push_back(0);
  }
  appendBigEndian64(message, bitLength);

  for (size_t offset = 0; offset < message.size(); offset += 64) {
    uint32_t w[80] = {};
    for (size_t i = 0; i < 16; ++i) {
      const size_t wordOffset = offset + i * 4;
      w[i] = (static_cast<uint32_t>(message[wordOffset]) << 24) |
          (static_cast<uint32_t>(message[wordOffset + 1]) << 16) |
          (static_cast<uint32_t>(message[wordOffset + 2]) << 8) |
          static_cast<uint32_t>(message[wordOffset + 3]);
    }
    for (size_t i = 16; i < 80; ++i) {
      w[i] = rotateLeft32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;

    for (uint32_t i = 0; i < 80; ++i) {
      uint32_t f;
      uint32_t k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const uint32_t temp = rotateLeft32(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rotateLeft32(b, 30);
      b = a;
      a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::vector<uint8_t> digest;
  digest.reserve(20);
  appendBigEndian32(digest, h0);
  appendBigEndian32(digest, h1);
  appendBigEndian32(digest, h2);
  appendBigEndian32(digest, h3);
  appendBigEndian32(digest, h4);
  return digest;
}

static std::vector<uint8_t> sha256FamilyDigest(
    const std::vector<uint8_t>& input,
    bool sha224) {
  static constexpr uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };

  uint32_t h[8] = {};
  if (sha224) {
    h[0] = 0xc1059ed8;
    h[1] = 0x367cd507;
    h[2] = 0x3070dd17;
    h[3] = 0xf70e5939;
    h[4] = 0xffc00b31;
    h[5] = 0x68581511;
    h[6] = 0x64f98fa7;
    h[7] = 0xbefa4fa4;
  } else {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
  }

  std::vector<uint8_t> message(input);
  const uint64_t bitLength = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(0x80);
  while ((message.size() % 64) != 56) {
    message.push_back(0);
  }
  appendBigEndian64(message, bitLength);

  for (size_t offset = 0; offset < message.size(); offset += 64) {
    uint32_t w[64] = {};
    for (size_t i = 0; i < 16; ++i) {
      const size_t wordOffset = offset + i * 4;
      w[i] = (static_cast<uint32_t>(message[wordOffset]) << 24) |
          (static_cast<uint32_t>(message[wordOffset + 1]) << 16) |
          (static_cast<uint32_t>(message[wordOffset + 2]) << 8) |
          static_cast<uint32_t>(message[wordOffset + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
      const uint32_t s0 = rotateRight32(w[i - 15], 7) ^
          rotateRight32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = rotateRight32(w[i - 2], 17) ^
          rotateRight32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];

    for (size_t i = 0; i < 64; ++i) {
      const uint32_t s1 = rotateRight32(e, 6) ^
          rotateRight32(e, 11) ^ rotateRight32(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t temp1 = hh + s1 + ch + k[i] + w[i];
      const uint32_t s0 = rotateRight32(a, 2) ^
          rotateRight32(a, 13) ^ rotateRight32(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;

      hh = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  std::vector<uint8_t> digest;
  digest.reserve(sha224 ? 28 : 32);
  for (size_t i = 0; i < (sha224 ? 7 : 8); ++i) {
    appendBigEndian32(digest, h[i]);
  }
  return digest;
}

static std::vector<uint8_t> sha512FamilyDigest(
    const std::vector<uint8_t>& input,
    bool sha384) {
  static constexpr uint64_t k[80] = {
      UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
      UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
      UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
      UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
      UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
      UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
      UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
      UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
      UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
      UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
      UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
      UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
      UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
      UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
      UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
      UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
      UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
      UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
      UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
      UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
      UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
      UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
      UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
      UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
      UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
      UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
      UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
      UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
      UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
      UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
      UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
      UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
      UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
      UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
      UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
      UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
      UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
      UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
      UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
      UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
  };

  uint64_t h[8] = {};
  if (sha384) {
    h[0] = UINT64_C(0xcbbb9d5dc1059ed8);
    h[1] = UINT64_C(0x629a292a367cd507);
    h[2] = UINT64_C(0x9159015a3070dd17);
    h[3] = UINT64_C(0x152fecd8f70e5939);
    h[4] = UINT64_C(0x67332667ffc00b31);
    h[5] = UINT64_C(0x8eb44a8768581511);
    h[6] = UINT64_C(0xdb0c2e0d64f98fa7);
    h[7] = UINT64_C(0x47b5481dbefa4fa4);
  } else {
    h[0] = UINT64_C(0x6a09e667f3bcc908);
    h[1] = UINT64_C(0xbb67ae8584caa73b);
    h[2] = UINT64_C(0x3c6ef372fe94f82b);
    h[3] = UINT64_C(0xa54ff53a5f1d36f1);
    h[4] = UINT64_C(0x510e527fade682d1);
    h[5] = UINT64_C(0x9b05688c2b3e6c1f);
    h[6] = UINT64_C(0x1f83d9abfb41bd6b);
    h[7] = UINT64_C(0x5be0cd19137e2179);
  }

  std::vector<uint8_t> message(input);
  const uint64_t bitLengthHigh = static_cast<uint64_t>(message.size() >> 61);
  const uint64_t bitLengthLow = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(0x80);
  while ((message.size() % 128) != 112) {
    message.push_back(0);
  }
  appendBigEndian64(message, bitLengthHigh);
  appendBigEndian64(message, bitLengthLow);

  for (size_t offset = 0; offset < message.size(); offset += 128) {
    uint64_t w[80] = {};
    for (size_t i = 0; i < 16; ++i) {
      const size_t wordOffset = offset + i * 8;
      w[i] = (static_cast<uint64_t>(message[wordOffset]) << 56) |
          (static_cast<uint64_t>(message[wordOffset + 1]) << 48) |
          (static_cast<uint64_t>(message[wordOffset + 2]) << 40) |
          (static_cast<uint64_t>(message[wordOffset + 3]) << 32) |
          (static_cast<uint64_t>(message[wordOffset + 4]) << 24) |
          (static_cast<uint64_t>(message[wordOffset + 5]) << 16) |
          (static_cast<uint64_t>(message[wordOffset + 6]) << 8) |
          static_cast<uint64_t>(message[wordOffset + 7]);
    }
    for (size_t i = 16; i < 80; ++i) {
      const uint64_t s0 = rotateRight64(w[i - 15], 1) ^
          rotateRight64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      const uint64_t s1 = rotateRight64(w[i - 2], 19) ^
          rotateRight64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = h[0];
    uint64_t b = h[1];
    uint64_t c = h[2];
    uint64_t d = h[3];
    uint64_t e = h[4];
    uint64_t f = h[5];
    uint64_t g = h[6];
    uint64_t hh = h[7];

    for (size_t i = 0; i < 80; ++i) {
      const uint64_t s1 = rotateRight64(e, 14) ^
          rotateRight64(e, 18) ^ rotateRight64(e, 41);
      const uint64_t ch = (e & f) ^ ((~e) & g);
      const uint64_t temp1 = hh + s1 + ch + k[i] + w[i];
      const uint64_t s0 = rotateRight64(a, 28) ^
          rotateRight64(a, 34) ^ rotateRight64(a, 39);
      const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint64_t temp2 = s0 + maj;

      hh = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  std::vector<uint8_t> digest;
  digest.reserve(sha384 ? 48 : 64);
  for (size_t i = 0; i < (sha384 ? 6 : 8); ++i) {
    appendBigEndian64(digest, h[i]);
  }
  return digest;
}

static std::vector<uint8_t> portableDigestBySpec(
    const PortableDigestSpec& spec,
    const std::vector<uint8_t>& input) {
  switch (spec.kind) {
    case PortableDigestKind::Md5:
      return md5Digest(input);
    case PortableDigestKind::Sha1:
      return sha1Digest(input);
    case PortableDigestKind::Sha224:
      return sha256FamilyDigest(input, true);
    case PortableDigestKind::Sha256:
      return sha256FamilyDigest(input, false);
    case PortableDigestKind::Sha384:
      return sha512FamilyDigest(input, true);
    case PortableDigestKind::Sha512:
      return sha512FamilyDigest(input, false);
  }
  return {};
}

static std::vector<uint8_t> portableHmac(
    const PortableDigestSpec& spec,
    std::vector<uint8_t> key,
    const std::vector<uint8_t>& data) {
  if (key.size() > spec.block_size) {
    key = portableDigestBySpec(spec, key);
  }
  key.resize(spec.block_size, 0);

  std::vector<uint8_t> inner;
  inner.reserve(spec.block_size + data.size());
  std::vector<uint8_t> outer;
  outer.reserve(spec.block_size + spec.output_size);
  for (uint8_t byte : key) {
    inner.push_back(static_cast<uint8_t>(byte ^ 0x36));
    outer.push_back(static_cast<uint8_t>(byte ^ 0x5c));
  }
  inner.insert(inner.end(), data.begin(), data.end());
  auto innerDigest = portableDigestBySpec(spec, inner);
  outer.insert(outer.end(), innerDigest.begin(), innerDigest.end());
  return portableDigestBySpec(spec, outer);
}

[[maybe_unused]] static std::vector<uint8_t> portablePbkdf2(
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t keyLength,
    const PortableDigestSpec& spec) {
  std::vector<uint8_t> derived;
  if (keyLength == 0) {
    return derived;
  }
  const size_t blockCount = (keyLength + spec.output_size - 1) / spec.output_size;
  derived.reserve(blockCount * spec.output_size);

  for (uint32_t blockIndex = 1; blockIndex <= blockCount; ++blockIndex) {
    std::vector<uint8_t> saltBlock(salt);
    appendBigEndian32(saltBlock, blockIndex);
    auto u = portableHmac(spec, password, saltBlock);
    auto t = u;
    for (uint32_t iter = 1; iter < iterations; ++iter) {
      u = portableHmac(spec, password, u);
      for (size_t i = 0; i < t.size(); ++i) {
        t[i] ^= u[i];
      }
    }
    derived.insert(derived.end(), t.begin(), t.end());
  }

  derived.resize(keyLength);
  return derived;
}
#endif

#if !defined(EXACT_NO_OPENSSL)
static std::string normalizeDigestName(std::string algorithm) {
  std::string normalized;
  normalized.reserve(algorithm.size());
  for (char ch : algorithm) {
    if (ch != '-' && ch != '_') {
      normalized.push_back(static_cast<char>(
          std::tolower(static_cast<unsigned char>(ch))));
    }
  }
  return normalized;
}

static const EVP_MD* openSslDigestForAlgorithm(const std::string& algorithm) {
  const auto normalized = normalizeDigestName(algorithm);
  if (normalized == "sha1") return EVP_sha1();
  if (normalized == "sha224") return EVP_sha224();
  if (normalized == "sha256") return EVP_sha256();
  if (normalized == "sha384") return EVP_sha384();
  if (normalized == "sha512") return EVP_sha512();
  if (normalized == "sha512224") return EVP_sha512_224();
  if (normalized == "sha512256") return EVP_sha512_256();
  if (normalized == "sha3224") return EVP_sha3_224();
  if (normalized == "sha3256") return EVP_sha3_256();
  if (normalized == "sha3384") return EVP_sha3_384();
  if (normalized == "sha3512") return EVP_sha3_512();
  if (normalized == "md5") return EVP_md5();
  return nullptr;
}

#if !defined(__APPLE__)
static const EVP_CIPHER* openSslAesCbcCipher(size_t keyLength) {
  if (keyLength == 16) return EVP_aes_128_cbc();
  if (keyLength == 24) return EVP_aes_192_cbc();
  if (keyLength == 32) return EVP_aes_256_cbc();
  return nullptr;
}

static const EVP_CIPHER* openSslAesCtrCipher(size_t keyLength) {
  if (keyLength == 16) return EVP_aes_128_ctr();
  if (keyLength == 24) return EVP_aes_192_ctr();
  if (keyLength == 32) return EVP_aes_256_ctr();
  return nullptr;
}

static const EVP_CIPHER* openSslAesGcmCipher(size_t keyLength) {
  if (keyLength == 16) return EVP_aes_128_gcm();
  if (keyLength == 24) return EVP_aes_192_gcm();
  if (keyLength == 32) return EVP_aes_256_gcm();
  return nullptr;
}
#endif

// @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
// Shared OpenSSL sign/verify core operating on RAW message bytes (ENG-23002).
// Signs/verifies the bytes exactly as given — no UTF-8 round-trip that would
// expand bytes >= 0x80 — and, for RSA, selects PSS padding with a caller-supplied
// salt length when usePss is set (otherwise PKCS#1 v1.5). Shared by the
// __exactSignSync/__exactVerifySync OpenSSL bridges and the ex_crypto_test_rsa_*
// hooks. saltLen < 0 means "use the digest length" (RSA_PSS_SALTLEN_DIGEST).
// Returns true on success and fills outSig; on failure sets err.
static bool opensslSignMessageCore(
    const std::vector<uint8_t>& data,
    const std::string& keyPem,
    const EVP_MD* md,
    bool usePss,
    int saltLen,
    std::vector<uint8_t>& outSig,
    std::string& err) {
  BIO* keyBio = BIO_new_mem_buf(keyPem.data(), static_cast<int>(keyPem.size()));
  if (!keyBio) { err = "failed to allocate key BIO"; return false; }
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
  BIO_free(keyBio);
  if (!pkey) { err = "invalid PEM private key"; return false; }

  EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
  if (!mdCtx) { EVP_PKEY_free(pkey); err = "failed to allocate digest context"; return false; }

  EVP_PKEY_CTX* pctx = nullptr;
  bool ok = false;
  do {
    if (EVP_DigestSignInit(mdCtx, &pctx, md, nullptr, pkey) != 1) {
      err = "EVP_DigestSignInit failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    if (usePss) {
      // -2 is Node's RSA_PSS_SALTLEN_MAX_SIGN, which OpenSSL spells
      // RSA_PSS_SALTLEN_AUTO in a sign context (maximum permissible salt);
      // any other negative value keeps the digest-length default (ENG-23129).
      int effSalt = saltLen >= 0 ? saltLen
                                 : (saltLen == -2 ? RSA_PSS_SALTLEN_AUTO : RSA_PSS_SALTLEN_DIGEST);
      if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) { err = "failed to set RSA-PSS padding"; break; }
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, effSalt) <= 0) { err = "failed to set RSA-PSS salt length"; break; }
      if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) { err = "failed to set MGF1 digest"; break; }
    }
    if (EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) != 1) {
      err = "EVP_DigestSignUpdate failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) != 1) {
      err = "EVP_DigestSignFinal (size) failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    outSig.resize(sigLen);
    if (EVP_DigestSignFinal(mdCtx, outSig.data(), &sigLen) != 1) {
      err = "signing failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    outSig.resize(sigLen);
    ok = true;
  } while (false);

  EVP_MD_CTX_free(mdCtx);
  EVP_PKEY_free(pkey);
  return ok;
}

// Returns 1 (verified), 0 (not verified), or -1 (error, err set).
static int opensslVerifyMessageCore(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& sig,
    const std::string& keyPem,
    const EVP_MD* md,
    bool usePss,
    int saltLen,
    std::string& err) {
  BIO* keyBio = BIO_new_mem_buf(keyPem.data(), static_cast<int>(keyPem.size()));
  if (!keyBio) { err = "failed to allocate key BIO"; return -1; }
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(keyBio, nullptr, nullptr, nullptr);
  BIO_free(keyBio);
  if (!pkey) { err = "invalid PEM public key"; return -1; }

  EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
  if (!mdCtx) { EVP_PKEY_free(pkey); err = "failed to allocate digest context"; return -1; }

  EVP_PKEY_CTX* pctx = nullptr;
  int rc = -1;
  do {
    if (EVP_DigestVerifyInit(mdCtx, &pctx, md, nullptr, pkey) != 1) {
      err = "EVP_DigestVerifyInit failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    if (usePss) {
      // -2 is Node's RSA_PSS_SALTLEN_AUTO (recover the salt length from the
      // signature), which is the same OpenSSL constant; any other negative
      // value keeps the digest-length default (ENG-23129).
      int effSalt = saltLen >= 0 ? saltLen
                                 : (saltLen == -2 ? RSA_PSS_SALTLEN_AUTO : RSA_PSS_SALTLEN_DIGEST);
      if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) { err = "failed to set RSA-PSS padding"; break; }
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, effSalt) <= 0) { err = "failed to set RSA-PSS salt length"; break; }
      if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) { err = "failed to set MGF1 digest"; break; }
    }
    if (EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size()) != 1) {
      err = "EVP_DigestVerifyUpdate failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
      break;
    }
    int v = EVP_DigestVerifyFinal(mdCtx, sig.data(), sig.size());
    if (v == 1) { rc = 1; }
    else if (v == 0) { rc = 0; }
    else { err = "verify failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)); rc = -1; }
  } while (false);

  EVP_MD_CTX_free(mdCtx);
  EVP_PKEY_free(pkey);
  return rc;
}
#endif

#if defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)
// SecItemImport/SecItemExport are macOS-only APIs (not available on iOS)

struct DerValue {
  const uint8_t* data = nullptr;
  size_t size = 0;
};

class DerReader {
 public:
  DerReader(const uint8_t* data, size_t size) : cursor_(data), end_(data + size) {}

  bool read(uint8_t expectedTag, DerValue& value) {
    if (cursor_ == end_ || *cursor_++ != expectedTag || cursor_ == end_) {
      return false;
    }

    size_t length = *cursor_++;
    if ((length & 0x80) != 0) {
      const size_t lengthBytes = length & 0x7f;
      if (lengthBytes == 0 || lengthBytes > 4 ||
          static_cast<size_t>(end_ - cursor_) < lengthBytes ||
          *cursor_ == 0) {
        return false;
      }
      length = 0;
      for (size_t i = 0; i < lengthBytes; ++i) {
        length = (length << 8) | *cursor_++;
      }
      // DER requires the shortest definite-length encoding.
      if (length < 128) {
        return false;
      }
    }

    if (length > static_cast<size_t>(end_ - cursor_)) {
      return false;
    }
    value = {cursor_, length};
    cursor_ += length;
    return true;
  }

  bool empty() const { return cursor_ == end_; }
  uint8_t nextTag() const { return cursor_ == end_ ? 0 : *cursor_; }

 private:
  const uint8_t* cursor_;
  const uint8_t* end_;
};

static bool isPemSpace(char ch) {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static int base64Value(char ch) {
  if (ch >= 'A' && ch <= 'Z') return ch - 'A';
  if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
  if (ch >= '0' && ch <= '9') return ch - '0' + 52;
  if (ch == '+') return 62;
  if (ch == '/') return 63;
  return -1;
}

// Decode exactly one unencrypted PKCS#8 PEM block. This intentionally accepts
// no alternate labels, concatenated blocks, non-canonical padding, or trailing
// non-whitespace: the fallback below must never broaden arbitrary strings into
// asymmetric key material.
static bool decodePkcs8PrivateKeyPem(
    const std::string& pem,
    std::vector<uint8_t>& der) {
  static constexpr char kHeader[] = "-----BEGIN PRIVATE KEY-----";
  static constexpr char kFooter[] = "-----END PRIVATE KEY-----";
  if (pem.size() > 32 * 1024) return false;

  size_t offset = 0;
  while (offset < pem.size() && isPemSpace(pem[offset])) ++offset;
  const size_t headerLength = sizeof(kHeader) - 1;
  if (pem.compare(offset, headerLength, kHeader) != 0) return false;
  offset += headerLength;
  if (offset == pem.size() || !isPemSpace(pem[offset])) return false;

  const auto footer = pem.find(kFooter, offset);
  if (footer == std::string::npos) return false;
  const size_t footerLength = sizeof(kFooter) - 1;
  for (size_t i = footer + footerLength; i < pem.size(); ++i) {
    if (!isPemSpace(pem[i])) return false;
  }

  std::string encoded;
  encoded.reserve(footer - offset);
  for (size_t i = offset; i < footer; ++i) {
    if (isPemSpace(pem[i])) continue;
    if (base64Value(pem[i]) < 0 && pem[i] != '=') return false;
    encoded.push_back(pem[i]);
  }
  if (encoded.empty() || encoded.size() % 4 != 0) return false;

  der.clear();
  der.reserve(encoded.size() / 4 * 3);
  for (size_t i = 0; i < encoded.size(); i += 4) {
    const bool isLast = i + 4 == encoded.size();
    const int a = base64Value(encoded[i]);
    const int b = base64Value(encoded[i + 1]);
    const int c = base64Value(encoded[i + 2]);
    const int d = base64Value(encoded[i + 3]);
    if (a < 0 || b < 0) return false;

    der.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
    if (encoded[i + 2] == '=') {
      if (!isLast || encoded[i + 3] != '=' || (b & 0x0f) != 0) return false;
      continue;
    }
    if (c < 0) return false;
    der.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
    if (encoded[i + 3] == '=') {
      if (!isLast || (c & 0x03) != 0) return false;
      continue;
    }
    if (d < 0) return false;
    der.push_back(static_cast<uint8_t>((c << 6) | d));
  }
  return true;
}

static bool derValueEquals(
    const DerValue& value,
    const uint8_t* expected,
    size_t expectedSize) {
  return value.size == expectedSize &&
      std::memcmp(value.data, expected, expectedSize) == 0;
}

static void appendDerLength(std::vector<uint8_t>& output, size_t length) {
  if (length < 128) {
    output.push_back(static_cast<uint8_t>(length));
    return;
  }
  uint8_t bytes[sizeof(size_t)];
  size_t count = 0;
  while (length != 0) {
    bytes[count++] = static_cast<uint8_t>(length & 0xff);
    length >>= 8;
  }
  output.push_back(static_cast<uint8_t>(0x80 | count));
  while (count != 0) output.push_back(bytes[--count]);
}

static void appendDerTlv(
    std::vector<uint8_t>& output,
    uint8_t tag,
    const uint8_t* value,
    size_t valueSize) {
  output.push_back(tag);
  appendDerLength(output, valueSize);
  output.insert(output.end(), value, value + valueSize);
}

// Security.framework imports SEC1 EC private keys, but not the ordinary
// PKCS#8 EC private keys emitted by Node/OpenSSL on every supported macOS
// release. Strictly validate the two nested ASN.1 structures, inject the named
// curve parameters from PrivateKeyInfo into ECPrivateKey, and import that SEC1
// representation. No generic PEM/DER parser or symmetric fallback is involved.
// @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
static SecKeyRef importNodePkcs8EcPrivateKey(const std::string& pemText) {
  static constexpr uint8_t kEcPublicKeyOid[] = {
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
  static constexpr uint8_t kP256Oid[] = {
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  static constexpr uint8_t kP384Oid[] = {0x2b, 0x81, 0x04, 0x00, 0x22};
  static constexpr uint8_t kP521Oid[] = {0x2b, 0x81, 0x04, 0x00, 0x23};
  struct CurveSpec {
    const uint8_t* oid;
    size_t oidSize;
    size_t coordinateSize;
    int keySizeBits;
  };
  static constexpr CurveSpec kCurves[] = {
      {kP256Oid, sizeof(kP256Oid), 32, 256},
      {kP384Oid, sizeof(kP384Oid), 48, 384},
      {kP521Oid, sizeof(kP521Oid), 66, 521},
  };

  std::vector<uint8_t> pkcs8;
  if (!decodePkcs8PrivateKeyPem(pemText, pkcs8)) return nullptr;

  DerReader rootReader(pkcs8.data(), pkcs8.size());
  DerValue privateKeyInfo;
  if (!rootReader.read(0x30, privateKeyInfo) || !rootReader.empty()) return nullptr;
  DerReader privateKeyInfoReader(privateKeyInfo.data, privateKeyInfo.size);
  DerValue version;
  DerValue algorithmIdentifier;
  DerValue privateKey;
  static constexpr uint8_t kPkcs8Version[] = {0x00};
  if (!privateKeyInfoReader.read(0x02, version) ||
      !derValueEquals(version, kPkcs8Version, sizeof(kPkcs8Version)) ||
      !privateKeyInfoReader.read(0x30, algorithmIdentifier) ||
      !privateKeyInfoReader.read(0x04, privateKey) ||
      !privateKeyInfoReader.empty()) {
    return nullptr;
  }

  DerReader algorithmReader(algorithmIdentifier.data, algorithmIdentifier.size);
  DerValue algorithmOid;
  DerValue curveOid;
  if (!algorithmReader.read(0x06, algorithmOid) ||
      !derValueEquals(algorithmOid, kEcPublicKeyOid, sizeof(kEcPublicKeyOid)) ||
      !algorithmReader.read(0x06, curveOid) || !algorithmReader.empty()) {
    return nullptr;
  }
  const CurveSpec* curve = nullptr;
  for (const auto& candidate : kCurves) {
    if (derValueEquals(curveOid, candidate.oid, candidate.oidSize)) {
      curve = &candidate;
      break;
    }
  }
  if (!curve) return nullptr;

  DerReader sec1RootReader(privateKey.data, privateKey.size);
  DerValue ecPrivateKey;
  if (!sec1RootReader.read(0x30, ecPrivateKey) || !sec1RootReader.empty()) {
    return nullptr;
  }
  DerReader ecPrivateKeyReader(ecPrivateKey.data, ecPrivateKey.size);
  DerValue ecVersion;
  DerValue privateScalar;
  static constexpr uint8_t kEcVersion[] = {0x01};
  if (!ecPrivateKeyReader.read(0x02, ecVersion) ||
      !derValueEquals(ecVersion, kEcVersion, sizeof(kEcVersion)) ||
      !ecPrivateKeyReader.read(0x04, privateScalar) ||
      privateScalar.size != curve->coordinateSize) {
    return nullptr;
  }

  if (ecPrivateKeyReader.nextTag() == 0xa0) {
    DerValue parameters;
    if (!ecPrivateKeyReader.read(0xa0, parameters)) return nullptr;
    DerReader parametersReader(parameters.data, parameters.size);
    DerValue innerCurveOid;
    if (!parametersReader.read(0x06, innerCurveOid) ||
        !derValueEquals(innerCurveOid, curve->oid, curve->oidSize) ||
        !parametersReader.empty()) {
      return nullptr;
    }
  }

  DerValue publicKeyField;
  if (!ecPrivateKeyReader.read(0xa1, publicKeyField) ||
      !ecPrivateKeyReader.empty()) {
    return nullptr;
  }
  DerReader publicKeyReader(publicKeyField.data, publicKeyField.size);
  DerValue publicKeyBits;
  if (!publicKeyReader.read(0x03, publicKeyBits) || !publicKeyReader.empty() ||
      publicKeyBits.size != 2 + 2 * curve->coordinateSize ||
      publicKeyBits.data[0] != 0 || publicKeyBits.data[1] != 0x04) {
    return nullptr;
  }

  std::vector<uint8_t> parameters;
  appendDerTlv(parameters, 0x06, curve->oid, curve->oidSize);
  std::vector<uint8_t> publicKey;
  appendDerTlv(publicKey, 0x03, publicKeyBits.data, publicKeyBits.size);
  std::vector<uint8_t> sec1Contents;
  appendDerTlv(sec1Contents, 0x02, kEcVersion, sizeof(kEcVersion));
  appendDerTlv(
      sec1Contents, 0x04, privateScalar.data, privateScalar.size);
  appendDerTlv(sec1Contents, 0xa0, parameters.data(), parameters.size());
  appendDerTlv(sec1Contents, 0xa1, publicKey.data(), publicKey.size());
  std::vector<uint8_t> sec1;
  appendDerTlv(sec1, 0x30, sec1Contents.data(), sec1Contents.size());

  auto keyData = adoptCF(CFDataCreate(
      kCFAllocatorDefault,
      sec1.data(),
      static_cast<CFIndex>(sec1.size())));
  if (!keyData) return nullptr;
  SecItemImportExportKeyParameters keyParams{};
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  SecExternalFormat inputFormat = kSecFormatOpenSSL;
  SecExternalItemType itemType = kSecItemTypePrivateKey;
  CFArrayRef importedItems = nullptr;
  const auto status = SecItemImport(
      keyData.get(),
      nullptr,
      &inputFormat,
      &itemType,
      0,
      &keyParams,
      nullptr,
      &importedItems);
  auto importedItemsHandle = adoptCF(importedItems);
  if (status != errSecSuccess || !importedItemsHandle ||
      CFArrayGetCount(importedItemsHandle.get()) != 1) {
    return nullptr;
  }
  auto maybeKey = CFArrayGetValueAtIndex(importedItemsHandle.get(), 0);
  if (!maybeKey || CFGetTypeID(maybeKey) != SecKeyGetTypeID()) return nullptr;
  auto key = static_cast<SecKeyRef>(const_cast<void*>(maybeKey));

  auto attributes = adoptCF(SecKeyCopyAttributes(key));
  if (!attributes) return nullptr;
  auto importedKeyType =
      CFDictionaryGetValue(attributes.get(), kSecAttrKeyType);
  auto importedKeyClass =
      CFDictionaryGetValue(attributes.get(), kSecAttrKeyClass);
  if (!importedKeyType || !importedKeyClass ||
      !CFEqual(importedKeyType, kSecAttrKeyTypeECSECPrimeRandom) ||
      !CFEqual(importedKeyClass, kSecAttrKeyClassPrivate)) {
    return nullptr;
  }
  int keySizeBits = 0;
  auto keySize = static_cast<CFNumberRef>(
      CFDictionaryGetValue(attributes.get(), kSecAttrKeySizeInBits));
  if (!keySize || !CFNumberGetValue(
                      keySize, kCFNumberIntType, &keySizeBits) ||
      keySizeBits != curve->keySizeBits) {
    return nullptr;
  }

  // Confirm that Security.framework derived the same public point carried in
  // the PKCS#8 key. This rejects internally inconsistent scalar/point pairs.
  auto derivedPublicKey = adoptCF(SecKeyCopyPublicKey(key));
  CFErrorRef exportError = nullptr;
  auto derivedPublicBytes = derivedPublicKey
      ? adoptCF(SecKeyCopyExternalRepresentation(
            derivedPublicKey.get(), &exportError))
      : CFRefPtr<CFDataRef>(nullptr);
  auto exportErrorHandle = adoptCF(exportError);
  if (!derivedPublicBytes ||
      static_cast<size_t>(CFDataGetLength(derivedPublicBytes.get())) !=
          publicKeyBits.size - 1 ||
      std::memcmp(
          CFDataGetBytePtr(derivedPublicBytes.get()),
          publicKeyBits.data + 1,
          publicKeyBits.size - 1) != 0) {
    return nullptr;
  }

  CFRetain(key);
  return key;
}

static SecKeyRef importPemKey(const std::string& pemText, SecExternalItemType itemType) {
  auto keyBytes = std::vector<uint8_t>(pemText.begin(), pemText.end());
  CFUniquePtr keyData(static_cast<const void*>(CFDataCreate(
      kCFAllocatorDefault,
      keyBytes.data(),
      static_cast<CFIndex>(keyBytes.size()))));
  if (!keyData) {
    return nullptr;
  }

  SecItemImportExportKeyParameters keyParams{};
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

  CFArrayRef importedItems = nullptr;
  SecExternalFormat inputFormat = kSecFormatPEMSequence;
  SecExternalItemType effectiveType = itemType;
  auto status = SecItemImport(
      static_cast<CFDataRef>(keyData.get()),
      nullptr,
      &inputFormat,
      &effectiveType,
      0,
      &keyParams,
      nullptr,
      &importedItems);
  CFUniquePtr importedItemsHandle(static_cast<const void*>(importedItems));

  if (status != noErr) {
    if (status != noErr && itemType != kSecItemTypeUnknown) {
      effectiveType = kSecItemTypeUnknown;
      importedItemsHandle.reset();
      importedItems = nullptr;
      status = SecItemImport(
          static_cast<CFDataRef>(keyData.get()),
          nullptr,
          &inputFormat,
          &effectiveType,
          0,
          &keyParams,
          nullptr,
          &importedItems);
      importedItemsHandle.reset(static_cast<const void*>(importedItems));
    }
  }

  if (status != noErr || !importedItems) {
    if (itemType == kSecItemTypePrivateKey) {
      return importNodePkcs8EcPrivateKey(pemText);
    }
    return nullptr;
  }

  auto importedItemsArray = static_cast<CFArrayRef>(importedItemsHandle.get());
  if (CFArrayGetCount(importedItemsArray) == 0) {
    return nullptr;
  }

  auto maybeKey = CFArrayGetValueAtIndex(importedItemsArray, 0);
  if (!maybeKey) {
    return nullptr;
  }

  if (CFGetTypeID(maybeKey) != SecKeyGetTypeID()) {
    return nullptr;
  }

  auto key = static_cast<SecKeyRef>(const_cast<void*>(maybeKey));
  CFRetain(key);
  return key;
}
#endif // defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)

// These helpers are only used by the non-Apple (Linux/OpenSSL) sign/verify path.
// On Apple, sign/verify uses Security.framework directly.
#if !defined(__APPLE__) && !defined(EXACT_NO_OPENSSL)
static const EVP_MD* selectDigestForCryptoAlgo(const std::string& algorithm) {
  return openSslDigestForAlgorithm(algorithm);
}

// @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
static std::string digestAlgorithmFromNodeCrypto(const std::string& algorithm) {
  auto lowered = algorithm;
  for (auto& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  // Dash/underscore-stripped copy so a hyphenated WebCrypto hash name such as
  // "SHA-384" matches the "sha384" tokens below. The substring fallbacks used to
  // test `lowered` directly, but "sha-384" contains no "sha384" substring, so a
  // dashed name missed every branch and silently fell through to the sha256
  // default — SHA-1/SHA-384/SHA-512 were all computed over SHA-256 on-device
  // (ENG-23024). Matching against the compact form fixes the digest selection.
  std::string compact;
  compact.reserve(lowered.size());
  for (char ch : lowered) {
    if (ch != '-' && ch != '_') compact.push_back(ch);
  }

  if (lowered == "ecdsa" || lowered == "ecdsa-with-sha1") return "sha1";
  if (lowered == "ecdsa-with-sha256" || lowered == "rsa-sha256" || lowered == "sha256") return "sha256";
  if (lowered == "ecdsa-with-sha384" || lowered == "rsa-sha384" || lowered == "sha384") return "sha384";
  if (lowered == "ecdsa-with-sha512" || lowered == "rsa-sha512" || lowered == "sha512") return "sha512";
  // Multi-part digest names must match before the plain shaNNN substring
  // checks: "sha512-256" contains "sha512" and would select the wrong digest,
  // and sha224/sha3-* had no tokens at all (ENG-23129).
  if (compact.find("sha512224") != std::string::npos) return "sha512-224";
  if (compact.find("sha512256") != std::string::npos) return "sha512-256";
  if (compact.find("sha3224") != std::string::npos) return "sha3-224";
  if (compact.find("sha3256") != std::string::npos) return "sha3-256";
  if (compact.find("sha3384") != std::string::npos) return "sha3-384";
  if (compact.find("sha3512") != std::string::npos) return "sha3-512";
  if (compact.find("sha224") != std::string::npos) return "sha224";
  if (compact.find("sha256") != std::string::npos) return "sha256";
  if (compact.find("sha384") != std::string::npos) return "sha384";
  if (compact.find("sha512") != std::string::npos) return "sha512";
  if (compact.find("sha1") != std::string::npos) return "sha1";
  if (compact.find("md5") != std::string::npos) return "md5";
  // Unknown: return the lowered name unchanged so openSslDigestForAlgorithm
  // misses and the bridge throws "unsupported algorithm" instead of silently
  // signing with SHA-256 (ENG-23129 — the old `return "sha256"` default
  // signed the wrong hash for anything unrecognized). sha224/sha3-* now reach
  // the digest table, which supports them.
  return lowered;
}
#endif



} // namespace

void unregisterSignalRuntime(ExactHermesRuntime* handle) {
  auto target = exactRuntimeCallbackTarget(handle);
  std::lock_guard<std::mutex> lock(g_signal_runtime_mutex);
  if (g_signal_runtime.runtime == target.runtime &&
      g_signal_runtime.nonce == target.nonce) {
    g_signal_runtime = {};
  }
}

#if !defined(EXACT_NO_OPENSSL)
// Test-only C ABI (ENG-23002) exercising the shared OpenSSL RSA sign/verify core
// that backs the on-device __exactSignSync/__exactVerifySync bridges. The JSI
// bridges themselves need a full Hermes runtime to invoke, so these let a Rust
// unit test sign RAW bytes with RSA-PSS + an explicit salt length and verify the
// result — the exact code path that ships on Android/Linux. `hash_name` is a
// normalized digest name ("sha256" etc.); `use_pss` selects PSS vs PKCS#1 v1.5;
// `salt_len` is the PSS salt length in bytes (-1 = digest length, -2 = max on
// sign / auto-recover on verify).
// ex_crypto_test_rsa_sign returns the signature length written into `out` (which
// must have capacity `out_cap` >= key size) or -1 on error.
extern "C" int ex_crypto_test_rsa_sign(
    const uint8_t* data,
    size_t data_len,
    const char* pem_key,
    size_t pem_len,
    const char* hash_name,
    int use_pss,
    int salt_len,
    uint8_t* out,
    size_t out_cap) {
  const EVP_MD* md = openSslDigestForAlgorithm(hash_name ? std::string(hash_name) : std::string());
  if (!md) return -1;
  std::vector<uint8_t> dataVec(data, data + data_len);
  std::string keyPem(pem_key, pem_len);
  std::vector<uint8_t> sig;
  std::string err;
  if (!opensslSignMessageCore(dataVec, keyPem, md, use_pss != 0, salt_len, sig, err)) {
    return -1;
  }
  if (sig.size() > out_cap) return -1;
  std::memcpy(out, sig.data(), sig.size());
  return static_cast<int>(sig.size());
}

// Returns 1 (verified), 0 (not verified), or -1 (error).
extern "C" int ex_crypto_test_rsa_verify(
    const uint8_t* data,
    size_t data_len,
    const uint8_t* sig,
    size_t sig_len,
    const char* pem_pub,
    size_t pem_pub_len,
    const char* hash_name,
    int use_pss,
    int salt_len) {
  const EVP_MD* md = openSslDigestForAlgorithm(hash_name ? std::string(hash_name) : std::string());
  if (!md) return -1;
  std::vector<uint8_t> dataVec(data, data + data_len);
  std::vector<uint8_t> sigVec(sig, sig + sig_len);
  std::string keyPem(pem_pub, pem_pub_len);
  std::string err;
  return opensslVerifyMessageCore(dataVec, sigVec, keyPem, md, use_pss != 0, salt_len, err);
}
#endif  // !EXACT_NO_OPENSSL

// Test-only C ABI (ENG-23024): expose the node-crypto hash-name normalizer that
// the on-device __exactSignSync/__exactVerifySync bridges run the requested hash
// through, so a Rust unit test can prove that a hyphenated WebCrypto hash name
// ("SHA-1"/"SHA-384"/"SHA-512") selects the requested digest instead of silently
// collapsing to sha256. Writes the normalized name (NUL-terminated) into `out`
// and returns its length, or -1 if the buffer is too small or no node-crypto
// normalizer is compiled for this platform/profile.
extern "C" int ex_crypto_test_node_hash_name(
    const char* algorithm, char* out, size_t out_cap) {
  std::string normalized;
#if defined(__APPLE__) && !defined(EXACT_PLATFORM_IOS)
  normalized = normalizeHashForNodeCrypto(algorithm ? std::string(algorithm) : std::string());
#elif !defined(__APPLE__) && !defined(EXACT_NO_OPENSSL)
  normalized = digestAlgorithmFromNodeCrypto(algorithm ? std::string(algorithm) : std::string());
#else
  (void)algorithm;
  (void)out;
  (void)out_cap;
  return -1;
#endif
  if (out == nullptr || normalized.size() + 1 > out_cap) return -1;
  std::memcpy(out, normalized.c_str(), normalized.size() + 1);
  return static_cast<int>(normalized.size());
}

void installCryptoHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  // --- Crypto: sync hash ---
  // __exactHashSync(algorithm, data) -> hex string
  auto hashSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHashSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHashSync: algorithm and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto inputBytes = extractBytes(runtime, args[1]);

        std::vector<uint8_t> digest;
#if defined(__APPLE__)
        if (algo == "sha256" || algo == "sha-256") {
          digest.resize(CC_SHA256_DIGEST_LENGTH);
          CC_SHA256(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha1" || algo == "sha-1") {
          digest.resize(CC_SHA1_DIGEST_LENGTH);
          CC_SHA1(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha224" || algo == "sha-224") {
          digest.resize(CC_SHA224_DIGEST_LENGTH);
          CC_SHA224(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha384" || algo == "sha-384") {
          digest.resize(CC_SHA384_DIGEST_LENGTH);
          CC_SHA384(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha512" || algo == "sha-512") {
          digest.resize(CC_SHA512_DIGEST_LENGTH);
          CC_SHA512(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "md5") {
#if !defined(EXACT_NO_OPENSSL)
          // Use OpenSSL for MD5 — CommonCrypto's CC_MD5 is deprecated
          unsigned int md5Len = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &md5Len, EVP_md5(), nullptr);
          digest.resize(md5Len);
#else
          digest = md5Digest(inputBytes);
#endif
#if !defined(EXACT_NO_OPENSSL)
        } else if (algo == "sha3224" || algo == "sha3-224") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_224(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3256" || algo == "sha3-256") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_256(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3384" || algo == "sha3-384") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_384(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3512" || algo == "sha3-512") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_512(), nullptr);
          digest.resize(digestLen);
#endif
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_MD* md = openSslDigestForAlgorithm(algo);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, md, nullptr);
        digest.resize(digestLen);
#else
        auto spec = portableDigestSpecForAlgorithm(algo);
        if (!spec) {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
        digest = portableDigestBySpec(*spec, inputBytes);
#endif

        // Convert to hex string
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : digest) {
          hex << std::setw(2) << static_cast<int>(b);
        }
        return facebook::jsi::String::createFromUtf8(runtime, hex.str());
      });
  rt.global().setProperty(rt, "__exactHashSync", std::move(hashSyncFn));

  // __exactHmacSync(algorithm, key, data) -> hex string
  auto hmacSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHmacSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHmacSync: algorithm, key, and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);

        // Get key bytes
        std::vector<uint8_t> keyBytes;
        if (args[1].isString()) {
          auto str = args[1].asString(runtime).utf8(runtime);
          keyBytes.assign(str.begin(), str.end());
        }

        // Get data bytes
        std::vector<uint8_t> dataBytes;
        if (args[2].isString()) {
          auto str = args[2].asString(runtime).utf8(runtime);
          dataBytes.assign(str.begin(), str.end());
        }

        std::vector<uint8_t> mac;
#if defined(__APPLE__)
        CCHmacAlgorithm ccAlgo;
        size_t macLen;
        if (algo == "sha256" || algo == "sha-256") {
          ccAlgo = kCCHmacAlgSHA256; macLen = CC_SHA256_DIGEST_LENGTH;
        } else if (algo == "sha1" || algo == "sha-1") {
          ccAlgo = kCCHmacAlgSHA1; macLen = CC_SHA1_DIGEST_LENGTH;
        } else if (algo == "sha384" || algo == "sha-384") {
          ccAlgo = kCCHmacAlgSHA384; macLen = CC_SHA384_DIGEST_LENGTH;
        } else if (algo == "sha512" || algo == "sha-512") {
          ccAlgo = kCCHmacAlgSHA512; macLen = CC_SHA512_DIGEST_LENGTH;
        } else if (algo == "md5") {
          ccAlgo = kCCHmacAlgMD5; macLen = CC_MD5_DIGEST_LENGTH;
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported HMAC algorithm: " + algo);
        }
        mac.resize(macLen);
        CCHmac(ccAlgo, keyBytes.data(), keyBytes.size(),
               dataBytes.data(), dataBytes.size(), mac.data());
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_MD* md = openSslDigestForAlgorithm(algo);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "Unsupported HMAC algorithm: " + algo);
        }
        unsigned int macLen = 0;
        mac.resize(EVP_MAX_MD_SIZE);
        HMAC(md, keyBytes.data(), keyBytes.size(),
             dataBytes.data(), dataBytes.size(), mac.data(), &macLen);
        mac.resize(macLen);
#else
        auto spec = portableDigestSpecForAlgorithm(algo);
        if (!spec) {
          throw facebook::jsi::JSError(runtime, "Unsupported HMAC algorithm: " + algo);
        }
        mac = portableHmac(*spec, keyBytes, dataBytes);
#endif

        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : mac) {
          hex << std::setw(2) << static_cast<int>(b);
        }
        return facebook::jsi::String::createFromUtf8(runtime, hex.str());
      });
  rt.global().setProperty(rt, "__exactHmacSync", std::move(hmacSyncFn));

  // __exactHashRaw(algorithm, data) -> Uint8Array (raw bytes, not hex)
  auto hashRawFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHashRaw"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHashRaw: algorithm and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto inputBytes = extractBytes(runtime, args[1]);

        std::vector<uint8_t> digest;
#if defined(__APPLE__)
        if (algo == "sha256" || algo == "sha-256") {
          digest.resize(CC_SHA256_DIGEST_LENGTH);
          CC_SHA256(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha1" || algo == "sha-1") {
          digest.resize(CC_SHA1_DIGEST_LENGTH);
          CC_SHA1(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha224" || algo == "sha-224") {
          digest.resize(CC_SHA224_DIGEST_LENGTH);
          CC_SHA224(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha384" || algo == "sha-384") {
          digest.resize(CC_SHA384_DIGEST_LENGTH);
          CC_SHA384(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha512" || algo == "sha-512") {
          digest.resize(CC_SHA512_DIGEST_LENGTH);
          CC_SHA512(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "md5") {
#if !defined(EXACT_NO_OPENSSL)
          // Use OpenSSL for MD5 — CommonCrypto's CC_MD5 is deprecated
          unsigned int md5Len = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &md5Len, EVP_md5(), nullptr);
          digest.resize(md5Len);
#else
          digest = md5Digest(inputBytes);
#endif
#if !defined(EXACT_NO_OPENSSL)
        } else if (algo == "sha3224" || algo == "sha3-224") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_224(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3256" || algo == "sha3-256") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_256(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3384" || algo == "sha3-384") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_384(), nullptr);
          digest.resize(digestLen);
        } else if (algo == "sha3512" || algo == "sha3-512") {
          unsigned int digestLen = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, EVP_sha3_512(), nullptr);
          digest.resize(digestLen);
#endif
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_MD* md = openSslDigestForAlgorithm(algo);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, md, nullptr);
        digest.resize(digestLen);
#else
        auto spec = portableDigestSpecForAlgorithm(algo);
        if (!spec) {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
        digest = portableDigestBySpec(*spec, inputBytes);
#endif
        return makeUint8Array(runtime, std::move(digest));
      });
  rt.global().setProperty(rt, "__exactHashRaw", std::move(hashRawFn));

  // --- SubtleCrypto: AES-CBC encrypt/decrypt ---
  // __exactAesCbcEncrypt(key, iv, data) -> Uint8Array (ciphertext with PKCS7 padding)
  auto aesCbcEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcEncrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        if (keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32) {
          throw facebook::jsi::JSError(runtime, "AES key must be 128, 192, or 256 bits");
        }
        if (ivBytes.size() != 16) {
          throw facebook::jsi::JSError(runtime, "AES-CBC IV must be 16 bytes");
        }
#if defined(__APPLE__)
        size_t outLen = 0;
        std::vector<uint8_t> out(data.size() + kCCBlockSizeAES128);
        CCCryptorStatus status = CCCrypt(
            kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(),
            data.data(), data.size(),
            out.data(), out.size(), &outLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CBC encryption failed: " + std::to_string(status));
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_CIPHER* cipher = openSslAesCbcCipher(keyBytes.size());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "AES-CBC unsupported key length");
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "AES-CBC encryption init failed");
        }
        std::vector<uint8_t> out(data.size() + EVP_CIPHER_block_size(cipher));
        int outLen = 0;
        int finalLen = 0;
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, keyBytes.data(), ivBytes.data()) != 1 ||
            EVP_EncryptUpdate(ctx, out.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1 ||
            EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-CBC encryption failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<size_t>(outLen + finalLen));
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CBC requires the openssl-crypto feature on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCbcEncrypt", std::move(aesCbcEncFn));

  // __exactAesCbcDecrypt(key, iv, data) -> Uint8Array (plaintext)
  auto aesCbcDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcDecrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        // Validate the IV length in common code, matching the encrypt path.
        // CCCrypt reads a full 16-byte AES block from the IV pointer, so a
        // short IV forwarded from subtle.decrypt({name:'AES-CBC', iv}) was an
        // out-of-bounds read on Apple while OpenSSL threw cleanly. (ENG-23467)
        if (ivBytes.size() != 16) {
          throw facebook::jsi::JSError(runtime, "AES-CBC IV must be 16 bytes");
        }
#if defined(__APPLE__)
        size_t outLen = 0;
        std::vector<uint8_t> out(data.size() + kCCBlockSizeAES128);
        CCCryptorStatus status = CCCrypt(
            kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(),
            data.data(), data.size(),
            out.data(), out.size(), &outLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CBC decryption failed: " + std::to_string(status));
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_CIPHER* cipher = openSslAesCbcCipher(keyBytes.size());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "AES-CBC unsupported key length");
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "AES-CBC decryption init failed");
        }
        std::vector<uint8_t> out(data.size() + EVP_CIPHER_block_size(cipher));
        int outLen = 0;
        int finalLen = 0;
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, keyBytes.data(), ivBytes.data()) != 1 ||
            EVP_DecryptUpdate(ctx, out.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1 ||
            EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-CBC decryption failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<size_t>(outLen + finalLen));
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CBC requires the openssl-crypto feature on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCbcDecrypt", std::move(aesCbcDecFn));

  // __exactAesCtrEncrypt(key, counter, data) -> Uint8Array
  auto aesCtrEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCtrEncrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, counter, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ctrBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        if (ctrBytes.size() != 16) {
          throw facebook::jsi::JSError(runtime, "AES-CTR counter must be 16 bytes");
        }
#if defined(__APPLE__)
        // CTR mode: use CCCryptorCreateWithMode
        CCCryptorRef cryptor = nullptr;
        CCCryptorStatus status = CCCryptorCreateWithMode(
            kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
            ctrBytes.data(), keyBytes.data(), keyBytes.size(),
            nullptr, 0, 0, kCCModeOptionCTR_BE, &cryptor);
        if (status != kCCSuccess || !cryptor) {
          throw facebook::jsi::JSError(runtime, "AES-CTR init failed");
        }
        std::vector<uint8_t> out(data.size());
        size_t outLen = 0;
        status = CCCryptorUpdate(cryptor, data.data(), data.size(), out.data(), out.size(), &outLen);
        CCCryptorRelease(cryptor);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CTR encryption failed");
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_CIPHER* cipher = openSslAesCtrCipher(keyBytes.size());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "AES-CTR unsupported key length");
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "AES-CTR init failed");
        }
        std::vector<uint8_t> out(data.size() + EVP_CIPHER_block_size(cipher));
        int outLen = 0;
        int finalLen = 0;
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, keyBytes.data(), ctrBytes.data()) != 1 ||
            EVP_EncryptUpdate(ctx, out.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1 ||
            EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-CTR encryption failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<size_t>(outLen + finalLen));
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CTR requires the openssl-crypto feature on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCtrEncrypt", std::move(aesCtrEncFn));

  // __exactAesGcmEncrypt(key, iv, data, aad, tagLength) -> Uint8Array (ciphertext + tag)
  auto aesGcmEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesGcmEncrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        std::vector<uint8_t> aad;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          aad = extractBytes(runtime, args[3]);
        }
        size_t tagLen = 16;
        if (count > 4 && args[4].isNumber()) {
          tagLen = static_cast<size_t>(args[4].asNumber()) / 8; // bits to bytes
        }
#if defined(__APPLE__)
        std::vector<uint8_t> out(data.size());
        std::vector<uint8_t> tag(tagLen);
        CCCryptorStatus status = CCCryptorGCMOneshotEncrypt(
            kCCAlgorithmAES,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(), ivBytes.size(),
            aad.data(), aad.size(),
            data.data(), data.size(),
            out.data(),
            tag.data(), tagLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-GCM encryption failed: " + std::to_string(status));
        }
        // Append tag to ciphertext
        out.insert(out.end(), tag.begin(), tag.end());
        return makeUint8Array(runtime, std::move(out));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_CIPHER* cipher = openSslAesGcmCipher(keyBytes.size());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "AES-GCM unsupported key length");
        }
        if (tagLen < 1 || tagLen > 16) {
          throw facebook::jsi::JSError(runtime, "AES-GCM tag length must be between 8 and 128 bits");
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "AES-GCM init failed");
        }
        std::vector<uint8_t> out(data.size() + tagLen);
        int outLen = 0;
        int totalLen = 0;
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(ivBytes.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM init failed");
        }
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM aad update failed");
        }
        if (!data.empty() &&
            EVP_EncryptUpdate(ctx, out.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM encryption failed");
        }
        totalLen = outLen;
        if (EVP_EncryptFinal_ex(ctx, out.data() + totalLen, &outLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM final failed");
        }
        totalLen += outLen;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tagLen), out.data() + totalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM tag generation failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<size_t>(totalLen) + tagLen);
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-GCM requires the openssl-crypto feature on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesGcmEncrypt", std::move(aesGcmEncFn));

  // __exactAesGcmDecrypt(key, iv, data, aad, tagLength) -> Uint8Array (plaintext)
  // data includes the tag appended at the end
  auto aesGcmDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesGcmDecrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto dataWithTag = extractBytes(runtime, args[2]);
        std::vector<uint8_t> aad;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          aad = extractBytes(runtime, args[3]);
        }
        size_t tagLen = 16;
        if (count > 4 && args[4].isNumber()) {
          tagLen = static_cast<size_t>(args[4].asNumber()) / 8;
        }
        if (dataWithTag.size() < tagLen) {
          throw facebook::jsi::JSError(runtime, "Data too short for GCM tag");
        }
        size_t cipherLen = dataWithTag.size() - tagLen;
#if defined(__APPLE__)
        std::vector<uint8_t> out(cipherLen);
        CCCryptorStatus status = CCCryptorGCMOneshotDecrypt(
            kCCAlgorithmAES,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(), ivBytes.size(),
            aad.data(), aad.size(),
            dataWithTag.data(), cipherLen,
            out.data(),
            dataWithTag.data() + cipherLen, tagLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-GCM decryption failed (auth tag mismatch or invalid data)");
        }
        return makeUint8Array(runtime, std::move(out));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_CIPHER* cipher = openSslAesGcmCipher(keyBytes.size());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "AES-GCM unsupported key length");
        }
        if (tagLen < 1 || tagLen > 16) {
          throw facebook::jsi::JSError(runtime, "AES-GCM tag length must be between 8 and 128 bits");
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "AES-GCM init failed");
        }
        std::vector<uint8_t> out(cipherLen);
        int outLen = 0;
        int totalLen = 0;
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(ivBytes.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM init failed");
        }
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM aad update failed");
        }
        if (cipherLen > 0 &&
            EVP_DecryptUpdate(ctx, out.data(), &outLen, dataWithTag.data(), static_cast<int>(cipherLen)) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM decryption failed");
        }
        totalLen = outLen;
        if (EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_GCM_SET_TAG,
                static_cast<int>(tagLen),
                const_cast<uint8_t*>(dataWithTag.data() + cipherLen)) != 1 ||
            EVP_DecryptFinal_ex(ctx, out.data() + totalLen, &outLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "AES-GCM decryption failed (auth tag mismatch or invalid data)");
        }
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<size_t>(totalLen + outLen));
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-GCM requires the openssl-crypto feature on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesGcmDecrypt", std::move(aesGcmDecFn));

#if !defined(EXACT_NO_OPENSSL)
  // __exactEvpCipherEncrypt(algorithm, key, iv, data) -> Uint8Array
  // Generic EVP cipher encrypt for DES, 3DES, Blowfish, ChaCha20-Poly1305, etc.
  auto evpCipherEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEvpCipherEncrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) throw facebook::jsi::JSError(runtime, "algorithm, key, iv, data required");
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto keyBytes = extractBytes(runtime, args[1]);
        auto ivBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);
        auto aad = (count > 4 && !args[4].isUndefined() && !args[4].isNull())
                       ? extractBytes(runtime, args[4])
                       : std::vector<uint8_t>();
        auto tagLen = (size_t)16;
        if (count > 5 && !args[5].isUndefined() && !args[5].isNull()) {
          auto requestedTagLen = static_cast<int>(args[5].asNumber());
          if (requestedTagLen >= 1 && requestedTagLen <= 16) tagLen = static_cast<size_t>(requestedTagLen);
        }

        const EVP_CIPHER* cipher = EVP_get_cipherbyname(algo.c_str());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "Unsupported cipher: " + algo);
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw facebook::jsi::JSError(runtime, "Failed to create cipher context");

        int outLen = 0;
        int finalLen = 0;
        bool isAEAD = (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
        bool isCCM = algo.find("-ccm") != std::string::npos;

        // Output buffer: data + block size + possible tag
        int blockSize = EVP_CIPHER_block_size(cipher);
        std::vector<uint8_t> out(data.size() + (blockSize * 2) + (isAEAD ? static_cast<int>(tagLen) : 0));

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher init failed");
        }

        // Set key and IV lengths if needed
        if ((int)ivBytes.size() != EVP_CIPHER_CTX_iv_length(ctx)) {
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivBytes.size(), nullptr);
        }

        if (isCCM) {
          if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, static_cast<int>(tagLen), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher set CCM tag length failed");
          }
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher key/iv init failed");
        }

        if (isCCM && isAEAD) {
          int msgLen = static_cast<int>(data.size());
          int msgLenOut = 0;
          if (EVP_EncryptUpdate(ctx, nullptr, &msgLenOut, nullptr, msgLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher set CCM message length failed");
          }
        }
        if (!aad.empty() && isAEAD) {
          int aadLen = 0;
          if (EVP_EncryptUpdate(ctx, nullptr, &aadLen, aad.data(), static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher encrypt aad failed");
          }
        }

        if (EVP_EncryptUpdate(ctx, out.data(), &outLen, data.data(), data.size()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher encrypt update failed");
        }

        if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher encrypt final failed");
        }

        int totalLen = outLen + finalLen;

        // For AEAD ciphers, append the auth tag
        if (isAEAD) {
          std::vector<uint8_t> tag(tagLen);
          if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tagLen), tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Failed to get auth tag");
          }
          memcpy(out.data() + totalLen, tag.data(), tag.size());
          totalLen += static_cast<int>(tag.size());
        }

        EVP_CIPHER_CTX_free(ctx);
        out.resize(totalLen);
        return makeUint8Array(runtime, std::move(out));
      });
  rt.global().setProperty(rt, "__exactEvpCipherEncrypt", std::move(evpCipherEncFn));
#endif // !EXACT_NO_OPENSSL

#if !defined(EXACT_NO_OPENSSL)
  // __exactEvpCipherDecrypt(algorithm, key, iv, data, authTag?) -> Uint8Array
  // Generic EVP cipher decrypt for DES, 3DES, Blowfish, ChaCha20-Poly1305, etc.
  auto evpCipherDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEvpCipherDecrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) throw facebook::jsi::JSError(runtime, "algorithm, key, iv, data required");
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto keyBytes = extractBytes(runtime, args[1]);
        auto ivBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);
        auto authTag = (count > 4 && !args[4].isUndefined() && !args[4].isNull())
                           ? extractBytes(runtime, args[4])
                           : std::vector<uint8_t>();
        auto aad = (count > 5 && !args[5].isUndefined() && !args[5].isNull())
                       ? extractBytes(runtime, args[5])
                       : std::vector<uint8_t>();
        auto tagLen = (size_t)16;
        if (!authTag.empty()) tagLen = authTag.size();
        if (count > 6 && !args[6].isUndefined() && !args[6].isNull()) {
          auto requestedTagLen = static_cast<int>(args[6].asNumber());
          if (requestedTagLen >= 1 && requestedTagLen <= 16) tagLen = static_cast<size_t>(requestedTagLen);
        }

        const EVP_CIPHER* cipher = EVP_get_cipherbyname(algo.c_str());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "Unsupported cipher: " + algo);
        }

        bool isAEAD = (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
        bool isCCM = algo.find("-ccm") != std::string::npos;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw facebook::jsi::JSError(runtime, "Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher init failed");
        }

        // Set IV length if needed
        if ((int)ivBytes.size() != EVP_CIPHER_CTX_iv_length(ctx)) {
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivBytes.size(), nullptr);
        }

        if (isCCM && isAEAD) {
          if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, static_cast<int>(tagLen), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher set CCM tag length failed");
          }
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher key/iv init failed");
        }

        // For AEAD ciphers, set the auth tag (from arg 4 or last 16 bytes of data)
        if (isAEAD) {
          if (!authTag.empty()) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagLen), authTag.data()) != 1) {
              EVP_CIPHER_CTX_free(ctx);
              throw facebook::jsi::JSError(runtime, "Failed to set auth tag");
            }
          } else if (data.size() >= 16) {
            // Tag appended to end of data
            auto tag = std::vector<uint8_t>(tagLen);
            if (tag.empty()) {
              tag.resize(16);
            }
            if (tag.size() < 16) {
              tag.resize(16);
            }
            memcpy(tag.data(), data.data() + data.size() - 16, 16);
            data.resize(data.size() - 16);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
              EVP_CIPHER_CTX_free(ctx);
              throw facebook::jsi::JSError(runtime, "Failed to set auth tag");
            }
          }
        }

        if (isCCM && isAEAD) {
          int msgLen = static_cast<int>(data.size());
          int msgLenOut = 0;
          if (EVP_DecryptUpdate(ctx, nullptr, &msgLenOut, nullptr, msgLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher set CCM message length failed");
          }
        }
        if (!aad.empty() && isAEAD) {
          int aadLen = 0;
          if (EVP_DecryptUpdate(ctx, nullptr, &aadLen, aad.data(), static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Cipher decrypt aad failed");
          }
        }

        int blockSize = EVP_CIPHER_block_size(cipher);
        std::vector<uint8_t> out(data.size() + (blockSize * 2));
        int outLen = 0;
        int finalLen = 0;

        if (EVP_DecryptUpdate(ctx, out.data(), &outLen, data.data(), data.size()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher decrypt update failed");
        }

        if (EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher decrypt final failed (auth tag mismatch or bad padding)");
        }

        EVP_CIPHER_CTX_free(ctx);
        out.resize(outLen + finalLen);
        return makeUint8Array(runtime, std::move(out));
      });
  rt.global().setProperty(rt, "__exactEvpCipherDecrypt", std::move(evpCipherDecFn));
#endif // !EXACT_NO_OPENSSL

  // __exactPbkdf2(password, salt, iterations, keyLength, hashAlgo) -> Uint8Array
  auto pbkdf2Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPbkdf2"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) throw facebook::jsi::JSError(runtime, "password, salt, iterations, keyLength, hash required");
        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        auto iterations = static_cast<unsigned int>(args[2].asNumber());
        auto keyLength = static_cast<size_t>(args[3].asNumber());
        auto hash = args[4].asString(runtime).utf8(runtime);
#if defined(__APPLE__)
        CCPseudoRandomAlgorithm prf;
        if (hash == "SHA-1" || hash == "sha1") prf = kCCPRFHmacAlgSHA1;
        else if (hash == "SHA-256" || hash == "sha256") prf = kCCPRFHmacAlgSHA256;
        else if (hash == "SHA-384" || hash == "sha384") prf = kCCPRFHmacAlgSHA384;
        else if (hash == "SHA-512" || hash == "sha512") prf = kCCPRFHmacAlgSHA512;
        else throw facebook::jsi::JSError(runtime, "Unsupported PBKDF2 hash: " + hash);
        std::vector<uint8_t> derivedKey(keyLength);
        CCCryptorStatus status = CCKeyDerivationPBKDF(
            kCCPBKDF2,
            reinterpret_cast<const char*>(password.data()), password.size(),
            salt.data(), salt.size(),
            prf, iterations,
            derivedKey.data(), keyLength);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "PBKDF2 derivation failed");
        }
        return makeUint8Array(runtime, std::move(derivedKey));
#elif !defined(EXACT_NO_OPENSSL)
        const EVP_MD* md = openSslDigestForAlgorithm(hash);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "Unsupported PBKDF2 hash: " + hash);
        }
        if (iterations == 0) {
          throw facebook::jsi::JSError(runtime, "PBKDF2 iterations must be greater than zero");
        }
        std::vector<uint8_t> derivedKey(keyLength);
        if (PKCS5_PBKDF2_HMAC(
                reinterpret_cast<const char*>(password.data()),
                static_cast<int>(password.size()),
                salt.data(),
                static_cast<int>(salt.size()),
                static_cast<int>(iterations),
                md,
                static_cast<int>(keyLength),
                derivedKey.data()) != 1) {
          throw facebook::jsi::JSError(runtime, "PBKDF2 derivation failed");
        }
        return makeUint8Array(runtime, std::move(derivedKey));
#else
        auto spec = portableDigestSpecForAlgorithm(hash);
        if (!spec || spec->kind == PortableDigestKind::Md5) {
          throw facebook::jsi::JSError(runtime, "Unsupported PBKDF2 hash: " + hash);
        }
        if (iterations == 0) {
          throw facebook::jsi::JSError(runtime, "PBKDF2 iterations must be greater than zero");
        }
        auto derivedKey = portablePbkdf2(password, salt, iterations, keyLength, *spec);
        return makeUint8Array(runtime, std::move(derivedKey));
#endif
      });
  rt.global().setProperty(rt, "__exactPbkdf2", std::move(pbkdf2Fn));

  // __exactScryptSync(password, salt, N, r, p, keylen) -> Uint8Array
  // Real scrypt implementation using Salsa20/8 core + PBKDF2-HMAC-SHA256
  auto scryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactScryptSync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 6) throw facebook::jsi::JSError(runtime, "password, salt, N, r, p, keylen required");
        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        uint64_t N = static_cast<uint64_t>(args[2].asNumber());
        uint32_t r = static_cast<uint32_t>(args[3].asNumber());
        uint32_t p = static_cast<uint32_t>(args[4].asNumber());
        size_t keylen = static_cast<size_t>(args[5].asNumber());

        // Validate parameters
        if (N == 0 || (N & (N - 1)) != 0) {
          throw facebook::jsi::JSError(runtime, "scrypt: N must be a power of 2");
        }
        if (r == 0) throw facebook::jsi::JSError(runtime, "scrypt: r must be > 0");
        if (p == 0) throw facebook::jsi::JSError(runtime, "scrypt: p must be > 0");
        // Check for overflow: p * 128 * r
        if (p > 0 && r > 0 && static_cast<uint64_t>(p) * 128 * r > 1073741824ULL) {
          throw facebook::jsi::JSError(runtime, "scrypt: parameters too large");
        }

#if defined(__APPLE__)
        // Helper lambdas for scrypt algorithm

        // Salsa20/8 core: applies 8 rounds of Salsa20 quarter-round in place
        // Input/output: 16 uint32_t words (64 bytes)
        auto salsa20_8 = [](uint32_t B[16]) {
          uint32_t x[16];
          std::memcpy(x, B, 64);

          #define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
          for (int i = 0; i < 8; i += 2) {
            // Column round
            x[ 4] ^= ROTL32(x[ 0] + x[12],  7);
            x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
            x[12] ^= ROTL32(x[ 8] + x[ 4], 13);
            x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
            x[ 9] ^= ROTL32(x[ 5] + x[ 1],  7);
            x[13] ^= ROTL32(x[ 9] + x[ 5],  9);
            x[ 1] ^= ROTL32(x[13] + x[ 9], 13);
            x[ 5] ^= ROTL32(x[ 1] + x[13], 18);
            x[14] ^= ROTL32(x[10] + x[ 6],  7);
            x[ 2] ^= ROTL32(x[14] + x[10],  9);
            x[ 6] ^= ROTL32(x[ 2] + x[14], 13);
            x[10] ^= ROTL32(x[ 6] + x[ 2], 18);
            x[ 3] ^= ROTL32(x[15] + x[11],  7);
            x[ 7] ^= ROTL32(x[ 3] + x[15],  9);
            x[11] ^= ROTL32(x[ 7] + x[ 3], 13);
            x[15] ^= ROTL32(x[11] + x[ 7], 18);
            // Row round
            x[ 1] ^= ROTL32(x[ 0] + x[ 3],  7);
            x[ 2] ^= ROTL32(x[ 1] + x[ 0],  9);
            x[ 3] ^= ROTL32(x[ 2] + x[ 1], 13);
            x[ 0] ^= ROTL32(x[ 3] + x[ 2], 18);
            x[ 6] ^= ROTL32(x[ 5] + x[ 4],  7);
            x[ 7] ^= ROTL32(x[ 6] + x[ 5],  9);
            x[ 4] ^= ROTL32(x[ 7] + x[ 6], 13);
            x[ 5] ^= ROTL32(x[ 4] + x[ 7], 18);
            x[11] ^= ROTL32(x[10] + x[ 9],  7);
            x[ 8] ^= ROTL32(x[11] + x[10],  9);
            x[ 9] ^= ROTL32(x[ 8] + x[11], 13);
            x[10] ^= ROTL32(x[ 9] + x[ 8], 18);
            x[12] ^= ROTL32(x[15] + x[14],  7);
            x[13] ^= ROTL32(x[12] + x[15],  9);
            x[14] ^= ROTL32(x[13] + x[12], 13);
            x[15] ^= ROTL32(x[14] + x[13], 18);
          }
          #undef ROTL32

          for (int i = 0; i < 16; i++) {
            B[i] += x[i];
          }
        };

        // scryptBlockMix: mixes 2*r 64-byte blocks
        // B is 2*r*16 uint32_t words (2*r * 64 bytes)
        // Output Y is same size, with even blocks then odd blocks
        auto blockMix = [&salsa20_8](uint32_t* B, uint32_t* Y, uint32_t r) {
          uint32_t blockCount = 2 * r;
          // X = B[2r-1] (last 64-byte block)
          uint32_t X[16];
          std::memcpy(X, &B[(blockCount - 1) * 16], 64);

          // Temporary arrays for even and odd blocks
          for (uint32_t i = 0; i < blockCount; i++) {
            // X = X xor B[i]
            for (int k = 0; k < 16; k++) {
              X[k] ^= B[i * 16 + k];
            }
            salsa20_8(X);
            // Copy result to Y
            std::memcpy(&Y[i * 16], X, 64);
          }

          // Rearrange: even blocks first, then odd blocks
          // Y currently has blocks in order 0,1,2,...,2r-1
          // We need: 0,2,4,...,2r-2, 1,3,5,...,2r-1
          std::vector<uint32_t> tmp(blockCount * 16);
          uint32_t half = 0;
          for (uint32_t i = 0; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          for (uint32_t i = 1; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          std::memcpy(Y, tmp.data(), blockCount * 64);
        };

        // scryptROMix: memory-hard function
        // B is 2*r*16 uint32_t words
        auto roMix = [&blockMix](uint32_t* B, uint64_t N, uint32_t r) {
          size_t blockWords = 2 * static_cast<size_t>(r) * 16; // words per block (each word is 4 bytes)
          size_t blockBytes = blockWords * 4;

          // Allocate V: N blocks
          std::vector<uint32_t> V(N * blockWords);
          std::vector<uint32_t> Y(blockWords);

          // Step 1: Build V
          for (uint64_t i = 0; i < N; i++) {
            std::memcpy(&V[i * blockWords], B, blockBytes);
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }

          // Step 2: Mix
          for (uint64_t i = 0; i < N; i++) {
            // Integerify: take last 64-byte block of B, interpret first 4 bytes as LE uint32
            uint32_t lastBlockStart = (2 * r - 1) * 16;
            uint64_t j = B[lastBlockStart] % N;

            // X = X xor V[j]
            for (size_t k = 0; k < blockWords; k++) {
              B[k] ^= V[j * blockWords + k];
            }
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }
        };

        // PBKDF2-HMAC-SHA256 implemented manually using CCHmac
        // (CommonCrypto's CCKeyDerivationPBKDF fails with empty password/salt)
        auto pbkdf2_sha256 = [](const uint8_t* pass, size_t passLen,
                                const uint8_t* saltData, size_t saltLen,
                                uint32_t iterations,
                                uint8_t* out, size_t outLen) {
          const size_t hLen = CC_SHA256_DIGEST_LENGTH; // 32
          uint32_t blockCount = static_cast<uint32_t>((outLen + hLen - 1) / hLen);

          for (uint32_t blockIdx = 1; blockIdx <= blockCount; blockIdx++) {
            // U_1 = HMAC-SHA256(pass, salt || INT_32_BE(blockIdx))
            // Prepare salt || INT_32_BE(blockIdx)
            std::vector<uint8_t> saltBlock(saltLen + 4);
            if (saltLen > 0) std::memcpy(saltBlock.data(), saltData, saltLen);
            saltBlock[saltLen + 0] = static_cast<uint8_t>((blockIdx >> 24) & 0xFF);
            saltBlock[saltLen + 1] = static_cast<uint8_t>((blockIdx >> 16) & 0xFF);
            saltBlock[saltLen + 2] = static_cast<uint8_t>((blockIdx >> 8) & 0xFF);
            saltBlock[saltLen + 3] = static_cast<uint8_t>(blockIdx & 0xFF);

            uint8_t U[CC_SHA256_DIGEST_LENGTH];
            uint8_t T[CC_SHA256_DIGEST_LENGTH];

            // U_1
            CCHmac(kCCHmacAlgSHA256, pass, passLen,
                   saltBlock.data(), saltBlock.size(), U);
            std::memcpy(T, U, hLen);

            // U_2 .. U_c
            for (uint32_t iter = 1; iter < iterations; iter++) {
              CCHmac(kCCHmacAlgSHA256, pass, passLen, U, hLen, U);
              for (size_t k = 0; k < hLen; k++) {
                T[k] ^= U[k];
              }
            }

            // Copy T to output
            size_t offset = static_cast<size_t>(blockIdx - 1) * hLen;
            size_t copyLen = (offset + hLen <= outLen) ? hLen : (outLen - offset);
            std::memcpy(out + offset, T, copyLen);
          }
        };

        // === Main scrypt algorithm ===
        size_t BLen = static_cast<size_t>(128) * r * p;
        std::vector<uint8_t> B(BLen);

        // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
        pbkdf2_sha256(password.data(), password.size(),
                      salt.data(), salt.size(),
                      1, B.data(), BLen);

        // Step 2: For each block i in 0..p, apply ROMix
        for (uint32_t i = 0; i < p; i++) {
          // Interpret B[i*128*r .. (i+1)*128*r] as uint32_t array (little-endian)
          uint32_t* block = reinterpret_cast<uint32_t*>(&B[static_cast<size_t>(i) * 128 * r]);
          // Note: On little-endian systems (x86/ARM), this is correct.
          // The scrypt spec defines the data as little-endian uint32 words.
          roMix(block, N, r);
        }

        // Step 3: Output = PBKDF2-HMAC-SHA256(password, B, 1, keylen)
        std::vector<uint8_t> derivedKey(keylen);
        pbkdf2_sha256(password.data(), password.size(),
                      B.data(), B.size(),
                      1, derivedKey.data(), keylen);

        return makeUint8Array(runtime, std::move(derivedKey));
#elif !defined(EXACT_NO_OPENSSL)
        std::vector<uint8_t> derivedKey(keylen);
        constexpr uint64_t kMaxScryptMemory = 1073741824ULL;
        if (EVP_PBE_scrypt(
                reinterpret_cast<const char*>(password.data()),
                password.size(),
                salt.data(),
                salt.size(),
                N,
                r,
                p,
                kMaxScryptMemory,
                derivedKey.data(),
                derivedKey.size()) != 1) {
          throw facebook::jsi::JSError(runtime, "scrypt derivation failed");
        }
        return makeUint8Array(runtime, std::move(derivedKey));
#else
        auto sha256Spec = portableDigestSpecForAlgorithm("sha256");
        if (!sha256Spec) {
          throw facebook::jsi::JSError(runtime, "scrypt: SHA-256 unavailable");
        }

        auto salsa20_8 = [](uint32_t B[16]) {
          uint32_t x[16];
          std::memcpy(x, B, 64);

          #define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
          for (int i = 0; i < 8; i += 2) {
            x[ 4] ^= ROTL32(x[ 0] + x[12],  7);
            x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
            x[12] ^= ROTL32(x[ 8] + x[ 4], 13);
            x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
            x[ 9] ^= ROTL32(x[ 5] + x[ 1],  7);
            x[13] ^= ROTL32(x[ 9] + x[ 5],  9);
            x[ 1] ^= ROTL32(x[13] + x[ 9], 13);
            x[ 5] ^= ROTL32(x[ 1] + x[13], 18);
            x[14] ^= ROTL32(x[10] + x[ 6],  7);
            x[ 2] ^= ROTL32(x[14] + x[10],  9);
            x[ 6] ^= ROTL32(x[ 2] + x[14], 13);
            x[10] ^= ROTL32(x[ 6] + x[ 2], 18);
            x[ 3] ^= ROTL32(x[15] + x[11],  7);
            x[ 7] ^= ROTL32(x[ 3] + x[15],  9);
            x[11] ^= ROTL32(x[ 7] + x[ 3], 13);
            x[15] ^= ROTL32(x[11] + x[ 7], 18);
            x[ 1] ^= ROTL32(x[ 0] + x[ 3],  7);
            x[ 2] ^= ROTL32(x[ 1] + x[ 0],  9);
            x[ 3] ^= ROTL32(x[ 2] + x[ 1], 13);
            x[ 0] ^= ROTL32(x[ 3] + x[ 2], 18);
            x[ 6] ^= ROTL32(x[ 5] + x[ 4],  7);
            x[ 7] ^= ROTL32(x[ 6] + x[ 5],  9);
            x[ 4] ^= ROTL32(x[ 7] + x[ 6], 13);
            x[ 5] ^= ROTL32(x[ 4] + x[ 7], 18);
            x[11] ^= ROTL32(x[10] + x[ 9],  7);
            x[ 8] ^= ROTL32(x[11] + x[10],  9);
            x[ 9] ^= ROTL32(x[ 8] + x[11], 13);
            x[10] ^= ROTL32(x[ 9] + x[ 8], 18);
            x[12] ^= ROTL32(x[15] + x[14],  7);
            x[13] ^= ROTL32(x[12] + x[15],  9);
            x[14] ^= ROTL32(x[13] + x[12], 13);
            x[15] ^= ROTL32(x[14] + x[13], 18);
          }
          #undef ROTL32

          for (int i = 0; i < 16; i++) {
            B[i] += x[i];
          }
        };

        auto blockMix = [&salsa20_8](uint32_t* B, uint32_t* Y, uint32_t r) {
          uint32_t blockCount = 2 * r;
          uint32_t X[16];
          std::memcpy(X, &B[(blockCount - 1) * 16], 64);
          for (uint32_t i = 0; i < blockCount; i++) {
            for (int k = 0; k < 16; k++) {
              X[k] ^= B[i * 16 + k];
            }
            salsa20_8(X);
            std::memcpy(&Y[i * 16], X, 64);
          }
          std::vector<uint32_t> tmp(blockCount * 16);
          uint32_t half = 0;
          for (uint32_t i = 0; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          for (uint32_t i = 1; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          std::memcpy(Y, tmp.data(), blockCount * 64);
        };

        auto roMix = [&blockMix](uint32_t* B, uint64_t N, uint32_t r) {
          size_t blockWords = 2 * static_cast<size_t>(r) * 16;
          size_t blockBytes = blockWords * 4;
          std::vector<uint32_t> V(N * blockWords);
          std::vector<uint32_t> Y(blockWords);
          for (uint64_t i = 0; i < N; i++) {
            std::memcpy(&V[i * blockWords], B, blockBytes);
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }
          for (uint64_t i = 0; i < N; i++) {
            uint32_t lastBlockStart = (2 * r - 1) * 16;
            uint64_t j = B[lastBlockStart] % N;
            for (size_t k = 0; k < blockWords; k++) {
              B[k] ^= V[j * blockWords + k];
            }
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }
        };

        size_t BLen = static_cast<size_t>(128) * r * p;
        auto B = portablePbkdf2(password, salt, 1, BLen, *sha256Spec);
        for (uint32_t i = 0; i < p; i++) {
          uint32_t* block = reinterpret_cast<uint32_t*>(&B[static_cast<size_t>(i) * 128 * r]);
          roMix(block, N, r);
        }

        auto derivedKey = portablePbkdf2(password, B, 1, keylen, *sha256Spec);
        return makeUint8Array(runtime, std::move(derivedKey));
#endif
      });
  rt.global().setProperty(rt, "__exactScryptSync", std::move(scryptFn));

#if defined(__APPLE__)
#if !defined(EXACT_PLATFORM_IOS)
  auto signFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSignSync"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        // args: algorithm, data (Uint8Array or string), key (PEM), scheme?, saltLength?
        if (count < 3 || !args[0].isString() || !args[2].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: algorithm, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = normalizeHashForNodeCrypto(rawAlgorithm);
        // Sign the RAW message bytes: a Uint8Array is taken byte-for-byte, and a
        // string is UTF-8 encoded, so bytes >= 0x80 are no longer mangled by a
        // string round-trip on the WebCrypto path (ENG-23002).
        auto dataBytes = extractBytes(runtime, args[1]);
        auto keyText = args[2].asString(runtime).utf8(runtime);
        bool usePss = false;
        int saltLen = -1;
        parseRsaSignScheme(runtime, args, count, 3, 4, usePss, saltLen);
        auto key = adoptCF(importPemKey(keyText, kSecItemTypePrivateKey));
        if (!key) {
#if !defined(EXACT_NO_OPENSSL)
          // Keep the feature-gated asymmetric OpenSSL parser for key kinds
          // outside the strict SecKey import surface. Malformed or
          // non-asymmetric keys still fail here and can never reach HMAC.
          // @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
          const EVP_MD* digest = openSslDigestForAlgorithm(hashName);
          std::vector<uint8_t> signature;
          std::string error;
          if (digest && opensslSignMessageCore(
                            dataBytes, keyText, digest, usePss, saltLen,
                            signature, error)) {
            return makeUint8Array(runtime, std::move(signature));
          }
#endif
          throw facebook::jsi::JSError(runtime, "__exactSignSync: invalid PEM private key");
        }

        auto isRsa = isRsaSecKey(key.get());
        if (usePss && !isRsa) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: RSA-PSS requires an RSA key");
        }
        // SecKey's message-PSS algorithms fix the salt length at the digest size,
        // so honor an explicit saltLength only when it matches; reject anything
        // else rather than silently producing a mismatched-salt signature.
        // Negative salt modes (-1 digest / -2 max) both produce a digest-length
        // salt here — a valid PSS signature that conformant verifiers accept in
        // auto mode (honest reduced profile, LLP 0006).
        if (usePss && saltLen >= 0 &&
            static_cast<size_t>(saltLen) != rsaHashDigestSize(hashName)) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactSignSync: RSA-PSS salt length " + std::to_string(saltLen) +
                  " is unsupported on this platform (SecKey uses salt length == digest size)");
        }
        auto algorithm = pickSecKeySignAlgorithm(hashName, isRsa, usePss);
        if (!algorithm) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: unsupported algorithm " + rawAlgorithm);
        }

        auto dataRef = adoptCF(CFDataCreate(
            kCFAllocatorDefault,
            dataBytes.data(),
            static_cast<CFIndex>(dataBytes.size())));
        if (!dataRef) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: failed to allocate data");
        }

        CFErrorRef error = nullptr;
        auto signatureRef = adoptCF(SecKeyCreateSignature(
            key.get(),
            algorithm,
            dataRef.get(),
            &error));
        auto errorRef = adoptCF(error);
        if (!signatureRef) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: signing failed");
        }

        auto signature = dataToString(signatureRef.get());
        return makeUint8Array(runtime, std::vector<uint8_t>(signature.begin(), signature.end()));
      });
  rt.global().setProperty(rt, "__exactSignSync", std::move(signFn));
#endif // !EXACT_PLATFORM_IOS

#if !defined(EXACT_PLATFORM_IOS)
  auto verifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactVerifySync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        // args: algorithm, signature, data (Uint8Array or string), key (PEM), scheme?, saltLength?
        if (count < 4 || !args[0].isString() || !args[3].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: algorithm, signature, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = normalizeHashForNodeCrypto(rawAlgorithm);
        auto signatureBytes = extractBytes(runtime, args[1]);
        // Verify against the RAW message bytes (see __exactSignSync — ENG-23002).
        auto dataBytes = extractBytes(runtime, args[2]);
        auto keyText = args[3].asString(runtime).utf8(runtime);
        bool usePss = false;
        int saltLen = -1;
        parseRsaSignScheme(runtime, args, count, 4, 5, usePss, saltLen);
        auto key = adoptCF(importPemKey(keyText, kSecItemTypePublicKey));
        if (!key) {
#if !defined(EXACT_NO_OPENSSL)
          // Match the private-key path above for SPKI EC public keys while
          // retaining a strict asymmetric parser and an explicit error on
          // malformed key material.
          // @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
          const EVP_MD* digest = openSslDigestForAlgorithm(hashName);
          std::string error;
          if (digest) {
            int result = opensslVerifyMessageCore(
                dataBytes, signatureBytes, keyText, digest, usePss, saltLen,
                error);
            if (result >= 0) {
              return facebook::jsi::Value(result == 1);
            }
          }
#endif
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: invalid PEM public key");
        }

        auto isRsa = isRsaSecKey(key.get());
        if (usePss && !isRsa) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: RSA-PSS requires an RSA key");
        }
        // Negative salt modes (-1 digest / -2 auto) can only check a
        // digest-length salt here: SecKey has no auto-recover mode, so a
        // conformant max-salt signature will not verify on this platform
        // (honest reduced profile, LLP 0006).
        if (usePss && saltLen >= 0 &&
            static_cast<size_t>(saltLen) != rsaHashDigestSize(hashName)) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactVerifySync: RSA-PSS salt length " + std::to_string(saltLen) +
                  " is unsupported on this platform (SecKey uses salt length == digest size)");
        }
        auto algorithm = pickSecKeySignAlgorithm(hashName, isRsa, usePss);
        if (!algorithm) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: unsupported algorithm " + rawAlgorithm);
        }

        auto signatureRef = adoptCF(CFDataCreate(
            kCFAllocatorDefault,
            signatureBytes.data(),
            static_cast<CFIndex>(signatureBytes.size())));
        auto dataRef = adoptCF(CFDataCreate(
            kCFAllocatorDefault,
            dataBytes.data(),
            static_cast<CFIndex>(dataBytes.size())));
        if (!dataRef || !signatureRef) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: failed to allocate data");
        }

        CFErrorRef error = nullptr;
        auto verified = SecKeyVerifySignature(
            key.get(),
            algorithm,
            dataRef.get(),
            signatureRef.get(),
            &error);
        auto errorRef = adoptCF(error);
        return facebook::jsi::Value(static_cast<bool>(verified));
      });
  rt.global().setProperty(rt, "__exactVerifySync", std::move(verifyFn));
#endif // !EXACT_PLATFORM_IOS

  auto generateKeyPairSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGenerateKeyPairSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key type required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        if (keyType != "rsa" && keyType != "ec" && keyType != "rsa-pss" &&
            keyType != "ecdsa" && keyType != "ed25519" && keyType != "x25519") {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported key type " + keyType);
        }

        uint32_t bits = 2048;
        uint32_t exponent = 65537;
        std::string namedCurve = "P-256";
        if (count >= 2 && args[1].isObject()) {
          auto options = args[1].asObject(runtime);
          if (options.hasProperty(runtime, "modulusLength")) {
            auto v = options.getProperty(runtime, "modulusLength");
            if (v.isNumber()) bits = static_cast<uint32_t>(v.asNumber());
          }
          if (options.hasProperty(runtime, "publicExponent")) {
            auto v = options.getProperty(runtime, "publicExponent");
            if (v.isNumber()) exponent = static_cast<uint32_t>(v.asNumber());
            else if (v.isString()) {
              exponent = static_cast<uint32_t>(std::stoul(v.asString(runtime).utf8(runtime)));
            }
          }
          if (options.hasProperty(runtime, "namedCurve")) {
            auto v = options.getProperty(runtime, "namedCurve");
            if (v.isString()) namedCurve = v.asString(runtime).utf8(runtime);
          }
        }

        // --- Ed25519 and X25519: use OpenSSL on macOS ---
        if (keyType == "ed25519" || keyType == "x25519") {
#if !defined(EXACT_NO_OPENSSL)
          int evpType = (keyType == "ed25519") ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(evpType, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create context for " + keyType);
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed for " + keyType);
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed for " + keyType);
          }
          EVP_PKEY_CTX_free(ctx);

          // Export as PEM
          BIO* privateBio = BIO_new(BIO_s_mem());
          BIO* publicBio = BIO_new(BIO_s_mem());
          if (!privateBio || !publicBio) {
            if (privateBio) BIO_free(privateBio);
            if (publicBio) BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate PEM buffers");
          }
          if (PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
              PEM_write_bio_PUBKEY(publicBio, pkey) != 1) {
            BIO_free(privateBio);
            BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to serialize PEM keys for " + keyType);
          }
          EVP_PKEY_free(pkey);

          char* privatePtr = nullptr;
          char* publicPtr = nullptr;
          auto privateLen = BIO_get_mem_data(privateBio, &privatePtr);
          auto publicLen = BIO_get_mem_data(publicBio, &publicPtr);
          std::string privatePem = privatePtr && privateLen > 0 ? std::string(privatePtr, static_cast<size_t>(privateLen)) : std::string();
          std::string publicPem = publicPtr && publicLen > 0 ? std::string(publicPtr, static_cast<size_t>(publicLen)) : std::string();
          BIO_free(privateBio);
          BIO_free(publicBio);

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
#else
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: " + keyType + " key generation requires OpenSSL (not available on iOS)");
#endif // !EXACT_NO_OPENSSL
        }

        // --- ECDSA: use Security.framework on macOS ---
        if (keyType == "ec" || keyType == "ecdsa") {
          uint32_t ecBits = 256;
          if (namedCurve == "P-256" || namedCurve == "prime256v1") ecBits = 256;
          else if (namedCurve == "P-384" || namedCurve == "secp384r1") ecBits = 384;
          else if (namedCurve == "P-521" || namedCurve == "secp521r1") ecBits = 521;
          else {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported EC curve " + namedCurve);
          }

          auto ecBitsValue = adoptCF(CFNumberCreate(
              kCFAllocatorDefault,
              kCFNumberSInt32Type,
              &ecBits));
          if (!ecBitsValue) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate EC options");
          }

          CFTypeRef ecKeys[2] = { kSecAttrKeyType, kSecAttrKeySizeInBits };
          CFTypeRef ecValues[2] = { kSecAttrKeyTypeECSECPrimeRandom, ecBitsValue.get() };
          auto ecParams = adoptCF(CFDictionaryCreate(
              kCFAllocatorDefault, ecKeys, ecValues, 2,
              &kCFTypeDictionaryKeyCallBacks,
              &kCFTypeDictionaryValueCallBacks));
          if (!ecParams) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate EC key params");
          }

          CFErrorRef ecError = nullptr;
          auto ecPrivateKey = adoptCF(SecKeyCreateRandomKey(
              static_cast<CFDictionaryRef>(ecParams.get()),
              &ecError));
          auto ecErrorRef = adoptCF(ecError);
          if (!ecPrivateKey) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }
          auto ecPublicKey = adoptCF(SecKeyCopyPublicKey(ecPrivateKey.get()));
          if (!ecPublicKey) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }

#if !defined(EXACT_PLATFORM_IOS)
          CFDataRef ecPrivateDataRaw = nullptr;
          CFDataRef ecPublicDataRaw = nullptr;
          auto ecExportStatus = SecItemExport(
              ecPrivateKey.get(),
              kSecFormatOpenSSL,
              kSecItemPemArmour,
              nullptr,
              &ecPrivateDataRaw);
          auto ecPrivateData = adoptCF(ecPrivateDataRaw);
          if (ecExportStatus == errSecSuccess) {
            ecExportStatus = SecItemExport(
                ecPublicKey.get(),
                kSecFormatOpenSSL,
                kSecItemPemArmour,
                nullptr,
                &ecPublicDataRaw);
          }
          auto ecPublicData = adoptCF(ecPublicDataRaw);
          if (ecExportStatus != errSecSuccess || !ecPrivateData || !ecPublicData) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to export EC PEM keys");
          }

          std::string privatePem = dataToString(ecPrivateData.get());
          std::string publicPem = dataToString(ecPublicData.get());
          auto replacePublicPemLabel = [](std::string& pem, const char* from, const char* to) {
            size_t pos = 0;
            const size_t fromLen = std::strlen(from);
            const size_t toLen = std::strlen(to);
            while ((pos = pem.find(from, pos)) != std::string::npos) {
              pem.replace(pos, fromLen, to);
              pos += toLen;
            }
          };
          replacePublicPemLabel(
              publicPem, "-----BEGIN ECDSA PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----");
          replacePublicPemLabel(
              publicPem, "-----END ECDSA PUBLIC KEY-----", "-----END PUBLIC KEY-----");

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
#else
          throw facebook::jsi::JSError(runtime, "PEM key export not yet available on iOS");
#endif // !EXACT_PLATFORM_IOS
        }

        // --- RSA ---
        if (bits < 1024) bits = 1024;
        if (bits > 16384) bits = 16384;

        if (exponent != 65537) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported public exponent");
        }

        auto bitsValue = adoptCF(CFNumberCreate(
            kCFAllocatorDefault,
            kCFNumberSInt32Type,
            &bits));
        if (!bitsValue) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate options");
        }

        CFTypeRef keys[2] = { kSecAttrKeyType, kSecAttrKeySizeInBits };
        CFTypeRef values[2] = { kSecAttrKeyTypeRSA, bitsValue.get() };
        auto params = adoptCF(CFDictionaryCreate(
            kCFAllocatorDefault,
            keys,
            values,
            2,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks));
        if (!params) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate key params");
        }

        CFErrorRef rsaError = nullptr;
        auto privateKey = adoptCF(SecKeyCreateRandomKey(
            static_cast<CFDictionaryRef>(params.get()),
            &rsaError));
        auto rsaErrorRef = adoptCF(rsaError);
        if (!privateKey) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed");
        }
        auto publicKey = adoptCF(SecKeyCopyPublicKey(privateKey.get()));
        if (!publicKey) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed");
        }

#if !defined(EXACT_PLATFORM_IOS)
        CFDataRef privateDataRaw = nullptr;
        CFDataRef publicDataRaw = nullptr;
        auto exportStatus = SecItemExport(
            privateKey.get(),
            kSecFormatOpenSSL,
            kSecItemPemArmour,
            nullptr,
            &privateDataRaw);
        auto privateData = adoptCF(privateDataRaw);
        if (exportStatus == errSecSuccess) {
          exportStatus = SecItemExport(
              publicKey.get(),
              kSecFormatOpenSSL,
              kSecItemPemArmour,
              nullptr,
              &publicDataRaw);
        }
        auto publicData = adoptCF(publicDataRaw);
        if (exportStatus != errSecSuccess || !privateData || !publicData) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to export PEM keys");
        }

        std::string privatePem = dataToString(privateData.get());
        std::string publicPem = dataToString(publicData.get());

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
        result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
        return result;
#else
        throw facebook::jsi::JSError(runtime, "PEM key export not yet available on iOS");
#endif // !EXACT_PLATFORM_IOS
      });
  rt.global().setProperty(rt, "__exactGenerateKeyPairSync", std::move(generateKeyPairSyncFn));
#else  // !defined(__APPLE__)
#if !defined(EXACT_NO_OPENSSL)
  auto signFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSignSync"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        // args: algorithm, data (Uint8Array or string), key (PEM), scheme?, saltLength?
        if (count < 3 || !args[0].isString() || !args[2].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: algorithm, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = digestAlgorithmFromNodeCrypto(rawAlgorithm);
        const EVP_MD* md = selectDigestForCryptoAlgo(hashName);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: unsupported algorithm " + rawAlgorithm);
        }

        // Sign the RAW message bytes (Uint8Array taken byte-for-byte, string
        // UTF-8 encoded) instead of the old string-only path that mangled bytes
        // >= 0x80, and thread the RSA-PSS scheme + salt length through so
        // RSA-PSS no longer silently signs PKCS#1 v1.5 (ENG-23002).
        auto data = extractBytes(runtime, args[1]);
        auto keyText = args[2].asString(runtime).utf8(runtime);
        bool usePss = false;
        int saltLen = -1;
        parseRsaSignScheme(runtime, args, count, 3, 4, usePss, saltLen);

        std::vector<uint8_t> signature;
        std::string err;
        if (!opensslSignMessageCore(data, keyText, md, usePss, saltLen, signature, err)) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: " + err);
        }
        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactSignSync", std::move(signFn));

  auto verifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactVerifySync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        // args: algorithm, signature, data (Uint8Array or string), key (PEM), scheme?, saltLength?
        if (count < 4 || !args[0].isString() || !args[3].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: algorithm, signature, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = digestAlgorithmFromNodeCrypto(rawAlgorithm);
        const EVP_MD* md = selectDigestForCryptoAlgo(hashName);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: unsupported algorithm " + rawAlgorithm);
        }

        auto signatureBytes = extractBytes(runtime, args[1]);
        // Verify against the RAW message bytes + RSA-PSS scheme/salt (ENG-23002).
        auto data = extractBytes(runtime, args[2]);
        auto keyText = args[3].asString(runtime).utf8(runtime);
        bool usePss = false;
        int saltLen = -1;
        parseRsaSignScheme(runtime, args, count, 4, 5, usePss, saltLen);

        std::string err;
        int result = opensslVerifyMessageCore(data, signatureBytes, keyText, md, usePss, saltLen, err);
        if (result < 0) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: " + err);
        }
        return facebook::jsi::Value(result == 1);
      });
  rt.global().setProperty(rt, "__exactVerifySync", std::move(verifyFn));

  auto generateKeyPairSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGenerateKeyPairSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key type required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        if (keyType != "rsa" && keyType != "ec" && keyType != "rsa-pss" &&
            keyType != "ecdsa" && keyType != "ed25519" && keyType != "x25519") {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported key type " + keyType);
        }

        uint32_t bits = 2048;
        uint32_t exponent = 65537;
        std::string namedCurve = "P-256";
        if (count >= 2 && args[1].isObject()) {
          auto options = args[1].asObject(runtime);
          if (options.hasProperty(runtime, "modulusLength")) {
            auto v = options.getProperty(runtime, "modulusLength");
            if (v.isNumber()) bits = static_cast<uint32_t>(v.asNumber());
          }
          if (options.hasProperty(runtime, "publicExponent")) {
            auto v = options.getProperty(runtime, "publicExponent");
            if (v.isNumber()) exponent = static_cast<uint32_t>(v.asNumber());
            else if (v.isString()) {
              exponent = static_cast<uint32_t>(std::stoul(v.asString(runtime).utf8(runtime)));
            }
          }
          if (options.hasProperty(runtime, "namedCurve")) {
            auto v = options.getProperty(runtime, "namedCurve");
            if (v.isString()) namedCurve = v.asString(runtime).utf8(runtime);
          }
        }

        // Helper lambda: generate EVP_PKEY and serialize to PEM
        auto serializeKeyPairToPem = [&](EVP_PKEY* pkey) -> facebook::jsi::Value {
          BIO* privateBio = BIO_new(BIO_s_mem());
          BIO* publicBio = BIO_new(BIO_s_mem());
          if (!privateBio || !publicBio) {
            if (privateBio) BIO_free(privateBio);
            if (publicBio) BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate PEM buffers");
          }
          if (PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
              PEM_write_bio_PUBKEY(publicBio, pkey) != 1) {
            BIO_free(privateBio);
            BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to serialize PEM keys");
          }
          EVP_PKEY_free(pkey);

          char* privatePtr = nullptr;
          char* publicPtr = nullptr;
          auto privateLen = BIO_get_mem_data(privateBio, &privatePtr);
          auto publicLen = BIO_get_mem_data(publicBio, &publicPtr);
          std::string privatePem = privatePtr && privateLen > 0 ? std::string(privatePtr, static_cast<size_t>(privateLen)) : std::string();
          std::string publicPem = publicPtr && publicLen > 0 ? std::string(publicPtr, static_cast<size_t>(publicLen)) : std::string();
          BIO_free(privateBio);
          BIO_free(publicBio);

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
        };

        // --- Ed25519 and X25519 ---
        if (keyType == "ed25519" || keyType == "x25519") {
          int evpType = (keyType == "ed25519") ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(evpType, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create context for " + keyType);
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed for " + keyType);
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed for " + keyType);
          }
          EVP_PKEY_CTX_free(ctx);
          return serializeKeyPairToPem(pkey);
        }

        // --- ECDSA ---
        if (keyType == "ec" || keyType == "ecdsa") {
          int nid = NID_X9_62_prime256v1;
          if (namedCurve == "P-256" || namedCurve == "prime256v1") nid = NID_X9_62_prime256v1;
          else if (namedCurve == "P-384" || namedCurve == "secp384r1") nid = NID_secp384r1;
          else if (namedCurve == "P-521" || namedCurve == "secp521r1") nid = NID_secp521r1;
          else {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported EC curve " + namedCurve);
          }

          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create EC context");
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC keygen init failed");
          }
          if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set EC curve");
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }
          EVP_PKEY_CTX_free(ctx);
          return serializeKeyPairToPem(pkey);
        }

        // --- RSA ---
        if (bits < 1024) bits = 1024;
        if (bits > 16384) bits = 16384;
        if (exponent != 65537) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported public exponent");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate key context");
        }
        if (EVP_PKEY_keygen_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set RSA key length");
        }

        BIGNUM* exp = nullptr;
        if (exponent == 0) {
          exponent = 65537;
        }
        exp = BN_new();
        if (!exp || !BN_set_word(exp, exponent) || EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exp) <= 0) {
          if (exp) BN_clear_free(exp);
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set public exponent");
        }
        // Note: after successful EVP_PKEY_CTX_set_rsa_keygen_pubexp, ownership of exp transfers
        // Do NOT free exp here

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        EVP_PKEY_CTX_free(ctx);
        return serializeKeyPairToPem(pkey);
      });
  rt.global().setProperty(rt, "__exactGenerateKeyPairSync", std::move(generateKeyPairSyncFn));
#else  // EXACT_NO_OPENSSL: reduced crypto profile (no asymmetric sign/verify)
  // Register the same JS surface as throwing stubs so callers get a clear
  // runtime error instead of a missing-global ReferenceError. Real asymmetric
  // crypto requires building ibex-runtime with the `openssl-crypto` feature.
  // @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles — reduced crypto profiles expose clear throwing stubs.
  auto makeUnavailableAsymCryptoFn =
      [](facebook::jsi::Runtime& rtRef, const char* name) {
        std::string fnName(name);
        return facebook::jsi::Function::createFromHostFunction(
            rtRef,
            facebook::jsi::PropNameID::forAscii(rtRef, name),
            0,
            [fnName](facebook::jsi::Runtime& runtime,
                     const facebook::jsi::Value&,
                     const facebook::jsi::Value*,
                     size_t) -> facebook::jsi::Value {
              throw facebook::jsi::JSError(
                  runtime,
                  fnName +
                      ": asymmetric crypto is unavailable in this build "
                      "(rebuild ibex-runtime with the openssl-crypto feature)");
            });
      };
  rt.global().setProperty(
      rt, "__exactSignSync", makeUnavailableAsymCryptoFn(rt, "__exactSignSync"));
  rt.global().setProperty(
      rt, "__exactVerifySync", makeUnavailableAsymCryptoFn(rt, "__exactVerifySync"));
  rt.global().setProperty(
      rt,
      "__exactGenerateKeyPairSync",
      makeUnavailableAsymCryptoFn(rt, "__exactGenerateKeyPairSync"));
#endif  // !EXACT_NO_OPENSSL
#endif

#if !defined(EXACT_NO_OPENSSL)
  // --- Ed25519 Sign ---
  // __exactEd25519Sign(privateKeyBytes, data) -> Uint8Array (64-byte signature)
  auto ed25519SignFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEd25519Sign"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: privateKey and data required");
        }
        auto privKeyBytes = extractBytes(runtime, args[0]);
        auto data = extractBytes(runtime, args[1]);

        // Import the private key - try raw 32-byte key first, then PEM/PKCS8
        EVP_PKEY* pkey = nullptr;
        if (privKeyBytes.size() == 32) {
          // Raw 32-byte Ed25519 private key seed
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privKeyBytes.data(), privKeyBytes.size());
        }
        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER/PKCS8 format
          const unsigned char* p = privKeyBytes.data();
          pkey = d2i_PrivateKey(EVP_PKEY_ED25519, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to import Ed25519 private key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to allocate context");
        }

        // Ed25519 uses NULL as the digest (it does its own hashing)
        if (EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: EVP_DigestSignInit failed");
        }

        size_t sigLen = 0;
        if (EVP_DigestSign(mdCtx, nullptr, &sigLen, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to get signature length");
        }
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSign(mdCtx, signature.data(), &sigLen, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: signing failed");
        }
        signature.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactEd25519Sign", std::move(ed25519SignFn));

  // --- Ed25519 Verify ---
  // __exactEd25519Verify(publicKeyBytes, signature, data) -> boolean
  auto ed25519VerifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEd25519Verify"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: publicKey, signature, and data required");
        }
        auto pubKeyBytes = extractBytes(runtime, args[0]);
        auto sigBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);

        // Import the public key - try raw 32-byte key first, then PEM/SPKI
        EVP_PKEY* pkey = nullptr;
        if (pubKeyBytes.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubKeyBytes.data(), pubKeyBytes.size());
        }
        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER/SPKI format
          const unsigned char* p = pubKeyBytes.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: failed to import Ed25519 public key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: failed to allocate context");
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: EVP_DigestVerifyInit failed");
        }

        auto result = EVP_DigestVerify(mdCtx, sigBytes.data(), sigBytes.size(), data.data(), data.size());
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        return facebook::jsi::Value(result == 1);
      });
  rt.global().setProperty(rt, "__exactEd25519Verify", std::move(ed25519VerifyFn));

  // --- ECDSA Sign ---
  // __exactEcdsaSign(curve, hash, privateKeyBytes, data) -> Uint8Array (DER-encoded signature)
  auto ecdsaSignFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdsaSign"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: curve, hash, privateKey, and data required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto hash = args[1].asString(runtime).utf8(runtime);
        auto privKeyBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);

        // Select digest
        const EVP_MD* md = nullptr;
        if (hash == "SHA-256" || hash == "sha256" || hash == "sha-256") md = EVP_sha256();
        else if (hash == "SHA-384" || hash == "sha384" || hash == "sha-384") md = EVP_sha384();
        else if (hash == "SHA-512" || hash == "sha512" || hash == "sha-512") md = EVP_sha512();
        else if (hash == "SHA-1" || hash == "sha1" || hash == "sha-1") md = EVP_sha1();
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: unsupported hash algorithm " + hash);
        }

        // Import private key - try PEM first, then DER/PKCS8
        EVP_PKEY* pkey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          const unsigned char* p = privKeyBytes.data();
          pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!pkey) {
          // Try as PKCS8 DER
          const unsigned char* p = privKeyBytes.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(privKeyBytes.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to import EC private key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to allocate context");
        }

        if (EVP_DigestSignInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: EVP_DigestSignInit failed");
        }
        if (EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: EVP_DigestSignUpdate failed");
        }

        size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to get signature length");
        }
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: signing failed");
        }
        signature.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactEcdsaSign", std::move(ecdsaSignFn));

  // --- ECDSA Verify ---
  // __exactEcdsaVerify(curve, hash, publicKeyBytes, signature, data) -> boolean
  auto ecdsaVerifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdsaVerify"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: curve, hash, publicKey, signature, and data required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto hash = args[1].asString(runtime).utf8(runtime);
        auto pubKeyBytes = extractBytes(runtime, args[2]);
        auto sigBytes = extractBytes(runtime, args[3]);
        auto data = extractBytes(runtime, args[4]);

        const EVP_MD* md = nullptr;
        if (hash == "SHA-256" || hash == "sha256" || hash == "sha-256") md = EVP_sha256();
        else if (hash == "SHA-384" || hash == "sha384" || hash == "sha-384") md = EVP_sha384();
        else if (hash == "SHA-512" || hash == "sha512" || hash == "sha-512") md = EVP_sha512();
        else if (hash == "SHA-1" || hash == "sha1" || hash == "sha-1") md = EVP_sha1();
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: unsupported hash algorithm " + hash);
        }

        // Import public key - try PEM first, then DER/SPKI
        EVP_PKEY* pkey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          const unsigned char* p = pubKeyBytes.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: failed to import EC public key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: failed to allocate context");
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: EVP_DigestVerifyInit failed");
        }
        if (EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: EVP_DigestVerifyUpdate failed");
        }

        auto result = EVP_DigestVerifyFinal(mdCtx, sigBytes.data(), sigBytes.size());
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        if (result != 1 && result != 0) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: verification error");
        }
        return facebook::jsi::Value(result == 1);
      });
  rt.global().setProperty(rt, "__exactEcdsaVerify", std::move(ecdsaVerifyFn));

  // --- X25519 Derive Bits (ECDH with Curve25519) ---
  // __exactX25519DeriveBits(privateKeyBytes, publicKeyBytes) -> Uint8Array (32-byte shared secret)
  auto x25519DeriveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactX25519DeriveBits"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: privateKey and publicKey required");
        }
        auto privKeyBytes = extractBytes(runtime, args[0]);
        auto pubKeyBytes = extractBytes(runtime, args[1]);

        // Import private key
        EVP_PKEY* privKey = nullptr;
        if (privKeyBytes.size() == 32) {
          privKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKeyBytes.data(), privKeyBytes.size());
        }
        if (!privKey) {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!privKey) {
          const unsigned char* p = privKeyBytes.data();
          privKey = d2i_PrivateKey(EVP_PKEY_X25519, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!privKey) {
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to import X25519 private key");
        }

        // Import public key
        EVP_PKEY* pubKey = nullptr;
        if (pubKeyBytes.size() == 32) {
          pubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pubKeyBytes.data(), pubKeyBytes.size());
        }
        if (!pubKey) {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey) {
          // crypto.diffieHellman() accepts a private KeyObject in the
          // publicKey slot (Node semantics, ENG-23144); import the private
          // material and let EVP_PKEY_derive_set_peer use its public half.
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PrivateKey(EVP_PKEY_X25519, nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey) {
          EVP_PKEY_free(privKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to import X25519 public key");
        }

        // Derive shared secret
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to create derive context");
        }

        if (EVP_PKEY_derive_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: derive init failed");
        }

        if (EVP_PKEY_derive_set_peer(ctx, pubKey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to set peer key");
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to get secret length");
        }

        std::vector<uint8_t> secret(secretLen);
        if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: key derivation failed");
        }
        secret.resize(secretLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        return makeUint8Array(runtime, std::move(secret));
      });
  rt.global().setProperty(rt, "__exactX25519DeriveBits", std::move(x25519DeriveFn));

  // --- Export Key to SPKI (SubjectPublicKeyInfo DER) ---
  // __exactExportKeySpki(keyType, keyData) -> Uint8Array (DER-encoded SPKI)
  auto exportSpkiFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExportKeySpki"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: keyType and keyData required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        auto keyData = extractBytes(runtime, args[1]);

        EVP_PKEY* pkey = nullptr;

        // Try to import the key based on type
        if (keyType == "ed25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, keyData.data(), keyData.size());
        } else if (keyType == "x25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, keyData.data(), keyData.size());
        }

        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER SPKI format (already SPKI - just pass through)
          const unsigned char* p = keyData.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(keyData.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: failed to import public key");
        }

        // Export to DER SPKI
        unsigned char* der = nullptr;
        int derLen = i2d_PUBKEY(pkey, &der);
        EVP_PKEY_free(pkey);
        if (derLen <= 0 || !der) {
          if (der) OPENSSL_free(der);
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: failed to export SPKI");
        }

        std::vector<uint8_t> result(der, der + derLen);
        OPENSSL_free(der);
        return makeUint8Array(runtime, std::move(result));
      });
  rt.global().setProperty(rt, "__exactExportKeySpki", std::move(exportSpkiFn));

  // --- Export Key to PKCS8 (PrivateKeyInfo DER) ---
  // __exactExportKeyPkcs8(keyType, keyData) -> Uint8Array (DER-encoded PKCS8)
  auto exportPkcs8Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExportKeyPkcs8"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: keyType and keyData required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        auto keyData = extractBytes(runtime, args[1]);

        EVP_PKEY* pkey = nullptr;

        // Try raw key import for Ed25519/X25519
        if (keyType == "ed25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, keyData.data(), keyData.size());
        } else if (keyType == "x25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, keyData.data(), keyData.size());
        }

        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER PKCS8 format
          const unsigned char* p = keyData.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(keyData.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to import private key");
        }

        // Export to PKCS8 DER
        PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
        EVP_PKEY_free(pkey);
        if (!p8) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to create PKCS8 structure");
        }

        unsigned char* der = nullptr;
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
        PKCS8_PRIV_KEY_INFO_free(p8);
        if (derLen <= 0 || !der) {
          if (der) OPENSSL_free(der);
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to export PKCS8");
        }

        std::vector<uint8_t> result(der, der + derLen);
        OPENSSL_free(der);
        return makeUint8Array(runtime, std::move(result));
      });
  rt.global().setProperty(rt, "__exactExportKeyPkcs8", std::move(exportPkcs8Fn));

  // --- Import Key from SPKI (SubjectPublicKeyInfo DER) ---
  // __exactImportKeySpki(keyData) -> { keyType: string, rawKeyData: Uint8Array }
  auto importSpkiFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactImportKeySpki"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: keyData required");
        }
        auto keyData = extractBytes(runtime, args[0]);

        // Parse DER SPKI
        const unsigned char* p = keyData.data();
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(keyData.size()));
        if (!pkey) {
          // Try PEM
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to parse SPKI key data");
        }

        // Determine key type
        std::string keyTypeStr;
        int pkeyType = EVP_PKEY_base_id(pkey);
        std::vector<uint8_t> rawKey;

        if (pkeyType == EVP_PKEY_ED25519) {
          keyTypeStr = "ed25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_public_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to extract Ed25519 public key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_X25519) {
          keyTypeStr = "x25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_public_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to extract X25519 public key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_EC) {
          keyTypeStr = "ec";
          // Export the full SPKI DER as rawKeyData (the caller can use it as-is)
          unsigned char* der = nullptr;
          int derLen = i2d_PUBKEY(pkey, &der);
          if (derLen > 0 && der) {
            rawKey.assign(der, der + derLen);
            OPENSSL_free(der);
          }
        } else if (pkeyType == EVP_PKEY_RSA) {
          keyTypeStr = "rsa";
          unsigned char* der = nullptr;
          int derLen = i2d_PUBKEY(pkey, &der);
          if (derLen > 0 && der) {
            rawKey.assign(der, der + derLen);
            OPENSSL_free(der);
          }
        } else {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: unsupported key type in SPKI");
        }

        EVP_PKEY_free(pkey);

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "keyType", facebook::jsi::String::createFromUtf8(runtime, keyTypeStr));
        result.setProperty(runtime, "rawKeyData", makeUint8Array(runtime, std::move(rawKey)));
        return result;
      });
  rt.global().setProperty(rt, "__exactImportKeySpki", std::move(importSpkiFn));

  // --- Import Key from PKCS8 (PrivateKeyInfo DER) ---
  // __exactImportKeyPkcs8(keyData) -> { keyType: string, rawKeyData: Uint8Array }
  auto importPkcs8Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactImportKeyPkcs8"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: keyData required");
        }
        auto keyData = extractBytes(runtime, args[0]);

        // Parse DER PKCS8
        EVP_PKEY* pkey = nullptr;
        {
          const unsigned char* p = keyData.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(keyData.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          // Try PEM
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to parse PKCS8 key data");
        }

        // Determine key type
        std::string keyTypeStr;
        int pkeyType = EVP_PKEY_base_id(pkey);
        std::vector<uint8_t> rawKey;

        if (pkeyType == EVP_PKEY_ED25519) {
          keyTypeStr = "ed25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_private_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to extract Ed25519 private key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_X25519) {
          keyTypeStr = "x25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_private_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to extract X25519 private key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_EC) {
          keyTypeStr = "ec";
          // Export as PKCS8 DER
          PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
          if (p8) {
            unsigned char* der = nullptr;
            int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (derLen > 0 && der) {
              rawKey.assign(der, der + derLen);
              OPENSSL_free(der);
            }
          }
        } else if (pkeyType == EVP_PKEY_RSA) {
          keyTypeStr = "rsa";
          PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
          if (p8) {
            unsigned char* der = nullptr;
            int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (derLen > 0 && der) {
              rawKey.assign(der, der + derLen);
              OPENSSL_free(der);
            }
          }
        } else {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: unsupported key type in PKCS8");
        }

        EVP_PKEY_free(pkey);

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "keyType", facebook::jsi::String::createFromUtf8(runtime, keyTypeStr));
        result.setProperty(runtime, "rawKeyData", makeUint8Array(runtime, std::move(rawKey)));
        return result;
      });
  rt.global().setProperty(rt, "__exactImportKeyPkcs8", std::move(importPkcs8Fn));
#endif // !EXACT_NO_OPENSSL

  // --- HKDF (RFC 5869) ---
  // __exactHkdf(hashAlgo, ikm, salt, info, length) -> Uint8Array
  auto hkdfFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHkdf"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) throw facebook::jsi::JSError(runtime, "__exactHkdf: hashAlgo, ikm, salt, info, length required");
        auto hashAlgo = args[0].asString(runtime).utf8(runtime);
        auto ikm = extractBytes(runtime, args[1]);
        auto salt = extractBytes(runtime, args[2]);
        auto info = extractBytes(runtime, args[3]);
        auto length = static_cast<size_t>(args[4].asNumber());

#if defined(__APPLE__)
        CCHmacAlgorithm ccAlgo;
        size_t hashLen;
        if (hashAlgo == "SHA-256" || hashAlgo == "sha256" || hashAlgo == "sha-256") {
          ccAlgo = kCCHmacAlgSHA256; hashLen = CC_SHA256_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-1" || hashAlgo == "sha1" || hashAlgo == "sha-1") {
          ccAlgo = kCCHmacAlgSHA1; hashLen = CC_SHA1_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-384" || hashAlgo == "sha384" || hashAlgo == "sha-384") {
          ccAlgo = kCCHmacAlgSHA384; hashLen = CC_SHA384_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-512" || hashAlgo == "sha512" || hashAlgo == "sha-512") {
          ccAlgo = kCCHmacAlgSHA512; hashLen = CC_SHA512_DIGEST_LENGTH;
        } else {
          throw facebook::jsi::JSError(runtime, "__exactHkdf: unsupported hash algorithm: " + hashAlgo);
        }

        // If salt is empty, use a hash-length block of zeros
        std::vector<uint8_t> actualSalt;
        if (salt.empty()) {
          actualSalt.resize(hashLen, 0);
        } else {
          actualSalt = std::move(salt);
        }

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        std::vector<uint8_t> prk(hashLen);
        CCHmac(ccAlgo, actualSalt.data(), actualSalt.size(),
               ikm.data(), ikm.size(), prk.data());

        // HKDF-Expand
        size_t n = (length + hashLen - 1) / hashLen;
        std::vector<uint8_t> okm;
        okm.reserve(n * hashLen);
        std::vector<uint8_t> prev;

        for (size_t i = 1; i <= n; i++) {
          // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
          std::vector<uint8_t> input;
          input.insert(input.end(), prev.begin(), prev.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(i));

          prev.resize(hashLen);
          CCHmac(ccAlgo, prk.data(), prk.size(),
                 input.data(), input.size(), prev.data());
          okm.insert(okm.end(), prev.begin(), prev.end());
        }
        okm.resize(length);
        return makeUint8Array(runtime, std::move(okm));
#elif !defined(EXACT_NO_OPENSSL)
        // OpenSSL path
        const EVP_MD* md = openSslDigestForAlgorithm(hashAlgo);
        if (!md || normalizeDigestName(hashAlgo) == "md5") {
          throw facebook::jsi::JSError(runtime, "__exactHkdf: unsupported hash algorithm: " + hashAlgo);
        }

        size_t hashLen = static_cast<size_t>(EVP_MD_size(md));

        std::vector<uint8_t> actualSalt;
        if (salt.empty()) {
          actualSalt.resize(hashLen, 0);
        } else {
          actualSalt = std::move(salt);
        }

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        unsigned int prkLen = 0;
        std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
        HMAC(md, actualSalt.data(), actualSalt.size(),
             ikm.data(), ikm.size(), prk.data(), &prkLen);
        prk.resize(prkLen);

        // HKDF-Expand
        size_t n = (length + hashLen - 1) / hashLen;
        std::vector<uint8_t> okm;
        okm.reserve(n * hashLen);
        std::vector<uint8_t> prev;

        for (size_t i = 1; i <= n; i++) {
          std::vector<uint8_t> input;
          input.insert(input.end(), prev.begin(), prev.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(i));

          unsigned int tLen = 0;
          prev.resize(EVP_MAX_MD_SIZE);
          HMAC(md, prk.data(), prk.size(),
               input.data(), input.size(), prev.data(), &tLen);
          prev.resize(tLen);
          okm.insert(okm.end(), prev.begin(), prev.end());
        }
        okm.resize(length);
        return makeUint8Array(runtime, std::move(okm));
#else
        auto spec = portableDigestSpecForAlgorithm(hashAlgo);
        if (!spec || spec->kind == PortableDigestKind::Md5) {
          throw facebook::jsi::JSError(runtime, "__exactHkdf: unsupported hash algorithm: " + hashAlgo);
        }
        const size_t hashLen = spec->output_size;

        std::vector<uint8_t> actualSalt;
        if (salt.empty()) {
          actualSalt.resize(hashLen, 0);
        } else {
          actualSalt = std::move(salt);
        }

        auto prk = portableHmac(*spec, actualSalt, ikm);
        size_t n = (length + hashLen - 1) / hashLen;
        std::vector<uint8_t> okm;
        okm.reserve(n * hashLen);
        std::vector<uint8_t> prev;

        for (size_t i = 1; i <= n; i++) {
          std::vector<uint8_t> input;
          input.insert(input.end(), prev.begin(), prev.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(i));
          prev = portableHmac(*spec, prk, input);
          okm.insert(okm.end(), prev.begin(), prev.end());
        }
        okm.resize(length);
        return makeUint8Array(runtime, std::move(okm));
#endif
      });
  rt.global().setProperty(rt, "__exactHkdf", std::move(hkdfFn));

#if !defined(EXACT_NO_OPENSSL)
  // --- ECDH DeriveBits for NIST curves ---
  // __exactEcdhDeriveBits(curve, privateKeyBytes, publicKeyBytes) -> Uint8Array
  auto ecdhDeriveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdhDeriveBits"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: curve, privateKey, and publicKey required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto privKeyBytes = extractBytes(runtime, args[1]);
        auto pubKeyBytes = extractBytes(runtime, args[2]);

        // Map curve name to NID
        int nid = 0;
        if (curve == "P-256" || curve == "prime256v1") nid = NID_X9_62_prime256v1;
        else if (curve == "P-384" || curve == "secp384r1") nid = NID_secp384r1;
        else if (curve == "P-521" || curve == "secp521r1") nid = NID_secp521r1;
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: unsupported curve " + curve);
        }

        // Import private key - try PEM first, then raw DER
        EVP_PKEY* privKey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!privKey) {
          // Try DER
          const unsigned char* p = privKeyBytes.data();
          privKey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!privKey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to import EC private key");
        }

        // Import public key - try PEM first, then raw uncompressed point, then DER
        EVP_PKEY* pubKey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          // Try DER/SPKI
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey && pubKeyBytes.size() > 0 && pubKeyBytes[0] == 0x04) {
          // Try as raw uncompressed point using modern EVP_PKEY_fromdata API
          const char* groupName = nullptr;
          if (nid == NID_X9_62_prime256v1) groupName = "P-256";
          else if (nid == NID_secp384r1) groupName = "P-384";
          else if (nid == NID_secp521r1) groupName = "P-521";
          if (groupName) {
            OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
            if (bld) {
              OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, groupName, 0);
              OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                  pubKeyBytes.data(), pubKeyBytes.size());
              OSSL_PARAM* osslParams = OSSL_PARAM_BLD_to_param(bld);
              if (osslParams) {
                EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                if (pctx) {
                  EVP_PKEY_fromdata_init(pctx);
                  EVP_PKEY_fromdata(pctx, &pubKey, EVP_PKEY_PUBLIC_KEY, osslParams);
                  EVP_PKEY_CTX_free(pctx);
                }
                OSSL_PARAM_free(osslParams);
              }
              OSSL_PARAM_BLD_free(bld);
            }
          }
        }
        if (!pubKey) {
          // crypto.diffieHellman() accepts a private KeyObject in the
          // publicKey slot (Node semantics, ENG-23144); import the private
          // material and let EVP_PKEY_derive_set_peer use its public half.
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey) {
          EVP_PKEY_free(privKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to import EC public key");
        }

        // Derive shared secret
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to create derive context");
        }

        if (EVP_PKEY_derive_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: derive init failed");
        }

        if (EVP_PKEY_derive_set_peer(ctx, pubKey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to set peer key");
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to get secret length");
        }

        std::vector<uint8_t> secret(secretLen);
        if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: key derivation failed");
        }
        secret.resize(secretLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        return makeUint8Array(runtime, std::move(secret));
      });
  rt.global().setProperty(rt, "__exactEcdhDeriveBits", std::move(ecdhDeriveFn));

  // --- RSA-OAEP Encrypt ---
  // __exactRsaOaepEncrypt(publicKeyData, hashAlgorithm, label, plaintext) -> Uint8Array (ciphertext)
  auto rsaOaepEncryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRsaOaepEncrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: publicKeyData, hashAlgorithm, label, and plaintext required");
        }

        auto keyBytes = extractBytes(runtime, args[0]);
        auto hashAlgorithm = args[1].asString(runtime).utf8(runtime);
        auto labelBytes = extractBytes(runtime, args[2]);
        auto plaintext = extractBytes(runtime, args[3]);

        // Select hash algorithm for OAEP (Web Crypto style names: SHA-1, SHA-256, SHA-384, SHA-512)
        const EVP_MD* md = nullptr;
        if (hashAlgorithm == "SHA-1" || hashAlgorithm == "sha-1" || hashAlgorithm == "sha1") md = EVP_sha1();
        else if (hashAlgorithm == "SHA-256" || hashAlgorithm == "sha-256" || hashAlgorithm == "sha256") md = EVP_sha256();
        else if (hashAlgorithm == "SHA-384" || hashAlgorithm == "sha-384" || hashAlgorithm == "sha384") md = EVP_sha384();
        else if (hashAlgorithm == "SHA-512" || hashAlgorithm == "sha-512" || hashAlgorithm == "sha512") md = EVP_sha512();
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: unsupported hash algorithm " + hashAlgorithm);
        }

        // Import public key from PEM
        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to allocate key BIO");
        }
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: invalid PEM public key");
        }

        // Create encryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to create context");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: EVP_PKEY_encrypt_init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP padding: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set MGF1 hash to match OAEP hash (Web Crypto spec requires this)
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set MGF1 hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set OAEP label if provided
        if (!labelBytes.empty()) {
          // OpenSSL takes ownership of the label buffer, so we must allocate with OPENSSL_malloc
          unsigned char* labelCopy = static_cast<unsigned char*>(OPENSSL_malloc(labelBytes.size()));
          if (!labelCopy) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to allocate label");
          }
          memcpy(labelCopy, labelBytes.data(), labelBytes.size());
          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelCopy, static_cast<int>(labelBytes.size())) <= 0) {
            OPENSSL_free(labelCopy);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP label: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
          }
          // labelCopy ownership transferred to ctx - do NOT free
        }

        // Determine output size
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to get output size: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<uint8_t> ciphertext(outLen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: encryption failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        ciphertext.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(ciphertext));
      });
  rt.global().setProperty(rt, "__exactRsaOaepEncrypt", std::move(rsaOaepEncryptFn));

  // --- RSA-OAEP Decrypt ---
  // __exactRsaOaepDecrypt(privateKeyData, hashAlgorithm, label, ciphertext) -> Uint8Array (plaintext)
  auto rsaOaepDecryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRsaOaepDecrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: privateKeyData, hashAlgorithm, label, and ciphertext required");
        }

        auto keyBytes = extractBytes(runtime, args[0]);
        auto hashAlgorithm = args[1].asString(runtime).utf8(runtime);
        auto labelBytes = extractBytes(runtime, args[2]);
        auto ciphertext = extractBytes(runtime, args[3]);

        // Select hash algorithm for OAEP (Web Crypto style names: SHA-1, SHA-256, SHA-384, SHA-512)
        const EVP_MD* md = nullptr;
        if (hashAlgorithm == "SHA-1" || hashAlgorithm == "sha-1" || hashAlgorithm == "sha1") md = EVP_sha1();
        else if (hashAlgorithm == "SHA-256" || hashAlgorithm == "sha-256" || hashAlgorithm == "sha256") md = EVP_sha256();
        else if (hashAlgorithm == "SHA-384" || hashAlgorithm == "sha-384" || hashAlgorithm == "sha384") md = EVP_sha384();
        else if (hashAlgorithm == "SHA-512" || hashAlgorithm == "sha-512" || hashAlgorithm == "sha512") md = EVP_sha512();
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: unsupported hash algorithm " + hashAlgorithm);
        }

        // Import private key from PEM
        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to allocate key BIO");
        }
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: invalid PEM private key");
        }

        // Create decryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to create context");
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: EVP_PKEY_decrypt_init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP padding: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set MGF1 hash to match OAEP hash (Web Crypto spec requires this)
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set MGF1 hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set OAEP label if provided
        if (!labelBytes.empty()) {
          // OpenSSL takes ownership of the label buffer, so we must allocate with OPENSSL_malloc
          unsigned char* labelCopy = static_cast<unsigned char*>(OPENSSL_malloc(labelBytes.size()));
          if (!labelCopy) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to allocate label");
          }
          memcpy(labelCopy, labelBytes.data(), labelBytes.size());
          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelCopy, static_cast<int>(labelBytes.size())) <= 0) {
            OPENSSL_free(labelCopy);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP label: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
          }
          // labelCopy ownership transferred to ctx - do NOT free
        }

        // Determine output size
        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to get output size: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<uint8_t> plaintext(outLen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen, ciphertext.data(), ciphertext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: decryption failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        plaintext.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(plaintext));
      });
  rt.global().setProperty(rt, "__exactRsaOaepDecrypt", std::move(rsaOaepDecryptFn));
#endif // !EXACT_NO_OPENSSL

  // --- Zlib: sync compress/decompress ---
  // __exactDeflateSync(data, level, mode, dictionary?) -> Uint8Array
  // mode: 0 = deflate (zlib header, windowBits=15), 1 = gzip (windowBits=15+16), 2 = raw (windowBits=-15)
  // dictionary: optional Uint8Array/Buffer for preset dictionary
  auto deflateSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDeflateSync"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactDeflateSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        int level = Z_DEFAULT_COMPRESSION;
        if (count > 1 && args[1].isNumber()) {
          level = static_cast<int>(args[1].asNumber());
        }
        int mode = 0; // 0=deflate, 1=gzip, 2=raw
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        // Optional dictionary (4th argument)
        std::vector<uint8_t> dictionary;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          dictionary = extractBytes(runtime, args[3]);
        }

        // deflate
        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15; // raw deflate: no header, no checksum
        } else if (mode == 1) {
          windowBits = 15 + 16; // gzip header
        } else {
          windowBits = 15; // zlib header (default)
        }
        if (deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
          throw facebook::jsi::JSError(runtime, "deflateInit2 failed");
        }

        // Set dictionary if provided (not supported for gzip mode)
        if (!dictionary.empty() && mode != 1) {
          int dictRet = deflateSetDictionary(&strm, dictionary.data(),
                                              static_cast<uInt>(dictionary.size()));
          if (dictRet != Z_OK) {
            deflateEnd(&strm);
            throw facebook::jsi::JSError(runtime, "deflateSetDictionary failed");
          }
        }

        strm.next_in = input.data();
        strm.avail_in = static_cast<uInt>(input.size());

        std::vector<uint8_t> output;
        uint8_t outBuf[32768];
        do {
          strm.next_out = outBuf;
          strm.avail_out = sizeof(outBuf);
          deflate(&strm, Z_FINISH);
          size_t have = sizeof(outBuf) - strm.avail_out;
          output.insert(output.end(), outBuf, outBuf + have);
        } while (strm.avail_out == 0);
        deflateEnd(&strm);

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactDeflateSync", std::move(deflateSyncFn));

  // __exactInflateSync(data, mode, strict?, flags?, dictionary?, maxOutputLength?)
  //   -> Uint8Array or [Uint8Array, bytesConsumed]
  // mode: 0 = deflate (zlib header, windowBits=15), 1 = gzip (windowBits=15+32), 2 = raw (windowBits=-15)
  // flags: bitmask - bit0=lenientMode (ignore trailing data), bit1=returnConsumed (return [data, consumed])
  // dictionary: optional Uint8Array/Buffer for preset dictionary (5th argument)
  auto inflateSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactInflateSync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactInflateSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        bool strictMode = false;
        bool lenientMode = false;
        bool returnConsumed = false;
        int mode = 0; // 0=deflate, 1=gzip, 2=raw
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int>(args[1].asNumber());
        }
        if (count > 2 && args[2].isBool()) {
          strictMode = args[2].getBool();
        }
        // 4th arg: flags number (bit0=lenient, bit1=returnConsumed)
        if (count > 3 && args[3].isNumber()) {
          int flags = static_cast<int>(args[3].asNumber());
          lenientMode = (flags & 1) != 0;
          returnConsumed = (flags & 2) != 0;
        }

        // 5th arg: optional dictionary
        std::vector<uint8_t> dictionary;
        if (count > 4 && !args[4].isUndefined() && !args[4].isNull()) {
          dictionary = extractBytes(runtime, args[4]);
        }
        const size_t outputLimit = ibex_zlib_streams::readZlibOutputLimit(
            runtime, count > 5 ? &args[5] : nullptr);

        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15; // raw inflate: no header expected
        } else if (mode == 1) {
          windowBits = 15 + 32; // auto-detect gzip/deflate
        } else {
          windowBits = 15; // zlib header (default)
        }
        if (inflateInit2(&strm, windowBits) != Z_OK) {
          throw facebook::jsi::JSError(runtime, "inflateInit2 failed");
        }
        if (mode == 2 && !dictionary.empty() &&
            inflateSetDictionary(&strm, dictionary.data(),
                                 static_cast<uInt>(dictionary.size())) != Z_OK) {
          inflateEnd(&strm);
          throw facebook::jsi::JSError(runtime, "inflateSetDictionary failed");
        }

        strm.next_in = const_cast<Bytef*>(input.data());
        strm.avail_in = static_cast<uInt>(input.size());

        std::vector<uint8_t> output;
        uint8_t outBuf[32768];
        int ret = Z_OK;

        // For gzip mode, support multi-member streams by looping
        do {
          do {
            strm.next_out = outBuf;
            strm.avail_out = sizeof(outBuf);
            ret = inflate(&strm, Z_NO_FLUSH);
            size_t have = sizeof(outBuf) - strm.avail_out;
            if (!ibex_zlib_streams::zlibOutputFits(
                    output.size(), have, outputLimit)) {
              inflateEnd(&strm);
              ibex_zlib_streams::throwZlibOutputLimit(runtime, outputLimit);
            }
            output.insert(output.end(), outBuf, outBuf + have);
            if (ret == Z_NEED_DICT) {
              if (dictionary.empty()) {
                inflateEnd(&strm);
                throw facebook::jsi::JSError(runtime, "inflate failed: dictionary required");
              }
              int dictRet = inflateSetDictionary(&strm, dictionary.data(),
                                                  static_cast<uInt>(dictionary.size()));
              if (dictRet != Z_OK) {
                inflateEnd(&strm);
                throw facebook::jsi::JSError(runtime, "inflateSetDictionary failed");
              }
              strm.avail_out = 0;
              continue; // Retry inflate after setting dictionary
            }
            if (ret == Z_MEM_ERROR) {
              inflateEnd(&strm);
              throw facebook::jsi::JSError(runtime, "inflate failed: memory error");
            }
            if (ret == Z_DATA_ERROR) {
              std::string msg = "inflate failed: data error";
              if (strm.msg) { msg += ": "; msg += strm.msg; }
              if (!lenientMode) {
                inflateEnd(&strm);
                throw facebook::jsi::JSError(runtime, msg);
              }
              // In lenient mode, stop processing but don't throw
              ret = Z_STREAM_END;
              break;
            }
          } while (strm.avail_out == 0);

          // Multi-member gzip: after Z_STREAM_END, reset and continue if more data
          if (ret == Z_STREAM_END && strm.avail_in > 0 && mode == 1) {
            // Save remaining input pointer
            uInt remaining = strm.avail_in;
            const Bytef* nextIn = strm.next_in;

            // A gzip stream may continue with another member or end in zero
            // padding. Arbitrary non-zero trailing bytes are not ignorable:
            // accepting them turns gzip into a format-smuggling boundary.
            if (remaining < 2 || nextIn[0] != 0x1f || nextIn[1] != 0x8b) {
              if (ibex_zlib_streams::isZeroPadding(nextIn, remaining)) {
                strm.avail_in = 0;
                break;
              }
              inflateEnd(&strm);
              throw facebook::jsi::JSError(runtime, "inflate failed: trailing data");
            }

            // Reinitialize for next gzip member
            inflateEnd(&strm);
            strm = {};
            if (inflateInit2(&strm, windowBits) != Z_OK) {
              throw facebook::jsi::JSError(runtime, "inflateInit2 failed for next gzip member");
            }
            strm.next_in = const_cast<Bytef*>(nextIn);
            strm.avail_in = remaining;
            ret = Z_OK;
          } else {
            break;
          }
        } while (true);

        // Record bytes consumed before inflateEnd clears strm
        size_t bytesConsumed = input.size() - strm.avail_in;

        // Check for truncated input: all input consumed but stream didn't reach Z_STREAM_END
        if (ret != Z_STREAM_END && strm.avail_in == 0 && !lenientMode) {
          inflateEnd(&strm);
          throw facebook::jsi::JSError(runtime, "inflate failed: unexpected end of file");
        }

        inflateEnd(&strm);

        if (strictMode && bytesConsumed < input.size()) {
          throw facebook::jsi::JSError(runtime, "inflate failed: trailing data");
        }

        if (returnConsumed) {
          // Return [Uint8Array, bytesConsumed]
          auto arr = facebook::jsi::Array(runtime, 2);
          arr.setValueAtIndex(runtime, 0, makeUint8Array(runtime, std::move(output)));
          arr.setValueAtIndex(runtime, 1, facebook::jsi::Value(static_cast<double>(bytesConsumed)));
          return arr;
        }

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactInflateSync", std::move(inflateSyncFn));
  ibex_zlib_streams::installZlibStreamHostFunctions(handle);

#if !defined(EXACT_NO_BROTLI)
  // --- Brotli: sync compress/decompress ---
  // __exactBrotliCompressSync(data, quality) -> Uint8Array
  // quality: 0-11, default BROTLI_DEFAULT_QUALITY (11)
  auto brotliCompressSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactBrotliCompressSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactBrotliCompressSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        int quality = BROTLI_DEFAULT_QUALITY;
        if (count > 1 && args[1].isNumber()) {
          quality = static_cast<int>(args[1].asNumber());
          if (quality < BROTLI_MIN_QUALITY) quality = BROTLI_MIN_QUALITY;
          if (quality > BROTLI_MAX_QUALITY) quality = BROTLI_MAX_QUALITY;
        }

        size_t maxSize = BrotliEncoderMaxCompressedSize(input.size());
        if (maxSize == 0) {
          // BrotliEncoderMaxCompressedSize returns 0 for very large inputs;
          // use a generous estimate
          maxSize = input.size() + (input.size() >> 2) + 1024;
        }
        std::vector<uint8_t> output(maxSize);
        size_t encodedSize = maxSize;

        BROTLI_BOOL ok = BrotliEncoderCompress(
            quality,
            BROTLI_DEFAULT_WINDOW,
            BROTLI_DEFAULT_MODE,
            input.size(),
            input.data(),
            &encodedSize,
            output.data());

        if (!ok) {
          throw facebook::jsi::JSError(runtime, "BrotliEncoderCompress failed");
        }

        output.resize(encodedSize);
        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactBrotliCompressSync", std::move(brotliCompressSyncFn));

  // __exactBrotliDecompressSync(data, strict?, flags?, maxOutputLength?)
  //   -> Uint8Array or [Uint8Array, bytesConsumed]
  // flags: bitmask - bit1=returnConsumed (return [data, consumed])
  auto brotliDecompressSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactBrotliDecompressSync"),
      4,
      [](facebook::jsi::Runtime& runtime,
        const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactBrotliDecompressSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        bool strictMode = false;
        bool returnConsumed = false;
        if (count > 1 && args[1].isBool()) {
          strictMode = args[1].getBool();
        }
        // 3rd arg: flags number (bit1=returnConsumed)
        if (count > 2 && args[2].isNumber()) {
          int flags = static_cast<int>(args[2].asNumber());
          returnConsumed = (flags & 2) != 0;
        }
        const size_t outputLimit = ibex_zlib_streams::readZlibOutputLimit(
            runtime, count > 3 ? &args[3] : nullptr);

        // Use streaming decoder for unknown output size
        BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!state) {
          throw facebook::jsi::JSError(runtime, "BrotliDecoderCreateInstance failed");
        }

        std::vector<uint8_t> output;
        const uint8_t* nextIn = input.data();
        size_t availableIn = input.size();
        BrotliDecoderResult result;
        bool acceptedTrailingData = false;

        do {
          uint8_t outBuf[32768];
          uint8_t* nextOut = outBuf;
          size_t availableOut = sizeof(outBuf);

          result = BrotliDecoderDecompressStream(
              state,
              &availableIn,
              &nextIn,
              &availableOut,
              &nextOut,
              nullptr);

          size_t have = sizeof(outBuf) - availableOut;
          // Brotli output is attacker-controlled. Enforce the caller's
          // remaining maxOutputLength and the fixed per-host-call ceiling
          // before vector growth, just like deflate/gzip inflation.
          // @ref LLP 0004#the-zlib-builtin
          if (!ibex_zlib_streams::zlibOutputFits(
                  output.size(), have, outputLimit)) {
            BrotliDecoderDestroyInstance(state);
            ibex_zlib_streams::throwZlibOutputLimit(runtime, outputLimit);
          }
          output.insert(output.end(), outBuf, outBuf + have);

          if (result == BROTLI_DECODER_RESULT_ERROR) {
            auto errorCode = BrotliDecoderGetErrorCode(state);
            if (!strictMode &&
                (errorCode == BROTLI_DECODER_ERROR_FORMAT_PADDING_1 ||
                 errorCode == BROTLI_DECODER_ERROR_FORMAT_PADDING_2)) {
              acceptedTrailingData = true;
              break;
            }
            if (!strictMode && availableIn > 0 && BrotliDecoderIsFinished(state)) {
              acceptedTrailingData = true;
              break;
            }

            if (errorCode == BROTLI_DECODER_ERROR_FORMAT_PADDING_1 ||
                errorCode == BROTLI_DECODER_ERROR_FORMAT_PADDING_2) {
              if (strictMode) {
                BrotliDecoderDestroyInstance(state);
                throw facebook::jsi::JSError(
                    runtime, "Brotli decompression failed: trailing data");
              }
            }

            BrotliDecoderDestroyInstance(state);
            throw facebook::jsi::JSError(runtime, "BrotliDecoderDecompressStream failed: corrupt data");
          }

          // Stop after decompressing one complete brotli stream (trailing data = new stream or garbage)
          if (result == BROTLI_DECODER_RESULT_SUCCESS) {
            break;
          }
        } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

        // Record bytes consumed
        size_t bytesConsumed = input.size() - availableIn;

        if (strictMode && !acceptedTrailingData && availableIn > 0) {
          BrotliDecoderDestroyInstance(state);
          throw facebook::jsi::JSError(
              runtime, "Brotli decompression failed: trailing data");
        }

        BrotliDecoderDestroyInstance(state);

        if (!acceptedTrailingData && result != BROTLI_DECODER_RESULT_SUCCESS) {
          throw facebook::jsi::JSError(runtime, "Brotli decompression failed: incomplete data");
        }

        if (returnConsumed) {
          // Return [Uint8Array, bytesConsumed]
          auto arr = facebook::jsi::Array(runtime, 2);
          arr.setValueAtIndex(runtime, 0, makeUint8Array(runtime, std::move(output)));
          arr.setValueAtIndex(runtime, 1, facebook::jsi::Value(static_cast<double>(bytesConsumed)));
          return arr;
        }

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactBrotliDecompressSync", std::move(brotliDecompressSyncFn));
#endif // !EXACT_NO_BROTLI

  // --- Signal handling setup (ENG-23234) ---
  // __exactPollSignal() -> signal number or 0
  // Drains one pending delivery per call (callers loop until 0). Per-signal
  // counters preserve distinct signals that arrived between drains.
  auto pollSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPollSignal"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        for (int sig = 1; sig <= kMaxTrappedSignal; sig++) {
          if (g_pending_signal_counts[sig].load(std::memory_order_relaxed) > 0) {
            g_pending_signal_counts[sig].fetch_sub(1, std::memory_order_relaxed);
            return facebook::jsi::Value(sig);
          }
        }
        return facebook::jsi::Value(0);
      });
  rt.global().setProperty(rt, "__exactPollSignal", std::move(pollSignalFn));

  // __exactTrapSignal(signalNumber) -> void
  // Installs the sigaction and arms the watcher thread that wakes this
  // runtime's event loop when a trapped signal arrives.
  auto trapSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTrapSignal"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTrapSignal: signal number required");
        }
        int sig = static_cast<int>(args[0].asNumber());
        if (sig <= 0 || sig > kMaxTrappedSignal) {
          throw facebook::jsi::JSError(runtime, "__exactTrapSignal: signal number out of range");
        }
        ensureSignalWatcher();
        // Route dispatch to the runtime that trapped last; the CLI has one
        // runtime for the process lifetime.
        {
          std::lock_guard<std::mutex> lock(g_signal_runtime_mutex);
          g_signal_runtime = exactRuntimeCallbackTarget(handle);
        }
        struct sigaction sa = {};
        sa.sa_handler =
#ifdef SIGXFSZ
            sig == SIGXFSZ ? SIG_IGN :
#endif
                             signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(sig, &sa, nullptr);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTrapSignal", std::move(trapSignalFn));

  // __exactResetSignal(signalNumber) -> void (restore default handler)
  // Also discards that signal's pending deliveries: after the last JS
  // listener is removed a stale pending must not be re-raised later by the
  // dispatcher's default-behavior fallback.
  auto resetSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactResetSignal"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactResetSignal: signal number required");
        }
        int sig = static_cast<int>(args[0].asNumber());
        struct sigaction sa = {};
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sigaction(sig, &sa, nullptr);
        if (sig > 0 && sig <= kMaxTrappedSignal) {
          g_pending_signal_counts[sig].store(0, std::memory_order_relaxed);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactResetSignal", std::move(resetSignalFn));

  // __exactSignalNumbers() -> { SIGINT: n, ... }
  // The authoritative platform-correct signal-name table, taken from the
  // compiler's own constants — kernel-accurate by construction. JS layers
  // must consume this instead of growing hand-copied Linux/Darwin tables
  // (the stream-enhance map hardcoded Linux numbers, so trapping SIGUSR2
  // trapped SIGSYS on Darwin). SIGKILL/SIGSTOP are deliberately absent:
  // they are untrappable, so listeners for them must not arm a sigaction.
  auto signalNumbersFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSignalNumbers"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        auto obj = facebook::jsi::Object(runtime);
        auto set = [&](const char* name, int value) {
          obj.setProperty(runtime, name, facebook::jsi::Value(value));
        };
        set("SIGHUP", SIGHUP);
        set("SIGINT", SIGINT);
        set("SIGQUIT", SIGQUIT);
        set("SIGILL", SIGILL);
        set("SIGTRAP", SIGTRAP);
        set("SIGABRT", SIGABRT);
        set("SIGBUS", SIGBUS);
        set("SIGFPE", SIGFPE);
        set("SIGUSR1", SIGUSR1);
        set("SIGSEGV", SIGSEGV);
        set("SIGUSR2", SIGUSR2);
        set("SIGPIPE", SIGPIPE);
        set("SIGALRM", SIGALRM);
        set("SIGTERM", SIGTERM);
        set("SIGCHLD", SIGCHLD);
        set("SIGCONT", SIGCONT);
        set("SIGTSTP", SIGTSTP);
        set("SIGTTIN", SIGTTIN);
        set("SIGTTOU", SIGTTOU);
        set("SIGURG", SIGURG);
        set("SIGXCPU", SIGXCPU);
        set("SIGXFSZ", SIGXFSZ);
        set("SIGVTALRM", SIGVTALRM);
        set("SIGPROF", SIGPROF);
        set("SIGWINCH", SIGWINCH);
        set("SIGSYS", SIGSYS);
#ifdef SIGIO
        set("SIGIO", SIGIO);
#endif
#ifdef SIGINFO
        set("SIGINFO", SIGINFO);
#endif
#ifdef SIGPWR
        set("SIGPWR", SIGPWR);
#endif
        return obj;
      });
  rt.global().setProperty(rt, "__exactSignalNumbers", std::move(signalNumbersFn));

  // --- Stdin reading ---
  // __exactStdinRead(maxBytes) -> Uint8Array, "" for EOF, or null for no data.
  // Non-blocking read from fd 0. Keep stdin byte-exact; the JS stream layers
  // decide whether to expose Buffer chunks or stream-decode text.
  auto stdinReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStdinRead"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        size_t maxBytes = 4096;
        if (count > 0 && args[0].isNumber()) {
          maxBytes = static_cast<size_t>(args[0].asNumber());
          if (maxBytes == 0) maxBytes = 4096;
          if (maxBytes > 262144) maxBytes = 262144;
        }

        // @ref LLP 0025#1-modes-descriptors-and-topology — REPL/transcript
        // and stdin-program workers expose fd 0 as EOF before any native
        // fcntl/read route can observe the inherited process descriptor.
        int32_t stdinRoute = ex_host_session_descriptor_read_route(0);
        if (stdinRoute == 1) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        if (stdinRoute != 0) {
          throw facebook::jsi::JSError(
              runtime, "EACCES: permission denied, read '/dev/fd/0'");
        }

        // Set stdin to non-blocking
        int flags = fcntl(0, F_GETFL, 0);
        if (flags == -1) return facebook::jsi::Value::null();
        fcntl(0, F_SETFL, flags | O_NONBLOCK);

        std::vector<uint8_t> buf(maxBytes);
        ssize_t nread = ::read(0, buf.data(), maxBytes);

        // Restore blocking mode
        fcntl(0, F_SETFL, flags);

        if (nread < 0) {
          // EAGAIN/EWOULDBLOCK means no data available (not an error)
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return facebook::jsi::Value::null();
          }
          // Real error
          return facebook::jsi::Value::null();
        }
        if (nread == 0) {
          // EOF — return empty string to distinguish from "no data"
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }

        buf.resize(static_cast<size_t>(nread));
        return makeUint8Array(runtime, std::move(buf));
      });
  rt.global().setProperty(rt, "__exactStdinRead", std::move(stdinReadFn));

  auto bytesToUtf8StringFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactBytesToUtf8String"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactBytesToUtf8String: bytes required");
        }

        const uint8_t* ptr = nullptr;
        size_t length = 0;

        if (args[0].isString()) {
          return facebook::jsi::Value(args[0].getString(runtime));
        }

        if (!args[0].isObject()) {
          throw facebook::jsi::JSError(runtime, "__exactBytesToUtf8String: expected ArrayBuffer or TypedArray");
        }

        auto obj = args[0].asObject(runtime);
        if (!extractArrayBufferView(runtime, obj, ptr, length)) {
          throw facebook::jsi::JSError(
              runtime, "__exactBytesToUtf8String: expected ArrayBuffer-backed view");
        }

        return facebook::jsi::String::createFromUtf8(runtime, ptr, length);
      });
  rt.global().setProperty(rt, "__exactBytesToUtf8String", std::move(bytesToUtf8StringFn));

  // Deferred: Dns host functions (registered lazily on first use)
  auto ensureDnsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactEnsureDns"), 0,
      [handle](facebook::jsi::Runtime&, const facebook::jsi::Value&,
               const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
        if (!handle->dns_functions_loaded) {
          handle->dns_functions_loaded = true;
          installDnsHostFunctions(handle);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactEnsureDns", std::move(ensureDnsFn));


  // __exactGrantCapability(moduleId, capability) -> void
  auto grantCapabilityFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGrantCapability"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value::undefined();
        }
        auto module_id = static_cast<uint64_t>(args[0].asNumber());
        auto capability = args[1].toString(runtime).utf8(runtime);
        ex_host_grant_capability(module_id, capability.c_str());
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactGrantCapability", std::move(grantCapabilityFn));

  // Deferred: Fs host functions (registered lazily on first use)

}
