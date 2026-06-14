#include "hermes_runtime_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
// @ref LLP 0001#21-crypto-profile-the-axis-that-caused-the-original-break —
// Windows is a no-OpenSSL crypto profile backed by CNG/BCrypt.
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

bool ntSuccess(NTSTATUS status) {
  return status >= 0;
}

std::string normalizeAlgorithm(std::string algorithm) {
  algorithm.erase(std::remove(algorithm.begin(), algorithm.end(), '-'), algorithm.end());
  for (auto& ch : algorithm) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return algorithm;
}

const wchar_t* bcryptAlgorithmId(const std::string& algorithm) {
  auto normalized = normalizeAlgorithm(algorithm);
  if (normalized == "sha1") return BCRYPT_SHA1_ALGORITHM;
  if (normalized == "sha256") return BCRYPT_SHA256_ALGORITHM;
  if (normalized == "sha384") return BCRYPT_SHA384_ALGORITHM;
  if (normalized == "sha512") return BCRYPT_SHA512_ALGORITHM;
  if (normalized == "md5") return BCRYPT_MD5_ALGORITHM;
  return nullptr;
}

std::vector<uint8_t> computeDigest(
    facebook::jsi::Runtime& runtime,
    const std::string& algorithm,
    const std::vector<uint8_t>& data,
    const std::optional<std::vector<uint8_t>>& hmac_key = std::nullopt) {
  const wchar_t* algorithm_id = bcryptAlgorithmId(algorithm);
  if (!algorithm_id) {
    throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algorithm);
  }

  BCRYPT_ALG_HANDLE algorithm_handle = nullptr;
  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  DWORD object_length = 0;
  DWORD hash_length = 0;
  DWORD result_length = 0;
  ULONG flags = hmac_key.has_value() ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;

  if (!ntSuccess(BCryptOpenAlgorithmProvider(&algorithm_handle, algorithm_id, nullptr, flags))) {
    throw facebook::jsi::JSError(runtime, "BCryptOpenAlgorithmProvider failed");
  }

  auto close_algorithm = [&]() {
    if (hash_handle) {
      BCryptDestroyHash(hash_handle);
      hash_handle = nullptr;
    }
    if (algorithm_handle) {
      BCryptCloseAlgorithmProvider(algorithm_handle, 0);
      algorithm_handle = nullptr;
    }
  };

  if (!ntSuccess(BCryptGetProperty(
          algorithm_handle,
          BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&object_length),
          sizeof(object_length),
          &result_length,
          0)) ||
      !ntSuccess(BCryptGetProperty(
          algorithm_handle,
          BCRYPT_HASH_LENGTH,
          reinterpret_cast<PUCHAR>(&hash_length),
          sizeof(hash_length),
          &result_length,
          0))) {
    close_algorithm();
    throw facebook::jsi::JSError(runtime, "BCryptGetProperty failed");
  }

  std::vector<uint8_t> object(object_length);
  PUCHAR key_ptr = nullptr;
  ULONG key_len = 0;
  if (hmac_key.has_value() && !hmac_key->empty()) {
    key_ptr = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(hmac_key->data()));
    key_len = static_cast<ULONG>(hmac_key->size());
  }
  if (!ntSuccess(BCryptCreateHash(
          algorithm_handle,
          &hash_handle,
          object.data(),
          static_cast<ULONG>(object.size()),
          key_ptr,
          key_len,
          0))) {
    close_algorithm();
    throw facebook::jsi::JSError(runtime, "BCryptCreateHash failed");
  }

  if (!data.empty() &&
      !ntSuccess(BCryptHashData(
          hash_handle,
          const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())),
          static_cast<ULONG>(data.size()),
          0))) {
    close_algorithm();
    throw facebook::jsi::JSError(runtime, "BCryptHashData failed");
  }

  std::vector<uint8_t> digest(hash_length);
  if (!ntSuccess(BCryptFinishHash(hash_handle, digest.data(), static_cast<ULONG>(digest.size()), 0))) {
    close_algorithm();
    throw facebook::jsi::JSError(runtime, "BCryptFinishHash failed");
  }

  close_algorithm();
  return digest;
}

std::string hexEncode(const std::vector<uint8_t>& bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) {
    out << std::setw(2) << static_cast<int>(byte);
  }
  return out.str();
}

} // namespace

void installCryptoHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

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
        auto algorithm = args[0].asString(runtime).utf8(runtime);
        auto data = extractBytes(runtime, args[1]);
        auto digest = computeDigest(runtime, algorithm, data);
        return facebook::jsi::String::createFromUtf8(runtime, hexEncode(digest));
      });
  rt.global().setProperty(rt, "__exactHashSync", std::move(hashSyncFn));

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
        auto algorithm = args[0].asString(runtime).utf8(runtime);
        auto data = extractBytes(runtime, args[1]);
        return makeUint8Array(runtime, computeDigest(runtime, algorithm, data));
      });
  rt.global().setProperty(rt, "__exactHashRaw", std::move(hashRawFn));

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
        auto algorithm = args[0].asString(runtime).utf8(runtime);
        auto key = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        auto digest = computeDigest(runtime, algorithm, data, key);
        return facebook::jsi::String::createFromUtf8(runtime, hexEncode(digest));
      });
  rt.global().setProperty(rt, "__exactHmacSync", std::move(hmacSyncFn));

  auto stdinReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStdinRead"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::null();
      });
  rt.global().setProperty(rt, "__exactStdinRead", std::move(stdinReadFn));

  auto noopSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactResetSignal"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactResetSignal", std::move(noopSignalFn));
}
