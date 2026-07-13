#include "hermes_runtime_internal.h"
#include "hermes_runtime_zlib_streams.h"

void unregisterSignalRuntime(ExactHermesRuntime*) {}

#ifndef NOMINMAX
#define NOMINMAX
#endif
// @ref LLP 0001#21-crypto-profile-the-axis-that-caused-the-original-break —
// Windows is a no-OpenSSL crypto profile backed by CNG/BCrypt.
#include <windows.h>
#include <bcrypt.h>
#include <zlib.h>

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

void installZlibHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  // @ref LLP 0001#current-buildrs-support-honest-status — zlib is required on
  // Windows too; this file is Windows' native host-registration root.
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
        int mode = 0;
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        std::vector<uint8_t> dictionary;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          dictionary = extractBytes(runtime, args[3]);
        }

        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15;
        } else if (mode == 1) {
          windowBits = 15 + 16;
        } else {
          windowBits = 15;
        }
        if (deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
          throw facebook::jsi::JSError(runtime, "deflateInit2 failed");
        }

        if (!dictionary.empty() && mode != 1) {
          int dictRet = deflateSetDictionary(
              &strm,
              dictionary.data(),
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
        int mode = 0;
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int>(args[1].asNumber());
        }
        if (count > 2 && args[2].isBool()) {
          strictMode = args[2].getBool();
        }
        if (count > 3 && args[3].isNumber()) {
          int flags = static_cast<int>(args[3].asNumber());
          lenientMode = (flags & 1) != 0;
          returnConsumed = (flags & 2) != 0;
        }

        std::vector<uint8_t> dictionary;
        if (count > 4 && !args[4].isUndefined() && !args[4].isNull()) {
          dictionary = extractBytes(runtime, args[4]);
        }
        const size_t outputLimit = ibex_zlib_streams::readZlibOutputLimit(
            runtime, count > 5 ? &args[5] : nullptr);

        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15;
        } else if (mode == 1) {
          windowBits = 15 + 32;
        } else {
          windowBits = 15;
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
              int dictRet = inflateSetDictionary(
                  &strm,
                  dictionary.data(),
                  static_cast<uInt>(dictionary.size()));
              if (dictRet != Z_OK) {
                inflateEnd(&strm);
                throw facebook::jsi::JSError(runtime, "inflateSetDictionary failed");
              }
              strm.avail_out = 0;
              continue;
            }
            if (ret == Z_MEM_ERROR) {
              inflateEnd(&strm);
              throw facebook::jsi::JSError(runtime, "inflate failed: memory error");
            }
            if (ret == Z_DATA_ERROR) {
              std::string msg = "inflate failed: data error";
              if (strm.msg) {
                msg += ": ";
                msg += strm.msg;
              }
              if (!lenientMode) {
                inflateEnd(&strm);
                throw facebook::jsi::JSError(runtime, msg);
              }
              ret = Z_STREAM_END;
              break;
            }
          } while (strm.avail_out == 0);

          if (ret == Z_STREAM_END && strm.avail_in > 0 && mode == 1) {
            uInt remaining = strm.avail_in;
            const Bytef* nextIn = strm.next_in;

            if (remaining < 2 || nextIn[0] != 0x1f || nextIn[1] != 0x8b) {
              if (ibex_zlib_streams::isZeroPadding(nextIn, remaining)) {
                strm.avail_in = 0;
                break;
              }
              inflateEnd(&strm);
              throw facebook::jsi::JSError(runtime, "inflate failed: trailing data");
            }

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

        size_t bytesConsumed = input.size() - strm.avail_in;

        if (ret != Z_STREAM_END && strm.avail_in == 0 && !lenientMode) {
          inflateEnd(&strm);
          throw facebook::jsi::JSError(runtime, "inflate failed: unexpected end of file");
        }

        inflateEnd(&strm);

        if (strictMode && bytesConsumed < input.size()) {
          throw facebook::jsi::JSError(runtime, "inflate failed: trailing data");
        }

        if (returnConsumed) {
          auto arr = facebook::jsi::Array(runtime, 2);
          arr.setValueAtIndex(runtime, 0, makeUint8Array(runtime, std::move(output)));
          arr.setValueAtIndex(runtime, 1, facebook::jsi::Value(static_cast<double>(bytesConsumed)));
          return arr;
        }

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactInflateSync", std::move(inflateSyncFn));
  ibex_zlib_streams::installZlibStreamHostFunctions(handle);
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

  installZlibHostFunctions(handle);

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
