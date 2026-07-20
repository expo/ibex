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
#include <wincrypt.h>
#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
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

std::optional<size_t> hkdfDigestLength(const std::string& algorithm) {
  auto normalized = normalizeAlgorithm(algorithm);
  if (normalized == "sha1") return 20;
  if (normalized == "sha256") return 32;
  if (normalized == "sha384") return 48;
  if (normalized == "sha512") return 64;
  return std::nullopt;
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

std::vector<uint8_t> derivePbkdf2(
    facebook::jsi::Runtime& runtime,
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    ULONGLONG iterations,
    size_t length,
    const std::string& algorithm) {
  const wchar_t* algorithm_id = bcryptAlgorithmId(algorithm);
  if (!algorithm_id) {
    throw facebook::jsi::JSError(
        runtime,
        "__exactPbkdf2: unsupported hash algorithm: " + algorithm);
  }
  if (password.size() > std::numeric_limits<ULONG>::max() ||
      salt.size() > std::numeric_limits<ULONG>::max() ||
      length > std::numeric_limits<ULONG>::max()) {
    throw facebook::jsi::JSError(runtime, "__exactPbkdf2: input or output is too large");
  }
  if (length == 0) return {};

  BCRYPT_ALG_HANDLE algorithm_handle = nullptr;
  if (!ntSuccess(BCryptOpenAlgorithmProvider(
          &algorithm_handle,
          algorithm_id,
          nullptr,
          BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
    throw facebook::jsi::JSError(runtime, "BCryptOpenAlgorithmProvider failed for PBKDF2");
  }

  std::vector<uint8_t> derived_key(length);
  UCHAR empty_input = 0;
  NTSTATUS status = BCryptDeriveKeyPBKDF2(
      algorithm_handle,
      password.empty() ? &empty_input : const_cast<PUCHAR>(password.data()),
      static_cast<ULONG>(password.size()),
      salt.empty() ? &empty_input : const_cast<PUCHAR>(salt.data()),
      static_cast<ULONG>(salt.size()),
      iterations,
      derived_key.data(),
      static_cast<ULONG>(derived_key.size()),
      0);
  BCryptCloseAlgorithmProvider(algorithm_handle, 0);
  if (!ntSuccess(status)) {
    throw facebook::jsi::JSError(runtime, "BCryptDeriveKeyPBKDF2 failed");
  }
  return derived_key;
}

uint32_t rotateLeft32(uint32_t value, uint32_t bits) {
  return (value << bits) | (value >> (32 - bits));
}

void salsa20_8(uint32_t block[16]) {
  uint32_t x[16];
  std::memcpy(x, block, sizeof(x));
  for (int round = 0; round < 8; round += 2) {
    x[4] ^= rotateLeft32(x[0] + x[12], 7);
    x[8] ^= rotateLeft32(x[4] + x[0], 9);
    x[12] ^= rotateLeft32(x[8] + x[4], 13);
    x[0] ^= rotateLeft32(x[12] + x[8], 18);
    x[9] ^= rotateLeft32(x[5] + x[1], 7);
    x[13] ^= rotateLeft32(x[9] + x[5], 9);
    x[1] ^= rotateLeft32(x[13] + x[9], 13);
    x[5] ^= rotateLeft32(x[1] + x[13], 18);
    x[14] ^= rotateLeft32(x[10] + x[6], 7);
    x[2] ^= rotateLeft32(x[14] + x[10], 9);
    x[6] ^= rotateLeft32(x[2] + x[14], 13);
    x[10] ^= rotateLeft32(x[6] + x[2], 18);
    x[3] ^= rotateLeft32(x[15] + x[11], 7);
    x[7] ^= rotateLeft32(x[3] + x[15], 9);
    x[11] ^= rotateLeft32(x[7] + x[3], 13);
    x[15] ^= rotateLeft32(x[11] + x[7], 18);
    x[1] ^= rotateLeft32(x[0] + x[3], 7);
    x[2] ^= rotateLeft32(x[1] + x[0], 9);
    x[3] ^= rotateLeft32(x[2] + x[1], 13);
    x[0] ^= rotateLeft32(x[3] + x[2], 18);
    x[6] ^= rotateLeft32(x[5] + x[4], 7);
    x[7] ^= rotateLeft32(x[6] + x[5], 9);
    x[4] ^= rotateLeft32(x[7] + x[6], 13);
    x[5] ^= rotateLeft32(x[4] + x[7], 18);
    x[11] ^= rotateLeft32(x[10] + x[9], 7);
    x[8] ^= rotateLeft32(x[11] + x[10], 9);
    x[9] ^= rotateLeft32(x[8] + x[11], 13);
    x[10] ^= rotateLeft32(x[9] + x[8], 18);
    x[12] ^= rotateLeft32(x[15] + x[14], 7);
    x[13] ^= rotateLeft32(x[12] + x[15], 9);
    x[14] ^= rotateLeft32(x[13] + x[12], 13);
    x[15] ^= rotateLeft32(x[14] + x[13], 18);
  }
  for (size_t index = 0; index < 16; ++index) block[index] += x[index];
}

void scryptBlockMix(uint32_t* block, uint32_t* scratch, uint32_t r) {
  const uint32_t block_count = 2 * r;
  uint32_t x[16];
  std::memcpy(x, &block[(block_count - 1) * 16], sizeof(x));
  for (uint32_t index = 0; index < block_count; ++index) {
    for (size_t word = 0; word < 16; ++word) x[word] ^= block[index * 16 + word];
    salsa20_8(x);
    std::memcpy(&scratch[index * 16], x, sizeof(x));
  }

  std::vector<uint32_t> reordered(static_cast<size_t>(block_count) * 16);
  uint32_t destination = 0;
  for (uint32_t index = 0; index < block_count; index += 2, ++destination) {
    std::memcpy(&reordered[destination * 16], &scratch[index * 16], sizeof(x));
  }
  for (uint32_t index = 1; index < block_count; index += 2, ++destination) {
    std::memcpy(&reordered[destination * 16], &scratch[index * 16], sizeof(x));
  }
  std::memcpy(scratch, reordered.data(), reordered.size() * sizeof(uint32_t));
}

void scryptRoMix(uint32_t* block, uint64_t n, uint32_t r) {
  const size_t block_words = 2 * static_cast<size_t>(r) * 16;
  const size_t block_bytes = block_words * sizeof(uint32_t);
  std::vector<uint32_t> history(static_cast<size_t>(n) * block_words);
  std::vector<uint32_t> scratch(block_words);

  for (uint64_t iteration = 0; iteration < n; ++iteration) {
    std::memcpy(&history[static_cast<size_t>(iteration) * block_words], block, block_bytes);
    scryptBlockMix(block, scratch.data(), r);
    std::memcpy(block, scratch.data(), block_bytes);
  }
  for (uint64_t iteration = 0; iteration < n; ++iteration) {
    const size_t last_block_start = (2 * static_cast<size_t>(r) - 1) * 16;
    const uint64_t selected = block[last_block_start] % n;
    for (size_t word = 0; word < block_words; ++word) {
      block[word] ^= history[static_cast<size_t>(selected) * block_words + word];
    }
    scryptBlockMix(block, scratch.data(), r);
    std::memcpy(block, scratch.data(), block_bytes);
  }
}

std::vector<uint8_t> aesCbcCrypt(
    facebook::jsi::Runtime& runtime,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& data,
    bool encrypt) {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw facebook::jsi::JSError(runtime, "AES key must be 128, 192, or 256 bits");
  }
  if (iv.size() != 16) {
    throw facebook::jsi::JSError(runtime, "AES-CBC IV must be 16 bytes");
  }
  const auto max_input_size = static_cast<size_t>(std::numeric_limits<ULONG>::max());
  if (data.size() > max_input_size || (encrypt && data.size() > max_input_size - 16)) {
    throw facebook::jsi::JSError(runtime, "AES-CBC input is too large");
  }

  BCRYPT_ALG_HANDLE algorithm_handle = nullptr;
  BCRYPT_KEY_HANDLE key_handle = nullptr;
  auto close_handles = [&]() {
    if (key_handle) {
      BCryptDestroyKey(key_handle);
      key_handle = nullptr;
    }
    if (algorithm_handle) {
      BCryptCloseAlgorithmProvider(algorithm_handle, 0);
      algorithm_handle = nullptr;
    }
  };

  if (!ntSuccess(BCryptOpenAlgorithmProvider(
          &algorithm_handle,
          BCRYPT_AES_ALGORITHM,
          nullptr,
          0))) {
    throw facebook::jsi::JSError(runtime, "BCryptOpenAlgorithmProvider failed for AES-CBC");
  }
  if (!ntSuccess(BCryptSetProperty(
          algorithm_handle,
          BCRYPT_CHAINING_MODE,
          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
          sizeof(BCRYPT_CHAIN_MODE_CBC),
          0))) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "BCryptSetProperty failed for AES-CBC");
  }

  DWORD object_length = 0;
  DWORD result_length = 0;
  if (!ntSuccess(BCryptGetProperty(
          algorithm_handle,
          BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&object_length),
          sizeof(object_length),
          &result_length,
          0))) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "BCryptGetProperty failed for AES-CBC");
  }

  std::vector<uint8_t> key_object(object_length);
  if (!ntSuccess(BCryptGenerateSymmetricKey(
          algorithm_handle,
          &key_handle,
          key_object.data(),
          static_cast<ULONG>(key_object.size()),
          const_cast<PUCHAR>(key.data()),
          static_cast<ULONG>(key.size()),
          0))) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "BCryptGenerateSymmetricKey failed for AES-CBC");
  }

  UCHAR empty_input = 0;
  auto* input = data.empty() ? &empty_input : const_cast<PUCHAR>(data.data());
  std::vector<uint8_t> mutable_iv(iv);
  ULONG output_length = 0;
  NTSTATUS status = encrypt
      ? BCryptEncrypt(
            key_handle,
            input,
            static_cast<ULONG>(data.size()),
            nullptr,
            mutable_iv.data(),
            static_cast<ULONG>(mutable_iv.size()),
            nullptr,
            0,
            &output_length,
            BCRYPT_BLOCK_PADDING)
      : BCryptDecrypt(
            key_handle,
            input,
            static_cast<ULONG>(data.size()),
            nullptr,
            mutable_iv.data(),
            static_cast<ULONG>(mutable_iv.size()),
            nullptr,
            0,
            &output_length,
            BCRYPT_BLOCK_PADDING);
  if (!ntSuccess(status)) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "AES-CBC output sizing failed");
  }

  std::vector<uint8_t> output(output_length);
  mutable_iv = iv;
  status = encrypt
      ? BCryptEncrypt(
            key_handle,
            input,
            static_cast<ULONG>(data.size()),
            nullptr,
            mutable_iv.data(),
            static_cast<ULONG>(mutable_iv.size()),
            output.data(),
            static_cast<ULONG>(output.size()),
            &output_length,
            BCRYPT_BLOCK_PADDING)
      : BCryptDecrypt(
            key_handle,
            input,
            static_cast<ULONG>(data.size()),
            nullptr,
            mutable_iv.data(),
            static_cast<ULONG>(mutable_iv.size()),
            output.data(),
            static_cast<ULONG>(output.size()),
            &output_length,
            BCRYPT_BLOCK_PADDING);
  close_handles();
  if (!ntSuccess(status)) {
    throw facebook::jsi::JSError(
        runtime,
        encrypt ? "AES-CBC encryption failed" : "AES-CBC decryption failed");
  }
  output.resize(output_length);
  return output;
}

void appendDerLength(std::vector<uint8_t>& output, size_t length) {
  if (length < 128) {
    output.push_back(static_cast<uint8_t>(length));
    return;
  }

  uint8_t encoded[sizeof(size_t)];
  size_t count = 0;
  while (length > 0) {
    encoded[count++] = static_cast<uint8_t>(length & 0xff);
    length >>= 8;
  }
  output.push_back(static_cast<uint8_t>(0x80 | count));
  while (count > 0) output.push_back(encoded[--count]);
}

std::vector<uint8_t> derWrap(uint8_t tag, const std::vector<uint8_t>& contents) {
  std::vector<uint8_t> encoded;
  encoded.reserve(1 + sizeof(size_t) + contents.size());
  encoded.push_back(tag);
  appendDerLength(encoded, contents.size());
  encoded.insert(encoded.end(), contents.begin(), contents.end());
  return encoded;
}

void appendBytes(std::vector<uint8_t>& output, const std::vector<uint8_t>& bytes) {
  output.insert(output.end(), bytes.begin(), bytes.end());
}

std::string pemEncode(
    facebook::jsi::Runtime& runtime,
    const char* label,
    const std::vector<uint8_t>& der) {
  if (der.empty() || der.size() > std::numeric_limits<DWORD>::max()) {
    throw facebook::jsi::JSError(runtime, "invalid DER key material");
  }

  DWORD encoded_length = 0;
  const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
  if (!CryptBinaryToStringA(
          der.data(),
          static_cast<DWORD>(der.size()),
          flags,
          nullptr,
          &encoded_length) ||
      encoded_length == 0) {
    throw facebook::jsi::JSError(runtime, "CryptBinaryToStringA failed for generated key");
  }

  std::string base64(encoded_length, '\0');
  if (!CryptBinaryToStringA(
          der.data(),
          static_cast<DWORD>(der.size()),
          flags,
          base64.data(),
          &encoded_length)) {
    throw facebook::jsi::JSError(runtime, "CryptBinaryToStringA failed for generated key");
  }
  base64.resize(encoded_length);
  if (!base64.empty() && base64.back() == '\0') base64.pop_back();

  std::string pem = "-----BEGIN ";
  pem += label;
  pem += "-----\n";
  for (size_t offset = 0; offset < base64.size(); offset += 64) {
    pem.append(base64, offset, std::min<size_t>(64, base64.size() - offset));
    pem.push_back('\n');
  }
  pem += "-----END ";
  pem += label;
  pem += "-----\n";
  return pem;
}

struct EcCurveConfig {
  const wchar_t* algorithm;
  ULONG bits;
  ULONG private_magic;
  std::vector<uint8_t> oid;
};

std::optional<EcCurveConfig> ecCurveConfig(std::string name) {
  auto normalized = normalizeAlgorithm(std::move(name));
  if (normalized == "p256" || normalized == "prime256v1" || normalized == "secp256r1") {
    return EcCurveConfig{
        BCRYPT_ECDSA_P256_ALGORITHM,
        256,
        BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
        {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}};
  }
  if (normalized == "p384" || normalized == "secp384r1") {
    return EcCurveConfig{
        BCRYPT_ECDSA_P384_ALGORITHM,
        384,
        BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
        {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}};
  }
  if (normalized == "p521" || normalized == "secp521r1") {
    return EcCurveConfig{
        BCRYPT_ECDSA_P521_ALGORITHM,
        521,
        BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
        {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}};
  }
  return std::nullopt;
}

std::pair<std::string, std::string> generateEcKeyPairPem(
    facebook::jsi::Runtime& runtime,
    const EcCurveConfig& curve) {
  BCRYPT_ALG_HANDLE algorithm_handle = nullptr;
  BCRYPT_KEY_HANDLE key_handle = nullptr;
  auto close_handles = [&]() {
    if (key_handle) {
      BCryptDestroyKey(key_handle);
      key_handle = nullptr;
    }
    if (algorithm_handle) {
      BCryptCloseAlgorithmProvider(algorithm_handle, 0);
      algorithm_handle = nullptr;
    }
  };

  if (!ntSuccess(BCryptOpenAlgorithmProvider(
          &algorithm_handle,
          curve.algorithm,
          nullptr,
          0)) ||
      !ntSuccess(BCryptGenerateKeyPair(
          algorithm_handle,
          &key_handle,
          curve.bits,
          0)) ||
      !ntSuccess(BCryptFinalizeKeyPair(key_handle, 0))) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "CNG EC key generation failed");
  }

  ULONG blob_length = 0;
  if (!ntSuccess(BCryptExportKey(
          key_handle,
          nullptr,
          BCRYPT_ECCPRIVATE_BLOB,
          nullptr,
          0,
          &blob_length,
          0)) ||
      blob_length < sizeof(BCRYPT_ECCKEY_BLOB)) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "CNG EC private-key sizing failed");
  }

  std::vector<uint8_t> blob(blob_length);
  if (!ntSuccess(BCryptExportKey(
          key_handle,
          nullptr,
          BCRYPT_ECCPRIVATE_BLOB,
          blob.data(),
          static_cast<ULONG>(blob.size()),
          &blob_length,
          0))) {
    close_handles();
    throw facebook::jsi::JSError(runtime, "CNG EC private-key export failed");
  }
  close_handles();
  blob.resize(blob_length);

  BCRYPT_ECCKEY_BLOB header{};
  std::memcpy(&header, blob.data(), sizeof(header));
  const size_t coordinate_length = header.cbKey;
  const size_t expected_length = sizeof(header) + coordinate_length * 3;
  if (header.dwMagic != curve.private_magic || coordinate_length == 0 ||
      expected_length != blob.size()) {
    throw facebook::jsi::JSError(runtime, "CNG EC private-key blob is malformed");
  }

  const auto coordinate = [&](size_t index) {
    const auto begin = blob.begin() +
        static_cast<std::vector<uint8_t>::difference_type>(sizeof(header) + index * coordinate_length);
    return std::vector<uint8_t>(begin, begin + coordinate_length);
  };
  const auto x = coordinate(0);
  const auto y = coordinate(1);
  const auto private_scalar = coordinate(2);

  // id-ecPublicKey (1.2.840.10045.2.1) plus the named-curve OID.
  std::vector<uint8_t> algorithm_identifier_contents = {
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
  appendBytes(algorithm_identifier_contents, curve.oid);
  const auto algorithm_identifier = derWrap(0x30, algorithm_identifier_contents);

  std::vector<uint8_t> public_point = {0x00, 0x04};
  appendBytes(public_point, x);
  appendBytes(public_point, y);
  const auto public_bit_string = derWrap(0x03, public_point);

  std::vector<uint8_t> spki_contents;
  appendBytes(spki_contents, algorithm_identifier);
  appendBytes(spki_contents, public_bit_string);
  const auto spki = derWrap(0x30, spki_contents);

  // RFC 5915 ECPrivateKey embedded in RFC 5208 PrivateKeyInfo. The public
  // point is included so consumers never have to reconstruct it from d.
  std::vector<uint8_t> ec_private_contents = {0x02, 0x01, 0x01};
  appendBytes(ec_private_contents, derWrap(0x04, private_scalar));
  appendBytes(ec_private_contents, derWrap(0xa1, public_bit_string));
  const auto ec_private_key = derWrap(0x30, ec_private_contents);

  std::vector<uint8_t> pkcs8_contents = {0x02, 0x01, 0x00};
  appendBytes(pkcs8_contents, algorithm_identifier);
  appendBytes(pkcs8_contents, derWrap(0x04, ec_private_key));
  const auto pkcs8 = derWrap(0x30, pkcs8_contents);

  return {
      pemEncode(runtime, "PRIVATE KEY", pkcs8),
      pemEncode(runtime, "PUBLIC KEY", spki)};
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

  // @ref LLP 0008#crypto — the no-OpenSSL Windows profile uses CNG for the
  // native primitives exposed through the canonical JavaScript crypto API.
  auto pbkdf2Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPbkdf2"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5 || !args[2].isNumber() || !args[3].isNumber() ||
            !args[4].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactPbkdf2: password, salt, iterations, length, and hash required");
        }

        double requested_iterations = args[2].asNumber();
        double requested_length = args[3].asNumber();
        if (!std::isfinite(requested_iterations) || requested_iterations < 1 ||
            std::floor(requested_iterations) != requested_iterations) {
          throw facebook::jsi::JSError(runtime, "__exactPbkdf2: invalid iteration count");
        }
        if (!std::isfinite(requested_length) || requested_length < 0 ||
            std::floor(requested_length) != requested_length ||
            requested_length > static_cast<double>(std::numeric_limits<ULONG>::max())) {
          throw facebook::jsi::JSError(runtime, "__exactPbkdf2: invalid output length");
        }

        auto algorithm = args[4].asString(runtime).utf8(runtime);
        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        auto length = static_cast<size_t>(requested_length);
        return makeUint8Array(
            runtime,
            derivePbkdf2(
                runtime,
                password,
                salt,
                static_cast<ULONGLONG>(requested_iterations),
                length,
                algorithm));
      });
  rt.global().setProperty(rt, "__exactPbkdf2", std::move(pbkdf2Fn));

  // @ref LLP 0008#crypto — CNG supplies scrypt's PBKDF2-HMAC-SHA256
  // stages while this portable Salsa20/8 ROMix preserves RFC 7914 behavior.
  auto scryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactScryptSync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 6 || !args[2].isNumber() || !args[3].isNumber() ||
            !args[4].isNumber() || !args[5].isNumber()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactScryptSync: password, salt, N, r, p, and length required");
        }

        const double requested_n = args[2].asNumber();
        const double requested_r = args[3].asNumber();
        const double requested_p = args[4].asNumber();
        const double requested_length = args[5].asNumber();
        constexpr uint64_t kMaxScryptMemory = 1073741824ULL;
        for (double value : {requested_n, requested_r, requested_p, requested_length}) {
          if (!std::isfinite(value) || value < 0 || std::floor(value) != value) {
            throw facebook::jsi::JSError(runtime, "__exactScryptSync: invalid numeric argument");
          }
        }
        if (requested_n > static_cast<double>(kMaxScryptMemory) ||
            requested_r > static_cast<double>(std::numeric_limits<uint32_t>::max()) ||
            requested_p > static_cast<double>(std::numeric_limits<uint32_t>::max()) ||
            requested_length > static_cast<double>(std::numeric_limits<ULONG>::max())) {
          throw facebook::jsi::JSError(runtime, "__exactScryptSync: numeric argument is too large");
        }

        const uint64_t n = static_cast<uint64_t>(requested_n);
        const uint32_t r = static_cast<uint32_t>(requested_r);
        const uint32_t p = static_cast<uint32_t>(requested_p);
        const size_t length = static_cast<size_t>(requested_length);
        if (n <= 1 || (n & (n - 1)) != 0 || r == 0 || p == 0) {
          throw facebook::jsi::JSError(runtime, "__exactScryptSync: invalid scrypt parameters");
        }

        if (n > kMaxScryptMemory / 128 / r ||
            static_cast<uint64_t>(p) > kMaxScryptMemory / 128 / r) {
          throw facebook::jsi::JSError(runtime, "__exactScryptSync: parameters are too large");
        }

        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        const size_t mixed_length = static_cast<size_t>(128) * r * p;
        auto mixed = derivePbkdf2(runtime, password, salt, 1, mixed_length, "sha256");
        for (uint32_t lane = 0; lane < p; ++lane) {
          auto* block = reinterpret_cast<uint32_t*>(
              &mixed[static_cast<size_t>(lane) * 128 * r]);
          scryptRoMix(block, n, r);
        }
        return makeUint8Array(
            runtime,
            derivePbkdf2(runtime, password, mixed, 1, length, "sha256"));
      });
  rt.global().setProperty(rt, "__exactScryptSync", std::move(scryptFn));

  // @ref LLP 0008#crypto — Windows AES-CBC uses the CNG symmetric-key
  // primitive with native PKCS#7 block padding.
  auto aesCbcEncryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcEncrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactAesCbcEncrypt: key, iv, and data required");
        }
        return makeUint8Array(
            runtime,
            aesCbcCrypt(
                runtime,
                extractBytes(runtime, args[0]),
                extractBytes(runtime, args[1]),
                extractBytes(runtime, args[2]),
                true));
      });
  rt.global().setProperty(rt, "__exactAesCbcEncrypt", std::move(aesCbcEncryptFn));

  auto aesCbcDecryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcDecrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactAesCbcDecrypt: key, iv, and data required");
        }
        return makeUint8Array(
            runtime,
            aesCbcCrypt(
                runtime,
                extractBytes(runtime, args[0]),
                extractBytes(runtime, args[1]),
                extractBytes(runtime, args[2]),
                false));
      });
  rt.global().setProperty(rt, "__exactAesCbcDecrypt", std::move(aesCbcDecryptFn));

  // @ref LLP 0008#crypto — Windows EC key generation uses CNG and exports
  // standards-shaped PKCS#8 private and SPKI public PEM values.
  auto generateKeyPairSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGenerateKeyPairSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactGenerateKeyPairSync: key type required");
        }
        const auto key_type = args[0].asString(runtime).utf8(runtime);
        if (key_type != "ec" && key_type != "ecdsa") {
          throw facebook::jsi::JSError(
              runtime,
              "__exactGenerateKeyPairSync: unsupported Windows key type " + key_type);
        }

        std::string named_curve = "P-256";
        if (count >= 2 && args[1].isObject()) {
          auto options = args[1].asObject(runtime);
          if (options.hasProperty(runtime, "namedCurve")) {
            const auto value = options.getProperty(runtime, "namedCurve");
            if (!value.isString()) {
              throw facebook::jsi::JSError(
                  runtime,
                  "__exactGenerateKeyPairSync: namedCurve must be a string");
            }
            named_curve = value.asString(runtime).utf8(runtime);
          }
        }

        auto curve = ecCurveConfig(named_curve);
        if (!curve.has_value()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactGenerateKeyPairSync: unsupported Windows EC curve " + named_curve);
        }
        auto pair = generateEcKeyPairPem(runtime, *curve);
        facebook::jsi::Object result(runtime);
        result.setProperty(
            runtime,
            "privateKey",
            facebook::jsi::String::createFromUtf8(runtime, pair.first));
        result.setProperty(
            runtime,
            "publicKey",
            facebook::jsi::String::createFromUtf8(runtime, pair.second));
        return result;
      });
  rt.global().setProperty(
      rt,
      "__exactGenerateKeyPairSync",
      std::move(generateKeyPairSyncFn));

  // @ref LLP 0008#crypto — Windows keeps the canonical JavaScript crypto
  // surface and supplies its available native primitives through BCrypt/CNG.
  auto hkdfFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHkdf"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5 || !args[0].isString() || !args[4].isNumber()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactHkdf: algorithm, ikm, salt, info, and length required");
        }

        auto algorithm = args[0].asString(runtime).utf8(runtime);
        auto hash_length = hkdfDigestLength(algorithm);
        if (!hash_length.has_value()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactHkdf: unsupported hash algorithm: " + algorithm);
        }

        double requested_length = args[4].asNumber();
        if (!std::isfinite(requested_length) || requested_length < 0 ||
            std::floor(requested_length) != requested_length ||
            requested_length > static_cast<double>(255 * *hash_length)) {
          throw facebook::jsi::JSError(runtime, "__exactHkdf: invalid output length");
        }

        auto ikm = extractBytes(runtime, args[1]);
        auto salt = extractBytes(runtime, args[2]);
        auto info = extractBytes(runtime, args[3]);
        auto length = static_cast<size_t>(requested_length);
        if (length == 0) {
          return makeUint8Array(runtime, {});
        }

        if (salt.empty()) {
          salt.resize(*hash_length, 0);
        }

        // RFC 5869 extract: PRK = HMAC-Hash(salt, IKM).
        auto prk = computeDigest(runtime, algorithm, ikm, salt);
        auto block_count = (length + *hash_length - 1) / *hash_length;
        std::vector<uint8_t> output;
        output.reserve(block_count * *hash_length);
        std::vector<uint8_t> previous;

        // RFC 5869 expand: T(i) = HMAC-Hash(PRK, T(i-1) || info || i).
        for (size_t block = 1; block <= block_count; ++block) {
          std::vector<uint8_t> input;
          input.reserve(previous.size() + info.size() + 1);
          input.insert(input.end(), previous.begin(), previous.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(block));
          previous = computeDigest(runtime, algorithm, input, prk);
          output.insert(output.end(), previous.begin(), previous.end());
        }

        output.resize(length);
        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactHkdf", std::move(hkdfFn));

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
