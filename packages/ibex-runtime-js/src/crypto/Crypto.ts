// @ts-nocheck
/**
 * Crypto - Web Crypto API Implementation
 *
 * @see https://www.w3.org/TR/WebCryptoAPI/
 *
 * Supported algorithms:
 * - Digest: SHA-1, SHA-256, SHA-384, SHA-512
 * - Encrypt/Decrypt: AES-GCM, AES-CBC, AES-CTR, RSA-OAEP
 * - Sign/Verify: HMAC, RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA, Ed25519
 * - Key generation: AES-GCM, AES-CBC, AES-CTR, HMAC, RSA-OAEP, RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA, ECDH, Ed25519, X25519
 * - Key derivation: PBKDF2, HKDF, X25519
 * - Key formats: raw, jwk, spki, pkcs8
 *
 * Note: This uses native crypto when available, with JS fallbacks for testing.
 */

import { getNativeCryptoModule } from "../native/NativeModules";
import { requireCapability, Capabilities, isSilentMode } from "../security/Capabilities";

// Declare native crypto bridge functions
declare global {
  // AES operations (algorithm-specific native bridges)
  var __exactAesCbcEncrypt: ((
    key: Uint8Array,
    iv: Uint8Array,
    data: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactAesCbcDecrypt: ((
    key: Uint8Array,
    iv: Uint8Array,
    data: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactAesCtrEncrypt: ((
    key: Uint8Array,
    counter: Uint8Array,
    data: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactAesGcmEncrypt: ((
    key: Uint8Array,
    iv: Uint8Array,
    data: Uint8Array,
    aad?: Uint8Array,
    tagLength?: number
  ) => Uint8Array) | undefined;

  var __exactAesGcmDecrypt: ((
    key: Uint8Array,
    iv: Uint8Array,
    data: Uint8Array,
    aad?: Uint8Array,
    tagLength?: number
  ) => Uint8Array) | undefined;

  // HMAC operation (returns hex string, not bytes)
  var __exactHmacSync: ((
    algorithm: string,
    key: string,
    data: string
  ) => string) | undefined;

  // RSA sign/verify. The native bridge signs the RAW message bytes (pass a
  // Uint8Array; a string is still accepted for legacy callers) and honours the
  // optional RSA scheme ("pss" selects RSA-PSS) + salt length so RSA-PSS is no
  // longer silently signed as PKCS#1 v1.5 (ENG-23002). PEM key as a string.
  var __exactSignSync: ((
    algorithm: string,
    data: Uint8Array | string,
    key: string,
    scheme?: "pkcs1" | "pss",
    saltLength?: number
  ) => Uint8Array) | undefined;

  var __exactVerifySync: ((
    algorithm: string,
    signature: Uint8Array,
    data: Uint8Array | string,
    key: string,
    scheme?: "pkcs1" | "pss",
    saltLength?: number
  ) => boolean) | undefined;

  // Key generation (returns PEM strings for asymmetric keys)
  var __exactGenerateKeyPairSync: ((
    keyType: string,
    options?: Record<string, any>
  ) => { publicKey: string; privateKey: string }) | undefined;

  // Key derivation
  var __exactPbkdf2: ((
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    keyLength: number,
    hashAlgo: string
  ) => Uint8Array) | undefined;

  var __exactHkdf: ((
    hashAlgo: string,
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number
  ) => Uint8Array) | undefined;

  // Ed25519 operations
  var __exactEd25519Sign: ((
    privateKey: Uint8Array,
    data: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactEd25519Verify: ((
    publicKey: Uint8Array,
    signature: Uint8Array,
    data: Uint8Array
  ) => boolean) | undefined;

  // ECDSA operations
  var __exactEcdsaSign: ((
    curve: string,
    hash: string,
    privateKey: Uint8Array,
    data: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactEcdsaVerify: ((
    curve: string,
    hash: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
    data: Uint8Array
  ) => boolean) | undefined;

  // X25519 key agreement
  var __exactX25519DeriveBits: ((
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ) => Uint8Array) | undefined;

  // ECDH key agreement for NIST curves
  var __exactEcdhDeriveBits: ((
    curve: string,
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ) => Uint8Array) | undefined;

  // RSA-OAEP encrypt/decrypt
  var __exactRsaOaepEncrypt: ((
    publicKeyData: Uint8Array,
    hashAlgorithm: string,
    label: Uint8Array,
    plaintext: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactRsaOaepDecrypt: ((
    privateKeyData: Uint8Array,
    hashAlgorithm: string,
    label: Uint8Array,
    ciphertext: Uint8Array
  ) => Uint8Array) | undefined;

  // SPKI/PKCS8 key format support
  var __exactExportKeySpki: ((
    keyType: string,
    keyData: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactExportKeyPkcs8: ((
    keyType: string,
    keyData: Uint8Array
  ) => Uint8Array) | undefined;

  var __exactImportKeySpki: ((
    keyData: Uint8Array
  ) => { keyType: string; algorithm: string; rawKeyData: Uint8Array }) | undefined;

  var __exactImportKeyPkcs8: ((
    keyData: Uint8Array
  ) => { keyType: string; algorithm: string; rawKeyData: Uint8Array }) | undefined;
}

/**
 * Wrap native bridge errors as DOMException with the appropriate name.
 * Native __exact* functions throw generic Error; WPT expects DOMException.
 */
function wrapNativeError(e: unknown, defaultName: string): DOMException {
  if (e instanceof DOMException) return e;
  const msg = (e instanceof Error) ? e.message : String(e);
  if (/not supported|unsupported|not available|unrecognized/i.test(msg)) {
    return new DOMException(msg, 'NotSupportedError');
  }
  if (/invalid key|bad key/i.test(msg)) {
    return new DOMException(msg, 'DataError');
  }
  if (/not extractable|usage/i.test(msg)) {
    return new DOMException(msg, 'InvalidAccessError');
  }
  return new DOMException(msg, defaultName);
}

export class SubtleCrypto {
  /**
   * Check capability before any subtle crypto operation.
   * @throws NotAllowedError if capability is not granted
   */
  #checkCapability(): void {
    requireCapability(Capabilities.CRYPTO_SUBTLE);
  }

  /**
   * Generate a cryptographic digest (hash)
   */
  async digest(
    algorithm: AlgorithmIdentifier,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    const alg = typeof algorithm === "string" ? algorithm : algorithm.name;
    const normalizedAlg = normalizeHashName(alg);
    const bytes = toUint8Array(data);

    const native = getNativeCryptoModule();
    if (native) {
      try {
        switch (normalizedAlg) {
          case "SHA-1": {
            if (native.digest) return await native.digest(normalizedAlg, bytes);
            return await native.sha1(bytes);
          }
          case "SHA-256": {
            if (native.digest) return await native.digest(normalizedAlg, bytes);
            return await native.sha256(bytes);
          }
          case "SHA-384": {
            if (native.digest) return await native.digest(normalizedAlg, bytes);
            return await native.sha384(bytes);
          }
          case "SHA-512": {
            if (native.digest) return await native.digest(normalizedAlg, bytes);
            return await native.sha512(bytes);
          }
        }
      } catch (_nativeErr) {
        // Native threw (e.g., stub not implemented), fall through to fallback path
      }
    }

    // Try platform crypto (Bun/Node/browser globalThis.crypto.subtle) if available
    const platformSubtle = getPlatformSubtle();
    if (platformSubtle) {
      try {
        return await platformSubtle.digest(algorithm, bytes);
      } catch (_platformErr) {
        // Platform crypto failed, fall through to pure JS
      }
    }

    // Pure JS fallback for supported hashes
    switch (normalizedAlg) {
      case "SHA-1":
        return jsSHA1(bytes);
      case "SHA-256":
        return jsSHA256(bytes);
      case "SHA-384":
        return jsSHA384(bytes);
      case "SHA-512":
        return jsSHA512(bytes);
      default:
        throw new DOMException(
          `Unrecognized algorithm name: ${alg}`,
          "NotSupportedError"
        );
    }
  }

  /**
   * Encrypt data using the specified algorithm and key
   */
  async encrypt(
    algorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    validateKey(key, 'encrypt');
    const bytes = toUint8Array(data);
    const alg = normalizeAlgorithm(algorithm);
    
    switch (alg.name.toUpperCase()) {
      case 'AES-GCM': {
        const params = algorithm as AesGcmParams;
        const iv = toUint8Array(params.iv);
        const additionalData = params.additionalData ? toUint8Array(params.additionalData) : undefined;
        const tagLength = params.tagLength ?? 128;

        if (typeof __exactAesGcmEncrypt === 'function') {
          try {
            const result = __exactAesGcmEncrypt((key as ExactCryptoKey)._keyData, iv, bytes, additionalData, tagLength);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-GCM', 'NotSupportedError');
      }

      case 'AES-CBC': {
        const params = algorithm as AesCbcParams;
        const iv = toUint8Array(params.iv);

        if (typeof __exactAesCbcEncrypt === 'function') {
          try {
            const result = __exactAesCbcEncrypt((key as ExactCryptoKey)._keyData, iv, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-CBC', 'NotSupportedError');
      }

      case 'AES-CTR': {
        const params = algorithm as AesCtrParams;
        const counter = toUint8Array(params.counter);

        if (typeof __exactAesCtrEncrypt === 'function') {
          try {
            const result = __exactAesCtrEncrypt((key as ExactCryptoKey)._keyData, counter, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-CTR', 'NotSupportedError');
      }

      case 'RSA-OAEP': {
        const params = algorithm as RsaOaepParams;
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash?.name || 'SHA-256';
        const label = params.label ? toUint8Array(params.label) : new Uint8Array(0);

        if (typeof __exactRsaOaepEncrypt === 'function') {
          try {
            const result = __exactRsaOaepEncrypt((key as ExactCryptoKey)._keyData, hash, label, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSA-OAEP', 'NotSupportedError');
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Decrypt data using the specified algorithm and key
   */
  async decrypt(
    algorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    validateKey(key, 'decrypt');
    const bytes = toUint8Array(data);
    const alg = normalizeAlgorithm(algorithm);

    switch (alg.name.toUpperCase()) {
      case 'AES-GCM': {
        const params = algorithm as AesGcmParams;
        const iv = toUint8Array(params.iv);
        const additionalData = params.additionalData ? toUint8Array(params.additionalData) : undefined;
        const tagLength = params.tagLength ?? 128;

        if (typeof __exactAesGcmDecrypt === 'function') {
          try {
            const result = __exactAesGcmDecrypt((key as ExactCryptoKey)._keyData, iv, bytes, additionalData, tagLength);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-GCM', 'NotSupportedError');
      }

      case 'AES-CBC': {
        const params = algorithm as AesCbcParams;
        const iv = toUint8Array(params.iv);

        if (typeof __exactAesCbcDecrypt === 'function') {
          try {
            const result = __exactAesCbcDecrypt((key as ExactCryptoKey)._keyData, iv, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-CBC', 'NotSupportedError');
      }

      case 'AES-CTR': {
        const params = algorithm as AesCtrParams;
        const counter = toUint8Array(params.counter);

        // CTR mode: encrypt and decrypt are the same operation
        if (typeof __exactAesCtrEncrypt === 'function') {
          try {
            const result = __exactAesCtrEncrypt((key as ExactCryptoKey)._keyData, counter, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for AES-CTR', 'NotSupportedError');
      }

      case 'RSA-OAEP': {
        const params = algorithm as RsaOaepParams;
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash?.name || 'SHA-256';
        const label = params.label ? toUint8Array(params.label) : new Uint8Array(0);

        if (typeof __exactRsaOaepDecrypt === 'function') {
          try {
            const result = __exactRsaOaepDecrypt((key as ExactCryptoKey)._keyData, hash, label, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSA-OAEP', 'NotSupportedError');
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Sign data using the specified algorithm and key
   */
  async sign(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    validateKey(key, 'sign');
    const bytes = toUint8Array(data);
    const alg = normalizeAlgorithm(algorithm);
    const native = getNativeCryptoModule();
    
    switch (alg.name.toUpperCase()) {
      case 'HMAC': {
        const hash = normalizeHashName((key.algorithm as HmacKeyAlgorithm).hash.name);

        if (native?.hmacSign) {
          return native.hmacSign(hash, (key as ExactCryptoKey)._keyData, bytes);
        }

        // Byte-accurate HMAC. The legacy __exactHmacSync bridge round-tripped the
        // key and data through JS strings that the native side re-encoded as
        // UTF-8, corrupting every byte >= 0x80 (so e.g. an HS256 JWT signed
        // elsewhere failed to verify). jsHmac operates on the raw bytes and
        // needs only a digest, so it is correct on every platform (ENG-22983).
        return jsHmac((key as ExactCryptoKey)._keyData, bytes, hash);
      }

      case 'RSASSA-PKCS1-V1_5': {
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;

        // Prefer a real WebCrypto implementation when the host provides one: it
        // signs the raw message bytes (the __exactSignSync bridge re-encodes the
        // message as UTF-8, corrupting bytes >= 0x80 — ENG-22983).
        const viaPlatform = await platformRsaSign(
          'RSASSA-PKCS1-v1_5', hash, undefined, key as ExactCryptoKey, bytes
        );
        if (viaPlatform) return viaPlatform;

        if (typeof __exactSignSync === 'function') {
          try {
            const keyStr = uint8ArrayToString((key as ExactCryptoKey)._keyData);
            // Pass the raw message bytes so the native bridge signs them
            // byte-for-byte instead of a UTF-8 re-encoding (ENG-23002).
            const result = __exactSignSync(hash, bytes, keyStr, 'pkcs1');
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSASSA-PKCS1-v1_5', 'NotSupportedError');
      }

      case 'RSA-PSS': {
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;
        const saltLength = (algorithm as RsaPssParams).saltLength;

        // Prefer a real WebCrypto when the host provides one. Otherwise the
        // native bridge now honours the PSS scheme + saltLength and signs the
        // raw message bytes, so on-device RSA-PSS is a genuine PSS signature
        // (it previously silently produced a PKCS#1 v1.5 signature — ENG-23002).
        const viaPlatform = await platformRsaSign(
          'RSA-PSS', hash, saltLength, key as ExactCryptoKey, bytes
        );
        if (viaPlatform) return viaPlatform;

        if (typeof __exactSignSync === 'function') {
          try {
            const keyStr = uint8ArrayToString((key as ExactCryptoKey)._keyData);
            const result = __exactSignSync(hash, bytes, keyStr, 'pss', saltLength);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSA-PSS', 'NotSupportedError');
      }

      case 'ECDSA': {
        const params = algorithm as EcdsaParams;
        const hash = typeof params.hash === 'string' ? params.hash : params.hash.name;
        const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;

        if (typeof __exactEcdsaSign === 'function') {
          try {
            const result = __exactEcdsaSign(curve, hash, (key as ExactCryptoKey)._keyData, bytes);
            // The native bridge (OpenSSL EVP) returns an X9.62 DER signature, but
            // WebCrypto mandates the raw fixed-length IEEE P1363 r||s form
            // (64 bytes for P-256), so convert at the boundary (ENG-22983).
            const p1363 = derToP1363(toUint8Array(result), getEcCoordSize(curve));
            return uint8ArrayToArrayBuffer(p1363);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for ECDSA', 'NotSupportedError');
      }

      case 'ED25519':
      case 'EDDSA': {
        if (typeof __exactEd25519Sign === 'function') {
          try {
            // If key data is 64 bytes (d[32] || x[32] from JWK import), pass only d portion
            const keyData = (key as ExactCryptoKey)._keyData;
            const privKeyData = keyData.length === 64 ? keyData.slice(0, 32) : keyData;
            const result = __exactEd25519Sign(privKeyData, bytes);
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for Ed25519', 'NotSupportedError');
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Verify a signature using the specified algorithm and key
   */
  async verify(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource
  ): Promise<boolean> {
    this.#checkCapability();
    validateKey(key, 'verify');
    const signatureBytes = toUint8Array(signature);
    const dataBytes = toUint8Array(data);
    const alg = normalizeAlgorithm(algorithm);
    const native = getNativeCryptoModule();
    
    switch (alg.name.toUpperCase()) {
      case 'HMAC': {
        const hash = normalizeHashName((key.algorithm as HmacKeyAlgorithm).hash.name);

        if (native?.hmacVerify) {
          return native.hmacVerify(hash, (key as ExactCryptoKey)._keyData, signatureBytes, dataBytes);
        }

        // Byte-accurate HMAC (see the sign() path); avoids the __exactHmacSync
        // UTF-8 round-trip that mangled bytes >= 0x80 (ENG-22983).
        const expectedSig = await jsHmac((key as ExactCryptoKey)._keyData, dataBytes, hash);
        return constantTimeCompare(new Uint8Array(expectedSig), signatureBytes);
      }

      case 'RSASSA-PKCS1-V1_5': {
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;

        const viaPlatform = await platformRsaVerify(
          'RSASSA-PKCS1-v1_5', hash, undefined, key as ExactCryptoKey, signatureBytes, dataBytes
        );
        if (viaPlatform !== null) return viaPlatform;

        if (typeof __exactVerifySync === 'function') {
          try {
            const keyStr = uint8ArrayToString((key as ExactCryptoKey)._keyData);
            // Verify against the raw message bytes byte-for-byte (ENG-23002).
            return __exactVerifySync(hash, signatureBytes, dataBytes, keyStr, 'pkcs1');
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSASSA-PKCS1-v1_5', 'NotSupportedError');
      }

      case 'RSA-PSS': {
        const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;
        const saltLength = (algorithm as RsaPssParams).saltLength;

        // A real WebCrypto verifies genuine PSS signatures (with saltLength).
        // The native bridge now also honours the PSS scheme + saltLength and
        // verifies against the raw message bytes (ENG-23002).
        const viaPlatform = await platformRsaVerify(
          'RSA-PSS', hash, saltLength, key as ExactCryptoKey, signatureBytes, dataBytes
        );
        if (viaPlatform !== null) return viaPlatform;

        if (typeof __exactVerifySync === 'function') {
          try {
            const keyStr = uint8ArrayToString((key as ExactCryptoKey)._keyData);
            return __exactVerifySync(hash, signatureBytes, dataBytes, keyStr, 'pss', saltLength);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSA-PSS', 'NotSupportedError');
      }

      case 'ECDSA': {
        const params = algorithm as EcdsaParams;
        const hash = typeof params.hash === 'string' ? params.hash : params.hash.name;
        const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;

        if (typeof __exactEcdsaVerify === 'function') {
          try {
            // WebCrypto passes the raw fixed-length P1363 r||s signature, but the
            // native verifier (OpenSSL EVP) expects X9.62 DER (ENG-22983).
            const derSig = p1363ToDer(signatureBytes, getEcCoordSize(curve));
            return __exactEcdsaVerify(curve, hash, (key as ExactCryptoKey)._keyData, derSig, dataBytes);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for ECDSA', 'NotSupportedError');
      }

      case 'ED25519':
      case 'EDDSA': {
        if (typeof __exactEd25519Verify === 'function') {
          try {
            return __exactEd25519Verify((key as ExactCryptoKey)._keyData, signatureBytes, dataBytes);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for Ed25519', 'NotSupportedError');
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Generate a new key or key pair
   */
  async generateKey(
    algorithm: RsaHashedKeyGenParams | EcKeyGenParams | AesKeyGenParams | HmacKeyGenParams | KmacKeyGenParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKeyPair | CryptoKey> {
    this.#checkCapability();
    const alg = normalizeAlgorithm(algorithm);
    if (typeof alg.name !== 'string') {
      throw new DOMException('Invalid algorithm', 'TypeError');
    }
    const algName = alg.name.toUpperCase();
    if (keyUsages.length === 0) {
      throw new DOMException('Key usages cannot be empty', 'SyntaxError');
    }
    
    switch (algName) {
      case 'AES-GCM':
      case 'AES-CBC':
      case 'AES-CTR':
      case 'AES-KW': {
        const params = algorithm as AesKeyGenParams;
        const length = params.length;
        
        if (![128, 192, 256].includes(length)) {
          throw new DOMException('Invalid key length', 'DataError');
        }
        
        // Generate random key bytes
        const keyData = new Uint8Array(length / 8);
        crypto.getRandomValues(keyData);
        
        return new ExactCryptoKey(
          'secret',
          extractable,
          { name: alg.name, length },
          keyUsages,
          keyData
        );
      }
      
      case 'HMAC': {
        const params = algorithm as HmacKeyGenParams;
        const hash = normalizeHashName(typeof params.hash === 'string' ? params.hash : params.hash.name);
        // Spec default for an omitted HMAC length is the hash *block* size
        // (512 for SHA-1/224/256, 1024 for SHA-384/512), not the digest size —
        // getHashLength returned the latter, halving the key (ENG-22983).
        const length = params.length ?? getHmacBlockSize(hash);

        const keyData = new Uint8Array(length / 8);
        crypto.getRandomValues(keyData);
        
        return new ExactCryptoKey(
          'secret',
          extractable,
          { name: 'HMAC', hash: { name: hash }, length },
          keyUsages,
          keyData
        );
      }
      
      case 'RSA-OAEP':
      case 'RSASSA-PKCS1-V1_5':
      case 'RSA-PSS': {
        const params = algorithm as RsaHashedKeyGenParams;
        const hash = normalizeRequiredHash(params.hash);

        if (typeof __exactGenerateKeyPairSync === 'function') {
          try {
            const result = __exactGenerateKeyPairSync('rsa', {
              modulusLength: params.modulusLength,
              // WebCrypto publicExponent is a big-endian BigInteger of arbitrary
              // length; the canonical value new Uint8Array([1,0,1]) is 3 bytes, so
              // reading a fixed 4-byte word threw RangeError (ENG-22983).
              publicExponent: params.publicExponent instanceof Uint8Array
                ? bigEndianBytesToNumber(params.publicExponent)
                : 65537,
            });

            const algorithmInfo = {
              name: alg.name,
              modulusLength: params.modulusLength,
              publicExponent: params.publicExponent,
              hash: { name: hash },
            };

            // Keys are PEM strings - store as UTF-8 bytes
            const pubKeyData = new TextEncoder().encode(result.publicKey);
            const privKeyData = new TextEncoder().encode(result.privateKey);

            return {
              publicKey: new ExactCryptoKey(
                'public',
                true,
                algorithmInfo,
                keyUsages.filter(u => ['encrypt', 'verify', 'wrapKey'].includes(u)),
                pubKeyData
              ),
              privateKey: new ExactCryptoKey(
                'private',
                extractable,
                algorithmInfo,
                keyUsages.filter(u => ['decrypt', 'sign', 'unwrapKey'].includes(u)),
                privKeyData
              ),
            };
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for RSA key generation', 'NotSupportedError');
      }

      case 'ECDSA':
      case 'ECDH': {
        const params = algorithm as EcKeyGenParams;

        if (typeof __exactGenerateKeyPairSync === 'function') {
          const result = __exactGenerateKeyPairSync('ec', {
            namedCurve: params.namedCurve,
          });

          const algorithmInfo = {
            name: alg.name,
            namedCurve: params.namedCurve,
          };

          // Keys are PEM strings - store as UTF-8 bytes
          const pubKeyData = new TextEncoder().encode(result.publicKey);
          const privKeyData = new TextEncoder().encode(result.privateKey);

          return {
            publicKey: new ExactCryptoKey(
              'public',
              true,
              algorithmInfo,
              alg.name === 'ECDSA'
                ? keyUsages.filter(u => u === 'verify')
                : keyUsages.filter(u => u === 'deriveKey' || u === 'deriveBits'),
              pubKeyData
            ),
            privateKey: new ExactCryptoKey(
              'private',
              extractable,
              algorithmInfo,
              alg.name === 'ECDSA'
                ? keyUsages.filter(u => u === 'sign')
                : keyUsages.filter(u => u === 'deriveKey' || u === 'deriveBits'),
              privKeyData
            ),
          };
        }
        throw new DOMException('Native crypto not available for EC key generation', 'NotSupportedError');
      }

      case 'ED25519':
      case 'EDDSA': {
        if (typeof __exactGenerateKeyPairSync === 'function') {
          const result = __exactGenerateKeyPairSync('ed25519', {});

          const algorithmInfo = { name: 'Ed25519' };

          // Keys are PEM strings - store as UTF-8 bytes
          const pubKeyData = new TextEncoder().encode(result.publicKey);
          const privKeyData = new TextEncoder().encode(result.privateKey);

          return {
            publicKey: new ExactCryptoKey(
              'public',
              true,
              algorithmInfo,
              keyUsages.filter(u => u === 'verify'),
              pubKeyData
            ),
            privateKey: new ExactCryptoKey(
              'private',
              extractable,
              algorithmInfo,
              keyUsages.filter(u => u === 'sign'),
              privKeyData
            ),
          };
        }
        throw new DOMException('Native crypto not available for Ed25519 key generation', 'NotSupportedError');
      }

      case 'X25519': {
        if (typeof __exactGenerateKeyPairSync === 'function') {
          const result = __exactGenerateKeyPairSync('x25519', {});

          const algorithmInfo = { name: 'X25519' };

          // Keys are PEM strings - store as UTF-8 bytes
          const pubKeyData = new TextEncoder().encode(result.publicKey);
          const privKeyData = new TextEncoder().encode(result.privateKey);

          return {
            publicKey: new ExactCryptoKey(
              'public',
              true,
              algorithmInfo,
              keyUsages.filter(u => u === 'deriveBits' || u === 'deriveKey'),
              pubKeyData
            ),
            privateKey: new ExactCryptoKey(
              'private',
              extractable,
              algorithmInfo,
              keyUsages.filter(u => u === 'deriveBits' || u === 'deriveKey'),
              privKeyData
            ),
          };
        }
        throw new DOMException('Native crypto not available for X25519 key generation', 'NotSupportedError');
      }

      case 'KMAC128':
      case 'KMAC256': {
        const params = algorithm as KmacKeyGenParams;
        const length = params.length;
        if (length !== 128 && length !== 160 && length !== 256) {
          throw new DOMException('Invalid key length', 'DataError');
        }

        for (const usage of keyUsages) {
          if (usage !== 'sign' && usage !== 'verify') {
            throw new DOMException(
              `Invalid key usage '${usage}' for ${algName}`,
              'SyntaxError'
            );
          }
        }

        const keyData = new Uint8Array(length / 8);
        crypto.getRandomValues(keyData);

        return new ExactCryptoKey(
          'secret',
          extractable,
          { name: alg.name, length },
          keyUsages,
          keyData
        );
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Import a key from external data
   */
  async importKey(
    format: KeyFormat,
    keyData: BufferSource | JsonWebKey,
    algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    this.#checkCapability();
    // Normalize tentative "raw-secret" format to "raw"
    if (format === ('raw-secret' as any)) format = 'raw';
    const alg = normalizeAlgorithm(algorithm);

    // Handle raw format (for symmetric keys)
    if (format === 'raw') {
      const rawData = toUint8Array(keyData as BufferSource);
      
      switch (alg.name.toUpperCase()) {
        case 'AES-GCM':
        case 'AES-CBC':
        case 'AES-CTR':
        case 'AES-KW': {
          if (![16, 24, 32].includes(rawData.length)) {
            throw new DOMException('Invalid key length', 'DataError');
          }
          return new ExactCryptoKey(
            'secret',
            extractable,
            { name: alg.name, length: rawData.length * 8 },
            keyUsages,
            rawData
          );
        }
        
        case 'HMAC': {
          const params = algorithm as HmacImportParams;
          const hash = normalizeHashName(typeof params.hash === 'string' ? params.hash : params.hash.name);
          return new ExactCryptoKey(
            'secret',
            extractable,
            { name: 'HMAC', hash: { name: hash }, length: rawData.length * 8 },
            keyUsages,
            rawData
          );
        }
        
        case 'PBKDF2':
        case 'HKDF': {
          return new ExactCryptoKey(
            'secret',
            false, // PBKDF2/HKDF keys are never extractable
            { name: alg.name },
            keyUsages,
            rawData
          );
        }

        case 'ED25519':
        case 'EDDSA': {
          if (rawData.length !== 32) {
            throw new DOMException('Ed25519 key must be 32 bytes', 'DataError');
          }
          return new ExactCryptoKey(
            'public',
            extractable,
            { name: 'Ed25519' },
            keyUsages,
            rawData
          );
        }

        case 'X25519': {
          if (rawData.length !== 32) {
            throw new DOMException('X25519 key must be 32 bytes', 'DataError');
          }
          return new ExactCryptoKey(
            'public',
            extractable,
            { name: 'X25519' },
            keyUsages,
            rawData
          );
        }

        default:
          throw new DOMException(`Unsupported algorithm for raw import: ${alg.name}`, 'NotSupportedError');
      }
    }

    // Handle JWK format
    if (format === 'jwk') {
      const jwk = keyData as JsonWebKey;
      return this._importJwk(jwk, algorithm, extractable, keyUsages);
    }
    
    // Handle SPKI format (for public keys)
    if (format === 'spki') {
      const rawData = toUint8Array(keyData as BufferSource);

      if (typeof __exactImportKeySpki === 'function') {
        try {
          const result = __exactImportKeySpki(rawData);
          const rawKeyData = result.rawKeyData instanceof Uint8Array
            ? result.rawKeyData
            : new Uint8Array(result.rawKeyData as any);

          // Determine algorithm info based on key type and provided algorithm
          const algName = alg.name.toUpperCase();
          let algorithmInfo: KeyAlgorithm;

          if (algName === 'ED25519' || algName === 'EDDSA') {
            algorithmInfo = { name: 'Ed25519' };
          } else if (algName === 'X25519') {
            algorithmInfo = { name: 'X25519' };
          } else if (algName.startsWith('RSA')) {
            algorithmInfo = {
              name: alg.name,
              hash: { name: normalizeHashName(typeof (algorithm as RsaHashedImportParams).hash === 'string' ? (algorithm as RsaHashedImportParams).hash : ((algorithm as RsaHashedImportParams).hash as any).name) },
            } as any;
          } else if (algName === 'ECDSA' || algName === 'ECDH') {
            algorithmInfo = {
              name: alg.name,
              namedCurve: (algorithm as EcKeyImportParams).namedCurve,
            };
          } else {
            algorithmInfo = { name: alg.name };
          }

          return new ExactCryptoKey('public', extractable, algorithmInfo, keyUsages, rawKeyData);
        } catch (e) {
          throw wrapNativeError(e, 'NotSupportedError');
        }
      }
      throw new DOMException('SPKI import requires native implementation', 'NotSupportedError');
    }

    // Handle PKCS8 format (for private keys)
    if (format === 'pkcs8') {
      const rawData = toUint8Array(keyData as BufferSource);

      if (typeof __exactImportKeyPkcs8 === 'function') {
        try {
          const result = __exactImportKeyPkcs8(rawData);
          const rawKeyData = result.rawKeyData instanceof Uint8Array
            ? result.rawKeyData
            : new Uint8Array(result.rawKeyData as any);

          const algName = alg.name.toUpperCase();
          let algorithmInfo: KeyAlgorithm;

          if (algName === 'ED25519' || algName === 'EDDSA') {
            algorithmInfo = { name: 'Ed25519' };
          } else if (algName === 'X25519') {
            algorithmInfo = { name: 'X25519' };
          } else if (algName.startsWith('RSA')) {
            algorithmInfo = {
              name: alg.name,
              hash: { name: normalizeHashName(typeof (algorithm as RsaHashedImportParams).hash === 'string' ? (algorithm as RsaHashedImportParams).hash : ((algorithm as RsaHashedImportParams).hash as any).name) },
            } as any;
          } else if (algName === 'ECDSA' || algName === 'ECDH') {
            algorithmInfo = {
              name: alg.name,
              namedCurve: (algorithm as EcKeyImportParams).namedCurve,
            };
          } else {
            algorithmInfo = { name: alg.name };
          }

          return new ExactCryptoKey('private', extractable, algorithmInfo, keyUsages, rawKeyData);
        } catch (e) {
          throw wrapNativeError(e, 'NotSupportedError');
        }
      }
      throw new DOMException('PKCS8 import requires native implementation', 'NotSupportedError');
    }
    
    throw new DOMException(`Unsupported format: ${format}`, 'NotSupportedError');
  }
    
  /**
   * Import a JWK key
   */
  private async _importJwk(
    jwk: JsonWebKey,
    algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    const alg = normalizeAlgorithm(algorithm);
    
    switch (jwk.kty) {
      case 'oct': {
        // Symmetric key
        if (!jwk.k) {
          throw new DOMException('Missing k parameter in JWK', 'DataError');
        }
        const rawData = base64UrlDecode(jwk.k);
        
        if (alg.name.toUpperCase().startsWith('AES')) {
          return new ExactCryptoKey(
            'secret',
            extractable,
            { name: alg.name, length: rawData.length * 8 },
            keyUsages,
            rawData
          );
        }
        
        if (alg.name.toUpperCase() === 'HMAC') {
          const params = algorithm as HmacImportParams;
          const hash = normalizeHashName(typeof params.hash === 'string' ? params.hash : params.hash.name);
          return new ExactCryptoKey(
            'secret',
            extractable,
            { name: 'HMAC', hash: { name: hash }, length: rawData.length * 8 },
            keyUsages,
            rawData
          );
        }
        
        throw new DOMException(`Unsupported algorithm for oct key: ${alg.name}`, 'NotSupportedError');
      }
      
      case 'RSA': {
        // Import RSA JWK - extract modulus and exponent
        if (!jwk.n || !jwk.e) {
          throw new DOMException('Missing n or e parameter in RSA JWK', 'DataError');
        }

        const isPrivate = !!jwk.d;
        const hash = (algorithm as RsaHashedImportParams).hash;
        const hashName = normalizeHashName(typeof hash === 'string' ? hash : hash.name);

        // Convert JWK RSA parameters to PEM format for the native sign/verify bridges
        const pemStr = rsaJwkToPem(jwk, isPrivate);
        const pemBytes = new TextEncoder().encode(pemStr);

        const algorithmInfo = {
          name: alg.name,
          hash: { name: hashName },
        };

        return new ExactCryptoKey(
          isPrivate ? 'private' : 'public',
          extractable,
          algorithmInfo,
          keyUsages,
          pemBytes
        );
      }

      case 'EC': {
        if (!jwk.x || !jwk.y) {
          throw new DOMException('Missing x or y parameter in EC JWK', 'DataError');
        }

        const isPrivate = !!jwk.d;
        const curve = jwk.crv || (algorithm as EcKeyImportParams).namedCurve;

        // Concatenate x, y (and d for private) coordinates as raw key data
        const x = base64UrlDecode(jwk.x);
        const y = base64UrlDecode(jwk.y);
        let keyDataBytes: Uint8Array;

        if (isPrivate && jwk.d) {
          const d = base64UrlDecode(jwk.d);
          keyDataBytes = new Uint8Array(1 + x.length + y.length + d.length);
          keyDataBytes[0] = 0x04; // uncompressed point
          keyDataBytes.set(x, 1);
          keyDataBytes.set(y, 1 + x.length);
          keyDataBytes.set(d, 1 + x.length + y.length);
        } else {
          keyDataBytes = new Uint8Array(1 + x.length + y.length);
          keyDataBytes[0] = 0x04; // uncompressed point
          keyDataBytes.set(x, 1);
          keyDataBytes.set(y, 1 + x.length);
        }

        const ecAlgorithmInfo = {
          name: alg.name,
          namedCurve: curve,
        };

        return new ExactCryptoKey(
          isPrivate ? 'private' : 'public',
          extractable,
          ecAlgorithmInfo,
          keyUsages,
          keyDataBytes
        );
      }

      case 'OKP': {
        // Octet Key Pair - Ed25519, X25519
        if (!jwk.x) {
          throw new DOMException('Missing x parameter in OKP JWK', 'DataError');
        }

        const isPrivate = !!jwk.d;
        const curve = jwk.crv;

        let keyDataBytes: Uint8Array;
        if (isPrivate && jwk.d) {
          // Store both d (private) and x (public) so JWK export can include both.
          // Format: d[32] || x[32] = 64 bytes total
          const dBytes = base64UrlDecode(jwk.d);
          const xBytes = base64UrlDecode(jwk.x);
          keyDataBytes = new Uint8Array(dBytes.length + xBytes.length);
          keyDataBytes.set(dBytes, 0);
          keyDataBytes.set(xBytes, dBytes.length);
        } else {
          keyDataBytes = base64UrlDecode(jwk.x);
        }

        let okpAlgName: string;
        if (curve === 'Ed25519') {
          okpAlgName = 'Ed25519';
        } else if (curve === 'X25519') {
          okpAlgName = 'X25519';
        } else {
          throw new DOMException(`Unsupported OKP curve: ${curve}`, 'NotSupportedError');
        }

        return new ExactCryptoKey(
          isPrivate ? 'private' : 'public',
          extractable,
          { name: okpAlgName },
          keyUsages,
          keyDataBytes
        );
      }

      default:
        throw new DOMException(`JWK import for ${jwk.kty} keys is not supported`, 'NotSupportedError');
    }
  }

  /**
   * Export a key to the specified format
   */
  async exportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    this.#checkCapability();
    if (!key.extractable) {
      throw new DOMException('Key is not extractable', 'InvalidAccessError');
    }
    
    const exactKey = key as ExactCryptoKey;
    
    if (format === 'raw') {
      if (key.type !== 'secret') {
        throw new DOMException('Raw export only supported for secret keys', 'InvalidAccessError');
      }
      return exactKey._keyData.buffer.slice(
        exactKey._keyData.byteOffset,
        exactKey._keyData.byteOffset + exactKey._keyData.byteLength
      );
    }
    
    if (format === 'jwk') {
      return this._exportJwk(exactKey);
    }

    if (format === 'spki') {
      if (key.type !== 'public') {
        throw new DOMException('SPKI export only supported for public keys', 'InvalidAccessError');
      }
      if (typeof __exactExportKeySpki === 'function') {
        const algName = key.algorithm.name.toUpperCase();
        const result = __exactExportKeySpki(algName, exactKey._keyData);
        return uint8ArrayToArrayBuffer(result);
      }
      throw new DOMException('SPKI export requires native implementation', 'NotSupportedError');
    }

    if (format === 'pkcs8') {
      if (key.type !== 'private') {
        throw new DOMException('PKCS8 export only supported for private keys', 'InvalidAccessError');
      }
      if (typeof __exactExportKeyPkcs8 === 'function') {
        const algName = key.algorithm.name.toUpperCase();
        const result = __exactExportKeyPkcs8(algName, exactKey._keyData);
        return uint8ArrayToArrayBuffer(result);
      }
      throw new DOMException('PKCS8 export requires native implementation', 'NotSupportedError');
    }

    throw new DOMException(`Export format ${format} is not supported`, 'NotSupportedError');
  }

  /**
   * Export a key as JWK
   */
  private _exportJwk(key: ExactCryptoKey): JsonWebKey {
    if (key.type === 'secret') {
      const algName = key.algorithm.name.toUpperCase();
      
      const jwk: JsonWebKey = {
        kty: 'oct',
        k: base64UrlEncode(key._keyData),
        ext: key.extractable,
        key_ops: [...key.usages],
      };
      
      if (algName.startsWith('AES')) {
        jwk.alg = `A${(key.algorithm as AesKeyAlgorithm).length}${algName.slice(4)}`;
      } else if (algName === 'HMAC') {
        const hash = (key.algorithm as HmacKeyAlgorithm).hash.name;
        jwk.alg = `HS${hash.replace('SHA-', '')}`;
      }
      
      return jwk;
    }
    
    // Asymmetric key export
    const algName = key.algorithm.name.toUpperCase();

    if (algName === 'ED25519' || algName === 'EDDSA') {
      const jwk: JsonWebKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        ext: key.extractable,
        key_ops: [...key.usages],
      };

      if (key.type === 'public') {
        jwk.x = base64UrlEncode(key._keyData);
      } else {
        // Private key: key data may be d[32] || x[32] (64 bytes from JWK import)
        // or a PEM string (from generateKey). Per Web Crypto spec, both x and d
        // must be present in a private OKP JWK.
        if (key._keyData.length === 64) {
          // Raw key data: d[32] || x[32]
          jwk.d = base64UrlEncode(key._keyData.slice(0, 32));
          jwk.x = base64UrlEncode(key._keyData.slice(32));
        } else {
          // PEM or other format -- export d only (x not available without native bridge)
          jwk.d = base64UrlEncode(key._keyData);
        }
      }

      return jwk;
    }

    if (algName === 'X25519') {
      const jwk: JsonWebKey = {
        kty: 'OKP',
        crv: 'X25519',
        ext: key.extractable,
        key_ops: [...key.usages],
      };

      if (key.type === 'public') {
        jwk.x = base64UrlEncode(key._keyData);
      } else {
        // Private key: key data may be d[32] || x[32] (64 bytes from JWK import)
        // or a PEM string (from generateKey). Per Web Crypto spec, both x and d
        // must be present in a private OKP JWK.
        if (key._keyData.length === 64) {
          // Raw key data: d[32] || x[32]
          jwk.d = base64UrlEncode(key._keyData.slice(0, 32));
          jwk.x = base64UrlEncode(key._keyData.slice(32));
        } else {
          // PEM or other format -- export d only (x not available without native bridge)
          jwk.d = base64UrlEncode(key._keyData);
        }
      }

      return jwk;
    }

    if (algName === 'ECDSA' || algName === 'ECDH') {
      const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;
      const data = key._keyData;

      // Key data format: 0x04 || x || y [|| d]
      const coordSize = (data.length - 1) / (key.type === 'private' ? 3 : 2);

      const jwk: JsonWebKey = {
        kty: 'EC',
        crv: curve,
        x: base64UrlEncode(data.slice(1, 1 + coordSize)),
        y: base64UrlEncode(data.slice(1 + coordSize, 1 + 2 * coordSize)),
        ext: key.extractable,
        key_ops: [...key.usages],
      };

      if (key.type === 'private') {
        jwk.d = base64UrlEncode(data.slice(1 + 2 * coordSize));
      }

      return jwk;
    }

    if (algName.startsWith('RSA') || algName === 'RSASSA-PKCS1-V1_5') {
      // RSA keys are stored as PEM strings encoded as UTF-8 bytes
      const pemStr = uint8ArrayToString(key._keyData);
      const rsaComponents = parseRsaPemToJwkComponents(pemStr, key.type === 'private');

      const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash?.name || 'SHA-256';
      let jwkAlg: string;
      if (algName === 'RSA-OAEP') {
        jwkAlg = hash === 'SHA-256' ? 'RSA-OAEP-256' : hash === 'SHA-384' ? 'RSA-OAEP-384' : hash === 'SHA-512' ? 'RSA-OAEP-512' : 'RSA-OAEP';
      } else if (algName === 'RSA-PSS') {
        jwkAlg = hash === 'SHA-256' ? 'PS256' : hash === 'SHA-384' ? 'PS384' : 'PS512';
      } else {
        jwkAlg = hash === 'SHA-256' ? 'RS256' : hash === 'SHA-384' ? 'RS384' : 'RS512';
      }

      const jwk: JsonWebKey = {
        kty: 'RSA',
        alg: jwkAlg,
        ext: key.extractable,
        key_ops: [...key.usages],
        ...rsaComponents,
      };

      return jwk;
    }

    throw new DOMException('JWK export for this key type is not supported', 'NotSupportedError');
  }

  /**
   * Derive bits from a base key
   */
  async deriveBits(
    algorithm: AlgorithmIdentifier | Pbkdf2Params | HkdfParams | EcdhKeyDeriveParams,
    baseKey: CryptoKey,
    length: number
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    validateKey(baseKey, 'deriveBits');
    const alg = normalizeAlgorithm(algorithm);
    
    switch (alg.name.toUpperCase()) {
      case 'PBKDF2': {
        const params = algorithm as Pbkdf2Params;
        const salt = toUint8Array(params.salt);
        const hash = typeof params.hash === 'string' ? params.hash : params.hash.name;
        const normalizedHash = normalizeHashName(hash);

        if (typeof __exactPbkdf2 === 'function') {
          // __exactPbkdf2(password, salt, iterations, keyLength, hashAlgo)
          const result = __exactPbkdf2(
            (baseKey as ExactCryptoKey)._keyData,
            salt,
            params.iterations,
            length / 8,
            normalizedHash
          );
          return uint8ArrayToArrayBuffer(result);
        }

        // JS fallback for PBKDF2-SHA256
        if (normalizedHash === 'SHA-256') {
          return jsPbkdf2Sha256(
            (baseKey as ExactCryptoKey)._keyData,
            salt,
            params.iterations,
            length / 8
          );
        }
        throw new DOMException('Native crypto not available for PBKDF2', 'NotSupportedError');
      }

      case 'HKDF': {
        const params = algorithm as HkdfParams;
        const salt = toUint8Array(params.salt);
        const info = toUint8Array(params.info);
        const hash = typeof params.hash === 'string' ? params.hash : params.hash.name;
        const normalizedHash = normalizeHashName(hash);

        if (typeof __exactHkdf === 'function') {
          const result = __exactHkdf(
            normalizedHash,
            (baseKey as ExactCryptoKey)._keyData,
            salt,
            info,
            length / 8
          );
          return uint8ArrayToArrayBuffer(result);
        }

        // JS fallback for HKDF
        return jsHkdf(
          (baseKey as ExactCryptoKey)._keyData,
          salt,
          info,
          normalizedHash,
          length / 8
        );
      }

      case 'X25519': {
        const params = algorithm as EcdhKeyDeriveParams;
        const publicKey = params.public as ExactCryptoKey;

        if (typeof __exactX25519DeriveBits === 'function') {
          try {
            // If base key data is 64 bytes (d[32] || x[32] from JWK import), pass only d portion
            const baseKeyData = (baseKey as ExactCryptoKey)._keyData;
            const privKeyData = baseKeyData.length === 64 ? baseKeyData.slice(0, 32) : baseKeyData;
            const result = __exactX25519DeriveBits(
              privKeyData,
              publicKey._keyData
            );
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for X25519', 'NotSupportedError');
      }

      case 'ECDH': {
        const params = algorithm as EcdhKeyDeriveParams;
        const publicKey = params.public as ExactCryptoKey;

        if (typeof __exactEcdhDeriveBits === 'function') {
          try {
            const curve = (baseKey.algorithm as EcKeyAlgorithm).namedCurve;
            const result = __exactEcdhDeriveBits(
              curve,
              (baseKey as ExactCryptoKey)._keyData,
              publicKey._keyData
            );
            return uint8ArrayToArrayBuffer(result);
          } catch (e) { throw wrapNativeError(e, 'OperationError'); }
        }
        throw new DOMException('Native crypto not available for ECDH', 'NotSupportedError');
      }

      default:
        throw new DOMException(`Unsupported algorithm: ${alg.name}`, 'NotSupportedError');
    }
  }

  /**
   * Derive a key from a base key
   */
  async deriveKey(
    algorithm: AlgorithmIdentifier | Pbkdf2Params | HkdfParams | EcdhKeyDeriveParams,
    baseKey: CryptoKey,
    derivedKeyAlgorithm: AlgorithmIdentifier | AesKeyGenParams | HmacKeyGenParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    this.#checkCapability();
    validateKey(baseKey, 'deriveKey');
    const derivedAlg = normalizeAlgorithm(derivedKeyAlgorithm);

    // Determine the length needed
    let length: number;
    if (derivedAlg.name.toUpperCase().startsWith('AES')) {
      length = (derivedKeyAlgorithm as AesKeyGenParams).length;
    } else if (derivedAlg.name.toUpperCase() === 'HMAC') {
      const params = derivedKeyAlgorithm as HmacKeyGenParams;
      const hash = normalizeHashName(typeof params.hash === 'string' ? params.hash : params.hash.name);
      // HMAC default length is the hash block size, not the digest size (ENG-22983).
      length = params.length ?? getHmacBlockSize(hash);
    } else {
      throw new DOMException(`Unsupported derived key algorithm: ${derivedAlg.name}`, 'NotSupportedError');
    }

    // Create a proxy key with 'deriveBits' usage for the internal deriveBits call
    const proxyKey = new ExactCryptoKey(
      (baseKey as ExactCryptoKey).type,
      (baseKey as ExactCryptoKey).extractable,
      (baseKey as ExactCryptoKey).algorithm,
      [...(baseKey as ExactCryptoKey).usages, 'deriveBits'],
      (baseKey as ExactCryptoKey)._keyData
    );

    // Derive the bits
    const bits = await this.deriveBits(algorithm, proxyKey, length);
    
    // Import as a key
    return this.importKey('raw', bits, derivedKeyAlgorithm, extractable, keyUsages);
  }

  /**
   * Wrap a key with another key
   */
  async wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams | RsaOaepParams
  ): Promise<ArrayBuffer> {
    this.#checkCapability();
    // Export the key
    const exported = await this.exportKey(format, key);
    
    // Get bytes from export
    let bytes: Uint8Array;
    if (exported instanceof ArrayBuffer) {
      bytes = new Uint8Array(exported);
    } else {
      // JWK - convert to JSON string
      bytes = new TextEncoder().encode(JSON.stringify(exported));
    }
    
    // Validate wrapping key has 'wrapKey' usage
    validateKey(wrappingKey, 'wrapKey');

    // Create a proxy key with 'encrypt' usage for the internal encrypt call
    const proxyKey = new ExactCryptoKey(
      (wrappingKey as any).type,
      (wrappingKey as any).extractable,
      (wrappingKey as any).algorithm,
      [...(wrappingKey as any).usages, 'encrypt'],
      (wrappingKey as any)._keyData
    );

    // Encrypt with wrapping key
    return this.encrypt(wrapAlgorithm, proxyKey, bytes);
  }

  /**
   * Unwrap a key
   */
  async unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams | RsaOaepParams,
    unwrappedKeyAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey> {
    this.#checkCapability();
    // Validate unwrapping key has 'unwrapKey' usage
    validateKey(unwrappingKey, 'unwrapKey');

    // Create a proxy key with 'decrypt' usage for the internal decrypt call
    const proxyKey = new ExactCryptoKey(
      (unwrappingKey as any).type,
      (unwrappingKey as any).extractable,
      (unwrappingKey as any).algorithm,
      [...(unwrappingKey as any).usages, 'decrypt'],
      (unwrappingKey as any)._keyData
    );

    // Decrypt the wrapped key
    const decrypted = await this.decrypt(unwrapAlgorithm, proxyKey, wrappedKey);
    
    // Import the key
    if (format === 'jwk') {
      const jwkString = new TextDecoder().decode(decrypted);
      const jwk = JSON.parse(jwkString);
      return this.importKey(format, jwk, unwrappedKeyAlgorithm, extractable, keyUsages);
    }
    
    return this.importKey(format, decrypted, unwrappedKeyAlgorithm, extractable, keyUsages);
  }
}

export class Crypto {
  private _subtle = new SubtleCrypto();

  get subtle(): SubtleCrypto {
    return this._subtle;
  }

  /**
   * Fill array with cryptographically secure random bytes
   */
  getRandomValues<T extends ArrayBufferView>(array: T): T {
    // Check capability before proceeding
    requireCapability(Capabilities.CRYPTO_RANDOM);

    if (
      !(
        array instanceof Int8Array ||
        array instanceof Uint8Array ||
        array instanceof Uint8ClampedArray ||
        array instanceof Int16Array ||
        array instanceof Uint16Array ||
        array instanceof Int32Array ||
        array instanceof Uint32Array ||
        array instanceof BigInt64Array ||
        array instanceof BigUint64Array
      )
    ) {
      throw new TypeError("Argument must be an integer-typed TypedArray");
    }

    if (array.byteLength > 65536) {
      throw new DOMException(
        "The ArrayBufferView's byte length exceeds the limit (65536)",
        "QuotaExceededError"
      );
    }

    const native = getNativeCryptoModule();
    if (native) {
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      native.getRandomValues(bytes);
      return array;
    }

    // Check if we're in test/debug mode via environment or global flag
    const isTestMode = (
      typeof process !== 'undefined' && 
      (process.env?.NODE_ENV === 'test' || process.env?.EXACT_ALLOW_INSECURE_CRYPTO === 'true')
    ) || (typeof (globalThis as any).__EXACT_TEST_MODE__ !== 'undefined');

    if (!isTestMode) {
      // In production, throw an error instead of using insecure fallback
      throw new DOMException(
        'crypto.getRandomValues requires native crypto module. ' +
        'The native module is not available and insecure fallbacks are disabled in production. ' +
        'Set EXACT_ALLOW_INSECURE_CRYPTO=true or __EXACT_TEST_MODE__=true for testing.',
        'NotSupportedError'
      );
    }

    // JS fallback for testing only (NOT cryptographically secure!)
    if (!isSilentMode()) {
      console.warn(
        "crypto.getRandomValues: Using INSECURE Math.random() fallback! " +
        "This is only acceptable in test environments."
      );
    }
    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }

  /**
   * Generate a random UUID v4
   */
  randomUUID(): `${string}-${string}-${string}-${string}-${string}` {
    // Check capability before proceeding
    requireCapability(Capabilities.CRYPTO_RANDOM);

    const native = getNativeCryptoModule();
    if (native) {
      return native.randomUUID() as `${string}-${string}-${string}-${string}-${string}`;
    }

    // JS fallback
    const bytes = new Uint8Array(16);
    this.getRandomValues(bytes);

    // Set version (4) and variant (10xx)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as `${string}-${string}-${string}-${string}-${string}`;
  }
}

// Helper to convert BufferSource to Uint8Array
function toUint8Array(data: BufferSource): Uint8Array {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError("Data must be an ArrayBuffer or ArrayBufferView");
}

// Simple SHA-256 implementation for testing (not optimized)
async function jsSHA256(data: Uint8Array): Promise<ArrayBuffer> {
  // Constants
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  // Initial hash values
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  // Pre-processing: add padding
  const msgLen = data.length;
  const bitLen = msgLen * 8;

  // Calculate padded length: message + 1 byte (0x80) + padding + 8 bytes (length)
  // Total must be multiple of 64
  let paddedLen = msgLen + 1 + 8; // minimum: msg + 0x80 + 64-bit length
  const remainder = paddedLen % 64;
  if (remainder > 0) {
    paddedLen += 64 - remainder;
  }
  if (paddedLen - msgLen - 1 < 8) {
    paddedLen += 64; // Need more space for length
  }

  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;

  // Append length as 64-bit big-endian (we only use 32 bits for length)
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen, false);

  // Process each 512-bit (64-byte) chunk
  for (let offset = 0; offset < paddedLen; offset += 64) {
    const W = new Uint32Array(64);

    // Copy chunk into first 16 words
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4, false);
    }

    // Extend to 64 words
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    // Initialize working variables
    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;

    // Main loop
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    // Add to hash
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  // Produce final hash
  const result = new ArrayBuffer(32);
  const resultView = new DataView(result);
  resultView.setUint32(0, h0, false);
  resultView.setUint32(4, h1, false);
  resultView.setUint32(8, h2, false);
  resultView.setUint32(12, h3, false);
  resultView.setUint32(16, h4, false);
  resultView.setUint32(20, h5, false);
  resultView.setUint32(24, h6, false);
  resultView.setUint32(28, h7, false);

  return result;
}

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

// DOMException for this module
class DOMException extends Error {
  readonly code: number = 0;
  constructor(message: string, name: string) {
    super(message);
    this.name = name;
  }
}

// =============================================================================
// Type Definitions
// =============================================================================

type AlgorithmIdentifier = string | { name: string };
type KeyFormat = "raw" | "spki" | "pkcs8" | "jwk";
type KeyUsage = "encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey";

interface CryptoKey {
  readonly type: string;
  readonly extractable: boolean;
  readonly algorithm: KeyAlgorithm;
  readonly usages: KeyUsage[];
}

interface KeyAlgorithm {
  name: string;
}

interface AesKeyAlgorithm extends KeyAlgorithm {
  length: number;
}

interface HmacKeyAlgorithm extends KeyAlgorithm {
  hash: { name: string };
  length: number;
}

interface RsaHashedKeyAlgorithm extends KeyAlgorithm {
  modulusLength: number;
  publicExponent: Uint8Array;
  hash: { name: string };
}

interface EcKeyAlgorithm extends KeyAlgorithm {
  namedCurve: string;
}

interface CryptoKeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
}

interface JsonWebKey {
  kty?: string;
  k?: string;
  alg?: string;
  ext?: boolean;
  key_ops?: string[];
  [key: string]: any;
}

// Algorithm parameter interfaces
interface AesCbcParams { name: string; iv: BufferSource; }
interface AesCtrParams { name: string; counter: BufferSource; length: number; }
interface AesGcmParams { name: string; iv: BufferSource; additionalData?: BufferSource; tagLength?: number; }
interface RsaOaepParams { name: string; label?: BufferSource; }
interface RsaPssParams { name: string; saltLength: number; }
interface EcdsaParams { name: string; hash: string | { name: string }; }
interface Pbkdf2Params { name: string; salt: BufferSource; iterations: number; hash: string | { name: string }; }
interface HkdfParams { name: string; salt: BufferSource; info: BufferSource; hash: string | { name: string }; }
interface EcdhKeyDeriveParams { name: string; public: CryptoKey; }

// Key generation parameter interfaces
interface AesKeyGenParams { name: string; length: number; }
interface HmacKeyGenParams { name: string; hash: string | { name: string }; length?: number; }
interface RsaHashedKeyGenParams { name: string; modulusLength: number; publicExponent: Uint8Array; hash: string | { name: string }; }
interface EcKeyGenParams { name: string; namedCurve: string; }
interface KmacKeyGenParams { name: string; length: number; }

// Import parameter interfaces
interface HmacImportParams { name: string; hash: string | { name: string }; length?: number; }
interface RsaHashedImportParams { name: string; hash: string | { name: string }; }
interface EcKeyImportParams { name: string; namedCurve: string; }

// =============================================================================
// ExactCryptoKey - Internal key implementation
// =============================================================================

export class ExactCryptoKey implements CryptoKey {
  readonly type: 'public' | 'private' | 'secret';
  readonly extractable: boolean;
  readonly algorithm: KeyAlgorithm;
  readonly usages: KeyUsage[];
  readonly _keyData: Uint8Array;

  constructor(
    type: 'public' | 'private' | 'secret',
    extractable: boolean,
    algorithm: KeyAlgorithm,
    usages: KeyUsage[],
    keyData: Uint8Array
  ) {
    this.type = type;
    this.extractable = extractable;
    this.algorithm = algorithm;
    this.usages = usages;
    this._keyData = keyData;
  }

  get [Symbol.toStringTag](): 'CryptoKey' {
    return 'CryptoKey';
  }
}

export { ExactCryptoKey as CryptoKey };

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Normalize algorithm identifier to object form
 */
function normalizeAlgorithm(algorithm: AlgorithmIdentifier | any): { name: string; [key: string]: any } {
  if (typeof algorithm === 'string') {
    return { name: algorithm };
  }
  return algorithm;
}

/**
 * Validate that a key can be used for the specified operation
 */
function validateKey(key: CryptoKey, operation: KeyUsage): void {
  if (!key.usages.includes(operation)) {
    throw new DOMException(
      `Key does not support the '${operation}' operation`,
      'InvalidAccessError'
    );
  }
}

/**
 * Normalize hash names like `sha256`, `SHA-256`, and `sha-256`.
 */
function normalizeHashName(hash: string): string {
  const normalized = hash.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  switch (normalized) {
    case "SHA1":
      return "SHA-1";
    case "SHA224":
      return "SHA-224";
    case "SHA256":
      return "SHA-256";
    case "SHA384":
      return "SHA-384";
    case "SHA512":
      return "SHA-512";
    default:
      throw new DOMException(`Unrecognized hash algorithm: ${hash}`, "NotSupportedError");
  }
}

/**
 * Return a platform subtle implementation for digest and HMAC fallbacks.
 * This avoids recursive calls into the same Exact crypto implementation.
 */
function getPlatformSubtle(): any | null {
  const g = globalThis as any;
  const candidate = g.crypto?.subtle;
  if (candidate && candidate !== crypto.subtle) {
    return candidate;
  }
  if (g.webcrypto?.subtle) {
    return g.webcrypto.subtle;
  }
  return null;
}

/**
 * Get hash output length in bits
 */
function getHashLength(hash: string): number {
  const normalized = normalizeHashName(hash);
  switch (normalized) {
    case "SHA-1":
      return 160;
    case "SHA-256":
      return 256;
    case "SHA-384":
      return 384;
    case "SHA-512":
      return 512;
    default:
      throw new DOMException(`Unsupported hash algorithm: ${hash}`, "NotSupportedError");
  }
}

/**
 * Get the HMAC key block size in bits for a hash. Per the WebCrypto spec this is
 * the default HMAC key length when none is supplied: 512 bits for SHA-1/224/256
 * and 1024 bits for SHA-384/512 (the hash's internal block size, NOT its digest
 * size).
 */
function getHmacBlockSize(hash: string): number {
  switch (normalizeHashName(hash)) {
    case "SHA-1":
    case "SHA-224":
    case "SHA-256":
      return 512;
    case "SHA-384":
    case "SHA-512":
      return 1024;
    default:
      throw new DOMException(`Unsupported hash algorithm: ${hash}`, "NotSupportedError");
  }
}

/**
 * Interpret a big-endian byte array as an unsigned integer. WebCrypto's
 * publicExponent is a variable-length big-endian BigInteger (BufferSource); the
 * canonical value [0x01,0x00,0x01] is only 3 bytes.
 */
function bigEndianBytesToNumber(bytes: Uint8Array): number {
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = value * 256 + bytes[i];
    if (!Number.isSafeInteger(value)) {
      throw new DOMException("publicExponent is too large", "OperationError");
    }
  }
  return value;
}

function normalizeRequiredHash(hash: string | { name: string } | undefined): string {
  if (typeof hash === 'string') {
    return normalizeHashName(hash);
  }
  if (hash && typeof hash === 'object' && typeof hash.name === 'string') {
    return normalizeHashName(hash.name);
  }
  throw new DOMException('Invalid hash algorithm', 'NotSupportedError');
}

/**
 * Return hash params in normalized format.
 */
function getHashParams(hash: string): { name: string; length: number } {
  const normalized = normalizeHashName(hash);
  return { name: normalized, length: getHashLength(normalized) / 8 };
}

/**
 * Base64URL encode
 */
function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): Uint8Array {
  // Add padding
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4) {
    padded += '=';
  }
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Constant-time comparison to prevent timing attacks
 */
function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Compute hash digest through platform subtle API when available.
 */
async function digestWithPlatformHash(hash: string, data: Uint8Array): Promise<ArrayBuffer> {
  const subtle = getPlatformSubtle();
  if (!subtle?.digest) {
    throw new DOMException(
      "Platform crypto.subtle.digest is not available for this fallback path",
      "NotSupportedError"
    );
  }
  const normalizedHash = normalizeHashName(hash);
  return subtle.digest({ name: normalizedHash }, data);
}

/**
 * Pure JS SHA-1 implementation
 */
async function jsSHA1(data: Uint8Array): Promise<ArrayBuffer> {
  let h0 = 0x67452301;
  let h1 = 0xEFCDAB89;
  let h2 = 0x98BADCFE;
  let h3 = 0x10325476;
  let h4 = 0xC3D2E1F0;

  const msgLen = data.length;
  const bitLen = msgLen * 8;
  let paddedLen = msgLen + 1 + 8;
  const remainder = paddedLen % 64;
  if (remainder > 0) paddedLen += 64 - remainder;
  if (paddedLen - msgLen - 1 < 8) paddedLen += 64;

  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen, false);

  function rotl(x: number, n: number): number {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  for (let offset = 0; offset < paddedLen; offset += 64) {
    const W = new Uint32Array(80);
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 80; i++) {
      W[i] = rotl(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4;

    for (let i = 0; i < 80; i++) {
      let f: number, k: number;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      const temp = (rotl(a, 5) + f + e + k + W[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const result = new ArrayBuffer(20);
  const rv = new DataView(result);
  rv.setUint32(0, h0, false);
  rv.setUint32(4, h1, false);
  rv.setUint32(8, h2, false);
  rv.setUint32(12, h3, false);
  rv.setUint32(16, h4, false);
  return result;
}

/**
 * Pure JS SHA-512/384 implementation using BigInt for 64-bit operations
 */
async function jsSHA512Core(data: Uint8Array, is384: boolean): Promise<ArrayBuffer> {
  // SHA-512 round constants (first 80 primes)
  const K: bigint[] = [
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
    0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
    0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
    0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
    0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
    0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
  ];

  const MASK64 = 0xffffffffffffffffn;

  function rotr64(x: bigint, n: number): bigint {
    return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
  }

  // Initial hash values
  let H: bigint[];
  if (is384) {
    H = [
      0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
      0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n,
    ];
  } else {
    H = [
      0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
      0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
    ];
  }

  // Padding
  const msgLen = data.length;
  const bitLen = BigInt(msgLen) * 8n;
  let paddedLen = msgLen + 1 + 16; // + 0x80 + 128-bit length
  const remainder = paddedLen % 128;
  if (remainder > 0) paddedLen += 128 - remainder;
  if (paddedLen - msgLen - 1 < 16) paddedLen += 128;

  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  // Append 128-bit length (big-endian) - we only use the low 64 bits
  const lenView = new DataView(padded.buffer);
  const lenHigh = Number((bitLen >> 32n) & 0xffffffffn);
  const lenLow = Number(bitLen & 0xffffffffn);
  lenView.setUint32(paddedLen - 8, lenHigh, false);
  lenView.setUint32(paddedLen - 4, lenLow, false);

  // Process each 1024-bit (128-byte) block
  const dv = new DataView(padded.buffer);
  for (let offset = 0; offset < paddedLen; offset += 128) {
    const W: bigint[] = new Array(80);
    for (let i = 0; i < 16; i++) {
      const hi = BigInt(dv.getUint32(offset + i * 8, false));
      const lo = BigInt(dv.getUint32(offset + i * 8 + 4, false));
      W[i] = ((hi << 32n) | lo) & MASK64;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7n);
      const s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6n);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) & MASK64;
    }

    let [a, b, c, d, e, f, g, h] = H;

    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ (~e & MASK64 & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & MASK64;

      h = g; g = f; f = e;
      e = (d + temp1) & MASK64;
      d = c; c = b; b = a;
      a = (temp1 + temp2) & MASK64;
    }

    H[0] = (H[0] + a) & MASK64;
    H[1] = (H[1] + b) & MASK64;
    H[2] = (H[2] + c) & MASK64;
    H[3] = (H[3] + d) & MASK64;
    H[4] = (H[4] + e) & MASK64;
    H[5] = (H[5] + f) & MASK64;
    H[6] = (H[6] + g) & MASK64;
    H[7] = (H[7] + h) & MASK64;
  }

  const outputWords = is384 ? 6 : 8;
  const result = new ArrayBuffer(outputWords * 8);
  const rv = new DataView(result);
  for (let i = 0; i < outputWords; i++) {
    rv.setUint32(i * 8, Number((H[i] >> 32n) & 0xffffffffn), false);
    rv.setUint32(i * 8 + 4, Number(H[i] & 0xffffffffn), false);
  }
  return result;
}

/**
 * SHA-384 digest (pure JS)
 */
async function jsSHA384(data: Uint8Array): Promise<ArrayBuffer> {
  return jsSHA512Core(data, true);
}

/**
 * SHA-512 digest (pure JS)
 */
async function jsSHA512(data: Uint8Array): Promise<ArrayBuffer> {
  return jsSHA512Core(data, false);
}

/**
 * Return the pure-JS digest function for a hash (works without native/platform).
 */
function getJsDigest(hash: string): (data: Uint8Array) => Promise<ArrayBuffer> {
  switch (normalizeHashName(hash)) {
    case "SHA-1":
      return jsSHA1;
    case "SHA-256":
      return jsSHA256;
    case "SHA-384":
      return jsSHA384;
    case "SHA-512":
      return jsSHA512;
    default:
      throw new DOMException(`Unsupported hash algorithm for HMAC: ${hash}`, "NotSupportedError");
  }
}

/**
 * Byte-accurate HMAC (RFC 2104) built on the pure-JS digests. Operates on the
 * raw key/data bytes so it is correct for arbitrary binary on every platform —
 * unlike the __exactHmacSync bridge, which corrupted bytes >= 0x80 (ENG-22983).
 */
async function jsHmac(key: Uint8Array, data: Uint8Array, hash: string): Promise<ArrayBuffer> {
  const normalizedHash = normalizeHashName(hash);
  const digest = getJsDigest(normalizedHash);
  const blockSize = getHmacBlockSize(normalizedHash) / 8; // 64 (SHA-1/256) or 128 (SHA-384/512) bytes

  // If the key is longer than the block size, hash it down first.
  let keyBytes = key;
  if (keyBytes.length > blockSize) {
    keyBytes = new Uint8Array(await digest(keyBytes));
  }

  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(keyBytes);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  // Inner: H(ipad || data)
  const innerData = new Uint8Array(blockSize + data.length);
  innerData.set(ipad);
  innerData.set(data, blockSize);
  const innerHash = new Uint8Array(await digest(innerData));

  // Outer: H(opad || innerHash)
  const outerData = new Uint8Array(blockSize + innerHash.length);
  outerData.set(opad);
  outerData.set(innerHash, blockSize);

  return digest(outerData);
}

/**
 * HMAC-SHA256 implementation (for JS fallback)
 */
async function jsHmacSha256(key: Uint8Array, data: Uint8Array): Promise<ArrayBuffer> {
  const blockSize = 64;
  const hashSize = 32;
  
  // If key is longer than block size, hash it
  let keyBytes = key;
  if (keyBytes.length > blockSize) {
    keyBytes = new Uint8Array(await jsSHA256(keyBytes));
  }
  
  // Pad key to block size
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(keyBytes);
  
  // Create ipad and opad
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }
  
  // Inner hash: H(ipad || data)
  const innerData = new Uint8Array(blockSize + data.length);
  innerData.set(ipad);
  innerData.set(data, blockSize);
  const innerHash = new Uint8Array(await jsSHA256(innerData));
  
  // Outer hash: H(opad || inner_hash)
  const outerData = new Uint8Array(blockSize + hashSize);
  outerData.set(opad);
  outerData.set(innerHash, blockSize);
  
  return jsSHA256(outerData);
}

/**
 * Convert Uint8Array to its underlying ArrayBuffer (handling offset/length)
 */
function uint8ArrayToArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}

/**
 * Convert Uint8Array to a binary string (one char per byte)
 */
function uint8ArrayToString(data: Uint8Array): string {
  let str = '';
  for (let i = 0; i < data.length; i++) {
    str += String.fromCharCode(data[i]);
  }
  return str;
}

/**
 * HKDF implementation (JS fallback) per RFC 5869
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
 * HKDF-Expand: iteratively compute T(i) = HMAC-Hash(PRK, T(i-1) || info || i) until enough bytes
 */
async function jsHkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  hash: string,
  length: number
): Promise<ArrayBuffer> {
  const hashLen = getHashLength(hash) / 8;

  // If salt is empty, use a hash-length block of zeros
  const actualSalt = salt.length > 0 ? salt : new Uint8Array(hashLen);

  // Extract: PRK = HMAC-Hash(salt, IKM)
  const prk = new Uint8Array(await jsHmac(actualSalt, ikm, hash));

  // Expand
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    prev = new Uint8Array(await jsHmac(prk, input, hash));
    okm.set(prev, (i - 1) * hashLen);
  }

  return okm.buffer.slice(0, length);
}

/**
 * Parse RSA PEM key (public or private) and extract JWK components.
 * This parses the base64-encoded DER within the PEM and extracts the
 * RSA parameters (n, e, d, p, q, dp, dq, qi) from the ASN.1 structure.
 */
function parseRsaPemToJwkComponents(pem: string, isPrivate: boolean): Record<string, string> {
  // Strip PEM headers and decode base64
  const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
  const der = base64Decode(b64);

  // Parse ASN.1 DER
  const parsed = parseAsn1(der, 0);

  if (isPrivate) {
    // PKCS#1 RSAPrivateKey or PKCS#8 PrivateKeyInfo
    // PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
    // PKCS#1: SEQUENCE { version, n, e, d, p, q, dp, dq, qi }
    let seq = parsed;
    if (seq.children && seq.children.length === 3 && seq.children[2].tag === 0x04) {
      // This is PKCS#8 - the RSAPrivateKey is inside the OCTET STRING
      seq = parseAsn1(seq.children[2].value as Uint8Array, 0);
    }
    if (!seq.children || seq.children.length < 9) {
      throw new DOMException('Invalid RSA private key structure', 'DataError');
    }
    // Skip version (index 0)
    return {
      n: base64UrlEncode(trimLeadingZero(seq.children[1].value as Uint8Array)),
      e: base64UrlEncode(trimLeadingZero(seq.children[2].value as Uint8Array)),
      d: base64UrlEncode(trimLeadingZero(seq.children[3].value as Uint8Array)),
      p: base64UrlEncode(trimLeadingZero(seq.children[4].value as Uint8Array)),
      q: base64UrlEncode(trimLeadingZero(seq.children[5].value as Uint8Array)),
      dp: base64UrlEncode(trimLeadingZero(seq.children[6].value as Uint8Array)),
      dq: base64UrlEncode(trimLeadingZero(seq.children[7].value as Uint8Array)),
      qi: base64UrlEncode(trimLeadingZero(seq.children[8].value as Uint8Array)),
    };
  } else {
    // PKCS#1 RSAPublicKey or SPKI SubjectPublicKeyInfo
    let seq = parsed;
    if (seq.children && seq.children.length === 2 && seq.children[1].tag === 0x03) {
      // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
      const bitStr = seq.children[1].value as Uint8Array;
      // BIT STRING has a leading byte for unused bits count (usually 0x00)
      seq = parseAsn1(bitStr.slice(1), 0);
    }
    if (!seq.children || seq.children.length < 2) {
      throw new DOMException('Invalid RSA public key structure', 'DataError');
    }
    return {
      n: base64UrlEncode(trimLeadingZero(seq.children[0].value as Uint8Array)),
      e: base64UrlEncode(trimLeadingZero(seq.children[1].value as Uint8Array)),
    };
  }
}

/**
 * Minimal ASN.1 DER parser
 */
interface Asn1Node {
  tag: number;
  value: Uint8Array;
  children?: Asn1Node[];
}

function parseAsn1(data: Uint8Array, offset: number): Asn1Node {
  const tag = data[offset];
  let lengthOffset = offset + 1;
  let length: number;

  if (data[lengthOffset] & 0x80) {
    const numLengthBytes = data[lengthOffset] & 0x7f;
    length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | data[lengthOffset + 1 + i];
    }
    lengthOffset += 1 + numLengthBytes;
  } else {
    length = data[lengthOffset];
    lengthOffset += 1;
  }

  const value = data.slice(lengthOffset, lengthOffset + length);
  const node: Asn1Node = { tag, value };

  // If it's a constructed type (SEQUENCE, SET), parse children
  if (tag === 0x30 || tag === 0x31) {
    node.children = [];
    let childOffset = 0;
    while (childOffset < value.length) {
      const child = parseAsn1(value, childOffset);
      node.children.push(child);
      // Compute child's total size
      let childLength = child.value.length;
      let headerLen = 2; // tag + length byte
      if (childLength >= 128) {
        let tmp = childLength;
        let numBytes = 0;
        while (tmp > 0) { numBytes++; tmp >>= 8; }
        headerLen = 2 + numBytes;
      }
      childOffset += headerLen + childLength;
    }
  }

  // For INTEGER, store raw value bytes (may have leading zero for positive)
  return node;
}

/**
 * Trim the leading zero byte from an ASN.1 INTEGER value
 * (ASN.1 uses a leading 0x00 to indicate a positive number when the high bit is set)
 */
function trimLeadingZero(data: Uint8Array): Uint8Array {
  if (data.length > 1 && data[0] === 0x00) {
    return data.slice(1);
  }
  return data;
}

/**
 * Standard base64 decode (not base64url)
 */
function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Standard base64 encode
 */
function base64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

/**
 * Decode a PEM-wrapped key (as stored in ExactCryptoKey._keyData) to its raw
 * DER bytes as an ArrayBuffer, for handing to a platform WebCrypto importKey.
 */
function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  const der = base64Decode(b64);
  return der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
}

/**
 * Sign an RSA message through a real platform WebCrypto when the host exposes
 * one, honouring the PSS scheme + saltLength and signing the raw message bytes.
 * Returns null when no platform subtle is available (caller falls back to the
 * native bridge). RSA keys are always stored as PKCS#8 PEM in _keyData.
 * (ENG-22983)
 */
async function platformRsaSign(
  scheme: "RSASSA-PKCS1-v1_5" | "RSA-PSS",
  hash: string,
  saltLength: number | undefined,
  key: ExactCryptoKey,
  data: Uint8Array
): Promise<ArrayBuffer | null> {
  const subtle = getPlatformSubtle();
  if (!subtle?.importKey || !subtle?.sign) return null;
  try {
    const der = pemToDer(uint8ArrayToString(key._keyData));
    const cryptoKey = await subtle.importKey(
      "pkcs8",
      der,
      { name: scheme, hash: { name: normalizeHashName(hash) } },
      false,
      ["sign"]
    );
    const signAlg = scheme === "RSA-PSS"
      ? { name: "RSA-PSS", saltLength: saltLength as number }
      : { name: "RSASSA-PKCS1-v1_5" };
    return await subtle.sign(signAlg, cryptoKey, data);
  } catch (e) {
    throw wrapNativeError(e, "OperationError");
  }
}

/**
 * Verify an RSA signature through a real platform WebCrypto when available.
 * Returns null when no platform subtle is available (caller falls back to the
 * native bridge). Public RSA keys are stored as SPKI PEM in _keyData.
 * (ENG-22983)
 */
async function platformRsaVerify(
  scheme: "RSASSA-PKCS1-v1_5" | "RSA-PSS",
  hash: string,
  saltLength: number | undefined,
  key: ExactCryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean | null> {
  const subtle = getPlatformSubtle();
  if (!subtle?.importKey || !subtle?.verify) return null;
  try {
    const der = pemToDer(uint8ArrayToString(key._keyData));
    const cryptoKey = await subtle.importKey(
      "spki",
      der,
      { name: scheme, hash: { name: normalizeHashName(hash) } },
      false,
      ["verify"]
    );
    const verifyAlg = scheme === "RSA-PSS"
      ? { name: "RSA-PSS", saltLength: saltLength as number }
      : { name: "RSASSA-PKCS1-v1_5" };
    return await subtle.verify(verifyAlg, cryptoKey, signature, data);
  } catch (e) {
    throw wrapNativeError(e, "OperationError");
  }
}

/**
 * ECDSA coordinate size in bytes for a named curve (r and s are each this wide
 * in the IEEE P1363 encoding).
 */
function getEcCoordSize(curve: string): number {
  switch (curve) {
    case "P-256":
    case "K-256":
    case "secp256k1":
      return 32;
    case "P-384":
      return 48;
    case "P-521":
      return 66;
    default:
      throw new DOMException(`Unsupported curve: ${curve}`, "NotSupportedError");
  }
}

/**
 * Strip all leading zero bytes, leaving at least one byte.
 */
function stripLeadingZeros(data: Uint8Array): Uint8Array {
  let i = 0;
  while (i < data.length - 1 && data[i] === 0) i++;
  return data.slice(i);
}

/**
 * Convert an X9.62 DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to
 * the raw fixed-length IEEE P1363 form r||s that WebCrypto uses (ENG-22983).
 */
function derToP1363(der: Uint8Array, coordSize: number): Uint8Array {
  const seq = parseAsn1(der, 0);
  if (seq.tag !== 0x30 || !seq.children || seq.children.length < 2) {
    throw new DOMException("Invalid DER ECDSA signature", "DataError");
  }
  const r = stripLeadingZeros(seq.children[0].value);
  const s = stripLeadingZeros(seq.children[1].value);
  if (r.length > coordSize || s.length > coordSize) {
    throw new DOMException("ECDSA signature component too large for curve", "DataError");
  }
  const out = new Uint8Array(coordSize * 2);
  out.set(r, coordSize - r.length);
  out.set(s, coordSize * 2 - s.length);
  return out;
}

/**
 * Convert a raw fixed-length IEEE P1363 ECDSA signature (r||s) to X9.62 DER
 * (SEQUENCE { INTEGER r, INTEGER s }) for the native verifier (ENG-22983).
 */
function p1363ToDer(sig: Uint8Array, coordSize: number): Uint8Array {
  if (sig.length !== coordSize * 2) {
    throw new DOMException("Invalid P1363 ECDSA signature length", "DataError");
  }
  const r = encodeAsn1Integer(addLeadingZero(stripLeadingZeros(sig.slice(0, coordSize))));
  const s = encodeAsn1Integer(addLeadingZero(stripLeadingZeros(sig.slice(coordSize))));
  return encodeAsn1Sequence(concatUint8Arrays([r, s]));
}

/**
 * Convert RSA JWK to PEM format
 * Constructs ASN.1 DER for PKCS#1 and wraps in PEM
 */
function rsaJwkToPem(jwk: JsonWebKey, isPrivate: boolean): string {
  if (isPrivate) {
    // PKCS#1 RSAPrivateKey
    const version = encodeAsn1Integer(new Uint8Array([0]));
    const n = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.n!)));
    const e = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.e!)));
    const d = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.d!)));
    const p = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.p!)));
    const q = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.q!)));
    const dp = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.dp!)));
    const dq = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.dq!)));
    const qi = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.qi!)));

    const inner = concatUint8Arrays([version, n, e, d, p, q, dp, dq, qi]);
    const seq = encodeAsn1Sequence(inner);

    // Wrap in PKCS#8 PrivateKeyInfo
    // SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING { seq } }
    const pkcs8Version = encodeAsn1Integer(new Uint8Array([0]));
    const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]); // OID 1.2.840.113549.1.1.1
    const nullTag = new Uint8Array([0x05, 0x00]);
    const algSeq = encodeAsn1Sequence(concatUint8Arrays([rsaOid, nullTag]));
    const octetStr = encodeAsn1Tag(0x04, seq);
    const pkcs8 = encodeAsn1Sequence(concatUint8Arrays([pkcs8Version, algSeq, octetStr]));

    const b64 = base64Encode(pkcs8);
    const lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN PRIVATE KEY-----\n' + lines.join('\n') + '\n-----END PRIVATE KEY-----\n';
  } else {
    // PKCS#1 RSAPublicKey wrapped in SubjectPublicKeyInfo (SPKI)
    const n = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.n!)));
    const e = encodeAsn1Integer(addLeadingZero(base64UrlDecode(jwk.e!)));
    const rsaPubKey = encodeAsn1Sequence(concatUint8Arrays([n, e]));

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    const nullTag = new Uint8Array([0x05, 0x00]);
    const algSeq = encodeAsn1Sequence(concatUint8Arrays([rsaOid, nullTag]));
    // BIT STRING: 0x00 prefix (no unused bits) + DER-encoded RSAPublicKey
    const bitStrContent = concatUint8Arrays([new Uint8Array([0x00]), rsaPubKey]);
    const bitStr = encodeAsn1Tag(0x03, bitStrContent);
    const spki = encodeAsn1Sequence(concatUint8Arrays([algSeq, bitStr]));

    const b64 = base64Encode(spki);
    const lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----\n';
  }
}

/** Encode ASN.1 INTEGER */
function encodeAsn1Integer(data: Uint8Array): Uint8Array {
  return encodeAsn1Tag(0x02, data);
}

/** Encode ASN.1 SEQUENCE */
function encodeAsn1Sequence(content: Uint8Array): Uint8Array {
  return encodeAsn1Tag(0x30, content);
}

/** Encode an ASN.1 TLV (tag-length-value) */
function encodeAsn1Tag(tag: number, content: Uint8Array): Uint8Array {
  const length = content.length;
  let header: Uint8Array;
  if (length < 128) {
    header = new Uint8Array([tag, length]);
  } else if (length < 256) {
    header = new Uint8Array([tag, 0x81, length]);
  } else if (length < 65536) {
    header = new Uint8Array([tag, 0x82, (length >> 8) & 0xff, length & 0xff]);
  } else {
    header = new Uint8Array([tag, 0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff]);
  }
  return concatUint8Arrays([header, content]);
}

/** Add leading zero byte if high bit is set (for ASN.1 positive INTEGER) */
function addLeadingZero(data: Uint8Array): Uint8Array {
  if (data.length > 0 && (data[0] & 0x80) !== 0) {
    const result = new Uint8Array(data.length + 1);
    result[0] = 0x00;
    result.set(data, 1);
    return result;
  }
  return data;
}

/** Concatenate multiple Uint8Arrays */
function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) totalLen += arr.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * PBKDF2-SHA256 implementation (for JS fallback)
 */
async function jsPbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLength: number
): Promise<ArrayBuffer> {
  const hashLength = 32; // SHA-256 output
  const numBlocks = Math.ceil(keyLength / hashLength);
  const result = new Uint8Array(numBlocks * hashLength);
  
  for (let block = 1; block <= numBlocks; block++) {
    // U1 = PRF(Password, Salt || INT(i))
    const blockData = new Uint8Array(salt.length + 4);
    blockData.set(salt);
    blockData[salt.length] = (block >> 24) & 0xff;
    blockData[salt.length + 1] = (block >> 16) & 0xff;
    blockData[salt.length + 2] = (block >> 8) & 0xff;
    blockData[salt.length + 3] = block & 0xff;
    
    let u = new Uint8Array(await jsHmacSha256(password, blockData));
    const f = new Uint8Array(u);
    
    // U2...Uc
    for (let i = 1; i < iterations; i++) {
      u = new Uint8Array(await jsHmacSha256(password, u));
      for (let j = 0; j < hashLength; j++) {
        f[j] ^= u[j];
      }
    }
    
    result.set(f, (block - 1) * hashLength);
  }
  
  return result.buffer.slice(0, keyLength);
}

// =============================================================================
// Singleton Export
// =============================================================================

export const crypto = new Crypto();
