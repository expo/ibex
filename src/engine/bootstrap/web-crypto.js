(function() {
  'use strict';

  var DOMException = globalThis.DOMException;
  var Promise = globalThis.Promise;
  var atob = globalThis.atob;
  var btoa = globalThis.btoa;

  // Helper: wrap native errors as DOMException with the appropriate name
  function wrapNativeError(e, defaultName) {
    if (e instanceof DOMException) return e;
    // Map known error message patterns to DOMException names
    var msg = (e && e.message) ? e.message : String(e);
    if (msg.indexOf('not supported') !== -1 || msg.indexOf('Unsupported') !== -1 || msg.indexOf('not available') !== -1 || msg.indexOf('unrecognized') !== -1) {
      return new DOMException(msg, 'NotSupportedError');
    }
    if (msg.indexOf('Invalid key') !== -1 || msg.indexOf('invalid key') !== -1 || msg.indexOf('Bad key') !== -1) {
      return new DOMException(msg, 'DataError');
    }
    if (msg.indexOf('not extractable') !== -1 || msg.indexOf('usage') !== -1) {
      return new DOMException(msg, 'InvalidAccessError');
    }
    return new DOMException(msg, defaultName || 'OperationError');
  }

  // getRandomValues - fills typed array with crypto-random values
  function getRandomValues(typedArray) {
    if (!typedArray || typeof typedArray.length !== 'number') {
      throw new TypeError('Expected a TypedArray');
    }
    // Only integer-typed TypedArrays are allowed (not Float32Array/Float64Array)
    if (!(typedArray instanceof Int8Array ||
          typedArray instanceof Uint8Array ||
          typedArray instanceof Uint8ClampedArray ||
          typedArray instanceof Int16Array ||
          typedArray instanceof Uint16Array ||
          typedArray instanceof Int32Array ||
          typedArray instanceof Uint32Array ||
          typedArray instanceof BigInt64Array ||
          typedArray instanceof BigUint64Array)) {
      throw new TypeError('Argument must be an integer-typed TypedArray');
    }
    if (typedArray.byteLength > 65536) {
      throw new DOMException('Quota exceeded', 'QuotaExceededError');
    }
    if (typeof __exactRandomBytes === 'function') {
      var bytes = __exactRandomBytes(typedArray.byteLength);
      var u8 = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
      for (var i = 0; i < bytes.length; i++) u8[i] = bytes[i];
    }
    return typedArray;
  }

  // randomUUID - generate a v4 UUID
  function randomUUID() {
    var bytes = new Uint8Array(16);
    getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
    var hex = '';
    for (var i = 0; i < 16; i++) {
      var h = bytes[i].toString(16);
      if (h.length === 1) h = '0' + h;
      hex += h;
      if (i === 3 || i === 5 || i === 7 || i === 9) hex += '-';
    }
    return hex;
  }

  // --- SubtleCrypto ---
  function normalizeAlgo(algo) {
    if (typeof algo === 'string') return { name: algo.toUpperCase() };
    if (algo && algo.name) return { name: algo.name.toUpperCase(), length: algo.length, hash: algo.hash, iv: algo.iv, counter: algo.counter, additionalData: algo.additionalData, tagLength: algo.tagLength, salt: algo.salt, iterations: algo.iterations, info: algo.info };
    throw new TypeError('Invalid algorithm');
  }

  function toBytes(data) {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (data instanceof Uint8Array) return data;
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    throw new TypeError('Expected BufferSource');
  }

  function CryptoKey(type, extractable, algorithm, usages, keyData) {
    this.type = type;
    this.extractable = extractable;
    this.algorithm = algorithm;
    this.usages = usages;
    this._keyData = keyData;
  }

  var subtle = {};

  // subtle.digest(algorithm, data) -> ArrayBuffer
  subtle.digest = function(algorithm, data) {
    var algo = normalizeAlgo(algorithm);
    var nameMap = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
    var hashName = nameMap[algo.name];
    if (!hashName) return Promise.reject(new DOMException('Unsupported digest algorithm: ' + algo.name, 'NotSupportedError'));
    var bytes = toBytes(data);
    // Convert to string for native bridge
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    if (typeof __exactHashRaw === 'function') {
      try {
        var result = __exactHashRaw(hashName, str);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    return Promise.reject(new DOMException('Native hash not available', 'NotSupportedError'));
  };

  // subtle.generateKey(algorithm, extractable, keyUsages) -> CryptoKey or CryptoKeyPair
  subtle.generateKey = function(algorithm, extractable, keyUsages) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'AES-GCM' || algo.name === 'AES-CBC' || algo.name === 'AES-CTR') {
      var length = algo.length || 256;
      if (length !== 128 && length !== 192 && length !== 256) {
        return Promise.reject(new DOMException('Invalid key length: ' + length, 'OperationError'));
      }
      var keyBytes = new Uint8Array(length / 8);
      getRandomValues(keyBytes);
      var key = new CryptoKey('secret', extractable, { name: algo.name, length: length }, keyUsages, keyBytes);
      return Promise.resolve(key);
    }
    if (algo.name === 'HMAC') {
      var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
      var hlen = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
      var klen = algo.length ? (algo.length / 8) : (hlen[hashAlgo.toUpperCase()] || 32);
      var hmacKey = new Uint8Array(klen);
      getRandomValues(hmacKey);
      var key = new CryptoKey('secret', extractable, { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: klen * 8 }, keyUsages, hmacKey);
      return Promise.resolve(key);
    }
    // Ed25519 / X25519 key pair generation via native bridge
    if (algo.name === 'ED25519' || algo.name === 'EDDSA') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        try {
          var result = __exactGenerateKeyPairSync('ed25519', {});
          var algorithmInfo = { name: 'Ed25519' };
          var pubKeyData = new TextEncoder().encode(result.publicKey);
          var privKeyData = new TextEncoder().encode(result.privateKey);
          return Promise.resolve({
            publicKey: new CryptoKey('public', true, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'verify'; }), pubKeyData),
            privateKey: new CryptoKey('private', extractable, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'sign'; }), privKeyData)
          });
        } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
      }
      return Promise.reject(new DOMException('Native crypto not available for Ed25519 key generation', 'NotSupportedError'));
    }
    if (algo.name === 'X25519') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        try {
          var result = __exactGenerateKeyPairSync('x25519', {});
          var algorithmInfo = { name: 'X25519' };
          var pubKeyData = new TextEncoder().encode(result.publicKey);
          var privKeyData = new TextEncoder().encode(result.privateKey);
          return Promise.resolve({
            publicKey: new CryptoKey('public', true, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'deriveBits' || u === 'deriveKey'; }), pubKeyData),
            privateKey: new CryptoKey('private', extractable, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'deriveBits' || u === 'deriveKey'; }), privKeyData)
          });
        } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
      }
      return Promise.reject(new DOMException('Native crypto not available for X25519 key generation', 'NotSupportedError'));
    }
    // RSA key pair generation via native bridge
    if (algo.name === 'RSA-OAEP' || algo.name === 'RSASSA-PKCS1-V1_5' || algo.name === 'RSA-PSS') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        try {
          var modulusLength = algo.modulusLength || 2048;
          var publicExponent = 65537;
          if (algo.publicExponent instanceof Uint8Array) {
            var dv = new DataView(algo.publicExponent.buffer, algo.publicExponent.byteOffset, algo.publicExponent.byteLength);
            publicExponent = dv.getUint32(algo.publicExponent.byteLength - 4, false);
          }
          var result = __exactGenerateKeyPairSync('rsa', { modulusLength: modulusLength, publicExponent: publicExponent });
          var hashName = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
          var algorithmInfo = { name: algo.name, modulusLength: modulusLength, publicExponent: algo.publicExponent, hash: { name: hashName } };
          var pubKeyData = new TextEncoder().encode(result.publicKey);
          var privKeyData = new TextEncoder().encode(result.privateKey);
          return Promise.resolve({
            publicKey: new CryptoKey('public', true, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'encrypt' || u === 'verify' || u === 'wrapKey'; }), pubKeyData),
            privateKey: new CryptoKey('private', extractable, algorithmInfo,
              keyUsages.filter(function(u) { return u === 'decrypt' || u === 'sign' || u === 'unwrapKey'; }), privKeyData)
          });
        } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
      }
      return Promise.reject(new DOMException('Native crypto not available for RSA key generation', 'NotSupportedError'));
    }
    // ECDSA / ECDH key pair generation via native bridge
    if (algo.name === 'ECDSA' || algo.name === 'ECDH') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        try {
          var result = __exactGenerateKeyPairSync('ec', { namedCurve: algo.namedCurve });
          var algorithmInfo = { name: algo.name, namedCurve: algo.namedCurve };
          var pubKeyData = new TextEncoder().encode(result.publicKey);
          var privKeyData = new TextEncoder().encode(result.privateKey);
          var pubUsages = algo.name === 'ECDSA'
            ? keyUsages.filter(function(u) { return u === 'verify'; })
            : keyUsages.filter(function(u) { return u === 'deriveBits' || u === 'deriveKey'; });
          var privUsages = algo.name === 'ECDSA'
            ? keyUsages.filter(function(u) { return u === 'sign'; })
            : keyUsages.filter(function(u) { return u === 'deriveBits' || u === 'deriveKey'; });
          return Promise.resolve({
            publicKey: new CryptoKey('public', true, algorithmInfo, pubUsages, pubKeyData),
            privateKey: new CryptoKey('private', extractable, algorithmInfo, privUsages, privKeyData)
          });
        } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
      }
      return Promise.reject(new DOMException('Native crypto not available for EC key generation', 'NotSupportedError'));
    }
    return Promise.reject(new DOMException('Unsupported algorithm for generateKey: ' + algo.name, 'NotSupportedError'));
  };

  // subtle.importKey(format, keyData, algorithm, extractable, keyUsages) -> CryptoKey
  subtle.importKey = function(format, keyData, algorithm, extractable, keyUsages) {
    // Normalize tentative "raw-secret" format to "raw"
    if (format === 'raw-secret') format = 'raw';
    var algo = normalizeAlgo(algorithm);
    if (format === 'raw') {
      var raw = toBytes(keyData);
      var keyAlgo = algo;
      if (algo.name === 'HMAC') {
        var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
        keyAlgo = { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: raw.length * 8 };
      } else if (algo.name === 'PBKDF2' || algo.name === 'HKDF') {
        keyAlgo = { name: algo.name };
      }
      var key = new CryptoKey('secret', extractable, keyAlgo, keyUsages, new Uint8Array(raw));
      return Promise.resolve(key);
    }
    if (format === 'jwk') {
      var jwk = keyData;
      if (jwk.kty === 'oct' && jwk.k) {
        var raw = base64urlDecode(jwk.k);
        var keyAlgo = algo;
        if (algo.name === 'HMAC') {
          var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
          keyAlgo = { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: raw.length * 8 };
        }
        var key = new CryptoKey('secret', extractable, keyAlgo, keyUsages, raw);
        return Promise.resolve(key);
      }
      return Promise.reject(new DOMException('Unsupported JWK key type: ' + jwk.kty, 'NotSupportedError'));
    }
    return Promise.reject(new DOMException('Unsupported key format: ' + format, 'NotSupportedError'));
  };

  // Base64url encode/decode helpers for JWK
  function base64urlEncode(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    var b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function base64urlDecode(str) {
    var padded = str.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // subtle.exportKey(format, key) -> ArrayBuffer or JsonWebKey
  subtle.exportKey = function(format, key) {
    if (!key.extractable) return Promise.reject(new DOMException('Key is not extractable', 'InvalidAccessError'));
    if (format === 'raw') {
      return Promise.resolve(key._keyData.buffer.slice(key._keyData.byteOffset, key._keyData.byteOffset + key._keyData.byteLength));
    }
    if (format === 'jwk') {
      var algName = key.algorithm && key.algorithm.name ? key.algorithm.name.toUpperCase() : '';
      var jwk = { kty: 'oct', k: base64urlEncode(key._keyData), ext: key.extractable, key_ops: key.usages };
      if (algName === 'AES-GCM') { jwk.alg = 'A' + key.algorithm.length + 'GCM'; }
      else if (algName === 'AES-CBC') { jwk.alg = 'A' + key.algorithm.length + 'CBC'; }
      else if (algName === 'AES-CTR') { jwk.alg = 'A' + key.algorithm.length + 'CTR'; }
      else if (algName === 'HMAC') {
        var hashName = key.algorithm.hash && typeof key.algorithm.hash === 'object' ? key.algorithm.hash.name : (key.algorithm.hash || 'SHA-256');
        var hmacAlgMap = { 'SHA-1': 'HS1', 'SHA-256': 'HS256', 'SHA-384': 'HS384', 'SHA-512': 'HS512' };
        jwk.alg = hmacAlgMap[hashName] || 'HS256';
      }
      return Promise.resolve(jwk);
    }
    return Promise.reject(new DOMException('Unsupported export format: ' + format, 'NotSupportedError'));
  };

  // subtle.encrypt(algorithm, key, data) -> ArrayBuffer
  subtle.encrypt = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    var plaintext = toBytes(data);
    if (algo.name === 'AES-CBC') {
      if (!algo.iv) return Promise.reject(new DOMException('AES-CBC requires iv', 'OperationError'));
      var iv = toBytes(algo.iv);
      if (typeof __exactAesCbcEncrypt !== 'function') return Promise.reject(new DOMException('AES-CBC not available', 'NotSupportedError'));
      try {
        var result = __exactAesCbcEncrypt(key._keyData, iv, plaintext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'AES-CTR') {
      if (!algo.counter) return Promise.reject(new DOMException('AES-CTR requires counter', 'OperationError'));
      var counter = toBytes(algo.counter);
      if (typeof __exactAesCtrEncrypt !== 'function') return Promise.reject(new DOMException('AES-CTR not available', 'NotSupportedError'));
      try {
        var result = __exactAesCtrEncrypt(key._keyData, counter, plaintext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'AES-GCM') {
      if (!algo.iv) return Promise.reject(new DOMException('AES-GCM requires iv', 'OperationError'));
      var iv = toBytes(algo.iv);
      var aad = algo.additionalData ? toBytes(algo.additionalData) : undefined;
      var tagLength = algo.tagLength || 128;
      if (typeof __exactAesGcmEncrypt !== 'function') return Promise.reject(new DOMException('AES-GCM not available', 'NotSupportedError'));
      try {
        var result = __exactAesGcmEncrypt(key._keyData, iv, plaintext, aad, tagLength);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    return Promise.reject(new DOMException('Unsupported encrypt algorithm: ' + algo.name, 'NotSupportedError'));
  };

  // subtle.decrypt(algorithm, key, data) -> ArrayBuffer
  subtle.decrypt = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    var ciphertext = toBytes(data);
    if (algo.name === 'AES-CBC') {
      if (!algo.iv) return Promise.reject(new DOMException('AES-CBC requires iv', 'OperationError'));
      var iv = toBytes(algo.iv);
      if (typeof __exactAesCbcDecrypt !== 'function') return Promise.reject(new DOMException('AES-CBC not available', 'NotSupportedError'));
      try {
        var result = __exactAesCbcDecrypt(key._keyData, iv, ciphertext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'AES-CTR') {
      if (!algo.counter) return Promise.reject(new DOMException('AES-CTR requires counter', 'OperationError'));
      var counter = toBytes(algo.counter);
      if (typeof __exactAesCtrEncrypt !== 'function') return Promise.reject(new DOMException('AES-CTR not available', 'NotSupportedError'));
      try {
        // CTR mode encrypt and decrypt are the same operation
        var result = __exactAesCtrEncrypt(key._keyData, counter, ciphertext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'AES-GCM') {
      if (!algo.iv) return Promise.reject(new DOMException('AES-GCM requires iv', 'OperationError'));
      var iv = toBytes(algo.iv);
      var aad = algo.additionalData ? toBytes(algo.additionalData) : undefined;
      var tagLength = algo.tagLength || 128;
      if (typeof __exactAesGcmDecrypt !== 'function') return Promise.reject(new DOMException('AES-GCM not available', 'NotSupportedError'));
      try {
        var result = __exactAesGcmDecrypt(key._keyData, iv, ciphertext, aad, tagLength);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    return Promise.reject(new DOMException('Unsupported decrypt algorithm: ' + algo.name, 'NotSupportedError'));
  };

  // subtle.sign(algorithm, key, data) -> ArrayBuffer
  subtle.sign = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'HMAC') {
      var rawHash = key.algorithm && key.algorithm.hash ? key.algorithm.hash : null;
      var hashAlgo = typeof rawHash === 'string' ? rawHash : (rawHash && rawHash.name ? rawHash.name : 'SHA-256');
      var nameMap = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
      var hashName = nameMap[hashAlgo.toUpperCase()];
      if (!hashName) return Promise.reject(new DOMException('Unsupported hash: ' + hashAlgo, 'NotSupportedError'));
      var bytes = toBytes(data);
      // Convert to strings for native bridge
      var dataStr = '';
      for (var i = 0; i < bytes.length; i++) dataStr += String.fromCharCode(bytes[i]);
      var keyStr = '';
      for (var j = 0; j < key._keyData.length; j++) keyStr += String.fromCharCode(key._keyData[j]);
      if (typeof __exactHmacSync !== 'function') return Promise.reject(new DOMException('HMAC not available', 'NotSupportedError'));
      try { var hex = __exactHmacSync(hashName, keyStr, dataStr); } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
      var result = new Uint8Array(hex.length / 2);
      for (var k = 0; k < hex.length; k += 2) {
        result[k / 2] = parseInt(hex.substr(k, 2), 16);
      }
      return Promise.resolve(result.buffer);
    }
    if (algo.name === 'ECDSA') {
      if (typeof __exactEcdsaSign !== 'function') return Promise.reject(new DOMException('ECDSA not available', 'NotSupportedError'));
      try {
        var ecHash = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
        var ecCurve = key.algorithm && key.algorithm.namedCurve ? key.algorithm.namedCurve : 'P-256';
        var ecResult = __exactEcdsaSign(ecCurve, ecHash, key._keyData, toBytes(data));
        return Promise.resolve(ecResult.buffer.slice(ecResult.byteOffset, ecResult.byteOffset + ecResult.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'ED25519' || algo.name === 'EDDSA') {
      if (typeof __exactEd25519Sign !== 'function') return Promise.reject(new DOMException('Ed25519 not available', 'NotSupportedError'));
      try {
        var edKeyData = key._keyData;
        var edPrivData = edKeyData.length === 64 ? edKeyData.slice(0, 32) : edKeyData;
        var edResult = __exactEd25519Sign(edPrivData, toBytes(data));
        return Promise.resolve(edResult.buffer.slice(edResult.byteOffset, edResult.byteOffset + edResult.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    return Promise.reject(new DOMException('Unsupported sign algorithm: ' + algo.name, 'NotSupportedError'));
  };

  // subtle.verify(algorithm, key, signature, data) -> boolean
  subtle.verify = function(algorithm, key, signature, data) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'ECDSA') {
      if (typeof __exactEcdsaVerify !== 'function') return Promise.reject(new DOMException('ECDSA not available', 'NotSupportedError'));
      try {
        var ecHash = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
        var ecCurve = key.algorithm && key.algorithm.namedCurve ? key.algorithm.namedCurve : 'P-256';
        return Promise.resolve(__exactEcdsaVerify(ecCurve, ecHash, key._keyData, toBytes(signature), toBytes(data)));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    if (algo.name === 'ED25519' || algo.name === 'EDDSA') {
      if (typeof __exactEd25519Verify !== 'function') return Promise.reject(new DOMException('Ed25519 not available', 'NotSupportedError'));
      try {
        return Promise.resolve(__exactEd25519Verify(key._keyData, toBytes(signature), toBytes(data)));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    // HMAC verify via sign-and-compare
    return subtle.sign(algorithm, key, data).then(function(computed) {
      var sig = toBytes(signature);
      var comp = new Uint8Array(computed);
      if (sig.length !== comp.length) return false;
      var diff = 0;
      for (var i = 0; i < sig.length; i++) diff |= sig[i] ^ comp[i];
      return diff === 0;
    });
  };

  // subtle.deriveBits(algorithm, baseKey, length) -> ArrayBuffer
  subtle.deriveBits = function(algorithm, baseKey, length) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'PBKDF2') {
      if (!algo.salt || !algo.iterations) return Promise.reject(new DOMException('PBKDF2 requires salt and iterations', 'OperationError'));
      var salt = toBytes(algo.salt);
      var hashName = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
      if (typeof __exactPbkdf2 !== 'function') return Promise.reject(new DOMException('PBKDF2 not available', 'NotSupportedError'));
      try {
        var result = __exactPbkdf2(baseKey._keyData, salt, algo.iterations, length / 8, hashName);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(wrapNativeError(e, 'OperationError')); }
    }
    return Promise.reject(new DOMException('Unsupported deriveBits algorithm: ' + algo.name, 'NotSupportedError'));
  };

  // subtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) -> CryptoKey
  subtle.deriveKey = function(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) {
    var derived = normalizeAlgo(derivedKeyAlgorithm);
    var length = derived.length || 256;
    return subtle.deriveBits(algorithm, baseKey, length).then(function(bits) {
      return subtle.importKey('raw', bits, derivedKeyAlgorithm, extractable, keyUsages);
    });
  };

  // subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm) -> ArrayBuffer
  subtle.wrapKey = function(format, key, wrappingKey, wrapAlgorithm) {
    return subtle.exportKey(format, key).then(function(exported) {
      return subtle.encrypt(wrapAlgorithm, wrappingKey, exported);
    });
  };

  // subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages)
  subtle.unwrapKey = function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
    return subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey).then(function(rawKey) {
      return subtle.importKey(format, rawKey, unwrappedKeyAlgorithm, extractable, keyUsages);
    });
  };

  // Set globalThis.crypto — only if the full SubtleCrypto from the JS runtime
  // bundle (bootstrap.ts) hasn't been installed yet. The full implementation
  // supports Ed25519, ECDSA, RSA, ECDH, X25519, PBKDF2, HKDF, etc. while this
  // shim only handles AES and HMAC. The full implementation marks itself with
  // __exactFullSubtle so we can detect it.
  if (typeof globalThis.crypto === 'object' && globalThis.crypto !== null &&
      typeof globalThis.crypto.subtle === 'object' && globalThis.crypto.subtle !== null &&
      globalThis.crypto.subtle.__exactFullSubtle === true) {
    // Full SubtleCrypto already installed by runtime bundle — skip overwrite.
    // Only fill in missing top-level methods if needed.
    if (typeof globalThis.crypto.getRandomValues !== 'function') {
      globalThis.crypto.getRandomValues = getRandomValues;
    }
    if (typeof globalThis.crypto.randomUUID !== 'function') {
      globalThis.crypto.randomUUID = randomUUID;
    }
  } else {
    // Create crypto object with read-only subtle property (matching browser behavior).
    // In browsers/Bun, crypto.subtle is a getter-only property — assigning to it is
    // silently ignored. This prevents test code from accidentally clobbering subtle.
    var cryptoObj = {
      getRandomValues: getRandomValues,
      randomUUID: randomUUID,
    };
    Object.defineProperty(cryptoObj, 'subtle', {
      get: function() { return subtle; },
      set: function() { /* no-op, matching browser behavior */ },
      enumerable: true,
      configurable: true,
    });
    globalThis.crypto = cryptoObj;
  }

  // Expose CryptoKey and SubtleCrypto as globals (WPT tests check instanceof)
  CryptoKey.prototype[Symbol.toStringTag] = 'CryptoKey';
  if (typeof globalThis.CryptoKey === 'undefined') {
    globalThis.CryptoKey = CryptoKey;
  }

  // SubtleCrypto constructor for instanceof checks
  function SubtleCrypto() {}
  SubtleCrypto.prototype = subtle;
  SubtleCrypto.prototype[Symbol.toStringTag] = 'SubtleCrypto';
  SubtleCrypto.prototype.constructor = SubtleCrypto;
  if (typeof globalThis.SubtleCrypto === 'undefined') {
    globalThis.SubtleCrypto = SubtleCrypto;
  }
})();
