var _CipherStreamTransform = null;
try {
  _CipherStreamTransform = require('stream').Transform;
} catch (e) {}

function randomBytes(len) {
  if (typeof __exactRandomBytes !== 'function') {
    throw new Error('Exact crypto not available');
  }
  var bytes = __exactRandomBytes(len);
  // Wrap as Buffer if available, so .toString('hex') etc. work
  if (typeof Buffer !== 'undefined' && Buffer.from) {
    return Buffer.from(bytes);
  }
  return bytes;
}

// --- createHash(algorithm) ---
function Hash(algorithm) {
  this._algo = algorithm.toLowerCase().replace('-', '');
  this._chunks = [];
}
Hash.prototype.update = function(data, encoding) {
  if (typeof data === 'string') {
    this._chunks.push(data);
  } else if (data && data.length !== undefined) {
    // Buffer or Uint8Array — convert to string for native bridge
    var str = '';
    for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
    this._chunks.push(str);
  }
  return this;
};
Hash.prototype.digest = function(encoding) {
  var joined = this._chunks.join('');
  if (!encoding || encoding === 'buffer') {
    // Return raw bytes as Buffer
    if (typeof __exactHashRaw === 'function') {
      var raw = __exactHashRaw(this._algo, joined);
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(raw);
      return raw;
    }
  }
  if (typeof __exactHashSync === 'function') {
    var hex = __exactHashSync(this._algo, joined);
    if (!encoding || encoding === 'hex') return hex;
    if (encoding === 'base64') {
      // hex to base64
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof btoa === 'function') {
        var str = '';
        for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
        return btoa(str);
      }
    }
    if (encoding === 'buffer') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
      return new Uint8Array(bytes);
    }
    return hex;
  }
  throw new Error('Native hash not available');
};
Hash.prototype.copy = function() {
  var h = new Hash(this._algo);
  h._chunks = this._chunks.slice();
  return h;
};

function createHash(algorithm) {
  return new Hash(algorithm);
}

// --- createHmac(algorithm, key) ---
function Hmac(algorithm, key) {
  this._algo = algorithm.toLowerCase().replace('-', '');
  this._key = typeof key === 'string' ? key : '';
  if (typeof key !== 'string' && key && key.length !== undefined) {
    var str = '';
    for (var i = 0; i < key.length; i++) str += String.fromCharCode(key[i]);
    this._key = str;
  }
  this._chunks = [];
}
Hmac.prototype.update = function(data, encoding) {
  if (typeof data === 'string') {
    this._chunks.push(data);
  } else if (data && data.length !== undefined) {
    var str = '';
    for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
    this._chunks.push(str);
  }
  return this;
};
Hmac.prototype.digest = function(encoding) {
  var joined = this._chunks.join('');
  if (typeof __exactHmacSync === 'function') {
    var hex = __exactHmacSync(this._algo, this._key, joined);
    if (!encoding || encoding === 'hex') return hex;
    if (encoding === 'base64') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof btoa === 'function') {
        var str = '';
        for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
        return btoa(str);
      }
    }
    if (encoding === 'buffer') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
      return new Uint8Array(bytes);
    }
    return hex;
  }
  throw new Error('Native HMAC not available');
};

function createHmac(algorithm, key) {
  return new Hmac(algorithm, key);
}

// --- getHashes() ---
function getHashes() {
  return ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
}

// --- timingSafeEqual ---
function timingSafeEqual(a, b) {
  if (a.length !== b.length) throw new RangeError('Input buffers must have the same byte length');
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function randomUUID(options) {
  if (options !== undefined && (typeof options !== 'object' || options === null)) {
    var err = new TypeError('[ERR_INVALID_ARG_TYPE]: The "options" argument must be of type object. Received type ' + typeof options);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (options && options.disableEntropyCache !== undefined && typeof options.disableEntropyCache !== 'boolean') {
    var err2 = new TypeError('[ERR_INVALID_ARG_TYPE]: The "options.disableEntropyCache" argument must be of type boolean. Received type ' + typeof options.disableEntropyCache);
    err2.code = 'ERR_INVALID_ARG_TYPE';
    throw err2;
  }
  // Use globalThis.crypto if available
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  // Fallback: generate UUID v4 from randomBytes
  var bytes = randomBytes(16);
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = typeof bytes[i] === 'number' ? bytes[i] : bytes.charCodeAt ? bytes.charCodeAt(i) : 0;
    hex += (b < 16 ? '0' : '') + b.toString(16);
  }
  // Set version (4) and variant (8, 9, a, or b)
  return hex.substr(0, 8) + '-' + hex.substr(8, 4) + '-4' + hex.substr(13, 3) + '-' +
    ((parseInt(hex.substr(16, 2), 16) & 0x3f | 0x80).toString(16)) + hex.substr(18, 2) + '-' + hex.substr(20, 12);
}

function randomInt(min, max) {
  if (max === undefined) { max = min; min = 0; }
  var range = max - min;
  var bytes = randomBytes(4);
  var b0 = typeof bytes[0] === 'number' ? bytes[0] : bytes.charCodeAt(0);
  var b1 = typeof bytes[1] === 'number' ? bytes[1] : bytes.charCodeAt(1);
  var b2 = typeof bytes[2] === 'number' ? bytes[2] : bytes.charCodeAt(2);
  var b3 = typeof bytes[3] === 'number' ? bytes[3] : bytes.charCodeAt(3);
  var val = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  return min + (val % range);
}

function randomFillSync(buf, offset, size) {
  offset = offset || 0;
  size = size || (buf.length - offset);
  var bytes = randomBytes(size);
  for (var i = 0; i < size; i++) {
    buf[offset + i] = typeof bytes[i] === 'number' ? bytes[i] : (bytes.charCodeAt ? bytes.charCodeAt(i) : 0);
  }
  return buf;
}

function _toBytes(value) {
  if (value === null || value === undefined) return new Uint8Array(0);
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var asView = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return asView;
  }
  if (typeof value === 'string') {
    var fromString = new Uint8Array(value.length);
    for (var i = 0; i < value.length; i++) fromString[i] = value.charCodeAt(i);
    return fromString;
  }
  if (typeof value.length === 'number') {
    var fromArray = new Uint8Array(value.length);
    for (var j = 0; j < value.length; j++) fromArray[j] = value[j];
    return fromArray;
  }
  return new Uint8Array(0);
}

function _normalizeKdfDigest(digest) {
  var normalized = (digest || 'sha1').toString().toLowerCase().replace(/-/g, '');
  if (normalized === 'md4') return 'md4';
  if (normalized === 'md5') return 'md5';
  if (normalized === 'sha1') return 'sha1';
  if (normalized === 'sha224') return 'sha224';
  if (normalized === 'sha256') return 'sha256';
  if (normalized === 'sha384') return 'sha384';
  if (normalized === 'sha512') return 'sha512';
  return 'sha256';
}

// --- pbkdf2Sync(password, salt, iterations, keylen, digest) ---
function pbkdf2Sync(password, salt, iterations, keylen, digest) {
  if (typeof __exactPbkdf2 !== 'function') {
    throw new Error('pbkdf2 not available');
  }
  if (typeof iterations !== 'number' || iterations <= 0) {
    throw new TypeError('Invalid iterations value');
  }
  if (typeof keylen !== 'number' || keylen <= 0) {
    throw new TypeError('Invalid keylen value');
  }
  var passBytes = _toBytes(password);
  var saltBytes = _toBytes(salt);
  var hashName = _normalizeKdfDigest(digest);
  var result = __exactPbkdf2(passBytes, saltBytes, iterations, keylen, hashName);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function pbkdf2(password, salt, iterations, keylen, digest, callback) {
  if (typeof digest === 'function') { callback = digest; digest = 'sha1'; }
  try {
    var result = pbkdf2Sync(password, salt, iterations, keylen, digest);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

// --- hkdfSync / hkdf ---
function hkdfSync(digest, ikm, salt, info, keylen) {
  if (typeof __exactHkdf !== 'function') {
    throw new Error('hkdf not available in this runtime');
  }
  var ikmBytes = _toBytes(ikm);
  var saltBytes = _toBytes(salt);
  var infoBytes = _toBytes(info);
  var hashName = _normalizeKdfDigest(digest);
  var result = __exactHkdf(hashName, ikmBytes, saltBytes, infoBytes, keylen);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function hkdf(digest, ikm, salt, info, keylen, callback) {
  try {
    var result = hkdfSync(digest, ikm, salt, info, keylen);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

// --- KeyObject ---
function KeyObject(type, data) {
  this._type = type; // 'secret', 'public', 'private'
  this._data = data;
}
Object.defineProperty(KeyObject.prototype, 'type', {
  get: function() { return this._type; },
  enumerable: true, configurable: true
});
Object.defineProperty(KeyObject.prototype, 'symmetricKeySize', {
  get: function() { return this._type === 'secret' ? this._data.length : undefined; },
  enumerable: true, configurable: true
});
KeyObject.prototype.export = function(options) {
  if (!options || !options.format || options.format === 'buffer') return this._data;
  return this._data;
};
KeyObject.prototype.equals = function(other) {
  if (!(other instanceof KeyObject)) return false;
  if (this._type !== other._type) return false;
  var a = _toBytes(this._data), b = _toBytes(other._data);
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

function createSecretKey(material, encoding) {
  var bytes;
  if (typeof material === 'string') {
    bytes = _toBytes(material);
  } else {
    bytes = _toBytes(material);
  }
  return new KeyObject('secret', bytes);
}

function createPublicKey(key) {
  var raw = (key && typeof key === 'object' && key.key) ? key.key : key;
  return new KeyObject('public', raw);
}

function createPrivateKey(key) {
  var raw = (key && typeof key === 'object' && key.key) ? key.key : key;
  return new KeyObject('private', raw);
}

function generateKeySync(type, options) {
  var len = (options && options.length) || 256;
  var bytes = randomBytes(len / 8);
  return createSecretKey(bytes);
}

// --- createCipheriv / createDecipheriv ---
function _toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) return new Uint8Array(data);
  if (typeof data === 'string') {
    var bytes = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(data);
}

function _normalizeCipherAlgorithm(algorithm) {
  var normalized = (algorithm || '').toString().toLowerCase().replace(/_/g, '-');
  normalized = normalized.replace(/\s+/g, '');
  normalized = normalized.replace(/^id-/, '');
  if (/^aes\d{3}(gcm|cbc|ctr|ccm)$/.test(normalized)) {
    normalized = normalized.replace(/^aes(\d{3})(gcm|cbc|ctr)$/, 'aes-$1-$2');
    normalized = normalized.replace(/^aes(\d{3})(ccm)$/, 'aes-$1-$2');
  } else if (/^aes\d{3}-wrap(-pad)?$/.test(normalized)) {
    normalized = normalized.replace(/^aes(\d{3})(-wrap(?:-pad)?)$/, 'aes-$1$2');
  } else if (/^aes-\d{3}(gcm|cbc|ctr|ccm)$/.test(normalized)) {
    normalized = normalized.replace(/^(aes-\d{3})(gcm|cbc|ctr)$/, '$1-$2');
    normalized = normalized.replace(/^(aes-\d{3})(ccm)$/, '$1-$2');
  } else if (/^aes-\d{3}$/.test(normalized)) {
    return normalized;
  } else if (/^aes\d{3}$/.test(normalized)) {
    return normalized;
  }
  return normalized;
}

function _isWrapAlgorithm(algorithm) {
  return algorithm.indexOf('wrap') !== -1;
}

// Map of known cipher algorithms to their key sizes and OpenSSL names
var _cipherInfo = {
  'aes-128-wrap': { keyBytes: 16, openssl: 'aes-128-wrap' },
  'aes-192-wrap': { keyBytes: 24, openssl: 'aes-192-wrap' },
  'aes-256-wrap': { keyBytes: 32, openssl: 'aes-256-wrap' },
  'aes-128-wrap-pad': { keyBytes: 16, openssl: 'aes-128-wrap-pad' },
  'aes-192-wrap-pad': { keyBytes: 24, openssl: 'aes-192-wrap-pad' },
  'aes-256-wrap-pad': { keyBytes: 32, openssl: 'aes-256-wrap-pad' },
  'aes-128-cbc': { keyBytes: 16, openssl: 'aes-128-cbc' },
  'aes-192-cbc': { keyBytes: 24, openssl: 'aes-192-cbc' },
  'aes-256-cbc': { keyBytes: 32, openssl: 'aes-256-cbc' },
  'aes-128-ctr': { keyBytes: 16, openssl: 'aes-128-ctr' },
  'aes-192-ctr': { keyBytes: 24, openssl: 'aes-192-ctr' },
  'aes-256-ctr': { keyBytes: 32, openssl: 'aes-256-ctr' },
  'aes-128-gcm': { keyBytes: 16, openssl: 'aes-128-gcm', aead: true },
  'aes-192-gcm': { keyBytes: 24, openssl: 'aes-192-gcm', aead: true },
  'aes-256-gcm': { keyBytes: 32, openssl: 'aes-256-gcm', aead: true },
  'aes-128-ccm': { keyBytes: 16, openssl: 'aes-128-ccm', aead: true },
  'aes-192-ccm': { keyBytes: 24, openssl: 'aes-192-ccm', aead: true },
  'aes-256-ccm': { keyBytes: 32, openssl: 'aes-256-ccm', aead: true },
  'chacha20-poly1305': { keyBytes: 32, openssl: 'chacha20-poly1305', aead: true },
  'chacha20': { keyBytes: 32, openssl: 'chacha20' },
  'des-cbc': { keyBytes: 8, openssl: 'des-cbc' },
  'des': { keyBytes: 8, openssl: 'des-cbc' },
  'des-ede3-cbc': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'des-ede3': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'des3': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'bf-cbc': { keyBytes: 16, openssl: 'bf-cbc' },
  'bf': { keyBytes: 16, openssl: 'bf-cbc' },
  'blowfish': { keyBytes: 16, openssl: 'bf-cbc' },
  'bf-ecb': { keyBytes: 16, openssl: 'bf-ecb' },
  'bf-cfb': { keyBytes: 16, openssl: 'bf-cfb' },
  'bf-ofb': { keyBytes: 16, openssl: 'bf-ofb' },
  'des-ecb': { keyBytes: 8, openssl: 'des-ecb' },
  'des-cfb': { keyBytes: 8, openssl: 'des-cfb' },
  'des-ofb': { keyBytes: 8, openssl: 'des-ofb' },
  'des-ede3-cfb': { keyBytes: 24, openssl: 'des-ede3-cfb' },
  'des-ede3-ofb': { keyBytes: 24, openssl: 'des-ede3-ofb' },
  'rc4': { keyBytes: 16, openssl: 'rc4' }
};

function _normalizeCipherOptions(algorithm, options) {
  var normalized = _normalizeCipherAlgorithm(algorithm);
  var info = _cipherInfo[normalized];
  var keyBytes = 16;
  if (info) {
    keyBytes = info.keyBytes;
  } else if (normalized.indexOf('aes-128-') === 0) {
    keyBytes = 16;
  } else if (normalized.indexOf('aes-192-') === 0) {
    keyBytes = 24;
  } else if (normalized.indexOf('aes-256-') === 0) {
    keyBytes = 32;
  }

  var opt = options || {};
  if (typeof opt === 'number') {
    opt = { authTagLength: opt };
  } else if (typeof opt === 'string') {
    opt = { iv: opt };
  } else if (typeof opt === 'object' && opt !== null) {
    opt = Object.create(opt);
  } else {
    opt = {};
  }
  if (typeof opt.authTagLength === 'number') {
    opt.authTagLength = Math.max(1, Math.floor(opt.authTagLength));
  }
  return {
    algorithm: normalized,
    keyBytes: keyBytes,
    authTagLength: opt.authTagLength || 16,
    ivOverride: opt.iv,
    tagLength: opt.tagLength || opt.authTagLength,
    isAead: info && info.aead,
    opensslName: info && info.openssl
  };
}

function _requireCipherMode(algorithm) {
  // AES modes handled by dedicated native functions
  if (algorithm.indexOf('aes-') === 0) {
    if (algorithm.indexOf('gcm') !== -1 || algorithm.indexOf('cbc') !== -1 || algorithm.indexOf('ctr') !== -1) {
      return true;
    }
    return !!_cipherInfo[algorithm] && typeof __exactEvpCipherEncrypt === 'function';
  }
  // All other algorithms handled by generic EVP bridge
  return !!_cipherInfo[algorithm] || typeof __exactEvpCipherEncrypt === 'function';
}

function _concatChunks(chunks) {
  var totalLen = 0;
  for (var i = 0; i < chunks.length; i++) totalLen += chunks[i].length;
  var combined = new Uint8Array(totalLen);
  var offset = 0;
  for (var j = 0; j < chunks.length; j++) {
    combined.set(chunks[j], offset);
    offset += chunks[j].length;
  }
  return combined;
}

function _parseInputData(data, inputEncoding) {
  if (typeof data === 'string') {
    if (inputEncoding === 'hex') {
      var bytes = new Uint8Array(data.length / 2);
      for (var i = 0; i < data.length; i += 2) bytes[i / 2] = parseInt(data.substr(i, 2), 16);
      return bytes;
    } else if (inputEncoding === 'base64') {
      var raw = atob(data);
      var bytes2 = new Uint8Array(raw.length);
      for (var j = 0; j < raw.length; j++) bytes2[j] = raw.charCodeAt(j);
      return bytes2;
    } else {
      return _toUint8Array(data);
    }
  }
  return _toUint8Array(data);
}

function Cipher(algorithm, key, iv, options) {
  if (_CipherStreamTransform) {
    _CipherStreamTransform.call(this);
  }
  var normalized = _normalizeCipherOptions(algorithm, options);
  if (!_requireCipherMode(normalized.algorithm)) {
    throw new Error('Unsupported cipher algorithm: ' + algorithm);
  }
  this._algo = normalized.algorithm;
  this._key = _toUint8Array(key);
  this._iv = _toUint8Array(normalized.ivOverride !== undefined ? normalized.ivOverride : iv);
  this._chunks = [];
  this._finalized = false;
  this._streamEnded = false;
  this._aad = null;
  this._authTag = null;
  this._authTagLength = normalized.authTagLength;
  this._cipherKeyBytes = normalized.keyBytes;
  this._isAead = normalized.isAead;
  this._opensslName = normalized.opensslName;
  this._inlineFinalized = false;
  this._inlineFinalResult = null;
}
if (_CipherStreamTransform) {
  Cipher.prototype._transform = function(chunk, encoding, callback) {
    this._chunks.push(_parseInputData(chunk, encoding));
    if (typeof callback === 'function') callback();
  };
  Cipher.prototype._flushStreamResult = function() {
    var result = this.final();
    if (result && result.length) {
      this.push(result);
    }
    this.push(null);
  };
  Cipher.prototype._final = function(callback) {
    this._flushStreamResult();
    if (typeof callback === 'function') callback();
  };
  Cipher.prototype.end = function(chunk, encoding, callback) {
    if (typeof chunk === 'function') { callback = chunk; chunk = null; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (this._streamEnded) {
      if (typeof callback === 'function') callback();
      return this;
    }
    this._streamEnded = true;
    if (chunk !== undefined && chunk !== null) {
      this._chunks.push(_parseInputData(chunk, encoding));
    }
    try {
      this._flushStreamResult();
      if (typeof callback === 'function') callback();
    } catch (e) {
      if (typeof callback === 'function') callback(e);
      else throw e;
    }
    return this;
  };
  Object.setPrototypeOf(Cipher.prototype, _CipherStreamTransform.prototype);
  Cipher.prototype.constructor = Cipher;
}
Cipher.prototype.update = function(data, inputEncoding, outputEncoding) {
  this._chunks.push(_parseInputData(data, inputEncoding));
  if (_isWrapAlgorithm(this._algo)) {
    if (this._inlineFinalized && this._finalized) {
      if (outputEncoding) return '';
      return typeof Buffer !== 'undefined' && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
    }
    var wrapResult = this.final();
    this._inlineFinalized = true;
    this._inlineFinalResult = wrapResult;
    if (outputEncoding) return wrapResult.toString(outputEncoding);
    return wrapResult;
  }
  if (outputEncoding) return '';
  return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
};
Cipher.prototype.final = function(outputEncoding) {
  if (this._inlineFinalized && this._finalized) {
    if (outputEncoding) return '';
    return typeof Buffer !== 'undefined' && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
  }
  this._finalized = true;
  var combined = _concatChunks(this._chunks);

  var result;
  if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('gcm') !== -1) {
    if (typeof __exactAesGcmEncrypt !== 'function') throw new Error('AES-GCM encrypt not available');
    var tagBits = this._authTagLength * 8;
    var encResult = __exactAesGcmEncrypt(this._key, this._iv, combined, this._aad, tagBits);
    var tagLen = this._authTagLength;
    var ciphertext = encResult.slice(0, encResult.length - tagLen);
    var tag = encResult.slice(encResult.length - tagLen);
    if (typeof Buffer !== 'undefined' && Buffer.from) {
      this._authTag = Buffer.from(tag);
      result = Buffer.from(ciphertext);
    } else {
      this._authTag = tag;
      result = ciphertext;
    }
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('cbc') !== -1) {
    if (typeof __exactAesCbcEncrypt !== 'function') throw new Error('AES-CBC encrypt not available');
    result = __exactAesCbcEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('ctr') !== -1) {
    if (typeof __exactAesCtrEncrypt !== 'function') throw new Error('AES-CTR encrypt not available');
    result = __exactAesCtrEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (typeof __exactEvpCipherEncrypt === 'function' && this._opensslName) {
    // Use generic EVP bridge for ChaCha20, DES, Blowfish, etc.
    var encResult;
    if (this._algo.indexOf('ccm') !== -1) {
      encResult = __exactEvpCipherEncrypt(this._opensslName, this._key, this._iv, combined, this._aad, this._authTagLength);
    } else {
      encResult = __exactEvpCipherEncrypt(this._opensslName, this._key, this._iv, combined);
    }
    if (this._isAead && encResult.length > 16) {
      // AEAD: last 16 bytes are the auth tag
      var tagLen = this._authTagLength;
      var ciphertext = encResult.slice(0, encResult.length - tagLen);
      var tag = encResult.slice(encResult.length - tagLen);
      if (typeof Buffer !== 'undefined' && Buffer.from) {
        this._authTag = Buffer.from(tag);
        result = Buffer.from(ciphertext);
      } else {
        this._authTag = tag;
        result = ciphertext;
      }
    } else {
      result = encResult;
      if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
    }
  } else {
    throw new Error('Unsupported cipher algorithm: ' + this._algo);
  }

  if (outputEncoding === 'hex') return result.toString('hex');
  if (outputEncoding === 'base64') return result.toString('base64');
  return result;
};
Cipher.prototype.setAutoPadding = function() { return this; };
Cipher.prototype.getAuthTag = function() {
  if (!this._finalized) throw new Error('Cannot get auth tag before calling final()');
  if (this._authTag === null) return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
  return this._authTag;
};
Cipher.prototype.setAAD = function(aad, options) {
  this._aad = _toUint8Array(aad);
  return this;
};

function Decipher(algorithm, key, iv, options) {
  if (_CipherStreamTransform) {
    _CipherStreamTransform.call(this);
  }
  var normalized = _normalizeCipherOptions(algorithm, options);
  if (!_requireCipherMode(normalized.algorithm)) {
    throw new Error('Unsupported decipher algorithm: ' + algorithm);
  }
  this._algo = normalized.algorithm;
  this._key = _toUint8Array(key);
  this._iv = _toUint8Array(normalized.ivOverride !== undefined ? normalized.ivOverride : iv);
  this._chunks = [];
  this._finalized = false;
  this._streamEnded = false;
  this._aad = null;
  this._authTag = null;
  this._authTagLength = normalized.authTagLength;
  this._cipherKeyBytes = normalized.keyBytes;
  this._isAead = normalized.isAead;
  this._opensslName = normalized.opensslName;
  this._inlineFinalized = false;
  this._inlineFinalResult = null;
}
if (_CipherStreamTransform) {
  Decipher.prototype._transform = function(chunk, encoding, callback) {
    this._chunks.push(_parseInputData(chunk, encoding));
    if (typeof callback === 'function') callback();
  };
  Decipher.prototype._flushStreamResult = function() {
    var result = this.final();
    if (result && result.length) {
      this.push(result);
    }
    this.push(null);
  };
  Decipher.prototype._final = function(callback) {
    this._flushStreamResult();
    if (typeof callback === 'function') callback();
  };
  Decipher.prototype.end = function(chunk, encoding, callback) {
    if (typeof chunk === 'function') { callback = chunk; chunk = null; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (this._streamEnded) {
      if (typeof callback === 'function') callback();
      return this;
    }
    this._streamEnded = true;
    if (chunk !== undefined && chunk !== null) {
      this._chunks.push(_parseInputData(chunk, encoding));
    }
    try {
      this._flushStreamResult();
      if (typeof callback === 'function') callback();
    } catch (e) {
      if (typeof callback === 'function') callback(e);
      else throw e;
    }
    return this;
  };
  Object.setPrototypeOf(Decipher.prototype, _CipherStreamTransform.prototype);
  Decipher.prototype.constructor = Decipher;
}
Decipher.prototype.update = function(data, inputEncoding, outputEncoding) {
  this._chunks.push(_parseInputData(data, inputEncoding));
  if (_isWrapAlgorithm(this._algo)) {
    if (this._inlineFinalized && this._finalized) {
      if (outputEncoding) return '';
      return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
    }
    var decodeResult = this.final();
    this._inlineFinalized = true;
    this._inlineFinalResult = decodeResult;
    if (outputEncoding) return decodeResult.toString(outputEncoding);
    return decodeResult;
  }
  if (outputEncoding) return '';
  return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
};
Decipher.prototype.final = function(outputEncoding) {
  if (this._inlineFinalized && this._finalized) {
    if (outputEncoding) return '';
    return typeof Buffer !== 'undefined' && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
  }
  this._finalized = true;
  var combined = _concatChunks(this._chunks);

  var result;
  if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('gcm') !== -1) {
    if (typeof __exactAesGcmDecrypt !== 'function') throw new Error('AES-GCM decrypt not available');
    if (!this._authTag) throw new Error('Unsupported state or unable to authenticate data');
    var tag = _toUint8Array(this._authTag);
    var dataWithTag = new Uint8Array(combined.length + tag.length);
    dataWithTag.set(combined, 0);
    dataWithTag.set(tag, combined.length);
    var tagBits = tag.length * 8;
    result = __exactAesGcmDecrypt(this._key, this._iv, dataWithTag, this._aad, tagBits);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('cbc') !== -1) {
    if (typeof __exactAesCbcDecrypt !== 'function') throw new Error('AES-CBC decrypt not available');
    result = __exactAesCbcDecrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('ctr') !== -1) {
    if (typeof __exactAesCtrEncrypt !== 'function') throw new Error('AES-CTR decrypt not available');
    result = __exactAesCtrEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (typeof __exactEvpCipherDecrypt === 'function' && this._opensslName) {
    // Use generic EVP bridge for ChaCha20, DES, Blowfish, etc.
    var authTag = this._isAead && this._authTag ? _toUint8Array(this._authTag) : undefined;
    if (this._algo.indexOf('ccm') !== -1) {
      result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined, authTag, this._aad, this._authTagLength);
    } else {
      result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined, authTag);
    }
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else {
    throw new Error('Unsupported decipher algorithm: ' + this._algo);
  }

  if (outputEncoding === 'hex') return result.toString('hex');
  if (outputEncoding === 'base64') return result.toString('base64');
  if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return result.toString('utf8');
  return result;
};
Decipher.prototype.setAutoPadding = function() { return this; };
Decipher.prototype.setAuthTag = function(tag) { this._authTag = _toUint8Array(tag); return this; };
Decipher.prototype.setAAD = function(aad, options) { this._aad = _toUint8Array(aad); return this; };

function createCipheriv(algorithm, key, iv, options) {
  return new Cipher(algorithm, key, iv, options);
}

function createDecipheriv(algorithm, key, iv, options) {
  return new Decipher(algorithm, key, iv, options);
}

// --- scryptSync / scrypt (native implementation via __exactScryptSync) ---
function _normalizeScryptOption(options) {
  var opts = options || {};
  var N = Number(opts.N || opts.cost || 16384);
  var r = Number(opts.r || opts.blockSize || 8);
  var p = Number(opts.p || opts.parallelization || 1);
  if (N <= 1 || (N & (N - 1)) !== 0) {
    throw new TypeError('scrypt: N must be a power of 2 and greater than 1');
  }
  if (r <= 0 || p <= 0) {
    throw new TypeError('scrypt: r and p must be positive integers');
  }
  return {
    N: N,
    r: r,
    p: p
  };
}

function scryptSync(password, salt, keylen, options) {
  if (typeof __exactScryptSync !== 'function') {
    throw new Error('crypto.scryptSync is not available on this platform');
  }
  if (typeof keylen !== 'number' || keylen <= 0) {
    throw new TypeError('Invalid key length value');
  }
  var normalized = _normalizeScryptOption(options);
  var passBytes = _toBytes(password);
  var saltBytes = _toBytes(salt);
  var result = __exactScryptSync(passBytes, saltBytes, normalized.N, normalized.r, normalized.p, keylen);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function scrypt(password, salt, keylen, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = scryptSync(password, salt, keylen, options);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

function _toByteString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  if (value instanceof ArrayBuffer) {
    value = new Uint8Array(value);
  }
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var view = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    var out = '';
    for (var i = 0; i < view.length; i++) out += String.fromCharCode(view[i]);
    return out;
  }
  if (typeof value === 'number') return String.fromCharCode(value & 0xff);
  if (typeof value.length === 'number') {
    var s = '';
    for (var i = 0; i < value.length; i++) s += String.fromCharCode((value[i] || 0) & 0xff);
    return s;
  }
  return String(value);
}

function _normalizeInputEncoding(encoding) {
  if (!encoding) return '';
  if (typeof encoding !== 'string') return '';
  return encoding.toLowerCase().replace(/_/g, '-');
}

function _toByteStringWithEncoding(value, encoding) {
  var inputEncoding = _normalizeInputEncoding(encoding);
  if (typeof value === 'string' && inputEncoding) {
    if (inputEncoding === 'hex') {
      if (value.length % 2 !== 0) {
        throw new TypeError('Invalid hex string');
      }
      var hexBytes = new Uint8Array(value.length / 2);
      for (var i = 0; i < value.length; i += 2) {
        hexBytes[i / 2] = parseInt(value.substr(i, 2), 16);
      }
      return _bytesToString(hexBytes);
    }
    if (inputEncoding === 'base64' || inputEncoding === 'base64url') {
      if (typeof atob !== 'function') return _toByteString(value);
      if (inputEncoding === 'base64url') {
        var base64Url = value.replace(/-/g, '+').replace(/_/g, '/');
        while (base64Url.length % 4 !== 0) base64Url += '=';
        return atob(base64Url);
      }
      return atob(value);
    }
  }
  return _toByteString(value);
}

function _bytesToString(bytes) {
  if (!bytes || !bytes.length) return '';
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

function _toByteArray(value) {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    var bytesFromString = [];
    for (var i = 0; i < value.length; i++) bytesFromString.push(value.charCodeAt(i) & 0xff);
    return bytesFromString;
  }
  if (value instanceof ArrayBuffer) {
    value = new Uint8Array(value);
  }
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var typed = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    var bytesFromView = [];
    for (var j = 0; j < typed.length; j++) bytesFromView.push(typed[j]);
    return bytesFromView;
  }
  if (typeof value.length === 'number') {
    var bytesFromArray = [];
    for (var k = 0; k < value.length; k++) bytesFromArray.push((value[k] || 0) & 0xff);
    return bytesFromArray;
  }
  return _toByteArray(_toByteString(value));
}

function _toHex(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var h = bytes[i].toString(16);
    if (h.length === 1) h = '0' + h;
    hex += h;
  }
  return hex;
}

function _hexToBytes(hex) {
  if (!hex) return [];
  if (hex.substr(0, 2) === '0x') hex = hex.substr(2);
  var normalized = hex.length % 2 === 1 ? '0' + hex : hex;
  var out = [];
  for (var i = 0; i < normalized.length; i += 2) {
    out.push(parseInt(normalized.substr(i, 2), 16));
  }
  return out;
}

function _bytesToBufferLike(bytes) {
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
  return new Uint8Array(bytes);
}

function _createCryptoError(ctor, code, message) {
  var err = new ctor(message);
  err.code = code;
  return err;
}

function _readInt(value) {
  return typeof value === 'number' && isFinite(value) && value === (value | 0);
}

function createDiffieHellman(sizeOrKey, generatorEncoding, generator) {
  var prime = sizeOrKey;
  var encoding = undefined;
  var gen = undefined;

  if (typeof prime === 'number') {
    if (!_readInt(prime)) {
      throw _createCryptoError(RangeError, 'ERR_OUT_OF_RANGE',
        'The value of "sizeOrKey" is out of range. It must be an integer. Received ' + prime);
    }
    if (prime <= 1) {
      throw _createCryptoError(Error, 'ERR_OSSL_BN_BITS_TOO_SMALL',
        'The size of the prime is too small; number of bits too small');
    }
    return {
      verifyError: 0,
      generateKeys: function() { return new Uint8Array(0); },
      computeSecret: function() { return new Uint8Array(0); },
      setPublicKey: function() {},
      setPrivateKey: function() {},
      getPrime: function() { return new Uint8Array(0); },
      getGenerator: function() { return new Uint8Array([2]); },
      getPrivateKey: function() { return new Uint8Array(0); },
      getPublicKey: function() { return new Uint8Array(0); }
    };
  }

  if (typeof prime === 'string') {
    if (typeof generatorEncoding === 'string') {
      encoding = generatorEncoding;
      gen = generator;
    } else {
      gen = generatorEncoding;
    }
  } else if (
    !(prime instanceof ArrayBuffer) &&
    !(ArrayBuffer && ArrayBuffer.isView && ArrayBuffer.isView(prime))
  ) {
    if (prime === undefined || prime === null) {
      throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
        'The "sizeOrKey" argument must be of type number, string, Buffer, ArrayBuffer, or ArrayBufferView. Received ' + String(prime));
    }
    throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "sizeOrKey" argument must be of type string. Received ' + typeof prime);
  }

  if (gen !== undefined) {
    if (typeof gen === 'number') {
      if (!_readInt(gen)) {
        throw _createCryptoError(RangeError, 'ERR_OUT_OF_RANGE',
          'The value of "generator" is out of range. It must be an integer. Received ' + gen);
      }
      if (gen < 2) {
        throw _createCryptoError(Error, 'ERR_OSSL_DH_BAD_GENERATOR',
          'The "generator" argument is invalid (bad generator)');
      }
    } else if (typeof gen === 'boolean' || typeof gen === 'symbol' || typeof gen === 'function') {
      throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
        'The "generator" argument must be of type number. Received ' + typeof gen);
    } else if (gen && typeof gen === 'object' && !(gen instanceof ArrayBuffer) &&
               !(ArrayBuffer && ArrayBuffer.isView && ArrayBuffer.isView(gen))) {
      throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
        'The "generator" argument is invalid');
    } else if ((typeof gen === 'object' || typeof gen === 'string') &&
               gen && gen.length !== undefined && gen.length < 2) {
      throw _createCryptoError(Error, 'ERR_OSSL_DH_BAD_GENERATOR',
        'The "generator" argument is invalid (bad generator)');
    }
  } else if (typeof prime === 'string' && encoding === undefined) {
    gen = 2;
  } else if (prime === '' && encoding === undefined && generatorEncoding === true) {
    throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "generator" argument must be of type number. Received boolean');
  }

  return {
    verifyError: 0,
    generateKeys: function() { return new Uint8Array(0); },
    computeSecret: function() { return new Uint8Array(0); },
    setPublicKey: function() {},
    setPrivateKey: function() {},
    getPrime: function() { return typeof prime === 'string' ? _toByteArray(prime) : _toByteArray(new Uint8Array(prime)); },
    getGenerator: function() { return _toByteArray(gen || 2); },
    getPrivateKey: function() { return new Uint8Array(0); },
    getPublicKey: function() { return new Uint8Array(0); }
  };
}

function createDiffieHellmanGroup(groupName) {
  return getDiffieHellman(groupName);
}

function createECDH(curve) {
  if (typeof curve !== 'string') {
    throw _createCryptoError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "curve" argument must be of type string. Received ' +
      (curve === undefined ? 'undefined' : typeof curve));
  }
  return {
    generateKeys: function() { return new Uint8Array(0); },
    computeSecret: function() { return new Uint8Array(0); },
    setPrivateKey: function() {},
    setPublicKey: function() {}
  };
}

function getDiffieHellman(groupName) {
  if (!groupName || groupName === 'unknown-group') {
    throw _createCryptoError(Error, 'ERR_CRYPTO_UNKNOWN_DH_GROUP', 'Unknown DH group');
  }
  return {
    verifyError: 0,
    generateKeys: function() { return new Uint8Array(0); },
    computeSecret: function() { return new Uint8Array(0); },
    setPublicKey: function() {},
    setPrivateKey: function() {},
    getPrime: function() { return new Uint8Array(0); },
    getGenerator: function() { return new Uint8Array([2]); },
    getPrivateKey: function() { return new Uint8Array(0); },
    getPublicKey: function() { return new Uint8Array(0); }
  };
}

function _isPemKeyText(value) {
  if (typeof value !== 'string') return false;
  return value.indexOf('-----BEGIN') === 0 ||
    value.indexOf('BEGIN PUBLIC KEY') !== -1 ||
    value.indexOf('BEGIN PRIVATE KEY') !== -1 ||
    value.indexOf('BEGIN RSA PUBLIC KEY') !== -1 ||
    value.indexOf('BEGIN RSA PRIVATE KEY') !== -1;
}

function _extractKeyText(key) {
  if (typeof key === 'string') return key;
  if (!key || typeof key !== 'object') return '';
  if (typeof key.key === 'string') return key.key;
  if (typeof key.pem === 'string') return key.pem;
  if (typeof key.exportedKey === 'string') return key.exportedKey;
  return '';
}

function _normalizeHashForSign(algorithm) {
  var name = (typeof algorithm === 'string' ? algorithm : (algorithm && algorithm.name) ? algorithm.name : '').toLowerCase();
  if (name.indexOf('sha1') !== -1) return 'sha1';
  if (name.indexOf('sha224') !== -1) return 'sha224';
  if (name.indexOf('sha256') !== -1) return 'sha256';
  if (name.indexOf('sha384') !== -1) return 'sha384';
  if (name.indexOf('sha512') !== -1) return 'sha512';
  if (name.indexOf('md5') !== -1) return 'md5';
  return 'sha256';
}

function _signatureOutput(signatureBytesLike, outputEncoding) {
  var signatureBytes = [];
  if (typeof signatureBytesLike === 'string') {
    signatureBytes = _hexToBytes(signatureBytesLike);
  } else {
    signatureBytes = _toByteArray(signatureBytesLike);
  }
  if (!outputEncoding) return _bytesToBufferLike(signatureBytes);
  if (outputEncoding === 'hex') return _toHex(signatureBytes);
  if (outputEncoding === 'base64') {
    if (typeof btoa !== 'function') return signatureBytes;
    var encodedInput = '';
    for (var i = 0; i < signatureBytes.length; i++) encodedInput += String.fromCharCode(signatureBytes[i]);
    return btoa(encodedInput);
  }
  if (outputEncoding === 'binary') return _bytesToBufferLike(signatureBytes);
  return _bytesToBufferLike(signatureBytes);
}

function sign(algorithm, data, key, outputEncoding) {
  var hash = _normalizeHashForSign(algorithm);
  var keyText = _extractKeyText(key);
  var dataText = _toByteString(data);
  var fallbackKey = keyText || _toByteString(key);

  if (typeof keyText === 'string' && _isPemKeyText(keyText) && typeof __exactSignSync === 'function') {
    try {
      var nativeBytes = __exactSignSync(hash, dataText, keyText);
      return _signatureOutput(nativeBytes, outputEncoding);
    } catch (e) {}
  }
  if (typeof __exactHmacSync === 'function') {
    var hmacHex = __exactHmacSync(hash, fallbackKey, dataText);
    return _signatureOutput(hmacHex, outputEncoding);
  }
  throw new Error('crypto.sign not available');
}

function verify(algorithm, data, key, signature) {
  var hash = _normalizeHashForSign(algorithm);
  var keyText = _extractKeyText(key);
  var fallbackKey = keyText || _toByteString(key);
  var signatureValue = signature;
  if (typeof signatureValue !== 'string' &&
      signatureValue &&
      !(signatureValue instanceof ArrayBuffer) &&
      !(typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(signatureValue)) &&
      !(typeof Buffer !== 'undefined' && typeof Buffer.isBuffer === 'function' && Buffer.isBuffer(signatureValue))) {
    signatureValue = _toByteArray(signatureValue);
  }
  var dataText = _toByteString(data);

  if (typeof keyText === 'string' && _isPemKeyText(keyText) && typeof __exactVerifySync === 'function') {
    try {
      return __exactVerifySync(hash, signatureValue, dataText, keyText);
    } catch (e) {}
  }

  if (typeof __exactHmacSync !== 'function') return false;
  var expectedHex = __exactHmacSync(hash, fallbackKey, dataText);
  var expected = _hexToBytes(expectedHex);
  var provided = _toByteArray(signatureValue);
  if (typeof signature === 'string' && signature.length === expected.length * 2 && /^[0-9a-fA-F]+$/.test(signature)) {
    provided = _hexToBytes(signature);
  }
  if (provided.length !== expected.length) return false;
  var mismatch = 0;
  for (var i = 0; i < expected.length; i++) {
    mismatch |= expected[i] ^ provided[i];
  }
  return mismatch === 0;
}

function Sign(algorithm) { this._algorithm = algorithm; this._chunks = []; }
Sign.prototype.update = function(data, inputEncoding) { this._chunks.push(_toByteStringWithEncoding(data, inputEncoding)); return this; };
Sign.prototype.sign = function(key, outputEncoding) { return sign(this._algorithm, this._chunks.join(''), key, outputEncoding); };
Sign.prototype.end = function(data, inputEncoding) {
  if (typeof data !== 'undefined') this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
  return this;
};

function createSign(algorithm) { return new Sign(algorithm); }

function Verify(algorithm) { this._algorithm = algorithm; this._chunks = []; }
Verify.prototype.update = function(data, inputEncoding) { this._chunks.push(_toByteStringWithEncoding(data, inputEncoding)); return this; };
Verify.prototype.verify = function(key, signature) { return verify(this._algorithm, this._chunks.join(''), key, signature); };
Verify.prototype.end = function(data, inputEncoding) {
  if (typeof data !== 'undefined') this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
  return this;
};

function createVerify(algorithm) { return new Verify(algorithm); }

function _applyKeyEncoding(value, encoding) {
  if (!encoding || !encoding.format || encoding.format === 'pem') return value;
  if (encoding.format === 'buffer') return _bytesToBufferLike(_toByteArray(value));
  return value;
}

function generateKeyPairSync(type, options) {
  if (typeof type === 'object' && type && !options) {
    options = type;
    type = options.type || 'rsa';
  }
  var keyType = (typeof type === 'string' ? type : (type && type.name) ? type.name : 'rsa').toLowerCase();

    if (keyType === 'rsa' || keyType === 'ec' || keyType === 'dsa' || keyType === 'x25519' || keyType === 'ed25519') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        var nativeOptions = options || {};
      if (keyType === 'rsa') {
        if (!nativeOptions.modulusLength) nativeOptions.modulusLength = 2048;
        if (!nativeOptions.publicExponent) nativeOptions.publicExponent = 65537;
      }
      if (keyType === 'ec') {
        if ((nativeOptions.publicKeyEncoding && nativeOptions.publicKeyEncoding.format === 'jwk') ||
            (nativeOptions.privateKeyEncoding && nativeOptions.privateKeyEncoding.format === 'jwk')) {
          if (nativeOptions.namedCurve === 'secp224r1') {
            throw _createCryptoError(Error, 'ERR_CRYPTO_JWK_UNSUPPORTED_CURVE',
              'Unsupported JWK EC curve: secp224r1.');
          }
        }
      }
      if (keyType === 'dsa') {
        if ((nativeOptions.publicKeyEncoding && nativeOptions.publicKeyEncoding.format === 'jwk') ||
            (nativeOptions.privateKeyEncoding && nativeOptions.privateKeyEncoding.format === 'jwk')) {
          throw _createCryptoError(Error, 'ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE',
            'Unsupported JWK Key Type.');
        }
      }
      if (!nativeOptions.publicKeyEncoding) {
        nativeOptions.publicKeyEncoding = { type: 'spki', format: 'pem' };
      }
      if (!nativeOptions.privateKeyEncoding) {
        nativeOptions.privateKeyEncoding = { type: 'pkcs1', format: 'pem' };
      }
      var pair = __exactGenerateKeyPairSync(keyType, nativeOptions);
      return {
        privateKey: _applyKeyEncoding(pair.privateKey, options && options.privateKeyEncoding),
        publicKey: _applyKeyEncoding(pair.publicKey, options && options.publicKeyEncoding)
      };
      }
      throw new Error('crypto.generateKeyPairSync is not available in this runtime');
    }
  throw new Error('Unsupported key pair type: ' + type);
}

function generateKeyPair(type, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = undefined;
  }
  if (typeof callback !== 'function') {
    return generateKeyPairSync(type, options);
  }
  try {
    var pair = generateKeyPairSync(type, options);
    setTimeout(function() { callback(null, pair.publicKey, pair.privateKey); }, 0);
  } catch (e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

var cryptoConstants = {
  SSL_OP_ALL: 0,
  SSL_OP_NO_SSLv2: 0,
  SSL_OP_NO_SSLv3: 0,
  SSL_OP_NO_TLSv1: 0,
  SSL_OP_NO_TLSv1_1: 0,
  POINT_CONVERSION_COMPRESSED: 4,
  POINT_CONVERSION_UNCOMPRESSED: 4,
  defaultCoreCipherList: '',
  defaultCipherList: ''
};

module.exports = {
  randomBytes: randomBytes,
  randomUUID: randomUUID,
  randomInt: randomInt,
  randomFillSync: randomFillSync,
  createHash: createHash,
  createHmac: createHmac,
  createCipheriv: createCipheriv,
  createDecipheriv: createDecipheriv,
  createSign: createSign,
  createVerify: createVerify,
  Sign: Sign,
  Verify: Verify,
  sign: sign,
  verify: verify,
  createDiffieHellman: createDiffieHellman,
  createDiffieHellmanGroup: createDiffieHellmanGroup,
  generateKeyPairSync: generateKeyPairSync,
  generateKeyPair: generateKeyPair,
  createECDH: createECDH,
  getDiffieHellman: getDiffieHellman,
  pbkdf2Sync: pbkdf2Sync,
  pbkdf2: pbkdf2,
  hkdfSync: hkdfSync,
  hkdf: hkdf,
  scryptSync: scryptSync,
  scrypt: scrypt,
  KeyObject: KeyObject,
  createSecretKey: createSecretKey,
  createPublicKey: createPublicKey,
  createPrivateKey: createPrivateKey,
  generateKeySync: generateKeySync,
  getHashes: getHashes,
  getCiphers: function() {
    return [
      'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
      'aes-128-ccm', 'aes-192-ccm', 'aes-256-ccm',
      'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
      'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
      'chacha20-poly1305', 'chacha20',
      'des-cbc', 'des-ecb', 'des-cfb', 'des-ofb',
      'des-ede3-cbc', 'des-ede3-cfb', 'des-ede3-ofb',
      'bf-cbc', 'bf-ecb', 'bf-cfb', 'bf-ofb',
      'rc4'
    ];
  },
  timingSafeEqual: timingSafeEqual,
  Hash: Hash,
  Hmac: Hmac,
  Cipher: Cipher,
  Decipher: Decipher,
  constants: cryptoConstants,
  getRandomValues: function(arr) {
    if (typeof globalThis.crypto === 'object' && typeof globalThis.crypto.getRandomValues === 'function') {
      return globalThis.crypto.getRandomValues(arr);
    }
    var bytes = randomBytes(arr.byteLength);
    var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    for (var i = 0; i < view.length; i++) view[i] = bytes[i];
    return arr;
  },
  webcrypto: typeof globalThis.crypto === 'object' ? globalThis.crypto : { getRandomValues: function(arr) { var bytes = randomBytes(arr.length); for (var i = 0; i < arr.length; i++) arr[i] = bytes[i]; return arr; } },
  argon2: function() {
    var e = new Error('argon2 is not supported');
    e.code = 'ERR_CRYPTO_ARGON2_NOT_SUPPORTED';
    throw e;
  },
  encapsulate: function() {
    var e = new Error('KEM operations are not supported');
    e.code = 'ERR_CRYPTO_KEM_NOT_SUPPORTED';
    throw e;
  },
  decapsulate: function() {
    var e = new Error('KEM operations are not supported');
    e.code = 'ERR_CRYPTO_KEM_NOT_SUPPORTED';
    throw e;
  }
};
