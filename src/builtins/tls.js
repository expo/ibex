var net;
try { net = require('net'); } catch(e) {}
var _kReinitializeHandle = Symbol.for('nodejs.net.kReinitializeHandle');

var eventsModule;
try { eventsModule = require('events'); } catch(e) {}

var EventEmitter = eventsModule && (eventsModule.EventEmitter || eventsModule);
var hasOwn = Object.prototype.hasOwnProperty;

var CLIENT_RENEG_LIMIT = 3;
var CLIENT_RENEG_WINDOW = 600;
var DEFAULT_ECDH_CURVE = 'auto';
var DEFAULT_MIN_VERSION = 'TLSv1.2';
var DEFAULT_MAX_VERSION = 'TLSv1.3';
var DEFAULT_CIPHERS = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384';

var _defaultTlsCipher = 'TLS_AES_256_GCM_SHA384';
var _tlsVersions = {
  'TLSv1': true,
  'TLSv1.1': true,
  'TLSv1.2': true,
  'TLSv1.3': true
};

var rootCertificates = Object.freeze([]);
var _systemCACertificates = Object.freeze([]);
var _extraCACertificates = Object.freeze([]);
var _defaultCACertificates = Object.freeze(rootCertificates.slice());

function _createError(code, message) {
  var err = new Error(message);
  err.code = code;
  return err;
}

function _getEmptyBuffer() {
  if (typeof Buffer !== 'undefined' && typeof Buffer.alloc === 'function') {
    return Buffer.alloc(0);
  }
  return typeof Uint8Array !== 'undefined' ? new Uint8Array(0) : [];
}

function _isArrayBufferView(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(value);
  }
  return typeof value.byteLength === 'number' && value.buffer;
}

function _cloneBufferLike(value) {
  if (value === null || typeof value === 'undefined') return _getEmptyBuffer();
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(value);
  }
  if (typeof Uint8Array !== 'undefined') {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice ? value.slice(0) : value);
    if (_isArrayBufferView(value)) {
      var offset = value.byteOffset || 0;
      var length = typeof value.byteLength === 'number' ? value.byteLength : value.length;
      return new Uint8Array(new Uint8Array(value.buffer, offset, length));
    }
  }
  return value;
}

function _stringToBytes(value) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(String(value));
  }
  var str = String(value);
  var out = typeof Uint8Array !== 'undefined' ? new Uint8Array(str.length) : [];
  for (var i = 0; i < str.length; i++) {
    out[i] = str.charCodeAt(i) & 255;
  }
  return out;
}

function _byteLength(value) {
  if (typeof value === 'string') return _stringToBytes(value).length || 0;
  if (!value) return 0;
  if (typeof value.length === 'number') return value.length;
  if (typeof value.byteLength === 'number') return value.byteLength;
  return 0;
}

function _mixinEventEmitter(target) {
  if (typeof EventEmitter !== 'function' || !EventEmitter.prototype || !target) return target;
  var names = typeof Object.getOwnPropertyNames === 'function'
    ? Object.getOwnPropertyNames(EventEmitter.prototype)
    : null;

  if (names && names.length) {
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (name === 'constructor' || target[name]) continue;
      if (typeof EventEmitter.prototype[name] === 'function') {
        target[name] = EventEmitter.prototype[name];
      }
    }
    return target;
  }

  for (var key in EventEmitter.prototype) {
    if (!target[key]) target[key] = EventEmitter.prototype[key];
  }
  return target;
}

function _cloneOwnProperties(source) {
  if (!source || typeof source !== 'object') return {};
  var target = {};
  for (var key in source) {
    if (hasOwn.call(source, key)) target[key] = source[key];
  }
  return target;
}

function _validateProtocolVersion(kind, value) {
  if (value === null || typeof value === 'undefined') return;
  if (typeof value !== 'string' || !_tlsVersions[value]) {
    throw _createError(
      'ERR_TLS_INVALID_PROTOCOL_VERSION',
      '"' + value + '" is not a valid ' + kind + ' TLS protocol version'
    );
  }
}

function _normalizeCipherName(ciphers) {
  if (typeof ciphers !== 'string' || !ciphers) {
    return _defaultTlsCipher;
  }
  var first = ciphers.split(/[:,]/)[0];
  return first || _defaultTlsCipher;
}

function _getCipherList() {
  var seen = {};
  var result = [];
  var parts = String(DEFAULT_CIPHERS || '').split(':');
  for (var i = 0; i < parts.length; i++) {
    var name = parts[i] && String(parts[i]).trim().toLowerCase();
    if (!name || seen[name]) continue;
    seen[name] = true;
    result.push(name);
  }
  result.sort();
  return result;
}

function _normalizeCACertificates(certs) {
  if (!Array.isArray(certs)) {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "certs" argument must be an instance of Array'
    );
  }

  var normalized = [];
  for (var i = 0; i < certs.length; i++) {
    var cert = certs[i];
    if (typeof cert === 'string') {
      normalized.push(cert);
      continue;
    }
    if (_isArrayBufferView(cert)) {
      normalized.push(_cloneBufferLike(cert));
      continue;
    }
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "certs[' + i + ']" argument must be of type string or an instance of ArrayBufferView'
    );
  }
  return Object.freeze(normalized);
}

function getCACertificates(type) {
  var certType = typeof type === 'undefined' ? 'default' : type;
  if (certType === 'default') return _defaultCACertificates;
  if (certType === 'bundled') return rootCertificates;
  if (certType === 'system') return _systemCACertificates;
  if (certType === 'extra') return _extraCACertificates;

  throw _createError(
    'ERR_INVALID_ARG_VALUE',
    'The argument "type" is invalid. Received ' + String(certType)
  );
}

function setDefaultCACertificates(certs) {
  _defaultCACertificates = _normalizeCACertificates(certs);
}

function _encodeALPNArray(protocols) {
  var chunks = [];
  var total = 0;
  for (var i = 0; i < protocols.length; i++) {
    if (typeof protocols[i] !== 'string') {
      throw _createError('ERR_INVALID_ARG_TYPE', 'ALPN protocol entries must be strings');
    }
    var bytes = _stringToBytes(protocols[i]);
    var length = _byteLength(bytes);
    if (length > 255) {
      throw _createError(
        'ERR_OUT_OF_RANGE',
        'The byte length of the protocol at index ' + i + ' exceeds the maximum length. It must be <= 255. Received ' + length
      );
    }
    chunks.push(bytes);
    total += 1 + length;
  }

  if (typeof Buffer !== 'undefined' && typeof Buffer.alloc === 'function') {
    var buffer = Buffer.alloc(total);
    var offset = 0;
    for (var j = 0; j < chunks.length; j++) {
      buffer[offset++] = _byteLength(chunks[j]);
      Buffer.from(chunks[j]).copy(buffer, offset);
      offset += _byteLength(chunks[j]);
    }
    return buffer;
  }

  var out = typeof Uint8Array !== 'undefined' ? new Uint8Array(total) : [];
  var pos = 0;
  for (var k = 0; k < chunks.length; k++) {
    var chunk = chunks[k];
    var size = _byteLength(chunk);
    out[pos++] = size;
    for (var m = 0; m < size; m++) {
      out[pos++] = chunk[m];
    }
  }
  return out;
}

function convertALPNProtocols(protocols, out) {
  var normalized;

  if (Array.isArray(protocols)) {
    normalized = _encodeALPNArray(protocols);
  } else if (_isArrayBufferView(protocols) || (typeof ArrayBuffer !== 'undefined' && protocols instanceof ArrayBuffer)) {
    normalized = _cloneBufferLike(protocols);
  } else {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "protocols" argument must be an instance of Array, Buffer, TypedArray, DataView, or ArrayBuffer'
    );
  }

  if (out && typeof out === 'object') {
    out.ALPNProtocols = normalized;
  }

  return normalized;
}

function _normalizeCheckError(error) {
  if (!error) return null;
  if (error instanceof Error) return error;
  if (typeof error === 'string') return new Error(error);
  return new Error('TLS server identity check failed');
}

function _generateFingerprint(seed, algorithm) {
  if (typeof __exactHashSync !== 'function') return '';
  try {
    var hash = __exactHashSync(algorithm || 'sha1', seed || '');
    if (typeof hash !== 'string') return '';
    return hash.toUpperCase().replace(/(.{2})(?!$)/g, '$1:');
  } catch(e) {
    return '';
  }
}

function _buildSyntheticCertificate(host, port, certSource) {
  var identity = host || 'localhost';
  var now = new Date();
  var validFrom = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
  var validTo = new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000));
  var portSuffix = port ? ':' + port : '';
  var seed = identity + portSuffix + String(now.getTime());
  return {
    subject: { CN: identity },
    issuer: { CN: certSource || 'ExactTLS' },
    subjectaltname: 'DNS:' + identity,
    valid_from: validFrom.toUTCString(),
    valid_to: validTo.toUTCString(),
    serialNumber: '0000000000000001',
    fingerprint: _generateFingerprint(seed + ':sha1', 'sha1'),
    fingerprint256: _generateFingerprint(seed + ':sha256', 'sha256'),
    raw: null
  };
}

function _isIpAddress(host) {
  if (!host || typeof host !== 'string') return false;
  if (host.indexOf(':') !== -1) return /^([0-9a-f:.]+)$/i.test(host);
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function _hostMatchesPattern(host, pattern) {
  if (!host || !pattern) return false;
  host = host.toLowerCase();
  pattern = pattern.toLowerCase();
  if (pattern[0] === '[' && pattern[pattern.length - 1] === ']') {
    pattern = pattern.substring(1, pattern.length - 1);
  }
  if (pattern.indexOf('*') === -1) return host === pattern;
  if (pattern.indexOf('*.') !== 0) return false;
  var suffix = pattern.substring(1);
  if (host.length <= suffix.length) return false;
  if (host.slice(-suffix.length) !== suffix) return false;
  return host.charAt(host.length - suffix.length - 1) === '.';
}

function _defaultCheckServerIdentity(hostname, cert) {
  if (!cert) return new Error('No server certificate');
  var host = (hostname || '').toLowerCase();
  if (!host) return new Error('Missing hostname');
  if (host[0] === '[' && host[host.length - 1] === ']') {
    host = host.substring(1, host.length - 1);
  }
  var isIp = _isIpAddress(host);

  var patterns = [];
  if (cert.subject && cert.subject.CN) patterns.push(cert.subject.CN);
  if (typeof cert.subjectaltname === 'string') {
    var parts = cert.subjectaltname.split(',');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (p.indexOf('DNS:') === 0) patterns.push(p.substr(4));
      if (p.indexOf('IP Address:') === 0) patterns.push('ip:' + p.substr(11).trim());
    }
  }

  if (!patterns.length) return null;

  for (var j = 0; j < patterns.length; j++) {
    var pattern = patterns[j];
    if (isIp && pattern.indexOf('ip:') === 0) {
      if (_hostMatchesPattern(host, pattern.substr(3).trim())) return null;
      continue;
    }
    if (!isIp && _hostMatchesPattern(host, pattern)) return null;
  }

  return new Error('Hostname/IP mismatch');
}

function checkServerIdentity(hostname, cert) {
  return _defaultCheckServerIdentity(hostname, cert);
}

function _copySocketMetadata(socket, rawSocket) {
  if (!socket || !rawSocket) return;
  if (typeof rawSocket.remoteAddress !== 'undefined') socket.remoteAddress = rawSocket.remoteAddress;
  if (typeof rawSocket.remotePort !== 'undefined') socket.remotePort = rawSocket.remotePort;
  if (typeof rawSocket.remoteFamily !== 'undefined') socket.remoteFamily = rawSocket.remoteFamily;
  if (typeof rawSocket.localAddress !== 'undefined') socket.localAddress = rawSocket.localAddress;
  if (typeof rawSocket.localPort !== 'undefined') socket.localPort = rawSocket.localPort;
  if (typeof rawSocket.localFamily !== 'undefined') socket.localFamily = rawSocket.localFamily;
  if (typeof rawSocket.readable === 'boolean') socket.readable = rawSocket.readable;
  if (typeof rawSocket.writable === 'boolean') socket.writable = rawSocket.writable;
}

function _bindSocket(wrapper, rawSocket) {
  if (!wrapper || !rawSocket) return rawSocket;
  wrapper._socket = rawSocket;
  _copySocketMetadata(wrapper, rawSocket);

  if (wrapper._boundSocket === rawSocket || typeof rawSocket.on !== 'function') {
    return rawSocket;
  }

  wrapper._boundSocket = rawSocket;
  var events = ['data', 'end', 'error', 'close', 'timeout', 'drain', 'lookup', 'ready', 'connect'];
  for (var i = 0; i < events.length; i++) {
    (function(eventName) {
      rawSocket.on(eventName, function() {
        if (eventName === 'connect') wrapper.connecting = false;
        if (eventName === 'end') wrapper.readable = false;
        if (eventName === 'close') wrapper.destroyed = true;
        _copySocketMetadata(wrapper, rawSocket);
        if (typeof wrapper.emit === 'function') {
          wrapper.emit.apply(wrapper, [eventName].concat(Array.prototype.slice.call(arguments)));
        }
      });
    })(events[i]);
  }

  return rawSocket;
}

function _callSocketMethod(wrapper, methodName, args, fallback) {
  if (wrapper && wrapper._socket && typeof wrapper._socket[methodName] === 'function') {
    return wrapper._socket[methodName].apply(wrapper._socket, args || []);
  }
  return fallback;
}

function _finalizeHandshake(socket) {
  var opts = socket._tlsOptions || {};
  var host = socket._servername || socket.remoteAddress || 'localhost';
  socket._peerCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts.cert || opts.pfx || 'ExactTLS');
  socket._localCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts.key || opts.cert || 'ExactTLS');
  socket._cipher = { name: _normalizeCipherName(opts.ciphers), version: socket._protocol };
  var check = opts.checkServerIdentity || checkServerIdentity;
  var result = _normalizeCheckError(check(host, socket._peerCertificate, opts));
  if (result) {
    socket.authorizationError = result.message || String(result);
    socket.authorized = false;
    return false;
  }
  socket.authorizationError = null;
  socket.authorized = true;
  return true;
}

function _decorateSecureContext(target, options) {
  var normalized = _cloneOwnProperties(options || {});
  _validateProtocolVersion('minimum', normalized.minVersion);
  _validateProtocolVersion('maximum', normalized.maxVersion);

  if (hasOwn.call(normalized, 'ALPNProtocols') && normalized.ALPNProtocols !== null && typeof normalized.ALPNProtocols !== 'undefined') {
    normalized.ALPNProtocols = convertALPNProtocols(normalized.ALPNProtocols);
  }

  target.context = normalized;
  target._options = normalized;
  return target;
}

function SecureContext(options) {
  if (!(this instanceof SecureContext)) return new SecureContext(options);
  this.context = {};
  this._options = this.context;
  if (options && typeof options === 'object') {
    _decorateSecureContext(this, options);
  }
}

function createSecureContext(options) {
  if (options instanceof SecureContext) return options;
  return new SecureContext(options || {});
}

function TLSSocket(socket, options) {
  if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);
  options = options || {};
  this._events = {};
  _mixinEventEmitter(this);
  this._socket = null;
  this._boundSocket = null;
  this._tlsOptions = _cloneOwnProperties(options);
  this.encrypted = true;
  this.authorized = false;
  this.authorizationError = null;
  this._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
  this._session = null;
  this._sessionReused = false;
  this._peerCertificate = null;
  this._localCertificate = null;
  this._secureEstablished = false;
  this._pending = true;
  this._servername = options.servername || options.host || options.hostname || null;
  this.servername = this._servername;
  this.alpnProtocol = null;
  this.connecting = true;
  this.readable = true;
  this.writable = true;
  this.destroyed = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.remoteFamily = 'IPv4';
  this.localAddress = null;
  this.localPort = null;
  this.localFamily = 'IPv4';
  this._cipher = { name: _normalizeCipherName(options.ciphers), version: this._protocol };

  if (socket) {
    this.connecting = !!socket.connecting;
    this._pending = !!socket.connecting;
    _bindSocket(this, socket);
  }
}

if (net && net.Socket && typeof Object.setPrototypeOf === 'function') {
  Object.setPrototypeOf(TLSSocket, net.Socket);
} else if (!TLSSocket.prototype) {
  TLSSocket.prototype = {};
}
TLSSocket.prototype.constructor = TLSSocket;

TLSSocket.prototype._setSocket = function(socket) {
  _bindSocket(this, socket);
  return this;
};

TLSSocket.prototype[_kReinitializeHandle] = function() {
  return this;
};

TLSSocket.prototype.getPeerCertificate = function() {
  return this._peerCertificate || {};
};

TLSSocket.prototype.getPeerX509Certificate = TLSSocket.prototype.getPeerCertificate;

TLSSocket.prototype.getCertificate = function() {
  return this._localCertificate || {};
};

TLSSocket.prototype.getCipher = function() {
  return this._cipher || {
    name: _normalizeCipherName(this._tlsOptions && this._tlsOptions.ciphers),
    version: this._protocol
  };
};

TLSSocket.prototype.getProtocol = function() {
  return this._protocol;
};

TLSSocket.prototype.getSession = function() {
  return this._session;
};

TLSSocket.prototype.setSession = function(session) {
  this._session = session || null;
  return this;
};

TLSSocket.prototype.isSessionReused = function() {
  return !!this._sessionReused;
};

TLSSocket.prototype.getFinished = function() {
  return null;
};

TLSSocket.prototype.getTLSTicket = function() {
  return null;
};

TLSSocket.prototype.getSharedSigalgs = function() {
  return [];
};

TLSSocket.prototype.renegotiate = function(options, callback) {
  if (typeof options === 'function') callback = options;
  if (typeof callback === 'function') {
    setTimeout(function() { callback(null); }, 0);
  }
  return true;
};

TLSSocket.prototype.disableRenegotiation = function() {
  this._renegotiationDisabled = true;
};

TLSSocket.prototype.enableTrace = function() {
  return _callSocketMethod(this, 'enableTrace', [], undefined);
};

TLSSocket.prototype.setMaxSendFragment = function(size) {
  if (typeof size !== 'number' || size !== (size | 0) || size < 512 || size > 16384) {
    return false;
  }
  this._maxSendFragment = size;
  return true;
};

TLSSocket.prototype.setEncoding = function(enc) {
  _callSocketMethod(this, 'setEncoding', [enc], this);
  return this;
};

TLSSocket.prototype.write = function(data, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  if (this._socket && typeof this._socket.write === 'function') {
    return this._socket.write(data, encoding, callback);
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  return true;
};

TLSSocket.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') {
    callback = data;
    data = undefined;
    encoding = undefined;
  }
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  this.writable = false;
  if (this._socket && typeof this._socket.end === 'function') {
    this._socket.end(data, encoding, callback);
    return this;
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  return this;
};

TLSSocket.prototype.destroy = function(err) {
  this.destroyed = true;
  this.readable = false;
  this.writable = false;
  if (this._socket && typeof this._socket.destroy === 'function') {
    this._socket.destroy(err);
  }
  return this;
};

TLSSocket.prototype.setTimeout = function(timeout, callback) {
  if (typeof callback === 'function' && typeof this.once === 'function') {
    this.once('timeout', callback);
  }
  _callSocketMethod(this, 'setTimeout', [timeout], this);
  return this;
};

TLSSocket.prototype.setNoDelay = function(noDelay) {
  _callSocketMethod(this, 'setNoDelay', [noDelay], this);
  return this;
};

TLSSocket.prototype.setKeepAlive = function(enable, initialDelay) {
  _callSocketMethod(this, 'setKeepAlive', [enable, initialDelay], this);
  return this;
};

TLSSocket.prototype.ref = function() {
  _callSocketMethod(this, 'ref', [], this);
  return this;
};

TLSSocket.prototype.unref = function() {
  _callSocketMethod(this, 'unref', [], this);
  return this;
};

TLSSocket.prototype.address = function() {
  if (this._socket && typeof this._socket.address === 'function') {
    return this._socket.address();
  }
  return {
    address: this.localAddress || this.remoteAddress,
    port: this.localPort || this.remotePort,
    family: this.localFamily || this.remoteFamily || 'IPv4'
  };
};

TLSSocket.prototype.pause = function() {
  _callSocketMethod(this, 'pause', [], this);
  return this;
};

TLSSocket.prototype.resume = function() {
  _callSocketMethod(this, 'resume', [], this);
  return this;
};

TLSSocket.prototype.pipe = function(dest, options) {
  if (this._socket && typeof this._socket.pipe === 'function') {
    return this._socket.pipe(dest, options);
  }
  return dest;
};

TLSSocket.prototype.cork = function() {
  _callSocketMethod(this, 'cork', [], this);
  return this;
};

TLSSocket.prototype.uncork = function() {
  _callSocketMethod(this, 'uncork', [], this);
  return this;
};

if (typeof Object.defineProperty === 'function') {
  Object.defineProperty(TLSSocket.prototype, 'bytesRead', {
    configurable: true,
    enumerable: true,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      if (this._socket && typeof this._socket.bytesRead === 'number') return this._socket.bytesRead;
      return 0;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'bytesWritten', {
    configurable: true,
    enumerable: true,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      if (this._socket && typeof this._socket.bytesWritten === 'number') return this._socket.bytesWritten;
      return 0;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'pending', {
    configurable: true,
    enumerable: true,
    get: function() {
      return typeof this._pending === 'boolean' ? this._pending : !this._secureEstablished;
    },
    set: function(value) {
      this._pending = !!value;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'readyState', {
    configurable: true,
    enumerable: true,
    get: function() {
      if (this._socket && typeof this._socket.readyState === 'string') {
        return this._socket.readyState;
      }
      if (this.destroyed) return 'closed';
      return this.connecting ? 'opening' : 'open';
    }
  });
}

function _normalizeTlsConnectArguments(args) {
  var options = {};
  var callback = null;

  if (!args || !args.length) {
    return { options: options, callback: callback };
  }

  var first = args[0];
  var second = args[1];
  var third = args[2];
  var fourth = args[3];

  if (first && typeof first === 'object' && !Array.isArray(first)) {
    options = _cloneOwnProperties(first);
    callback = typeof second === 'function' ? second : null;
    return { options: options, callback: callback };
  }

  if (typeof first === 'number') {
    options.port = first;
    if (typeof second === 'string') {
      options.host = second;
      if (third && typeof third === 'object' && !Array.isArray(third)) {
        var thirdOptions = _cloneOwnProperties(third);
        for (var key in thirdOptions) {
          if (hasOwn.call(thirdOptions, key)) options[key] = thirdOptions[key];
        }
        callback = typeof fourth === 'function' ? fourth : null;
      } else {
        callback = typeof third === 'function' ? third : null;
      }
    } else if (second && typeof second === 'object' && !Array.isArray(second)) {
      var secondOptions = _cloneOwnProperties(second);
      for (var key2 in secondOptions) {
        if (hasOwn.call(secondOptions, key2)) options[key2] = secondOptions[key2];
      }
      callback = typeof third === 'function' ? third : null;
    } else {
      callback = typeof second === 'function' ? second : null;
    }
    if (!options.host && !options.hostname) options.host = 'localhost';
    return { options: options, callback: callback };
  }

  if (typeof first === 'string') {
    options.host = first;
    if (typeof second === 'number') {
      options.port = second;
      if (third && typeof third === 'object' && !Array.isArray(third)) {
        var thirdOptions2 = _cloneOwnProperties(third);
        for (var key3 in thirdOptions2) {
          if (hasOwn.call(thirdOptions2, key3)) options[key3] = thirdOptions2[key3];
        }
        callback = typeof fourth === 'function' ? fourth : null;
      } else {
        callback = typeof third === 'function' ? third : null;
      }
    } else if (second && typeof second === 'object' && !Array.isArray(second)) {
      var secondOptions2 = _cloneOwnProperties(second);
      for (var key4 in secondOptions2) {
        if (hasOwn.call(secondOptions2, key4)) options[key4] = secondOptions2[key4];
      }
      callback = typeof third === 'function' ? third : null;
    } else {
      callback = typeof second === 'function' ? second : null;
    }
    if (typeof options.port === 'undefined') options.port = 443;
    return { options: options, callback: callback };
  }

  return { options: options, callback: callback };
}

function connect() {
  var parsed = _normalizeTlsConnectArguments(arguments);
  var options = parsed.options || {};
  var cb = parsed.callback;

  var socket = new TLSSocket(options.socket || null, options);
  if (typeof cb === 'function' && typeof socket.once === 'function') {
    socket.once('secureConnect', cb);
  }

  var host = options.host || options.hostname || 'localhost';
  var port = typeof options.port === 'undefined' ? 443 : options.port;
  if (typeof port === 'string') port = Number(port);
  socket.remoteAddress = host;
  socket.remotePort = port;
  socket.connecting = true;
  socket.pending = true;
  if (options.servername || options.sni) {
    socket.servername = options.servername || options.sni;
    socket._servername = socket.servername;
  }
  socket._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
  socket.authorized = false;
  socket.authorizationError = null;

  try {
    var connectOptions = _cloneOwnProperties(options);
    if (!options.socket) {
      if (connectOptions.path) {
        delete connectOptions.host;
        delete connectOptions.hostname;
        delete connectOptions.port;
      } else {
        connectOptions.port = port;
        connectOptions.host = host;
        if (!connectOptions.hostname && options.hostname) {
          connectOptions.hostname = options.hostname;
        }
        if (
          !connectOptions.family &&
          connectOptions.autoSelectFamily === undefined &&
          host === 'localhost'
        ) {
          connectOptions.autoSelectFamily = true;
        }
      }
    }

    var netSocket = options.socket || (net && typeof net.connect === 'function'
      ? net.connect(connectOptions)
      : null);

    if (!netSocket) {
      setTimeout(function() {
        var err = new Error('net module not available for TLS transport');
        err.code = 'ECONNREFUSED';
        socket.emit('error', err);
      }, 0);
      return socket;
    }

    socket._setSocket(netSocket);

    var completed = false;
    function onConnect() {
      if (completed) return;
      completed = true;
      socket.connecting = false;
      socket.pending = false;
      socket.encrypted = true;
      socket._secureEstablished = true;
      _copySocketMetadata(socket, netSocket);
      socket.remoteAddress = host;
      socket.remotePort = port;
      socket.servername = options.servername || options.host || options.hostname || socket.servername;
      socket._session = null;
      socket._sessionReused = false;

      var handshakeOk = _finalizeHandshake(socket);
      if (handshakeOk || options.rejectUnauthorized === false) {
        socket.emit('secure', true);
        socket.emit('secureConnect');
      } else if (socket.authorizationError) {
        var err = new Error(socket.authorizationError);
        socket.emit('error', err);
        socket.destroy(err);
      }
    }

    if (typeof netSocket.on === 'function') {
      netSocket.on('connect', onConnect);
    }

    if (netSocket.connecting === false) {
      setTimeout(onConnect, 0);
    }
  } catch(e) {
    setTimeout(function() { socket.emit('error', e); }, 0);
  }

  return socket;
}

function addContext(serverName, context, server) {
  if (!server || !server._contexts) return false;
  if (typeof serverName !== 'string' || !serverName) {
    throw _createError('ERR_INVALID_ARG_TYPE', 'The "serverName" argument must be a non-empty string');
  }

  var secureContext = context instanceof SecureContext
    ? context
    : createSecureContext(context && context.context ? context.context : (context || {}));

  server._contexts[serverName] = secureContext;
  return true;
}

function _createBareServer() {
  var server = { _events: {} };
  _mixinEventEmitter(server);
  server.listen = function() { return this; };
  server.close = function(callback) {
    if (typeof callback === 'function') setTimeout(callback, 0);
    return this;
  };
  server.address = function() { return null; };
  server.ref = function() { return this; };
  server.unref = function() { return this; };
  return server;
}

function _decorateServer(server, options, secureConnectionListener) {
  var serverOptions = options || {};
  server._tlsOptions = _cloneOwnProperties(serverOptions);
  server._sharedCreds = createSecureContext(serverOptions);
  server._contexts = Object.create(null);
  server.requestCert = !!serverOptions.requestCert;
  server.rejectUnauthorized = !!serverOptions.rejectUnauthorized;
  server.allowHalfOpen = !!serverOptions.allowHalfOpen;
  server.addContext = function(serverName, context) {
    return addContext(serverName, context, server);
  };
  server.setSecureContext = function(nextOptions) {
    server._tlsOptions = _cloneOwnProperties(nextOptions || {});
    server._sharedCreds = createSecureContext(nextOptions || {});
    return server;
  };
  server.getTicketKeys = function() {
    return server._ticketKeys ? _cloneBufferLike(server._ticketKeys) : _getEmptyBuffer();
  };
  server.setTicketKeys = function(keys) {
    if (!_isArrayBufferView(keys)) {
      throw _createError(
        'ERR_INVALID_ARG_TYPE',
        'The "buffer" argument must be an instance of Buffer, TypedArray, or DataView'
      );
    }
    if (_byteLength(keys) !== 48) {
      throw _createError('ERR_TLS_INVALID_TICKET_KEYS', 'Session ticket keys must be a 48-byte buffer');
    }
    server._ticketKeys = _cloneBufferLike(keys);
    return server;
  };

  if (typeof secureConnectionListener === 'function' && typeof server.on === 'function') {
    server.on('secureConnection', secureConnectionListener);
  }

  return server;
}

function _createServerTLSSocket(server, rawSocket) {
  var serverOptions = server._tlsOptions || {};
  var tlsSocket = new TLSSocket(rawSocket, serverOptions);
  tlsSocket._server = server;
  tlsSocket.server = server;
  tlsSocket.connecting = false;
  tlsSocket.pending = false;
  tlsSocket._secureEstablished = true;
  tlsSocket._protocol = serverOptions.minVersion || serverOptions.maxVersion || DEFAULT_MAX_VERSION;
  _copySocketMetadata(tlsSocket, rawSocket);
  tlsSocket._peerCertificate = _buildSyntheticCertificate(
    tlsSocket.remoteAddress || tlsSocket.servername || 'localhost',
    tlsSocket.remotePort,
    serverOptions.cert || 'ExactTLS'
  );
  tlsSocket._localCertificate = _buildSyntheticCertificate(
    tlsSocket.remoteAddress || 'localhost',
    tlsSocket.remotePort,
    serverOptions.key || serverOptions.cert || 'ExactTLS'
  );
  tlsSocket._cipher = {
    name: _normalizeCipherName(serverOptions.ciphers),
    version: tlsSocket._protocol
  };
  tlsSocket.authorized = !server.requestCert;
  tlsSocket.authorizationError = null;
  tlsSocket.emit('secure', true);
  return tlsSocket;
}

function createServer(options, secureConnectionListener) {
  if (typeof options === 'function') {
    secureConnectionListener = options;
    options = {};
  }

  var serverOptions = options || {};
  var server = net && typeof net.createServer === 'function'
    ? net.createServer(serverOptions, function(rawSocket) {
        var tlsSocket = _createServerTLSSocket(server, rawSocket);
        server.emit('secureConnection', tlsSocket);
      })
    : _createBareServer();

  if (typeof Object.setPrototypeOf === 'function' && Server.prototype) {
    Object.setPrototypeOf(server, Server.prototype);
  }

  return _decorateServer(server, serverOptions, secureConnectionListener);
}

function Server(options, secureConnectionListener) {
  if (!(this instanceof Server)) return createServer(options, secureConnectionListener);
  return createServer(options, secureConnectionListener);
}

if (net && net.Server && net.Server.prototype && typeof Object.create === 'function') {
  Server.prototype = Object.create(net.Server.prototype);
} else {
  Server.prototype = {};
}
Server.prototype.constructor = Server;

function getCiphers() {
  return _getCipherList().slice();
}

module.exports = {
  CLIENT_RENEG_LIMIT: CLIENT_RENEG_LIMIT,
  CLIENT_RENEG_WINDOW: CLIENT_RENEG_WINDOW,
  TLSSocket: TLSSocket,
  Server: Server,
  SecureContext: SecureContext,
  connect: connect,
  createSecureContext: createSecureContext,
  checkServerIdentity: checkServerIdentity,
  createServer: createServer,
  convertALPNProtocols: convertALPNProtocols,
  getCACertificates: getCACertificates,
  setDefaultCACertificates: setDefaultCACertificates,
  getCiphers: getCiphers,
  DEFAULT_ECDH_CURVE: DEFAULT_ECDH_CURVE,
  DEFAULT_MIN_VERSION: DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION: DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS: DEFAULT_CIPHERS,
  rootCertificates: rootCertificates
};
module.exports.default = module.exports;
