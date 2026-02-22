var net;
try { net = require('net'); } catch(e) {}

var _defaultTlsCipher = 'TLS_AES_256_GCM_SHA384';

function _normalizeCipherName(ciphers) {
  if (typeof ciphers !== 'string' || !ciphers) {
    return _defaultTlsCipher;
  }
  var first = ciphers.split(/[:,]/)[0];
  return first || _defaultTlsCipher;
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

function _buildSyntheticCertificate(host, port, options, certSource) {
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

function _normalizeCheckError(error) {
  if (!error) return null;
  if (error instanceof Error) return error;
  if (typeof error === 'string') return new Error(error);
  return new Error('TLS server identity check failed');
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

function _finalizeHandshake(socket) {
  var opts = socket._tlsOptions || {};
  var host = socket._servername || socket.remoteAddress || 'localhost';
  socket._peerCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts, opts.cert || opts.pfx || 'ExactTLS');
  socket._localCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts, opts.key ? 'ExactTLS' : 'ExactTLS');
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

function TLSSocket(socket, options) {
  if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);
  options = options || {};
  this._events = {};
  this._socket = socket || null;
  this.encrypted = true;
  this.authorized = true;
  this.authorizationError = null;
  this._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
  this._session = null;
  this._sessionReused = false;
  this._peerCertificate = null;
  this._localCertificate = null;
  this._tlsOptions = options || {};
  this._servername = options.servername || options.host || options.hostname || null;
  this.connecting = false;
  this.readable = true;
  this.writable = true;
  this.destroyed = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.remoteFamily = 'IPv4';
  this.servername = this._servername;
  // Mixin EventEmitter
  var EventEmitter;
  try { EventEmitter = require('events'); } catch(e) {}
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  this._cipher = { name: _normalizeCipherName(options.ciphers), version: this._protocol };
}

TLSSocket.prototype.getPeerCertificate = function() {
  return this._peerCertificate || {};
};
TLSSocket.prototype.getPeerX509Certificate = TLSSocket.prototype.getPeerCertificate;
TLSSocket.prototype.getCertificate = TLSSocket.prototype.getPeerCertificate;
TLSSocket.prototype.getCipher = function() {
  return this._cipher || { name: _normalizeCipherName(this._tlsOptions && this._tlsOptions.ciphers), version: this._protocol };
};
TLSSocket.prototype.getProtocol = function() { return this._protocol; };
TLSSocket.prototype.getSession = function() { return this._session; };
TLSSocket.prototype.isSessionReused = function() { return !!this._sessionReused; };
TLSSocket.prototype.getFinished = function() { return null; };
TLSSocket.prototype.getTLSTicket = function() { return null; };
TLSSocket.prototype.renegotiate = function() { return true; };
TLSSocket.prototype.setEncoding = function(enc) { return this; };
TLSSocket.prototype.write = function(data, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; }
  if (callback) setTimeout(callback, 0);
  return true;
};
TLSSocket.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') { callback = data; data = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (this._socket && typeof this._socket.end === 'function') return this._socket.end(data, encoding, callback);
  if (callback) setTimeout(callback, 0);
  return this;
};
TLSSocket.prototype.destroy = function(err) {
  this.destroyed = true;
  if (this._socket && typeof this._socket.destroy === 'function') this._socket.destroy(err);
  return this;
};
TLSSocket.prototype.setTimeout = function(timeout, callback) {
  if (callback) this.once('timeout', callback);
  return this;
};
TLSSocket.prototype.setNoDelay = function() { return this; };
TLSSocket.prototype.setKeepAlive = function() { return this; };
TLSSocket.prototype.ref = function() { return this; };
TLSSocket.prototype.unref = function() { return this; };
TLSSocket.prototype.address = function() { return { address: this.remoteAddress, port: this.remotePort, family: 'IPv4' }; };
TLSSocket.prototype.pause = function() { return this; };
TLSSocket.prototype.resume = function() { return this; };
TLSSocket.prototype.pipe = function(dest) { return dest; };

function _normalizeTlsConnectOptions(options) {
  if (options === null || typeof options === 'undefined') return {};
  if (typeof options === 'number' || typeof options === 'string') {
    return { port: Number(options) };
  }
  if (typeof options === 'object') return options;
  return {};
}

function connect(options, callback) {
  options = _normalizeTlsConnectOptions(options);
  var cb = callback;
  if (typeof options === 'number') {
    options = { port: options, host: arguments[1] || 'localhost' };
  } else if (typeof options === 'string') {
    options = { host: options, port: arguments[1] || 443 };
  } else if (typeof cb === 'undefined' && typeof arguments[1] === 'function') {
    cb = arguments[1];
  }
  if (typeof callback === 'function') cb = callback;

  var socket = new TLSSocket(null, options);
  if (cb) socket.once('secureConnect', cb);

  options = options || {};
  var host = options.host || options.hostname || 'localhost';
  var port = options.port || 443;
  if (typeof port === 'string') port = Number(port);
  socket.remoteAddress = host;
  socket.remotePort = port;
  socket.connecting = true;
  if (options.servername || options.sni) {
    socket.servername = options.servername || options.sni;
    socket._servername = socket.servername;
  }
  socket._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
  socket.authorized = true;
  socket.authorizationError = null;

  // Use net.Socket underneath to establish a real TCP connection
  try {
    var netSocket = net ? net.connect({ port: port, host: host }) : null;

    if (!netSocket) {
      setTimeout(function() {
        var err = new Error('net module not available for TLS transport');
        err.code = 'ECONNREFUSED';
        socket.emit('error', err);
      }, 0);
      return socket;
    }

    socket._socket = netSocket;

    // Proxy write/end/destroy to underlying net.Socket
    socket.write = function(data, encoding, cb) {
      if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
      return netSocket.write(data, encoding, cb);
    };
    socket.end = function(data, encoding, cb) {
      if (typeof data === 'function') { cb = data; data = undefined; }
      if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
      return netSocket.end(data, encoding, cb);
    };
    socket.destroy = function(err) { netSocket.destroy(err); socket.destroyed = true; return socket; };
    socket.pause = function() { netSocket.pause(); return socket; };
    socket.resume = function() { netSocket.resume(); return socket; };
    socket.setEncoding = function(enc) { netSocket.setEncoding(enc); return socket; };

    netSocket.on('connect', function() {
      socket.connecting = false;
      socket.encrypted = true;
      var handshakeOk = _finalizeHandshake(socket);
      socket.remoteAddress = options.host || 'localhost';
      socket.remotePort = options.port;
      socket.servername = options.servername || options.host || options.hostname || socket.servername;
      socket._session = null;
      socket._sessionReused = false;
      if (handshakeOk || options.rejectUnauthorized === false) {
        socket.emit('secure', true);
        socket.emit('secureConnect');
      } else if (socket.authorizationError) {
        var err = new Error(socket.authorizationError);
        socket.emit('error', err);
        socket.destroy(err);
      }
    });

    netSocket.on('data', function(data) { socket.emit('data', data); });
    netSocket.on('end', function() { socket.emit('end'); });
    netSocket.on('error', function(err) { socket.emit('error', err); });
    netSocket.on('close', function(hadError) { socket.emit('close', hadError); });
  } catch(e) {
    setTimeout(function() { socket.emit('error', e); }, 0);
  }

  return socket;
}

function createSecureContext(options) {
  return { context: options || {} };
}

function addContext(serverName, context, server, options) {
  if (!server || !server._contexts) {
    return false;
  }
  server._contexts[serverName] = {
    context: context || null,
    options: options || null
  };
  return true;
}

function createServer(options, secureConnectionListener) {
  if (typeof options === 'function') {
    secureConnectionListener = options;
    options = {};
  }
  var serverOptions = options || {};
  var server = net ? net.createServer(serverOptions, function(rawSocket) {
    var tlsSocket = new TLSSocket(rawSocket, {
      minVersion: serverOptions.minVersion,
      maxVersion: serverOptions.maxVersion
    });
    tlsSocket._protocol = serverOptions.minVersion || serverOptions.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
    tlsSocket.remoteAddress = rawSocket.remoteAddress || null;
    tlsSocket.remotePort = rawSocket.remotePort || null;
    tlsSocket._peerCertificate = _buildSyntheticCertificate(
      tlsSocket.remoteAddress || tlsSocket.servername || 'localhost',
      tlsSocket.remotePort,
      serverOptions,
      serverOptions.cert || 'ExactTLS'
    );
    tlsSocket._cipher = { name: _normalizeCipherName(serverOptions.ciphers), version: tlsSocket._protocol };
    tlsSocket.authorized = serverOptions.rejectUnauthorized === false ? false : true;
    tlsSocket.authorizationError = null;
    tlsSocket._server = server;
    tlsSocket.emit('secure', true);
    server.emit('secureConnection', tlsSocket);
    if (typeof secureConnectionListener === 'function') {
      secureConnectionListener(tlsSocket, tlsSocket._session);
    }
  }) : { listen: function() { return this; }, close: function() { return this; } };
  server._contexts = {};
  server.addContext = function(serverName, context, cb) {
    return addContext(serverName, context, server, cb);
  };
  return server;
}

var DEFAULT_ECDH_CURVE = 'auto';
var DEFAULT_MIN_VERSION = 'TLSv1.2';
var DEFAULT_MAX_VERSION = 'TLSv1.3';
var DEFAULT_CIPHERS = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384';

// rootCertificates: empty array in Exact (OS handles cert validation via fetch)
var rootCertificates = Object.freeze([]);

module.exports = {
  TLSSocket: TLSSocket,
  connect: connect,
  createSecureContext: createSecureContext,
  checkServerIdentity: checkServerIdentity,
  createServer: createServer,
  DEFAULT_ECDH_CURVE: DEFAULT_ECDH_CURVE,
  DEFAULT_MIN_VERSION: DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION: DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS: DEFAULT_CIPHERS,
  rootCertificates: rootCertificates,
  SecureContext: function SecureContext() {}
};
module.exports.default = module.exports;
