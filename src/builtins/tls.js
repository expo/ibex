var net;
try { net = require('net'); } catch(e) {
  // Optional during reduced-runtime bootstrap; callers validate availability.
}
var _kReinitializeHandle = Symbol.for('nodejs.net.kReinitializeHandle');
var _kRunOwnedServer = Symbol.for('ibex.tls.runOwnedServer');
var _kCloseOwnedServer = Symbol.for('ibex.tls.closeOwnedServer');
var _kRegisterNetServerOwnerGuard = Symbol.for('ibex.net.registerServerOwnerGuard');
var _kSetHttpResetAsEof = Symbol.for('ibex.tls.setHttpResetAsEof');
var _kFlowControlStats = Symbol.for('ibex.tls.flowControlStats');

var eventsModule;
try { eventsModule = require('events'); } catch(e) {
  // Optional during reduced-runtime bootstrap; callers validate availability.
}
var cryptoModule;
try { cryptoModule = require('crypto'); } catch(e) {
  // Optional during reduced-runtime bootstrap; callers validate availability.
}
var StringDecoder = null;
try { StringDecoder = require('node:string_decoder').StringDecoder; } catch (_decoderErr) {
  try { StringDecoder = require('string_decoder').StringDecoder; } catch (_decoderErr2) {
    // The byte fallback below handles runtimes without either decoder module.
  }
}

var EventEmitter = eventsModule && (eventsModule.EventEmitter || eventsModule);
var _tlsErrorMonitor = eventsModule && eventsModule.errorMonitor;
var hasOwn = Object.prototype.hasOwnProperty;

var CLIENT_RENEG_LIMIT = 3;
var CLIENT_RENEG_WINDOW = 600;
var DEFAULT_ECDH_CURVE = 'auto';
var DEFAULT_MIN_VERSION = 'TLSv1.2';
var DEFAULT_MAX_VERSION = 'TLSv1.3';
var DEFAULT_CIPHERS = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384';

var _defaultTlsCipher = 'TLS_AES_256_GCM_SHA384';
var _tlsServersByPort = Object.create(null);
var _tlsServerStates = typeof WeakMap === 'function' ? new WeakMap() : null;
var _tlsSocketPrivateStates = typeof WeakMap === 'function' ? new WeakMap() : null;
var _tlsTransportIdentities = typeof WeakMap === 'function' ? new WeakMap() : null;
var _secureContextStates = typeof WeakMap === 'function' ? new WeakMap() : null;
var MAX_PENDING_TLS_HANDSHAKES = 1024;
var TLS_LOOPBACK_HANDSHAKE_TIMEOUT_MS = 30000;
// Native engine selectors and per-source pipe backpressure are private
// control-plane state. Public writable object properties must not become
// authority-bearing handles or let one destination resume another's source.
var _nativeTlsEngineIds = typeof WeakMap === 'function' ? new WeakMap() : null;
var _nativeTlsOwnerTokens = typeof WeakMap === 'function' ? new WeakMap() : null;
var _tlsPipeBackpressureStates = typeof WeakMap === 'function' ? new WeakMap() : null;
var _defaultTls13CipherPriority = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_AES_128_GCM_SHA256'
];
var _supportedTls13CipherPriority = _defaultTls13CipherPriority.concat([
  'TLS_AES_128_CCM_8_SHA256'
]);
var _legacyCipherPriority = [
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'AES256-SHA',
  'AES256-SHA256'
];
var _supportedCipherSet = Object.create(null);
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

function _normalizeTlsHighWaterMark(value, fallback) {
  var number = Number(value);
  if (!isFinite(number) || number <= 0) number = Number(fallback);
  if (!isFinite(number) || number <= 0) number = 16384;
  return Math.max(1, Math.floor(number));
}

function _tlsWriteBuffer(data, encoding) {
  return typeof data === 'string'
    ? (typeof Buffer !== 'undefined' ? Buffer.from(data, encoding || 'utf8') : _stringToBytes(data))
    : _cloneBufferLike(data);
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

// Define an own, writable data property. With TLSSocket.prototype chained to
// net.Socket.prototype (see the wiring below the TLSSocket methods), a plain
// `this.x = v` in the constructor can hit an inherited accessor instead of
// creating an own property — e.g. Node/bun's net.Socket exposes remoteAddress
// and stream state (readable/writable/destroyed) as prototype accessors whose
// setters silently drop the value when the internal state is missing. TLSSocket
// carries its own flat state, so force own data properties for those names.
function _defineOwnDataProperty(target, name, value) {
  var protectedState = _tlsSocketPrivateStates && _tlsSocketPrivateStates.get(target);
  if (protectedState && typeof Object.defineProperty === 'function') {
    protectedState.publicValues[name] = value;
    Object.defineProperty(target, name, {
      enumerable: true,
      configurable: false,
      get: function() {
        _tlsAssertOwner(target);
        return protectedState.publicValues[name];
      },
      set: function(nextValue) {
        _tlsAssertMutableOwner(target);
        protectedState.publicValues[name] = nextValue;
      }
    });
    return;
  }
  if (typeof Object.defineProperty === 'function') {
    try {
      Object.defineProperty(target, name, {
        value: value,
        writable: true,
        enumerable: true,
        configurable: true
      });
      return;
    } catch (_definePropErr) { /* ignored: non-configurable inherited property; fall back to plain assignment below */ }
  }
  target[name] = value;
}

var _tlsPrivatePropertyNames = [
  '_events', '_socket', '_boundSocket', '_boundSocketListeners', '_tlsOptions',
  '_authorizationErrorObject',
  '_protocol', '_session', '_sessionReused', '_peerCertificate', '_localCertificate',
  '_readableHighWaterMark', '_writableHighWaterMark', '_bufferedBytes',
  '_bridgeNeedDrain', '_secureEstablished', '_tlsApplicationReady', '_tlsUserPaused',
  '_tlsErrorEmitted', '_tlsCloseEmitted', '_tlsDeferredTransportClose',
  '_tlsDeferredCloseHadError', '_pending', '_servername', '_cipher', '_writeHeld',
  '_heldWrites', '_heldWriteBytes', '_heldEnd', '_tlsTransportUndecided',
  '_tlsAwaitingConnectEvent', '_tlsUndecidedEvents', '_tlsUndecidedData',
  '_tlsUndecidedDataBytes', '_tlsUndecidedInputPaused',
  '_tlsUndecidedTransportEnded', '_tlsUndecidedTransportClosed',
  '_tlsPendingTerminalError', '_tlsFailureError', '_tlsSuppressRawClose',
  '_bridged', '_bridgePendingWrites', '_bridgePendingWriteBytes', '_bridgeHeldEnd',
  '_bridgeTransportBackpressured', '_bridgeCipherQueue', '_bridgeCipherQueueBytes',
  '_bridgeReadQueue', '_bridgeReadQueueBytes', '_bridgeReadQueueOffset',
  '_bridgeDecodedTail', '_bridgeDecoder', '_bridgeEncoding', '_bridgePaused',
  '_bridgeInputPaused', '_bridgeEndEmitted', '_bridgeEndScheduled',
  '_bridgeShutdownQueued', '_bridgeNativeEnded', '_bridgeDecoderFinalized',
  '_bridgeWriteRetryScheduled', '_bridgeTransportEofApplied', '_bridgeTransportEnded',
  '_bridgeProcessingCipher', '_bridgeDrainingPlain', '_bridgeDrainScheduled',
  '_bridgeReadDepth', '_bridgeFailed', '_bridgeCipherSuites', '_bridgePumpActive',
  '_bridgePumpAgain', '_bridgeWriteInFlight', '_bridgeDrainDuringWrite',
  '_ciphertextHighWaterMark', '_tlsHandshakeFinalizing', '_tlsLoopbackConnectionKey',
  '_server', '_renegotiationDisabled', '_maxSendFragment', '_isWriting', '_writeQueue',
  '_captureRejections'
];

function _installTlsPrivateState(target) {
  if (!_tlsSocketPrivateStates || typeof Object.defineProperty !== 'function') {
    throw _createError(
      'ERR_TLS_PRIVATE_STATE_UNAVAILABLE',
      'TLSSocket requires WeakMap-backed private state'
    );
  }
  var state = { values: Object.create(null), publicValues: Object.create(null) };
  _tlsSocketPrivateStates.set(target, state);
  for (var i = 0; i < _tlsPrivatePropertyNames.length; i++) {
    (function(name) {
      if (hasOwn.call(target, name)) state.values[name] = target[name];
      try { delete target[name]; } catch (_deletePrivateErr) {
        // Non-configurable host fields remain authoritative projections.
      }
      Object.defineProperty(target, name, {
        enumerable: false,
        configurable: false,
        get: function() {
          if (name === '_events') {
            _tlsAssertOwner(target);
            return state.values[name];
          }
          throw _createError(
            'ERR_TLS_PRIVATE_STATE',
            'TLSSocket internal state is not publicly accessible'
          );
        },
        set: function(_value) {
          if (name === '_events') {
            _tlsAssertMutableOwner(target);
            state.values[name] = _value;
            return;
          }
          throw _createError(
            'ERR_TLS_PRIVATE_STATE',
            'TLSSocket internal state is not publicly mutable'
          );
        }
      });
    })(_tlsPrivatePropertyNames[i]);
  }
}

function _tlsPriv(target) {
  var state = _tlsSocketPrivateStates && _tlsSocketPrivateStates.get(target);
  if (!state) {
    throw _createError('ERR_TLS_INVALID_SOCKET', 'Invalid TLSSocket receiver');
  }
  return state.values;
}

function _tlsPub(target) {
  var state = _tlsSocketPrivateStates && _tlsSocketPrivateStates.get(target);
  if (!state) {
    throw _createError('ERR_TLS_INVALID_SOCKET', 'Invalid TLSSocket receiver');
  }
  return state.publicValues;
}

function _tlsListenerCountInternal(socket, eventName) {
  var events = _tlsPriv(socket)._events;
  var listener = events && events[eventName];
  if (!listener) return 0;
  return typeof listener === 'function' ? 1 : listener.length || 0;
}

function _tlsEmitInternal(socket, eventName, args) {
  _tlsAssertOwner(socket);
  var eventArgs = args || [];
  var events = _tlsPriv(socket)._events;
  var captureRejections = eventName !== 'error' && !!(
    _tlsPriv(socket)._captureRejections ||
    (EventEmitter && EventEmitter.captureRejections) ||
    (eventsModule && eventsModule.captureRejections)
  );
  function invoke(listener) {
    var result = listener.apply(socket, eventArgs);
    if (!captureRejections || !result || typeof result.then !== 'function') return;
    result.then(undefined, function(error) {
      _tlsEmitInternal(socket, 'error', [error]);
    });
  }
  function dispatch(name) {
    var handler = events && events[name];
    if (!handler) return false;
    if (typeof handler === 'function') {
      invoke(handler);
      return true;
    }
    var listeners = handler.slice ? handler.slice() : [];
    for (var i = 0; i < listeners.length; i++) {
      if (typeof listeners[i] === 'function') invoke(listeners[i]);
    }
    return listeners.length > 0;
  }
  if (eventName === 'error' && _tlsErrorMonitor) dispatch(_tlsErrorMonitor);
  var handled = dispatch(eventName);
  if (!handled && eventName === 'error') {
    var error = eventArgs[0];
    if (error instanceof Error) throw error;
    throw _createError('ERR_UNHANDLED_ERROR', 'Unhandled error event');
  }
  return handled;
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

function _markSupportedCiphers(list) {
  for (var i = 0; i < list.length; i++) {
    _supportedCipherSet[list[i]] = true;
  }
}

_markSupportedCiphers(_supportedTls13CipherPriority);
_markSupportedCiphers(_legacyCipherPriority);

function _isTls13CipherName(name) {
  return typeof name === 'string' && name.indexOf('TLS_') === 0;
}

function _supportsTls13(options) {
  var maxVersion = options && options.maxVersion;
  if (!maxVersion) maxVersion = DEFAULT_MAX_VERSION;
  return maxVersion === 'TLSv1.3';
}

function _createCipherTypeError(value) {
  return _createError(
    'ERR_INVALID_ARG_TYPE',
    'The "ciphers" argument must be of type string. Received ' + typeof value
  );
}

function _createCipherValueError(value) {
  return _createError(
    'ERR_INVALID_ARG_VALUE',
    'The property \'ciphers\' is invalid. Received ' + JSON.stringify(value)
  );
}

function _createNoCipherMatchError() {
  var err = new Error('no cipher match');
  err.code = 'ERR_SSL_NO_CIPHER_MATCH';
  return err;
}

function _createTlsAlertHandshakeFailureError() {
  return _createError(
    'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
    'sslv3 alert handshake failure'
  );
}

function _createNoSharedCipherError() {
  return _createError('ERR_SSL_NO_SHARED_CIPHER', 'no shared cipher');
}

function _uniqueCipherList(list) {
  var out = [];
  var seen = Object.create(null);
  for (var i = 0; i < list.length; i++) {
    var name = list[i];
    if (!name || seen[name]) continue;
    seen[name] = true;
    out.push(name);
  }
  return out;
}

function _normalizeCipherTokens(ciphers, mode) {
  if (ciphers === undefined || ciphers === null || ciphers === '') {
    return [];
  }
  if (typeof ciphers !== 'string') {
    throw _createCipherTypeError(ciphers);
  }

  var tokens = String(ciphers).split(':');
  var normalized = [];
  for (var i = 0; i < tokens.length; i++) {
    var token = tokens[i] && String(tokens[i]).trim();
    if (!token) {
      throw _createCipherValueError(ciphers);
    }
    var exclude = token.charAt(0) === '!';
    var name = exclude ? token.slice(1) : token;
    if (!name) {
      throw _createCipherValueError(ciphers);
    }
    if (!_supportedCipherSet[name]) {
      if (mode === 'server') {
        throw _createNoCipherMatchError();
      }
      throw _createCipherValueError(ciphers);
    }
    normalized.push({
      name: name,
      exclude: exclude,
      tls13: _isTls13CipherName(name)
    });
  }
  return normalized;
}

function _resolveCipherSuites(options, mode) {
  var tlsOptions = options || {};
  var ciphers = tlsOptions.ciphers;
  var allowTls13 = _supportsTls13(tlsOptions);
  var tokens = _normalizeCipherTokens(ciphers, mode);
  var excludes = Object.create(null);
  var includes = [];
  for (var i = 0; i < tokens.length; i++) {
    if (tokens[i].exclude) excludes[tokens[i].name] = true;
    else includes.push(tokens[i]);
  }

  var suites = [];
  if (ciphers === undefined || ciphers === null || ciphers === '') {
    if (allowTls13) suites = suites.concat(_defaultTls13CipherPriority);
    suites = suites.concat(_legacyCipherPriority);
    return _uniqueCipherList(suites);
  }

  var tls13Includes = [];
  var legacyIncludes = [];
  for (var j = 0; j < includes.length; j++) {
    if (includes[j].tls13) tls13Includes.push(includes[j].name);
    else legacyIncludes.push(includes[j].name);
  }

  if (allowTls13) {
    var tls13Base = tls13Includes.length ? tls13Includes : _defaultTls13CipherPriority.slice();
    for (var k = 0; k < tls13Base.length; k++) {
      if (!excludes[tls13Base[k]]) suites.push(tls13Base[k]);
    }
  }

  var legacyBase = legacyIncludes.length ? legacyIncludes : [];
  for (var m = 0; m < legacyBase.length; m++) {
    if (!excludes[legacyBase[m]]) suites.push(legacyBase[m]);
  }

  suites = _uniqueCipherList(suites);
  if (!suites.length) {
    throw _createNoCipherMatchError();
  }
  return suites;
}

function _negotiateTlsVersion(clientOptions, serverOptions) {
  var order = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
  var clientMin = order.indexOf((clientOptions && clientOptions.minVersion) || DEFAULT_MIN_VERSION);
  var clientMax = order.indexOf((clientOptions && clientOptions.maxVersion) || DEFAULT_MAX_VERSION);
  var serverMin = order.indexOf((serverOptions && serverOptions.minVersion) || DEFAULT_MIN_VERSION);
  var serverMax = order.indexOf((serverOptions && serverOptions.maxVersion) || DEFAULT_MAX_VERSION);
  var minimum = Math.max(clientMin, serverMin);
  var maximum = Math.min(clientMax, serverMax);
  return minimum <= maximum ? order[maximum] : null;
}

function _selectNegotiatedCipher(clientOptions, serverOptions, negotiatedProtocol) {
  var clientSuites = _resolveCipherSuites(clientOptions, 'client');
  var serverSuites = _resolveCipherSuites(serverOptions, 'server');
  var clientSet = Object.create(null);
  var serverSet = Object.create(null);
  for (var i = 0; i < clientSuites.length; i++) clientSet[clientSuites[i]] = true;
  for (var j = 0; j < serverSuites.length; j++) serverSet[serverSuites[j]] = true;

  if (negotiatedProtocol === 'TLSv1.3') {
    for (var k = 0; k < _supportedTls13CipherPriority.length; k++) {
      var tls13Cipher = _supportedTls13CipherPriority[k];
      if (clientSet[tls13Cipher] && serverSet[tls13Cipher]) {
        return tls13Cipher;
      }
    }
    return null;
  }

  for (var m = 0; m < _legacyCipherPriority.length; m++) {
    var legacyCipher = _legacyCipherPriority[m];
    if (clientSet[legacyCipher] && serverSet[legacyCipher]) {
      return legacyCipher;
    }
  }

  return null;
}

function _tlsServerState(server) {
  if (!_tlsServerStates || !server) return null;
  var state = _tlsServerStates.get(server);
  if (!state) {
    state = {
      server: server,
      options: {},
      advertisedOptions: {},
      pendingSockets: [],
      pendingHandshakes: [],
      registeredEntry: null,
      ownerPump: null,
      ownerToken: null,
      closed: true,
      retired: false
    };
    _tlsServerStates.set(server, state);
  }
  return state;
}

function _tlsAdvertisedServerOptions(options) {
  var source = options || {};
  return {
    // Certificates and CAs are public verification material. Private keys,
    // PFX blobs, and passphrases deliberately never cross the server-owner
    // boundary through the loopback coordinator.
    cert: source.cert || null,
    ca: source.ca,
    hasPfx: source.pfx !== undefined && source.pfx !== null,
    hasKey: source.key !== undefined && source.key !== null,
    ciphers: source.ciphers,
    minVersion: source.minVersion,
    maxVersion: source.maxVersion,
    requestCert: source.requestCert === true,
    rejectUnauthorized: source.rejectUnauthorized === true
  };
}

function _tlsAdvertisedClientOptions(options) {
  var source = options || {};
  return {
    // A client certificate is public; its key/PFX/passphrase remain private to
    // the client owner. Synthetic loopback mTLS always reports authorization
    // unsupported because it cannot perform CertificateVerify.
    cert: source.cert || null,
    pfx: source.pfx !== undefined && source.pfx !== null ? true : null,
    hasKey: source.key !== undefined && source.key !== null
  };
}

function _normalizeTlsRegistryAddress(address) {
  if (address === undefined || address === null) return null;
  var value = String(address).toLowerCase();
  if (value.charAt(0) === '[' && value.charAt(value.length - 1) === ']') {
    value = value.slice(1, -1);
  }
  var scope = value.indexOf('%');
  if (scope !== -1) value = value.slice(0, scope);
  if (value.indexOf('::ffff:') === 0 && /^::ffff:\d+\.\d+\.\d+\.\d+$/.test(value)) {
    value = value.slice(7);
  }
  return value;
}

function _tlsAddressFamily(address, family) {
  // IPv4-mapped IPv6 endpoints normalize to dotted IPv4 above; use that
  // canonical family even when the platform reports the accepted side as
  // `IPv6`, so both halves of a dual-stack connection derive the same key.
  if (address && /^\d+\.\d+\.\d+\.\d+$/.test(address)) return 'ipv4';
  var normalizedFamily = family && String(family).toLowerCase();
  if (normalizedFamily === 'ipv4' || normalizedFamily === '4') return 'ipv4';
  if (normalizedFamily === 'ipv6' || normalizedFamily === '6') return 'ipv6';
  return address && address.indexOf(':') !== -1 ? 'ipv6' : 'ipv4';
}

function _removeTlsRegistryEntry(entry) {
  if (!entry) return;
  var key = String(entry.port);
  var bucket = _tlsServersByPort[key];
  if (!bucket) return;
  var index = bucket.indexOf(entry);
  if (index !== -1) bucket.splice(index, 1);
  if (!bucket.length) delete _tlsServersByPort[key];
}

function _tlsServerAccessibleFromCurrentPrincipal(entry) {
  if (!entry || !entry.server) return false;
  var state = _tlsServerState(entry.server);
  if (!state || state.closed) return false;
  if (state.ownerToken == null || typeof __exactTlsOwnerToken !== 'function') return true;
  try {
    __exactTlsOwnerToken('assert', state.ownerToken);
    return true;
  } catch (_wrongServerOwner) {
    return false;
  }
}

function _tlsAssertServerOwner(server) {
  var state = _tlsServerState(server);
  if (!state || typeof __exactTlsOwnerToken !== 'function') return;
  if (state.ownerToken == null) {
    throw _createError(
      'ERR_TLS_SERVER_CLOSED',
      'TLS server owner capability is not active; call listen() before using the server again'
    );
  }
  __exactTlsOwnerToken('assert', state.ownerToken);
}

function _registerTlsServer(server) {
  if (!server || typeof server.address !== 'function') return;
  var address = server.address();
  var state = _tlsServerState(server);
  if (!state) return;
  state.closed = false;
  if (!address || typeof address.port === 'undefined' || address.port === null) return;
  _removeTlsRegistryEntry(state.registeredEntry);
  var normalizedAddress = _normalizeTlsRegistryAddress(address.address);
  var entry = {
    server: server,
    port: Number(address.port),
    address: normalizedAddress,
    family: _tlsAddressFamily(normalizedAddress, address.family)
  };
  var key = String(entry.port);
  if (!_tlsServersByPort[key]) _tlsServersByPort[key] = [];
  _tlsServersByPort[key].push(entry);
  state.registeredEntry = entry;
}

function _unregisterTlsServer(server) {
  var state = _tlsServerState(server);
  if (!state) return;
  state.closed = true;
  _removeTlsRegistryEntry(state.registeredEntry);
  state.registeredEntry = null;
}

function _lookupTlsServer(port, destinationAddress, destinationFamily) {
  if (port === undefined || port === null) return null;
  var bucket = _tlsServersByPort[String(Number(port))];
  if (!bucket || !bucket.length) return null;
  var address = _normalizeTlsRegistryAddress(destinationAddress);
  var family = _tlsAddressFamily(address, destinationFamily);
  for (var i = 0; i < bucket.length; i++) {
    if (address && bucket[i].address === address &&
        _tlsServerAccessibleFromCurrentPrincipal(bucket[i])) return bucket[i].server;
  }
  var wildcard = family === 'ipv6' ? '::' : '0.0.0.0';
  for (var j = 0; j < bucket.length; j++) {
    if (bucket[j].family === family && bucket[j].address === wildcard) {
      if (_tlsServerAccessibleFromCurrentPrincipal(bucket[j])) return bucket[j].server;
    }
  }
  // An IPv6 wildcard listener may be dual-stack. Only select it when there is
  // no competing IPv4 entry, so same-port v4/v6 listeners cannot cross-pair.
  if (family === 'ipv4') {
    var dualStack = null;
    var hasIpv4 = false;
    for (var k = 0; k < bucket.length; k++) {
      if (bucket[k].family === 'ipv4') hasIpv4 = true;
      if (bucket[k].family === 'ipv6' && bucket[k].address === '::') {
        if (_tlsServerAccessibleFromCurrentPrincipal(bucket[k])) dualStack = bucket[k].server;
      }
    }
    if (!hasIpv4 && dualStack) return dualStack;
  }
  return !address && bucket.length === 1 && _tlsServerAccessibleFromCurrentPrincipal(bucket[0])
    ? bucket[0].server
    : null;
}

function _tlsConnectionEndpoint(address, family, port) {
  var normalizedAddress = _normalizeTlsRegistryAddress(address);
  if (!normalizedAddress || port === undefined || port === null) return null;
  return _tlsAddressFamily(normalizedAddress, family) + ':' + normalizedAddress + ':' +
    String(Number(port));
}

function _tlsClientConnectionKey(identity, peerPort) {
  if (!identity) return null;
  var local = _tlsConnectionEndpoint(
    identity.localAddress,
    identity.localFamily,
    identity.localPort
  );
  var remote = _tlsConnectionEndpoint(
    identity.remoteAddress,
    identity.remoteFamily,
    peerPort
  );
  return local && remote ? local + '>' + remote : null;
}

function _tlsServerConnectionKey(rawSocket) {
  if (!rawSocket) return null;
  var remote = _tlsConnectionEndpoint(
    rawSocket.remoteAddress,
    rawSocket.remoteFamily,
    rawSocket.remotePort
  );
  var local = _tlsConnectionEndpoint(
    rawSocket.localAddress,
    rawSocket.localFamily,
    rawSocket.localPort
  );
  return remote && local ? remote + '>' + local : null;
}

function _captureTlsTransportIdentity(wrapper, rawSocket) {
  if (!_tlsTransportIdentities || !wrapper || !rawSocket) return null;
  var existing = _tlsTransportIdentities.get(wrapper);
  if (existing) return existing;
  var identity = {
    localAddress: rawSocket.localAddress || null,
    localPort: rawSocket.localPort,
    localFamily: rawSocket.localFamily || null,
    remoteAddress: rawSocket.remoteAddress || null,
    remotePort: rawSocket.remotePort,
    remoteFamily: rawSocket.remoteFamily || null
  };
  if (typeof Object.freeze === 'function') Object.freeze(identity);
  _tlsTransportIdentities.set(wrapper, identity);
  return identity;
}

function _shiftPendingServerSocket(server, connectionKey) {
  var state = _tlsServerState(server);
  if (!state || !state.pendingSockets.length) return null;
  for (var i = 0; i < state.pendingSockets.length;) {
    var entry = state.pendingSockets[i];
    var candidate = entry && entry.socket;
    if (!candidate || _tlsPub(candidate).destroyed) {
      state.pendingSockets.splice(i, 1);
      continue;
    }
    if ((connectionKey && _tlsPriv(candidate)._tlsLoopbackConnectionKey === connectionKey) ||
        (!connectionKey && !_tlsPriv(candidate)._tlsLoopbackConnectionKey)) {
      state.pendingSockets.splice(i, 1);
      return entry;
    }
    i++;
  }
  return null;
}

function _shiftPendingServerHandshake(server, connectionKey) {
  var state = _tlsServerState(server);
  if (!state) return null;
  for (var i = 0; i < state.pendingHandshakes.length; i++) {
    var handshake = state.pendingHandshakes[i];
    if ((connectionKey && handshake.connectionKey === connectionKey) ||
        (!connectionKey && !handshake.connectionKey)) {
      state.pendingHandshakes.splice(i, 1);
      if (handshake.timeout) clearTimeout(handshake.timeout);
      handshake.timeout = null;
      return handshake;
    }
  }
  return null;
}

function _queuePendingServerHandshake(server, handshake, connectionKey) {
  var state = _tlsServerState(server);
  if (!state || state.closed ||
      state.pendingHandshakes.length >= MAX_PENDING_TLS_HANDSHAKES) return false;
  handshake.connectionKey = connectionKey || null;
  state.pendingHandshakes.push(handshake);
  handshake.timeout = setTimeout(function() {
    if (handshake.clientSocket) _tlsAssertOwner(handshake.clientSocket);
    var index = state.pendingHandshakes.indexOf(handshake);
    if (index === -1) return;
    state.pendingHandshakes.splice(index, 1);
    var err = _createError('ERR_TLS_HANDSHAKE_TIMEOUT', 'TLS loopback handshake timed out');
    _clearLoopbackClientCloseWatch(handshake);
    if (handshake.clientSocket && !handshake.clientSocket.destroyed) {
      _destroyTlsSocketWithError(handshake.clientSocket, err, false);
    }
  }, TLS_LOOPBACK_HANDSHAKE_TIMEOUT_MS);
  if (handshake.timeout && typeof handshake.timeout.unref === 'function') handshake.timeout.unref();
  return true;
}

function _watchLoopbackClientClose(handshake) {
  if (!handshake || !handshake.clientSocket || handshake.clientCloseListener) return;
  handshake.clientCloseListener = function() {
    if (handshake.delivered) return;
    handshake.ok = false;
    handshake.serverError = _createError(
      'ECONNRESET',
      'TLS client closed before the server handshake completed'
    );
  };
  handshake.clientSocket.once('close', handshake.clientCloseListener);
}

function _clearLoopbackClientCloseWatch(handshake) {
  if (!handshake || !handshake.clientCloseListener) return;
  if (handshake.clientSocket && typeof handshake.clientSocket.removeListener === 'function') {
    handshake.clientSocket.removeListener('close', handshake.clientCloseListener);
  }
  handshake.clientCloseListener = null;
  handshake.delivered = true;
}

function _deliverServerHandshake(server, connectionKey, handshake) {
  var deliveryState = _tlsServerState(server);
  if (!deliveryState || deliveryState.closed) return false;
  _watchLoopbackClientClose(handshake);
  var pendingEntry = _shiftPendingServerSocket(server, connectionKey);
  if (pendingEntry) {
    // Do not invoke server-owned socket methods or emit server events from the
    // client principal. The server-owner pump consumes this message next turn.
    pendingEntry.handshake = handshake;
    deliveryState.pendingSockets.push(pendingEntry);
    return 'accepted';
  }
  return _queuePendingServerHandshake(server, handshake, connectionKey)
    ? 'queued'
    : false;
}

function _publishLoopbackClientHandshake(socket, handshake) {
  if (!handshake || handshake.clientPublished) return !!(handshake && handshake.ok);
  handshake.clientPublished = true;
  handshake.resumeClient = null;
  _tlsAssertOwner(socket);
  if (_tlsPub(socket).destroyed || _tlsRawTransportDestroyed(socket)) {
    if (!_tlsPub(socket).destroyed) _terminateTlsForDestroyedTransport(socket);
    _tlsReleaseHeldWrites(socket, 'drop');
    handshake.ok = false;
    handshake.serverError = _createError(
      'ECONNRESET',
      'TLS client closed before secureConnect'
    );
    return false;
  }
  _tlsEmitInternal(socket, 'secureConnect');
  if (_tlsPub(socket).destroyed || _tlsRawTransportDestroyed(socket)) {
    if (!_tlsPub(socket).destroyed) _terminateTlsForDestroyedTransport(socket);
    _tlsReleaseHeldWrites(socket, 'drop');
    handshake.ok = false;
    handshake.serverError = _createError(
      'ECONNRESET',
      'TLS client closed during secureConnect'
    );
    return false;
  }
  _tlsEmitInternal(socket, 'secure', [true]);
  if (_tlsPub(socket).destroyed || _tlsRawTransportDestroyed(socket)) {
    if (!_tlsPub(socket).destroyed) _terminateTlsForDestroyedTransport(socket);
    _tlsReleaseHeldWrites(socket, 'drop');
    handshake.ok = false;
    handshake.serverError = _createError(
      'ECONNRESET',
      'TLS client closed during secure'
    );
    return false;
  }
  if (!_tlsReleaseHeldWrites(socket, 'raw')) {
    handshake.ok = false;
    handshake.serverError = _createError(
      'ECONNRESET',
      'TLS client transport failed while releasing queued writes'
    );
    return false;
  }
  return true;
}

function _normalizeCipherName(ciphers) {
  if (typeof ciphers !== 'string' || !ciphers) {
    return _defaultTlsCipher;
  }
  var first = ciphers.split(/[:,]/)[0];
  if (first && first.charAt(0) === '!') first = first.slice(1);
  return first || _defaultTlsCipher;
}

function _getCipherList() {
  var result = [];
  var suites = _supportedTls13CipherPriority.concat(_legacyCipherPriority);
  for (var i = 0; i < suites.length; i++) {
    result.push(String(suites[i]).toLowerCase());
  }
  result.sort();
  return _uniqueCipherList(result);
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

var _certificateParseCache = typeof Map !== 'undefined' ? new Map() : null;
var _certificateParseCacheBytes = 0;
var MAX_CERTIFICATE_PARSE_CACHE_ENTRIES = 256;
var MAX_CERTIFICATE_PARSE_CACHE_BYTES = 4 * 1024 * 1024;

function _cacheParsedCertificate(pem, parsed) {
  if (!_certificateParseCache) return;
  var size = (pem.length * 2) + _byteLength(parsed && parsed.raw);
  if (size > MAX_CERTIFICATE_PARSE_CACHE_BYTES / 4) return;
  while (_certificateParseCache.size >= MAX_CERTIFICATE_PARSE_CACHE_ENTRIES ||
         _certificateParseCacheBytes + size > MAX_CERTIFICATE_PARSE_CACHE_BYTES) {
    var oldest = _certificateParseCache.keys().next();
    if (oldest.done) break;
    var evicted = _certificateParseCache.get(oldest.value);
    _certificateParseCache.delete(oldest.value);
    _certificateParseCacheBytes = Math.max(
      0,
      _certificateParseCacheBytes - (evicted && evicted.cacheBytes || 0)
    );
  }
  _certificateParseCache.set(pem, { certificate: parsed, cacheBytes: size });
  _certificateParseCacheBytes += size;
}

function _pemSourceToString(source) {
  if (source == null) return '';
  if (typeof source === 'string') return source;
  if (Array.isArray(source)) {
    var combined = '';
    for (var i = 0; i < source.length; i++) {
      combined += _pemSourceToString(source[i]);
      if (combined && combined[combined.length - 1] !== '\n') combined += '\n';
    }
    return combined;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(source)) {
    return source.toString('utf8');
  }
  if (_isArrayBufferView(source)) {
    return _bufferFromBytes(source).toString ? _bufferFromBytes(source).toString('utf8') : String(source);
  }
  return String(source);
}

var _maxClientIdentityBytes = 16 * 1024 * 1024;

function _normalizePfxIdentity(source, fallbackPassphrase) {
  if (source === undefined || source === null) return null;
  var selected = source;
  var passphrase = fallbackPassphrase;
  if (Array.isArray(selected)) {
    if (selected.length !== 1) {
      throw _createError(
        'ERR_TLS_PFX_UNSUPPORTED',
        'This TLS transport accepts exactly one pfx client identity'
      );
    }
    selected = selected[0];
  }
  if (selected && typeof selected === 'object' &&
      !_isArrayBufferView(selected) &&
      !(typeof ArrayBuffer !== 'undefined' && selected instanceof ArrayBuffer) &&
      !(typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(selected))) {
    if (!hasOwn.call(selected, 'buf')) {
      throw _createError('ERR_INVALID_ARG_TYPE', 'The "pfx" identity object must contain a buf property');
    }
    if (selected.passphrase !== undefined && selected.passphrase !== null) {
      passphrase = String(selected.passphrase);
    }
    selected = selected.buf;
  }

  var bytes;
  if (typeof selected === 'string') {
    if (selected.length > _maxClientIdentityBytes) {
      throw _createError(
        'ERR_TLS_PFX_TOO_LARGE',
        'The "pfx" client identity exceeds the 16 MiB limit'
      );
    }
    bytes = typeof Uint8Array !== 'undefined' ? new Uint8Array(selected.length) : [];
    for (var i = 0; i < selected.length; i++) bytes[i] = selected.charCodeAt(i) & 255;
  } else if (
    _isArrayBufferView(selected) ||
    (typeof ArrayBuffer !== 'undefined' && selected instanceof ArrayBuffer)
  ) {
    var selectedLength = typeof selected.byteLength === 'number'
      ? selected.byteLength
      : (typeof selected.length === 'number' ? selected.length : 0);
    // @ref LLP 0004#the-tls-builtin — reject before base64/JSON amplification;
    // the native decoder independently enforces the same bound.
    if (selectedLength > _maxClientIdentityBytes) {
      throw _createError(
        'ERR_TLS_PFX_TOO_LARGE',
        'The "pfx" client identity exceeds the 16 MiB limit'
      );
    }
    bytes = selected;
  } else {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "pfx" option must be a string, Buffer, TypedArray, DataView, ArrayBuffer, or one identity object'
    );
  }
  var buffer = _bufferFromBytes(bytes);
  if (!buffer || typeof buffer.toString !== 'function') {
    throw _createError('ERR_TLS_PFX_UNSUPPORTED', 'Unable to encode the pfx client identity');
  }
  return {
    encoded: buffer.toString('base64'),
    passphrase: passphrase === undefined || passphrase === null ? null : String(passphrase)
  };
}

function _bufferFromBase64(value) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(value, 'base64');
  }
  var binary = atob(value);
  var out = typeof Uint8Array !== 'undefined' ? new Uint8Array(binary.length) : [];
  for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) & 255;
  return out;
}

function _bufferFromBytes(value) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    if (typeof Buffer.isBuffer === 'function' && Buffer.isBuffer(value)) return value;
    // Buffer.from(TypedArray) copies, while the ArrayBuffer overload creates a
    // view. TLS owns/retains these JS buffers until the native/raw consumer is
    // finished, so sharing the backing store avoids an extra 64 KiB copy in
    // each direction without changing its lifetime.
    if (_isArrayBufferView(value) && value.buffer) {
      return Buffer.from(value.buffer, value.byteOffset || 0, value.byteLength);
    }
    return Buffer.from(value);
  }
  return value;
}

function _splitPemCertificates(source) {
  var normalized = _pemSourceToString(source);
  if (!normalized) return [];
  var matches = normalized.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches || [];
}

function _readDerElement(bytes, offset) {
  if (offset >= bytes.length) return null;
  var startOffset = offset;
  var tag = bytes[offset++];
  if (offset >= bytes.length) return null;
  var lengthByte = bytes[offset++];
  var length = 0;
  if ((lengthByte & 0x80) === 0) {
    length = lengthByte;
  } else {
    var count = lengthByte & 0x7f;
    if (!count || offset + count > bytes.length) return null;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | bytes[offset++];
    }
  }
  var valueStart = offset;
  var valueEnd = offset + length;
  if (valueEnd > bytes.length) return null;
  return {
    tag: tag,
    startOffset: startOffset,
    valueStart: valueStart,
    valueEnd: valueEnd,
    nextOffset: valueEnd
  };
}

function _readDerChildren(bytes, start, end) {
  var children = [];
  var offset = start;
  while (offset < end) {
    var element = _readDerElement(bytes, offset);
    if (!element) break;
    children.push(element);
    offset = element.nextOffset;
  }
  return children;
}

function _bytesToAscii(bytes, start, end) {
  var chars = [];
  for (var i = start; i < end; i++) chars.push(String.fromCharCode(bytes[i]));
  return chars.join('');
}

function _bytesToUtf8(bytes, start, end) {
  var raw = _bufferFromBytes(bytes.slice ? bytes.slice(start, end) : Array.prototype.slice.call(bytes, start, end));
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(raw)) {
    return raw.toString('utf8');
  }
  if (typeof TextDecoder !== 'undefined') {
    try {
      return new TextDecoder('utf-8').decode(raw);
    } catch (_decodeErr) {
      // Invalid peer text falls through to the raw-byte representation.
    }
  }
  return _bytesToAscii(bytes, start, end);
}

function _bytesToBmpString(bytes, start, end) {
  var chars = [];
  for (var i = start; i + 1 < end; i += 2) {
    chars.push(String.fromCharCode((bytes[i] << 8) | bytes[i + 1]));
  }
  return chars.join('');
}

function _bytesToHex(bytes, start, end) {
  var out = '';
  for (var i = start; i < end; i++) {
    var hex = bytes[i].toString(16).toUpperCase();
    out += hex.length === 1 ? '0' + hex : hex;
  }
  return out;
}

function _sliceBytes(bytes, start, end) {
  if (bytes.slice) return bytes.slice(start, end);
  return Array.prototype.slice.call(bytes, start, end);
}

function _decodeDerOid(bytes, start, end) {
  if (start >= end) return '';
  var first = bytes[start++];
  var parts = [Math.floor(first / 40), first % 40];
  var value = 0;
  while (start < end) {
    var byte = bytes[start++];
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function _decodeDerString(bytes, element) {
  if (!element) return '';
  if (element.tag === 0x0c) return _bytesToUtf8(bytes, element.valueStart, element.valueEnd);
  if (element.tag === 0x16 || element.tag === 0x13) return _bytesToAscii(bytes, element.valueStart, element.valueEnd);
  if (element.tag === 0x1e) return _bytesToBmpString(bytes, element.valueStart, element.valueEnd);
  return _bytesToUtf8(bytes, element.valueStart, element.valueEnd);
}

function _attributeNameForOid(oid) {
  if (oid === '2.5.4.3') return 'CN';
  if (oid === '2.5.4.6') return 'C';
  if (oid === '2.5.4.7') return 'L';
  if (oid === '2.5.4.8') return 'ST';
  if (oid === '2.5.4.10') return 'O';
  if (oid === '2.5.4.11') return 'OU';
  if (oid === '1.2.840.113549.1.9.1') return 'emailAddress';
  return oid;
}

function _parseDerName(bytes, element) {
  var result = {};
  if (!element || element.tag !== 0x30) return result;
  var rdns = _readDerChildren(bytes, element.valueStart, element.valueEnd);
  for (var i = 0; i < rdns.length; i++) {
    if (rdns[i].tag !== 0x31) continue;
    var attrs = _readDerChildren(bytes, rdns[i].valueStart, rdns[i].valueEnd);
    for (var j = 0; j < attrs.length; j++) {
      if (attrs[j].tag !== 0x30) continue;
      var attrChildren = _readDerChildren(bytes, attrs[j].valueStart, attrs[j].valueEnd);
      if (attrChildren.length < 2) continue;
      var oid = _decodeDerOid(bytes, attrChildren[0].valueStart, attrChildren[0].valueEnd);
      var attrName = _attributeNameForOid(oid);
      var attrValue = _decodeDerString(bytes, attrChildren[1]);
      if (hasOwn.call(result, attrName)) {
        if (Array.isArray(result[attrName])) {
          result[attrName].push(attrValue);
        } else {
          result[attrName] = [result[attrName], attrValue];
        }
      } else {
        result[attrName] = attrValue;
      }
    }
  }
  return result;
}

var _certMonthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// OpenSSL/Node cert time formatting: "May 31 21:39:12 2026 GMT" with a
// two-space day pad for single digits ("Aug  8 21:17:05 2016 GMT"). Node
// v25.9.0 oracle format for getPeerCertificate().valid_from/valid_to.
function _formatCertTime(year, month, day, hour, minute, second) {
  var monthName = _certMonthNames[Number(month) - 1] || month;
  var dayNum = Number(day);
  var dayText = dayNum < 10 ? ' ' + dayNum : String(dayNum);
  return monthName + ' ' + dayText + ' ' + hour + ':' + minute + ':' + second + ' ' + year + ' GMT';
}

function _formatDerTime(bytes, element) {
  if (!element) return '';
  var text = _bytesToAscii(bytes, element.valueStart, element.valueEnd);
  if (element.tag === 0x17 && text.length >= 12) {
    var year = Number(text.slice(0, 2));
    year += year >= 50 ? 1900 : 2000;
    return _formatCertTime(
      String(year), text.slice(2, 4), text.slice(4, 6),
      text.slice(6, 8), text.slice(8, 10), text.slice(10, 12)
    );
  }
  if (element.tag === 0x18 && text.length >= 14) {
    return _formatCertTime(
      text.slice(0, 4), text.slice(4, 6), text.slice(6, 8),
      text.slice(8, 10), text.slice(10, 12), text.slice(12, 14)
    );
  }
  return text;
}

function _fingerprintFromRaw(raw, algorithm) {
  if (!raw || typeof __exactHashSync !== 'function') return '';
  try {
    var hash = __exactHashSync(algorithm, raw);
    return typeof hash === 'string'
      ? hash.toUpperCase().replace(/(.{2})(?!$)/g, '$1:')
      : '';
  } catch (_fingerprintErr) {
    return '';
  }
}

function _extensionNameForOid(oid) {
  if (oid === '1.3.6.1.5.5.7.48.1') return 'OCSP';
  if (oid === '1.3.6.1.5.5.7.48.2') return 'CA Issuers';
  return oid;
}

function _curveNamesForOid(oid) {
  if (oid === '1.2.840.10045.3.1.7') {
    return { asn1Curve: 'prime256v1', nistCurve: 'P-256', bits: 256 };
  }
  if (oid === '1.3.132.0.34') {
    return { asn1Curve: 'secp384r1', nistCurve: 'P-384', bits: 384 };
  }
  if (oid === '1.3.132.0.35') {
    return { asn1Curve: 'secp521r1', nistCurve: 'P-521', bits: 521 };
  }
  return null;
}

function _parseAuthorityInfoAccess(bytes, element) {
  if (!element || element.tag !== 0x04) return undefined;
  var wrapped = _readDerElement(bytes, element.valueStart);
  if (!wrapped || wrapped.nextOffset > element.valueEnd || wrapped.tag !== 0x30) return undefined;
  var entries = _readDerChildren(bytes, wrapped.valueStart, wrapped.valueEnd);
  var infoAccess = {};
  var hasEntries = false;
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].tag !== 0x30) continue;
    var parts = _readDerChildren(bytes, entries[i].valueStart, entries[i].valueEnd);
    if (parts.length < 2) continue;
    var methodOid = _decodeDerOid(bytes, parts[0].valueStart, parts[0].valueEnd);
    var location = parts[1];
    if (location.tag !== 0x86) continue;
    var entryName = _extensionNameForOid(methodOid) + ' - URI';
    if (!hasOwn.call(infoAccess, entryName)) infoAccess[entryName] = [];
    infoAccess[entryName].push(_bytesToAscii(bytes, location.valueStart, location.valueEnd));
    hasEntries = true;
  }
  return hasEntries ? infoAccess : undefined;
}

function _formatSubjectAltNameText(value) {
  if (typeof value !== 'string') return '';
  if (!/[\u0000-\u001f"\\]/.test(value)) return value;
  return '"' + value.replace(/[\u0000-\u001f"\\]/g, function(ch) {
    var code = ch.charCodeAt(0);
    if (ch === '"' || ch === '\\') return '\\' + ch;
    var hex = code.toString(16).toUpperCase();
    while (hex.length < 4) hex = '0' + hex;
    return '\\u' + hex;
  }) + '"';
}

function _formatIpAddress(bytes, start, end) {
  var length = end - start;
  if (length === 4) {
    return String(bytes[start]) + '.' + String(bytes[start + 1]) + '.' +
      String(bytes[start + 2]) + '.' + String(bytes[start + 3]);
  }
  if (length === 16) {
    var parts = [];
    for (var i = start; i < end; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return parts.join(':');
  }
  return _bytesToHex(bytes, start, end);
}

function _parseSubjectAltName(bytes, element) {
  if (!element || element.tag !== 0x04) return undefined;
  var wrapped = _readDerElement(bytes, element.valueStart);
  if (!wrapped || wrapped.nextOffset > element.valueEnd || wrapped.tag !== 0x30) return undefined;
  var names = _readDerChildren(bytes, wrapped.valueStart, wrapped.valueEnd);
  var out = [];
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (name.tag === 0x82) {
      out.push('DNS:' + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
    } else if (name.tag === 0x86) {
      out.push('URI:' + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
    } else if (name.tag === 0x87) {
      out.push('IP Address:' + _formatIpAddress(bytes, name.valueStart, name.valueEnd));
    } else if (name.tag === 0x81) {
      out.push('email:' + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
    }
  }
  return out.length ? out.join(', ') : undefined;
}

function _parseSubjectPublicKeyInfo(bytes, element) {
  if (!element || element.tag !== 0x30) return {};
  var children = _readDerChildren(bytes, element.valueStart, element.valueEnd);
  if (children.length < 2 || children[0].tag !== 0x30 || children[1].tag !== 0x03) return {};

  var algorithmParts = _readDerChildren(bytes, children[0].valueStart, children[0].valueEnd);
  if (!algorithmParts.length) return {};

  var algorithmOid = _decodeDerOid(bytes, algorithmParts[0].valueStart, algorithmParts[0].valueEnd);
  var bitString = children[1];
  var bitStringStart = bitString.valueStart;
  if (bitStringStart >= bitString.valueEnd) return {};
  var unusedBits = bytes[bitStringStart];
  if (unusedBits !== 0) return {};

  if (algorithmOid === '1.2.840.113549.1.1.1') {
    var rsaKey = _readDerElement(bytes, bitStringStart + 1);
    if (!rsaKey || rsaKey.tag !== 0x30 || rsaKey.nextOffset > bitString.valueEnd) return {};
    var rsaParts = _readDerChildren(bytes, rsaKey.valueStart, rsaKey.valueEnd);
    if (rsaParts.length < 2) return {};
    var modulusHex = _bytesToHex(bytes, rsaParts[0].valueStart, rsaParts[0].valueEnd).replace(/^00+/, '') || '0';
    var exponentHex = _bytesToHex(bytes, rsaParts[1].valueStart, rsaParts[1].valueEnd).replace(/^0+/, '') || '0';
    return {
      pubkey: _bufferFromBytes(_sliceBytes(bytes, element.startOffset, element.nextOffset)),
      modulus: modulusHex,
      exponent: '0x' + exponentHex.toLowerCase(),
      bits: modulusHex.length / 2 * 8
    };
  }

  if (algorithmOid === '1.2.840.10045.2.1') {
    var point = _bufferFromBytes(_sliceBytes(bytes, bitStringStart + 1, bitString.valueEnd));
    var curveOid = algorithmParts[1] ? _decodeDerOid(bytes, algorithmParts[1].valueStart, algorithmParts[1].valueEnd) : '';
    var curveNames = _curveNamesForOid(curveOid);
    var pointBits = point && point.length > 1 ? ((point.length - 1) / 2) * 8 : undefined;
    return {
      pubkey: point,
      bits: curveNames && curveNames.bits ? curveNames.bits : pointBits,
      asn1Curve: curveNames && curveNames.asn1Curve ? curveNames.asn1Curve : undefined,
      nistCurve: curveNames && curveNames.nistCurve ? curveNames.nistCurve : undefined
    };
  }

  return {};
}

function _parseCertificateExtensions(bytes, tbsChildren, startIdx) {
  var parsed = {};
  for (var i = startIdx; i < tbsChildren.length; i++) {
    if (tbsChildren[i].tag !== 0xa3) continue;
    var extensionWrappers = _readDerChildren(bytes, tbsChildren[i].valueStart, tbsChildren[i].valueEnd);
    if (!extensionWrappers.length || extensionWrappers[0].tag !== 0x30) continue;
    var extensions = _readDerChildren(bytes, extensionWrappers[0].valueStart, extensionWrappers[0].valueEnd);
    for (var j = 0; j < extensions.length; j++) {
      if (extensions[j].tag !== 0x30) continue;
      var parts = _readDerChildren(bytes, extensions[j].valueStart, extensions[j].valueEnd);
      if (parts.length < 2) continue;
      var extOid = _decodeDerOid(bytes, parts[0].valueStart, parts[0].valueEnd);
      var valueElement = parts[parts.length - 1];
      if (extOid === '1.3.6.1.5.5.7.1.1') {
        var infoAccess = _parseAuthorityInfoAccess(bytes, valueElement);
        if (infoAccess) parsed.infoAccess = infoAccess;
      } else if (extOid === '2.5.29.17') {
        var subjectAltName = _parseSubjectAltName(bytes, valueElement);
        if (subjectAltName) parsed.subjectaltname = subjectAltName;
      }
    }
  }
  return parsed;
}

function _cloneSimpleObject(value) {
  if (!value || typeof value !== 'object') return value;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (Array.isArray(value)) {
    var arr = [];
    for (var i = 0; i < value.length; i++) arr.push(_cloneSimpleObject(value[i]));
    return arr;
  }
  var clone = {};
  for (var key in value) {
    if (hasOwn.call(value, key)) clone[key] = _cloneSimpleObject(value[key]);
  }
  return clone;
}

function _cloneCertificate(cert, detailed, seen) {
  if (!cert || typeof cert !== 'object') return {};
  if (!detailed) {
    var shallow = {};
    for (var key in cert) {
      if (!hasOwn.call(cert, key) || key === 'issuerCertificate') continue;
      shallow[key] = _cloneSimpleObject(cert[key]);
    }
    return shallow;
  }
  seen = seen || [];
  for (var i = 0; i < seen.length; i++) {
    if (seen[i].source === cert) return seen[i].clone;
  }
  var clone = {};
  seen.push({ source: cert, clone: clone });
  for (var key2 in cert) {
    if (!hasOwn.call(cert, key2)) continue;
    if (key2 === 'issuerCertificate' && cert[key2]) {
      clone[key2] = _cloneCertificate(cert[key2], true, seen);
    } else {
      clone[key2] = _cloneSimpleObject(cert[key2]);
    }
  }
  return clone;
}

function _toX509CertificateData(cert, includeIssuer) {
  if (!cert || typeof cert !== 'object') return null;
  var data = {
    __exactX509Data: true,
    raw: cert.raw || null,
    pem: typeof cert.pem === 'string' ? cert.pem : '',
    subject: _cloneSimpleObject(cert.subject),
    issuer: _cloneSimpleObject(cert.issuer),
    subjectAltName: cert.subjectaltname,
    infoAccess: _cloneSimpleObject(cert.infoAccess),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
    fingerprint: cert.fingerprint,
    fingerprint256: cert.fingerprint256,
    keyUsage: _cloneSimpleObject(cert.keyUsage),
    legacyObject: _cloneCertificate(cert, true)
  };
  if (includeIssuer && cert.issuerCertificate && cert.issuerCertificate !== cert) {
    data.issuerCertificate = _toX509CertificateData(cert.issuerCertificate, false);
  }
  return data;
}

function _toX509Certificate(cert, includeIssuer) {
  if (!cert || !cryptoModule || typeof cryptoModule.X509Certificate !== 'function') {
    return undefined;
  }
  return new cryptoModule.X509Certificate(_toX509CertificateData(cert, includeIssuer));
}

function _nameKey(name) {
  if (!name || typeof name !== 'object') return '';
  var parts = [];
  var keys = Object.keys(name).sort();
  for (var i = 0; i < keys.length; i++) {
    parts.push(keys[i] + '=' + String(name[keys[i]]));
  }
  return parts.join(',');
}

function _parsePemCertificate(pem, host, port) {
  if (typeof pem !== 'string' || pem.indexOf('BEGIN CERTIFICATE') === -1) return null;
  if (_certificateParseCache && _certificateParseCache.has(pem)) {
    var cached = _certificateParseCache.get(pem);
    // Map insertion order is our bounded LRU order.
    _certificateParseCache.delete(pem);
    _certificateParseCache.set(pem, cached);
    return _cloneCertificate(cached.certificate, true);
  }

  try {
    var base64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
    var der = _bufferFromBase64(base64);
    var bytes = der;
    var root = _readDerElement(bytes, 0);
    if (!root || root.tag !== 0x30) return null;
    var rootChildren = _readDerChildren(bytes, root.valueStart, root.valueEnd);
    if (!rootChildren.length) return null;
    var tbs = rootChildren[0];
    var tbsChildren = _readDerChildren(bytes, tbs.valueStart, tbs.valueEnd);
    var idx = 0;
    if (tbsChildren[idx] && tbsChildren[idx].tag === 0xa0) idx += 1;
    var serialElement = tbsChildren[idx++];
    idx += 1; // signature algorithm
    var issuerElement = tbsChildren[idx++];
    var validityElement = tbsChildren[idx++];
    var subjectElement = tbsChildren[idx++];
    var subjectPublicKeyInfoElement = tbsChildren[idx++];
    var validityChildren = validityElement ? _readDerChildren(bytes, validityElement.valueStart, validityElement.valueEnd) : [];
    var raw = _bufferFromBytes(der);
    var keyInfo = _parseSubjectPublicKeyInfo(bytes, subjectPublicKeyInfoElement);
    var extensionInfo = _parseCertificateExtensions(bytes, tbsChildren, idx);
    var parsed = {
      subject: _parseDerName(bytes, subjectElement),
      issuer: _parseDerName(bytes, issuerElement),
      valid_from: _formatDerTime(bytes, validityChildren[0]),
      valid_to: _formatDerTime(bytes, validityChildren[1]),
      serialNumber: _bytesToHex(bytes, serialElement.valueStart, serialElement.valueEnd).replace(/^00+/, '') || '0',
      fingerprint: _fingerprintFromRaw(raw, 'sha1'),
      fingerprint256: _fingerprintFromRaw(raw, 'sha256'),
      fingerprint512: _fingerprintFromRaw(raw, 'sha512'),
      raw: raw,
      ca: false
    };
    for (var key in keyInfo) {
      if (hasOwn.call(keyInfo, key) && keyInfo[key] !== undefined) parsed[key] = keyInfo[key];
    }
    if (extensionInfo.infoAccess !== undefined) parsed.infoAccess = extensionInfo.infoAccess;
    if (extensionInfo.subjectaltname !== undefined) parsed.subjectaltname = extensionInfo.subjectaltname;
    _cacheParsedCertificate(pem, parsed);
    return _cloneCertificate(parsed, true);
  } catch (_parseErr) {
    return null;
  }
}

function _buildCertificateChain(host, port, leafSource, chainSource, trustedSource) {
  var blocks = _splitPemCertificates(leafSource).concat(_splitPemCertificates(chainSource));
  var trustedBlocks = _splitPemCertificates(trustedSource);
  var parsed = [];
  var seen = Object.create(null);

  function appendBlock(block) {
    var cert = _parsePemCertificate(block, host, port);
    if (!cert || !cert.serialNumber || seen[cert.serialNumber]) return;
    seen[cert.serialNumber] = true;
    parsed.push(cert);
  }

  for (var i = 0; i < blocks.length; i++) appendBlock(blocks[i]);
  if (!parsed.length) {
    return _buildSyntheticCertificate(host, port, leafSource || 'ExactTLS');
  }

  // Loopback-emulation nicety only: a configured PEM without a SAN still
  // "matches" the destination hostname so emulated identity checks pass. The
  // native bridge path (_buildBridgedPeerChain) never synthesizes altnames —
  // real endpoints must fail hostname validation honestly.
  if (!parsed[0].subjectaltname) {
    parsed[0].subjectaltname = 'DNS:' + (host || 'localhost');
  }

  var lastIssuerKey = _nameKey(parsed[parsed.length - 1].issuer);
  for (var j = 0; j < trustedBlocks.length; j++) {
    var trusted = _parsePemCertificate(trustedBlocks[j], host, port);
    if (!trusted || !trusted.serialNumber || seen[trusted.serialNumber]) continue;
    if (!lastIssuerKey || _nameKey(trusted.subject) === lastIssuerKey) {
      seen[trusted.serialNumber] = true;
      parsed.push(trusted);
      lastIssuerKey = _nameKey(trusted.issuer);
    }
  }

  for (var k = 0; k < parsed.length; k++) {
    parsed[k].ca = k > 0 || _nameKey(parsed[k].subject) === _nameKey(parsed[k].issuer);
    if (k + 1 < parsed.length) {
      parsed[k].issuerCertificate = parsed[k + 1];
    }
  }
  if (_nameKey(parsed[parsed.length - 1].subject) === _nameKey(parsed[parsed.length - 1].issuer)) {
    parsed[parsed.length - 1].issuerCertificate = parsed[parsed.length - 1];
  }

  return parsed[0];
}

function _buildPeerCertificate(host, port, remoteOptions, localOptions) {
  var remote = remoteOptions || {};
  if (remote.cert || remote.pfx) {
    return _buildCertificateChain(host, port, remote.cert || remote.pfx, remote.ca, localOptions && localOptions.ca);
  }
  return _buildSyntheticCertificate(host, port, remote.cert || remote.pfx || 'ExactTLS');
}

function _buildLocalCertificate(host, port, options) {
  var local = options || {};
  if (local.cert) {
    return _buildCertificateChain(host, port, local.cert, local.ca, null);
  }
  // A private key or opaque PFX is never certificate metadata and must not be
  // copied into a public getCertificate() projection.
  return null;
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
    issuer: { CN: 'ExactTLS' },
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
  return _canonicalizeIp(host) !== undefined;
}

// True when a destination host can only reach this machine. Used by connect()
// to decide whether an in-process tls.Server registry hit is meaningful: the
// registry is keyed by port only, so a non-loopback destination that happens to
// collide with a local listener's port must not be treated as in-process.
function _isLoopbackHost(host) {
  if (!host || typeof host !== 'string') return false;
  var normalized = _unfqdn(host).toLowerCase();
  if (normalized === 'localhost' || normalized === 'ip6-localhost') return true;
  var canonical = _canonicalizeIp(normalized);
  if (!canonical) return false;
  if (canonical.indexOf('.') !== -1) {
    // Connecting to an unspecified address reaches a local listener on the
    // platforms ibex supports; the whole 127/8 block is loopback.
    return canonical === '0.0.0.0' || canonical.indexOf('127.') === 0;
  }
  if (canonical === '0000:0000:0000:0000:0000:0000:0000:0000' ||
      canonical === '0000:0000:0000:0000:0000:0000:0000:0001') return true;
  // IPv4-mapped loopback (`::ffff:127/8`) in canonical 16-bit form.
  return /^0000:0000:0000:0000:0000:ffff:7f[0-9a-f]{2}:/.test(canonical);
}

function _unfqdn(host) {
  return String(host || '').replace(/[.]$/, '');
}

function _toLowerCaseAscii(ch) {
  return String.fromCharCode(ch.charCodeAt(0) + 32);
}

function _splitHost(host) {
  return _unfqdn(host).replace(/[A-Z]/g, _toLowerCaseAscii).split('.');
}

function _checkHostPattern(hostParts, pattern, wildcards) {
  if (!pattern) return false;
  var patternParts = _splitHost(pattern);
  if (hostParts.length !== patternParts.length) return false;
  for (var i = 0; i < patternParts.length; i++) {
    if (patternParts[i] === '') return false;
    if (/[^\u0021-\u007F]/u.test(patternParts[i])) return false;
  }
  for (var j = hostParts.length - 1; j > 0; j--) {
    if (hostParts[j] !== patternParts[j]) return false;
  }
  var hostSubdomain = hostParts[0];
  var patternSubdomain = patternParts[0];
  var patternSubdomainParts = patternSubdomain.split('*', 3);
  if (patternSubdomainParts.length === 1 || patternSubdomain.indexOf('xn--') !== -1) {
    return hostSubdomain === patternSubdomain;
  }
  if (!wildcards) return false;
  if (patternSubdomainParts.length > 2) return false;
  if (patternParts.length <= 2) return false;
  var prefix = patternSubdomainParts[0];
  var suffix = patternSubdomainParts[1];
  if (prefix.length + suffix.length > hostSubdomain.length) return false;
  if (hostSubdomain.indexOf(prefix) !== 0) return false;
  if (hostSubdomain.slice(hostSubdomain.length - suffix.length) !== suffix) return false;
  return true;
}

var _jsonStringPattern =
  /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;

function _splitEscapedAltNames(altNames) {
  var result = [];
  var currentToken = '';
  var offset = 0;
  while (offset !== altNames.length) {
    var nextSep = altNames.indexOf(',', offset);
    var nextQuote = altNames.indexOf('"', offset);
    if (nextQuote !== -1 && (nextSep === -1 || nextQuote < nextSep)) {
      currentToken += altNames.substring(offset, nextQuote);
      var match = _jsonStringPattern.exec(altNames.substring(nextQuote));
      if (!match) throw new Error('Invalid subject alternative name format');
      currentToken += JSON.parse(match[0]);
      offset = nextQuote + match[0].length;
    } else if (nextSep !== -1) {
      currentToken += altNames.substring(offset, nextSep);
      result.push(currentToken);
      currentToken = '';
      offset = nextSep + 2;
    } else {
      currentToken += altNames.substring(offset);
      offset = altNames.length;
    }
  }
  result.push(currentToken);
  return result;
}

function _canonicalizeIp(host) {
  var value = String(host || '');
  var version = net && typeof net.isIP === 'function' ? net.isIP(value) : 0;
  if (version === 4) {
    var octets = value.split('.');
    return octets.map(function(octet) { return String(Number(octet)); }).join('.');
  }
  if (version !== 6) return undefined;

  // A scope identifier selects an interface, not a certificate identity.
  // net.isIP validated it above; remove it before canonical comparison.
  var zoneIndex = value.indexOf('%');
  if (zoneIndex !== -1) value = value.slice(0, zoneIndex);
  value = value.toLowerCase();

  // Convert an embedded dotted-quad tail to the two equivalent 16-bit words
  // before expanding `::`, so textual IPv6 spellings compare byte-for-byte.
  var lastColon = value.lastIndexOf(':');
  if (lastColon !== -1 && value.slice(lastColon + 1).indexOf('.') !== -1) {
    var tail = value.slice(lastColon + 1).split('.');
    var high = (Number(tail[0]) << 8) | Number(tail[1]);
    var low = (Number(tail[2]) << 8) | Number(tail[3]);
    value = value.slice(0, lastColon + 1) + high.toString(16) + ':' + low.toString(16);
  }

  var doubleColon = value.indexOf('::');
  var leftText = doubleColon === -1 ? value : value.slice(0, doubleColon);
  var rightText = doubleColon === -1 ? '' : value.slice(doubleColon + 2);
  var left = leftText ? leftText.split(':') : [];
  var right = rightText ? rightText.split(':') : [];
  var words;
  if (doubleColon === -1) {
    if (left.length !== 8) return undefined;
    words = left;
  } else {
    var omitted = 8 - left.length - right.length;
    if (omitted < 1) return undefined;
    words = left.slice();
    for (var i = 0; i < omitted; i++) words.push('0');
    words = words.concat(right);
  }
  if (words.length !== 8) return undefined;
  for (var j = 0; j < words.length; j++) {
    words[j] = ('0000' + Number.parseInt(words[j], 16).toString(16)).slice(-4);
  }
  return words.join(':');
}

function _createAltNameError(reason, hostname, cert) {
  var err = new Error('Hostname/IP does not match certificate\'s altnames: ' + reason);
  err.reason = reason;
  err.host = hostname;
  err.cert = cert;
  err.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
  return err;
}

function _createAuthorizationError(code, message) {
  var err = new Error(message);
  err.code = code;
  return err;
}

function _bufferEquals(left, right) {
  if (left === right) return true;
  if (!left || !right) return false;
  var leftLength = typeof left.length === 'number' ? left.length : left.byteLength;
  var rightLength = typeof right.length === 'number' ? right.length : right.byteLength;
  if (leftLength !== rightLength) return false;
  for (var i = 0; i < leftLength; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function _certificateEquals(left, right) {
  if (!left || !right) return false;
  if (left.fingerprint256 && right.fingerprint256 && left.fingerprint256 === right.fingerprint256) {
    return true;
  }
  if (left.raw && right.raw && _bufferEquals(left.raw, right.raw)) {
    return true;
  }
  return (
    left.serialNumber &&
    right.serialNumber &&
    left.serialNumber === right.serialNumber &&
    _nameKey(left.subject) === _nameKey(right.subject)
  );
}

function _collectCertificateChain(cert) {
  var chain = [];
  var current = cert;
  while (current) {
    chain.push(current);
    if (!current.issuerCertificate || current.issuerCertificate === current) {
      break;
    }
    current = current.issuerCertificate;
  }
  return chain;
}

function _collectTrustedCertificates(source, host, port) {
  var blocks = _splitPemCertificates(source);
  if (!blocks.length) return [];
  var certs = [];
  for (var i = 0; i < blocks.length; i++) {
    var cert = _parsePemCertificate(blocks[i], host, port);
    if (!cert) return null;
    certs.push(cert);
  }
  return certs;
}

function _isSelfSignedCertificate(cert) {
  return !!cert && _nameKey(cert.subject) === _nameKey(cert.issuer);
}

function _certificateTimeValue(value) {
  if (!value) return NaN;
  var text = String(value);
  var time = Date.parse(text);
  if (Number.isFinite(time)) return time;
  // OpenSSL/Node cert time format ("May 31 21:39:12 2026 GMT"); Hermes'
  // Date.parse does not understand it, so parse it explicitly.
  var match = /^([A-Za-z]{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4}) GMT$/.exec(text);
  if (match) {
    var month = _certMonthNames.indexOf(match[1]);
    if (month !== -1) {
      return Date.UTC(
        Number(match[6]), month, Number(match[2]),
        Number(match[3]), Number(match[4]), Number(match[5])
      );
    }
  }
  return NaN;
}

function _normalizePemSignature(source) {
  return _pemSourceToString(source).replace(/\s+/g, '');
}

function _sourceContainsCertificate(source, certSource) {
  if (source == null || certSource == null) return false;
  var normalizedSource = _normalizePemSignature(source);
  var normalizedCert = _normalizePemSignature(certSource);
  return !!normalizedSource && !!normalizedCert && normalizedSource.indexOf(normalizedCert) !== -1;
}

function _validatePeerAuthorization(peerCert, options, host, port, remoteOptions) {
  if (!peerCert) return null;

  if (remoteOptions && remoteOptions.__exactExpired === true) {
    return _createAuthorizationError('CERT_HAS_EXPIRED', 'certificate has expired');
  }

  var now = Date.now();
  var validTo = _certificateTimeValue(peerCert.valid_to);
  if (!isNaN(validTo) && validTo < now) {
    return _createAuthorizationError('CERT_HAS_EXPIRED', 'certificate has expired');
  }

  var validFrom = _certificateTimeValue(peerCert.valid_from);
  if (!isNaN(validFrom) && validFrom > now) {
    return _createAuthorizationError('CERT_NOT_YET_VALID', 'certificate is not yet valid');
  }

  var trustedSource = options && options.ca !== undefined ? options.ca : _defaultCACertificates;
  var peerSource = remoteOptions && (remoteOptions.cert || remoteOptions.pfx);
  if (_sourceContainsCertificate(trustedSource, peerSource)) {
    return null;
  }
  var trusted = _collectTrustedCertificates(trustedSource, host, port);
  if (trusted === null) {
    return _createAuthorizationError('UNABLE_TO_GET_ISSUER_CERT', 'unable to get issuer certificate');
  }
  if (!trusted.length) {
    return (_isSelfSignedCertificate(peerCert) || !!peerSource)
      ? _createAuthorizationError('DEPTH_ZERO_SELF_SIGNED_CERT', 'self-signed certificate')
      : null;
  }

  var chain = _collectCertificateChain(peerCert);
  for (var i = 0; i < chain.length; i++) {
    for (var j = 0; j < trusted.length; j++) {
      if (_certificateEquals(chain[i], trusted[j])) {
        return null;
      }
    }
  }

  return (_isSelfSignedCertificate(peerCert) || !!peerSource)
    ? _createAuthorizationError('DEPTH_ZERO_SELF_SIGNED_CERT', 'self-signed certificate')
    : _createAuthorizationError('UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'unable to verify the first certificate');
}

function _defaultCheckServerIdentity(hostname, cert) {
  var subject = cert && cert.subject;
  var altNames = cert && cert.subjectaltname;
  var dnsNames = [];
  var ips = [];

  hostname = '' + hostname;

  if (altNames) {
    var splitAltNames = altNames.indexOf('"') !== -1 ?
      _splitEscapedAltNames(altNames) :
      altNames.split(', ');
    for (var i = 0; i < splitAltNames.length; i++) {
      var name = splitAltNames[i];
      if (name.indexOf('DNS:') === 0) {
        dnsNames.push(name.slice(4));
      } else if (name.indexOf('IP Address:') === 0) {
        ips.push(_canonicalizeIp(name.slice(11)));
      }
    }
  }

  var valid = false;
  var reason = 'Unknown reason';
  hostname = _unfqdn(hostname);

  if (_isIpAddress(hostname)) {
    valid = ips.indexOf(_canonicalizeIp(hostname)) !== -1;
    if (!valid) {
      reason = 'IP: ' + hostname + ' is not in the cert\'s list: ' + ips.join(', ');
    }
  } else if (dnsNames.length > 0 || (subject && subject.CN)) {
    var hostParts = _splitHost(hostname);
    if (dnsNames.length > 0) {
      for (var j = 0; j < dnsNames.length; j++) {
        if (_checkHostPattern(hostParts, dnsNames[j], true)) {
          valid = true;
          break;
        }
      }
      if (!valid) {
        reason = 'Host: ' + hostname + '. is not in the cert\'s altnames: ' + altNames;
      }
    } else {
      var cn = subject.CN;
      if (Array.isArray(cn)) {
        for (var k = 0; k < cn.length; k++) {
          if (_checkHostPattern(hostParts, cn[k], true)) {
            valid = true;
            break;
          }
        }
      } else if (cn) {
        valid = _checkHostPattern(hostParts, cn, true);
      }
      if (!valid) {
        reason = 'Host: ' + hostname + '. is not cert\'s CN: ' + cn;
      }
    }
  } else {
    reason = 'Cert does not contain a DNS name';
  }

  if (!valid) return _createAltNameError(reason, hostname, cert);
}

function checkServerIdentity(hostname, cert) {
  return _defaultCheckServerIdentity(hostname, cert);
}

function _translateInfoAccess(value) {
  if (value == null) return value;
  if (typeof value !== 'string') return value;
  var infoAccess = Object.create(null);
  if (!value) return infoAccess;
  var lines = value.split('\n');
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var sep = line.indexOf(':');
    if (sep === -1) continue;
    var key = line.slice(0, sep);
    var entryValue = line.slice(sep + 1);
    if (!hasOwn.call(infoAccess, key)) infoAccess[key] = [];
    infoAccess[key].push(entryValue);
  }
  return infoAccess;
}

function translatePeerCertificate(cert, seen) {
  if (cert == null || cert === 0) return null;
  if (!cert || typeof cert !== 'object') return cert;
  seen = seen || [];
  for (var i = 0; i < seen.length; i++) {
    if (seen[i].source === cert) return seen[i].clone;
  }
  var clone = {};
  seen.push({ source: cert, clone: clone });
  for (var key in cert) {
    if (!hasOwn.call(cert, key)) continue;
    if (key === 'issuerCertificate') {
      clone[key] = cert[key] && typeof cert[key] === 'object'
        ? translatePeerCertificate(cert[key], seen)
        : null;
    } else if (key === 'infoAccess') {
      clone[key] = _translateInfoAccess(cert[key]);
    } else {
      clone[key] = cert[key];
    }
  }
  return clone;
}

function _copySocketMetadata(socket, rawSocket) {
  if (!socket || !rawSocket) return;
  if (typeof rawSocket.remoteAddress !== 'undefined') _tlsPub(socket).remoteAddress = rawSocket.remoteAddress;
  if (typeof rawSocket.remotePort !== 'undefined') _tlsPub(socket).remotePort = rawSocket.remotePort;
  if (typeof rawSocket.remoteFamily !== 'undefined') _tlsPub(socket).remoteFamily = rawSocket.remoteFamily;
  if (typeof rawSocket.localAddress !== 'undefined') _tlsPub(socket).localAddress = rawSocket.localAddress;
  if (typeof rawSocket.localPort !== 'undefined') _tlsPub(socket).localPort = rawSocket.localPort;
  if (typeof rawSocket.localFamily !== 'undefined') _tlsPub(socket).localFamily = rawSocket.localFamily;
  if (!_tlsPriv(socket)._tlsTransportUndecided && typeof rawSocket.readable === 'boolean') {
    _tlsPub(socket).readable = rawSocket.readable;
  }
  if (typeof rawSocket.writable === 'boolean') _tlsPub(socket).writable = rawSocket.writable;
  if (!_tlsPriv(socket)._tlsTransportUndecided && typeof rawSocket.destroyed === 'boolean') {
    _tlsPub(socket).destroyed = rawSocket.destroyed;
  }
  if (typeof rawSocket.connecting === 'boolean') _tlsPub(socket).connecting = rawSocket.connecting;
  if (typeof rawSocket._isWriting === 'boolean') _tlsPriv(socket)._isWriting = rawSocket._isWriting;
  if (rawSocket._writeQueue) _tlsPriv(socket)._writeQueue = rawSocket._writeQueue;
}

function _holdUndecidedTlsData(wrapper, rawSocket, chunk) {
  var copy = _tlsWriteBuffer(chunk);
  var length = _byteLength(copy);
  var retained = _tlsPriv(wrapper)._tlsUndecidedDataBytes || 0;
  var limit = Math.max(
    512 * 1024,
    Math.min(1024 * 1024, (_tlsPriv(wrapper)._readableHighWaterMark || 16384) * 8)
  );
  if (length > limit - retained) {
    if (rawSocket && typeof rawSocket.pause === 'function') rawSocket.pause();
    _destroyTlsSocketWithError(wrapper, _createError(
      'ERR_TLS_BUFFER_OVERFLOW',
      'TLS transport sent too much data before the handshake path was selected'
    ), false);
    return;
  }
  if (!_tlsPriv(wrapper)._tlsUndecidedData) _tlsPriv(wrapper)._tlsUndecidedData = [];
  _tlsPriv(wrapper)._tlsUndecidedData.push(copy);
  if (!_tlsPriv(wrapper)._tlsUndecidedEvents) _tlsPriv(wrapper)._tlsUndecidedEvents = [];
  _tlsPriv(wrapper)._tlsUndecidedEvents.push({ type: 'data', chunk: copy });
  _tlsPriv(wrapper)._tlsUndecidedDataBytes = retained + length;
  if (!_tlsPriv(wrapper)._tlsUndecidedInputPaused && rawSocket && typeof rawSocket.pause === 'function') {
    _tlsPriv(wrapper)._tlsUndecidedInputPaused = true;
    rawSocket.pause();
  }
}

function _holdUndecidedTlsTerminal(wrapper, eventName, hadError) {
  if (!_tlsPriv(wrapper)._tlsUndecidedEvents) _tlsPriv(wrapper)._tlsUndecidedEvents = [];
  _tlsPriv(wrapper)._tlsUndecidedEvents.push({ type: eventName, hadError: hadError === true });
  if (eventName === 'end') _tlsPriv(wrapper)._tlsUndecidedTransportEnded = true;
  if (eventName === 'close') _tlsPriv(wrapper)._tlsUndecidedTransportClosed = true;
}

// Drain one ordered batch without dropping the guard. Native bridge startup
// uses this repeatedly because processing an old record can synchronously
// write a response whose raw write hook emits a newer record.
function _drainUndecidedTlsData(socket) {
  var events = _tlsPriv(socket)._tlsUndecidedEvents || [];
  var pending = [];
  for (var i = 0; i < events.length; i++) {
    if (events[i].type === 'data') pending.push(events[i].chunk);
  }
  var inputPaused = _tlsPriv(socket)._tlsUndecidedInputPaused === true;
  var transportEnded = _tlsPriv(socket)._tlsUndecidedTransportEnded === true;
  var transportClosed = _tlsPriv(socket)._tlsUndecidedTransportClosed === true;
  _tlsPriv(socket)._tlsUndecidedEvents = [];
  _tlsPriv(socket)._tlsUndecidedData = [];
  // The retained-byte bound applies to the currently queued batch. Native
  // bridge startup may drain several batches as engine writes synchronously
  // trigger newer raw input; bytes already handed off no longer consume the
  // retention budget.
  _tlsPriv(socket)._tlsUndecidedDataBytes = 0;
  _tlsPriv(socket)._tlsUndecidedTransportEnded = false;
  _tlsPriv(socket)._tlsUndecidedTransportClosed = false;
  return {
    events: events,
    pending: pending,
    inputPaused: inputPaused,
    transportEnded: transportEnded,
    transportClosed: transportClosed
  };
}

function _takeUndecidedTlsData(socket) {
  var batch = _drainUndecidedTlsData(socket);
  _tlsPriv(socket)._tlsTransportUndecided = false;
  _tlsPriv(socket)._tlsUndecidedEvents = null;
  _tlsPriv(socket)._tlsUndecidedData = null;
  _tlsPriv(socket)._tlsUndecidedDataBytes = 0;
  _tlsPriv(socket)._tlsUndecidedInputPaused = false;
  return batch;
}

function _emitTlsErrorOnce(socket, err) {
  if (_tlsPriv(socket)._tlsErrorEmitted) return;
  _tlsPriv(socket)._tlsErrorEmitted = true;
  _tlsEmitInternal(socket, 'error', [err]);
}

function _detachBoundSocketListeners(socket) {
  var values = _tlsPriv(socket);
  var listeners = values._boundSocketListeners || [];
  values._boundSocketListeners = [];
  for (var i = 0; i < listeners.length; i++) {
    var entry = listeners[i];
    if (!entry || !entry.rawSocket) continue;
    try {
      if (typeof entry.rawSocket.removeListener === 'function') {
        entry.rawSocket.removeListener(entry.eventName, entry.listener);
      } else if (typeof entry.rawSocket.off === 'function') {
        entry.rawSocket.off(entry.eventName, entry.listener);
      }
    } catch (_detachRawListenerErr) {
      // A custom transport may throw during listener removal. The listener's
      // terminal-state check below still prevents post-close state mutation.
    }
  }
}

function _emitTlsCloseOnce(socket, hadError) {
  if (_tlsPriv(socket)._tlsCloseEmitted) {
    // A native owner-token close that threw remains retryable without
    // duplicating the already-published close event.
    _tlsReleaseOwner(socket);
    return;
  }
  _tlsBridgeRelease(socket);
  _tlsPriv(socket)._tlsCloseEmitted = true;
  _detachBoundSocketListeners(socket);
  _tlsPub(socket).destroyed = true;
  _tlsPub(socket).readable = false;
  _tlsPub(socket).writable = false;
  try {
    _tlsEmitInternal(socket, 'close', [hadError === true]);
  } finally {
    var privateState = _tlsSocketPrivateStates && _tlsSocketPrivateStates.get(socket);
    if (privateState) {
      var values = privateState.values;
      values._tlsOptions = null;
      values._socket = null;
      values._boundSocket = null;
      values._boundSocketListeners = null;
      values._peerCertificate = null;
      values._localCertificate = null;
      values._heldWrites = null;
      values._heldEnd = null;
      values._bridgePendingWrites = null;
      values._bridgeHeldEnd = null;
      values._bridgeReadQueue = null;
      values._bridgeCipherQueue = null;
      values._tlsUndecidedEvents = null;
      values._tlsUndecidedData = null;
      values._bridgeDecoder = null;
      values._bridgeDecodedTail = null;
      // Event listeners may close over credentials or plaintext. Once the
      // terminal close event has run, retaining them would re-expose those
      // closures after the native owner token is gone.
      var terminalEvents = Object.create(null);
      if (typeof Object.freeze === 'function') Object.freeze(terminalEvents);
      values._events = terminalEvents;
    }
    _tlsReleaseOwner(socket);
  }
}

function _destroyTlsSocketWithError(socket, err, replayHeldClose) {
  _tlsPriv(socket)._tlsPendingTerminalError = err;
  var synthesize = function() {
    var unhandled = null;
    try {
      _emitTlsErrorOnce(socket, err);
    } catch (emitErr) {
      unhandled = emitErr;
    }
    _emitTlsCloseOnce(socket, true);
    if (unhandled) throw unhandled;
  };
  // A retained close has already consumed the raw socket's only close event,
  // so synthesize both terminal wrapper events now. Otherwise give the raw
  // socket's normal destroy(error) event turn priority and only backfill
  // terminal events when a custom/embedder socket does not emit them.
  if (replayHeldClose) {
    _tlsPriv(socket)._tlsSuppressRawClose = true;
    try {
      socket.destroy(err);
    } finally {
      _tlsPriv(socket)._tlsSuppressRawClose = false;
    }
    synthesize();
  } else {
    socket.destroy(err);
    setTimeout(function() {
      _tlsAssertOwner(socket);
      if (!_tlsPriv(socket)._tlsErrorEmitted || !_tlsPriv(socket)._tlsCloseEmitted) synthesize();
    }, 0);
  }
}

function _bindSocket(wrapper, rawSocket) {
  if (!wrapper || !rawSocket) return rawSocket;
  if (_tlsPriv(wrapper)._boundSocket && _tlsPriv(wrapper)._boundSocket !== rawSocket) {
    throw _createError(
      'ERR_TLS_SOCKET_ALREADY_BOUND',
      'A TLSSocket transport cannot be replaced after it has been bound'
    );
  }
  _tlsPriv(wrapper)._socket = rawSocket;
  _copySocketMetadata(wrapper, rawSocket);
  if (rawSocket.connecting === false) _captureTlsTransportIdentity(wrapper, rawSocket);

  if (_tlsPriv(wrapper)._boundSocket === rawSocket || typeof rawSocket.on !== 'function') {
    return rawSocket;
  }

  _tlsPriv(wrapper)._boundSocket = rawSocket;
  if (!_tlsPriv(wrapper)._boundSocketListeners) {
    _tlsPriv(wrapper)._boundSocketListeners = [];
  }
  var events = ['data', 'end', 'error', 'close', 'timeout', 'drain', 'lookup', 'ready', 'connect'];
  for (var i = 0; i < events.length; i++) {
    (function(eventName) {
      var listener = function() {
        // Custom transports can retain and invoke listener closures after
        // close even when removeListener is missing or hostile. Terminal TLS
        // state is immutable and no longer has an active owner token.
        if (_tlsPriv(wrapper)._tlsCloseEmitted) return;
        _tlsAssertOwner(wrapper);
        // Once public destroy begins, only the raw close notification may
        // reconcile the wrapper's final error -> close sequence.
        if (_tlsPub(wrapper).destroyed && eventName !== 'close') return;
        // Capture the real transport tuple before forwarding `connect` to user
        // code. Loopback pairing consumes only this private snapshot, never
        // caller-writable wrapper/raw metadata.
        if (eventName === 'connect') _captureTlsTransportIdentity(wrapper, rawSocket);
        // For an already-connected socket, connect() selects the in-process
        // emulation or native TLS bridge on the next turn. Bytes received in
        // that window are never authenticated application data. Retain a
        // bounded copy and pause the transport until the selected path can
        // consume it as plaintext or ciphertext, respectively.
        if (_tlsPriv(wrapper)._tlsTransportUndecided && eventName === 'data') {
          _holdUndecidedTlsData(wrapper, rawSocket, arguments[0]);
          return;
        }
        if (_tlsPriv(wrapper)._tlsTransportUndecided && eventName === 'end') {
          _holdUndecidedTlsTerminal(wrapper, 'end');
          return;
        }
        if (_tlsPriv(wrapper)._tlsTransportUndecided && eventName === 'close') {
          if (_tlsPriv(wrapper)._tlsAwaitingConnectEvent) {
            var connectCloseError = _tlsPriv(wrapper)._tlsPendingTerminalError;
            if (!connectCloseError && arguments[0] === true) {
              connectCloseError = _createError('ECONNRESET', 'read ECONNRESET');
              _tlsPriv(wrapper)._tlsPendingTerminalError = connectCloseError;
            }
            var connectCloseUnhandled = null;
            if (connectCloseError && !_tlsPriv(wrapper)._tlsErrorEmitted) {
              try {
                _emitTlsErrorOnce(wrapper, connectCloseError);
              } catch (emitErr) {
                connectCloseUnhandled = emitErr;
              }
            }
            _takeUndecidedTlsData(wrapper);
            _tlsPriv(wrapper)._tlsAwaitingConnectEvent = false;
            _tlsPub(wrapper).connecting = false;
            _tlsReleaseHeldWrites(wrapper, 'drop');
            _tlsDropBridgeWrites(wrapper);
            _emitTlsCloseOnce(wrapper, arguments[0] === true || !!connectCloseError);
            if (connectCloseUnhandled) throw connectCloseUnhandled;
            return;
          }
          _holdUndecidedTlsTerminal(wrapper, 'close', arguments[0]);
          return;
        }
        if (_tlsPriv(wrapper)._tlsSuppressRawClose && eventName === 'close') {
          _tlsPriv(wrapper)._tlsDeferredCloseHadError =
            _tlsPriv(wrapper)._tlsDeferredCloseHadError || arguments[0] === true;
          return;
        }
        if (_tlsPub(wrapper).destroyed && eventName === 'end') return;
        if (_tlsPub(wrapper).destroyed && eventName === 'close') {
          var destroyedCloseUnhandled = null;
          var destroyedCloseError = _tlsPriv(wrapper)._tlsFailureError ||
            _tlsPriv(wrapper)._tlsPendingTerminalError;
          if (destroyedCloseError && !_tlsPriv(wrapper)._tlsErrorEmitted) {
            try {
              _emitTlsErrorOnce(wrapper, destroyedCloseError);
            } catch (emitErr) {
              destroyedCloseUnhandled = emitErr;
            }
          }
          _emitTlsCloseOnce(
            wrapper,
            arguments[0] === true || !!destroyedCloseError
          );
          if (destroyedCloseUnhandled) throw destroyedCloseUnhandled;
          return;
        }
        // Bridged (real TLS) sockets: raw-socket bytes are ciphertext for the
        // native engine, never application data — route them (and transport
        // EOF) through the bridge instead of re-emitting (ENG-23492).
        if (_tlsPriv(wrapper)._bridged) {
          if (eventName === 'data') {
            _tlsBridgeOnCiphertext(wrapper, arguments[0]);
            return;
          }
          if (eventName === 'drain') {
            _tlsBridgeOnRawDrain(wrapper);
            return;
          }
          if (eventName === 'end') {
            _tlsBridgeOnTransportEnd(wrapper);
            return;
          }
          if (eventName === 'close') {
            // Some transports omit `end` on an abrupt close. Apply native EOF
            // before releasing so an in-flight handshake fails loudly and
            // authenticated plaintext/end ordering is preserved.
            _tlsPriv(wrapper)._tlsDeferredTransportClose = true;
            _tlsPriv(wrapper)._tlsDeferredCloseHadError =
              _tlsPriv(wrapper)._tlsDeferredCloseHadError || arguments[0] === true;
            _tlsBridgeOnTransportEnd(wrapper);
            // Do not fall through to raw close forwarding. Authenticated
            // plaintext may be queued in readable mode; its data and `end`
            // must drain before _tlsBridgeMaybeEmitEnd releases the engine and
            // replays exactly one wrapper close.
            return;
          }
        }
        if (eventName === 'error') {
          if (_tlsPriv(wrapper)._tlsErrorEmitted) return;
          _tlsPriv(wrapper)._tlsPendingTerminalError = arguments[0];
          _tlsPriv(wrapper)._tlsErrorEmitted = true;
        }
        if (eventName === 'close' && _tlsPriv(wrapper)._tlsCloseEmitted) return;
        if (eventName === 'connect') _tlsPub(wrapper).connecting = false;
        if (eventName === 'end') _tlsPub(wrapper).readable = false;
        _copySocketMetadata(wrapper, rawSocket);
        if (eventName === 'close') {
          var unhandledBridgeError = null;
          var pendingCloseError = _tlsPriv(wrapper)._tlsFailureError ||
            _tlsPriv(wrapper)._tlsPendingTerminalError;
          if (pendingCloseError && !_tlsPriv(wrapper)._tlsErrorEmitted) {
            try {
              _emitTlsErrorOnce(wrapper, pendingCloseError);
            } catch (emitErr) {
              unhandledBridgeError = emitErr;
            }
          }
          _tlsBridgeRelease(wrapper);
          _emitTlsCloseOnce(wrapper, arguments[0] === true || !!pendingCloseError);
          if (unhandledBridgeError) throw unhandledBridgeError;
          return;
        }
        _tlsEmitInternal(wrapper, eventName, Array.prototype.slice.call(arguments));
      };
      _tlsPriv(wrapper)._boundSocketListeners.push({
        rawSocket: rawSocket,
        eventName: eventName,
        listener: listener
      });
      rawSocket.on(eventName, listener);
    })(events[i]);
  }

  return rawSocket;
}

function _callSocketMethod(wrapper, methodName, args, fallback) {
  if (wrapper && _tlsPriv(wrapper)._socket && typeof _tlsPriv(wrapper)._socket[methodName] === 'function') {
    return _tlsPriv(wrapper)._socket[methodName].apply(_tlsPriv(wrapper)._socket, args || []);
  }
  return fallback;
}

function _tlsRawTransportDestroyed(socket) {
  return !!(socket && _tlsPriv(socket)._socket && _tlsPriv(socket)._socket.destroyed);
}

function _tlsRawTransportUnexpectedlyDestroyed(socket) {
  return _tlsRawTransportDestroyed(socket) && !_tlsPriv(socket)._tlsDeferredTransportClose;
}

function _tlsTransportTerminatedSince(socket, rawWasDestroyed, closeWasDeferred) {
  return (!rawWasDestroyed && _tlsRawTransportDestroyed(socket)) ||
    (!closeWasDeferred && _tlsPriv(socket)._tlsDeferredTransportClose);
}

function _tlsPendingWriteError(socket) {
  return _tlsPriv(socket)._tlsFailureError || _createError(
    'ERR_STREAM_DESTROYED',
    'TLS socket was destroyed before the pending write completed'
  );
}

function _tlsSettleWriteCallbacks(items, endCallback, err) {
  var callbacks = [];
  var pending = items || [];
  for (var i = 0; i < pending.length; i++) {
    if (typeof pending[i].callback === 'function') {
      callbacks.push(pending[i].callback);
      pending[i].callback = null;
    }
  }
  if (typeof endCallback === 'function') callbacks.push(endCallback);
  for (var j = 0; j < callbacks.length; j++) {
    (function(callback) {
      setTimeout(function() { callback(err); }, 0);
    })(callbacks[j]);
  }
}

function _tlsTerminateIfTransportChanged(socket, rawWasDestroyed, closeWasDeferred) {
  if (!_tlsTransportTerminatedSince(socket, rawWasDestroyed, closeWasDeferred)) return false;
  _tlsDropBridgeWrites(socket);
  if (!_tlsPub(socket).destroyed) _terminateTlsForDestroyedTransport(socket);
  return true;
}

function _tlsDropBridgeWrites(socket) {
  _tlsSettleWriteCallbacks(
    _tlsPriv(socket)._bridgePendingWrites,
    _tlsPriv(socket)._bridgeHeldEnd,
    _tlsPendingWriteError(socket)
  );
  _tlsPriv(socket)._bridgePendingWrites = null;
  _tlsPriv(socket)._bridgePendingWriteBytes = 0;
  _tlsPriv(socket)._bridgeHeldEnd = null;
  _tlsBridgeUpdateBufferedBytes(socket);
}

function _terminateTlsForDestroyedTransport(socket) {
  var hadError = _tlsPriv(socket)._tlsDeferredCloseHadError === true;
  _tlsReleaseHeldWrites(socket, 'drop');
  if (!_tlsPub(socket).destroyed) socket.destroy();
  _emitTlsCloseOnce(socket, hadError);
}

function _finalizeHandshake(socket, peerOptions, negotiatedCipher) {
  var opts = _tlsPriv(socket)._tlsOptions || {};
  var remoteOptions = peerOptions || {};
  var host = _tlsPriv(socket)._servername || _tlsPub(socket).remoteAddress || 'localhost';
  _tlsPriv(socket)._peerCertificate = _buildPeerCertificate(host, _tlsPub(socket).remotePort, remoteOptions, opts);
  _tlsPriv(socket)._localCertificate = _buildLocalCertificate(host, _tlsPub(socket).remotePort, opts);
  _tlsPriv(socket)._cipher = {
    name: negotiatedCipher || _normalizeCipherName(remoteOptions.ciphers || opts.ciphers),
    version: _tlsPriv(socket)._protocol
  };
  _tlsPriv(socket)._authorizationErrorObject = null;
  // Node semantics (verified v25.9.0): rejectUnauthorized:false only prevents
  // the connection from being aborted — certificate validation still runs and
  // _tlsPub(socket).authorized / _tlsPub(socket).authorizationError reflect its result (e.g.
  // authorized=false with authorizationError='DEPTH_ZERO_SELF_SIGNED_CERT' for
  // a self-signed peer). Callers use the return value (authorization success)
  // together with rejectUnauthorized to decide whether to error/destroy.
  var authorizationError = _validatePeerAuthorization(
    _tlsPriv(socket)._peerCertificate,
    opts,
    host,
    _tlsPub(socket).remotePort,
    remoteOptions
  );
  if (authorizationError) {
    _tlsPub(socket).authorizationError = authorizationError.code || authorizationError.message || String(authorizationError);
    _tlsPriv(socket)._authorizationErrorObject = authorizationError;
    _tlsPub(socket).authorized = false;
    return false;
  }
  var check = opts.checkServerIdentity || checkServerIdentity;
  var result = null;
  try {
    result = _normalizeCheckError(check(host, _tlsPriv(socket)._peerCertificate, opts));
  } catch (error) {
    result = _normalizeCheckError(error);
  }
  if (result) {
    _tlsPub(socket).authorizationError = result.code || result.message || String(result);
    _tlsPriv(socket)._authorizationErrorObject = result;
    _tlsPub(socket).authorized = false;
    return false;
  }
  _tlsPub(socket).authorizationError = null;
  _tlsPriv(socket)._authorizationErrorObject = null;
  _tlsPub(socket).authorized = true;
  return true;
}

function _loopbackClientAuthorizationError(serverOptions, clientOptions, host, port) {
  if (!serverOptions.requestCert) return null;
  if (!clientOptions || !(clientOptions.cert || clientOptions.pfx)) {
    return _createError(
      'ERR_TLS_CERT_REQUIRED',
      'TLS client certificate required'
    );
  }
  if (clientOptions.pfx) {
    return _createError(
      'ERR_TLS_PFX_UNSUPPORTED',
      'Loopback TLS emulation cannot verify a PFX client identity'
    );
  }
  // Synthetic loopback TLS has no CertificateVerify exchange and therefore
  // cannot prove possession of the private key, even when certificate bytes
  // happen to match a configured CA. Never report such a peer as authorized.
  return _createError(
    'ERR_TLS_LOOPBACK_AUTH_UNSUPPORTED',
    'Loopback TLS emulation cannot cryptographically verify a client identity'
  );
}

function _finalizeServerHandshake(socket, clientOptions, negotiatedCipher, negotiatedProtocol) {
  var serverOptions = _tlsPriv(socket)._tlsOptions || {};
  var host = _tlsPub(socket).remoteAddress || _tlsPub(socket).servername || 'localhost';
  _tlsPriv(socket)._peerCertificate = (clientOptions && (clientOptions.cert || clientOptions.pfx))
    ? _buildPeerCertificate(host, _tlsPub(socket).remotePort, clientOptions, serverOptions)
    : null;
  _tlsPriv(socket)._localCertificate = _buildLocalCertificate(host, _tlsPub(socket).remotePort, serverOptions);
  _tlsPriv(socket)._cipher = {
    name: negotiatedCipher || _normalizeCipherName(serverOptions.ciphers),
    version: negotiatedProtocol || _tlsPriv(socket)._protocol
  };
  if (negotiatedProtocol) _tlsPriv(socket)._protocol = negotiatedProtocol;
  _tlsPub(socket).connecting = false;
  _tlsPriv(socket)._pending = false;
  _tlsPriv(socket)._secureEstablished = true;
  var clientAuthorizationError = _loopbackClientAuthorizationError(
    serverOptions,
    clientOptions,
    host,
    _tlsPub(socket).remotePort
  );
  _tlsPub(socket).authorizationError = clientAuthorizationError
    ? (clientAuthorizationError.code || clientAuthorizationError.message)
    : null;
  _tlsPriv(socket)._authorizationErrorObject = clientAuthorizationError;
  _tlsPub(socket).authorized = !clientAuthorizationError;
  return !clientAuthorizationError || !serverOptions.rejectUnauthorized;
}

function _applyPendingServerHandshake(server, tlsSocket, handshake) {
  if (!server || !tlsSocket || !handshake) return;
  _clearLoopbackClientCloseWatch(handshake);
  if (handshake.ok) {
    var serverAccepted = _finalizeServerHandshake(
      tlsSocket,
      handshake.clientOptions,
      handshake.cipher,
      handshake.protocol
    );
    if (!serverAccepted) {
      var clientCertErr = _tlsPriv(tlsSocket)._authorizationErrorObject || _createError(
        'ERR_TLS_CERT_REQUIRED',
        'TLS client certificate rejected'
      );
      server.emit('tlsClientError', clientCertErr, tlsSocket);
      // The pre-secure socket was never published, so destroying it with the
      // peer error would create an unhandled raw/wrapper `error`. The server's
      // tlsClientError event is the sole error channel for this private socket.
      tlsSocket.destroy();
      return;
    }
    _tlsEmitInternal(tlsSocket, 'secure', [true]);
    server.emit('secureConnection', tlsSocket);
    if (!_tlsPub(tlsSocket).destroyed && _tlsPriv(tlsSocket)._socket &&
        typeof _tlsPriv(tlsSocket)._socket.resume === 'function') {
      _tlsPriv(tlsSocket)._socket.resume();
    }
    return;
  }
  _tlsPub(tlsSocket).authorizationError = handshake.serverError && handshake.serverError.message
    ? handshake.serverError.message
    : 'handshake failure';
  server.emit('tlsClientError', handshake.serverError, tlsSocket);
  tlsSocket.destroy();
}

function _decorateSecureContext(target, options) {
  var normalized = _cloneOwnProperties(options || {});
  _validateProtocolVersion('minimum', normalized.minVersion);
  _validateProtocolVersion('maximum', normalized.maxVersion);
  normalized._cipherSuites = _resolveCipherSuites(normalized, 'server');

  if (hasOwn.call(normalized, 'ALPNProtocols') && normalized.ALPNProtocols !== null && typeof normalized.ALPNProtocols !== 'undefined') {
    normalized.ALPNProtocols = convertALPNProtocols(normalized.ALPNProtocols);
  }

  var opaqueContext = {};
  if (typeof Object.freeze === 'function') Object.freeze(opaqueContext);
  var state = { options: normalized, secureContext: target, opaqueContext: opaqueContext };
  if (_secureContextStates) {
    _secureContextStates.set(target, state);
    _secureContextStates.set(opaqueContext, state);
  }
  if (typeof Object.defineProperty === 'function') {
    Object.defineProperty(target, 'context', {
      value: opaqueContext,
      enumerable: true,
      configurable: false,
      writable: false
    });
  } else {
    target.context = opaqueContext;
  }
  return target;
}

function SecureContext(options) {
  if (!(this instanceof SecureContext)) return new SecureContext(options);
  _decorateSecureContext(this, options && typeof options === 'object' ? options : {});
}

function createSecureContext(options) {
  if (options instanceof SecureContext) return options;
  return new SecureContext(options || {});
}

function TLSSocket(socket, options, deferSocketBinding) {
  if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);
  options = options || {};
  this._events = {};
  _mixinEventEmitter(this);
  _installTlsPrivateState(this);
  _tlsPriv(this)._socket = null;
  _tlsPriv(this)._boundSocket = null;
  _tlsPriv(this)._boundSocketListeners = [];
  _tlsPriv(this)._tlsOptions = _cloneOwnProperties(options);
  _defineOwnDataProperty(this, 'encrypted', true);
  _defineOwnDataProperty(this, 'allowHalfOpen', options.allowHalfOpen === true);
  _defineOwnDataProperty(this, 'authorized', false);
  _defineOwnDataProperty(this, 'authorizationError', null);
  _tlsPriv(this)._authorizationErrorObject = null;
  _tlsPriv(this)._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
  _tlsPriv(this)._session = null;
  _tlsPriv(this)._sessionReused = false;
  _tlsPriv(this)._peerCertificate = null;
  _tlsPriv(this)._localCertificate = null;
  _tlsPriv(this)._readableHighWaterMark = _normalizeTlsHighWaterMark(
    options.readableHighWaterMark,
    socket && socket.readableHighWaterMark
  );
  _tlsPriv(this)._writableHighWaterMark = _normalizeTlsHighWaterMark(
    options.writableHighWaterMark,
    socket && socket.writableHighWaterMark
  );
  _tlsPriv(this)._bufferedBytes = 0;
  _tlsPriv(this)._bridgeNeedDrain = false;
  _tlsPriv(this)._secureEstablished = false;
  _tlsPriv(this)._tlsApplicationReady = false;
  _tlsPriv(this)._tlsUserPaused = false;
  _tlsPriv(this)._tlsErrorEmitted = false;
  _tlsPriv(this)._tlsCloseEmitted = false;
  _tlsPriv(this)._tlsDeferredTransportClose = false;
  _tlsPriv(this)._tlsDeferredCloseHadError = false;
  _tlsPriv(this)._captureRejections = options.captureRejections === true;
  _tlsPriv(this)._pending = true;
  _tlsPriv(this)._servername = options.servername || options.host || options.hostname || null;
  _defineOwnDataProperty(this, 'servername', _tlsPriv(this)._servername);
  _defineOwnDataProperty(this, 'alpnProtocol', null);
  _defineOwnDataProperty(this, 'connecting', true);
  _defineOwnDataProperty(this, 'readable', true);
  _defineOwnDataProperty(this, 'writable', true);
  _defineOwnDataProperty(this, 'destroyed', false);
  _defineOwnDataProperty(this, 'remoteAddress', null);
  _defineOwnDataProperty(this, 'remotePort', null);
  _defineOwnDataProperty(this, 'remoteFamily', 'IPv4');
  _defineOwnDataProperty(this, 'localAddress', null);
  _defineOwnDataProperty(this, 'localPort', null);
  _defineOwnDataProperty(this, 'localFamily', 'IPv4');
  _tlsPriv(this)._cipher = { name: _normalizeCipherName(options.ciphers), version: _tlsPriv(this)._protocol };

  if (socket) _tlsCaptureOwner(this);
  try {
    if (socket) {
      _tlsPub(this).connecting = !!socket.connecting;
      _tlsPriv(this)._pending = !!socket.connecting;
      if (!deferSocketBinding) _bindSocket(this, socket);
    }
  } catch (bindErr) {
    _tlsReleaseOwner(this);
    throw bindErr;
  }
}

// Static-side inheritance (net.Socket's static members). The instance-side
// prototype chain is wired after all TLSSocket.prototype members are defined —
// see the block following the property accessors below (ENG-23448).
if (net && net.Socket && typeof Object.setPrototypeOf === 'function') {
  Object.setPrototypeOf(TLSSocket, net.Socket);
}
TLSSocket.prototype.constructor = TLSSocket;

TLSSocket.prototype._setSocket = function(socket) {
  _tlsAssertMutableOwner(this);
  _tlsCaptureOwner(this);
  if (_tlsPriv(this)._boundSocket && _tlsPriv(this)._boundSocket !== socket) {
    throw _createError(
      'ERR_TLS_SOCKET_ALREADY_BOUND',
      'A TLSSocket transport cannot be replaced after it has been bound'
    );
  }
  _bindSocket(this, socket);
  return this;
};

TLSSocket.prototype[_kReinitializeHandle] = function() {
  _tlsAssertOwner(this);
  return this;
};

// HTTP needs to control reset-as-EOF behavior on the wrapped transport without
// recovering the private raw socket selector. Keep that mutation inside TLS's
// owner boundary and expose only the narrow boolean operation.
TLSSocket.prototype[_kSetHttpResetAsEof] = function(enabled) {
  _tlsAssertMutableOwner(this);
  var socket = _tlsPriv(this)._socket;
  if (socket) socket._allowResetAsEof = enabled === true;
};

// Owner-only scalar diagnostics preserve the bounded-ciphertext regression
// without reopening the private queues or their native selectors.
TLSSocket.prototype[_kFlowControlStats] = function() {
  _tlsAssertOwner(this);
  var result = {
    retainedCiphertextBytes: _tlsPriv(this)._bridgeCipherQueueBytes || 0,
    ciphertextHighWaterMark: _tlsPriv(this)._ciphertextHighWaterMark || 0
  };
  return typeof Object.freeze === 'function' ? Object.freeze(result) : result;
};

TLSSocket.prototype.getPeerCertificate = function(detailed) {
  _tlsAssertOwner(this);
  return _tlsPriv(this)._peerCertificate ? _cloneCertificate(_tlsPriv(this)._peerCertificate, detailed === true) : {};
};

TLSSocket.prototype.getPeerX509Certificate = function() {
  _tlsAssertOwner(this);
  return _toX509Certificate(_tlsPriv(this)._peerCertificate, true);
};

TLSSocket.prototype.getCertificate = function() {
  _tlsAssertOwner(this);
  return _tlsPriv(this)._localCertificate ? _cloneCertificate(_tlsPriv(this)._localCertificate, true) : {};
};

TLSSocket.prototype.getX509Certificate = function() {
  _tlsAssertOwner(this);
  return _toX509Certificate(_tlsPriv(this)._localCertificate, false);
};

TLSSocket.prototype.getCipher = function() {
  _tlsAssertOwner(this);
  return _tlsPriv(this)._cipher || {
    name: _normalizeCipherName(_tlsPriv(this)._tlsOptions && _tlsPriv(this)._tlsOptions.ciphers),
    version: _tlsPriv(this)._protocol
  };
};

TLSSocket.prototype.getProtocol = function() {
  _tlsAssertOwner(this);
  return _tlsPriv(this)._protocol;
};

TLSSocket.prototype.getSession = function() {
  _tlsAssertOwner(this);
  return _tlsPriv(this)._session;
};

TLSSocket.prototype.setSession = function(session) {
  _tlsAssertMutableOwner(this);
  _tlsPriv(this)._session = session || null;
  return this;
};

TLSSocket.prototype.isSessionReused = function() {
  _tlsAssertOwner(this);
  return !!_tlsPriv(this)._sessionReused;
};

TLSSocket.prototype.getFinished = function() {
  _tlsAssertOwner(this);
  return null;
};

TLSSocket.prototype.getTLSTicket = function() {
  _tlsAssertOwner(this);
  return null;
};

TLSSocket.prototype.getSharedSigalgs = function() {
  _tlsAssertOwner(this);
  return [];
};

// Node contract for renegotiate(), verified against Node v25.9.0 (ENG-23448):
//   * options must be an object and callback (if given) a function — otherwise
//     ERR_INVALID_ARG_TYPE is thrown, even on a destroyed socket;
//   * a destroyed socket returns undefined without invoking the callback;
//   * on TLSv1.3 renegotiation does not exist in the protocol: returns false
//     and the callback receives an ERR_SSL_WRONG_SSL_VERSION error;
//   * disableRenegotiation() does NOT block a self-initiated renegotiate() —
//     in Node it errors the disabled socket only when the PEER renegotiates
//     (ERR_TLS_RENEGOTIATION_DISABLED via 'error'); the emulation has no real
//     renegotiation, and cross-socket peer notification is not emulated.
TLSSocket.prototype.renegotiate = function(options, callback) {
  _tlsAssertOwner(this);
  if (options === null || typeof options !== 'object') {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "options" argument must be of type object. Received ' +
        (options === null ? 'null' : typeof options)
    );
  }
  if (callback !== undefined && typeof callback !== 'function') {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "callback" argument must be of type function. Received ' + typeof callback
    );
  }
  if (_tlsPub(this).destroyed) return undefined;
  var protocol = _tlsPriv(this)._protocol;
  if (protocol === 'TLSv1.3') {
    if (typeof callback === 'function') {
      var err = _createError(
        'ERR_SSL_WRONG_SSL_VERSION',
        'error:0A00010A:SSL routines::wrong ssl version'
      );
      err.library = 'SSL routines';
      err.reason = 'wrong ssl version';
      setTimeout(function() { callback(err); }, 0);
    }
    return false;
  }
  // TLSv1.2 and below: the emulated renegotiation is an immediate no-op
  // success, matching Node's observable result for a loopback renegotiate.
  if (typeof callback === 'function') {
    setTimeout(function() { callback(null); }, 0);
  }
  return true;
};

TLSSocket.prototype.disableRenegotiation = function() {
  _tlsAssertMutableOwner(this);
  _tlsPriv(this)._renegotiationDisabled = true;
};

TLSSocket.prototype.enableTrace = function() {
  _tlsAssertMutableOwner(this);
  return _callSocketMethod(this, 'enableTrace', [], undefined);
};

TLSSocket.prototype.setMaxSendFragment = function(size) {
  _tlsAssertMutableOwner(this);
  if (typeof size !== 'number' || size !== (size | 0) || size < 512 || size > 16384) {
    return false;
  }
  _tlsPriv(this)._maxSendFragment = size;
  return true;
};

TLSSocket.prototype.setEncoding = function(enc) {
  _tlsAssertMutableOwner(this);
  // Record the wrapper encoding even before the TCP connect decides between
  // in-process emulation and the native bridge. Applying it to the raw socket
  // early would decode TLS ciphertext as text on the bridged path.
  _tlsPriv(this)._bridgeEncoding = enc || null;
  _tlsPriv(this)._bridgeDecoder = enc && StringDecoder ? new StringDecoder(enc) : null;
  _tlsPriv(this)._bridgeDecoderFinalized = false;
  _tlsPriv(this)._bridgeDecodedTail = null;
  if (_tlsPriv(this)._bridged || _tlsPriv(this)._writeHeld || _tlsPub(this).connecting || _tlsPriv(this)._pending) {
    return this;
  }
  _callSocketMethod(this, 'setEncoding', [enc], this);
  return this;
};

// Explicit delegation shadows for the state-dependent net.Socket methods that
// became reachable once TLSSocket.prototype was chained to net.Socket.prototype
// (see the wiring below). The inherited implementations dereference net.Socket
// constructor state (_readBuffer, _handle, ...) that this wrapper never has;
// data flows through the wrapped raw socket, so delegate there instead.
TLSSocket.prototype.read = function(size) {
  _tlsAssertMutableOwner(this);
  // A connect-created wrapper is undecided until TCP connect. Never delegate
  // read() to the raw socket in that window: if the peer wins the race, those
  // bytes are TLS ciphertext. Once the loopback path is selected _writeHeld is
  // cleared and the raw socket becomes a valid plaintext delegate.
  if (_tlsPriv(this)._writeHeld && !_tlsPriv(this)._bridged) return null;
  if (_tlsPriv(this)._bridged) {
    _tlsPriv(this)._bridgeReadDepth = (_tlsPriv(this)._bridgeReadDepth || 0) + 1;
    try {
      var queuedBeforeRead = _tlsPriv(this)._bridgeReadQueueBytes || 0;
      var readLowWater = Math.max(1, Math.floor(_tlsPriv(this)._readableHighWaterMark / 2));
      if (queuedBeforeRead === 0 ||
          (!_tlsPriv(this)._bridgePaused && _tlsPriv(this)._bridgeInputPaused &&
           queuedBeforeRead <= readLowWater)) {
        _tlsBridgeDrainPlain(this);
      }
      var queue = _tlsPriv(this)._bridgeReadQueue || [];
      if (!queue.length) {
        if (_tlsPriv(this)._bridgeDecodedTail !== null && _tlsPriv(this)._bridgeDecodedTail !== undefined) {
          var decoderTail = _tlsPriv(this)._bridgeDecodedTail;
          _tlsPriv(this)._bridgeDecodedTail = null;
          _tlsBridgeMaybeEmitEnd(this);
          return decoderTail;
        }
        return null;
      }
      var available = _tlsPriv(this)._bridgeReadQueueBytes || 0;
      if (typeof size === 'number' && size > available && !_tlsPriv(this)._bridgeNativeEnded) return null;
      var wanted = typeof size === 'number' && size > 0 ? Math.min(size, available) : available;
      var offset = _tlsPriv(this)._bridgeReadQueueOffset || 0;
      var firstAvailable = _byteLength(queue[0]) - offset;
      var result;
      if (wanted <= firstAvailable) {
        result = queue[0].slice(offset, offset + wanted);
        offset += wanted;
        if (offset >= _byteLength(queue[0])) {
          queue.shift();
          offset = 0;
        }
      } else {
        result = typeof Buffer !== 'undefined' && typeof Buffer.allocUnsafe === 'function'
          ? Buffer.allocUnsafe(wanted)
          : new Uint8Array(wanted);
        var copied = 0;
        while (copied < wanted && queue.length) {
          var source = queue[0];
          var take = Math.min(wanted - copied, _byteLength(source) - offset);
          var slice = source.slice(offset, offset + take);
          if (typeof slice.copy === 'function') slice.copy(result, copied);
          else result.set(slice, copied);
          copied += take;
          offset += take;
          if (offset >= _byteLength(source)) {
            queue.shift();
            offset = 0;
          }
        }
      }
      _tlsPriv(this)._bridgeReadQueue = queue;
      _tlsPriv(this)._bridgeReadQueueOffset = offset;
      _tlsPriv(this)._bridgeReadQueueBytes = available - wanted;
      var encodedResult = _tlsBridgeEncode(this, result);
      _tlsBridgeMaybeResumeInput(this);
      _tlsBridgeMaybeEmitEnd(this);
      return encodedResult;
    } finally {
      _tlsPriv(this)._bridgeReadDepth = Math.max(0, (_tlsPriv(this)._bridgeReadDepth || 1) - 1);
    }
  }
  return _callSocketMethod(this, 'read', [size], null);
};

TLSSocket.prototype.push = function(chunk, encoding) {
  _tlsAssertMutableOwner(this);
  return _callSocketMethod(this, 'push', [chunk, encoding], false);
};

TLSSocket.prototype.unshift = function(chunk) {
  _tlsAssertMutableOwner(this);
  return _callSocketMethod(this, 'unshift', [chunk], undefined);
};

// ibex's net.Socket exposes close() as a destroy alias; mirror that against the
// wrapper's own destroy (which tears down the raw socket too).
TLSSocket.prototype.close = function(err) {
  return this.destroy(err);
};

TLSSocket.prototype.connect = function() {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'connect', Array.prototype.slice.call(arguments), this);
  return this;
};

TLSSocket.prototype.write = function(data, encoding, callback) {
  _tlsAssertMutableOwner(this);
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  // connect() holds application writes until the loopback-vs-bridge decision
  // is made on TCP connect: consumers (e.g. http.js) write the request the
  // moment 'connect' fires, which is BEFORE the bridged handshake — letting
  // those bytes through would send plaintext ahead of the ClientHello.
  if (_tlsPriv(this)._writeHeld) {
    if (!_tlsPriv(this)._heldWrites) _tlsPriv(this)._heldWrites = [];
    var heldBuffer = _tlsWriteBuffer(data, encoding);
    var heldLength = _byteLength(heldBuffer);
    _tlsPriv(this)._heldWrites.push({ buffer: heldBuffer, offset: 0, callback: callback });
    _tlsPriv(this)._heldWriteBytes = (_tlsPriv(this)._heldWriteBytes || 0) + heldLength;
    _tlsPriv(this)._bufferedBytes = _tlsPriv(this)._heldWriteBytes;
    if (_tlsPriv(this)._heldWriteBytes >= _tlsPriv(this)._writableHighWaterMark) _tlsPriv(this)._bridgeNeedDrain = true;
    return _tlsPriv(this)._heldWriteBytes < _tlsPriv(this)._writableHighWaterMark;
  }
  if (_tlsPriv(this)._bridged) {
    return _tlsBridgeWrite(this, data, encoding, callback);
  }
  if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.write === 'function') {
    return _tlsPriv(this)._socket.write(data, encoding, callback);
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  return true;
};

TLSSocket.prototype.end = function(data, encoding, callback) {
  _tlsAssertMutableOwner(this);
  if (typeof data === 'function') {
    callback = data;
    data = undefined;
    encoding = undefined;
  }
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  if (_tlsPriv(this)._writeHeld) {
    if (data !== undefined && data !== null) {
      this.write(data, encoding);
    }
    _tlsPub(this).writable = false;
    _tlsPriv(this)._heldEnd = typeof callback === 'function' ? callback : true;
    return this;
  }
  if (_tlsPriv(this)._bridged) {
    if (data !== undefined && data !== null) {
      _tlsBridgeWrite(this, data, encoding, null);
    }
    _tlsPub(this).writable = false;
    _tlsPriv(this)._bridgeHeldEnd = typeof callback === 'function' ? callback : true;
    _tlsBridgeMaybeFinishEnd(this);
    return this;
  }
  _tlsPub(this).writable = false;
  if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.end === 'function') {
    _tlsPriv(this)._socket.end(data, encoding, callback);
    return this;
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  return this;
};

TLSSocket.prototype.destroy = function(err) {
  _tlsAssertMutableOwner(this);
  // Native release is ownership-checked. Do it before mutating wrapper state
  // so a caller running as the wrong principal cannot make the real owner's
  // socket permanently unusable; the private selector remains retryable when
  // close throws.
  _tlsBridgeRelease(this);
  if (err && !_tlsPriv(this)._tlsFailureError) _tlsPriv(this)._tlsFailureError = err;
  _tlsReleaseHeldWrites(this, 'drop');
  _tlsDropBridgeWrites(this);
  _tlsPub(this).destroyed = true;
  _tlsPub(this).readable = false;
  _tlsPub(this).writable = false;
  _tlsPriv(this)._writeHeld = false;
  _tlsPriv(this)._heldWrites = null;
  _tlsPriv(this)._heldWriteBytes = 0;
  _tlsPriv(this)._heldEnd = null;
  _tlsPriv(this)._bridgePendingWrites = null;
  _tlsPriv(this)._bridgePendingWriteBytes = 0;
  _tlsPriv(this)._bridgeHeldEnd = null;
  _tlsPriv(this)._bridgeReadQueue = null;
  _tlsPriv(this)._bridgeReadQueueBytes = 0;
  _tlsPriv(this)._bridgeReadQueueOffset = 0;
  _tlsPriv(this)._bridgeDecoder = null;
  _tlsPriv(this)._bridgeDecodedTail = null;
  _tlsPriv(this)._bridgeCipherQueue = null;
  _tlsPriv(this)._bridgeCipherQueueBytes = 0;
  _tlsPriv(this)._tlsTransportUndecided = false;
  _tlsPriv(this)._tlsAwaitingConnectEvent = false;
  _tlsPriv(this)._tlsUndecidedEvents = null;
  _tlsPriv(this)._tlsUndecidedData = null;
  _tlsPriv(this)._tlsUndecidedDataBytes = 0;
  _tlsPriv(this)._tlsUndecidedInputPaused = false;
  _tlsPriv(this)._tlsUndecidedTransportEnded = false;
  _tlsPriv(this)._tlsUndecidedTransportClosed = false;
  var rawDestroyError = null;
  if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.destroy === 'function') {
    try { _tlsPriv(this)._socket.destroy(err); } catch (destroyErr) { rawDestroyError = destroyErr; }
  }
  var destroyedSocket = this;
  var terminalError = err || rawDestroyError;
  setTimeout(function() {
    _tlsAssertOwner(destroyedSocket);
    // Custom/reduced transports are allowed to omit raw terminal events. A
    // public destroy must still settle exactly once with Node's error→close
    // ordering; normal raw events win this race and the flags deduplicate it.
    var unhandled = null;
    if (terminalError && !_tlsPriv(destroyedSocket)._tlsErrorEmitted) {
      try { _emitTlsErrorOnce(destroyedSocket, terminalError); } catch (emitErr) { unhandled = emitErr; }
    }
    if (!_tlsPriv(destroyedSocket)._tlsCloseEmitted) {
      _emitTlsCloseOnce(destroyedSocket, !!terminalError);
    }
    if (unhandled) throw unhandled;
  }, 0);
  return this;
};

TLSSocket.prototype.setTimeout = function(timeout, callback) {
  _tlsAssertMutableOwner(this);
  if (typeof callback === 'function' && typeof this.once === 'function') {
    this.once('timeout', callback);
  }
  _callSocketMethod(this, 'setTimeout', [timeout], this);
  return this;
};

TLSSocket.prototype.setNoDelay = function(noDelay) {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'setNoDelay', [noDelay], this);
  return this;
};

TLSSocket.prototype.setKeepAlive = function(enable, initialDelay) {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'setKeepAlive', [enable, initialDelay], this);
  return this;
};

TLSSocket.prototype.ref = function() {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'ref', [], this);
  return this;
};

TLSSocket.prototype.unref = function() {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'unref', [], this);
  return this;
};

TLSSocket.prototype.address = function() {
  _tlsAssertOwner(this);
  if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.address === 'function') {
    return _tlsPriv(this)._socket.address();
  }
  return {
    address: _tlsPub(this).localAddress || _tlsPub(this).remoteAddress,
    port: _tlsPub(this).localPort || _tlsPub(this).remotePort,
    family: _tlsPub(this).localFamily || _tlsPub(this).remoteFamily || 'IPv4'
  };
};

TLSSocket.prototype.pause = function() {
  _tlsAssertMutableOwner(this);
  _tlsPriv(this)._tlsUserPaused = true;
  if (_tlsPriv(this)._bridged) {
    _tlsPriv(this)._bridgePaused = true;
    // Track the raw pause in bridge state so resume() can actually restart the
    // transport. Calling raw.pause() alone left _bridgeInputPaused false, and
    // the guarded resume path then treated an explicitly paused socket as
    // already flowing forever.
    _tlsBridgePauseInput(this);
    return this;
  }
  _callSocketMethod(this, 'pause', [], this);
  return this;
};

TLSSocket.prototype.resume = function() {
  _tlsAssertMutableOwner(this);
  _tlsPriv(this)._tlsUserPaused = false;
  if (_tlsPriv(this)._tlsTransportUndecided) {
    // The raw transport may be paused by the security guard, not the caller.
    // Path selection owns that pause until retained bytes become ciphertext or
    // the connection is rejected.
    if (!_tlsPriv(this)._tlsUndecidedInputPaused) {
      _callSocketMethod(this, 'resume', [], this);
    }
    return this;
  }
  if (_tlsPriv(this)._bridged) {
    _tlsPriv(this)._bridgePaused = false;
    _tlsBridgeFlushReadQueue(this);
    _tlsBridgeMaybeResumeInput(this);
    return this;
  }
  _callSocketMethod(this, 'resume', [], this);
  return this;
};

TLSSocket.prototype.on = function(eventName, listener) {
  _tlsAssertMutableOwner(this);
  var result = EventEmitter && EventEmitter.prototype && EventEmitter.prototype.on
    ? EventEmitter.prototype.on.call(this, eventName, listener)
    : this;
  var pipeBackpressure = _tlsPipeBackpressureStates &&
    _tlsPipeBackpressureStates.get(this);
  if (_tlsPriv(this)._bridged && eventName === 'data' && !_tlsPriv(this)._tlsUserPaused &&
      (!pipeBackpressure || pipeBackpressure.awaiting === 0)) {
    _tlsPriv(this)._bridgePaused = false;
    _tlsBridgeFlushReadQueue(this);
    _tlsBridgeMaybeResumeInput(this);
  }
  return result;
};

TLSSocket.prototype.addListener = TLSSocket.prototype.on;

TLSSocket.prototype.once = function(eventName, listener) {
  _tlsAssertMutableOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.once
    ? EventEmitter.prototype.once.call(this, eventName, listener)
    : this.on(eventName, listener);
};

TLSSocket.prototype.prependListener = function(eventName, listener) {
  _tlsAssertMutableOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.prependListener
    ? EventEmitter.prototype.prependListener.call(this, eventName, listener)
    : this.on(eventName, listener);
};

TLSSocket.prototype.prependOnceListener = function(eventName, listener) {
  _tlsAssertMutableOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.prependOnceListener
    ? EventEmitter.prototype.prependOnceListener.call(this, eventName, listener)
    : this.once(eventName, listener);
};

TLSSocket.prototype.removeListener = function(eventName, listener) {
  // Listener removal is monotonic cleanup and remains safe after terminal
  // owner release. EventEmitter once-wrappers perform this during close.
  _tlsAssertOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.removeListener
    ? EventEmitter.prototype.removeListener.call(this, eventName, listener)
    : this;
};

TLSSocket.prototype.off = TLSSocket.prototype.removeListener;

TLSSocket.prototype.removeAllListeners = function(eventName) {
  _tlsAssertOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.removeAllListeners
    ? EventEmitter.prototype.removeAllListeners.call(this, eventName)
    : this;
};

TLSSocket.prototype.emit = function() {
  _tlsAssertMutableOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.emit
    ? EventEmitter.prototype.emit.apply(this, arguments)
    : false;
};

TLSSocket.prototype.setMaxListeners = function() {
  _tlsAssertMutableOwner(this);
  return EventEmitter && EventEmitter.prototype && EventEmitter.prototype.setMaxListeners
    ? EventEmitter.prototype.setMaxListeners.apply(this, arguments)
    : this;
};

var _tlsEmitterReadMethods = ['getMaxListeners', 'eventNames', 'listenerCount', 'listeners', 'rawListeners'];
for (var _tlsEmitterReadIndex = 0;
     _tlsEmitterReadIndex < _tlsEmitterReadMethods.length;
     _tlsEmitterReadIndex++) {
  (function(name) {
    TLSSocket.prototype[name] = function() {
      _tlsAssertOwner(this);
      var method = EventEmitter && EventEmitter.prototype && EventEmitter.prototype[name];
      if (typeof method === 'function') return method.apply(this, arguments);
      return name === 'getMaxListeners' || name === 'listenerCount' ? 0 : [];
    };
  })(_tlsEmitterReadMethods[_tlsEmitterReadIndex]);
}

TLSSocket.prototype.pipe = function(dest, options) {
  _tlsAssertMutableOwner(this);
  // `tls.connect(...).pipe(dest)` is normally called before TCP connect, while
  // the loopback-vs-wire-TLS path is still undecided. Pipe from wrapper data in
  // that window so a later bridged connection can never expose raw ciphertext.
  if (_tlsPriv(this)._bridged || _tlsPriv(this)._writeHeld) {
    var source = this;
    var shouldEnd = !options || options.end !== false;
    var backpressureState = _tlsPipeBackpressureStates && _tlsPipeBackpressureStates.get(source);
    if (!backpressureState) {
      backpressureState = { awaiting: 0 };
      if (_tlsPipeBackpressureStates) _tlsPipeBackpressureStates.set(source, backpressureState);
    }
    var awaitingDrain = false;
    var activeWrite = null;
    var cleaned = false;
    function remove(emitter, eventName, listener) {
      if (emitter && typeof emitter.removeListener === 'function') {
        emitter.removeListener(eventName, listener);
      }
    }
    function cleanup() {
      if (cleaned) return;
      cleaned = true;
      remove(source, 'data', onData);
      remove(source, 'end', onEnd);
      remove(source, 'close', onSourceClose);
      if (_tlsErrorMonitor) remove(source, _tlsErrorMonitor, onSourceErrorMonitor);
      remove(dest, 'drain', onDrain);
      remove(dest, 'close', onDestClose);
      remove(dest, 'finish', onDestFinish);
      if (_tlsErrorMonitor) remove(dest, _tlsErrorMonitor, onDestErrorMonitor);
      releaseBackpressure();
    }
    function pauseForPipe() {
      if (_tlsPriv(source)._bridged) _tlsPriv(source)._bridgePaused = true;
      _callSocketMethod(source, 'pause', [], source);
    }
    function resumeForPipe() {
      if (_tlsPriv(source)._tlsUserPaused) return;
      if (_tlsPriv(source)._tlsTransportUndecided && _tlsPriv(source)._tlsUndecidedInputPaused) return;
      if (_tlsPriv(source)._bridged) {
        _tlsPriv(source)._bridgePaused = false;
        _tlsBridgeFlushReadQueue(source);
        _tlsBridgeMaybeResumeInput(source);
        return;
      }
      _callSocketMethod(source, 'resume', [], source);
    }
    function applyBackpressure() {
      if (awaitingDrain) return;
      awaitingDrain = true;
      backpressureState.awaiting++;
      if (backpressureState.awaiting === 1) pauseForPipe();
    }
    function releaseBackpressure() {
      if (!awaitingDrain) return;
      awaitingDrain = false;
      backpressureState.awaiting = Math.max(0, backpressureState.awaiting - 1);
      if (backpressureState.awaiting === 0) resumeForPipe();
    }
    function onData(chunk) {
      var accepted = true;
      var previousWrite = activeWrite;
      var writeFrame = { drained: false };
      activeWrite = writeFrame;
      try {
        if (dest && typeof dest.write === 'function') accepted = dest.write(chunk);
      } catch (writeErr) {
        cleanup();
        throw writeErr;
      } finally {
        activeWrite = previousWrite;
      }
      if (!cleaned && accepted === false && !writeFrame.drained) {
        applyBackpressure();
      }
    }
    function onDrain() {
      if (activeWrite) activeWrite.drained = true;
      releaseBackpressure();
    }
    function onEnd() {
      if (shouldEnd && dest && typeof dest.end === 'function') dest.end();
      cleanup();
    }
    function onSourceClose() { cleanup(); }
    function onSourceErrorMonitor() { cleanup(); }
    function onDestErrorMonitor() { cleanup(); }
    function onDestClose() { cleanup(); }
    function onDestFinish() { cleanup(); }
    source.once('end', onEnd);
    source.once('close', onSourceClose);
    if (_tlsErrorMonitor) source.on(_tlsErrorMonitor, onSourceErrorMonitor);
    if (dest && typeof dest.on === 'function') {
      dest.on('drain', onDrain);
      var addDestTerminal = typeof dest.once === 'function'
        ? function(name, listener) { dest.once(name, listener); }
        : function(name, listener) { dest.on(name, listener); };
      addDestTerminal('close', onDestClose);
      addDestTerminal('finish', onDestFinish);
      if (_tlsErrorMonitor) dest.on(_tlsErrorMonitor, onDestErrorMonitor);
      if (typeof dest.emit === 'function') dest.emit('pipe', source);
    }
    if (dest && dest.destroyed) cleanup();
    if (!cleaned) source.on('data', onData);
    if (!cleaned && backpressureState.awaiting === 0) resumeForPipe();
    return dest;
  }
  if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.pipe === 'function') {
    return _tlsPriv(this)._socket.pipe(dest, options);
  }
  return dest;
};

TLSSocket.prototype.cork = function() {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'cork', [], this);
  return this;
};

TLSSocket.prototype.uncork = function() {
  _tlsAssertMutableOwner(this);
  _callSocketMethod(this, 'uncork', [], this);
  return this;
};

if (typeof Object.defineProperty === 'function') {
  Object.defineProperty(TLSSocket.prototype, 'readableHighWaterMark', {
    configurable: true,
    enumerable: false,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      _tlsAssertOwner(this);
      return _tlsPriv(this)._readableHighWaterMark;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'writableHighWaterMark', {
    configurable: true,
    enumerable: false,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      _tlsAssertOwner(this);
      return _tlsPriv(this)._writableHighWaterMark;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'bytesRead', {
    configurable: true,
    enumerable: true,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      _tlsAssertOwner(this);
      if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.bytesRead === 'number') return _tlsPriv(this)._socket.bytesRead;
      return 0;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'bytesWritten', {
    configurable: true,
    enumerable: true,
    get: function() {
      if (this === TLSSocket.prototype) return undefined;
      _tlsAssertOwner(this);
      if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.bytesWritten === 'number') return _tlsPriv(this)._socket.bytesWritten;
      return 0;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'pending', {
    configurable: true,
    enumerable: true,
    get: function() {
      _tlsAssertOwner(this);
      return typeof _tlsPriv(this)._pending === 'boolean' ? _tlsPriv(this)._pending : !_tlsPriv(this)._secureEstablished;
    },
    set: function(value) {
      _tlsAssertMutableOwner(this);
      _tlsPriv(this)._pending = !!value;
    }
  });

  Object.defineProperty(TLSSocket.prototype, 'readyState', {
    configurable: true,
    enumerable: true,
    get: function() {
      _tlsAssertOwner(this);
      if (_tlsPriv(this)._socket && typeof _tlsPriv(this)._socket.readyState === 'string') {
        return _tlsPriv(this)._socket.readyState;
      }
      if (_tlsPub(this).destroyed) return 'closed';
      return _tlsPub(this).connecting ? 'opening' : 'open';
    }
  });
}

// Node's TLSSocket extends net.Socket (a stream.Duplex), so
// `new tls.TLSSocket(sock) instanceof net.Socket` must hold and the Socket API
// surface must resolve through the chain (ENG-23448). Two guards keep the
// inherited surface honest about state this wrapper does not have:
//   * The plain EventEmitter methods are copied onto TLSSocket.prototype as own
//     properties BEFORE the chain is wired, so they shadow net.Socket.prototype's
//     on/addListener/prependListener hooks (and, when this file runs under bun
//     for unit tests, stream.Readable.prototype.on) — those implementations
//     dereference net.Socket internals (_readBuffer / _readableState) that a
//     TLSSocket wrapper never initializes and would throw on first use.
//   * State-dependent Socket methods outside the delegation surface
//     (read/push/unshift/close/connect above) are shadowed explicitly to
//     delegate to the wrapped raw socket.
_mixinEventEmitter(TLSSocket.prototype);
if (net && net.Socket && net.Socket.prototype && typeof Object.setPrototypeOf === 'function') {
  Object.setPrototypeOf(TLSSocket.prototype, net.Socket.prototype);
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

// ============================================================
// Native TLS bridge (ENG-23492)
//
// Real TLS for out-of-process endpoints. A sans-IO rustls client engine
// (src/engine/tls_bridge.rs via src/engine/hermes_runtime_tls.cc) holds the
// TLS state machine; this file owns ALL I/O, shoveling ciphertext between the
// existing net.Socket and the engine and plaintext between the engine and the
// TLSSocket wrapper. Chain trust is evaluated natively (the JS
// _validatePeerAuthorization is a fingerprint comparator, not a signature
// verifier) with the verdict recorded instead of aborting, so
// rejectUnauthorized:false still completes the handshake and reports
// authorized:false with the real code. Hostname/identity checking stays here
// in JS (checkServerIdentity is user-overridable in Node).
// @ref LLP 0004#the-tls-builtin — native bridge design + trust-evaluation split
// ============================================================

function _tlsBridgeAvailable() {
  return _nativeTlsEngineIds !== null &&
    _nativeTlsOwnerTokens !== null &&
    typeof __exactTlsOwnerToken === 'function' &&
    typeof __exactTlsEngineNew === 'function' &&
    typeof __exactTlsEngineWriteTls === 'function' &&
    typeof __exactTlsEngineReadTls === 'function' &&
    typeof __exactTlsEngineReadPlain === 'function' &&
    typeof __exactTlsEngineWritePlain === 'function' &&
    typeof __exactTlsEngineStatus === 'function' &&
    typeof __exactTlsEngineTransportEof === 'function' &&
    typeof __exactTlsEngineShutdown === 'function' &&
    typeof __exactTlsEnginePeerCerts === 'function' &&
    typeof __exactTlsEngineClose === 'function';
}

function _tlsGetEngineId(socket) {
  return _nativeTlsEngineIds ? _nativeTlsEngineIds.get(socket) : undefined;
}

function _tlsSetEngineId(socket, id) {
  if (_nativeTlsEngineIds) _nativeTlsEngineIds.set(socket, id);
}

function _tlsDeleteEngineId(socket) {
  if (_nativeTlsEngineIds) _nativeTlsEngineIds.delete(socket);
}

function _tlsAssertOwner(socket) {
  var token = _nativeTlsOwnerTokens
    ? _nativeTlsOwnerTokens.get(socket)
    : undefined;
  if (token != null) {
    __exactTlsOwnerToken('assert', token);
    return;
  }
  var id = _tlsGetEngineId(socket);
  if (id == null) return;
  // Status is an ownership-checked, non-mutating native lookup. Calling it
  // before touching JS queues prevents a foreign principal from injecting
  // bytes that a later owner-attributed callback would otherwise transmit.
  __exactTlsEngineStatus(id);
}

function _tlsAssertMutableOwner(socket) {
  // The native owner token is intentionally released at terminal close. Keep
  // the public terminal snapshot readable, but never let the absence of that
  // token turn setters or methods into ambient mutation authority.
  _tlsAssertOwner(socket);
  var token = _nativeTlsOwnerTokens
    ? _nativeTlsOwnerTokens.get(socket)
    : undefined;
  var privateState = _tlsSocketPrivateStates && _tlsSocketPrivateStates.get(socket);
  if (token == null && privateState && privateState.values._tlsCloseEmitted) {
    throw _createError(
      'ERR_TLS_SOCKET_CLOSED',
      'A closed TLSSocket cannot be mutated or reused'
    );
  }
}

function _tlsCaptureOwner(socket) {
  if (!_nativeTlsOwnerTokens || typeof __exactTlsOwnerToken !== 'function') return;
  if (_nativeTlsOwnerTokens.has(socket)) {
    _tlsAssertOwner(socket);
    return;
  }
  _nativeTlsOwnerTokens.set(socket, __exactTlsOwnerToken('new'));
}

function _tlsReleaseOwner(socket) {
  var token = _nativeTlsOwnerTokens
    ? _nativeTlsOwnerTokens.get(socket)
    : undefined;
  if (token == null) return;
  __exactTlsOwnerToken('close', token);
  _nativeTlsOwnerTokens.delete(socket);
}

function _tlsNativeEngineConfig(options, host, cipherSuites) {
  var servername = options.servername || options.sni || null;
  var pfxIdentity = _normalizePfxIdentity(options.pfx, options.passphrase);
  var caSource = options.ca !== undefined && options.ca !== null
    ? options.ca
    : (_defaultCACertificates.length ? _defaultCACertificates : null);
  return {
    // Measured Node v25.9.0: SNI is only sent when servername was explicitly
    // provided (bare tls.connect({host}) sends none). ibex https.js always
    // sets servername, so https clients get SNI.
    servername: servername ? String(servername) : null,
    host: host ? String(host) : null,
    alpn: _alpnProtocolsToList(options.ALPNProtocols),
    ca: caSource !== null ? _pemSourceToString(caSource) : null,
    cert: options.cert !== undefined && options.cert !== null ? _pemSourceToString(options.cert) : null,
    key: options.key !== undefined && options.key !== null ? _pemSourceToString(options.key) : null,
    passphrase: pfxIdentity
      ? pfxIdentity.passphrase
      : (options.passphrase !== undefined && options.passphrase !== null
        ? String(options.passphrase)
        : null),
    pfx: pfxIdentity ? pfxIdentity.encoded : null,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    hasSession: options.session !== undefined && options.session !== null,
    cipherSuites: cipherSuites || _resolveCipherSuites(options, 'client'),
    minVersion: options.minVersion || null,
    maxVersion: options.maxVersion || null
  };
}

// Decode an ALPNProtocols option (string array, or the length-prefixed wire
// buffer produced by convertALPNProtocols) into a plain string list.
function _alpnProtocolsToList(protocols) {
  if (!protocols) return [];
  if (Array.isArray(protocols)) {
    var listed = [];
    for (var i = 0; i < protocols.length; i++) listed.push(String(protocols[i]));
    return listed;
  }
  var view = _cloneBufferLike(protocols);
  var out = [];
  var offset = 0;
  var total = typeof view.length === 'number' ? view.length : 0;
  while (offset < total) {
    var size = view[offset++];
    var end = Math.min(offset + size, total);
    var proto = '';
    for (; offset < end; offset++) proto += String.fromCharCode(view[offset]);
    out.push(proto);
  }
  return out;
}

function _wrapBase64Lines(b64) {
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return lines.join('\n');
}

// Build a Node-shaped peer certificate chain from the DER chain presented on
// the wire (leaf first, base64 DER entries), reusing the emulation's DER/PEM
// parser. issuerCertificate links follow the presented order; a self-signed
// tail links to itself like Node's chain does.
function _buildBridgedPeerChain(derChain) {
  var parsed = [];
  for (var i = 0; i < derChain.length; i++) {
    var pem = '-----BEGIN CERTIFICATE-----\n' +
      _wrapBase64Lines(derChain[i]) +
      '\n-----END CERTIFICATE-----\n';
    var cert = _parsePemCertificate(pem);
    if (cert) parsed.push(cert);
  }
  if (!parsed.length) return null;
  for (var k = 0; k < parsed.length; k++) {
    parsed[k].ca = k > 0 || _nameKey(parsed[k].subject) === _nameKey(parsed[k].issuer);
    if (k + 1 < parsed.length) parsed[k].issuerCertificate = parsed[k + 1];
  }
  var last = parsed[parsed.length - 1];
  if (_nameKey(last.subject) === _nameKey(last.issuer)) {
    last.issuerCertificate = last;
  }
  return parsed[0];
}

// Map the native verifier's coarse verdict onto Node's OpenSSL-style codes.
// UNKNOWN_ISSUER is refined by presented-chain shape; every mapping below is
// oracle-pinned against Node v25.9.0 (local openssl-generated CA fixtures).
function _refineBridgeVerifyError(verify, peerCert) {
  var code = verify && verify.code;
  if (!code) {
    return _createAuthorizationError('UNABLE_TO_VERIFY_CERT', 'certificate verification failed');
  }
  if (code === 'UNKNOWN_ISSUER') {
    var chain = _collectCertificateChain(peerCert);
    var tail = chain.length ? chain[chain.length - 1] : null;
    if (chain.length === 1 && _isSelfSignedCertificate(chain[0])) {
      return _createAuthorizationError('DEPTH_ZERO_SELF_SIGNED_CERT', 'self-signed certificate');
    }
    if (tail && _isSelfSignedCertificate(tail)) {
      return _createAuthorizationError(
        'SELF_SIGNED_CERT_IN_CHAIN',
        'self-signed certificate in certificate chain'
      );
    }
    if (chain.length > 1) {
      return _createAuthorizationError(
        'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
        'unable to get local issuer certificate'
      );
    }
    return _createAuthorizationError(
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'unable to verify the first certificate'
    );
  }
  if (code === 'CERT_HAS_EXPIRED') {
    return _createAuthorizationError('CERT_HAS_EXPIRED', 'certificate has expired');
  }
  if (code === 'CERT_NOT_YET_VALID') {
    return _createAuthorizationError('CERT_NOT_YET_VALID', 'certificate is not yet valid');
  }
  if (code === 'CERT_REVOKED') {
    return _createAuthorizationError('CERT_REVOKED', 'certificate revoked');
  }
  if (code === 'CERT_SIGNATURE_FAILURE') {
    return _createAuthorizationError('CERT_SIGNATURE_FAILURE', 'certificate signature failure');
  }
  if (code === 'INVALID_PURPOSE') {
    return _createAuthorizationError('INVALID_PURPOSE', 'unsupported certificate purpose');
  }
  return _createAuthorizationError(code, verify.reason || 'certificate verification failed');
}

function _tlsBridgeStatus(socket) {
  var id = _tlsGetEngineId(socket);
  if (id == null) return null;
  var status = JSON.parse(__exactTlsEngineStatus(id));
  if (!status || typeof status !== 'object' || Array.isArray(status)) {
    throw _createError('ERR_TLS_ENGINE_STATUS', 'Native TLS engine returned an invalid status');
  }
  return status;
}

function _tlsBridgeRelease(socket) {
  var id = _tlsGetEngineId(socket);
  if (id == null) return;
  __exactTlsEngineClose(id);
  // Forget the authority-bearing selector only after native release confirms
  // success. A wrong-principal close remains retryable by the actual owner.
  _tlsDeleteEngineId(socket);
}

function _tlsBridgeFail(socket, err) {
  var replayHeldClose = _tlsPriv(socket)._tlsDeferredTransportClose === true;
  // Native release is the owner-authenticated commit point. If a retained
  // wrapper reaches this path under the wrong principal, leave every JS
  // lifecycle flag and queue intact so the actual owner can retry.
  _tlsBridgeRelease(socket);
  _tlsPriv(socket)._bridgeFailed = true;
  _tlsPriv(socket)._tlsFailureError = err;
  if (_tlsPub(socket).destroyed) return;
  _destroyTlsSocketWithError(socket, err, replayHeldClose);
  _tlsPriv(socket)._tlsDeferredTransportClose = false;
}

function _tlsBridgeErrorFromStatus(socket, fallbackMessage) {
  var status;
  try {
    status = _tlsBridgeStatus(socket);
  } catch (statusErr) {
    return statusErr;
  }
  if (status && status.verify && status.verify.checked &&
      !status.verify.chainOk && status.verify.code) {
    var peer = _tlsPriv(socket)._peerCertificate;
    if (!peer) {
      try {
        peer = _buildBridgedPeerChain(
          JSON.parse(__exactTlsEnginePeerCerts(_tlsGetEngineId(socket))) || []
        );
      } catch (peerErr) {
        return peerErr;
      }
    }
    return _refineBridgeVerifyError(status.verify, peer);
  }
  var message = (status && status.error) || fallbackMessage || 'TLS handshake failed';
  var code = (status && status.errorCode) || 'ERR_TLS_HANDSHAKE_FAILURE';
  return _createError(code, message);
}

// Drain ciphertext the engine wants to send into the raw socket.
function _tlsBridgePumpOut(socket) {
  if (_tlsPriv(socket)._bridgePumpActive) {
    _tlsPriv(socket)._bridgePumpAgain = true;
    return !_tlsPriv(socket)._bridgeTransportBackpressured;
  }
  if (_tlsGetEngineId(socket) == null || _tlsPriv(socket)._bridgeTransportBackpressured) return false;
  _tlsPriv(socket)._bridgePumpActive = true;
  try {
  for (;;) {
    var raw = _tlsPriv(socket)._socket;
    if (!raw || typeof raw.write !== 'function' || raw.destroyed) {
      // Do not call readTls until a live transport exists: readTls consumes
      // the engine's pending ciphertext. Consuming and discarding it here can
      // lose ClientHello/application/close_notify bytes and report success.
      if (!_tlsPub(socket).destroyed && !_tlsPriv(socket)._tlsDeferredTransportClose) {
        _tlsBridgeFail(socket, _createError('ERR_TLS_SOCKET_CLOSED', 'TLS transport is not writable'));
      }
      return false;
    }
    var chunk;
    try {
      var engineId = _tlsGetEngineId(socket);
      if (engineId == null) return false;
      chunk = __exactTlsEngineReadTls(engineId, 65536);
    } catch (e) {
      // Native probe/lease/read failures are terminal. Swallowing one after
      // the engine may have reserved or consumed output leaves the connection
      // hung and can silently discard TLS alerts or application ciphertext.
      _tlsBridgeFail(socket, e);
      return false;
    }
    if (!chunk || typeof chunk === 'string' || !chunk.byteLength) return true;
    var accepted;
    _tlsPriv(socket)._bridgeWriteInFlight = true;
    _tlsPriv(socket)._bridgeDrainDuringWrite = false;
    try {
      accepted = raw.write(_bufferFromBytes(chunk));
    } catch (writeErr) {
      _tlsBridgeFail(socket, writeErr);
      return false;
    } finally {
      _tlsPriv(socket)._bridgeWriteInFlight = false;
    }
    if (_tlsPub(socket).destroyed || _tlsGetEngineId(socket) == null) return false;
    if (raw.destroyed) {
      if (!_tlsPriv(socket)._tlsDeferredTransportClose) {
        _tlsBridgeFail(socket, _createError(
          'ERR_TLS_SOCKET_CLOSED',
          'TLS transport closed while writing ciphertext'
        ));
      }
      return false;
    }
    if (accepted === false) {
      if (!_tlsPriv(socket)._bridgeDrainDuringWrite) {
        _tlsPriv(socket)._bridgeTransportBackpressured = true;
        _tlsPriv(socket)._bridgeNeedDrain = true;
        return false;
      }
      _tlsPriv(socket)._bridgeDrainDuringWrite = false;
    }
  }
  } finally {
    _tlsPriv(socket)._bridgePumpActive = false;
  }
}

function _tlsBridgeEncode(socket, data) {
  if (!_tlsPriv(socket)._bridgeEncoding || !data || typeof data.toString !== 'function') return data;
  if (_tlsPriv(socket)._bridgeDecoder && typeof _tlsPriv(socket)._bridgeDecoder.write === 'function') {
    return _tlsPriv(socket)._bridgeDecoder.write(data);
  }
  return data.toString(_tlsPriv(socket)._bridgeEncoding);
}

function _tlsBridgeEmitData(socket, data) {
  var encoded = _tlsBridgeEncode(socket, data);
  if (typeof encoded === 'string' && encoded.length === 0) return true;
  var rawWasDestroyed = _tlsRawTransportDestroyed(socket);
  var closeWasDeferred = _tlsPriv(socket)._tlsDeferredTransportClose === true;
  _tlsEmitInternal(socket, 'data', [encoded]);
  if (_tlsTerminateIfTransportChanged(socket, rawWasDestroyed, closeWasDeferred)) return false;
  if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
    _terminateTlsForDestroyedTransport(socket);
  }
  return !_tlsPub(socket).destroyed && _tlsGetEngineId(socket) != null;
}

function _tlsBridgeIsFlowing(socket) {
  return !_tlsPriv(socket)._bridgePaused && _tlsListenerCountInternal(socket, 'data') > 0;
}

function _tlsBridgePauseInput(socket) {
  if (_tlsPriv(socket)._bridgeInputPaused) return;
  _tlsPriv(socket)._bridgeInputPaused = true;
  var raw = _tlsPriv(socket)._socket;
  if (raw && typeof raw.pause === 'function') raw.pause();
}

// Drain decrypted plaintext out of the engine into 'data' events (or 'end').
function _tlsBridgeDrainPlain(socket) {
  // Decrypted application bytes are not public until native chain processing
  // and the user-overridable identity check have both completed. In
  // particular, checkServerIdentity may re-enter read()/resume().
  if (!_tlsPriv(socket)._tlsApplicationReady || _tlsGetEngineId(socket) == null) return false;
  if (_tlsPriv(socket)._bridgeDrainingPlain) return false;
  _tlsPriv(socket)._bridgeDrainingPlain = true;
  var madeProgress = false;
  try {
  for (;;) {
    var flowing = _tlsBridgeIsFlowing(socket);
    var capacity = flowing
      ? 65536
      : Math.max(0, _tlsPriv(socket)._readableHighWaterMark - (_tlsPriv(socket)._bridgeReadQueueBytes || 0));
    if (capacity <= 0) {
      _tlsBridgePauseInput(socket);
      return madeProgress;
    }
    var chunk;
    try {
      var engineId = _tlsGetEngineId(socket);
      if (engineId == null) return madeProgress;
      chunk = __exactTlsEngineReadPlain(engineId, Math.min(65536, capacity));
    } catch (e) {
      // A read-status exception is intentionally terse at the JSI boundary.
      // Resolve the engine's recorded rustls error before release so callers
      // get the real code/reason (for example an unauthenticated EOF) instead
      // of the generic host-function message.
      _tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket, e && e.message));
      return madeProgress;
    }
    if (chunk === null) {
      _tlsPriv(socket)._bridgeNativeEnded = true;
      _tlsBridgeMaybeEmitEnd(socket);
      return madeProgress;
    }
    if (!chunk || typeof chunk === 'string' || !chunk.byteLength) return madeProgress;
    madeProgress = true;
    if (_tlsGetEngineId(socket) == null || _tlsPub(socket).destroyed) return madeProgress;
    var data = _bufferFromBytes(chunk);
    if (flowing) {
      if (!_tlsBridgeEmitData(socket, data)) return madeProgress;
    } else {
      if (!_tlsPriv(socket)._bridgeReadQueue) _tlsPriv(socket)._bridgeReadQueue = [];
      _tlsPriv(socket)._bridgeReadQueue.push(data);
      _tlsPriv(socket)._bridgeReadQueueBytes = (_tlsPriv(socket)._bridgeReadQueueBytes || 0) + _byteLength(data);
      var rawWasDestroyed = _tlsRawTransportDestroyed(socket);
      var closeWasDeferred = _tlsPriv(socket)._tlsDeferredTransportClose === true;
      _tlsEmitInternal(socket, 'readable');
      if (_tlsTerminateIfTransportChanged(socket, rawWasDestroyed, closeWasDeferred)) {
        return madeProgress;
      }
      if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
        _terminateTlsForDestroyedTransport(socket);
        return madeProgress;
      }
    }
  }
  } finally {
    _tlsPriv(socket)._bridgeDrainingPlain = false;
  }
}

function _tlsBridgeFlushReadQueue(socket) {
  if (_tlsPriv(socket)._bridgePaused || !_tlsPriv(socket)._bridgeReadQueue || !_tlsPriv(socket)._bridgeReadQueue.length ||
      _tlsListenerCountInternal(socket, 'data') === 0) return;
  var pending = _tlsPriv(socket)._bridgeReadQueue;
  var firstOffset = _tlsPriv(socket)._bridgeReadQueueOffset || 0;
  _tlsPriv(socket)._bridgeReadQueue = [];
  _tlsPriv(socket)._bridgeReadQueueBytes = 0;
  _tlsPriv(socket)._bridgeReadQueueOffset = 0;
  var i = 0;
  for (; i < pending.length && !_tlsPriv(socket)._bridgePaused && !_tlsPub(socket).destroyed &&
         _tlsGetEngineId(socket) != null; i++) {
    var chunk = i === 0 && firstOffset ? pending[i].slice(firstOffset) : pending[i];
    if (!_tlsBridgeEmitData(socket, chunk)) return;
  }
  if (i < pending.length && !_tlsPub(socket).destroyed && _tlsGetEngineId(socket) != null) {
    _tlsPriv(socket)._bridgeReadQueue = pending.slice(i);
    for (; i < pending.length; i++) _tlsPriv(socket)._bridgeReadQueueBytes += _byteLength(pending[i]);
  }
  if (!_tlsPub(socket).destroyed && _tlsGetEngineId(socket) != null) _tlsBridgeMaybeEmitEnd(socket);
}

function _tlsBridgeFlushPendingWrites(socket) {
  if (_tlsRawTransportUnexpectedlyDestroyed(socket)) {
    _terminateTlsForDestroyedTransport(socket);
    return;
  }
  if (_tlsRawTransportDestroyed(socket)) {
    _tlsDropBridgeWrites(socket);
    return;
  }
  _tlsBridgeDrainApplicationWrites(socket);
  _tlsBridgeMaybeFinishEnd(socket);
}

function _tlsBridgeUpdateBufferedBytes(socket) {
  _tlsPriv(socket)._bufferedBytes = (_tlsPriv(socket)._heldWriteBytes || 0) +
    (_tlsPriv(socket)._bridgePendingWriteBytes || 0);
}

function _tlsBridgeMaybeEmitDrain(socket) {
  if (!_tlsPriv(socket)._bridgeNeedDrain || _tlsPriv(socket)._bridgeTransportBackpressured ||
      (_tlsPriv(socket)._bridgePendingWriteBytes || 0) >= _tlsPriv(socket)._writableHighWaterMark ||
      !_tlsPriv(socket)._tlsApplicationReady || _tlsPub(socket).destroyed) return;
  _tlsPriv(socket)._bridgeNeedDrain = false;
  if (_tlsPriv(socket)._bridgeDrainScheduled) return;
  _tlsPriv(socket)._bridgeDrainScheduled = true;
  setTimeout(function() {
    _tlsAssertOwner(socket);
    _tlsPriv(socket)._bridgeDrainScheduled = false;
    if (!_tlsPub(socket).destroyed) _tlsEmitInternal(socket, 'drain');
  }, 0);
}

function _tlsBridgeDrainApplicationWrites(socket) {
  if (!_tlsPriv(socket)._tlsApplicationReady || _tlsGetEngineId(socket) == null ||
      _tlsPriv(socket)._bridgeTransportBackpressured || _tlsPub(socket).destroyed) return;
  var pending = _tlsPriv(socket)._bridgePendingWrites || [];
  var zeroProgressRetries = 0;
  while (pending.length && !_tlsPriv(socket)._bridgeTransportBackpressured && !_tlsPub(socket).destroyed) {
    var item = pending[0];
    var total = _byteLength(item.buffer);
    if (item.offset >= total) {
      pending.shift();
      if (typeof item.callback === 'function') setTimeout(item.callback, 0);
      continue;
    }
    var chunk = item.offset === 0 ? item.buffer : item.buffer.slice(item.offset);
    var accepted;
    try {
      var engineId = _tlsGetEngineId(socket);
      accepted = engineId == null ? -1 : __exactTlsEngineWritePlain(engineId, chunk);
    } catch (e) {
      _tlsBridgeFail(socket, e);
      return;
    }
    if (accepted < 0) {
      _tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket, 'TLS write failed'));
      return;
    }
    if (accepted === 0) {
      // rustls can temporarily fill its plaintext buffer. Draining the TLS
      // records it already produced is what creates room for this same write;
      // waiting without pumping can deadlock forever because no raw `drain`
      // event is required when the transport accepted all ciphertext.
      _tlsBridgePumpOut(socket);
      if (_tlsPriv(socket)._bridgeTransportBackpressured || _tlsPub(socket).destroyed) return;
      if (++zeroProgressRetries <= 1) continue;
      if (!_tlsPriv(socket)._bridgeWriteRetryScheduled) {
        _tlsPriv(socket)._bridgeWriteRetryScheduled = true;
        setTimeout(function() {
          _tlsAssertOwner(socket);
          _tlsPriv(socket)._bridgeWriteRetryScheduled = false;
          _tlsBridgeDrainApplicationWrites(socket);
        }, 0);
      }
      return;
    }
    zeroProgressRetries = 0;
    item.offset += accepted;
    _tlsPriv(socket)._bridgePendingWriteBytes = Math.max(
      0,
      (_tlsPriv(socket)._bridgePendingWriteBytes || 0) - accepted
    );
    _tlsBridgeUpdateBufferedBytes(socket);
    _tlsBridgePumpOut(socket);
  }
  _tlsPriv(socket)._bridgePendingWrites = pending;
  _tlsBridgeMaybeEmitDrain(socket);
  _tlsBridgeMaybeFinishEnd(socket);
}

function _tlsBridgeMaybeFinishEnd(socket) {
  if (!_tlsPriv(socket)._bridgeHeldEnd || !_tlsPriv(socket)._tlsApplicationReady || _tlsPub(socket).destroyed ||
      (_tlsPriv(socket)._bridgePendingWrites && _tlsPriv(socket)._bridgePendingWrites.length)) return;
  if (!_tlsPriv(socket)._bridgeShutdownQueued) {
    _tlsPriv(socket)._bridgeShutdownQueued = true;
    var engineId = _tlsGetEngineId(socket);
    if (engineId != null && typeof __exactTlsEngineShutdown === 'function') {
      try {
        __exactTlsEngineShutdown(engineId);
      } catch (shutdownErr) {
        _tlsPriv(socket)._bridgeShutdownQueued = false;
        throw shutdownErr;
      }
    }
  }
  _tlsBridgePumpOut(socket);
  var status;
  try {
    status = _tlsBridgeStatus(socket);
  } catch (statusErr) {
    _tlsBridgeFail(socket, statusErr);
    return;
  }
  if (status && status.error) {
    _tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket, 'TLS shutdown failed'));
    return;
  }
  if (_tlsPriv(socket)._bridgeTransportBackpressured || (status && status.wantsWrite)) return;
  var callback = _tlsPriv(socket)._bridgeHeldEnd;
  _tlsPriv(socket)._bridgeHeldEnd = null;
  var raw = _tlsPriv(socket)._socket;
  if (raw && typeof raw.end === 'function') {
    raw.end(typeof callback === 'function' ? callback : undefined);
  } else if (typeof callback === 'function') {
    setTimeout(callback, 0);
  }
}

function _tlsBridgeOnRawDrain(socket) {
  if (_tlsPriv(socket)._bridgeWriteInFlight) {
    _tlsPriv(socket)._bridgeDrainDuringWrite = true;
    _tlsPriv(socket)._bridgeTransportBackpressured = false;
    _tlsPriv(socket)._bridgePumpAgain = true;
    return;
  }
  _tlsPriv(socket)._bridgeTransportBackpressured = false;
  _tlsBridgePumpOut(socket);
  if (!_tlsPriv(socket)._bridgeTransportBackpressured) _tlsBridgeProcessCipherQueue(socket);
  if (!_tlsPriv(socket)._bridgeTransportBackpressured) _tlsBridgeDrainApplicationWrites(socket);
  _tlsBridgeMaybeFinishEnd(socket);
  _tlsBridgeMaybeEmitDrain(socket);
}

// Release writes held since connect(): 'raw' flushes into the raw socket
// (loopback emulation path), 'bridge' transfers them into the bridged
// pre-secureConnect queue, 'drop' discards them (the connection failed).
function _tlsReleaseHeldWrites(socket, mode) {
  if (!_tlsPriv(socket)._writeHeld) return true;
  _tlsPriv(socket)._writeHeld = false;
  var held = _tlsPriv(socket)._heldWrites || [];
  _tlsPriv(socket)._heldWrites = null;
  _tlsPriv(socket)._heldWriteBytes = 0;
  var heldEnd = _tlsPriv(socket)._heldEnd;
  _tlsPriv(socket)._heldEnd = null;
  if (mode === 'drop') {
    _tlsSettleWriteCallbacks(held, heldEnd, _tlsPendingWriteError(socket));
    _tlsBridgeUpdateBufferedBytes(socket);
    return true;
  }
  if (mode === 'bridge') {
    if (!_tlsPriv(socket)._bridgePendingWrites) _tlsPriv(socket)._bridgePendingWrites = [];
    for (var i = 0; i < held.length; i++) {
      _tlsPriv(socket)._bridgePendingWrites.push(held[i]);
      _tlsPriv(socket)._bridgePendingWriteBytes = (_tlsPriv(socket)._bridgePendingWriteBytes || 0) +
        Math.max(0, _byteLength(held[i].buffer) - (held[i].offset || 0));
    }
    _tlsBridgeUpdateBufferedBytes(socket);
    if (heldEnd) _tlsPriv(socket)._bridgeHeldEnd = heldEnd;
    return true;
  }
  var raw = _tlsPriv(socket)._socket;
  if (!raw || raw.destroyed) {
    _tlsSettleWriteCallbacks(held, heldEnd, _tlsPendingWriteError(socket));
    _tlsBridgeUpdateBufferedBytes(socket);
    return false;
  }
  var flushError = null;
  try {
    if (_tlsPriv(socket)._bridgeEncoding && typeof raw.setEncoding === 'function') {
      raw.setEncoding(_tlsPriv(socket)._bridgeEncoding);
    }
  } catch (encodingErr) {
    flushError = encodingErr;
  }
  for (var j = 0; !flushError && j < held.length; j++) {
    if (raw.destroyed) {
      flushError = _tlsPendingWriteError(socket);
      break;
    }
    var item = held[j];
    var originalCallback = item.callback;
    if (typeof originalCallback === 'function') {
      item.callback = (function(entry, callback) {
        var settled = false;
        return function(err) {
          if (settled) return;
          settled = true;
          entry.callback = null;
          callback(err);
        };
      })(item, originalCallback);
    }
    try {
      if (typeof raw.write === 'function') {
        raw.write(item.buffer, item.callback);
      } else if (typeof item.callback === 'function') {
        setTimeout(item.callback, 0);
      }
    } catch (writeErr) {
      flushError = writeErr;
    }
    if (!flushError && raw.destroyed) flushError = _tlsPendingWriteError(socket);
    if (flushError) {
      if (typeof item.callback === 'function') item.callback(flushError);
      _tlsSettleWriteCallbacks(held.slice(j + 1), heldEnd, flushError);
    }
  }
  if (!flushError && heldEnd && typeof raw.end === 'function') {
    try {
      if (!raw.destroyed) raw.end(typeof heldEnd === 'function' ? heldEnd : undefined);
      if (raw.destroyed && typeof heldEnd === 'function') heldEnd(_tlsPendingWriteError(socket));
    } catch (endErr) {
      flushError = endErr;
      if (typeof heldEnd === 'function') heldEnd(endErr);
    }
  }
  _tlsBridgeUpdateBufferedBytes(socket);
  if (!flushError) return true;
  if (!_tlsPub(socket).destroyed) _destroyTlsSocketWithError(socket, flushError, false);
  return false;
}

function _tlsBridgeWrite(socket, data, encoding, callback) {
  if (_tlsPub(socket).destroyed || _tlsGetEngineId(socket) == null) {
    if (typeof callback === 'function') {
      var destroyedErr = _tlsPendingWriteError(socket);
      setTimeout(function() { callback(destroyedErr); }, 0);
    }
    return false;
  }
  var buf = _tlsWriteBuffer(data, encoding);
  var length = _byteLength(buf);
  if (!_tlsPriv(socket)._bridgePendingWrites) _tlsPriv(socket)._bridgePendingWrites = [];
  _tlsPriv(socket)._bridgePendingWrites.push({ buffer: buf, offset: 0, callback: callback });
  _tlsPriv(socket)._bridgePendingWriteBytes = (_tlsPriv(socket)._bridgePendingWriteBytes || 0) + length;
  _tlsBridgeUpdateBufferedBytes(socket);
  if (_tlsPriv(socket)._tlsApplicationReady) _tlsBridgeDrainApplicationWrites(socket);
  // Draining can itself discover raw-socket backpressure while forwarding the
  // generated ciphertext, so the return value must be computed afterwards.
  var backpressured = _tlsPriv(socket)._bridgeTransportBackpressured ||
    _tlsPriv(socket)._bridgePendingWriteBytes >= _tlsPriv(socket)._writableHighWaterMark;
  if (backpressured) _tlsPriv(socket)._bridgeNeedDrain = true;
  return !backpressured;
}

function _finalizeBridgedHandshake(socket) {
  if (_tlsPriv(socket)._secureEstablished || _tlsPriv(socket)._tlsHandshakeFinalizing || _tlsPub(socket).destroyed) return;
  var opts = _tlsPriv(socket)._tlsOptions || {};
  var status;
  try {
    status = _tlsBridgeStatus(socket);
  } catch (statusErr) {
    _tlsBridgeFail(socket, statusErr);
    return;
  }
  if (status.error) {
    _tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket));
    return;
  }
  if (status.handshaking) return;

  _tlsPriv(socket)._tlsHandshakeFinalizing = true;
  try {
  _tlsPub(socket).encrypted = true;
  if (status.protocol) _tlsPriv(socket)._protocol = status.protocol;
  _tlsPriv(socket)._cipher = {
    name: status.cipher || null,
    standardName: status.cipherStandard || status.cipher || null,
    version: status.protocol || _tlsPriv(socket)._protocol
  };
  // Node v25.9.0 oracle: alpnProtocol is false when no protocol was
  // negotiated, and servername is false when no SNI was sent.
  _tlsPub(socket).alpnProtocol = status.alpn || false;
  if (!(opts.servername || opts.sni)) _tlsPub(socket).servername = false;
  _tlsPriv(socket)._session = null;
  _tlsPriv(socket)._sessionReused = false;

  var derChain = [];
  try {
    derChain = JSON.parse(__exactTlsEnginePeerCerts(_tlsGetEngineId(socket))) || [];
  } catch (peerCertErr) {
    _tlsBridgeFail(socket, peerCertErr);
    return;
  }
  _tlsPriv(socket)._peerCertificate = _buildBridgedPeerChain(derChain);
  _tlsPriv(socket)._localCertificate = opts.cert ? _buildLocalCertificate(
    _tlsPriv(socket)._servername || _tlsPub(socket).remoteAddress || 'localhost', _tlsPub(socket).remotePort, opts) : null;

  // Node semantics: the (native) chain verification verdict comes first; only
  // a trusted chain proceeds to the hostname/identity check, which runs here
  // in JS so options.checkServerIdentity overrides behave exactly like Node.
  var verifyError = null;
  if (!status.verify || !status.verify.checked || !_tlsPriv(socket)._peerCertificate) {
    verifyError = _createAuthorizationError(
      'UNABLE_TO_VERIFY_CERT',
      'certificate verification failed'
    );
  } else if (!status.verify.chainOk) {
    verifyError = _refineBridgeVerifyError(status.verify, _tlsPriv(socket)._peerCertificate);
  }
  var rawDestroyedBeforeIdentity = _tlsRawTransportDestroyed(socket);
  var closeDeferredBeforeIdentity = _tlsPriv(socket)._tlsDeferredTransportClose === true;
  if (!verifyError) {
    var check = opts.checkServerIdentity || checkServerIdentity;
    var identityHost = _tlsPriv(socket)._servername || _tlsPub(socket).remoteAddress || 'localhost';
    try {
      verifyError = _normalizeCheckError(check(identityHost, _tlsPriv(socket)._peerCertificate, opts));
    } catch (checkErr) {
      verifyError = _normalizeCheckError(checkErr);
    }
  }
  if (_tlsTerminateIfTransportChanged(
    socket,
    rawDestroyedBeforeIdentity,
    closeDeferredBeforeIdentity
  )) return;
  if (verifyError) {
    _tlsPub(socket).authorized = false;
    _tlsPub(socket).authorizationError = verifyError.code || verifyError.message || String(verifyError);
    _tlsPriv(socket)._authorizationErrorObject = verifyError;
  } else {
    _tlsPub(socket).authorized = true;
    _tlsPub(socket).authorizationError = null;
    _tlsPriv(socket)._authorizationErrorObject = null;
  }

  // checkServerIdentity is user code and can synchronously destroy either the
  // wrapper or supplied raw socket. Do not publish a secure handshake after
  // that callback has terminated the transport.
  if (_tlsPub(socket).destroyed || _tlsRawTransportUnexpectedlyDestroyed(socket) ||
      _tlsGetEngineId(socket) == null) {
    if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
      _terminateTlsForDestroyedTransport(socket);
    }
    _tlsDropBridgeWrites(socket);
    return;
  }

  if (_tlsPub(socket).authorized || opts.rejectUnauthorized === false) {
    // Publish the secure state only after every authorization callback has
    // returned. Writes/reads re-entered from checkServerIdentity stay queued.
    _tlsPriv(socket)._secureEstablished = true;
    _tlsPriv(socket)._pending = false;
    {
      var rawDestroyedBeforeSecureConnect = _tlsRawTransportDestroyed(socket);
      var closeDeferredBeforeSecureConnect = _tlsPriv(socket)._tlsDeferredTransportClose === true;
      _tlsEmitInternal(socket, 'secureConnect');
      if (_tlsTerminateIfTransportChanged(
        socket,
        rawDestroyedBeforeSecureConnect,
        closeDeferredBeforeSecureConnect
      )) return;
      if (_tlsPub(socket).destroyed || _tlsRawTransportUnexpectedlyDestroyed(socket) ||
          _tlsGetEngineId(socket) == null) {
        if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
          _terminateTlsForDestroyedTransport(socket);
        }
        _tlsDropBridgeWrites(socket);
        return;
      }
      var rawDestroyedBeforeSecure = _tlsRawTransportDestroyed(socket);
      var closeDeferredBeforeSecure = _tlsPriv(socket)._tlsDeferredTransportClose === true;
      _tlsEmitInternal(socket, 'secure', [true]);
      if (_tlsTerminateIfTransportChanged(
        socket,
        rawDestroyedBeforeSecure,
        closeDeferredBeforeSecure
      )) return;
      if (_tlsPub(socket).destroyed || _tlsRawTransportUnexpectedlyDestroyed(socket) ||
          _tlsGetEngineId(socket) == null) {
        if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
          _terminateTlsForDestroyedTransport(socket);
        }
        _tlsDropBridgeWrites(socket);
        return;
      }
    }
    _tlsPriv(socket)._tlsApplicationReady = true;
    _tlsBridgeFlushPendingWrites(socket);
    return;
  }
  _tlsPriv(socket)._bridgePendingWrites = null;
  _tlsBridgeFail(socket, _tlsPriv(socket)._authorizationErrorObject || _createError(
    'UNABLE_TO_VERIFY_CERT',
    'certificate verification failed'
  ));
  } finally {
    _tlsPriv(socket)._tlsHandshakeFinalizing = false;
  }
}

function _tlsBridgeScheduleEnd(socket) {
  if (_tlsPriv(socket)._bridgeEndScheduled || _tlsPriv(socket)._bridgeEndEmitted || _tlsPub(socket).destroyed) return;
  _tlsPriv(socket)._bridgeEndScheduled = true;
  var finish = function() {
    _tlsAssertOwner(socket);
    _tlsPriv(socket)._bridgeEndScheduled = false;
    if (!_tlsPub(socket).destroyed) _tlsBridgeMaybeEmitEnd(socket);
  };
  if (typeof process === 'object' && process && typeof process.nextTick === 'function') {
    process.nextTick(finish);
  } else {
    setTimeout(finish, 0);
  }
}

function _tlsBridgeMaybeFinalizeDeferredClose(socket) {
  if (!_tlsPriv(socket)._tlsDeferredTransportClose || _tlsPriv(socket)._tlsCloseEmitted ||
      !_tlsPriv(socket)._bridgeEndEmitted || (_tlsPriv(socket)._bridgeReadQueueBytes || 0) > 0 ||
      _tlsPriv(socket)._bridgeDecodedTail !== null && _tlsPriv(socket)._bridgeDecodedTail !== undefined) return;
  var hadError = _tlsPriv(socket)._tlsDeferredCloseHadError === true;
  _tlsBridgeRelease(socket);
  _tlsPriv(socket)._tlsDeferredTransportClose = false;
  _tlsPriv(socket)._tlsDeferredCloseHadError = false;
  _emitTlsCloseOnce(socket, hadError);
}

function _tlsBridgeMaybeEmitEnd(socket) {
  if (_tlsPub(socket).destroyed || _tlsGetEngineId(socket) == null) return;
  if (_tlsRawTransportUnexpectedlyDestroyed(socket)) {
    _terminateTlsForDestroyedTransport(socket);
    return;
  }
  if (_tlsPriv(socket)._bridgeEndEmitted) {
    _tlsBridgeMaybeFinalizeDeferredClose(socket);
    return;
  }
  if (!_tlsPriv(socket)._bridgeNativeEnded ||
      (_tlsPriv(socket)._bridgeReadQueueBytes || 0) > 0) return;
  // @ref LLP 0004#the-tls-builtin — `read()` must return all authenticated
  // plaintext (including StringDecoder's EOF tail) before `end` is observable.
  // Native EOF can surface reentrantly while read() pumps the sans-I/O engine;
  // defer finalization until every nested read frame has returned to its caller.
  if ((_tlsPriv(socket)._bridgeReadDepth || 0) > 0) {
    _tlsBridgeScheduleEnd(socket);
    return;
  }
  if (_tlsPriv(socket)._bridgeDecoder && !_tlsPriv(socket)._bridgeDecoderFinalized &&
      typeof _tlsPriv(socket)._bridgeDecoder.end === 'function') {
    _tlsPriv(socket)._bridgeDecoderFinalized = true;
    var trailing = _tlsPriv(socket)._bridgeDecoder.end();
    if (trailing) {
      if (_tlsBridgeIsFlowing(socket)) {
        var rawWasDestroyed = _tlsRawTransportDestroyed(socket);
        var closeWasDeferred = _tlsPriv(socket)._tlsDeferredTransportClose === true;
        _tlsEmitInternal(socket, 'data', [trailing]);
        if (_tlsTerminateIfTransportChanged(
          socket,
          rawWasDestroyed,
          closeWasDeferred
        )) return;
        if (_tlsPub(socket).destroyed || _tlsRawTransportUnexpectedlyDestroyed(socket) ||
            _tlsGetEngineId(socket) == null) return;
      } else {
        _tlsPriv(socket)._bridgeDecodedTail = trailing;
        var rawWasDestroyedReadable = _tlsRawTransportDestroyed(socket);
        var closeWasDeferredReadable = _tlsPriv(socket)._tlsDeferredTransportClose === true;
        _tlsEmitInternal(socket, 'readable');
        if (_tlsTerminateIfTransportChanged(
          socket,
          rawWasDestroyedReadable,
          closeWasDeferredReadable
        )) return;
        if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
          _terminateTlsForDestroyedTransport(socket);
        }
        // In readable mode the decoder's EOF chunk is still buffered data.
        // Node emits `end` only after read() consumes it.
        return;
      }
    }
  }
  if (_tlsPriv(socket)._bridgeDecodedTail !== null && _tlsPriv(socket)._bridgeDecodedTail !== undefined) return;
  _tlsPriv(socket)._bridgeEndEmitted = true;
  _tlsPriv(socket)._bridgeEndScheduled = false;
  _tlsPub(socket).readable = false;
  var rawWasDestroyedEnd = _tlsRawTransportDestroyed(socket);
  var closeWasDeferredEnd = _tlsPriv(socket)._tlsDeferredTransportClose === true;
  _tlsEmitInternal(socket, 'end');
  if (_tlsTerminateIfTransportChanged(
    socket,
    rawWasDestroyedEnd,
    closeWasDeferredEnd
  )) return;
  if (!_tlsPub(socket).destroyed && _tlsRawTransportUnexpectedlyDestroyed(socket)) {
    _terminateTlsForDestroyedTransport(socket);
    return;
  }
  if (!_tlsPub(socket).allowHalfOpen && _tlsPub(socket).writable &&
      !_tlsPriv(socket)._tlsDeferredTransportClose && !_tlsRawTransportDestroyed(socket)) {
    _tlsPub(socket).writable = false;
    _tlsPriv(socket)._bridgeHeldEnd = true;
    _tlsBridgeMaybeFinishEnd(socket);
  }
  // A raw close retained during path selection has already spent the
  // transport's only close notification. On a clean authenticated EOF,
  // release the native engine and replay close only after all plaintext and
  // the wrapper `end` event have drained.
  _tlsBridgeMaybeFinalizeDeferredClose(socket);
}

function _tlsBridgeReadBackpressured(socket) {
  return !_tlsBridgeIsFlowing(socket) &&
    (_tlsPriv(socket)._bridgeReadQueueBytes || 0) >= _tlsPriv(socket)._readableHighWaterMark;
}

function _tlsBridgeResumeRawInput(socket) {
  if (_tlsPriv(socket)._bridgePaused || _tlsBridgeReadBackpressured(socket) ||
      (_tlsPriv(socket)._bridgeCipherQueue && _tlsPriv(socket)._bridgeCipherQueue.length) ||
      _tlsPub(socket).destroyed || _tlsPriv(socket)._tlsTransportUndecided) return;
  if (_tlsPriv(socket)._bridgeInputPaused) {
    _tlsPriv(socket)._bridgeInputPaused = false;
    var raw = _tlsPriv(socket)._socket;
    if (raw && typeof raw.resume === 'function' && !raw.destroyed) raw.resume();
  }
}

function _tlsBridgeProcessCipherQueue(socket) {
  if (_tlsPriv(socket)._bridgeProcessingCipher || _tlsGetEngineId(socket) == null || _tlsPub(socket).destroyed) return;
  _tlsPriv(socket)._bridgeProcessingCipher = true;
  var stalls = 0;
  try {
    _tlsBridgeDrainPlain(socket);
    while (_tlsPriv(socket)._bridgeCipherQueue && _tlsPriv(socket)._bridgeCipherQueue.length &&
           _tlsGetEngineId(socket) != null && !_tlsPub(socket).destroyed) {
      if (_tlsBridgeReadBackpressured(socket)) {
        _tlsBridgePauseInput(socket);
        return;
      }
      var item = _tlsPriv(socket)._bridgeCipherQueue[0];
      var total = _byteLength(item.buffer);
      if (item.offset >= total) {
        _tlsPriv(socket)._bridgeCipherQueue.shift();
        continue;
      }
      var remainder = item.offset === 0 ? item.buffer : item.buffer.slice(item.offset);
      var consumed;
      try {
        consumed = __exactTlsEngineWriteTls(_tlsGetEngineId(socket), remainder);
      } catch (e) {
        _tlsBridgeFail(socket, e);
        return;
      }
      _tlsBridgePumpOut(socket);
      if (consumed < 0) {
        _tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket));
        return;
      }
      if (!_tlsPriv(socket)._secureEstablished) _finalizeBridgedHandshake(socket);
      if (_tlsGetEngineId(socket) == null || _tlsPub(socket).destroyed) return;
      var drained = _tlsBridgeDrainPlain(socket);
      if (consumed > 0) {
        item.offset += consumed;
        _tlsPriv(socket)._bridgeCipherQueueBytes = Math.max(
          0,
          (_tlsPriv(socket)._bridgeCipherQueueBytes || 0) - consumed
        );
        stalls = 0;
      } else if (_tlsPriv(socket)._bridgeTransportBackpressured) {
        _tlsBridgePauseInput(socket);
        return;
      } else if (_tlsBridgeReadBackpressured(socket)) {
        _tlsBridgePauseInput(socket);
        return;
      } else if (drained) {
        stalls = 0;
      } else if (++stalls > 1) {
        _tlsBridgeFail(socket, _createError('ERR_TLS_HANDSHAKE_FAILURE', 'TLS receive stalled'));
        return;
      }
    }
  } finally {
    _tlsPriv(socket)._bridgeProcessingCipher = false;
  }
  if (_tlsPriv(socket)._bridgeTransportEnded && !_tlsPriv(socket)._bridgeTransportEofApplied) {
    var engineId = _tlsGetEngineId(socket);
    if (engineId != null) {
      try {
        __exactTlsEngineTransportEof(engineId);
      } catch (e) {
        _tlsBridgeFail(socket, e);
        return;
      }
      // Commit only after the native engine accepts EOF. A denied/busy host
      // call must not turn a retryable transport end into a permanent no-op.
      _tlsPriv(socket)._bridgeTransportEofApplied = true;
    } else {
      return;
    }
    if (!_tlsPriv(socket)._secureEstablished) {
      var status;
      try {
        status = _tlsBridgeStatus(socket);
      } catch (statusErr) {
        _tlsBridgeFail(socket, statusErr);
        return;
      }
      _tlsBridgeFail(socket, (status && status.error)
        ? _tlsBridgeErrorFromStatus(socket)
        : _createError('ECONNRESET', 'read ECONNRESET'));
      return;
    }
    _tlsBridgeDrainPlain(socket);
  }
  _tlsBridgeResumeRawInput(socket);
  _tlsBridgeMaybeEmitEnd(socket);
}

function _tlsBridgeMaybeResumeInput(socket) {
  if (_tlsPub(socket).destroyed || _tlsPriv(socket)._bridgePaused) return;
  var queued = _tlsPriv(socket)._bridgeReadQueueBytes || 0;
  var lowWater = Math.max(1, Math.floor(_tlsPriv(socket)._readableHighWaterMark / 2));
  if (queued === 0 || (_tlsPriv(socket)._bridgeInputPaused && queued <= lowWater)) {
    _tlsBridgeDrainPlain(socket);
  }
  if (_tlsBridgeReadBackpressured(socket)) {
    _tlsBridgePauseInput(socket);
    return;
  }
  if (_tlsPriv(socket)._bridgeCipherQueue && _tlsPriv(socket)._bridgeCipherQueue.length) {
    _tlsBridgeProcessCipherQueue(socket);
  }
  _tlsBridgeResumeRawInput(socket);
}

function _tlsBridgeOnCiphertext(socket, chunk) {
  if (_tlsGetEngineId(socket) == null) return;
  var input = _bufferFromBytes(chunk);
  var inputLength = _byteLength(input);
  var retained = _tlsPriv(socket)._bridgeCipherQueueBytes || 0;
  if (inputLength > _tlsPriv(socket)._ciphertextHighWaterMark - retained) {
    // pause() normally prevents a second raw chunk while ciphertext is
    // retained, but EventEmitter reentrancy can still deliver already-queued
    // chunks. Fail closed instead of allowing attacker-controlled receive
    // memory to grow without bound.
    _tlsBridgePauseInput(socket);
    _tlsBridgeFail(socket, _createError(
      'ERR_TLS_BUFFER_OVERFLOW',
      'TLS ciphertext buffer exceeded its high water mark'
    ));
    return;
  }
  if (!_tlsPriv(socket)._bridgeCipherQueue) _tlsPriv(socket)._bridgeCipherQueue = [];
  _tlsPriv(socket)._bridgeCipherQueue.push({ buffer: input, offset: 0 });
  _tlsPriv(socket)._bridgeCipherQueueBytes = retained + inputLength;
  _tlsBridgeProcessCipherQueue(socket);
  if (!_tlsPub(socket).destroyed && _tlsGetEngineId(socket) != null &&
      _tlsPriv(socket)._bridgeCipherQueue && _tlsPriv(socket)._bridgeCipherQueue.length) {
    _tlsBridgePauseInput(socket);
  }
}

function _tlsBridgeOnTransportEnd(socket) {
  if (_tlsPub(socket).destroyed) return;
  if (_tlsGetEngineId(socket) == null) {
    if (_tlsPriv(socket)._bridgeFailed) return;
    _tlsPub(socket).readable = false;
    if (!_tlsPriv(socket)._bridgeEndEmitted) {
      _tlsPriv(socket)._bridgeEndEmitted = true;
      _tlsEmitInternal(socket, 'end');
    }
    return;
  }
  _tlsPriv(socket)._bridgeTransportEnded = true;
  _tlsBridgeProcessCipherQueue(socket);
}

// Start real TLS over the already-connected raw socket. Runs in place of the
// old ERR_TLS_EMULATION_LOOPBACK_ONLY failure for every out-of-process peer.
function _startTlsBridge(socket, netSocket, options, host, port) {
  _tlsAssertOwner(socket);
  var hasClientIdentity = options.pfx != null || options.cert != null || options.key != null;
  if (hasClientIdentity && options.rejectUnauthorized !== false &&
      typeof options.checkServerIdentity === 'function' &&
      options.checkServerIdentity !== checkServerIdentity) {
    var customIdentityErr = _createError(
      'ERR_TLS_CLIENT_IDENTITY_CUSTOM_CHECK_UNSUPPORTED',
      'Strict TLS client identities cannot use a custom checkServerIdentity in this transport'
    );
    var customIdentityTransport = _takeUndecidedTlsData(socket);
    _tlsReleaseHeldWrites(socket, 'drop');
    _destroyTlsSocketWithError(
      socket,
      customIdentityErr,
      customIdentityTransport.transportClosed
    );
    return;
  }
  _tlsPriv(socket)._bridged = true;
  _tlsPriv(socket)._bridgeEndEmitted = false;
  if (_tlsPriv(socket)._bridgeEncoding === undefined) _tlsPriv(socket)._bridgeEncoding = null;
  if (_tlsPriv(socket)._bridgeEncoding && !_tlsPriv(socket)._bridgeDecoder && StringDecoder) {
    _tlsPriv(socket)._bridgeDecoder = new StringDecoder(_tlsPriv(socket)._bridgeEncoding);
  }
  _tlsPriv(socket)._bridgePendingWrites = [];
  _tlsPriv(socket)._bridgePendingWriteBytes = 0;
  _tlsPriv(socket)._bridgeReadQueue = [];
  _tlsPriv(socket)._bridgeReadQueueBytes = 0;
  _tlsPriv(socket)._bridgeReadQueueOffset = 0;
  _tlsPriv(socket)._bridgeCipherQueue = [];
  _tlsPriv(socket)._bridgeCipherQueueBytes = 0;
  // Ibex's raw net.Socket reads at most 256 KiB per poll. Permit one already-
  // queued reentrant poll in addition to the chunk that triggered pause(), but
  // keep attacker-controlled retained ciphertext explicitly bounded.
  _tlsPriv(socket)._ciphertextHighWaterMark = Math.max(
    512 * 1024,
    Math.min(1024 * 1024, _tlsPriv(socket)._readableHighWaterMark * 8)
  );
  _tlsPriv(socket)._bridgePaused = _tlsPriv(socket)._tlsUserPaused === true;
  _tlsPriv(socket)._bridgeInputPaused = false;
  _tlsPriv(socket)._bridgeTransportBackpressured = false;
  _tlsPriv(socket)._bridgeTransportEnded = false;
  _tlsPriv(socket)._bridgeTransportEofApplied = false;
  _tlsPriv(socket)._bridgeNativeEnded = false;
  _tlsPriv(socket)._bridgeReadDepth = 0;
  _tlsPriv(socket)._bridgeEndScheduled = false;
  _tlsPriv(socket)._bridgeDecoderFinalized = false;
  _tlsPriv(socket)._bridgeDecodedTail = null;
  _tlsPriv(socket)._bridgeShutdownQueued = false;
  _tlsPriv(socket)._pending = true;
  _tlsPriv(socket)._secureEstablished = false;
  _tlsPriv(socket)._tlsApplicationReady = false;
  var engineId = _tlsGetEngineId(socket);
  if (engineId == null) {
    try {
      engineId = __exactTlsEngineNew(JSON.stringify(_tlsNativeEngineConfig(
        options,
        host,
        _tlsPriv(socket)._bridgeCipherSuites
      )));
    } catch (engineErr) {
      var failedUndecided = _takeUndecidedTlsData(socket);
      _tlsReleaseHeldWrites(socket, 'drop');
      _destroyTlsSocketWithError(socket, engineErr, failedUndecided.transportClosed);
      return;
    }
    _tlsSetEngineId(socket, engineId);
  } else {
    _tlsAssertOwner(socket);
  }
  // Writes held since connect() move into the bridged pre-secure queue only
  // after identity/config parsing succeeds, so a fail-loud construction error
  // cannot strand callbacks or partially transition the write state.
  _tlsReleaseHeldWrites(socket, 'bridge');

  // Feed every retained event in wire order while the guard remains active.
  // Processing an old record may synchronously write a TLS response; custom
  // sockets can emit newer data/end/close from that write. Those events join
  // the next batch instead of overtaking bytes already retained.
  for (;;) {
    var undecided = _drainUndecidedTlsData(socket);
    if (undecided.inputPaused) _tlsPriv(socket)._bridgeInputPaused = true;
    if (!undecided.events.length) break;
    for (var scan = 0; scan < undecided.events.length; scan++) {
      if (undecided.events[scan].type === 'close') {
        _tlsPriv(socket)._tlsDeferredTransportClose = true;
        _tlsPriv(socket)._tlsDeferredCloseHadError = _tlsPriv(socket)._tlsDeferredCloseHadError ||
          undecided.events[scan].hadError === true;
        break;
      }
    }
    for (var i = 0; i < undecided.events.length && !_tlsPub(socket).destroyed &&
           _tlsGetEngineId(socket) != null; i++) {
      var event = undecided.events[i];
      if (event.type === 'data') {
        _tlsBridgeOnCiphertext(socket, event.chunk);
      } else {
        _tlsBridgeOnTransportEnd(socket);
      }
    }
    if (_tlsPub(socket).destroyed || _tlsGetEngineId(socket) == null) return;
  }
  var finalUndecided = _takeUndecidedTlsData(socket);
  if (finalUndecided.inputPaused) _tlsPriv(socket)._bridgeInputPaused = true;

  // Send any ClientHello bytes not already pumped while processing retained
  // input, then reconcile user/guard pause ownership.
  _tlsBridgePumpOut(socket);
  _tlsBridgeMaybeResumeInput(socket);
}

function connect() {
  var parsed = _normalizeTlsConnectArguments(arguments);
  var options = parsed.options || {};
  var cb = parsed.callback;

  _validateProtocolVersion('minimum', options.minVersion);
  _validateProtocolVersion('maximum', options.maxVersion);
  var bridgeCipherSuites = _resolveCipherSuites(options, 'client');
  if (options.session !== undefined && options.session !== null) {
    throw _createError('ERR_TLS_SESSION_UNSUPPORTED',
      'TLS session resumption input is not supported by this transport');
  }
  if (options.maxVersion === 'TLSv1' || options.maxVersion === 'TLSv1.1') {
    throw _createError('ERR_TLS_INVALID_PROTOCOL_VERSION',
      'This TLS transport supports maximum versions TLSv1.2 and TLSv1.3');
  }

  // Defer binding until the undecided-transport guard is installed. A custom
  // or already-flowing socket may emit data synchronously from `on('data')`.
  var socket = new TLSSocket(options.socket || null, options, true);
  _tlsCaptureOwner(socket);
  _tlsPriv(socket)._tlsTransportUndecided = true;
  _tlsPriv(socket)._tlsAwaitingConnectEvent = true;
  _tlsPriv(socket)._tlsUndecidedEvents = [];
  _tlsPriv(socket)._tlsUndecidedData = [];
  _tlsPriv(socket)._tlsUndecidedDataBytes = 0;
  _tlsPriv(socket)._tlsUndecidedInputPaused = false;
  _tlsPriv(socket)._tlsUndecidedTransportEnded = false;
  _tlsPriv(socket)._tlsUndecidedTransportClosed = false;
  _tlsPriv(socket)._bridgeCipherSuites = bridgeCipherSuites;
  if (typeof cb === 'function' && typeof socket.once === 'function') {
    socket.once('secureConnect', cb);
  }
  // Hold application writes until the loopback-vs-bridge decision on TCP
  // connect. Consumers write the moment 'connect' fires; on the bridged path
  // those bytes must wait for the real handshake or they would go out as
  // plaintext ahead of the ClientHello (ENG-23492).
  _tlsPriv(socket)._writeHeld = true;
  _tlsPriv(socket)._heldWrites = [];
  _tlsPriv(socket)._heldWriteBytes = 0;

  var host = options.host || options.hostname || 'localhost';
  var port = typeof options.port === 'undefined' ? 443 : options.port;
  if (typeof port === 'string') port = Number(port);
  _tlsPub(socket).remoteAddress = host;
  _tlsPub(socket).remotePort = port;
  _tlsPub(socket).connecting = true;
  _tlsPriv(socket)._pending = true;
  if (options.servername || options.sni) {
    _tlsPub(socket).servername = options.servername || options.sni;
    _tlsPriv(socket)._servername = _tlsPub(socket).servername;
  }
  _tlsPriv(socket)._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
  _tlsPub(socket).authorized = false;
  _tlsPub(socket).authorizationError = null;

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
        _tlsAssertOwner(socket);
        var err = new Error('net module not available for TLS transport');
        err.code = 'ECONNREFUSED';
        _destroyTlsSocketWithError(socket, err, false);
      }, 0);
      return socket;
    }

    _tlsPriv(socket)._tlsAwaitingConnectEvent = netSocket.connecting !== false;
    socket._setSocket(netSocket);

    var completed = false;
    function onConnect() {
      if (completed) return;
      _tlsAssertOwner(socket);
      completed = true;
      _tlsPriv(socket)._tlsAwaitingConnectEvent = false;
      // The wrapper's forwarded `connect` event runs first. User callbacks are
      // allowed to destroy there; never resurrect that socket or publish a
      // server/client secure handshake afterward.
      if (_tlsPub(socket).destroyed) {
        _takeUndecidedTlsData(socket);
        _tlsReleaseHeldWrites(socket, 'drop');
        return;
      }
      if (_tlsRawTransportDestroyed(socket) &&
          !_tlsPriv(socket)._tlsUndecidedTransportEnded &&
          !_tlsPriv(socket)._tlsUndecidedTransportClosed) {
        _takeUndecidedTlsData(socket);
        _terminateTlsForDestroyedTransport(socket);
        return;
      }
      _tlsPub(socket).connecting = false;
      _tlsPriv(socket)._pending = false;
      _tlsPub(socket).encrypted = true;
      _tlsPriv(socket)._secureEstablished = true;
      _copySocketMetadata(socket, netSocket);
      _tlsPub(socket).remoteAddress = host;
      _tlsPub(socket).remotePort = port;
      _tlsPub(socket).servername = options.servername || options.host || options.hostname || _tlsPub(socket).servername;
      _tlsPriv(socket)._session = null;
      _tlsPriv(socket)._sessionReused = false;

      // In-process peer detection uses the actual connected destination,
      // including address family. Caller-supplied sockets are deliberately
      // excluded: their writable metadata cannot authenticate which accepted
      // transport they correspond to, and previously allowed tuple forgery to
      // publish a plain TCP connection as secure.
      var transportIdentity = _tlsTransportIdentities && _tlsTransportIdentities.get(socket);
      var peerHost = transportIdentity && transportIdentity.remoteAddress || host;
      var peerPort = transportIdentity && transportIdentity.remotePort !== undefined &&
        transportIdentity.remotePort !== null ? transportIdentity.remotePort : port;
      var peerFamily = transportIdentity && transportIdentity.remoteFamily;
      var tlsServer = !options.socket && _isLoopbackHost(peerHost)
        ? _lookupTlsServer(peerPort, peerHost, peerFamily)
        : null;
      var loopbackConnectionKey = tlsServer
        ? _tlsClientConnectionKey(transportIdentity, peerPort)
        : null;
      if (tlsServer && !loopbackConnectionKey) tlsServer = null;
      var serverHandshake = null;
      if (tlsServer) {
        var loopbackState = _tlsServerState(tlsServer);
        var serverOptions = loopbackState ? loopbackState.advertisedOptions : {};
        var advertisedClientOptions = _tlsAdvertisedClientOptions(options);
        var negotiatedProtocol = _negotiateTlsVersion(options, serverOptions);
        var negotiatedCipher = negotiatedProtocol
          ? _selectNegotiatedCipher(options, serverOptions, negotiatedProtocol)
          : null;
        if (!negotiatedCipher) {
          var clientErr = _createTlsAlertHandshakeFailureError();
          var serverErr = negotiatedProtocol
            ? _createNoSharedCipherError()
            : _createError('ERR_SSL_UNSUPPORTED_PROTOCOL', 'no mutually supported TLS protocol');
          serverHandshake = {
            ok: false,
            clientOptions: advertisedClientOptions,
            cipher: null,
            protocol: null,
            clientSocket: socket,
            serverError: serverErr
          };
          _deliverServerHandshake(tlsServer, loopbackConnectionKey, serverHandshake);
          var failedCipherTransport = _takeUndecidedTlsData(socket);
          _tlsReleaseHeldWrites(socket, 'drop');
          _destroyTlsSocketWithError(
            socket,
            clientErr,
            failedCipherTransport.transportClosed
          );
          return;
        }

        serverHandshake = {
          ok: true,
          clientOptions: advertisedClientOptions,
          cipher: negotiatedCipher,
          protocol: negotiatedProtocol,
          clientSocket: socket,
          serverError: null
        };
        _tlsPriv(socket)._protocol = negotiatedProtocol;

        // Synthetic loopback TLS does not exchange encrypted records or prove
        // possession of the server key. Strict authentication must therefore
        // fail loudly; permissive callers may use the compatibility transport,
        // but it is always reported as unauthorized below.
        if (options.rejectUnauthorized !== false) {
          var unsupportedAuthErr = _createError(
            'ERR_TLS_LOOPBACK_AUTH_UNSUPPORTED',
            'Loopback TLS emulation cannot cryptographically verify the server identity'
          );
          serverHandshake.ok = false;
          serverHandshake.serverError = _createError(
            'ECONNRESET',
            'TLS client rejected the synthetic loopback handshake'
          );
          _deliverServerHandshake(tlsServer, loopbackConnectionKey, serverHandshake);
          _takeUndecidedTlsData(socket);
          _tlsReleaseHeldWrites(socket, 'drop');
          _destroyTlsSocketWithError(socket, unsupportedAuthErr, false);
          return;
        }

        var handshakeOkLocal = _finalizeHandshake(socket, serverOptions, negotiatedCipher);
        if (handshakeOkLocal) {
          var permissiveAuthErr = _createError(
            'ERR_TLS_LOOPBACK_AUTH_UNSUPPORTED',
            'Loopback TLS emulation does not provide cryptographic peer authentication'
          );
          _tlsPub(socket).authorized = false;
          _tlsPub(socket).authorizationError = permissiveAuthErr.code;
          _tlsPriv(socket)._authorizationErrorObject = permissiveAuthErr;
          handshakeOkLocal = false;
        }
        if (_tlsPub(socket).destroyed) {
          _takeUndecidedTlsData(socket);
          _tlsReleaseHeldWrites(socket, 'drop');
          return;
        }
        var earlyTransport = _takeUndecidedTlsData(socket);
        if (earlyTransport.pending.length || earlyTransport.transportEnded ||
            earlyTransport.transportClosed) {
          var earlyErr = _createError(
            'ERR_TLS_UNEXPECTED_EARLY_DATA',
            'TLS transport produced data or closed before the handshake path was selected'
          );
          // The paired in-process server has already accepted the raw socket.
          // Give it a terminal handshake result too so neither side can hang.
          serverHandshake.ok = false;
          serverHandshake.serverError = earlyErr;
          _deliverServerHandshake(tlsServer, loopbackConnectionKey, serverHandshake);
          _tlsReleaseHeldWrites(socket, 'drop');
          _destroyTlsSocketWithError(socket, earlyErr, earlyTransport.transportClosed);
          return;
        }
        if (_tlsRawTransportDestroyed(socket)) {
          _terminateTlsForDestroyedTransport(socket);
          return;
        }
        var loopbackClientAuthError = _loopbackClientAuthorizationError(
          serverOptions,
          options,
          peerHost,
          peerPort
        );
        if (loopbackClientAuthError && serverOptions.rejectUnauthorized) {
          serverHandshake.ok = false;
          serverHandshake.serverError = loopbackClientAuthError;
          _deliverServerHandshake(tlsServer, loopbackConnectionKey, serverHandshake);
          var clientCertificateAlert = _createError(
            'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
            'TLS server rejected the client certificate'
          );
          _tlsReleaseHeldWrites(socket, 'drop');
          _destroyTlsSocketWithError(socket, clientCertificateAlert, false);
          return;
        }
        if (handshakeOkLocal || options.rejectUnauthorized === false) {
          serverHandshake.resumeClient = function() {
            return _publishLoopbackClientHandshake(socket, serverHandshake);
          };
          // Queue the server handoff before publishing client success. When
          // TCP accept has not produced a server-owned socket yet, keep client
          // writes/security events held until accept consumes this message.
          var delivery = _deliverServerHandshake(
            tlsServer,
            loopbackConnectionKey,
            serverHandshake
          );
          if (!delivery) {
            var queueErr = _createError(
              'ERR_TLS_HANDSHAKE_QUEUE_FULL',
              'TLS loopback handshake queue is full'
            );
            _tlsReleaseHeldWrites(socket, 'drop');
            _destroyTlsSocketWithError(socket, queueErr, false);
            return;
          }
          if (delivery === 'queued') return;
          _publishLoopbackClientHandshake(socket, serverHandshake);
        } else if (_tlsPub(socket).authorizationError) {
          serverHandshake.ok = false;
          // Certificate/identity rejection belongs to the client. The server
          // only observes the peer closing the transport.
          serverHandshake.serverError = _createError(
            'ECONNRESET',
            'TLS client rejected the server identity'
          );
          _deliverServerHandshake(tlsServer, loopbackConnectionKey, serverHandshake);
          var localErr = _tlsPriv(socket)._authorizationErrorObject || new Error(_tlsPub(socket).authorizationError);
          _tlsReleaseHeldWrites(socket, 'drop');
          _destroyTlsSocketWithError(socket, localErr, false);
        }
        return;
      }

      // The peer is NOT an in-process tls.Server: perform REAL TLS through
      // the native bridge (ENG-23492). The sans-IO engine handshakes over
      // this already-connected raw socket; secureConnect only fires once the
      // real handshake completes and the real peer chain has been validated.
      // @ref LLP 0004#the-tls-builtin — out-of-process peers use the native bridge
      if (_tlsBridgeAvailable()) {
        if (_tlsPub(socket).destroyed) return;
        _startTlsBridge(socket, netSocket, options, host, port);
        return;
      }

      // No native bridge in this build (e.g. the bun test harness or an
      // embedded host without net host functions): fail loudly instead of
      // fabricating a handshake. This emulation performs no wire
      // cryptography; completing "secureConnect" here against a real TLS
      // endpoint would report a secure, authorized connection over cleartext
      // while the remote server stalls waiting for a ClientHello. destroy(err)
      // delivers exactly one 'error' event through the raw-socket binding.
      // @ref LLP 0004#fail-loud-boundary-without-the-bridge — refuse to fabricate TLS without the bridge
      var emulationErr = _createError(
        'ERR_TLS_EMULATION_LOOPBACK_ONLY',
        'tls.connect: this Ibex build lacks the native TLS bridge; refusing to fabricate a secure connection to ' +
          peerHost + ':' + peerPort + ', which is not a tls.Server running in this process. ' +
          'Only loopback connections to an in-process tls.Server are supported here ' +
          '(LLP 0004; native TLS bridge: ENG-23492).'
      );
      var unavailableTransport = _takeUndecidedTlsData(socket);
      _tlsReleaseHeldWrites(socket, 'drop');
      _destroyTlsSocketWithError(
        socket,
        emulationErr,
        unavailableTransport.transportClosed
      );
    }

    if (typeof netSocket.on === 'function') {
      netSocket.on('connect', onConnect);
    }

    if (netSocket.connecting === false) {
      setTimeout(onConnect, 0);
    }
  } catch(e) {
    setTimeout(function() {
      _tlsAssertOwner(socket);
      if (!_tlsPub(socket).destroyed) _destroyTlsSocketWithError(socket, e, false);
    }, 0);
  }

  return socket;
}

function addContext(serverName, context, server) {
  var state = _tlsServerState(server);
  if (!server || !state) return false;
  _tlsAssertServerOwner(server);
  if (typeof serverName !== 'string' || !serverName) {
    throw _createError('ERR_INVALID_ARG_TYPE', 'The "serverName" argument must be a non-empty string');
  }

  var knownContextState = _secureContextStates && _secureContextStates.get(context);
  if (!knownContextState && context && context.context) {
    knownContextState = _secureContextStates && _secureContextStates.get(context.context);
  }
  var secureContext = context instanceof SecureContext
    ? context
    : (knownContextState
      ? knownContextState.secureContext
      : createSecureContext(context || {}));

  state.contexts[serverName] = secureContext;
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

function _startTlsServerOwnerPump(server) {
  var state = _tlsServerState(server);
  if (!state || state.ownerPump || typeof setInterval !== 'function') return;
  state.ownerPump = setInterval(function() {
    _tlsAssertServerOwner(server);
    var now = Date.now();
    for (var i = 0; i < state.pendingSockets.length;) {
      var entry = state.pendingSockets[i];
      var tlsSocket = entry && entry.socket;
      if (!tlsSocket || _tlsPub(tlsSocket).destroyed) {
        state.pendingSockets.splice(i, 1);
        continue;
      }
      if (entry.handshake) {
        state.pendingSockets.splice(i, 1);
        var handshake = entry.handshake;
        entry.handshake = null;
        try {
          _tlsAssertOwner(tlsSocket);
          _applyPendingServerHandshake(server, tlsSocket, handshake);
        } catch (handoffErr) {
          server.emit('tlsClientError', handoffErr, tlsSocket);
          try { tlsSocket.destroy(); } catch (_handoffDestroyErr) {
            // The failed handoff may already have destroyed the socket.
          }
        }
        continue;
      }
      if (entry.deadline <= now) {
        state.pendingSockets.splice(i, 1);
        var timeoutErr = _createError(
          'ERR_TLS_HANDSHAKE_TIMEOUT',
          'TLS loopback handshake timed out'
        );
        server.emit('tlsClientError', timeoutErr, tlsSocket);
        try { tlsSocket.destroy(); } catch (_timeoutDestroyErr) {
          // Timeout delivery races with ordinary socket teardown.
        }
        continue;
      }
      i++;
    }
    if (!state.pendingSockets.length && state.ownerPump) {
      clearInterval(state.ownerPump);
      state.ownerPump = null;
    }
  }, 10);
  if (state.ownerPump && typeof state.ownerPump.unref === 'function') state.ownerPump.unref();
}

function _scheduleTlsServerRetirement(state) {
  if (!state) return;
  state.retired = true;
  if (state.tokenCloseTimer) return;
  var closingToken = state.ownerToken;
  state.tokenCloseTimer = setTimeout(function() {
    _tlsAssertServerOwner(state.server);
    state.tokenCloseTimer = null;
    if (state.ownerToken !== closingToken) return;
    state.options = {};
    state.advertisedOptions = {};
    state.sharedCreds = null;
    state.contexts = Object.create(null);
    state.ticketKeys = null;
    state.events = Object.create(null);
    if (closingToken != null && typeof __exactTlsOwnerToken === 'function') {
      __exactTlsOwnerToken('close', closingToken);
    }
    state.ownerToken = null;
  }, 0);
  if (state.tokenCloseTimer && typeof state.tokenCloseTimer.unref === 'function') {
    state.tokenCloseTimer.unref();
  }
}

function _stopTlsServerOwnerPump(server) {
  var state = _tlsServerState(server);
  if (!state) return;
  if (state.ownerPump) clearInterval(state.ownerPump);
  state.ownerPump = null;
  var pending = state.pendingSockets.splice(0, state.pendingSockets.length);
  for (var i = 0; i < pending.length; i++) {
    if (pending[i].socket && !_tlsPub(pending[i].socket).destroyed) {
      try { pending[i].socket.destroy(); } catch (_pendingDestroyErr) {
        // Server close races with pending-socket teardown.
      }
    }
  }
  var handshakes = state.pendingHandshakes.splice(0, state.pendingHandshakes.length);
  for (var j = 0; j < handshakes.length; j++) {
    if (handshakes[j].timeout) clearTimeout(handshakes[j].timeout);
    _clearLoopbackClientCloseWatch(handshakes[j]);
    var clientSocket = handshakes[j].clientSocket;
    if (clientSocket && !_tlsPub(clientSocket).destroyed) {
      try {
        _destroyTlsSocketWithError(
          clientSocket,
          _createError('ERR_TLS_SERVER_CLOSED', 'TLS server closed during handshake'),
          false
        );
      } catch (_clientCloseErr) {
        // The client may have closed before the server-close notification.
      }
    }
  }
  // This reduced TLS server becomes terminal after close. Scrubbing before
  // token release prevents a different principal from relistening the JS
  // object and inheriting credentials or ticket keys.
  _scheduleTlsServerRetirement(state);
}

function _runTlsServerOwned(server, callback, args) {
  _tlsAssertServerOwner(server);
  return callback.apply(server, args || []);
}

function _guardTlsServerNetState(server, state) {
  if (!server || !state || state.netStateGuarded ||
      typeof Object.defineProperty !== 'function') return;
  state.netStateGuarded = true;
  var registerOwnerGuard = server[_kRegisterNetServerOwnerGuard];
  if (typeof registerOwnerGuard === 'function') {
    // Ibex net.Server keeps its transport state in a module-private WeakMap.
    // Register exactly one public-surface guard while allowing net's own hot
    // accept path to use the private state directly. No broad "trusted depth"
    // flag exists for a user getter/listener to inherit reentrantly.
    registerOwnerGuard.call(server, function() {
      _tlsAssertServerOwner(server);
    });
    state.netOwnerGuardRegistered = true;
  } else {
    // Reduced test/embedder shims do not expose net's private-state hook.
    // Preserve the same owner checks with fixed accessors as a fallback.
    state.netValues = Object.create(null);
    var names = [
      'listening', 'maxConnections', '_handle', '_acceptTimer', '_connections',
      '_closing', '_workers', '_isUnix', '_socketPath', '_listenToken',
      '_listeningPending', '_readableAll', '_writableAll', 'ipv6Only',
      'allowHalfOpen', 'pauseOnConnect', 'noDelay', 'keepAlive',
      'keepAliveInitialDelay', 'blockList', 'captureRejections', '_connectionKey',
      '_unrefed', '_unref', '_reusePort', '_port', '_requestedPort', '_host',
      'host'
    ];
    for (var i = 0; i < names.length; i++) {
      (function(name) {
        state.netValues[name] = server[name];
        try {
          Object.defineProperty(server, name, {
            enumerable: true,
            configurable: false,
            get: function() {
              _tlsAssertServerOwner(server);
              return state.netValues[name];
            },
            set: function(value) {
              _tlsAssertServerOwner(server);
              state.netValues[name] = value;
            }
          });
        } catch (_netStateGuardErr) {
          // Lifecycle and event methods remain fixed owner-checked boundaries
          // when a reduced embedder provides a non-configurable field.
        }
      })(names[i]);
    }
  }
  try {
    Object.defineProperty(server, _kRunOwnedServer, {
      value: function(callback, args) {
        return _runTlsServerOwned(server, callback, args);
      },
      enumerable: false,
      configurable: false,
      writable: false
    });
  } catch (_ownedRunnerGuardErr) {
    // Frozen hosts retain the existing guarded lifecycle method.
  }
  try {
    Object.defineProperty(server, _kCloseOwnedServer, {
      value: function(phase) {
        _tlsAssertServerOwner(server);
        if (phase === 'retire') {
          _scheduleTlsServerRetirement(state);
          return;
        }
        state.retired = true;
        if (!state.closed) {
          _unregisterTlsServer(server);
          state.closed = true;
        }
      },
      enumerable: false,
      configurable: false,
      writable: false
    });
  } catch (_ownedCloseGuardErr) {
    // Frozen hosts retain the existing guarded lifecycle method.
  }
}

function _guardTlsServerLifecycle(server, state) {
  if (!server || !state || state.lifecycleGuarded) return;
  state.lifecycleGuarded = true;
  var originalListen = server.listen;
  if (typeof originalListen === 'function') {
    var guardedListen = function() {
      if (state.retired) {
        throw _createError(
          'ERR_TLS_SERVER_CLOSED',
          'A closed TLS server cannot be listened on again in this runtime'
        );
      }
      _tlsAssertServerOwner(server);
      var wasClosed = state.closed;
      state.closed = false;
      try {
        return _runTlsServerOwned(
          server,
          originalListen,
          Array.prototype.slice.call(arguments)
        );
      } catch (listenErr) {
        state.closed = wasClosed;
        throw listenErr;
      }
    };
    if (typeof Object.defineProperty === 'function') {
      try {
        Object.defineProperty(server, 'listen', {
          value: guardedListen,
          enumerable: false,
          configurable: false,
          writable: false
        });
      } catch (_listenGuardErr) { server.listen = guardedListen; }
    } else {
      server.listen = guardedListen;
    }
  }
  var guardedMethods = ['close', 'ref', 'unref', 'address', 'getConnections'];
  for (var i = 0; i < guardedMethods.length; i++) {
    (function(name, original) {
      if (typeof original !== 'function') return;
      var guarded = function() {
        var args = Array.prototype.slice.call(arguments);
        if (name === 'close' && !state.netOwnerGuardRegistered &&
            typeof server[_kCloseOwnedServer] === 'function') {
          server[_kCloseOwnedServer]('begin');
          var fallbackCloseResult = _runTlsServerOwned(server, original, args);
          // Reduced net shims do not emit a close event. Their callback timer
          // was queued by the original method, so retirement queued here runs
          // only after that final owner-attributed callback.
          server[_kCloseOwnedServer]('retire');
          return fallbackCloseResult;
        }
        return _runTlsServerOwned(
          server,
          original,
          args
        );
      };
      if (typeof Object.defineProperty === 'function') {
        try {
          Object.defineProperty(server, name, {
            value: guarded,
            enumerable: false,
            configurable: false,
            writable: false
          });
          return;
        } catch (_lifecycleMethodGuardErr) {
          // Assignment fallback below covers configurable legacy hosts.
        }
      }
      server[name] = guarded;
    })(guardedMethods[i], server[guardedMethods[i]]);
  }
}

function _guardTlsServerEventSurface(server, state) {
  if (!server || !state || state.eventSurfaceGuarded) return;
  state.eventSurfaceGuarded = true;
  if (typeof Object.defineProperty === 'function') {
    state.events = server._events || Object.create(null);
    try {
      Object.defineProperty(server, '_events', {
        enumerable: false,
        configurable: false,
        get: function() {
          _tlsAssertServerOwner(server);
          return state.events;
        },
        set: function(value) {
          _tlsAssertServerOwner(server);
          state.events = value;
        }
      });
    } catch (_eventsGuardErr) {
      // Some reduced EventEmitter shims define a fixed event table. The
      // guarded methods below remain the authority boundary in that case.
    }
  }
  var methods = [
    'on', 'addListener', 'once', 'prependListener', 'prependOnceListener',
    'removeListener', 'off', 'removeAllListeners', 'emit', 'listenerCount',
    'listeners', 'rawListeners'
  ];
  for (var i = 0; i < methods.length; i++) {
    (function(name, original) {
      if (typeof original !== 'function') return;
      var guarded = function() {
        _tlsAssertServerOwner(server);
        return original.apply(server, arguments);
      };
      if (typeof Object.defineProperty === 'function') {
        try {
          Object.defineProperty(server, name, {
            value: guarded,
            enumerable: false,
            configurable: false,
            writable: false
          });
          return;
        } catch (_methodGuardErr) {
          // Assignment fallback below covers configurable legacy hosts.
        }
      }
      server[name] = guarded;
    })(methods[i], server[methods[i]]);
  }
}

function _defineTlsServerStateProperty(server, state, name, value) {
  if (typeof Object.defineProperty !== 'function') {
    server[name] = value;
    return;
  }
  if (!state.publicValues) state.publicValues = Object.create(null);
  state.publicValues[name] = value;
  Object.defineProperty(server, name, {
    enumerable: true,
    configurable: false,
    get: function() {
      _tlsAssertServerOwner(server);
      return state.publicValues[name];
    },
    set: function(nextValue) {
      _tlsAssertServerOwner(server);
      state.publicValues[name] = nextValue;
    }
  });
}

function _defineTlsServerMethod(server, name, implementation) {
  var method = function() {
    _tlsAssertServerOwner(server);
    return implementation.apply(server, arguments);
  };
  if (typeof Object.defineProperty === 'function') {
    Object.defineProperty(server, name, {
      value: method,
      enumerable: false,
      configurable: false,
      writable: false
    });
  } else {
    server[name] = method;
  }
}

function _decorateServer(server, options, secureConnectionListener) {
  var serverOptions = options || {};
  var state = _tlsServerState(server);
  if (state.ownerToken == null && typeof __exactTlsOwnerToken === 'function') {
    state.ownerToken = __exactTlsOwnerToken('new');
  }
  state.options = _cloneOwnProperties(serverOptions);
  state.advertisedOptions = _tlsAdvertisedServerOptions(serverOptions);
  state.sharedCreds = createSecureContext(serverOptions);
  state.contexts = Object.create(null);
  state.ticketKeys = null;
  _guardTlsServerNetState(server, state);
  _guardTlsServerLifecycle(server, state);
  _guardTlsServerEventSurface(server, state);
  _defineTlsServerStateProperty(server, state, 'requestCert', !!serverOptions.requestCert);
  _defineTlsServerStateProperty(server, state, 'rejectUnauthorized', !!serverOptions.rejectUnauthorized);
  _defineTlsServerMethod(server, 'addContext', function(serverName, context) {
    return addContext(serverName, context, server);
  });
  _defineTlsServerMethod(server, 'setSecureContext', function(nextOptions) {
    state.options = _cloneOwnProperties(nextOptions || {});
    state.advertisedOptions = _tlsAdvertisedServerOptions(nextOptions || {});
    state.sharedCreds = createSecureContext(nextOptions || {});
    return server;
  });
  _defineTlsServerMethod(server, 'getTicketKeys', function() {
    return state.ticketKeys ? _cloneBufferLike(state.ticketKeys) : _getEmptyBuffer();
  });
  _defineTlsServerMethod(server, 'setTicketKeys', function(keys) {
    if (!_isArrayBufferView(keys)) {
      throw _createError(
        'ERR_INVALID_ARG_TYPE',
        'The "buffer" argument must be an instance of Buffer, TypedArray, or DataView'
      );
    }
    if (_byteLength(keys) !== 48) {
      throw _createError('ERR_TLS_INVALID_TICKET_KEYS', 'Session ticket keys must be a 48-byte buffer');
    }
    state.ticketKeys = _cloneBufferLike(keys);
    return server;
  });

  if (typeof secureConnectionListener === 'function' && typeof server.on === 'function') {
    server.on('secureConnection', secureConnectionListener);
  }

  if (typeof server.on === 'function' && !state.registryHooksInstalled) {
    state.registryHooksInstalled = true;
    server.on('listening', function() {
      _registerTlsServer(server);
    });
    server.on('close', function() {
      _unregisterTlsServer(server);
      _stopTlsServerOwnerPump(server);
    });
  }

  return server;
}

function _createServerTLSSocket(server, rawSocket) {
  var state = _tlsServerState(server);
  var serverOptions = state ? state.options : {};
  if (state && state.pendingSockets.length >= MAX_PENDING_TLS_HANDSHAKES) {
    var capacityErr = _createError(
      'ERR_TLS_HANDSHAKE_QUEUE_FULL',
      'TLS loopback handshake queue is full'
    );
    server.emit('tlsClientError', capacityErr, rawSocket);
    if (rawSocket && typeof rawSocket.destroy === 'function') rawSocket.destroy();
    return null;
  }
  if (rawSocket && typeof rawSocket.pause === 'function') rawSocket.pause();
  var tlsSocket = new TLSSocket(rawSocket, serverOptions);
  _tlsPriv(tlsSocket)._server = server;
  tlsSocket.server = server;
  _tlsPub(tlsSocket).connecting = false;
  _tlsPriv(tlsSocket)._pending = true;
  _tlsPriv(tlsSocket)._secureEstablished = false;
  _tlsPriv(tlsSocket)._protocol = serverOptions.minVersion || serverOptions.maxVersion || DEFAULT_MAX_VERSION;
  _copySocketMetadata(tlsSocket, rawSocket);
  _tlsPriv(tlsSocket)._peerCertificate = null;
  _tlsPriv(tlsSocket)._localCertificate = _buildLocalCertificate(
    _tlsPub(tlsSocket).remoteAddress || 'localhost',
    _tlsPub(tlsSocket).remotePort,
    { cert: serverOptions.cert, ca: serverOptions.ca }
  );
  _tlsPriv(tlsSocket)._cipher = {
    name: _normalizeCipherName(serverOptions.ciphers),
    version: _tlsPriv(tlsSocket)._protocol
  };
  _tlsPub(tlsSocket).authorized = false;
  _tlsPub(tlsSocket).authorizationError = null;
  _tlsPriv(tlsSocket)._tlsLoopbackConnectionKey = _tlsServerConnectionKey(rawSocket);
  var pendingHandshake = _shiftPendingServerHandshake(
    server,
    _tlsPriv(tlsSocket)._tlsLoopbackConnectionKey
  );
  if (pendingHandshake) {
    if (pendingHandshake.ok && typeof pendingHandshake.resumeClient === 'function') {
      pendingHandshake.resumeClient();
    }
    _applyPendingServerHandshake(server, tlsSocket, pendingHandshake);
  } else {
    var entry = {
      socket: tlsSocket,
      handshake: null,
      deadline: Date.now() + TLS_LOOPBACK_HANDSHAKE_TIMEOUT_MS
    };
    state.pendingSockets.push(entry);
    _startTlsServerOwnerPump(server);
    tlsSocket.once('close', function() {
      var index = state.pendingSockets.indexOf(entry);
      if (index !== -1) state.pendingSockets.splice(index, 1);
    });
  }
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
        // 'secureConnection' (or 'tlsClientError' on failure) is emitted by
        // _applyPendingServerHandshake once the handshake actually resolves —
        // either synchronously here (if a handshake is already queued) or later
        // when the client-side connect computes it. Emitting it again here
        // duplicated the event on success (doubling request parsers/accounting)
        // and wrongly emitted it for a destroyed socket after handshake failure.
        _createServerTLSSocket(server, rawSocket);
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
  translatePeerCertificate: translatePeerCertificate,
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
