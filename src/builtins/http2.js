var eventsModule;
try { eventsModule = require('events'); } catch(e) {}

var EventEmitter = eventsModule && (eventsModule.EventEmitter || eventsModule);
var hasOwn = Object.prototype.hasOwnProperty;

var constants = {
  // Error codes
  NGHTTP2_NO_ERROR: 0,
  NGHTTP2_PROTOCOL_ERROR: 1,
  NGHTTP2_INTERNAL_ERROR: 2,
  NGHTTP2_FLOW_CONTROL_ERROR: 3,
  NGHTTP2_SETTINGS_TIMEOUT: 4,
  NGHTTP2_STREAM_CLOSED: 5,
  NGHTTP2_FRAME_SIZE_ERROR: 6,
  NGHTTP2_REFUSED_STREAM: 7,
  NGHTTP2_CANCEL: 8,
  NGHTTP2_COMPRESSION_ERROR: 9,
  NGHTTP2_CONNECT_ERROR: 10,
  NGHTTP2_ENHANCE_YOUR_CALM: 11,
  NGHTTP2_INADEQUATE_SECURITY: 12,
  NGHTTP2_HTTP_1_1_REQUIRED: 13,

  // Settings
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE: 1,
  NGHTTP2_SETTINGS_ENABLE_PUSH: 2,
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: 3,
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: 4,
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE: 5,
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: 6,
  NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL: 8,

  DEFAULT_SETTINGS_HEADER_TABLE_SIZE: 4096,
  DEFAULT_SETTINGS_ENABLE_PUSH: 1,
  DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE: 65535,
  DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS: 4294967295,
  DEFAULT_SETTINGS_MAX_FRAME_SIZE: 16384,
  DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: 65535,
  DEFAULT_SETTINGS_ENABLE_CONNECT_PROTOCOL: 0,

  PADDING_STRATEGY_NONE: 0,
  PADDING_STRATEGY_CALLBACK: 1,
  PADDING_STRATEGY_ALIGNED: 1,
  PADDING_STRATEGY_MAX: 2,

  // HTTP status codes
  HTTP_STATUS_CONTINUE: 100,
  HTTP_STATUS_SWITCHING_PROTOCOLS: 101,
  HTTP_STATUS_OK: 200,
  HTTP_STATUS_CREATED: 201,
  HTTP_STATUS_ACCEPTED: 202,
  HTTP_STATUS_NO_CONTENT: 204,
  HTTP_STATUS_MOVED_PERMANENTLY: 301,
  HTTP_STATUS_FOUND: 302,
  HTTP_STATUS_NOT_MODIFIED: 304,
  HTTP_STATUS_BAD_REQUEST: 400,
  HTTP_STATUS_UNAUTHORIZED: 401,
  HTTP_STATUS_FORBIDDEN: 403,
  HTTP_STATUS_NOT_FOUND: 404,
  HTTP_STATUS_METHOD_NOT_ALLOWED: 405,
  HTTP_STATUS_INTERNAL_SERVER_ERROR: 500,
  HTTP_STATUS_NOT_IMPLEMENTED: 501,
  HTTP_STATUS_BAD_GATEWAY: 502,
  HTTP_STATUS_SERVICE_UNAVAILABLE: 503,
  HTTP_STATUS_GATEWAY_TIMEOUT: 504,

  // Header fields
  HTTP2_HEADER_STATUS: ':status',
  HTTP2_HEADER_METHOD: ':method',
  HTTP2_HEADER_AUTHORITY: ':authority',
  HTTP2_HEADER_SCHEME: ':scheme',
  HTTP2_HEADER_PATH: ':path',
  HTTP2_HEADER_HTTP2_SETTINGS: 'http2-settings',
  HTTP2_HEADER_CONTENT_TYPE: 'content-type',
  HTTP2_HEADER_CONTENT_LENGTH: 'content-length',
  HTTP2_HEADER_ACCEPT: 'accept',
  HTTP2_HEADER_ACCEPT_ENCODING: 'accept-encoding'
};

var sensitiveHeaders = typeof Symbol === 'function'
  ? Symbol('nodejs.http2.sensitiveHeaders')
  : '__sensitiveHeaders';

var _settingDefinitions = [
  { key: 'headerTableSize', id: constants.NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, type: 'uint32' },
  { key: 'enablePush', id: constants.NGHTTP2_SETTINGS_ENABLE_PUSH, type: 'boolean' },
  { key: 'maxConcurrentStreams', id: constants.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, type: 'uint32' },
  { key: 'initialWindowSize', id: constants.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, type: 'uint32' },
  { key: 'maxFrameSize', id: constants.NGHTTP2_SETTINGS_MAX_FRAME_SIZE, type: 'frameSize' },
  { key: 'maxHeaderListSize', id: constants.NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, type: 'uint32' },
  { key: 'enableConnectProtocol', id: constants.NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, type: 'boolean' }
];

function _createError(code, message) {
  var err = new Error(message);
  err.code = code;
  return err;
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

function _isArrayBufferView(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(value);
  }
  return typeof value.byteLength === 'number' && value.buffer;
}

function _isDataView(value) {
  return typeof DataView !== 'undefined' && value instanceof DataView;
}

function _isTypedArray(value) {
  return _isArrayBufferView(value) && !_isDataView(value);
}

function _bufferFrom(value) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(value);
  }
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (_isTypedArray(value)) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength || value.length);
  }
  return value;
}

function _alloc(length) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.alloc === 'function') {
    return Buffer.alloc(length);
  }
  return typeof Uint8Array !== 'undefined' ? new Uint8Array(length) : [];
}

function _setUint16BE(buf, offset, value) {
  buf[offset] = (value >>> 8) & 255;
  buf[offset + 1] = value & 255;
}

function _setUint32BE(buf, offset, value) {
  buf[offset] = (value >>> 24) & 255;
  buf[offset + 1] = (value >>> 16) & 255;
  buf[offset + 2] = (value >>> 8) & 255;
  buf[offset + 3] = value & 255;
}

function _readUint16BE(buf, offset) {
  return ((buf[offset] << 8) | buf[offset + 1]) >>> 0;
}

function _readUint32BE(buf, offset) {
  return (
    (((buf[offset] << 24) >>> 0) +
      ((buf[offset + 1] << 16) >>> 0) +
      ((buf[offset + 2] << 8) >>> 0) +
      (buf[offset + 3] >>> 0)) >>> 0
  );
}

function _validateSettingsObject(settings) {
  if (typeof settings === 'undefined') return {};
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    throw _createError('ERR_INVALID_ARG_TYPE', 'The "settings" argument must be of type object');
  }
  return settings;
}

function _validateSettingValue(name, value, type) {
  if (type === 'boolean') {
    if (typeof value !== 'boolean') {
      throw _createError(
        'ERR_HTTP2_INVALID_SETTING_VALUE',
        'Invalid value for setting "' + name + '": ' + value
      );
    }
    return value ? 1 : 0;
  }

  if (typeof value !== 'number' || value !== (value >>> 0)) {
    throw _createError(
      'ERR_HTTP2_INVALID_SETTING_VALUE',
      'Invalid value for setting "' + name + '": ' + value
    );
  }

  if (type === 'frameSize' && (value < 16384 || value > 16777215)) {
    throw _createError(
      'ERR_HTTP2_INVALID_SETTING_VALUE',
      'Invalid value for setting "' + name + '": ' + value
    );
  }

  return value >>> 0;
}

function _normalizePackedSettings(settings) {
  var normalized = {};
  if (hasOwn.call(settings, 'maxHeaderListSize')) {
    normalized.maxHeaderListSize = settings.maxHeaderListSize;
  }
  if (hasOwn.call(settings, 'maxHeaderSize')) {
    if (hasOwn.call(settings, 'maxHeaderListSize') &&
        typeof process !== 'undefined' &&
        typeof process.emitWarning === 'function') {
      process.emitWarning('settings.maxHeaderSize overwrite settings.maxHeaderListSize');
    }
    normalized.maxHeaderListSize = settings.maxHeaderSize;
  }

  for (var i = 0; i < _settingDefinitions.length; i++) {
    var definition = _settingDefinitions[i];
    if (definition.key === 'maxHeaderListSize') continue;
    if (hasOwn.call(settings, definition.key)) {
      normalized[definition.key] = settings[definition.key];
    }
  }

  return normalized;
}

function _createUnsupportedError(methodName) {
  return _createError(
    'ERR_HTTP2_UNSUPPORTED',
    methodName + ' is not supported in this runtime without native HTTP/2 support'
  );
}

function createServer() {
  throw _createUnsupportedError('http2.createServer');
}

function createSecureServer() {
  throw _createUnsupportedError('http2.createSecureServer');
}

function connect() {
  throw _createUnsupportedError('http2.connect');
}

function performServerHandshake() {
  throw _createUnsupportedError('http2.performServerHandshake');
}

function getDefaultSettings() {
  return {
    headerTableSize: constants.DEFAULT_SETTINGS_HEADER_TABLE_SIZE,
    enablePush: true,
    initialWindowSize: constants.DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
    maxFrameSize: constants.DEFAULT_SETTINGS_MAX_FRAME_SIZE,
    maxConcurrentStreams: constants.DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS,
    maxHeaderSize: constants.DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
    maxHeaderListSize: constants.DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
    enableConnectProtocol: false
  };
}

function getPackedSettings(settings) {
  settings = _validateSettingsObject(settings);
  var normalized = _normalizePackedSettings(settings);
  var entries = [];

  for (var i = 0; i < _settingDefinitions.length; i++) {
    var definition = _settingDefinitions[i];
    if (!hasOwn.call(normalized, definition.key)) continue;
    entries.push({
      id: definition.id,
      value: _validateSettingValue(definition.key, normalized[definition.key], definition.type)
    });
  }

  var out = _alloc(entries.length * 6);
  for (var j = 0; j < entries.length; j++) {
    var offset = j * 6;
    _setUint16BE(out, offset, entries[j].id);
    _setUint32BE(out, offset + 2, entries[j].value);
  }
  return out;
}

function getUnpackedSettings(buf) {
  if (!_isTypedArray(buf)) {
    throw _createError(
      'ERR_INVALID_ARG_TYPE',
      'The "buf" argument must be an instance of Buffer or TypedArray'
    );
  }

  var bytes = _bufferFrom(buf);
  if ((bytes.length || 0) % 6 !== 0) {
    throw _createError(
      'ERR_HTTP2_INVALID_PACKED_SETTINGS_LENGTH',
      'Packed settings length must be a multiple of six'
    );
  }

  var settings = {};
  var custom = null;
  for (var i = 0; i < bytes.length; i += 6) {
    var id = _readUint16BE(bytes, i);
    var value = _readUint32BE(bytes, i + 2);
    if (id === constants.NGHTTP2_SETTINGS_HEADER_TABLE_SIZE) {
      settings.headerTableSize = value;
    } else if (id === constants.NGHTTP2_SETTINGS_ENABLE_PUSH) {
      settings.enablePush = value !== 0;
    } else if (id === constants.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
      settings.maxConcurrentStreams = value;
    } else if (id === constants.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE) {
      settings.initialWindowSize = value;
    } else if (id === constants.NGHTTP2_SETTINGS_MAX_FRAME_SIZE) {
      settings.maxFrameSize = value;
    } else if (id === constants.NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE) {
      settings.maxHeaderListSize = value;
    } else if (id === constants.NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) {
      settings.enableConnectProtocol = value !== 0;
    } else {
      if (!custom) custom = {};
      custom[id] = value;
    }
  }

  if (custom) settings.customSettings = custom;
  return settings;
}

function Http2ServerRequest(stream, headers) {
  if (!(this instanceof Http2ServerRequest)) return new Http2ServerRequest(stream, headers);
  this._events = {};
  _mixinEventEmitter(this);
  this.stream = stream || null;
  this.headers = headers || {};
  this.rawHeaders = [];
  this.rawTrailers = [];
  this.trailers = {};
  this.method = this.headers[constants.HTTP2_HEADER_METHOD] || null;
  this.authority = this.headers[constants.HTTP2_HEADER_AUTHORITY] || null;
  this.scheme = this.headers[constants.HTTP2_HEADER_SCHEME] || null;
  this.url = this.headers[constants.HTTP2_HEADER_PATH] || '/';
  this.httpVersion = '2.0';
  this.httpVersionMajor = 2;
  this.httpVersionMinor = 0;
  this.complete = false;
  this.aborted = false;
}

Http2ServerRequest.prototype.setTimeout = function(timeout, callback) {
  if (this.stream && typeof this.stream.setTimeout === 'function') {
    this.stream.setTimeout(timeout, callback);
  } else if (typeof callback === 'function' && typeof this.once === 'function') {
    this.once('timeout', callback);
  }
  return this;
};

Http2ServerRequest.prototype.pause = function() {
  if (this.stream && typeof this.stream.pause === 'function') this.stream.pause();
  return this;
};

Http2ServerRequest.prototype.resume = function() {
  if (this.stream && typeof this.stream.resume === 'function') this.stream.resume();
  return this;
};

Http2ServerRequest.prototype.destroy = function(err) {
  this.aborted = true;
  if (this.stream && typeof this.stream.destroy === 'function') this.stream.destroy(err);
  return this;
};

function Http2ServerResponse(stream) {
  if (!(this instanceof Http2ServerResponse)) return new Http2ServerResponse(stream);
  this._events = {};
  _mixinEventEmitter(this);
  this.stream = stream || null;
  this.statusCode = 200;
  this.statusMessage = '';
  this.sendDate = true;
  this.headersSent = false;
  this.finished = false;
  this.writableEnded = false;
  this.writableFinished = false;
  this._headers = Object.create(null);
  this._body = [];
}

Http2ServerResponse.prototype.setHeader = function(name, value) {
  this._headers[String(name).toLowerCase()] = value;
  return this;
};

Http2ServerResponse.prototype.getHeader = function(name) {
  return this._headers[String(name).toLowerCase()];
};

Http2ServerResponse.prototype.getHeaderNames = function() {
  return Object.keys(this._headers);
};

Http2ServerResponse.prototype.hasHeader = function(name) {
  return hasOwn.call(this._headers, String(name).toLowerCase());
};

Http2ServerResponse.prototype.removeHeader = function(name) {
  delete this._headers[String(name).toLowerCase()];
  return this;
};

Http2ServerResponse.prototype.writeHead = function(statusCode, statusMessage, headers) {
  this.statusCode = statusCode;
  if (typeof statusMessage === 'string') {
    this.statusMessage = statusMessage;
  } else if (statusMessage && typeof statusMessage === 'object') {
    headers = statusMessage;
  }
  if (headers) {
    for (var key in headers) {
      if (hasOwn.call(headers, key)) this.setHeader(key, headers[key]);
    }
  }
  return this;
};

Http2ServerResponse.prototype.flushHeaders = function() {
  this.headersSent = true;
  if (this.stream && typeof this.stream.respond === 'function') {
    var headers = {};
    headers[constants.HTTP2_HEADER_STATUS] = this.statusCode;
    for (var key in this._headers) {
      if (hasOwn.call(this._headers, key)) headers[key] = this._headers[key];
    }
    this.stream.respond(headers);
  }
  return this;
};

Http2ServerResponse.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  if (this.finished) {
    if (typeof callback === 'function') callback(new Error('write after end'));
    return false;
  }
  if (!this.headersSent) this.flushHeaders();
  if (chunk !== null && typeof chunk !== 'undefined') {
    this._body.push(chunk);
  }
  if (this.stream && typeof this.stream.write === 'function') {
    return this.stream.write(chunk, encoding, callback);
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  return true;
};

Http2ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') {
    callback = chunk;
    chunk = undefined;
    encoding = undefined;
  }
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }
  if (this.finished) {
    if (typeof callback === 'function') setTimeout(callback, 0);
    return this;
  }
  if (chunk !== null && typeof chunk !== 'undefined') {
    this.write(chunk, encoding);
  } else if (!this.headersSent) {
    this.flushHeaders();
  }
  this.finished = true;
  this.writableEnded = true;
  this.writableFinished = true;
  if (this.stream && typeof this.stream.end === 'function') {
    this.stream.end();
  }
  if (typeof callback === 'function') setTimeout(callback, 0);
  if (typeof this.emit === 'function') this.emit('finish');
  return this;
};

Http2ServerResponse.prototype.createPushResponse = function(_headers, callback) {
  var err = _createUnsupportedError('http2 push');
  if (typeof callback === 'function') setTimeout(function() { callback(err); }, 0);
};

module.exports = {
  constants: constants,
  sensitiveHeaders: sensitiveHeaders,
  Http2ServerRequest: Http2ServerRequest,
  Http2ServerResponse: Http2ServerResponse,
  createServer: createServer,
  createSecureServer: createSecureServer,
  connect: connect,
  performServerHandshake: performServerHandshake,
  getDefaultSettings: getDefaultSettings,
  getPackedSettings: getPackedSettings,
  getUnpackedSettings: getUnpackedSettings
};
module.exports.default = module.exports;
