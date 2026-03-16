var EventEmitter = require('events').EventEmitter;
var Readable = null;
function getReadableCtor() {
  if (Readable) return Readable;
  try {
    var streamModule = require('node:stream');
    if (streamModule && typeof streamModule.Readable === 'function') {
      Readable = streamModule.Readable;
    }
  } catch (_streamErr) {}
  return Readable;
}

function upgradeTcpIncomingMessagePrototype() {
  var ReadableCtor = getReadableCtor();
  if (!ReadableCtor) return null;
  if (TcpIncomingMessage.prototype && TcpIncomingMessage.prototype._usesReadablePrototype) {
    return ReadableCtor;
  }

  var currentProto = TcpIncomingMessage.prototype;
  var nextProto = Object.create(ReadableCtor.prototype);
  if (currentProto) {
    var names = Object.getOwnPropertyNames(currentProto);
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (name === 'constructor') continue;
      Object.defineProperty(nextProto, name, Object.getOwnPropertyDescriptor(currentProto, name));
    }
  }
  Object.defineProperty(nextProto, '_usesReadablePrototype', {
    value: true,
    writable: true,
    configurable: true
  });
  nextProto.constructor = TcpIncomingMessage;
  TcpIncomingMessage.prototype = nextProto;
  return ReadableCtor;
}

// Shared symbol for timeout tracking (matches internal/timers)
var kTimeout = Symbol.for('kTimeout');
var kOutHeaders = Symbol.for('nodejs.http.outHeadersKey');
var captureRejectionSymbol = typeof Symbol === 'function' && typeof Symbol.for === 'function'
  ? Symbol.for('nodejs.rejection')
  : null;

// Header name validation regex
var HEADER_NAME_RE = /^[\^_`a-zA-Z\-0-9\!#$%&'*+.|~]+$/;
var DEFAULT_OUTGOING_HIGH_WATER_MARK = 64 * 1024;

function validateHeaderName(name) {
  if (typeof name !== 'string' || !HEADER_NAME_RE.test(name)) {
    var err = new TypeError('Header name must be a valid HTTP token ["' + String(name) + '"]');
    err.code = 'ERR_INVALID_HTTP_TOKEN';
    throw err;
  }
}

function validateHeaderValue(name, value) {
  if (value === undefined) {
    var err = new TypeError('Invalid value "undefined" for header "' + name + '"');
    err.code = 'ERR_HTTP_INVALID_HEADER_VALUE';
    throw err;
  }
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      validateHeaderValue(name, value[i]);
    }
    return;
  }
  if (_checkInvalidHeaderChar(String(value))) {
    throw _createInvalidHeaderContentError(name, 'header');
  }
}

function resolveHeaderName(value) {
  if (typeof value !== 'string') {
    return String(value || '');
  }
  return value.toLowerCase();
}

function getDefaultOutgoingHighWaterMark() {
  try {
    var streamModule = require('node:stream');
    if (streamModule && typeof streamModule.getDefaultHighWaterMark === 'function') {
      return streamModule.getDefaultHighWaterMark(false);
    }
  } catch (_streamErr) {}
  return DEFAULT_OUTGOING_HIGH_WATER_MARK;
}

function _createInvalidHeaderContentError(name, kind) {
  var err = new TypeError('Invalid character in ' + kind + ' content ["' + String(name) + '"]');
  err.code = 'ERR_INVALID_CHAR';
  return err;
}

function _createNullWriteError() {
  var err = new TypeError('May not write null values to stream');
  err.code = 'ERR_STREAM_NULL_VALUES';
  return err;
}

function _createInvalidChunkTypeError(chunk) {
  var received;
  if (chunk === undefined) {
    received = 'Received undefined';
  } else {
    received = 'Received type ' + typeof chunk + ' (' + String(chunk) + ')';
  }
  var err = new TypeError(
    'The "chunk" argument must be of type string or an instance of Buffer or Uint8Array. ' + received
  );
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _createStreamDestroyedError() {
  var err = new Error('Cannot call write after a stream was destroyed');
  err.code = 'ERR_STREAM_DESTROYED';
  return err;
}

function _createMethodNotImplementedError(methodName) {
  var err = new Error('The ' + methodName + '() method is not implemented');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  return err;
}

function _createCannotPipeError() {
  var err = new Error('Cannot pipe, not readable');
  err.code = 'ERR_STREAM_CANNOT_PIPE';
  return err;
}

function _isOutgoingChunk(chunk) {
  return typeof chunk === 'string' ||
    (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) ||
    (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(chunk));
}

function _getOutgoingChunkLength(chunk, encoding) {
  if (typeof chunk === 'string') {
    if (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function') {
      return Buffer.byteLength(chunk, encoding || 'utf8');
    }
    return chunk.length;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
    return chunk.length;
  }
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
    return chunk.byteLength;
  }
  return 0;
}

function _toOutgoingBodyPart(chunk, encoding) {
  if (chunk == null) return null;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof Buffer !== 'undefined' &&
      typeof ArrayBuffer !== 'undefined' &&
      ArrayBuffer.isView &&
      ArrayBuffer.isView(chunk)) {
    var _len = chunk.byteLength || chunk.length || 0;
    var _copy = Buffer.alloc(_len);
    _copy.set(new Uint8Array(chunk.buffer, chunk.byteOffset || 0, _len));
    return _copy;
  }
  if (typeof Buffer !== 'undefined') {
    if (typeof chunk === 'string') {
      return Buffer.from(chunk, encoding || 'utf8');
    }
    return Buffer.from(String(chunk), encoding || 'utf8');
  }
  return typeof chunk === 'string' ? chunk : String(chunk);
}

function _concatOutgoingBodyParts(parts) {
  if (!parts || parts.length === 0) {
    return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : '';
  }
  if (typeof Buffer !== 'undefined') {
    var buffers = [];
    var total = 0;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (part == null) continue;
      var buf = Buffer.isBuffer(part) ? part : Buffer.from(String(part), 'utf8');
      buffers.push(buf);
      total += buf.length;
    }
    return buffers.length > 0 ? Buffer.concat(buffers, total) : Buffer.alloc(0);
  }
  return parts.join('');
}

function _getOutgoingBodyPartLength(part) {
  if (part == null) return 0;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(part)) {
    return part.length;
  }
  if (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function') {
    return Buffer.byteLength(String(part));
  }
  return String(part).length;
}

function _hasChunkedTransferEncoding(value) {
  return value != null && String(value).toLowerCase().indexOf('chunked') !== -1;
}

function _responseCanHaveBody(statusCode, method) {
  if (method === 'HEAD') return false;
  return !(statusCode >= 100 && statusCode < 200) &&
    statusCode !== 204 &&
    statusCode !== 304;
}

function _ensureOutgoingHeaderState(target) {
  if (!target._headers || typeof target._headers !== 'object') target._headers = {};
  if (!target._headerNames || typeof target._headerNames !== 'object') target._headerNames = {};
  if (!target._removedHeaderNames || typeof target._removedHeaderNames !== 'object') {
    target._removedHeaderNames = {};
  }
}

function _ensureOutgoingBufferState(target) {
  if (!target.outputData || !Array.isArray(target.outputData)) target.outputData = [];
  if (typeof target.outputSize !== 'number') target.outputSize = 0;
}

function _recordOutgoingBytes(target, size) {
  _ensureOutgoingBufferState(target);
  if (!size) return;
  target.outputSize += size;
}

function _consumeOutgoingBytes(target, size) {
  _ensureOutgoingBufferState(target);
  if (!size) return;
  target.outputSize -= size;
  if (target.outputSize < 0) {
    target.outputSize = 0;
  }
}

function _resetOutgoingBufferState(target) {
  _ensureOutgoingBufferState(target);
  target.outputData.length = 0;
  target.outputSize = 0;
}

function _scheduleOutgoingDrainFallback(target) {
  if (!target || target._drainFallbackScheduled) return;
  target._drainFallbackScheduled = true;
  var emitDrain = function() {
    target._drainFallbackScheduled = false;
    if (target.destroyed || target._closed || target.closed) return;
    _resetOutgoingBufferState(target);
    if (typeof target.emit === 'function') {
      target.emit('drain');
    }
  };
  if (typeof process !== 'undefined' && process && typeof process.nextTick === 'function') {
    process.nextTick(emitDrain);
  } else {
    setTimeout(emitDrain, 0);
  }
}

function _validateTrailerName(name) {
  if (typeof name !== 'string' || !HEADER_NAME_RE.test(name)) {
    var err = new TypeError('Trailer name must be a valid HTTP token ["' + String(name) + '"]');
    err.code = 'ERR_INVALID_HTTP_TOKEN';
    throw err;
  }
}

function _validateTrailerValue(name, value) {
  if (value === undefined) {
    var err = new TypeError('Invalid value "undefined" for trailer "' + name + '"');
    err.code = 'ERR_HTTP_INVALID_HEADER_VALUE';
    throw err;
  }
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      _validateTrailerValue(name, value[i]);
    }
    return;
  }
  if (_checkInvalidHeaderChar(String(value))) {
    throw _createInvalidHeaderContentError(name, 'trailer');
  }
}

function _appendIncomingTrailerValue(target, rawTarget, name, value) {
  if (!target || !rawTarget) return;
  var lowerName = resolveHeaderName(name);
  if (target[lowerName] === undefined) {
    target[lowerName] = value;
  } else if (Array.isArray(target[lowerName])) {
    target[lowerName].push(value);
  } else {
    target[lowerName] = [target[lowerName], value];
  }
  rawTarget.push(name, value);
}

function _parseTrailerSection(section, target, rawTarget) {
  if (!section || !target || !rawTarget) return;
  var lines = section.split('\r\n');
  for (var i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    var colonIdx = lines[i].indexOf(':');
    if (colonIdx <= 0) continue;
    var name = lines[i].substring(0, colonIdx).trim();
    var value = lines[i].substring(colonIdx + 1).trim();
    _appendIncomingTrailerValue(target, rawTarget, name, value);
  }
}

function _formatOutgoingTrailers(headers, headerNames) {
  if (!headers || typeof headers !== 'object') return '';
  var trailer = '';
  for (var key in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, key)) continue;
    var casedName = (headerNames && headerNames[key]) || key;
    var value = headers[key];
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) {
        trailer += casedName + ': ' + value[i] + '\r\n';
      }
    } else {
      trailer += casedName + ': ' + value + '\r\n';
    }
  }
  return trailer;
}

function _hasOutgoingTrailers(target) {
  if (!target || !target._trailers) return false;
  for (var key in target._trailers) {
    if (Object.prototype.hasOwnProperty.call(target._trailers, key)) {
      return true;
    }
  }
  return false;
}

function _invalidTimeoutTypeError(value) {
  var err = new TypeError('The "timeout" argument must be of type number.' +
    _invalidArgTypeHelper(value));
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _validateTimeoutValue(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw _invalidTimeoutTypeError(value);
  }
  if (!isFinite(value) || value < 0 || value > 2147483647) {
    var err = new RangeError('The value of "timeout" is out of range. It must be >= 0 && <= 2147483647. Received ' + value);
    err.code = 'ERR_OUT_OF_RANGE';
    throw err;
  }
  return Math.floor(value);
}

function initOutgoingMessage(target) {
  _ensureOutgoingHeaderState(target);
  target[kOutHeaders] = null;
  target._header = null;
  target._headersSent = false;
  target._isOutgoingMessage = true;
  target._hasBody = true;
  target.outputData = [];
  target.outputSize = 0;
  target._outgoingHighWaterMark = getDefaultOutgoingHighWaterMark();
  target.writable = true;
  target.finished = false;
  target.writableEnded = false;
  target.writableFinished = false;
  target.writableCorked = 0;
  target.destroyed = false;
  target._closed = false;
  target.closed = false;
  target.errored = undefined;
  if (target.socket === undefined) {
    target.socket = null;
  }
}

function OutgoingMessage() {
  EventEmitter.call(this);
  initOutgoingMessage(this);
}
OutgoingMessage.prototype = Object.create(EventEmitter.prototype);
OutgoingMessage.prototype.constructor = OutgoingMessage;

Object.defineProperty(OutgoingMessage.prototype, 'headersSent', {
  get: function() {
    return this._header !== null || !!this._headersSent;
  },
  set: function(value) {
    this._headersSent = !!value;
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(OutgoingMessage.prototype, 'connection', {
  get: function() {
    return this.socket;
  },
  set: function(value) {
    this.socket = value;
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(OutgoingMessage.prototype, 'writableObjectMode', {
  get: function() {
    return false;
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(OutgoingMessage.prototype, 'writableHighWaterMark', {
  get: function() {
    if (this.socket && typeof this.socket.writableHighWaterMark === 'number') {
      return this.socket.writableHighWaterMark;
    }
    return this._outgoingHighWaterMark || getDefaultOutgoingHighWaterMark();
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(OutgoingMessage.prototype, 'writableLength', {
  get: function() {
    var socketLength = this.socket && typeof this.socket.writableLength === 'number'
      ? this.socket.writableLength
      : 0;
    var outputSize = typeof this.outputSize === 'number' ? this.outputSize : 0;
    return socketLength + outputSize;
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(OutgoingMessage.prototype, 'writableNeedDrain', {
  get: function() {
    return this.writableLength >= this.writableHighWaterMark;
  },
  enumerable: true,
  configurable: true
});

OutgoingMessage.prototype._implicitHeader = function() {
  throw _createMethodNotImplementedError('_implicitHeader');
};

OutgoingMessage.prototype.setHeader = function(name, value) {
  if (this._header !== null || this._headersSent) {
    throw _createHeadersSentError('set');
  }
  validateHeaderName(name);
  name = String(name);
  validateHeaderValue(name, value);
  _ensureOutgoingHeaderState(this);
  var lc = resolveHeaderName(name);
  this._headers[lc] = value;
  this._headerNames[lc] = name;
  delete this._removedHeaderNames[lc];
  if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
    this[kOutHeaders] = {};
  }
  this[kOutHeaders][lc] = [name, value];
  return this;
};

OutgoingMessage.prototype.getHeader = function(name) {
  _validateHeaderLookupName(name);
  return this._headers[resolveHeaderName(name)];
};

OutgoingMessage.prototype.removeHeader = function(name) {
  if (this._header !== null || this._headersSent) {
    throw _createHeadersSentError('remove');
  }
  _validateHeaderLookupName(name);
  validateHeaderName(name);
  name = String(name);
  _ensureOutgoingHeaderState(this);
  var lc = resolveHeaderName(name);
  delete this._headers[lc];
  delete this._headerNames[lc];
  this._removedHeaderNames[lc] = true;
  if (this[kOutHeaders] && typeof this[kOutHeaders] === 'object') {
    delete this[kOutHeaders][lc];
  }
  return this;
};

OutgoingMessage.prototype.getHeaders = function() {
  var clone = Object.create(null);
  for (var key in this._headers) {
    if (Object.prototype.hasOwnProperty.call(this._headers, key)) {
      clone[key] = this._headers[key];
    }
  }
  return clone;
};

OutgoingMessage.prototype.getHeaderNames = function() {
  return Object.keys(this._headers || {});
};

OutgoingMessage.prototype.getRawHeaderNames = function() {
  var result = [];
  for (var key in this._headerNames) {
    if (Object.prototype.hasOwnProperty.call(this._headerNames, key)) {
      result.push(this._headerNames[key]);
    }
  }
  return result;
};

OutgoingMessage.prototype.hasHeader = function(name) {
  _validateHeaderLookupName(name);
  return resolveHeaderName(name) in (this._headers || {});
};

OutgoingMessage.prototype._renderHeaders = function() {
  if (this._header !== null) {
    var sentErr = new Error('Cannot render headers after they are sent to the client');
    sentErr.code = 'ERR_HTTP_HEADERS_SENT';
    throw sentErr;
  }
  var source = this[kOutHeaders];
  if (!source || typeof source !== 'object') return {};
  var rendered = {};
  for (var key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    var entry = source[key];
    if (Array.isArray(entry) && entry.length >= 2) {
      rendered[entry[0]] = entry[1];
    }
  }
  return rendered;
};

OutgoingMessage.prototype.addTrailers = function(headers) {
  if (arguments.length === 0 || headers == null) {
    throw new TypeError('Cannot convert undefined or null to object');
  }
  this._trailers = this._trailers || {};
  this._trailerNames = this._trailerNames || {};
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    _validateTrailerName(name);
    _validateTrailerValue(name, headers[name]);
    var lc = resolveHeaderName(name);
    this._trailers[lc] = headers[name];
    this._trailerNames[lc] = name;
  }
};

OutgoingMessage.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = undefined;
  }

  if (this.destroyed) {
    var destroyedErr = _createStreamDestroyedError();
    if (callback) {
      setTimeout(function() {
        callback(destroyedErr);
      }, 0);
    }
    return false;
  }
  if (chunk === null) {
    throw _createNullWriteError();
  }
  if (!_isOutgoingChunk(chunk)) {
    throw _createInvalidChunkTypeError(chunk);
  }

  if (this._header === null) {
    this._implicitHeader();
  }

  var length = _getOutgoingChunkLength(chunk, encoding);
  // Empty string/buffer writes are no-ops (Node.js behavior)
  if (length === 0) {
    if (typeof callback === 'function') {
      setTimeout(callback, 0);
    }
    return true;
  }
  if (this.socket && typeof this.socket.write === 'function') {
    _recordOutgoingBytes(this, length);
    return this.socket.write(
      chunk,
      encoding,
      typeof callback === 'function'
        ? function() { setTimeout(callback, 0); }
        : undefined
    );
  }

  _ensureOutgoingBufferState(this);
  this.outputData.push(chunk);
  _recordOutgoingBytes(this, length);
  if (typeof callback === 'function') {
    setTimeout(callback, 0);
  }
  return this.writableLength < this.writableHighWaterMark;
};

OutgoingMessage.prototype.end = function(chunk, encoding, callback) {
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
    if (typeof callback === 'function') {
      setTimeout(callback, 0);
    }
    return this;
  }

  if (this._header === null) {
    this._implicitHeader();
  }
  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }

  this.finished = true;
  this._finished = true;
  this.writableEnded = true;
  var self = this;
  function finish() {
    if (self.writableFinished) return;
    _resetOutgoingBufferState(self);
    self.writableFinished = true;
    if (typeof callback === 'function') {
      callback();
    }
    self.emit('finish');
  }

  if (this.socket && typeof this.socket.end === 'function') {
    this.socket.end('', function() {
      setTimeout(finish, 0);
    });
  } else {
    setTimeout(finish, 0);
  }
  return this;
};

OutgoingMessage.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  this.destroyed = true;
  this._closed = true;
  this.closed = true;
  _resetOutgoingBufferState(this);
  if (this.socket && typeof this.socket.destroy === 'function' && !this.socket.destroyed) {
    try {
      this.socket.destroy(err);
    } catch (_destroyErr) {}
  }
  if (err) {
    this.errored = err;
    this.emit('error', err);
  }
  this.emit('close');
  return this;
};

if (captureRejectionSymbol) {
  OutgoingMessage.prototype[captureRejectionSymbol] = function(err) {
    this.destroy(err);
  };
}

OutgoingMessage.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') {
    this.once('timeout', callback);
  }
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs);
  } else {
    this.once('socket', function(socket) {
      if (socket && typeof socket.setTimeout === 'function') {
        socket.setTimeout(msecs);
      }
    });
  }
  return this;
};

OutgoingMessage.prototype.flushHeaders = function() {
  if (this._header === null) {
    this._implicitHeader();
  }
};

OutgoingMessage.prototype.cork = function() {
  this.writableCorked += 1;
};

OutgoingMessage.prototype.uncork = function() {
  if (this.writableCorked > 0) {
    this.writableCorked -= 1;
  }
};

OutgoingMessage.prototype.pipe = function() {
  throw _createCannotPipeError();
};

function _createHttpAsyncIterator(message, options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    var optionsErr = new TypeError('The "options" argument must be of type object. Received type ' + typeof options + ' (' + options + ')');
    optionsErr.code = 'ERR_INVALID_ARG_TYPE';
    throw optionsErr;
  }

  var queue = [];
  var finishedState;
  var pendingResolve = null;
  var cleanedUp = false;

  function wake() {
    if (!pendingResolve) return;
    var resolve = pendingResolve;
    pendingResolve = null;
    resolve();
  }

  function onData(chunk) {
    queue.push(chunk);
    wake();
  }

  function onEnd() {
    finishedState = null;
    wake();
  }

  function onError(err) {
    finishedState = err || new Error('Stream error');
    wake();
  }

  function onClose() {
    if (finishedState === undefined) {
      finishedState = null;
    }
    wake();
  }

  function cleanup() {
    if (cleanedUp || !message) return;
    cleanedUp = true;
    if (typeof message.off === 'function') {
      message.off('data', onData);
      message.off('end', onEnd);
      message.off('error', onError);
      message.off('close', onClose);
    } else if (typeof message.removeListener === 'function') {
      message.removeListener('data', onData);
      message.removeListener('end', onEnd);
      message.removeListener('error', onError);
      message.removeListener('close', onClose);
    }
  }

  if (message && typeof message.on === 'function') {
    message.on('data', onData);
    message.on('end', onEnd);
    message.on('error', onError);
    message.on('close', onClose);
  }

  if (message && typeof message.resume === 'function') {
    message.resume();
  }

  return {
    next: function() {
      return (async function() {
        while (true) {
          if (queue.length > 0) {
            return { value: queue.shift(), done: false };
          }
          if (finishedState) {
            cleanup();
            throw finishedState;
          }
          if (finishedState === null) {
            cleanup();
            return { value: undefined, done: true };
          }
          await new Promise(function(resolve) {
            pendingResolve = resolve;
          });
        }
      })();
    },
    return: function() {
      cleanup();
      finishedState = null;
      if ((!options || options.destroyOnReturn !== false) && message && typeof message.destroy === 'function' && !message.destroyed) {
        message.destroy();
      }
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      cleanup();
      finishedState = err || new Error('Stream iterator error');
      if (message && typeof message.destroy === 'function' && !message.destroyed) {
        message.destroy(finishedState);
      }
      return Promise.reject(finishedState);
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
}

function _attachHttpAsyncIterator(proto) {
  if (!proto) return;
  proto.iterator = function(options) {
    return _createHttpAsyncIterator(this, options);
  };
  proto[Symbol.asyncIterator] = function(options) {
    return _createHttpAsyncIterator(this, options);
  };
}

// Convert a lowercase header name to HTTP title case (e.g. content-length -> Content-Length)
function toHeaderCase(name) {
  return name.replace(/(?:^|-)([a-z])/g, function(match, letter, offset) {
    return offset === 0 ? letter.toUpperCase() : '-' + letter.toUpperCase();
  });
}

// Headers that should NOT be comma-joined (single value only)
var _singleValueHeaders = {
  'age': true, 'authorization': true, 'content-length': true,
  'content-type': true, 'etag': true, 'expires': true, 'from': true,
  'host': true, 'if-modified-since': true, 'if-unmodified-since': true,
  'last-modified': true, 'location': true, 'max-forwards': true,
  'proxy-authorization': true, 'referer': true, 'retry-after': true,
  'server': true, 'user-agent': true
};

function _appendIncomingHeaderValue(dest, key, value) {
  if (key === 'set-cookie') {
    if (dest[key] !== undefined) {
      if (Array.isArray(dest[key])) {
        dest[key].push(value);
      } else {
        dest[key] = [dest[key], value];
      }
    } else {
      dest[key] = [value];
    }
    return;
  }

  if (dest[key] !== undefined) {
    if (_singleValueHeaders[key]) {
      return;
    }
    if (key === 'cookie') {
      dest[key] = dest[key] + '; ' + value;
    } else {
      dest[key] = dest[key] + ', ' + value;
    }
    return;
  }

  dest[key] = value;
}

function _cloneOutgoingHeaderValue(value) {
  return Array.isArray(value) ? value.slice() : value;
}

function _normalizeOutgoingHeaderValue(name, value) {
  if (Array.isArray(value)) {
    if (resolveHeaderName(name) === 'host') {
      var hostErr = new TypeError('The "options.headers.host" property must be of type string.');
      hostErr.code = 'ERR_INVALID_ARG_TYPE';
      throw hostErr;
    }
    var normalized = new Array(value.length);
    for (var i = 0; i < value.length; i++) {
      validateHeaderValue(String(name), value[i]);
      normalized[i] = String(value[i]);
    }
    return normalized;
  }
  validateHeaderValue(String(name), value);
  return String(value);
}

function _removeClientRequestHeaderEntries(target, lowerName) {
  if (!target || !target._headerList || !target._headerList.length) return;
  var next = [];
  for (var i = 0; i < target._headerList.length; i++) {
    var pair = target._headerList[i];
    if (resolveHeaderName(pair[0]) !== lowerName) {
      next.push(pair);
    }
  }
  target._headerList = next;
}

function _appendClientRequestHeaderEntries(target, headerName, value) {
  if (!target._headerList) target._headerList = [];
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      target._headerList.push([headerName, value[i]]);
    }
    return;
  }
  target._headerList.push([headerName, value]);
}

function _setClientRequestHeaderState(target, headerName, value, appendOnly) {
  validateHeaderName(headerName);
  var lowerName = resolveHeaderName(headerName);
  var normalizedValue = _normalizeOutgoingHeaderValue(headerName, value);
  if (!appendOnly) {
    _removeClientRequestHeaderEntries(target, lowerName);
  }
  _appendClientRequestHeaderEntries(target, headerName, normalizedValue);
  target.headers[lowerName] = _cloneOutgoingHeaderValue(normalizedValue);
  target._headerNames[lowerName] = headerName;
  if (!target[kOutHeaders] || typeof target[kOutHeaders] !== 'object') {
    target[kOutHeaders] = {};
  }
  target[kOutHeaders][lowerName] = [headerName, _cloneOutgoingHeaderValue(normalizedValue)];
}

function _initializeClientRequestHeaders(target, source) {
  target.headers = {};
  target._headerNames = {};
  target._headerList = [];
  target[kOutHeaders] = {};

  if (!source || typeof source !== 'object') return;

  if (Array.isArray(source)) {
    if (source.length > 0 && Array.isArray(source[0])) {
      for (var i = 0; i < source.length; i++) {
        var pair = source[i];
        if (!Array.isArray(pair) || pair.length < 2) continue;
        var pairName = String(pair[0]);
        var pairValue = _normalizeOutgoingHeaderValue(pairName, pair[1]);
        var pairLowerName = resolveHeaderName(pairName);
        _appendClientRequestHeaderEntries(target, pairName, pairValue);
        if (target.headers[pairLowerName] === undefined) {
          target.headers[pairLowerName] = _cloneOutgoingHeaderValue(pairValue);
        } else if (!_singleValueHeaders[pairLowerName]) {
          if (Array.isArray(target.headers[pairLowerName])) {
            if (Array.isArray(pairValue)) {
              Array.prototype.push.apply(target.headers[pairLowerName], pairValue);
            } else {
              target.headers[pairLowerName].push(pairValue);
            }
          } else if (Array.isArray(pairValue)) {
            target.headers[pairLowerName] = [target.headers[pairLowerName]].concat(pairValue);
          } else if (pairLowerName === 'cookie') {
            target.headers[pairLowerName] = target.headers[pairLowerName] + '; ' + pairValue;
          } else {
            target.headers[pairLowerName] = [target.headers[pairLowerName], pairValue];
          }
        }
        target._headerNames[pairLowerName] = pairName;
        target[kOutHeaders][pairLowerName] = [pairName, _cloneOutgoingHeaderValue(target.headers[pairLowerName])];
      }
      return;
    }
    if (source.length % 2 !== 0) {
      var headersErr = new TypeError('The argument \'headers\' is invalid. Received ' + JSON.stringify(source));
      headersErr.code = 'ERR_INVALID_ARG_VALUE';
      throw headersErr;
    }
    for (var j = 0; j + 1 < source.length; j += 2) {
      var headerName = String(source[j]);
      var headerValue = _normalizeOutgoingHeaderValue(headerName, source[j + 1]);
      var lowerName = resolveHeaderName(headerName);
      _appendClientRequestHeaderEntries(target, headerName, headerValue);
      if (target.headers[lowerName] === undefined) {
        target.headers[lowerName] = _cloneOutgoingHeaderValue(headerValue);
      } else if (!_singleValueHeaders[lowerName]) {
        if (Array.isArray(target.headers[lowerName])) {
          if (Array.isArray(headerValue)) {
            Array.prototype.push.apply(target.headers[lowerName], headerValue);
          } else {
            target.headers[lowerName].push(headerValue);
          }
        } else if (Array.isArray(headerValue)) {
          target.headers[lowerName] = [target.headers[lowerName]].concat(headerValue);
        } else {
          target.headers[lowerName] = [target.headers[lowerName], headerValue];
        }
      }
      target._headerNames[lowerName] = headerName;
      target[kOutHeaders][lowerName] = [headerName, _cloneOutgoingHeaderValue(target.headers[lowerName])];
    }
    return;
  }

  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      _setClientRequestHeaderState(target, String(key), source[key], false);
    }
  }
}

function _appendClientRequestHeaderLines(request, list) {
  if (!request || !list) return;
  for (var i = 0; i < request._headerList.length; i++) {
    var pair = request._headerList[i];
    list.push(pair[0] + ': ' + pair[1] + '\r\n');
  }
}

function _clientRequestHasHeader(request, lowerName) {
  return !!request &&
    !!request.headers &&
    Object.prototype.hasOwnProperty.call(request.headers, lowerName);
}

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + input.name;
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
}

function _validateHeaderLookupName(name) {
  if (typeof name !== 'string') {
    var err = new TypeError('The "name" argument must be of type string.' + _invalidArgTypeHelper(name));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

function toHttpUrl(options) {
  if (typeof options === "string") {
    return options;
  }
  if (options === null || options === undefined) {
    throw new TypeError("Invalid request target");
  }
  if (typeof options === "object") {
    if (typeof options.toString === "function" && options instanceof Date) {
      return String(options);
    }
    if (typeof options.href === "string") return options.href;
    if (typeof options.url === "string") return options.url;
    var protocol = options.protocol || "http:";
    var hostname = options.hostname || options.host || "localhost";
    // Strip port from host if combined
    if (hostname.indexOf(':') !== -1 && hostname.charAt(0) !== '[') {
      var hostParts = hostname.split(':');
      hostname = hostParts[0];
      if (!options.port && hostParts[1]) {
        options.port = hostParts[1];
      }
    }
    var port = options.port ? ":" + options.port : "";
    var path = options.path;
    if (path === undefined) {
      var pathname = options.pathname || "/";
      var search = options.search || "";
      var hash = options.hash || "";
      if (search && search.charAt(0) !== "?") {
        search = "?" + search;
      }
      if (hash && hash.charAt(0) !== '#') {
        hash = '#' + hash;
      }
      path = pathname + search + hash;
    }
    return protocol + "//" + hostname + port + path;
  }
  throw new TypeError("Invalid request target");
}

function toHttpPath(options) {
  if (!options) return "/";
  if (typeof options === "string") return "/";
  var p = options.path;
  if (p === undefined) {
    var pathname = options.pathname || "/";
    var search = options.search || "";
    var hash = options.hash || "";
    if (search && search.charAt(0) !== "?") {
      search = "?" + search;
    }
    if (hash && hash.charAt(0) !== '#') {
      hash = '#' + hash;
    }
    p = pathname + search + hash;
  }
  // Empty string path should default to "/" (Node.js behavior)
  if (!p) p = "/";
  return p;
}

function normalizeClientRequestOptions(options) {
  if (typeof options === 'string') {
    try {
      var parsedUrl = new URL(options);
      return {
        __exactOriginalUrl: options,
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port ? Number(parsedUrl.port) : undefined,
        path: parsedUrl.pathname + (parsedUrl.search || ''),
        method: 'GET'
      };
    } catch (_parseClientRequestUrlErr) {
      return { href: options, method: 'GET' };
    }
  }
  if (options instanceof URL) {
    var normalizedUrlOptions = {
      protocol: options.protocol,
      hostname: options.hostname,
      port: options.port ? Number(options.port) : undefined,
      path: options.pathname + (options.search || ''),
      method: 'GET'
    };
    for (var optionKey in options) {
      if (Object.prototype.hasOwnProperty.call(options, optionKey)) {
        normalizedUrlOptions[optionKey] = options[optionKey];
      }
    }
    return normalizedUrlOptions;
  }
  if (options && typeof options === 'object') {
    // Handle server.address() style objects: { address, family, port }
    // Map 'address' to 'hostname' if hostname/host not already set
    if (options.address && !options.hostname && !options.host) {
      options = Object.assign({}, options);
      options.hostname = options.address;
    }
  }
  return options;
}

function validateClientRequestPath(path) {
  if (path == null) return;
  var pathString = String(path);
  if (/[^\u0021-\u00ff]/.test(pathString)) {
    var err = new TypeError('Request path contains unescaped characters');
    err.code = 'ERR_UNESCAPED_CHARACTERS';
    throw err;
  }
}

function hasUrlOptionOverrides(options) {
  if (!options || typeof options !== "object") return false;
  return (
    Object.prototype.hasOwnProperty.call(options, "href") ||
    Object.prototype.hasOwnProperty.call(options, "url") ||
    Object.prototype.hasOwnProperty.call(options, "protocol") ||
    Object.prototype.hasOwnProperty.call(options, "hostname") ||
    Object.prototype.hasOwnProperty.call(options, "host") ||
    Object.prototype.hasOwnProperty.call(options, "port") ||
    Object.prototype.hasOwnProperty.call(options, "path") ||
    Object.prototype.hasOwnProperty.call(options, "pathname") ||
    Object.prototype.hasOwnProperty.call(options, "search") ||
    Object.prototype.hasOwnProperty.call(options, "hash")
  );
}

function toMethod(options) {
  var m = (options && options.method) || "GET";
  // Empty string should default to GET (Node.js behavior)
  if (!m) m = "GET";
  return m.toUpperCase();
}

function toHeaders(source) {
  if (!source || typeof source !== "object") return {};
  var out = {};
  if (Array.isArray(source)) {
    for (var i = 0; i < source.length; i++) {
      var entry = source[i];
      if (!Array.isArray(entry) || entry.length < 2) continue;
      var entryKey = String(entry[0]);
      var entryValue = entry[1];
      var entryHeaderName = resolveHeaderName(entryKey);
      validateHeaderName(entryKey);
      if (Array.isArray(entryValue)) {
        if (entryHeaderName === 'host') {
          var hostArrayErr = new TypeError('The "options.headers.host" property must be of type string.');
          hostArrayErr.code = 'ERR_INVALID_ARG_TYPE';
          throw hostArrayErr;
        }
        entryValue = entryValue.map(function(item) {
          validateHeaderValue(entryKey, item);
          return String(item);
        }).join(entryHeaderName === 'cookie' ? '; ' : ', ');
      } else {
        validateHeaderValue(entryKey, entryValue);
        entryValue = String(entryValue);
      }
      if (out[entryHeaderName] !== undefined && !_singleValueHeaders[entryHeaderName]) {
        out[entryHeaderName] += (entryHeaderName === 'cookie' ? '; ' : ', ') + entryValue;
      } else {
        out[entryHeaderName] = entryValue;
      }
    }
    return out;
  }
  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      var val = source[key];
      var headerName = resolveHeaderName(key);
      validateHeaderName(String(key));
      if (Array.isArray(val)) {
        if (headerName === 'host') {
          var hostErr = new TypeError('The "options.headers.host" property must be of type string.');
          hostErr.code = 'ERR_INVALID_ARG_TYPE';
          throw hostErr;
        }
        out[headerName] = val.map(function(item) {
          validateHeaderValue(String(key), item);
          return String(item);
        }).join(headerName === 'cookie' ? '; ' : ', ');
      } else {
        validateHeaderValue(String(key), val);
        out[headerName] = String(val);
      }
    }
  }
  return out;
}

function applyOutgoingHeaderEntries(target, headers) {
  if (!target || !headers) return;
  if (Array.isArray(headers) && headers.length > 0 && Array.isArray(headers[0])) {
    for (var i = 0; i < headers.length; i++) {
      var pair = headers[i];
      if (!Array.isArray(pair) || pair.length !== 2) {
        var pairHeadersErr = new TypeError('The argument \'headers\' is invalid. Received ' + JSON.stringify(headers));
        pairHeadersErr.code = 'ERR_INVALID_ARG_VALUE';
        throw pairHeadersErr;
      }
      var pairName = String(pair[0]);
      var pairValue = pair[1];
      validateHeaderName(pairName);
      validateHeaderValue(pairName, pairValue);
      var pairLc = resolveHeaderName(pairName);
      target._headers[pairLc] = pairValue;
      target._headerNames[pairLc] = pairName;
      delete target._removedHeaderNames[pairLc];
      if (!target[kOutHeaders] || typeof target[kOutHeaders] !== 'object') {
        target[kOutHeaders] = {};
      }
      target[kOutHeaders][pairLc] = [pairName, pairValue];
    }
    return;
  }
  if (Array.isArray(headers)) {
    if (headers.length % 2 !== 0) {
      var headersErr = new TypeError('The argument \'headers\' is invalid. Received ' + JSON.stringify(headers));
      headersErr.code = 'ERR_INVALID_ARG_VALUE';
      throw headersErr;
    }
    for (var j = 0; j + 1 < headers.length; j += 2) {
      var hName = String(headers[j]);
      var hVal = headers[j + 1];
      validateHeaderName(hName);
      validateHeaderValue(hName, hVal);
      var lc = resolveHeaderName(hName);
      target._headers[lc] = hVal;
      target._headerNames[lc] = hName;
      delete target._removedHeaderNames[lc];
      if (!target[kOutHeaders] || typeof target[kOutHeaders] !== 'object') {
        target[kOutHeaders] = {};
      }
      target[kOutHeaders][lc] = [hName, hVal];
    }
    return;
  }
  for (var k in headers) {
    if (Object.prototype.hasOwnProperty.call(headers, k)) {
      validateHeaderName(k);
      validateHeaderValue(k, headers[k]);
      var lc2 = resolveHeaderName(k);
      target._headers[lc2] = headers[k];
      target._headerNames[lc2] = k;
      delete target._removedHeaderNames[lc2];
      if (!target[kOutHeaders] || typeof target[kOutHeaders] !== 'object') {
        target[kOutHeaders] = {};
      }
      target[kOutHeaders][lc2] = [k, headers[k]];
    }
  }
}

function parseHeaders(response) {
  var result = {};
  if (response && response.headers && typeof response.headers.forEach === 'function') {
    response.headers.forEach(function(value, key) {
      result[key] = value;
    });
  }
  return result;
}

function toBuffer(value) {
  if (value == null) return null;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') {
    if (typeof Buffer !== 'undefined') return Buffer.from(value, 'latin1');
    return value;
  }
  return typeof Buffer !== 'undefined' ? Buffer.from(String(value), 'latin1') : String(value);
}

function isValidMethodStart(byte) {
  return (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || byte === 42;
}

function emitClientError(server, socket, rawPacket, bytesParsed) {
  var raw = toBuffer(rawPacket);
  var err = new Error('Parse Error: Invalid method encountered');
  err.code = 'HPE_INVALID_METHOD';
  err.rawPacket = raw || toBuffer('');
  err.bytesParsed = bytesParsed;
  if (server && typeof server.emit === 'function') {
    server.emit('clientError', err, socket);
  }
}

function parseInvalidClientRequest(server, socket, chunk) {
  if (!chunk || !chunk.length) return;
  if (!socket._exactHttpClientErrorState) return;
  var state = socket._exactHttpClientErrorState;
  if (state.done) return;

  var data = toBuffer(chunk);
  if (!data || !data.length) return;
  if (state.awaitingReplay) {
    emitClientError(server, socket, data, data.length);
    state.done = true;
    return;
  }

  if (isValidMethodStart(data[0])) {
    state.done = true;
    return;
  }

  emitClientError(server, socket, data.slice(0, 1), 1);
  var remaining = data.slice(1);
  if (remaining.length > 0) {
    emitClientError(server, socket, remaining, remaining.length);
    state.done = true;
  } else {
    state.awaitingReplay = true;
  }
}

function setupHttpClientErrorParsing(server, socket) {
  if (!socket || !socket.on) return;
  if (socket._exactHttpClientParserAttached) return;
  socket._exactHttpClientParserAttached = true;
  socket._exactHttpClientErrorState = { done: false, awaitingReplay: false };

  var onData = function(data) {
    parseInvalidClientRequest(server, socket, data);
    if (socket._exactHttpClientErrorState.done) {
      socket.removeListener('data', onData);
    }
  };

  socket.on('data', onData);
  var buffered = socket.read();
  if (buffered && buffered.length) {
    parseInvalidClientRequest(server, socket, buffered);
    if (socket._exactHttpClientErrorState.done) {
      socket.removeListener('data', onData);
    }
  }
}

// ---------------------------------------------------------------------------
// IncomingMessage - supports both client responses AND server-side construction
// Node.js: new http.IncomingMessage(socket) — socket is optional
// ---------------------------------------------------------------------------
function IncomingMessage(socketOrResponse) {
  EventEmitter.call(this);
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor) {
    try { ReadableCtor.call(this); } catch (_readableInitErr) {}
  }

  // If called with a fetch Response object (internal path)
  if (socketOrResponse && typeof socketOrResponse === 'object'
      && typeof socketOrResponse.status === 'number'
      && socketOrResponse.headers && typeof socketOrResponse.headers.forEach === 'function') {
    this.statusCode = socketOrResponse.status;
    this.statusMessage = socketOrResponse.statusText;
    this.headers = parseHeaders(socketOrResponse);
    this.rawHeaders = [];
    for (var key in this.headers) {
      this.rawHeaders.push(key, this.headers[key]);
    }
    this.httpVersion = "1.1";
    this.httpVersionMajor = 1;
    this.httpVersionMinor = 1;
    this.aborted = false;
    this.complete = false;
    this.readable = true;
    this.socket = null;
    this.trailers = {};
    this.rawTrailers = [];
    this.method = null;
    this.url = '';
    this._response = socketOrResponse;
    this._consumed = false;
    return;
  }

  // Standard Node.js IncomingMessage constructor: new IncomingMessage(socket)
  this.socket = socketOrResponse !== undefined ? socketOrResponse : undefined;
  this.httpVersion = '1.1';
  this.httpVersionMajor = 1;
  this.httpVersionMinor = 1;
  this.complete = false;
  this.headers = {};
  this.rawHeaders = [];
  this.trailers = {};
  this.rawTrailers = [];
  this.readable = true;
  this.aborted = false;
  this.statusCode = null;
  this.statusMessage = null;
  this.method = null;
  this.url = '';
  this._consumed = false;
  this._response = null;
  this._body = '';
}
// Inherit from Readable if available, otherwise EventEmitter.
// Always ensure EventEmitter methods are available in the chain.
var _IncomingMessageBase = (function() {
  var R = getReadableCtor();
  if (R && R.prototype) {
    // Check if Readable already inherits from EventEmitter
    if (typeof R.prototype.on === 'function') {
      return R.prototype;
    }
    // Readable exists but doesn't have EventEmitter methods in its chain.
    // Build a combined prototype: Readable methods + EventEmitter methods.
    var combined = Object.create(EventEmitter.prototype);
    var names = Object.getOwnPropertyNames(R.prototype);
    for (var i = 0; i < names.length; i++) {
      if (names[i] !== 'constructor') {
        Object.defineProperty(combined, names[i], Object.getOwnPropertyDescriptor(R.prototype, names[i]));
      }
    }
    return combined;
  }
  return EventEmitter.prototype;
})();
IncomingMessage.prototype = Object.create(_IncomingMessageBase);
IncomingMessage.prototype.constructor = IncomingMessage;

// Provide a fallback read() if Readable didn't supply one
if (typeof IncomingMessage.prototype.read !== 'function') {
  IncomingMessage.prototype.read = function() { return null; };
}
if (typeof IncomingMessage.prototype._read !== 'function') {
  IncomingMessage.prototype._read = function() {};
}
if (typeof IncomingMessage.prototype.resume !== 'function') {
  IncomingMessage.prototype.resume = function() { return this; };
}
if (typeof IncomingMessage.prototype.pause !== 'function') {
  IncomingMessage.prototype.pause = function() { return this; };
}
if (typeof IncomingMessage.prototype.push !== 'function') {
  IncomingMessage.prototype.push = function() { return true; };
}

// connection getter/setter mirrors socket
Object.defineProperty(IncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

// _addHeaderLine: used by the parser to add a header to the message
IncomingMessage.prototype._addHeaderLine = function(field, value, dest) {
  var key = field.toLowerCase();
  if (dest === undefined) dest = this.headers;
  _appendIncomingHeaderValue(dest, key, value);
};

IncomingMessage.prototype._consumeBody = function() {
  if (this._consumed) return;
  this._consumed = true;
  var self = this;
  var response = this._response;
  var canPush = typeof self.push === 'function';
  function deliverChunk(chunk) {
    if (canPush) {
      self.push(chunk);
    } else {
      self.emit('data', chunk);
    }
  }
  function deliverEnd() {
    self.complete = true;
    if (canPush) {
      self.push(null);
    } else {
      self.emit('end');
      self.emit('close');
    }
  }
  if (!response) {
    if (self._body) {
      var body = self._body;
      setTimeout(function() {
        deliverChunk(body);
        deliverEnd();
      }, 0);
    } else {
      setTimeout(function() {
        deliverEnd();
      }, 0);
    }
    return;
  }
  if (response.body && typeof response.body.getReader === 'function') {
    var reader = response.body.getReader();
    var decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null;
    function pump() {
      reader.read().then(function(result) {
        if (result.done) {
          deliverEnd();
          return;
        }
        var chunk = result.value;
        if (chunk instanceof Uint8Array && decoder) {
          deliverChunk(decoder.decode(chunk, { stream: true }));
        } else {
          deliverChunk(chunk);
        }
        pump();
      }).catch(function(err) {
        self.emit("error", err);
      });
    }
    pump();
  } else {
    response
      .text()
      .then(function(text) {
        if (text) deliverChunk(text);
        deliverEnd();
      })
      .catch(function(err) {
        self.emit("error", err);
      });
  }
};
IncomingMessage.prototype.setEncoding = function() { return this; };
if (!IncomingMessage.prototype.pause) {
  IncomingMessage.prototype.pause = function() { return this; };
}
IncomingMessage.prototype.resume = function() {
  if (this._response) this._consumeBody();
  return this;
};
IncomingMessage.prototype._read = function() {
  // Trigger consumption of the response body when Readable requests data
  if (this._response && !this._consumed) this._consumeBody();
};
IncomingMessage.prototype.destroy = function(err) {
  if (err) this.emit('error', err);
  this.emit("close");
  return this;
};
IncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  return this;
};
_attachHttpAsyncIterator(IncomingMessage.prototype);

// ---------------------------------------------------------------------------
// ClientRequest
// ---------------------------------------------------------------------------
function ClientRequest(options, callback) {
  EventEmitter.call(this);
  initOutgoingMessage(this);
  options = normalizeClientRequestOptions(options);
  this.options = options || {};
  this._defaultAgent = globalAgent;
  var skipDefaultAgent = this.options.__exactSkipDefaultAgent === true;

  // Validate hostname/host type
  if (this.options.hostname !== undefined && this.options.hostname !== null && typeof this.options.hostname !== 'string') {
    var err = new TypeError('The "options.hostname" property must be of type string or one of undefined or null.' +
      _invalidArgTypeHelper(this.options.hostname));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (this.options.host !== undefined && this.options.host !== null && typeof this.options.host !== 'string') {
    var err = new TypeError('The "options.host" property must be of type string or one of undefined or null.' +
      _invalidArgTypeHelper(this.options.host));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  // Validate method type
  if (this.options.method !== undefined && this.options.method !== null && typeof this.options.method !== 'string') {
    var err = new TypeError('The "options.method" property must be of type string.' +
      _invalidArgTypeHelper(this.options.method));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  // Validate method is a valid HTTP token
  if (this.options.method !== undefined && this.options.method !== null) {
    var methodStr = String(this.options.method);
    if (methodStr && !HEADER_NAME_RE.test(methodStr)) {
      var mErr = new TypeError('Method must be a valid HTTP token ["' + methodStr + '"]');
      mErr.code = 'ERR_INVALID_HTTP_TOKEN';
      throw mErr;
    }
  }
  if (this.options.insecureHTTPParser !== undefined && typeof this.options.insecureHTTPParser !== 'boolean') {
    var insecureParserErr = new TypeError('The "options.insecureHTTPParser" property must be of type boolean.' +
      _invalidArgTypeHelper(this.options.insecureHTTPParser));
    insecureParserErr.code = 'ERR_INVALID_ARG_TYPE';
    throw insecureParserErr;
  }
  var requestTimeout = _validateTimeoutValue(this.options.timeout);
  if (requestTimeout !== undefined) {
    this.options.timeout = requestTimeout;
  }

  var resolvedAgent = this.options.agent;
  if (resolvedAgent === false) {
    resolvedAgent = new Agent();
  } else if (resolvedAgent === null || resolvedAgent === undefined) {
    if (skipDefaultAgent) {
      resolvedAgent = null;
    } else if (typeof this.options.createConnection !== 'function') {
      resolvedAgent = this._defaultAgent;
    } else {
      resolvedAgent = null;
    }
  } else if (typeof resolvedAgent.addRequest !== 'function') {
    var agentErr = new TypeError('The "options.agent" property must be one of Agent-like Object, undefined, or false.' +
      _invalidArgTypeHelper(resolvedAgent));
    agentErr.code = 'ERR_INVALID_ARG_TYPE';
    throw agentErr;
  }

  this._url = typeof this.options.__exactOriginalUrl === "string"
    ? this.options.__exactOriginalUrl
    : toHttpUrl(this.options);
  this.method = toMethod(this.options);
  this.path = toHttpPath(this.options);
  validateClientRequestPath(this.path);
  this._headersIsArray = Array.isArray(this.options.headers);
  this._setDefaultHeaders = this.options.setDefaultHeaders !== false;
  this._setHostHeader = this.options.setHost !== undefined
    ? this.options.setHost !== false
    : this._setDefaultHeaders;
  _initializeClientRequestHeaders(this, this.options.headers);
  this._bodyParts = [];
  this._ended = false;
  this._sent = false;
  this._closed = false;
  this._aborted = false;
  this.aborted = false;
  this.headersSent = false;
  this.finished = false;
  this.writableEnded = false;
  this.writableFinished = false;
  this.destroyed = false;
  this.maxHeadersCount = 2000;
  this.reusedSocket = false;
  this.socket = null;
  this.agent = resolvedAgent;
  this.host = this.options.hostname || this.options.host || 'localhost';
  this.protocol = this.options.protocol || (this.agent && this.agent.protocol) || 'http:';
  this.timeout = requestTimeout;
  this.timeoutCb = null;
  this._timeoutEmitted = false;
  this.res = null;
  this._pendingRawRequest = null;
  this._agentDispatched = false;
  this._pendingSocketDrain = false;
  this._pendingSocketWrites = 0;
  this._socketDrainListenerAttached = false;
  this._responseEndedBeforeRequestEnd = false;
  this._streamingRequest = false;
  this._requestHeadWritten = false;
  this._requestUsesChunkedEncoding = false;
  this._requestFinalQueued = false;
  this._requestFinalSent = false;
  this._pendingRequestWrites = [];
  this._destroyRequested = false;
  this._abortResponse = null;
  this._abortSignal = null;
  this._abortSignalListener = null;
  this._last = true;
  this.shouldKeepAlive = false;

  if (!this._headersIsArray &&
      this._setHostHeader &&
      !_clientRequestHasHeader(this, 'host')) {
    var defaultPort = this.protocol === 'https:' ? 443 : 80;
    var headerHost = this.host;
    var configuredPort = this.options && this.options.port != null ? Number(this.options.port) : null;
    if (configuredPort && configuredPort !== defaultPort) {
      headerHost += ':' + configuredPort;
    }
    _setClientRequestHeaderState(this, 'Host', headerHost, false);
  }
  if (!this._headersIsArray &&
      this.options &&
      this.options.auth &&
      !_clientRequestHasHeader(this, 'authorization')) {
    _setClientRequestHeaderState(
      this,
      'Authorization',
      'Basic ' + Buffer.from(String(this.options.auth)).toString('base64'),
      false
    );
  }

  if (this.agent) {
    if (this.options && this.options.agent === false) {
      this._last = true;
      this.shouldKeepAlive = false;
    } else {
      this._last = false;
      this.shouldKeepAlive = true;
    }
  }

  if (this.options && Object.prototype.hasOwnProperty.call(this.options, 'signal')) {
    attachRequestAbortSignal(this, this.options.signal);
  }

  if (typeof callback === "function") {
    this.once("response", callback);
  }

  if (_requestUsesSocketTransport(this)) {
    this._ensureSocketAssigned();
  }
}
ClientRequest.prototype = Object.create(EventEmitter.prototype);
ClientRequest.prototype.constructor = ClientRequest;

// parser getter - delegates to socket.parser for compat with Node.js internal APIs
Object.defineProperty(ClientRequest.prototype, 'parser', {
  get: function() {
    if (this._parser !== undefined) return this._parser;
    if (this.socket && this.socket.parser !== undefined) return this.socket.parser;
    return null;
  },
  set: function(val) {
    this._parser = val;
  },
  enumerable: true,
  configurable: true
});

function _requestUsesSocketTransport(request) {
  if (!request) return false;
  if (request.options && request.options.socketPath) return true;
  if (request.options && typeof request.options.createConnection === 'function') return true;
  if (request.protocol === 'http:') return true;
  return !!(
    request.protocol === 'https:' &&
    request.agent &&
    request.agent.protocol === 'https:' &&
    typeof request.agent.addRequest === 'function'
  );
}

ClientRequest.prototype._implicitHeader = function() {
  if (this._header !== null) return;
  this._header = '';
};

ClientRequest.prototype.setHeader = function(name, value) {
  var lc = resolveHeaderName(name);
  validateHeaderName(name);
  _setClientRequestHeaderState(this, String(name), value, false);
};

ClientRequest.prototype.getHeader = function(name) {
  _validateHeaderLookupName(name);
  return this.headers[resolveHeaderName(name)];
};

ClientRequest.prototype.removeHeader = function(name) {
  _validateHeaderLookupName(name);
  var key = resolveHeaderName(name);
  var value = this.headers[key];
  delete this.headers[key];
  delete this._headerNames[key];
  if (this[kOutHeaders] && typeof this[kOutHeaders] === 'object') {
    delete this[kOutHeaders][key];
  }
  _removeClientRequestHeaderEntries(this, key);
  return value;
};

ClientRequest.prototype.getHeaders = function() {
  var clone = Object.create(null);
  for (var key in this.headers) {
    if (Object.prototype.hasOwnProperty.call(this.headers, key)) {
      clone[key] = this.headers[key];
    }
  }
  return clone;
};

ClientRequest.prototype.getHeaderNames = function() {
  return Object.keys(this.headers);
};

ClientRequest.prototype.getRawHeaderNames = function() {
  var result = [];
  for (var key in this._headerNames) {
    if (Object.prototype.hasOwnProperty.call(this._headerNames, key)) {
      result.push(this._headerNames[key]);
    }
  }
  return result;
};

ClientRequest.prototype.hasHeader = function(name) {
  _validateHeaderLookupName(name);
  return resolveHeaderName(name) in this.headers;
};

ClientRequest.prototype.flushHeaders = function() {
  if (this._sent) return this;
  if (this.protocol === 'http:') {
    this._startStreamingRequest();
    this._ensureSocketAssigned();
    if (this._writePendingRequest) {
      this._writePendingRequest();
    }
  } else {
    this._send();
  }
  return this;
};

function _buildRawTcpRequestHead(request, host, port, bodyLength, forceChunked) {
  var reqLine = request.method + ' ' + request.path + ' HTTP/1.1\r\n';
  var headerLines = [];
  if (request._setHostHeader && !_clientRequestHasHeader(request, 'host')) {
    headerLines.push('Host: ' + host + (port !== 80 ? ':' + port : '') + '\r\n');
  }
  _appendClientRequestHeaderLines(request, headerLines);
  if (typeof bodyLength === 'number' &&
      !request.headers['content-length'] &&
      !request.headers['transfer-encoding'] &&
      request._setDefaultHeaders) {
    if (bodyLength > 0 || request.method === 'POST' || request.method === 'PUT') {
      headerLines.push('Content-Length: ' + bodyLength + '\r\n');
    }
  } else if (forceChunked &&
             !request.headers['content-length'] &&
             !request.headers['transfer-encoding'] &&
             request._setDefaultHeaders) {
    headerLines.push('Transfer-Encoding: chunked\r\n');
  }
  if (!request.headers['connection'] && request._setDefaultHeaders) {
    headerLines.push('Connection: ' + (request.shouldKeepAlive ? 'keep-alive' : 'close') + '\r\n');
  }
  headerLines.push('\r\n');
  return reqLine + headerLines.join('');
}

function _buildChunkedRequestFrame(bodyPart) {
  var chunk = bodyPart == null ? _toOutgoingBodyPart('', 'utf8') : bodyPart;
  var chunkLength = _getOutgoingBodyPartLength(chunk);
  if (typeof Buffer !== 'undefined') {
    var prefix = Buffer.from(chunkLength.toString(16) + '\r\n', 'ascii');
    var suffix = Buffer.from('\r\n', 'ascii');
    return Buffer.concat([prefix, chunk, suffix], prefix.length + chunk.length + suffix.length);
  }
  return chunkLength.toString(16) + '\r\n' + chunk + '\r\n';
}

ClientRequest.prototype._startStreamingRequest = function() {
  if (this._sent || this._aborted || this.destroyed || this._destroyRequested) return;
  this._sent = true;
  this.headersSent = true;
  this._streamingRequest = true;
  if (this._setDefaultHeaders &&
      !this.headers['content-length'] &&
      !this.headers['transfer-encoding']) {
    this.headers['transfer-encoding'] = 'chunked';
    this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
    if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
      this[kOutHeaders] = {};
    }
    this[kOutHeaders]['transfer-encoding'] = ['Transfer-Encoding', 'chunked'];
    _removeClientRequestHeaderEntries(this, 'transfer-encoding');
    _appendClientRequestHeaderEntries(this, 'Transfer-Encoding', 'chunked');
    this._requestUsesChunkedEncoding = true;
  } else {
    this._requestUsesChunkedEncoding = _hasChunkedTransferEncoding(this.headers['transfer-encoding']);
  }
  var resolved = this._resolveConnectionOptions();
  this._pendingRawRequest = _buildRawTcpRequestHead(
    this,
    resolved.host,
    resolved.port,
    null,
    this._requestUsesChunkedEncoding
  );
};

ClientRequest.prototype._queueStreamingRequestBody = function(chunk, encoding, callback) {
  var body = _toOutgoingBodyPart(chunk, encoding);
  var queuedLength = this._requestUsesChunkedEncoding
    ? _getOutgoingBodyPartLength(_buildChunkedRequestFrame(body))
    : _getOutgoingBodyPartLength(body);
  this._pendingRequestWrites.push({
    body: body,
    queuedLength: queuedLength,
    callback: typeof callback === 'function' ? callback : null
  });
  _recordOutgoingBytes(this, queuedLength);
  if (this._writePendingRequest) {
    this._writePendingRequest();
  } else {
    this._ensureSocketAssigned();
  }
};

function emitRequestTimeout() {
  var req = this && this._httpMessage;
  if (req && !req._timeoutEmitted) {
    req._timeoutEmitted = true;
    req.emit('timeout');
  }
}

function listenSocketTimeout(req) {
  if (req.timeoutCb) return;
  req.timeoutCb = emitRequestTimeout;
  if (req.socket) {
    req.socket.on('timeout', req.timeoutCb);
  } else {
    req.once('socket', function(socket) {
      socket.on('timeout', req.timeoutCb);
    });
  }
}

function setSocketTimeout(socket, timeout) {
  if (!socket || typeof socket.setTimeout !== 'function') return;
  socket.setTimeout(timeout);
}

function clearSocketTimeoutListener(req, socket) {
  if (!req || !socket || !req.timeoutCb) return;
  socket.removeListener('timeout', req.timeoutCb);
  req.timeoutCb = null;
}

function ReusedHandle(type, handle) {
  this.type = type || 'Socket';
  this.handle = handle;
}

function freeSocketErrorListener() {
  if (typeof this.destroy === 'function') {
    this.destroy();
  }
  if (typeof this.emit === 'function') {
    this.emit('agentRemove');
  }
}

function asyncResetHandle(socket) {
  var handle = socket && socket._handle;
  if (handle && typeof handle.asyncReset === 'function') {
    try {
      handle.asyncReset(new ReusedHandle(
        typeof handle.getProviderType === 'function' ? handle.getProviderType() : 'Socket',
        handle
      ));
    } catch (_asyncResetErr) {}
  }
}

function createInvalidAgentSchedulingError(value) {
  var err = new TypeError("The argument 'scheduling' must be one of: 'fifo', 'lifo'. Received '" + value + "'");
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function isReusableAgentSocket(socket) {
  return !!socket &&
    !socket.destroyed &&
    socket.writable !== false &&
    socket.connecting !== true &&
    socket._connected === true &&
    socket.readyState !== 'closed';
}

function takeFreeAgentSocket(freeSockets, scheduling) {
  if (!freeSockets || freeSockets.length === 0) return null;
  while (freeSockets.length > 0) {
    var index = scheduling === 'fifo' ? 0 : (freeSockets.length - 1);
    var socket = freeSockets[index];
    if (!isReusableAgentSocket(socket)) {
      freeSockets.splice(index, 1);
      if (socket && typeof socket.destroy === 'function') {
        try { socket.destroy(); } catch (_destroyFreeAgentSocketErr) {}
      }
      continue;
    }
    freeSockets.splice(index, 1);
    return socket;
  }
  return null;
}

function mergeAgentRequestOptions(agent, req, options, port, localAddress) {
  var normalizedOptions;
  if (typeof options === 'string') {
    normalizedOptions = { host: options, port: port, localAddress: localAddress };
  } else {
    normalizedOptions = Object.assign({}, options || {});
  }

  normalizedOptions = Object.assign(normalizedOptions, agent.options);

  var requestOptions = req && req.options && typeof req.options === 'object' ? req.options : null;
  if (!normalizedOptions.socketPath && requestOptions && requestOptions.socketPath) {
    normalizedOptions.socketPath = requestOptions.socketPath;
  }
  if (normalizedOptions.host === undefined && requestOptions && requestOptions.host !== undefined) {
    normalizedOptions.host = requestOptions.host;
  }
  if (normalizedOptions.hostname === undefined && requestOptions && requestOptions.hostname !== undefined) {
    normalizedOptions.hostname = requestOptions.hostname;
  }
  if (normalizedOptions.port === undefined && requestOptions && requestOptions.port !== undefined) {
    normalizedOptions.port = requestOptions.port;
  }
  if (normalizedOptions.localAddress === undefined && requestOptions && requestOptions.localAddress !== undefined) {
    normalizedOptions.localAddress = requestOptions.localAddress;
  }
  if (normalizedOptions.family === undefined && requestOptions && requestOptions.family !== undefined) {
    normalizedOptions.family = requestOptions.family;
  }
  if (normalizedOptions.host === undefined && req && req.host !== undefined) {
    normalizedOptions.host = req.host;
  }

  if (normalizedOptions.socketPath) {
    normalizedOptions.path = normalizedOptions.socketPath;
  } else {
    delete normalizedOptions.path;
  }
  return normalizedOptions;
}

function setRequestSocket(agent, req, socket, options) {
  req.onSocket(socket, options);
  var agentTimeout = agent && agent.options ? agent.options.timeout : undefined;
  if (req.timeout === undefined || req.timeout === null) {
    if (agentTimeout !== undefined) {
      listenSocketTimeout(req);
      setSocketTimeout(socket, agentTimeout);
    }
    return;
  }
  listenSocketTimeout(req);
  setSocketTimeout(socket, req.timeout);
}

function scheduleNextTick(fn) {
  if (typeof process !== 'undefined' && process && typeof process.nextTick === 'function') {
    process.nextTick(fn);
    return;
  }
  setTimeout(fn, 0);
}

function isUsableQueuedAgentRequest(req) {
  return !!req &&
    !req.destroyed &&
    !req._closed &&
    !req._aborted &&
    !req.aborted;
}

function shiftUsableQueuedAgentRequest(queue) {
  if (!queue || queue.length === 0) return null;
  while (queue.length > 0) {
    var nextReq = queue.shift();
    if (!isUsableQueuedAgentRequest(nextReq)) {
      if (nextReq) {
        nextReq._queuedAgentOptions = undefined;
      }
      continue;
    }
    return nextReq;
  }
  return null;
}

function createRequestAbortError() {
  var err = new Error('The operation was aborted');
  err.code = 'ABORT_ERR';
  err.name = 'AbortError';
  return err;
}

function isAbortSignal(value) {
  return !!value &&
    typeof value === 'object' &&
    typeof value.aborted === 'boolean' &&
    typeof value.addEventListener === 'function' &&
    typeof value.removeEventListener === 'function';
}

function validateRequestAbortSignal(signal) {
  if (signal === undefined) return;
  if (isAbortSignal(signal)) return;
  var signalValue = typeof signal === 'string' ? "'" + signal + "'" : typeof signal;
  var err = new TypeError('The "options.signal" property must be an instance of AbortSignal. Received ' + signalValue);
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function detachRequestAbortSignal(req) {
  if (!req || !req._abortSignal || !req._abortSignalListener) return;
  try {
    req._abortSignal.removeEventListener('abort', req._abortSignalListener);
  } catch (_detachAbortSignalErr) {}
  req._abortSignal = null;
  req._abortSignalListener = null;
}

function attachRequestAbortSignal(req, signal) {
  if (signal === undefined) return true;
  validateRequestAbortSignal(signal);
  detachRequestAbortSignal(req);
  if (signal.aborted) {
    req.destroy(createRequestAbortError());
    return false;
  }
  req._abortSignal = signal;
  req._abortSignalListener = function() {
    detachRequestAbortSignal(req);
    req.destroy(createRequestAbortError());
  };
  signal.addEventListener('abort', req._abortSignalListener, { once: true });
  return true;
}

function isAbortLikeRequestError(err) {
  if (!err) return false;
  return err.code === 'ABORT_ERR' ||
    (err.code === 'ECONNRESET' && (err.message === 'aborted' || err.message === 'socket hang up'));
}

ClientRequest.prototype._deferToConnect = function(method, args) {
  var self = this;
  function invoke() {
    if (!self.socket || typeof self.socket[method] !== 'function') return;
    if (self.socket.writable !== false) {
      self.socket[method].apply(self.socket, args);
    }
  }
  function onSocket() {
    if (!self.socket) return;
    if (self.socket.connecting) {
      self.socket.once('connect', invoke);
    } else {
      invoke();
    }
  }
  if (!this.socket) {
    this.once('socket', onSocket);
  } else {
    onSocket();
  }
};

ClientRequest.prototype.onSocket = function(socket, requestOptions, err) {
  var self = this;
  var earlySocketError = null;
  function captureEarlySocketError(socketErr) {
    if (!earlySocketError) {
      earlySocketError = socketErr;
    }
  }
  if (socket && typeof socket.once === 'function') {
    socket.once('error', captureEarlySocketError);
  }
  scheduleNextTick(function() {
    if (socket && typeof socket.removeListener === 'function') {
      socket.removeListener('error', captureEarlySocketError);
    }
    if (!err && earlySocketError) {
      err = earlySocketError;
    }
    if (err) {
      if (self.destroyed || self._destroyRequested || self._closed || self._aborted) {
        if (!self._aborted && !isAbortLikeRequestError(err)) {
          self.errored = err;
          self.emit('error', err);
        }
        if (!self._closed) {
          self._closed = true;
          self.emit('close');
        }
        if (socket && typeof socket.destroy === 'function') {
          try { socket.destroy(); } catch (_lateSocketDestroyErr) {}
        }
        return;
      }
      self.destroyed = true;
      if (socket && typeof socket.destroy === 'function') {
        try { socket.destroy(err); } catch (_destroyErr) {}
      }
      self.emit('error', err);
      if (!self._closed) {
        self._closed = true;
        self.emit('close');
      }
      return;
    }
    if (!socket) {
      return;
    }
    if (self.socket && self.socket !== socket && !self.socket.destroyed) {
      if (socket._httpMessage === self) {
        socket._httpMessage = null;
      }
      if (!socket.destroyed && typeof socket.destroy === 'function') {
        try { socket.destroy(); } catch (_extraSocketDestroyErr) {}
      }
      return;
    }
    if (self.destroyed || self._destroyRequested || self._closed) {
      if (socket._httpMessage === self) {
        socket._httpMessage = null;
      }
      if (!socket.destroyed && typeof socket.destroy === 'function') {
        try { socket.destroy(); } catch (_deadSocketDestroyErr) {}
      }
      return;
    }
    self.socket = socket;
    if (self.timeout !== undefined && self.timeout !== null) {
      listenSocketTimeout(self);
      setSocketTimeout(socket, self.timeout);
    } else if (self.agent && self.agent.options && self.agent.options.timeout !== undefined) {
      listenSocketTimeout(self);
      setSocketTimeout(socket, self.agent.options.timeout);
    }
    self._attachToSocket(socket, requestOptions || self.options);
    self.emit('socket', socket);
  });
};

ClientRequest.prototype.setTimeout = function(timeout, callback) {
  timeout = _validateTimeoutValue(timeout);
  this.timeout = timeout;
  this._timeoutEmitted = false;
  if (callback) {
    this.once('timeout', callback);
  }
  if (timeout === 0) {
    if (this.socket && typeof this.socket.setTimeout === 'function') {
      this.socket.setTimeout(0);
    }
    if (this.socket) {
      clearSocketTimeoutListener(this, this.socket);
    }
    return this;
  }
  listenSocketTimeout(this);
  if (this.socket) {
    setSocketTimeout(this.socket, timeout);
  }
  return this;
};

ClientRequest.prototype.clearTimeout = function(callback) {
  return this.setTimeout(0, callback);
};

ClientRequest.prototype.setNoDelay = function(noDelay) {
  this._deferToConnect('setNoDelay', [noDelay]);
};

ClientRequest.prototype.setSocketKeepAlive = function(enable, initialDelay) {
  this._deferToConnect('setKeepAlive', [enable, initialDelay]);
};

function _coerceClientRequestBodyChunk(chunk, encoding) {
  if (chunk == null) return null;
  if (typeof Buffer !== 'undefined') {
    if (Buffer.isBuffer(chunk)) {
      return Buffer.from(chunk);
    }
    if (typeof ArrayBuffer !== 'undefined') {
      if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
        var _len = chunk.byteLength || chunk.length || 0;
        var _copy = Buffer.alloc(_len);
        _copy.set(new Uint8Array(chunk.buffer, chunk.byteOffset || 0, _len));
        return _copy;
      }
      if (chunk instanceof ArrayBuffer) {
        return Buffer.from(chunk);
      }
    }
    return Buffer.from(String(chunk), encoding || 'utf8');
  }
  if (typeof chunk === 'string') return chunk;
  return String(chunk);
}

ClientRequest.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this.destroyed) {
    var destroyedErr = _createStreamDestroyedError();
    if (callback) {
      setTimeout(function() {
        callback(destroyedErr);
      }, 0);
    }
    return false;
  }
  if (chunk === null) {
    throw _createNullWriteError();
  }
  if (chunk !== undefined && chunk !== null && !_isOutgoingChunk(chunk)) {
    throw _createInvalidChunkTypeError(chunk);
  }

  // Empty string/buffer writes are no-ops (Node.js behavior)
  if (chunk !== undefined && chunk !== null && _getOutgoingChunkLength(chunk, encoding) === 0) {
    if (callback) setTimeout(callback, 0);
    return true;
  }

  var isUpgradeRequest = !this._sent &&
    !this._ended &&
    this.protocol === 'http:' &&
    typeof this.headers['upgrade'] === 'string' &&
    typeof this.headers['connection'] === 'string' &&
    this.headers['connection'].toLowerCase().indexOf('upgrade') !== -1;

  if (chunk !== undefined && chunk !== null && !isUpgradeRequest && this.protocol === 'http:' && !this._ended) {
    if (!this._streamingRequest) {
      this._startStreamingRequest();
    }
    this._queueStreamingRequestBody(chunk, encoding, callback);
    var streamingWriteOk = this.writableLength < this.writableHighWaterMark;
    if (!streamingWriteOk) {
      _scheduleOutgoingDrainFallback(this);
    }
    return streamingWriteOk;
  }

  if (chunk !== undefined && chunk !== null) {
    this._bodyParts.push(_coerceClientRequestBodyChunk(chunk, encoding));
    _recordOutgoingBytes(this, _getOutgoingChunkLength(chunk, encoding));
  }
  if (isUpgradeRequest) {
    this._send();
  } else if (callback) {
    setTimeout(callback, 0);
  }
  var requestWriteOk = this.writableLength < this.writableHighWaterMark;
  if (!requestWriteOk) {
    _scheduleOutgoingDrainFallback(this);
  }
  return requestWriteOk;
};

ClientRequest.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._ended || this._aborted || this.destroyed || this._destroyRequested) {
    if (callback) setTimeout(callback, 0);
    return this;
  }
  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }
  this._ended = true;
  this.writableEnded = true;
  this.finished = true;
  if (callback) this.once('finish', callback);
  if (this._streamingRequest) {
    this._requestFinalQueued = true;
    if (this._writePendingRequest) {
      this._writePendingRequest();
    } else {
      this._ensureSocketAssigned();
    }
  } else {
    this._send();
  }
  return this;
};

ClientRequest.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  if (!err && !this._aborted && !this.res) {
    err = new Error('socket hang up');
    err.code = 'ECONNRESET';
  }
  this._destroyRequested = true;
  this.destroyed = true;
  this.closed = true;
  detachRequestAbortSignal(this);
  if (err) {
    this.errored = err;
  }
  if (typeof this._abortResponse === 'function') {
    try { this._abortResponse(err); } catch (_abortResponseErr) {}
  }
  if (this._abortController) {
    try { this._abortController.abort(); } catch(e) {}
  }
  if (this.socket && !this.socket.destroyed) {
    if (!err && !this.res && this.socket.connecting) {
      this.socket._suppressCloseBeforeConnectError = true;
    }
    try { this.socket.destroy(err); } catch(e) {}
  } else if (!this._closed) {
    this._closed = true;
    var self = this;
    scheduleNextTick(function() {
      if (err) self.emit("error", err);
      self.emit("close");
    });
  }
  return this;
};

ClientRequest.prototype.abort = function() {
  if (this._aborted) return;
  this._aborted = true;
  this.aborted = true;
  var self = this;
  scheduleNextTick(function() {
    self.emit("abort");
  });
  this.destroy();
};

ClientRequest.prototype._send = function() {
  if (this._sent || this._aborted || this.destroyed || this._destroyRequested) return;
  this._sent = true;
  this.headersSent = true;
  var body = null;
  if (this._bodyParts.length > 0) {
    if (typeof Buffer !== 'undefined' && Buffer.concat) {
      body = Buffer.concat(this._bodyParts.map(function(part) {
        return _coerceClientRequestBodyChunk(part);
      }));
      if (body.length === 0) body = null;
    } else {
      body = this._bodyParts.join("");
    }
  }

  var useFetch = typeof fetch === "function";
  if (_requestUsesSocketTransport(this)) {
    useFetch = false;
  }
  if (useFetch) {
    try {
      var parsedUrl = new URL(this._url);
      if (parsedUrl.protocol === "http:") {
        useFetch = false;
      }
    } catch (_err) {}
  }

  if (useFetch) {
    this._sendViaFetch(body);
  } else {
    this._sendViaTcp(body);
  }
};

ClientRequest.prototype._sendViaFetch = function(body) {
  var init = {
    method: this.method,
    headers: this.headers
  };
  if (this.method !== "GET" && this.method !== "HEAD") {
    init.body = body;
  }
  if (typeof AbortController !== 'undefined') {
    this._abortController = new AbortController();
    init.signal = this._abortController.signal;
    if (this._aborted) {
      this._abortController.abort();
    }
  }
  var self = this;
  fetch(this._url, init)
    .then(function(response) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      if (self._aborted || self.destroyed || self._destroyRequested) return;
      var responseMessage = new IncomingMessage(response);
      self.emit("response", responseMessage);
      responseMessage._consumeBody();
    })
    .catch(function(err) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      if (self._aborted || self.destroyed || self._destroyRequested) return;
      self.emit("error", err);
      self.emit("close");
    });
};

ClientRequest.prototype._sendViaTcp = function(body) {
  var self = this;
  var resolved = this._resolveConnectionOptions();
  var options = resolved.options;
  var host = resolved.host;
  var port = resolved.port;

  // Build raw HTTP request
  var reqLine = this.method + ' ' + this.path + ' HTTP/1.1\r\n';
  var headerLines = [];
  if (this._setHostHeader && !_clientRequestHasHeader(this, 'host')) {
    headerLines.push('Host: ' + host + (port !== 80 ? ':' + port : '') + '\r\n');
  }
  _appendClientRequestHeaderLines(this, headerLines);
  if (!this.headers['content-length'] &&
      !this.headers['transfer-encoding'] &&
      this._setDefaultHeaders) {
    if (body) {
      var bodyLen = (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(body))
        ? body.length
        : ((typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(body)
          : body.length);
      headerLines.push('Content-Length: ' + bodyLen + '\r\n');
    } else if (this.method === 'POST' || this.method === 'PUT') {
      headerLines.push('Content-Length: 0\r\n');
    }
  }
  if (!this.headers['connection'] && this._setDefaultHeaders) {
    headerLines.push('Connection: ' + (this.shouldKeepAlive ? 'keep-alive' : 'close') + '\r\n');
  }
  headerLines.push('\r\n');

  var rawRequest = reqLine + headerLines.join('');
  if (body && typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(body)) {
    rawRequest = Buffer.concat([Buffer.from(rawRequest, 'latin1'), body]);
  } else if (body) {
    rawRequest += body;
  }
  this._pendingRawRequest = rawRequest;

  if (this._writePendingRequest) {
    this._writePendingRequest();
    return;
  }

  this._ensureSocketAssigned();
};

ClientRequest.prototype._resolveConnectionOptions = function() {
  var options = (this.options && typeof this.options === 'object') ? this.options : {};
  var host = options.hostname || options.host;
  var port = options.port;
  var defaultPort = options.defaultPort ||
    (this.agent && this.agent.defaultPort) ||
    (this.protocol === 'https:' ? 443 : 80);
  if (!host || !port) {
    try {
      var parsed = new URL(this._url);
      if (!host) host = parsed.hostname;
      if (!port) {
        if (parsed.port) {
          port = Number(parsed.port);
        } else {
          port = defaultPort;
        }
      }
      if ((!options.path || options.path === '/') && parsed.pathname) {
        this.path = parsed.pathname + (parsed.search || '');
      }
    } catch (_err) {}
  }
  if (host && host.indexOf(':') !== -1 && host.charAt(0) !== '[') {
    var parts = host.split(':');
    host = parts[0];
    if (!port && parts[1]) port = Number(parts[1]);
  }
  if (!host) host = 'localhost';
  if (!port) port = defaultPort || 80;

  var connectionOptions = {};
  for (var optKey in options) {
    if (Object.prototype.hasOwnProperty.call(options, optKey)) {
      if (optKey === 'signal') continue;
      connectionOptions[optKey] = options[optKey];
    }
  }
  if (options.socketPath) {
    connectionOptions.path = options.socketPath;
  } else {
    delete connectionOptions.path;
    connectionOptions.host = host;
    if (options.hostname) {
      connectionOptions.hostname = options.hostname;
    }
    connectionOptions.port = port;
  }

  return {
    host: host,
    port: port,
    options: connectionOptions
  };
};

ClientRequest.prototype._ensureSocketAssigned = function() {
  if (this.socket || this._agentDispatched || !_requestUsesSocketTransport(this) ||
      this.destroyed || this._destroyRequested) return;

  var net;
  try { net = require('net'); } catch (e) {
    this.emit("error", new Error("Neither fetch nor net module available"));
    if (!this._closed) {
      this._closed = true;
      this.emit("close");
    }
    return;
  }

  var resolved = this._resolveConnectionOptions();
  var connectionOptions = resolved.options;
  var self = this;

  if (this.agent && typeof this.agent.addRequest === 'function') {
    if (!this._agentDispatched) {
      this._agentDispatched = true;
      this.agent.addRequest(this, connectionOptions);
    }
    return;
  }

  var createConnection = connectionOptions.createConnection || this.options.createConnection || null;
  if (createConnection) {
    var created = false;
    function oncreate(err, socket) {
      if (created) return;
      created = true;
      self.onSocket(socket, connectionOptions, err);
    }
    try {
      var maybeSocket = createConnection(connectionOptions, oncreate);
      if (maybeSocket) {
        oncreate(null, maybeSocket);
      }
    } catch (createErr) {
      oncreate(createErr);
    }
    return;
  }

  self.onSocket(net.createConnection(connectionOptions), connectionOptions);
};

ClientRequest.prototype._attachToSocket = function(socket, requestOptions) {
  var self = this;
  if (!socket) return;
  socket._allowResetAsEof = false;
  if (socket._socket && typeof socket._socket === 'object') {
    socket._socket._allowResetAsEof = false;
  }

  var responseBuffer = '';
  var headersParsed = false;
  var statusCode = 200;
  var statusMessage = 'OK';
  var responseHeaders = {};
  var rawResponseHeaders = [];
  var contentLength = -1;
  var isChunked = false;
  var bodyBytesReceived = 0;
  var responseEmitted = false;
  var responseEnded = false;
  var skipResponseBody = false;
  var tcpIncoming = null;
  var chunkParserState = 'size';
  var chunkRemaining = 0;
  var chunkBuffer = '';
  var socketRetired = false;
  var parseErrored = false;

  function setSocketResetAsEofFlag(enabled) {
    if (!socket) return;
    socket._allowResetAsEof = enabled === true;
    if (socket._socket && typeof socket._socket === 'object') {
      socket._socket._allowResetAsEof = enabled === true;
    }
  }

  function createResponseParseError(rawPacket, bytesParsed, code, reason) {
    var raw = toBuffer(rawPacket);
    var message = reason || 'Expected HTTP/, RTSP/ or ICE/';
    var err = new Error('Parse Error: ' + message);
    err.code = code || 'HPE_INVALID_CONSTANT';
    err.rawPacket = raw || toBuffer('');
    err.bytesParsed = typeof bytesParsed === 'number' ? bytesParsed : 0;
    if (reason) {
      err.reason = reason;
    }
    return err;
  }

  function emitResponseParseError(rawPacket, bytesParsed, finishParsedResponse, code, reason) {
    if (parseErrored || self._aborted) return;
    parseErrored = true;
    socket._hadError = true;
    socket.removeListener('data', onData);
    socket.removeListener('end', onEnd);
    self.emit('error', createResponseParseError(rawPacket, bytesParsed, code, reason));
    try {
      socket.destroy();
    } catch (_responseParseDestroyErr) {}
    if (finishParsedResponse && responseEmitted && !responseEnded) {
      finishResponse();
    }
  }

  function pushIncomingResponseChunk(chunk) {
    if (!tcpIncoming) return true;
    try {
      if (typeof tcpIncoming._pushBodyChunk === 'function') tcpIncoming._pushBodyChunk(chunk);
      else if (typeof tcpIncoming.push === 'function') tcpIncoming.push(chunk);
      else tcpIncoming.emit('data', chunk);
      return true;
    } catch (err) {
      responseEnded = true;
      tcpIncoming.complete = true;
      scheduleNextTick(function() {
        throw err;
      });
      return false;
    }
  }

  function clearAbortResponseHook() {
    if (self._abortResponse === abortAttachedResponse) {
      self._abortResponse = null;
    }
  }

  function finishRequestWrite() {
    if (self.writableFinished) return;
    _resetOutgoingBufferState(self);
    self.writableFinished = true;
    self.emit('finish');
  }

  function maybeReleaseSocketAfterFlush() {
    if (self._responseEndedBeforeRequestEnd) {
      retireSocketFromAgent();
      return;
    }
    if (!self._waitingForSocketDrain || !responseEnded) return;
    self._waitingForSocketDrain = false;
    if (self.shouldKeepAlive && tcpIncoming && !tcpIncoming.aborted) {
      releaseSocket();
    }
  }

  function beginSocketWrite() {
    self._pendingSocketWrites += 1;
    self._pendingSocketDrain = true;
  }

  function endSocketWrite() {
    if (self._pendingSocketWrites > 0) {
      self._pendingSocketWrites -= 1;
    }
    self._pendingSocketDrain = self._pendingSocketWrites > 0;
  }

  function onSocketDrain() {
    self._drainFallbackScheduled = false;
    _resetOutgoingBufferState(self);
    if (!self.destroyed && !self._closed) {
      self.emit('drain');
    }
    if (self._streamingRequest) {
      flushQueuedRequestBody();
    }
    maybeReleaseSocketAfterFlush();
  }

  function retireSocketFromAgent() {
    if (socketRetired) return;
    socketRetired = true;
    clearAbortResponseHook();
    clearSocketTimeoutListener(self, socket);
    cleanupRequestListeners();
    self.destroyed = true;
    if (self.res) {
      self.res.socket = null;
    }
    socket._httpMessage = null;
    if (typeof socket.unref === 'function') {
      socket.unref();
    }
    scheduleNextTick(function() {
      if (typeof socket.emit === 'function') {
        socket.emit('agentRemove');
      }
      if (!self._closed) {
        self._closed = true;
        self.emit('close');
      }
    });
  }

  function cleanupRequestListeners() {
    socket.removeListener('data', onData);
    socket.removeListener('end', onEnd);
    socket.removeListener('close', onClose);
    socket.removeListener('error', onError);
    socket.removeListener('drain', onSocketDrain);
  }

  function releaseSocket() {
    clearAbortResponseHook();
    if (!self.agent || !self.shouldKeepAlive || !tcpIncoming || tcpIncoming.aborted ||
        !tcpIncoming.shouldKeepAlive || socket.destroyed || socket.writable === false) {
      if (!socket.destroyed) {
        try {
          if (typeof socket.end === 'function') socket.end();
          else socket.destroy();
        } catch (_endErr) {
          try { socket.destroy(); } catch (_destroyErr) {}
        }
      }
      return;
    }

    if (typeof socket.setTimeout === 'function') {
      socket.setTimeout(self.agent.options && self.agent.options.timeout ? self.agent.options.timeout : 0);
    }
    clearSocketTimeoutListener(self, socket);
    cleanupRequestListeners();
    self.destroyed = true;
    if (self.res) {
      self.res.socket = null;
    }
    if (!self._closed) {
      self._closed = true;
      scheduleNextTick(function() {
        self.emit('close');
        socket.emit('free');
      });
    }
  }

  function finishResponse() {
    if (responseEnded) return;
    responseEnded = true;
    setSocketResetAsEofFlag(true);
    clearAbortResponseHook();
    if (tcpIncoming) {
      if (socket && tcpIncoming._socketTimeoutListener) {
        socket.removeListener('timeout', tcpIncoming._socketTimeoutListener);
        tcpIncoming._socketTimeoutListener = null;
      }
      tcpIncoming._finishResponse();
    }
    finishRequestWrite();
  }

  function abortResponse(err) {
    if (responseEnded) return;
    responseEnded = true;
    setSocketResetAsEofFlag(false);
    clearAbortResponseHook();
    if (tcpIncoming) {
      if (socket && tcpIncoming._socketTimeoutListener) {
        socket.removeListener('timeout', tcpIncoming._socketTimeoutListener);
        tcpIncoming._socketTimeoutListener = null;
      }
      var abortErr = err || new Error('aborted');
      if (!abortErr.code) {
        abortErr.code = 'ECONNRESET';
      }
      _abortIncomingMessageStream(tcpIncoming, abortErr);
    } else if (!self._aborted && !socket._hadError) {
      socket._hadError = true;
      var hangupErr = new Error('socket hang up');
      hangupErr.code = 'ECONNRESET';
      self.emit('error', hangupErr);
    }
  }

  function abortAttachedResponse(err) {
    if (!responseEmitted && !headersParsed) {
      return false;
    }
    abortResponse(err);
    return true;
  }

  function finishUpgrade(upgradeHead) {
    if (responseEnded) return;
    responseEmitted = true;
    responseEnded = true;
    setSocketResetAsEofFlag(false);
    clearAbortResponseHook();
    socket._httpMessage = null;
    socket.parser = null;
    clearSocketTimeoutListener(self, socket);
    if (typeof socket.setTimeout === 'function') {
      socket.setTimeout(0);
    }
    cleanupRequestListeners();
    if (self.agent && typeof socket.emit === 'function') {
      socket.emit('agentRemove');
    }
    finishRequestWrite();
    self.emit('upgrade', tcpIncoming, socket, upgradeHead);
    if (!self._closed) {
      self._closed = true;
      scheduleNextTick(function() {
        self.emit('close');
      });
    }
  }

  function processChunkedData(data) {
    chunkBuffer += data;
    while (chunkBuffer.length > 0) {
      if (chunkParserState === 'size') {
        var nlIdx = chunkBuffer.indexOf('\r\n');
        if (nlIdx === -1) return;
        var sizeStr = chunkBuffer.substring(0, nlIdx).split(';')[0].trim();
        chunkRemaining = parseInt(sizeStr, 16);
        chunkBuffer = chunkBuffer.substring(nlIdx + 2);
        if (isNaN(chunkRemaining)) {
          emitResponseParseError(data, 0, false);
          return;
        }
        if (chunkRemaining === 0) {
          chunkParserState = 'trailers';
          continue;
        }
        chunkParserState = 'data';
      } else if (chunkParserState === 'data') {
        if (chunkBuffer.length < chunkRemaining) {
          if (chunkBuffer.length > 0 && tcpIncoming) {
            var partBuf = (typeof Buffer !== 'undefined') ? Buffer.from(chunkBuffer, 'latin1') : chunkBuffer;
            if (!pushIncomingResponseChunk(partBuf)) return;
            chunkRemaining -= chunkBuffer.length;
            chunkBuffer = '';
          }
          return;
        }
        var chunkData = chunkBuffer.substring(0, chunkRemaining);
        chunkBuffer = chunkBuffer.substring(chunkRemaining);
        chunkRemaining = 0;
        if (tcpIncoming && chunkData) {
          var chunkDataBuf = (typeof Buffer !== 'undefined') ? Buffer.from(chunkData, 'latin1') : chunkData;
          if (!pushIncomingResponseChunk(chunkDataBuf)) return;
        }
        chunkParserState = 'chunk-end';
      } else if (chunkParserState === 'chunk-end') {
        if (chunkBuffer.length < 2) return;
        chunkBuffer = chunkBuffer.substring(2);
        chunkParserState = 'size';
      } else if (chunkParserState === 'trailers') {
        if (chunkBuffer.indexOf('\r\n') === 0) {
          chunkBuffer = chunkBuffer.substring(2);
          finishResponse();
          return;
        }
        var trailerEndIdx = chunkBuffer.indexOf('\r\n\r\n');
        if (trailerEndIdx === -1) return;
        if (tcpIncoming) {
          _parseTrailerSection(
            chunkBuffer.substring(0, trailerEndIdx),
            tcpIncoming.trailers,
            tcpIncoming.rawTrailers
          );
        }
        chunkBuffer = chunkBuffer.substring(trailerEndIdx + 4);
        finishResponse();
        return;
      }
    }
  }

  function pushIdentityResponseData(data) {
    if (!data || skipResponseBody) {
      return true;
    }
    var dataBytes = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
      ? Buffer.byteLength(data, 'latin1') : data.length;
    if (contentLength >= 0) {
      var remainingBytes = contentLength - bodyBytesReceived;
      if (remainingBytes <= 0) {
        emitResponseParseError(data, 0, true);
        return false;
      }

      var dataToPush = data;
      var extraData = '';
      if (dataBytes > remainingBytes) {
        dataToPush = data.substring(0, remainingBytes);
        extraData = data.substring(remainingBytes);
        dataBytes = remainingBytes;
      }

      if (dataToPush.length > 0) {
        bodyBytesReceived += dataBytes;
        var dataToPushBuf = (typeof Buffer !== 'undefined') ? Buffer.from(dataToPush, 'latin1') : dataToPush;
        if (!pushIncomingResponseChunk(dataToPushBuf)) return false;
      }

      if (extraData.length > 0) {
        emitResponseParseError(extraData, 0, true);
        return false;
      }

      if (bodyBytesReceived >= contentLength) {
        finishResponse();
      }
      return true;
    }

    bodyBytesReceived += dataBytes;
    var dataBuf = (typeof Buffer !== 'undefined') ? Buffer.from(data, 'latin1') : data;
    return pushIncomingResponseChunk(dataBuf);
  }

  function onData(chunk) {
    if (responseEnded || self._aborted || (tcpIncoming && tcpIncoming.aborted)) {
      return;
    }
    var str = typeof chunk === 'string' ? chunk : chunk.toString('latin1');

    if (!headersParsed) {
      responseBuffer += str;
      var headerEnd = responseBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      var headerSection = responseBuffer.substring(0, headerEnd);
      var bodyStart = responseBuffer.substring(headerEnd + 4);
      headersParsed = true;

      var lines = headerSection.split('\r\n');
      var httpVerMajor = 1;
      var httpVerMinor = 1;
      if (lines.length > 0) {
        var statusLine = lines[0];
        var statusParts = statusLine.match(/^HTTP\/(\d)\.(\d)\s+(\d+)\s*(.*)/);
        if (!statusParts) {
          emitResponseParseError(headerSection, 0, false);
          return;
        }
        httpVerMajor = parseInt(statusParts[1], 10) || 1;
        httpVerMinor = parseInt(statusParts[2], 10) || 1;
        statusCode = parseInt(statusParts[3], 10);
        statusMessage = statusParts[4] || '';
      }
      for (var i = 1; i < lines.length; i++) {
        var colonIdx = lines[i].indexOf(':');
        if (colonIdx > 0) {
          var hKey = lines[i].substring(0, colonIdx).trim();
          var hVal = lines[i].substring(colonIdx + 1).trim();
          var hKeyLower = hKey.toLowerCase();
          _appendIncomingHeaderValue(responseHeaders, hKeyLower, hVal);
          rawResponseHeaders.push(hKey, hVal);
        }
      }
      var cl = responseHeaders['content-length'];
      if (cl !== undefined) contentLength = parseInt(cl, 10) || 0;
      var te = responseHeaders['transfer-encoding'];
      if (cl !== undefined && te !== undefined) {
        var reason = "Transfer-Encoding can't be present with Content-Length";
        var headerLower = headerSection.toLowerCase();
        var teIndex = headerLower.indexOf('transfer-encoding');
        if (teIndex < 0) teIndex = 0;
        emitResponseParseError(responseBuffer, teIndex, false, 'HPE_INVALID_TRANSFER_ENCODING', reason);
        return;
      }
      if (te && te.toLowerCase().indexOf('chunked') !== -1) {
        isChunked = true;
      }
      skipResponseBody = statusCode === 204 || statusCode === 304 || self.method === 'HEAD';

      tcpIncoming = new TcpIncomingMessage(statusCode, statusMessage, responseHeaders, rawResponseHeaders);
      tcpIncoming.socket = socket;
      tcpIncoming.req = self;
      tcpIncoming.httpVersionMajor = httpVerMajor;
      tcpIncoming.httpVersionMinor = httpVerMinor;
      tcpIncoming.httpVersion = httpVerMajor + '.' + httpVerMinor;
      tcpIncoming._socketTimeoutListener = function() {
        tcpIncoming.emit('timeout');
      };
      socket.on('timeout', tcpIncoming._socketTimeoutListener);
      self.res = tcpIncoming;
      var connHdr = (responseHeaders['connection'] || '').toLowerCase();
      var responseEndsAtEof = !isChunked &&
        contentLength < 0 &&
        statusCode !== 204 &&
        statusCode !== 304 &&
        (statusCode < 100 || statusCode >= 200);
      if (httpVerMajor === 1 && httpVerMinor === 0) {
        tcpIncoming.shouldKeepAlive = connHdr.indexOf('keep-alive') !== -1;
      } else {
        tcpIncoming.shouldKeepAlive = connHdr.indexOf('close') === -1;
      }
      if (responseEndsAtEof && self.method !== 'HEAD') {
        tcpIncoming.shouldKeepAlive = false;
      }
      if (self.shouldKeepAlive && !tcpIncoming.shouldKeepAlive) {
        self.shouldKeepAlive = false;
      }
      var isUpgradeResponse = statusCode === 101 &&
        connHdr.indexOf('upgrade') !== -1 &&
        typeof responseHeaders['upgrade'] === 'string' &&
        responseHeaders['upgrade'].length > 0;
      var isConnectResponse = self.method === 'CONNECT' &&
        statusCode >= 200 &&
        statusCode < 300;

      if (isUpgradeResponse) {
        var upgradeHead = (typeof Buffer !== 'undefined')
          ? Buffer.from(bodyStart, 'latin1')
          : bodyStart;
        finishUpgrade(upgradeHead);
        return;
      }
      if (isConnectResponse) {
        responseEmitted = true;
        responseEnded = true;
        clearAbortResponseHook();
        socket._httpMessage = null;
        socket.parser = null;
        clearSocketTimeoutListener(self, socket);
        if (typeof socket.setTimeout === 'function') {
          socket.setTimeout(0);
        }
        cleanupRequestListeners();
        finishRequestWrite();
        self.emit('connect', tcpIncoming, socket,
          (typeof Buffer !== 'undefined') ? Buffer.from(bodyStart, 'latin1') : bodyStart);
        if (!self._closed) {
          self._closed = true;
          scheduleNextTick(function() {
            self.emit('close');
          });
        }
        return;
      }

      tcpIncoming.on('end', function() {
        if (socket && tcpIncoming._socketTimeoutListener) {
          socket.removeListener('timeout', tcpIncoming._socketTimeoutListener);
          tcpIncoming._socketTimeoutListener = null;
        }
        clearSocketTimeoutListener(self, socket);
        if (self.shouldKeepAlive && !tcpIncoming.aborted) {
          if (!self._ended || !self.writableEnded || !self.finished) {
            self._responseEndedBeforeRequestEnd = true;
            return;
          }
          if (self._pendingSocketDrain) {
            self._waitingForSocketDrain = true;
            return;
          }
          releaseSocket();
        } else if (!socket.destroyed) {
          try {
            if (typeof socket.end === 'function') socket.end();
            else socket.destroy();
          } catch (_closeErr) {
            try { socket.destroy(); } catch (_destroyErr) {}
          }
        }
      });
      tcpIncoming.on('timeout', function() {
        self.emit('timeout');
      });

      responseEmitted = true;
      // Check listener count BEFORE emit, because once() listeners are removed during emit
      var hadResponseListeners = self.listenerCount ? self.listenerCount('response') > 0 : true;
      var responseListenerErr = null;
      try {
        self.emit('response', tcpIncoming);
      } catch (emitErr) {
        responseListenerErr = emitErr;
      }
      if (!hadResponseListeners) {
        if (typeof tcpIncoming._dump === 'function') tcpIncoming._dump();
        else if (typeof tcpIncoming.resume === 'function') tcpIncoming.resume();
      }

      if (bodyStart.length > 0 && !skipResponseBody) {
        if (isChunked) {
          processChunkedData(bodyStart);
        } else {
          if (!pushIdentityResponseData(bodyStart)) return;
        }
      }
      if (skipResponseBody) {
        finishResponse();
        if (responseListenerErr) {
          scheduleNextTick(function() {
            throw responseListenerErr;
          });
        }
        return;
      }
      if (!isChunked && contentLength === 0) {
        finishResponse();
      }
      if (responseListenerErr) {
        scheduleNextTick(function() {
          throw responseListenerErr;
        });
      }
    } else if (tcpIncoming && !skipResponseBody) {
      if (isChunked) {
        processChunkedData(str);
      } else {
        pushIdentityResponseData(str);
      }
    }
  }

  function onEnd() {
    if (!responseEmitted && socket && typeof socket._consumeReadBuffer === 'function' && socket._readBufferLength > 0) {
      var trailingData = socket._consumeReadBuffer();
      if (trailingData && trailingData.length > 0) {
        onData(trailingData);
      }
    }
    if (!responseEmitted && responseBuffer.length > 0) {
      if (responseBuffer.indexOf('HTTP/') !== 0 &&
          responseBuffer.indexOf('RTSP/') !== 0 &&
          responseBuffer.indexOf('ICE/') !== 0) {
        emitResponseParseError(responseBuffer, 0, false);
        responseEnded = true;
        return;
      }
      onData('');
    }
    if (!responseEmitted) {
      if (!self._aborted) {
        var closeErr = new Error('socket hang up');
        closeErr.code = 'ECONNRESET';
        self.emit('error', closeErr);
      }
      responseEnded = true;
      return;
    }
    if (responseEnded) return;
    if (contentLength >= 0 || isChunked || (tcpIncoming && tcpIncoming.shouldKeepAlive) || self._aborted) {
      abortResponse();
      return;
    }
    finishResponse();
  }

  function onClose() {
    if (!responseEmitted && socket && typeof socket._consumeReadBuffer === 'function' && socket._readBufferLength > 0) {
      var closeTrailingData = socket._consumeReadBuffer();
      if (closeTrailingData && closeTrailingData.length > 0) {
        onData(closeTrailingData);
      }
    }
    if (!responseEmitted) {
      if (!self._closed) {
        self._closed = true;
        self.emit('close');
      }
      return;
    }
    if (!responseEnded) {
      abortResponse();
      return;
    }
    if (!self._closed) {
      self._closed = true;
      self.emit('close');
    }
  }

  function onError(err) {
    var completedFixedLengthResponse = responseEmitted &&
      !isChunked &&
      contentLength >= 0 &&
      bodyBytesReceived >= contentLength;
    if (err && err.code === 'ECONNRESET') {
      if (responseEmitted) {
        if (!responseEnded && !completedFixedLengthResponse) {
          abortResponse(err);
        }
        return;
      }
      if (responseEnded || completedFixedLengthResponse) {
        return;
      }
    }
    socket._hadError = true;
    if ((self._aborted || self._destroyRequested) &&
        self.errored !== err) {
      if (!self.res || isAbortLikeRequestError(err)) {
        return;
      }
    }
    self.emit('error', err);
  }

  function flushQueuedRequestBody() {
    if (!self._streamingRequest || !self._requestHeadWritten || self.destroyed || self._aborted) {
      return;
    }

    while (self._pendingRequestWrites.length > 0) {
      (function(item) {
        _consumeOutgoingBytes(self, item.queuedLength);
        beginSocketWrite();
        try {
          var payload = self._requestUsesChunkedEncoding
            ? _buildChunkedRequestFrame(item.body)
            : item.body;
          socket.write(payload, function(writeErr) {
            endSocketWrite();
            if (writeErr) {
              socket._hadError = true;
              if (!self._aborted) {
                self.emit('error', writeErr);
              }
              return;
            }
            if (item.callback) {
              item.callback();
            }
            if (self._requestFinalQueued) {
              flushQueuedRequestBody();
            } else {
              maybeReleaseSocketAfterFlush();
            }
          });
        } catch (writeErr) {
          endSocketWrite();
          socket._hadError = true;
          if (!self._aborted) {
            self.emit('error', writeErr);
          }
        }
      })(self._pendingRequestWrites.shift());
    }

    if (!self._requestFinalQueued || self._requestFinalSent || self._pendingSocketDrain) {
      return;
    }

    self._requestFinalSent = true;
    if (self._requestUsesChunkedEncoding) {
      beginSocketWrite();
      try {
        socket.write('0\r\n\r\n', function(writeErr) {
          endSocketWrite();
          if (writeErr) {
            socket._hadError = true;
            if (!self._aborted) {
              self.emit('error', writeErr);
            }
            return;
          }
          finishRequestWrite();
          maybeReleaseSocketAfterFlush();
        });
      } catch (writeErr) {
        endSocketWrite();
        socket._hadError = true;
        if (!self._aborted) {
          self.emit('error', writeErr);
        }
      }
      return;
    }

    finishRequestWrite();
    maybeReleaseSocketAfterFlush();
  }

  socket._httpMessage = self;
  self._abortResponse = abortAttachedResponse;
  socket.on('data', onData);
  socket.on('end', onEnd);
  socket.on('close', onClose);
  socket.on('error', onError);
  socket.on('drain', onSocketDrain);

  if (self.timeout !== undefined && self.timeout !== null) {
    listenSocketTimeout(self);
    setSocketTimeout(socket, self.timeout);
  } else if (self.agent && self.agent.options && self.agent.options.timeout !== undefined) {
    listenSocketTimeout(self);
    setSocketTimeout(socket, self.agent.options.timeout);
  }

  function getSocketConnectOptions() {
    var connectOptions = {};
    var sourceOptions = requestOptions;
    if (!sourceOptions || typeof sourceOptions !== 'object') {
      sourceOptions = null;
    }
    if (sourceOptions) {
      for (var sourceKey in sourceOptions) {
        if (Object.prototype.hasOwnProperty.call(sourceOptions, sourceKey)) {
          connectOptions[sourceKey] = sourceOptions[sourceKey];
        }
      }
    }
    if (connectOptions.socketPath) {
      connectOptions.path = connectOptions.socketPath;
    }
    if (!connectOptions.path && connectOptions.port === undefined) {
      var resolvedConnect = self._resolveConnectionOptions();
      var fallbackOptions = resolvedConnect && resolvedConnect.options;
      if (fallbackOptions && typeof fallbackOptions === 'object') {
        for (var fallbackKey in fallbackOptions) {
          if (!Object.prototype.hasOwnProperty.call(fallbackOptions, fallbackKey)) continue;
          if (connectOptions[fallbackKey] !== undefined) continue;
          connectOptions[fallbackKey] = fallbackOptions[fallbackKey];
        }
      }
      if (connectOptions.socketPath && !connectOptions.path) {
        connectOptions.path = connectOptions.socketPath;
      }
    }
    return connectOptions;
  }

  function writeRawRequest() {
    var rawRequest = self._pendingRawRequest || '';
    if (self._requestHeadWritten || self.destroyed || self._aborted || !rawRequest) {
      flushQueuedRequestBody();
      return;
    }
    self._requestHeadWritten = true;
    beginSocketWrite();
    try {
      socket.write(rawRequest, function(writeErr) {
        endSocketWrite();
        if (writeErr) {
          socket._hadError = true;
          if (!self._aborted) {
            self.emit('error', writeErr);
          }
          return;
        }
        if (self._streamingRequest) {
          flushQueuedRequestBody();
          return;
        }
        finishRequestWrite();
        maybeReleaseSocketAfterFlush();
      });
    } catch (writeErr) {
      endSocketWrite();
      socket._hadError = true;
      if (!self._aborted) {
        self.emit('error', writeErr);
      }
    }
  }
  self._writePendingRequest = writeRawRequest;

  if (!socket.connecting && socket._connected !== true && typeof socket.connect === 'function') {
    try {
      socket.connect(getSocketConnectOptions());
    } catch (connectErr) {
      socket._hadError = true;
      self.emit('error', connectErr);
      return;
    }
  }

  if (socket.connecting || socket._connected !== true) {
    socket.once('connect', writeRawRequest);
  } else {
    writeRawRequest();
  }
};

// TCP-based IncomingMessage for client responses
function TcpIncomingMessage(statusCode, statusMessage, headers, rawHeaders) {
  var ReadableCtor = upgradeTcpIncomingMessagePrototype();
  if (ReadableCtor) {
    ReadableCtor.call(this);
  } else {
    EventEmitter.call(this);
  }
  this.statusCode = statusCode;
  this.statusMessage = statusMessage;
  this.headers = headers;
  this.rawHeaders = rawHeaders || [];
  this.trailers = {};
  this.rawTrailers = [];
  this.httpVersion = '1.1';
  this.httpVersionMajor = 1;
  this.httpVersionMinor = 1;
  this.aborted = false;
  this.complete = false;
  this._consumed = false;
  this.readable = true;
  this.socket = null;
  this.method = null;
  this.url = null;
  // Determine shouldKeepAlive based on HTTP version and Connection header
  var connHeader = (headers && headers['connection']) ? headers['connection'].toLowerCase() : '';
  if (this.httpVersionMajor === 1 && this.httpVersionMinor === 0) {
    this.shouldKeepAlive = connHeader.indexOf('keep-alive') !== -1;
  } else {
    this.shouldKeepAlive = connHeader.indexOf('close') === -1;
  }
  this._httpCloseEmitted = false;
  this._manualChunks = [];
  this._manualReadableScheduled = false;
  this._manualFlowing = false;
  this._manualEnded = false;
  this._manualEndEmitted = false;
}

function _abortIncomingMessageStream(message, err) {
  if (!message) return;
  if (!message.aborted) {
    message.aborted = true;
    if (typeof message.emit === 'function') {
      message.emit('aborted');
    }
  }
  if (message._manualChunks && typeof message._manualChunks.length === 'number') {
    message._manualChunks.length = 0;
  }
  message._manualFlowing = false;
  if (message._readableState) {
    message._readableState.flowing = false;
    message._readableState.reading = false;
    message._readableState.length = 0;
    if (message._readableState.buffer) {
      if (typeof message._readableState.buffer.clear === 'function') {
        message._readableState.buffer.clear();
      } else if (Array.isArray(message._readableState.buffer)) {
        message._readableState.buffer.length = 0;
      }
    }
  }
  if (typeof message.destroy === 'function') {
    if (message.listenerCount && message.listenerCount('error') > 0) {
      message.destroy(err);
    } else {
      message.destroy();
    }
    return;
  }
  message.destroyed = true;
  message.readable = false;
  if (message.listenerCount && message.listenerCount('error') > 0) {
    message.emit('error', err);
  }
  if (typeof message._emitHttpClose === 'function') {
    message._emitHttpClose();
  } else if (typeof message.emit === 'function') {
    message.emit('close');
  }
}

TcpIncomingMessage.prototype = Object.create((Readable || EventEmitter).prototype);
TcpIncomingMessage.prototype.constructor = TcpIncomingMessage;

Object.defineProperty(TcpIncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

TcpIncomingMessage.prototype._read = function() {};
TcpIncomingMessage.prototype._emitHttpClose = function() {
  if (this._httpCloseEmitted) return;
  this._httpCloseEmitted = true;
  this.emit('close');
};
TcpIncomingMessage.prototype._scheduleManualReadable = function() {
  var self = this;
  if (self._manualReadableScheduled) return;
  self._manualReadableScheduled = true;
  setTimeout(function() {
    self._manualReadableScheduled = false;
    if (self.destroyed || self.aborted) return;
    if (self._manualChunks.length > 0 && self.listenerCount && self.listenerCount('readable') > 0) {
      self.emit('readable');
    }
    if (self._manualEnded && self._manualChunks.length === 0) {
      self._emitManualEnd();
    }
  }, 0);
};
TcpIncomingMessage.prototype._emitManualEnd = function() {
  if (this.destroyed || this.aborted) return;
  if (this._manualEndEmitted) return;
  this._manualEndEmitted = true;
  this.complete = true;
  this.emit('end');
  this._emitHttpClose();
};
TcpIncomingMessage.prototype._flushManualData = function() {
  var self = this;
  if (self.destroyed || self.aborted) {
    self._manualChunks.length = 0;
    return;
  }
  if (!self._manualFlowing && (!self.listenerCount || self.listenerCount('data') === 0)) {
    return;
  }
  self._manualFlowing = true;
  while (self._manualChunks.length > 0) {
    if (self.destroyed || self.aborted) {
      self._manualChunks.length = 0;
      return;
    }
    self.emit('data', self._manualChunks.shift());
  }
  if (self.destroyed || self.aborted) {
    self._manualChunks.length = 0;
    return;
  }
  if (self._manualEnded && self._manualChunks.length === 0) {
    setTimeout(function() {
      self._emitManualEnd();
    }, 0);
  }
};
TcpIncomingMessage.prototype._pushBodyChunk = function(chunk) {
  if (this.destroyed || this.aborted) return;
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && typeof this.push === 'function') {
    this.push(chunk);
    return;
  }
  if (this._encoding && typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
    chunk = chunk.toString(this._encoding);
  }
  this._manualChunks.push(chunk);
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else {
    this._scheduleManualReadable();
  }
};
TcpIncomingMessage.prototype._finishResponse = function() {
  var ReadableCtor = getReadableCtor();
  this.complete = true;
  if (ReadableCtor && this._readableState && typeof this.push === 'function') {
    if (this._readableState && this._readableState.endEmitted) {
      this._emitHttpClose();
      return;
    }
    this.push(null);
    if (this._readableState && this._readableState.endEmitted) {
      this._emitHttpClose();
    } else {
      var self = this;
      this.once('end', function() {
        self._emitHttpClose();
      });
    }
    return;
  }
  this._manualEnded = true;
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else if (this._manualChunks.length === 0) {
    this._emitManualEnd();
  } else {
    this._scheduleManualReadable();
  }
};
TcpIncomingMessage.prototype.setEncoding = function(enc) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.setEncoding) {
    ReadableCtor.prototype.setEncoding.call(this, enc);
    return this;
  }
  this._encoding = enc;
  for (var i = 0; i < this._manualChunks.length; i++) {
    var chunk = this._manualChunks[i];
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
      this._manualChunks[i] = chunk.toString(enc);
    }
  }
  return this;
};
TcpIncomingMessage.prototype.pause = function() {
  var ReadableCtor = getReadableCtor();
  this._paused = true;
  this._manualFlowing = false;
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.pause) {
    return ReadableCtor.prototype.pause.call(this);
  }
  return this;
};
TcpIncomingMessage.prototype.resume = function() {
  var ReadableCtor = getReadableCtor();
  this._paused = false;
  this._manualFlowing = true;
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.resume) {
    return ReadableCtor.prototype.resume.call(this);
  }
  this._flushManualData();
  return this;
};
TcpIncomingMessage.prototype._dump = function() {
  this._dumped = true;
  return this.resume();
};
TcpIncomingMessage.prototype.read = function(size) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.read) {
    return ReadableCtor.prototype.read.call(this, size);
  }
  if (this._manualChunks.length === 0) {
    if (this._manualEnded) this._emitManualEnd();
    return null;
  }
  var chunk = this._manualChunks.shift();
  if (this._manualChunks.length === 0 && this._manualEnded) {
    var self = this;
    setTimeout(function() {
      self._emitManualEnd();
    }, 0);
  }
  return chunk;
};
TcpIncomingMessage.prototype.on = function(event, listener) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && typeof this.push === 'function' && typeof ReadableCtor.prototype.on === 'function') {
    return ReadableCtor.prototype.on.call(this, event, listener);
  }
  EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'data') {
    this._manualFlowing = true;
    this._flushManualData();
  } else if (event === 'readable' && this._manualChunks.length > 0) {
    this._scheduleManualReadable();
  } else if (event === 'end' && this._manualEnded && this._manualChunks.length === 0) {
    this._emitManualEnd();
  }
  return this;
};
TcpIncomingMessage.prototype.addListener = TcpIncomingMessage.prototype.on;
TcpIncomingMessage.prototype.pipe = function(dest, options) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.pipe) {
    return ReadableCtor.prototype.pipe.call(this, dest, options);
  }
  var self = this;
  self.on('data', function(chunk) {
    var canWrite = dest.write(chunk);
    if (!canWrite && self.pause) self.pause();
  });
  dest.on('drain', function() { if (self.resume) self.resume(); });
  self.on('end', function() {
    if (!options || options.end !== false) {
      dest.end();
    }
  });
  return dest;
};
TcpIncomingMessage.prototype._destroy = function(err, callback) {
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(); } catch(e) {}
  }
  if (typeof callback === 'function') callback(err || null);
};
TcpIncomingMessage.prototype.destroy = function(err) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.destroy) {
    return ReadableCtor.prototype.destroy.call(this, err);
  }
  if (this.destroyed) return this;
  this.destroyed = true;
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(); } catch(e) {}
  }
  if (err) this.emit('error', err);
  this._emitHttpClose();
  return this;
};
TcpIncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs, callback);
  }
  return this;
};
_attachHttpAsyncIterator(TcpIncomingMessage.prototype);

function request(options, callback) {
  var requestOptions = normalizeClientRequestOptions(options);
  // Support request(url, options, callback) signature
  if (typeof callback === 'object' && callback !== null) {
    var extraOptions = callback;
    callback = arguments[2];
    if (typeof requestOptions === 'object') {
      for (var k in extraOptions) {
        if (Object.prototype.hasOwnProperty.call(extraOptions, k)) {
          requestOptions[k] = extraOptions[k];
        }
      }
      if (hasUrlOptionOverrides(extraOptions)) {
        delete requestOptions.__exactOriginalUrl;
      }
    }
  }
  return new ClientRequest(requestOptions, callback);
}

function get(options, callback) {
  var req = request(options, callback);
  req.end();
  return req;
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------
function Agent(options) {
  if (!(this instanceof Agent)) {
    return new Agent(options);
  }
  EventEmitter.call(this);
  this.options = options || {};
  if (this.options.timeout !== undefined) {
    this.options.timeout = _validateTimeoutValue(this.options.timeout);
  }
  this.defaultPort = this.options.defaultPort || 80;
  this.protocol = this.options.protocol || 'http:';
  if (this.options.noDelay === undefined) {
    this.options.noDelay = true;
  }
  this.keepAlive = this.options.keepAlive || false;
  this.keepAliveMsecs = this.options.keepAliveMsecs || 1000;
  this.maxSockets = this.options.maxSockets || Agent.defaultMaxSockets;
  this.maxFreeSockets = this.options.maxFreeSockets || 256;
  this.maxTotalSockets = this.options.maxTotalSockets;
  this.scheduling = this.options.scheduling || 'lifo';
  this.totalSocketCount = 0;
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
  this.agentKeepAliveTimeoutBuffer =
    typeof this.options.agentKeepAliveTimeoutBuffer === 'number' &&
    this.options.agentKeepAliveTimeoutBuffer >= 0 &&
    isFinite(this.options.agentKeepAliveTimeoutBuffer)
      ? this.options.agentKeepAliveTimeoutBuffer
      : 1000;

  if (this.maxTotalSockets !== undefined) {
    if (typeof this.maxTotalSockets !== 'number') {
      var receivedValue = typeof this.maxTotalSockets === 'string'
        ? "'" + this.maxTotalSockets + "'"
        : String(this.maxTotalSockets);
      var maxTotalTypeErr = new TypeError('The "maxTotalSockets" argument must be of type number. Received type ' +
        typeof this.maxTotalSockets + ' (' + receivedValue + ')');
      maxTotalTypeErr.code = 'ERR_INVALID_ARG_TYPE';
      throw maxTotalTypeErr;
    }
    if (this.maxTotalSockets <= 0 || !isFinite(this.maxTotalSockets)) {
      if (this.maxTotalSockets !== Infinity) {
        var maxTotalRangeErr = new RangeError('The value of "maxTotalSockets" is out of range. It must be > 0. Received ' + this.maxTotalSockets);
        maxTotalRangeErr.code = 'ERR_OUT_OF_RANGE';
        throw maxTotalRangeErr;
      }
    }
  } else {
    this.maxTotalSockets = Infinity;
  }

  if (this.scheduling !== 'fifo' && this.scheduling !== 'lifo') {
    throw createInvalidAgentSchedulingError(this.scheduling);
  }

  var self = this;
  this.on('free', function(socket, requestOptions) {
    var name = self.getName(requestOptions);
    if (!isReusableAgentSocket(socket)) {
      if (socket && typeof socket.destroy === 'function') {
        socket.destroy();
      }
      return;
    }

    var requests = self.requests[name];
    if (requests && requests.length > 0) {
      var nextReq = shiftUsableQueuedAgentRequest(requests);
      if (requests.length === 0) {
        delete self.requests[name];
      }
      if (nextReq) {
        nextReq._queuedAgentOptions = undefined;
        setRequestSocket(self, nextReq, socket, requestOptions);
        return;
      }
    }

    var req = socket._httpMessage;
    if (!req || !req.shouldKeepAlive || !self.keepAlive) {
      socket.destroy();
      return;
    }

    var freeSockets = self.freeSockets[name] || [];
    var freeLen = freeSockets.length;
    var activeLen = self.sockets[name] ? self.sockets[name].length : 0;
    if (self.totalSocketCount > self.maxTotalSockets ||
        activeLen + freeLen > self.maxSockets ||
        freeLen >= self.maxFreeSockets ||
        !self.keepSocketAlive(socket)) {
      socket.destroy();
      return;
    }

    self.freeSockets[name] = freeSockets;
    socket._httpMessage = null;
    self.removeSocket(socket, requestOptions);
    socket.once('error', freeSocketErrorListener);
    freeSockets.push(socket);
  });
}
Agent.prototype = Object.create(EventEmitter.prototype);
Agent.prototype.constructor = Agent;
Agent.defaultMaxSockets = Infinity;

Agent.prototype.destroy = function() {
  var key;
  for (key in this.sockets) {
    var socks = this.sockets[key];
    if (Array.isArray(socks)) {
      for (var i = 0; i < socks.length; i++) {
        try { socks[i].destroy(); } catch(e) {}
      }
    }
  }
  for (key in this.freeSockets) {
    var socks2 = this.freeSockets[key];
    if (Array.isArray(socks2)) {
      for (var j = 0; j < socks2.length; j++) {
        try { socks2[j].destroy(); } catch(e) {}
      }
    }
  }
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
};

Agent.prototype.getName = function(options) {
  if (!options) options = {};
  var name = (options.host || 'localhost') + ':' +
    (options.port || '') + ':' +
    (options.localAddress || '');
  if (options.socketPath) name += ':' + options.socketPath;
  if (options.family === 4 || options.family === 6) {
    if (!options.socketPath) name += ':';
    name += options.family;
  }
  return name;
};

Agent.prototype.addRequest = function(req, options, port, localAddress) {
  options = mergeAgentRequestOptions(this, req, options, port, localAddress);
  var name = this.getName(options);
  this.sockets[name] = this.sockets[name] || [];

  var freeSockets = this.freeSockets[name];
  var socket = null;
  if (freeSockets) {
    socket = takeFreeAgentSocket(freeSockets, this.scheduling);
    if (freeSockets.length === 0) {
      delete this.freeSockets[name];
    }
  }
  var freeLen = freeSockets ? freeSockets.length : 0;
  var socketLen = freeLen + this.sockets[name].length;

  if (socket) {
    asyncResetHandle(socket);
    this.reuseSocket(socket, req);
    this.sockets[name].push(socket);
    setRequestSocket(this, req, socket, options);
    return;
  }

  if (socketLen < this.maxSockets && this.totalSocketCount < this.maxTotalSockets) {
    var self = this;
    this.createSocket(req, options, function(err, createdSocket) {
      if (err) {
        req.onSocket(createdSocket, options, err);
        return;
      }
      setRequestSocket(self, req, createdSocket, options);
    });
    return;
  }

  if (!this.requests[name]) {
    this.requests[name] = [];
  }
  req._queuedAgentOptions = options;
  this.requests[name].push(req);
};

Agent.prototype.createConnection = function(options, callback) {
  var net;
  try { net = require('net'); } catch(e) { return null; }
  return net.createConnection(options, callback);
};

function installAgentListeners(agent, socket, options) {
  function onFree() {
    agent.emit('free', socket, options);
  }
  function onClose() {
    agent.totalSocketCount--;
    agent.removeSocket(socket, options);
  }
  function onTimeout() {
    var pools = agent.freeSockets;
    for (var name in pools) {
      if (Object.prototype.hasOwnProperty.call(pools, name) && pools[name].indexOf(socket) !== -1) {
        socket.destroy();
        return;
      }
    }
  }
  function onRemove() {
    agent.totalSocketCount--;
    agent.removeSocket(socket, options);
    socket.removeListener('close', onClose);
    socket.removeListener('free', onFree);
    socket.removeListener('timeout', onTimeout);
    socket.removeListener('agentRemove', onRemove);
  }

  socket.on('free', onFree);
  socket.on('close', onClose);
  socket.on('timeout', onTimeout);
  socket.on('agentRemove', onRemove);
}

Agent.prototype.createSocket = function(req, options, callback) {
  options = Object.assign({}, options || {}, this.options);
  if (options.socketPath) {
    options.path = options.socketPath;
  } else {
    delete options.path;
  }

  var timeout = req.timeout;
  if (timeout === undefined || timeout === null) {
    timeout = this.options.timeout;
  }
  if (timeout !== undefined) {
    options.timeout = timeout;
  }

  var name = this.getName(options);
  var self = this;
  var finished = false;

  function oncreate(err, socket) {
    if (finished) return;
    finished = true;
    if (err) {
      callback(err, socket || null);
      return;
    }
    self.sockets[name] = self.sockets[name] || [];
    self.sockets[name].push(socket);
    self.totalSocketCount++;
    installAgentListeners(self, socket, options);
    callback(null, socket);
  }

  if (this.keepAlive) {
    options.keepAlive = true;
    options.keepAliveInitialDelay = this.keepAliveMsecs;
  }

  var createConnection = options.createConnection;
  if (typeof createConnection === 'function') {
    try {
      var maybeSocket = createConnection(options, oncreate);
      if (maybeSocket) {
        oncreate(null, maybeSocket);
      }
    } catch (err) {
      oncreate(err, null);
    }
    return;
  }

  var newSocket = this.createConnection(options, oncreate);
  if (newSocket) {
    oncreate(null, newSocket);
  }
};

Agent.prototype.removeSocket = function(socket, options) {
  var name = this.getName(options || {});
  var sets = [this.sockets];
  if (!socket.writable) {
    sets.push(this.freeSockets);
  }

  for (var i = 0; i < sets.length; i++) {
    var pool = sets[i];
    if (pool[name]) {
      var index = pool[name].indexOf(socket);
      if (index !== -1) {
        pool[name].splice(index, 1);
        if (pool[name].length === 0) {
          delete pool[name];
        }
      }
    }
  }

  var req = null;
  var reqOptions = null;
  if (this.requests[name] && this.requests[name].length > 0) {
    req = shiftUsableQueuedAgentRequest(this.requests[name]);
    if (this.requests[name].length === 0) {
      delete this.requests[name];
    }
    reqOptions = req ? (req._queuedAgentOptions || options) : null;
  } else {
    for (var key in this.requests) {
      if (!Object.prototype.hasOwnProperty.call(this.requests, key) || !this.requests[key] || this.requests[key].length === 0) continue;
      if (this.sockets[key] && this.sockets[key].length > 0) break;
      req = shiftUsableQueuedAgentRequest(this.requests[key]);
      if (this.requests[key].length === 0) {
        delete this.requests[key];
      }
      if (req) {
        reqOptions = req._queuedAgentOptions;
        break;
      }
    }
  }

  if (req && reqOptions) {
    var self = this;
    req._queuedAgentOptions = undefined;
    this.createSocket(req, reqOptions, function(err, newSocket) {
      if (err) {
        req.onSocket(newSocket, reqOptions, err);
        return;
      }
      setRequestSocket(self, req, newSocket, reqOptions);
    });
  }
};

Agent.prototype.keepSocketAlive = function(socket) {
  if (typeof socket.setKeepAlive === 'function') {
    socket.setKeepAlive(true, this.keepAliveMsecs);
  }
  if (typeof socket.unref === 'function') {
    socket.unref();
  }

  var agentTimeout = this.options.timeout || 0;
  var canKeepSocketAlive = true;
  if (socket._httpMessage && socket._httpMessage.res && socket._httpMessage.res.headers) {
    var keepAliveHint = socket._httpMessage.res.headers['keep-alive'];
    if (keepAliveHint) {
      var hintMatch = /^timeout=(\d+)/.exec(keepAliveHint);
      if (hintMatch) {
        var hintedTimeout = (parseInt(hintMatch[1], 10) * 1000) - this.agentKeepAliveTimeoutBuffer;
        hintedTimeout = hintedTimeout > 0 ? hintedTimeout : 0;
        if (hintedTimeout === 0) {
          canKeepSocketAlive = false;
        } else if (agentTimeout === 0 || hintedTimeout < agentTimeout) {
          agentTimeout = hintedTimeout;
        }
      }
    }
  }

  if (typeof socket.setTimeout === 'function') {
    socket.setTimeout(agentTimeout);
  }
  return canKeepSocketAlive;
};

Agent.prototype.reuseSocket = function(socket, req) {
  socket.removeListener('error', freeSocketErrorListener);
  req.reusedSocket = true;
  if (typeof socket.ref === 'function') {
    socket.ref();
  }
};

var globalAgent = new Agent();

var METHODS = [
  "ACL", "BIND", "CHECKOUT", "CONNECT", "COPY", "DELETE", "GET", "HEAD",
  "LINK", "LOCK", "M-SEARCH", "MERGE", "MKACTIVITY", "MKCALENDAR",
  "MKCOL", "MOVE", "NOTIFY", "OPTIONS", "PATCH", "POST", "PROPFIND",
  "PROPPATCH", "PURGE", "PUT", "QUERY", "REBIND", "REPORT", "SEARCH",
  "SOURCE", "SUBSCRIBE", "TRACE", "UNBIND", "UNLINK", "UNLOCK",
  "UNSUBSCRIBE"
];

var STATUS_CODES = {
  100: "Continue",
  101: "Switching Protocols",
  102: "Processing",
  103: "Early Hints",
  200: "OK",
  201: "Created",
  202: "Accepted",
  203: "Non-Authoritative Information",
  204: "No Content",
  205: "Reset Content",
  206: "Partial Content",
  207: "Multi-Status",
  208: "Already Reported",
  226: "IM Used",
  300: "Multiple Choices",
  301: "Moved Permanently",
  302: "Found",
  303: "See Other",
  304: "Not Modified",
  305: "Use Proxy",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  402: "Payment Required",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  406: "Not Acceptable",
  407: "Proxy Authentication Required",
  408: "Request Timeout",
  409: "Conflict",
  410: "Gone",
  411: "Length Required",
  412: "Precondition Failed",
  413: "Payload Too Large",
  414: "URI Too Long",
  415: "Unsupported Media Type",
  416: "Range Not Satisfiable",
  417: "Expectation Failed",
  418: "I'm a Teapot",
  421: "Misdirected Request",
  422: "Unprocessable Entity",
  423: "Locked",
  424: "Failed Dependency",
  425: "Too Early",
  426: "Upgrade Required",
  428: "Precondition Required",
  429: "Too Many Requests",
  431: "Request Header Fields Too Large",
  451: "Unavailable For Legal Reasons",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
  505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates",
  507: "Insufficient Storage",
  508: "Loop Detected",
  510: "Not Extended",
  511: "Network Authentication Required"
};

// ---------------------------------------------------------------------------
// HTTP/1.1 Request Parser (for net.js-based server)
// ---------------------------------------------------------------------------
function HttpRequestParser() {
  this._buffer = '';
  this._state = 0; // 0=REQUEST_LINE, 1=HEADERS, 2=BODY, 3=CHUNKED_SIZE, 4=CHUNKED_DATA, 5=CHUNKED_TRAILER, 6=DISCARD_BODY
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';
  this._isChunked = false;
  this._chunkRemaining = 0;
  this._streamingBody = false;
  this.onRequest = null;
  this.onHeadersComplete = null;
  this.onBody = null;
  this.onMessageComplete = null;
  this.onError = null;
}

var MAX_PREBUFFERED_HTTP_REQUEST_BODY = 1024 * 1024;
var MAX_HTTP_CHUNK_EXTENSION_LENGTH = 16 * 1024;

function _toHttpParserString(chunk) {
  if (typeof chunk === 'string') {
    return chunk;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
    return chunk.toString('latin1');
  }
  if (chunk && typeof chunk === 'object' && typeof Buffer !== 'undefined') {
    try {
      if (ArrayBuffer.isView(chunk)) {
        return Buffer
          .from(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0)
          .toString('latin1');
      }
      if (chunk instanceof ArrayBuffer) {
        return Buffer.from(chunk).toString('latin1');
      }
    } catch (_coerceErr) {}
  }
  try {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(chunk).toString('latin1');
    }
  } catch (_bufferErr) {}
  try {
    return chunk.toString('latin1');
  } catch (_stringErr) {
    return String(chunk);
  }
}

HttpRequestParser.prototype.execute = function(chunk) {
  chunk = _toHttpParserString(chunk);
  this._buffer += chunk;
  this._parse();
};

HttpRequestParser.prototype._resetMessageState = function() {
  this._state = 0;
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';
  this._isChunked = false;
  this._chunkRemaining = 0;
  this._streamingBody = false;
};

HttpRequestParser.prototype._buildRequestData = function(options) {
  options = options || {};
  var verParts = this._httpVersion.split('.');
  return {
    method: this._method,
    url: this._url,
    httpVersion: this._httpVersion,
    httpVersionMajor: verParts[0] !== undefined ? (parseInt(verParts[0], 10) || 1) : 1,
    httpVersionMinor: verParts[1] !== undefined ? parseInt(verParts[1], 10) : 1,
    headers: this._headers,
    rawHeaders: this._rawHeaders,
    body: options.body !== undefined ? options.body : this._bodyData,
    hasBody: options.hasBody === true || (options.body !== undefined ? options.body.length > 0 : this._bodyData.length > 0),
    bodyComplete: options.bodyComplete !== false,
    oversizedBody: options.oversizedBody === true
  };
};

HttpRequestParser.prototype._emitParseError = function() {
  this._buffer = '';
  this._resetMessageState();
  if (typeof this.onError === 'function') {
    this.onError.apply(this, arguments);
  }
};

function _parseHttpChunkSizeLine(line) {
  if (typeof line !== 'string' || line.length === 0) {
    return null;
  }
  if (line.indexOf('\r') !== -1 || line.indexOf('\n') !== -1) {
    return null;
  }

  var sizePart = line;
  var semiIdx = line.indexOf(';');
  if (semiIdx !== -1) {
    var extension = line.substring(semiIdx + 1);
    if (extension.length > MAX_HTTP_CHUNK_EXTENSION_LENGTH) {
      return { error: 'chunk_extension_overflow' };
    }
    sizePart = line.substring(0, semiIdx);
  }

  sizePart = sizePart.trim();
  if (!/^[0-9A-Fa-f]+$/.test(sizePart)) {
    return null;
  }

  return {
    size: parseInt(sizePart, 16)
  };
}

HttpRequestParser.prototype._parse = function() {
  while (this._buffer.length > 0) {
    if (this._state === 0) {
      var idx = this._buffer.indexOf('\r\n');
      if (idx === -1) return;
      var line = this._buffer.substring(0, idx);
      this._buffer = this._buffer.substring(idx + 2);
      var spaceIdx = line.indexOf(' ');
      if (spaceIdx <= 0) {
        this._emitParseError();
        return;
      }
      this._method = line.substring(0, spaceIdx);
      var rest = line.substring(spaceIdx + 1);
      var spaceIdx2 = rest.lastIndexOf(' ');
      if (spaceIdx2 <= 0) {
        this._emitParseError();
        return;
      }
      this._url = rest.substring(0, spaceIdx2);
      var ver = rest.substring(spaceIdx2 + 1);
      if (!/^HTTP\/\d+\.\d+$/.test(ver)) {
        this._emitParseError();
        return;
      }
      this._httpVersion = ver.substring(5);
      this._state = 1;
    } else if (this._state === 1) {
      var idx2 = this._buffer.indexOf('\r\n');
      if (idx2 === -1) return;
      if (idx2 === 0) {
        this._buffer = this._buffer.substring(2);
        var te = this._headers['transfer-encoding'];
        this._isChunked = !!(te && te.toLowerCase().indexOf('chunked') !== -1);
        var cl = this._headers['content-length'];
        this._contentLength = cl !== undefined ? (parseInt(cl, 10) || 0) : 0;
        if (this._isChunked || this._contentLength > 0) {
          this._streamingBody = typeof this.onBody === 'function';
        }
        if (!this._streamingBody &&
            this._contentLength > MAX_PREBUFFERED_HTTP_REQUEST_BODY) {
          if (typeof this.onHeadersComplete === 'function') {
            this.onHeadersComplete();
          }
          this._emitRequest({
            hasBody: true,
            bodyComplete: false,
            oversizedBody: true,
            deferReset: true
          });
          this._state = 6;
          continue;
        }
        if (this._isChunked || this._contentLength > 0) {
          if (typeof this.onHeadersComplete === 'function') {
            this.onHeadersComplete(
              this._streamingBody
                ? this._buildRequestData({ body: '', hasBody: true, bodyComplete: false })
                : undefined
            );
          }
        } else if (typeof this.onHeadersComplete === 'function') {
          this.onHeadersComplete();
        }
        if (this._isChunked) {
          this._isChunked = true;
          this._state = 3;
          continue;
        }
        if (this._contentLength > 0) {
          this._state = 2;
        } else {
          this._emitRequest();
        }
      } else {
        var headerLine = this._buffer.substring(0, idx2);
        this._buffer = this._buffer.substring(idx2 + 2);
        var colonIdx = headerLine.indexOf(':');
        if (colonIdx > 0) {
          var key = headerLine.substring(0, colonIdx);
          var value = headerLine.substring(colonIdx + 1).trim();
          var keyLower = key.toLowerCase();
          _appendIncomingHeaderValue(this._headers, keyLower, value);
          this._rawHeaders.push(key, value);
        }
      }
    } else if (this._state === 2) {
      if (this._streamingBody) {
        if (this._buffer.length === 0) return;
        var bodyChunkLength = this._buffer.length < this._contentLength ? this._buffer.length : this._contentLength;
        var bodyChunk = this._buffer.substring(0, bodyChunkLength);
        this._buffer = this._buffer.substring(bodyChunkLength);
        this._contentLength -= bodyChunkLength;
        if (bodyChunk.length > 0 && typeof this.onBody === 'function') {
          this.onBody(bodyChunk);
        }
        if (this._contentLength === 0) {
          if (typeof this.onMessageComplete === 'function') {
            this.onMessageComplete();
          }
          this._resetMessageState();
          continue;
        }
        return;
      }
      if (this._buffer.length >= this._contentLength) {
        this._bodyData = this._buffer.substring(0, this._contentLength);
        this._buffer = this._buffer.substring(this._contentLength);
        this._emitRequest();
      } else {
        return;
      }
    } else if (this._state === 3) {
      // CHUNKED_SIZE
      if (this._buffer.indexOf('\r\n') === -1 &&
          this._buffer.length > (MAX_HTTP_CHUNK_EXTENSION_LENGTH + 32)) {
        this._emitParseError('chunk_extension_overflow');
        return;
      }
      var nlIdx = this._buffer.indexOf('\r\n');
      if (nlIdx === -1) return;
      var chunkLine = this._buffer.substring(0, nlIdx);
      var parsedChunkLine = _parseHttpChunkSizeLine(chunkLine);
      if (!parsedChunkLine) {
        this._emitParseError();
        return;
      }
      if (parsedChunkLine.error === 'chunk_extension_overflow') {
        this._emitParseError('chunk_extension_overflow');
        return;
      }
      this._chunkRemaining = parsedChunkLine.size;
      this._buffer = this._buffer.substring(nlIdx + 2);
      if (isNaN(this._chunkRemaining) || this._chunkRemaining === 0) {
        this._state = 5;
      } else {
        this._state = 4;
      }
    } else if (this._state === 4) {
      // CHUNKED_DATA
      if (this._buffer.length < this._chunkRemaining) {
        if (this._streamingBody) {
          if (this._buffer.length > 0 && typeof this.onBody === 'function') {
            this.onBody(this._buffer);
          }
        } else {
          this._bodyData += this._buffer;
        }
        this._chunkRemaining -= this._buffer.length;
        this._buffer = '';
        return;
      }
      var chunkData = this._buffer.substring(0, this._chunkRemaining);
      if (this._streamingBody) {
        if (chunkData.length > 0 && typeof this.onBody === 'function') {
          this.onBody(chunkData);
        }
      } else {
        this._bodyData += chunkData;
      }
      this._buffer = this._buffer.substring(this._chunkRemaining);
      this._chunkRemaining = 0;
      if (this._buffer.length < 2) {
        this._state = 3;
        return;
      }
      if (this._buffer.charAt(0) !== '\r' || this._buffer.charAt(1) !== '\n') {
        this._emitParseError();
        return;
      }
      this._buffer = this._buffer.substring(2);
      this._state = 3;
    } else if (this._state === 5) {
      // CHUNKED_TRAILER
      var nlIdx2 = this._buffer.indexOf('\r\n');
      if (nlIdx2 === -1) return;
      if (nlIdx2 === 0) {
        this._buffer = this._buffer.substring(2);
        if (this._streamingBody) {
          if (typeof this.onMessageComplete === 'function') {
            this.onMessageComplete();
          }
          this._resetMessageState();
        } else {
          this._emitRequest();
        }
      } else {
        this._buffer = this._buffer.substring(nlIdx2 + 2);
      }
    } else if (this._state === 6) {
      if (this._buffer.length >= this._contentLength) {
        this._buffer = this._buffer.substring(this._contentLength);
        this._resetMessageState();
      } else {
        this._contentLength -= this._buffer.length;
        this._buffer = '';
        return;
      }
    }
  }
};

HttpRequestParser.prototype._emitRequest = function(options) {
  options = options || {};
  var reqData = this._buildRequestData(options);
  if (options.deferReset !== true) {
    this._resetMessageState();
  }

  if (typeof this.onRequest === 'function') {
    this.onRequest(reqData);
  }
};

HttpRequestParser.prototype.close = function() {
  this.onRequest = null;
  this.onHeadersComplete = null;
  this.onBody = null;
  this.onMessageComplete = null;
  this.onError = null;
};

// ---------------------------------------------------------------------------
// ServerResponse
// ---------------------------------------------------------------------------
function ServerResponse(reqOrServerId, requestId) {
  EventEmitter.call(this);
  initOutgoingMessage(this);
  this.statusCode = 200;
  this.statusMessage = undefined;
  this._headers = {};
  this._headerNames = {};
  this._removedHeaderNames = {};
  this[kOutHeaders] = null;
  this._header = null;
  this._headerStatusCode = undefined;
  this._headerStatusMessage = undefined;
  this._headersSent = false;
  this._finished = false;
  this._streaming = false;
  this._bodyParts = [];
  this.socket = null;
  this._socketDrainListener = null;
  this.writableEnded = false;
  this.writableFinished = false;
  this.sendDate = true;

  if (typeof reqOrServerId === 'number') {
    this._serverId = reqOrServerId;
    this._requestId = requestId || 0;
    this._nativeMode = true;
    this._req = null;
    this.req = null;
  } else {
    this._serverId = 0;
    this._requestId = 0;
    this._nativeMode = false;
    this._req = reqOrServerId || null;
    this.req = this._req;
  }
}
ServerResponse.prototype = Object.create(EventEmitter.prototype);
ServerResponse.prototype.constructor = ServerResponse;
if (typeof Object.setPrototypeOf === 'function') {
  Object.setPrototypeOf(ClientRequest.prototype, OutgoingMessage.prototype);
  Object.setPrototypeOf(ServerResponse.prototype, OutgoingMessage.prototype);
} else {
  ClientRequest.prototype.__proto__ = OutgoingMessage.prototype;
  ServerResponse.prototype.__proto__ = OutgoingMessage.prototype;
}

// headersSent as getter
Object.defineProperty(ServerResponse.prototype, 'headersSent', {
  get: function() { return this._headersSent; },
  set: function(v) { this._headersSent = v; },
  enumerable: true,
  configurable: true
});

// connection getter/setter
Object.defineProperty(ServerResponse.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

Object.defineProperty(ServerResponse.prototype, 'writableNeedDrain', {
  get: function() {
    return !!(this.socket && this.socket.writableNeedDrain);
  },
  enumerable: true,
  configurable: true
});

Object.defineProperty(ServerResponse.prototype, 'writableHighWaterMark', {
  get: function() {
    if (this.socket && typeof this.socket.writableHighWaterMark === 'number') {
      return this.socket.writableHighWaterMark;
    }
    return 16384;
  },
  enumerable: true,
  configurable: true
});

ServerResponse.prototype.assignSocket = function(socket) {
  if (this.socket) {
    var socketAssignedErr = new Error('ServerResponse has an already assigned socket');
    socketAssignedErr.code = 'ERR_HTTP_SOCKET_ASSIGNED';
    throw socketAssignedErr;
  }
  this.socket = socket;
  if (!socket) return;
  socket._httpMessage = this;
  var self = this;
  this._socketDrainListener = function() {
    if (!self._finished && !self.destroyed) {
      self._drainFallbackScheduled = false;
      _resetOutgoingBufferState(self);
      self.emit('drain');
    }
  };
  if (typeof socket.on === 'function') {
    socket.on('drain', this._socketDrainListener);
  }
  this.emit('socket', socket);
};

ServerResponse.prototype.detachSocket = function(socket) {
  if (socket && this._socketDrainListener && typeof socket.removeListener === 'function') {
    socket.removeListener('drain', this._socketDrainListener);
  }
  if (socket) socket._httpMessage = null;
  this.socket = null;
};

ServerResponse.prototype.setHeader = function(name, value) {
  if (this._header !== null || this._headersSent) {
    throw _createHeadersSentError('set');
  }
  validateHeaderName(name);
  name = String(name);
  validateHeaderValue(name, value);
  var lc = name.toLowerCase();
  this._headers[lc] = value;
  this._headerNames[lc] = name;
  delete this._removedHeaderNames[lc];
  if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
    this[kOutHeaders] = {};
  }
  this[kOutHeaders][lc] = [name, value];
  return this;
};
ServerResponse.prototype.getHeader = function(name) {
  _validateHeaderLookupName(name);
  return this._headers[resolveHeaderName(name)];
};
ServerResponse.prototype.removeHeader = function(name) {
  if (this._header !== null || this._headersSent) {
    throw _createHeadersSentError('remove');
  }
  _validateHeaderLookupName(name);
  validateHeaderName(name);
  name = String(name);
  var lc = resolveHeaderName(name);
  delete this._headers[lc];
  delete this._headerNames[lc];
  this._removedHeaderNames[lc] = true;
  if (this[kOutHeaders] && typeof this[kOutHeaders] === 'object') {
    delete this[kOutHeaders][lc];
  }
  return this;
};
ServerResponse.prototype.getHeaders = function() {
  var clone = Object.create(null);
  for (var k in this._headers) {
    if (Object.prototype.hasOwnProperty.call(this._headers, k)) clone[k] = this._headers[k];
  }
  return clone;
};
ServerResponse.prototype.getHeaderNames = function() {
  return Object.keys(this._headers);
};
ServerResponse.prototype.getRawHeaderNames = function() {
  var result = [];
  for (var k in this._headerNames) {
    if (Object.prototype.hasOwnProperty.call(this._headerNames, k)) {
      result.push(this._headerNames[k]);
    }
  }
  return result;
};
ServerResponse.prototype.hasHeader = function(name) {
  _validateHeaderLookupName(name);
  return resolveHeaderName(name) in this._headers;
};

ServerResponse.prototype._implicitHeader = function() {
  if (this._header !== null) return;
  this.writeHead(this.statusCode);
};

ServerResponse.prototype.writeHead = function(statusCode, statusMessage, headers) {
  if (this._header !== null || this._headersSent) {
    throw _createHeadersSentError('write');
  }
  // Validate status code
  var sc = statusCode;
  if (typeof sc === 'string') sc = Number(sc);
  if (typeof sc !== 'number' || sc !== sc || sc < 100 || sc > 999 || Math.floor(sc) !== sc) {
    var scErr = new RangeError('Invalid status code: ' + String(statusCode === undefined ? 'undefined' : statusCode));
    scErr.code = 'ERR_HTTP_INVALID_STATUS_CODE';
    throw scErr;
  }
  this.statusCode = sc;
  if (Array.isArray(statusMessage)) {
    headers = statusMessage;
    statusMessage = undefined;
  } else if (typeof statusMessage === 'string') {
    this.statusMessage = statusMessage;
  } else if (typeof statusMessage === 'object' && statusMessage !== null) {
    headers = statusMessage;
    statusMessage = undefined;
  }
  if (statusMessage === undefined) {
    this.statusMessage = STATUS_CODES[sc] || 'unknown';
  }
  this._headerStatusCode = sc;
  this._headerStatusMessage = this.statusMessage !== undefined ? this.statusMessage : (STATUS_CODES[sc] || 'unknown');
  if (headers) {
    applyOutgoingHeaderEntries(this, headers);
  }
  this._header = '';
  return this;
};

ServerResponse.prototype._renderHeaders = function() {
  if (this._header !== null) {
    var sentErr = new Error('Cannot render headers after they are sent to the client');
    sentErr.code = 'ERR_HTTP_HEADERS_SENT';
    throw sentErr;
  }
  var source = this[kOutHeaders];
  if (!source || typeof source !== 'object') return {};
  var rendered = {};
  for (var key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    var entry = source[key];
    if (Array.isArray(entry) && entry.length >= 2) {
      rendered[entry[0]] = entry[1];
    }
  }
  return rendered;
};

ServerResponse.prototype.writeContinue = function() {
  if (!this.socket) return;
  try { this.socket.write('HTTP/1.1 100 Continue\r\n\r\n'); } catch(e) {}
};

ServerResponse.prototype.writeProcessing = function() {
  if (!this.socket) return;
  try { this.socket.write('HTTP/1.1 102 Processing\r\n\r\n'); } catch(e) {}
};

ServerResponse.prototype.writeEarlyHints = function(hints, callback) {
  if (!this.socket) { if (callback) callback(); return; }
  var head = 'HTTP/1.1 103 Early Hints\r\n';
  if (hints) {
    for (var k in hints) {
      if (Object.prototype.hasOwnProperty.call(hints, k)) {
        var vals = Array.isArray(hints[k]) ? hints[k] : [hints[k]];
        for (var i = 0; i < vals.length; i++) {
          head += k + ': ' + vals[i] + '\r\n';
        }
      }
    }
  }
  head += '\r\n';
  try { this.socket.write(head, callback); } catch(e) { if (callback) callback(e); }
};

ServerResponse.prototype.addTrailers = function(headers) {
  OutgoingMessage.prototype.addTrailers.call(this, headers);
  this.trailers = this.trailers || {};
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    var lc = resolveHeaderName(name);
    this.trailers[name] = headers[name];
    if (this._trailers && !Object.prototype.hasOwnProperty.call(this._trailers, name)) {
      Object.defineProperty(this._trailers, name, {
        value: this._trailers[lc],
        configurable: true,
        writable: true,
        enumerable: false,
      });
    }
  }
  return this;
};

ServerResponse.prototype._ensureImplicitHeaders = function() {
  if (this._headersSent || this._header !== null) return;
  if (this.statusMessage !== undefined) {
    this.writeHead(this.statusCode, this.statusMessage);
  } else {
    this.writeHead(this.statusCode);
  }
};

function _coerceServerResponseSocketChunk(chunk, encoding) {
  if (chunk == null) return null;
  if (typeof Buffer !== 'undefined') {
    if (Buffer.isBuffer(chunk)) {
      return Buffer.from(chunk);
    }
    if (typeof ArrayBuffer !== 'undefined') {
      if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
        var _len = chunk.byteLength || chunk.length || 0;
        var _copy = Buffer.alloc(_len);
        _copy.set(new Uint8Array(chunk.buffer, chunk.byteOffset || 0, _len));
        return _copy;
      }
      if (chunk instanceof ArrayBuffer) {
        return Buffer.from(chunk);
      }
    }
    return Buffer.from(String(chunk), encoding || 'utf8');
  }
  return typeof chunk === 'string' ? chunk : String(chunk);
}

function _concatServerResponseSocketBody(parts) {
  if (!parts || parts.length === 0) {
    return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : '';
  }
  if (typeof Buffer !== 'undefined' && Buffer.concat) {
    return Buffer.concat(parts.map(function(part) {
      return _coerceServerResponseSocketChunk(part);
    }));
  }
  return parts.join('');
}

// Native bridge streaming helpers
ServerResponse.prototype._ensureStreaming = function() {
  if (!this._nativeMode) return false;
  if (this._streaming) return true;
  if (typeof __exactHttpRespondStream !== 'function') return false;
  this._ensureImplicitHeaders();
  var headersJson = JSON.stringify(this._headers);
  var result = __exactHttpRespondStream(
    this._serverId,
    this._requestId,
    _getServerResponseStatusCode(this),
    headersJson
  );
  if (result === 0) { this._streaming = true; this._headersSent = true; return true; }
  return false;
};
ServerResponse.prototype._sendChunk = function(chunk) {
  if (typeof __exactHttpRespondChunk !== 'function') return;
  if (typeof chunk === 'string') {
    var encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
    var bytes = encoder ? encoder.encode(chunk) : null;
    if (bytes) __exactHttpRespondChunk(this._serverId, this._requestId, bytes);
  } else if (chunk) {
    __exactHttpRespondChunk(this._serverId, this._requestId, chunk);
  }
};

ServerResponse.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) callback(new Error('write after end')); return false; }
  var writeOk = true;
  if (chunk === null) {
    throw _createNullWriteError();
  }
  if (chunk !== undefined && chunk !== null) {
    if (!_isOutgoingChunk(chunk)) {
      throw _createInvalidChunkTypeError(chunk);
    }
    // Empty string/buffer writes trigger header flush but don't send body data
    var chunkLen = _getOutgoingChunkLength(chunk, encoding);
    if (chunkLen === 0) {
      // Still need to flush headers if not yet sent (Node.js compat)
      if (!this._headersSent && this.socket && !this._nativeMode) {
        this._send(undefined);
      }
      if (callback) setTimeout(callback, 0);
      return true;
    }
    var data = this._nativeMode
      ? _toOutgoingBodyPart(chunk, encoding)
      : _coerceServerResponseSocketChunk(chunk, encoding);
    if (this._nativeMode && this._ensureStreaming()) {
      this._sendChunk(data);
    } else if (this._streaming && this.socket && !this._nativeMode) {
      // Already streaming: use chunked encoding to send data
      if (this._useChunkedEncoding) {
        try {
          var streamChunkedFrame = _buildChunkedRequestFrame(data);
          writeOk = this.socket.write(streamChunkedFrame);
        } catch(e) {
          writeOk = false;
        }
      } else {
        try {
          writeOk = this.socket.write(data);
        } catch(e) {
          writeOk = false;
        }
      }
    } else if (this.socket && !this._nativeMode) {
      writeOk = this._send(data);
    } else {
      _recordOutgoingBytes(this, _getOutgoingBodyPartLength(data));
      this._bodyParts.push(data);
    }
  }
  if (callback) setTimeout(callback, 0);
  var responseWriteOk = writeOk && this.writableLength < this.writableHighWaterMark;
  if (!responseWriteOk) {
    _scheduleOutgoingDrainFallback(this);
  }
  return responseWriteOk;
};

ServerResponse.prototype._streamChunk = function(data, callback) {
  if (!this._headersSent) {
    this._ensureImplicitHeaders();
    var statusCode = _getServerResponseStatusCode(this);
    var statusMsg = _getServerResponseStatusMessage(this);
    var head = 'HTTP/1.1 ' + statusCode + ' ' + statusMsg + '\r\n';
    for (var k in this._headers) {
      if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
        var casedName = this._headerNames[k] || toHeaderCase(k);
        head += casedName + ': ' + this._headers[k] + '\r\n';
      }
    }
    head += '\r\n';
    this._headersSent = true;
    this._streaming = true;
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
      return this.socket.write(
        Buffer.concat([Buffer.from(head, 'latin1'), data]),
        callback ? function() { setTimeout(callback, 0); } : undefined
      );
    }
    return this.socket.write(head + data, callback ? function() { setTimeout(callback, 0); } : undefined);
  } else {
    return this.socket.write(data, callback ? function() { setTimeout(callback, 0); } : undefined);
  }
};

ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this.destroyed || this._closed || this.closed) {
    if (callback) setTimeout(callback, 0);
    return this;
  }
  if (this._finished) {
    var hasChunk = chunk !== undefined && chunk !== null;
    var finishedErr = new Error(hasChunk ? 'write after end' : 'stream already finished');
    finishedErr.code = hasChunk ? 'ERR_STREAM_WRITE_AFTER_END' : 'ERR_STREAM_ALREADY_FINISHED';
    if (callback) {
      setTimeout(function() {
        callback(finishedErr);
      }, 0);
    }
    if (hasChunk) {
      var selfFinished = this;
      setTimeout(function() {
        selfFinished.emit('error', finishedErr);
      }, 0);
    }
    return this;
  }
  if (callback) this.once('finish', callback);
  if (chunk !== undefined && chunk !== null) {
    if (!_isOutgoingChunk(chunk)) {
      throw _createInvalidChunkTypeError(chunk);
    }
    if (!this._nativeMode && !this._headersSent && !this._streaming) {
      var endData = _coerceServerResponseSocketChunk(chunk, encoding);
      this._bodyParts.push(endData);
      _recordOutgoingBytes(this, _getOutgoingBodyPartLength(endData));
    } else {
      this.write(chunk, encoding);
    }
  }
  this._finished = true;
  this.finished = true;
  this.writableEnded = true;

  if (this._nativeMode) {
    if (this._streaming) {
      if (typeof __exactHttpRespondEnd === 'function') __exactHttpRespondEnd(this._serverId, this._requestId);
      _resetOutgoingBufferState(this);
      this.writableFinished = true;
      var selfStreaming = this;
      setTimeout(function() {
        selfStreaming.emit('finish');
        if (!selfStreaming._closed) {
          selfStreaming._closed = true;
          selfStreaming.closed = true;
          selfStreaming.emit('close');
        }
      }, 0);
    } else {
      this._sendNativeResponse();
    }
  } else {
    this._sendSocketResponse();
  }
  return this;
};

ServerResponse.prototype._sendNativeResponse = function() {
  this._ensureImplicitHeaders();
  var headersJson = JSON.stringify(this._headers);
  var body = _concatOutgoingBodyParts(this._bodyParts);
  var statusCode = _getServerResponseStatusCode(this);
  this._headersSent = true;
  if (typeof __exactHttpRespond === 'function') {
    __exactHttpRespond(this._serverId, this._requestId, statusCode, headersJson, body);
  } else if (typeof __exactHttpRespondString === 'function') {
    __exactHttpRespondString(
      this._serverId,
      this._requestId,
      statusCode,
      headersJson,
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(body)) ? body.toString('utf8') : body
    );
  }
  _resetOutgoingBufferState(this);
  this.writableFinished = true;
  var self = this;
  setTimeout(function() {
    self.emit('finish');
    if (!self._closed) {
      self._closed = true;
      self.closed = true;
      self.emit('close');
    }
  }, 0);
};

ServerResponse.prototype._sendSocketResponse = function() {
  var socket = this.socket;
  if (socket) {
    var req = this._req;
    var reqConnection = (req && req.headers && req.headers['connection']) || '';
    var reqTE = (req && req.headers && req.headers['te']) || '';
    var httpVersionMajor = (req && req.httpVersionMajor != null) ? req.httpVersionMajor : 1;
    var httpVersionMinor = (req && req.httpVersionMinor != null) ? req.httpVersionMinor : 1;
    var respConnection = this._headers['connection'] || '';
    var reqConnectionLower = reqConnection.toLowerCase();
    var respConnectionLower = (typeof respConnection === 'string') ? respConnection.toLowerCase() : '';

    var clientSupportsKeepAlive;
    if (httpVersionMajor === 1 && httpVersionMinor === 0) {
      clientSupportsKeepAlive = reqConnectionLower.indexOf('keep-alive') !== -1;
    } else {
      clientSupportsKeepAlive = reqConnectionLower.indexOf('close') === -1;
    }

    var keepAlive = clientSupportsKeepAlive
      && respConnectionLower.indexOf('close') === -1;

    if (!this._headersSent) {
      this._ensureImplicitHeaders();
      var body = _concatServerResponseSocketBody(this._bodyParts);
      var bodyLength = _getOutgoingBodyPartLength(body);
      var statusCode = _getServerResponseStatusCode(this);
      var statusMsg = _getServerResponseStatusMessage(this);
      var canHaveBody = _responseCanHaveBody(statusCode, req && req.method);
      var head = 'HTTP/1.1 ' + statusCode + ' ' + statusMsg + '\r\n';
      var shouldSendTrailers = _hasOutgoingTrailers(this) &&
        httpVersionMajor === 1 && httpVersionMinor === 1;
      if (shouldSendTrailers) {
        keepAlive = false;
      }

      if (httpVersionMajor === 1 && httpVersionMinor === 0) {
        var hasExplicitFraming = this._headers['content-length'] != null
          || (this._headers['transfer-encoding'] || '').toString().toLowerCase().indexOf('chunked') !== -1;
        var clientSendsTE = reqTE.toLowerCase().indexOf('chunked') !== -1;
        if (!hasExplicitFraming && !clientSendsTE) {
          keepAlive = false;
          if (this._headers['connection']) {
            this._headers['connection'] = 'close';
          }
        }
      }
      if (shouldSendTrailers && !_hasChunkedTransferEncoding(this._headers['transfer-encoding'])) {
        delete this._headers['content-length'];
        delete this._headerNames['content-length'];
        if (this[kOutHeaders] && typeof this[kOutHeaders] === 'object') {
          delete this[kOutHeaders]['content-length'];
        }
        this._headers['transfer-encoding'] = 'chunked';
        this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
      }
      if (this._headers['content-length'] == null &&
          !_hasChunkedTransferEncoding(this._headers['transfer-encoding'])) {
        if (shouldSendTrailers &&
            httpVersionMajor === 1 &&
            httpVersionMinor === 1) {
          this._headers['transfer-encoding'] = 'chunked';
          this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
        } else if (keepAlive &&
            canHaveBody &&
            httpVersionMajor === 1 &&
            httpVersionMinor === 1) {
          this._headers['transfer-encoding'] = 'chunked';
          this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
        } else if (canHaveBody &&
            !this._removedHeaderNames['content-length']) {
          this._headers['content-length'] = String(bodyLength);
          this._headerNames['content-length'] = 'Content-Length';
        }
      }
      this._useChunkedEncoding = _hasChunkedTransferEncoding(this._headers['transfer-encoding']);
      if (!canHaveBody) {
        if (this._useChunkedEncoding) {
          keepAlive = false;
        }
        this._useChunkedEncoding = false;
        body = typeof Buffer !== 'undefined' ? Buffer.alloc(0) : '';
        bodyLength = 0;
      }
      if (socket._httpServer && socket._httpServer._closing) {
        keepAlive = false;
      }
      var autoConnectionValue = null;
      if (!this._headers['connection']) {
        if (this._removedHeaderNames['connection']) {
          keepAlive = false;
        } else {
          autoConnectionValue = keepAlive ? 'keep-alive' : 'close';
        }
      } else {
        keepAlive = (typeof this._headers['connection'] === 'string')
          ? this._headers['connection'].toLowerCase().indexOf('keep-alive') !== -1
          : false;
      }
      if (this.sendDate && !this._headers['date'] && !this._removedHeaderNames['date']) {
        this._headers['date'] = new Date().toUTCString();
        this._headerNames['date'] = 'Date';
      }
      if (autoConnectionValue !== null) {
        this._headers['connection'] = autoConnectionValue;
        this._headerNames['connection'] = 'Connection';
      }
      for (var k in this._headers) {
        if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
          var casedName = this._headerNames[k] || toHeaderCase(k);
          var hVal = this._headers[k];
          if (Array.isArray(hVal)) {
            for (var hi = 0; hi < hVal.length; hi++) {
              head += casedName + ': ' + hVal[hi] + '\r\n';
            }
          } else {
            head += casedName + ': ' + hVal + '\r\n';
          }
        }
      }
      head += '\r\n';
      this._headersSent = true;
      var useChunkedBody = this._useChunkedEncoding;

      if (keepAlive) {
        try {
          socket.write(head);
          if (useChunkedBody) {
            if (bodyLength > 0) socket.write(_buildChunkedRequestFrame(body));
            socket.write('0\r\n' + _formatOutgoingTrailers(this._trailers, this._trailerNames) + '\r\n');
          } else if (bodyLength > 0) {
            socket.write(body);
          }
        } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
        this.detachSocket(socket);
        socket.parser = null;
        socket[kTimeout] = null;
        try {
          if (useChunkedBody && bodyLength === 0) {
            socket.end(head + '0\r\n' + _formatOutgoingTrailers(this._trailers, this._trailerNames) + '\r\n');
          } else if (!useChunkedBody && bodyLength === 0) {
            socket.write(head, function(writeErr) {
              if (writeErr) {
                try { socket.destroy(writeErr); } catch (_destroyAfterHeadErr) {}
                return;
              }
              setTimeout(function() {
                if (!socket.destroyed) {
                  try { socket.end(); } catch (_endAfterHeadErr) {}
                }
              }, 0);
            });
          } else {
            if (useChunkedBody) {
              socket.write(head);
              socket.write(_buildChunkedRequestFrame(body));
              socket.end('0\r\n' + _formatOutgoingTrailers(this._trailers, this._trailerNames) + '\r\n');
            } else {
              var finalBody = (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(body))
                ? Buffer.concat([Buffer.from(head, 'latin1'), body])
                : head + body;
              socket._ended = true;
              socket.write(finalBody, function(writeErr) {
                if (writeErr) {
                  try { socket.destroy(writeErr); } catch (_destroyAfterBodyErr) {}
                  return;
                }
                setTimeout(function() {
                  if (!socket.destroyed) {
                    try {
                      socket.end(typeof Buffer !== 'undefined' && Buffer.alloc ? Buffer.alloc(0) : '');
                    } catch (_endAfterBodyErr) {}
                  }
                }, 0);
              });
            }
          }
        } catch(e) {
          try { socket.destroy(); } catch(e2) {}
        }
      }
    } else {
      // Headers already sent (streaming mode)
      var remainingBody = _concatServerResponseSocketBody(this._bodyParts);
      var remainingBodyLength = _getOutgoingBodyPartLength(remainingBody);
      this._bodyParts = [];
      var streamKeepAlive = (this._headers['connection'] || '').toString().toLowerCase().indexOf('keep-alive') !== -1;
      if (!streamKeepAlive) {
        streamKeepAlive = keepAlive;
      }
      if (streamKeepAlive) {
        try {
          if (this._useChunkedEncoding) {
            if (remainingBodyLength > 0) socket.write(_buildChunkedRequestFrame(remainingBody));
            socket.write('0\r\n' + _formatOutgoingTrailers(this._trailers, this._trailerNames) + '\r\n');
          } else if (remainingBodyLength > 0) {
            socket.write(remainingBody);
          }
        } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
        this.detachSocket(socket);
        socket.parser = null;
        socket[kTimeout] = null;
        try {
          if (this._useChunkedEncoding) {
            if (remainingBodyLength > 0) socket.write(_buildChunkedRequestFrame(remainingBody));
            socket.end('0\r\n' + _formatOutgoingTrailers(this._trailers, this._trailerNames) + '\r\n');
          } else if (remainingBodyLength > 0) {
            socket.end(remainingBody);
          } else {
            socket.end();
          }
        } catch(e) {
          try { socket.destroy(); } catch(e2) {}
        }
      }
    }
  }

  _resetOutgoingBufferState(this);
  this.writableFinished = true;
  var self = this;
  setTimeout(function() {
    self.emit('finish');
    if (!self._closed) {
      self._closed = true;
      self.closed = true;
      self.emit('close');
    }
  }, 0);
};

ServerResponse.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs);
  }
  return this;
};

// _send is an internal method that flushes buffered writes to the socket
ServerResponse.prototype._send = function(data) {
  var hasData = data !== undefined && data !== null;
  if (data && _getOutgoingBodyPartLength(data) > 0) {
    this._bodyParts.push(data);
  }
  var writeOk = true;
  // In socket mode, flush any pending body parts (or flush headers if not yet sent)
  if (this.socket && !this._nativeMode &&
      (this._bodyParts.length > 0 || !this._headersSent)) {
    var flushed = _concatServerResponseSocketBody(this._bodyParts);
    var flushedLength = _getOutgoingBodyPartLength(flushed);
    this._bodyParts = [];

    // Determine if chunked encoding should be used (HTTP/1.1 only)
    var req = this._req;
    var isHttp10 = req && req.httpVersionMajor === 1 && req.httpVersionMinor === 0;

    if (!this._headersSent) {
      this._ensureImplicitHeaders();
      // Start streaming - set connection before transfer-encoding for proper header ordering
      if (!this._headers['connection']) {
        this._headers['connection'] = 'close';
        this._headerNames['connection'] = 'Connection';
      }
      if (!isHttp10 && !this._headers['content-length'] && !this._headers['transfer-encoding']) {
        this._headers['transfer-encoding'] = 'chunked';
        this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
        this._useChunkedEncoding = true;
      } else {
        this._useChunkedEncoding = _hasChunkedTransferEncoding(this._headers['transfer-encoding']);
      }
      var statusCode = _getServerResponseStatusCode(this);
      var statusMsg = _getServerResponseStatusMessage(this);
      var head = 'HTTP/1.1 ' + statusCode + ' ' + statusMsg + '\r\n';
      if (this.sendDate && !this._headers['date']) {
        this._headers['date'] = new Date().toUTCString();
        this._headerNames['date'] = 'Date';
      }
      for (var k in this._headers) {
        if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
          var casedName = this._headerNames[k] || toHeaderCase(k);
          var hVal = this._headers[k];
          if (Array.isArray(hVal)) {
            for (var hi = 0; hi < hVal.length; hi++) {
              head += casedName + ': ' + hVal[hi] + '\r\n';
            }
          } else {
            head += casedName + ': ' + hVal + '\r\n';
          }
        }
      }
      head += '\r\n';
      this._headersSent = true;
      this._streaming = true;
      if (this._useChunkedEncoding) {
        try {
          writeOk = this.socket.write(head);
          if (flushedLength > 0) {
            var chunkedFrame = _buildChunkedRequestFrame(flushed);
            writeOk = this.socket.write(chunkedFrame) && writeOk;
          }
        } catch(e) {
          writeOk = false;
        }
      } else {
        try {
          writeOk = this.socket.write(head);
          if (flushedLength > 0) {
            writeOk = this.socket.write(flushed) && writeOk;
          }
        } catch(e) {
          writeOk = false;
        }
      }
    } else {
      // Already streaming
      if (this._useChunkedEncoding && flushedLength > 0) {
        try {
          var chunkedFrame2 = _buildChunkedRequestFrame(flushed);
          writeOk = this.socket.write(chunkedFrame2);
        } catch(e) {
          writeOk = false;
        }
      } else if (flushedLength > 0) {
        try {
          writeOk = this.socket.write(flushed);
        } catch(e) {
          writeOk = false;
        }
      }
    }
  }
  return writeOk;
};

ServerResponse.prototype.flushHeaders = function() {
  if (this._headersSent) return;
  if (this.socket && !this._nativeMode) {
    this._ensureImplicitHeaders();
    var statusCode = _getServerResponseStatusCode(this);
    var statusMsg = _getServerResponseStatusMessage(this);
    var head = 'HTTP/1.1 ' + statusCode + ' ' + statusMsg + '\r\n';
    if (this.sendDate && !this._headers['date']) {
      this._headers['date'] = new Date().toUTCString();
      this._headerNames['date'] = 'Date';
    }
    for (var k in this._headers) {
      if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
        var casedName = this._headerNames[k] || toHeaderCase(k);
        var hVal = this._headers[k];
        if (Array.isArray(hVal)) {
          for (var hi = 0; hi < hVal.length; hi++) {
            head += casedName + ': ' + hVal[hi] + '\r\n';
          }
        } else {
          head += casedName + ': ' + hVal + '\r\n';
        }
      }
    }
    head += '\r\n';
    this._headersSent = true;
    this._streaming = true;
    try { this.socket.write(head); } catch(e) {}
  }
};

ServerResponse.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  if (this._finished || this.finished) {
    this.destroyed = true;
    if (err) this.errored = err;
    return this;
  }
  this._finished = true;
  this.finished = true;
  this.destroyed = true;
  this._closed = true;
  this.closed = true;
  this.writableEnded = true;
  this.writableFinished = true;
  _resetOutgoingBufferState(this);
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(err); } catch(e) {}
  }
  if (err) this.errored = err;
  this.emit('close');
  return this;
};

ServerResponse.prototype.cork = function() {};
ServerResponse.prototype.uncork = function() {};

// ---------------------------------------------------------------------------
// ServerIncomingMessage for server-side requests
// ---------------------------------------------------------------------------
function ServerIncomingMessage(requestData, serverId) {
  EventEmitter.call(this);
  this.method = requestData.method || 'GET';
  this.url = requestData.url || '/';
  this.httpVersion = requestData.httpVersion || '1.1';
  this.httpVersionMajor = requestData.httpVersionMajor != null ? requestData.httpVersionMajor : 1;
  this.httpVersionMinor = requestData.httpVersionMinor != null ? requestData.httpVersionMinor : 1;
  this.headers = {};
  this.rawHeaders = [];
  this.trailers = {};
  this.rawTrailers = [];
  this.path = requestData.path || requestData.url || '/';
  this.query = requestData.query || '';
  this.socket = null;
  this.readable = true;

  var rawBody = requestData.body || '';
  if (serverId && rawBody) {
    if (typeof atob === 'function') {
      try { rawBody = atob(rawBody); } catch(e) {}
    } else {
      var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      var lookup = {};
      for (var ci = 0; ci < chars.length; ci++) lookup[chars[ci]] = ci;
      var b64 = rawBody.replace(/[^A-Za-z0-9+\/]/g, '');
      var decoded = '';
      for (var bi = 0; bi < b64.length; bi += 4) {
        var a = lookup[b64[bi]] || 0, b = lookup[b64[bi+1]] || 0;
        var c = lookup[b64[bi+2]] || 0, d = lookup[b64[bi+3]] || 0;
        decoded += String.fromCharCode((a << 2) | (b >> 4));
        if (b64[bi+2] !== '=') decoded += String.fromCharCode(((b & 15) << 4) | (c >> 2));
        if (b64[bi+3] !== '=') decoded += String.fromCharCode(((c & 3) << 6) | d);
      }
      rawBody = decoded;
    }
  }
  this._manualChunks = [];
  if (rawBody) {
    this._manualChunks.push((typeof Buffer !== 'undefined') ? Buffer.from(rawBody, 'latin1') : rawBody);
  }
  this._manualFlowing = false;
  this._manualEnded = requestData.bodyComplete !== false;
  this._manualEndEmitted = false;
  this._manualReadableScheduled = false;
  this._encoding = null;
  this._serverId = serverId || 0;
  this._requestId = requestData.id || 0;

  if (requestData.headers) {
    if (Array.isArray(requestData.headers)) {
      for (var ki = 0; ki < requestData.headers.length; ki++) {
        var pair = requestData.headers[ki];
        if (!pair || pair.length < 2) continue;
        var lkPair = resolveHeaderName(pair[0]);
        this.headers[lkPair] = pair[1];
      }
    } else if (typeof requestData.headers === 'object') {
      for (var kh in requestData.headers) {
        if (Object.prototype.hasOwnProperty.call(requestData.headers, kh)) {
          var lk = resolveHeaderName(kh);
          this.headers[lk] = requestData.headers[kh];
        }
      }
    }
  }
  if (Array.isArray(requestData.rawHeaders) && requestData.rawHeaders.length > 0) {
    this.rawHeaders = requestData.rawHeaders.slice();
  } else if (requestData.headers) {
    if (Array.isArray(requestData.headers)) {
      for (var rhi = 0; rhi < requestData.headers.length; rhi++) {
        var rawPair = requestData.headers[rhi];
        if (!rawPair || rawPair.length < 2) continue;
        this.rawHeaders.push(rawPair[0], rawPair[1]);
      }
    } else if (typeof requestData.headers === 'object') {
      for (var rhk in requestData.headers) {
        if (Object.prototype.hasOwnProperty.call(requestData.headers, rhk)) {
          this.rawHeaders.push(rhk, requestData.headers[rhk]);
        }
      }
    }
  }
  this.complete = this._manualEnded;
  this.aborted = false;
  this.destroyed = false;
  this._closeEmitted = false;
  this._closeScheduled = false;
}
ServerIncomingMessage.prototype = Object.create(EventEmitter.prototype);
ServerIncomingMessage.prototype.constructor = ServerIncomingMessage;

Object.defineProperty(ServerIncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

ServerIncomingMessage.prototype.setEncoding = function(enc) {
  this._encoding = enc;
  for (var i = 0; i < this._manualChunks.length; i++) {
    var chunk = this._manualChunks[i];
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
      this._manualChunks[i] = chunk.toString(enc);
    }
  }
  return this;
};
ServerIncomingMessage.prototype._emitHttpClose = function() {
  if (this._closeEmitted || this._closeScheduled) return;
  this._closeEmitted = true;
  this.emit('close');
};
ServerIncomingMessage.prototype._scheduleManualReadable = function() {
  var self = this;
  if (self._manualReadableScheduled) return;
  self._manualReadableScheduled = true;
  setTimeout(function() {
    self._manualReadableScheduled = false;
    if (self.destroyed) return;
    if (self._manualChunks.length > 0 && self.listenerCount && self.listenerCount('readable') > 0) {
      self.emit('readable');
    }
    if (self._manualEnded && self._manualChunks.length === 0) {
      self._emitManualEnd();
    }
  }, 0);
};
ServerIncomingMessage.prototype._emitManualEnd = function() {
  if (this._manualEndEmitted) return;
  this._manualEndEmitted = true;
  this.complete = true;
  this.readable = false;
  if (this._readableState) {
    this._readableState.ended = true;
  }
  this.emit('end');
  if (this._readableState) {
    this._readableState.endEmitted = true;
  }
  this._emitHttpClose();
};
ServerIncomingMessage.prototype._flushManualData = function() {
  var self = this;
  if (!this._manualFlowing && (!this.listenerCount || this.listenerCount('data') === 0)) {
    return;
  }
  this._manualFlowing = true;
  while (this._manualChunks.length > 0) {
    this.emit('data', this._manualChunks.shift());
  }
  if (this._manualEnded && this._manualChunks.length === 0) {
    setTimeout(function() {
      self._emitManualEnd();
    }, 0);
  }
};
ServerIncomingMessage.prototype._pushBodyChunk = function(chunk) {
  if (this.destroyed || chunk == null) return;
  if (this._encoding && typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
    chunk = chunk.toString(this._encoding);
  }
  this._manualChunks.push(chunk);
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else {
    this._scheduleManualReadable();
  }
};
ServerIncomingMessage.prototype._finishBody = function() {
  if (this._manualEnded) return;
  this._manualEnded = true;
  this.complete = true;
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else if (this._manualChunks.length === 0) {
    this._emitManualEnd();
  } else {
    this._scheduleManualReadable();
  }
};
ServerIncomingMessage.prototype.isPaused = function() {
  return !this._manualFlowing;
};
ServerIncomingMessage.prototype.pause = function() {
  this._manualFlowing = false;
  return this;
};
ServerIncomingMessage.prototype.resume = function() {
  this._manualFlowing = true;
  this._flushManualData();
  return this;
};
ServerIncomingMessage.prototype.read = function() {
  if (this._manualChunks.length === 0) {
    if (this._manualEnded) this._emitManualEnd();
    return null;
  }
  var readBody = this._manualChunks.shift();
  if (this._manualChunks.length === 0 && this._manualEnded) {
    var self = this;
    setTimeout(function() {
      self._emitManualEnd();
    }, 0);
  }
  return readBody;
};
ServerIncomingMessage.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  var wasComplete = this.complete;
  this.destroyed = true;
  this.readable = false;
  this.complete = true;
  this._closeScheduled = true;
  if (wasComplete && err && (err.code === 'ABORT_ERR' || err.name === 'AbortError')) {
    err = null;
  }
  if (!err && !wasComplete) {
    err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    this.aborted = true;
  }
  var self = this;
  setTimeout(function() {
    if (err) self.emit('error', err);
    if (!self._closeEmitted) {
      self._closeEmitted = true;
      self.emit('close');
    }
    var socket = self.socket;
    var activeResponse = socket && socket._httpMessage;
    if (
      socket &&
      !socket.destroyed &&
      activeResponse &&
      activeResponse._finished !== true
    ) {
      try { self.socket.destroy(); } catch(e) {}
    }
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs);
  }
  return this;
};

ServerIncomingMessage.prototype.on = function(event, listener) {
  EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'data') {
    this.resume();
  } else if (event === 'readable' && this._manualChunks.length > 0) {
    this._scheduleManualReadable();
  } else if (event === 'end' && this._manualEnded && this._manualChunks.length === 0) {
    this._scheduleManualReadable();
  }
  return this;
};
ServerIncomingMessage.prototype.addListener = ServerIncomingMessage.prototype.on;
ServerIncomingMessage.prototype.pipe = function(dest, options) {
  var self = this;
  self.on('data', function(chunk) {
    var canWrite = dest.write(chunk);
    if (!canWrite && self.pause) self.pause();
  });
  dest.on('drain', function() {
    if (self.resume) self.resume();
  });
  self.on('end', function() {
    if (!options || options.end !== false) {
      dest.end();
    }
  });
  return dest;
};
_attachHttpAsyncIterator(ServerIncomingMessage.prototype);

var _defaultHttpHighWaterMark = 16 * 1024;
try {
  var _streamState = require('internal/streams/state');
  if (_streamState && typeof _streamState.getDefaultHighWaterMark === 'function') {
    _defaultHttpHighWaterMark = _streamState.getDefaultHighWaterMark();
  }
} catch (_streamStateErr) {}

function _copyPrototypeMembers(target, ctor) {
  if (!target || !ctor || !ctor.prototype) return;
  var proto = ctor.prototype;
  var names = Object.getOwnPropertyNames(proto);
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (name === 'constructor') continue;
    var descriptor = Object.getOwnPropertyDescriptor(proto, name);
    if (!descriptor) continue;
    try {
      Object.defineProperty(target, name, descriptor);
    } catch (_copyErr) {}
  }
}

function _createServerIncomingMessage(server, requestData, serverId, socket) {
  var req = new ServerIncomingMessage(requestData, serverId);
  var highWaterMark = server && typeof server[kHighWaterMark] === 'number'
    ? server[kHighWaterMark]
    : _defaultHttpHighWaterMark;
  req._readableState = req._readableState || {};
  req._readableState.highWaterMark = highWaterMark;
  if (socket) req.socket = socket;
  if (server && server._incomingMessageCtor && server._incomingMessageCtor !== ServerIncomingMessage) {
    _copyPrototypeMembers(req, server._incomingMessageCtor);
  }
  return req;
}

function _createServerResponse(server, req, serverId, requestId) {
  var res = serverId
    ? new ServerResponse(serverId, requestId || 0)
    : new ServerResponse(req);
  res[kHighWaterMark] = server && typeof server[kHighWaterMark] === 'number'
    ? server[kHighWaterMark]
    : _defaultHttpHighWaterMark;
  if (server && server._serverResponseCtor && server._serverResponseCtor !== ServerResponse) {
    _copyPrototypeMembers(res, server._serverResponseCtor);
  }
  return res;
}

function _destroyHttpTimer(timer) {
  if (!timer) return;
  clearTimeout(timer);
  if (typeof timer.destroy === 'function') {
    try { timer.destroy(); } catch (_destroyTimerErr) {}
  }
}

function _createHeadersSentError(action) {
  var err = new Error('Cannot ' + action + ' headers after they are sent to the client');
  err.code = 'ERR_HTTP_HEADERS_SENT';
  return err;
}

function _getServerResponseStatusCode(response) {
  return response && response._headerStatusCode != null ? response._headerStatusCode : response.statusCode;
}

function _getServerResponseStatusMessage(response) {
  if (!response) return 'Unknown';
  if (response._headerStatusMessage !== undefined) return response._headerStatusMessage;
  if (response.statusMessage !== undefined) return response.statusMessage;
  var statusCode = _getServerResponseStatusCode(response);
  return STATUS_CODES[statusCode] || 'Unknown';
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
function Server(options, requestListener) {
  if (!(this instanceof Server)) {
    return new Server(options, requestListener);
  }
  if (typeof options === 'function') {
    // Handle Server(requestListener, options) form
    var _tmpListener = options;
    options = (typeof requestListener === 'object' && requestListener !== null) ? requestListener : {};
    requestListener = _tmpListener;
  }
  options = options || {};
  EventEmitter.call(this);
  this._listening = false;
  this._closing = false;
  this._port = 0;
  this._hostname = '127.0.0.1';
  this._netServer = null;
  this._serverId = 0;
  this._useNative = false;
  this._sockets = typeof Set === 'function' ? new Set() : null;
  this._socketTimeout = 0;
  this._serverTimeoutId = null;
  this[kConnectionsCheckingInterval] = null;
  this.timeout = 0;
  this.keepAliveTimeout = options.keepAliveTimeout != null ? options.keepAliveTimeout : 5000;
  this.maxHeadersCount = options.maxHeadersCount != null ? options.maxHeadersCount : 2000;
  this.requestTimeout = options.requestTimeout != null ? options.requestTimeout : 300000;
  this.headersTimeout = options.headersTimeout != null ? options.headersTimeout : Math.min(60000, this.requestTimeout || 60000);
  this.maxRequestsPerSocket = options.maxRequestsPerSocket != null ? options.maxRequestsPerSocket : 0;
  this.connectionsCheckingInterval =
    options.connectionsCheckingInterval != null ? options.connectionsCheckingInterval : 30000;
  this[kHighWaterMark] = options.highWaterMark != null ? options.highWaterMark : _defaultHttpHighWaterMark;
  this._incomingMessageCtor = options.IncomingMessage || ServerIncomingMessage;
  this._serverResponseCtor = options.ServerResponse || ServerResponse;

  if (this.requestTimeout > 0 && this.headersTimeout > this.requestTimeout) {
    var timeoutRangeErr = new RangeError('The value of "headersTimeout" is out of range. It must be <= requestTimeout. Received ' + this.headersTimeout);
    timeoutRangeErr.code = 'ERR_OUT_OF_RANGE';
    throw timeoutRangeErr;
  }

  if (typeof requestListener === 'function') {
    this.on('request', requestListener);
  }

  var selfTimer = this;
  this.on('listening', function() {
    if (selfTimer[kConnectionsCheckingInterval]) {
      _destroyHttpTimer(selfTimer[kConnectionsCheckingInterval]);
    }
    if (selfTimer.connectionsCheckingInterval > 0) {
      selfTimer[kConnectionsCheckingInterval] = setInterval(function() {
        if (!selfTimer._sockets) return;
        var now = Date.now();
        selfTimer._sockets.forEach(function(socket) {
          if (socket.destroyed) return;
          if (socket._headersTimeoutAt && now >= socket._headersTimeoutAt) {
            socket._headersTimeoutAt = 0;
            socket._requestTimeoutAt = 0;
            if (socket._headersTimeoutId) {
              _destroyHttpTimer(socket._headersTimeoutId);
              socket._headersTimeoutId = null;
            }
            if (socket._requestTimeoutId) {
              _destroyHttpTimer(socket._requestTimeoutId);
              socket._requestTimeoutId = null;
            }
            socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n');
            return;
          }
          if (socket._requestTimeoutAt && now >= socket._requestTimeoutAt) {
            socket._requestTimeoutAt = 0;
            if (socket._requestTimeoutId) {
              _destroyHttpTimer(socket._requestTimeoutId);
              socket._requestTimeoutId = null;
            }
            socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n');
          }
        });
      }, selfTimer.connectionsCheckingInterval);
      if (selfTimer[kConnectionsCheckingInterval] && typeof selfTimer[kConnectionsCheckingInterval].unref === 'function') {
        selfTimer[kConnectionsCheckingInterval].unref();
      }
    }
  });

  var net;
  try { net = require('net'); } catch(e) {}
  if (net && typeof net.createServer === 'function') {
    var self = this;
    this._netServer = net.createServer(function(socket) {
      self._onConnection(socket);
    });
  }
}

function normalizeListenCallbackHost(hostname) {
  if (!hostname || hostname === '0.0.0.0' || hostname === '::') {
    return 'localhost';
  }
  return hostname;
}

Server.prototype = Object.create(EventEmitter.prototype);
Server.prototype.constructor = Server;

Object.defineProperty(Server.prototype, 'listening', {
  get: function() { return this._listening; },
  enumerable: true,
  configurable: true
});

Server.prototype._onConnection = function(socket) {
  socket[kTimeout] = null;
  socket.parser = null;
  socket._httpMessage = null;
  socket._isIdle = true;
  socket._httpServer = this;
  socket._headersTimeoutId = null;
  socket._requestTimeoutId = null;
  socket._headersTimeoutAt = null;
  socket._requestTimeoutAt = null;
  socket._headersComplete = false;
  socket._requestTimeoutArmed = false;
  if (typeof socket.encrypted !== 'boolean') {
    socket.encrypted = false;
  }

  var self = this;
  if (self._sockets) self._sockets.add(socket);

  if (self._socketTimeout && typeof socket.setTimeout === 'function') {
    socket.setTimeout(self._socketTimeout, function() {
      self.emit('timeout', socket);
    });
  }

  this.emit('connection', socket);

  var parser = new HttpRequestParser();
  socket.parser = parser;
  function sendBadRequestAndClose() {
    if (socket.destroyed) return;
    try {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    } catch (_writeErr) {
      try { socket.destroy(); } catch (_destroyErr) {}
    }
  }
  function sendChunkExtensionTooLargeAndClose() {
    if (socket.destroyed) return;
    try {
      socket.end('HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n');
    } catch (_writeErr2) {
      try { socket.destroy(); } catch (_destroyErr2) {}
    }
  }
  function isValidConnectTarget(target) {
    if (typeof target !== 'string' || !target) return false;
    if (/^https?:\/\//i.test(target)) {
      try {
        var targetUrl = new URL(target);
        return !!targetUrl.hostname && !!targetUrl.port;
      } catch (_targetUrlErr) {
        return false;
      }
    }
    if (target.charAt(0) === '[') {
      var bracketEnd = target.indexOf(']');
      if (bracketEnd <= 0 || bracketEnd + 2 >= target.length || target.charAt(bracketEnd + 1) !== ':') {
        return false;
      }
      return /^\d+$/.test(target.substring(bracketEnd + 2));
    }
    var colonIdx = target.lastIndexOf(':');
    if (colonIdx <= 0 || colonIdx === target.length - 1) {
      return false;
    }
    return /^\d+$/.test(target.substring(colonIdx + 1));
  }

  function headerValueContainsToken(value, token) {
    if (typeof value !== 'string' || typeof token !== 'string' || !token) {
      return false;
    }
    var targetToken = token.toLowerCase();
    var parts = value.split(',');
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].trim().toLowerCase() === targetToken) {
        return true;
      }
    }
    return false;
  }

  function isUpgradeRequest(reqData) {
    if (!reqData || reqData.method === 'CONNECT' || !reqData.headers) {
      return false;
    }
    return headerValueContainsToken(reqData.headers['connection'], 'upgrade') &&
      typeof reqData.headers['upgrade'] === 'string' &&
      reqData.headers['upgrade'].length > 0;
  }

  function hasPendingHttpRequestData() {
    if (!socket.parser || !parser) return false;
    return parser._state !== 0 ||
      (typeof parser._buffer === 'string' && parser._buffer.length > 0);
  }

  function armPendingRequestTimeouts() {
    if (socket.destroyed || !hasPendingHttpRequestData()) {
      return;
    }
    // Only re-arm if no timeout is currently active; avoid resetting
    // an already-running headers timeout each time a data chunk arrives.
    if (socket._headersTimeoutId || socket._requestTimeoutId) {
      return;
    }
    clearHeadersTimeout();
    clearRequestTimeout();
    socket._headersComplete = false;
    armRequestParsingTimeouts();
  }

  function clearHeadersTimeout() {
    if (socket._headersTimeoutId) {
      _destroyHttpTimer(socket._headersTimeoutId);
      socket._headersTimeoutId = null;
    }
    socket._headersTimeoutAt = null;
    socket._headersComplete = true;
  }

  function clearRequestTimeout() {
    if (socket._requestTimeoutId) {
      _destroyHttpTimer(socket._requestTimeoutId);
      socket._requestTimeoutId = null;
    }
    socket._requestTimeoutAt = null;
    socket._requestTimeoutArmed = false;
  }

  function sendRequestTimeout() {
    clearHeadersTimeout();
    clearRequestTimeout();
    if (socket.destroyed) return;
    try {
      socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n');
    } catch (_timeoutWriteErr) {
      try { socket.destroy(); } catch (_timeoutDestroyErr) {}
    }
  }

  function armRequestParsingTimeouts() {
    if (socket.destroyed) return;
    if (!socket._requestTimeoutArmed && self.requestTimeout > 0) {
      socket._requestTimeoutArmed = true;
      socket._requestTimeoutAt = Date.now() + self.requestTimeout;
      socket._requestTimeoutId = setTimeout(sendRequestTimeout, self.requestTimeout);
      if (socket._requestTimeoutId && typeof socket._requestTimeoutId.unref === 'function') {
        socket._requestTimeoutId.unref();
      }
    }
    if (!socket._headersComplete && !socket._headersTimeoutId && self.headersTimeout > 0) {
      socket._headersTimeoutAt = Date.now() + self.headersTimeout;
      socket._headersTimeoutId = setTimeout(sendRequestTimeout, self.headersTimeout);
      if (socket._headersTimeoutId && typeof socket._headersTimeoutId.unref === 'function') {
        socket._headersTimeoutId.unref();
      }
    }
  }

  function emitServerRequest(reqData, preserveRequestTimeout) {
    clearHeadersTimeout();
    if (!preserveRequestTimeout) {
      clearRequestTimeout();
    }
    var req = _createServerIncomingMessage(self, reqData, 0, socket);
    req.complete = reqData.bodyComplete !== false;

    if (req.method === 'CONNECT') {
      if (!isValidConnectTarget(req.url)) {
        socket.parser = null;
        if (parser) parser.close();
        sendBadRequestAndClose();
        return null;
      }
      socket._isIdle = false;
      socket.parser = null;
      var head = (typeof Buffer !== 'undefined')
        ? Buffer.from(parser && parser._buffer ? parser._buffer : '', 'latin1')
        : (parser && parser._buffer ? parser._buffer : '');
      if (parser) {
        parser._buffer = '';
        parser.close();
      }
      if (self.listenerCount('connect') > 0) {
        self.emit('connect', req, socket, head);
      } else {
        sendBadRequestAndClose();
      }
      return req;
    }

    if (isUpgradeRequest(reqData) && self.listenerCount('upgrade') > 0) {
      socket._isIdle = false;
      socket.parser = null;
      var upgradeHead = (typeof Buffer !== 'undefined')
        ? Buffer.from(parser && parser._buffer ? parser._buffer : '', 'latin1')
        : (parser && parser._buffer ? parser._buffer : '');
      if (parser) {
        parser._buffer = '';
        parser.close();
      }
      self.emit('upgrade', req, socket, upgradeHead);
      return req;
    }

    _activeReq = req;
    req.once('end', function() {
      req.complete = true;
      if (_activeReq === req) _activeReq = null;
    });

    var res = _createServerResponse(self, req);
    res.req = req;
    res.assignSocket(socket);
    _activeRes = res;
    socket._isIdle = false;

    res.once('close', function() {
      if (req.complete && _activeReq === req) {
        _activeReq = null;
      }
      if (req.complete && !req._closeEmitted && !req._closeScheduled) {
        req.readable = false;
        if (req._readableState) {
          req._readableState.ended = true;
        }
        req._closeEmitted = true;
        req.emit('close');
      }
      socket._isIdle = true;
      if (reqData.oversizedBody && !socket.destroyed) {
        try { socket.destroy(); } catch(e) {}
        return;
      }
      if (self._closing && !socket.destroyed) {
        if (!socket._writeQueue || socket._writeQueue.length === 0) {
          try {
            if (typeof socket.end === 'function') {
              socket.end();
            } else {
              socket.destroy();
            }
          } catch(e) {}
        }
      }
      if (!socket.destroyed) {
        clearHeadersTimeout();
        clearRequestTimeout();
        armPendingRequestTimeouts();
      }
    });

    self.emit('request', req, res);
    return req;
  }

  parser.onError = function(code) {
    socket.parser = null;
    if (parser) parser.close();
    if (code === 'chunk_extension_overflow') {
      sendChunkExtensionTooLargeAndClose();
      return;
    }
    sendBadRequestAndClose();
  };

  parser.onHeadersComplete = function(reqData) {
    clearHeadersTimeout();
    socket._isIdle = false;
    if (reqData && reqData.bodyComplete === false && !_activeReq) {
      emitServerRequest(reqData, true);
    }
  };

  parser.onBody = function(bodyChunk) {
    if (!_activeReq || typeof _activeReq._pushBodyChunk !== 'function') return;
    var bodyBuffer = (typeof Buffer !== 'undefined') ? Buffer.from(bodyChunk, 'latin1') : bodyChunk;
    _activeReq._pushBodyChunk(bodyBuffer);
  };

  parser.onMessageComplete = function() {
    clearRequestTimeout();
    if (_activeReq && typeof _activeReq._finishBody === 'function') {
      _activeReq._finishBody();
    }
  };

  armRequestParsingTimeouts();

  socket.on('data', function(chunk) {
    if ((socket._headersTimeoutAt && Date.now() >= socket._headersTimeoutAt) ||
        (socket._requestTimeoutAt && Date.now() >= socket._requestTimeoutAt)) {
      sendRequestTimeout();
      return;
    }
    if (socket._isIdle && !socket._requestTimeoutArmed && !socket.destroyed) {
      socket._headersComplete = false;
      armRequestParsingTimeouts();
    }
    if (socket.parser) {
      parser.execute(chunk);
      if (socket._isIdle) {
        armPendingRequestTimeouts();
      }
    }
  });

  var _activeReq = null;
  var _activeRes = null;

  socket.on('close', function() {
    clearHeadersTimeout();
    clearRequestTimeout();
    var abortedReq = _activeReq || (_activeRes && _activeRes._req);
    if (abortedReq && _activeRes && !_activeRes._finished) {
      abortedReq.aborted = true;
      abortedReq.emit('aborted');
      var abortErr = new Error('aborted');
      abortErr.code = 'ECONNRESET';
      if (!abortedReq.listenerCount || abortedReq.listenerCount('error') > 0) {
        abortedReq.emit('error', abortErr);
      }
    }
    _activeReq = null;
    if (_activeRes && !_activeRes._closed) {
      _activeRes.destroyed = true;
      _activeRes._closed = true;
      _activeRes.closed = true;
      _activeRes.emit('close');
      _activeRes = null;
    }
    socket.parser = null;
    socket[kTimeout] = null;
    if (socket._httpMessage) socket._httpMessage = null;
    if (parser) parser.close();
    if (self._sockets) self._sockets.delete(socket);
  });

  socket.on('error', function() {});

  parser.onRequest = function(reqData) {
    if (_activeReq && reqData.bodyComplete === false) {
      return;
    }
    emitServerRequest(reqData, false);
  };
};

Server.prototype.listen = function(port, hostname, callback) {
  if (typeof port === 'function') {
    callback = port;
    port = 0;
    hostname = '0.0.0.0';
  } else if (typeof port === 'object' && port !== null) {
    var opts = port;
    port = opts.port || 0;
    if (typeof hostname === 'function') {
      callback = hostname;
      hostname = undefined;
    }
    hostname = opts.host || opts.hostname || hostname || '127.0.0.1';
  }
  if (typeof hostname === 'function') {
    callback = hostname;
    hostname = '127.0.0.1';
  }
  port = port || 0;
  hostname = hostname || '127.0.0.1';

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  this._port = port;
  this._hostname = hostname;

  if (this._netServer) {
    var self = this;
    this._netServer.on('error', function(err) {
      self.emit('error', err);
    });
    this._netServer.listen(port, hostname, function() {
      self._port = self._netServer && self._netServer._port ? self._netServer._port : self._port;
      self._hostname = self._netServer && self._netServer._host ? self._netServer._host : self._hostname;
      self._listening = true;
      self.emit('listening', null, normalizeListenCallbackHost(self._hostname), self._port);
    });
  } else if (typeof __exactHttpServe === 'function') {
    this._useNative = true;
    var resultJson = __exactHttpServe(port, hostname);
    var result;
    try { result = JSON.parse(resultJson); } catch(e) {
      var self2 = this;
      setTimeout(function() { self2.emit('error', new Error('Server start failed')); }, 0);
      return this;
    }

    if (result.error) {
      var self3 = this;
      var errMsg = result.error;
      setTimeout(function() { self3.emit('error', new Error(errMsg)); }, 0);
      return this;
    }

    this._serverId = result.id;
    this._port = result.port || port;
    this._listening = true;

    var self4 = this;
    setTimeout(function() { self4.emit('listening', null, normalizeListenCallbackHost(self4._hostname), self4._port); }, 0);
    this._pollLoop();
  } else {
    var self5 = this;
    setTimeout(function() { self5.emit('error', new Error('HTTP server not available')); }, 0);
  }

  return this;
};

Server.prototype._pollLoop = function() {
  if (this._closing || !this._listening || !this._useNative) return;
  var self = this;

  function poll() {
    if (self._closing || !self._listening) return;
    var json = null;
    if (typeof __exactHttpPoll === 'function') {
      json = __exactHttpPoll(self._serverId);
    }
    if (json) {
      self._handleNativeRequest(json);
      setTimeout(poll, 0);
    } else if (typeof __exactHttpWait === 'function') {
      __exactHttpWait(self._serverId, 1000).then(function(waitJson) {
        if (waitJson) self._handleNativeRequest(waitJson);
        setTimeout(poll, 0);
      }).catch(function() {
        setTimeout(poll, 50);
      });
    } else {
      setTimeout(poll, 50);
    }
  }
  poll();
};

Server.prototype._handleNativeRequest = function(json) {
  var data;
  try { data = JSON.parse(json); } catch(e) { return; }

  var req = _createServerIncomingMessage(this, data, this._serverId, null);
  var res = _createServerResponse(this, null, this._serverId, data.id || 0);

  if (req.listenerCount && req.listenerCount('data') > 0) {
    req.resume();
  }
  this.emit('request', req, res);
};

Server.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._closing = true;
  this._listening = false;
  if (this[kConnectionsCheckingInterval]) {
    _destroyHttpTimer(this[kConnectionsCheckingInterval]);
    this[kConnectionsCheckingInterval] = null;
  }
  if (this._serverTimeoutId) {
    clearTimeout(this._serverTimeoutId);
    this._serverTimeoutId = null;
  }
  this.closeIdleConnections();

  var self = this;
  if (this._netServer) {
    // Periodically cull idle sockets after close(); active requests are allowed
    // to finish like Node's HTTP server instead of being reset mid-flight.
    var _closeGuardTimer = setTimeout(function() {
      self.closeIdleConnections();
    }, 100);
    if (_closeGuardTimer && typeof _closeGuardTimer.unref === 'function') {
      _closeGuardTimer.unref();
    }
    this._netServer.close(function() {
      clearTimeout(_closeGuardTimer);
      self.closeIdleConnections();
      self.emit('close');
    });
  } else if (this._useNative) {
    if (typeof __exactHttpClose === 'function' && this._serverId) {
      __exactHttpClose(this._serverId, 0);
    }
    setTimeout(function() { self.emit('close'); }, 0);
  } else {
    setTimeout(function() { self.emit('close'); }, 0);
  }
  return this;
};

if (typeof Symbol === 'function' && Symbol.dispose) {
  Server.prototype[Symbol.dispose] = function() {
    this.close();
  };
}

if (typeof Symbol === 'function' && Symbol.asyncDispose) {
  Server.prototype[Symbol.asyncDispose] = function() {
    var self = this;
    return new Promise(function(resolve, reject) {
      try {
        self.close(function() {
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  };
}

Server.prototype.closeAllConnections = function() {
  if (!this._sockets) return;
  var sockets = [];
  this._sockets.forEach(function(s) { sockets.push(s); });
  for (var i = 0; i < sockets.length; i++) {
    try { sockets[i].destroy(); } catch(e) {}
  }
};

Server.prototype.closeIdleConnections = function() {
  if (!this._sockets) return;
  var sockets = [];
  this._sockets.forEach(function(s) { sockets.push(s); });
  for (var i = 0; i < sockets.length; i++) {
    var sock = sockets[i];
    if (sock._isIdle && (!sock._writeQueue || sock._writeQueue.length === 0)) {
      try {
        if (typeof sock.end === 'function') {
          sock.end();
        } else {
          sock.destroy();
        }
      } catch(e) {}
    }
  }
};

Server.prototype.address = function() {
  if (this._netServer && typeof this._netServer.address === 'function') {
    var netAddress = this._netServer.address();
    if (this._netServer._handle != null && netAddress != null) {
      return netAddress;
    }
  }
  if (!this._listening) {
    return null;
  }
  if (this._netServer && typeof this._netServer.address === 'function') {
    return this._netServer.address();
  }
  if (this._useNative) {
    if (typeof __exactHttpAddress === 'function') {
      var json = __exactHttpAddress(this._serverId);
      if (json) {
        try { return JSON.parse(json); } catch(e) {}
      }
    }
    return { address: this._hostname || '127.0.0.1', family: 'IPv4', port: this._port || 0 };
  }
  return null;
};

Server.prototype.setTimeout = function(msecs, callback) {
  if (typeof msecs === 'function') {
    callback = msecs;
    msecs = undefined;
  }
  if (msecs === undefined) msecs = 0;
  this.timeout = msecs;
  if (msecs == null || msecs <= 0) {
    if (this._serverTimeoutId) {
      clearTimeout(this._serverTimeoutId);
      this._serverTimeoutId = null;
    }
    return this;
  }
  var self = this;
  this._socketTimeout = msecs;
  if (typeof callback === 'function') {
    this.on('timeout', callback);
  }
  if (this._serverTimeoutId) clearTimeout(this._serverTimeoutId);
  this._serverTimeoutId = setTimeout(function() {
    self._serverTimeoutId = null;
    if (self._sockets && self._sockets.size > 0) {
      var sockets = [];
      self._sockets.forEach(function(s) { sockets.push(s); });
      for (var i = 0; i < sockets.length; i++) {
        self.emit('timeout', sockets[i]);
      }
    } else {
      self.emit('timeout');
    }
  }, msecs);
  function applyTimeout(socket) {
    if (socket && typeof socket.setTimeout === 'function') {
      socket.setTimeout(msecs, function() {
        self.emit('timeout', socket);
      });
    }
  }
  if (this._sockets) {
    this._sockets.forEach(applyTimeout);
  }
  this._socketTimeoutApplier = applyTimeout;
  return this;
};

Server.prototype.ref = function() {
  if (this._netServer && typeof this._netServer.ref === 'function') {
    this._netServer.ref();
  } else if (this._useNative && typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 1);
  }
  return this;
};
Server.prototype.unref = function() {
  if (this._netServer && typeof this._netServer.unref === 'function') {
    this._netServer.unref();
  } else if (this._useNative && typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 0);
  }
  return this;
};

function createServer(options, requestListener) {
  // Server constructor handles argument normalization
  return new Server(options, requestListener);
}

var internalOptions;
try {
  internalOptions = require('internal/options');
} catch (_err) {
  internalOptions = null;
}
var configuredMaxHeaderSize = internalOptions && typeof internalOptions.getOptionValue === 'function'
  ? internalOptions.getOptionValue('--max-http-header-size')
  : undefined;
var maxHeaderSize = typeof configuredMaxHeaderSize === 'number' && isFinite(configuredMaxHeaderSize) && configuredMaxHeaderSize > 0
  ? configuredMaxHeaderSize
  : 16384;

// Module exports - avoid getter syntax for Hermes compatibility
var _wsGlobal = typeof WebSocket !== 'undefined' ? WebSocket : undefined;
var _ceGlobal = typeof CloseEvent !== 'undefined' ? CloseEvent : undefined;
var _meGlobal = typeof MessageEvent !== 'undefined' ? MessageEvent : undefined;

// _checkIsHttpToken / _checkInvalidHeaderChar helpers for _http_common
function _checkIsHttpToken(val) {
  return typeof val === 'string' && HEADER_NAME_RE.test(val);
}
function _checkInvalidHeaderChar(val) {
  if (typeof val !== 'string') return false;
  for (var i = 0; i < val.length; i++) {
    var ch = val.charCodeAt(i);
    if (ch === 9) continue; // TAB
    if (ch < 32 || ch === 127 || ch > 255) return true;
  }
  return false;
}

// Fake HTTPParser for _http_common compatibility
function HTTPParser() {}
HTTPParser.REQUEST = 'REQUEST';
HTTPParser.RESPONSE = 'RESPONSE';
HTTPParser.kOnHeaders = 0;
HTTPParser.kOnHeadersComplete = 1;
HTTPParser.kOnBody = 2;
HTTPParser.kOnMessageComplete = 3;
HTTPParser.kOnExecute = 4;

// parsers free list (stub)
var parsers = { max: 1000, alloc: function() { return new HTTPParser(); }, free: function() {} };

// Internal module symbol exports
var kConnectionsCheckingInterval = Symbol.for('nodejs.http.kConnectionsCheckingInterval');
var kHighWaterMark = Symbol.for('nodejs.http.kHighWaterMark');

module.exports = {
  request: request,
  get: get,
  Agent: Agent,
  createServer: createServer,
  Server: Server,
  ServerResponse: ServerResponse,
  OutgoingMessage: OutgoingMessage,
  IncomingMessage: IncomingMessage,
  ServerIncomingMessage: ServerIncomingMessage,
  ClientRequest: ClientRequest,
  METHODS: METHODS,
  STATUS_CODES: STATUS_CODES,
  globalAgent: globalAgent,
  kTimeout: kTimeout,
  maxHeaderSize: maxHeaderSize,
  validateHeaderName: validateHeaderName,
  validateHeaderValue: validateHeaderValue,
  WebSocket: _wsGlobal,
  CloseEvent: _ceGlobal,
  MessageEvent: _meGlobal,
  // Internal exports for _http_common, _http_agent, etc.
  _checkIsHttpToken: _checkIsHttpToken,
  _checkInvalidHeaderChar: _checkInvalidHeaderChar,
  HTTPParser: HTTPParser,
  parsers: parsers,
  methods: METHODS,
  kConnectionsCheckingInterval: kConnectionsCheckingInterval,
  kHighWaterMark: kHighWaterMark
};
