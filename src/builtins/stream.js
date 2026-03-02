var EventEmitter = require('node:events').EventEmitter;
var StringDecoder;
try {
  StringDecoder = require('node:string_decoder').StringDecoder;
} catch (e) {
  StringDecoder = null;
}

var defaultHighWaterMark = 65536;
var defaultHighWaterMarkObjectMode = 16;
var awaitDrainWriterStateSymbol = typeof Symbol === 'function' ? Symbol('exact-await-drain-writer-state') : '__exactAwaitDrainWriterState';

function _awaitDrainSizeGetter() {
  var state = this && this[awaitDrainWriterStateSymbol];
  if (!state) return 0;
  var current = state.awaitDrainWriters;
  if (!current) return 0;
  if (current === this) return 1;
  if (typeof current.has === 'function' && current.has(this)) return current.size;
  return 0;
}

_awaitDrainSizeGetter.__exactAwaitDrainSizeGetter = true;

function _hasOwnAwaitDrainSizeDescriptor(value) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return false;
  var desc = Object.getOwnPropertyDescriptor(value, 'size');
  return !!(desc && desc.get && desc.get.__exactAwaitDrainSizeGetter);
}

function _attachAwaitDrainSizeAccessor(value, state) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return;
  if (typeof Object.defineProperty !== 'function') return;
  value[awaitDrainWriterStateSymbol] = state;
  if (_hasOwnAwaitDrainSizeDescriptor(value)) return;
  try {
    Object.defineProperty(value, 'size', {
      configurable: true,
      enumerable: false,
      get: _awaitDrainSizeGetter
    });
  } catch (_err) {}
}

function _clearAwaitDrainSizeAccessor(value, state) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return;
  if (value[awaitDrainWriterStateSymbol] !== state) return;
  if (_hasOwnAwaitDrainSizeDescriptor(value)) {
    try {
      delete value.size;
    } catch (_err) {}
  }
  try {
    delete value[awaitDrainWriterStateSymbol];
  } catch (_err) {}
}

function _defineStateAlias(obj, publicName, internalName) {
  if (typeof obj !== 'object' || obj === null) return;
  if (typeof Object.defineProperty !== 'function') {
    obj[publicName] = obj[internalName];
    return;
  }
  try {
    Object.defineProperty(obj, publicName, {
      configurable: true,
      enumerable: true,
      get: function() {
        return obj[internalName];
      },
      set: function(value) {
        obj[internalName] = value;
      }
    });
  } catch (_err) {
    obj[publicName] = obj[internalName];
  }
}

function Stream() {
  EventEmitter.call(this);
  if (!this._events || typeof this._events !== 'object') {
    this._events = {};
  }
  if (this._events.close === undefined) this._events.close = undefined;
  if (this._events.error === undefined) this._events.error = undefined;
  if (this._events.prefinish === undefined) this._events.prefinish = undefined;
  if (this._events.finish === undefined) this._events.finish = undefined;
  if (this._events.drain === undefined) this._events.drain = undefined;
  if (this._events.data === undefined) this._events.data = undefined;
  if (this._events.end === undefined) this._events.end = undefined;
  if (this._events.readable === undefined) this._events.readable = undefined;
  this._closed = false;
  this._destroyed = false;
  this.destroyed = false;
  this._needsClose = false;
}

function _ensureAwaitDrainWriters(readableState) {
  if (!readableState) return null;
  return readableState.awaitDrainWriters || null;
}

function _addAwaitDrainWriter(readableState, writer) {
  if (!readableState) return;
  var current = readableState.awaitDrainWriters;
  if (!current) {
    readableState.awaitDrainWriters = writer;
    _attachAwaitDrainSizeAccessor(writer, readableState);
    return;
  }
  if (!(current instanceof Set)) {
    if (current === writer) return;
    current = new Set([current]);
    readableState.awaitDrainWriters = current;
    _clearAwaitDrainSizeAccessor(current, readableState);
  }
  current.add(writer);
  _attachAwaitDrainSizeAccessor(writer, readableState);
}

function _removeAwaitDrainWriter(readableState, writer) {
  if (!readableState) return;
  var current = readableState.awaitDrainWriters;
  if (!current) return;
  if (current instanceof Set) {
    current.delete(writer);
    _clearAwaitDrainSizeAccessor(writer, readableState);
    if (current.size === 0) {
      current.forEach(function(entry) {
        _clearAwaitDrainSizeAccessor(entry, readableState);
      });
      readableState.awaitDrainWriters = null;
    }
    return;
  }
  if (current === writer) {
    _clearAwaitDrainSizeAccessor(current, readableState);
    readableState.awaitDrainWriters = null;
  }
}

function _hasAwaitDrainWriters(readableState) {
  if (!readableState) return false;
  var current = readableState.awaitDrainWriters;
  if (!current) return false;
  if (current instanceof Set) return current.size > 0;
  return true;
}

function _isZeroLengthChunk(chunk, objectMode) {
  if (objectMode) return false;
  if (chunk === null || chunk === undefined) return false;
  if (typeof chunk === 'string') return chunk.length === 0;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) return chunk.length === 0;
  if (chunk instanceof ArrayBuffer) return chunk.byteLength === 0;
  if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) return chunk.byteLength === 0;
  if (typeof chunk.length === 'number') return chunk.length === 0;
  return false;
}

function _bufferFromChunk(chunk) {
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (chunk instanceof ArrayBuffer) {
    return Buffer ? Buffer.from(new Uint8Array(chunk)) : new Uint8Array(chunk);
  }
  if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
    return Buffer ? Buffer.from(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0) : new Uint8Array(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0);
  }
  if (typeof chunk === 'string') {
    return Buffer ? Buffer.from(chunk) : new TextEncoder().encode(chunk);
  }
  return Buffer ? Buffer.from(String(chunk)) : new TextEncoder().encode(String(chunk));
}

function _decodeChunk(state, chunk) {
  if (!state || !state.encoding || !state.decoder) return chunk;
  if (chunk == null) return chunk;
  var asBuffer = _bufferFromChunk(chunk);
  return state.decoder.write(asBuffer);
}

function _nextTick(fn) {
  if (typeof process === 'object' && process && typeof process.nextTick === 'function') {
    return process.nextTick(fn);
  }
  return setTimeout(fn, 0);
}

function _setReadableEncoding(state, enc) {
  if (!enc) {
    state.encoding = null;
    state.decoder = null;
    return;
  }
  if (!StringDecoder) {
    if (typeof enc !== 'string') {
      throw TypeError('Must have string encoding');
    }
    state.encoding = enc;
    state.decoder = null;
    return;
  }
  var normalized = String(enc).toLowerCase();
  try {
    state.decoder = new StringDecoder(normalized);
  } catch (err) {
    throw err;
  }
  state.encoding = normalized;
  state.readableEncoding = normalized;
  state.readable = true;
  var content = '';
  if (state.buffer && state.buffer.length) {
    for (var i = 0; i < state.buffer.length; i++) {
      content += state.decoder.write(_bufferFromChunk(state.buffer[i]));
    }
    state.buffer = content === '' ? [] : [content];
    state.length = state.objectMode ? state.buffer.length : content.length;
    if (state.length === 0) state.ended = state.ended;
  }
}
Stream.prototype = Object.create(EventEmitter.prototype);
Stream.prototype.constructor = Stream;

Stream.prototype._emitClose = function() {
  this._close(true);
};

Stream.prototype._close = function(force) {
  if (this._closed) {
    return;
  }
  if (
    !force &&
    this._readableState &&
    this._writableState &&
    (!this._readableState.endEmitted || !this._writableState.finished)
  ) {
    this._needsClose = true;
    return;
  }
  // Respect emitClose: false on writable streams
  if (this._writableState && this._writableState.emitClose === false) {
    return;
  }
  this._needsClose = false;
  this._closed = true;
  this.emit('close');
};

Stream.prototype._undestroy = function() {
  this._destroyed = false;
  this.destroyed = false;
  this._closed = false;
  this._needsClose = false;
  this.readable = true;
  this.writable = true;
  this.writableEnded = false;
  this.writableFinished = false;
  this.readableEnded = false;
  this.readableDidRead = false;
  this.readableAborted = false;
  this.writableCorked = 0;
  this.writableLength = 0;
  this.writableNeedDrain = false;
  this._needDrain = false;
  this._written = [];
  this._writeQueue = [];
  this._pipeCleanups = null;
  this.errored = null;
  if (this._readableState) {
    this._readableState.awaitDrainWriters = null;
    this._readableState.ended = false;
    this._readableState.endedRead = false;
    this._readableState.readableDidRead = false;
    this._readableState.dataEmitted = false;
    this._readableState.endEmitted = false;
    this._readableState.endConsumed = false;
    this._readableState.readable = true;
    this._readableState.destroyed = false;
    this._readableState.errored = null;
    this._readableState.errorEmitted = false;
    this._readableState.length = 0;
    this._readableState.pendingcb = 0;
    this._readableState.reading = false;
    this._readableState.readingMore = false;
    this._readableState.resumeScheduled = false;
  }
  if (this._writableState) {
    this._writableState.highWaterMark = this.writableHighWaterMark || this._writableState.highWaterMark;
    this._writableState.objectMode = !!this.writableObjectMode || this._writableState.objectMode;
    this._writableState.length = 0;
    this._writableState.writing = false;
    this._writableState.ended = false;
    this._writableState.finished = false;
    this._writableState.destroyed = false;
    this._writableState.needDrain = false;
    this._writableState.ending = false;
    this._writableState.sync = false;
    this._writableState.bufferProcessing = false;
    this._writableState.pendingcb = 0;
    this._writableState.errored = null;
    this._writableState.errorEmitted = false;
    this._writableState.emitClose = (typeof this._writableState.emitClose === 'boolean') ? this._writableState.emitClose : true;
    this._writableState.autoDestroy = (typeof this._writableState.autoDestroy === 'boolean') ? this._writableState.autoDestroy : true;
  }
};

Stream.prototype.destroy = function(error, callback) {
  if (this._destroyed || this.destroyed) {
    if (typeof callback === 'function') {
      setTimeout(function() { callback(); }, 0);
    }
    return this;
  }
  this._destroyed = true;
  this.destroyed = true;
  // Set readableAborted: true when destroyed before end was consumed by a listener
  if (this._readableState) {
    if (!this._readableState.endConsumed) {
      this.readableAborted = true;
    }
    this._readableState.destroyed = true;
    this.readable = false;
    if (error) {
      this._readableState.errored = error;
      this.errored = error;
    }
  }
  if (this._writableState) {
    this._writableState.destroyed = true;
    this.writable = false;
    if (error) {
      this._writableState.errored = error;
      this.errored = error;
    }
  }
  var self = this;
  function emitErrorAndClose(err) {
  if (err) {
      self.errored = err;
      if (self._readableState) self._readableState.errored = err;
      if (self._writableState) self._writableState.errored = err;
      var hasErrorListener = false;
      if (typeof self.listenerCount === 'function') {
        hasErrorListener = self.listenerCount('error') > 0;
      } else if (self._events && self._events.error) {
        hasErrorListener = true;
      }
      if (hasErrorListener) {
        try {
          self.emit('error', err);
        } catch (emitErr) {
          if (
            typeof process === 'object' &&
            process &&
            typeof process.emit === 'function' &&
            typeof process.listenerCount === 'function' &&
            process.listenerCount('uncaughtException') > 0
          ) {
            try {
              process.emit('uncaughtException', emitErr);
              return;
            } catch (emitToProcessErr) {
              throw emitToProcessErr;
            }
          }
          if (
            typeof globalThis.__exactUncaughtExceptionHandler === 'function' &&
            globalThis.__exactUncaughtExceptionHandler(emitErr)
          ) {
            // routed to process uncaughtException
          } else {
            throw emitErr;
          }
        }
      }
      if (self._readableState) self._readableState.errorEmitted = true;
      if (self._writableState) self._writableState.errorEmitted = true;
    }
    self._close(true);
    if (typeof callback === 'function') callback(err);
  }
  if (typeof this._destroy === 'function') {
    this._destroy(error || null, function(err) {
      // Defer error/close when using custom _destroy
      setTimeout(function() { emitErrorAndClose(err); }, 0);
    });
  } else {
    // Defer error/close when using default destroy path
    setTimeout(function() { emitErrorAndClose(error || null); }, 0);
  }
  return this;
};

function Readable(options) {
  if (!(this instanceof Readable)) return new Readable(options);
  Stream.call(this);
  this._data = [];
  this._ended = false;
  // Determine objectMode: readableObjectMode overrides objectMode if present
  var objMode = (options && options.readableObjectMode != null) ? !!options.readableObjectMode :
                !!(options && options.objectMode);
  // Determine highWaterMark: explicit highWaterMark wins, then readableHighWaterMark, then default
  var hwm;
  if (options && options.highWaterMark != null) {
    hwm = options.highWaterMark;
  } else if (options && options.readableHighWaterMark != null) {
    hwm = options.readableHighWaterMark;
  } else {
    hwm = objMode ? defaultHighWaterMarkObjectMode : defaultHighWaterMark;
  }
  this.readableHighWaterMark = hwm;
  this.readableObjectMode = objMode;
  this.readableEncoding = (options && options.encoding) || null;
  this.readableFlowing = null;
  this.readableEnded = false;
  this.readableAborted = false;
  this.readableDidRead = false;
  this.readable = true;
  this.errored = null;
  this._readableState = {
    highWaterMark: hwm,
    objectMode: objMode,
    length: 0,
    reading: false,
    ended: false,
    endedRead: false,
    needReadable: false,
    emittedReadable: false,
    readable: true,
    readableListening: false,
    resumeScheduled: false,
    sync: false,
    readingMore: false,
    flowing: null,
    endedDueToPush: false,
    pipes: [],
    pipesCount: 0,
    encodeStrings: true,
    errorEmitted: false,
    errored: null,
    endedFlowing: false,
    emittedClose: true,
    autoDestroy: (options && options.autoDestroy !== undefined) ? options.autoDestroy !== false : true,
    defaultEncoding: 'utf8',
    encoding: (options && options.encoding) || null,
    decoder: null,
    readable: true,
    readableDidRead: false,
    dataEmitted: false,
    endEmitted: false,
    endConsumed: false,
    buffer: this._data,
    needDrain: false,
    pendingcb: 0,
    awaitDrainWriters: null,
  };
  _defineStateAlias(this, 'readableState', '_readableState');
  if (options && options.encoding != null) {
    _setReadableEncoding(this._readableState, options.encoding);
  }
  Object.defineProperty(this._readableState, 'endedEmitted', {
    configurable: true,
    enumerable: true,
    get: function() {
      return this.endEmitted;
    },
    set: function(value) {
      this.endEmitted = value;
    }
  });
  Object.defineProperty(this._readableState, 'endedRead', {
    configurable: true,
    enumerable: true,
    get: function() {
      return this.ended;
    },
    set: function(value) {
      this.ended = !!value;
    }
  });
  if (options && options.defaultEncoding !== undefined) {
    var _validEncodings = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1 };
    if (!_validEncodings[String(options.defaultEncoding).toLowerCase()]) {
      var encErr = new TypeError('Unknown encoding: ' + options.defaultEncoding);
      encErr.code = 'ERR_UNKNOWN_ENCODING';
      throw encErr;
    }
    this._readableState.defaultEncoding = options.defaultEncoding;
  }
  if (options && typeof options.read === 'function') this._read = options.read;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  // construct callback support
  if (options && typeof options.construct === 'function') {
    this._readableState.constructed = false;
    var self = this;
    var called = false;
    setTimeout(function() {
      options.construct(function(err) {
        if (called) {
          var multiErr = new Error('Callback called multiple times');
          multiErr.code = 'ERR_MULTIPLE_CALLBACK';
          self.emit('error', multiErr);
          return;
        }
        called = true;
        self._readableState.constructed = true;
        if (err) {
          self.destroy(err);
        }
      });
    }, 0);
  } else {
    this._readableState.constructed = true;
  }
}
Readable.prototype = Object.create(Stream.prototype);
Readable.prototype.constructor = Readable;

// Override emit to track when 'end' event is consumed by a listener
Readable.prototype.emit = function(event) {
  if (event === 'end' && this._readableState && this.listenerCount('end') > 0) {
    this._readableState.endConsumed = true;
  }
  return EventEmitter.prototype.emit.apply(this, arguments);
};

function readableStateChunkLength(chunk, objectMode) {
  if (chunk == null) return 0;
  if (objectMode) return 1;
  if (typeof chunk === 'string') return chunk.length;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) return chunk.length;
  if (typeof ArrayBuffer !== 'undefined' && chunk instanceof ArrayBuffer) return chunk.byteLength;
  if (ArrayBuffer.isView(chunk)) return chunk.byteLength;
  if (typeof chunk.length === 'number') return chunk.length;
  return 1;
}

function _nextPowerOf2(value) {
  value = value >>> 0;
  value -= 1;
  value |= value >>> 1;
  value |= value >>> 2;
  value |= value >>> 4;
  value |= value >>> 8;
  value |= value >>> 16;
  value += 1;
  if (value < 16) value = 16;
  if (value > 0x40000000) value = 0x40000000;
  return value;
}

function _coerceReadSize(value) {
  if (value === undefined || value === null) return NaN;
  if (typeof value !== 'number') {
    value = Number(value);
  }
  if (isNaN(value) || value <= 0) return NaN;
  return Math.floor(value);
}

function _consumeReadableChunk(stream, needed) {
  var state = stream._readableState;
  var chunk = stream._data[0];
  var consumed = 0;
  if (state.objectMode) {
    chunk = stream._data.shift();
    consumed = chunk === undefined ? 0 : 1;
    if (consumed > 0) {
      stream._updateReadableLength(-consumed);
    }
    return chunk;
  }
  if (needed === null) {
    chunk = stream._data.shift();
    consumed = readableStateChunkLength(chunk, state.objectMode);
    if (consumed > 0) {
      stream._updateReadableLength(-consumed);
    }
    return chunk;
  }

  var out = [];
  var bytes = needed;
  var allString = true;
  while (stream._data.length > 0 && bytes > 0) {
    var current = stream._data[0];
    if (typeof current === 'string') {
      var currentLen = current.length;
      if (currentLen > bytes) {
        out.push(current.slice(0, bytes));
        stream._data[0] = current.slice(bytes);
        consumed += bytes;
        bytes = 0;
        continue;
      }
      out.push(current);
      stream._data.shift();
      consumed += currentLen;
      bytes -= currentLen;
    } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(current)) {
      if (current.length > bytes) {
        out.push(current.slice(0, bytes));
        stream._data[0] = current.slice(bytes);
        consumed += bytes;
        bytes = 0;
        continue;
      }
      out.push(current);
      stream._data.shift();
      consumed += current.length;
      bytes -= current.length;
    } else if (current && current.buffer instanceof ArrayBuffer && typeof current.byteLength === 'number') {
      if (current.byteLength > bytes) {
        out.push(current.slice(0, bytes));
        stream._data[0] = current.slice(bytes);
        consumed += bytes;
        bytes = 0;
        continue;
      }
      out.push(current);
      stream._data.shift();
      consumed += current.byteLength;
      bytes -= current.byteLength;
    } else {
      allString = false;
      out.push(current);
      stream._data.shift();
      consumed += readableStateChunkLength(current, state.objectMode);
      break;
    }
  }
  if (consumed > 0) {
    stream._updateReadableLength(-consumed);
  }
  if (out.length === 1) return out[0];
  if (allString && out.length > 0 && typeof out[0] === 'string') {
    return out.join('');
  }
  if (typeof Buffer !== 'undefined' && (Buffer.isBuffer(out[0]) || out[0] instanceof ArrayBuffer || (out[0] && out[0].buffer instanceof ArrayBuffer))) {
    var total = 0;
    for (var i = 0; i < out.length; i++) {
      total += readableStateChunkLength(out[i], false);
    }
    var outBuffer = Buffer ? Buffer.alloc(total) : new Uint8Array(total);
    var offset = 0;
    for (var j = 0; j < out.length; j++) {
      var item = out[j];
      var piece;
      if (typeof item === 'string') piece = Buffer ? Buffer.from(item) : new TextEncoder().encode(item);
      else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(item)) piece = item;
      else if (item && item.buffer instanceof ArrayBuffer) {
        piece = Buffer && Buffer.isBuffer(item) ? item : Buffer.from(new Uint8Array(item.buffer, item.byteOffset || 0, item.byteLength || item.length || 0));
      } else {
        piece = Buffer ? Buffer.from(String(item)) : new TextEncoder().encode(String(item));
      }
      if (Buffer && Buffer.isBuffer(piece)) {
        piece.copy(outBuffer, offset);
        offset += piece.length;
      } else if (typeof piece.subarray === 'function') {
        outBuffer.set(piece, offset);
        offset += piece.length;
      }
    }
    return outBuffer;
  }
  return out[0];
}

Readable.prototype._updateReadableLength = function(delta) {
  var state = this._readableState;
  if (typeof delta === 'number' && isFinite(delta)) {
    state.length += delta;
    if (state.length < 0) {
      state.length = 0;
    }
    this.readableLength = state.length;
    state.readableListening = this._events && this._events.readable !== undefined;
    return;
  }
  throw new Error("The \"delta\" argument must be a finite number");
};

Readable.prototype._syncReadableState = function() {
  var state = this._readableState;
  state.ended = this._ended;
  if (!state.ended) {
    state.needReadable = state.length > 0;
  }
};

Readable.prototype._emitReadableIfNeeded = function() {
  var state = this._readableState;
  if (!state.needReadable || state.emittedReadable || state.readableFlowing || this.readableFlowing === true) {
    return;
  }
  state.emittedReadable = true;
  state.needReadable = false;
  var self = this;
  _nextTick(function() {
    if (self._destroyed || self._closed) {
      return;
    }
    self.emit('readable');
  });
};

Readable.prototype._readFromSource = function(size) {
  var state = this._readableState;
  if (this._destroyed || !state || state.reading || state.readingMore || typeof this._read !== 'function') return;
  state.reading = true;
  state.readingMore = true;
  state.sync = true;
  try {
    var hwm = state && state.highWaterMark;
    if (size == null) size = hwm;
    this._read(size);
  } finally {
    state.reading = false;
    state.readingMore = false;
    state.sync = false;
  }
};

Readable.prototype.push = function(chunk) {
  if (this._destroyed) return false;
  var state = this._readableState;
  if (chunk === null || chunk === undefined) {
    if (state.ended || state.endEmitted) return false;
    this._ended = true;
    this.readableEnded = true;
    state.ended = true;
    state.needReadable = true;
    state.emittedReadable = false;
    this._syncReadableState();
    if (state.sync) {
      var self = this;
      var emitReadable = typeof process === 'object' &&
        process &&
        typeof process.nextTick === 'function'
        ? process.nextTick
        : function(fn) { setTimeout(fn, 0); };
      emitReadable(function() {
        self._emitReadableIfNeeded();
      });
    } else {
      this._emitReadableIfNeeded();
    }
    return false;
  }
  if (state.encoding && state.decoder && !state.objectMode) {
    chunk = _decodeChunk(state, chunk);
  }
  var chunkLength = readableStateChunkLength(chunk, state.objectMode);
  if (_isZeroLengthChunk(chunk, this._readableState.objectMode)) {
    return this._readableState.length < this._readableState.highWaterMark;
  }

  if (this.readableFlowing === true) {
    this._data.push(chunk);
    this._updateReadableLength(chunkLength);
    this._syncReadableState();
    this._readableState.needReadable = false;
    this._readableState.emittedReadable = false;
    if (this._readableState.reading) {
      return state.length < state.highWaterMark;
    }
    if (this.readableFlowing !== true) {
      return state.length < state.highWaterMark;
    }
    var flowingChunk = this._data.shift();
    this._updateReadableLength(-readableStateChunkLength(flowingChunk, this._readableState.objectMode));
    this._syncReadableState();
    if (this.readableFlowing !== true) {
      this._data.unshift(flowingChunk);
      this._updateReadableLength(readableStateChunkLength(flowingChunk, this._readableState.objectMode));
      this._syncReadableState();
      return state.length < state.highWaterMark;
    }
    if (this._readableState) {
      this._readableState.dataEmitted = true;
    }
    this.emit('data', flowingChunk);
    return state.length < state.highWaterMark;
  }

  this._data.push(chunk);
  this._updateReadableLength(chunkLength);
  this._syncReadableState();
  this._readableState.needReadable = true;
  this._readableState.emittedReadable = false;
  this._emitReadableIfNeeded();
  return state.length < state.highWaterMark;
};

Readable.prototype.read = function(size) {
  if (this._destroyed) return null;
  this.readableDidRead = true;
  if (this._readableState) {
    this._readableState.readableDidRead = true;
  }
  var n = _coerceReadSize(size);
  var requestedSize = n;
  var state = this._readableState;

  if (size === 0) {
    if (state.length === 0 && !this._ended && !state.reading) {
      this._readFromSource(state.highWaterMark);
    }
    if (state.length > 0 && !state.endEmitted) {
      state.needReadable = true;
      state.emittedReadable = false;
      state.reading = false;
    }
    return null;
  }

  if (!isNaN(n) && n > state.highWaterMark) {
    state.highWaterMark = _nextPowerOf2(n);
  }

  if (!this._ended && !state.reading) {
    if (!isNaN(n)) {
      if (state.length < n) {
        this._readFromSource(n);
      }
    } else {
      var shouldReadMore = state.needReadable || state.length === 0;
      while (shouldReadMore && state.length < state.highWaterMark) {
        var beforeRead = state.length;
        this._readFromSource(state.highWaterMark);
        if (state.length === beforeRead) {
          break;
        }
        if (state.length >= state.highWaterMark && state.needReadable) {
          beforeRead = state.length;
          this._readFromSource(state.highWaterMark);
          if (state.length === beforeRead) {
            break;
          }
        }
        shouldReadMore = false;
      }
    }
  }

  if (!isNaN(n) && state.length < n && !this._ended) {
    state.needReadable = true;
    state.emittedReadable = false;
    return null;
  }

  if (this._data.length === 0) {
    state.needReadable = !this._ended;
    state.emittedReadable = false;
    if (this._ended && !state.endEmitted) {
      state.endEmitted = true;
      this.readable = false;
      this.emit('end');
      if (state.autoDestroy && !this._destroyed) {
        this.destroy();
      } else {
        this._close();
      }
    }
    return null;
  }

  if (size !== 0 && state.ended && state.endEmitted && state.length === 0) {
    return null;
  }

  if (state.objectMode) {
    n = isNaN(n) ? 1 : n;
  }
  if (isNaN(requestedSize) && !state.objectMode) {
    n = state.length;
  } else if (state.length < n) {
    n = state.length;
  }

  var chunk;
  while (true) {
    chunk = _consumeReadableChunk(this, isNaN(requestedSize) ? null : n);
    if (chunk === undefined || chunk === null) {
      chunk = null;
      break;
    }
    if (!state.objectMode && typeof chunk === 'string' && chunk.length === 0) {
      chunk = null;
    }
    if (chunk === null && state.length > 0) {
      continue;
    }
    break;
  }
  if (chunk === null) {
    return null;
  }
  this._syncReadableState();
  this._readableState.needReadable = (!this._ended && state.length <= state.highWaterMark);
  this._readableState.emittedReadable = false;
  if (this._readableState) {
    this._readableState.dataEmitted = true;
  }
  if (this.readableFlowing === true) {
    this.emit('data', chunk);
  }
  if (state.autoDestroy && state.endEmitted && state.ended && !this._destroyed && state.length === 0) {
    this.destroy();
  }
  if (state.length === 0 && !this._ended) {
    var self = this;
    _nextTick(function() {
      if (!self._destroyed && !state.ended && !state.reading) {
        self._readFromSource(state.highWaterMark);
      }
    });
  }
  return chunk;
};

Readable.prototype.unshift = function(chunk) {
  if (this._readableState && this._readableState.encoding && this._readableState.decoder && !this._readableState.objectMode) {
    chunk = _decodeChunk(this._readableState, chunk);
  }
  if (_isZeroLengthChunk(chunk, this._readableState.objectMode)) {
    return false;
  }
  this._data.unshift(chunk);
  this._updateReadableLength(readableStateChunkLength(chunk, this._readableState.objectMode));
  this._syncReadableState();
  this._readableState.needReadable = true;
  this._readableState.emittedReadable = false;
  this._emitReadableIfNeeded();
};

Readable.prototype.setEncoding = function(enc) {
  _setReadableEncoding(this._readableState, enc);
  this.readableEncoding = this._readableState.encoding;
  return this;
};

Readable.prototype.resume = function() {
  if (this.readableFlowing !== true) {
    this.readableFlowing = true;
    this._readableState.reading = false;
    this._readableState.resumeScheduled = false;
    // Flush buffered data asynchronously
    var self = this;
    var schedule = typeof process === 'object' &&
      process &&
      typeof process.nextTick === 'function'
      ? process.nextTick
      : function(fn) { setTimeout(fn, 0); };

    schedule(function() {
      if (self._destroyed || self.readableFlowing !== true) return;
      self.read(0);
      while (self.readableFlowing === true) {
        var chunk = self.read();
        if (chunk === null) {
          return;
        }
      }
    }, 0);
  }
  return this;
};

Readable.prototype.pause = function() {
  if (this.readableFlowing !== false) {
    this.readableFlowing = false;
    this._syncReadableState();
    this.emit('pause');
  }
  return this;
};

Readable.prototype.on = function(event, listener) {
  var result = EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'readable') {
    var state = this._readableState;
    this.readableFlowing = false;
    state.readableListening = true;
    state.needReadable = true;
    state.emittedReadable = false;
    if (state.length > 0) {
      this._emitReadableIfNeeded();
    } else if (!state.reading) {
      var self = this;
      var tick = typeof process === 'object' &&
        process &&
        typeof process.nextTick === 'function'
        ? process.nextTick
        : function(fn) { setTimeout(fn, 0); };
      tick(function() { self.read(0); });
    }
  }
  // Adding a 'data' listener starts flowing mode (unless explicitly paused)
  if (event === 'data') {
    if (this.readableFlowing !== false) {
      this.resume();
    }
  }
  return result;
};

Readable.prototype.addListener = Readable.prototype.on;

Readable.prototype.isPaused = function() {
  return this.readableFlowing === false;
};

Readable.prototype._read = function(size) {};

// Symbol.asyncIterator support for Readable streams
Readable.prototype[Symbol.asyncIterator] = function() {
  var stream = this;
  var ended = false;
  var error = null;
  var pendingResolves = [];
  var buffer = [];

  stream.on('data', function(chunk) {
    if (pendingResolves.length > 0) {
      var resolve = pendingResolves.shift();
      resolve({ value: chunk, done: false });
    } else {
      buffer.push(chunk);
    }
  });

  stream.on('end', function() {
    ended = true;
    while (pendingResolves.length > 0) {
      var resolve = pendingResolves.shift();
      resolve({ value: undefined, done: true });
    }
  });

  stream.on('error', function(err) {
    error = err;
    ended = true;
    while (pendingResolves.length > 0) {
      var resolve = pendingResolves.shift();
      resolve(Promise.reject(err));
    }
  });

  return {
    next: function() {
      if (error) {
        return Promise.reject(error);
      }
      if (buffer.length > 0) {
        return Promise.resolve({ value: buffer.shift(), done: false });
      }
      if (ended) {
        return Promise.resolve({ value: undefined, done: true });
      }
      return new Promise(function(resolve) {
        pendingResolves.push(resolve);
      });
    },
    return: function() {
      ended = true;
      if (typeof stream.destroy === 'function') stream.destroy();
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      ended = true;
      if (typeof stream.destroy === 'function') stream.destroy(err);
      return Promise.reject(err);
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
};

// Helper to create Node.js-style coded errors
function makeError(Constructor, code, message) {
  var err = new Constructor('[' + code + ']: ' + message);
  err.code = code;
  return err;
}

// --- Stream Helper Methods (Node.js 17+) ---

// toArray() - collect all chunks into an array, returns Promise
Readable.prototype.toArray = function(options) {
  var stream = this;
  var signal = options && options.signal;
  return new Promise(function(resolve, reject) {
    if (signal && signal.aborted) {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      reject(abortErr);
      return;
    }
    var onAbort;
    if (signal) {
      onAbort = function() {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        reject(abortErr);
        if (typeof stream.destroy === 'function') stream.destroy(abortErr);
      };
      signal.addEventListener('abort', onAbort);
    }
    var result = [];
    stream.on('data', function(chunk) { result.push(chunk); });
    stream.on('end', function() {
      if (signal && onAbort) signal.removeEventListener('abort', onAbort);
      resolve(result);
    });
    stream.on('error', function(err) {
      if (signal && onAbort) signal.removeEventListener('abort', onAbort);
      reject(err);
    });
  });
};

// forEach() - call fn for each chunk, returns Promise
Readable.prototype.forEach = function(fn, options) {
  // Validation - throws async (returns rejected promise)
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn));
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options));
    }
    if (options.concurrency !== undefined) {
      if (typeof options.concurrency !== 'number' || options.concurrency < 1) {
        return Promise.reject(makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.concurrency" is out of range.'));
      }
    }
  }
  var stream = this;
  var signal = options && options.signal;
  var concurrency = (options && options.concurrency) || 1;
  return (async function() {
    if (signal && signal.aborted) {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      throw abortErr;
    }
    var abortPromise;
    var onAbort;
    if (signal) {
      abortPromise = new Promise(function(_, reject) {
        onAbort = function() {
          var err = new Error('The operation was aborted');
          err.code = 'ABORT_ERR';
          err.name = 'AbortError';
          reject(err);
        };
        signal.addEventListener('abort', onAbort);
      });
    }
    try {
      if (concurrency === 1) {
        for await (var chunk of stream) {
          if (signal && signal.aborted) {
            var abortErr2 = new Error('The operation was aborted');
            abortErr2.code = 'ABORT_ERR';
            abortErr2.name = 'AbortError';
            throw abortErr2;
          }
          var callArg = signal ? { signal: signal } : {};
          if (abortPromise) {
            await Promise.race([fn(chunk, callArg), abortPromise]);
          } else {
            await fn(chunk, callArg);
          }
        }
      } else {
        // Concurrent forEach: pull items and run up to `concurrency` callbacks at once
        var iter = stream[Symbol.asyncIterator]();
        var sourceEnded = false;
        var slots = new Array(concurrency);
        var slotFree = new Array(concurrency);
        for (var si = 0; si < concurrency; si++) {
          slots[si] = null;
          slotFree[si] = true;
        }

        function findFreeSlot() {
          for (var i = 0; i < concurrency; i++) {
            if (slotFree[i]) return i;
          }
          return -1;
        }

        while (!sourceEnded) {
          var slotIdx = findFreeSlot();
          if (slotIdx === -1) {
            // All slots busy - wait for one to free up (or abort)
            var waitPromises = [];
            for (var wi = 0; wi < concurrency; wi++) {
              if (!slotFree[wi] && slots[wi]) waitPromises.push(slots[wi]);
            }
            if (abortPromise) waitPromises.push(abortPromise);
            await Promise.race(waitPromises);
            slotIdx = findFreeSlot();
            if (slotIdx === -1) continue; // abortPromise rejected, will be caught by try/finally
          }
          // Pull next item
          var nr;
          if (abortPromise) {
            nr = await Promise.race([iter.next(), abortPromise]);
          } else {
            nr = await iter.next();
          }
          if (nr.done) { sourceEnded = true; break; }
          var callArg3 = signal ? { signal: signal } : {};
          slotFree[slotIdx] = false;
          slots[slotIdx] = Promise.resolve(fn(nr.value, callArg3)).then(
            (function(idx) { return function() { slotFree[idx] = true; }; })(slotIdx),
            (function(idx) { return function(err) { slotFree[idx] = true; throw err; }; })(slotIdx)
          );
        }
        // Wait for all active slots
        var activeSlots = [];
        for (var fi = 0; fi < concurrency; fi++) {
          if (!slotFree[fi] && slots[fi]) activeSlots.push(slots[fi]);
        }
        if (activeSlots.length > 0) {
          if (abortPromise) {
            await Promise.race([Promise.all(activeSlots), abortPromise]);
          } else {
            await Promise.all(activeSlots);
          }
        }
      }
    } finally {
      if (signal && onAbort) {
        signal.removeEventListener('abort', onAbort);
      }
    }
  })();
};

// filter() - returns a new Readable with chunks passing predicate
Readable.prototype.filter = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
    }
    if (options.concurrency !== undefined) {
      if (typeof options.concurrency !== 'number' || options.concurrency < 1) {
        throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.concurrency" is out of range.');
      }
    }
    if (options.signal !== undefined && (typeof options.signal !== 'object' || options.signal === null)) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof options.signal);
    }
  }
  var source = this;
  var signal = options && options.signal;
  var concurrency = (options && options.concurrency) || 1;
  var ac = new AbortController();
  var childSignal = ac.signal;
  var result;
  if (concurrency === 1) {
    result = Readable.from((async function*() {
      for await (var chunk of source) {
        if (await fn(chunk, { signal: childSignal })) {
          yield chunk;
        }
      }
    })(), { objectMode: true });
  } else {
    result = Readable.from((async function*() {
      var queue = [];
      var sourceEnded = false;
      var sourceIter = source[Symbol.asyncIterator]();

      function startOne() {
        return sourceIter.next().then(function(r) {
          if (r.done) { sourceEnded = true; return null; }
          var chunk = r.value;
          return fn(chunk, { signal: childSignal }).then(function(keep) {
            return { chunk: chunk, keep: keep };
          });
        });
      }

      // Fill initial queue
      for (var i = 0; i < concurrency && !sourceEnded; i++) {
        queue.push(startOne());
      }

      while (queue.length > 0) {
        var entry = await queue.shift();
        if (entry === null) continue;
        if (!sourceEnded) {
          queue.push(startOne());
        }
        if (entry.keep) {
          yield entry.chunk;
        }
      }
    })(), { objectMode: true });
  }
  result.readable = true;
  // When result is destroyed, also destroy the source to stop the pipeline
  result.on('close', function() {
    ac.abort();
    if (!source._destroyed) source.destroy();
  });
  if (signal) {
    signal.addEventListener('abort', function() {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      result.destroy(abortErr);
    });
  }
  return result;
};

// map() - returns a new Readable with transformed chunks
Readable.prototype.map = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
    }
    if (options.concurrency !== undefined) {
      if (typeof options.concurrency !== 'number' || options.concurrency < 1) {
        throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.concurrency" is out of range.');
      }
    }
    if (options.signal !== undefined && (typeof options.signal !== 'object' || options.signal === null)) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof options.signal);
    }
  }
  var source = this;
  var signal = options && options.signal;
  var ac = new AbortController();
  var childSignal = ac.signal;
  var result = Readable.from((async function*() {
    for await (var chunk of source) {
      yield await fn(chunk, { signal: childSignal });
    }
  })(), { objectMode: true });
  result.readable = true;
  result.on('close', function() {
    ac.abort();
    if (!source._destroyed) source.destroy();
  });
  if (signal) {
    signal.addEventListener('abort', function() {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      result.destroy(abortErr);
    });
  }
  return result;
};

// flatMap() - map + flatten results
Readable.prototype.flatMap = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
    }
    if (options.concurrency !== undefined) {
      if (typeof options.concurrency !== 'number' || options.concurrency < 1) {
        throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.concurrency" is out of range.');
      }
    }
    if (options.signal !== undefined && (typeof options.signal !== 'object' || options.signal === null)) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof options.signal);
    }
  }
  var source = this;
  var result = Readable.from((async function*() {
    for await (var chunk of source) {
      var mapped = await fn(chunk);
      if (mapped && typeof mapped[Symbol.asyncIterator] === 'function') {
        for await (var item of mapped) yield item;
      } else if (mapped && typeof mapped[Symbol.iterator] === 'function' && typeof mapped !== 'string') {
        for (var i = 0; i < mapped.length; i++) yield mapped[i];
      } else {
        yield mapped;
      }
    }
  })(), { objectMode: true });
  result.readable = true;
  result.on('close', function() { if (!source._destroyed) source.destroy(); });
  return result;
};

// reduce() - reduce stream to a single value, returns Promise
Readable.prototype.reduce = function(fn, initial, options) {
  if (typeof fn !== 'function') {
    throw new TypeError('The "fn" argument must be of type function');
  }
  var hasInitial = arguments.length >= 2;
  var stream = this;
  return (async function() {
    var acc = initial;
    var first = true;
    for await (var chunk of stream) {
      if (first && !hasInitial) {
        acc = chunk;
        first = false;
      } else {
        acc = await fn(acc, chunk);
        first = false;
      }
    }
    if (first && !hasInitial) {
      throw new TypeError('Reduce of empty stream with no initial value');
    }
    return acc;
  })();
};

// take() - take first N chunks
Readable.prototype.take = function(limit, options) {
  limit = Number(limit);
  if (isNaN(limit)) limit = 0;
  if (limit < 0) {
    throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "limit" is out of range. It must be >= 0. Received ' + limit);
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
    }
    if (options.signal !== undefined && typeof options.signal !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof options.signal);
    }
  }
  var source = this;
  var signal = options && options.signal;
  var result = Readable.from((async function*() {
    var count = 0;
    for await (var chunk of source) {
      if (count >= limit) break;
      yield chunk;
      count++;
    }
  })(), { objectMode: true });
  result.on('close', function() { if (!source._destroyed) source.destroy(); });
  if (signal) {
    if (signal.aborted) {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      setTimeout(function() { result.destroy(abortErr); }, 0);
    } else {
      signal.addEventListener('abort', function() {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        result.destroy(abortErr);
      });
    }
  }
  return result;
};

// drop() - skip first N chunks
Readable.prototype.drop = function(count, options) {
  if (typeof count !== 'number' || count < 0) {
    throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "limit" is out of range. It must be >= 0. Received ' + count);
  }
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
    }
    if (options.signal !== undefined && typeof options.signal !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof options.signal);
    }
  }
  var source = this;
  var signal = options && options.signal;
  var result = Readable.from((async function*() {
    var skipped = 0;
    for await (var chunk of source) {
      if (skipped < count) {
        skipped++;
        continue;
      }
      yield chunk;
    }
  })(), { objectMode: true });
  result.on('close', function() { if (!source._destroyed) source.destroy(); });
  if (signal) {
    if (signal.aborted) {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      setTimeout(function() { result.destroy(abortErr); }, 0);
    } else {
      signal.addEventListener('abort', function() {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        result.destroy(abortErr);
      });
    }
  }
  return result;
};

// some() - returns true if any chunk passes predicate
Readable.prototype.some = function(fn, options) {
  if (typeof fn !== 'function') {
    throw new TypeError('The "fn" argument must be of type function');
  }
  var stream = this;
  return (async function() {
    for await (var chunk of stream) {
      if (await fn(chunk)) return true;
    }
    return false;
  })();
};

// every() - returns true if all chunks pass predicate
Readable.prototype.every = function(fn, options) {
  if (typeof fn !== 'function') {
    throw new TypeError('The "fn" argument must be of type function');
  }
  var stream = this;
  return (async function() {
    for await (var chunk of stream) {
      if (!(await fn(chunk))) return false;
    }
    return true;
  })();
};

// find() - returns first chunk passing predicate
Readable.prototype.find = function(fn, options) {
  if (typeof fn !== 'function') {
    throw new TypeError('The "fn" argument must be of type function');
  }
  var stream = this;
  return (async function() {
    for await (var chunk of stream) {
      if (await fn(chunk)) return chunk;
    }
    return undefined;
  })();
};

// compose() on prototype - compose this readable with a transform function or Duplex/Transform stream
Readable.prototype.compose = function(val, options) {
  if (val === undefined || val === null) {
    var err = new TypeError('The "val" argument must be of type function. Received ' + String(val));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  var signal = options && options.signal;

  // If val is a Duplex or Transform stream (has both _read/_write or write+pipe), compose via pipe
  if (typeof val === 'object' && val !== null && typeof val.write === 'function' && typeof val.on === 'function') {
    // Check if it's a Readable (not writable) - those should be rejected
    if (typeof val._read === 'function' && typeof val._write !== 'function' && typeof val.write !== 'function') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_VALUE', 'The argument \'val\' is invalid. Received an instance of Readable');
    }
    // It's a Duplex/Transform - pipe source → val, return val as Readable
    var source = this;
    source.pipe(val);
    if (signal) {
      if (signal.aborted) {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        val.destroy(abortErr);
      } else {
        signal.addEventListener('abort', function() {
          var abortErr2 = new Error('The operation was aborted');
          abortErr2.code = 'ABORT_ERR';
          abortErr2.name = 'AbortError';
          val.destroy(abortErr2);
        });
      }
    }
    return val;
  }

  // If val is a non-writable stream (Readable), reject
  if (typeof val === 'object' && val !== null && typeof val.pipe === 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_VALUE', 'The argument \'val\' is invalid. Received an instance of Readable');
  }

  if (typeof val !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "val" argument must be of type function. Received type ' + typeof val);
  }

  // val is a function (sync or async generator)
  var source2 = this;
  if (signal && signal.aborted) {
    var abortErr3 = new Error('The operation was aborted');
    abortErr3.code = 'ABORT_ERR';
    abortErr3.name = 'AbortError';
    var errStream = new Readable({ objectMode: true });
    setTimeout(function() { errStream.destroy(abortErr3); }, 0);
    return errStream;
  }
  var result = Readable.from(val(source2), { objectMode: true });
  if (signal) {
    signal.addEventListener('abort', function() {
      var abortErr4 = new Error('The operation was aborted');
      abortErr4.code = 'ABORT_ERR';
      abortErr4.name = 'AbortError';
      result.destroy(abortErr4);
    });
  }
  return result;
};

// setDefaultHighWaterMark / getDefaultHighWaterMark
Readable.setDefaultHighWaterMark = function(objectMode, value) {
  if (objectMode) {
    defaultHighWaterMarkObjectMode = value;
  } else {
    defaultHighWaterMark = value;
  }
};

Readable.getDefaultHighWaterMark = function(objectMode) {
  return objectMode ? defaultHighWaterMarkObjectMode : defaultHighWaterMark;
};

function _isReadableLike(value) {
  return !!(value && typeof value.read === 'function' && typeof value.on === 'function');
}

function _isWritableLike(value) {
  return !!(value && typeof value.write === 'function' && typeof value.on === 'function');
}

function _toReadable(value, options) {
  if (!value) return null;
  if (typeof Blob !== 'undefined' && value instanceof Blob && typeof value.stream === 'function') {
    return Readable.fromWeb(value.stream());
  }
  if (value && typeof value.getReader === 'function') {
    return Readable.fromWeb(value);
  }
  if (_isReadableLike(value)) {
    return value;
  }
  return Readable.from(value, options);
}

function _toWritable(value, options) {
  if (!value) return null;
  if (_isWritableLike(value)) {
    return value;
  }
  if (value && typeof value.getWriter === 'function') {
    return Writable.fromWeb(value, options);
  }
  return null;
}

function _connectReadableToDuplex(readable, duplex) {
  if (!readable || !duplex) return;
  readable.on('data', function(chunk) {
    if (!duplex.push(chunk) && typeof readable.pause === 'function') {
      readable.pause();
    }
  });
  readable.on('error', function(err) {
    duplex.destroy(err);
  });
  readable.on('end', function() {
    duplex.push(null);
  });
  readable.on('close', function() {
    duplex.push(null);
  });
  duplex.on('pause', function() {
    if (typeof readable.pause === 'function') readable.pause();
  });
  duplex.on('resume', function() {
    if (typeof readable.resume === 'function') readable.resume();
  });
}

function _duplexFromReadableWritable(readable, writable, options) {
  if (!readable && !writable) {
    var _err = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'Invalid argument');
    throw _err;
  }
  var readableObjectMode = options && options.readableObjectMode != null ? !!options.readableObjectMode :
    (options && options.objectMode != null ? !!options.objectMode : (readable && readable._readableState && readable._readableState.objectMode));
  var writableObjectMode = options && options.writableObjectMode != null ? !!options.writableObjectMode :
    (options && options.objectMode != null ? !!options.objectMode : (writable && writable._writableState && writable._writableState.objectMode));
  var duplex = new Duplex({
    readableObjectMode: readableObjectMode,
    writableObjectMode: writableObjectMode,
    write: function(chunk, encoding, callback) {
      if (writable && typeof writable.write === 'function') {
        return writable.write(chunk, encoding, callback);
      }
      if (typeof callback === 'function') callback();
    },
    final: function(callback) {
      if (writable && typeof writable.end === 'function') {
        if (typeof callback === 'function') {
          writable.end(function(err) {
            callback(err);
          });
          return;
        }
        writable.end();
      }
      if (typeof callback === 'function') {
        callback();
      }
    },
    read: function() {}
  });
  if (writable && typeof writable.on === 'function') {
    writable.on('error', function(err) {
      duplex.destroy(err);
    });
  }
  if (readable) {
    _connectReadableToDuplex(readable, duplex);
  }
  return duplex;
}

function _duplexFromFunction(value, options) {
  var src = new PassThrough({
    readableObjectMode: options && options.objectMode ? options.objectMode : (options && options.writableObjectMode),
    writableObjectMode: options && options.objectMode ? options.objectMode : (options && options.readableObjectMode)
  });
  var output = value(src);
  if (output === undefined) {
    throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE', 'The \"source\" argument must return a value');
  }
  var readable = _toReadable(output, options);
  return _duplexFromReadableWritable(readable, src, options);
}

Duplex.from = function(value, options) {
  if (value === null || value === undefined) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The first argument must be of type function, object, Promise, or stream. Received undefined');
  }
  if (value instanceof Duplex) {
    return value;
  }
  if (typeof value === 'function') {
    return _duplexFromFunction(value, options);
  }
  if (_isReadableLike(value) && !value._writableState) {
    return value;
  }
  if (_isWritableLike(value) && !value._readableState) {
    return value;
  }
  if (value && (typeof value.readable !== 'undefined' || typeof value.writable !== 'undefined')) {
    var readableFromObject = _toReadable(value && value.readable, options);
    var writableFromObject = _toWritable(value && value.writable, options);
    if (readableFromObject && writableFromObject) {
      return _duplexFromReadableWritable(readableFromObject, writableFromObject, options);
    }
    if (readableFromObject) {
      return readableFromObject;
    }
    if (writableFromObject) {
      return writableFromObject;
    }
  }
  if (_isReadableLike(value) && _isWritableLike(value)) {
    return value;
  }
  var readable = _toReadable(value, options);
  if (readable && !readable._writableState) {
    return readable;
  }
  throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE', 'The first argument must be a valid stream argument.');
};

Duplex.fromWeb = function(value, options) {
  if (value === null || value === undefined) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be of type ReadableStream or WritableStream. Received undefined');
  }
  var readable = null;
  var writable = null;

  if (value.readable !== undefined || value.writable !== undefined) {
    if (value.readable && typeof value.readable.getReader === 'function') {
      readable = Readable.fromWeb(value.readable, options);
    }
    if (value.writable && typeof value.writable.getWriter === 'function') {
      writable = Writable.fromWeb(value.writable, options);
    }
  } else if (typeof value.getReader === 'function' && !value.getWriter) {
    readable = Readable.fromWeb(value, options);
  } else if (typeof value.getWriter === 'function' && !value.getReader) {
    writable = Writable.fromWeb(value, options);
  } else if (typeof value.getReader === 'function' && typeof value.getWriter === 'function') {
    readable = Readable.fromWeb(value.readable || value, options);
    writable = Writable.fromWeb(value.writable || value, options);
  }

  if (readable && !writable) {
    return readable;
  }
  if (writable && !readable) {
    return writable;
  }
  if (!readable && !writable) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be a readable/writable web stream pair.');
  }
  return _duplexFromReadableWritable(readable, writable, options);
};

Duplex.toWeb = function(duplex) {
  if (!duplex) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be a stream.');
  }
  return {
    readable: Readable.toWeb(duplex),
    writable: Writable.toWeb(duplex)
  };
};

// --- End Stream Helper Methods ---

Readable.from = function(iterable, options) {
  var readable = new Readable(options);
  // Handle signal option
  if (options && options.signal) {
    var sig = options.signal;
    if (sig.aborted) {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      readable.destroy(abortErr);
      return readable;
    }
    sig.addEventListener('abort', function() {
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      readable.destroy(abortErr);
    });
  }
  if (!iterable) {
    readable.push(null);
    return readable;
  }
  if (typeof iterable === 'string' || iterable instanceof Uint8Array) {
    readable.push(iterable);
    readable.push(null);
    return readable;
  }
  // Async iterable (including async generators)
  if (typeof iterable[Symbol.asyncIterator] === 'function') {
    var asyncIter = iterable[Symbol.asyncIterator]();
    var reading = false;
    function readNext() {
      if (reading || readable._destroyed) return;
      reading = true;
      asyncIter.next().then(function(result) {
        reading = false;
        if (readable._destroyed) {
          if (typeof asyncIter.return === 'function') {
            asyncIter.return();
          }
          return;
        }
        if (result.done) {
          readable.push(null);
        } else if (result.value === null) {
          var nullErr = new TypeError('May not write null values to stream');
          nullErr.code = 'ERR_STREAM_NULL_VALUES';
          readable.destroy(nullErr);
        } else {
          readable.push(result.value);
          readNext();
        }
      }).catch(function(err) {
        reading = false;
        if (!readable._destroyed) {
          readable.destroy(err);
        }
      });
    }
    readNext();
    return readable;
  }
  // Sync iterable - store data in buffer without emitting events
  // Events will be emitted when consumers start listening
  if (typeof iterable[Symbol.iterator] === 'function') {
    var iterator = iterable[Symbol.iterator]();
    var next = iterator.next();
    while (!next.done) {
      var value = next.value;
      readable._data.push(value);
      readable._updateReadableLength(readableStateChunkLength(value, readable._readableState.objectMode));
      next = iterator.next();
    }
    readable._syncReadableState();
    readable._ended = true;
    readable.readableEnded = true;
    readable._readableState.ended = true;
    readable._readableState.needReadable = true;
    // Mark as needing replay when consumers attach
    readable._needsReplay = true;
    return readable;
  }
  // Promise
  if (iterable instanceof Promise || (iterable && typeof iterable.then === 'function')) {
    function pushFromResolvedValue(value) {
      if (readable._destroyed) return;
      if (value && (value instanceof Promise || typeof value.then === 'function')) {
        value.then(pushFromResolvedValue).catch(function(err) {
          if (!readable._destroyed) {
            readable.destroy(err);
          }
        });
        return;
      }

      if (value && typeof value[Symbol.asyncIterator] === 'function') {
        var asyncIter = value[Symbol.asyncIterator]();
        var reading = false;
        function readNext() {
          if (reading || readable._destroyed) return;
          reading = true;
          asyncIter.next().then(function(result) {
            reading = false;
            if (readable._destroyed) {
              if (typeof asyncIter.return === 'function') {
                asyncIter.return();
              }
              return;
            }
            if (result.done) {
              readable.push(null);
            } else {
              readable.push(result.value);
              readNext();
            }
          }).catch(function(err) {
            reading = false;
            if (!readable._destroyed) {
              readable.destroy(err);
            }
          });
        }
        readNext();
        return;
      }

      if (typeof value === 'string' || value instanceof Uint8Array) {
        readable.push(value);
        readable.push(null);
        return;
      }

      if (value && typeof value[Symbol.iterator] === 'function') {
        try {
          var iterator = value[Symbol.iterator]();
          var next = iterator.next();
          while (!next.done) {
            if (readable._destroyed) {
              if (typeof iterator.return === 'function') {
                iterator.return();
              }
              return;
            }
            readable.push(next.value);
            next = iterator.next();
          }
          readable.push(null);
        } catch (err) {
          readable.destroy(err);
        }
        return;
      }

      readable.push(value);
      readable.push(null);
    }

    iterable.then(pushFromResolvedValue).catch(function(err) {
      if (!readable._destroyed) {
        readable.destroy(err);
      }
    });
    return readable;
  }
  readable.push(null);
  return readable;
};

// Readable.toWeb() - convert Node Readable to WHATWG ReadableStream
Readable.toWeb = function(nodeReadable) {
  return new ReadableStream({
    start: function(controller) {
      nodeReadable.on('data', function(chunk) {
        if (typeof chunk === 'string') {
          if (typeof TextEncoder !== 'undefined') {
            chunk = new TextEncoder().encode(chunk);
          } else if (typeof Buffer !== 'undefined' && Buffer.from) {
            chunk = Buffer.from(chunk);
          }
        }
        controller.enqueue(chunk);
      });
      nodeReadable.on('end', function() {
        controller.close();
      });
      nodeReadable.on('error', function(err) {
        controller.error(err);
      });
    },
    cancel: function() {
      if (typeof nodeReadable.destroy === 'function') nodeReadable.destroy();
    }
  });
};

// Readable.fromWeb() - convert WHATWG ReadableStream to Node Readable
Readable.fromWeb = function(webStream, options) {
  var readable = new Readable(options);
  var reader = webStream.getReader();
  function pump() {
    reader.read().then(function(result) {
      if (result.done) {
        readable.push(null);
      } else {
        readable.push(result.value);
        pump();
      }
    }).catch(function(err) {
      readable.destroy(err);
    });
  }
  pump();
  return readable;
};

function Writable(options) {
  if (!(this instanceof Writable) && !(this instanceof Duplex)) return new Writable(options);
  Stream.call(this);
  var self = this;
  // Determine objectMode: writableObjectMode overrides objectMode if present
  var objMode = (options && options.writableObjectMode != null) ? !!options.writableObjectMode :
                !!(options && options.objectMode);
  // Determine highWaterMark: explicit highWaterMark wins, then writableHighWaterMark, then default
  var hwm;
  if (options && options.highWaterMark != null) {
    hwm = options.highWaterMark;
  } else if (options && options.writableHighWaterMark != null) {
    hwm = options.writableHighWaterMark;
  } else {
    hwm = objMode ? defaultHighWaterMarkObjectMode : defaultHighWaterMark;
  }
  this.writableEnded = false;
  this.writableFinished = false;
  this.writableHighWaterMark = hwm;
  this.writableObjectMode = objMode;
  this.writableLength = 0;
  this.writableAborted = false;
  this.writableCorked = 0;
  this.writableNeedDrain = false;
  this.writable = true;
  this.errored = null;
  this._written = [];
  this._needDrain = false;
  this._writableState = {
    highWaterMark: hwm,
    objectMode: objMode,
    length: 0,
    writing: false,
    ended: false,
    finished: false,
    destroyed: false,
    decodeStrings: true,
    defaultEncoding: 'utf8',
    needDrain: false,
    ending: false,
    sync: false,
    bufferProcessing: false,
    errored: null,
    emitClose: (options && options.emitClose !== undefined) ? options.emitClose !== false : true,
    autoDestroy: (options && options.autoDestroy !== undefined) ? options.autoDestroy !== false : true,
    pendingcb: 0,
    constructed: true,
    prefinished: false,
    errorEmitted: false,
    emittedClose: false,
    corked: 0,
  };
  _defineStateAlias(this, 'writableState', '_writableState');
  Object.defineProperty(this._writableState, "corked", {
    configurable: true,
    enumerable: true,
    get: function() {
      return self.writableCorked;
    },
    set: function(value) {
      self.writableCorked = value;
    }
  });
  if (options && options.defaultEncoding !== undefined) {
    var _validEncs = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1 };
    if (!_validEncs[String(options.defaultEncoding).toLowerCase()]) {
      var encErr = new TypeError('Unknown encoding: ' + options.defaultEncoding);
      encErr.code = 'ERR_UNKNOWN_ENCODING';
      throw encErr;
    }
    this._writableState.defaultEncoding = options.defaultEncoding;
  }
  if (options && typeof options.write === 'function') this._write = options.write;
  if (options && typeof options.writev === 'function') this._writev = options.writev;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  if (options && typeof options.final === 'function') this._final = options.final;
  // construct callback support
  if (options && typeof options.construct === 'function') {
    this._writableState.constructed = false;
    var called = false;
    setTimeout(function() {
      options.construct(function(err) {
        if (called) {
          var multiErr = new Error('Callback called multiple times');
          multiErr.code = 'ERR_MULTIPLE_CALLBACK';
          self.emit('error', multiErr);
          return;
        }
        called = true;
        self._writableState.constructed = true;
        if (err) {
          self.destroy(err);
        }
      });
    }, 0);
  }
}
Writable.prototype = Object.create(Stream.prototype);
Writable.prototype.constructor = Writable;
Writable.prototype._undestroy = Stream.prototype._undestroy;

Writable.prototype._write = function(chunk, encoding, callback) {
  var err = new Error('The _write() method is not implemented');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  if (typeof callback === 'function') callback(err);
  else throw err;
};

Writable.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  // ERR_STREAM_DESTROYED - reject writes after destroy
  if (this._destroyed) {
    var destroyErr = new Error('Cannot call write after a stream was destroyed');
    destroyErr.code = 'ERR_STREAM_DESTROYED';
    if (typeof callback === 'function') {
      setTimeout(function() { callback(destroyErr); }, 0);
      return false;
    }
    throw destroyErr;
  }
  // ERR_STREAM_WRITE_AFTER_END - reject writes after end
  if (this.writableEnded) {
    var endErr = new Error('write after end');
    endErr.code = 'ERR_STREAM_WRITE_AFTER_END';
    if (typeof callback === 'function') {
      setTimeout(function() { callback(endErr); }, 0);
    }
    if (this._writableState && this._writableState.autoDestroy === false) {
      this.emit('error', endErr);
      this.errored = endErr;
      if (this._writableState) {
        this._writableState.errored = endErr;
      }
      return false;
    }
    this.destroy(endErr);
    return false;
  }
  // ERR_STREAM_NULL_VALUES - null is never valid in objectMode or otherwise
  if (chunk === null) {
    throw makeError(TypeError, 'ERR_STREAM_NULL_VALUES', 'May not write null values to stream');
  }
  // ERR_INVALID_ARG_TYPE - in non-objectMode, only strings, Buffers, and Uint8Arrays are valid
  if (!this.writableObjectMode && typeof chunk === 'string') {
    var enc = this._writableState && this._writableState.defaultEncoding ? this._writableState.defaultEncoding : (encoding || 'utf8');
    if (typeof Buffer !== 'undefined' && Buffer.from) {
      chunk = Buffer.from(chunk, enc);
    } else {
      if (typeof TextEncoder !== 'undefined') {
        chunk = new TextEncoder().encode(chunk);
      } else {
        var textBytes = new Uint8Array(chunk.length);
        for (var ti = 0; ti < chunk.length; ti++) {
          textBytes[ti] = chunk.charCodeAt(ti) & 0xff;
        }
        chunk = textBytes;
      }
    }
  }
  if (!this.writableObjectMode && typeof chunk !== 'string' &&
      !(typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) &&
      !(chunk instanceof Uint8Array)) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "chunk" argument must be of type string or an instance of Buffer or Uint8Array. Received type ' + typeof chunk);
  }
  var chunkLen = 0;
  if (chunk !== undefined) {
    this._written.push(chunk);
    chunkLen = readableStateChunkLength(chunk, this.writableObjectMode || (this._writableState && this._writableState.objectMode));
    this.writableLength += chunkLen;
  }
  if (this.writableCorked > 0) {
    if (!this._writeQueue) this._writeQueue = [];
    this._writeQueue.push({
      chunk: chunk,
      encoding: encoding || 'utf8',
      callback: typeof callback === 'function' ? callback : null,
      chunkLen: chunkLen
    });
    var shouldNeedDrainNow = this.writableLength > this.writableHighWaterMark;
    if (shouldNeedDrainNow) {
      this._needDrain = true;
      this.writableNeedDrain = true;
      if (this._writableState) {
        this._writableState.needDrain = true;
      }
      return false;
    }
    return true;
  }
  var shouldNeedDrain = this.writableLength > this.writableHighWaterMark;
  var self = this;
  var state = this._writableState;
  this._writableState.writing = true;
  var hadNeedDrain = this._needDrain || this.writableNeedDrain;
  var callbackCalled = false;
  var onWriteComplete = function(err) {
    if (callbackCalled) return;
    callbackCalled = true;
    self._writableState.writing = false;
    self.writableLength -= chunkLen;
    if (self.writableLength < 0) self.writableLength = 0;
    var shouldEmitDrain = !err && (hadNeedDrain || shouldNeedDrain) &&
                          !(state && state.ending) &&
                          !self._destroyed &&
                          self.writableLength < self.writableHighWaterMark;
    if (shouldEmitDrain) {
      self._needDrain = false;
      self.writableNeedDrain = false;
      if (self._writableState) {
        self._writableState.needDrain = false;
      }
    }
    if (err) {
      self.writable = false;
      self.errored = err;
      if (self._writableState) self._writableState.errored = err;
      if (typeof callback === 'function') callback(err);
      // autoDestroy on write error
      if (self._writableState && self._writableState.autoDestroy && !self._destroyed) {
        self.destroy(err);
      }
    } else {
      if (typeof callback === 'function') callback();
    }
    if (shouldEmitDrain) {
      var emitDrain = typeof process === 'object' &&
                      process &&
                      typeof process.nextTick === 'function'
                      ? process.nextTick
                      : function(fn) { setTimeout(fn, 0); };
      emitDrain(function() {
        self.emit('drain');
      });
    }
  };
  if (shouldNeedDrain) {
    this._needDrain = true;
    this.writableNeedDrain = true;
    if (this._writableState) {
      this._writableState.needDrain = true;
    }
  }
  try {
    self._write(chunk, encoding || 'utf8', onWriteComplete);
  } catch (err) {
    onWriteComplete(err);
    return false;
  }
  return !shouldNeedDrain;
};

Writable.prototype._flushWriteQueue = function() {
  if (!this._writeQueue || this._writeQueue.length === 0) {
    return;
  }
  if (!this._writableState || this._writableState.writing || this._writableState.bufferProcessing) {
    return;
  }
  var self = this;
  var state = this._writableState;
  var batch = this._writeQueue;
  this._writeQueue = [];
  state.bufferProcessing = true;
  state.writing = true;

  var hadNeedDrain = this._needDrain || this.writableNeedDrain;
  var totalLen = 0;
  var shouldNeedDrain = this.writableLength > this.writableHighWaterMark;
  for (var bi = 0; bi < batch.length; bi++) {
    totalLen += batch[bi].chunkLen || 0;
  }

  var maybeEmitDrain = function() {
    if (self._destroyed) return;
    if (state && state.ending) return;
    if (!hadNeedDrain && !shouldNeedDrain) return;
    if (self.writableLength >= self.writableHighWaterMark) return;
    if (!self._needDrain && !self.writableNeedDrain) return;
    self._needDrain = false;
    self.writableNeedDrain = false;
    if (self._writableState) {
      self._writableState.needDrain = false;
    }
    var emitDrain = typeof process === 'object' &&
                    process &&
                    typeof process.nextTick === 'function'
                    ? process.nextTick
                    : function(fn) { setTimeout(fn, 0); };
    emitDrain(function() {
      self.emit('drain');
    });
  };

  var cleanup = function(err) {
    state.bufferProcessing = false;
    state.writing = false;
    self.writableLength -= totalLen;
    if (self.writableLength < 0) self.writableLength = 0;
    if (err) {
      self.writable = false;
      self.errored = err;
      if (state) state.errored = err;
      for (var bi2 = 0; bi2 < batch.length; bi2++) {
        if (typeof batch[bi2].callback === 'function') {
          batch[bi2].callback(err);
        }
      }
      if (state.autoDestroy && !self._destroyed) {
        self.destroy(err);
      }
      return;
    }
    maybeEmitDrain();
    for (var bi3 = 0; bi3 < batch.length; bi3++) {
      if (typeof batch[bi3].callback === 'function') batch[bi3].callback();
    }
    if (!self._destroyed && self._writeQueue && self._writeQueue.length) {
      self._flushWriteQueue();
    }
  };

  if (typeof self._writev === 'function' && batch.length > 1) {
    var writevBatch = [];
    for (var wi = 0; wi < batch.length; wi++) {
      writevBatch.push({
        chunk: batch[wi].chunk,
        encoding: batch[wi].encoding
      });
    }
    try {
      self._writev(writevBatch, function(err) {
        cleanup(err);
      });
    } catch (err) {
      cleanup(err);
    }
    return;
  }

  var index = 0;
  function runNext() {
    if (index >= batch.length) {
      cleanup();
      return;
    }
    var item = batch[index++];
    var itemDone = false;
    try {
      self._write(item.chunk, item.encoding, function(err) {
        if (itemDone) return;
        itemDone = true;
        if (err) {
          cleanup(err);
          return;
        }
        if (typeof item.callback === 'function') item.callback();
        runNext();
      });
    } catch (err) {
      cleanup(err);
    }
  }
  runNext();
};

Writable.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = null; encoding = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }

  // If already finished, async callback with ERR_STREAM_ALREADY_FINISHED
  if (this.writableFinished) {
    var finishedErr = new Error('write after end');
    finishedErr.code = 'ERR_STREAM_ALREADY_FINISHED';
    if (typeof callback === 'function') {
      setTimeout(function() { callback(finishedErr); }, 0);
    }
    return this;
  }

  // If already ended but not yet finished, just queue the callback
  if (this.writableEnded) {
    if (typeof callback === 'function') {
      if (!this._endCallbacks) this._endCallbacks = [];
      this._endCallbacks.push(callback);
    }
    return this;
  }

  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }
  if (this.writableCorked > 0) {
    this.writableCorked = 1;
    this.uncork();
  }
  this.writableEnded = true;
  this.writable = false;
  this._writableState.ending = true;
  this._writableState.ended = true;
  var state = this._writableState;
  var scheduleDone = typeof process === 'object' &&
                     process &&
                     typeof process.nextTick === 'function'
                     ? process.nextTick
                     : function(fn) { setTimeout(fn, 0); };

  var self = this;
  // Collect end callbacks (if multiple end() calls happened before writableEnded)
  if (!this._endCallbacks) this._endCallbacks = [];
  if (typeof callback === 'function') this._endCallbacks.push(callback);

  var done = function() {
    if (self._destroyed || self.errored) {
      var errorCbs = self._endCallbacks;
      self._endCallbacks = [];
      for (var e = 0; e < errorCbs.length; e++) { errorCbs[e](self.errored || null); }
      return;
    }
    if (state && (state.writing || state.bufferProcessing || (self._writeQueue && self._writeQueue.length))) {
      if (typeof setTimeout === 'function') {
        return setTimeout(done, 0);
      }
      return scheduleDone(done);
    }
    return scheduleDone(function() {
      if (self._destroyed || self.errored) {
        // If destroyed or errored before finish fires, don't emit finish
        var cbs = self._endCallbacks;
        self._endCallbacks = [];
        for (var j = 0; j < cbs.length; j++) { cbs[j](self.errored || null); }
        return;
      }
      if (state && state.prefinished) return;
      if (state) state.prefinished = true;
      self.emit('prefinish');
      // Defer finish emission
      if (self._destroyed || self.errored) return;
      self.writableFinished = true;
      self._writableState.finished = true;
      self.emit('finish');
      if (self._writableState.autoDestroy && !self._destroyed) {
        self.destroy();
      } else {
        self._close();
      }
      var cbs = self._endCallbacks;
      self._endCallbacks = [];
      for (var j = 0; j < cbs.length; j++) { cbs[j](null); }
    });
  };

  if (typeof this._final === 'function') {
    this._final(function(err) {
      if (err) {
        self.destroy(err);
        var cbs = self._endCallbacks;
        self._endCallbacks = [];
        for (var j = 0; j < cbs.length; j++) { cbs[j](err); }
        return;
      }
      done();
    });
  } else {
    done();
  }

  return this;
};

Writable.prototype.cork = function() {
  this.writableCorked++;
};
Writable.prototype.uncork = function() {
  if (this.writableCorked > 0) {
    this.writableCorked--;
    if (this.writableCorked <= 0) {
      this._flushWriteQueue();
    }
  }
};
Writable.prototype.setDefaultEncoding = function(enc) {
  if (!this._writableState) return this;
  if (typeof enc === 'string') {
    this._writableState.defaultEncoding = enc;
  }
  return this;
};

// Writable.toWeb / fromWeb
Writable.toWeb = function(nodeWritable) {
  return new WritableStream({
    write: function(chunk) {
      return new Promise(function(resolve, reject) {
        nodeWritable.write(chunk, function(err) {
          if (err) reject(err); else resolve();
        });
      });
    },
    close: function() {
      return new Promise(function(resolve) {
        nodeWritable.end(function() { resolve(); });
      });
    },
    abort: function(reason) {
      if (typeof nodeWritable.destroy === 'function') nodeWritable.destroy(reason);
    }
  });
};

Writable.fromWeb = function(webWritable, options) {
  var writer = webWritable.getWriter();
  return new Writable(Object.assign({}, options, {
    write: function(chunk, encoding, callback) {
      writer.write(chunk).then(function() { callback(); }).catch(callback);
    },
    final: function(callback) {
      writer.close().then(function() { callback(); }).catch(callback);
    }
  }));
};

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);
  // For Duplex, we need to handle construct once (not twice)
  var construct = options && options.construct;
  if (construct) {
    var optsNoConstruct = Object.assign({}, options);
    delete optsNoConstruct.construct;
    Readable.call(this, optsNoConstruct);
    Writable.call(this, optsNoConstruct);
  } else {
    Readable.call(this, options);
    Writable.call(this, options);
  }
  this.writableEnded = false;
  this.writableFinished = false;
  this.writableAborted = false;
  this.allowHalfOpen = !(options && options.allowHalfOpen === false);
  // Handle readable option - when readable is false, the stream is not a readable stream
  // so readableAborted should never be set to true
  if (options && options.readable === false) {
    this.readableAborted = false;
    this._readableState.endEmitted = true;
    this._readableState.endConsumed = true; // Prevent destroy from setting readableAborted
  }
  // construct callback for Duplex (only once)
  if (typeof construct === 'function') {
    this._readableState.constructed = false;
    this._writableState.constructed = false;
    var self = this;
    var called = false;
    setTimeout(function() {
      construct(function(err) {
        if (called) {
          var multiErr = new Error('Callback called multiple times');
          multiErr.code = 'ERR_MULTIPLE_CALLBACK';
          self.emit('error', multiErr);
          return;
        }
        called = true;
        self._readableState.constructed = true;
        self._writableState.constructed = true;
        if (err) {
          self.destroy(err);
        }
      });
    }, 0);
  }
}
Duplex.prototype = Object.create(Readable.prototype);
Object.keys(Writable.prototype).forEach(function(k) {
  if (!Duplex.prototype[k]) Duplex.prototype[k] = Writable.prototype[k];
});
Duplex.prototype.constructor = Duplex;

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  if (!this._writableState) {
    Writable.call(this, options);
  }
  this._transformState = {
    pendingWrites: 0,
    finalCallback: null,
    finalizing: false
  };
  if (!options || typeof options.final !== 'function') {
    this._final = function(callback) {
      var state = this._transformState || {};
      if (state.finalizing) return;
      state.finalizing = true;
      if (state.pendingWrites > 0) {
        state.finalCallback = callback;
        return;
      }
      this.push(null);
      if (typeof callback === 'function') callback();
    };
  }
  if (options && typeof options.transform === 'function') this._transform = options.transform;
  if (options && typeof options.flush === 'function') this._flush = options.flush;
}
Transform.prototype = Object.create(Duplex.prototype);
Transform.prototype.constructor = Transform;

Transform.prototype._transform = function(chunk, encoding, callback) {
  var err = new Error('The _transform() method is not implemented');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  if (typeof callback === 'function') callback(err);
  else throw err;
};

Transform.prototype._write = function(chunk, encoding, callback) {
  var self = this;
  var callbackCalled = false;
  var state = self._transformState || {};
  state.pendingWrites = (state.pendingWrites || 0) + 1;

  function finalizeIfNeeded() {
    if (!state.finalizing || state.pendingWrites > 0 || typeof state.finalCallback !== 'function') {
      return;
    }
    var finalCallback = state.finalCallback;
    state.finalCallback = null;
    self.push(null);
    finalCallback();
  }

  function done(err, transformedChunk) {
    if (callbackCalled) return;
    callbackCalled = true;
    state.pendingWrites = Math.max(0, state.pendingWrites - 1);
    if (err) {
      if (typeof callback === 'function') callback(err);
      return;
    }
    if (transformedChunk !== undefined) {
      self.push(transformedChunk);
    }
    finalizeIfNeeded();
    if (typeof callback === 'function') {
      callback();
    }
  }
  try {
    this._transform(chunk, encoding || 'utf8', done);
  } catch (err) {
    state.pendingWrites = Math.max(0, state.pendingWrites - 1);
    done(err);
  }
};

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);
  Transform.call(this, options);
}
PassThrough.prototype = Object.create(Transform.prototype);
PassThrough.prototype.constructor = PassThrough;
PassThrough.prototype._transform = function(chunk, encoding, callback) {
  this.push(chunk);
  if (typeof callback === 'function') callback();
};

Stream.prototype.pipe = function(dest, options) {
  var source = this;
  var state = source._readableState;
  var hasDrainListener = false;

  if (state) {
    state.pipes.push(dest);
    state.pipesCount = state.pipes.length;
  }

  function isWritableTarget() {
    if (!dest) return false;
    if (dest.writable === false) return false;
    if (dest._destroyed) return false;
    if (dest._writableState) {
      if (dest._writableState.destroyed || dest._writableState.ended || dest._writableState.ending) return false;
      if (dest._writableState.writable === false) return false;
    }
    return true;
  }

  function handlePipeError(err) {
    if (typeof process === 'object' && process && typeof process.emit === 'function' && typeof process.listenerCount === 'function' && process.listenerCount('uncaughtException') > 0) {
      process.emit('uncaughtException', err);
      return;
    }
    if (typeof globalThis.__exactUncaughtExceptionHandler === 'function' && globalThis.__exactUncaughtExceptionHandler(err)) {
      return;
    }
    throw err;
  }

  function ondata(chunk) {
    if (!isWritableTarget()) {
      unpipe();
      return;
    }

    if (dest && typeof dest.write === 'function') {
      try {
        var ok = dest.write(chunk);
        if (ok === false && typeof source.pause === 'function') {
          pause();
        }
      } catch (err) {
        if (typeof dest.destroy === 'function') {
          dest.destroy(err);
        } else {
          onerror(err);
        }
      }
    }
  }

  function pause() {
    if (!state) return;
    _addAwaitDrainWriter(state, dest);
    if (!hasDrainListener) {
      dest.on('drain', ondrain);
      hasDrainListener = true;
    }
    if (typeof source.pause === 'function') {
      source.pause();
    }
  }

  function ondrain() {
    if (state) {
      _removeAwaitDrainWriter(state, dest);
    }
    if (hasDrainListener) {
      dest.removeListener('drain', ondrain);
      hasDrainListener = false;
    }
    if (typeof source.resume === 'function' && (!state || !_hasAwaitDrainWriters(state))) {
      source.resume();
    }
  }

  function onend() {
    var canFinishDestination = true;
    if (dest && dest._destroyed) {
      canFinishDestination = false;
    }
    if (dest && dest._writableState && dest._writableState.errored) {
      canFinishDestination = false;
    }
    if (dest && typeof dest.writable === 'boolean' && dest.writable === false) {
      canFinishDestination = false;
    }
    if ((!options || options.end !== false) && canFinishDestination && dest && typeof dest.end === 'function') {
      dest.end();
    }
  }

  function onerror(err) {
    unpipe();
    if (dest && typeof dest.removeListener === 'function') {
      dest.removeListener('error', onerror);
    }
    var shouldForwardToDestination = false;
    if (dest && typeof dest.listenerCount === 'function') {
      shouldForwardToDestination = dest.listenerCount('error') > 0;
    } else if (dest && dest._events && dest._events.error) {
      shouldForwardToDestination = true;
    }

    if (shouldForwardToDestination) {
      if (dest && typeof dest.emit === 'function') {
        try {
          dest.emit('error', err);
        } catch (destEmitErr) {
          handlePipeError(destEmitErr);
        }
      }
      return;
    }

    if (dest && typeof dest.destroy === 'function') {
      try {
        dest.destroy(err);
      } catch (destroyErr) {
        handlePipeError(destroyErr);
      }
    }
  }

  function onfinish() {
    unpipe();
  }

  // When dest closes/finishes, clean up the pipe
  function onclose() {
    unpipe();
  }

  function ondestroy() {
    unpipe();
  }

  // If the destination is destroyed or errors, stop piping to avoid writes
  // to a destroyed destination.
  if (dest && typeof dest.on === 'function') {
    if (typeof dest.prependListener === 'function') {
      dest.prependListener('error', onerror);
    } else {
      dest.on('error', onerror);
    }
    dest.on('close', onclose);
    dest.on('finish', onfinish);
    dest.on('destroy', ondestroy);
  }

  function unpipe() {
    source.removeListener('data', ondata);
    source.removeListener('end', onend);
    if (hasDrainListener) {
      dest.removeListener('drain', ondrain);
      hasDrainListener = false;
    }
    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('error', onerror);
    dest.removeListener('destroy', ondestroy);
    if (state) {
      var idx = state.pipes.indexOf(dest);
      if (idx !== -1) state.pipes.splice(idx, 1);
      state.pipesCount = state.pipes.length;
      if (state.pipes.length === 0) {
        state.awaitDrainWriters = null;
      }
    }
  }

  source.on('data', ondata);
  if (state && state.endEmitted) {
    _nextTick(onend);
  } else {
    source.on('end', onend);
  }

  // Store unpipe function for later
  if (!source._pipeCleanups) source._pipeCleanups = new Map();
  source._pipeCleanups.set(dest, unpipe);

  if (dest && dest.writableNeedDrain === true) {
    pause();
  } else if (!state || source.readableFlowing !== true) {
    if (typeof source.resume === 'function') source.resume();
  }

  dest.emit('pipe', source);
  return dest;
};

Stream.prototype.unpipe = function(dest) {
  var state = this._readableState;
  if (state) {
    if (state.pipesCount === 0 && (!dest || !this._pipeCleanups)) return this;
  } else if (!dest || !this._pipeCleanups) {
    return this;
  }

  if (!dest) {
    var dests = state && state.pipes ? state.pipes.slice() : [];
    if (this._pipeCleanups) {
      dests = dests.concat(Array.prototype.slice.call(this._pipeCleanups.keys()));
    }
    if (state) {
      state.pipes = [];
      state.pipesCount = 0;
      state.awaitDrainWriters = null;
    }
    for (var i = 0; i < dests.length; i++) {
      if (this._pipeCleanups && this._pipeCleanups.has(dests[i])) {
        this._pipeCleanups.get(dests[i])();
        this._pipeCleanups.delete(dests[i]);
      }
      if (dests[i] && typeof dests[i].emit === 'function') {
        dests[i].emit('unpipe', this);
      }
    }
    return this;
  }

  if (this._pipeCleanups && this._pipeCleanups.has(dest)) {
    this._pipeCleanups.get(dest)();
    this._pipeCleanups.delete(dest);
  }
  if (state && state.pipes) {
    var idx = state.pipes.indexOf(dest);
    if (idx !== -1) {
      state.pipes.splice(idx, 1);
      state.pipesCount = state.pipes.length;
    }
  }
  if (state && state.pipes && state.pipes.length === 0) {
    state.awaitDrainWriters = null;
  }
  if (dest && typeof dest.emit === 'function') {
    dest.emit('unpipe', this);
  }
  return this;
};

// wrap() - wrap old-style stream as Readable
Readable.prototype.wrap = function(stream) {
  var self = this;
  stream.on('data', function(chunk) {
    self.push(chunk);
  });
  stream.on('end', function() {
    self.push(null);
  });
  stream.on('error', function(err) {
    self.destroy(err);
  });
  return this;
};

function pipeline() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  var callback = null;
  var options = null;
  var last = null;

  // Last arg can be callback
  if (typeof args[args.length - 1] === 'function') {
    callback = args.pop();
  }
  last = args[args.length - 1];
  if (
    args.length > 1 &&
    last &&
    typeof last === 'object' &&
    !Array.isArray(last) &&
    !last.pipe
  ) {
    options = args.pop();
  }

  var streams = args;
  if (streams.length === 0) {
    var err = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams[0]" argument must be of type Stream. Received undefined');
    throw err;
  }
  if (streams.length < 2) {
    var err = makeError(Error, 'ERR_MISSING_ARGS', 'The "streams" argument must be specified');
    throw err;
  }

  var signal = options && options.signal;
  var error = null;
  var finished = false;
  var promiseResolve = null;
  var promiseReject = null;
  var listeners = [];

  function destroyAll(err) {
    for (var i = 0; i < streams.length; i++) {
      if (streams[i] && typeof streams[i].destroy === 'function' && !streams[i]._destroyed) {
        streams[i].destroy(err);
      }
    }
  }

  function addListener(stream, event, handler) {
    if (!stream || typeof stream.on !== 'function' || typeof stream.removeListener !== 'function') return;
    stream.on(event, handler);
    listeners.push([stream, event, handler]);
  }

  function cleanup() {
    for (var li = 0; li < listeners.length; li++) {
      listeners[li][0].removeListener(listeners[li][1], listeners[li][2]);
    }
    listeners = [];
    if (signal && signal.removeEventListener) {
      signal.removeEventListener('abort', onAbort);
    }
  }

  function settle(err) {
    if (finished) return;
    finished = true;
    cleanup();
    if (err || error) {
      if (promiseReject) {
        promiseReject(err || error);
      }
      if (typeof callback === 'function') {
        callback(err || error);
      }
      return;
    }
    if (promiseResolve) {
      promiseResolve();
    }
    if (typeof callback === 'function') {
      callback(null);
    }
  }

  function onError(err) {
    if (error) return;
    error = err;
    destroyAll(err);
    settle(err);
  }

  function onFinish() {
    settle(null);
  }

  function onAbort() {
    var abortErr = new Error('The operation was aborted');
    abortErr.code = 'ABORT_ERR';
    abortErr.name = 'AbortError';
    error = error || abortErr;
    destroyAll(abortErr);
    settle(abortErr);
  }

  if (signal) {
    if (signal.aborted) {
      onAbort();
      if (!callback) {
        return Promise.reject(error);
      }
      return;
    }
    signal.addEventListener('abort', onAbort);
  }

  var streamErrors = [];
  for (var i = 0; i + 1 < streams.length; i++) {
    var src = streams[i];
    var dst = streams[i + 1];
    if (typeof src.pipe === 'function') {
      try {
        src.pipe(dst);
      } catch (err) {
        onError(err);
        break;
      }
    }
    streamErrors.push(src);
  }
  streamErrors.push(streams[streams.length - 1]);
  var seen = [];
  for (var se = 0; se < streamErrors.length; se++) {
    if (seen.indexOf(streamErrors[se]) === -1) {
      addListener(streamErrors[se], 'error', onError);
      seen.push(streamErrors[se]);
    }
  }

  var last = streams[streams.length - 1];
  addListener(last, 'finish', onFinish);
  addListener(last, 'end', onFinish);

  if (!callback) {
    return new Promise(function(resolve, reject) {
      if (finished) {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
        return;
      }
      promiseResolve = resolve;
      promiseReject = reject;
    });
  }

  return last;
}

function finished(stream, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (callback !== undefined && typeof callback !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "callback" argument must be of type function. Received ' + typeof callback);
  }
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received ' + typeof options);
  }
  if (options && typeof options.readable !== 'undefined' && typeof options.readable !== 'boolean') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "readable" argument must be of type boolean. Received ' + typeof options.readable);
  }
  if (options && typeof options.writable !== 'undefined' && typeof options.writable !== 'boolean') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "writable" argument must be of type boolean. Received ' + typeof options.writable);
  }
  if (options && typeof options.error !== 'undefined' && typeof options.error !== 'boolean') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "error" argument must be of type boolean. Received ' + typeof options.error);
  }
  if (options && typeof options.cleanup !== 'undefined' && typeof options.cleanup !== 'boolean') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "cleanup" argument must be of type boolean. Received ' + typeof options.cleanup);
  }
  if (options && typeof options.signal !== 'undefined') {
    if (
      options.signal === null ||
      typeof options.signal !== 'object' ||
      typeof options.signal.addEventListener !== 'function'
    ) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" argument must be of type AbortSignal. Received ' + options.signal);
    }
  }

  options = options || {};
  var hasReadableCapability = !!(
    stream &&
    (stream._readableState ||
     (typeof stream.read === 'function' && stream.readable !== false))
  );
  var hasWritableCapability = !!(
    stream &&
    (stream._writableState ||
     (typeof stream.write === 'function' && stream.writable !== false))
  );

  // Validate that the first argument is a stream
  if (!stream || (!hasReadableCapability && !hasWritableCapability)) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be an instance of Stream. Received ' + (stream === null ? 'null' : typeof stream));
  }

  var called = false;
  var shouldWaitReadable = options.readable !== false;
  var shouldWaitWritable = options.writable !== false;
  if (!hasReadableCapability) {
    shouldWaitReadable = false;
  }
  if (!hasWritableCapability) {
    shouldWaitWritable = false;
  }
  var shouldEmitError = options.error !== false;
  var shouldCleanup = options.cleanup !== false;
  var error = null;

  function isReadableDone() {
    return !shouldWaitReadable ||
      stream.readableEnded ||
      stream.readable === false ||
      (stream._readableState && (stream._readableState.ended || stream._readableState.endEmitted));
  }

  function isWritableDone() {
    return !shouldWaitWritable ||
      stream.writableFinished ||
      stream.writable === false ||
      (stream._writableState && stream._writableState.finished);
  }

  function getCurrentError() {
    if (!shouldEmitError) return null;
    if (stream._readableState && stream._readableState.errored) return stream._readableState.errored;
    if (stream._writableState && stream._writableState.errored) return stream._writableState.errored;
    if (stream.errored) return stream.errored;
    return null;
  }

  var cleanup = function() {};
  function done(err) {
    if (called) return;
    if (err) {
      error = err;
    }
    called = true;
    if (shouldCleanup) {
      cleanup();
    }
    if (typeof callback === 'function') callback(err || null);
  }

  var onFinish = function() {
    var readableDone = isReadableDone();
    var writableDone = isWritableDone();
    if (readableDone && writableDone) {
      done(null);
    }
  };
  var onEnd = function() { onFinish(); };
  var onError = function(err) {
    if (shouldEmitError) {
      done(err);
    }
  };
  var onClose = function() {
    var readableDone = isReadableDone();
    var writableDone = isWritableDone();
    if (!readableDone || !writableDone) {
      done(new Error('premature close'));
    } else {
      done(null);
    }
  };

  if (shouldWaitReadable && stream.on) {
    stream.on('end', onEnd);
  }
  if (shouldWaitWritable && stream.on) {
    stream.on('finish', onFinish);
  }
  if (stream.on) {
    stream.on('error', onError);
    stream.on('close', onClose);
  }

  // Return cleanup function
  cleanup = function() {
    if (stream.removeListener) {
      stream.removeListener('end', onEnd);
      stream.removeListener('finish', onFinish);
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
    }
    if (options && options.signal && typeof options.signal.removeEventListener === 'function') {
      options.signal.removeEventListener('abort', onSignalAbort);
    }
  };

  // AbortSignal support
  if (options.signal) {
    var onSignalAbort = function() {
      var err = new Error('The operation was aborted');
      err.code = 'ABORT_ERR';
      err.name = 'AbortError';
      done(err);
    };
    options.signal.addEventListener('abort', onSignalAbort);
    if (options.signal.aborted) {
      onSignalAbort();
    }
  }

  var immediateError = getCurrentError();
  if (immediateError || (isReadableDone() && isWritableDone())) {
    done(immediateError);
  }

  // If no callback, return a promise
  if (typeof callback !== 'function') {
    return new Promise(function(resolve, reject) {
      if (called) {
        if (error) reject(error);
        else resolve();
        return;
      }
      callback = function(err) {
        if (err) reject(err); else resolve();
      };
    });
  }

  return cleanup;
}

// compose() - compose multiple Transform/Duplex streams into one
function compose() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  if (args.length === 0) throw new Error('compose requires at least one stream');
  if (args.length === 1) {
    if (typeof args[0] === 'function') {
      return Duplex.from(args[0]);
    }
    return args[0];
  }

  var normalized = [];
  for (var ni = 0; ni < args.length; ni++) {
    var stage = args[ni];
    if (typeof stage === 'function') {
      stage = Duplex.from(stage);
    }
    if (!stage || typeof stage.pipe !== 'function') {
      var pipeErr = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams" argument must be a stream.');
      throw pipeErr;
    }
    normalized.push(stage);
  }

  var first = normalized[0];
  var last = normalized[normalized.length - 1];

  // Pipe all streams together
  for (var j = 0; j + 1 < normalized.length; j++) {
    if (typeof normalized[j + 1].write !== 'function') {
      var writeErr = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams" argument must have a writable stream in the middle.');
      throw writeErr;
    }
    normalized[j].pipe(normalized[j + 1]);
  }

  // Create a Duplex that writes to first and reads from last
  var composed = new Duplex({
    write: function(chunk, encoding, callback) {
      var self = this;
      if (typeof first.write === 'function') {
        var done = false;
        var hasCallback = typeof callback === 'function';
        var wrapped = function(err) {
          if (done) return;
          done = true;
          if (typeof first.removeListener === 'function' && onDrain) {
            first.removeListener('drain', onDrain);
          }
          if (typeof callback === 'function') callback(err);
        };
        var onDrain = function() {
          if (done) return;
          done = true;
          if (typeof first.removeListener === 'function' && onDrain) {
            first.removeListener('drain', onDrain);
          }
          if (typeof callback === 'function') {
            callback();
          } else if (typeof self.emit === 'function') {
            self.emit('drain');
          }
        };
        var ok;
        try {
          if (hasCallback) {
            ok = first.write(chunk, encoding, wrapped);
          } else {
            ok = first.write(chunk, encoding);
          }
        } catch (err) {
          wrapped(err);
          return false;
        }
        if (ok === false && !hasCallback) {
          if (typeof first.on === 'function') {
            first.on('drain', onDrain);
          }
        }
        return ok;
      } else if (hasCallback) {
        callback();
      }
      return true;
    },
    final: function(callback) {
      var done = false;
      var finish = function(err) {
        if (done) return;
        done = true;
        if (typeof callback === 'function') callback(err);
      };
      try {
        if (typeof first.end === 'function') {
          first.end(function(err) {
            if (err) {
              if (typeof first.destroy === 'function') first.destroy(err);
            }
            finish(err);
          });
        } else {
          finish();
        }
      } catch (err) {
        finish(err);
      }
    },
    read: function() {}
  });

  // Forward data from last stream to composed
  last.on('data', function(chunk) {
    composed.push(chunk);
  });
  last.on('end', function() {
    composed.push(null);
  });

  // Forward errors from all streams
  function safeDestroyComposed(err) {
    if (composed._destroyed || composed.destroyed) return;
    try {
      composed.destroy(err);
      return;
    } catch (e) {
      // Node-style stream errors are emitted, and no error listener may be attached.
      // avoid throwing from composed.destroy() so callers without 'error' handlers still continue.
      if (composed._writableState) composed._writableState.errored = err;
      if (composed._readableState) composed._readableState.errored = err;
      composed.errored = err;
      if (typeof composed._close === 'function') {
        composed._close(true);
      }
    }
  }

  for (var k = 0; k < normalized.length; k++) {
    (function(s) {
      s.on('error', function(err) {
        safeDestroyComposed(err);
      });
    })(normalized[k]);
  }

  return composed;
}

function _abortErrorFromSignal() {
  var err = new Error('The operation was aborted');
  err.code = 'ABORT_ERR';
  err.name = 'AbortError';
  return err;
}

function _toConsumerBufferChunk(chunk) {
  if (chunk == null) {
    return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return typeof Buffer !== 'undefined' ? Buffer.from(chunk) : new TextEncoder().encode(chunk);
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength);
  }
  return typeof Buffer !== 'undefined' ? Buffer.from(String(chunk)) : new TextEncoder().encode(String(chunk));
}

function _toConsumerBuffer(chunks) {
  if (!chunks || chunks.length === 0) {
    return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
  }
  var normalized = [];
  var totalLen = 0;
  for (var i = 0; i < chunks.length; i++) {
    var byteChunk = _toConsumerBufferChunk(chunks[i]);
    normalized.push(byteChunk);
    totalLen += byteChunk.length;
  }
  if (typeof Buffer !== 'undefined' && Buffer.concat) {
    var asBuffers = [];
    for (var j = 0; j < normalized.length; j++) {
      if (Buffer.isBuffer(normalized[j])) {
        asBuffers.push(normalized[j]);
      } else {
        asBuffers.push(Buffer.from(normalized[j]));
      }
    }
    return Buffer.concat(asBuffers);
  }
  var out = new Uint8Array(totalLen);
  var offset = 0;
  for (var k = 0; k < normalized.length; k++) {
    var part = normalized[k];
    if (!part || part.length === 0) continue;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function _collectChunksFromStream(stream, options) {
  if (!stream) {
    return Promise.reject(new TypeError('Expected a stream'));
  }

  if (stream && typeof stream[Symbol.asyncIterator] === 'function') {
    return new Promise(function(resolve, reject) {
      var iterator = stream[Symbol.asyncIterator]();
      var chunks = [];
      var done = false;

      function doneWith(err, value) {
        if (done) return;
        done = true;
        if (options && options.signal && options.signal.removeEventListener) {
          options.signal.removeEventListener('abort', onAbort);
        }
        if (err) reject(err);
        else resolve(value);
      }

      function onAbort() {
        if (typeof iterator.return === 'function') {
          iterator.return();
        }
        doneWith(_abortErrorFromSignal());
      }

      function readNext() {
        if (options && options.signal && options.signal.aborted) {
          doneWith(_abortErrorFromSignal());
          return;
        }
        iterator.next().then(function(item) {
          if (item.done) {
            doneWith(null, chunks);
            return;
          }
          chunks.push(item.value);
          readNext();
        }).catch(doneWith);
      }

      if (options && options.signal && typeof options.signal.addEventListener === 'function') {
        options.signal.addEventListener('abort', onAbort);
      }
      readNext();
    });
  }

  if (stream && typeof stream.getReader === 'function') {
    return new Promise(function(resolve, reject) {
      var reader = stream.getReader();
      var chunks = [];
      function onAbort() {
        reader.cancel();
        if (options && options.signal && options.signal.removeEventListener) {
          options.signal.removeEventListener('abort', onAbort);
        }
        reject(_abortErrorFromSignal());
      }
      function pump() {
        reader.read().then(function(result) {
          if (result.done) {
            if (options && options.signal && options.signal.removeEventListener) {
              options.signal.removeEventListener('abort', onAbort);
            }
            if (typeof reader.releaseLock === 'function') {
              reader.releaseLock();
            }
            resolve(chunks);
            return;
          }
          chunks.push(result.value);
          pump();
        }).catch(function(err) {
          if (typeof reader.releaseLock === 'function') {
            reader.releaseLock();
          }
          if (options && options.signal && options.signal.removeEventListener) {
            options.signal.removeEventListener('abort', onAbort);
          }
          reject(err);
        });
      }
      if (options && options.signal && options.signal.aborted) {
        onAbort();
        return;
      }
      if (options && options.signal && typeof options.signal.addEventListener === 'function') {
        options.signal.addEventListener('abort', onAbort);
      }
      pump();
    });
  }

  if (typeof stream.on === 'function') {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var done = false;
      var onData = function(chunk) {
        chunks.push(chunk);
      };
      var detach = function() {
        stream.removeListener('data', onData);
        stream.removeListener('end', onEnd);
        stream.removeListener('close', onEnd);
        stream.removeListener('error', onError);
      };
      function onEnd() {
        if (done) return;
        done = true;
        if (options && options.signal && options.signal.removeEventListener) {
          options.signal.removeEventListener('abort', onAbort);
        }
        detach();
        resolve(chunks);
      }
      function onError(err) {
        if (done) return;
        done = true;
        if (options && options.signal && options.signal.removeEventListener) {
          options.signal.removeEventListener('abort', onAbort);
        }
        detach();
        reject(err);
      }
      var onAbort = function() {
        if (done) return;
        done = true;
        if (typeof stream.destroy === 'function') {
          stream.destroy(_abortErrorFromSignal());
        }
        if (options && options.signal && options.signal.removeEventListener) {
          options.signal.removeEventListener('abort', onAbort);
        }
        detach();
        reject(_abortErrorFromSignal());
      };
      stream.on('data', onData);
      stream.on('end', onEnd);
      stream.on('close', onEnd);
      stream.on('error', onError);
      if (options && options.signal && typeof options.signal.addEventListener === 'function') {
        options.signal.addEventListener('abort', onAbort);
      }
      if (typeof stream.resume === 'function' && stream.readableFlowing !== false) {
        stream.resume();
      }
      if (options && options.signal && options.signal.aborted) {
        onAbort();
      }
    });
  }

  return Promise.reject(new TypeError('Expected a readable stream'));
}

function _textStreamConsumer(stream, options) {
  return new Promise(function(resolve, reject) {
    _collectChunksFromStream(stream, options).then(function(chunks) {
      var u8 = _toConsumerBuffer(chunks);
      if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(u8)) {
        resolve(u8.toString(options && options.encoding ? options.encoding : 'utf8'));
        return;
      }
      if (typeof TextDecoder !== 'undefined') {
        resolve(new TextDecoder(options && options.encoding ? options.encoding : 'utf8').decode(u8));
        return;
      }
      var bytes = Array.prototype.slice.call(u8);
      resolve(String.fromCharCode.apply(null, bytes));
    }, reject);
  });
}

function _jsonStreamConsumer(stream, options) {
  return new Promise(function(resolve, reject) {
    _textStreamConsumer(stream, options).then(function(text) {
      try {
        resolve(JSON.parse(text));
      } catch (err) {
        reject(err);
      }
    }, reject);
  });
}

function _bufferStreamConsumer(stream, options) {
  return new Promise(function(resolve, reject) {
    _collectChunksFromStream(stream, options).then(function(chunks) {
      resolve(_toConsumerBuffer(chunks));
    }, reject);
  });
}

function _arrayBufferStreamConsumer(stream, options) {
  return new Promise(function(resolve, reject) {
    _collectChunksFromStream(stream, options).then(function(chunks) {
      var buffer = _toConsumerBuffer(chunks);
      if (buffer.buffer) {
        if (buffer.byteOffset === 0 && buffer.byteLength === buffer.buffer.byteLength) {
          resolve(buffer.buffer);
          return;
        }
        if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(buffer)) {
          resolve(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
          return;
        }
      }
      var copy = new Uint8Array(buffer.length || 0);
      copy.set(buffer);
      resolve(copy.buffer);
    }, reject);
  });
}

function _blobStreamConsumer(stream, options) {
  return new Promise(function(resolve, reject) {
    if (typeof Blob === 'undefined') {
      reject(new Error('Blob is not supported'));
      return;
    }
    _collectChunksFromStream(stream, options).then(function(chunks) {
      resolve(new Blob(chunks));
    }, reject);
  });
}

// addAbortSignal utility
function addAbortSignal(signal, stream) {
  if (!signal || typeof signal.addEventListener !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" argument must be of type AbortSignal.');
  }
  if (!stream || typeof stream.destroy !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be an instance of Stream. Received ' + (stream === null ? 'null' : typeof stream));
  }
  signal.addEventListener('abort', function() {
    var err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    stream.destroy(err);
  });
  return stream;
}

// Node.js exports the Stream constructor directly with subclasses as properties
Stream.Stream = Stream;
Stream.Readable = Readable;
Stream.Writable = Writable;
Stream.Duplex = Duplex;
Stream.Transform = Transform;
Stream.PassThrough = PassThrough;
Stream.pipeline = pipeline;
Stream.finished = finished;
Stream.compose = compose;
Stream.addAbortSignal = addAbortSignal;
Stream.getDefaultHighWaterMark = Readable.getDefaultHighWaterMark;
Stream.setDefaultHighWaterMark = Readable.setDefaultHighWaterMark;

// destroy() — standalone function to destroy a stream
Stream.destroy = function destroy(stream, err) {
  if (stream && typeof stream.destroy === 'function') {
    stream.destroy(err);
  }
  return stream;
};

var _webStreamStateCache = new WeakMap();

function _wrapWebStreamReaderState(reader, state) {
  if (reader && typeof reader.read === 'function' && !reader.__exactWebStreamReaderWrapped) {
    var originalRead = reader.read;
    reader.read = function() {
      state.readable.disturbed = true;
      var result = originalRead.apply(this, arguments);
      if (result && typeof result.then === 'function') {
        result.then(function(value) {
          if (value && value.done) {
            state.readable.closed = true;
          }
        }, function() {
          state.readable.closed = true;
          state.readable.errored = true;
        });
      }
      return result;
    };
    reader.__exactWebStreamReaderWrapped = true;
  }
  if (reader && typeof reader.cancel === 'function' && !reader.__exactWebStreamReaderCancelWrapped) {
    var originalCancel = reader.cancel;
    reader.cancel = function(reason) {
      state.readable.closed = true;
      if (reason) state.readable.errored = true;
      return originalCancel.call(this, reason);
    };
    reader.__exactWebStreamReaderCancelWrapped = true;
  }
}

function _wrapWebStreamWriterState(writer, state) {
  if (writer && typeof writer.write === 'function' && !writer.__exactWebStreamWriterWrapped) {
    var originalWrite = writer.write;
    writer.write = function() {
      state.writable.disturbed = true;
      return originalWrite.apply(this, arguments);
    };
    writer.__exactWebStreamWriterWrapped = true;
  }
  if (writer && typeof writer.close === 'function' && !writer.__exactWebStreamWriterCloseWrapped) {
    var originalClose = writer.close;
    writer.close = function() {
      state.writable.closed = true;
      return originalClose.apply(this, arguments);
    };
    writer.__exactWebStreamWriterCloseWrapped = true;
  }
  if (writer && typeof writer.abort === 'function' && !writer.__exactWebStreamWriterAbortWrapped) {
    var originalAbort = writer.abort;
    writer.abort = function(reason) {
      state.writable.closed = true;
      if (reason) state.writable.errored = true;
      return originalAbort.call(this, reason);
    };
    writer.__exactWebStreamWriterAbortWrapped = true;
  }
  if (writer && typeof writer.releaseLock === 'function' && !writer.__exactWebStreamWriterReleaseWrapped) {
    var originalRelease = writer.releaseLock;
    writer.releaseLock = function() {
      var releaseResult = originalRelease.apply(this, arguments);
      if (state.writable.disturbed || state.writable.closed || state.writable.errored) {
        state.writable.disturbed = true;
      }
      return releaseResult;
    };
    writer.__exactWebStreamWriterReleaseWrapped = true;
  }
}

function _patchWebStreamPrototypeInterop() {
  if (typeof globalThis.ReadableStream === 'function' &&
      globalThis.ReadableStream.prototype &&
      typeof globalThis.ReadableStream.prototype.getReader === 'function' &&
      !globalThis.ReadableStream.prototype.__exactWebStreamInteropPatched) {
    var originalGetReader = globalThis.ReadableStream.prototype.getReader;
    globalThis.ReadableStream.prototype.getReader = function() {
      var state = _getWebStreamState(this);
      var reader = originalGetReader.apply(this, arguments);
      if (state && reader) {
        _wrapWebStreamReaderState(reader, state);
      }
      return reader;
    };
    globalThis.ReadableStream.prototype.__exactWebStreamInteropPatched = true;
  }

  if (typeof globalThis.WritableStream === 'function' &&
      globalThis.WritableStream.prototype &&
      typeof globalThis.WritableStream.prototype.getWriter === 'function' &&
      !globalThis.WritableStream.prototype.__exactWebStreamInteropPatched) {
    var originalGetWriter = globalThis.WritableStream.prototype.getWriter;
    globalThis.WritableStream.prototype.getWriter = function() {
      var state = _getWebStreamState(this);
      var writer = originalGetWriter.apply(this, arguments);
      if (state && writer) {
        _wrapWebStreamWriterState(writer, state);
      }
      return writer;
    };
    globalThis.WritableStream.prototype.__exactWebStreamInteropPatched = true;
  }
}

_patchWebStreamPrototypeInterop();

function _installWebStreamReaderTracker(stream, state) {
  if (!stream || typeof stream.getReader !== 'function' || !stream.getReader) return;
  try {
    if (stream.__exactWebStreamReaderPatched) return;
  } catch (_) {
    return;
  }

  var originalGetReader = stream.getReader;
  if (typeof originalGetReader !== 'function' || originalGetReader.__exactStreamInteropPatched) {
    return;
  }

  stream.getReader = function() {
    var reader = originalGetReader.apply(this, arguments);
    _wrapWebStreamReaderState(reader, state);
    return reader;
  };

  originalGetReader.__exactStreamInteropPatched = true;
  stream.__exactWebStreamReaderPatched = true;
}

function _installWebStreamWriterTracker(stream, state) {
  if (!stream || typeof stream.getWriter !== 'function' || !stream.getWriter) return;
  try {
    if (stream.__exactWebStreamWriterPatched) return;
  } catch (_) {
    return;
  }

  var originalGetWriter = stream.getWriter;
  if (typeof originalGetWriter !== 'function' || originalGetWriter.__exactStreamInteropPatched) {
    return;
  }

  stream.getWriter = function() {
    var writer = originalGetWriter.apply(this, arguments);
    _wrapWebStreamWriterState(writer, state);
    return writer;
  };

  originalGetWriter.__exactStreamInteropPatched = true;
  stream.__exactWebStreamWriterPatched = true;
}

function _getWebStreamState(stream) {
  if (!stream) return null;
  if ((typeof stream.getReader !== 'function' && typeof stream.getWriter !== 'function')) {
    return null;
  }

  var state = _webStreamStateCache.get(stream);
  if (!state) {
    state = {
      readable: {
        disturbed: false,
        closed: false,
        errored: false
      },
      writable: {
        disturbed: false,
        closed: false,
        errored: false
      }
    };
    _webStreamStateCache.set(stream, state);

    if (stream.closed && typeof stream.closed.then === 'function') {
      stream.closed.then(
        function() {
          state.readable.closed = true;
          state.writable.closed = true;
        },
        function() {
          state.readable.closed = true;
          state.readable.errored = true;
          state.writable.closed = true;
          state.writable.errored = true;
        }
      );
    }

    _installWebStreamReaderTracker(stream, state);
    _installWebStreamWriterTracker(stream, state);
  }

  return state;
}

// isReadable / isWritable / isDisturbed — stream state inspection
Stream.isReadable = function isReadable(stream) {
  if (!stream) return false;
  if (typeof stream.readable === 'boolean') return stream.readable;
  var webState = _getWebStreamState(stream);
  if (webState) {
    return !webState.readable.closed && !webState.readable.disturbed;
  }
  if (typeof stream._readableState === 'object') {
    return !stream._readableState.destroyed && !stream._readableState.ended;
  }
  return false;
};

Stream.isWritable = function isWritable(stream) {
  if (!stream) return false;
  if (typeof stream.writable === 'boolean') return stream.writable;
  var webState = _getWebStreamState(stream);
  if (webState) {
    return !webState.writable.closed;
  }
  if (typeof stream._writableState === 'object') {
    return !stream._writableState.destroyed && !stream._writableState.ended;
  }
  return false;
};

Stream.isDisturbed = function isDisturbed(stream) {
  if (!stream) return false;
  var webState = _getWebStreamState(stream);
  if (webState) {
    return !!(webState.readable.disturbed || webState.writable.disturbed);
  }
  if (stream._readableState) {
    return stream._readableState.dataEmitted === true ||
           stream._readableState.readableAborted === true ||
           stream.readableDidRead === true ||
           stream._readableState.readableDidRead === true;
  }
  return stream.readableDidRead === true || stream.readableAborted === true || false;
};

Stream.isErrored = function isErrored(stream) {
  if (!stream) return false;
  var webState = _getWebStreamState(stream);
  if (webState) {
    return webState.readable.errored === true || webState.writable.errored === true;
  }
  return stream._readableState ? stream._readableState.errored !== null :
         stream._writableState ? stream._writableState.errored !== null :
         false;
};

Readable.isReadable = Stream.isReadable;
Readable.isWritable = Stream.isWritable;
Readable.isDisturbed = Stream.isDisturbed;
Readable.isErrored = Stream.isErrored;
Writable.isReadable = Stream.isReadable;
Writable.isWritable = Stream.isWritable;
Writable.isDisturbed = Stream.isDisturbed;
Writable.isErrored = Stream.isErrored;
Duplex.isReadable = Stream.isReadable;
Duplex.isWritable = Stream.isWritable;
Duplex.isDisturbed = Stream.isDisturbed;
Duplex.isErrored = Stream.isErrored;
Transform.isReadable = Stream.isReadable;
Transform.isWritable = Stream.isWritable;
Transform.isDisturbed = Stream.isDisturbed;
Transform.isErrored = Stream.isErrored;
PassThrough.isReadable = Stream.isReadable;
PassThrough.isWritable = Stream.isWritable;
PassThrough.isDisturbed = Stream.isDisturbed;
PassThrough.isErrored = Stream.isErrored;

// promises namespace
Stream.promises = {
  pipeline: function() {
    var args = Array.prototype.slice.call(arguments);
    return new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) reject(err);
        else resolve();
      });
      try {
        pipeline.apply(null, args);
      } catch (err) {
        reject(err);
      }
    });
  },
  finished: function(stream, opts) {
    return new Promise(function(resolve, reject) {
      try {
        finished(stream, opts || {}, function(err) {
          if (err) reject(err);
          else resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }
};

Stream.consumers = {
  text: function(stream, options) { return _textStreamConsumer(stream, options); },
  json: function(stream, options) { return _jsonStreamConsumer(stream, options); },
  buffer: function(stream, options) { return _bufferStreamConsumer(stream, options); },
  arrayBuffer: function(stream, options) { return _arrayBufferStreamConsumer(stream, options); },
  blob: function(stream, options) { return _blobStreamConsumer(stream, options); }
};

module.exports = Stream;
