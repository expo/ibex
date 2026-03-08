var EventEmitter = require('node:events').EventEmitter;
var StringDecoder;
var util = require('node:util');
var kPromisifyCustom = util.promisify && util.promisify.custom ? util.promisify.custom : undefined;
try {
  StringDecoder = require('node:string_decoder').StringDecoder;
} catch (e) {
  StringDecoder = null;
}

var defaultHighWaterMark = 65536;
var defaultHighWaterMarkObjectMode = 16;

function _validateHighWaterMarkOption(propertyName, value) {
  if (value === undefined || value === null) return null;
  var numeric = Number(value);
  if (!isFinite(numeric) || isNaN(numeric) || numeric < 0) {
    throw makeError(
      TypeError,
      'ERR_INVALID_ARG_VALUE',
      "The property 'options." + propertyName + "' is invalid. Received " + String(value)
    );
  }
  return Math.floor(numeric);
}
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

function _syncWritableBufferState(stream) {
  if (!stream || !stream._writableState) return;
  var queue = stream._writeQueue || [];
  stream._writableState.bufferedRequest = queue.length > 0 ? queue[0] : null;
  stream._writableState.bufferedRequestCount = queue.length;
}

function _drainPendingEnd(stream) {
  if (!stream || !stream._writableState) return;
  var state = stream._writableState;
  var pending = state._pendingEnd;
  if (typeof pending !== 'function') return;
  if (
    state.writing ||
    state.bufferProcessing ||
    (stream._writeQueue && stream._writeQueue.length)
  ) {
    return;
  }
  state._pendingEnd = null;
  state._pendingEndScheduled = false;
  pending();
}

function _resumeWritableAfterConstruct(stream) {
  if (!stream || !stream._writableState || stream._destroyed) return;
  var state = stream._writableState;
  if (state.constructed === false) return;
  if (stream._writeQueue && stream._writeQueue.length) {
    stream._flushWriteQueue();
    return;
  }
  _drainPendingEnd(stream);
}

function _shouldAutoDestroyOnReadableEnd(stream, readableState) {
  if (!stream || !readableState) return false;
  if (!readableState.autoDestroy || stream._destroyed || stream._closed) return false;
  if (stream._writableState && stream.writable !== false) {
    return false;
  }
  return true;
}

function _scheduleHalfOpenWritableEnd(stream) {
  if (!stream || stream.allowHalfOpen !== false || !stream._writableState) return;
  var writableState = stream._writableState;
  if (writableState.ending || writableState.ended || writableState.finished || stream._destroyed || stream._closed) {
    return;
  }
  _nextTick(function() {
    if (!stream || stream._destroyed || stream._closed || !stream._writableState) return;
    var nextWritableState = stream._writableState;
    if (nextWritableState.ending || nextWritableState.ended || nextWritableState.finished || stream._destroyed || stream._closed) {
      return;
    }
    stream.end();
  });
}

function _createWriteQueueItem(chunk, encoding, callback, chunkLen) {
  return {
    chunk: chunk,
    encoding: encoding || 'utf8',
    callback: _wrapCallbackOnce(callback),
    chunkLen: chunkLen || 0
  };
}

function _wrapCallbackOnce(callback) {
  if (typeof callback !== 'function') return null;
  var called = false;
  return function(err) {
    if (called) return;
    called = true;
    callback(err);
  };
}

function _finishIfError(stream, err) {
  if (!stream || !err) return;
  if (stream._destroyed) return;
  stream.destroy(err);
}

function _createAbortError(err) {
  if (err) {
    if (typeof err === 'object' && err && err.name && err.code) {
      return err;
    }
    if (err instanceof Error) return err;
  }
  var abortErr = new Error('The operation was aborted');
  abortErr.code = 'ABORT_ERR';
  abortErr.name = 'AbortError';
  return abortErr;
}

function _scheduleDrain(stream) {
  if (!stream) return;
  _nextTick(function() { stream.emit('drain'); });
}

function Stream() {
  EventEmitter.call(this);
  if (!this._events || typeof this._events !== 'object') {
    this._events = {};
  }
  this._closed = false;
  _defineStateAlias(this, 'closed', '_closed');
  this._destroyed = false;
  this.destroyed = false;
  this._needsClose = false;
}

function _ensureAwaitDrainWriters(readableState) {
  if (!readableState) return null;
  return readableState.awaitDrainWriters || null;
}

function _normalizeAwaitDrainWriters(readableState) {
  if (!readableState) return null;
  var current = readableState.awaitDrainWriters;
  var pipeCount = readableState.pipesCount || 0;

  if (pipeCount > 1) {
    if (!current) {
      current = new Set();
      readableState.awaitDrainWriters = current;
      return current;
    }
    if (!(current instanceof Set)) {
      current = new Set([current]);
      readableState.awaitDrainWriters = current;
    }
    return current;
  }

  if (current instanceof Set) {
    if (current.size === 0) {
      readableState.awaitDrainWriters = null;
      return null;
    }
    if (current.size === 1) {
      var only = current.values().next().value;
      readableState.awaitDrainWriters = only;
      _attachAwaitDrainSizeAccessor(only, readableState);
      return only;
    }
  }

  return current || null;
}

function _addAwaitDrainWriter(readableState, writer) {
  if (!readableState) return;
  var current = _normalizeAwaitDrainWriters(readableState);
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
  var current = _normalizeAwaitDrainWriters(readableState);
  if (!current) return;
  if (current instanceof Set) {
    current.delete(writer);
    _clearAwaitDrainSizeAccessor(writer, readableState);
    if (current.size === 0) {
      if ((readableState.pipesCount || 0) <= 1) {
        readableState.awaitDrainWriters = null;
      }
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

function _isBinaryReadableChunk(chunk) {
  if (chunk == null) return false;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) return true;
  if (typeof ArrayBuffer !== 'undefined' && chunk instanceof ArrayBuffer) return true;
  return !!(typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(chunk));
}

function _markPromiseHandled(promise) {
  if (promise && typeof promise.catch === 'function') {
    promise.catch(function() {});
  }
  return promise;
}

function _nextTick(fn) {
  if (typeof queueMicrotask === 'function') {
    queueMicrotask(fn);
    return;
  }
  if (
    typeof globalThis === 'object' &&
    globalThis &&
    typeof globalThis.process === 'object' &&
    globalThis.process &&
    typeof globalThis.process.nextTick === 'function'
  ) {
    return globalThis.process.nextTick(fn);
  }
  if (typeof process === 'object' && process && typeof process.nextTick === 'function') {
    return process.nextTick(fn);
  }
  return setTimeout(fn, 0);
}

function _setReadableEncoding(state, enc) {
  if (enc === null || enc === undefined) {
    enc = 'utf8';
  }
  if (enc === false || enc === '') {
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
    state.buffer.length = 0;
    if (content !== '') {
      state.buffer.push(content);
    }
    state.length = state.objectMode ? state.buffer.length : content.length;
    if (state.length === 0) state.ended = state.ended;
  }
}
Stream.prototype = Object.create(EventEmitter.prototype);
Stream.prototype.constructor = Stream;

// Set destroyed on Stream.prototype so that subclasses can check it before calling super constructor
Stream.prototype.destroyed = false;

// Symbol.asyncDispose support - destroys stream and returns promise that resolves on close
var _asyncDisposeSymbol = (typeof Symbol !== 'undefined') ? (Symbol.asyncDispose || Symbol.for('nodejs.asyncDispose')) : null;
if (_asyncDisposeSymbol) {
  Stream.prototype[_asyncDisposeSymbol] = function() {
    var self = this;
    return new Promise(function(resolve) {
      if (self.destroyed) {
        resolve();
        return;
      }
      self.once('close', function() {
        resolve();
      });
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      self.destroy(abortErr);
    });
  };
}

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
  // Respect emitClose: false on writable or readable streams
  if (this._writableState && this._writableState.emitClose === false) {
    return;
  }
  if (this._readableState && this._readableState.emitClose === false) {
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
    this._readableState.endScheduled = false;
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
    this._readableState.emittingData = false;
  }
  if (this._writableState) {
    this._writableState.highWaterMark = this.writableHighWaterMark || this._writableState.highWaterMark;
    this._writableState.objectMode = !!this.writableObjectMode || this._writableState.objectMode;
    this._writableState.length = 0;
    this._writableState.bufferedRequest = null;
    this._writableState.bufferedRequestCount = 0;
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
    this._writableState.finished = false;
    if (this._writeQueue) this._writeQueue.length = 0;
    this._writeQueue = [];
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
      if (self._readableState) self._readableState.errorEmitted = true;
      if (self._writableState) self._writableState.errorEmitted = true;
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
    }
    self._close(true);
    if (typeof callback === 'function') callback(err);
  }
  if (typeof this._destroy === 'function') {
    this._destroy(error || null, function(err) {
      // Set errored state synchronously so tests can check it
      if (err) {
        self.errored = err;
        if (self._readableState) self._readableState.errored = err;
        if (self._writableState) self._writableState.errored = err;
      }
      // Defer error emit/close without slipping behind user nextTick observers.
      _nextTick(function() { emitErrorAndClose(err); });
    });
  } else {
    // Defer error/close when using default destroy path
    _nextTick(function() { emitErrorAndClose(error || null); });
  }
  return this;
};

function Readable(options) {
  if (!(this instanceof Readable)) return new Readable(options);
  Stream.call(this);
  // Pre-initialize event slots to match Node.js key ordering
  this._events.close = undefined;
  this._events.error = undefined;
  this._events.data = undefined;
  this._events.end = undefined;
  this._events.readable = undefined;
  this._data = [];
  this._ended = false;
  var supportsSplitOptions = this instanceof Duplex;
  // Determine objectMode: readableObjectMode overrides objectMode if present on Duplex/Transform
  var objMode = (supportsSplitOptions && options && options.readableObjectMode != null) ? !!options.readableObjectMode :
                !!(options && options.objectMode);
  // Determine highWaterMark: explicit highWaterMark wins, then readableHighWaterMark, then default
  var hwm;
  if (options && options.highWaterMark != null) {
    hwm = _validateHighWaterMarkOption('highWaterMark', options.highWaterMark);
  } else if (supportsSplitOptions && options && options.readableHighWaterMark != null) {
    hwm = _validateHighWaterMarkOption('readableHighWaterMark', options.readableHighWaterMark);
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
    emitClose: (options && options.emitClose !== undefined) ? options.emitClose !== false : true,
    emittedClose: false,
    autoDestroy: (options && options.autoDestroy !== undefined) ? options.autoDestroy !== false : true,
    defaultEncoding: 'utf8',
    encoding: (options && options.encoding) || null,
    decoder: null,
    readable: true,
    readableDidRead: false,
    dataEmitted: false,
    endEmitted: false,
    endScheduled: false,
    endConsumed: false,
    buffer: this._data,
    needDrain: false,
    pendingcb: 0,
    awaitDrainWriters: null,
    emittingData: false,
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
  if (options && typeof options._read === 'function') this._read = options._read;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  if (options && typeof options._destroy === 'function') this._destroy = options._destroy;
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
  if (options && options.signal != null) {
    addAbortSignal(options.signal, this);
  }
}
Readable.prototype = Object.create(Stream.prototype);
Readable.prototype.constructor = Readable;

// Define readable state getters on prototype so Object.hasOwn(Readable.prototype, ...) works
Object.defineProperties(Readable.prototype, {
  readableEnded: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? !!this._readableState.endEmitted : false;
    },
    set: function(val) {
      if (this._readableState) this._readableState.endEmitted = !!val;
    }
  },
  readableFlowing: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? this._readableState.flowing : null;
    },
    set: function(val) {
      if (this._readableState) this._readableState.flowing = val;
    }
  },
  readableHighWaterMark: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? this._readableState.highWaterMark : 16384;
    },
    set: function(val) {
      if (this._readableState) this._readableState.highWaterMark = val;
    }
  },
  readableLength: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? this._readableState.length : 0;
    },
    set: function(val) {
      if (this._readableState) this._readableState.length = val;
    }
  },
  readableObjectMode: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? !!this._readableState.objectMode : false;
    },
    set: function(val) {
      if (this._readableState) this._readableState.objectMode = !!val;
    }
  },
  readableEncoding: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? (this._readableState.encoding || null) : null;
    },
    set: function(val) {
      if (this._readableState) this._readableState.encoding = val;
    }
  },
  readableDidRead: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._readableState ? !!this._readableState.readableDidRead : false;
    },
    set: function(val) {
      if (this._readableState) this._readableState.readableDidRead = !!val;
    }
  },
  readableAborted: {
    configurable: true,
    enumerable: true,
    get: function() {
      return !!(this._readableState && this._readableState.destroyed &&
                !this._readableState.endEmitted);
    },
    set: function(val) {
      // computed, no-op
    }
  }
});

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
  if (isNaN(value)) return NaN;
  return Math.floor(value);
}

function _howMuchToRead(n, state) {
  if (n <= 0 || (state.length === 0 && state.ended)) return 0;
  if (state.objectMode) return 1;
  if (isNaN(n)) {
    if (state.flowing === true && state.length > 0) {
      return readableStateChunkLength(state.buffer[0], false);
    }
    return state.length;
  }
  if (n <= state.length) return n;
  return state.ended ? state.length : 0;
}

function _maybeReadMore(stream, state) {
  if (!state ||
      state.readingMore ||
      state.reading ||
      state.ended ||
      state.errored ||
      state.constructed === false) {
    return;
  }
  state.readingMore = true;
  _nextTick(function() {
    while (!state.reading &&
           !state.ended &&
           !state.errored &&
           (state.length < state.highWaterMark ||
            (stream.readableFlowing === true && state.length === 0))) {
      var length = state.length;
      stream.read(0);
      if (state.length === length) {
        break;
      }
    }
    state.readingMore = false;
  });
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

function _scheduleReadableEnd(stream, state) {
  if (!state || state.endEmitted || state.endScheduled) {
    return;
  }
  state.endScheduled = true;
  _nextTick(function() {
    var readableState = stream && stream._readableState;
    if (!readableState) {
      return;
    }
    if (readableState.endEmitted ||
        !readableState.ended ||
        readableState.length !== 0 ||
        readableState.destroyed ||
        readableState.errored) {
      readableState.endScheduled = false;
      return;
    }
    readableState.endScheduled = false;
    readableState.endEmitted = true;
    stream.readable = false;
    stream.readableEnded = true;
    stream._syncReadableState();
    stream.emit('end');
    _scheduleHalfOpenWritableEnd(stream);
    if (_shouldAutoDestroyOnReadableEnd(stream, readableState)) {
      stream.destroy();
    } else {
      stream._close();
    }
  });
}

function _markReadableDidRead(stream, state) {
  stream.readableDidRead = true;
  if (state) {
    state.readableDidRead = true;
  }
}

function _emitReadableData(stream, state, chunk) {
  _markReadableDidRead(stream, state);
  if (state) {
    state.dataEmitted = true;
    state.emittingData = true;
  }
  try {
    stream.emit('data', chunk);
  } finally {
    if (state) {
      state.emittingData = false;
    }
  }
}

function _releaseTransformBackpressure(stream, state) {
  var transformState = stream && stream._transformState;
  var readableState = state || (stream && stream._readableState);
  if (!transformState ||
      typeof transformState.backpressureCallback !== 'function' ||
      !readableState) {
    return;
  }
  if (readableState.length >= readableState.highWaterMark &&
      readableState.length !== 0) {
    return;
  }
  var callback = transformState.backpressureCallback;
  transformState.backpressureCallback = null;
  _nextTick(callback);
}

function _emitReadableNow(stream, state, force) {
  if (!state || (state.emittedReadable && !force)) {
    return;
  }
  state.emittedReadable = true;
  state.needReadable = false;
  if (!state.destroyed &&
      !state.errored &&
      (state.length > 0 || state.ended)) {
    stream.emit('readable');
  }
  state.emittedReadable = false;
  if (stream.readableFlowing !== true &&
      !state.ended &&
      state.length <= state.highWaterMark) {
    state.needReadable = true;
  }
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
};

Readable.prototype._emitReadableIfNeeded = function() {
  var state = this._readableState;
  if (!state.needReadable ||
      state.emittedReadable ||
      state.readableFlowing ||
      this.readableFlowing === true ||
      (state.length === 0 && !state.ended)) {
    return;
  }
  state.emittedReadable = true;
  state.needReadable = false;
  var self = this;
  _nextTick(function() {
    var readableState = self && self._readableState;
    if (self._destroyed || self._closed || !readableState) {
      return;
    }
    if (!readableState.destroyed &&
        !readableState.errored &&
        (readableState.length > 0 || readableState.ended)) {
      self.emit('readable');
    }
    readableState.emittedReadable = false;
    if (self.readableFlowing !== true &&
        !readableState.ended &&
        readableState.length <= readableState.highWaterMark) {
      readableState.needReadable = true;
    }
  });
};

Readable.prototype._readFromSource = function(size) {
  var state = this._readableState;
  if (this.readableFlowing === true ||
      this._destroyed ||
      !state ||
      state.reading ||
      typeof this._read !== 'function') {
    return;
  }
  state.reading = true;
  state.sync = true;
  try {
    var hwm = state && state.highWaterMark;
    if (size == null) size = hwm;
    this._read(size);
  } catch (err) {
    if (!state.errored) {
      state.errored = err;
      _destroyStreamWithError(this, err);
    }
  } finally {
    state.sync = false;
  }
};

Readable.prototype.push = function(chunk, encoding) {
  if (this._destroyed) return false;
  var state = this._readableState;
  var self = this;
  if (chunk === null && (state.ended || state.endEmitted || state.endScheduled)) {
    return false;
  }
  if (state.ended || state.endEmitted || (state.errored || state.destroyed)) {
    if (!state.errorEmitted && !state.errored) {
      var pushErr = makeError(Error, 'ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF');
      state.errored = pushErr;
      this.errored = pushErr;
      if (typeof this.listenerCount === 'function' ? this.listenerCount('error') > 0 : this._events && this._events.error) {
        state.errorEmitted = true;
        this.emit('error', pushErr);
      }
    }
    return false;
  }
  if (chunk === null) {
    if (state.ended || state.endEmitted) return false;
    var hadReadableEventPending = state.emittedReadable;
    var wasReading = state.reading;
    state.reading = false;
    var endedChunk = '';
    if (state.encoding && state.decoder && !state.objectMode) {
      try {
        endedChunk = state.decoder.end();
      } catch (err) {
        endedChunk = '';
      }
    }
    if (typeof endedChunk === 'string' && endedChunk.length > 0) {
      var endedLength = endedChunk.length;
      this._data.push(endedChunk);
      this._updateReadableLength(endedLength);
      if (this.readableFlowing === true) {
        var wasFlowingOnEnd = true;
        if (this._readableState) {
          this._readableState.dataEmitted = true;
        }
        while (this._data.length > 0 && this.readableFlowing === true) {
          var endingFlowChunk = this._data.shift();
          this._updateReadableLength(-readableStateChunkLength(endingFlowChunk, this._readableState.objectMode));
          _emitReadableData(this, this._readableState, endingFlowChunk);
          this._syncReadableState();
        }
        if (wasFlowingOnEnd && !state.endEmitted && state.length === 0) {
          _nextTick(function() {
            if (self._destroyed || self._closed || state.endEmitted) return;
            self.read();
          });
        }
      }
    }
    this._ended = true;
    state.ended = true;
    if (!hadReadableEventPending) {
      state.needReadable = true;
      state.emittedReadable = false;
    }
    if (wasReading &&
        state.readingMore &&
        state.readableListening &&
        this.readableFlowing !== true) {
      _emitReadableNow(this, state, true);
    }
    if (this.readableFlowing === true && state.length === 0 && !state.endEmitted) {
      _nextTick(function() {
        if (self._destroyed || self._closed || state.endEmitted) return;
        self.read();
      });
    }
    this._syncReadableState();
    // If flowing mode and buffer is empty, directly schedule 'end' event
    var isFlowing = state.readableFlowing || this.readableFlowing === true;
    if (isFlowing && this._data.length === 0 && !state.endEmitted) {
      var self = this;
      _nextTick(function() {
        if (!state.endEmitted && !state.destroyed && !state.errored) {
          state.endEmitted = true;
          self.readable = false;
          self.readableEnded = true;
          self.emit('end');
          _scheduleHalfOpenWritableEnd(self);
          if (_shouldAutoDestroyOnReadableEnd(self, state)) {
            self.destroy();
          } else {
            self._close();
          }
        }
      });
    } else if (!hadReadableEventPending && state.sync) {
      _nextTick(function() {
        self._emitReadableIfNeeded();
      });
    } else if (!hadReadableEventPending) {
      if (state.readableListening && this.readableFlowing !== true) {
        _emitReadableNow(this, state);
      } else {
        this._emitReadableIfNeeded();
      }
    }
    _maybeReadMore(this, state);
    return false;
  }
  // Convert strings to Buffers in non-objectMode (Node.js behavior)
  if (!state.objectMode && typeof chunk === 'string' && typeof Buffer !== 'undefined' && Buffer.from) {
    chunk = Buffer.from(chunk, encoding || state.defaultEncoding || 'utf8');
    encoding = '';
  }
  if (state.encoding && state.decoder && _isBinaryReadableChunk(chunk)) {
    chunk = _decodeChunk(state, chunk);
  }
  var chunkLength = readableStateChunkLength(chunk, state.objectMode);
  if (_isZeroLengthChunk(chunk, this._readableState.objectMode)) {
    state.reading = false;
    _maybeReadMore(this, state);
    return this._readableState.length < this._readableState.highWaterMark ||
      this._readableState.length === 0;
  }
  state.reading = false;

  if (this.readableFlowing === true) {
    this._data.push(chunk);
    this._updateReadableLength(chunkLength);
    this._syncReadableState();
    this._readableState.needReadable = false;
    this._readableState.emittedReadable = false;
    if (this._readableState.reading) {
      return state.length < state.highWaterMark || state.length === 0;
    }
    if (this._readableState.resumeScheduled) {
      _maybeReadMore(this, state);
      return state.length < state.highWaterMark || state.length === 0;
    }
    if (this._readableState.emittingData) {
      _maybeReadMore(this, state);
      return state.length < state.highWaterMark || state.length === 0;
    }
    if (this.readableFlowing !== true) {
      return state.length < state.highWaterMark || state.length === 0;
    }
    var flowingChunk = this._data.shift();
    this._updateReadableLength(-readableStateChunkLength(flowingChunk, this._readableState.objectMode));
    this._syncReadableState();
    if (this.readableFlowing !== true) {
      this._data.unshift(flowingChunk);
      this._updateReadableLength(readableStateChunkLength(flowingChunk, this._readableState.objectMode));
      this._syncReadableState();
      return state.length < state.highWaterMark || state.length === 0;
    }
    _maybeReadMore(this, state);
    _emitReadableData(this, this._readableState, flowingChunk);
    while (this.readableFlowing === true && this._readableState && this._readableState.length > 0) {
      var reentrantChunk = this.read();
      if (reentrantChunk === null || reentrantChunk === undefined) {
        break;
      }
    }
    return state.length < state.highWaterMark || state.length === 0;
  }

  this._data.push(chunk);
  this._updateReadableLength(chunkLength);
  var hadReadableEventPending = this._readableState.emittedReadable;
  this._syncReadableState();
  if (!hadReadableEventPending) {
    this._readableState.needReadable = true;
    this._readableState.emittedReadable = false;
  }
  if (!hadReadableEventPending) {
    this._emitReadableIfNeeded();
  }
  _maybeReadMore(this, state);
  return state.length < state.highWaterMark || state.length === 0;
};

Readable.prototype.read = function(size) {
  if (this._destroyed) return null;
  var state = this._readableState;
  var n = _coerceReadSize(size);
  var nOrig = n;

  if (!isNaN(n) && n > state.highWaterMark) {
    state.highWaterMark = _nextPowerOf2(n);
  }

  if (n !== 0) {
    state.emittedReadable = false;
  }

  if (n === 0 &&
      state.needReadable &&
      ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) ||
       state.ended)) {
    if (state.length === 0 && state.ended && !state.endEmitted) {
      if (this.readableFlowing === true) {
        this.pause();
      }
      _scheduleReadableEnd(this, state);
    } else if (state.length > 0 && !this._ended) {
      state.needReadable = true;
      state.emittedReadable = false;
      this._emitReadableIfNeeded();
    }
    return null;
  }

  n = _howMuchToRead(n, state);
  if (n === 0 && state.ended) {
    state.needReadable = false;
    if (state.length === 0 && !state.endEmitted) {
      if (this.readableFlowing === true) {
        this.pause();
      }
      _scheduleReadableEnd(this, state);
    }
    return null;
  }

  var shouldRead = state.needReadable ||
    state.length === 0 ||
    state.length - n < state.highWaterMark;
    if (shouldRead &&
        !state.reading &&
        !state.ended &&
        !state.errored &&
        !state.destroyed &&
        state.constructed !== false) {
      state.reading = true;
      state.sync = true;
      if (state.length === 0) {
        state.needReadable = true;
      }
      try {
        this._read(state.highWaterMark);
      } catch (err) {
        if (!state.errored) {
          state.errored = err;
          _destroyStreamWithError(this, err);
        }
      } finally {
        state.sync = false;
      }
    if (!state.reading) {
      n = _howMuchToRead(nOrig, state);
    }
  }

  if (state.length === 0 && state.ended && !state.endEmitted) {
    if (this.readableFlowing === true) {
      this.pause();
    }
    _scheduleReadableEnd(this, state);
    return null;
  }

  if (state.length === 0 && !this.readableFlowing) {
    state.needReadable = true;
    if (state.constructed !== false && !state.reading && !this._destroyed) {
      _nextTick(function() {
        this._readFromSource(state.highWaterMark);
      }.bind(this));
    }
    return null;
  }

  if (n === 0 && nOrig !== 0) {
    state.needReadable = !state.ended;
    state.emittedReadable = false;
    return null;
  }

  // read(0) should trigger a pull/readable check without consuming a chunk.
  if (nOrig === 0) {
    return null;
  }

  var chunk;
  var readAmount = n;
  while (true) {
    chunk = _consumeReadableChunk(this, readAmount);
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
    if (state.ended && state.length === 0 && !state.endEmitted && !state.readableEnded) {
      if (this.readableFlowing === true) {
        this.pause();
      }
      _scheduleReadableEnd(this, state);
    }
    return null;
  }

  this._syncReadableState();
  this._readableState.needReadable = (!state.ended && state.length === 0);
  _markReadableDidRead(this, state);
  _releaseTransformBackpressure(this, state);
  var hasDataListener = typeof this.listenerCount === 'function'
    ? this.listenerCount('data') > 0
    : !!(this._events && this._events.data !== undefined);
  if (this.readableFlowing === true || hasDataListener) {
    _emitReadableData(this, state, chunk);
  }
  if (state.ended && state.length === 0 && !state.endEmitted) {
    var self = this;
    var hasReadableListener = state.readableListening ||
      !!(this._events && this._events.readable !== undefined);
    _nextTick(function() {
      if (self._destroyed || self.destroyed || self._closed || !self._readableState || self._readableState.endEmitted) return;
      if (!self._readableState.ended || self._readableState.length !== 0) return;
      if (hasReadableListener &&
          self.readableFlowing !== true &&
          self._readableState.readingMore) {
        self._readableState.needReadable = true;
        self._readableState.emittedReadable = false;
        if (self._readableState.readingMore) {
          _emitReadableNow(self, self._readableState);
          self._readableState.needReadable = true;
          self._readableState.emittedReadable = false;
        }
        self._emitReadableIfNeeded();
        return;
      }
      self.read(0);
    });
  }
  if (state.length === 0) {
    _maybeReadMore(this, state);
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
  var hadReadableEventPending = this._readableState.emittedReadable;
  this._syncReadableState();
  if (!hadReadableEventPending) {
    this._readableState.needReadable = true;
    this._readableState.emittedReadable = false;
  }
  if (!hadReadableEventPending) {
    this._emitReadableIfNeeded();
  }
  _maybeReadMore(this, this._readableState);
};

Readable.prototype.setEncoding = function(enc) {
  _setReadableEncoding(this._readableState, enc);
  this.readableEncoding = this._readableState.encoding;
  return this;
};

Readable.prototype.resume = function() {
  if (this.readableFlowing !== true) {
    var shouldEmitResume = this.readableFlowing === false;
    this.readableFlowing = true;
    this._readableState.reading = false;
    this._readableState.resumeScheduled = true;
    // Flush buffered data asynchronously
    var self = this;
    var schedule = _nextTick;

    var resumeEmitted = false;
    function flowReadable() {
      if (!resumeEmitted) {
        resumeEmitted = true;
        self._readableState.resumeScheduled = false;
        if (shouldEmitResume) {
          self.emit('resume');
        }
      }
      if (self._destroyed || self.readableFlowing !== true) return;
      self.read(0);
      var readsThisTick = 0;
      while (self.readableFlowing === true && readsThisTick < 64) {
        var chunk = self.read();
        if (chunk === null || chunk === undefined) {
          return;
        }
        readsThisTick += 1;
      }
      if (self.readableFlowing === true) {
        schedule(flowReadable);
      }
    }

    schedule(flowReadable, 0);
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
  if (event === 'readable' && arguments.length === 1) {
    var state = this._readableState;
    this.readableFlowing = false;
    if (state) {
      state.readableListening = true;
      state.needReadable = true;
      state.emittedReadable = false;
      if (state.length > 0) {
        this._emitReadableIfNeeded();
      } else if (!state.reading) {
        var self = this;
        _nextTick(function() { self.read(0); });
      }
    }
    return this;
  }
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
      _nextTick(function() { self.read(0); });
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

// iterator() method (Node.js API)
Readable.prototype.iterator = function(options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options + ' (' + options + ')');
  }
  return this[Symbol.asyncIterator](options);
};

// Symbol.asyncIterator support for Readable streams
Readable.prototype[Symbol.asyncIterator] = function(options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options + ' (' + options + ')');
  }

  var stream = this;
  var finishedState;
  var cleanedUp = false;
  var finalized = false;
  var pending = [];
  var buffered = [];
  var flushScheduled = false;
  var legacyMode = typeof stream.read !== 'function';
  var useDataEvents =
    legacyMode ||
    (typeof stream.listenerCount === 'function' && stream.listenerCount('data') > 0);

  function finalize(err) {
    if (finalized) return;
    finalized = true;
    if (typeof stream.destroy === 'function' && !stream._destroyed) {
      stream.destroy(err);
      return;
    }
    if (!err && typeof stream.close === 'function' && !stream._closed) {
      stream.close();
    }
  }

  function syncFinishedState() {
    if (finishedState !== undefined) {
      return;
    }
    var state = stream && stream._readableState;
    if (state && state.errored) {
      finishedState = state.errored;
      return;
    }
    if (stream && stream.errored) {
      finishedState = stream.errored;
      return;
    }
    if (state && state.endEmitted) {
      finishedState = null;
      return;
    }
    if (stream && stream._closed) {
      finishedState = makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
    }
  }

  function resolveNext(chunk) {
    if (pending.length === 0) {
      buffered.push(chunk);
      return;
    }
    pending.shift().resolve({ value: chunk, done: false });
  }

  function flushPending() {
    flushScheduled = false;
    syncFinishedState();
    while (pending.length > 0) {
      if (buffered.length > 0) {
        pending.shift().resolve({ value: buffered.shift(), done: false });
        continue;
      }
      if (!useDataEvents) {
        var chunk = (stream._destroyed || stream.destroyed) ? null : stream.read();
        if (chunk !== null && chunk !== undefined) {
          pending.shift().resolve({ value: chunk, done: false });
          continue;
        }
      }
      if (finishedState !== undefined) {
        cleanup();
        if (finishedState) {
          var err = finishedState;
          finishedState = null;
          finalize(err);
          pending.shift().reject(err);
          continue;
        }
        pending.shift().resolve({ value: undefined, done: true });
        continue;
      }
      break;
    }
  }

  function scheduleFlush() {
    if (flushScheduled) return;
    flushScheduled = true;
    _nextTick(function() {
      flushPending();
    });
  }

  function onReadable() {
    flushPending();
  }

  function onData(chunk) {
    buffered.push(chunk);
    if (legacyMode) {
      scheduleFlush();
      return;
    }
    flushPending();
  }

  function onEnd() {
    finishedState = null;
    flushPending();
  }

  function onError(err) {
    if (legacyMode) {
      buffered.length = 0;
    }
    finishedState = err || new Error('Stream error');
    flushPending();
  }

  function onClose() {
    if (finishedState !== undefined) {
      flushPending();
      return;
    }
    var state = stream && stream._readableState;
    if (state && state.endEmitted) {
      finishedState = null;
    } else {
      finishedState = makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
    }
    flushPending();
  }

  function ensureFlowing() {
    if (legacyMode || !useDataEvents) {
      return;
    }
    if (typeof stream.resume === 'function' && stream.readableFlowing !== true) {
      stream.resume();
    }
  }

  function cleanup() {
    if (cleanedUp) return;
    cleanedUp = true;
    if (typeof stream.off === 'function') {
      stream.off('data', onData);
      stream.off('readable', onReadable);
      stream.off('end', onEnd);
      stream.off('error', onError);
      stream.off('close', onClose);
    } else if (typeof stream.removeListener === 'function') {
      stream.removeListener('data', onData);
      stream.removeListener('readable', onReadable);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
    }
  }

  if (useDataEvents) {
    stream.on('data', onData);
  }
  if (!useDataEvents) {
    stream.on('readable', onReadable);
  }
  stream.on('end', onEnd);
  stream.on('error', onError);
  stream.on('close', onClose);

  if (
    typeof stream.pause === 'function' &&
    typeof stream.listenerCount === 'function' &&
    stream.listenerCount('data') === 0
  ) {
    stream.pause();
  }

  return {
    stream: stream,
    next: function() {
      return new Promise(function(resolve, reject) {
        ensureFlowing();
        pending.push({ resolve: resolve, reject: reject });
        flushPending();
      });
    },
    return: function() {
      var state = stream && stream._readableState;
      var ended =
        finishedState === null ||
        !!(state && (state.endEmitted || state.ended)) ||
        !!(stream && stream.readableEnded);
      cleanup();
      finishedState = null;
      while (pending.length > 0) {
        pending.shift().resolve({ value: undefined, done: true });
      }
      if (!options || options.destroyOnReturn !== false) {
        if (!ended && !(stream && stream._closed)) {
          finalize(null);
        }
      }
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      cleanup();
      finishedState = err || new Error('Stream iterator error');
      while (pending.length > 0) {
        pending.shift().reject(finishedState);
      }
      finalize(finishedState);
      return Promise.reject(finishedState);
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
};

// Helper to create Node.js-style coded errors
function makeError(Constructor, code, message) {
  var err = new Constructor(message);
  err.code = code;
  err.toString = function() {
    return this.name + ' [' + this.code + ']: ' + this.message;
  };
  return err;
}

var _streamOperatorEmpty = {};
var _streamOperatorEof = {};

function _isAbortSignalLike(signal) {
  return !!(signal &&
    typeof signal === 'object' &&
    typeof signal.addEventListener === 'function' &&
    typeof signal.aborted === 'boolean');
}

function _normalizeReadableOperatorOptions(options, config) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received type ' + typeof options);
  }

  var normalized = {
    signal: options && options.signal !== undefined ? options.signal : null
  };

  if (normalized.signal !== null && !_isAbortSignalLike(normalized.signal)) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof normalized.signal);
  }

  if (config && config.concurrency) {
    var concurrency = 1;
    if (options && options.concurrency != null) {
      concurrency = Math.floor(options.concurrency);
    }
    if (typeof concurrency !== 'number' || !isFinite(concurrency) || concurrency < 1) {
      throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.concurrency" is out of range.');
    }
    normalized.concurrency = concurrency;
  }

  if (config && config.highWaterMark) {
    var highWaterMark = normalized.concurrency ? normalized.concurrency - 1 : 0;
    if (options && options.highWaterMark != null) {
      highWaterMark = Math.floor(options.highWaterMark);
    }
    if (typeof highWaterMark !== 'number' || !isFinite(highWaterMark) || highWaterMark < 0) {
      throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "options.highWaterMark" is out of range.');
    }
    normalized.highWaterMark = highWaterMark;
    normalized.bufferHighWaterMark = highWaterMark + (normalized.concurrency || 0);
  }

  return normalized;
}

function _abortControllerWithReason(controller, reason) {
  if (!controller || typeof controller.abort !== 'function') return;
  try {
    controller.abort(reason);
  } catch (_err) {
    controller.abort();
  }
}

function _combineAbortSignals(primary, secondary) {
  var signals = [];
  if (_isAbortSignalLike(primary)) signals.push(primary);
  if (_isAbortSignalLike(secondary)) signals.push(secondary);
  if (signals.length === 0) return null;
  if (signals.length === 1) return signals[0];
  if (typeof AbortSignal !== 'undefined' && AbortSignal && typeof AbortSignal.any === 'function') {
    return AbortSignal.any(signals);
  }

  var controller = new AbortController();
  function forwardAbort(signal) {
    if (signal.aborted) {
      _abortControllerWithReason(controller, signal.reason);
      return;
    }
    signal.addEventListener('abort', function() {
      _abortControllerWithReason(controller, signal.reason);
    }, { once: true });
  }
  for (var i = 0; i < signals.length; i++) {
    forwardAbort(signals[i]);
  }
  return controller.signal;
}

function _toIntegerOrInfinity(number) {
  number = Number(number);
  if (isNaN(number)) return 0;
  if (number < 0) {
    throw makeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "number" is out of range. It must be >= 0. Received ' + number);
  }
  if (!isFinite(number)) return number;
  return Math.floor(number);
}

function _attachReadableAbortSignal(result, signal) {
  if (!_isAbortSignalLike(signal)) return;
  if (signal.aborted) {
    var abortErr = _createAbortError(signal.reason);
    setTimeout(function() {
      if (!result._destroyed) {
        result.destroy(abortErr);
      }
    }, 0);
    return;
  }
  signal.addEventListener('abort', function() {
    if (!result._destroyed) {
      result.destroy(_createAbortError(signal.reason));
    }
  }, { once: true });
}

function _createReadableOperatorStream(iterable, options) {
  var result = Readable.from(iterable, { objectMode: true });
  result.readable = true;
  return result;
}

async function _consumeAsyncIterable(iterable, onValue) {
  if (!iterable || typeof iterable[Symbol.asyncIterator] !== 'function') {
    return;
  }
  var iterator = iterable[Symbol.asyncIterator]();
  var completed = false;
  try {
    while (true) {
      var next = await iterator.next();
      if (!next || next.done) {
        completed = true;
        return;
      }
      await onValue(next.value);
    }
  } finally {
    if (!completed) {
      _safelyReturnAsyncIterator(iterator);
    }
  }
}

function _createReadableMapIterable(source, fn, options) {
  var controller = new AbortController();
  var signal = _combineAbortSignals(options && options.signal, controller.signal);
  var signalOpt = { signal: signal };
  var queue = [];
  var notifyConsumer = null;
  var resumePump = null;
  var done = false;
  var completed = false;
  var cleanedUp = false;
  var terminalError = null;
  var inFlight = 0;
  var sourceCompleted = false;
  var sourceIter = source && typeof source[Symbol.asyncIterator] === 'function'
    ? source[Symbol.asyncIterator]()
    : null;

  function wakeConsumer() {
    if (!notifyConsumer) return;
    var resolve = notifyConsumer;
    notifyConsumer = null;
    resolve();
  }

  function cleanupSourceIterator() {
    if (!sourceIter || sourceCompleted) return;
    sourceCompleted = true;
    _safelyReturnAsyncIterator(sourceIter);
  }

  function maybeResumePump() {
    if (
      resumePump &&
      !done &&
      inFlight < options.concurrency &&
      queue.length < options.bufferHighWaterMark
    ) {
      var resolve = resumePump;
      resumePump = null;
      resolve();
    }
  }

  function onMapperSettled() {
    if (inFlight > 0) {
      inFlight -= 1;
    }
    maybeResumePump();
  }

  function finalize() {
    if (cleanedUp) return;
    cleanedUp = true;
    done = true;
    cleanupSourceIterator();
    if (resumePump) {
      var resume = resumePump;
      resumePump = null;
      resume();
    }
    _abortControllerWithReason(controller, signal && signal.reason);
    if (!completed && source && typeof source.destroy === 'function' && !source._destroyed) {
      if (terminalError) {
        source.destroy(terminalError);
      } else {
        source.destroy();
      }
    }
  }

  (async function() {
    try {
      if (signal && signal.aborted) {
        throw _createAbortError(signal.reason);
      }

      if (!sourceIter) {
        queue.push(_streamOperatorEof);
        wakeConsumer();
        return;
      }

      while (!done) {
        var next = await sourceIter.next();
        if (!next || next.done) {
          sourceCompleted = true;
          queue.push(_streamOperatorEof);
          wakeConsumer();
          return;
        }

        if (done) {
          return;
        }

        if (signal && signal.aborted) {
          throw _createAbortError(signal.reason);
        }

        var mapped;
        try {
          mapped = fn(next.value, signalOpt);
          if (mapped === _streamOperatorEmpty) {
            continue;
          }
          mapped = Promise.resolve(mapped);
        } catch (err) {
          mapped = Promise.reject(err);
        }

        inFlight += 1;
        mapped.then(onMapperSettled, function() {
          done = true;
          onMapperSettled();
        });

        queue.push(mapped);
        wakeConsumer();

        if (!done && (queue.length >= options.bufferHighWaterMark || inFlight >= options.concurrency)) {
          await new Promise(function(resolve) {
            resumePump = resolve;
          });
        }
      }
    } catch (err) {
      var rejected = Promise.reject(err);
      rejected.then(function() {}, function() {});
      queue.push(rejected);
      wakeConsumer();
    } finally {
      cleanupSourceIterator();
      done = true;
      wakeConsumer();
    }
  })();

  return {
    next: function() {
      return (async function() {
        while (true) {
          while (queue.length > 0) {
            var mappedValue;
          try {
            mappedValue = await queue[0];
          } catch (err) {
            terminalError = err;
            finalize();
            throw err;
          }

          queue.shift();
          maybeResumePump();

            if (mappedValue === _streamOperatorEof) {
              completed = true;
              finalize();
              return { value: undefined, done: true };
            }

            if (signal && signal.aborted) {
              terminalError = _createAbortError(signal.reason);
              finalize();
              throw terminalError;
            }

            if (mappedValue === _streamOperatorEmpty) {
              continue;
            }

            return { value: mappedValue, done: false };
          }

          if (done) {
            completed = true;
            finalize();
            if (terminalError) {
              throw terminalError;
            }
            return { value: undefined, done: true };
          }

          await new Promise(function(resolve) {
            notifyConsumer = resolve;
          });
        }
      })();
    },
    return: function() {
      completed = true;
      finalize();
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      terminalError = err || new Error('Stream iterator error');
      finalize();
      return Promise.reject(terminalError);
    },
    [Symbol.asyncIterator]: function() {
      return this;
    }
  };
}

// --- Stream Helper Methods (Node.js 17+) ---

// toArray() - collect all chunks into an array, returns Promise
Readable.prototype.toArray = function(options) {
  var stream = this;
  var normalized;
  try {
    normalized = _normalizeReadableOperatorOptions(options, { signal: true });
  } catch (err) {
    return Promise.reject(err);
  }
  return (async function() {
    var result = [];
    if (normalized.signal && normalized.signal.aborted) {
      var preAbortErr = _createAbortError(normalized.signal.reason);
      if (!stream._destroyed && typeof stream.destroy === 'function') {
        stream.destroy(preAbortErr);
      }
      throw preAbortErr;
    }
    await _consumeAsyncIterable(stream, async function(value) {
      if (normalized.signal && normalized.signal.aborted) {
        var abortErr = _createAbortError(normalized.signal.reason);
        if (!stream._destroyed && typeof stream.destroy === 'function') {
          stream.destroy(abortErr);
        }
        throw abortErr;
      }
      result.push(value);
    });
    return result;
  })();
};

// forEach() - call fn for each chunk, returns Promise
Readable.prototype.forEach = function(fn, options) {
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn));
  }
  var normalized;
  try {
    normalized = _normalizeReadableOperatorOptions(options, {
      signal: true,
      concurrency: true,
      highWaterMark: true
    });
  } catch (err) {
    return Promise.reject(err);
  }
  return (async function() {
    async function forEachFn(value, callOptions) {
      await fn(value, callOptions);
      return _streamOperatorEmpty;
    }
    var iterable = _createReadableMapIterable(this, forEachFn, normalized);
    await _consumeAsyncIterable(iterable, function() {});
  }).call(this);
};

// filter() - returns a new Readable with chunks passing predicate
Readable.prototype.filter = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  var normalized = _normalizeReadableOperatorOptions(options, {
    signal: true,
    concurrency: true,
    highWaterMark: true
  });
  var iterable = _createReadableMapIterable(this, async function(value, callOptions) {
    if (await fn(value, callOptions)) {
      return value;
    }
    return _streamOperatorEmpty;
  }, normalized);
  var result = _createReadableOperatorStream(iterable, normalized);
  _attachReadableAbortSignal(result, normalized.signal);
  return result;
};

// map() - returns a new Readable with transformed chunks
Readable.prototype.map = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  var normalized = _normalizeReadableOperatorOptions(options, {
    signal: true,
    concurrency: true,
    highWaterMark: true
  });
  var result = _createReadableOperatorStream(_createReadableMapIterable(this, fn, normalized), normalized);
  _attachReadableAbortSignal(result, normalized.signal);
  return result;
};

// flatMap() - map + flatten results
Readable.prototype.flatMap = function(fn, options) {
  if (typeof fn !== 'function') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn);
  }
  var normalized = _normalizeReadableOperatorOptions(options, {
    signal: true,
    concurrency: true,
    highWaterMark: true
  });
  var values = _createReadableMapIterable(this, fn, normalized);
  var flattened = (function() {
    var queue = [];
    var resolveNext = null;
    var rejectYield = null;
    var done = false;
    var error = null;
    var abortSentinel = {};
    var valuesIter = values && typeof values[Symbol.asyncIterator] === 'function'
      ? values[Symbol.asyncIterator]()
      : null;
    var valuesDone = !valuesIter;

    function settle(result) {
      if (!resolveNext) return;
      var resolve = resolveNext;
      resolveNext = null;
      resolve(result);
    }

    function finalize(err) {
      if (done) return;
      done = true;
      error = err || null;
      if (valuesIter && !valuesDone) {
        valuesDone = true;
        _safelyReturnAsyncIterator(valuesIter);
      }
      if (err === abortSentinel) {
        settle({ value: undefined, done: true });
        return;
      }
      if (err) {
        settle(Promise.reject(err));
        return;
      }
      settle({ value: undefined, done: true });
    }

    function enqueue(value) {
      if (done) {
        return Promise.reject(abortSentinel);
      }
      return new Promise(function(resolve, reject) {
        var item = { value: value, done: false };
        rejectYield = reject;
        if (resolveNext) {
          var flush = resolveNext;
          resolveNext = null;
          flush(item);
          Promise.resolve().then(function() {
            rejectYield = null;
            resolve();
          });
          return;
        }
        queue.push(item);
        rejectYield = null;
        resolve();
      });
    }

    (async function() {
      try {
        while (valuesIter) {
          if (normalized.signal && normalized.signal.aborted) {
            throw _createAbortError(normalized.signal.reason);
          }
          var nextMapped = await valuesIter.next();
          if (!nextMapped || nextMapped.done) {
            valuesDone = true;
            finalize();
            return;
          }
          var mapped = nextMapped.value;
          if (mapped && typeof mapped[Symbol.asyncIterator] === 'function') {
            var mappedIter = mapped[Symbol.asyncIterator]();
            var mappedDone = false;
            try {
              while (true) {
                var nextItem = await mappedIter.next();
                if (!nextItem || nextItem.done) {
                  mappedDone = true;
                  break;
                }
                await enqueue(nextItem.value);
              }
            } finally {
              if (!mappedDone) {
                _safelyReturnAsyncIterator(mappedIter);
              }
            }
          } else if (mapped && typeof mapped[Symbol.iterator] === 'function' && typeof mapped !== 'string') {
            for (var i = 0; i < mapped.length; i++) {
              await enqueue(mapped[i]);
            }
          } else {
            await enqueue(mapped);
          }
        }
        finalize();
      } catch (err) {
        finalize(err);
      }
    })();

    return {
      [Symbol.asyncIterator]: function() {
        return this;
      },
      next: function() {
        if (queue.length > 0) {
          return Promise.resolve(queue.shift());
        }
        if (done) {
          return error ? Promise.reject(error) : Promise.resolve({ value: undefined, done: true });
        }
        return new Promise(function(resolve) {
          resolveNext = resolve;
        });
      },
      return: function() {
        done = true;
        queue.length = 0;
        if (rejectYield) {
          var reject = rejectYield;
          rejectYield = null;
          reject(abortSentinel);
        }
        if (valuesIter && !valuesDone) {
          valuesDone = true;
          _safelyReturnAsyncIterator(valuesIter);
        }
        settle({ value: undefined, done: true });
        return Promise.resolve({ value: undefined, done: true });
      },
      throw: function(err) {
        done = true;
        error = err;
        queue.length = 0;
        if (rejectYield) {
          var reject = rejectYield;
          rejectYield = null;
          reject(err);
        }
        if (valuesIter && !valuesDone) {
          valuesDone = true;
          _safelyReturnAsyncIterator(valuesIter);
        }
        settle(Promise.reject(err));
        return Promise.reject(err);
      }
    };
  })();
  var result = _createReadableOperatorStream(flattened, normalized);
  _attachReadableAbortSignal(result, normalized.signal);
  return result;
};

function _createReduceEmptyError() {
  var err = new TypeError('Reduce of an empty stream requires an initial value');
  err.code = 'ERR_MISSING_ARGS';
  return err;
}

// reduce() - reduce stream to a single value, returns Promise
Readable.prototype.reduce = function(fn, initial, options) {
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "reducer" argument must be of type function. Received type ' + typeof fn));
  }
  var normalized;
  try {
    normalized = _normalizeReadableOperatorOptions(options, { signal: true });
  } catch (err) {
    return Promise.reject(err);
  }
  var hasInitial = arguments.length >= 2;
  var stream = this;
  return (async function() {
    if (normalized.signal && normalized.signal.aborted) {
      var preAbortErr = _createAbortError(normalized.signal.reason);
      if (typeof stream.once === 'function') {
        stream.once('error', function() {});
      }
      if (!stream._destroyed && typeof stream.destroy === 'function') {
        stream.destroy(preAbortErr);
      }
      throw preAbortErr;
    }
    var controller = new AbortController();
    var reducerSignal = _combineAbortSignals(normalized.signal, controller.signal);
    var acc = initial;
    var receivedValue = false;
    try {
      await _consumeAsyncIterable(stream, async function(chunk) {
        receivedValue = true;
        if (normalized.signal && normalized.signal.aborted) {
          var abortErr = _createAbortError(normalized.signal.reason);
          if (!stream._destroyed && typeof stream.destroy === 'function') {
            stream.destroy(abortErr);
          }
          throw abortErr;
        }
        if (!hasInitial) {
          acc = chunk;
          hasInitial = true;
        } else {
          acc = await fn(acc, chunk, { signal: reducerSignal });
        }
      });
    } finally {
      _abortControllerWithReason(controller, normalized.signal && normalized.signal.reason);
    }
    if (!receivedValue && !hasInitial) {
      throw _createReduceEmptyError();
    }
    return acc;
  })();
};

// take() - take first N chunks
Readable.prototype.take = function(limit, options) {
  limit = _toIntegerOrInfinity(limit);
  var normalized = _normalizeReadableOperatorOptions(options, { signal: true });
  var signal = normalized.signal;
  var source = this;
  var ended = false;
  var result = new Readable({
    objectMode: true,
    read: function() {
      if (!ended && source && typeof source.resume === 'function') {
        source.resume();
      }
    }
  });
  result.readable = true;

  function cleanup() {
    if (!source || typeof source.removeListener !== 'function') return;
    source.removeListener('data', onData);
    source.removeListener('end', onEnd);
    source.removeListener('error', onError);
  }

  function closeSource(err) {
    if (!source || source._destroyed || typeof source.destroy !== 'function') return;
    source.destroy(err);
  }

  function finish(err) {
    if (ended) return;
    ended = true;
    cleanup();
    if (err) {
      if (!result._destroyed) {
        result.destroy(err);
      }
      closeSource(err);
      return;
    }
    result.push(null);
    closeSource();
  }

  function onData(chunk) {
    if (ended) return;
    if (signal && signal.aborted) {
      finish(_createAbortError(signal.reason));
      return;
    }
    if (limit <= 0) {
      finish();
      return;
    }
    limit -= 1;
    if (!result.push(chunk) && source && typeof source.pause === 'function') {
      source.pause();
    }
    if (limit <= 0) {
      finish();
    }
  }

  function onEnd() {
    finish();
  }

  function onError(err) {
    finish(err);
  }

  result._destroy = function(error, cb) {
    ended = true;
    cleanup();
    closeSource(error || null);
    cb(error || null);
  };

  if (source && typeof source.pause === 'function') {
    source.pause();
  }
  source.on('data', onData);
  source.on('end', onEnd);
  source.on('error', onError);
  _attachReadableAbortSignal(result, signal);
  return result;
};

// drop() - skip first N chunks
Readable.prototype.drop = function(count, options) {
  count = _toIntegerOrInfinity(count);
  var normalized = _normalizeReadableOperatorOptions(options, { signal: true });
  var signal = normalized.signal;
  var source = this;
  var ended = false;
  var result = new Readable({
    objectMode: true,
    read: function() {
      if (!ended && source && typeof source.resume === 'function') {
        source.resume();
      }
    }
  });
  result.readable = true;

  function cleanup() {
    if (!source || typeof source.removeListener !== 'function') return;
    source.removeListener('data', onData);
    source.removeListener('end', onEnd);
    source.removeListener('error', onError);
  }

  function closeSource(err) {
    if (!source || source._destroyed || typeof source.destroy !== 'function') return;
    source.destroy(err);
  }

  function finish(err) {
    if (ended) return;
    ended = true;
    cleanup();
    if (err) {
      if (!result._destroyed) {
        result.destroy(err);
      }
      closeSource(err);
      return;
    }
    result.push(null);
  }

  function onData(chunk) {
    if (ended) return;
    if (signal && signal.aborted) {
      finish(_createAbortError(signal.reason));
      return;
    }
    if (count-- > 0) {
      return;
    }
    if (!result.push(chunk) && source && typeof source.pause === 'function') {
      source.pause();
    }
  }

  function onEnd() {
    finish();
  }

  function onError(err) {
    finish(err);
  }

  result._destroy = function(error, cb) {
    ended = true;
    cleanup();
    closeSource(error || null);
    cb(error || null);
  };

  if (source && typeof source.pause === 'function') {
    source.pause();
  }
  source.on('data', onData);
  source.on('end', onEnd);
  source.on('error', onError);
  _attachReadableAbortSignal(result, signal);
  return result;
};

// some() - returns true if any chunk passes predicate
Readable.prototype.some = function(fn, options) {
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn));
  }
  return (async function() {
    var normalized = _normalizeReadableOperatorOptions(options, {
      signal: true,
      concurrency: true,
      highWaterMark: true
    });
    var iterable = _createReadableMapIterable(this, async function(value, callOptions) {
      return (await fn(value, callOptions)) ? value : _streamOperatorEmpty;
    }, normalized);
    var found = false;
    await _consumeAsyncIterable(iterable, function(chunk) {
      if (chunk !== _streamOperatorEmpty) {
        found = true;
        throw _streamOperatorEof;
      }
    }).catch(function(err) {
      if (err !== _streamOperatorEof) throw err;
    });
    if (found) return true;
    return false;
  }).call(this);
};

// every() - returns true if all chunks pass predicate
Readable.prototype.every = function(fn, options) {
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn));
  }
  return (async function() {
    var normalized = _normalizeReadableOperatorOptions(options, {
      signal: true,
      concurrency: true,
      highWaterMark: true
    });
    var iterable = _createReadableMapIterable(this, async function(value, callOptions) {
      return (await fn(value, callOptions)) ? _streamOperatorEmpty : value;
    }, normalized);
    var failed = false;
    await _consumeAsyncIterable(iterable, function(chunk) {
      if (chunk !== _streamOperatorEmpty) {
        failed = true;
        throw _streamOperatorEof;
      }
    }).catch(function(err) {
      if (err !== _streamOperatorEof) throw err;
    });
    if (failed) return false;
    return true;
  }).call(this);
};

// find() - returns first chunk passing predicate
Readable.prototype.find = function(fn, options) {
  if (typeof fn !== 'function') {
    return Promise.reject(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fn" argument must be of type function. Received type ' + typeof fn));
  }
  return (async function() {
    var normalized = _normalizeReadableOperatorOptions(options, {
      signal: true,
      concurrency: true,
      highWaterMark: true
    });
    var iterable = _createReadableMapIterable(this, async function(value, callOptions) {
      return (await fn(value, callOptions)) ? value : _streamOperatorEmpty;
    }, normalized);
    var foundChunk = undefined;
    await _consumeAsyncIterable(iterable, function(chunk) {
      if (chunk !== _streamOperatorEmpty) {
        foundChunk = chunk;
        throw _streamOperatorEof;
      }
    }).catch(function(err) {
      if (err !== _streamOperatorEof) throw err;
    });
    if (foundChunk !== undefined) return foundChunk;
    return undefined;
  }).call(this);
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
  return !!(value &&
    (typeof value.read === 'function' || value.readable === true) &&
    typeof value.on === 'function');
}

function _isWritableLike(value) {
  return !!(value &&
    (typeof value.write === 'function' || value.writable === true) &&
    typeof value.on === 'function');
}

function _isStreamLike(value) {
  return _isReadableLike(value) || _isWritableLike(value);
}

function _readableObjectModeOf(value) {
  if (!value) return undefined;
  if (typeof value.readableObjectMode === 'boolean') return value.readableObjectMode;
  if (value._readableState && typeof value._readableState.objectMode === 'boolean') {
    return value._readableState.objectMode;
  }
  return undefined;
}

function _writableObjectModeOf(value) {
  if (!value) return undefined;
  if (typeof value.writableObjectMode === 'boolean') return value.writableObjectMode;
  if (value._writableState && typeof value._writableState.objectMode === 'boolean') {
    return value._writableState.objectMode;
  }
  return undefined;
}

function _stageCanRead(value) {
  return !!(value && value._readableState && value.readable !== false);
}

function _stageCanWrite(value) {
  return !!(value && value._writableState && value.writable !== false);
}

function _inferComposeFunctionOptions(stages, index) {
  var prev = stages[index - 1];
  var next = stages[index + 1];
  var writableObjectMode = _readableObjectModeOf(prev);
  var readableObjectMode = _writableObjectModeOf(next);
  if (writableObjectMode === undefined && readableObjectMode === undefined) {
    return undefined;
  }
  var inferred = {};
  if (writableObjectMode !== undefined) {
    inferred.writableObjectMode = writableObjectMode;
  }
  if (readableObjectMode !== undefined) {
    inferred.readableObjectMode = readableObjectMode;
  }
  if (writableObjectMode !== undefined && readableObjectMode !== undefined && writableObjectMode === readableObjectMode) {
    inferred.objectMode = writableObjectMode;
  }
  return inferred;
}

function _normalizePrematureCloseError(err) {
  if (!err) return null;
  if (err.code) return err;
  if (typeof err === 'string' && err.indexOf('premature close') !== -1) {
    return makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', err);
  }
  if (err && typeof err.message === 'string' && err.message === 'premature close') {
    return makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
  }
  return err;
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

function _normalizeReadableFromOptions(options) {
  var normalized = options ? Object.assign({}, options) : {};
  if (normalized.objectMode === undefined) {
    normalized.objectMode = true;
  }
  return normalized;
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
  var sourceEnded = false;
  function endDuplexStream() {
    if (sourceEnded) return;
    sourceEnded = true;
    if (!duplex._destroyed) {
      duplex.push(null);
    }
  }
  readable.on('data', function(chunk) {
    if (!duplex.push(chunk) && typeof readable.pause === 'function') {
      readable.pause();
    }
  });
  readable.on('error', function(err) {
    _destroyStreamWithError(duplex, err);
  });
  readable.on('end', function() {
    endDuplexStream();
  });
  readable.on('close', function() {
    var readableState = readable._readableState;
    if (
      readableState &&
      readableState.errored
    ) {
      return;
    }
    endDuplexStream();
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
  var duplexReadable = options && options.readable != null ? !!options.readable : !!readable;
  var duplexWritable = options && options.writable != null ? !!options.writable : !!writable;
  var duplex = new Duplex({
    readable: duplexReadable,
    writable: duplexWritable,
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
      _destroyStreamWithError(duplex, err);
    });
  }
  if (readable) {
    _connectReadableToDuplex(readable, duplex);
  }
  return duplex;
}

function _ensureComposeStageReadableEnd(stage) {
  if (!stage || typeof stage.on !== 'function' || typeof stage.push !== 'function') return;
  if (stage._isPipelineFunction || stage._transformState) return;
  stage.on('finish', function() {
    function maybeCloseReadable() {
      var readableState = stage._readableState;
      if (!readableState || stage._destroyed || stage.destroyed) return;
      if (readableState.ended || readableState.endEmitted) return;
      if (readableState.length > 0) {
        _nextTick(maybeCloseReadable);
        return;
      }
      try {
        stage.push(null);
      } catch (_err) {}
    }
    _nextTick(maybeCloseReadable);
  });
}

function _duplexFromFunction(value, options) {
  var inputObjectMode = options && options.objectMode != null ? !!options.objectMode :
    (options && options.writableObjectMode != null ? !!options.writableObjectMode : true);
  var outputObjectMode = options && options.objectMode != null ? !!options.objectMode :
    (options && options.readableObjectMode != null ? !!options.readableObjectMode : true);
  var srcOptions = options ? Object.assign({}, options) : {};
  if (srcOptions.objectMode == null) {
    srcOptions.objectMode = inputObjectMode;
  }
  srcOptions.readableObjectMode = inputObjectMode;
  srcOptions.writableObjectMode = inputObjectMode;
  var src = new PassThrough(srcOptions);
  var output = value(src);
  if (output === undefined) {
    throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE', 'The \"source\" argument must return a value');
  }
  if (output && typeof output.then === 'function') {
    var sinkOptions = options ? Object.assign({}, options) : {};
    sinkOptions.readable = false;
    var sink = _duplexFromReadableWritable(null, src, sinkOptions);
    sink._pipelineResult = Promise.resolve(output);
    sink._pipelineResult.catch(function(err) {
      if (!sink._destroyed) {
        sink.destroy(err);
      }
    });
    sink._isPipelineFunction = true;
    return sink;
  }
  var readableOptions = options ? Object.assign({}, options) : {};
  if (options == null || options.objectMode == null) {
    readableOptions.objectMode = outputObjectMode;
    readableOptions.readableObjectMode = outputObjectMode;
  }
  var readable = _toReadable(output, readableOptions);
  if (
    value && typeof value.length === 'number' && value.length > 0 &&
    output && typeof output[Symbol.iterator] === 'function' &&
    readable && readable._syncIterableHasData === false
  ) {
    throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE', 'The "source" argument must return a value');
  }
  var duplexOptions = options ? Object.assign({}, options) : {};
  if (value && typeof value.length === 'number' && value.length === 0) {
    duplexOptions.writable = false;
  }
  var duplex = _duplexFromReadableWritable(readable, src, duplexOptions);
  duplex._isPipelineFunction = true;
  return duplex;
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
    var readableOnlyOptions = options ? Object.assign({}, options) : {};
    readableOnlyOptions.writable = false;
    return _duplexFromReadableWritable(value, null, readableOnlyOptions);
  }
  if (_isWritableLike(value) && !value._readableState) {
    var writableOnlyOptions = options ? Object.assign({}, options) : {};
    writableOnlyOptions.readable = false;
    return _duplexFromReadableWritable(null, value, writableOnlyOptions);
  }
  if (value && (typeof value.readable !== 'undefined' || typeof value.writable !== 'undefined')) {
    var readableFromObject = _toReadable(value && value.readable, options);
    var writableFromObject = _toWritable(value && value.writable, options);
    if (readableFromObject && writableFromObject) {
      return _duplexFromReadableWritable(readableFromObject, writableFromObject, options);
    }
    if (readableFromObject) {
      var readableOptions = options ? Object.assign({}, options) : {};
      readableOptions.writable = false;
      return _duplexFromReadableWritable(readableFromObject, null, readableOptions);
    }
    if (writableFromObject) {
      var writableOptions = options ? Object.assign({}, options) : {};
      writableOptions.readable = false;
      return _duplexFromReadableWritable(null, writableFromObject, writableOptions);
    }
  }
  if (_isReadableLike(value) && _isWritableLike(value)) {
    return value;
  }
  var writable = _toWritable(value, options);
  if (writable) {
    var writableValueOptions = options ? Object.assign({}, options) : {};
    writableValueOptions.readable = false;
    return _duplexFromReadableWritable(null, writable, writableValueOptions);
  }
  var readable = _toReadable(value, options);
  if (readable && !readable._writableState) {
    var readableValueOptions = options ? Object.assign({}, options) : {};
    readableValueOptions.writable = false;
    return _duplexFromReadableWritable(readable, null, readableValueOptions);
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
var _hermesUnhandledRejectionFilter = 0;
var _hermesUnhandledRejectionEmitPatched = false;
var _hermesUnhandledRejectionOriginalEmit = null;

function _suppressHermesAsyncIteratorUnhandledRejections() {
  if (typeof process !== 'object' || process === null || typeof process.emit !== 'function') return;
  _hermesUnhandledRejectionFilter += 2;
  setTimeout(function() {
    _hermesUnhandledRejectionFilter = Math.max(0, _hermesUnhandledRejectionFilter - 2);
  }, 0);
}

function _safelyReturnAsyncIterator(asyncIter) {
  if (!asyncIter || typeof asyncIter.return !== 'function') return;
  var iteratorReturnResult;
  try {
    iteratorReturnResult = asyncIter.return();
  } catch (_err) {
    return;
  }
  if (!iteratorReturnResult || typeof iteratorReturnResult.then !== 'function') return;
  iteratorReturnResult.catch(function() {});
}

function _destroyStreamWithError(stream, err) {
  if (!stream || stream._destroyed) return;
  if (err) {
    if (stream._readableState) {
      stream._readableState.errored = err;
    }
    if (stream._writableState) {
      stream._writableState.errored = err;
    }
    stream.errored = err;
  }
  if (typeof stream.destroy === 'function' && !stream._destroyed) {
    stream.destroy(err);
  }
}

Readable.from = function(iterable, options) {
  if (typeof process === 'object' && process !== null && typeof process.emit === 'function') {
    if (!_hermesUnhandledRejectionEmitPatched) {
      _hermesUnhandledRejectionOriginalEmit = process.emit;
      process.emit = function(name, reason, promise) {
        if (
          name === 'unhandledRejection' &&
          _hermesUnhandledRejectionFilter > 0 &&
          reason &&
          typeof reason.stack === 'string' &&
          reason.stack.indexOf('at next (native)') !== -1
        ) {
          _hermesUnhandledRejectionFilter--;
          return false;
        }
        return _hermesUnhandledRejectionOriginalEmit.call(this, name, reason, promise);
      };
      _hermesUnhandledRejectionEmitPatched = true;
    }
  }

  var readableOptions = _normalizeReadableFromOptions(options);
  var readable = new Readable(readableOptions);
  var readableStream = readable;
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
    if (readableStream) {
      readableStream.push(null);
    }
    return readable;
  }
  if (typeof iterable === 'string' || iterable instanceof Uint8Array) {
    readableStream.push(iterable);
    readableStream.push(null);
    return readable;
  }
  // Async iterable (including async generators)
  if (typeof iterable[Symbol.asyncIterator] === 'function') {
    var asyncIter = iterable[Symbol.asyncIterator]();
    var reading = false;
    var destroyCallback = _nextTick;

    readable._read = function() {
      if (!reading) {
        reading = true;
        nextAsync();
      }
    };

    readable._destroy = function(error, cb) {
      async function closeAsyncIterator() {
        var hasError = error !== undefined && error !== null;
        if (hasError && typeof asyncIter.throw === 'function') {
          var thrown = await asyncIter.throw(error);
          if (thrown && thrown.value !== undefined) {
            await thrown.value;
          }
          if (thrown && thrown.done) {
            return;
          }
        }
        if (typeof asyncIter.return === 'function') {
          var returned = await asyncIter.return();
          if (returned && returned.value !== undefined) {
            await returned.value;
          }
        }
      }

      Promise.resolve().then(closeAsyncIterator).then(function() {
        destroyCallback(function() { cb(error || null); });
      }, function(err) {
        destroyCallback(function() { cb(err || error || null); });
      });
    };

    async function nextAsync() {
      while (true) {
        try {
          _suppressHermesAsyncIteratorUnhandledRejections();
          var result = await asyncIter.next();
          if (!readableStream || readableStream._destroyed) {
            _safelyReturnAsyncIterator(asyncIter);
            return;
          }
          if (!result || result.done) {
            readableStream.push(null);
            return;
          }
          if (result.value === null) {
            reading = false;
            var nullErr = new TypeError('May not write null values to stream');
            nullErr.code = 'ERR_STREAM_NULL_VALUES';
            throw nullErr;
          }
          if (readableStream.push(result.value)) {
            continue;
          }
          reading = false;
          return;
        } catch (err) {
          reading = false;
          if (!readableStream || readableStream._destroyed) {
            return;
          }
          readableStream.destroy(err);
          return;
        }
      }
    }

    return readable;
  }
  // Sync iterable - store data in buffer without emitting events
  // Events will be emitted when consumers start listening
  if (typeof iterable[Symbol.iterator] === 'function') {
    var iterator = null;
    var hasSyncIterableData = false;
    try {
      iterator = iterable[Symbol.iterator]();
    } catch (err) {
      if (!readable._destroyed) {
        _destroyStreamWithError(readable, err);
      }
      return readable;
    }
    try {
      var next = iterator.next();
      while (!next.done) {
        hasSyncIterableData = true;
        if (next.value === null) {
          var nullErr = new TypeError('May not write null values to stream');
          nullErr.code = 'ERR_STREAM_NULL_VALUES';
          if (!readableStream._destroyed) {
            _destroyStreamWithError(readableStream, nullErr);
          }
          _safelyReturnAsyncIterator(iterator);
          return readable;
        }
        readableStream._data.push(next.value);
        readableStream._updateReadableLength(
          readableStateChunkLength(next.value, readableStream._readableState.objectMode)
        );
        next = iterator.next();
      }
    } catch (err) {
      if (!readableStream._destroyed) {
        _destroyStreamWithError(readableStream, err);
      }
      if (iterator) {
        _safelyReturnAsyncIterator(iterator);
      }
      return readable;
    }
    readableStream._syncIterableHasData = hasSyncIterableData;
    readableStream._syncReadableState();
    readableStream._ended = true;
    readableStream._readableState.ended = true;
    readableStream._readableState.needReadable = true;
    // Mark as needing replay when consumers attach
    readableStream._needsReplay = true;
    return readable;
  }
  // Promise
  if (iterable instanceof Promise || (iterable && typeof iterable.then === 'function')) {
    function pushFromResolvedValue(value) {
      if (!readableStream || readableStream._destroyed) return;
      if (value && (value instanceof Promise || typeof value.then === 'function')) {
        value.then(pushFromResolvedValue).catch(function(err) {
          if (!readableStream || readableStream._destroyed) return;
          if (!readableStream._destroyed) {
            _destroyStreamWithError(readableStream, err);
          }
        });
        return;
      }

      if (value && typeof value[Symbol.asyncIterator] === 'function') {
        var asyncIter = value[Symbol.asyncIterator]();
        var reading = false;
        function readNext() {
          if (reading || !readableStream || readableStream._destroyed) return;
          reading = true;
          _suppressHermesAsyncIteratorUnhandledRejections();
        var next;
          try {
            next = asyncIter.next();
          } catch (err) {
            reading = false;
            if (!readableStream || readableStream._destroyed) return;
            if (!readableStream._destroyed) {
              _destroyStreamWithError(readableStream, err);
            }
            return;
          }
          Promise.resolve(next).then(function(result) {
            reading = false;
            if (!readableStream || readableStream._destroyed) {
              _safelyReturnAsyncIterator(asyncIter);
              return;
            }
            if (result.done) {
              readableStream.push(null);
            } else {
              readableStream.push(result.value);
              readNext();
            }
          }).catch(function(err) {
            reading = false;
            if (!readableStream || readableStream._destroyed) return;
            if (!readableStream._destroyed) {
              _destroyStreamWithError(readableStream, err);
            }
      });
    }
    scheduleRead(readNext);
    return;
  }

      if (typeof value === 'string' || value instanceof Uint8Array) {
        readableStream.push(value);
        readableStream.push(null);
        return;
      }

      if (value && typeof value[Symbol.iterator] === 'function') {
        try {
          var iterator = value[Symbol.iterator]();
          var next = iterator.next();
          while (!next.done) {
            if (!readableStream || readableStream._destroyed) {
              if (typeof iterator.return === 'function') {
                iterator.return();
              }
              return;
            }
            if (next.value === null) {
              var nullErr = new TypeError('May not write null values to stream');
              nullErr.code = 'ERR_STREAM_NULL_VALUES';
              if (!readableStream._destroyed) {
                _destroyStreamWithError(readableStream, nullErr);
              }
              _safelyReturnAsyncIterator(iterator);
              return;
            }
            readableStream.push(next.value);
            next = iterator.next();
          }
          readableStream.push(null);
        } catch (err) {
          if (readableStream && !readableStream._destroyed) {
            _destroyStreamWithError(readableStream, err);
          }
          if (typeof iterator === 'object' && iterator && typeof iterator.return === 'function') {
            _safelyReturnAsyncIterator(iterator);
          }
        }
        return;
      }

      readableStream.push(value);
      readableStream.push(null);
    }

    iterable.then(pushFromResolvedValue).catch(function(err) {
      if (!readableStream || readableStream._destroyed) return;
      if (!readableStream._destroyed) {
        _destroyStreamWithError(readableStream, err);
      }
    });
    return readable;
  }
  readableStream.push(null);
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
  // Pre-initialize event slots to match Node.js key ordering
  this._events.close = undefined;
  this._events.error = undefined;
  this._events.prefinish = undefined;
  this._events.finish = undefined;
  this._events.drain = undefined;
  var self = this;
  var supportsSplitOptions = this instanceof Duplex;
  // Determine objectMode: writableObjectMode overrides objectMode if present on Duplex/Transform
  var objMode = (supportsSplitOptions && options && options.writableObjectMode != null) ? !!options.writableObjectMode :
                !!(options && options.objectMode);
  var decodeStrings = options && options.decodeStrings != null ? !!options.decodeStrings : true;
  // Determine highWaterMark: explicit highWaterMark wins, then writableHighWaterMark, then default
  var hwm;
  if (options && options.highWaterMark != null) {
    hwm = _validateHighWaterMarkOption('highWaterMark', options.highWaterMark);
  } else if (supportsSplitOptions && options && options.writableHighWaterMark != null) {
    hwm = _validateHighWaterMarkOption('writableHighWaterMark', options.writableHighWaterMark);
  } else {
    hwm = objMode ? defaultHighWaterMarkObjectMode : defaultHighWaterMark;
  }
  this.writable = true;
  this.errored = null;
  this._written = [];
  this._writeQueue = [];
  this._pipeCleanups = null;
  this._needDrain = false;
  this._writableState = {
    highWaterMark: hwm,
    objectMode: objMode,
    decodeStrings: decodeStrings,
    length: 0,
    writing: false,
    ended: false,
    finished: false,
    destroyed: false,
    bufferedRequest: null,
    bufferedRequestCount: 0,
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
  this._writableState.getBuffer = function() {
    if (!self._writeQueue || !self._writeQueue.length) return [];
    var stateBuffer = [];
    for (var gi = 0; gi < self._writeQueue.length; gi++) {
      var queued = self._writeQueue[gi];
      stateBuffer.push({
        chunk: queued.chunk,
        encoding: queued.encoding,
        callback: queued.callback
      });
    }
    return stateBuffer;
  };
  // corked is stored directly in _writableState and accessed via prototype getter
  if (options && options.defaultEncoding !== undefined && options.defaultEncoding !== null) {
    var _validEncs = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1 };
    if (!_validEncs[String(options.defaultEncoding).toLowerCase()]) {
      var encErr = new TypeError('Unknown encoding: ' + options.defaultEncoding);
      encErr.code = 'ERR_UNKNOWN_ENCODING';
      throw encErr;
    }
    this._writableState.defaultEncoding = options.defaultEncoding;
  }
  if (options && typeof options.write === 'function') this._write = options.write;
  if (options && typeof options._write === 'function') this._write = options._write;
  if (options && typeof options.writev === 'function') this._writev = options.writev;
  if (options && typeof options._writev === 'function') this._writev = options._writev;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  if (options && typeof options._destroy === 'function') this._destroy = options._destroy;
  if (options && typeof options.final === 'function') this._final = options.final;
  if (options && typeof options._final === 'function') this._final = options._final;
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
          return;
        }
        _resumeWritableAfterConstruct(self);
      });
    }, 0);
  }
}
Writable.prototype = Object.create(Stream.prototype);
Writable.prototype.constructor = Writable;
Writable.prototype._undestroy = Stream.prototype._undestroy;

// Define writableFinished, writableEnded, writableAborted, writableLength,
// writableHighWaterMark, writableCorked, writableNeedDrain, writableObjectMode
// as prototype getters/setters so Object.hasOwn(Writable.prototype, ...) works
Object.defineProperties(Writable.prototype, {
  writableFinished: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? !!this._writableState.finished : false;
    },
    set: function(val) {
      if (this._writableState) this._writableState.finished = !!val;
    }
  },
  writableEnded: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? !!this._writableState.ended : false;
    },
    set: function(val) {
      if (this._writableState) this._writableState.ended = !!val;
    }
  },
  writableAborted: {
    configurable: true,
    enumerable: true,
    get: function() {
      return !!(this._writableState && this._writableState.destroyed &&
                !this._writableState.finished);
    },
    set: function(val) {
      // no-op, computed
    }
  },
  writableLength: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? this._writableState.length : 0;
    },
    set: function(val) {
      if (this._writableState) this._writableState.length = val;
    }
  },
  writableHighWaterMark: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? this._writableState.highWaterMark : 0;
    },
    set: function(val) {
      if (this._writableState) this._writableState.highWaterMark = val;
    }
  },
  writableCorked: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? this._writableState.corked : 0;
    },
    set: function(val) {
      if (this._writableState) this._writableState.corked = val;
    }
  },
  writableNeedDrain: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? !!this._writableState.needDrain : false;
    },
    set: function(val) {
      if (this._writableState) this._writableState.needDrain = !!val;
    }
  },
  writableObjectMode: {
    configurable: true,
    enumerable: true,
    get: function() {
      return this._writableState ? !!this._writableState.objectMode : false;
    },
    set: function(val) {
      if (this._writableState) this._writableState.objectMode = !!val;
    }
  },
});

// Verify defineProperties applied (catch silent errors)
if (!Object.hasOwn(Writable.prototype, 'writableFinished')) {
  // Fallback: try individual defineProperty calls
  try {
    Object.defineProperty(Writable.prototype, 'writableFinished', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? !!this._writableState.finished : false; },
      set: function(val) { if (this._writableState) this._writableState.finished = !!val; }
    });
    Object.defineProperty(Writable.prototype, 'writableEnded', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? !!this._writableState.ended : false; },
      set: function(val) { if (this._writableState) this._writableState.ended = !!val; }
    });
    Object.defineProperty(Writable.prototype, 'writableAborted', {
      configurable: true, enumerable: true,
      get: function() { return !!(this._writableState && this._writableState.destroyed && !this._writableState.finished); },
      set: function() {}
    });
    Object.defineProperty(Writable.prototype, 'writableLength', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? this._writableState.length : 0; },
      set: function(val) { if (this._writableState) this._writableState.length = val; }
    });
    Object.defineProperty(Writable.prototype, 'writableHighWaterMark', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? this._writableState.highWaterMark : 0; },
      set: function(val) { if (this._writableState) this._writableState.highWaterMark = val; }
    });
    Object.defineProperty(Writable.prototype, 'writableCorked', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? this._writableState.corked : 0; },
      set: function(val) { if (this._writableState) this._writableState.corked = val; }
    });
    Object.defineProperty(Writable.prototype, 'writableNeedDrain', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? !!this._writableState.needDrain : false; },
      set: function(val) { if (this._writableState) this._writableState.needDrain = !!val; }
    });
    Object.defineProperty(Writable.prototype, 'writableObjectMode', {
      configurable: true, enumerable: true,
      get: function() { return this._writableState ? !!this._writableState.objectMode : false; },
      set: function(val) { if (this._writableState) this._writableState.objectMode = !!val; }
    });
  } catch (_defErr) {
    // Silently fail if defineProperty doesn't work
  }
}

Writable.prototype.__exactWritableProtoPatched = true;

// Custom Symbol.hasInstance so Duplex instances pass `instanceof Writable`
Object.defineProperty(Writable, Symbol.hasInstance, {
  value: function(object) {
    // First check the normal prototype chain
    if (Function.prototype[Symbol.hasInstance].call(this, object)) return true;
    if (this !== Writable) return false;
    // For Writable specifically, also check if object has _writableState
    // This allows Duplex (which inherits from Readable, not Writable) to pass
    return object != null && typeof object === 'object' && object._writableState != null;
  }
});

Writable.prototype._write = function(chunk, encoding, callback) {
  if (typeof this._writev === 'function') {
    // If _writev is implemented but _write is not, delegate single writes through _writev
    this._writev([{ chunk: chunk, encoding: encoding }], callback);
    return;
  }
  var err = new Error('The _write() method is not implemented');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  throw err;
};

Writable.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  var state = this._writableState;

  // If the stream is errored, return false immediately
  if (state && state.errored) {
    if (typeof callback === 'function') {
      _nextTick(function() { callback(state.errored); });
    }
    return false;
  }

  var hasErrorListener = false;
  if (state) {
    if (typeof this.listenerCount === 'function') {
      hasErrorListener = this.listenerCount('error') > 0;
    } else if (this._events && this._events.error) {
      hasErrorListener = true;
    }
  }

  if (this._destroyed) {
    var destroyErr = new Error('Cannot call write after a stream was destroyed');
    destroyErr.code = 'ERR_STREAM_DESTROYED';
    if (typeof callback === 'function') {
      setTimeout(function() { callback(destroyErr); }, 0);
      return false;
    }
    if (hasErrorListener && state && !state.errorEmitted) {
      this.errored = destroyErr;
      if (state) {
        state.errored = destroyErr;
        state.errorEmitted = true;
      }
      this.emit('error', destroyErr);
      return false;
    }
    if (state && state.errorEmitted) {
      if (state.errored == null) {
        state.errored = destroyErr;
      }
      this.errored = this.errored || destroyErr;
      return false;
    }
    throw destroyErr;
  }

  if (this.writableEnded || (state && state.ending)) {
    var endErr = new Error('write after end');
    endErr.code = 'ERR_STREAM_WRITE_AFTER_END';
    if (state) state.errored = endErr;
    this.errored = endErr;
    var _endSelf = this;
    _nextTick(function() {
      if (typeof callback === 'function') {
        callback(endErr);
      }
      if (state && !state.errorEmitted) {
        state.errorEmitted = true;
        _endSelf.emit('error', endErr);
      }
    });
    return false;
  }

  if (chunk === null) {
    throw makeError(TypeError, 'ERR_STREAM_NULL_VALUES', 'May not write null values to stream');
  }

  // Validate encoding when decodeStrings is false and chunk is a string
  if (!this.writableObjectMode && typeof chunk === 'string' && encoding) {
    var _validWriteEncs = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1, 'buffer': 1 };
    if (!_validWriteEncs[String(encoding).toLowerCase()]) {
      throw makeError(TypeError, 'ERR_UNKNOWN_ENCODING', 'Unknown encoding: ' + encoding);
    }
  }

  if (!this.writableObjectMode && this._writableState.decodeStrings !== false && typeof chunk === 'string') {
    var enc = state && state.defaultEncoding ? state.defaultEncoding : (encoding || 'utf8');
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
    encoding = 'buffer';
  }

  if (!this.writableObjectMode && typeof chunk !== 'string' &&
      !(typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) &&
      !(chunk instanceof Uint8Array)) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "chunk" argument must be of type string or an instance of Buffer or Uint8Array. Received type ' + typeof chunk);
  }

  var chunkLen = 0;
  if (chunk !== undefined) {
    this._written.push(chunk);
    chunkLen = readableStateChunkLength(chunk, this.writableObjectMode || (state && state.objectMode));
    this.writableLength += chunkLen;
  }
  _syncWritableBufferState(this);

  var shouldNeedDrain = this.writableLength > this.writableHighWaterMark;
  var queued = _createWriteQueueItem(chunk, encoding || 'utf8', callback, chunkLen);

  if (state.constructed === false || this.writableCorked > 0 || state.writing || state.bufferProcessing) {
    this._writeQueue.push(queued);
    _syncWritableBufferState(this);
    if (shouldNeedDrain) {
      this._needDrain = true;
      this.writableNeedDrain = true;
      state.needDrain = true;
    }
    return !shouldNeedDrain;
  }

  if (typeof state.pendingcb === 'number') {
    state.pendingcb++;
  }
  state.writing = true;
  if (shouldNeedDrain) {
    this._needDrain = true;
    this.writableNeedDrain = true;
    state.needDrain = true;
  }
  var hadNeedDrain = this._needDrain || this.writableNeedDrain;
  var callbackCalled = false;
  var self = this;
  var onWriteComplete = function(err) {
    if (callbackCalled) return;
    callbackCalled = true;
    state.writing = false;
    if (typeof state.pendingcb === 'number' && state.pendingcb > 0) {
      state.pendingcb--;
    }
    self.writableLength -= chunkLen;
    if (self.writableLength < 0) self.writableLength = 0;
    _syncWritableBufferState(self);

    if (err) {
      self.errored = err;
      if (state) state.errored = err;
      // Call the write callback first, then emit error (Node.js guarantees callback before error event)
      if (typeof queued.callback === 'function') {
        queued.callback(err);
      }
      _nextTick(function() {
        if (state.autoDestroy && !self._destroyed) {
          self.destroy(err);
        } else if (!state.errorEmitted) {
          state.errorEmitted = true;
          self.emit('error', err);
        }
      });
      return;
    }

    var shouldEmitDrain = (hadNeedDrain || shouldNeedDrain) &&
                          !(state && state.ending) &&
                          !self._destroyed &&
                          self.writableLength < self.writableHighWaterMark;
    if (shouldEmitDrain) {
      self._needDrain = false;
      self.writableNeedDrain = false;
      state.needDrain = false;
      _scheduleDrain(self);
    }

    if (typeof queued.callback === 'function') queued.callback();
    if (self._writeQueue && self._writeQueue.length) {
      self._flushWriteQueue();
    }
    _drainPendingEnd(self);
  };

  if (shouldNeedDrain) {
    this._needDrain = true;
    this.writableNeedDrain = true;
    state.needDrain = true;
  }

  try {
    self._write(chunk, encoding || 'utf8', onWriteComplete);
  } catch (err) {
    if (err && err.code === 'ERR_METHOD_NOT_IMPLEMENTED') {
      throw err;
    }
    onWriteComplete(err);
    return false;
  }
  return !shouldNeedDrain;
};

Writable.prototype._flushWriteQueue = function() {
  if (!this._writeQueue || this._writeQueue.length === 0) {
    return;
  }
  if (!this._writableState || this._writableState.writing || this._writableState.bufferProcessing || this._writableState.constructed === false) {
    return;
  }
  var self = this;
  var state = this._writableState;
  var batch = this._writeQueue;
  this._writeQueue = [];
  _syncWritableBufferState(this);
  state.bufferProcessing = true;
  state.writing = true;

  var hadNeedDrain = this._needDrain || this.writableNeedDrain;
  var totalLen = 0;
  for (var bi = 0; bi < batch.length; bi++) {
    totalLen += batch[bi].chunkLen || 0;
  }

  var maybeEmitDrain = function() {
    if (self._destroyed) return;
    if (state && state.ending) return;
    if (!hadNeedDrain) return;
    if (self.writableLength >= self.writableHighWaterMark) return;
    if (!self._needDrain && !self.writableNeedDrain) return;
    self._needDrain = false;
    self.writableNeedDrain = false;
    state.needDrain = false;
    _scheduleDrain(self);
  };

  var cleanup = function(err) {
    state.bufferProcessing = false;
    state.writing = false;
    self.writableLength -= totalLen;
    if (self.writableLength < 0) self.writableLength = 0;
    _syncWritableBufferState(self);
    if (err) {
      for (var bi2 = 0; bi2 < batch.length; bi2++) {
        if (typeof batch[bi2].callback === 'function') {
          batch[bi2].callback(err);
        }
      }
      _finishIfError(self, err);
      return;
    }
    maybeEmitDrain();
    for (var bi3 = 0; bi3 < batch.length; bi3++) {
      if (typeof batch[bi3].callback === 'function') {
        batch[bi3].callback();
      }
    }
    if (!self._destroyed && self._writeQueue && self._writeQueue.length) {
      self._flushWriteQueue();
    }
    _drainPendingEnd(self);
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
        self.writableLength -= item.chunkLen || 0;
        if (self.writableLength < 0) self.writableLength = 0;
        if (err) {
          cleanup(err);
          return;
        }
        if (typeof item.callback === 'function') {
          item.callback();
        }
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
  var state = this._writableState;
  if (!state) {
    if (typeof callback === 'function') {
      setTimeout(function() { callback(null); }, 0);
    }
    return this;
  }

  if (this.writableFinished) {
    var finishedErr = new Error('write after end');
    finishedErr.code = 'ERR_STREAM_ALREADY_FINISHED';
    if (typeof callback === 'function') {
      setTimeout(function() { callback(finishedErr); }, 0);
    }
    return this;
  }

  if (this.writableEnded) {
    if (typeof callback === 'function') {
      if (!this._endCallbacks) this._endCallbacks = [];
      this._endCallbacks.push(callback);
    }
    return this;
  }

  if (!this._endCallbacks) this._endCallbacks = [];
  if (typeof callback === 'function') {
    this._endCallbacks.push(callback);
  }

  var self = this;
  var scheduleDone = function(fn) {
    if (typeof setTimeout === 'function') {
      setTimeout(fn, 0);
    } else {
      fn();
    }
  };

  var done = function(err) {
    state._pendingEnd = null;
    if (self._destroyed) {
      var endErr = err || self.errored;
      var eCbs = self._endCallbacks;
      self._endCallbacks = [];
      if (eCbs) {
        for (var e = 0; e < eCbs.length; e++) {
          eCbs[e](endErr || null);
        }
      }
      return;
    }
    if (state.writing || state.bufferProcessing || (self._writeQueue && self._writeQueue.length)) {
      state._pendingEnd = done;
      state._pendingEndScheduled = true;
      return;
    }
    if (err) {
      state.writing = false;
      self.destroy(err);
      return;
    }
    if (state.prefinished) {
      return;
    }
    state.prefinished = true;
    // prefinish fires synchronously
    self.emit('prefinish');
    if (
      self._destroyed ||
      self.destroyed ||
      (self._writableState && self._writableState.destroyed) ||
      self.errored ||
      state.errored
    ) {
      var endError = self.errored || state.errored || null;
      var endCallbacks = self._endCallbacks;
      self._endCallbacks = [];
      if (endCallbacks) {
        for (var d = 0; d < endCallbacks.length; d++) {
          endCallbacks[d](endError);
        }
      }
      return;
    }
    // finish fires asynchronously
    _nextTick(function() {
      if (self._destroyed || state.finished) return;
      self.writableFinished = true;
      state.finished = true;
      self.emit('finish');
      state.errorEmitted = false;
      var shouldDestroy = self._writableState.autoDestroy && !self._destroyed;
      if (self._readableState && self.readable !== false && self._readableState.readable !== false) {
        shouldDestroy = false;
      }
      if (shouldDestroy) {
        self.destroy();
      } else {
        self._close();
      }
      var callbacks = self._endCallbacks;
      self._endCallbacks = [];
      for (var j = 0; j < callbacks.length; j++) {
        callbacks[j](null);
      }
    });
  };

  var finish = function(err) {
    if (state._pendingEndScheduled) return;
    state._pendingEndScheduled = true;
    state._pendingEnd = null;
    // Call done synchronously - prefinish fires sync, finish fires async
    done(err);
  };

  var attemptFinal = function(err) {
    if (err) {
      state._pendingEnd = null;
      finish(err);
      return;
    }
    if (state._pendingEndScheduled) {
      return;
    }
    if (state.constructed === false) {
      state._pendingEnd = attemptFinal;
      state._pendingEndScheduled = true;
      return;
    }
    if (state.writing || state.bufferProcessing || (self._writeQueue && self._writeQueue.length)) {
      state._pendingEnd = attemptFinal;
      state._pendingEndScheduled = true;
      return;
    }
    if (typeof self._final === 'function') {
      state._pendingEndScheduled = true;
      try {
        self._final(function(finalErr) {
          state._pendingEndScheduled = false;
          finish(finalErr);
        });
      } catch (finalCatchErr) {
        state._pendingEndScheduled = false;
        finish(finalCatchErr);
      }
      return;
    }
    finish();
  };

  var markEnded = function() {
    if (state.ending) {
      return;
    }
    this.writableEnded = true;
    this.writable = false;
    state.ending = true;
    state.ended = true;
  }.bind(this);

  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding, function(writeErr) {
      attemptFinal(writeErr);
    });
    markEnded();
  } else {
    markEnded();
    attemptFinal();
  }

  if (this.writableCorked > 0) {
    this.writableCorked = 1;
    this.uncork();
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
  if (typeof enc !== 'string') {
    var encStr;
    if (enc === null) encStr = 'null';
    else if (enc === undefined) encStr = 'undefined';
    else if (typeof enc === 'object') {
      try { encStr = JSON.stringify(enc); } catch(e) { encStr = String(enc); }
      if (encStr === undefined) encStr = String(enc);
    } else encStr = String(enc);
    var typeErr = new TypeError('Unknown encoding: ' + encStr);
    typeErr.code = 'ERR_UNKNOWN_ENCODING';
    throw typeErr;
  }
  var normalized = enc.toLowerCase();
  var _validEncs2 = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1 };
  if (!_validEncs2[normalized]) {
    var encErr2 = new TypeError('Unknown encoding: ' + enc);
    encErr2.code = 'ERR_UNKNOWN_ENCODING';
    throw encErr2;
  }
  this._writableState.defaultEncoding = normalized;
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
  // Re-order event slots: Duplex should have close, error, prefinish, finish, drain, data, end, readable
  // Readable added data/end/readable before Writable added prefinish/finish/drain, so fix the order
  if (this._events) {
    delete this._events.data;
    delete this._events.end;
    delete this._events.readable;
    this._events.data = undefined;
    this._events.end = undefined;
    this._events.readable = undefined;
  }
  this.allowHalfOpen = !(options && options.allowHalfOpen === false);
  // Handle readable option - when readable is false, the stream is not a readable stream
  // so readableAborted should never be set to true
  if (options && options.readable === false) {
    this.readable = false;
    this.readableAborted = false;
    this._readableState.ended = true;
    this._readableState.endEmitted = true;
    this._readableState.endConsumed = true; // Prevent destroy from setting readableAborted
  }
  if (options && options.writable === false) {
    this.writable = false;
    this.writableEnded = true;
    this.writableFinished = true;
    if (this._writableState) {
      this._writableState.ended = true;
      this._writableState.ending = true;
      this._writableState.finished = true;
    }
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
          return;
        }
        _resumeWritableAfterConstruct(self);
      });
    }, 0);
  }
}
Duplex.prototype = Object.create(Readable.prototype);
// Copy Writable prototype methods and accessors to Duplex prototype
// Use getOwnPropertyDescriptor to preserve getters/setters
Object.getOwnPropertyNames(Writable.prototype).forEach(function(k) {
  if (k === 'constructor') return;
  if (Duplex.prototype.hasOwnProperty(k)) return;
  var desc = Object.getOwnPropertyDescriptor(Writable.prototype, k);
  if (desc) {
    Object.defineProperty(Duplex.prototype, k, desc);
  }
});
Duplex.prototype.constructor = Duplex;

function _transformDefaultFinal(callback) {
  var self = this;
  if (typeof self._flush === 'function' && !self.destroyed) {
    self._flush(function(err, data) {
      if (err) {
        if (typeof callback === 'function') callback(err);
        else self.destroy(err);
        return;
      }
      if (data !== undefined && data !== null) {
        self.push(data);
      }
      if (!self._readableState || !self._readableState.ended) {
        self.push(null);
      }
      if (typeof callback === 'function') callback();
    });
  } else {
    if (!self._readableState || !self._readableState.ended) {
      self.push(null);
    }
    if (typeof callback === 'function') callback();
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  if (!this._writableState) {
    Writable.call(this, options);
  }
  this._transformState = {
    pendingWrites: 0,
    finalCallback: null,
    finalizing: false,
    backpressureCallback: null
  };
  // Default _final calls _flush and push(null)
  if (options && typeof options.transform === 'function') this._transform = options.transform;
  if (options && typeof options.flush === 'function') this._flush = options.flush;
  // If user provided final via options, Writable constructor already set this._final = options.final.
  // Use prefinish to call _flush and push(null) if user has their own _final.
  // If no user final, set the default _final which calls _flush.
  var _self = this;
  var _userSetFinal = (options && typeof options.final === 'function') ||
                      (options && typeof options._final === 'function');
  if (!_userSetFinal) {
    this._final = _transformDefaultFinal;
  }
  this.on('prefinish', function() {
    if (_self._final !== _transformDefaultFinal) {
      _transformDefaultFinal.call(_self);
    }
  });
}
Transform.prototype = Object.create(Duplex.prototype);
Transform.prototype.constructor = Transform;

Transform.prototype._transform = function(chunk, encoding, callback) {
  var err = new Error('The _transform() method is not implemented');
  err.code = 'ERR_METHOD_NOT_IMPLEMENTED';
  throw err;
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
    var canPushMore = true;
    if (transformedChunk !== undefined) {
      canPushMore = self.push(transformedChunk);
    }
    if (canPushMore === false) {
      state.backpressureCallback = function() {
        finalizeIfNeeded();
        if (typeof callback === 'function') {
          callback();
        }
      };
      return;
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
    if (err && err.code === 'ERR_METHOD_NOT_IMPLEMENTED') {
      throw err;
    }
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
  if (typeof callback === 'function') callback(null, chunk);
};

Stream.prototype.pipe = function(dest, options) {
  var source = this;
  var state = source._readableState;
  var hasDrainListener = false;
  var sourceEnded = false;
  var destinationEndScheduled = false;

  if (state) {
    state.pipes.push(dest);
    state.pipesCount = state.pipes.length;
    _normalizeAwaitDrainWriters(state);
  }

  function isWritableTarget() {
    if (!dest) return false;
    if (dest.writable === false) return false;
    if (dest._destroyed) return false;
    if (dest._writableState) {
      if (
        dest._writableState.destroyed ||
        dest._writableState.ended ||
        dest._writableState.ending ||
        dest._writableState.finished
      ) return false;
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
        var writableState = dest._writableState;
        if (writableState && writableState.errored) {
          var syncWriteError = writableState.errored;
          onerror(syncWriteError);
          if (source && typeof source.destroy === 'function' && !source._destroyed) {
            source.destroy(syncWriteError);
          }
          return;
        }
        if (
          dest._destroyed ||
          dest.destroyed ||
          (writableState && writableState.destroyed)
        ) {
          var syncDestroyError = (writableState && writableState.errored) || dest.errored ||
            makeError(Error, 'ERR_STREAM_DESTROYED', 'Cannot call write after a stream was destroyed');
          onerror(syncDestroyError);
          if (source && typeof source.destroy === 'function' && !source._destroyed) {
            source.destroy(syncDestroyError);
          } else if (typeof source.pause === 'function') {
            source.pause();
          }
          return;
        }
        if (ok === false && typeof source.pause === 'function') {
          pause();
        }
      } catch (err) {
        if (err && err.code === 'ERR_STREAM_WRITE_AFTER_END') {
          unpipe();
          return;
        }
        if (typeof dest.destroy === 'function') {
          dest.destroy(err);
        } else {
          onerror(err);
        }
      }
    }
    if (sourceEnded) {
      maybeEndDestination();
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
    if (sourceEnded) {
      maybeEndDestination();
    }
  }

  function onend() {
    sourceEnded = true;
    maybeEndDestination();
  }

  function onendcleanup() {
    if (!state || (state.length === 0 && !_hasAwaitDrainWriters(state))) {
      cleanupQuietly();
    }
  }

  function canFinishDestination() {
    if (!dest || dest._destroyed) return false;
    if (dest._writableState && dest._writableState.errored) return false;
    if (dest._writableState && dest._writableState.ending) return false;
    if (dest._writableState && dest._writableState.ended) return false;
    if (typeof dest.writable === 'boolean' && dest.writable === false) return false;
    return true;
  }

  function maybeEndDestination() {
    if (!sourceEnded || destinationEndScheduled) return;
    if (!canFinishDestination()) return;
    if (options && options.end === false) return;
    if (state && state.length > 0) return;
    if (state && _hasAwaitDrainWriters(state)) return;
    if (!dest || typeof dest.end !== 'function') return;
    destinationEndScheduled = true;
    try {
      dest.end();
    } catch (_err) {
      destinationEndScheduled = false;
      onerror(_err);
    }
  }

  function cleanup() {
    unpipe(true);
  }

  function cleanupQuietly() {
    unpipe(false);
  }

  function onsourceclose() {
    if (!sourceEnded) {
      sourceEnded = true;
      maybeEndDestination();
    }
  }

  function onsourceclosecleanup() {
    if (state) {
      // Some sources (notably fs.ReadStream with autoClose) can emit `close`
      // after queueing EOF but before buffered data/backpressure has fully
      // drained through the pipe. In that case we must keep the pipe listeners
      // alive so `ondrain`/`end` can still drive the destination to `end()`.
      if (state.ended && (!state.endEmitted || state.length > 0 || _hasAwaitDrainWriters(state))) {
        return;
      }
    }
    cleanupQuietly();
  }

  function onerror(err) {
    if (dest && typeof dest.removeListener === 'function') {
      dest.removeListener('error', onerror);
    }
    if (source && typeof source.unpipe === 'function') {
      source.unpipe(dest);
    } else {
      unpipe(true);
    }

    var hasOtherErrorListeners = false;
    if (dest && typeof dest.listenerCount === 'function') {
      hasOtherErrorListeners = dest.listenerCount('error') > 0;
    } else if (dest && dest._events && dest._events.error) {
      hasOtherErrorListeners = true;
    }

    if (!hasOtherErrorListeners) {
      handlePipeError(err);
    }
  }

  // When dest closes/finishes, clean up the pipe
  function onclose() {
    cleanupQuietly();
  }

  function onfinish() {
    cleanupQuietly();
  }

  function ondestroy() {
    cleanupQuietly();
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

  function unpipe(emitUnpipe) {
    source.removeListener('data', ondata);
    source.removeListener('end', onend);
    source.removeListener('end', onendcleanup);
    source.removeListener('close', onsourceclose);
    source.removeListener('close', onsourceclosecleanup);
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
      _normalizeAwaitDrainWriters(state);
      if (state.pipes.length === 0 && typeof source.pause === 'function') {
        source.pause();
      }
      if (emitUnpipe !== false && dest && typeof dest.emit === 'function') {
        dest.emit('unpipe', source);
      }
      if (state.pipes.length === 0) {
        state.awaitDrainWriters = null;
      }
    }
    if (source._pipeCleanups && source._pipeCleanups.has(dest)) {
      var cleanups = source._pipeCleanups.get(dest);
      if (Array.isArray(cleanups)) {
        var cleanupIdx = cleanups.indexOf(unpipe);
        if (cleanupIdx !== -1) cleanups.splice(cleanupIdx, 1);
        if (cleanups.length === 0) {
          source._pipeCleanups.delete(dest);
        }
      } else {
        source._pipeCleanups.delete(dest);
      }
    }
  }

  source.on('data', ondata);
  if (state && state.endEmitted) {
    _nextTick(onend);
  } else {
    source.on('end', onend);
    source.on('end', onendcleanup);
    source.on('close', onsourceclose);
    source.on('close', onsourceclosecleanup);
  }

  // Store unpipe function for later
  if (!source._pipeCleanups) source._pipeCleanups = new Map();
  var existingCleanups = source._pipeCleanups.get(dest);
  if (!existingCleanups) {
    source._pipeCleanups.set(dest, [unpipe]);
  } else {
    existingCleanups.push(unpipe);
  }

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
  var cleanupBuckets = this._pipeCleanups;
  if (state) {
    if (state.pipesCount === 0 && (!dest || !cleanupBuckets)) return this;
  } else if (!dest || !cleanupBuckets) {
    return this;
  }

  if (!dest) {
    var dests = state && state.pipes ? state.pipes.slice() : [];
    if (state) {
      state.pipes = [];
      state.pipesCount = 0;
      state.awaitDrainWriters = null;
    }
    for (var i = 0; i < dests.length; i++) {
      var unpipeDest = dests[i];
      if (cleanupBuckets && cleanupBuckets.has(unpipeDest)) {
        var list = cleanupBuckets.get(unpipeDest);
        if (Array.isArray(list)) {
          var cleanupFn;
          while (list.length) {
            cleanupFn = list.shift();
            if (typeof cleanupFn === 'function') {
              cleanupFn();
            }
          }
      }
      cleanupBuckets.delete(unpipeDest);
    }
    }
    cleanupBuckets = null;
    this._pipeCleanups = null;
    if (typeof this.pause === 'function') {
      this.pause();
    }
    return this;
  }

  if (cleanupBuckets && cleanupBuckets.has(dest)) {
    var cleanupList = cleanupBuckets.get(dest);
    if (Array.isArray(cleanupList) && cleanupList.length) {
      var cleanupEntry = cleanupList.shift();
      if (typeof cleanupEntry === 'function') {
        cleanupEntry();
      }
    }
    if (!cleanupList.length) {
      cleanupBuckets.delete(dest);
    }
  } else if (state && state.pipes) {
    var idx = state.pipes.indexOf(dest);
    if (idx !== -1) {
      state.pipes.splice(idx, 1);
      state.pipesCount = state.pipes.length;
      _normalizeAwaitDrainWriters(state);
      if (state.pipes.length === 0) {
        state.awaitDrainWriters = null;
        if (typeof this.pause === 'function') {
          this.pause();
        }
      }
    }
    if (dest && typeof dest.emit === 'function') {
      dest.emit('unpipe', this);
    }
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
  var __pipelineDebug = (typeof process === 'object' && process && process.env &&
    process.env.EXACT_PIPELINE_DEBUG === '1') || !!(typeof process === 'object' && process && process.__exactPipelineDebug);
  var __pipelineStateDebug = typeof process === 'object' && process &&
    process.env && process.env.EXACT_PIPELINE_STATE_DEBUG === '1';
  function __pipelineGetCallerLine() {
    if (!__pipelineDebug) return 'unknown';
    var stack = new Error().stack || '';
    var lines = stack.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var match = /test-stream-pipeline\.js:(\d+):(\d+)\)/.exec(lines[i]);
      if (!match) {
        match = /upstream-test-stream-pipeline\.js:(\d+):(\d+)\)/.exec(lines[i]);
      }
      if (!match) {
        match = /test-stream-pipeline-no-asyncgen-run\.js:(\d+):(\d+)\)/.exec(lines[i]);
      }
      if (match) {
        return match[1];
      }
    }
    for (var j = 0; j < lines.length; j++) {
      var genericMatch = /\(([^()]+\.js):(\d+):(\d+)\)/.exec(lines[j]);
      if (genericMatch) {
        var file = genericMatch[1];
        if (file.indexOf('stream.js') === -1 && file.indexOf('process') === -1) {
          return genericMatch[2];
        }
      }
    }
    if (lines.length > 1 && lines[1] && lines[1].indexOf(':') !== -1) {
      var fallback = /:(\d+):(\d+)\)/.exec(lines[1]);
      if (fallback) {
        return fallback[1];
      }
    }
    if (lines.length > 2 && lines[2] && lines[2].indexOf('.js:') !== -1) {
      var markerMatch = /([^() ]+\.js:\d+:\d+)/.exec(lines[2]);
      if (markerMatch) {
        return markerMatch[1];
      }
    }
    return 'unknown';
  }
  var __pipelineDebugId = (parseInt(process.__exactPipelineId || '0', 10) + 1);
  if (typeof process === 'object' && process) {
    process.__exactPipelineId = __pipelineDebugId;
  }
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  var callback = null;
  var hasCallback = false;
  var options = null;
  var shouldPipeEnd = true;
  var error = null;
  var settled = false;
  var awaitingResult = false;
  var listeners = [];
  var streams = [];
  var __pipelineLine318Probe = false;
  var __pipelineLine318ProbeCount = 0;
  function isPipelineOptions(value) {
    return value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      typeof value.pipe !== 'function' &&
      typeof value.write !== 'function' &&
      typeof value.read !== 'function';
  }
  var __pipelineCallerLine = __pipelineGetCallerLine();
  if (__pipelineDebug) {
    console.log('pipeline', __pipelineDebugId, 'start', __pipelineCallerLine, 'streamCount', args.length);
  }
  if (__pipelineStateDebug) {
    console.log('pipeline', __pipelineDebugId, 'state-start', __pipelineCallerLine);
  }
  __pipelineLine318Probe = __pipelineStateDebug && __pipelineCallerLine === '318';
  if (__pipelineLine318Probe) {
    console.log('pipeline', __pipelineDebugId, 'enable-line318-probe');
  }
  if (typeof args[args.length - 1] === 'function') {
    callback = args.pop();
    hasCallback = true;
  } else {
    var invalidCallbackCandidate = args[args.length - 1];
    var receivedMessage = 'undefined';
    if (typeof invalidCallbackCandidate === 'string') {
      receivedMessage = "type string ('" + invalidCallbackCandidate + "')";
    } else if (invalidCallbackCandidate === null) {
      receivedMessage = 'null';
    } else if (typeof invalidCallbackCandidate === 'function') {
      receivedMessage = 'an instance of Function';
    } else if (typeof invalidCallbackCandidate === 'object') {
      var callbackCandidateType = invalidCallbackCandidate && invalidCallbackCandidate.constructor &&
        invalidCallbackCandidate.constructor.name
        ? invalidCallbackCandidate.constructor.name
        : typeof invalidCallbackCandidate;
      receivedMessage = 'an instance of ' + callbackCandidateType;
    } else {
      receivedMessage = 'type ' + typeof invalidCallbackCandidate;
    }
    throw makeError(
      TypeError,
      'ERR_INVALID_ARG_TYPE',
      'The "streams[stream.length - 1]" property must be of type function. Received ' + receivedMessage
    );
  }
  if (hasCallback && args.length > 1 && isPipelineOptions(args[args.length - 1])) {
    options = args.pop();
  }

  try {
  var parsedArrayAsStreams = false;
  if (Array.isArray(args[0])) {
    var isArrayOfStreams = true;
    if (args[0].length <= 1) {
      isArrayOfStreams = false;
    }
    for (var i = 0; i < args[0].length; i++) {
      if (!_isReadableLike(args[0][i]) && !_isWritableLike(args[0][i])) {
        isArrayOfStreams = false;
        break;
      }
    }
    if (isArrayOfStreams) {
      streams = args[0];
      parsedArrayAsStreams = true;
      if (args.length > 2) {
        var invalidOptionsValue = args[1];
        throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received ' + (typeof invalidOptionsValue));
      }
      if (args.length > 1) {
        if (!isPipelineOptions(args[1])) {
          throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received ' + (typeof args[1]));
        }
        options = args[1];
      }
    }
  }
  if (!parsedArrayAsStreams) {
    var lastArg = args[args.length - 1];
    if (args.length > 1 && isPipelineOptions(lastArg)) {
      options = args.pop();
    }
    streams = args;
  }
  for (var transform = 0; transform < streams.length; transform++) {
    if (typeof streams[transform] === 'function') {
      streams[transform] = Duplex.from(streams[transform]);
    } else if (
      streams[transform] &&
      !_isReadableLike(streams[transform]) &&
      !_isWritableLike(streams[transform]) &&
      (typeof streams[transform][Symbol.asyncIterator] === 'function' ||
      typeof streams[transform][Symbol.iterator] === 'function')
    ) {
      streams[transform] = Readable.from(streams[transform]);
    }
  }
  streams = streams.slice();

  if (options && options.signal != null && typeof options.signal !== 'object') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" argument must be of type AbortSignal. Received ' + options.signal);
  }
  if (options && options.end === false) {
    shouldPipeEnd = false;
  }
  if (streams.length < 2) {
    if (streams.length === 1 && (!_isReadableLike(streams[0]) && !_isWritableLike(streams[0]))) {
      var receivedValue = streams[0];
      var receivedType = typeof receivedValue === 'undefined' ? 'undefined' : typeof receivedValue;
      throw makeError(
        TypeError,
        'ERR_INVALID_ARG_TYPE',
        'The "streams[stream.length - 1]" property must be of type function. Received ' + receivedType
      );
    }
    throw makeError(Error, 'ERR_MISSING_ARGS', 'The "streams" argument must be specified');
  }

  var signal = options && options.signal;
  var last = streams[streams.length - 1];
  var lastAppearsEarlier = false;
  for (var la = 0; la < streams.length - 1; la++) {
    if (streams[la] === last) {
      lastAppearsEarlier = true;
      break;
    }
  }

  function normalizePipelineError(err) {
    if (!err) return err;
    if (err.code) return err;
    return _normalizePrematureCloseError(err);
  }

  function destroyAll(err) {
    for (var i = 0; i < streams.length; i++) {
      if (streams[i] && typeof streams[i].destroy === 'function' && !streams[i]._destroyed) {
        streams[i].destroy(err);
      }
    }
  }

  function addListener(stream, event, handler) {
    if (!stream || typeof stream.on !== 'function' || typeof stream.removeListener !== 'function') return;
    if (typeof handler !== 'function') return;
    stream.on(event, handler);
    listeners.push([stream, event, handler]);
  }

  function addPairCloseGuard(src, dst) {
  var state = {
    src: src,
    dst: dst,
    ended: false
  };
  if (!src || !dst) return state;

  addListener(src, 'end', function() {
    state.ended = true;
  });
  addListener(src, 'close', function() {
    state.ended = true;
  });
  addListener(src, 'error', function() {
    state.ended = true;
  });
  addListener(dst, 'close', function() {
    if (state.ended) return;
    _nextTick(function() {
      if (!state.ended) {
        onError(makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close'));
      }
    });
  });
  return state;
}

function isReadableDone(stream) {
  if (!stream) return true;
  if (stream.closed === true) return true;
  if (stream._readableState && stream._readableState.destroyed) {
    if (!stream.closed) return false;
    return true;
  }
  if (stream._destroyed || stream.destroyed || (stream._writableState && stream._writableState.destroyed)) {
    return false;
  }
  if (stream._readableState) {
    if (stream.readable === false && !stream._writableState) return false;
    if (stream._readableState.endEmitted || stream._readableState.ended) return true;
    if (stream.readable === false && stream._writableState) {
      if (stream.writableEnded || stream._writableState.finished || stream._writableState.ended) {
        return true;
      }
      return false;
    }
    return false;
  }
  if (stream.readable === false) return true;
  return !_isReadableLike(stream);
}

function isWritableDone(stream) {
  if (stream && stream.closed === true) return true;
  if (
    stream._destroyed ||
    stream.destroyed ||
    (stream._readableState && stream._readableState.destroyed) ||
    (stream._writableState && stream._writableState.destroyed)
  ) return true;
  if (!stream) return true;
  if (stream._writableState) {
    var writableState = stream._writableState;
    var done = writableState.finished || (
      writableState.ended &&
      !writableState.ending
    );
    return done;
  }
  if (stream.writable === false) return true;
  if (stream.writableEnded || stream.writableFinished) return true;
  return !_isWritableLike(stream);
}

function isStreamDone(stream) {
  if (!stream) return true;
  var readableDone = !_isReadableLike(stream) || isReadableDone(stream);
  var writableDone = !_isWritableLike(stream) || isWritableDone(stream);
  if (!shouldPipeEnd && stream === last) {
    writableDone = true;
  }
  if (stream === streams[0] && stream._isPipelineFunction) {
    writableDone = true;
  }
  if (stream === streams[0] && stream._readableState && stream._writableState) {
    writableDone = true;
  }
  if (stream === last) {
    readableDone = true;
  }
  return readableDone && writableDone;
}

  function getStreamError(stream) {
    if (!stream) return null;
    if (stream._readableState && stream._readableState.errored) return stream._readableState.errored;
    if (stream._writableState && stream._writableState.errored) return stream._writableState.errored;
    return stream.errored || null;
  }

  function getAnyStreamError() {
    for (var errIndex = 0; errIndex < streamErrors.length; errIndex++) {
      var streamError = getStreamError(streamErrors[errIndex]);
      if (streamError) {
        return normalizePipelineError(streamError);
      }
    }
    return null;
  }

  function allStreamsDone() {
    if (__pipelineStateDebug && __pipelineCallerLine === '318' && streamErrors && streamErrors.length) {
      console.log(
        'pipeline',
        __pipelineDebugId,
        'allStreamsDone check start',
        streamErrors.length
      );
    }
  for (var i = 0; i < streamErrors.length; i++) {
    var stream = streamErrors[i];
    var readableDone = !_isReadableLike(stream) || isReadableDone(stream);
    var writableDone = !_isWritableLike(stream) || isWritableDone(stream);
    var streamIsFirst = stream === streams[0];
    if (stream === last && !shouldPipeEnd) {
      writableDone = true;
    }
    if (stream === last) {
      readableDone = true;
    }
    if (streamIsFirst && stream && stream._isPipelineFunction) {
      writableDone = true;
    }
    if (streamIsFirst && stream && stream._readableState && stream._writableState) {
      writableDone = true;
    }
    if (__pipelineStateDebug && __pipelineCallerLine === '318') {
      var ws = stream && stream._writableState;
      var rs = stream && stream._readableState;
        console.log(
          'pipeline',
          __pipelineDebugId,
          'streamState',
          i,
          'rd',
          stream && stream.readable,
          !!(rs && rs.ended),
          !!(rs && rs.endEmitted),
          !!(rs && rs.destroyed),
          'wr',
          stream && stream.writable,
          !!(ws && ws.finished),
          !!(ws && ws.ended),
          !!(ws && ws.ending),
          !!(ws && ws._pendingEndScheduled),
          'destroyed',
          !!(stream && (stream.destroyed || stream._destroyed))
        );
      }
      if (!readableDone || !writableDone) {
        return false;
      }
    }
    return true;
  }

  function logLine318States(label) {
    if (!__pipelineLine318Probe || !streamErrors || !streamErrors.length) return;
    var line = label || '';
    console.log(
      'pipeline',
      __pipelineDebugId,
      'state',
      __pipelineCallerLine,
      line
    );
    for (var i = 0; i < streamErrors.length; i++) {
      var stream = streamErrors[i];
      var ws = stream && stream._writableState;
      var rs = stream && stream._readableState;
      console.log(
        'pipeline',
        __pipelineDebugId,
        'stream',
        i,
        'rd',
        stream && stream.readable,
        !!(rs && rs.ended),
        !!(rs && rs.endEmitted),
        !!(rs && rs.destroyed),
        'wr',
        stream && stream.writable,
        !!(ws && ws.finished),
        !!(ws && ws.ended),
        !!(ws && ws.ending),
        !!(ws && ws._pendingEndScheduled),
        !!(ws && ws.destroyed),
        !!(stream && (stream.destroyed || stream._destroyed))
      );
    }
  }

  function allStreamsDestroyed() {
    var allDestroyed = true;
    for (var i = 0; i < streamErrors.length; i++) {
      var stream = streamErrors[i];
      if (!stream) continue;
      if (
        !stream.destroyed &&
        !stream._destroyed &&
        !(stream._readableState && stream._readableState.destroyed) &&
        !(stream._writableState && stream._writableState.destroyed)
      ) {
        allDestroyed = false;
        break;
      }
    }
    return allDestroyed;
  }

  function allStreamsClosed() {
    for (var i = 0; i < streamErrors.length; i++) {
      var stream = streamErrors[i];
      if (!stream || stream.closed !== true) {
        return false;
      }
    }
    return true;
  }

  function scheduleLine318Probe() {
    if (!__pipelineLine318Probe || settled || __pipelineLine318ProbeCount > 20) return;
    logLine318States('probe-' + __pipelineLine318ProbeCount);
    __pipelineLine318ProbeCount += 1;
    setTimeout(function() {
      scheduleLine318Probe();
    }, 250);
  }

  var errorSettleAttempts = 0;
  function settleAfterError() {
    if (settled || awaitingResult) return;
    var allDone = allStreamsDone();
    var allClosed = allStreamsClosed();
    var allDestroyed = allStreamsDestroyed();
    if (allDone || allClosed) {
      if (allDone && !allClosed && allDestroyed && errorSettleAttempts < 50) {
        errorSettleAttempts += 1;
        var fastScheduler = typeof setTimeout === 'function' ? function(fn) { setTimeout(fn, 1); } : function(fn) { setTimeout(fn, 0); };
        fastScheduler(settleAfterError);
        return;
      }
      settle(error);
      return;
    }
    if (errorSettleAttempts > 500) {
      settle(error);
      return;
    }
    errorSettleAttempts += 1;
    var scheduler = typeof setTimeout === 'function' ? function(fn) { setTimeout(fn, 1); } : function(fn) { setTimeout(fn, 0); };
    scheduler(settleAfterError);
  }

  function connectWithoutPipe(src, dst, shouldPipeEnd) {
    if (!src || !dst || typeof src.on !== 'function' || typeof dst.write !== 'function') return false;
    var ended = false;
    var awaitingDrain = false;
    function isDestinationWritable() {
      if (!dst || dst.writable === false) return false;
      if (dst._destroyed || dst.destroyed) return false;
      if (!dst._writableState) return true;
      if (dst._writableState.destroyed || dst._writableState.ending || dst._writableState.ended || dst._writableState.finished) return false;
      if (dst._writableState.writable === false) return false;
      return true;
    }
    function endDestination() {
      if (ended) return;
      ended = true;
      if (shouldPipeEnd && typeof dst.end === 'function') {
        try {
          dst.end();
        } catch (_err) {
          onError(_err);
        }
      }
    }
    function onDrain() {
      awaitingDrain = false;
      if (typeof src.resume === 'function') src.resume();
      if (dst && typeof dst.removeListener === 'function') {
        dst.removeListener('drain', onDrain);
      }
    }
    function onData(chunk) {
      if (ended || settled || error) return;
      if (!isDestinationWritable()) {
        if (typeof dst !== 'undefined' && dst && typeof dst.destroy === 'function') {
          endDestination();
        }
        return;
      }
      var canContinue = true;
      var wrote = false;
      var onWrite = function(err) {
        if (err) {
          onError(err);
        }
        wrote = true;
      };
      try {
        canContinue = dst.write(chunk, 'utf8', onWrite);
      } catch (_err) {
        onError(_err);
        return;
      }
      if (!wrote && dst && dst._writableState && dst._writableState.writing) {
        wrote = true;
      }
      if (canContinue === false) {
        if (typeof src.pause === 'function') {
          src.pause();
        }
        if (dst && typeof dst.on === 'function' && !awaitingDrain) {
          addListener(dst, 'drain', onDrain);
        }
        awaitingDrain = true;
      }
    }
    addListener(src, 'data', onData);
    addListener(src, 'end', endDestination);
    addListener(src, 'close', endDestination);
    if (dst && dst.writableNeedDrain === true) {
      if (typeof src.pause === 'function') {
        src.pause();
      }
      if (typeof dst.on === 'function' && !awaitingDrain) {
        addListener(dst, 'drain', onDrain);
      }
      awaitingDrain = true;
    }
    if (!awaitingDrain && typeof src.resume === 'function') {
      src.resume();
    }
    return true;
  }

  function cleanup() {
    for (var li = 0; li < listeners.length; li++) {
      listeners[li][0].removeListener(listeners[li][1], listeners[li][2]);
    }
    listeners = [];
    if (signal && signal.removeEventListener) {
      signal.removeEventListener('abort', onAbort);
    } else if (signal && signal.removeListener) {
      signal.removeListener('abort', onAbort);
    }
  }

  function settle(err) {
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'settle', err && (err.message || err.code || err));
    }
    if (settled) return;
    if (awaitingResult) return;
    if (err) {
      error = err;
    } else if (!error) {
      error = getAnyStreamError();
    }
    var lastResult = last && last._pipelineResult;
    if (lastResult && typeof lastResult.then === 'function') {
      awaitingResult = true;
    var scheduleSettle = _nextTick;
      if (__pipelineDebug) {
        console.log('pipeline', __pipelineDebugId, 'awaitingResult');
      }
    lastResult.then(function(value) {
      awaitingResult = false;
      if (__pipelineDebug) {
        console.log('pipeline', __pipelineDebugId, 'resultThen', value);
      }
      scheduleSettle(function() {
        settleWithResult(error, value);
      });
      }, function(pipelineErr) {
        awaitingResult = false;
        settleWithResult(error || pipelineErr);
      });
      return;
    }
    settleWithResult(error);
  }

  function settleWithResult(finalErr, finalValue) {
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'settleWithResult', finalErr && (finalErr.message || finalErr.code || finalErr));
    }
    if (settled) return;
    settled = true;
    cleanup();
    finalErr = normalizePipelineError(finalErr);
    if (finalErr) {
      if (typeof callback === 'function') {
        callback(finalErr);
      }
      return;
    }
    if (typeof callback === 'function') {
      callback(undefined, finalValue);
      return;
    }
  }

  function onError(err) {
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'onError', err && (err.message || err.code || err));
    }
    if (error) return;
    error = normalizePipelineError(err);
    destroyAll(error);
    settleAfterError();
  }

  function onFinish() {
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'onFinish start', settled ? 'settled' : 'open', error ? 'error' : 'ok');
    }
    if (settled || error) return;
    if (lastAppearsEarlier) return;
    if (!allStreamsDone()) return;
    var finalError = getAnyStreamError();
    if (finalError) {
      settle(finalError);
      return;
    }
    var scheduler = _nextTick;
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'onFinish scheduling settle');
    }
    scheduler(function() {
      if (settled || error) return;
      if (__pipelineDebug) {
        console.log('pipeline', __pipelineDebugId, 'onFinish delayed settle');
      }
      settle(getAnyStreamError());
    });
  }

  function onClose(stream) {
    if (__pipelineDebug) {
      console.log('pipeline', __pipelineDebugId, 'onClose', stream === last ? 'last' : 'other');
    }
    if (settled || error) return;
    var streamError = getAnyStreamError() || getStreamError(stream);
    if (streamError) {
      onError(streamError);
      return;
    }
    var scheduler = function(fn) { setTimeout(fn, 1); };
    scheduler(function() {
      if (settled || error) return;
      if (__pipelineDebug) {
        console.log('pipeline', __pipelineDebugId, 'onClose delayed');
      }
      var delayedStreamError = getAnyStreamError() || getStreamError(stream);
      if (delayedStreamError) {
        onError(delayedStreamError);
        return;
      }
      if (!isStreamDone(stream)) {
        onError(makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close'));
      } else if ((stream === last || allStreamsDone()) && !settled && !error) {
        settle(null);
      }
    });
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
      return;
    }
    if (signal.addEventListener) {
      signal.addEventListener('abort', onAbort);
    } else if (signal.addListener) {
      signal.addListener('abort', onAbort);
    }
  }

  var streamErrors = streams.slice(0);
  if (__pipelineLine318Probe) {
    scheduleLine318Probe();
  }
  for (var i = 0; i + 1 < streams.length; i++) {
    var src = streams[i];
    var dst = streams[i + 1];
    var shouldPipeEndForThisPair = i + 1 === streams.length - 1 ? shouldPipeEnd : true;
    addPairCloseGuard(src, dst);
    if (typeof src.pipe === 'function') {
      try {
        src.pipe(dst, { end: shouldPipeEndForThisPair });
      } catch (err) {
        onError(err);
        break;
      }
    } else if (!connectWithoutPipe(src, dst, shouldPipeEndForThisPair)) {
      onError(makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams[' + (i + 1) + ']" argument must be of type Stream. Received ' + typeof dst));
      break;
    }
  }
  var seen = [];
  for (var se = 0; se < streamErrors.length; se++) {
    if (seen.indexOf(streamErrors[se]) === -1) {
      addListener(streamErrors[se], 'error', onError);
      addListener(streamErrors[se], 'close', function closeHandlerForStream(stream) {
        return function() {
          onClose(stream);
        };
      }(streamErrors[se]));
      addListener(streamErrors[se], 'end', onFinish);
      addListener(streamErrors[se], 'finish', onFinish);
      seen.push(streamErrors[se]);
    }
  }

  addListener(last, 'finish', onFinish);
  addListener(last, 'end', onFinish);
  addListener(last, 'close', function() {
    onClose(last);
  });
  return last;
  } catch (err) {
    throw err;
  }
}

function finished(stream, options, callback) {
  if (
    arguments.length < 3 &&
    callback === undefined &&
    options !== undefined &&
    options !== null &&
    typeof options !== 'function' &&
    typeof options !== 'object'
  ) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "callback" argument must be of type function. Received ' + typeof options);
  }
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
     typeof stream.read === 'function' ||
     stream.complete === true)
  );
  var hasWritableCapability = !!(
    stream &&
    (stream._writableState ||
     typeof stream.write === 'function' ||
     typeof stream.end === 'function')
  );
  var isLegacyStream = !!(
    stream &&
    stream instanceof Stream &&
    !hasReadableCapability &&
    !hasWritableCapability
  );

  // Validate that the first argument is a stream
  if (!stream || (!hasReadableCapability && !hasWritableCapability && !isLegacyStream)) {
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
  var aborted = !!(
    stream.aborted === true ||
    stream.readableAborted === true ||
    stream.writableAborted === true
  );

  function isReadableDone() {
    return !shouldWaitReadable ||
      stream.readableEnded ||
      stream.complete === true ||
      (stream._readableState && stream._readableState.endEmitted);
  }

  function isWritableDone() {
    return !shouldWaitWritable ||
      stream.writableFinished;
  }

  function isReadableClosedCleanly() {
    var state = stream._readableState;
    return !shouldWaitReadable ||
      stream.readableEnded ||
      stream.complete === true ||
      (state &&
        (state.endEmitted ||
         (state.ended &&
          state.length === 0 &&
          !state.errored &&
          !stream.errored &&
          !stream.destroyed)));
  }

  function isWritableClosedCleanly() {
    var state = stream._writableState;
    return !shouldWaitWritable ||
      stream.writableFinished ||
      (state &&
        state.finished &&
        !state.errored &&
        !stream.errored);
  }

  function getCurrentError() {
    if (!shouldEmitError) return null;
    if (error) return error;
    if (stream._readableState && stream._readableState.errored && stream._readableState.errored !== true) {
      return stream._readableState.errored;
    }
    if (stream._writableState && stream._writableState.errored && stream._writableState.errored !== true) {
      return stream._writableState.errored;
    }
    if (stream.errored && stream.errored !== true) return stream.errored;
    return null;
  }

  var cleanup = function() {};
  function done(err) {
    if (called) return;
    if (err == null) {
      err = undefined;
    } else {
      error = err;
    }
    called = true;
    if (shouldCleanup) {
      cleanup();
    }
    if (typeof callback === 'function') callback(err);
  }

  var onFinish = function() {
    var readableDone = isReadableDone();
    var writableDone = isWritableDone();
    if (aborted && !(stream._closed || stream.closed)) {
      return;
    }
    if (readableDone && writableDone) {
      done(null);
    }
  };
  var onEnd = function() { onFinish(); };
  var onAborted = function() {
    aborted = true;
  };
  var onError = function(err) {
    if (shouldEmitError) {
      if (!suppressClose && !(stream._closed || stream.closed)) {
        error = err || error;
        return;
      }
      done(err);
    }
  };
  var closeQueued = false;
  var onClose = function() {
    if (closeQueued) return;
    closeQueued = true;
    var readableDone = isReadableClosedCleanly();
    var writableDone = isWritableClosedCleanly();
    _nextTick(function() {
      closeQueued = false;
      if (called) return;
      var currentError = getCurrentError();
      if (currentError) {
        done(currentError);
        return;
      }
      if (!readableDone || !writableDone) {
        var prematureErr = new Error('premature close');
        prematureErr.code = 'ERR_STREAM_PREMATURE_CLOSE';
        done(prematureErr);
      } else {
        done(null);
      }
    });
  };

  function onSignalAbort() {
    var err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    done(err);
  }

  if (shouldWaitReadable && stream.on) {
    stream.on('end', onEnd);
  }
  if (shouldWaitWritable && stream.on) {
    stream.on('finish', onFinish);
  }
  if (stream.on) {
    stream.on('error', onError);
    stream.on('close', onClose);
    stream.on('aborted', onAborted);
  }

  // Return cleanup function
  cleanup = function() {
    if (stream.removeListener) {
      stream.removeListener('end', onEnd);
      stream.removeListener('finish', onFinish);
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
      stream.removeListener('aborted', onAborted);
    }
    if (options && options.signal && typeof options.signal.removeEventListener === 'function') {
      options.signal.removeEventListener('abort', onSignalAbort);
    }
  };

  // AbortSignal support
  if (options.signal) {
    options.signal.addEventListener('abort', onSignalAbort);
    if (options.signal.aborted) {
      onSignalAbort();
    }
  }

  function makePrematureCloseError() {
    var prematureErr = new Error('premature close');
    prematureErr.code = 'ERR_STREAM_PREMATURE_CLOSE';
    return prematureErr;
  }

  function hasNoPendingCallbacks(state) {
    return !state || state.pendingcb === undefined || state.pendingcb === 0;
  }

  var immediateError = getCurrentError();
  var suppressClose = !!(
    (stream._readableState && stream._readableState.emitClose === false) ||
    (stream._writableState && stream._writableState.emitClose === false)
  );
  var alreadyClosed = !!(stream._closed || stream.closed || (stream._destroyed && suppressClose));
  if (immediateError) {
    if (alreadyClosed || suppressClose) {
      done(immediateError);
    }
  } else if (
    !isLegacyStream &&
    !shouldWaitReadable &&
    !stream._composePending &&
    (suppressClose || Stream.isReadable(stream)) &&
    (isWritableDone() || Stream.isWritable(stream) === false) &&
    hasNoPendingCallbacks(stream._writableState)
  ) {
    _nextTick(function() {
      if (!called) done(null);
    });
  } else if (!isLegacyStream && alreadyClosed && !stream._composePending) {
    done(isReadableClosedCleanly() && isWritableClosedCleanly() ? null : makePrematureCloseError());
  } else if (!isLegacyStream && (isReadableDone() && isWritableDone()) && !stream._composePending) {
    done(null);
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
  if (args.length === 0) {
    throw makeError(TypeError, 'ERR_MISSING_ARGS', 'The "streams" argument must be specified');
  }
  if (args.length === 1) {
    if (typeof args[0] === 'function') {
      return Duplex.from(args[0]);
    }
    return args[0];
  }

  var normalized = [];
  var typeHints = [];
  for (var ni = 0; ni < args.length; ni++) {
    var stage = args[ni];
    if (typeof stage === 'function') {
      stage = Duplex.from(stage, _inferComposeFunctionOptions(args, ni));
    } else if (!stage || (typeof stage !== 'object' && typeof stage !== 'function')) {
      var invalidStageErr = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams" argument must be a stream.');
      throw invalidStageErr;
    } else if (stage && typeof stage.pipe !== 'function') {
      try {
        stage = Duplex.from(stage);
      } catch (_err) {
        // Fall through to the standardized type error below.
      }
    }
    typeHints.push(typeof args[ni] === 'function');
    if (!stage || typeof stage.pipe !== 'function') {
      var pipeErr = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams" argument must be a stream.');
      throw pipeErr;
    }
    normalized.push(stage);
  }

  var first = normalized[0];
  var last = normalized[normalized.length - 1];

  for (var vi = 0; vi < normalized.length; vi++) {
    if (vi < normalized.length - 1 && !_stageCanRead(normalized[vi])) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_VALUE', 'The "streams" argument must contain readable streams before the last stage.');
    }
    if (vi > 0 && !_stageCanWrite(normalized[vi])) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_VALUE', 'The "streams" argument must contain writable streams after the first stage.');
    }
  }

  for (var ci = 0; ci + 1 < normalized.length; ci++) {
    _ensureComposeStageReadableEnd(normalized[ci]);
  }

  // Pipe all streams together
  for (var j = 0; j + 1 < normalized.length; j++) {
    if (typeof normalized[j + 1].write !== 'function') {
      var writeErr = makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "streams" argument must have a writable stream in the middle.');
      throw writeErr;
    }
    normalized[j].pipe(normalized[j + 1]);
  }

  // Create a Duplex that writes to first and reads from last
  var composedReadableObjectMode = _readableObjectModeOf(last);
  var composedWritableObjectMode = _writableObjectModeOf(first);
  var composedReadable = !!(last && last._readableState && last.readable !== false);
  var composedWritable = !!(first && first._writableState && first.writable !== false);
  var composed = new Duplex({
    readableObjectMode: composedReadableObjectMode,
    writableObjectMode: composedWritableObjectMode,
    destroy: function(err, callback) {
      for (var di = 0; di < normalized.length; di++) {
        var inner = normalized[di];
        if (!inner || inner === this || typeof inner.destroy !== 'function') continue;
        if (inner._destroyed || inner.destroyed) continue;
        try {
          inner.destroy(err);
        } catch (_destroyErr) {}
      }
      if (typeof callback === 'function') callback(err);
    },
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
            if (ok === false && first && first._writableState && (!first._writableState.needDrain && !first._needDrain && !first.writableNeedDrain)) {
              ok = true;
            }
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
      var lastCleanup = null;
      var waitingForLastFinish = false;
      var finish = function(err) {
        if (done) return;
        done = true;
        if (typeof lastCleanup === 'function') {
          lastCleanup();
          lastCleanup = null;
        }
        if (typeof callback === 'function') callback(err);
      };
      try {
        if (last && last !== first && typeof last.on === 'function' && _stageCanWrite(last)) {
          waitingForLastFinish = true;
          lastCleanup = finished(last, { readable: false }, function(err) {
            waitingForLastFinish = false;
            finish(err);
          });
        }
        if (typeof first.end === 'function') {
          first.end(function(err) {
            if (err) {
              if (typeof first.destroy === 'function') first.destroy(err);
              finish(err);
              return;
            }
            if (!waitingForLastFinish) {
              finish();
            }
          });
        } else {
          if (!waitingForLastFinish) {
            finish();
          }
        }
      } catch (err) {
        finish(err);
      }
    },
    read: function() {}
  });

  composed.readable = composedReadable;
  composed.writable = composedWritable;
  composed._composePending = !composedReadable && !composedWritable;

  // Forward data from last stream to composed
  if (composedReadable && last && typeof last.on === 'function') {
    var scheduleEnd = _nextTick;
    function finalizeComposedReadableEnd() {
      var composedError = composed.errored ||
        (composed._readableState && composed._readableState.errored) ||
        (composed._writableState && composed._writableState.errored);
      if (composedError || composed._destroyed || composed.destroyed) return;
      for (var ui = 0; ui < normalized.length - 1; ui++) {
        var upstream = normalized[ui];
        if (!upstream || upstream.readable === false || !upstream._readableState) continue;
        if (upstream._readableState.errored) return;
        if (!upstream._readableState.ended && !upstream._readableState.endEmitted) {
          scheduleEnd(finalizeComposedReadableEnd);
          return;
        }
      }
      composed.push(null);
    }
    last.on('data', function(chunk) {
      composed.push(chunk);
    });
    last.on('end', function() {
      scheduleEnd(finalizeComposedReadableEnd);
    });
  }

  if (composed._composePending && last && typeof last.on === 'function') {
    var finalizeComposed = function() {
      if (!composed._composePending || composed._destroyed || composed.destroyed) return;
      composed._composePending = false;
      if (typeof composed._close === 'function') {
        composed._close(true);
      } else {
        composed.emit('close');
      }
    };
    if (last._pipelineResult && typeof last._pipelineResult.then === 'function') {
      last._pipelineResult.then(finalizeComposed, function(err) {
        safeDestroyComposed(err);
      });
    } else {
      last.on('finish', finalizeComposed);
      last.on('close', finalizeComposed);
    }
  }

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
  if (!signal || typeof signal !== 'object' || typeof signal.aborted !== 'boolean') {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" argument must be of type AbortSignal.');
  }
  if (
    !stream ||
    (typeof stream.destroy !== 'function' &&
      typeof stream.on !== 'function' &&
      typeof stream.read !== 'function' &&
      !Stream.isReadable(stream) &&
      !Stream.isWritable(stream))
  ) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be an instance of Stream. Received ' + (stream === null ? 'null' : typeof stream));
  }
  return addAbortSignalNoValidate(signal, stream);
}

function addAbortSignalNoValidate(signal, streamInstance) {
  if (!streamInstance) return streamInstance;

  if (!signal || typeof signal !== 'object' || typeof signal.aborted === 'undefined') {
    return streamInstance;
  }

  var listener;
  var onAbort = function() {
    if (streamInstance && !streamInstance._destroyed) {
      var abortErr = _createAbortError(signal.reason);
      if (typeof streamInstance.destroy === 'function') {
        streamInstance.destroy(abortErr);
      }
    }
  };

  if (typeof signal.addEventListener === 'function') {
    listener = function() {
      signal.removeEventListener('abort', listener);
      onAbort();
    };
    if (signal.aborted) {
      listener();
      return streamInstance;
    }
    signal.addEventListener('abort', listener);
  } else if (typeof signal.addListener === 'function') {
    listener = function() {
      signal.removeListener('abort', listener);
      onAbort();
    };
    if (signal.aborted) {
      listener();
      return streamInstance;
    }
    signal.addListener('abort', listener);
  }

  if (typeof streamInstance.once === 'function') {
    streamInstance.once('close', function cleanupAbortSignal() {
      if (signal && typeof signal.removeEventListener === 'function' && listener) {
        signal.removeEventListener('abort', listener);
      } else if (typeof signal.removeListener === 'function' && listener) {
        signal.removeListener('abort', listener);
      }
    });
  }
  if (typeof streamInstance.on === 'function' && typeof streamInstance.removeListener === 'function') {
    streamInstance.on('finish', function cleanupAbortSignalFinish() {
      if (signal && typeof signal.removeEventListener === 'function' && listener) {
        signal.removeEventListener('abort', listener);
      } else if (typeof signal.removeListener === 'function' && listener) {
        signal.removeListener('abort', listener);
      }
      streamInstance.removeListener('finish', cleanupAbortSignalFinish);
    });
  }

  return streamInstance;
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
Stream.addAbortSignalNoValidate = addAbortSignalNoValidate;
Stream.getDefaultHighWaterMark = Readable.getDefaultHighWaterMark;
Stream.setDefaultHighWaterMark = Readable.setDefaultHighWaterMark;

// destroy() — standalone function to destroy a stream
Stream.destroy = function destroy(stream, err) {
  if (!stream || typeof stream.destroy !== 'function') return stream;
  // When called without an error, the standalone destroy() emits AbortError
  if (err === undefined) {
    var abortErr = new Error('The operation was aborted');
    abortErr.code = 'ABORT_ERR';
    abortErr.name = 'AbortError';
    stream.destroy(abortErr);
  } else {
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
  if (writer && writer.closed && typeof writer.closed.catch === 'function' && !writer.__exactWebStreamWriterClosedHandled) {
    _markPromiseHandled(writer.closed);
    writer.__exactWebStreamWriterClosedHandled = true;
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
    if (args.length > 0 && typeof args[args.length - 1] === 'function') {
      return _markPromiseHandled(Promise.reject(new TypeError('The callback argument is not supported')));
    }
    return _markPromiseHandled(new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) reject(err);
        else resolve();
      });
      try {
        pipeline.apply(null, args);
      } catch (err) {
        reject(err);
      }
    }));
  },
  finished: function(stream, opts) {
    if (typeof opts === 'function') {
      return _markPromiseHandled(Promise.reject(new TypeError('The callback argument is not supported')));
    }
    if (opts !== undefined && opts !== null && typeof opts !== 'object') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be of type object. Received ' + (typeof opts));
    }
    if (opts && typeof opts.cleanup !== 'undefined' && typeof opts.cleanup !== 'boolean') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "cleanup" argument must be of type boolean. Received ' + typeof opts.cleanup);
    }
    return _markPromiseHandled(new Promise(function(resolve, reject) {
      try {
        finished(stream, opts || {}, function(err) {
          if (err) reject(err);
          else resolve();
        });
      } catch (err) {
        reject(err);
      }
    }));
  }
};

if (kPromisifyCustom) {
  Stream.pipeline[kPromisifyCustom] = Stream.promises.pipeline;
  Stream.finished[kPromisifyCustom] = Stream.promises.finished;
}

Stream.consumers = {
  text: function(stream, options) { return _textStreamConsumer(stream, options); },
  json: function(stream, options) { return _jsonStreamConsumer(stream, options); },
  buffer: function(stream, options) { return _bufferStreamConsumer(stream, options); },
  arrayBuffer: function(stream, options) { return _arrayBufferStreamConsumer(stream, options); },
  blob: function(stream, options) { return _blobStreamConsumer(stream, options); }
};

// duplexPair - creates a pair of connected Duplex streams
function duplexPair(options) {
  var d1 = new Duplex(Object.assign({ objectMode: true }, options));
  var d2 = new Duplex(Object.assign({ objectMode: true }, options));
  d1._write = function(chunk, enc, cb) {
    if (!d2.push(chunk)) {
      d1._readableState.awaitDrainWriters = d2;
    }
    cb();
  };
  d2._write = function(chunk, enc, cb) {
    if (!d1.push(chunk)) {
      d2._readableState.awaitDrainWriters = d1;
    }
    cb();
  };
  d1._read = function() {
    if (d2._readableState && d2._readableState.awaitDrainWriters === d1) {
      d2._readableState.awaitDrainWriters = null;
    }
  };
  d2._read = function() {
    if (d1._readableState && d1._readableState.awaitDrainWriters === d2) {
      d1._readableState.awaitDrainWriters = null;
    }
  };
  d1.on('end', function() { d2.push(null); });
  d2.on('end', function() { d1.push(null); });
  d1._final = function(cb) {
    d2.push(null);
    cb();
  };
  d2._final = function(cb) {
    d1.push(null);
    cb();
  };
  return [d1, d2];
}

Stream.duplexPair = duplexPair;
Duplex.duplexPair = duplexPair;

module.exports = Stream;
