var EventEmitter = require('node:events').EventEmitter;

var defaultHighWaterMark = 16384;
var defaultHighWaterMarkObjectMode = 16;

function Stream() {
  EventEmitter.call(this);
  this._closed = false;
  this._destroyed = false;
  this.destroyed = false;
  this._needsClose = false;
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
    // Synchronous path when no _destroy
    emitErrorAndClose(error || null);
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
    autoDestroy: true,
    awaitDrainWriters: null,
    defaultEncoding: 'utf8',
    encoding: (options && options.encoding) || null,
    readable: true,
    endedEmitted: false,
    endEmitted: false,
    endConsumed: false,
    buffer: this._data,
    needDrain: false,
    pendingcb: 0,
  };
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

Readable.prototype._updateReadableLength = function() {
  var state = this._readableState;
  state.length = 0;
  for (var i = 0; i < this._data.length; i++) {
    state.length += readableStateChunkLength(this._data[i], state.objectMode);
  }
  this.readableLength = state.length;
  state.reading = !state.ended && !!this._read && state.length < state.highWaterMark;
  state.readableListening = this._events && this._events.readable !== undefined;
};

Readable.prototype._syncReadableState = function() {
  var state = this._readableState;
  state.ended = this._ended;
  state.reading = !state.ended && !!this._read && state.length < state.highWaterMark;
  state.needReadable = state.length > 0 && !state.ended;
};

Readable.prototype._emitReadableIfNeeded = function() {
  var state = this._readableState;
  if (!state.needReadable || state.emittedReadable || state.readableFlowing || this.readableFlowing === true) {
    return;
  }
  state.emittedReadable = true;
  state.needReadable = false;
  this.emit('readable');
};

Readable.prototype._readFromSource = function() {
  if (this._destroyed || this._readableState.reading || typeof this._read !== 'function') return;
  this._readableState.reading = true;
  try {
    this._read();
  } finally {
    this._readableState.reading = false;
  }
};

Readable.prototype.push = function(chunk) {
  if (this._destroyed) return false;
  if (chunk === null || chunk === undefined) {
    this._ended = true;
    this.readableEnded = true;
    this._readableState.ended = true;
    // If flowing, emit end immediately; otherwise buffer the end signal
    if (this.readableFlowing === true) {
      this.readable = false;
      this._updateReadableLength();
      if (this._readableState.length > 0) {
        this._syncReadableState();
        this._emitReadableIfNeeded();
      }
      this._readableState.endEmitted = true;
      this._readableState.endedEmitted = true;
      this.emit('end');
      this._close();
    } else {
      // Buffered end - will be emitted when the buffer is flushed via resume
      this._updateReadableLength();
      this._syncReadableState();
    }
    return false;
  }
  this._data.push(chunk);
  this._updateReadableLength();
  this._syncReadableState();
  this._readableState.needReadable = true;
  this._readableState.emittedReadable = false;
  // Only emit 'data' immediately if in flowing mode
  if (this.readableFlowing === true) {
    this.emit('data', chunk);
  }
  this._emitReadableIfNeeded();
  return this._readableState.length < this._readableState.highWaterMark;
};

Readable.prototype.read = function() {
  if (this._destroyed) return null;
  this.readableDidRead = true;
  if (this._data.length === 0 && !this._ended) {
    this._readFromSource();
  }
  var chunk = this._data.shift();
  if (chunk === undefined) return null;
  this._updateReadableLength();
  this._syncReadableState();
  if (this._data.length > 0 && !this._ended) {
    this._readableState.needReadable = true;
    this._readableState.emittedReadable = false;
  } else {
    this._readableState.needReadable = false;
    this._readableState.emittedReadable = false;
  }
  return chunk;
};

Readable.prototype.unshift = function(chunk) {
  this._data.unshift(chunk);
  this._updateReadableLength();
  this._syncReadableState();
  this._readableState.needReadable = true;
  this._readableState.emittedReadable = false;
  this._emitReadableIfNeeded();
};

Readable.prototype.setEncoding = function(enc) {
  this.readableEncoding = enc;
  return this;
};

Readable.prototype.resume = function() {
  if (this.readableFlowing !== true) {
    this.readableFlowing = true;
    this._readableState.reading = false;
    this._readableState.resumeScheduled = false;
    // Flush buffered data asynchronously
    var self = this;
  setTimeout(function() {
      if (self._destroyed || self.readableFlowing !== true) return;
      while (self.readableFlowing === true) {
        if (self._data.length === 0 && !self._ended) {
          self._readFromSource();
        }
        if (self._data.length === 0) {
          if (self._ended && !self._readableState.endEmitted) {
            self.readable = false;
            self._readableState.endEmitted = true;
            self._readableState.endedEmitted = true;
            self.emit('end');
            self._close();
          }
          return;
        }
        var chunk = self._data.shift();
        self._updateReadableLength();
        self.emit('data', chunk);
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
    this._readableState.readableListening = true;
    var state = this._readableState;
    if (state.needReadable && !state.emittedReadable) {
      state.emittedReadable = true;
      state.needReadable = false;
      var self = this;
      setTimeout(function() {
        if (self._readableState.length > 0 && !self._ended) {
          self.emit('readable');
        }
      }, 0);
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
      readable._data.push(next.value);
      next = iterator.next();
    }
    readable._updateReadableLength();
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
    iterable.then(function(value) {
      readable.push(value);
      readable.push(null);
    }).catch(function(err) {
      readable.destroy(err);
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
    autoDestroy: true,
    pendingcb: 0,
    constructed: true,
    prefinished: false,
    errorEmitted: false,
    emittedClose: false,
    corked: 0,
  };
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

Writable.prototype._undestroy = function() {
  this._destroyed = false;
  this.destroyed = false;
  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finished = false;
    this._writableState.errored = null;
    this._writableState.errorEmitted = false;
  }
  this.writable = true;
  this.writableEnded = false;
  this.writableFinished = false;
  this.errored = null;
  this._closed = false;
};

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
      return false;
    }
    this.emit('error', endErr);
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
    chunkLen = (chunk && chunk.length) ? chunk.length : 0;
    this.writableLength += chunkLen;
  }
  var self = this;
  this._writableState.writing = true;
  this._write(chunk, encoding || 'utf8', function(err) {
    self._writableState.writing = false;
    self.writableLength -= chunkLen;
    if (self.writableLength < 0) self.writableLength = 0;
    if (!self._destroyed && self._needDrain && self.writableLength < self.writableHighWaterMark) {
      self._needDrain = false;
      self.writableNeedDrain = false;
      self.emit('drain');
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
  });
  if (this.writableLength >= this.writableHighWaterMark) {
    this._needDrain = true;
    this.writableNeedDrain = true;
    return false;
  }
  return true;
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
  this.writableEnded = true;
  this.writable = false;
  this._writableState.ending = true;
  this._writableState.ended = true;

  var self = this;
  // Collect end callbacks (if multiple end() calls happened before writableEnded)
  if (!this._endCallbacks) this._endCallbacks = [];
  if (typeof callback === 'function') this._endCallbacks.push(callback);

  var done = function() {
    if (self._destroyed || self.errored) {
      // If destroyed or errored before finish fires, don't emit finish
      var cbs = self._endCallbacks;
      self._endCallbacks = [];
      for (var j = 0; j < cbs.length; j++) { cbs[j](self.errored || null); }
      return;
    }
    self.emit('prefinish');
    // Defer finish emission
    setTimeout(function() {
      if (self._destroyed || self.errored) return;
      self.writableFinished = true;
      self._writableState.finished = true;
      self.emit('finish');
      self._close();
      var cbs = self._endCallbacks;
      self._endCallbacks = [];
      for (var j = 0; j < cbs.length; j++) { cbs[j](null); }
    }, 0);
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
};

Writable.prototype.cork = function() {
  this.writableCorked++;
  this._writableState.corked++;
};
Writable.prototype.uncork = function() {
  if (this.writableCorked > 0) {
    this.writableCorked--;
    this._writableState.corked--;
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
  if (!options || typeof options.final !== 'function') {
    this._final = function(callback) {
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

Transform.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  var self = this;
  this._transform(chunk, encoding || 'utf8', function(err) {
    if (err) { self.emit('error', err); }
    if (typeof callback === 'function') callback(err);
  });
  return true;
};

function PassThrough(options) {
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

  function ondata(chunk) {
    if (dest && typeof dest.write === 'function') {
      var ok = dest.write(chunk);
      if (ok === false && typeof source.pause === 'function') {
        // Track which writer caused backpressure
        if (state) {
          state.awaitDrainWriters = dest;
        }
        if (!hasDrainListener) {
          dest.on('drain', ondrain);
          hasDrainListener = true;
        }
        source.pause();
      }
    }
  }

  function ondrain() {
    if (state) {
      state.awaitDrainWriters = null;
    }
    if (hasDrainListener) {
      dest.removeListener('drain', ondrain);
      hasDrainListener = false;
    }
    if (typeof source.resume === 'function') {
      source.resume();
    }
  }

  function onend() {
    if ((!options || options.end !== false) && dest && typeof dest.end === 'function') {
      dest.end();
    }
  }

  function onerror(err) {
    unpipe();
    if (dest && typeof dest.destroy === 'function') {
      dest.destroy(err);
    }
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
    dest.on('error', onerror);
    dest.on('close', ondestroy);
    dest.on('destroy', ondestroy);
  }

  dest.on('close', onclose);

  function unpipe() {
    source.removeListener('data', ondata);
    source.removeListener('end', onend);
    source.removeListener('error', onerror);
    if (hasDrainListener) {
      dest.removeListener('drain', ondrain);
      hasDrainListener = false;
    }
    dest.removeListener('close', onclose);
    dest.removeListener('error', onerror);
    dest.removeListener('close', ondestroy);
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
  source.on('end', onend);
  source.on('error', onerror);

  // Store unpipe function for later
  if (!source._pipeCleanups) source._pipeCleanups = new Map();
  source._pipeCleanups.set(dest, unpipe);

  dest.emit('pipe', source);
  return dest;
};

// unpipe() - remove pipe destination
Readable.prototype.unpipe = function(dest) {
  var state = this._readableState;
  if (!state || state.pipesCount === 0) return this;

  if (!dest) {
    // Unpipe all
    var dests = state.pipes.slice();
    state.pipes = [];
    state.pipesCount = 0;
    for (var i = 0; i < dests.length; i++) {
      if (this._pipeCleanups && this._pipeCleanups.has(dests[i])) {
        this._pipeCleanups.get(dests[i])();
        this._pipeCleanups.delete(dests[i]);
      }
      dests[i].emit('unpipe', this);
    }
    return this;
  }

  if (this._pipeCleanups && this._pipeCleanups.has(dest)) {
    this._pipeCleanups.get(dest)();
    this._pipeCleanups.delete(dest);
  }
  dest.emit('unpipe', this);
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

  // Last arg can be callback or options
  if (typeof args[args.length - 1] === 'function') {
    callback = args.pop();
  } else if (args.length > 1 && typeof args[args.length - 1] === 'object' && args[args.length - 1] !== null && !args[args.length - 1].pipe) {
    options = args.pop();
    if (typeof args[args.length - 1] === 'function') callback = args.pop();
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
  var destroyedBySignal = false;

  function destroyAll(error) {
    for (var i = 0; i < streams.length; i++) {
      if (streams[i] && typeof streams[i].destroy === 'function' && !streams[i]._destroyed) {
        streams[i].destroy(error);
      }
    }
  }

  // AbortSignal support
  if (signal) {
    if (signal.aborted) {
      destroyedBySignal = true;
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      destroyAll(abortErr);
      if (callback) { callback(abortErr); return; }
      return Promise.reject(abortErr);
    }
    signal.addEventListener('abort', function() {
      destroyedBySignal = true;
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      destroyAll(abortErr);
    });
  }

  var error = null;
  var finished_count = 0;
  var total = streams.length;

  function onError(err) {
    if (!error) {
      error = err;
      destroyAll(err);
    }
  }

  // Pipe each stream to the next
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
    src.on('error', onError);
  }
  // Listen for error on last stream too
  streams[streams.length - 1].on('error', onError);

  // If no callback, return a Promise
  if (!callback) {
    return new Promise(function(resolve, reject) {
      var last = streams[streams.length - 1];
      last.on('finish', function() {
        if (error) reject(error); else resolve();
      });
      last.on('end', function() {
        if (error) reject(error); else resolve();
      });
    });
  }

  // With callback: wait for last stream to finish
  var last = streams[streams.length - 1];
  var called = false;
  function done(err) {
    if (called) return;
    called = true;
    callback(err || error || null);
  }
  last.on('finish', function() { done(null); });
  last.on('end', function() { done(null); });
  last.on('error', done);
}

function finished(stream, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  // Validate that the first argument is a stream
  if (!stream || (typeof stream.on !== 'function' && typeof stream.pipe !== 'function')) {
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "stream" argument must be an instance of Stream. Received ' + (stream === null ? 'null' : typeof stream));
  }

  var called = false;

  function done(err) {
    if (called) return;
    called = true;
    if (cleanup) cleanup();
    if (typeof callback === 'function') callback(err || null);
  }

  var onFinish = function() { done(null); };
  var onEnd = function() { done(null); };
  var onError = function(err) { done(err); };
  var onClose = function() {
    // If stream closed without ending, it's an error
    if (!stream._ended && !stream.writableFinished) {
      done(new Error('premature close'));
    } else {
      done(null);
    }
  };

  if (options.readable !== false && stream.on) {
    stream.on('end', onEnd);
  }
  if (options.writable !== false && stream.on) {
    stream.on('finish', onFinish);
  }
  if (stream.on) {
    stream.on('error', onError);
    stream.on('close', onClose);
  }

  // AbortSignal support
  if (options.signal) {
    options.signal.addEventListener('abort', function() {
      var err = new Error('The operation was aborted');
      err.code = 'ABORT_ERR';
      err.name = 'AbortError';
      done(err);
    });
  }

  // Return cleanup function
  var cleanup = function() {
    if (stream.removeListener) {
      stream.removeListener('end', onEnd);
      stream.removeListener('finish', onFinish);
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
    }
  };

  // If no callback, return a promise
  if (typeof callback !== 'function') {
    return new Promise(function(resolve, reject) {
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
  if (args.length === 1) return args[0];

  var first = args[0];
  var last = args[args.length - 1];

  // Pipe all streams together
  for (var j = 0; j + 1 < args.length; j++) {
    args[j].pipe(args[j + 1]);
  }

  // Create a Duplex that writes to first and reads from last
  var composed = new Duplex({
    write: function(chunk, encoding, callback) {
      if (typeof first.write === 'function') {
        var ok = first.write(chunk, encoding, callback);
        if (!ok && typeof callback !== 'function') {
          first.once('drain', function() {});
        }
      } else if (typeof callback === 'function') {
        callback();
      }
    },
    final: function(callback) {
      if (typeof first.end === 'function') first.end();
      callback();
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
  for (var k = 0; k < args.length; k++) {
    (function(s) {
      s.on('error', function(err) {
        composed.destroy(err);
      });
    })(args[k]);
  }

  return composed;
}

// addAbortSignal utility
function addAbortSignal(signal, stream) {
  if (!signal || typeof signal.addEventListener !== 'function') {
    throw new Error('The first argument must be an AbortSignal');
  }
  if (!stream || typeof stream.destroy !== 'function') {
    throw new Error('The second argument must be a stream');
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

// isReadable / isWritable / isDisturbed — stream state inspection
Stream.isReadable = function isReadable(stream) {
  if (!stream) return false;
  if (typeof stream.readable === 'boolean') return stream.readable;
  if (typeof stream._readableState === 'object') {
    return !stream._readableState.destroyed && !stream._readableState.ended;
  }
  return false;
};

Stream.isWritable = function isWritable(stream) {
  if (!stream) return false;
  if (typeof stream.writable === 'boolean') return stream.writable;
  if (typeof stream._writableState === 'object') {
    return !stream._writableState.destroyed && !stream._writableState.ended;
  }
  return false;
};

Stream.isDisturbed = function isDisturbed(stream) {
  if (!stream) return false;
  if (stream._readableState) {
    return stream._readableState.dataEmitted === true ||
           stream._readableState.readableAborted === true;
  }
  return stream.readableDidRead === true || stream.readableAborted === true || false;
};

Stream.isErrored = function isErrored(stream) {
  if (!stream) return false;
  return stream._readableState ? stream._readableState.errored !== null :
         stream._writableState ? stream._writableState.errored !== null :
         false;
};

// promises namespace
Stream.promises = {
  pipeline: function() {
    var args = Array.prototype.slice.call(arguments);
    return new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) reject(err);
        else resolve();
      });
      pipeline.apply(null, args);
    });
  },
  finished: function(stream, opts) {
    return new Promise(function(resolve, reject) {
      finished(stream, opts || {}, function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
};

module.exports = Stream;
