var EventEmitter = require('node:events').EventEmitter;

function Stream() {
  EventEmitter.call(this);
  this._closed = false;
  this._destroyed = false;
}
Stream.prototype = Object.create(EventEmitter.prototype);
Stream.prototype.constructor = Stream;

Stream.prototype._emitClose = function() {
  if (this._closed) {
    return;
  }
  this._closed = true;
  this.emit('close');
};

Stream.prototype.destroy = function(error) {
  if (this._destroyed) return this;
  this._destroyed = true;
  if (error !== undefined) {
    this.emit('error', error);
  }
  this._emitClose();
  return this;
};

function Readable(options) {
  Stream.call(this);
  this._data = [];
  this._ended = false;
  this.readableHighWaterMark = (options && options.highWaterMark) || 16384;
  this.readableObjectMode = !!(options && options.objectMode);
  this.readableEncoding = (options && options.encoding) || null;
  this.readableFlowing = null;
  this.readableEnded = false;
  this._readableState = {
    highWaterMark: (options && options.highWaterMark) || 16384,
    objectMode: !!(options && options.objectMode),
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
    awaitDrainWriters: [],
    defaultEncoding: 'utf8',
    encoding: (options && options.encoding) || null,
    readable: true,
    endedEmitted: false,
    endEmitted: false,
    buffer: this._data,
    needDrain: false,
    pendingcb: 0,
  };
  if (options && typeof options.read === 'function') this._read = options.read;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
}
Readable.prototype = Object.create(Stream.prototype);
Readable.prototype.constructor = Readable;

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

Readable.prototype.push = function(chunk) {
  if (chunk === null || chunk === undefined) {
    this._ended = true;
    this.readableEnded = true;
    this._updateReadableLength();
    this._readableState.endEmitted = true;
    this._readableState.endedEmitted = true;
    this._readableState.ended = true;
    if (this._readableState.length > 0) {
      this._syncReadableState();
      this._emitReadableIfNeeded();
    }
    this.emit('end');
    this._emitClose();
    return false;
  }
  this._data.push(chunk);
  this._updateReadableLength();
  this._syncReadableState();
  this._readableState.needReadable = true;
  this._readableState.emittedReadable = false;
  this.emit('data', chunk);
  this._emitReadableIfNeeded();
  return true;
};

Readable.prototype.read = function() {
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
  this.readableFlowing = true;
  this._readableState.reading = false;
  this._readableState.resumeScheduled = false;
  return this;
};

Readable.prototype.pause = function() {
  this.readableFlowing = false;
  this._syncReadableState();
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
  var pendingResolve = null;
  var buffer = [];

  stream.on('data', function(chunk) {
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
      resolve({ value: chunk, done: false });
    } else {
      buffer.push(chunk);
    }
  });

  stream.on('end', function() {
    ended = true;
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
      resolve({ value: undefined, done: true });
    }
  });

  stream.on('error', function(err) {
    error = err;
    ended = true;
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
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
        pendingResolve = resolve;
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

Readable.from = function(iterable, options) {
  var readable = new Readable(options);
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
      if (reading) return;
      reading = true;
      asyncIter.next().then(function(result) {
        reading = false;
        if (result.done) {
          readable.push(null);
        } else {
          readable.push(result.value);
          readNext();
        }
      }).catch(function(err) {
        reading = false;
        readable.destroy(err);
      });
    }
    readNext();
    return readable;
  }
  // Sync iterable
  if (typeof iterable[Symbol.iterator] === 'function') {
    var iterator = iterable[Symbol.iterator]();
    var next = iterator.next();
    while (!next.done) {
      readable.push(next.value);
      next = iterator.next();
    }
    readable.push(null);
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
  Stream.call(this);
  this.writableEnded = false;
  this.writableFinished = false;
  this.writableHighWaterMark = (options && options.highWaterMark) || 16384;
  this.writableObjectMode = !!(options && options.objectMode);
  this.writableLength = 0;
  this._written = [];
  this._needDrain = false;
  if (options && typeof options.write === 'function') this._write = options.write;
  if (options && typeof options.writev === 'function') this._writev = options.writev;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  if (options && typeof options.final === 'function') this._final = options.final;
}
Writable.prototype = Object.create(Stream.prototype);
Writable.prototype.constructor = Writable;

Writable.prototype._write = function(chunk, encoding, callback) {
  if (typeof callback === 'function') callback();
};

Writable.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  var chunkLen = 0;
  if (chunk !== undefined) {
    this._written.push(chunk);
    chunkLen = (chunk && chunk.length) ? chunk.length : 0;
    this.writableLength += chunkLen;
  }
  var self = this;
  this._write(chunk, encoding || 'utf8', function(err) {
    self.writableLength -= chunkLen;
    if (self.writableLength < 0) self.writableLength = 0;
    if (self._needDrain && self.writableLength < self.writableHighWaterMark) {
      self._needDrain = false;
      self.emit('drain');
    }
    if (err) { if (typeof callback === 'function') callback(err); }
    else { if (typeof callback === 'function') callback(); }
  });
  if (this.writableLength >= this.writableHighWaterMark) {
    this._needDrain = true;
    return false;
  }
  return true;
};

Writable.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }
  this.writableEnded = true;
  var self = this;
  var done = function() {
    self.writableFinished = true;
    self.emit('finish');
    self._emitClose();
    if (typeof callback === 'function') callback();
  };
  if (typeof this._final === 'function') {
    this._final(done);
  } else {
    done();
  }
};

Writable.prototype.cork = function() {};
Writable.prototype.uncork = function() {};
Writable.prototype.setDefaultEncoding = function(enc) { return this; };

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
  Readable.call(this, options);
  Writable.call(this, options);
  this.writableEnded = false;
  this.writableFinished = false;
  this.allowHalfOpen = !(options && options.allowHalfOpen === false);
}
Duplex.prototype = Object.create(Readable.prototype);
Object.keys(Writable.prototype).forEach(function(k) {
  if (!Duplex.prototype[k]) Duplex.prototype[k] = Writable.prototype[k];
});
Duplex.prototype.constructor = Duplex;

function Transform(options) {
  Duplex.call(this, options);
  if (options && typeof options.transform === 'function') this._transform = options.transform;
  if (options && typeof options.flush === 'function') this._flush = options.flush;
}
Transform.prototype = Object.create(Duplex.prototype);
Transform.prototype.constructor = Transform;

Transform.prototype._transform = function(chunk, encoding, callback) {
  this.push(chunk);
  if (typeof callback === 'function') callback();
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

Stream.prototype.pipe = function(dest) {
  var source = this;
  source.on('data', function(chunk) {
    if (dest && typeof dest.write === 'function') {
      var ok = dest.write(chunk);
      if (ok === false && typeof source.pause === 'function') {
        source.pause();
        dest.once('drain', function() {
          if (typeof source.resume === 'function') {
            source.resume();
          }
        });
      }
    }
  });
  source.on('end', function() {
    if (dest && typeof dest.end === 'function') {
      dest.end();
    }
  });
  source.on('error', function(err) {
    if (dest && typeof dest.destroy === 'function') {
      dest.destroy(err);
    }
  });
  return dest;
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
  if (streams.length < 2) {
    var err = new Error('pipeline requires at least 2 streams');
    if (callback) { callback(err); return; }
    return Promise.reject(err);
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
