var Transform = require('node:stream').Transform;

function toBytes(data) {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) buf[i] = data.charCodeAt(i);
    return buf;
  }
  if (data instanceof Uint8Array) return data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    return new Uint8Array(data.buffer || data, data.byteOffset || 0, data.length);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return new Uint8Array(data);
}

function toBuffer(uint8) {
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(uint8);
  return uint8;
}

function countBytesForChunk(chunk, encoding) {
  if (chunk === null || chunk === undefined) return 0;
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, encoding || 'utf8');
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) return chunk.length;
  if (chunk instanceof ArrayBuffer) return chunk.byteLength;
  if (ArrayBuffer.isView(chunk)) return chunk.byteLength;
  return chunk.length || 0;
}

// mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw (no header/checksum)
function deflateSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 0);
  return toBuffer(result);
}

function inflateSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 0);
  return toBuffer(result);
}

function gzipSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 1);
  return toBuffer(result);
}

function gunzipSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 1);
  return toBuffer(result);
}

function deflateRawSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 2);
  return toBuffer(result);
}

function inflateRawSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 2);
  return toBuffer(result);
}

function unzipSync(data) {
  // Auto-detect gzip or deflate
  return gunzipSync(data);
}

// Async wrappers (use sync under the hood with nextTick callback)
function deflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = deflateSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function inflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = inflateSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function gzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = gzipSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function gunzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = gunzipSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function zstdCompressSync(data, options) {
  var bytes = toBytes(data);
  var level = -1;
  if (options && options.level !== undefined) {
    level = options.level;
  } else if (options && options.params && options.params[100] !== undefined) {
    level = options.params[100];
  }
  var result = __exactDeflateSync(bytes, level, 0);
  return toBuffer(result);
}

function zstdDecompressSync(data, options) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 0);
  return toBuffer(result);
}

function zstdCompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = zstdCompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function zstdDecompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = zstdDecompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

// Brotli compression/decompression
function brotliCompressSync(data, options) {
  var bytes = toBytes(data);
  var quality = 11; // BROTLI_DEFAULT_QUALITY
  if (options && options.params) {
    // BROTLI_PARAM_QUALITY = 1
    if (options.params[1] !== undefined) {
      quality = options.params[1];
    }
  }
  if (typeof __exactBrotliCompressSync !== 'function') throw new Error('brotliCompressSync not available');
  var result = __exactBrotliCompressSync(bytes, quality);
  return toBuffer(result);
}
function brotliDecompressSync(data, options) {
  var bytes = toBytes(data);
  if (typeof __exactBrotliDecompressSync !== 'function') throw new Error('brotliDecompressSync not available');
  var result = __exactBrotliDecompressSync(bytes);
  return toBuffer(result);
}
function brotliCompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = brotliCompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}
function brotliDecompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = brotliDecompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

// --- Stream-based zlib API (Transform streams) ---
// Base class for all zlib Transform streams
function ZlibTransform(syncFn, opts, isDecoder, roundTripSync) {
  Transform.call(this, opts);
  this._syncFn = syncFn;
  this._isDecoder = !!isDecoder;
  this._roundTripSync = typeof roundTripSync === 'function' ? roundTripSync : null;
  this._chunks = [];
  this._bytesWritten = 0;
  this.bytesWritten = 0;
  this.bytesRead = 0;

  var defaultFinal = this._final;
  this._final = function(callback) {
    var finalSelf = this;
    if (typeof callback !== 'function') callback = function() {};
    this._flush(function(err) {
      if (err) {
        callback(err);
        return;
      }
      if (typeof defaultFinal === 'function') {
        defaultFinal.call(finalSelf, callback);
      } else {
        callback();
      }
    });
  };
}
ZlibTransform.prototype = Object.create(Transform.prototype);
ZlibTransform.prototype.constructor = ZlibTransform;

ZlibTransform.prototype._transform = function(chunk, encoding, callback) {
  this._bytesWritten += countBytesForChunk(chunk, encoding || 'utf8');
  this.bytesWritten = this._bytesWritten;
  this.bytesRead = this._bytesWritten;
  var self = this;
  var transformState = self._transformState || {};

  var wrappedCallback = callback;
  callback = function(err) {
    if (typeof wrappedCallback === 'function') {
      wrappedCallback(err);
    }
    if (!transformState || !transformState._flushQueue || !transformState._flushQueue.length) {
      return;
    }
    if (transformState._flushing || (transformState.pendingWrites > 0)) {
      return;
    }
    if (self._writableState && self._writableState.writing) {
      return;
    }
    var next = transformState._flushQueue.shift();
    if (next && typeof self._flush === 'function') {
      self._flush(next[1]);
    }
  };

  if (typeof chunk === 'string') {
    this._chunks.push(Buffer.from(chunk, encoding));
  } else {
    this._chunks.push(chunk);
  }
  if (typeof callback !== 'function') return;
  if (typeof process === 'object' && process && typeof process.nextTick === 'function') {
    process.nextTick(callback);
  } else {
    setTimeout(callback, 0);
  }
};

ZlibTransform.prototype._flush = function(callback) {
  try {
    var input = Buffer.concat(this._chunks);
    var result = this._syncFn(input);

    if (this._isDecoder) {
      if (!this._roundTripSync) {
        throw new Error('Missing reverse codec for zlib stream byte accounting');
      }
      this._bytesWritten = countBytesForChunk(this._roundTripSync(result));
      this.bytesWritten = this._bytesWritten;
      this.bytesRead = this._bytesWritten;
    }

    this.push(result);
    callback();
  } catch (e) {
    this._bytesWritten = 0;
    this.bytesWritten = 0;
    this.bytesRead = 0;
    callback(e);
  }
};

ZlibTransform.prototype.flush = function(kind, callback) {
  if (typeof kind === 'function') {
    callback = kind;
    kind = undefined;
  }
  var flushCallback = typeof callback === 'function' ? callback : null;
  var state = this._transformState || (this._transformState = {});

  if (state._flushing || (state.pendingWrites > 0) ||
      (this._writableState && this._writableState.writing)) {
    state._flushQueue = state._flushQueue || [];
    state._flushQueue.push([kind, flushCallback]);
    return this;
  }

  if (!this._chunks || this._chunks.length === 0) {
    if (typeof flushCallback === 'function') {
      setTimeout(function() { flushCallback(); }, 0);
    }
    return this;
  }

  state._flushing = true;
  var self = this;
  var writableState = self._writableState || {};
  this._flush(function(err) {
    state._flushing = false;
    var shouldEmitDrain = false;
    if (!err) {
      shouldEmitDrain = self._needDrain || self.writableNeedDrain || writableState.needDrain;
      if (shouldEmitDrain) {
        self._needDrain = false;
        self.writableNeedDrain = false;
        writableState.needDrain = false;
      }
    }
    if (!err) {
      self._chunks = [];
    }
    if (typeof flushCallback === 'function') {
      flushCallback(err);
    }
    if (
      shouldEmitDrain &&
      !err &&
      !self._destroyed &&
      !writableState.writing &&
      (writableState.writableLength == null || writableState.writableLength < writableState.highWaterMark)
    ) {
      var drain = function() {
        self.emit('drain');
      };
      if (typeof process === 'object' &&
          process &&
          typeof process.nextTick === 'function') {
        process.nextTick(drain);
      } else {
        setTimeout(drain, 0);
      }
    }
    if (state._flushQueue && state._flushQueue.length > 0) {
      var next = state._flushQueue.shift();
      if (next && typeof self._flush === 'function') {
        self._flush(next[1]);
      }
    }
  });
  return this;
};

ZlibTransform.prototype.reset = function() {
  this._chunks = [];
  this._bytesWritten = 0;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  return this;
};

ZlibTransform.prototype.params = function(level, strategy, callback) {
  this._level = level;
  this._strategy = strategy;
  if (typeof callback === 'function') {
    setTimeout(function() { callback(); }, 0);
  }
  return this;
};

ZlibTransform.prototype.close = function(callback) {
  return this.destroy(null, callback);
};

// Deflate stream (zlib header)
function Deflate(opts) {
  ZlibTransform.call(this, deflateSync, opts, false, null);
}
Deflate.prototype = Object.create(ZlibTransform.prototype);
Deflate.prototype.constructor = Deflate;

// Inflate stream (zlib header)
function Inflate(opts) {
  ZlibTransform.call(this, inflateSync, opts, true, deflateSync);
}
Inflate.prototype = Object.create(ZlibTransform.prototype);
Inflate.prototype.constructor = Inflate;

// Gzip stream
function Gzip(opts) {
  ZlibTransform.call(this, gzipSync, opts, false, null);
}
Gzip.prototype = Object.create(ZlibTransform.prototype);
Gzip.prototype.constructor = Gzip;

// Gunzip stream
function Gunzip(opts) {
  ZlibTransform.call(this, gunzipSync, opts, true, gzipSync);
}
Gunzip.prototype = Object.create(ZlibTransform.prototype);
Gunzip.prototype.constructor = Gunzip;

// DeflateRaw stream (no header/checksum)
function DeflateRaw(opts) {
  ZlibTransform.call(this, deflateRawSync, opts, false, null);
}
DeflateRaw.prototype = Object.create(ZlibTransform.prototype);
DeflateRaw.prototype.constructor = DeflateRaw;

// InflateRaw stream (no header/checksum)
function InflateRaw(opts) {
  ZlibTransform.call(this, inflateRawSync, opts, true, deflateRawSync);
}
InflateRaw.prototype = Object.create(ZlibTransform.prototype);
InflateRaw.prototype.constructor = InflateRaw;

function createDeflate(options) { return new Deflate(options); }
function createInflate(options) { return new Inflate(options); }
function createGzip(options) { return new Gzip(options); }
function createGunzip(options) { return new Gunzip(options); }
function createDeflateRaw(options) { return new DeflateRaw(options); }
function createInflateRaw(options) { return new InflateRaw(options); }

// Zstd placeholder stream classes
function ZstdCompress(opts) {
  Deflate.call(this, opts);
}
ZstdCompress.prototype = Object.create(Deflate.prototype);
ZstdCompress.prototype.constructor = ZstdCompress;

function ZstdDecompress(opts) {
  Inflate.call(this, opts);
}
ZstdDecompress.prototype = Object.create(Inflate.prototype);
ZstdDecompress.prototype.constructor = ZstdDecompress;

function createZstdCompress(options) { return new ZstdCompress(options); }
function createZstdDecompress(options) { return new ZstdDecompress(options); }

// BrotliCompress stream
function BrotliCompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliCompressSync(buf, opts); }, opts, false, null);
}
BrotliCompress.prototype = Object.create(ZlibTransform.prototype);
BrotliCompress.prototype.constructor = BrotliCompress;

// BrotliDecompress stream
function BrotliDecompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliDecompressSync(buf, opts); }, opts, true, function(buf) { return brotliCompressSync(buf, opts); });
}
BrotliDecompress.prototype = Object.create(ZlibTransform.prototype);
BrotliDecompress.prototype.constructor = BrotliDecompress;

function createBrotliCompress(options) { return new BrotliCompress(options); }
function createBrotliDecompress(options) { return new BrotliDecompress(options); }

// Constants
var constants = {
  Z_NO_COMPRESSION: 0,
  Z_BEST_SPEED: 1,
  Z_BEST_COMPRESSION: 9,
  Z_DEFAULT_COMPRESSION: -1,
  Z_NO_FLUSH: 0,
  Z_PARTIAL_FLUSH: 1,
  Z_SYNC_FLUSH: 2,
  Z_FULL_FLUSH: 3,
  Z_FINISH: 4,
  Z_BLOCK: 5,
  Z_TREES: 6,
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_NEED_DICT: 2,
  Z_ERRNO: -1,
  Z_STREAM_ERROR: -2,
  Z_DATA_ERROR: -3,
  Z_MEM_ERROR: -4,
  Z_BUF_ERROR: -5,
  Z_VERSION_ERROR: -6,
  BROTLI_OPERATION_PROCESS: 0,
  BROTLI_OPERATION_FLUSH: 1,
  BROTLI_OPERATION_FINISH: 2,
  BROTLI_PARAM_MODE: 0,
  BROTLI_MODE_GENERIC: 0,
  BROTLI_MODE_TEXT: 1,
  BROTLI_MODE_FONT: 2,
  BROTLI_PARAM_QUALITY: 1,
  BROTLI_MIN_QUALITY: 0,
  BROTLI_MAX_QUALITY: 11,
  BROTLI_DEFAULT_QUALITY: 11,
  BROTLI_PARAM_LGWIN: 2,
  BROTLI_MIN_WINDOW_BITS: 10,
  BROTLI_MAX_WINDOW_BITS: 24,
  BROTLI_DEFAULT_WINDOW: 22,
  BROTLI_PARAM_LGBLOCK: 3,
  BROTLI_MIN_INPUT_BLOCK_BITS: 16,
  BROTLI_MAX_INPUT_BLOCK_BITS: 24,
  BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: 4,
  BROTLI_PARAM_SIZE_HINT: 5,
  BROTLI_PARAM_LARGE_WINDOW: 6,
  BROTLI_PARAM_NPOSTFIX: 7,
  BROTLI_PARAM_NDIRECT: 8,
  ZSTD_CLEVEL_DEFAULT: 3,
  ZSTD_btlazy2: 6,
  ZSTD_btopt: 7,
  ZSTD_btultra: 8,
  ZSTD_btultra2: 9,
  ZSTD_c_chainLog: 103,
  ZSTD_c_checksumFlag: 201,
  ZSTD_c_compressionLevel: 100,
  ZSTD_c_contentSizeFlag: 200,
  ZSTD_c_dictIDFlag: 202,
  ZSTD_c_enableLongDistanceMatching: 160,
  ZSTD_c_hashLog: 102,
  ZSTD_c_jobSize: 401,
  ZSTD_c_ldmBucketSizeLog: 163,
  ZSTD_c_ldmHashLog: 161,
  ZSTD_c_ldmHashRateLog: 164,
  ZSTD_c_ldmMinMatch: 162,
  ZSTD_c_minMatch: 105,
  ZSTD_c_nbWorkers: 400,
  ZSTD_c_overlapLog: 402,
  ZSTD_c_searchLog: 104,
  ZSTD_c_strategy: 107,
  ZSTD_c_targetLength: 106,
  ZSTD_c_windowLog: 101,
  ZSTD_COMPRESS: 10,
  ZSTD_DECOMPRESS: 11,
  ZSTD_dfast: 2,
  ZSTD_fast: 1,
  ZSTD_greedy: 3,
  ZSTD_lazy: 4,
  ZSTD_lazy2: 5,
  ZSTD_d_windowLogMax: 100,
  ZSTD_e_continue: 0,
  ZSTD_e_end: 2,
  ZSTD_e_flush: 1,
  ZSTD_error_checksum_wrong: 22,
  ZSTD_error_corruption_detected: 20,
  ZSTD_error_dictionary_corrupted: 30,
  ZSTD_error_dictionary_wrong: 32,
  ZSTD_error_dictionaryCreation_failed: 34,
  ZSTD_error_dstBuffer_null: 74,
  ZSTD_error_dstSize_tooSmall: 70,
  ZSTD_error_frameParameter_unsupported: 14,
  ZSTD_error_frameParameter_windowTooLarge: 16,
  ZSTD_error_GENERIC: 1,
  ZSTD_error_init_missing: 62,
  ZSTD_error_literals_headerWrong: 24,
  ZSTD_error_maxSymbolValue_tooLarge: 46,
  ZSTD_error_maxSymbolValue_tooSmall: 48,
  ZSTD_error_memory_allocation: 64,
  ZSTD_error_no_error: 0,
  ZSTD_error_noForwardProgress_destFull: 80,
  ZSTD_error_noForwardProgress_inputEmpty: 82,
  ZSTD_error_parameter_combination_unsupported: 41,
  ZSTD_error_parameter_outOfBound: 42,
  ZSTD_error_parameter_unsupported: 40,
  ZSTD_error_prefix_unknown: 10,
  ZSTD_error_srcSize_wrong: 72,
  ZSTD_error_stabilityCondition_notRespected: 50,
  ZSTD_error_stage_wrong: 60,
  ZSTD_error_tableLog_tooLarge: 44,
  ZSTD_error_version_unsupported: 12,
  ZSTD_error_workSpace_tooSmall: 66,
  BROTLI_DECODER_RESULT_ERROR: 0,
  BROTLI_DECODER_RESULT_SUCCESS: 1,
  BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: 2,
  BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: 3
};

module.exports = {
  deflateSync: deflateSync,
  inflateSync: inflateSync,
  gzipSync: gzipSync,
  gunzipSync: gunzipSync,
  deflateRawSync: deflateRawSync,
  inflateRawSync: inflateRawSync,
  unzipSync: unzipSync,
  deflate: deflate,
  inflate: inflate,
  gzip: gzip,
  gunzip: gunzip,
  zstdCompressSync: zstdCompressSync,
  zstdDecompressSync: zstdDecompressSync,
  zstdCompress: zstdCompress,
  zstdDecompress: zstdDecompress,
  brotliCompressSync: brotliCompressSync,
  brotliDecompressSync: brotliDecompressSync,
  brotliCompress: brotliCompress,
  brotliDecompress: brotliDecompress,
  createDeflate: createDeflate,
  createInflate: createInflate,
  createGzip: createGzip,
  createGunzip: createGunzip,
  createDeflateRaw: createDeflateRaw,
  createInflateRaw: createInflateRaw,
  createZstdCompress: createZstdCompress,
  createZstdDecompress: createZstdDecompress,
  ZstdCompress: ZstdCompress,
  ZstdDecompress: ZstdDecompress,
  createBrotliCompress: createBrotliCompress,
  createBrotliDecompress: createBrotliDecompress,
  Deflate: Deflate,
  Inflate: Inflate,
  Gzip: Gzip,
  Gunzip: Gunzip,
  DeflateRaw: DeflateRaw,
  InflateRaw: InflateRaw,
  BrotliCompress: BrotliCompress,
  BrotliDecompress: BrotliDecompress,
  constants: constants
};
