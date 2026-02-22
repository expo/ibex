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
function ZlibTransform(syncFn, opts) {
  Transform.call(this, opts);
  this._syncFn = syncFn;
  this._chunks = [];
}
ZlibTransform.prototype = Object.create(Transform.prototype);
ZlibTransform.prototype.constructor = ZlibTransform;

ZlibTransform.prototype._transform = function(chunk, encoding, callback) {
  if (typeof chunk === 'string') {
    this._chunks.push(Buffer.from(chunk, encoding));
  } else {
    this._chunks.push(chunk);
  }
  callback();
};

ZlibTransform.prototype._flush = function(callback) {
  try {
    var input = Buffer.concat(this._chunks);
    var result = this._syncFn(input);
    this.push(result);
    callback();
  } catch (e) {
    callback(e);
  }
};

// Override end() to call _flush before finishing, since the base Transform
// uses _final (not _flush) in this runtime's stream implementation
ZlibTransform.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = null; encoding = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (chunk !== undefined && chunk !== null) {
    if (typeof chunk === 'string') {
      this._chunks.push(Buffer.from(chunk, encoding || 'utf8'));
    } else {
      this._chunks.push(chunk);
    }
  }
  var self = this;
  this._flush(function(err) {
    if (err) {
      self.emit('error', err);
      if (typeof callback === 'function') callback(err);
      return;
    }
    self.push(null);
    self.writableEnded = true;
    self.writableFinished = true;
    self.emit('finish');
    self._emitClose();
    if (typeof callback === 'function') callback();
  });
};

// Deflate stream (zlib header)
function Deflate(opts) {
  ZlibTransform.call(this, deflateSync, opts);
}
Deflate.prototype = Object.create(ZlibTransform.prototype);
Deflate.prototype.constructor = Deflate;

// Inflate stream (zlib header)
function Inflate(opts) {
  ZlibTransform.call(this, inflateSync, opts);
}
Inflate.prototype = Object.create(ZlibTransform.prototype);
Inflate.prototype.constructor = Inflate;

// Gzip stream
function Gzip(opts) {
  ZlibTransform.call(this, gzipSync, opts);
}
Gzip.prototype = Object.create(ZlibTransform.prototype);
Gzip.prototype.constructor = Gzip;

// Gunzip stream
function Gunzip(opts) {
  ZlibTransform.call(this, gunzipSync, opts);
}
Gunzip.prototype = Object.create(ZlibTransform.prototype);
Gunzip.prototype.constructor = Gunzip;

// DeflateRaw stream (no header/checksum)
function DeflateRaw(opts) {
  ZlibTransform.call(this, deflateRawSync, opts);
}
DeflateRaw.prototype = Object.create(ZlibTransform.prototype);
DeflateRaw.prototype.constructor = DeflateRaw;

// InflateRaw stream (no header/checksum)
function InflateRaw(opts) {
  ZlibTransform.call(this, inflateRawSync, opts);
}
InflateRaw.prototype = Object.create(ZlibTransform.prototype);
InflateRaw.prototype.constructor = InflateRaw;

function createDeflate(options) { return new Deflate(options); }
function createInflate(options) { return new Inflate(options); }
function createGzip(options) { return new Gzip(options); }
function createGunzip(options) { return new Gunzip(options); }
function createDeflateRaw(options) { return new DeflateRaw(options); }
function createInflateRaw(options) { return new InflateRaw(options); }
// BrotliCompress stream
function BrotliCompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliCompressSync(buf, opts); }, opts);
}
BrotliCompress.prototype = Object.create(ZlibTransform.prototype);
BrotliCompress.prototype.constructor = BrotliCompress;

// BrotliDecompress stream
function BrotliDecompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliDecompressSync(buf, opts); }, opts);
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
