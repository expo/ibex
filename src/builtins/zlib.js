var Transform = require('node:stream').Transform;

// ---------------------------------------------------------------------------
// Capture kMaxLength at module load time (Node.js behavior)
// ---------------------------------------------------------------------------
var _kMaxLength = (function() {
  try {
    var buf = require('buffer');
    return buf.kMaxLength != null ? buf.kMaxLength : Infinity;
  } catch(e) {
    return Infinity;
  }
})();

// Valid brotli parameter keys (0-8)
var VALID_BROTLI_PARAMS = [0, 1, 2, 3, 4, 5, 6, 7, 8];
var ZLIB_STREAM_DEFLATE = 0;
var ZLIB_STREAM_INFLATE = 1;
var Z_NO_FLUSH = 0;
var Z_SYNC_FLUSH = 2;
var Z_FULL_FLUSH = 3;
var Z_FINISH = 4;
// Native inflation builds one result ArrayBuffer per host call. Keep that
// allocation finite even when callers omit maxOutputLength; streams can still
// process arbitrarily long inputs across multiple bounded writes.
var NATIVE_ZLIB_OUTPUT_LIMIT = 64 * 1024 * 1024;
var _zlibControlMarkers = typeof WeakMap === 'function' ? new WeakMap() : null;
// @ref LLP 0021#handles-dynamic-authority-and-generations — numeric ids are
// native registry selectors, not transferable bearer authority.
// Native stream ids are authority-bearing mutable-state handles. Keep them in
// module-private storage so assigning a guessed `_nativeId` on a public stream
// object cannot redirect this trusted builtin into another package's stream.
var _nativeZlibStreamIds = typeof WeakMap === 'function' ? new WeakMap() : null;
var _nativeZlibOwnerState = typeof WeakMap === 'function' ? new WeakMap() : null;
var _nativeZlibOwnerStamps = typeof WeakMap === 'function' ? new WeakMap() : null;
var _zlibControlSymbol = typeof Symbol === 'function' ? Symbol('ibex.zlib.control') : null;

function setZlibControlMarker(marker, control) {
  if (_zlibControlMarkers) _zlibControlMarkers.set(marker, control);
  else if (_zlibControlSymbol) marker[_zlibControlSymbol] = control;
}

function getZlibControlMarker(marker) {
  if (!marker || (typeof marker !== 'object' && typeof marker !== 'function')) return null;
  if (_zlibControlMarkers) return _zlibControlMarkers.get(marker) || null;
  return _zlibControlSymbol ? marker[_zlibControlSymbol] || null : null;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function makeError(code, name, message) {
  var Ctor = name === 'RangeError' ? RangeError : name === 'TypeError' ? TypeError : Error;
  var err = new Ctor(message);
  err.code = code;
  return err;
}

function invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + (input.name || '');
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
}

function validateInput(data) {
  if (typeof data === 'string') return;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) return;
  if (data instanceof ArrayBuffer) return;
  if (ArrayBuffer.isView(data)) return;
  var msg = 'The "buffer" argument must be of type string or an instance of Buffer, TypedArray, DataView, or ArrayBuffer.';
  msg += invalidArgTypeHelper(data);
  throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError', msg);
}

function checkKMaxLength(length) {
  if (_kMaxLength !== Infinity && length > _kMaxLength) {
    throw makeError('ERR_BUFFER_TOO_LARGE', 'RangeError',
      'Cannot create a Buffer larger than ' + _kMaxLength + ' bytes');
  }
}

function validateMaxOutputLength(options) {
  if (!options || options.maxOutputLength === undefined) return Infinity;
  var value = options.maxOutputLength;
  if (typeof value !== 'number') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "options.maxOutputLength" property must be of type number. Received type ' + typeof value + " ('" + String(value) + "')");
  }
  if (value !== value || value < 0) {
    throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
      'The value of "options.maxOutputLength" is out of range. It must be >= 0. Received ' + String(value));
  }
  return value;
}

function checkMaxOutputLength(length, maxOutputLength) {
  if (length > maxOutputLength) {
    throw makeError('ERR_BUFFER_TOO_LARGE', 'RangeError',
      'Cannot create a Buffer larger than ' + maxOutputLength + ' bytes');
  }
}

function nativeZlibOutputBudget(maxOutputLength, outputLength) {
  var used = typeof outputLength === 'number' && outputLength > 0 ? outputLength : 0;
  var remaining = maxOutputLength === Infinity
    ? NATIVE_ZLIB_OUTPUT_LIMIT
    : Math.max(0, maxOutputLength - used);
  if (_kMaxLength !== Infinity) {
    remaining = Math.min(remaining, Math.max(0, _kMaxLength - used));
  }
  return Math.min(NATIVE_ZLIB_OUTPUT_LIMIT, remaining);
}

function nativeZlibOutputError(error) {
  if (!error || !error.message || !/^zlib output exceeds maxOutputLength/.test(error.message)) {
    return null;
  }
  return makeError('ERR_BUFFER_TOO_LARGE', 'RangeError', error.message);
}

function isNativeZlibTrailingError(error) {
  return !!(error && error.message && /^inflate failed: trailing data/.test(error.message));
}

function toBytes(data) {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) buf[i] = data.charCodeAt(i);
    return buf;
  }
  if (data instanceof Uint8Array) return data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    return new Uint8Array(data.buffer, data.byteOffset || 0, data.length);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data);
}

function toBuffer(uint8) {
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(uint8);
  return uint8;
}

function copyBytesForNative(data) {
  var bytes = toBytes(data);
  // @ref LLP 0004#the-zlib-builtin — the stateful JSI bridge consumes bytes
  // synchronously, so whole-buffer views can remain zero-copy. Normalize
  // sliced views, though: Buffer subarrays can expose backing-store geometry
  // that Hermes reports inconsistently across an async Transform turn, which
  // otherwise trips the bridge's mandatory bounds check.
  if (bytes.byteOffset !== 0 || bytes.byteLength !== bytes.buffer.byteLength) {
    return new Uint8Array(bytes);
  }
  return bytes;
}

function countBytesForChunk(chunk, encoding) {
  if (chunk === null || chunk === undefined) return 0;
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, encoding || 'utf8');
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) return chunk.length;
  if (chunk instanceof ArrayBuffer) return chunk.byteLength;
  if (ArrayBuffer.isView(chunk)) return chunk.byteLength;
  return chunk.length || 0;
}

function chunkToBuffer(chunk) {
  if (chunk == null) return Buffer.alloc(0);
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return Buffer.from(chunk);
  }
  if (chunk instanceof ArrayBuffer) {
    return Buffer.from(chunk);
  }
  if (ArrayBuffer.isView(chunk)) {
    return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  return Buffer.from(chunk);
}

function concatChunks(chunks) {
  if (!chunks || chunks.length === 0) return Buffer.alloc(0);
  if (chunks.length === 1) {
    return chunkToBuffer(chunks[0]);
  }
  return Buffer.concat(chunks.map(chunkToBuffer));
}

// Wrap inflate errors with Z_DATA_ERROR code
function wrapInflateError(e) {
  if (!e) return e;
  if (e.code) return e; // Already has a code
  var outputError = nativeZlibOutputError(e);
  if (outputError) return outputError;
  var msg = e.message || String(e);
  // Strip "inflate failed: data error: " prefix to match Node.js behavior
  msg = msg.replace(/^inflate failed:\s*(data error:\s*)?/, '');
  var err = new Error(msg);
  err.code = 'Z_DATA_ERROR';
  err.errno = -3;
  return err;
}

function normalizeZlibStreamError(e) {
  if (!e || !e.message) return e;
  if (e.code) return e;
  var outputError = nativeZlibOutputError(e);
  if (outputError) return outputError;
  var msg = e.message;
  if (/^inflate failed:/.test(msg)) {
    var detail = msg.replace(/^inflate failed:\s*(data error:\s*)?/, '');
    var inflateErr = new Error(detail);
    inflateErr.code = 'Z_DATA_ERROR';
    inflateErr.errno = -3;
    return inflateErr;
  }
  if (/unexpected end of file|invalid stored block|invalid block type|unknown compression method|incorrect data check/.test(msg)) {
    var dataErr = new Error(msg);
    var unexpectedEnd = /unexpected end of file/.test(msg);
    dataErr.code = unexpectedEnd ? 'Z_BUF_ERROR' : 'Z_DATA_ERROR';
    dataErr.errno = unexpectedEnd ? -5 : -3;
    return dataErr;
  }
  return e;
}

// Guarded access to the native deflate/inflate bridge. On builds where the
// host functions are not registered (the bridge registration is
// platform-gated; Windows lacks it today) a bare call raised a bewildering
// ReferenceError from inside gzipSync — fail with a clear "not available"
// error instead, matching the existing brotli/zstd guards (ENG-23456).
function _nativeDeflateSync(bytes, level, mode, dict) {
  if (typeof __exactDeflateSync !== 'function') {
    throw new Error('zlib deflate is not available in this build (native zlib bridge not registered on this platform)');
  }
  return __exactDeflateSync(bytes, level, mode, dict);
}

function _nativeInflateSync(bytes, mode, gzipMulti, flags, dict, maxOutputLength) {
  if (typeof __exactInflateSync !== 'function') {
    throw new Error('zlib inflate is not available in this build (native zlib bridge not registered on this platform)');
  }
  return __exactInflateSync(bytes, mode, gzipMulti, flags, dict, maxOutputLength);
}

function nativeZlibStreamsAvailable() {
  return _nativeZlibStreamIds !== null &&
    typeof __exactZlibCreate === 'function' &&
    typeof __exactZlibWrite === 'function' &&
    typeof __exactZlibParams === 'function' &&
    typeof __exactZlibCheckOwner === 'function' &&
    typeof __exactZlibClose === 'function';
}

function assertNativeZlibStreamOwner(stream) {
  var owner = _nativeZlibOwnerStamps && _nativeZlibOwnerStamps.get(stream);
  if (owner) {
    owner.host('assert', owner.stamp);
    return;
  }
  var id = _nativeZlibStreamIds && _nativeZlibStreamIds.get(stream);
  if (id) {
    __exactZlibCheckOwner(id);
  }
}

function registerNativeZlibStreamOwner(stream) {
  if (!_nativeZlibOwnerStamps || !nativeZlibStreamsAvailable() ||
      typeof __exactNetOwner !== 'function') {
    return;
  }
  // __exactNetOwner's stamp is a principal/runtime identity proof, not a
  // positive network grant. Unlike the codec selector it remains valid after
  // native z_stream cleanup, so event/listener projections stay authenticated
  // until the JS wrapper itself becomes unreachable.
  var host = __exactNetOwner;
  _nativeZlibOwnerStamps.set(stream, {
    host: host,
    stamp: host('new')
  });
}

function findZlibPropertyDescriptor(object, property) {
  var current = object;
  while (current) {
    var descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (descriptor) return descriptor;
    current = Object.getPrototypeOf(current);
  }
  return null;
}

function sealNativeZlibOwnerProperty(stream, property) {
  var ownDescriptor = Object.getOwnPropertyDescriptor(stream, property);
  if (ownDescriptor && ownDescriptor.configurable === false) return;

  var descriptor = ownDescriptor || findZlibPropertyDescriptor(Object.getPrototypeOf(stream), property);
  var state = _nativeZlibOwnerState.get(stream);
  var cell;
  if (descriptor && (typeof descriptor.get === 'function' || typeof descriptor.set === 'function')) {
    cell = {
      get: descriptor.get,
      set: descriptor.set,
      enumerable: !!(ownDescriptor && descriptor.enumerable)
    };
  } else {
    cell = {
      value: descriptor ? descriptor.value : stream[property],
      writable: !descriptor || descriptor.writable !== false,
      enumerable: !!(ownDescriptor && descriptor && descriptor.enumerable)
    };
  }
  state.set(property, cell);

  var projected = {
    configurable: false,
    enumerable: cell.enumerable,
    get: function() {
      assertNativeZlibStreamOwner(stream);
      if (cell.get) return cell.get.call(stream);
      return cell.value;
    }
  };
  if (cell.set || cell.writable) {
    projected.set = function(value) {
      assertNativeZlibStreamOwner(stream);
      if (cell.set) {
        cell.set.call(stream, value);
      } else {
        cell.value = value;
      }
    };
  }
  Object.defineProperty(stream, property, projected);
}

function sealNativeZlibOwnerState(stream) {
  if (!_nativeZlibOwnerState || _nativeZlibOwnerState.has(stream)) return;
  _nativeZlibOwnerState.set(stream, new Map());

  // @ref LLP 0004#the-zlib-builtin — codec callbacks, buffered plaintext,
  // native dispatch configuration, and output limits are part of the retained
  // transform's authority-bearing mutable state. A foreign wrapper must not
  // plant code/data here for a later owner-context write or finalization.
  // The production builtin resolves node:stream to Ibex's guarded stream
  // implementation. Sealing the complete instance/prototype surface here as
  // well keeps the zlib invariant self-contained (and covers embedders that
  // supply another compatible Transform implementation).
  Object.getOwnPropertyNames(stream).forEach(function(property) {
    sealNativeZlibOwnerProperty(stream, property);
  });
  var prototype = Object.getPrototypeOf(stream);
  while (prototype && prototype !== Object.prototype) {
    Object.getOwnPropertyNames(prototype).forEach(function(property) {
      if (property === 'constructor') return;
      var descriptor = Object.getOwnPropertyDescriptor(prototype, property);
      if (descriptor && (typeof descriptor.value === 'function' || descriptor.get || descriptor.set)) {
        sealNativeZlibOwnerProperty(stream, property);
      }
    });
    if (typeof Object.getOwnPropertySymbols === 'function') {
      Object.getOwnPropertySymbols(prototype).forEach(function(property) {
        var descriptor = Object.getOwnPropertyDescriptor(prototype, property);
        if (descriptor && (typeof descriptor.value === 'function' || descriptor.get || descriptor.set)) {
          sealNativeZlibOwnerProperty(stream, property);
        }
      });
    }
    prototype = Object.getPrototypeOf(prototype);
  }

  [
    '_bytesWritten',
    '_chunks',
    '_finishFlush',
    '_flushed',
    '_flushFlag',
    '_handle',
    '_isDecoder',
    '_level',
    '_maxOutputLength',
    '_multiMember',
    '_nativeAvailable',
    '_nativeDictionary',
    '_nativeKind',
    '_nativeMode',
    '_outputLength',
    '_strategy',
    '_syncFn',
    'bytesRead',
    'bytesWritten',
    '_closeNativeStream',
    '_destroy',
    '_ensureNativeStream',
    '_flush',
    '_processChunk',
    '_pushNativeOutput',
    '_transform',
    '_writeNative',
    'close',
    'destroy',
    'end',
    'flush',
    'params',
    'reset',
    'setEncoding',
    'write'
  ].forEach(function(property) {
    sealNativeZlibOwnerProperty(stream, property);
  });
}

// Internal: inflate and return [buffer, bytesConsumed]
// flags=2 means returnConsumed=true (bit1), non-lenient
function inflateSyncConsumed(bytes, mode, flags, maxOutputLength) {
  var raw = _nativeInflateSync(
    bytes,
    mode,
    false,
    flags === undefined ? 2 : flags,
    undefined,
    maxOutputLength);
  if (Array.isArray(raw)) {
    return [toBuffer(raw[0]), raw[1]];
  }
  return [toBuffer(raw), bytes.length];
}

// Internal: brotli decompress and return [buffer, bytesConsumed]
// flags=2 means returnConsumed=true (bit1)
function brotliDecompressSyncConsumed(bytes, maxOutputLength) {
  if (typeof __exactBrotliDecompressSync !== 'function') {
    throw new Error('brotliDecompressSync not available');
  }
  var raw = __exactBrotliDecompressSync(
    bytes,
    false,
    2,
    maxOutputLength === undefined
      ? nativeZlibOutputBudget(Infinity, 0)
      : maxOutputLength);
  if (Array.isArray(raw)) {
    return [toBuffer(raw[0]), raw[1]];
  }
  return [toBuffer(raw), bytes.length];
}

// ---------------------------------------------------------------------------
// Sync functions
// ---------------------------------------------------------------------------

// mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw (no header/checksum)
function deflateSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, true, false);
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var dict = (options && options.dictionary) ? toBytes(options.dictionary) : undefined;
  var buf = toBuffer(_nativeDeflateSync(bytes, level, 0, dict));
  if (options && options.info) return { engine: new Deflate(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function inflateSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, false, false);
  var maxOutputLength = validateMaxOutputLength(options);
  var bytes = toBytes(data);
  var lenient = !!(options && options.finishFlush === 2 /* Z_SYNC_FLUSH */);
  var dict = (options && options.dictionary) ? toBytes(options.dictionary) : undefined;
  var result;
  try {
    result = toBuffer(_nativeInflateSync(
      bytes,
      0,
      false,
      lenient ? 1 : 0,
      dict,
      nativeZlibOutputBudget(maxOutputLength, 0)));
  } catch (e) {
    var outputError = nativeZlibOutputError(e);
    if (outputError) throw outputError;
    if (isNativeZlibTrailingError(e)) throw wrapInflateError(e);
    if (lenient) return toBuffer(new Uint8Array(0));
    throw wrapInflateError(e);
  }
  checkKMaxLength(result.length);
  checkMaxOutputLength(result.length, maxOutputLength);
  if (options && options.info) return { engine: new Inflate(options), buffer: result }; // eslint-disable-line no-use-before-define
  return result;
}

function gzipSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, true, true);
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var buf = toBuffer(_nativeDeflateSync(bytes, level, 1));
  if (options && options.info) return { engine: new Gzip(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function gunzipSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, false, true);
  var maxOutputLength = validateMaxOutputLength(options);
  var bytes = toBytes(data);
  var lenient = !!(options && options.finishFlush === 2 /* Z_SYNC_FLUSH */);

  // Handle multi-member (concatenated) gzip
  var allOutputs = [];
  var outputLength = 0;
  var remaining = bytes;
  while (remaining.length > 0) {
    var memberResult;
    var consumed;
    try {
      var raw = _nativeInflateSync(
        remaining,
        1,
        false,
        lenient ? 3 : (2 /* returnConsumed */),
        undefined,
        nativeZlibOutputBudget(maxOutputLength, outputLength));
      if (Array.isArray(raw)) {
        memberResult = toBuffer(raw[0]);
        consumed = raw[1];
      } else {
        memberResult = toBuffer(raw);
        consumed = remaining.length;
      }
    } catch (e) {
      var outputError = nativeZlibOutputError(e);
      if (outputError) throw outputError;
      if (isNativeZlibTrailingError(e)) throw wrapInflateError(e);
      if (lenient) return toBuffer(new Uint8Array(0));
      throw wrapInflateError(e);
    }
    allOutputs.push(memberResult);
    outputLength += memberResult.length;
    if (consumed >= remaining.length || consumed === 0) break;
    remaining = remaining.slice(consumed);
  }

  var result = allOutputs.length === 1 ? allOutputs[0] : Buffer.concat(allOutputs);
  checkKMaxLength(result.length);
  checkMaxOutputLength(result.length, maxOutputLength);
  if (options && options.info) return { engine: new Gunzip(options), buffer: result }; // eslint-disable-line no-use-before-define
  return result;
}

function deflateRawSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, true, false);
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var dict = (options && options.dictionary) ? toBytes(options.dictionary) : undefined;
  var buf = toBuffer(_nativeDeflateSync(bytes, level, 2, dict));
  if (options && options.info) return { engine: new DeflateRaw(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function inflateRawSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, false, false);
  var maxOutputLength = validateMaxOutputLength(options);
  var bytes = toBytes(data);
  var lenient = !!(options && options.finishFlush === 2 /* Z_SYNC_FLUSH */);
  var dict = (options && options.dictionary) ? toBytes(options.dictionary) : undefined;
  var result;
  try {
    result = toBuffer(_nativeInflateSync(
      bytes,
      2,
      false,
      lenient ? 1 : 0,
      dict,
      nativeZlibOutputBudget(maxOutputLength, 0)));
  } catch (e) {
    var outputError = nativeZlibOutputError(e);
    if (outputError) throw outputError;
    if (isNativeZlibTrailingError(e)) throw wrapInflateError(e);
    if (lenient) return toBuffer(new Uint8Array(0));
    throw wrapInflateError(e);
  }
  checkKMaxLength(result.length);
  checkMaxOutputLength(result.length, maxOutputLength);
  if (options && options.info) return { engine: new InflateRaw(options), buffer: result }; // eslint-disable-line no-use-before-define
  return result;
}

function unzipSync(data, options) {
  validateInput(data);
  validateZlibOptions(options, false, true);
  var maxOutputLength = validateMaxOutputLength(options);
  var bytes = toBytes(data);
  var lenient = !!(options && options.finishFlush === 2 /* Z_SYNC_FLUSH */);

  // Check if data starts with gzip magic bytes (1f 8b) for multi-member support
  var isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;

  if (isGzip) {
    // Handle multi-member (concatenated) gzip
    var allOutputs = [];
    var outputLength = 0;
    var remaining = bytes;
    while (remaining.length > 0) {
      var memberResult;
      var consumed;
      try {
        var raw = _nativeInflateSync(
          remaining,
          1,
          false,
          lenient ? 3 : 2,
          undefined,
          nativeZlibOutputBudget(maxOutputLength, outputLength));
        if (Array.isArray(raw)) {
          memberResult = toBuffer(raw[0]);
          consumed = raw[1];
        } else {
          memberResult = toBuffer(raw);
          consumed = remaining.length;
        }
      } catch (e) {
        var outputError = nativeZlibOutputError(e);
        if (outputError) throw outputError;
        if (isNativeZlibTrailingError(e)) throw wrapInflateError(e);
        if (lenient) return toBuffer(new Uint8Array(0));
        throw wrapInflateError(e);
      }
      allOutputs.push(memberResult);
      outputLength += memberResult.length;
      if (consumed >= remaining.length || consumed === 0) break;
      remaining = remaining.slice(consumed);
    }
    var result = allOutputs.length === 1 ? allOutputs[0] : Buffer.concat(allOutputs);
    checkKMaxLength(result.length);
    checkMaxOutputLength(result.length, maxOutputLength);
    if (options && options.info) return { engine: new Unzip(options), buffer: result }; // eslint-disable-line no-use-before-define
    return result;
  }

  // Non-gzip: single member only
  var singleResult;
  try {
    singleResult = toBuffer(_nativeInflateSync(
      bytes,
      1,
      false,
      lenient ? 1 : 0,
      undefined,
      nativeZlibOutputBudget(maxOutputLength, 0)));
  } catch (e) {
    var outputError = nativeZlibOutputError(e);
    if (outputError) throw outputError;
    if (isNativeZlibTrailingError(e)) throw wrapInflateError(e);
    if (lenient) return toBuffer(new Uint8Array(0));
    throw wrapInflateError(e);
  }
  checkKMaxLength(singleResult.length);
  checkMaxOutputLength(singleResult.length, maxOutputLength);
  if (options && options.info) return { engine: new Unzip(options), buffer: singleResult }; // eslint-disable-line no-use-before-define
  return singleResult;
}

// ---------------------------------------------------------------------------
// Brotli
// ---------------------------------------------------------------------------

// BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING = 4, this is a boolean flag
var BROTLI_BOOLEAN_PARAMS = [4];

function validateBrotliParams(params) {
  if (!params) return;
  var paramKeys = Object.keys(params);
  for (var i = 0; i < paramKeys.length; i++) {
    var key = paramKeys[i];
    var numKey = Number(key);
    if (String(numKey) !== key || VALID_BROTLI_PARAMS.indexOf(numKey) === -1) {
      throw makeError('ERR_BROTLI_INVALID_PARAM', 'RangeError', key + ' is not a valid Brotli parameter');
    }
    var val = params[key];
    if (typeof val !== 'number' && typeof val !== 'boolean') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "params[' + key + ']" argument must be of type number or boolean. Received type ' + typeof val);
    }
    // Boolean-only params must be true or false (not arbitrary numbers)
    if (BROTLI_BOOLEAN_PARAMS.indexOf(numKey) !== -1) {
      if (typeof val === 'number' && val !== 0 && val !== 1) {
        throw makeError('ERR_ZLIB_INITIALIZATION_FAILED', 'Error', 'Initialization failed');
      }
    }
  }
}

function brotliCompressSync(data, options) {
  validateInput(data);
  var bytes = toBytes(data);
  var quality = 11; // BROTLI_DEFAULT_QUALITY
  if (options) {
    if (options.flush !== undefined) {
      if (typeof options.flush !== 'number' || !isFinite(options.flush) || options.flush < 0 || options.flush > 3) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.flush" is out of range. It must be >= 0 and <= 3. Received ' + String(options.flush));
      }
    }
    if (options.finishFlush !== undefined) {
      if (typeof options.finishFlush !== 'number' || !isFinite(options.finishFlush) || options.finishFlush < 0 || options.finishFlush > 3) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.finishFlush" is out of range. It must be >= 0 and <= 3. Received ' + String(options.finishFlush));
      }
    }
    if (options.params) {
      validateBrotliParams(options.params);
      if (options.params[1] !== undefined) {
        quality = options.params[1];
      }
    }
  }
  if (typeof __exactBrotliCompressSync !== 'function') throw new Error('brotliCompressSync not available');
  var buf = toBuffer(__exactBrotliCompressSync(bytes, quality));
  if (options && options.info) return { engine: new BrotliCompress(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function brotliDecompressSync(data, options) {
  validateInput(data);
  var bytes = toBytes(data);
  var maxOutputLength = validateMaxOutputLength(options);
  if (typeof __exactBrotliDecompressSync !== 'function') throw new Error('brotliDecompressSync not available');
  var result;
  try {
    result = __exactBrotliDecompressSync(
      bytes,
      false,
      0,
      nativeZlibOutputBudget(maxOutputLength, 0));
  } catch (e) {
    var outputError = nativeZlibOutputError(e);
    if (outputError) throw outputError;
    throw e;
  }
  checkMaxOutputLength(result.length, maxOutputLength);
  checkKMaxLength(result.length);
  var buf = toBuffer(result);
  if (options && options.info) return { engine: new BrotliDecompress(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

// ---------------------------------------------------------------------------
// Zstd
//
// The host ABI registers only deflate/inflate/brotli one-shot codecs (see
// hermes_runtime_crypto.cc) — there is NO native zstd backend. The previous
// implementation silently fell back to raw zlib-deflate output labelled as
// zstd: bytes produced by zstdCompressSync failed in any real zstd decoder
// ("unknown frame descriptor"), and the empty-input special case emitted a
// genuine zstd frame that the inflate fallback then couldn't parse
// (zstdDecompressSync(zstdCompressSync(Buffer.alloc(0))) threw). Rather than
// emit wrong-format data with no error, we surface ENOSYS until a real native
// zstd bridge is wired up. The `typeof __exactZstd*Sync === 'function'` guards
// remain so registering that bridge later transparently enables zstd.
// ---------------------------------------------------------------------------

function zstdNotSupported(op) {
  var err = new Error(
    'zstd ' + op + ' is not supported: this runtime has no native zstd backend registered');
  err.code = 'ENOSYS';
  return err;
}

function zstdCompressSync(data, options) {
  validateInput(data);
  var bytes = toBytes(data);
  if (typeof __exactZstdCompressSync !== 'function') {
    throw zstdNotSupported('compression');
  }
  var level = -1;
  if (options && options.level !== undefined) {
    level = options.level;
  } else if (options && options.params && options.params[100] !== undefined) {
    level = options.params[100];
  }
  var buf = toBuffer(__exactZstdCompressSync(bytes, level));
  if (options && options.info) return { engine: new ZstdCompress(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function zstdDecompressSync(data, options) {
  validateInput(data);
  var bytes = toBytes(data);
  var maxOutputLength = validateMaxOutputLength(options);
  if (typeof __exactZstdDecompressSync !== 'function') {
    throw zstdNotSupported('decompression');
  }
  var result;
  try {
    result = __exactZstdDecompressSync(
      bytes,
      nativeZlibOutputBudget(maxOutputLength, 0));
  } catch (e) {
    var outputError = nativeZlibOutputError(e);
    if (outputError) throw outputError;
    throw e;
  }
  checkMaxOutputLength(result.length, maxOutputLength);
  checkKMaxLength(result.length);
  var buf = toBuffer(result);
  if (options && options.info) return { engine: new ZstdDecompress(options), buffer: buf }; // eslint-disable-line no-use-before-define
  return buf;
}

function zstdCompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new ZstdCompress(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = zstdCompressSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function zstdDecompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new ZstdDecompress(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = zstdDecompressSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

// ---------------------------------------------------------------------------
// Options validation helpers
// ---------------------------------------------------------------------------

function validateLevelArg(val, name) {
  if (typeof val !== 'number') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "' + name + '" argument must be of type number. Received type ' + typeof val + " ('" + String(val) + "')");
  }
  if (!isFinite(val)) {
    throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
      'The value of "' + name + '" is out of range. It must be a finite number. Received ' + String(val));
  }
  if (val < -1 || val > 9) {
    throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
      'The value of "' + name + '" is out of range. It must be >= -1 and <= 9. Received ' + String(val));
  }
}

function validateStrategyArg(val, name) {
  if (typeof val !== 'number') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "' + name + '" argument must be of type number. Received type ' + typeof val + " ('" + String(val) + "')");
  }
  if (!isFinite(val)) {
    throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
      'The value of "' + name + '" is out of range. It must be a finite number. Received ' + String(val));
  }
  if (val < 0 || val > 4) {
    throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
      'The value of "' + name + '" is out of range. It must be >= 0 and <= 4. Received ' + String(val));
  }
}

function validateZlibOptions(opts, isDeflater, isGzip) {
  if (!opts) return;
  if (opts.chunkSize !== undefined) {
    if (typeof opts.chunkSize !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.chunkSize" property must be of type number. Received type ' + typeof opts.chunkSize + " ('" + String(opts.chunkSize) + "')");
    }
    if (!isFinite(opts.chunkSize)) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.chunkSize" is out of range. It must be a finite number. Received ' + String(opts.chunkSize));
    }
    if (opts.chunkSize < 64) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.chunkSize" is out of range. It must be >= 64. Received ' + String(opts.chunkSize));
    }
  }
  if (opts.windowBits !== undefined) {
    if (typeof opts.windowBits !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.windowBits" property must be of type number. Received type ' + typeof opts.windowBits + " ('" + String(opts.windowBits) + "')");
    }
    if (!isFinite(opts.windowBits)) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.windowBits" is out of range. It must be a finite number. Received ' + String(opts.windowBits));
    }
    if (isDeflater) {
      var minWin = isGzip ? 9 : 8;
      if (opts.windowBits < minWin || opts.windowBits > 15) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.windowBits" is out of range. It must be >= ' + minWin + ' and <= 15. Received ' + String(opts.windowBits));
      }
    }
  }
  if (opts.level !== undefined) {
    if (typeof opts.level !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.level" property must be of type number. Received type ' + typeof opts.level + " ('" + String(opts.level) + "')");
    }
    // NaN for level is treated as default (Z_DEFAULT_COMPRESSION) - matches Node.js behavior
    if (!isNaN(opts.level)) {
      if (!isFinite(opts.level)) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.level" is out of range. It must be a finite number. Received ' + String(opts.level));
      }
      if (opts.level < -1 || opts.level > 9) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.level" is out of range. It must be >= -1 and <= 9. Received ' + String(opts.level));
      }
    }
  }
  if (opts.memLevel !== undefined) {
    if (typeof opts.memLevel !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.memLevel" property must be of type number. Received type ' + typeof opts.memLevel + " ('" + String(opts.memLevel) + "')");
    }
    if (!isFinite(opts.memLevel)) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.memLevel" is out of range. It must be a finite number. Received ' + String(opts.memLevel));
    }
    if (opts.memLevel < 1 || opts.memLevel > 9) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.memLevel" is out of range. It must be >= 1 and <= 9. Received ' + String(opts.memLevel));
    }
  }
  if (opts.strategy !== undefined) {
    if (typeof opts.strategy !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.strategy" property must be of type number. Received type ' + typeof opts.strategy + " ('" + String(opts.strategy) + "')");
    }
    // NaN for strategy is treated as default (Z_DEFAULT_STRATEGY) - matches Node.js behavior
    if (!isNaN(opts.strategy)) {
      if (!isFinite(opts.strategy)) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.strategy" is out of range. It must be a finite number. Received ' + String(opts.strategy));
      }
      if (opts.strategy < 0 || opts.strategy > 4) {
        throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
          'The value of "options.strategy" is out of range. It must be >= 0 and <= 4. Received ' + String(opts.strategy));
      }
    }
  }
  if (opts.flush !== undefined) {
    if (typeof opts.flush !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.flush" property must be of type number. Received type ' + typeof opts.flush + " ('" + String(opts.flush) + "')");
    }
    if (!isFinite(opts.flush) || opts.flush < 0 || opts.flush > 5) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.flush" is out of range. It must be >= 0 and <= 5. Received ' + String(opts.flush));
    }
  }
  if (opts.finishFlush !== undefined) {
    if (typeof opts.finishFlush !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.finishFlush" property must be of type number. Received type ' + typeof opts.finishFlush + " ('" + String(opts.finishFlush) + "')");
    }
    if (!isFinite(opts.finishFlush) || opts.finishFlush < 0 || opts.finishFlush > 5) {
      throw makeError('ERR_OUT_OF_RANGE', 'RangeError',
        'The value of "options.finishFlush" is out of range. It must be >= 0 and <= 5. Received ' + String(opts.finishFlush));
    }
  }
  if (opts.dictionary !== undefined) {
    if (!(typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(opts.dictionary)) &&
        !(opts.dictionary instanceof ArrayBuffer) &&
        !ArrayBuffer.isView(opts.dictionary)) {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "options.dictionary" property must be an instance of Buffer, TypedArray, DataView, or ArrayBuffer. Received type ' + typeof opts.dictionary + " ('" + String(opts.dictionary) + "')");
    }
  }
}

// ---------------------------------------------------------------------------
// Async convenience functions
// All require a callback; throw ERR_INVALID_ARG_TYPE if missing.
// Note: Stream constructors (Deflate, Inflate, etc.) are function declarations
// and thus hoisted, so they can be referenced here before their declaration.
// ---------------------------------------------------------------------------

function deflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new Deflate(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = deflateSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function inflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new Inflate(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = inflateSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function gzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new Gzip(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = gzipSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function gunzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new Gunzip(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = gunzipSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function unzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new Unzip(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = unzipSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function inflateRaw(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new InflateRaw(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = inflateRawSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function deflateRaw(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new DeflateRaw(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = deflateRawSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function brotliCompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new BrotliCompress(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = brotliCompressSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

function brotliDecompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof callback !== 'function') {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "callback" argument must be of type function. Received undefined');
  }
  var info = options && options.info;
  var engine = info ? new BrotliDecompress(options) : null; // eslint-disable-line no-use-before-define
  var syncOpts = info ? Object.assign({}, options, { info: false }) : options;
  try {
    var result = brotliDecompressSync(data, syncOpts);
    var ret = info ? { engine: engine, buffer: result } : result;
    setTimeout(function() { callback(null, ret); }, 0);
  } catch(e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

// ---------------------------------------------------------------------------
// Stream wrapper functions - return { output, consumed } for decoders
// ---------------------------------------------------------------------------

function inflateStreamFn(buf) {
  var r = inflateSyncConsumed(
    toBytes(buf),
    0,
    this._finishFlush === 2 ? 3 : 2,
    nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
  return { output: r[0], consumed: r[1] };
}

function gunzipStreamFn(buf) {
  var r = inflateSyncConsumed(
    toBytes(buf),
    1,
    this._finishFlush === 2 ? 3 : 2,
    nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
  return { output: r[0], consumed: r[1] };
}

function inflateRawStreamFn(buf) {
  var r = inflateSyncConsumed(
    toBytes(buf),
    2,
    this._finishFlush === 2 ? 3 : 2,
    nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
  return { output: r[0], consumed: r[1] };
}

function unzipStreamFn(buf) {
  // mode=1: auto-detect gzip/deflate (handles both via windowBits=15+32)
  var r = inflateSyncConsumed(
    toBytes(buf),
    1,
    this._finishFlush === 2 ? 3 : 2,
    nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
  return { output: r[0], consumed: r[1] };
}

// ---------------------------------------------------------------------------
// ZlibTransform base class
// ---------------------------------------------------------------------------

function ZlibTransform(syncFn, opts, isDecoder, nativeMode, dictionary) {
  // The second argument is an Ibex-internal stream-core hook. It is retained
  // in a module-private WeakMap by node:stream, so even a saved base-prototype
  // write/end/destroy method must authenticate before it mutates stream state.
  registerNativeZlibStreamOwner(this);
  Transform.call(this, opts, assertNativeZlibStreamOwner);
  this._syncFn = syncFn;
  this._isDecoder = !!isDecoder;
  this._chunks = [];
  this._bytesWritten = 0;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this._handle = {};
  this._flushed = false;
  this._nativeMode = typeof nativeMode === 'number' ? nativeMode : null;
  this._nativeKind = this._isDecoder ? ZLIB_STREAM_INFLATE : ZLIB_STREAM_DEFLATE;
  this._nativeDictionary = dictionary;
  this._nativeAvailable = this._nativeMode !== null && nativeZlibStreamsAvailable();
  this._outputLength = 0;

  this._level = (opts && opts.level !== undefined && !isNaN(opts.level) && isFinite(opts.level)) ? opts.level : -1;
  this._strategy = (opts && opts.strategy !== undefined && !isNaN(opts.strategy) && isFinite(opts.strategy)) ? opts.strategy : 0;
  this._finishFlush = opts && opts.finishFlush;
  this._flushFlag = opts && opts.flush !== undefined ? opts.flush : Z_NO_FLUSH;
  this._maxOutputLength = isDecoder ? validateMaxOutputLength(opts) : Infinity;

  // Establish native runtime/principal ownership at construction, before a
  // retained stream can be destroyed or queued by another compartment.
  if (this._nativeAvailable) this._ensureNativeStream();

  var self = this;
  var defaultFinal = this._final;
  this._final = function(callback) {
    if (typeof callback !== 'function') callback = function() {};
    if (self._flushed) {
      // Already flushed, just finish
      if (typeof defaultFinal === 'function') {
        defaultFinal.call(self, callback);
      } else {
        callback();
      }
      return;
    }
    self._flush(function(err) {
      if (err) {
        callback(err);
        return;
      }
      if (typeof defaultFinal === 'function') {
        defaultFinal.call(self, callback);
      } else {
        callback();
      }
    });
  };
  sealNativeZlibOwnerState(this);
}
ZlibTransform.prototype = Object.create(Transform.prototype);
ZlibTransform.prototype.constructor = ZlibTransform;

ZlibTransform.prototype.setEncoding = function(enc) {
  assertNativeZlibStreamOwner(this);
  if (Transform.prototype.setEncoding) {
    return Transform.prototype.setEncoding.call(this, enc);
  }
  this._readableEncoding = enc;
  return this;
};

ZlibTransform.prototype._ensureNativeStream = function() {
  if (!this._nativeAvailable) return false;
  if (_nativeZlibStreamIds.get(this)) {
    assertNativeZlibStreamOwner(this);
    return true;
  }
  // @ref LLP 0004#the-zlib-builtin — stream transforms use native z_stream state
  // when the bridge exists, falling back only for JS-only one-shot harnesses.
  var id = __exactZlibCreate(
    this._nativeKind,
    this._nativeMode,
    this._level,
    this._strategy,
    this._nativeDictionary);
  _nativeZlibStreamIds.set(this, id);
  return true;
};

ZlibTransform.prototype._closeNativeStream = function() {
  var id = _nativeZlibStreamIds && _nativeZlibStreamIds.get(this);
  if (!id) return;
  if (typeof __exactZlibClose === 'function') {
    __exactZlibClose(id);
    // The native registry remains authoritative until close succeeds. In
    // particular, a principal-mismatch exception must not strand the owner's
    // stream by forgetting the only ID it can use to retry cleanup.
    _nativeZlibStreamIds.delete(this);
  }
};

ZlibTransform.prototype._pushNativeOutput = function(raw) {
  assertNativeZlibStreamOwner(this);
  var result = toBuffer(raw || new Uint8Array(0));
  if (this._isDecoder) {
    var nextLength = this._outputLength + result.length;
    checkMaxOutputLength(nextLength, this._maxOutputLength);
    this._outputLength = nextLength;
    this.bytesRead = this.bytesWritten;
  }
  if (result.length > 0) {
    this.push(result);
  }
  return result;
};

ZlibTransform.prototype._writeNative = function(chunk, flushFlag, final) {
  assertNativeZlibStreamOwner(this);
  var raw = __exactZlibWrite(
    _nativeZlibStreamIds.get(this),
    copyBytesForNative(chunk || Buffer.alloc(0)),
    flushFlag,
    !!final,
    this._isDecoder && this._finishFlush === Z_SYNC_FLUSH,
    this._isDecoder
      ? nativeZlibOutputBudget(this._maxOutputLength, this._outputLength)
      : NATIVE_ZLIB_OUTPUT_LIMIT);
  return this._pushNativeOutput(raw);
};

ZlibTransform.prototype.write = function(chunk, encoding, callback) {
  assertNativeZlibStreamOwner(this);
  if (chunk !== null && chunk !== undefined &&
      typeof chunk !== 'string' &&
      !Buffer.isBuffer(chunk) &&
      !(chunk instanceof ArrayBuffer) &&
      !ArrayBuffer.isView(chunk)) {
    // Always throw synchronously for invalid types, even in objectMode
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'Invalid data, chunk must be a string or Buffer, not ' + (typeof chunk));
  }
  return Transform.prototype.write.call(this, chunk, encoding, callback);
};

ZlibTransform.prototype.end = function(chunk, encoding, callback) {
  assertNativeZlibStreamOwner(this);
  return Transform.prototype.end.call(this, chunk, encoding, callback);
};

ZlibTransform.prototype._transform = function(chunk, encoding, callback) {
  assertNativeZlibStreamOwner(this);
  var control = getZlibControlMarker(chunk);
  if (control) {
    try {
      if (control.type === 'flush') {
        if (this._ensureNativeStream()) {
          this._writeNative(Buffer.alloc(0), control.kind, false);
        }
      } else if (control.type === 'params') {
        this._level = control.level;
        this._strategy = control.strategy;
        if (!this._isDecoder && this._ensureNativeStream()) {
          this._pushNativeOutput(__exactZlibParams(
            _nativeZlibStreamIds.get(this), control.level, control.strategy));
        }
      }
      callback();
    } catch (controlErr) {
      callback(normalizeZlibStreamError(controlErr));
    }
    return;
  }
  if (chunk !== null && chunk !== undefined &&
      typeof chunk !== 'string' &&
      !Buffer.isBuffer(chunk) &&
      !(chunk instanceof ArrayBuffer) &&
      !ArrayBuffer.isView(chunk)) {
    var err = makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'Invalid data, chunk must be a string or Buffer, not ' + typeof chunk);
    if (typeof callback === 'function') {
      callback(err);
    } else {
      this.emit('error', err);
    }
    return;
  }

  this._bytesWritten += countBytesForChunk(chunk, encoding || 'utf8');
  this.bytesWritten = this._bytesWritten;

  var inputChunk = chunk;
  if (typeof chunk === 'string') {
    inputChunk = Buffer.from(chunk, encoding);
  }

  if (this._ensureNativeStream()) {
    try {
      this._writeNative(inputChunk, this._flushFlag, false);
      if (typeof callback === 'function') callback();
    } catch (e) {
      if (typeof callback === 'function') {
        callback(normalizeZlibStreamError(e));
      } else {
        this.emit('error', normalizeZlibStreamError(e));
      }
    }
    return;
  }

  this._chunks.push(inputChunk);
  if (typeof callback !== 'function') return;
  if (typeof process === 'object' && process && typeof process.nextTick === 'function') {
    process.nextTick(callback);
  } else {
    setTimeout(callback, 0);
  }
};

ZlibTransform.prototype._flush = function(callback) {
  assertNativeZlibStreamOwner(this);
  if (typeof callback !== 'function') callback = function() {};
  if (this._flushed) { callback(); return; }
  this._flushed = true;
  if (this._ensureNativeStream()) {
    var streamErr = null;
    try {
      var finalFlush = this._isDecoder && this._finishFlush === Z_SYNC_FLUSH ? Z_SYNC_FLUSH : Z_FINISH;
      this._writeNative(Buffer.alloc(0), finalFlush, true);
    } catch (e) {
      streamErr = e;
    }
    try {
      this._closeNativeStream();
    } catch (closeErr) {
      // Preserve the codec failure when best-effort cleanup also fails. The
      // private stream ID remains registered so destruction by the owner can
      // retry the close.
      if (!streamErr) streamErr = closeErr;
    }
    callback(streamErr ? normalizeZlibStreamError(streamErr) : undefined);
    return;
  }
  try {
    var input = concatChunks(this._chunks);

    // Handle multi-member gzip streams (concatenated gzip)
    if (this._multiMember && input.length > 0) {
      var allOutputs = [];
      var remaining = input;
      var totalConsumed = 0;

      while (remaining.length > 0) {
        var resultRaw;
        try {
          resultRaw = this._syncFn.call(this, remaining);
        } catch (innerErr) {
          throw innerErr;
        }

        var memberOutput;
        var consumed = remaining.length;
        if (resultRaw && typeof resultRaw === 'object' && resultRaw.output !== undefined) {
          memberOutput = resultRaw.output;
          if (typeof resultRaw.consumed === 'number') {
            consumed = resultRaw.consumed;
          }
        } else {
          memberOutput = resultRaw;
        }

        allOutputs.push(memberOutput);
        totalConsumed += consumed;

        if (consumed >= remaining.length || consumed === 0) break;
        remaining = remaining.slice(consumed);
      }

      var finalResult = allOutputs.length === 1 ? allOutputs[0] : Buffer.concat(allOutputs);
      checkMaxOutputLength(finalResult.length, this._maxOutputLength);

      if (this._isDecoder) {
        this._bytesWritten = totalConsumed;
        this.bytesWritten = totalConsumed;
        this.bytesRead = this.bytesWritten;
      }

      this.push(finalResult);
      callback();
      return;
    }

    var resultRaw = this._syncFn.call(this, input);

    var result;
    if (resultRaw && typeof resultRaw === 'object' && resultRaw.output !== undefined) {
      result = resultRaw.output;
      if (this._isDecoder && typeof resultRaw.consumed === 'number') {
        this._bytesWritten = resultRaw.consumed;
        this.bytesWritten = resultRaw.consumed;
      }
    } else {
      result = resultRaw;
    }

    if (this._isDecoder) {
      this.bytesRead = this.bytesWritten;
      checkMaxOutputLength(result.length, this._maxOutputLength);
    }

    this.push(result);
    callback();
  } catch (e) {
    var finalErr = e;
    if (e && e.message) {
      var msg = e.message;
      // Map inflate error messages to Z_DATA_ERROR
      if (/^inflate failed:/.test(msg)) {
        var detail = msg.replace(/^inflate failed:\s*(data error:\s*)?/, '');
        finalErr = new Error(detail);
        var unexpectedEnd = /unexpected end of file/.test(msg);
        finalErr.code = unexpectedEnd ? 'Z_BUF_ERROR' : 'Z_DATA_ERROR';
        finalErr.errno = unexpectedEnd ? -5 : -3;
      } else if (!e.code && /unexpected end of file|invalid stored block|invalid block type|unknown compression method|incorrect data check/.test(msg)) {
        finalErr = new Error(msg);
        var secondaryUnexpectedEnd = /unexpected end of file/.test(msg);
        finalErr.code = secondaryUnexpectedEnd ? 'Z_BUF_ERROR' : 'Z_DATA_ERROR';
        finalErr.errno = secondaryUnexpectedEnd ? -5 : -3;
      }
    }
    // @ref LLP 0004#the-zlib-builtin — the one-shot fallback still enforces
    // the decoder budget natively, so normalize its overflow like every other
    // stream path instead of leaking the bridge's internal error message.
    callback(normalizeZlibStreamError(finalErr));
  }
};

ZlibTransform.prototype.flush = function(kind, callback) {
  assertNativeZlibStreamOwner(this);
  if (typeof kind === 'function') {
    callback = kind;
    kind = undefined;
  }
  var flushCallback = typeof callback === 'function' ? callback : null;
  if (this._flushed || this.writableEnded ||
      (this._writableState && (this._writableState.ended || this._writableState.finished))) {
    if (flushCallback) {
      if (typeof process === 'object' && process && typeof process.nextTick === 'function') process.nextTick(flushCallback);
      else setTimeout(flushCallback, 0);
    }
    return this;
  }
  var marker = Buffer.alloc(0);
  setZlibControlMarker(marker, { type: 'flush', kind: kind === undefined ? Z_FULL_FLUSH : kind });
  // A zero-byte control write is serialized by Transform behind all writes
  // already accepted by the writable side, matching Node's flush ordering.
  Transform.prototype.write.call(this, marker, function(err) {
    if (flushCallback) flushCallback(err);
  });
  return this;
};

ZlibTransform.prototype.reset = function() {
  assertNativeZlibStreamOwner(this);
  this._closeNativeStream();
  this._chunks = [];
  this._bytesWritten = 0;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this._flushed = false;
  this._outputLength = 0;
  // Closing removes the old native selector. Re-establish ownership before
  // reset returns so a retained foreign wrapper never observes an unguarded
  // live interval between reset and the next write.
  if (this._nativeAvailable) this._ensureNativeStream();
  return this;
};

ZlibTransform.prototype.params = function(level, strategy, callback) {
  assertNativeZlibStreamOwner(this);
  validateLevelArg(level, 'level');
  validateStrategyArg(strategy, 'strategy');
  var marker = Buffer.alloc(0);
  setZlibControlMarker(marker, { type: 'params', level: level, strategy: strategy });
  Transform.prototype.write.call(this, marker, function(err) {
    if (typeof callback === 'function') callback(err);
  });
  return this;
};

ZlibTransform.prototype.close = function(callback) {
  return this.destroy(null, callback);
};

ZlibTransform.prototype.destroy = function(err, callback) {
  // Transform.destroy mutates its JS lifecycle flags before `_destroy` runs.
  // Reject a wrong principal synchronously while both JS and native state are
  // untouched, leaving the real owner a working cleanup path.
  assertNativeZlibStreamOwner(this);
  return Transform.prototype.destroy.call(this, err, callback);
};

ZlibTransform.prototype._destroy = function(err, callback) {
  assertNativeZlibStreamOwner(this);
  this._closeNativeStream();
  this._handle = null;
  if (typeof callback === 'function') callback(err);
};

// _processChunk: synchronous compress/decompress (used by tests)
ZlibTransform.prototype._processChunk = function(chunk, flushFlag) {
  var resultRaw = this._syncFn.call(this, chunk);
  if (resultRaw && typeof resultRaw === 'object' && resultRaw.output !== undefined) {
    return resultRaw.output;
  }
  return resultRaw;
};

// ---------------------------------------------------------------------------
// Concrete stream classes
// ---------------------------------------------------------------------------

function Deflate(opts) {
  if (!(this instanceof Deflate)) return new Deflate(opts);
  validateZlibOptions(opts, true, false);
  var _dict = (opts && opts.dictionary) ? toBytes(opts.dictionary) : undefined;
  ZlibTransform.call(this, function(buf) {
    var level = this._level;
    return toBuffer(_nativeDeflateSync(toBytes(buf), level, 0, _dict));
  }, opts, false, 0, _dict);
}
Deflate.prototype = Object.create(ZlibTransform.prototype);
Deflate.prototype.constructor = Deflate;

function Inflate(opts) {
  if (!(this instanceof Inflate)) return new Inflate(opts);
  validateZlibOptions(opts, false, false);
  var _dict = (opts && opts.dictionary) ? toBytes(opts.dictionary) : undefined;
  ZlibTransform.call(this, function(buf) {
    var r = _nativeInflateSync(
      toBytes(buf),
      0,
      false,
      this._finishFlush === 2 ? 3 : 2,
      _dict,
      nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
    if (Array.isArray(r)) return { output: toBuffer(r[0]), consumed: r[1] };
    return { output: toBuffer(r), consumed: toBytes(buf).length };
  }, opts, true, 0, _dict);
}
Inflate.prototype = Object.create(ZlibTransform.prototype);
Inflate.prototype.constructor = Inflate;

function Gzip(opts) {
  if (!(this instanceof Gzip)) return new Gzip(opts);
  validateZlibOptions(opts, true, true);
  ZlibTransform.call(this, function(buf) {
    var level = this._level;
    return toBuffer(_nativeDeflateSync(toBytes(buf), level, 1));
  }, opts, false, 1);
}
Gzip.prototype = Object.create(ZlibTransform.prototype);
Gzip.prototype.constructor = Gzip;

function Gunzip(opts) {
  if (!(this instanceof Gunzip)) return new Gunzip(opts);
  validateZlibOptions(opts, false, true);
  ZlibTransform.call(this, gunzipStreamFn, opts, true, 1);
  this._multiMember = true;
}
Gunzip.prototype = Object.create(ZlibTransform.prototype);
Gunzip.prototype.constructor = Gunzip;

function DeflateRaw(opts) {
  if (!(this instanceof DeflateRaw)) return new DeflateRaw(opts);
  validateZlibOptions(opts, true, false);
  var _opts = opts;
  var _dict = (_opts && _opts.dictionary) ? toBytes(_opts.dictionary) : undefined;
  ZlibTransform.call(this, function(buf) {
    var level = this._level;
    return toBuffer(_nativeDeflateSync(toBytes(buf), level, 2, _dict));
  }, opts, false, 2, _dict);
}
DeflateRaw.prototype = Object.create(ZlibTransform.prototype);
DeflateRaw.prototype.constructor = DeflateRaw;

function InflateRaw(opts) {
  if (!(this instanceof InflateRaw)) return new InflateRaw(opts);
  validateZlibOptions(opts, false, false);
  var _dict = (opts && opts.dictionary) ? toBytes(opts.dictionary) : undefined;
  ZlibTransform.call(this, function(buf) {
    var r = _nativeInflateSync(
      toBytes(buf),
      2,
      false,
      this._finishFlush === 2 ? 3 : 2,
      _dict,
      nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
    if (Array.isArray(r)) return { output: toBuffer(r[0]), consumed: r[1] };
    return { output: toBuffer(r), consumed: toBytes(buf).length };
  }, opts, true, 2, _dict);
}
InflateRaw.prototype = Object.create(ZlibTransform.prototype);
InflateRaw.prototype.constructor = InflateRaw;

function Unzip(opts) {
  if (!(this instanceof Unzip)) return new Unzip(opts);
  validateZlibOptions(opts, false, true);
  ZlibTransform.call(this, unzipStreamFn, opts, true, 1);
  this._multiMember = true;
}
Unzip.prototype = Object.create(ZlibTransform.prototype);
Unzip.prototype.constructor = Unzip;

function BrotliCompress(opts) {
  if (!(this instanceof BrotliCompress)) return new BrotliCompress(opts);
  if (opts && opts.params) {
    validateBrotliParams(opts.params);
  }
  var _opts = opts;
  ZlibTransform.call(this, function(buf) { return brotliCompressSync(buf, _opts); }, opts, false);
}
BrotliCompress.prototype = Object.create(ZlibTransform.prototype);
BrotliCompress.prototype.constructor = BrotliCompress;

function BrotliDecompress(opts) {
  if (!(this instanceof BrotliDecompress)) return new BrotliDecompress(opts);
  ZlibTransform.call(this, function(buf) {
    var r = brotliDecompressSyncConsumed(
      toBytes(buf),
      nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
    return { output: r[0], consumed: r[1] };
  }, opts, true);
}
BrotliDecompress.prototype = Object.create(ZlibTransform.prototype);
BrotliDecompress.prototype.constructor = BrotliDecompress;

// Zstd stream classes. Like the sync entry points, these surface ENOSYS rather
// than emitting zlib-deflate bytes mislabelled as zstd (see the Zstd section
// above). The error propagates through _flush as a stream 'error' event.

function ZstdCompress(opts) {
  if (!(this instanceof ZstdCompress)) return new ZstdCompress(opts);
  var _opts = opts;
  ZlibTransform.call(this, function(buf) {
    if (typeof __exactZstdCompressSync !== 'function') {
      throw zstdNotSupported('compression');
    }
    var bytes = toBytes(buf);
    var level = -1;
    if (_opts && _opts.level !== undefined) {
      level = _opts.level;
    } else if (_opts && _opts.params && _opts.params[100] !== undefined) {
      level = _opts.params[100];
    }
    return toBuffer(__exactZstdCompressSync(bytes, level));
  }, opts, false);
}
ZstdCompress.prototype = Object.create(ZlibTransform.prototype);
ZstdCompress.prototype.constructor = ZstdCompress;

function ZstdDecompress(opts) {
  if (!(this instanceof ZstdDecompress)) return new ZstdDecompress(opts);
  ZlibTransform.call(this, function(buf) {
    if (typeof __exactZstdDecompressSync !== 'function') {
      throw zstdNotSupported('decompression');
    }
    var bytes = toBytes(buf);
    var r = __exactZstdDecompressSync(
      bytes,
      nativeZlibOutputBudget(this._maxOutputLength, this._outputLength));
    return { output: toBuffer(r), consumed: bytes.length };
  }, opts, true);
}
ZstdDecompress.prototype = Object.create(ZlibTransform.prototype);
ZstdDecompress.prototype.constructor = ZstdDecompress;

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

function createDeflate(options) { return new Deflate(options); }
function createInflate(options) { return new Inflate(options); }
function createGzip(options) { return new Gzip(options); }
function createGunzip(options) { return new Gunzip(options); }
function createDeflateRaw(options) { return new DeflateRaw(options); }
function createInflateRaw(options) { return new InflateRaw(options); }
function createUnzip(options) { return new Unzip(options); }
function createBrotliCompress(options) { return new BrotliCompress(options); }
function createBrotliDecompress(options) { return new BrotliDecompress(options); }
function createZstdCompress(options) { return new ZstdCompress(options); }
function createZstdDecompress(options) { return new ZstdDecompress(options); }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

var constants = Object.freeze({
  Z_NO_COMPRESSION: 0,
  Z_BEST_SPEED: 1,
  Z_BEST_COMPRESSION: 9,
  Z_DEFAULT_COMPRESSION: -1,
  Z_FILTERED: 1,
  Z_HUFFMAN_ONLY: 2,
  Z_RLE: 3,
  Z_FIXED: 4,
  Z_DEFAULT_STRATEGY: 0,
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
  Z_MAX_CHUNK: Infinity,
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
});

// zlib.codes - frozen mapping
var codes = Object.freeze({
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_NEED_DICT: 2,
  Z_ERRNO: -1,
  Z_STREAM_ERROR: -2,
  Z_DATA_ERROR: -3,
  Z_MEM_ERROR: -4,
  Z_BUF_ERROR: -5,
  Z_VERSION_ERROR: -6
});

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------

var _crc32Table = null;
function _getCrc32Table() {
  if (_crc32Table) return _crc32Table;
  _crc32Table = new Uint32Array(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) {
      if (c & 1) {
        c = 0xEDB88320 ^ (c >>> 1);
      } else {
        c = c >>> 1;
      }
    }
    _crc32Table[i] = c;
  }
  return _crc32Table;
}

function crc32(data, value) {
  // Validate first argument
  if (typeof data !== 'string' &&
      !(typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) &&
      !ArrayBuffer.isView(data) &&
      !(data instanceof ArrayBuffer)) {
    throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
      'The "data" argument must be of type string or an instance of Buffer, TypedArray, or DataView.' +
      invalidArgTypeHelper(data));
  }
  // Validate second argument
  if (value !== undefined) {
    if (typeof value !== 'number') {
      throw makeError('ERR_INVALID_ARG_TYPE', 'TypeError',
        'The "value" argument must be of type number.' +
        invalidArgTypeHelper(value));
    }
  }

  // Use native if available
  if (typeof __exactCrc32 === 'function') {
    var bytes = toBytes(data);
    return __exactCrc32(bytes, value || 0) >>> 0;
  }

  // Pure JS CRC32 implementation
  var table = _getCrc32Table();
  var crc = (value !== undefined ? value : 0) ^ 0xFFFFFFFF;
  var buf;
  if (typeof data === 'string') {
    buf = toBytes(data);
  } else if (data instanceof ArrayBuffer) {
    buf = new Uint8Array(data);
  } else if (ArrayBuffer.isView(data)) {
    buf = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  } else {
    buf = data;
  }
  for (var i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

var zlibExports = {
  deflateSync: deflateSync,
  inflateSync: inflateSync,
  gzipSync: gzipSync,
  gunzipSync: gunzipSync,
  deflateRawSync: deflateRawSync,
  inflateRawSync: inflateRawSync,
  unzipSync: unzipSync,
  brotliCompressSync: brotliCompressSync,
  brotliDecompressSync: brotliDecompressSync,
  zstdCompressSync: zstdCompressSync,
  zstdDecompressSync: zstdDecompressSync,
  deflate: deflate,
  inflate: inflate,
  gzip: gzip,
  gunzip: gunzip,
  deflateRaw: deflateRaw,
  inflateRaw: inflateRaw,
  unzip: unzip,
  brotliCompress: brotliCompress,
  brotliDecompress: brotliDecompress,
  zstdCompress: zstdCompress,
  zstdDecompress: zstdDecompress,
  createDeflate: createDeflate,
  createInflate: createInflate,
  createGzip: createGzip,
  createGunzip: createGunzip,
  createDeflateRaw: createDeflateRaw,
  createInflateRaw: createInflateRaw,
  createUnzip: createUnzip,
  createBrotliCompress: createBrotliCompress,
  createBrotliDecompress: createBrotliDecompress,
  createZstdCompress: createZstdCompress,
  createZstdDecompress: createZstdDecompress,
  Deflate: Deflate,
  Inflate: Inflate,
  Gzip: Gzip,
  Gunzip: Gunzip,
  DeflateRaw: DeflateRaw,
  InflateRaw: InflateRaw,
  Unzip: Unzip,
  BrotliCompress: BrotliCompress,
  BrotliDecompress: BrotliDecompress,
  ZstdCompress: ZstdCompress,
  ZstdDecompress: ZstdDecompress,
  constants: constants,
  crc32: crc32
};

// Make 'codes' non-writable on module exports (setter must throw TypeError)
Object.defineProperty(zlibExports, 'codes', {
  get: function() { return codes; },
  set: function() { throw new TypeError('Cannot assign to read only property \'codes\' of object'); },
  enumerable: true,
  configurable: false
});

// Expose constants directly on exports as non-writable
var constKeys = Object.keys(constants);
for (var k = 0; k < constKeys.length; k++) {
  (function(key) {
    Object.defineProperty(zlibExports, key, {
      get: function() { return constants[key]; },
      set: function() {},
      enumerable: true,
      configurable: false
    });
  })(constKeys[k]);
}

module.exports = zlibExports;
