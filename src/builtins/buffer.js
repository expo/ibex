var BufferProto = {};

function coerceEncoding(encoding) {
  if (!encoding) return "utf8";
  var normalized = String(encoding).toLowerCase().replace("-", "");
  if (normalized === "utf8") return "utf8";
  if (normalized === "utf-8") return "utf8";
  return normalized;
}

function _isValidEncoding(enc) {
  if (typeof enc !== 'string') return false;
  var norm = enc.toLowerCase().replace(/-/g, '');
  return ["utf8", "ascii", "latin1", "binary", "hex", "base64", "base64url", "ucs2", "utf16le"].indexOf(norm) !== -1;
}

function decodeBytes(bytes, encoding, start, end) {
  var enc = coerceEncoding(encoding || "utf8");
  var slice = (start !== undefined || end !== undefined) ? Uint8Array.prototype.slice.call(bytes, start || 0, end) : bytes;
  if (enc === "hex") {
    var out = "";
    for (var i = 0; i < slice.length; i++) {
      var value = slice[i].toString(16);
      if (value.length === 1) out += "0";
      out += value;
    }
    return out;
  }
  if (enc === "base64" || enc === "base64url") {
    var binary = "";
    for (var i = 0; i < slice.length; i++) binary += String.fromCharCode(slice[i]);
    var b64 = typeof btoa === "function" ? btoa(binary) : "";
    if (enc === "base64url") {
      return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }
    return b64;
  }
  if (enc === "latin1" || enc === "binary") {
    var result = "";
    for (var i = 0; i < slice.length; i++) result += String.fromCharCode(slice[i]);
    return result;
  }
  if (enc === "ascii") {
    var result = "";
    for (var i = 0; i < slice.length; i++) result += String.fromCharCode(slice[i] & 0x7F);
    return result;
  }
  if (enc === "utf16le" || enc === "ucs2" || enc === "ucs-2" || enc === "utf-16le") {
    var result = "";
    for (var i = 0; i + 1 < slice.length; i += 2) {
      result += String.fromCharCode(slice[i] | (slice[i + 1] << 8));
    }
    return result;
  }
  if (typeof TextDecoder !== "undefined") {
    var view = (slice.__isExactBuffer) ? new Uint8Array(slice) : slice;
    return new TextDecoder("utf-8").decode(view);
  }
  var result = "";
  for (var i = 0; i < slice.length; i++) {
    result += String.fromCharCode(slice[i]);
  }
  return result;
}

function encodeString(value, encoding) {
  var enc = coerceEncoding(encoding || "utf8");
  var str = String(value);
  if (enc === "hex") {
    var values = [];
    for (var i = 0; i < str.length - 1; i += 2) {
      var byte = parseInt(str.substr(i, 2), 16);
      if (isNaN(byte)) {
        break;
      }
      values.push(byte);
    }
    var bytes = new Uint8Array(values.length);
    for (var j = 0; j < values.length; j++) {
      bytes[j] = values[j];
    }
    return bytes;
  }
  if (enc === "base64" || enc === "base64url") {
    var b64str = str;
    if (enc === "base64url") {
      b64str = b64str.replace(/-/g, "+").replace(/_/g, "/");
    }
    // Strip non-base64 characters (Node.js is lenient)
    b64str = b64str.replace(/[^A-Za-z0-9+/]/g, '');
    // Add proper padding
    var pad = b64str.length % 4;
    if (pad === 2) b64str += "==";
    else if (pad === 3) b64str += "=";
    else if (pad === 1) b64str = b64str.slice(0, -1); // invalid, remove trailing char
    if (typeof atob === "function" && b64str.length > 0) {
      try {
        var raw = atob(b64str);
        var b = new Uint8Array(raw.length);
        for (var j = 0; j < raw.length; j++) b[j] = raw.charCodeAt(j);
        return b;
      } catch(e) {
        return new Uint8Array(0);
      }
    }
    return new Uint8Array(0);
  }
  if (enc === "latin1" || enc === "binary") {
    var lat = new Uint8Array(str.length);
    for (var k = 0; k < str.length; k++) lat[k] = str.charCodeAt(k) & 0xff;
    return lat;
  }
  if (enc === "ascii") {
    var asc = new Uint8Array(str.length);
    for (var m = 0; m < str.length; m++) asc[m] = str.charCodeAt(m) & 0x7f;
    return asc;
  }
  if (enc === "utf16le" || enc === "ucs2" || enc === "ucs-2" || enc === "utf-16le") {
    var u16 = new Uint8Array(str.length * 2);
    for (var p = 0; p < str.length; p++) {
      var code = str.charCodeAt(p);
      u16[p * 2] = code & 0xff;
      u16[p * 2 + 1] = (code >> 8) & 0xff;
    }
    return u16;
  }
  // utf8
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(str);
  }
  var fallback = new Uint8Array(str.length);
  for (var n = 0; n < str.length; n++) {
    fallback[n] = str.charCodeAt(n) & 0xff;
  }
  return fallback;
}

function _isBufferLike(v) {
  return !!(v && (v.__isExactBuffer || v instanceof Uint8Array));
}

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + input.name;
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  if (typeof input === 'string') return " Received type string ('" + input + "')";
  if (typeof input === 'number') return ' Received type number (' + input + ')';
  if (typeof input === 'boolean') return ' Received type boolean (' + input + ')';
  if (typeof input === 'bigint') return ' Received type bigint (' + input + 'n)';
  if (typeof input === 'symbol') return ' Received type symbol (' + String(input) + ')';
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
}

function _errInvalidArgType(name, expected, actual) {
  var msg = 'The "' + name + '" argument must be ' + expected + '.' + _invalidArgTypeHelper(actual);
  var err = new TypeError(msg);
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _errOutOfRange(name, range, value) {
  var msg = 'The value of "' + name + '" is out of range. It must be ' + range + '. Received ' + value;
  var err = new RangeError(msg);
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _errBufferOOB(what) {
  var msg = what ? ('"' + what + '" is outside of buffer bounds') : 'Attempt to access memory outside buffer bounds';
  var err = new RangeError(msg);
  err.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
  return err;
}

function _errUnknownEncoding(enc) {
  var err = new TypeError('Unknown encoding: ' + enc);
  err.code = 'ERR_UNKNOWN_ENCODING';
  return err;
}

function _errInvalidArgValue(name, value, reason) {
  var msg = "The argument '" + name + "' is invalid." + (reason ? ' ' + reason : '') + ' Received ' + String(value);
  var err = new TypeError(msg);
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _checkOffset(offset, byteLength, length) {
  if (offset === undefined || offset === null) offset = 0;
  if (typeof offset !== 'number') {
    throw _errInvalidArgType('offset', 'of type number', offset);
  }
  if (offset !== offset || offset % 1 !== 0) {
    throw _errOutOfRange('offset', 'an integer', offset);
  }
  if (offset < 0 || offset + byteLength > length) {
    if (offset < 0 || offset > length) {
      throw _errOutOfRange('offset', '>= 0 and <= ' + (length - byteLength), offset);
    }
    throw _errBufferOOB();
  }
}

function _checkReadOffset(offset, byteLength, length) {
  if (offset === undefined) return 0;
  if (typeof offset !== 'number') {
    throw _errInvalidArgType('offset', 'of type number', offset);
  }
  if (offset !== offset || offset % 1 !== 0) {
    throw _errOutOfRange('offset', 'an integer', offset);
  }
  if (offset < 0 || offset + byteLength > length) {
    if (offset < 0 || offset > length - byteLength) {
      throw _errOutOfRange('offset', '>= 0 and <= ' + (length - byteLength), offset);
    }
    throw _errBufferOOB();
  }
  return offset;
}

function toByteArray(value, encoding) {
  if (typeof value === "number") {
    if (value < 0 || value > 0xffffffff || value % 1 !== 0 || value !== value) {
      throw _errOutOfRange('value', '>= 0 and <= 4294967295', value !== value ? 'NaN' : value);
    }
    return new Uint8Array(value);
  }
  if (value == null) {
    var errMsg = 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.' +
      _invalidArgTypeHelper(value);
    var err = new TypeError(errMsg);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    // TypedArrays like Uint16Array, Uint32Array, etc.
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === "string") {
    // Validate encoding if it's a string
    if (typeof encoding === 'string' && encoding !== '' && !_isValidEncoding(encoding)) {
      throw _errUnknownEncoding(encoding);
    }
    return encodeString(value, encoding);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (value && typeof value === "object" && value.type === "Buffer" && Array.isArray(value.data)) {
    return new Uint8Array(value.data);
  }
  // Symbol.toPrimitive
  if (typeof value === 'object' && value !== null && typeof value[Symbol.toPrimitive] === 'function') {
    var prim = value[Symbol.toPrimitive]('string');
    if (typeof prim === 'string') {
      return encodeString(prim, encoding);
    }
  }
  // valueOf / String objects
  if (typeof value === "object" && value !== null && typeof value.valueOf === "function") {
    var unboxed = value.valueOf();
    if (typeof unboxed === 'string') {
      return encodeString(unboxed, encoding);
    }
  }
  // Array-like objects
  if (typeof value === 'object' && value !== null && typeof value.length === 'number') {
    var len = value.length;
    if (len !== len || len < 0) len = 0;
    else len = Math.floor(len);
    var arr = new Uint8Array(len);
    for (var i = 0; i < len; i++) arr[i] = (value[i] || 0) & 0xff;
    return arr;
  }
  var err = new TypeError(
    'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.' +
    _invalidArgTypeHelper(value)
  );
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function Buffer(value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw _errInvalidArgType('string', 'of type string', value);
    }
    return Buffer.alloc(value);
  }
  if (typeof value === 'string') {
    return Buffer.from(value, encodingOrOffset);
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return Buffer.from(value, encodingOrOffset, length);
  }
  if (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) {
    return Buffer.from(value, encodingOrOffset, length);
  }
  return Buffer.from(value, encodingOrOffset);
}

function makeBuffer(bytes, noCopy) {
  var buffer;
  if (noCopy && bytes instanceof Uint8Array) {
    // Wrap existing Uint8Array without copying (for subarray/slice views)
    buffer = bytes;
  } else {
    buffer = new Uint8Array(bytes);
  }
  if (Buffer._protoReady) {
    Object.setPrototypeOf(buffer, Buffer.prototype);
  } else {
    for (var key in BufferProto) {
      buffer[key] = BufferProto[key];
    }
    buffer.__isExactBuffer = true;
  }
  return buffer;
}

Buffer.isBuffer = function(candidate) {
  return !!(candidate && candidate.__isExactBuffer);
};

Buffer.from = function(value, encodingOrOffset, length) {
  if (value && value.__isExactBuffer) {
    return makeBuffer(new Uint8Array(value));
  }
  if (typeof value === 'number') {
    var err = new TypeError(
      'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received type number (' + value + ')'
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    // Verify it's a real ArrayBuffer (not a fake subclass)
    var realByteLength;
    try {
      realByteLength = value.byteLength;
    } catch(e) {
      // Fake ArrayBuffer subclass - fall through to generic handling
      var err = new TypeError(
        'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.' +
        _invalidArgTypeHelper(value)
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    // Validate offset - coerce to number, NaN/non-numeric -> 0, Infinity -> throw
    var offset = Number(encodingOrOffset);
    if (!isFinite(offset) && offset === offset) {
      // Infinity or -Infinity
      throw _errBufferOOB('offset');
    }
    if (offset !== offset) offset = 0; // NaN -> 0
    offset = Math.floor(offset);
    if (offset < 0) offset = 0;
    if (offset > realByteLength) {
      throw _errBufferOOB('offset');
    }
    // Validate length
    var len;
    if (length !== undefined) {
      len = Number(length);
      if (len !== len) len = 0;
      if (!isFinite(len) || offset + len > realByteLength) {
        throw _errBufferOOB('length');
      }
      len = Math.floor(len);
      if (len < 0) len = 0;
    } else {
      len = realByteLength - offset;
    }
    return makeBuffer(new Uint8Array(value, offset, len), true);
  }
  if (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) {
    var offset = encodingOrOffset || 0;
    var len = length !== undefined ? length : value.byteLength - offset;
    return makeBuffer(new Uint8Array(value, offset, len), true);
  }
  // Check for fake ArrayBuffer subclasses
  if (typeof value === 'object' && value !== null && !(value instanceof Uint8Array) && !Array.isArray(value) &&
      typeof value.length !== 'number' && typeof value[Symbol.iterator] === 'undefined' &&
      value.constructor && /^(AB|.*ArrayBuffer)$/.test(value.constructor.name) &&
      !(value instanceof ArrayBuffer)) {
    var err = new TypeError(
      'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.' +
      _invalidArgTypeHelper(value)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  return makeBuffer(toByteArray(value, encodingOrOffset));
};

Buffer.alloc = function(size, fill, encoding) {
  if (typeof size !== 'number') {
    throw _errInvalidArgType('size', 'of type number', size);
  }
  if (size !== size) {
    throw _errOutOfRange('size', 'a non-negative integer', 'NaN');
  }
  if (size < 0 || size > 2147483647) {
    throw _errOutOfRange('size', '>= 0 && <= 2147483647', size);
  }
  var bytes = new Uint8Array(size || 0);
  if (fill === undefined || fill === null) {
    return makeBuffer(bytes);
  }
  // Validate encoding
  if (encoding !== undefined && typeof encoding !== 'string') {
    throw _errInvalidArgType('encoding', 'of type string', encoding);
  }
  if (typeof fill === "string") {
    if (fill.length === 0) return makeBuffer(bytes);
    // Validate encoding if provided
    if (encoding !== undefined && !_isValidEncoding(encoding)) {
      throw _errUnknownEncoding(encoding);
    }
    var enc = coerceEncoding(encoding || "utf8");
    // For hex encoding, validate the fill string
    if (enc === 'hex') {
      // Must be valid hex and have even length
      if (fill.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(fill)) {
        var errMsg = "The argument 'value' is invalid. Received '" + fill + "'";
        var err = new TypeError(errMsg);
        err.code = 'ERR_INVALID_ARG_VALUE';
        throw err;
      }
    }
    var fillBytes = encodeString(fill, enc);
    if (fillBytes.length === 0) {
      var errMsg = "The argument 'value' is invalid. Received '" + fill + "'";
      var err = new TypeError(errMsg);
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
    if (fillBytes.length === 1) {
      for (var i = 0; i < bytes.length; i++) bytes[i] = fillBytes[0];
    } else {
      for (var i = 0; i < bytes.length; i++) bytes[i] = fillBytes[i % fillBytes.length];
    }
  } else if (typeof fill === "number") {
    var fillValue = fill & 0xff;
    for (var i = 0; i < bytes.length; i++) bytes[i] = fillValue;
  } else if (fill === true) {
    for (var i = 0; i < bytes.length; i++) bytes[i] = 1;
  } else if (fill === false) {
    // already zeroed
  } else if (_isBufferLike(fill)) {
    if (fill.length === 0) {
      var errMsg = "The argument 'value' is invalid. Received Buffer(0) []";
      var err = new TypeError(errMsg);
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
    for (var i = 0; i < bytes.length; i++) bytes[i] = fill[i % fill.length];
  }
  return makeBuffer(bytes);
};

Buffer.allocUnsafe = function(size) {
  if (typeof size !== 'number' || size !== size) {
    throw _errOutOfRange('size', 'a non-negative integer', size !== size ? 'NaN' : size);
  }
  if (size < 0 || size > 2147483647) {
    throw _errOutOfRange('size', '>= 0 && <= 2147483647', size);
  }
  return makeBuffer(new Uint8Array(size || 0));
};
Buffer.allocUnsafeSlow = Buffer.allocUnsafe;

Buffer.byteLength = function(string, encoding) {
  if (typeof string !== 'string' && !_isBufferLike(string) &&
      !(string instanceof ArrayBuffer) && !ArrayBuffer.isView(string) &&
      !(typeof SharedArrayBuffer !== 'undefined' && string instanceof SharedArrayBuffer)) {
    throw _errInvalidArgType('string', 'of type string or an instance of Buffer or ArrayBuffer', string);
  }
  if (typeof string !== 'string') {
    return string.byteLength !== undefined ? string.byteLength : string.length;
  }
  if (!encoding || !_isValidEncoding(encoding)) {
    // Unknown encoding treated as utf8
    return encodeString(string, "utf8").length;
  }
  return encodeString(string, encoding).length;
};

Buffer.compare = function(a, b) {
  if (!_isBufferLike(a)) {
    var err = new TypeError(
      'The "buf1" argument must be an instance of Buffer or Uint8Array.' +
      _invalidArgTypeHelper(a)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (!_isBufferLike(b)) {
    var err = new TypeError(
      'The "buf2" argument must be an instance of Buffer or Uint8Array.' +
      _invalidArgTypeHelper(b)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  var i = 0;
  var max = Math.min(a.length, b.length);
  while (i < max) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    i += 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
};

Buffer.concat = function(list, totalLength) {
  if (!Array.isArray(list)) {
    var err = new TypeError('The "list" argument must be an instance of Array.' + _invalidArgTypeHelper(list));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  // Validate each item
  for (var v = 0; v < list.length; v++) {
    if (!_isBufferLike(list[v])) {
      var err = new TypeError('The "list[' + v + ']" argument must be an instance of Buffer or Uint8Array.' + _invalidArgTypeHelper(list[v]));
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
  if (list.length === 0) return Buffer.alloc(0);
  var total = totalLength;
  if (total !== undefined) {
    if (typeof total !== 'number' || total % 1 !== 0) {
      throw _errOutOfRange('length', 'an integer', total);
    }
    if (total < 0 || total > Number.MAX_SAFE_INTEGER) {
      throw _errOutOfRange('length', '>= 0 && <= ' + Number.MAX_SAFE_INTEGER, total);
    }
  } else {
    total = 0;
    for (var i = 0; i < list.length; i++) total += list[i].length;
  }
  var result = Buffer.alloc(total);
  var offset = 0;
  for (var j = 0; j < list.length; j++) {
    var buf = list[j];
    for (var k = 0; k < buf.length && offset < total; k++) {
      result[offset++] = buf[k];
    }
  }
  return result;
};

Buffer.of = function() {
  var bytes = new Uint8Array(arguments.length);
  for (var i = 0; i < arguments.length; i++) bytes[i] = arguments[i] & 0xff;
  return makeBuffer(bytes);
};

Buffer.isEncoding = function(encoding) {
  return _isValidEncoding(encoding);
};

Buffer.copyBytesFrom = function(source, sourceOffset, length) {
  if (!ArrayBuffer.isView(source) || source instanceof DataView) {
    var err = new TypeError('The "source" argument must be an instance of TypedArray.' + _invalidArgTypeHelper(source));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (sourceOffset !== undefined) {
    if (typeof sourceOffset !== 'number') {
      throw _errInvalidArgType('sourceOffset', 'of type number', sourceOffset);
    }
    if (sourceOffset < 0 || sourceOffset !== sourceOffset || sourceOffset % 1 !== 0) {
      var reason = sourceOffset !== sourceOffset ? 'NaN' : sourceOffset;
      throw _errOutOfRange('sourceOffset', '>= 0', reason);
    }
  } else {
    sourceOffset = 0;
  }
  if (length !== undefined) {
    if (typeof length !== 'number') {
      throw _errInvalidArgType('length', 'of type number', length);
    }
    if (length < 0 || length !== length || length % 1 !== 0) {
      var reason = length !== length ? 'NaN' : length;
      throw _errOutOfRange('length', '>= 0', reason);
    }
  } else {
    length = source.length - sourceOffset;
  }
  if (length > source.length - sourceOffset) {
    length = source.length - sourceOffset;
  }
  var bytesPerElement = source.BYTES_PER_ELEMENT || 1;
  var byteLength = length * bytesPerElement;
  var sourceBytes = new Uint8Array(source.buffer, source.byteOffset + sourceOffset * bytesPerElement, byteLength);
  return makeBuffer(new Uint8Array(sourceBytes));
};

Buffer.poolSize = 8192;

BufferProto.toString = function(encoding, start, end) {
  // If encoding is provided, validate it
  if (encoding !== undefined) {
    // Convert encoding to string for validation
    var encStr;
    if (encoding !== null && typeof encoding === 'object' && typeof encoding.toString === 'function') {
      encStr = encoding.toString();
    } else {
      encStr = encoding;
    }
    if (typeof encStr === 'string' && encStr !== '') {
      if (!_isValidEncoding(encStr)) {
        throw _errUnknownEncoding(encStr);
      }
    } else if (encStr !== undefined && encStr !== '') {
      // Numbers, null, false, etc. should throw
      throw _errUnknownEncoding(encStr);
    }
    encoding = encStr;
  }
  // Coerce start and end values like Node.js
  var s = start !== undefined ? Number(start) : 0;
  var e = end !== undefined ? Number(end) : this.length;
  if (s !== s) s = 0; // NaN -> 0
  if (e !== e) e = 0; // NaN -> 0
  if (s < 0) s = 0;
  if (e < 0) e = 0;
  s = Math.floor(s);
  e = Math.floor(e);
  if (s >= this.length) return '';
  if (e > this.length) e = this.length;
  if (e <= s) return '';
  return decodeBytes(this, encoding, s, e);
};

BufferProto.toLocaleString = BufferProto.toString;

BufferProto._toByteString = function(encoding) {
  return decodeBytes(this, encoding || 'latin1');
};

BufferProto.equals = function(other) {
  if (!_isBufferLike(other)) {
    var err = new TypeError(
      'The "otherBuffer" argument must be an instance of Buffer or Uint8Array.' +
      _invalidArgTypeHelper(other)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (other.length !== this.length) return false;
  for (var i = 0; i < this.length; i++) {
    if (this[i] !== other[i]) return false;
  }
  return true;
};

BufferProto.toJSON = function() {
  return { type: "Buffer", data: Array.prototype.slice.call(this) };
};

BufferProto.slice = function(start, end) {
  // Node.js Buffer.slice is deprecated and is an alias for subarray (returns a view)
  var sub = Uint8Array.prototype.subarray.call(this, start, end);
  return makeBuffer(sub, true);
};

BufferProto.subarray = function(start, end) {
  var sub = Uint8Array.prototype.subarray.call(this, start, end);
  return makeBuffer(sub, true);
};

BufferProto.copy = function(target, targetStart, sourceStart, sourceEnd) {
  // Validate source (this)
  if (!_isBufferLike(this) && !ArrayBuffer.isView(this)) {
    throw _errInvalidArgType('source', 'an instance of Buffer or Uint8Array', this);
  }
  // Validate target
  if (!_isBufferLike(target) && !ArrayBuffer.isView(target)) {
    throw _errInvalidArgType('target', 'an instance of Buffer or Uint8Array', target);
  }

  // Coerce targetStart - may throw via Symbol.toPrimitive
  if (targetStart !== undefined && targetStart !== null && typeof targetStart === 'object' && typeof targetStart[Symbol.toPrimitive] === 'function') {
    targetStart = targetStart[Symbol.toPrimitive]('number');
  }
  targetStart = targetStart == null ? 0 : Number(targetStart);
  if (targetStart !== targetStart) targetStart = 0; // NaN -> 0
  targetStart = Math.floor(targetStart);

  if (targetStart < 0) {
    throw _errOutOfRange('targetStart', '>= 0', targetStart);
  }

  sourceStart = sourceStart == null ? 0 : Number(sourceStart);
  if (sourceStart !== sourceStart) sourceStart = 0;
  sourceStart = Math.floor(sourceStart);

  if (sourceStart < 0) {
    throw _errOutOfRange('sourceStart', '>= 0', sourceStart);
  }
  if (sourceStart > this.length) {
    throw _errOutOfRange('sourceStart', '<= ' + this.length, sourceStart);
  }

  if (sourceEnd !== undefined) {
    sourceEnd = Number(sourceEnd);
    if (sourceEnd !== sourceEnd) sourceEnd = 0;
    sourceEnd = Math.floor(sourceEnd);
    if (sourceEnd < 0) {
      throw _errOutOfRange('sourceEnd', '>= 0', sourceEnd);
    }
  } else {
    sourceEnd = this.length;
  }

  // sourceStart > sourceEnd => 0 bytes
  if (sourceStart >= sourceEnd) return 0;

  // Clamp to source length
  if (sourceEnd > this.length) sourceEnd = this.length;

  // targetStart > target length => 0 bytes
  var targetLen;
  if (ArrayBuffer.isView(target) && !(target instanceof Uint8Array)) {
    // For typed arrays like Uint16Array, copy byte-by-byte into the underlying buffer
    targetLen = target.byteLength;
    var targetBytes = new Uint8Array(target.buffer, target.byteOffset, target.byteLength);
    var length = Math.min(sourceEnd - sourceStart, targetLen - targetStart);
    if (length <= 0) return 0;
    for (var i = 0; i < length; i++) {
      targetBytes[targetStart + i] = this[sourceStart + i];
    }
    return length;
  } else {
    targetLen = target.length;
  }
  if (targetStart >= targetLen) return 0;

  var length = Math.min(sourceEnd - sourceStart, targetLen - targetStart);
  if (length <= 0) return 0;
  for (var i = 0; i < length; i++) {
    target[targetStart + i] = this[sourceStart + i];
  }
  return length;
};

BufferProto.write = function(value, offset, length, encoding) {
  if (typeof length === "string") {
    encoding = length;
    length = null;
  }
  if (typeof offset === "string") {
    encoding = offset;
    offset = 0;
    length = null;
  }

  if (offset == null) offset = 0;
  if (typeof offset !== 'number') {
    var offErr = new TypeError('The "offset" argument must be of type number. Received type ' + typeof offset);
    offErr.code = 'ERR_INVALID_ARG_TYPE';
    throw offErr;
  }
  if (offset < 0 || offset > this.length) {
    var rangeErr = new RangeError('The value of "offset" is out of range. It must be >= 0 && <= ' + this.length + '. Received ' + offset);
    rangeErr.code = 'ERR_OUT_OF_RANGE';
    throw rangeErr;
  }

  var _enc = coerceEncoding(encoding || 'utf8');
  if (encoding !== undefined && encoding !== null && typeof encoding === 'string' && !_isValidEncoding(encoding)) {
    throw _errUnknownEncoding(encoding);
  }

  var bytes = encodeString(String(value), _enc);
  if (length == null || length > bytes.length) length = bytes.length;
  for (var i = 0; i < length && (offset + i) < this.length; i++) {
    this[offset + i] = bytes[i];
  }
  return Math.min(length, this.length - offset);
};

BufferProto.compare = function(target, targetStart, targetEnd, sourceStart, sourceEnd) {
  if (!_isBufferLike(target)) {
    var err = new TypeError(
      'The "target" argument must be an instance of Buffer or Uint8Array.' +
      _invalidArgTypeHelper(target)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  // Validate targetStart
  if (targetStart !== undefined) {
    if (typeof targetStart !== 'number') {
      throw _errInvalidArgType('targetStart', 'of type number', targetStart);
    }
    if (targetStart < 0 || !isFinite(targetStart)) {
      throw _errOutOfRange('targetStart', '>= 0 and <= ' + target.length, targetStart);
    }
  } else {
    targetStart = 0;
  }

  // Validate targetEnd
  if (targetEnd !== undefined) {
    if (typeof targetEnd !== 'number') {
      throw _errInvalidArgType('targetEnd', 'of type number', targetEnd);
    }
    if (targetEnd < 0 || targetEnd > target.length) {
      throw _errOutOfRange('targetEnd', '>= 0 and <= ' + target.length, targetEnd);
    }
  } else {
    targetEnd = target.length;
  }

  // Validate sourceStart
  if (sourceStart !== undefined) {
    if (typeof sourceStart !== 'number') {
      throw _errInvalidArgType('sourceStart', 'of type number', sourceStart);
    }
    if (sourceStart < 0 || !isFinite(sourceStart)) {
      throw _errOutOfRange('sourceStart', '>= 0 and <= ' + this.length, sourceStart);
    }
  } else {
    sourceStart = 0;
  }

  // Validate sourceEnd
  if (sourceEnd !== undefined) {
    if (typeof sourceEnd !== 'number') {
      throw _errInvalidArgType('sourceEnd', 'of type number', sourceEnd);
    }
    if (sourceEnd < 0 || sourceEnd > this.length) {
      throw _errOutOfRange('sourceEnd', '>= 0 and <= ' + this.length, sourceEnd);
    }
  } else {
    sourceEnd = this.length;
  }

  var sLen = sourceEnd - sourceStart;
  var tLen = targetEnd - targetStart;
  var len = Math.min(sLen, tLen);
  for (var i = 0; i < len; i++) {
    if (this[sourceStart + i] !== target[targetStart + i]) {
      return this[sourceStart + i] < target[targetStart + i] ? -1 : 1;
    }
  }
  if (sLen === tLen) return 0;
  return sLen < tLen ? -1 : 1;
};

// Validate offset for read methods
function _validateReadOffset(offset, byteLength, bufLength) {
  if (offset === undefined) return 0;
  if (typeof offset !== 'number') {
    throw _errInvalidArgType('offset', 'of type number', offset);
  }
  if (offset !== offset || (offset % 1 !== 0 && isFinite(offset))) {
    throw _errOutOfRange('offset', 'an integer', offset);
  }
  if (offset < 0 || offset + byteLength > bufLength) {
    var maxOffset = bufLength - byteLength;
    if (maxOffset < 0) {
      throw _errBufferOOB();
    }
    throw _errOutOfRange('offset', '>= 0 and <= ' + maxOffset, offset);
  }
  return offset;
}

// Validate offset for write methods
function _validateWriteOffset(offset, byteLength, bufLength) {
  if (offset === undefined) return 0;
  if (typeof offset !== 'number') {
    throw _errInvalidArgType('offset', 'of type number', offset);
  }
  if (offset !== offset || (offset % 1 !== 0 && isFinite(offset))) {
    throw _errOutOfRange('offset', 'an integer', offset);
  }
  if (offset < 0 || offset + byteLength > bufLength) {
    var maxOffset = bufLength - byteLength;
    if (maxOffset < 0) {
      throw _errBufferOOB();
    }
    throw _errOutOfRange('offset', '>= 0 and <= ' + maxOffset, offset);
  }
  return offset;
}

// Value range validation helpers for write methods
function _checkInt(value, min, max) {
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < min || value > max) {
    throw _errOutOfRange('value', '>= ' + min + ' and <= ' + max, value);
  }
}

function _checkUInt(value, max) {
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < 0 || value > max) {
    throw _errOutOfRange('value', '>= 0 and <= ' + max, value);
  }
}

// Read unsigned integers
BufferProto.readUInt8 = function(offset) {
  offset = _validateReadOffset(offset, 1, this.length);
  return this[offset];
};
BufferProto.readUInt16LE = function(offset) {
  offset = _validateReadOffset(offset, 2, this.length);
  return this[offset] | (this[offset+1] << 8);
};
BufferProto.readUInt16BE = function(offset) {
  offset = _validateReadOffset(offset, 2, this.length);
  return (this[offset] << 8) | this[offset+1];
};
BufferProto.readUInt32LE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return (this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24)) >>> 0;
};
BufferProto.readUInt32BE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return (this[offset] * 0x1000000 + (this[offset+1] << 16) + (this[offset+2] << 8) + this[offset+3]) >>> 0;
};

// Read signed integers
BufferProto.readInt8 = function(offset) {
  offset = _validateReadOffset(offset, 1, this.length);
  var v = this[offset]; return v > 127 ? v - 256 : v;
};
BufferProto.readInt16LE = function(offset) { var v = this.readUInt16LE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt16BE = function(offset) { var v = this.readUInt16BE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt32LE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24);
};
BufferProto.readInt32BE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return (this[offset] << 24) | (this[offset+1] << 16) | (this[offset+2] << 8) | this[offset+3];
};

// Variable-length read (1-6 bytes)
function _validateByteLength(byteLength) {
  if (typeof byteLength !== 'number') throw _errInvalidArgType('byteLength', 'of type number', byteLength);
  if (byteLength !== byteLength || (byteLength % 1 !== 0 && isFinite(byteLength))) throw _errOutOfRange('byteLength', 'an integer', byteLength);
  if (byteLength < 1 || byteLength > 6) throw _errOutOfRange('byteLength', '>= 1 and <= 6', byteLength);
}

BufferProto.readUIntLE = function(offset, byteLength) {
  _validateByteLength(byteLength);
  if (typeof offset !== 'number') throw _errInvalidArgType('offset', 'of type number', offset);
  offset = _validateReadOffset(offset, byteLength, this.length);
  var val = 0;
  var mul = 1;
  for (var i = 0; i < byteLength; i++) {
    val += this[offset + i] * mul;
    mul *= 0x100;
  }
  return val;
};
BufferProto.readUIntBE = function(offset, byteLength) {
  _validateByteLength(byteLength);
  if (typeof offset !== 'number') throw _errInvalidArgType('offset', 'of type number', offset);
  offset = _validateReadOffset(offset, byteLength, this.length);
  var val = 0;
  var mul = 1;
  for (var i = byteLength - 1; i >= 0; i--) {
    val += this[offset + i] * mul;
    mul *= 0x100;
  }
  return val;
};
BufferProto.readIntLE = function(offset, byteLength) {
  _validateByteLength(byteLength);
  if (typeof offset !== 'number') throw _errInvalidArgType('offset', 'of type number', offset);
  offset = _validateReadOffset(offset, byteLength, this.length);
  var val = 0;
  var mul = 1;
  for (var i = 0; i < byteLength; i++) {
    val += this[offset + i] * mul;
    mul *= 0x100;
  }
  if (val >= mul / 2) val -= mul;
  return val;
};
BufferProto.readIntBE = function(offset, byteLength) {
  _validateByteLength(byteLength);
  if (typeof offset !== 'number') throw _errInvalidArgType('offset', 'of type number', offset);
  offset = _validateReadOffset(offset, byteLength, this.length);
  var val = 0;
  var mul = 1;
  for (var i = byteLength - 1; i >= 0; i--) {
    val += this[offset + i] * mul;
    mul *= 0x100;
  }
  if (val >= mul / 2) val -= mul;
  return val;
};

// Read floats/doubles via DataView
BufferProto.readFloatLE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset, true);
};
BufferProto.readFloatBE = function(offset) {
  offset = _validateReadOffset(offset, 4, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset, false);
};
BufferProto.readDoubleLE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset, true);
};
BufferProto.readDoubleBE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset, false);
};

// BigInt read
BufferProto.readBigInt64LE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigInt64(offset, true);
};
BufferProto.readBigInt64BE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigInt64(offset, false);
};
BufferProto.readBigUInt64LE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(offset, true);
};
BufferProto.readBigUInt64BE = function(offset) {
  offset = _validateReadOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(offset, false);
};

// Write unsigned integers with value range checking
BufferProto.writeUInt8 = function(value, offset) {
  _checkUInt(value, 0xff);
  offset = _validateWriteOffset(offset, 1, this.length);
  this[offset] = value & 0xff; return offset + 1;
};
BufferProto.writeUInt16LE = function(value, offset) {
  _checkUInt(value, 0xffff);
  offset = _validateWriteOffset(offset, 2, this.length);
  this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; return offset + 2;
};
BufferProto.writeUInt16BE = function(value, offset) {
  _checkUInt(value, 0xffff);
  offset = _validateWriteOffset(offset, 2, this.length);
  this[offset] = (value >>> 8) & 0xff; this[offset+1] = value & 0xff; return offset + 2;
};
BufferProto.writeUInt32LE = function(value, offset) {
  _checkUInt(value, 0xffffffff);
  offset = _validateWriteOffset(offset, 4, this.length);
  this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; this[offset+2] = (value >>> 16) & 0xff; this[offset+3] = (value >>> 24) & 0xff; return offset + 4;
};
BufferProto.writeUInt32BE = function(value, offset) {
  _checkUInt(value, 0xffffffff);
  offset = _validateWriteOffset(offset, 4, this.length);
  this[offset] = (value >>> 24) & 0xff; this[offset+1] = (value >>> 16) & 0xff; this[offset+2] = (value >>> 8) & 0xff; this[offset+3] = value & 0xff; return offset + 4;
};

// Write signed integers with value range checking
BufferProto.writeInt8 = function(value, offset) {
  _checkInt(value, -0x80, 0x7f);
  offset = _validateWriteOffset(offset, 1, this.length);
  this[offset] = value < 0 ? value + 256 : value; return offset + 1;
};
BufferProto.writeInt16LE = function(value, offset) {
  _checkInt(value, -0x8000, 0x7fff);
  offset = _validateWriteOffset(offset, 2, this.length);
  var v = value < 0 ? value + 0x10000 : value;
  this[offset] = v & 0xff; this[offset+1] = (v >>> 8) & 0xff; return offset + 2;
};
BufferProto.writeInt16BE = function(value, offset) {
  _checkInt(value, -0x8000, 0x7fff);
  offset = _validateWriteOffset(offset, 2, this.length);
  var v = value < 0 ? value + 0x10000 : value;
  this[offset] = (v >>> 8) & 0xff; this[offset+1] = v & 0xff; return offset + 2;
};
BufferProto.writeInt32LE = function(value, offset) {
  _checkInt(value, -0x80000000, 0x7fffffff);
  offset = _validateWriteOffset(offset, 4, this.length);
  var v = value < 0 ? value + 0x100000000 : value;
  this[offset] = v & 0xff; this[offset+1] = (v >>> 8) & 0xff; this[offset+2] = (v >>> 16) & 0xff; this[offset+3] = (v >>> 24) & 0xff; return offset + 4;
};
BufferProto.writeInt32BE = function(value, offset) {
  _checkInt(value, -0x80000000, 0x7fffffff);
  offset = _validateWriteOffset(offset, 4, this.length);
  var v = value < 0 ? value + 0x100000000 : value;
  this[offset] = (v >>> 24) & 0xff; this[offset+1] = (v >>> 16) & 0xff; this[offset+2] = (v >>> 8) & 0xff; this[offset+3] = v & 0xff; return offset + 4;
};

// Variable-length write (1-6 bytes)
function _validateWriteByteLength(byteLength) {
  if (typeof byteLength !== 'number') throw _errInvalidArgType('byteLength', 'of type number', byteLength);
  if (byteLength !== byteLength || (byteLength % 1 !== 0 && isFinite(byteLength))) throw _errOutOfRange('byteLength', 'an integer', byteLength);
  if (byteLength < 1 || byteLength > 6) throw _errOutOfRange('byteLength', '>= 1 and <= 6', byteLength);
}

function _validateWriteVarOffset(offset, byteLength, bufLength) {
  if (offset === undefined || typeof offset !== 'number') {
    throw _errInvalidArgType('offset', 'of type number', offset);
  }
  if (offset !== offset || (offset % 1 !== 0 && isFinite(offset))) {
    throw _errOutOfRange('offset', 'an integer', offset);
  }
  var maxOffset = bufLength - byteLength;
  if (offset < 0 || offset > maxOffset) {
    throw _errOutOfRange('offset', '>= 0 and <= ' + maxOffset, offset);
  }
  return offset;
}

BufferProto.writeUIntLE = function(value, offset, byteLength) {
  _validateWriteByteLength(byteLength);
  // Validate value range
  var max = Math.pow(2, byteLength * 8);
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < 0 || value >= max) {
    var rangeStr;
    if (byteLength < 5) {
      rangeStr = '>= 0 and <= ' + (max - 1);
    } else {
      rangeStr = '>= 0 and < 2 ** ' + (byteLength * 8);
    }
    var received = byteLength > 4 ? String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') : value;
    throw _errOutOfRange('value', rangeStr, received);
  }
  offset = _validateWriteVarOffset(offset, byteLength, this.length);
  var mul = 1;
  for (var i = 0; i < byteLength; i++) {
    this[offset + i] = (value / mul) & 0xff;
    mul *= 0x100;
  }
  return offset + byteLength;
};
BufferProto.writeUIntBE = function(value, offset, byteLength) {
  _validateWriteByteLength(byteLength);
  // Validate value range
  var max = Math.pow(2, byteLength * 8);
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < 0 || value >= max) {
    var rangeStr;
    if (byteLength < 5) {
      rangeStr = '>= 0 and <= ' + (max - 1);
    } else {
      rangeStr = '>= 0 and < 2 ** ' + (byteLength * 8);
    }
    var received = byteLength > 4 ? String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') : value;
    throw _errOutOfRange('value', rangeStr, received);
  }
  offset = _validateWriteVarOffset(offset, byteLength, this.length);
  var mul = 1;
  for (var i = byteLength - 1; i >= 0; i--) {
    this[offset + i] = (value / mul) & 0xff;
    mul *= 0x100;
  }
  return offset + byteLength;
};
BufferProto.writeIntLE = function(value, offset, byteLength) {
  _validateWriteByteLength(byteLength);
  // Validate value range
  var total = Math.pow(256, byteLength);
  var min = -(total / 2);
  var max = total / 2 - 1;
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < min || value > max) {
    var rangeStr;
    if (byteLength > 4) {
      rangeStr = '>= -(2 ** ' + (byteLength * 8 - 1) + ') and < 2 ** ' + (byteLength * 8 - 1);
    } else {
      rangeStr = '>= ' + min + ' and <= ' + max;
    }
    var received = byteLength > 4 ? String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') : value;
    throw _errOutOfRange('value', rangeStr, received);
  }
  offset = _validateWriteVarOffset(offset, byteLength, this.length);
  var val = value < 0 ? value + total : value;
  var mul = 1;
  for (var i = 0; i < byteLength; i++) {
    this[offset + i] = (val / mul) & 0xff;
    mul *= 0x100;
  }
  return offset + byteLength;
};
BufferProto.writeIntBE = function(value, offset, byteLength) {
  _validateWriteByteLength(byteLength);
  // Validate value range
  var total = Math.pow(256, byteLength);
  var min = -(total / 2);
  var max = total / 2 - 1;
  if (typeof value !== 'number') {
    throw _errInvalidArgType('value', 'of type number', value);
  }
  if (value < min || value > max) {
    var rangeStr;
    if (byteLength > 4) {
      rangeStr = '>= -(2 ** ' + (byteLength * 8 - 1) + ') and < 2 ** ' + (byteLength * 8 - 1);
    } else {
      rangeStr = '>= ' + min + ' and <= ' + max;
    }
    var received = byteLength > 4 ? String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') : value;
    throw _errOutOfRange('value', rangeStr, received);
  }
  offset = _validateWriteVarOffset(offset, byteLength, this.length);
  var val = value < 0 ? value + total : value;
  var mul = 1;
  for (var i = byteLength - 1; i >= 0; i--) {
    this[offset + i] = (val / mul) & 0xff;
    mul *= 0x100;
  }
  return offset + byteLength;
};

// Write floats/doubles via DataView
BufferProto.writeFloatLE = function(value, offset) {
  offset = _validateWriteOffset(offset, 4, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, true); return offset + 4;
};
BufferProto.writeFloatBE = function(value, offset) {
  offset = _validateWriteOffset(offset, 4, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, false); return offset + 4;
};
BufferProto.writeDoubleLE = function(value, offset) {
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, true); return offset + 8;
};
BufferProto.writeDoubleBE = function(value, offset) {
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, false); return offset + 8;
};

// BigInt write
function _checkBigInt64(value) {
  if (typeof value !== 'bigint') {
    throw _errInvalidArgType('value', 'of type bigint', value);
  }
  if (value > 0x7fffffffffffffffn || value < -0x8000000000000000n) {
    throw _errOutOfRange('value', '>= -(2n ** 63n) and < 2n ** 63n', String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') + 'n');
  }
}
function _checkBigUInt64(value) {
  if (typeof value !== 'bigint') {
    throw _errInvalidArgType('value', 'of type bigint', value);
  }
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw _errOutOfRange('value', '>= 0n and < 2n ** 64n', String(value).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, '$1_') + 'n');
  }
}
BufferProto.writeBigInt64LE = function(value, offset) {
  _checkBigInt64(value);
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setBigInt64(offset, value, true); return offset + 8;
};
BufferProto.writeBigInt64BE = function(value, offset) {
  _checkBigInt64(value);
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setBigInt64(offset, value, false); return offset + 8;
};
BufferProto.writeBigUInt64LE = function(value, offset) {
  _checkBigUInt64(value);
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(offset, value, true); return offset + 8;
};
BufferProto.writeBigUInt64BE = function(value, offset) {
  _checkBigUInt64(value);
  offset = _validateWriteOffset(offset, 8, this.length);
  new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(offset, value, false); return offset + 8;
};

// Swap byte order
BufferProto.swap16 = function() {
  if (this.length % 2 !== 0) throw new RangeError('Buffer size must be a multiple of 16-bits');
  for (var i = 0; i < this.length; i += 2) { var a = this[i]; this[i] = this[i+1]; this[i+1] = a; }
  return this;
};
BufferProto.swap32 = function() {
  if (this.length % 4 !== 0) throw new RangeError('Buffer size must be a multiple of 32-bits');
  for (var i = 0; i < this.length; i += 4) { var a = this[i]; var b = this[i+1]; this[i] = this[i+3]; this[i+1] = this[i+2]; this[i+2] = b; this[i+3] = a; }
  return this;
};
BufferProto.swap64 = function() {
  if (this.length % 8 !== 0) throw new RangeError('Buffer size must be a multiple of 64-bits');
  for (var i = 0; i < this.length; i += 8) {
    var a = this[i]; var b = this[i+1]; var c = this[i+2]; var d = this[i+3];
    this[i] = this[i+7]; this[i+1] = this[i+6]; this[i+2] = this[i+5]; this[i+3] = this[i+4];
    this[i+4] = d; this[i+5] = c; this[i+6] = b; this[i+7] = a;
  }
  return this;
};

// Node.js aliases (readUintXX = readUIntXX)
BufferProto.readUint8 = BufferProto.readUInt8;
BufferProto.readUint16LE = BufferProto.readUInt16LE;
BufferProto.readUint16BE = BufferProto.readUInt16BE;
BufferProto.readUint32LE = BufferProto.readUInt32LE;
BufferProto.readUint32BE = BufferProto.readUInt32BE;
BufferProto.readBigUint64LE = BufferProto.readBigUInt64LE;
BufferProto.readBigUint64BE = BufferProto.readBigUInt64BE;
BufferProto.writeUint8 = BufferProto.writeUInt8;
BufferProto.writeUint16LE = BufferProto.writeUInt16LE;
BufferProto.writeUint16BE = BufferProto.writeUInt16BE;
BufferProto.writeUint32LE = BufferProto.writeUInt32LE;
BufferProto.writeUint32BE = BufferProto.writeUInt32BE;
BufferProto.writeBigUint64LE = BufferProto.writeBigUInt64LE;
BufferProto.writeBigUint64BE = BufferProto.writeBigUInt64BE;
BufferProto.readUintLE = BufferProto.readUIntLE;
BufferProto.readUintBE = BufferProto.readUIntBE;
BufferProto.writeUintLE = BufferProto.writeUIntLE;
BufferProto.writeUintBE = BufferProto.writeUIntBE;

BufferProto.fill = function(value, start, end, encoding) {
  if (typeof start === 'string') {
    encoding = start;
    start = 0;
    end = this.length;
  } else if (typeof end === 'string') {
    encoding = end;
    end = this.length;
  }
  start = start == null ? 0 : start;
  end = end == null ? this.length : end;
  if (typeof value === "string") {
    if (value.length === 0) return this;
    var fillBytes = encodeString(value, encoding || "utf8");
    if (fillBytes.length === 0) return this;
    if (fillBytes.length === 1) {
      for (var i = start; i < end && i < this.length; i++) this[i] = fillBytes[0];
    } else {
      for (var i = start; i < end && i < this.length; i++) this[i] = fillBytes[(i - start) % fillBytes.length];
    }
  } else if (_isBufferLike(value)) {
    if (value.length === 0) return this;
    for (var i = start; i < end && i < this.length; i++) this[i] = value[(i - start) % value.length];
  } else {
    var fill = (typeof value === 'number') ? value & 0xff : 0;
    for (var i = start; i < end && i < this.length; i++) {
      this[i] = fill;
    }
  }
  return this;
};

// indexOf / lastIndexOf / includes
function _bufferIndexOf(self, val, byteOffset, encoding, dir) {
  // dir: true = indexOf, false = lastIndexOf
  var selfLen = self.length;

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset;
    byteOffset = dir ? 0 : selfLen;
  }

  if (byteOffset === undefined || byteOffset === null) {
    byteOffset = dir ? 0 : selfLen;
  }

  byteOffset = Number(byteOffset);
  if (byteOffset !== byteOffset) { // NaN
    byteOffset = dir ? 0 : selfLen;
  }

  if (dir) {
    // indexOf
    if (byteOffset < 0) byteOffset = Math.max(0, selfLen + byteOffset);
    if (byteOffset >= selfLen) {
      if (typeof val === 'string' && val.length === 0) return selfLen;
      if (_isBufferLike(val) && val.length === 0) return selfLen;
      return -1;
    }
  } else {
    // lastIndexOf
    if (byteOffset < 0) byteOffset = selfLen + byteOffset;
    if (byteOffset < 0) return -1;
    if (byteOffset >= selfLen) byteOffset = selfLen - 1;
  }

  var needle;
  if (typeof val === 'number') {
    // Search for a single byte
    val = val & 0xff;
    if (dir) {
      for (var i = byteOffset; i < selfLen; i++) {
        if (self[i] === val) return i;
      }
    } else {
      for (var i = Math.min(byteOffset, selfLen - 1); i >= 0; i--) {
        if (self[i] === val) return i;
      }
    }
    return -1;
  }

  if (typeof val === 'string') {
    if (val.length === 0) {
      if (dir) {
        return Math.min(byteOffset, selfLen);
      } else {
        return Math.min(byteOffset, selfLen);
      }
    }
    needle = encodeString(val, encoding || 'utf8');
  } else if (_isBufferLike(val)) {
    if (val.length === 0) {
      if (dir) {
        return Math.min(byteOffset, selfLen);
      } else {
        return Math.min(byteOffset, selfLen);
      }
    }
    needle = val;
  } else {
    var err = new TypeError(
      'The "value" argument must be one of type number or string or an instance of Buffer or Uint8Array.' +
      _invalidArgTypeHelper(val)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  var needleLen = needle.length;
  if (needleLen > selfLen) return -1;

  if (dir) {
    // indexOf
    for (var i = byteOffset; i <= selfLen - needleLen; i++) {
      var found = true;
      for (var j = 0; j < needleLen; j++) {
        if (self[i + j] !== needle[j]) { found = false; break; }
      }
      if (found) return i;
    }
  } else {
    // lastIndexOf
    var startAt = Math.min(byteOffset, selfLen - needleLen);
    for (var i = startAt; i >= 0; i--) {
      var found = true;
      for (var j = 0; j < needleLen; j++) {
        if (self[i + j] !== needle[j]) { found = false; break; }
      }
      if (found) return i;
    }
  }
  return -1;
}

BufferProto.indexOf = function(val, byteOffset, encoding) {
  return _bufferIndexOf(this, val, byteOffset, encoding, true);
};

BufferProto.lastIndexOf = function(val, byteOffset, encoding) {
  return _bufferIndexOf(this, val, byteOffset, encoding, false);
};

BufferProto.includes = function(val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1;
};

// Custom inspect
var customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

function _inspectBuffer(buf, name) {
  var len = buf.length;
  var max = INSPECT_MAX_BYTES;
  var str = '';
  for (var i = 0; i < Math.min(len, max); i++) {
    if (str.length > 0) str += ' ';
    var hex = buf[i].toString(16);
    str += hex.length === 1 ? '0' + hex : hex;
  }
  if (len > max) str += ' ... ' + (len - max) + ' more bytes';
  return '<' + name + ' ' + str + '>';
}

BufferProto[customInspectSymbol] = function() {
  var name = this.__isExactBuffer ? 'Buffer' : (this.constructor && this.constructor.name || 'Uint8Array');
  return _inspectBuffer(this, name);
};

BufferProto.inspect = BufferProto[customInspectSymbol];

// parent property - same as buffer property
Object.defineProperty(BufferProto, 'parent', {
  get: function() { try { return this.buffer; } catch(e) { return undefined; } },
  enumerable: true
});

// offset property - same as byteOffset
Object.defineProperty(BufferProto, 'offset', {
  get: function() { try { return this.byteOffset; } catch(e) { return undefined; } },
  enumerable: true
});

// Set up Buffer.prototype inheriting from Uint8Array.prototype
// MUST be done after all BufferProto methods are defined
Buffer.prototype = Object.create(Uint8Array.prototype, {
  constructor: { value: Buffer, writable: true, configurable: true }
});
for (var _bk in BufferProto) {
  if (Object.prototype.hasOwnProperty.call(BufferProto, _bk)) {
    Buffer.prototype[_bk] = BufferProto[_bk];
  }
}
// Copy symbol-keyed properties
var _bSymbols = Object.getOwnPropertySymbols(BufferProto);
for (var _si = 0; _si < _bSymbols.length; _si++) {
  Buffer.prototype[_bSymbols[_si]] = BufferProto[_bSymbols[_si]];
}

// Define parent and offset on prototype
Object.defineProperty(Buffer.prototype, 'parent', {
  get: function() {
    try {
      return this.buffer;
    } catch(e) {
      return undefined;
    }
  },
  enumerable: true
});
Object.defineProperty(Buffer.prototype, 'offset', {
  get: function() {
    try {
      return this.byteOffset;
    } catch(e) {
      return undefined;
    }
  },
  enumerable: true
});

Buffer.prototype.__isExactBuffer = true;
Buffer._protoReady = true;

var kMaxLength = 2147483647; // 2^31 - 1
var kStringMaxLength = 536870888; // ~512MB, same as V8
var INSPECT_MAX_BYTES = 50;

var constants = {
  MAX_LENGTH: kMaxLength,
  MAX_STRING_LENGTH: kStringMaxLength,
};

// isAscii / isUtf8
function isAscii(input) {
  if (!ArrayBuffer.isView(input) && !(input instanceof ArrayBuffer) && !(typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)) {
    var err = new TypeError('The "input" argument must be an instance of ArrayBuffer, Buffer, TypedArray, or DataView.' + _invalidArgTypeHelper(input));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  // Check for detached buffer
  var ab = input instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)
    ? input : (input.buffer || input);
  if (ab.byteLength === 0 && input.byteLength === undefined) {
    // detached check
    try {
      new Uint8Array(ab);
    } catch(e) {
      var stateErr = new TypeError('Cannot perform operation on a detached ArrayBuffer');
      stateErr.code = 'ERR_INVALID_STATE';
      throw stateErr;
    }
  }
  var bytes;
  if (input instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else {
    bytes = input;
  }
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] > 127) return false;
  }
  return true;
}

function isUtf8(input) {
  if (!ArrayBuffer.isView(input) && !(input instanceof ArrayBuffer) && !(typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)) {
    var err = new TypeError('The "input" argument must be an instance of ArrayBuffer, Buffer, TypedArray, or DataView.' + _invalidArgTypeHelper(input));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  var bytes;
  if (input instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } else {
    bytes = input;
  }
  // Validate UTF-8 byte sequences
  var i = 0;
  while (i < bytes.length) {
    var b = bytes[i];
    if (b <= 0x7f) {
      i++;
    } else if (b >= 0xc2 && b <= 0xdf) {
      if (i + 1 >= bytes.length || (bytes[i+1] & 0xc0) !== 0x80) return false;
      i += 2;
    } else if (b >= 0xe0 && b <= 0xef) {
      if (i + 2 >= bytes.length) return false;
      var b1 = bytes[i+1], b2 = bytes[i+2];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80) return false;
      if (b === 0xe0 && b1 < 0xa0) return false;
      if (b === 0xed && b1 > 0x9f) return false;
      i += 3;
    } else if (b >= 0xf0 && b <= 0xf4) {
      if (i + 3 >= bytes.length) return false;
      var b1 = bytes[i+1], b2 = bytes[i+2], b3 = bytes[i+3];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80 || (b3 & 0xc0) !== 0x80) return false;
      if (b === 0xf0 && b1 < 0x90) return false;
      if (b === 0xf4 && b1 > 0x8f) return false;
      i += 4;
    } else {
      return false;
    }
  }
  return true;
}

// SlowBuffer
function SlowBuffer(size) {
  if (typeof size !== 'number' || size !== size) {
    throw _errOutOfRange('size', 'a non-negative integer', size !== size ? 'NaN' : size);
  }
  if (size < 0 || size > 2147483647) {
    throw _errOutOfRange('size', '>= 0 && <= 2147483647', size);
  }
  return Buffer.allocUnsafeSlow(size);
}
SlowBuffer.prototype = Buffer.prototype;

// INSPECT_MAX_BYTES with setter validation
var _inspectMaxBytes = 50;
var bufferModule = {
  Buffer: Buffer,
  atob: typeof atob === "function" ? atob : undefined,
  btoa: typeof btoa === "function" ? btoa : undefined,
  SlowBuffer: SlowBuffer,
  Blob: typeof Blob === "undefined" ? undefined : Blob,
  kMaxLength: kMaxLength,
  kStringMaxLength: kStringMaxLength,
  constants: constants,
  isAscii: isAscii,
  isUtf8: isUtf8,
};

Object.defineProperty(bufferModule, 'INSPECT_MAX_BYTES', {
  get: function() { return _inspectMaxBytes; },
  set: function(val) {
    if (typeof val !== 'number') {
      var err = new TypeError('The "INSPECT_MAX_BYTES" property must be of type number. Received type ' + typeof val);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (val < 0 || val !== val) {
      var err = new RangeError('The value of "INSPECT_MAX_BYTES" is out of range. It must be a non-negative number. Received ' + val);
      err.code = 'ERR_OUT_OF_RANGE';
      throw err;
    }
    _inspectMaxBytes = val;
    INSPECT_MAX_BYTES = val;
  },
  enumerable: true,
  configurable: true
});

module.exports = bufferModule;
