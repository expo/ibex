var BufferProto = {};
var objectToString = Object.prototype.toString;
var detachedArrayBuffersSymbol =
  typeof Symbol === "function" && typeof Symbol.for === "function"
    ? Symbol.for("exact.detachedArrayBuffers")
    : "__exactDetachedArrayBuffers";

function getDetachedArrayBuffers() {
  if (typeof globalThis === "undefined" || typeof WeakSet !== "function") {
    return null;
  }
  var detached = globalThis[detachedArrayBuffersSymbol];
  if (!detached || typeof detached.has !== "function") {
    try {
      detached = new WeakSet();
      globalThis[detachedArrayBuffersSymbol] = detached;
    } catch (err) {
      return null;
    }
  }
  return detached;
}

function isFiniteNumber(value) {
  return typeof value === "number" && value === value && value !== Infinity && value !== -Infinity;
}

function hasArrayBufferLikeTag(value) {
  if (!value || typeof value !== "object") return false;
  var tag = objectToString.call(value);
  return tag === "[object ArrayBuffer]" || tag === "[object SharedArrayBuffer]";
}

function isArrayBufferLike(value) {
  return getArrayBufferByteLength(value) !== null;
}

function getArrayBufferBacking(value) {
  if (!hasArrayBufferLikeTag(value)) return null;
  if (objectToString.call(value) === "[object SharedArrayBuffer]" &&
      value._buffer && objectToString.call(value._buffer) === "[object ArrayBuffer]") {
    return value._buffer;
  }
  return value;
}

function getArrayBufferByteLength(value) {
  var backing = getArrayBufferBacking(value);
  if (!backing) return null;
  try {
    var byteLength = backing.byteLength;
    return typeof byteLength === "number" ? byteLength : null;
  } catch (err) {
    return null;
  }
}

function isDetachedArrayBuffer(value) {
  var backing = getArrayBufferBacking(value);
  if (!backing) return false;
  var detached = getDetachedArrayBuffers();
  return !!(detached && detached.has(backing));
}

function throwIfDetachedBufferView(value) {
  if (value && typeof value === "object" && isDetachedArrayBuffer(value.buffer)) {
    throw new TypeError("Cannot operate on a detached ArrayBuffer");
  }
}

function formatReceivedValue(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  var type = typeof value;
  if (type === "function") {
    return "function " + (value.name || "<anonymous>");
  }
  if (type !== "object") {
    return "type " + type + " (" + String(value) + ")";
  }
  if (value && value.constructor && value.constructor.name) {
    return "an instance of " + value.constructor.name;
  }
  return String(value);
}

function formatReceivedValueWithQuotedString(value) {
  if (typeof value === "string") {
    return "type string ('" + value + "')";
  }
  return formatReceivedValue(value);
}

function isUint8Array(value) {
  return !!(value && (value.__isExactBuffer || objectToString.call(value) === "[object Uint8Array]"));
}

function getWritableByteView(value) {
  if (isUint8Array(value)) return value;
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  return null;
}

function getViewLength(value) {
  var view = getWritableByteView(value);
  return view ? view.byteLength : null;
}

function compareBytes(a, b, aStart, aEnd, bStart, bEnd) {
  var aLength = aEnd - aStart;
  var bLength = bEnd - bStart;
  var len = Math.min(aLength, bLength);
  for (var i = 0; i < len; i++) {
    var aValue = a[aStart + i];
    var bValue = b[bStart + i];
    if (aValue !== bValue) {
      return aValue < bValue ? -1 : 1;
    }
  }
  if (aLength === bLength) return 0;
  return aLength < bLength ? -1 : 1;
}

function getFillBytes(value, encoding) {
  if (typeof value === "string") {
    var stringBytes = encodeString(value, encoding || "utf8");
    return stringBytes.length > 0 ? stringBytes : null;
  }
  if (typeof value === "number") {
    return [value & 0xff];
  }
  if (value === true) {
    return [1];
  }
  if (value === false || value === 0 || value == null) {
    return [0];
  }
  if (value && value.__isExactBuffer) {
    return value.length > 0 ? value : null;
  }
  if (ArrayBuffer.isView(value)) {
    return value.byteLength > 0
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : null;
  }
  if (isArrayBufferLike(value)) {
    var arrayBufferBytes = new Uint8Array(value);
    return arrayBufferBytes.length > 0 ? arrayBufferBytes : null;
  }
  return [0];
}

function fillRange(target, value, start, end, encoding) {
  var fillBytes = getFillBytes(value, encoding);
  return fillRangeWithBytes(target, fillBytes, start, end);
}

var _Uint8Array_fill = typeof Uint8Array !== "undefined" && Uint8Array.prototype.fill
  ? Uint8Array.prototype.fill : null;

function fillRangeWithBytes(target, fillBytes, start, end) {
  var from = start == null ? 0 : start;
  var to = end == null ? target.length : end;
  if (from < 0) from = 0;
  if (to < from) to = from;
  if (to > target.length) to = target.length;
  var length = to - from;
  if (length <= 0) {
    return target;
  }
  var i;
  if (!fillBytes || fillBytes.length === 0) {
    if (_Uint8Array_fill && target instanceof Uint8Array) {
      _Uint8Array_fill.call(target, 0, from, to);
      return target;
    }
    for (i = from; i < to; i++) {
      target[i] = 0;
    }
    return target;
  }
  if (_Uint8Array_fill && target instanceof Uint8Array && fillBytes.length === 1) {
    _Uint8Array_fill.call(target, fillBytes[0] & 0xff, from, to);
    return target;
  }
  if (typeof target.set === "function" && typeof target.subarray === "function") {
    var firstCopy = fillBytes.length < length ? fillBytes.length : length;
    target.set(firstCopy === fillBytes.length ? fillBytes : fillBytes.subarray(0, firstCopy), from);
    var copied = firstCopy;
    while (copied < length) {
      var copyLength = copied < (length - copied) ? copied : (length - copied);
      target.set(target.subarray(from, from + copyLength), from + copied);
      copied += copyLength;
    }
    return target;
  }
  for (i = from; i < to; i++) {
    target[i] = fillBytes[(i - from) % fillBytes.length] & 0xff;
  }
  return target;
}

function toEncodingCheckBytes(value) {
  if (isUint8Array(value)) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  if (isArrayBufferLike(value)) {
    return new Uint8Array(getArrayBufferBacking(value));
  }
  throw makeInvalidArgTypeError(
    "input",
    "an instance of ArrayBuffer, Buffer, TypedArray, or DataView",
    value
  );
}

function isAsciiBytes(value) {
  var constructorTarget = this instanceof isAsciiBytes ? this : null;
  var bytes = toEncodingCheckBytes(value);
  for (var i = 0; i < bytes.length; i++) {
    if ((bytes[i] & 0x80) !== 0) {
      return returnBooleanLike(constructorTarget, false);
    }
  }
  return returnBooleanLike(constructorTarget, true);
}

function isUtf8Bytes(value) {
  var constructorTarget = this instanceof isUtf8Bytes ? this : null;
  var bytes = toEncodingCheckBytes(value);
  if (bytes.length === 0) {
    return returnBooleanLike(constructorTarget, true);
  }
  if (typeof TextDecoder === "function") {
    try {
      var decoder = new TextDecoder("utf-8", { fatal: true });
      decoder.decode(bytes);
      return returnBooleanLike(constructorTarget, true);
    } catch (err) {
      return returnBooleanLike(constructorTarget, false);
    }
  }
  var i = 0;
  while (i < bytes.length) {
    var byte1 = bytes[i++];
    if ((byte1 & 0x80) === 0) {
      continue;
    }
    if ((byte1 & 0xe0) === 0xc0) {
      if (i >= bytes.length) return returnBooleanLike(constructorTarget, false);
      var byte2 = bytes[i++];
      if ((byte2 & 0xc0) !== 0x80 || (byte1 & 0xfe) === 0xc0) {
        return returnBooleanLike(constructorTarget, false);
      }
      continue;
    }
    if ((byte1 & 0xf0) === 0xe0) {
      if (i + 1 >= bytes.length) return returnBooleanLike(constructorTarget, false);
      var byte3a = bytes[i++];
      var byte3b = bytes[i++];
      if ((byte3a & 0xc0) !== 0x80 || (byte3b & 0xc0) !== 0x80) {
        return returnBooleanLike(constructorTarget, false);
      }
      var codePoint3 =
        ((byte1 & 0x0f) << 12) | ((byte3a & 0x3f) << 6) | (byte3b & 0x3f);
      if (codePoint3 < 0x800 || (codePoint3 >= 0xd800 && codePoint3 <= 0xdfff)) {
        return returnBooleanLike(constructorTarget, false);
      }
      continue;
    }
    if ((byte1 & 0xf8) === 0xf0) {
      if (i + 2 >= bytes.length) return returnBooleanLike(constructorTarget, false);
      var byte4a = bytes[i++];
      var byte4b = bytes[i++];
      var byte4c = bytes[i++];
      if (
        (byte4a & 0xc0) !== 0x80 ||
        (byte4b & 0xc0) !== 0x80 ||
        (byte4c & 0xc0) !== 0x80
      ) {
        return returnBooleanLike(constructorTarget, false);
      }
      var codePoint4 =
        ((byte1 & 0x07) << 18) |
        ((byte4a & 0x3f) << 12) |
        ((byte4b & 0x3f) << 6) |
        (byte4c & 0x3f);
      if (codePoint4 < 0x10000 || codePoint4 > 0x10ffff) {
        return returnBooleanLike(constructorTarget, false);
      }
      continue;
    }
    return returnBooleanLike(constructorTarget, false);
  }
  return returnBooleanLike(constructorTarget, true);
}

function wrapBooleanLike(target, value) {
  var result = value === true;
  try {
    Object.defineProperty(target, "__exactBooleanValue", {
      value: result,
      configurable: true,
      enumerable: false,
      writable: true,
    });
    Object.defineProperty(target, "valueOf", {
      value: function() {
        return result;
      },
      configurable: true,
      enumerable: false,
      writable: true,
    });
    Object.defineProperty(target, "toString", {
      value: function() {
        return result ? "true" : "false";
      },
      configurable: true,
      enumerable: false,
      writable: true,
    });
  } catch (err) {
    target.__exactBooleanValue = result;
    target.valueOf = function() {
      return result;
    };
    target.toString = function() {
      return result ? "true" : "false";
    };
  }
  return target;
}

function returnBooleanLike(target, value) {
  if (!target || typeof target !== "object") {
    return value;
  }
  return wrapBooleanLike(target, value);
}

function createOutOfRangeError(name, expectation, received) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + expectation + '. Received ' + received);
  err.code = "ERR_OUT_OF_RANGE";
  return err;
}

function makeFirstArgumentError(value) {
  var err = new TypeError(
    "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received " +
    formatReceivedValue(value)
  );
  err.code = "ERR_INVALID_ARG_TYPE";
  return err;
}

function makeBufferBoundsError(which) {
  var err = new RangeError('"' + which + '" is outside of buffer bounds');
  err.code = "ERR_BUFFER_OUT_OF_BOUNDS";
  return err;
}

function normalizeInteger(value, fallback) {
  if (value === undefined) return fallback;
  var number = Number(value);
  if (number !== number) return fallback;
  if (!isFiniteNumber(number)) return number;
  if (number < 0) return Math.ceil(number);
  return Math.floor(number);
}

function toArrayLikeLength(value) {
  var number = Number(value && value.length);
  if (!isFiniteNumber(number) || number <= 0) return 0;
  number = Math.floor(number);
  if (number > 0x7fffffff) return 0x7fffffff;
  return number;
}

function fromArrayLike(value) {
  var length = toArrayLikeLength(value);
  var bytes = new Uint8Array(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = value[i] & 0xff;
  }
  return bytes;
}

function fromArrayBuffer(value, byteOffset, length) {
  var backing = getArrayBufferBacking(value);
  var totalLength = getArrayBufferByteLength(value);
  if (totalLength === null) {
    throw makeFirstArgumentError(value);
  }
  totalLength = totalLength >>> 0;
  var offset = normalizeInteger(byteOffset, 0);
  if (!isFiniteNumber(offset) || offset < 0 || offset > totalLength) {
    throw makeBufferBoundsError("offset");
  }
  var viewLength;
  if (length === undefined) {
    viewLength = totalLength - offset;
  } else {
    viewLength = normalizeInteger(length, 0);
    if (!isFiniteNumber(viewLength) || viewLength < 0 || offset + viewLength > totalLength) {
      throw makeBufferBoundsError("length");
    }
  }
  return makeBuffer(new Uint8Array(backing, offset, viewLength));
}

function formatBigIntWithSeparators(value) {
  var negative = value < 0n;
  var digits = (negative ? -value : value).toString();
  var formatted = "";
  var prefixLength = digits.length % 3;
  if (prefixLength > 0) {
    formatted = digits.slice(0, prefixLength);
  }
  for (var i = prefixLength; i < digits.length; i += 3) {
    if (formatted) formatted += "_";
    formatted += digits.slice(i, i + 3);
  }
  if (!formatted) formatted = "0";
  return (negative ? "-" : "") + formatted + "n";
}

function base64ByteLength(value) {
  return decodeBase64Bytes(value).length;
}

function decodeBase64Char(code) {
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x47;
  if (code >= 0x30 && code <= 0x39) return code + 0x04;
  if (code === 0x2b || code === 0x2d) return 62;
  if (code === 0x2f || code === 0x5f) return 63;
  return -1;
}

function decodeBase64Bytes(value) {
  var input = String(value);
  var sextets = [];
  for (var i = 0; i < input.length; i++) {
    var code = input.charCodeAt(i);
    if (code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d || code === 0x20) {
      continue;
    }
    if (code === 0x3d) {
      break;
    }
    var sextet = decodeBase64Char(code);
    if (sextet >= 0) {
      sextets.push(sextet);
    }
  }

  var fullGroups = Math.floor(sextets.length / 4);
  var remainder = sextets.length % 4;
  var byteLength = fullGroups * 3;
  if (remainder === 2) {
    byteLength += 1;
  } else if (remainder === 3) {
    byteLength += 2;
  }

  var bytes = new Uint8Array(byteLength);
  var outIndex = 0;
  var sextetIndex = 0;

  for (var group = 0; group < fullGroups; group++) {
    var a = sextets[sextetIndex++];
    var b = sextets[sextetIndex++];
    var c = sextets[sextetIndex++];
    var d = sextets[sextetIndex++];
    bytes[outIndex++] = (a << 2) | (b >> 4);
    bytes[outIndex++] = ((b & 0x0f) << 4) | (c >> 2);
    bytes[outIndex++] = ((c & 0x03) << 6) | d;
  }

  if (remainder === 2) {
    var tailA = sextets[sextetIndex++];
    var tailB = sextets[sextetIndex++];
    bytes[outIndex++] = (tailA << 2) | (tailB >> 4);
  } else if (remainder === 3) {
    var tailC = sextets[sextetIndex++];
    var tailD = sextets[sextetIndex++];
    var tailE = sextets[sextetIndex++];
    bytes[outIndex++] = (tailC << 2) | (tailD >> 4);
    bytes[outIndex++] = ((tailD & 0x0f) << 4) | (tailE >> 2);
  }

  return bytes;
}

function validateBigIntWrite(value, signed) {
  if (typeof value !== "bigint") {
    var typeErr = new TypeError('The "value" argument must be of type bigint. Received ' + formatReceivedValue(value));
    typeErr.code = "ERR_INVALID_ARG_TYPE";
    throw typeErr;
  }
  var min = signed ? -(1n << 63n) : 0n;
  var max = signed ? (1n << 63n) - 1n : (1n << 64n) - 1n;
  if (value < min || value > max) {
    var rangeErr = new RangeError(
      'The value of "value" is out of range. It must be ' +
      (signed ? '>= -(2n ** 63n) and < 2n ** 63n' : '>= 0n and < 2n ** 64n') +
      '. Received ' + formatBigIntWithSeparators(value)
    );
    rangeErr.code = "ERR_OUT_OF_RANGE";
    throw rangeErr;
  }
}

function formatNumberWithSeparators(value) {
  var negative = value < 0;
  var digits = String(Math.abs(value));
  return (negative ? "-" : "") + digits.replace(/(\d)(?=(\d{3})+(?!\d))/g, "$1_");
}

function makeInvalidArgTypeError(name, expected, value) {
  var err = new TypeError('The "' + name + '" argument must be ' + expected + '. Received ' + formatReceivedValue(value));
  err.code = "ERR_INVALID_ARG_TYPE";
  return err;
}

function makeInvalidArgValueError(name, value) {
  var err = new TypeError("The argument '" + name + "' is invalid. Received " + String(value));
  err.code = "ERR_INVALID_ARG_VALUE";
  return err;
}

function makeUnknownEncodingError(encoding) {
  var err = new TypeError("Unknown encoding: " + encoding);
  err.code = "ERR_UNKNOWN_ENCODING";
  return err;
}

function makeOutOfBoundsReadError() {
  var err = new RangeError("Attempt to access memory outside buffer bounds");
  err.code = "ERR_BUFFER_OUT_OF_BOUNDS";
  return err;
}

function normalizeToInteger(value) {
  return value < 0 ? Math.ceil(value) : Math.floor(value);
}

function validateOffset(offset, byteLength, bufferLength) {
  if (offset === undefined) return 0;
  if (typeof offset !== "number") {
    throw makeInvalidArgTypeError("offset", "of type number", offset);
  }
  if (offset !== offset || offset !== Math.floor(offset)) {
    throw createOutOfRangeError("offset", "an integer", offset);
  }
  offset = normalizeToInteger(offset);
  var maxOffset = Math.max(bufferLength - byteLength, 0);
  if (!isFiniteNumber(offset) || offset < 0 || offset > maxOffset) {
    if (bufferLength < byteLength && offset >= 0 && isFiniteNumber(offset)) {
      throw makeOutOfBoundsReadError();
    }
    throw createOutOfRangeError("offset", ">= 0 and <= " + maxOffset, offset);
  }
  if (offset + byteLength > bufferLength) {
    throw makeOutOfBoundsReadError();
  }
  return offset;
}

function validateByteLength(byteLength) {
  if (typeof byteLength !== "number") {
    throw makeInvalidArgTypeError("byteLength", "of type number", byteLength);
  }
  if (byteLength !== byteLength || byteLength !== Math.floor(byteLength)) {
    throw createOutOfRangeError("byteLength", "an integer", byteLength);
  }
  if (!isFiniteNumber(byteLength) || byteLength < 1 || byteLength > 6) {
    throw createOutOfRangeError("byteLength", ">= 1 and <= 6", byteLength);
  }
  return byteLength;
}

function validateWriteValue(value, min, max, bits, signed) {
  if (typeof value !== "number" || value !== Math.floor(value) || !isFiniteNumber(value) || value < min || value > max) {
    var expectation;
    var received = value;
    if (!signed && bits >= 40) {
      expectation = ">= 0 and < 2 ** " + bits;
      received = formatNumberWithSeparators(value);
    } else if (signed && bits > 32) {
      expectation = ">= -(2 ** " + (bits - 1) + ") and < 2 ** " + (bits - 1);
      received = formatNumberWithSeparators(value);
    } else {
      expectation = ">= " + min + " and <= " + max;
    }
    throw createOutOfRangeError("value", expectation, received);
  }
}

function normalizeCopyIndex(value, name, fallback) {
  if (value === undefined) return fallback;
  var number = Number(value);
  if (number !== number) return fallback;
  if (!isFiniteNumber(number)) {
    throw createOutOfRangeError(name, ">= 0", value);
  }
  return normalizeToInteger(number);
}

function normalizeCompareIndex(value, name, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== "number") {
    throw makeInvalidArgTypeError(name, "of type number", value);
  }
  if (value !== value || value !== Math.floor(value)) {
    throw createOutOfRangeError(name, "an integer", value);
  }
  if (!isFiniteNumber(value)) {
    throw createOutOfRangeError(name, ">= 0 && <= 2147483647", value);
  }
  return normalizeToInteger(value);
}

function normalizeFillIndex(value, name, fallback, bufferLength) {
  if (value === undefined) return fallback;
  if (typeof value !== "number") {
    throw makeInvalidArgTypeError(name, "of type number", value);
  }
  if (value !== value) {
    throw createOutOfRangeError(name, "an integer", value);
  }
  if (!isFiniteNumber(value) || value < 0 || value > bufferLength) {
    throw createOutOfRangeError(name, ">= 0 && <= " + bufferLength, value);
  }
  return normalizeToInteger(value);
}

function coerceEncoding(encoding) {
  if (!encoding) return "utf8";
  var normalized = String(encoding).toLowerCase().replace("-", "");
  if (normalized === "utf8") return "utf8";
  if (normalized === "utf-8") return "utf8";
  return normalized;
}

function decodeUtf8Bytes(bytes) {
  var result = "";
  var i = 0;
  var len = bytes.length;
  while (i < len) {
    var b = bytes[i];
    if (b < 0x80) {
      result += String.fromCharCode(b);
      i++;
      continue;
    }
    var seqLen;
    var minCp;
    if ((b & 0xE0) === 0xC0) {
      seqLen = 2;
      minCp = 0x80;
    } else if ((b & 0xF0) === 0xE0) {
      seqLen = 3;
      minCp = 0x800;
    } else if ((b & 0xF8) === 0xF0) {
      seqLen = 4;
      minCp = 0x10000;
    } else {
      result += "\uFFFD";
      i++;
      continue;
    }
    var got = 1;
    for (var j = 1; j < seqLen && i + j < len; j++) {
      if ((bytes[i + j] & 0xC0) !== 0x80) {
        break;
      }
      got++;
    }
    if (got < seqLen) {
      result += "\uFFFD";
      i += got;
      continue;
    }
    var cp;
    if (seqLen === 2) {
      cp = ((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F);
    } else if (seqLen === 3) {
      cp = ((b & 0x0F) << 12) |
        ((bytes[i + 1] & 0x3F) << 6) |
        (bytes[i + 2] & 0x3F);
    } else {
      cp = ((b & 0x07) << 18) |
        ((bytes[i + 1] & 0x3F) << 12) |
        ((bytes[i + 2] & 0x3F) << 6) |
        (bytes[i + 3] & 0x3F);
    }
    if (cp < minCp || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) {
      result += "\uFFFD";
      i++;
      continue;
    }
    if (cp > 0xFFFF) {
      cp -= 0x10000;
      result += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
    } else {
      result += String.fromCharCode(cp);
    }
    i += seqLen;
  }
  return result;
}

function decodeBytes(bytes, encoding, start, end) {
  var enc = coerceEncoding(encoding || "utf8");
  var sliceStart = start || 0;
  var slice = (start !== undefined || end !== undefined)
    ? (typeof bytes.subarray === "function" ? bytes.subarray(sliceStart, end) : Uint8Array.prototype.slice.call(bytes, sliceStart, end))
    : bytes;
  if (enc === "utf8") {
    var hasUtf8Bom = slice &&
      slice.length >= 3 &&
      slice[0] === 0xef &&
      slice[1] === 0xbb &&
      slice[2] === 0xbf;
    if (typeof __exactBytesToUtf8String === "function" && !hasUtf8Bom) {
      return __exactBytesToUtf8String(slice);
    }
    return decodeUtf8Bytes(slice);
  }
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
    return decodeBase64Bytes(str);
  }
  if (enc === "latin1" || enc === "binary") {
    var lat = new Uint8Array(str.length);
    for (var k = 0; k < str.length; k++) lat[k] = str.charCodeAt(k) & 0xff;
    return lat;
  }
  if (enc === "ascii") {
    var asc = new Uint8Array(str.length);
    for (var m = 0; m < str.length; m++) asc[m] = str.charCodeAt(m) & 0xff;
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

function toByteArray(value, encoding) {
  if (value == null) {
    throw makeFirstArgumentError(value);
  }
  if (isUint8Array(value)) {
    return new Uint8Array(value);
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    return fromArrayLike(value);
  }
  if (isArrayBufferLike(value)) {
    return new Uint8Array(value);
  }
  if (typeof value === "string") {
    if (encoding !== undefined && encoding !== null) {
      var encodingName = String(encoding);
      if (typeof Buffer === "function" && Buffer.isEncoding && !Buffer.isEncoding(encodingName)) {
        throw makeUnknownEncodingError(encoding);
      }
    }
    return encodeString(value, encoding);
  }
  if (
    value &&
    typeof value === "object" &&
    typeof Symbol === "function" &&
    Symbol.toPrimitive &&
    typeof value[Symbol.toPrimitive] === "function"
  ) {
    var primitive = value[Symbol.toPrimitive]("string");
    if (primitive !== value && (typeof primitive !== "object" || primitive === null)) {
      return toByteArray(primitive, encoding);
    }
  }
  if (typeof value === "object" && value !== null && typeof value.valueOf === "function") {
    var unboxed = value.valueOf();
    if (unboxed !== value) {
      return toByteArray(unboxed, encoding);
    }
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (typeof value === "object" && value !== null && ("length" in value || "buffer" in value)) {
    return fromArrayLike(value);
  }
  if (value && typeof value === "object" && value.type === "Buffer" && Array.isArray(value.data)) {
    return new Uint8Array(value.data);
  }
  throw makeFirstArgumentError(value);
}

function Buffer(value, encoding, length) {
  if (typeof value === "number") {
    if (arguments.length > 1) {
      throw makeInvalidArgTypeError("string", "of type string", value);
    }
    return Buffer.alloc(value);
  }
  return Buffer.from(value, encoding, length);
}

function makeBuffer(bytes) {
  var buffer = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
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

Buffer.from = function(value, encoding, length) {
  if (typeof value === "number") {
    throw makeFirstArgumentError(value);
  }
  if (value && value.__isExactBuffer) {
    return makeBuffer(new Uint8Array(value));
  }
  if (isArrayBufferLike(value)) {
    return fromArrayBuffer(value, encoding, length);
  }
  if (isUint8Array(value)) {
    return makeBuffer(new Uint8Array(value));
  }
  return makeBuffer(toByteArray(value, encoding));
};

function normalizeBufferSize(size) {
  if (typeof size !== "number") {
    throw makeInvalidArgTypeError("size", "of type number", size);
  }
  if (size !== size) {
    var sizeErr = new RangeError('The value of "size" is out of range. It must be a non-negative integer. Received ' + (size !== size ? "NaN" : size));
    sizeErr.code = "ERR_OUT_OF_RANGE";
    throw sizeErr;
  }
  if (!isFiniteNumber(size) || size < 0 || size > kMaxLength) {
    var rangeErr = new RangeError('The value of "size" is out of range. It must be >= 0 && <= ' + kMaxLength + '. Received ' + size);
    rangeErr.code = "ERR_OUT_OF_RANGE";
    throw rangeErr;
  }
  return normalizeInteger(size, 0);
}

function getAllocFillBytes(value, encoding) {
  if (encoding !== undefined && encoding !== null && typeof encoding !== "string") {
    throw makeInvalidArgTypeError("encoding", "of type string", encoding);
  }
  if (typeof value === "string") {
    var enc = encoding == null ? "utf8" : encoding;
    if (typeof Buffer === "function" && Buffer.isEncoding && !Buffer.isEncoding(enc)) {
      throw makeUnknownEncodingError(enc);
    }
    var stringBytes = encodeString(value, enc);
    if (coerceEncoding(enc) === "hex" && value.length > 0 && (value.length % 2 !== 0 || stringBytes.length * 2 !== value.length)) {
      throw makeInvalidArgValueError("value", value);
    }
    if (value.length > 0 && stringBytes.length === 0) {
      throw makeInvalidArgValueError("value", value);
    }
    return stringBytes;
  }
  if (value && value.__isExactBuffer) {
    if (value.length === 0) {
      throw makeInvalidArgValueError("value", value);
    }
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    if (value.byteLength === 0) {
      throw makeInvalidArgValueError("value", value);
    }
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  if (isArrayBufferLike(value)) {
    var bytes = new Uint8Array(value);
    if (bytes.length === 0) {
      throw makeInvalidArgValueError("value", value);
    }
    return bytes;
  }
  return getFillBytes(value, encoding);
}

Buffer.alloc = function(size, fill, encoding) {
  size = normalizeBufferSize(size);
  var bytes = new Uint8Array(size || 0);
  if (fill === undefined || fill === null) {
    return makeBuffer(bytes);
  }
  var fillBytes = getAllocFillBytes(fill, encoding);
  fillRangeWithBytes(bytes, fillBytes, 0, bytes.length);
  return makeBuffer(bytes);
};

Buffer.allocUnsafe = function(size) {
  size = normalizeBufferSize(size);
  return makeBuffer(new Uint8Array(size || 0));
};
Buffer.allocUnsafeSlow = Buffer.allocUnsafe;
Buffer.poolSize = 8192;

Buffer.byteLength = function(string, encoding) {
  if (typeof string !== 'string' && !(string && string.__isExactBuffer) &&
      !isArrayBufferLike(string) && !ArrayBuffer.isView(string)) {
    var err = new TypeError(
      'The "string" argument must be of type string or an instance of Buffer or ArrayBuffer. Received ' +
      formatReceivedValue(string)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (typeof string !== 'string') {
    if (ArrayBuffer.isView(string) &&
        typeof string.length === "number") {
      var bytesPerElement = string && string.constructor && string.constructor.BYTES_PER_ELEMENT;
      if (typeof bytesPerElement !== "number") {
        bytesPerElement = string.BYTES_PER_ELEMENT;
      }
      if (typeof bytesPerElement === "number") {
        return string.length * bytesPerElement;
      }
    }
    if (ArrayBuffer.isView(string) && typeof string.byteLength === "number") {
      return string.byteLength;
    }
    if (typeof string.byteLength !== "undefined") {
      return string.byteLength;
    }
    return string.length;
  }
  var normalizedEncoding = coerceEncoding(encoding || "utf8");
  if (normalizedEncoding === "base64" || normalizedEncoding === "base64url") {
    return base64ByteLength(string);
  }
  return encodeString(string, normalizedEncoding).length;
};

Buffer.compare = function(a, b) {
  if (!isUint8Array(a)) {
    var buf1Err = new TypeError(
      'The "buf1" argument must be an instance of Buffer or Uint8Array. Received ' +
      formatReceivedValueWithQuotedString(a)
    );
    buf1Err.code = "ERR_INVALID_ARG_TYPE";
    throw buf1Err;
  }
  if (!isUint8Array(b)) {
    var buf2Err = new TypeError(
      'The "buf2" argument must be an instance of Buffer or Uint8Array. Received ' +
      formatReceivedValueWithQuotedString(b)
    );
    buf2Err.code = "ERR_INVALID_ARG_TYPE";
    throw buf2Err;
  }
  return compareBytes(a, b, 0, a.length, 0, b.length);
};

Buffer.concat = function(list, totalLength) {
  if (!Array.isArray(list)) {
    var listErr = new TypeError('The "list" argument must be an instance of Array. Received ' + formatReceivedValue(list));
    listErr.code = "ERR_INVALID_ARG_TYPE";
    throw listErr;
  }
  if (list.length === 0) return Buffer.alloc(0);
  var total = totalLength;
  if (total === undefined) {
    total = 0;
    for (var i = 0; i < list.length; i++) {
      if (!isUint8Array(list[i])) {
        var itemErr = new TypeError(
          'The "list[' + i + ']" argument must be an instance of Buffer or Uint8Array. Received ' +
          formatReceivedValue(list[i])
        );
        itemErr.code = "ERR_INVALID_ARG_TYPE";
        throw itemErr;
      }
      total += list[i].length;
    }
  } else {
    if (typeof total !== "number") {
      throw makeInvalidArgTypeError("length", "of type number", total);
    }
    if (total !== Math.floor(total)) {
      throw createOutOfRangeError("length", "an integer", total);
    }
    if (total < 0 || total > Number.MAX_SAFE_INTEGER) {
      throw createOutOfRangeError("length", ">= 0 && <= 9007199254740991", total);
    }
    for (var j = 0; j < list.length; j++) {
      if (!isUint8Array(list[j])) {
        var listItemErr = new TypeError(
          'The "list[' + j + ']" argument must be an instance of Buffer or Uint8Array. Received ' +
          formatReceivedValue(list[j])
        );
        listItemErr.code = "ERR_INVALID_ARG_TYPE";
        throw listItemErr;
      }
    }
  }
  var result = Buffer.alloc(total);
  var offset = 0;
  for (var k = 0; k < list.length; k++) {
    var buf = list[k];
    for (var m = 0; m < buf.length && offset < total; m++) {
      result[offset++] = buf[m];
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
  return typeof encoding === "string" &&
    ["utf8", "utf-8", "ascii", "latin1", "binary", "hex", "base64", "base64url", "ucs2", "ucs-2", "utf16le", "utf-16le"]
    .indexOf(encoding.toLowerCase()) !== -1;
};

function toSearchBytes(value, encoding) {
  if (typeof value === "string") {
    return encodeString(value, encoding || "utf8");
  }
  if (typeof value === "number") {
    var number = Number(value);
    if (number !== number) {
      number = 0;
    }
    return new Uint8Array([number & 0xff]);
  }
  if (isUint8Array(value)) {
    return value;
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  if (isArrayBufferLike(value)) {
    return new Uint8Array(getArrayBufferBacking(value));
  }
  throw makeInvalidArgTypeError(
    "value",
    "of type string, number, Buffer, Uint8Array, or ArrayBuffer",
    value
  );
}

function normalizeIndexOfOffset(bufferLength, byteOffset) {
  if (byteOffset === undefined) return 0;
  var offset = Number(byteOffset);
  if (offset !== offset) return 0;
  if (!isFiniteNumber(offset)) {
    return offset < 0 ? 0 : bufferLength;
  }
  offset = normalizeToInteger(offset);
  if (offset < 0) {
    offset += bufferLength;
  }
  if (offset < 0) return 0;
  if (offset > bufferLength) return bufferLength;
  return offset;
}

function normalizeLastIndexOfOffset(bufferLength, byteOffset) {
  if (bufferLength === 0) return -1;
  if (byteOffset === undefined) return bufferLength - 1;
  var offset = Number(byteOffset);
  if (offset !== offset) return bufferLength - 1;
  if (!isFiniteNumber(offset)) {
    return offset < 0 ? -1 : bufferLength - 1;
  }
  offset = normalizeToInteger(offset);
  if (offset < 0) {
    offset += bufferLength;
  }
  if (offset < 0) return -1;
  if (offset >= bufferLength) return bufferLength - 1;
  return offset;
}

function findBufferSequence(buffer, value, byteOffset, encoding, backwards) {
  if (typeof byteOffset === "string") {
    encoding = byteOffset;
    byteOffset = backwards ? undefined : 0;
  }

  var needle = toSearchBytes(value, encoding);
  var offset = backwards
    ? normalizeLastIndexOfOffset(buffer.length, byteOffset)
    : normalizeIndexOfOffset(buffer.length, byteOffset);

  if (needle.length === 0) {
    if (backwards) {
      if (offset < 0) return -1;
      return offset > buffer.length ? buffer.length : offset;
    }
    return offset > buffer.length ? buffer.length : offset;
  }

  if (needle.length > buffer.length) {
    return -1;
  }

  if (backwards) {
    var start = offset;
    var maxStart = buffer.length - needle.length;
    if (start > maxStart) {
      start = maxStart;
    }
    for (var i = start; i >= 0; i--) {
      if (compareBytes(buffer, needle, i, i + needle.length, 0, needle.length) === 0) {
        return i;
      }
    }
    return -1;
  }

  var end = buffer.length - needle.length;
  for (var j = offset; j <= end; j++) {
    if (compareBytes(buffer, needle, j, j + needle.length, 0, needle.length) === 0) {
      return j;
    }
  }
  return -1;
}

function getSliceView(target) {
  var view = getWritableByteView(target);
  if (!view) {
    throw makeInvalidArgTypeError("this", "an instance of Buffer or Uint8Array", target);
  }
  return view;
}

function normalizeSliceBound(value, name, fallback, length) {
  if (value === undefined) return fallback;
  if (typeof value !== "number") {
    throw makeInvalidArgTypeError(name, "of type number", value);
  }
  if (value !== value) {
    throw createOutOfRangeError(name, "an integer", value);
  }
  if (!isFiniteNumber(value) || value < 0 || value > length) {
    throw createOutOfRangeError(name, ">= 0 && <= " + length, value);
  }
  return normalizeToInteger(value);
}

function sliceWithEncoding(target, encoding, start, end) {
  var view = getSliceView(target);
  var length = view.byteLength;
  var actualStart = normalizeSliceBound(start, "start", 0, length);
  var actualEnd = normalizeSliceBound(end, "end", length, length);
  if (actualEnd <= actualStart) {
    return "";
  }
  if (encoding === "hex" && (actualEnd - actualStart) * 2 > kStringMaxLength) {
    throw new Error("Cannot create a string longer than " + kStringMaxLength + " characters");
  }
  return decodeBytes(view, encoding, actualStart, actualEnd);
}

BufferProto.toString = function(encoding, start, end) {
  var enc;
  if (encoding === undefined) {
    enc = "utf8";
  } else {
    enc = String(encoding);
    if (!Buffer.isEncoding(enc)) {
      throw makeUnknownEncodingError(enc);
    }
  }

  var actualStart;
  if (start === undefined) {
    actualStart = 0;
  } else {
    var startNumber = Number(start);
    if (startNumber !== startNumber) startNumber = 0;
    if (!isFinite(startNumber)) {
      actualStart = startNumber < 0 ? 0 : this.length;
    } else {
      actualStart = normalizeToInteger(startNumber);
      if (actualStart < 0) actualStart = 0;
      if (actualStart > this.length) actualStart = this.length;
    }
  }

  var actualEnd;
  if (end === undefined) {
    actualEnd = this.length;
  } else {
    var endNumber = Number(end);
    if (endNumber !== endNumber) endNumber = 0;
    if (!isFinite(endNumber)) {
      actualEnd = endNumber < 0 ? 0 : this.length;
    } else {
      actualEnd = normalizeToInteger(endNumber);
      if (actualEnd < 0) actualEnd = 0;
      if (actualEnd > this.length) actualEnd = this.length;
    }
  }

  if (actualEnd <= actualStart) return "";
  return decodeBytes(this, enc, actualStart, actualEnd);
};

BufferProto._toByteString = function(encoding) {
  return decodeBytes(this, encoding || 'latin1');
};

BufferProto.equals = function(other) {
  if (!isUint8Array(other)) {
    var otherErr = new TypeError(
      'The "otherBuffer" argument must be an instance of Buffer or Uint8Array. Received ' +
      formatReceivedValueWithQuotedString(other)
    );
    otherErr.code = "ERR_INVALID_ARG_TYPE";
    throw otherErr;
  }
  return compareBytes(this, other, 0, this.length, 0, other.length) === 0;
};

BufferProto.toJSON = function() {
  var view = getWritableByteView(this);
  if (!view) {
    return { type: "Buffer", data: [] };
  }
  return {
    type: "Buffer",
    data: Array.prototype.slice.call(
      new Uint8Array(view.buffer, view.byteOffset || 0, view.byteLength)
    ),
  };
};

BufferProto.toLocaleString = BufferProto.toString;
BufferProto.inspect = function() {
  if (typeof Bun !== "undefined" && Bun && typeof Bun.inspect === "function") {
    return Bun.inspect(this);
  }
  if (typeof require === "function") {
    try {
      var bunMod = require("bun");
      if (bunMod && typeof bunMod.inspect === "function") {
        return bunMod.inspect(this);
      }
    } catch (_bunInspectErr) {}
    try {
      return require("node:util").inspect(this).replace(/'/g, '"');
    } catch (_utilInspectErr) {}
  }
  return "<Buffer " + decodeBytes(this, "hex") + ">";
};

BufferProto.asciiSlice = function(start, end) {
  return sliceWithEncoding(this, "ascii", start, end);
};

BufferProto.latin1Slice = function(start, end) {
  return sliceWithEncoding(this, "latin1", start, end);
};

BufferProto.utf8Slice = function(start, end) {
  return sliceWithEncoding(this, "utf8", start, end);
};

BufferProto.hexSlice = function(start, end) {
  return sliceWithEncoding(this, "hex", start, end);
};

BufferProto.ucs2Slice = function(start, end) {
  return sliceWithEncoding(this, "ucs2", start, end);
};

BufferProto.base64Slice = function(start, end) {
  return sliceWithEncoding(this, "base64", start, end);
};

BufferProto.base64urlSlice = function(start, end) {
  return sliceWithEncoding(this, "base64url", start, end);
};

BufferProto.indexOf = function(value, byteOffset, encoding) {
  return findBufferSequence(this, value, byteOffset, encoding, false);
};

BufferProto.includes = function(value, byteOffset, encoding) {
  return this.indexOf(value, byteOffset, encoding) !== -1;
};

BufferProto.lastIndexOf = function(value, byteOffset, encoding) {
  return findBufferSequence(this, value, byteOffset, encoding, true);
};

BufferProto.slice = function(start, end) {
  throwIfDetachedBufferView(this);
  return makeBuffer(Uint8Array.prototype.subarray.call(this, start, end));
};

BufferProto.subarray = function(start, end) {
  throwIfDetachedBufferView(this);
  return makeBuffer(Uint8Array.prototype.subarray.call(this, start, end));
};

BufferProto.copy = function(target, targetStart, sourceStart, sourceEnd) {
  if (!isUint8Array(this)) {
    var thisErr = new TypeError('The "this" argument must be an instance of Buffer or Uint8Array. Received ' + formatReceivedValue(this));
    thisErr.code = "ERR_INVALID_ARG_TYPE";
    throw thisErr;
  }
  var targetBytes = getWritableByteView(target);
  if (!targetBytes) {
    var targetErr = new TypeError('The "target" argument must be an instance of Buffer or Uint8Array. Received ' + formatReceivedValue(target));
    targetErr.code = "ERR_INVALID_ARG_TYPE";
    throw targetErr;
  }
  targetStart = normalizeCopyIndex(targetStart, "targetStart", 0);
  sourceStart = normalizeCopyIndex(sourceStart, "sourceStart", 0);
  sourceEnd = sourceEnd == null ? this.length : normalizeCopyIndex(sourceEnd, "sourceEnd", this.length);

  if (targetStart < 0) throw createOutOfRangeError("targetStart", ">= 0", targetStart);
  if (sourceStart < 0) throw createOutOfRangeError("sourceStart", ">= 0", sourceStart);
  if (sourceEnd < 0) throw createOutOfRangeError("sourceEnd", ">= 0", sourceEnd);
  if (sourceStart > this.length) throw createOutOfRangeError("sourceStart", ">= 0 && <= " + this.length, sourceStart);
  if (sourceEnd > this.length) sourceEnd = this.length;
  if (sourceEnd <= sourceStart || targetStart >= targetBytes.length) return 0;

  var length = Math.min(sourceEnd - sourceStart, targetBytes.length - targetStart);
  if (this.buffer === targetBytes.buffer &&
      sourceStart < targetStart &&
      targetStart < sourceStart + length) {
    for (var i = length - 1; i >= 0; i--) {
      targetBytes[targetStart + i] = this[sourceStart + i];
    }
    return length;
  }
  for (var i = 0; i < length; i++) {
    targetBytes[targetStart + i] = this[sourceStart + i];
  }
  return length;
};

function encodeUtf16beString(value) {
  var bytes = encodeString(value, "utf16le");
  for (var i = 0; i + 1 < bytes.length; i += 2) {
    var lo = bytes[i];
    bytes[i] = bytes[i + 1];
    bytes[i + 1] = lo;
  }
  return bytes;
}

function clampEncodedWriteLength(bytes, limit, encoding) {
  var safeLimit = Math.min(bytes.length, limit);
  if (safeLimit <= 0) {
    return 0;
  }
  var enc = coerceEncoding(encoding || "utf8");
  if (enc === "utf16le" || enc === "ucs2" || enc === "ucs-2" || enc === "utf-16le" || enc === "utf16be") {
    return safeLimit - (safeLimit % 2);
  }
  if (enc !== "utf8") {
    return safeLimit;
  }
  var completeLength = 0;
  while (completeLength < safeLimit) {
    var byte = bytes[completeLength];
    var sequenceLength = 1;
    if ((byte & 0x80) === 0) {
      sequenceLength = 1;
    } else if ((byte & 0xe0) === 0xc0) {
      sequenceLength = 2;
    } else if ((byte & 0xf0) === 0xe0) {
      sequenceLength = 3;
    } else if ((byte & 0xf8) === 0xf0) {
      sequenceLength = 4;
    }
    if (completeLength + sequenceLength > safeLimit) {
      break;
    }
    completeLength += sequenceLength;
  }
  return completeLength;
}

function writeEncodedValue(targetValue, value, offset, length, encoding) {
  var target = getWritableByteView(targetValue);
  if (!target) {
    var thisErr = new TypeError(
      'The "this" argument must be an instance of Buffer or Uint8Array. Received ' + formatReceivedValue(targetValue)
    );
    thisErr.code = "ERR_INVALID_ARG_TYPE";
    throw thisErr;
  }

  var offsetNumber = offset === undefined ? 0 : Number(offset);
  var offsetWasNaN = offset !== undefined && offsetNumber !== offsetNumber;
  if (offsetWasNaN) offsetNumber = 0;
  if (!isFiniteNumber(offsetNumber)) {
    offsetNumber = offsetNumber < 0 ? 0 : target.length;
  } else {
    offsetNumber = normalizeInteger(offsetNumber);
  }
  if (offsetNumber < 0 || offsetNumber > target.length) {
    throw makeBufferBoundsError("offset");
  }

  var remaining = target.length - offsetNumber;
  var lengthNumber;
  if (length === undefined) {
    lengthNumber = remaining;
  } else {
    lengthNumber = Number(length);
    if (lengthNumber !== lengthNumber) {
      lengthNumber = remaining;
    } else if (!isFiniteNumber(lengthNumber)) {
      lengthNumber = lengthNumber < 0 ? 0 : remaining;
    } else {
      lengthNumber = normalizeInteger(lengthNumber);
      if (lengthNumber < 0) lengthNumber = 0;
    }
    if (lengthNumber > remaining) {
      if (offsetWasNaN) {
        lengthNumber = remaining;
      } else {
        throw makeBufferBoundsError("length");
      }
    }
  }

  var bytes = encoding === "utf16be"
    ? encodeUtf16beString(value)
    : encodeString(value, encoding);
  var bytesToWrite = clampEncodedWriteLength(bytes, lengthNumber, encoding);
  for (var i = 0; i < bytesToWrite; i++) {
    target[offsetNumber + i] = bytes[i];
  }
  return bytesToWrite;
}

BufferProto.utf8Write = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "utf8");
};

BufferProto.utf16leWrite = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "utf16le");
};

BufferProto.ucs2Write = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "ucs2");
};

BufferProto.utf16beWrite = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "utf16be");
};

BufferProto.latin1Write = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "latin1");
};

BufferProto.asciiWrite = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "ascii");
};

BufferProto.base64Write = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "base64");
};

BufferProto.base64urlWrite = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "base64url");
};

BufferProto.hexWrite = function(value, offset, length) {
  return writeEncodedValue(this, value, offset, length, "hex");
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

  var _validEncodings = { 'utf8': 1, 'utf-8': 1, 'ascii': 1, 'latin1': 1, 'binary': 1, 'hex': 1, 'base64': 1, 'base64url': 1, 'ucs2': 1, 'ucs-2': 1, 'utf16le': 1, 'utf-16le': 1 };
  var _enc = (encoding || 'utf8').toLowerCase();
  if (!_validEncodings[_enc]) {
    throw new TypeError('Unknown encoding: ' + encoding);
  }

  var bytes = encodeString(String(value), _enc);
  if (length == null || length > bytes.length) length = bytes.length;
  if (length > this.length - offset) length = this.length - offset;
  length = clampEncodedWriteLength(bytes, length, _enc);
  for (var i = 0; i < length && (offset + i) < this.length; i++) {
    this[offset + i] = bytes[i];
  }
  return Math.min(length, this.length - offset);
};

BufferProto.compare = function(target, targetStart, targetEnd, sourceStart, sourceEnd) {
  if (!isUint8Array(target)) {
    var compareErr = new TypeError(
      'The "target" argument must be an instance of Buffer or Uint8Array. Received ' +
      formatReceivedValueWithQuotedString(target)
    );
    compareErr.code = "ERR_INVALID_ARG_TYPE";
    throw compareErr;
  }
  targetStart = normalizeCompareIndex(targetStart, "targetStart", 0);
  targetEnd = normalizeCompareIndex(targetEnd, "targetEnd", target.length);
  sourceStart = normalizeCompareIndex(sourceStart, "sourceStart", 0);
  sourceEnd = normalizeCompareIndex(sourceEnd, "sourceEnd", this.length);

  if (targetStart < 0) throw createOutOfRangeError("targetStart", ">= 0", targetStart);
  if (targetEnd < 0) throw createOutOfRangeError("targetEnd", ">= 0", targetEnd);
  if (sourceStart < 0) throw createOutOfRangeError("sourceStart", ">= 0", sourceStart);
  if (sourceEnd < 0) throw createOutOfRangeError("sourceEnd", ">= 0", sourceEnd);
  if (targetEnd > target.length) throw createOutOfRangeError("targetEnd", ">= 0 && <= " + target.length, targetEnd);
  if (sourceEnd > this.length) throw createOutOfRangeError("sourceEnd", ">= 0 && <= " + this.length, sourceEnd);

  if (sourceStart >= sourceEnd) return targetStart >= targetEnd ? 0 : -1;
  if (targetStart >= targetEnd) return 1;

  return compareBytes(this, target, sourceStart, sourceEnd, targetStart, targetEnd);
};

// Read unsigned integers
BufferProto.readUInt8 = function(offset) {
  offset = validateOffset(offset, 1, this.length);
  return this[offset];
};
BufferProto.readUInt16LE = function(offset) {
  offset = validateOffset(offset, 2, this.length);
  return this[offset] | (this[offset + 1] << 8);
};
BufferProto.readUInt16BE = function(offset) {
  offset = validateOffset(offset, 2, this.length);
  return (this[offset] << 8) | this[offset + 1];
};
BufferProto.readUInt32LE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return (this[offset] | (this[offset + 1] << 8) | (this[offset + 2] << 16) | (this[offset + 3] << 24)) >>> 0;
};
BufferProto.readUInt32BE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return (this[offset] * 0x1000000 + (this[offset + 1] << 16) + (this[offset + 2] << 8) + this[offset + 3]) >>> 0;
};
BufferProto.readUIntLE = function(offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  offset = validateOffset(offset, byteLength, this.length);
  var value = 0;
  for (var i = 0; i < byteLength; i++) {
    value += this[offset + i] * Math.pow(2, 8 * i);
  }
  return value;
};
BufferProto.readUIntBE = function(offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  offset = validateOffset(offset, byteLength, this.length);
  var value = 0;
  for (var i = 0; i < byteLength; i++) {
    value = (value * 0x100) + this[offset + i];
  }
  return value;
};

// Read signed integers
BufferProto.readInt8 = function(offset) {
  offset = validateOffset(offset, 1, this.length);
  var v = this[offset];
  return v > 127 ? v - 256 : v;
};
BufferProto.readInt16LE = function(offset) {
  var v = this.readUInt16LE(offset);
  return v > 0x7fff ? v - 0x10000 : v;
};
BufferProto.readInt16BE = function(offset) {
  var v = this.readUInt16BE(offset);
  return v > 0x7fff ? v - 0x10000 : v;
};
BufferProto.readInt32LE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return this[offset] | (this[offset + 1] << 8) | (this[offset + 2] << 16) | (this[offset + 3] << 24);
};
BufferProto.readInt32BE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return (this[offset] << 24) | (this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3];
};
BufferProto.readIntLE = function(offset, byteLength) {
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  var value = this.readUIntLE(offset, byteLength);
  var limit = Math.pow(2, 8 * byteLength - 1);
  return value >= limit ? value - Math.pow(2, 8 * byteLength) : value;
};
BufferProto.readIntBE = function(offset, byteLength) {
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  var value = this.readUIntBE(offset, byteLength);
  var limit = Math.pow(2, 8 * byteLength - 1);
  return value >= limit ? value - Math.pow(2, 8 * byteLength) : value;
};

// Read floats/doubles via DataView
BufferProto.readFloatLE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset, true);
};
BufferProto.readFloatBE = function(offset) {
  offset = validateOffset(offset, 4, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset, false);
};
BufferProto.readDoubleLE = function(offset) {
  offset = validateOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset, true);
};
BufferProto.readDoubleBE = function(offset) {
  offset = validateOffset(offset, 8, this.length);
  return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset, false);
};
BufferProto.readBigUInt64LE = function(offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  var lo = BigInt(this.readUInt32LE(offset));
  var hi = BigInt(this.readUInt32LE(offset + 4));
  return (hi << 32n) | lo;
};
BufferProto.readBigUInt64BE = function(offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  var hi = BigInt(this.readUInt32BE(offset));
  var lo = BigInt(this.readUInt32BE(offset + 4));
  return (hi << 32n) | lo;
};
BufferProto.readBigInt64LE = function(offset) {
  var value = this.readBigUInt64LE(offset);
  return value >= (1n << 63n) ? value - (1n << 64n) : value;
};
BufferProto.readBigInt64BE = function(offset) {
  var value = this.readBigUInt64BE(offset);
  return value >= (1n << 63n) ? value - (1n << 64n) : value;
};

// Write unsigned integers
BufferProto.writeUInt8 = function(value, offset) {
  validateWriteValue(value, 0, 0xff, 8, false);
  offset = validateOffset(offset, 1, this.length);
  this[offset] = value & 0xff;
  return offset + 1;
};
BufferProto.writeUInt16LE = function(value, offset) {
  validateWriteValue(value, 0, 0xffff, 16, false);
  offset = validateOffset(offset, 2, this.length);
  this[offset] = value & 0xff;
  this[offset + 1] = (value >>> 8) & 0xff;
  return offset + 2;
};
BufferProto.writeUInt16BE = function(value, offset) {
  validateWriteValue(value, 0, 0xffff, 16, false);
  offset = validateOffset(offset, 2, this.length);
  this[offset] = (value >>> 8) & 0xff;
  this[offset + 1] = value & 0xff;
  return offset + 2;
};
BufferProto.writeUInt32LE = function(value, offset) {
  validateWriteValue(value, 0, 0xffffffff, 32, false);
  offset = validateOffset(offset, 4, this.length);
  this[offset] = value & 0xff;
  this[offset + 1] = (value >>> 8) & 0xff;
  this[offset + 2] = (value >>> 16) & 0xff;
  this[offset + 3] = (value >>> 24) & 0xff;
  return offset + 4;
};
BufferProto.writeUInt32BE = function(value, offset) {
  validateWriteValue(value, 0, 0xffffffff, 32, false);
  offset = validateOffset(offset, 4, this.length);
  this[offset] = (value >>> 24) & 0xff;
  this[offset + 1] = (value >>> 16) & 0xff;
  this[offset + 2] = (value >>> 8) & 0xff;
  this[offset + 3] = value & 0xff;
  return offset + 4;
};
BufferProto.writeUIntLE = function(value, offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  validateWriteValue(value, 0, Math.pow(2, 8 * byteLength) - 1, byteLength * 8, false);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  offset = validateOffset(offset, byteLength, this.length);
  for (var i = 0; i < byteLength; i++) {
    this[offset + i] = value & 0xff;
    value = Math.floor(value / 0x100);
  }
  return offset + byteLength;
};
BufferProto.writeUIntBE = function(value, offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  validateWriteValue(value, 0, Math.pow(2, 8 * byteLength) - 1, byteLength * 8, false);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  offset = validateOffset(offset, byteLength, this.length);
  for (var i = byteLength - 1; i >= 0; i--) {
    this[offset + i] = value & 0xff;
    value = Math.floor(value / 0x100);
  }
  return offset + byteLength;
};

// Write signed integers
BufferProto.writeInt8 = function(value, offset) {
  validateWriteValue(value, -0x80, 0x7f, 8, true);
  offset = validateOffset(offset, 1, this.length);
  this[offset] = value < 0 ? value + 0x100 : value;
  return offset + 1;
};
BufferProto.writeInt16LE = function(value, offset) {
  validateWriteValue(value, -0x8000, 0x7fff, 16, true);
  return this.writeUInt16LE(value < 0 ? value + 0x10000 : value, offset);
};
BufferProto.writeInt16BE = function(value, offset) {
  validateWriteValue(value, -0x8000, 0x7fff, 16, true);
  return this.writeUInt16BE(value < 0 ? value + 0x10000 : value, offset);
};
BufferProto.writeInt32LE = function(value, offset) {
  validateWriteValue(value, -0x80000000, 0x7fffffff, 32, true);
  return this.writeUInt32LE(value < 0 ? value + 0x100000000 : value, offset);
};
BufferProto.writeInt32BE = function(value, offset) {
  validateWriteValue(value, -0x80000000, 0x7fffffff, 32, true);
  return this.writeUInt32BE(value < 0 ? value + 0x100000000 : value, offset);
};
BufferProto.writeIntLE = function(value, offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  var min = -Math.pow(2, 8 * byteLength - 1);
  var max = Math.pow(2, 8 * byteLength - 1) - 1;
  validateWriteValue(value, min, max, byteLength * 8, true);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  if (value < 0) value += Math.pow(2, 8 * byteLength);
  return this.writeUIntLE(value, offset, byteLength);
};
BufferProto.writeIntBE = function(value, offset, byteLength) {
  byteLength = validateByteLength(byteLength);
  var min = -Math.pow(2, 8 * byteLength - 1);
  var max = Math.pow(2, 8 * byteLength - 1) - 1;
  validateWriteValue(value, min, max, byteLength * 8, true);
  if (offset === undefined) throw makeInvalidArgTypeError("offset", "of type number", offset);
  if (value < 0) value += Math.pow(2, 8 * byteLength);
  return this.writeUIntBE(value, offset, byteLength);
};

// Write floats/doubles via DataView
BufferProto.writeFloatLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, true); return offset + 4; };
BufferProto.writeFloatBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, false); return offset + 4; };
BufferProto.writeDoubleLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, true); return offset + 8; };
BufferProto.writeDoubleBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, false); return offset + 8; };
BufferProto.writeBigInt64LE = function(value, offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  validateBigIntWrite(value, true);
  var unsignedValue = value < 0n ? value + (1n << 64n) : value;
  this.writeUInt32LE(Number(unsignedValue & 0xffffffffn), offset);
  this.writeUInt32LE(Number((unsignedValue >> 32n) & 0xffffffffn), offset + 4);
  return offset + 8;
};
BufferProto.writeBigInt64BE = function(value, offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  validateBigIntWrite(value, true);
  var unsignedValue = value < 0n ? value + (1n << 64n) : value;
  this.writeUInt32BE(Number((unsignedValue >> 32n) & 0xffffffffn), offset);
  this.writeUInt32BE(Number(unsignedValue & 0xffffffffn), offset + 4);
  return offset + 8;
};
BufferProto.writeBigUInt64LE = function(value, offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  validateBigIntWrite(value, false);
  this.writeUInt32LE(Number(value & 0xffffffffn), offset);
  this.writeUInt32LE(Number((value >> 32n) & 0xffffffffn), offset + 4);
  return offset + 8;
};
BufferProto.writeBigUInt64BE = function(value, offset) {
  offset = offset || 0;
  validateOffset(offset, 8, this.length);
  validateBigIntWrite(value, false);
  this.writeUInt32BE(Number((value >> 32n) & 0xffffffffn), offset);
  this.writeUInt32BE(Number(value & 0xffffffffn), offset + 4);
  return offset + 8;
};

// Swap byte order
BufferProto.swap16 = function() {
  if (this.length % 2 !== 0) throw new RangeError("Buffer size must be a multiple of 16-bits");
  for (var i = 0; i < this.length; i += 2) { var a = this[i]; this[i] = this[i + 1]; this[i + 1] = a; }
  return this;
};
BufferProto.swap32 = function() {
  if (this.length % 4 !== 0) throw new RangeError("Buffer size must be a multiple of 32-bits");
  for (var i = 0; i < this.length; i += 4) { var a = this[i]; var b = this[i + 1]; this[i] = this[i + 3]; this[i + 1] = this[i + 2]; this[i + 2] = b; this[i + 3] = a; }
  return this;
};
BufferProto.swap64 = function() {
  if (this.length % 8 !== 0) throw new RangeError("Buffer size must be a multiple of 64-bits");
  for (var i = 0; i < this.length; i += 8) {
    var a = this[i]; var b = this[i + 1]; var c = this[i + 2]; var d = this[i + 3];
    this[i] = this[i + 7]; this[i + 1] = this[i + 6]; this[i + 2] = this[i + 5]; this[i + 3] = this[i + 4];
    this[i + 4] = d; this[i + 5] = c; this[i + 6] = b; this[i + 7] = a;
  }
  return this;
};

// Node.js aliases (readUintXX = readUIntXX)
BufferProto.readUint8 = BufferProto.readUInt8;
BufferProto.readUint16LE = BufferProto.readUInt16LE;
BufferProto.readUint16BE = BufferProto.readUInt16BE;
BufferProto.readUint32LE = BufferProto.readUInt32LE;
BufferProto.readUint32BE = BufferProto.readUInt32BE;
BufferProto.readUintLE = BufferProto.readUIntLE;
BufferProto.readUintBE = BufferProto.readUIntBE;
BufferProto.readBigUint64LE = BufferProto.readBigUInt64LE;
BufferProto.readBigUint64BE = BufferProto.readBigUInt64BE;
BufferProto.writeUint8 = BufferProto.writeUInt8;
BufferProto.writeUint16LE = BufferProto.writeUInt16LE;
BufferProto.writeUint16BE = BufferProto.writeUInt16BE;
BufferProto.writeUint32LE = BufferProto.writeUInt32LE;
BufferProto.writeUint32BE = BufferProto.writeUInt32BE;
BufferProto.writeUintLE = BufferProto.writeUIntLE;
BufferProto.writeUintBE = BufferProto.writeUIntBE;
BufferProto.writeBigUint64LE = BufferProto.writeBigUInt64LE;
BufferProto.writeBigUint64BE = BufferProto.writeBigUInt64BE;

BufferProto.fill = function(value, start, end, encoding) {
  var bufferLength = getViewLength(this);
  if (bufferLength === null) {
    throw makeInvalidArgTypeError("this", "an instance of Buffer or Uint8Array", this);
  }
  if (typeof start === "string") {
    encoding = start;
    start = 0;
    end = bufferLength;
  } else if (typeof end === "string") {
    encoding = end;
    end = bufferLength;
  } else if (end === undefined) {
    end = bufferLength;
  }
  if (encoding !== undefined && encoding !== null && typeof encoding !== "string") {
    throw makeInvalidArgTypeError("encoding", "of type string", encoding);
  }
  start = normalizeFillIndex(start, "start", 0, bufferLength);
  end = normalizeFillIndex(end, "end", bufferLength, bufferLength);
  var fillBytes = getAllocFillBytes(value, encoding);
  if (end <= start) {
    return this;
  }
  fillRangeWithBytes(this, fillBytes, start, end);
  return this;
};

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
Object.defineProperty(Buffer.prototype, "parent", {
  get: function() {
    if (!this || typeof this !== "object" || !ArrayBuffer.isView(this)) return undefined;
    return this.buffer;
  },
  enumerable: false,
  configurable: true
});
Object.defineProperty(Buffer.prototype, "offset", {
  get: function() {
    if (!this || typeof this !== "object" || !ArrayBuffer.isView(this)) return undefined;
    return this.byteOffset;
  },
  enumerable: false,
  configurable: true
});
Buffer.prototype.__isExactBuffer = true;
Buffer._protoReady = true;

var kMaxLength = 4294967296; // 2^32
var kStringMaxLength = 2147483647; // 2^31 - 1
var INSPECT_MAX_BYTES = 50;

var constants = {
  MAX_LENGTH: kMaxLength,
  MAX_STRING_LENGTH: kStringMaxLength,
};

var exported = {
  Buffer: Buffer,
  atob: typeof atob === "function" ? atob : undefined,
  btoa: typeof btoa === "function" ? btoa : undefined,
  SlowBuffer: Buffer,
  Blob: typeof Blob === "undefined" ? undefined : Blob,
  File: typeof File === "undefined" ? undefined : File,
  isAscii: isAsciiBytes,
  isUtf8: isUtf8Bytes,
  kMaxLength: kMaxLength,
  INSPECT_MAX_BYTES: INSPECT_MAX_BYTES,
  constants: constants,
};
exported.default = exported;
Object.defineProperty(exported, "INSPECT_MAX_BYTES", {
  get: function() {
    return INSPECT_MAX_BYTES;
  },
  set: function(value) {
    if (typeof value !== "number") {
      throw makeInvalidArgTypeError("value", "of type number", value);
    }
    if (value !== value || value < 0) {
      throw createOutOfRangeError("value", ">= 0", value);
    }
    INSPECT_MAX_BYTES = value;
  },
  enumerable: true,
  configurable: true
});

module.exports = exported;
