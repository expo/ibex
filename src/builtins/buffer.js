var BufferProto = {};

function coerceEncoding(encoding) {
  if (!encoding) return "utf8";
  var normalized = String(encoding).toLowerCase().replace("-", "");
  if (normalized === "utf8") return "utf8";
  if (normalized === "utf-8") return "utf8";
  return normalized;
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
      var pad = b64str.length % 4;
      if (pad === 2) b64str += "==";
      else if (pad === 3) b64str += "=";
    }
    if (typeof atob === "function") {
      var raw = atob(b64str);
      var b = new Uint8Array(raw.length);
      for (var j = 0; j < raw.length; j++) b[j] = raw.charCodeAt(j);
      return b;
    }
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

function toByteArray(value, encoding) {
  if (typeof value === "number") {
    if (value < 0 || value > 0xffffffff || value % 1 !== 0) {
      throw new TypeError("Invalid Buffer size");
    }
    return new Uint8Array(value);
  }
  if (value == null) {
    throw new TypeError("Cannot convert null to Buffer");
  }
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (typeof value === "string") {
    return encodeString(value, encoding);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (value && typeof value === "object" && value.type === "Buffer" && Array.isArray(value.data)) {
    return new Uint8Array(value.data);
  }
  if (typeof value === "object" && value !== null && typeof value.valueOf === "function") {
    var unboxed = value.valueOf();
    if (unboxed !== value) {
      return toByteArray(unboxed, encoding);
    }
  }
  throw new TypeError("Unsupported value type for Buffer");
}

function Buffer(value, encoding) {
  return Buffer.from(value, encoding);
}

function makeBuffer(bytes) {
  var buffer = new Uint8Array(bytes);
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

Buffer.from = function(value, encoding) {
  if (value && value.__isExactBuffer) {
    return makeBuffer(new Uint8Array(value));
  }
  return makeBuffer(toByteArray(value, encoding));
};

Buffer.alloc = function(size, fill, encoding) {
  var bytes = new Uint8Array(size || 0);
  if (fill === undefined || fill === null) {
    return makeBuffer(bytes);
  }
  var fillValue;
  if (typeof fill === "string") {
    fillValue = encodeString(fill, encoding || "utf8")[0];
  } else if (typeof fill === "number") {
    fillValue = fill & 0xff;
  } else if (fill === true) {
    fillValue = 1;
  } else if (fill === false || fill === 0) {
    fillValue = 0;
  } else if (fill.__isExactBuffer) {
    fill = fill[0] || 0;
    fillValue = fill;
  } else {
    fillValue = 0;
  }
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = fillValue;
  }
  return makeBuffer(bytes);
};

Buffer.allocUnsafe = Buffer.alloc;

Buffer.byteLength = function(string, encoding) {
  return encodeString(String(string), encoding || "utf8").length;
};

Buffer.compare = function(a, b) {
  if (!(a && a.__isExactBuffer) || !(b && b.__isExactBuffer)) {
    throw new TypeError("Arguments must be Buffers");
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
  if (!Array.isArray(list)) throw new TypeError("list argument must be an Array of Buffers");
  if (list.length === 0) return Buffer.alloc(0);
  if (list.length === 1) return list[0];
  var total = totalLength;
  if (total === undefined) {
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
  return typeof encoding === "string" &&
    ["utf8", "utf-8", "ascii", "latin1", "binary", "hex", "base64", "base64url", "ucs2", "ucs-2", "utf16le", "utf-16le"]
    .indexOf(encoding.toLowerCase()) !== -1;
};

BufferProto.toString = function(encoding, start, end) {
  return decodeBytes(this, encoding, start, end);
};

BufferProto.equals = function(other) {
  if (!other || !other.__isExactBuffer) return false;
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
  return makeBuffer(Uint8Array.prototype.slice.call(this, start, end));
};

BufferProto.subarray = function(start, end) {
  return makeBuffer(Uint8Array.prototype.slice.call(this, start, end));
};

BufferProto.copy = function(target, targetStart, sourceStart, sourceEnd) {
  targetStart = targetStart || 0;
  sourceStart = sourceStart || 0;
  sourceEnd = sourceEnd == null ? this.length : sourceEnd;
  var length = Math.max(0, Math.min(this.length, sourceEnd) - sourceStart);
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

  var bytes = encodeString(String(value), encoding || "utf8");
  if (offset == null) offset = 0;
  if (length == null || length > bytes.length) length = bytes.length;
  for (var i = 0; i < length && (offset + i) < this.length; i++) {
    this[offset + i] = bytes[i];
  }
  return Math.min(length, this.length - offset);
};

BufferProto.compare = function(target, targetStart, targetEnd, sourceStart, sourceEnd) {
  if (!target || !target.__isExactBuffer) throw new TypeError("Argument must be a Buffer");
  sourceStart = sourceStart || 0;
  sourceEnd = sourceEnd == null ? this.length : sourceEnd;
  targetStart = targetStart || 0;
  targetEnd = targetEnd == null ? target.length : targetEnd;
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

// Read unsigned integers
BufferProto.readUInt8 = function(offset) { return this[offset || 0]; };
BufferProto.readUInt16LE = function(offset) { offset = offset || 0; return this[offset] | (this[offset+1] << 8); };
BufferProto.readUInt16BE = function(offset) { offset = offset || 0; return (this[offset] << 8) | this[offset+1]; };
BufferProto.readUInt32LE = function(offset) { offset = offset || 0; return (this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24)) >>> 0; };
BufferProto.readUInt32BE = function(offset) { offset = offset || 0; return (this[offset] * 0x1000000 + (this[offset+1] << 16) + (this[offset+2] << 8) + this[offset+3]) >>> 0; };

// Read signed integers
BufferProto.readInt8 = function(offset) { var v = this[offset || 0]; return v > 127 ? v - 256 : v; };
BufferProto.readInt16LE = function(offset) { var v = this.readUInt16LE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt16BE = function(offset) { var v = this.readUInt16BE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt32LE = function(offset) { offset = offset || 0; return this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24); };
BufferProto.readInt32BE = function(offset) { offset = offset || 0; return (this[offset] << 24) | (this[offset+1] << 16) | (this[offset+2] << 8) | this[offset+3]; };

// Read floats/doubles via DataView
BufferProto.readFloatLE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset || 0, true); };
BufferProto.readFloatBE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset || 0, false); };
BufferProto.readDoubleLE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset || 0, true); };
BufferProto.readDoubleBE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset || 0, false); };

// Write unsigned integers
BufferProto.writeUInt8 = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; return offset + 1; };
BufferProto.writeUInt16LE = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; return offset + 2; };
BufferProto.writeUInt16BE = function(value, offset) { offset = offset || 0; this[offset] = (value >>> 8) & 0xff; this[offset+1] = value & 0xff; return offset + 2; };
BufferProto.writeUInt32LE = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; this[offset+2] = (value >>> 16) & 0xff; this[offset+3] = (value >>> 24) & 0xff; return offset + 4; };
BufferProto.writeUInt32BE = function(value, offset) { offset = offset || 0; this[offset] = (value >>> 24) & 0xff; this[offset+1] = (value >>> 16) & 0xff; this[offset+2] = (value >>> 8) & 0xff; this[offset+3] = value & 0xff; return offset + 4; };

// Write signed integers
BufferProto.writeInt8 = function(value, offset) { offset = offset || 0; this[offset] = value < 0 ? value + 256 : value; return offset + 1; };
BufferProto.writeInt16LE = function(value, offset) { return this.writeUInt16LE(value < 0 ? value + 0x10000 : value, offset); };
BufferProto.writeInt16BE = function(value, offset) { return this.writeUInt16BE(value < 0 ? value + 0x10000 : value, offset); };
BufferProto.writeInt32LE = function(value, offset) { return this.writeUInt32LE(value < 0 ? value + 0x100000000 : value, offset); };
BufferProto.writeInt32BE = function(value, offset) { return this.writeUInt32BE(value < 0 ? value + 0x100000000 : value, offset); };

// Write floats/doubles via DataView
BufferProto.writeFloatLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, true); return offset + 4; };
BufferProto.writeFloatBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, false); return offset + 4; };
BufferProto.writeDoubleLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, true); return offset + 8; };
BufferProto.writeDoubleBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, false); return offset + 8; };

// Swap byte order
BufferProto.swap16 = function() {
  for (var i = 0; i < this.length; i += 2) { var a = this[i]; this[i] = this[i+1]; this[i+1] = a; }
  return this;
};
BufferProto.swap32 = function() {
  for (var i = 0; i < this.length; i += 4) { var a = this[i]; var b = this[i+1]; this[i] = this[i+3]; this[i+1] = this[i+2]; this[i+2] = b; this[i+3] = a; }
  return this;
};
BufferProto.swap64 = function() {
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
BufferProto.writeUint8 = BufferProto.writeUInt8;
BufferProto.writeUint16LE = BufferProto.writeUInt16LE;
BufferProto.writeUint16BE = BufferProto.writeUInt16BE;
BufferProto.writeUint32LE = BufferProto.writeUInt32LE;
BufferProto.writeUint32BE = BufferProto.writeUInt32BE;

BufferProto.fill = function(value, start, end) {
  start = start == null ? 0 : start;
  end = end == null ? this.length : end;
  var fill = typeof value === "string" ? encodeString(value, "utf8")[0] : value;
  for (var i = start; i < end && i < this.length; i++) {
    this[i] = fill & 0xff;
  }
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
Buffer.prototype.__isExactBuffer = true;
Buffer._protoReady = true;

module.exports = {
  Buffer: Buffer,
  atob: typeof atob === "function" ? atob : undefined,
  btoa: typeof btoa === "function" ? btoa : undefined,
  SlowBuffer: Buffer,
  Blob: typeof Blob === "undefined" ? undefined : Blob,
};
