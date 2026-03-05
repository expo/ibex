function normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var lowered = String(enc).toLowerCase().replace(/[-_]/g, '');
  if (lowered === 'utf8') return 'utf8';
  if (lowered === 'ascii') return 'ascii';
  if (lowered === 'latin1' || lowered === 'binary') return 'latin1';
  if (lowered === 'base64') return 'base64';
  if (lowered === 'base64url') return 'base64url';
  if (lowered === 'hex') return 'hex';
  if (lowered === 'utf16le' || lowered === 'ucs2') return 'utf16le';
  throw new TypeError('Unknown encoding: ' + enc);
}

function utf8ByteLength(leadByte) {
  if (leadByte < 0x80) return 1;
  if ((leadByte & 0xE0) === 0xC0) return 2;
  if ((leadByte & 0xF0) === 0xE0) return 3;
  if ((leadByte & 0xF8) === 0xF0) return 4;
  return 1;
}

// UTF-8 decoder following WHATWG "maximal subpart" replacement rule.
// Must produce identical output to the _decodeUtf8 in buffer.js.
function _decodeUtf8Complete(bytes) {
  var result = '';
  var i = 0;
  var len = bytes.length;
  while (i < len) {
    var b = bytes[i];
    if (b < 0x80) {
      result += String.fromCharCode(b);
      i++;
      continue;
    }
    var seqLen, minCp;
    if ((b & 0xE0) === 0xC0)      { seqLen = 2; minCp = 0x80; }
    else if ((b & 0xF0) === 0xE0)  { seqLen = 3; minCp = 0x800; }
    else if ((b & 0xF8) === 0xF0)  { seqLen = 4; minCp = 0x10000; }
    else {
      result += '\uFFFD';
      i++;
      continue;
    }
    var got = 1;
    for (var j = 1; j < seqLen && i + j < len; j++) {
      if ((bytes[i + j] & 0xC0) !== 0x80) break;
      got++;
    }
    if (got < seqLen) {
      result += '\uFFFD';
      i += got;
      continue;
    }
    var cp;
    if (seqLen === 2) {
      cp = ((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F);
    } else if (seqLen === 3) {
      cp = ((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F);
    } else {
      cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
    }
    if (cp < minCp || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) {
      result += '\uFFFD';
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

function decodeUtf8Char(bytes, len) {
  var cp;
  if (len === 2) {
    cp = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
  } else if (len === 3) {
    cp = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
  } else if (len === 4) {
    cp = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) | ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
  } else {
    return String.fromCharCode(bytes[0]);
  }
  if (cp > 0xFFFF) {
    cp -= 0x10000;
    return String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
  }
  return String.fromCharCode(cp);
}

// Disable TextDecoder streaming mode; we use non-streaming TextDecoder for each
// complete chunk to match Buffer.toString('utf8') replacement behavior exactly.
var utf8DecoderSupportsStream = false;

function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  this._buf = null;
  this._bufLen = 0;
  this._needBytes = 0;
  this._utf8Decoder = (this.encoding === 'utf8' && utf8DecoderSupportsStream)
    ? new TextDecoder('utf-8')
    : null;
}

StringDecoder.prototype.write = function write(buf) {
  if (!buf || (typeof buf === 'object' && buf.length === 0)) return '';
  var bytes;
  if (buf instanceof Uint8Array) {
    bytes = buf;
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    bytes = new Uint8Array(buf.buffer || buf, buf.byteOffset || 0, buf.length);
  } else if (typeof buf === 'string') {
    return buf;
  } else {
    bytes = new Uint8Array(buf);
  }
  if (bytes.length === 0) return '';
  var enc = this.encoding;
  if (enc === 'ascii') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i] & 0x7F);
    return result;
  }
  if (enc === 'latin1') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'hex') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      if (h.length === 1) h = '0' + h;
      result += h;
    }
    return result;
  }
  if (enc === 'base64' || enc === 'base64url') {
    var input;
    if (this._bufLen > 0) {
      input = new Uint8Array(this._bufLen + bytes.length);
      for (var i = 0; i < this._bufLen; i++) input[i] = this._buf[i];
      for (var i = 0; i < bytes.length; i++) input[this._bufLen + i] = bytes[i];
    } else {
      input = bytes;
    }
    var remainder = input.length % 3;
    var encodeLen = input.length - remainder;
    if (remainder > 0) {
      this._buf = new Uint8Array(remainder);
      for (var i = 0; i < remainder; i++) this._buf[i] = input[encodeLen + i];
      this._bufLen = remainder;
    } else {
      this._buf = null;
      this._bufLen = 0;
    }
    if (encodeLen === 0) return '';
    var toEncode = (encodeLen === input.length) ? input : input.slice(0, encodeLen);
    var binary = '';
    for (var i = 0; i < toEncode.length; i++) binary += String.fromCharCode(toEncode[i]);
    var b64 = typeof btoa === 'function' ? btoa(binary) : '';
    if (enc === 'base64url') {
      return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    return b64;
  }
  if (enc === 'utf16le') {
    var input;
    if (this._bufLen > 0) {
      input = new Uint8Array(this._bufLen + bytes.length);
      for (var i = 0; i < this._bufLen; i++) input[i] = this._buf[i];
      for (var i = 0; i < bytes.length; i++) input[this._bufLen + i] = bytes[i];
    } else {
      input = bytes;
    }
    var remainder = input.length % 2;
    var decodeLen = input.length - remainder;
    if (remainder > 0) {
      this._buf = new Uint8Array(1);
      this._buf[0] = input[decodeLen];
      this._bufLen = 1;
    } else {
      this._buf = null;
      this._bufLen = 0;
    }
    var result = '';
    for (var i = 0; i < decodeLen; i += 2) {
      result += String.fromCharCode(input[i] | (input[i + 1] << 8));
    }
    return result;
  }
  return this._writeUtf8(bytes);
};

StringDecoder.prototype._writeUtf8 = function _writeUtf8(bytes) {
  if (this._utf8Decoder) {
    return this._utf8Decoder.decode(bytes, { stream: true });
  }

  // Strategy: combine any buffered bytes with new bytes, find where to split
  // off incomplete trailing multi-byte sequences, then decode the complete
  // portion with TextDecoder (non-streaming) to match Buffer.toString('utf8').
  var input;
  if (this._bufLen > 0) {
    input = new Uint8Array(this._bufLen + bytes.length);
    for (var j = 0; j < this._bufLen; j++) input[j] = this._buf[j];
    for (var j = 0; j < bytes.length; j++) input[this._bufLen + j] = bytes[j];
    this._buf = null;
    this._bufLen = 0;
    this._needBytes = 0;
  } else {
    input = bytes;
  }

  if (input.length === 0) return '';

  // Scan backwards from end to find any incomplete multi-byte sequence
  var trailStart = input.length;
  // Check if the last few bytes form an incomplete UTF-8 sequence
  // We need to look back at most 3 bytes (max incomplete = 3 bytes of a 4-byte seq)
  for (var back = 1; back <= 3 && back <= input.length; back++) {
    var idx = input.length - back;
    var b = input[idx];
    if (b < 0x80) {
      // ASCII - no incomplete sequence
      break;
    }
    if ((b & 0xC0) === 0x80) {
      // Continuation byte - keep scanning back
      continue;
    }
    // Lead byte found
    var seqLen = utf8ByteLength(b);
    if (idx + seqLen > input.length) {
      // Incomplete sequence
      trailStart = idx;
    }
    break;
  }

  // Buffer any trailing incomplete bytes
  if (trailStart < input.length) {
    var remaining = input.length - trailStart;
    this._buf = new Uint8Array(remaining);
    for (var j = 0; j < remaining; j++) this._buf[j] = input[trailStart + j];
    this._bufLen = remaining;
    this._needBytes = utf8ByteLength(input[trailStart]);
  }

  // Decode the complete portion using maximal-subpart replacement algorithm
  // (same as Buffer.toString('utf8') uses).
  if (trailStart === 0) return '';
  var toDecode = (trailStart === input.length) ? input : input.slice(0, trailStart);
  return _decodeUtf8Complete(toDecode);
};

StringDecoder.prototype.end = function end(buf) {
  var result = '';
  if (buf && (typeof buf === 'string' || (typeof buf === 'object' && buf.length > 0))) {
    result = this.write(buf);
  }
  var enc = this.encoding;
  if (enc === 'utf8' && this._utf8Decoder) {
    // Check if the streaming decoder has buffered incomplete bytes by attempting
    // a non-streaming flush. If it produces anything (replacement chars), emit
    // a single U+FFFD instead, matching Node.js "maximal subpart" behavior.
    var flushed = this._utf8Decoder.decode(new Uint8Array(), { stream: false });
    if (flushed.length > 0) {
      result += '\uFFFD';
    }
    this._utf8Decoder = null;
  } else if (this._bufLen > 0) {
    if (enc === 'utf8') {
      result += '\uFFFD';
    } else if (enc === 'utf16le') {
      // Lone trailing byte is discarded in Node.js utf16le StringDecoder
    } else if (enc === 'base64' || enc === 'base64url') {
      var binary = '';
      for (var i = 0; i < this._bufLen; i++) binary += String.fromCharCode(this._buf[i]);
      var b64 = typeof btoa === 'function' ? btoa(binary) : '';
      if (enc === 'base64url') {
        b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      }
      result += b64;
    }
  }
  // Always reset state after end() so next write() starts fresh
  this._buf = null;
  this._bufLen = 0;
  this._needBytes = 0;
  // Recreate the streaming TextDecoder so the decoder is reusable after end()
  if (this.encoding === 'utf8' && utf8DecoderSupportsStream && !this._utf8Decoder) {
    this._utf8Decoder = new TextDecoder('utf-8');
  }
  return result;
};

StringDecoder.prototype.text = function text(buf, i) {
  return this.write(buf);
};

StringDecoder.prototype[Symbol.toPrimitive] = function() {
  return 'StringDecoder';
};

StringDecoder.prototype.toString = function() {
  return '[object StringDecoder]';
};

module.exports = StringDecoder;
module.exports.StringDecoder = StringDecoder;
