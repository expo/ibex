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

var utf8DecoderSupportsStream = false;
if (typeof TextDecoder === 'function') {
  try {
    var _probeUtf8Decoder = new TextDecoder('utf-8');
    _probeUtf8Decoder.decode(new Uint8Array(), { stream: true });
    utf8DecoderSupportsStream = true;
  } catch (err) {
    utf8DecoderSupportsStream = false;
  }
}

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

  var result = '';
  var i = 0;
  if (this._bufLen > 0) {
    var need = this._needBytes - this._bufLen;
    if (bytes.length < need) {
      var newBuf = new Uint8Array(this._bufLen + bytes.length);
      for (var j = 0; j < this._bufLen; j++) newBuf[j] = this._buf[j];
      for (var j = 0; j < bytes.length; j++) newBuf[this._bufLen + j] = bytes[j];
      this._buf = newBuf;
      this._bufLen = newBuf.length;
      return '';
    }
    var charBytes = new Uint8Array(this._needBytes);
    for (var j = 0; j < this._bufLen; j++) charBytes[j] = this._buf[j];
    for (var j = 0; j < need; j++) charBytes[this._bufLen + j] = bytes[j];
    var valid = true;
    for (var j = 1; j < this._needBytes; j++) {
      if ((charBytes[j] & 0xC0) !== 0x80) { valid = false; break; }
    }
    if (valid) {
      if (typeof TextDecoder !== 'undefined') {
        result += new TextDecoder('utf-8').decode(charBytes);
      } else {
        result += decodeUtf8Char(charBytes, this._needBytes);
      }
    } else {
      result += '\uFFFD';
    }
    i = need;
    this._buf = null;
    this._bufLen = 0;
    this._needBytes = 0;
  }
  while (i < bytes.length) {
    var b = bytes[i];
    var seqLen = utf8ByteLength(b);
    if (i + seqLen <= bytes.length) {
      if (seqLen === 1) {
        if (b >= 0x80) {
          result += '\uFFFD';
        } else {
          result += String.fromCharCode(b);
        }
        i += 1;
      } else {
        var valid = true;
        for (var j = 1; j < seqLen; j++) {
          if ((bytes[i + j] & 0xC0) !== 0x80) { valid = false; break; }
        }
        if (valid) {
          if (typeof TextDecoder !== 'undefined') {
            result += new TextDecoder('utf-8').decode(bytes.slice(i, i + seqLen));
          } else {
            result += decodeUtf8Char(bytes.slice(i, i + seqLen), seqLen);
          }
          i += seqLen;
        } else {
          result += '\uFFFD';
          i += 1;
        }
      }
    } else {
      var remaining = bytes.length - i;
      this._buf = new Uint8Array(remaining);
      for (var j = 0; j < remaining; j++) this._buf[j] = bytes[i + j];
      this._bufLen = remaining;
      this._needBytes = seqLen;
      break;
    }
  }
  return result;
};

StringDecoder.prototype.end = function end(buf) {
  var result = '';
  if (buf && (typeof buf === 'string' || (typeof buf === 'object' && buf.length > 0))) {
    result = this.write(buf);
  }
  var enc = this.encoding;
  if (enc === 'utf8' && this._utf8Decoder) {
    result += this._utf8Decoder.decode(new Uint8Array(), { stream: false });
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
  if (this._bufLen > 0) {
    this._buf = null;
    this._bufLen = 0;
    this._needBytes = 0;
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
