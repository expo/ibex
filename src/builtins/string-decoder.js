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

function toDecoderBuffer(buf) {
  if (typeof buf === 'string') return buf;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    return buf;
  }
  if (typeof Buffer !== 'undefined' && Buffer.from) {
    if (typeof ArrayBuffer !== 'undefined' && buf instanceof ArrayBuffer) {
      return Buffer.from(new Uint8Array(buf));
    }
    if (typeof ArrayBuffer !== 'undefined' &&
        ArrayBuffer.isView &&
        ArrayBuffer.isView(buf)) {
      return Buffer.from(buf.buffer, buf.byteOffset || 0, buf.byteLength || buf.length || 0);
    }
    return Buffer.from(buf);
  }
  return buf;
}

function bufferToEncoding(buf, encoding, start, end) {
  var out = buf.toString(encoding, start, end);
  if (encoding === 'base64url') {
    return out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  return out;
}

function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  this.lastNeed = 0;
  this.lastTotal = 0;

  var lastCharBytes;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      lastCharBytes = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      this.text = utf8Text;
      this.end = utf8End;
      lastCharBytes = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      lastCharBytes = 3;
      break;
    case 'base64url':
      this.text = base64UrlText;
      this.end = base64UrlEnd;
      lastCharBytes = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }

  this.lastChar = Buffer.allocUnsafe(lastCharBytes);
}

StringDecoder.prototype.write = function write(buf) {
  if (buf == null) return '';
  buf = toDecoderBuffer(buf);
  if (typeof buf === 'string') return buf;
  if (!buf || buf.length === 0) return '';

  var result;
  var offset;
  if (this.lastNeed) {
    result = this.fillLast(buf);
    if (result === undefined) {
      return '';
    }
    offset = this.lastNeed;
    this.lastNeed = 0;
  } else {
    offset = 0;
  }

  if (offset < buf.length) {
    var tail = this.text(buf, offset);
    return result ? result + tail : tail;
  }

  return result || '';
};

StringDecoder.prototype.text = utf8Text;
StringDecoder.prototype.end = utf8End;

StringDecoder.prototype.fillLast = function fillLast(buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return bufferToEncoding(this.lastChar, this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
  return undefined;
};

function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;
  if (byte >> 5 === 0x06) return 2;
  if (byte >> 4 === 0x0E) return 3;
  if (byte >> 3 === 0x1E) return 4;
  return (byte >> 6 === 0x02 ? -1 : -2);
}

function utf8CheckIncomplete(self, buf, offset) {
  var j = buf.length - 1;
  if (j < offset) return 0;

  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < offset || nb === -2) return 0;

  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < offset || nb === -2) return 0;

  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) {
        nb = 0;
      } else {
        self.lastNeed = nb - 3;
      }
    }
    return nb;
  }

  return 0;
}

function utf8CheckExtraBytes(self, buf) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\uFFFD';
  }

  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\uFFFD';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\uFFFD';
      }
    }
  }

  return undefined;
}

function utf8FillLast(buf) {
  var result = utf8CheckExtraBytes(this, buf);
  if (result !== undefined) {
    return result;
  }

  var prefixLength = this.lastTotal - this.lastNeed;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, prefixLength, 0, this.lastNeed);
    return this.lastChar.toString('utf8', 0, this.lastTotal);
  }

  buf.copy(this.lastChar, prefixLength, 0, buf.length);
  this.lastNeed -= buf.length;
  return undefined;
}

function utf8Text(buf, offset) {
  var total = utf8CheckIncomplete(this, buf, offset);
  if (!this.lastNeed) {
    return buf.toString('utf8', offset);
  }

  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', offset, end);
}

function utf8End(buf) {
  var result = (buf && buf.length) ? this.write(buf) : '';
  if (this.lastNeed) {
    this.lastNeed = 0;
    this.lastTotal = 0;
    return result + '\uFFFD';
  }
  return result;
}

function utf16Text(buf, offset) {
  if ((buf.length - offset) % 2 === 0) {
    var result = buf.toString('utf16le', offset);
    if (result) {
      var code = result.charCodeAt(result.length - 1);
      if (code >= 0xD800 && code <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return result.slice(0, -1);
      }
    }
    return result;
  }

  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', offset, buf.length - 1);
}

function utf16End(buf) {
  var result = (buf && buf.length) ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    this.lastNeed = 0;
    this.lastTotal = 0;
    return result + this.lastChar.toString('utf16le', 0, end);
  }
  return result;
}

function base64Text(buf, offset) {
  var remainder = (buf.length - offset) % 3;
  if (remainder === 0) {
    return buf.toString('base64', offset);
  }

  this.lastNeed = 3 - remainder;
  this.lastTotal = 3;
  if (remainder === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', offset, buf.length - remainder);
}

function base64End(buf) {
  var result = (buf && buf.length) ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = 3 - this.lastNeed;
    this.lastNeed = 0;
    this.lastTotal = 0;
    return result + this.lastChar.toString('base64', 0, end);
  }
  return result;
}

function base64UrlText(buf, offset) {
  var result = base64Text.call(this, buf, offset);
  return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlEnd(buf) {
  var result = base64End.call(this, buf);
  return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function simpleWrite(buf) {
  buf = toDecoderBuffer(buf);
  if (typeof buf === 'string') return buf;
  return bufferToEncoding(buf, this.encoding);
}

function simpleEnd(buf) {
  return (buf && buf.length) ? this.write(buf) : '';
}

StringDecoder.prototype.text = function text(buf, offset) {
  this.lastNeed = 0;
  this.lastTotal = 0;
  return this.write(buf.slice(offset));
};

StringDecoder.prototype[Symbol.toPrimitive] = function() {
  return 'StringDecoder';
};

var stringDecoderToString = function() {
  return '[object StringDecoder]';
};
StringDecoder.prototype.toString = stringDecoderToString;
// Lazy builtin evaluation runs after primordial prototypes are locked down.
// Define the own override directly so Object.prototype.toString being
// non-writable cannot make the sloppy assignment above disappear.
// @ref LLP 0013#mechanism-1-lockdown — locked intrinsics remain shared.
Object.defineProperty(StringDecoder.prototype, 'toString', {
  value: stringDecoderToString,
  writable: true,
  configurable: true,
  enumerable: true
});

module.exports = StringDecoder;
module.exports.StringDecoder = StringDecoder;
