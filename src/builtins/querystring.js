var qs = {};

qs.escape = function escape(str) {
  if (typeof str !== 'string') {
    if (typeof str === 'object')
      str = String(str);
    else
      str = str + '';
  }

  var len = str.length;
  if (len === 0) return '';

  var out = '';
  var lastPos = 0;

  for (var i = 0; i < len; i++) {
    var c = str.charCodeAt(i);

    // ASCII range
    if (c < 0x80) {
      if (__qsNoEscape(c)) continue;
      if (lastPos < i) out += str.slice(lastPos, i);
      lastPos = i + 1;
      out += __qsHex(c);
      continue;
    }

    if (lastPos < i) out += str.slice(lastPos, i);

    if (c < 0x800) {
      // 2-byte UTF-8
      lastPos = i + 1;
      out += __qsHex(0xC0 | (c >> 6)) + __qsHex(0x80 | (c & 0x3F));
    } else if (c < 0xD800 || c >= 0xE000) {
      // 3-byte UTF-8
      lastPos = i + 1;
      out += __qsHex(0xE0 | (c >> 12)) +
             __qsHex(0x80 | ((c >> 6) & 0x3F)) +
             __qsHex(0x80 | (c & 0x3F));
    } else {
      // Surrogate pair
      i++;
      if (i >= len) {
        var err = new URIError('URI malformed');
        err.code = 'ERR_INVALID_URI';
        throw err;
      }
      var c2 = str.charCodeAt(i) & 0x3FF;
      lastPos = i + 1;
      c = 0x10000 + (((c & 0x3FF) << 10) | c2);
      out += __qsHex(0xF0 | (c >> 18)) +
             __qsHex(0x80 | ((c >> 12) & 0x3F)) +
             __qsHex(0x80 | ((c >> 6) & 0x3F)) +
             __qsHex(0x80 | (c & 0x3F));
    }
  }

  if (lastPos === 0) return str;
  if (lastPos < len) return out + str.slice(lastPos);
  return out;
};

function __qsNoEscape(c) {
  if (c >= 0x30 && c <= 0x39) return true; // 0-9
  if (c >= 0x41 && c <= 0x5A) return true; // A-Z
  if (c >= 0x61 && c <= 0x7A) return true; // a-z
  return c === 0x21 || c === 0x27 || c === 0x28 || c === 0x29 || c === 0x2A ||
         c === 0x2D || c === 0x2E || c === 0x5F || c === 0x7E;
}

function __qsHex(byte) {
  var hex = byte.toString(16).toUpperCase();
  return '%' + (hex.length === 1 ? '0' + hex : hex);
}

qs.unescape = function unescape(str) {
  try {
    return decodeURIComponent(str.replace(/\+/g, ' '));
  } catch (e) {
    return str;
  }
};

qs.stringify = function stringify(obj, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var encode = (options && typeof options.encodeURIComponent === 'function')
    ? options.encodeURIComponent
    : qs.escape;

  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return '';
  }

  var keys = Object.keys(obj);
  var parts = [];

  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = obj[key];
    var encodedKey = encode(key);

    if (Array.isArray(value)) {
      for (var j = 0; j < value.length; j++) {
        var item = value[j];
        if (item === null || item === undefined) {
          parts.push(encodedKey + eq);
        } else {
          parts.push(encodedKey + eq + encode(String(item)));
        }
      }
    } else if (value === null || value === undefined) {
      parts.push(encodedKey + eq);
    } else {
      parts.push(encodedKey + eq + encode(String(value)));
    }
  }

  return parts.join(sep);
};

qs.parse = function parse(str, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }
  var decode = (options && typeof options.decodeURIComponent === 'function')
    ? options.decodeURIComponent
    : qs.unescape;

  var obj = Object.create(null);

  if (typeof str !== 'string' || str.length === 0) {
    return obj;
  }

  var pairs = str.split(sep);
  var len = pairs.length;
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; i++) {
    var pair = pairs[i];
    var eqIdx = pair.indexOf(eq);
    var key, value;

    if (eqIdx >= 0) {
      key = decode(pair.substring(0, eqIdx));
      value = decode(pair.substring(eqIdx + eq.length));
    } else {
      key = decode(pair);
      value = '';
    }

    if (key === '') continue;

    if (obj[key] !== undefined) {
      if (Array.isArray(obj[key])) {
        obj[key].push(value);
      } else {
        obj[key] = [obj[key], value];
      }
    } else {
      obj[key] = value;
    }
  }

  return obj;
};

qs.encode = qs.stringify;
qs.decode = qs.parse;

module.exports = qs;
