var qs = {};

qs.escape = function escape(str) {
  return encodeURIComponent(str);
};

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
