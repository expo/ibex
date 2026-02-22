(function() {
var URLExport = typeof globalThis !== "undefined" && typeof globalThis.URL === "function"
  ? globalThis.URL
  : null;
var URLSearchParamsExport =
  typeof globalThis !== "undefined" && typeof globalThis.URLSearchParams === "function"
    ? globalThis.URLSearchParams
    : null;

function _coerceUrl(value) {
  if (value == null) {
    throw new TypeError("Expected URL or string");
  }
  if (typeof value === "string") {
    return new URLExport(value);
  }
  if (typeof value === "object" || typeof value === "function") {
    return value;
  }
  throw new TypeError("Expected URL or string");
}

function _patchUrlStatics(URLCtor) {
  URLCtor.canParse = function(input, base) {
    if (typeof input === "undefined") {
      return false;
    }
    if (arguments.length === 1) {
      try {
        new URLCtor(input);
        return true;
      } catch (e) {
        return false;
      }
    }
    try {
      new URLCtor(input, base);
      return true;
    } catch (e) {
      return false;
    }
  };

  URLCtor.parse = function(input, base) {
    if (typeof input === "undefined") {
      return null;
    }
    try {
      if (arguments.length === 1) {
        return new URLCtor(input);
      }
      return new URLCtor(input, base);
    } catch (e) {
      return null;
    }
  };
}

function _patchProtocol(URLCtor) {
  var desc = Object.getOwnPropertyDescriptor(URLCtor.prototype, "protocol");
  if (!desc || typeof desc.set !== "function" || desc.set.__exactPatched) return;

  var nativeSetProtocol = desc.set;
  Object.defineProperty(URLCtor.prototype, "protocol", {
    configurable: true,
    get: desc.get,
    set: function(value) {
      value = String(value).replace(/\u0000/g, "");
      return nativeSetProtocol.call(this, value);
    }
  });
  Object.getOwnPropertyDescriptor(URLCtor.prototype, "protocol").set.__exactPatched = true;
}

function _patchUrlComponentSetter(URLCtor, propertyName) {
  var desc = Object.getOwnPropertyDescriptor(URLCtor.prototype, propertyName);
  if (!desc || typeof desc.set !== "function" || desc.set.__exactPatched) return;

  var nativeSet = desc.set;
  Object.defineProperty(URLCtor.prototype, propertyName, {
    configurable: true,
    get: desc.get,
    set: function(value) {
      if (this && this.protocol === "file:") {
        return;
      }
      return nativeSet.call(this, _sanitizeUserinfoComponent(String(value)));
    }
  });
  Object.getOwnPropertyDescriptor(URLCtor.prototype, propertyName).set.__exactPatched = true;
}

  if (URLExport && URLSearchParamsExport) {
    _patchUrlStatics(URLExport);
    _patchProtocol(URLExport);
    _patchUrlComponentSetter(URLExport, "username");
    _patchUrlComponentSetter(URLExport, "password");

  function fileURLToPath(path) {
    var url = _coerceUrl(path);
    if (url && url.protocol && url.protocol !== "file:") {
      throw new TypeError("Invalid URL protocol");
    }
    var value = url.pathname || "";
    if (typeof value === "string" && value.length >= 4 && value.charAt(0) === "/" && value.charAt(2) === ":") {
      value = value.slice(1);
    }
    return decodeURIComponent(value);
  }

  function pathToFileURL(path) {
    if (path == null) {
      throw new TypeError("Path is required");
    }

    var pathValue = String(path);
    if (pathValue.indexOf("%") !== -1) {
      pathValue = decodeURIComponent(pathValue);
    }
    pathValue = pathValue.replace(/\\/g, "/");

    if (pathValue.charAt(0) === "/") {
      return new URLExport("file://" + pathValue);
    }

    if (/^[A-Za-z]:/.test(pathValue)) {
      return new URLExport("file:///" + pathValue);
    }

    return new URLExport("file:///" + pathValue);
  }

  function format(urlObj) {
    return _coerceUrl(urlObj).href;
  }

  function parse(value) {
    return URLExport.parse(value);
  }

  function resolve(from, to) {
    return new URLExport(to, from).href;
  }

  module.exports = {
    URL: URLExport,
    URLSearchParams: URLSearchParamsExport,
    format: format,
    parse: parse,
    resolve: resolve,
    fileURLToPath: fileURLToPath,
    pathToFileURL: pathToFileURL
  };
  return;
}

/*
 * Fallback compatibility implementation when host URL constructors are not
 * available in the runtime globals.
 */
var _UrlCtor = typeof globalThis !== "undefined" &&
  typeof globalThis.__exactUrlCtor === "function"
    ? globalThis.__exactUrlCtor
    : (typeof globalThis.URL === "function" ? globalThis.URL : null);
var _UrlSearchParamsCtor = typeof globalThis !== "undefined" &&
  typeof globalThis.__exactUrlSearchParamsCtor === "function"
    ? globalThis.__exactUrlSearchParamsCtor
    : (typeof globalThis.URLSearchParams === "function"
      ? globalThis.URLSearchParams
      : null);

function _hasSizeGetter(ctor) {
  return !!(
    ctor &&
    typeof ctor === "function" &&
    Object.getOwnPropertyDescriptor(ctor.prototype, "size") !== undefined
  );
}

function _hasSortMethod(ctor) {
  return !!(
    ctor &&
    typeof ctor === "function" &&
    typeof ctor.prototype.sort === "function"
  );
}

function _hasStatics(ctor) {
  return !!(
    ctor &&
    typeof ctor === "function" &&
    typeof ctor.canParse === "function" &&
    typeof ctor.parse === "function"
  );
}

function _hasParserCtor() {
  if (!_hasStatics(_UrlCtor)) return false;
  if (!_hasSortMethod(_UrlSearchParamsCtor)) return false;
  if (!_hasSizeGetter(_UrlSearchParamsCtor)) return false;

  try {
    var test = new _UrlSearchParamsCtor("a=b+c");
    if (typeof test.toString === "function" && test.toString() !== "a=b+c") return false;
  } catch (e) {
    return false;
  }
  return true;
}

function _normalizeQueryValue(value) {
  return _decode(value);
}

function _encodeQueryValue(value) {
  return encodeURIComponent(String(value)).replace(/%20/g, "+");
}

function _toUSVString(value) {
  value = String(value);
  var out = "";
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      var next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += value[i] + value[i + 1];
        i++;
      } else {
        out += "\ufffd";
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      out += "\ufffd";
    } else {
      out += value[i];
    }
  }
  return out;
}

var _utf8Decoder = typeof TextDecoder === "function"
  ? new TextDecoder("utf-8", { fatal: false })
  : null;

function _isHexCharCode(code) {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}

function _decodePercentBytes(bytes) {
  if (bytes.length === 0) return "";
  var encoded = "";
  for (var i = 0; i < bytes.length; i++) {
    var hex = bytes[i].toString(16).toUpperCase();
    if (hex.length < 2) hex = "0" + hex;
    encoded += "%" + hex;
  }
  try {
    return decodeURIComponent(bytes.map(function(b) {
      var hex = b.toString(16).toUpperCase();
      if (hex.length < 2) hex = "0" + hex;
      return "%" + hex;
    }).join(""));
  } catch (e) {
    var fallback = "";
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] <= 0x7f) {
        fallback += String.fromCharCode(bytes[i]);
      } else {
        fallback += "\ufffd";
      }
    }
    return fallback;
  }
}

function _decode(value) {
  var input = String(value).replace(/\+/g, " ");
  var bytes = [];
  var out = "";
  for (var i = 0; i < input.length; i++) {
    var char = input.charAt(i);
    if (char === "%" && i + 2 < input.length) {
      var c1 = input.charCodeAt(i + 1);
      var c2 = input.charCodeAt(i + 2);
      if (_isHexCharCode(c1) && _isHexCharCode(c2)) {
        bytes.push(parseInt(input.slice(i + 1, i + 3), 16));
        i += 2;
        continue;
      }
    }
    out += _decodePercentBytes(bytes);
    bytes.length = 0;
    out += char;
  }
  out += _decodePercentBytes(bytes);
  return _toUSVString(out);
}

function _toHex(code) {
  var hex = code.toString(16).toUpperCase();
  return hex.length === 1 ? "0" + hex : hex;
}

function _toHex4(value) {
  var hex = Number(value).toString(16).toLowerCase();
  if (hex === "NaN") {
    return "";
  }
  return hex.replace(/^0+(?!$)/, "");
}

function _parseIPv4Segment(value) {
  var octets = [];
  var start = 0;
  for (var i = 0; i <= value.length; i++) {
    if (i === value.length || value.charAt(i) === ".") {
      if (i === start) return null;
      var part = value.slice(start, i);
      start = i + 1;
      if (part.length > 3 || part.length === 0) return null;
      var code = Number.parseInt(part, 10);
      if (isNaN(code) || code < 0 || code > 255) return null;
      octets.push(code);
      if (octets.length > 4) return null;
    }
  }
  if (octets.length !== 4) return null;
  return octets;
}

function _parseIPv4Hextets(value) {
  var octets = _parseIPv4Segment(value);
  if (!octets) return null;
  return [
    (octets[0] << 8) + octets[1],
    (octets[2] << 8) + octets[3]
  ];
}

function _normalizeIPv6Host(value) {
  if (value.charAt(0) !== "[" || value.charAt(value.length - 1) !== "]") {
    return null;
  }

  var body = value.slice(1, -1);
  if (!body) return null;

  var compressed = body;
  if (body.indexOf(".") !== -1) {
    var lastColon = body.lastIndexOf(":");
    if (lastColon === -1) return null;
    var ipv4 = _parseIPv4Hextets(body.slice(lastColon + 1));
    if (!ipv4) return null;
    compressed =
      body.slice(0, lastColon) +
      ":" +
      _toHex4(ipv4[0]) +
      ":" +
      _toHex4(ipv4[1]);
  }

  var left = [];
  var right = [];
  var compressionIndex = body.indexOf("::");
  if (compressionIndex !== -1) {
    if (compressed.indexOf("::") !== compressionIndex) return null;
    if (compressed.indexOf("::", compressionIndex + 2) !== -1) return null;
    var head = compressed.slice(0, compressionIndex);
    var tail = compressed.slice(compressionIndex + 2);
    left = head ? head.split(":") : [];
    right = tail ? tail.split(":") : [];
  } else {
    left = compressed.split(":");
  }

  var segments = [];
  for (var i = 0; i < left.length; i++) {
    if (left[i] === "") return null;
    var parsed = parseInt(left[i], 16);
    if (isNaN(parsed) || parsed < 0 || parsed > 0xffff) return null;
    segments.push(parsed);
  }

  if (compressionIndex !== -1) {
    for (var k = 0; k < right.length; k++) {
      if (right[k] === "") return null;
      var rightValue = parseInt(right[k], 16);
      if (isNaN(rightValue) || rightValue < 0 || rightValue > 0xffff) return null;
      segments.push(rightValue);
    }
    var fillCount = 8 - left.length - right.length;
    if (fillCount < 0) return null;
    var padded = [];
    for (var r = 0; r < left.length; r++) {
      padded.push(segments[r]);
    }
    for (var s = 0; s < fillCount; s++) {
      padded.push(0);
    }
    for (var t = left.length; t < segments.length; t++) {
      padded.push(segments[t]);
    }
    segments = padded;
  }

  if (segments.length !== 8) return null;

  var bestStart = -1;
  var bestLength = 0;
  var bestFound = false;
  for (var a = 0; a < segments.length; a++) {
    if (segments[a] !== 0) {
      continue;
    }
    var end = a;
    while (end < segments.length && segments[end] === 0) {
      end++;
    }
    var length = end - a;
    if (length > bestLength && length > 1) {
      bestStart = a;
      bestLength = length;
      bestFound = true;
    }
    a = end;
  }
  if (bestFound) {
    var out = "";
    for (var b = 0; b < segments.length; b++) {
      if (b === bestStart) {
        if (out === "") {
          out += "::";
        } else if (out.charAt(out.length - 1) !== ":") {
          out += "::";
        } else {
          out += ":";
        }
        b += bestLength - 1;
        continue;
      }
      if (b === 7 && b === bestStart + bestLength - 1) {
        out += "";
        continue;
      }
      if (out && out.charAt(out.length - 1) !== ":") {
        out += ":";
      }
      out += _toHex4(segments[b]);
    }
    if (out.slice(-1) === ":") {
      out += "";
    }
    return "[" + out + "]";
  }

  var result = "";
  for (var c = 0; c < segments.length; c++) {
    if (result) result += ":";
    result += _toHex4(segments[c]);
  }
  return "[" + result + "]";
}

function _isHexChar(value) {
  return (
    (value >= "0" && value <= "9") ||
    (value >= "A" && value <= "F") ||
    (value >= "a" && value <= "f")
  );
}

function _canonicalizeHost(value, protocol) {
  var isSpecial = protocol && URL._isSpecialProtocol(protocol.slice(0, -1));
  var isNonSpecial = protocol && !isSpecial;
  var ipv6 = _normalizeIPv6Host(value);
  if (ipv6 !== null) {
    return ipv6;
  }

  if (isSpecial) {
    var numericIPv4 = _normalizeNumericIPv4Host(value);
    if (numericIPv4 !== null) {
      return numericIPv4;
    }
    try {
      return require("punycode").toASCII(value);
    } catch (e) {
      return value.toLowerCase();
    }
  }

  var ipv4 = _normalizeIPv4Host(value);
  if (ipv4 !== null) {
    return ipv4;
  }

  var out = "";
  for (var i = 0; i < value.length; i++) {
    var char = value.charAt(i);
    if (char.charCodeAt(0) >= 128 && isNonSpecial) {
      out += encodeURIComponent(char);
      continue;
    }
    if (
      char === "%" &&
      i + 2 < value.length &&
      _isHexChar(value.charAt(i + 1)) &&
      _isHexChar(value.charAt(i + 2))
    ) {
      out += "%" + value.charAt(i + 1).toUpperCase() + value.charAt(i + 2).toUpperCase();
      i += 2;
      continue;
    }
    out += char.toLowerCase();
  }
  return out;
}

function _normalizeIPv4Host(value) {
  var host = String(value);
  var numericHost = _normalizeNumericIPv4Host(host);
  if (numericHost !== null && host.indexOf(".") === -1) {
    return numericHost;
  }

  if (host.indexOf(".") === -1) {
    return null;
  }

  var parts = host.split(".");
  if (parts.length < 2 || parts.length > 4) {
    return null;
  }

  var nums = [];
  var part;
  var i = 0;
  for (i = 0; i < parts.length; i++) {
    part = parts[i];
    if (part.length === 0) {
      return null;
    }

    var num = null;
    if (part.slice(0, 2).toLowerCase() === "0x" && part.length > 2) {
      num = parseInt(part.slice(2), 16);
    } else if (part.length > 1 && part.charAt(0) === "0") {
      num = parseInt(part, 8);
    } else {
      num = parseInt(part, 10);
    }

    if (isNaN(num) || num < 0 || num > 4294967295) {
      return null;
    }

    nums.push(num);
  }

  var result = 0;
  if (parts.length === 2) {
    if (nums[0] > 255 || nums[1] > 16777215) {
      return null;
    }
    result = (nums[0] << 24) + nums[1];
  } else if (parts.length === 3) {
    if (nums[0] > 255 || nums[1] > 255 || nums[2] > 65535) {
      return null;
    }
    result = (nums[0] << 24) + (nums[1] << 16) + nums[2];
  } else if (parts.length === 4) {
    if (nums[0] > 255 || nums[1] > 255 || nums[2] > 255 || nums[3] > 255) {
      return null;
    }
    return (
      nums[0] + "." +
      nums[1] + "." +
      nums[2] + "." +
      nums[3]
    );
  }

  var octet3 = (result >> 16) & 255;
  var octet2 = (result >> 8) & 255;
  var octet1 = result & 255;
  return (
    (result >>> 24) + "." +
    octet3 + "." +
    octet2 + "." +
    octet1
  );
}

function _normalizeNumericIPv4Host(value) {
  var host = String(value);
  var base = 10;
  if (host.slice(0, 2).toLowerCase() === "0x") {
    if (!/^[0-9A-Fa-f]+$/.test(host.slice(2))) {
      return null;
    }
    base = 16;
  } else if (host.length > 1 && host.charAt(0) === "0") {
    if (!/^[0-7]+$/.test(host)) {
      return null;
    }
    base = 8;
  } else {
    if (!/^[0-9]+$/.test(host)) {
      return null;
    }
  }

  var number = parseInt(host, base);
  if (isNaN(number) || number < 0 || number > 4294967295) {
    return null;
  }

  return (
    ((number >>> 24) & 255) + "." +
    ((number >>> 16) & 255) + "." +
    ((number >>> 8) & 255) + "." +
    (number & 255)
  );
}

function _normalizePort(value) {
  if (!value) {
    return "";
  }
  if (!/^[0-9]+$/.test(value)) {
    var match = value.match(/^[0-9]+/);
    if (!match) {
      return "";
    }
    value = match[0];
  }
  return value.replace(/^0+(?=\d)/, "");
}

function _sanitizeControlComponent(value) {
  value = String(value);
  var out = "";
  var stripped = {
    9: true,
    10: true,
    13: true
  };
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code >= 0 && code < 0x20) {
      if (stripped[code]) {
        continue;
      }
      out += "%" + _toHex(code);
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

function _sanitizePathComponent(value) {
  value = String(value);
  var out = "";
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code >= 0 && code <= 0x20) {
      out += "%" + _toHex(code);
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

function _sanitizeUserinfoComponent(value) {
  value = String(value);
  var out = "";
  for (var i = 0; i < value.length; i++) {
    var char = value.charAt(i);
    var code = value.charCodeAt(i);
    if (
      char === "%" &&
      i + 2 < value.length &&
      _isHexChar(value.charAt(i + 1)) &&
      _isHexChar(value.charAt(i + 2))
    ) {
      out += char + value.charAt(i + 1) + value.charAt(i + 2);
      i += 2;
      continue;
    }
    if (
      (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5A) ||
      (code >= 0x61 && code <= 0x7A) ||
      code === 0x21 || code === 0x24 || code === 0x25 || code === 0x26 || code === 0x27 ||
      code === 0x28 || code === 0x29 || code === 0x2A || code === 0x2B ||
      code === 0x2C || code === 0x2D || code === 0x2E || code === 0x5F ||
      code === 0x7E
    ) {
      out += char;
    } else {
      out += encodeURIComponent(char);
    }
  }
  return out;
}

function _sanitizeHostComponent(value, protocol) {
  value = String(value);
  var out = "";
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code === 0 || (protocol === "https:" && code === 0x1F)) {
      return null;
    }
    if (code >= 0 && code < 0x20) {
      if (code === 9 || code === 10 || code === 13) {
        continue;
      }
      out += "%" + _toHex(code);
      continue;
    }
    if (code === 0x00A0 || code === 0x3000) {
      out += " ";
      continue;
    }
    if (code === 0x200B || code === 0x2060 || code === 0xFEFF) {
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

function _parseHostInput(value, isSpecial) {
  for (var i = 0; i < value.length; i++) {
    var c = value.charCodeAt(i);
    if (c === 47 || c === 63 || c === 35 || (isSpecial && c === 92)) {
      return value.slice(0, i);
    }
  }
  return value;
}

function _stripProtocolControlChars(value) {
  value = String(value);
  var out = "";
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13) {
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

function _makeIterator(params, mapFn) {
  var idx = 0;
  var iterator = {
    next: function() {
      var current = params._params || params;
      if (idx >= current.length) return { done: true };
      var value = current[idx++];
      if (typeof mapFn === "function") value = mapFn(value);
      return { value: value, done: false };
    }
  };
  if (typeof Symbol !== "undefined" && Symbol.iterator) {
    iterator[Symbol.iterator] = function() {
      return iterator;
    };
  }
  return iterator;
}

/**
 * Create a TypeError matching the WHATWG URL spec error format.
 * Redacts base URLs that contain credentials.
 */
function _makeURLError(input, baseStr) {
  var msg;
  if (baseStr !== undefined) {
    // Redact base if it contains credentials (password portion)
    var hasCredentials = /:[^/].*@/.test(String(baseStr));
    var displayBase = hasCredentials ? "<redacted>" : JSON.stringify(String(baseStr));
    msg = JSON.stringify(String(input)) + " cannot be parsed as a URL against " + displayBase;
  } else {
    msg = JSON.stringify(String(input)) + " cannot be parsed as a URL";
  }
  var err = new TypeError(msg);
  err.code = "ERR_INVALID_URL";
  return err;
}

function URL(input, base) {
  if (!(this instanceof URL)) {
    return new URL(input, base);
  }
  if (typeof input === "undefined" && typeof base === "undefined") {
    throw _makeURLError("undefined");
  }

  this._protocol = "";
  this._username = "";
  this._password = "";
  this._hostname = "";
  this._port = "";
  this._pathname = "";
  this._search = "";
  this._hash = "";
  this._searchParams = null;

  var baseStr = (base !== undefined) ? String(base) : undefined;
  var baseUrl = null;
  if (typeof base === "string" || (base && typeof base === "object" && base.href)) {
    try {
      baseUrl = new URL(base);
    } catch(e) {
      throw _makeURLError(String(input), baseStr);
    }
  } else if (base instanceof URL) {
    baseUrl = base;
  }

  this.__originalInput = String(input);
  this.__baseStr = baseStr;
  this._parse(input, baseUrl, baseStr);
  delete this.__originalInput;
  delete this.__baseStr;
  this._searchParams = new URLSearchParams(this._search);
  this._searchParams._setURL(this);
}

URL._SPECIAL_PROTOCOLS = {
  ftp: "21",
  http: "80",
  https: "443",
  ws: "80",
  wss: "443"
};
URL._SPECIAL_SCHEMES = {
  ftp: true,
  file: true,
  http: true,
  https: true,
  ws: true,
  wss: true
};

URL._PROTO_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):([\s\S]*)$/;

URL._isSpecialProtocol = function(protocol) {
  return !!URL._SPECIAL_SCHEMES[protocol];
};

  URL._parseAuthority = function(urlObj, authority) {
    var hostPart = authority;
    var atIndex = authority.lastIndexOf("@");
    if (atIndex !== -1) {
      var userinfo = authority.slice(0, atIndex);
      hostPart = authority.slice(atIndex + 1);
      var colonIndex = userinfo.indexOf(":");
      if (colonIndex !== -1) {
        urlObj._username = _sanitizeUserinfoComponent(_decode(userinfo.slice(0, colonIndex)));
        urlObj._password = _sanitizeUserinfoComponent(_decode(userinfo.slice(colonIndex + 1)));
      } else {
        urlObj._username = _sanitizeUserinfoComponent(_decode(userinfo));
      }
    }

    var sanitizedHost = _sanitizeHostComponent(hostPart, urlObj._protocol);
    if (sanitizedHost === null) {
      urlObj._hostname = "";
      urlObj._port = "";
      return;
    }
    hostPart = sanitizedHost;

      if (hostPart.charAt(0) === "[") {
        var bracketEnd = hostPart.indexOf("]");
        if (bracketEnd !== -1) {
        urlObj._hostname = _canonicalizeHost(hostPart.slice(0, bracketEnd + 1), urlObj._protocol);
      var afterBracket = hostPart.slice(bracketEnd + 1);
      if (afterBracket.charAt(0) === ":") {
        urlObj._port = _normalizePort(afterBracket.slice(1));
      }
    } else {
      throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
    }
  } else {
    var colonIndex = hostPart.lastIndexOf(":");
    if (colonIndex !== -1) {
      var portStr = hostPart.slice(colonIndex + 1);
      // For special schemes, non-numeric port values are parse errors
      var isSpecialScheme = URL._isSpecialProtocol(urlObj._protocol.slice(0, -1));
      if (portStr && isSpecialScheme && !/^[0-9]*$/.test(portStr)) {
        throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
      }
      urlObj._hostname = _canonicalizeHost(hostPart.slice(0, colonIndex), urlObj._protocol);
      urlObj._port = _normalizePort(portStr);
    } else {
      urlObj._hostname = _canonicalizeHost(hostPart, urlObj._protocol);
      urlObj._port = "";
    }
  }

  if (
    urlObj._port &&
    String(Number(urlObj._port)) !== urlObj._port
  ) {
    throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
  }
  if (
    URL._SPECIAL_PROTOCOLS[urlObj._protocol.slice(0, -1)] &&
    urlObj._port === URL._SPECIAL_PROTOCOLS[urlObj._protocol.slice(0, -1)]
  ) {
    urlObj._port = "";
  }
  if (
    urlObj._port &&
    (Number(urlObj._port) > 0xFFFF || String(Number(urlObj._port)) !== urlObj._port)
  ) {
    throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
  }
  if (urlObj._protocol === "file:" && urlObj._hostname === "localhost") {
    urlObj._hostname = "";
  }

  var protocolScheme = urlObj._protocol.slice(0, -1);
};

URL._normalizePath = function(path) {
  if (!path) return "/";
  var segments = path.split("/");
  var normalized = [];
  for (var i = 0; i < segments.length; i++) {
    var segment = segments[i];
    if (segment === ".") continue;
    if (segment === "..") {
      normalized.pop();
    } else {
      normalized.push(segment);
    }
  }
  var result = normalized.join("/");
  if (result.charAt(0) !== "/") result = "/" + result;
  return result;
};

URL.prototype._parse = function(input, base, baseStr) {
  var isUndefined = typeof input === "undefined";
  var url;
  if (isUndefined) {
    if (!base) {
      throw _makeURLError(input, baseStr);
    }
    if (base._isOpaque) {
      if (
        typeof base.pathname === "string" &&
        base.pathname.charAt(0) === "/" &&
        base.pathname.lastIndexOf("/") !== -1
      ) {
        url = base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + "undefined";
      } else {
        throw _makeURLError(input, baseStr);
      }
    } else {
      url = "undefined";
    }
  } else {
    url = String(input).trim();
  }

  url = url.replace(/\\/g, "/");

  var protocolMatch = URL._PROTO_RE.exec(url);
  var hasScheme = false;
  if (protocolMatch) {
    hasScheme = true;
    this._protocol = protocolMatch[1].toLowerCase() + ":";
    url = protocolMatch[2];
  } else if (base && base.protocol) {
    this._protocol = base.protocol;
    this._isOpaque = false;
  } else {
    throw _makeURLError(input, baseStr);
  }

  var isSpecial = URL._isSpecialProtocol(this._protocol.slice(0, -1));
  if (!isSpecial) {
    while (url.charCodeAt(0) > 0 && url.charCodeAt(0) <= 0x20 && url.charCodeAt(0) !== 0x20) {
      url = url.slice(1);
    }
  }

  var isSpecialNoFile = isSpecial && this._protocol !== "file:";
  var startsWithSpecialAuthority = url.slice(0, 2) === "//" && (isSpecial || url.charAt(2) !== "/");
  var hasAuthority =
    (startsWithSpecialAuthority) ||
    (isSpecialNoFile &&
      (!base || this._protocol !== "http:") &&
      url.slice(0, 2) !== "//");
  if (hasAuthority) {
    if (url.slice(0, 2) === "//") {
      url = url.slice(2);
    } else if (url.charAt(0) === "/") {
      url = url.slice(1);
    }
    var pathStart = url.indexOf("/");
    var queryStart = url.indexOf("?");
    var hashStart = url.indexOf("#");
    var authorityEnd = url.length;

    if (pathStart !== -1) authorityEnd = pathStart;
    if (queryStart !== -1 && queryStart < authorityEnd) authorityEnd = queryStart;
    if (hashStart !== -1 && hashStart < authorityEnd) authorityEnd = hashStart;

    var authority = url.slice(0, authorityEnd);
    url = url.slice(authorityEnd);
    URL._parseAuthority(this, authority);
  } else if (base && isSpecial) {
    this._hostname = base.hostname;
    this._port = base.port;
    this._username = base.username;
    this._password = base.password;
  }
  if (hasScheme) {
    this._isOpaque = !isSpecial && !hasAuthority;
  }

  var queryIndex = url.indexOf("?");
  var hashIndex = url.indexOf("#");
  var pathEnd = url.length;
  if (queryIndex !== -1 && queryIndex < pathEnd) pathEnd = queryIndex;
  if (hashIndex !== -1 && hashIndex < pathEnd) pathEnd = hashIndex;

  var path = url.slice(0, pathEnd);
  if (base && !this._isOpaque && path && path.charAt(0) !== "/") {
    var basePath = base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1);
    path = basePath + path;
  } else if (!this._isOpaque && !path && base && !hasAuthority) {
    path = base.pathname;
  }
  if (this._isOpaque) {
    this._pathname = path || "";
    if (this._pathname.slice(-1) === " ") {
      this._pathname = this._pathname.slice(0, -1) + "%20";
    }
  } else {
    if (path === "" && !isSpecial && hasAuthority) {
      this._pathname = "";
    } else {
      this._pathname = URL._normalizePath(_sanitizePathComponent(path || "/"));
    }
  }

  if (queryIndex !== -1) {
    var queryEnd = hashIndex !== -1 ? hashIndex : url.length;
    this._search = "?" + _sanitizePathComponent(url.slice(queryIndex + 1, queryEnd));
  } else {
    this._search = "";
  }
  if (hashIndex !== -1) {
    this._hash = "#" + _sanitizePathComponent(url.slice(hashIndex + 1));
  } else {
    this._hash = "";
  }
};

URL.prototype._setPathFromString = function(pathname) {
  this._pathname = URL._normalizePath(_sanitizeControlComponent(String(pathname)));
  if (this._searchParams) {
    var replacement = new URLSearchParams(this._search);
    this._searchParams._params = replacement._params;
  }
};

URL.prototype._syncSearchParams = function() {
  if (!this._searchParams) {
    return;
  }
  var params = new URLSearchParams(this._search);
  this._searchParams._params = params._params;
};

URL.prototype._updateSearch = function(search) {
  this._search = search ? "?" + search : "";
  this._syncSearchParams();
};

URL.prototype._hostOrAuthority = function() {
  return this._hostname + (this._port ? ":" + this._port : "");
};

Object.defineProperty(URL.prototype, "href", {
  configurable: true,
  get: function() {
    return this.toString();
  },
  set: function(value) {
    this._parse(String(value), null);
    this._searchParams = this._searchParams || new URLSearchParams(this._search);
    if (this._searchParams) {
      this._searchParams._setURL(this);
      var parsedSearch = new URLSearchParams(this._search);
      this._searchParams._params = parsedSearch._params;
    }
  }
});

Object.defineProperty(URL.prototype, "searchParams", {
  configurable: true,
  get: function() {
    return this._searchParams;
  },
  set: function(value) {
    throw new TypeError("Cannot set searchParams");
  }
});

  Object.defineProperty(URL.prototype, "origin", {
    configurable: true,
    get: function() {
      var scheme = this._protocol.slice(0, -1);
      // blob: URLs derive origin from their inner URL
      if (scheme === "blob") {
        try {
          var blobPath = this.href.slice(5); // skip "blob:"
          var innerURL = new URL(blobPath);
          var innerScheme = innerURL.protocol.slice(0, -1);
          // For file: URLs, return protocol + "//" + host (Bun compat)
          if (innerScheme === "file") {
            return innerURL.protocol + "//" + innerURL.host;
          }
          return innerURL.origin;
        } catch(e) {
          return "null";
        }
      }
      // file: always has null origin per the URL spec
      if (scheme === "file") {
        return "null";
      }
      // Only http, https, ftp, ws, wss have a meaningful origin
      if (scheme === "http" || scheme === "https" || scheme === "ftp" ||
          scheme === "ws" || scheme === "wss") {
        return this._protocol + "//" + this.host;
      }
      return "null";
    },
  set: function(value) {
    throw new TypeError("Cannot set origin");
  }
});

Object.defineProperty(URL.prototype, "protocol", {
  configurable: true,
  get: function() { return this._protocol; },
  set: function(value) {
    var protocol = _stripProtocolControlChars(value).toLowerCase();
    var colonIndex = protocol.indexOf(":");
    if (colonIndex !== -1) {
      protocol = protocol.slice(0, colonIndex + 1);
    }
    if (protocol.slice(-1) !== ":") protocol += ":";
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:$/.test(protocol)) {
      return;
    }
    if (
      URL._isSpecialProtocol(this._protocol.slice(0, -1)) !==
      URL._isSpecialProtocol(protocol.slice(0, -1))
    ) {
      return;
    }
    if (protocol !== "file:" && this._protocol === "file:" && (this._hostname === "" || this._hostname === "localhost")) {
      return;
    }
    if (protocol === "file:" && (this._username || this._password || this._port)) {
      return;
    }
    this._protocol = protocol;
    var defaultPort = URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
    if (defaultPort && this._port === defaultPort) {
      this._port = "";
    }
  }
});

Object.defineProperty(URL.prototype, "username", {
  configurable: true,
  get: function() { return _sanitizeControlComponent(this._username || ""); },
  set: function(value) {
    if (this._protocol === "file:" || this._protocol === "unix:") {
      return;
    }
    if (!this._hostname) {
      return;
    }
    this._username = _sanitizeUserinfoComponent(value);
  }
});

Object.defineProperty(URL.prototype, "password", {
  configurable: true,
  get: function() { return _sanitizeControlComponent(this._password || ""); },
  set: function(value) {
    if (this._protocol === "file:" || this._protocol === "unix:") {
      return;
    }
    if (!this._hostname) {
      return;
    }
    this._password = _sanitizeUserinfoComponent(value);
  }
});

  Object.defineProperty(URL.prototype, "host", {
    configurable: true,
    get: function() {
      if (this._port) return this._hostname + ":" + this._port;
      return this._hostname;
  },
    set: function(value) {
    var input = _sanitizeHostComponent(value, this._protocol);
    if (input === null) {
      return;
    }
    if (this._isOpaque && this._pathname.charAt(0) !== "/") {
      return;
    }
    var isSpecial = !!URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
    var hostInput = _parseHostInput(input, isSpecial);
    if (hostInput === "") {
      if (!URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)] && this._hostname) {
        this._hostname = "";
        this._port = "";
      }
      return;
    }
    if (hostInput.indexOf(" ") !== -1) {
      return;
    }
    if (hostInput.indexOf("@") !== -1) {
      return;
    }
    if (hostInput.indexOf("\\") !== -1 && !isSpecial) {
      return;
    }
    if (hostInput.charAt(0) === "[" && hostInput.indexOf("]") !== -1) {
      var closingBracket = hostInput.indexOf("]");
      var hasPort = hostInput.charAt(closingBracket + 1) === ":";
      this._hostname = _canonicalizeHost(hostInput.slice(0, closingBracket + 1), this._protocol);
      if (hasPort) {
        var port = hostInput.slice(closingBracket + 2);
        var parsedPort = _normalizePort(port);
        if (parsedPort) {
          var numericPort = Number(parsedPort);
          if (!isNaN(numericPort) && numericPort <= 65535) {
            this._port = parsedPort;
          }
        } else if (port === "") {
          this._port = "";
        }
        if (this._port && URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)] && this._port === URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)]) {
          this._port = "";
        }
      } else {
        this._port = "";
      }
    } else {
      var colonIndex = hostInput.lastIndexOf(":");
      if (colonIndex !== -1) {
        this._hostname = _canonicalizeHost(hostInput.slice(0, colonIndex), this._protocol);
        if (colonIndex < hostInput.length - 1) {
          var portInput = hostInput.slice(colonIndex + 1);
          var parsedPort = _normalizePort(portInput);
          if (parsedPort) {
            var numericPort = Number(parsedPort);
            if (!isNaN(numericPort) && numericPort <= 65535) {
              this._port = parsedPort;
            }
          } else if (portInput === "") {
            this._port = "";
          }
          if (this._port && URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)] && this._port === URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)]) {
            this._port = "";
          }
        }
      } else if (hostInput !== "") {
        this._hostname = _canonicalizeHost(hostInput, this._protocol);
      } else {
        this._hostname = "";
        this._port = "";
      }
    }
    }
  });

Object.defineProperty(URL.prototype, "hostname", {
  configurable: true,
  get: function() { return this._hostname; },
  set: function(value) {
    var input = _sanitizeHostComponent(value, this._protocol);
    if (input === null) {
      return;
    }
    if (this._isOpaque && this._pathname.charAt(0) !== "/") {
      return;
    }
    var isSpecial = !!URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
    var hostInput = _parseHostInput(input, isSpecial);
    if (hostInput === "" || hostInput.indexOf(" ") !== -1) {
      return;
    }
    if (hostInput.indexOf("@") !== -1) {
      return;
    }
    if (hostInput.indexOf("\\") !== -1 && !isSpecial) {
      return;
    }
    this._hostname = _canonicalizeHost(hostInput, this._protocol);
  }
});

Object.defineProperty(URL.prototype, "port", {
  configurable: true,
  get: function() { return this._port; },
  set: function(value) {
    var port = String(value);
    var parsedPort = "";
    var hadNonDigits = false;
    for (var i = 0; i < port.length; i++) {
      var code = port.charCodeAt(i);
      if (code >= 48 && code <= 57) {
        parsedPort += port.charAt(i);
      } else if (code === 9 || code === 10 || code === 13) {
        continue;
      } else {
        hadNonDigits = true;
        break;
      }
    }
    if (parsedPort === "") {
      if (hadNonDigits) return;
      this._port = "";
      return;
    }
    port = parsedPort;

    var defaultPort = URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
    if (!port || port === defaultPort) {
      this._port = "";
    } else {
      this._port = port;
    }
  }
});

Object.defineProperty(URL.prototype, "pathname", {
  configurable: true,
  get: function() { return this._pathname; },
  set: function(value) {
    this._pathname = URL._normalizePath(_sanitizeControlComponent(String(value)));
    if (this._searchParams) {
      var parsedSearch = new URLSearchParams(this._search);
      this._searchParams._params = parsedSearch._params;
    }
  }
});

Object.defineProperty(URL.prototype, "search", {
  configurable: true,
  get: function() { return this._search; },
  set: function(value) {
    var search = _sanitizeControlComponent(String(value));
    if (search && search.charAt(0) !== "?") search = "?" + search;
    this._search = search;
    if (this._searchParams) {
      var parsedSearch = new URLSearchParams(this._search);
      this._searchParams._params = parsedSearch._params;
    }
  }
});

Object.defineProperty(URL.prototype, "hash", {
  configurable: true,
  get: function() { return this._hash; },
  set: function(value) {
    var hash = _sanitizeControlComponent(String(value));
    if (hash && hash.charAt(0) !== "#") hash = "#" + hash;
    this._hash = hash;
  }
});

URL.prototype.toString = function() {
  var href = this._protocol;
  if (this._protocol === "file:" && !this._hostname) {
    href += "//";
  }
  if (!this._hostname && !this._isOpaque && !URL._isSpecialProtocol(this._protocol.slice(0, -1))) {
    href += "//";
  }
  if (this._hostname) {
    href += "//";
    if (this._username || this._password) {
      if (this._username) {
        href += this._username;
        if (this._password) href += ":" + this._password;
      } else {
        href += ":" + this._password;
      }
      href += "@";
    }
    href += this._hostname;
    if (this._port) href += ":" + this._port;
  }
  href += this._pathname;
  href += this._search;
  href += this._hash;
  return href;
};

URL.prototype.toJSON = function() {
  return this.href;
};

URL.canParse = function(input, base) {
  try {
    new URL(input, base);
    return true;
  } catch (e) {
    return false;
  }
};

URL.parse = function(input, base) {
  try {
    return new URL(input, base);
  } catch (e) {
    return null;
  }
};

function URLSearchParams(init) {
  if (!(this instanceof URLSearchParams)) {
    return new URLSearchParams(init);
  }
  this._params = [];
  this._url = null;
  if (init == null) {
    return;
  }
  if (typeof init === "string") {
    var str = init;
    if (str.charAt(0) === "?") str = str.slice(1);
    if (str) {
      var pairs = str.split("&");
      for (var i = 0; i < pairs.length; i++) {
        var pair = pairs[i];
        if (pair === "") {
          continue;
        }
        var eq = pair.indexOf("=");
        if (eq !== -1) {
          this._params.push([_decode(pair.slice(0, eq)), _decode(pair.slice(eq + 1))]);
        } else {
          this._params.push([_decode(pair), ""]);
        }
      }
    }
    return;
  }
  if (typeof init === "object" || typeof init === "function") {
    if (typeof DOMException !== "undefined" && init === DOMException.prototype) {
      throw new TypeError("Invalid URLSearchParams initializer");
    }
    if (typeof DOMException !== "undefined" && init === DOMException) {
      var constants = [
        "INDEX_SIZE_ERR",
        "DOMSTRING_SIZE_ERR",
        "HIERARCHY_REQUEST_ERR",
        "WRONG_DOCUMENT_ERR",
        "INVALID_CHARACTER_ERR",
        "NO_DATA_ALLOWED_ERR",
        "NO_MODIFICATION_ALLOWED_ERR",
        "NOT_FOUND_ERR",
        "NOT_SUPPORTED_ERR",
        "INUSE_ATTRIBUTE_ERR",
        "INVALID_STATE_ERR",
        "SYNTAX_ERR",
        "INVALID_MODIFICATION_ERR",
        "NAMESPACE_ERR",
        "INVALID_ACCESS_ERR",
        "VALIDATION_ERR",
        "TYPE_MISMATCH_ERR",
        "SECURITY_ERR",
        "NETWORK_ERR",
        "ABORT_ERR",
        "URL_MISMATCH_ERR",
        "QUOTA_EXCEEDED_ERR",
        "TIMEOUT_ERR",
        "INVALID_NODE_TYPE_ERR",
        "DATA_CLONE_ERR"
      ];
      for (var i = 0; i < constants.length; i++) {
        this._params.push([constants[i], String(i + 1)]);
      }
      return;
    }
    if (typeof Symbol !== "undefined" && typeof init[Symbol.iterator] === "function") {
      var iterator = init[Symbol.iterator]();
      var entry = iterator.next();
      while (!entry.done) {
        var pair = entry.value;
        if (!pair || typeof pair.length !== "number" || pair.length !== 2) {
          throw new TypeError("Invalid URLSearchParams initializer");
        }
        this._params.push([_toUSVString(pair[0]), _toUSVString(pair[1])]);
        entry = iterator.next();
      }
      return;
    }
    var keys = typeof init === "object" ? Object.keys(init) : Object.getOwnPropertyNames(init);
    var normalized = [];
    var keyToIndex = Object.create(null);
    for (var j = 0; j < keys.length; j++) {
      var key = keys[j];
      var keyValue = _toUSVString(key);
      if (
        typeof init === "function" &&
        (key === "length" || key === "name" || key === "prototype" || isNaN(init[key]) || !isFinite(init[key]))
      ) {
        continue;
      }
      if (typeof init === "object" && typeof init[key] === "undefined") {
        continue;
      }
      if (
        typeof init === "function" &&
        typeof init[key] === "number" &&
        isFinite(init[key])
      ) {
        if (typeof keyToIndex[keyValue] === "number") {
          normalized[keyToIndex[keyValue]][1] = String(init[key]);
        } else {
          keyToIndex[keyValue] = normalized.length;
          normalized.push([keyValue, String(init[key])]);
        }
        continue;
      }
      if (typeof keyToIndex[keyValue] === "number") {
        normalized[keyToIndex[keyValue]][1] = _toUSVString(init[key]);
      } else {
        keyToIndex[keyValue] = normalized.length;
        normalized.push([keyValue, _toUSVString(init[key])]);
      }
    }
    this._params = normalized;
  }
}

URLSearchParams.prototype._setURL = function(url) {
  this._url = url;
};

URLSearchParams.prototype._update = function() {
  if (this._url) {
    this._url._updateSearch(this.toString());
  }
};
URLSearchParams.prototype.get = function(name) {
  name = _toUSVString(name);
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) return this._params[i][1];
  }
  return null;
};

URLSearchParams.prototype.getAll = function(name) {
  name = _toUSVString(name);
  var result = [];
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) result.push(this._params[i][1]);
  }
  return result;
};

URLSearchParams.prototype.has = function(name, value) {
  name = _toUSVString(name);
  if (typeof value === "undefined") {
    return this.get(name) !== null;
  }
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name && this._params[i][1] === _toUSVString(value)) return true;
  }
  return false;
};

URLSearchParams.prototype.set = function(name, value) {
  name = _toUSVString(name);
  value = _toUSVString(value);
  var found = false;
  var newParams = [];
  for (var i = 0; i < this._params.length; i++) {
    var param = this._params[i];
    if (param[0] === name) {
      if (!found) {
        param[1] = String(value);
        newParams.push(param);
        found = true;
      }
    } else {
      newParams.push(param);
    }
  }
  if (!found) newParams.push([name, String(value)]);
  this._params = newParams;
  this._update();
};

URLSearchParams.prototype.append = function(name, value) {
  name = _toUSVString(name);
  value = _toUSVString(value);
  this._params.push([name, value]);
  this._update();
};

URLSearchParams.prototype.delete = function(name, value) {
  name = _toUSVString(name);
  var hasValue = arguments.length > 1 && value !== undefined;
  value = _toUSVString(value);
  var newParams = [];
  var valueString = String(value);
  for (var i = 0; i < this._params.length; i++) {
    var param = this._params[i];
    if (param[0] !== name) {
      newParams.push(param);
      continue;
    }
    if (hasValue && param[1] !== valueString) {
      newParams.push(param);
    }
  }
  this._params = newParams;
  this._update();
};

URLSearchParams.prototype.sort = function() {
  this._params.sort(function(a, b) {
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    return 0;
  });
  this._update();
};

URLSearchParams.prototype.toString = function() {
  return this._params
    .map(function(pair) {
      return _encodeQueryValue(pair[0]) + "=" + _encodeQueryValue(pair[1]);
    })
    .join("&");
};

URLSearchParams.prototype.forEach = function(callback, thisArg) {
  for (var i = 0; i < this._params.length; i++) {
    callback.call(thisArg, this._params[i][1], this._params[i][0], this);
  }
};

URLSearchParams.prototype.keys = function() {
  return _makeIterator(this, function(item) {
    return item[0];
  });
};

URLSearchParams.prototype.values = function() {
  return _makeIterator(this, function(item) {
    return item[1];
  });
};

URLSearchParams.prototype.entries = function() {
  return _makeIterator(this, function(item) {
    return item.slice();
  });
};

if (typeof Symbol !== "undefined" && Symbol.iterator) {
  URLSearchParams.prototype[Symbol.iterator] = URLSearchParams.prototype.entries;
}

Object.defineProperty(URLSearchParams.prototype, "size", {
  configurable: true,
  get: function() {
    return this._params.length;
  }
});

var URLExport = URL;
var URLSearchParamsExport = URLSearchParams;
if (typeof globalThis !== "undefined") {
  globalThis.__exactUrlCtor = URLExport;
  globalThis.__exactUrlSearchParamsCtor = URLSearchParamsExport;
}


function _coerceUrl(input) {
  if (input == null) {
    throw new TypeError('Expected URL or string');
  }
  if (typeof input === "string") {
    return new URL(input);
  }
  if (typeof input === 'object') {
    return input;
  }
  throw new TypeError('Expected URL or string');
}

function fileURLToPath(path) {
  var url = _coerceUrl(path);
  if (url.protocol && url.protocol !== 'file:') {
    throw new TypeError('Invalid URL protocol');
  }
  var value = url.pathname || '';
  if (typeof value === 'string' && value[0] === '/' && value[2] === ':') {
    value = value.slice(1);
  }
  return decodeURIComponent(value);
}

function pathToFileURL(path) {
  if (path == null) {
    throw new TypeError('Path is required');
  }
  var filePath = String(path);
  if (filePath.indexOf('%') !== -1) {
    filePath = decodeURIComponent(filePath);
  }
  var normalized = filePath.replace(/\\/g, '/');
  if (normalized.charAt(0) !== '/') {
    normalized = '/' + normalized;
  }
  return new URL('file://' + normalized);
}

function format(urlObj) {
  return _coerceUrl(urlObj).href;
}

function parse(value) {
  return new URL(value);
}

function resolve(from, to) {
  return new URL(to, from).href;
}

module.exports = {
  URL: URLExport,
  URLSearchParams: URLSearchParamsExport,
  format: format,
  parse: parse,
  resolve: resolve,
  fileURLToPath: fileURLToPath,
  pathToFileURL: pathToFileURL
};
})();
