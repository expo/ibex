//#region src/builtins/url.js
(function() {
	var URLExport = typeof globalThis !== "undefined" && typeof globalThis.URL === "function" ? globalThis.URL : null;
	var URLSearchParamsExport = typeof globalThis !== "undefined" && typeof globalThis.URLSearchParams === "function" ? globalThis.URLSearchParams : null;
	function _canUseHostUrlConstructors(URLCtor, URLSearchParamsCtor) {
		if (typeof URLCtor !== "function" || typeof URLSearchParamsCtor !== "function") return false;
		try {
			if (new URLSearchParamsCtor([["a", "b"]]).toString() !== "a=b") return false;
			if (new URLSearchParamsCtor([["b", "%2sf*"]]).toString() !== "b=%252sf*") return false;
			if (typeof DOMException === "function") {
				if (new URLSearchParamsCtor(DOMException).get("TIMEOUT_ERR") !== "23") return false;
			}
			if (new URLCtor("http://ExAmPlE.CoM").origin !== "http://example.com") return false;
			var fileHostProbe = new URLCtor("file://y/");
			fileHostProbe.host = "loc%41lhost";
			if (fileHostProbe.href !== "file:///") return false;
			var filePortRejected = false;
			try {
				new URLCtor("file://example:1/");
			} catch (_filePortErr) {
				filePortRejected = true;
			}
			if (!filePortRejected) return false;
			return true;
		} catch (e) {
			return false;
		}
	}
	function _coerceUrl(value) {
		if (value == null) throw new TypeError("Expected URL or string");
		if (typeof value === "string") return new URLExport(value);
		if (typeof value === "object" || typeof value === "function") return value;
		throw new TypeError("Expected URL or string");
	}
	var _objectURLCounter = 0;
	var _objectURLRegistry = {};
	function _createObjectURL(object) {
		if (arguments.length === 0) {
			var err = /* @__PURE__ */ new TypeError("The \"object\" argument must be specified");
			err.code = "ERR_MISSING_ARGS";
			throw err;
		}
		var url = "blob:exact:" + ++_objectURLCounter;
		_objectURLRegistry[url] = object;
		return url;
	}
	function _revokeObjectURL(url) {
		if (arguments.length === 0) {
			var err = /* @__PURE__ */ new TypeError("The \"url\" argument must be specified");
			err.code = "ERR_MISSING_ARGS";
			throw err;
		}
		delete _objectURLRegistry[String(url)];
	}
	function _patchUrlStatics(URLCtor) {
		URLCtor.canParse = function(input, base) {
			if (arguments.length === 0) {
				var err = /* @__PURE__ */ new TypeError("The \"url\" argument must be specified");
				err.code = "ERR_MISSING_ARGS";
				throw err;
			}
			if (typeof input === "undefined") return false;
			if (arguments.length === 1) try {
				new URLCtor(input);
				return true;
			} catch (e) {
				return false;
			}
			try {
				new URLCtor(input, base);
				return true;
			} catch (e) {
				return false;
			}
		};
		URLCtor.parse = function(input, base) {
			if (typeof input === "undefined") return null;
			try {
				if (arguments.length === 1) return new URLCtor(input);
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
				if (this && this.protocol === "file:") return;
				return nativeSet.call(this, _sanitizeUserinfoComponent(String(value)));
			}
		});
		Object.getOwnPropertyDescriptor(URLCtor.prototype, propertyName).set.__exactPatched = true;
	}
	if (URLExport && URLSearchParamsExport && _canUseHostUrlConstructors(URLExport, URLSearchParamsExport)) {
		_patchUrlStatics(URLExport);
		_patchProtocol(URLExport);
		_patchUrlComponentSetter(URLExport, "username");
		_patchUrlComponentSetter(URLExport, "password");
		URLExport.createObjectURL = _createObjectURL;
		URLExport.revokeObjectURL = _revokeObjectURL;
		var _nativeCanParse = URLExport.canParse ? URLExport.canParse.bind(URLExport) : null;
		function _wrappedCanParse(input, base) {
			if (arguments.length === 0) {
				var err = /* @__PURE__ */ new TypeError("The \"url\" argument must be specified");
				err.code = "ERR_MISSING_ARGS";
				throw err;
			}
			if (_nativeCanParse) return arguments.length === 1 ? _nativeCanParse(input) : _nativeCanParse(input, base);
			try {
				arguments.length === 1 ? new URLExport(input) : new URLExport(input, base);
				return true;
			} catch (e) {
				return false;
			}
		}
		function fileURLToPath(path) {
			if (typeof path !== "string" && !(typeof path === "object" && path !== null && typeof path.href === "string")) {
				var typeErr = /* @__PURE__ */ new TypeError("The \"path\" argument must be of type string or an instance of URL. Received " + (path === null ? "null" : typeof path === "object" ? "an instance of " + (path.constructor ? path.constructor.name : "Object") : "type " + typeof path));
				typeErr.code = "ERR_INVALID_ARG_TYPE";
				throw typeErr;
			}
			if (typeof path === "string" && !path.startsWith("file:") && !/^[A-Za-z][A-Za-z0-9+.-]+:/.test(path)) return path;
			var url = _coerceUrl(path);
			if (url && url.protocol && url.protocol !== "file:") {
				var schemeErr = /* @__PURE__ */ new TypeError("The URL must be of scheme file");
				schemeErr.code = "ERR_INVALID_URL_SCHEME";
				throw schemeErr;
			}
			var value = url.pathname || "";
			if (value.match(/%2[fF]/)) {
				var pathErr = /* @__PURE__ */ new TypeError("File URL path must not include encoded / characters");
				pathErr.code = "ERR_INVALID_FILE_URL_PATH";
				pathErr.input = url;
				throw pathErr;
			}
			if (value.match(/%5[cC]/)) {
				var bsErr = /* @__PURE__ */ new TypeError("File URL path must not include encoded \\ characters");
				bsErr.code = "ERR_INVALID_FILE_URL_PATH";
				bsErr.input = url;
				throw bsErr;
			}
			if (typeof value === "string" && value.length >= 4 && value.charAt(0) === "/" && value.charAt(2) === ":") value = value.slice(1);
			return decodeURIComponent(value);
		}
		function pathToFileURL(path) {
			if (path == null) throw new TypeError("Path is required");
			var pathValue = String(path).replace(/\\/g, "/");
			if (pathValue.charAt(0) === "/") return new URLExport("file://" + _encodeFileURLPath(pathValue));
			return new URLExport("file:///" + _encodeFileURLPath(pathValue));
		}
		function format(urlObj, options) {
			if (options !== void 0 && options !== null && typeof options !== "object") {
				var err = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + typeof options);
				err.code = "ERR_INVALID_ARG_TYPE";
				throw err;
			}
			var url = _coerceUrl(urlObj);
			var href = url.href;
			if (options) {
				if (options.auth === false) {
					var authority = url.username ? url.password ? url.username + ":" + url.password + "@" : url.username + "@" : "";
					if (authority) href = href.replace(authority, "");
				}
				if (options.fragment === false) {
					var hashIdx = href.indexOf("#");
					if (hashIdx !== -1) href = href.substring(0, hashIdx);
				}
				if (options.search === false) {
					var searchIdx = href.indexOf("?");
					var hashIdx2 = href.indexOf("#");
					if (searchIdx !== -1) href = href.substring(0, searchIdx) + (hashIdx2 !== -1 ? href.substring(hashIdx2) : "");
				}
			}
			return href;
		}
		function parse(value) {
			if (typeof value !== "string") {
				var err = /* @__PURE__ */ new TypeError("The \"url\" argument must be of type string. Received type " + (value === null ? "null" : typeof value));
				err.code = "ERR_INVALID_ARG_TYPE";
				throw err;
			}
			return URLExport.parse(value);
		}
		function resolve(from, to) {
			return new URLExport(to, from).href;
		}
		module.exports = {
			URL: URLExport,
			URLSearchParams: URLSearchParamsExport,
			createObjectURL: URLExport.createObjectURL,
			revokeObjectURL: URLExport.revokeObjectURL,
			format,
			parse,
			resolve,
			fileURLToPath,
			pathToFileURL,
			canParse: _wrappedCanParse,
			domainToASCII: typeof URLExport.domainToASCII === "function" ? URLExport.domainToASCII.bind(URLExport) : function(domain) {
				return domain;
			},
			domainToUnicode: typeof URLExport.domainToUnicode === "function" ? URLExport.domainToUnicode.bind(URLExport) : function(domain) {
				return domain;
			}
		};
		return;
	}
	typeof globalThis !== "undefined" && typeof globalThis.__exactUrlCtor === "function" ? globalThis.__exactUrlCtor : typeof globalThis.URL === "function" && globalThis.URL;
	typeof globalThis !== "undefined" && typeof globalThis.__exactUrlSearchParamsCtor === "function" ? globalThis.__exactUrlSearchParamsCtor : typeof globalThis.URLSearchParams === "function" && globalThis.URLSearchParams;
	function _encodeQueryValue(value) {
		return encodeURIComponent(String(value)).replace(/%20/g, "+").replace(/%2A/gi, "*");
	}
	function _toUSVString(value) {
		value = String(value);
		var out = "";
		for (var i = 0; i < value.length; i++) {
			var code = value.charCodeAt(i);
			if (code >= 55296 && code <= 56319) {
				var next = value.charCodeAt(i + 1);
				if (next >= 56320 && next <= 57343) {
					out += value[i] + value[i + 1];
					i++;
				} else out += "�";
			} else if (code >= 56320 && code <= 57343) out += "�";
			else out += value[i];
		}
		return out;
	}
	typeof TextDecoder === "function" && new TextDecoder("utf-8", { fatal: false });
	function _isHexCharCode(code) {
		return code >= 48 && code <= 57 || code >= 65 && code <= 70 || code >= 97 && code <= 102;
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
			for (var i = 0; i < bytes.length; i++) if (bytes[i] <= 127) fallback += String.fromCharCode(bytes[i]);
			else fallback += "�";
			return fallback;
		}
	}
	function _decode(value, plusAsSpace) {
		var input = String(value);
		if (plusAsSpace !== false) input = input.replace(/\+/g, " ");
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
		if (hex === "NaN") return "";
		return hex.replace(/^0+(?!$)/, "");
	}
	function _parseIPv4Segment(value) {
		var octets = [];
		var start = 0;
		for (var i = 0; i <= value.length; i++) if (i === value.length || value.charAt(i) === ".") {
			if (i === start) return null;
			var part = value.slice(start, i);
			start = i + 1;
			if (part.length > 3 || part.length === 0) return null;
			if (!/^[0-9]+$/.test(part)) return null;
			var code = Number.parseInt(part, 10);
			if (isNaN(code) || code < 0 || code > 255) return null;
			octets.push(code);
			if (octets.length > 4) return null;
		}
		if (octets.length !== 4) return null;
		return octets;
	}
	function _parseIPv4Hextets(value) {
		var octets = _parseIPv4Segment(value);
		if (!octets) return null;
		return [(octets[0] << 8) + octets[1], (octets[2] << 8) + octets[3]];
	}
	function _normalizeIPv6Host(value) {
		if (value.charAt(0) !== "[" || value.charAt(value.length - 1) !== "]") return null;
		var body = value.slice(1, -1);
		if (!body) return null;
		var compressed = body;
		if (body.indexOf(".") !== -1) {
			var lastColon = body.lastIndexOf(":");
			if (lastColon === -1) return null;
			var ipv4 = _parseIPv4Hextets(body.slice(lastColon + 1));
			if (!ipv4) return null;
			compressed = body.slice(0, lastColon) + ":" + _toHex4(ipv4[0]) + ":" + _toHex4(ipv4[1]);
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
		} else left = compressed.split(":");
		var segments = [];
		for (var i = 0; i < left.length; i++) {
			if (left[i] === "") return null;
			var parsed = parseInt(left[i], 16);
			if (isNaN(parsed) || parsed < 0 || parsed > 65535) return null;
			segments.push(parsed);
		}
		if (compressionIndex !== -1) {
			for (var k = 0; k < right.length; k++) {
				if (right[k] === "") return null;
				var rightValue = parseInt(right[k], 16);
				if (isNaN(rightValue) || rightValue < 0 || rightValue > 65535) return null;
				segments.push(rightValue);
			}
			var fillCount = 8 - left.length - right.length;
			if (fillCount < 0) return null;
			var padded = [];
			for (var r = 0; r < left.length; r++) padded.push(segments[r]);
			for (var s = 0; s < fillCount; s++) padded.push(0);
			for (var t = left.length; t < segments.length; t++) padded.push(segments[t]);
			segments = padded;
		}
		if (segments.length !== 8) return null;
		var bestStart = -1;
		var bestLength = 0;
		var bestFound = false;
		for (var a = 0; a < segments.length; a++) {
			if (segments[a] !== 0) continue;
			var end = a;
			while (end < segments.length && segments[end] === 0) end++;
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
					if (out === "") out += "::";
					else if (out.charAt(out.length - 1) !== ":") out += "::";
					else out += ":";
					b += bestLength - 1;
					continue;
				}
				if (b === 7 && b === bestStart + bestLength - 1) {
					out += "";
					continue;
				}
				if (out && out.charAt(out.length - 1) !== ":") out += ":";
				out += _toHex4(segments[b]);
			}
			if (out.slice(-1) === ":") out += "";
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
		return value >= "0" && value <= "9" || value >= "A" && value <= "F" || value >= "a" && value <= "f";
	}
	function _canonicalizeHost(value, protocol) {
		value = String(value);
		if (typeof value.normalize === "function") try {
			value = value.normalize("NFKC");
		} catch (_normalizeErr) {}
		value = value.replace(/[\u3002\uFF0E\uFF61]/g, ".");
		var isSpecial = protocol && URL._isSpecialProtocol(protocol.slice(0, -1));
		var isNonSpecial = protocol && !isSpecial;
		if (isSpecial && value.indexOf("%") !== -1) try {
			value = decodeURIComponent(value);
		} catch (_decodeHostErr) {}
		if (isSpecial) {
			value = value.replace(/\u00AD/g, "");
			if (/[^.]\.$/.test(value)) value = value.slice(0, -1);
		}
		var ipv6 = _normalizeIPv6Host(value);
		if (ipv6 !== null) return ipv6;
		if (isSpecial) {
			var ipv4Special = _normalizeIPv4Host(value);
			if (ipv4Special !== null) return ipv4Special;
			if (_endsInNumber(value)) return "";
			try {
				return require("punycode").toASCII(value).toLowerCase();
			} catch (e) {
				return value.toLowerCase();
			}
		}
		var ipv4 = _normalizeIPv4Host(value);
		if (ipv4 !== null) return ipv4;
		var out = "";
		for (var i = 0; i < value.length; i++) {
			var char = value.charAt(i);
			if (char.charCodeAt(0) >= 128 && isNonSpecial) {
				out += encodeURIComponent(char);
				continue;
			}
			if (char === "%" && i + 2 < value.length && _isHexChar(value.charAt(i + 1)) && _isHexChar(value.charAt(i + 2))) {
				out += "%" + value.charAt(i + 1) + value.charAt(i + 2);
				i += 2;
				continue;
			}
			out += isNonSpecial ? char : char.toLowerCase();
		}
		return out;
	}
	function _normalizeIPv4Host(value) {
		var host = String(value);
		var numericHost = _normalizeNumericIPv4Host(host);
		if (numericHost !== null && host.indexOf(".") === -1) return numericHost;
		if (host.indexOf(".") === -1) return null;
		var parts = host.split(".");
		if (parts.length < 2 || parts.length > 4) return null;
		var nums = [];
		var part;
		var i = 0;
		for (i = 0; i < parts.length; i++) {
			part = parts[i];
			if (part.length === 0) return null;
			var num = null;
			if (part.slice(0, 2).toLowerCase() === "0x" && part.length > 2) {
				if (!/^[0-9A-Fa-f]+$/.test(part.slice(2))) return null;
				num = parseInt(part.slice(2), 16);
			} else if (part.slice(0, 2).toLowerCase() === "0x") num = 0;
			else if (part.length > 1 && part.charAt(0) === "0") {
				if (!/^[0-7]+$/.test(part)) return null;
				num = parseInt(part, 8);
			} else {
				if (!/^[0-9]+$/.test(part)) return null;
				num = parseInt(part, 10);
			}
			if (isNaN(num) || num < 0 || num > 4294967295) return null;
			nums.push(num);
		}
		var result = 0;
		if (parts.length === 2) {
			if (nums[0] > 255 || nums[1] > 16777215) return null;
			result = (nums[0] << 24) + nums[1];
		} else if (parts.length === 3) {
			if (nums[0] > 255 || nums[1] > 255 || nums[2] > 65535) return null;
			result = (nums[0] << 24) + (nums[1] << 16) + nums[2];
		} else if (parts.length === 4) {
			if (nums[0] > 255 || nums[1] > 255 || nums[2] > 255 || nums[3] > 255) return null;
			return nums[0] + "." + nums[1] + "." + nums[2] + "." + nums[3];
		}
		var octet3 = result >> 16 & 255;
		var octet2 = result >> 8 & 255;
		var octet1 = result & 255;
		return (result >>> 24) + "." + octet3 + "." + octet2 + "." + octet1;
	}
	function _normalizeNumericIPv4Host(value) {
		var host = String(value);
		var base = 10;
		if (host.slice(0, 2).toLowerCase() === "0x") {
			if (host.length > 2 && !/^[0-9A-Fa-f]+$/.test(host.slice(2))) return null;
			base = 16;
		} else if (host.length > 1 && host.charAt(0) === "0") {
			if (!/^[0-7]+$/.test(host)) return null;
			base = 8;
		} else if (!/^[0-9]+$/.test(host)) return null;
		var number = base === 16 && host.length === 2 ? 0 : parseInt(host, base);
		if (isNaN(number) || number < 0 || number > 4294967295) return null;
		return (number >>> 24 & 255) + "." + (number >>> 16 & 255) + "." + (number >>> 8 & 255) + "." + (number & 255);
	}
	function _endsInNumber(host) {
		var value = String(host);
		if (value.charAt(value.length - 1) === ".") value = value.slice(0, -1);
		var parts = value.split(".");
		var last = parts[parts.length - 1];
		if (!last) return false;
		return /^0[xX][0-9A-Fa-f]*$/.test(last) || /^[0-9]+$/.test(last);
	}
	var _INVALID_IDNA_CHARS = " #%/:?@[\\]^|<>";
	function _stringFromCodePointSafe(codePoint) {
		if (typeof String.fromCodePoint === "function") return String.fromCodePoint(codePoint);
		if (codePoint <= 65535) return String.fromCharCode(codePoint);
		codePoint -= 65536;
		return String.fromCharCode((codePoint >> 10 & 1023) + 55296, (codePoint & 1023) + 56320);
	}
	function _containsForbiddenIdnaCodePoint(host) {
		if (!host) return false;
		if (host.indexOf("\0") !== -1) return true;
		if (typeof "".normalize !== "function") return false;
		for (var i = 0; i < host.length;) {
			var codePoint = typeof host.codePointAt === "function" ? host.codePointAt(i) : host.charCodeAt(i);
			if (codePoint <= 31 || codePoint === 127 || codePoint === 65533 || codePoint >= 64976 && codePoint <= 65007 || codePoint >= 65534 && (codePoint & 65534) === 65534) return true;
			var char = _stringFromCodePointSafe(codePoint);
			var normalized;
			try {
				normalized = char.normalize("NFKD");
			} catch (e) {
				normalized = char;
			}
			for (var j = 0; j < _INVALID_IDNA_CHARS.length; j++) if (normalized.indexOf(_INVALID_IDNA_CHARS.charAt(j)) !== -1) return true;
			i += codePoint > 65535 ? 2 : 1;
		}
		return false;
	}
	function _hasDisallowedPunycodeLabel(host) {
		if (!host || host.toLowerCase().indexOf("xn--") === -1) return false;
		var punycode;
		try {
			punycode = require("punycode");
		} catch (_punycodeLoadErr) {
			return false;
		}
		if (!punycode || typeof punycode.toUnicode !== "function") return false;
		var labels = String(host).split(".");
		for (var i = 0; i < labels.length; i++) {
			var label = labels[i];
			if (!/^xn--/i.test(label)) continue;
			var decodedLabel = punycode.toUnicode(label);
			if (!decodedLabel || decodedLabel.toLowerCase() === label.toLowerCase()) return true;
			if (_containsForbiddenIdnaCodePoint(decodedLabel)) return true;
			if (typeof "".normalize === "function") try {
				if (decodedLabel.normalize("NFKC") !== decodedLabel) return true;
			} catch (_punycodeNormalizeErr) {}
		}
		return false;
	}
	function _normalizePort(value) {
		if (!value) return "";
		if (!/^[0-9]+$/.test(value)) {
			var match = value.match(/^[0-9]+/);
			if (!match) return "";
			value = match[0];
		}
		return value.replace(/^0+(?=\d)/, "");
	}
	function _stripAsciiTabAndNewline(value) {
		return String(value).replace(/[\t\n\r]/g, "");
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
			if (code >= 0 && code < 32) {
				if (stripped[code]) continue;
				out += "%" + _toHex(code);
				continue;
			}
			out += value.charAt(i);
		}
		return out;
	}
	function _isC0ControlOrNonAscii(codePoint) {
		return codePoint <= 31 || codePoint > 126;
	}
	function _percentEncodeUrlComponent(value, shouldEncode, preservePercentTriples) {
		value = _toUSVString(value);
		var out = "";
		for (var i = 0; i < value.length;) {
			var char = value.charAt(i);
			var codePoint = value.charCodeAt(i);
			var nextIndex = i + 1;
			if (preservePercentTriples && char === "%" && nextIndex + 1 < value.length && _isHexChar(value.charAt(nextIndex)) && _isHexChar(value.charAt(nextIndex + 1))) {
				out += "%" + value.charAt(nextIndex) + value.charAt(nextIndex + 1);
				i += 3;
				continue;
			}
			if (codePoint >= 55296 && codePoint <= 56319 && nextIndex < value.length) {
				var low = value.charCodeAt(nextIndex);
				if (low >= 56320 && low <= 57343) {
					char += value.charAt(nextIndex);
					codePoint = (codePoint - 55296 << 10) + (low - 56320) + 65536;
					nextIndex += 1;
				}
			}
			if (codePoint === 9 || codePoint === 10 || codePoint === 13) {
				i = nextIndex;
				continue;
			}
			if (shouldEncode(codePoint, char)) try {
				var encodedChar = encodeURIComponent(char);
				if (encodedChar === char && codePoint <= 127) encodedChar = "%" + _toHex(codePoint);
				out += encodedChar;
			} catch (_encodeComponentErr) {
				out += encodeURIComponent(_toUSVString(char));
			}
			else out += char;
			i = nextIndex;
		}
		return out;
	}
	function _shouldEncodePathCodePoint(codePoint, char) {
		return _isC0ControlOrNonAscii(codePoint) || char === " " || char === "\"" || char === "#" || char === "?" || char === "<" || char === ">" || char === "^" || char === "`" || char === "{" || char === "}";
	}
	function _shouldEncodeQueryCodePoint(codePoint, char) {
		return _isC0ControlOrNonAscii(codePoint) || char === " " || char === "\"" || char === "#" || char === "<" || char === ">";
	}
	function _shouldEncodeFragmentCodePoint(codePoint, char) {
		return _isC0ControlOrNonAscii(codePoint) || char === " " || char === "\"" || char === "<" || char === ">" || char === "`";
	}
	function _shouldEncodeUserinfoCodePoint(codePoint, char) {
		return _shouldEncodePathCodePoint(codePoint, char) || char === "/" || char === ":" || char === ";" || char === "=" || char === "@" || char === "[" || char === "\\" || char === "]" || char === "^" || char === "|";
	}
	function _sanitizePathComponent(value) {
		return _percentEncodeUrlComponent(value, _shouldEncodePathCodePoint, true);
	}
	function _sanitizeQueryComponent(value, isSpecial) {
		return _percentEncodeUrlComponent(value, function(codePoint, char) {
			return _shouldEncodeQueryCodePoint(codePoint, char) || isSpecial && char === "'";
		}, true);
	}
	function _sanitizeFragmentComponent(value) {
		return _percentEncodeUrlComponent(value, _shouldEncodeFragmentCodePoint, true);
	}
	function _sanitizeOpaquePathComponent(value) {
		return _percentEncodeUrlComponent(value, function(codePoint) {
			return _isC0ControlOrNonAscii(codePoint);
		}, true);
	}
	function _trimUrlInput(value) {
		value = String(value);
		var start = 0;
		var end = value.length;
		while (start < end && value.charCodeAt(start) <= 32) start += 1;
		while (end > start && value.charCodeAt(end - 1) <= 32) end -= 1;
		return value.slice(start, end);
	}
	function _sanitizeUserinfoComponent(value) {
		return _percentEncodeUrlComponent(value, _shouldEncodeUserinfoCodePoint, true);
	}
	function _sanitizeHostComponent(value, protocol) {
		value = String(value);
		var out = "";
		var isSpecialProtocol = !!(protocol && protocol.slice && URL._isSpecialProtocol(protocol.slice(0, -1)));
		for (var i = 0; i < value.length; i++) {
			var code = value.charCodeAt(i);
			if (code === 0 || protocol === "https:" && code === 31) return null;
			if (code >= 0 && code < 32) {
				if (code === 9 || code === 10 || code === 13) continue;
				if (isSpecialProtocol) return null;
				out += "%" + _toHex(code);
				continue;
			}
			if (code === 127) {
				if (isSpecialProtocol) return null;
				out += "%7F";
				continue;
			}
			if (code === 160 || code === 12288) {
				out += " ";
				continue;
			}
			if (code === 8203 || code === 8288 || code === 65279) continue;
			out += value.charAt(i);
		}
		return out;
	}
	function _hasForbiddenNonSpecialHostCodePoint(value) {
		var host = String(value);
		if (!host) return false;
		if (host.charAt(0) === "[") return false;
		var colonIndex = host.lastIndexOf(":");
		if (colonIndex !== -1 && /^[0-9]*$/.test(host.slice(colonIndex + 1))) host = host.slice(0, colonIndex);
		return /[ #/:<>?@[\\\]^|]/.test(host);
	}
	function _parseHostInput(value, isSpecial) {
		for (var i = 0; i < value.length; i++) {
			var c = value.charCodeAt(i);
			if (c === 47 || c === 63 || c === 35 || isSpecial && c === 92) return value.slice(0, i);
		}
		return value;
	}
	function _stripProtocolControlChars(value) {
		value = String(value);
		var out = "";
		for (var i = 0; i < value.length; i++) {
			var code = value.charCodeAt(i);
			if (code === 9 || code === 10 || code === 13) continue;
			out += value.charAt(i);
		}
		return out;
	}
	function _hasInvalidPercentEscape(value) {
		for (var i = 0; i < value.length; i++) {
			if (value.charAt(i) !== "%") continue;
			if (i + 2 >= value.length || !_isHexChar(value.charAt(i + 1)) || !_isHexChar(value.charAt(i + 2))) return true;
			i += 2;
		}
		return false;
	}
	function _makeIterator(params, mapFn) {
		var idx = 0;
		var iterator = { next: function() {
			var current = params._params || params;
			if (idx >= current.length) return { done: true };
			var value = current[idx++];
			if (typeof mapFn === "function") value = mapFn(value);
			return {
				value,
				done: false
			};
		} };
		if (typeof Symbol !== "undefined" && Symbol.iterator) iterator[Symbol.iterator] = function() {
			return iterator;
		};
		return iterator;
	}
	/**
	* Create a TypeError matching the WHATWG URL spec error format.
	* Redacts base URLs that contain credentials.
	*/
	function _makeURLError(input, baseStr) {
		var msg;
		if (baseStr !== void 0) {
			var displayBase = /:[^/].*@/.test(String(baseStr)) ? "<redacted>" : JSON.stringify(String(baseStr));
			msg = JSON.stringify(String(input)) + " cannot be parsed as a URL against " + displayBase;
		} else msg = JSON.stringify(String(input)) + " cannot be parsed as a URL";
		var err = new TypeError(msg);
		err.code = "ERR_INVALID_URL";
		err.input = String(input);
		return err;
	}
	function _isSingleDotPathSegment(segment) {
		var lower = String(segment || "").toLowerCase();
		return lower === "." || lower === "%2e";
	}
	function _isDoubleDotPathSegment(segment) {
		var lower = String(segment || "").toLowerCase();
		return lower === ".." || lower === ".%2e" || lower === "%2e." || lower === "%2e%2e";
	}
	var _legacyUrlParseDeprecationWarned = false;
	var _legacyInvalidUrlWarned = false;
	function _shouldFallbackFromWhatwgInvalidUrlError(value) {
		return typeof value === "string" && (value.indexOf(":.") !== -1 || /^git\+ssh:\/\/[^/]+:[^/]/i.test(value) || /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/\//.test(value));
	}
	function _emitLegacyInvalidUrlWarnings(value) {
		if (typeof process !== "object" || !process || typeof process.emitWarning !== "function") return;
		if (!_legacyUrlParseDeprecationWarned) {
			_legacyUrlParseDeprecationWarned = true;
			var legacyWarn = /* @__PURE__ */ new Error("`url.parse()` behavior is not standardized and prone to errors that have security implications. Use the WHATWG URL API instead. CVEs are not issued for `url.parse()` vulnerabilities.");
			legacyWarn.name = "DeprecationWarning";
			legacyWarn.code = "DEP0169";
			process.emitWarning(legacyWarn);
		}
		if (!_legacyInvalidUrlWarned) {
			_legacyInvalidUrlWarned = true;
			var invalidWarn = /* @__PURE__ */ new Error("The URL " + value + " is invalid. Future versions of Node.js will throw an error.");
			invalidWarn.name = "DeprecationWarning";
			invalidWarn.code = "DEP0170";
			process.emitWarning(invalidWarn);
		}
	}
	function _markLegacyMalformedAuthority(result, value) {
		if (result && typeof value === "string" && result.protocol && result.protocol !== "file:" && _slashedProtocol[result.protocol] && result.host && typeof result.pathname === "string" && result.pathname.slice(0, 2) === "//" && /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/\/[^/?#]/.test(value)) try {
			Object.defineProperty(result, "__exactLegacyMalformedAuthority", {
				value: true,
				configurable: true,
				enumerable: false,
				writable: false
			});
		} catch (_) {}
		return result;
	}
	function URL(input, base) {
		if (!(this instanceof URL)) return new URL(input, base);
		if (arguments.length === 0) {
			var missingArgsErr = /* @__PURE__ */ new TypeError("The \"url\" argument must be specified");
			missingArgsErr.code = "ERR_MISSING_ARGS";
			throw missingArgsErr;
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
		var baseStr = base !== void 0 ? String(base) : void 0;
		var baseUrl = null;
		if (base instanceof URL) baseUrl = base;
		else if (typeof base === "string" || base && typeof base === "object" && base.href) try {
			baseUrl = new URL(String(base));
		} catch (e) {
			throw _makeURLError(String(input), baseStr);
		}
		var inputStr = String(input);
		this.__originalInput = inputStr;
		this.__baseStr = baseStr;
		this._parse(inputStr, baseUrl, baseStr);
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
			if (hostPart === "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			var colonIndex = userinfo.indexOf(":");
			if (colonIndex !== -1) {
				urlObj._username = _sanitizeUserinfoComponent(userinfo.slice(0, colonIndex));
				urlObj._password = _sanitizeUserinfoComponent(userinfo.slice(colonIndex + 1));
			} else urlObj._username = _sanitizeUserinfoComponent(userinfo);
		}
		var sanitizedHost = _sanitizeHostComponent(hostPart, urlObj._protocol);
		if (sanitizedHost === null) {
			if (authority !== "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			urlObj._hostname = "";
			urlObj._port = "";
			return;
		}
		hostPart = sanitizedHost;
		if (authority !== "" && hostPart === "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (URL._isSpecialProtocol(urlObj._protocol.slice(0, -1)) && authority !== "" && hostPart === "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (!URL._isSpecialProtocol(urlObj._protocol.slice(0, -1)) && hostPart !== "") {
			var nonSpecialValidationHost = hostPart;
			if (nonSpecialValidationHost.charAt(0) === "[") {
				if (nonSpecialValidationHost.indexOf("]") === -1) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			} else {
				var nonSpecialColonIndex = nonSpecialValidationHost.lastIndexOf(":");
				if (nonSpecialColonIndex !== -1) {
					var nonSpecialPort = nonSpecialValidationHost.slice(nonSpecialColonIndex + 1);
					if (/^[0-9]*$/.test(nonSpecialPort)) nonSpecialValidationHost = nonSpecialValidationHost.slice(0, nonSpecialColonIndex);
				}
				if (_hasForbiddenNonSpecialHostCodePoint(nonSpecialValidationHost)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			}
		}
		if (URL._isSpecialProtocol(urlObj._protocol.slice(0, -1)) && _hasInvalidPercentEscape(hostPart)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (URL._isSpecialProtocol(urlObj._protocol.slice(0, -1)) && hostPart) {
			var validationHost = hostPart;
			if (validationHost.charAt(0) === "[") {
				var validationBracketEnd = validationHost.indexOf("]");
				if (validationBracketEnd === -1) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
				validationHost = validationHost.slice(0, validationBracketEnd + 1);
			} else {
				var validationColonIndex = validationHost.lastIndexOf(":");
				if (validationColonIndex !== -1) {
					var validationPort = validationHost.slice(validationColonIndex + 1);
					if (/^[0-9]*$/.test(validationPort)) validationHost = validationHost.slice(0, validationColonIndex);
				}
			}
			if (validationHost.charAt(0) === "[") {
				if (_normalizeIPv6Host(validationHost) === null || validationHost.indexOf("\0") !== -1) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			} else {
				try {
					validationHost = _decode(validationHost, false);
				} catch (_validationHostDecodeErr) {}
				if (_containsForbiddenIdnaCodePoint(validationHost)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			}
		}
		if (hostPart.charAt(0) === "[") {
			var bracketEnd = hostPart.indexOf("]");
			if (bracketEnd !== -1) {
				var normalizedIpv6 = _normalizeIPv6Host(hostPart.slice(0, bracketEnd + 1));
				if (normalizedIpv6 === null) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
				urlObj._hostname = normalizedIpv6;
				var afterBracket = hostPart.slice(bracketEnd + 1);
				if (afterBracket.charAt(0) === ":") {
					if (urlObj._protocol === "file:") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
					var bracketPort = afterBracket.slice(1);
					if (bracketPort && !/^[0-9]*$/.test(bracketPort)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
					urlObj._port = _normalizePort(bracketPort);
				} else if (afterBracket !== "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
			} else throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		} else {
			var colonIndex = hostPart.lastIndexOf(":");
			if (colonIndex !== -1) {
				var portStr = hostPart.slice(colonIndex + 1);
				if (urlObj._protocol === "file:") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
				if (hostPart.slice(0, colonIndex) === "") throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
				if (portStr && !/^[0-9]*$/.test(portStr)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
				urlObj._hostname = _canonicalizeHost(hostPart.slice(0, colonIndex), urlObj._protocol);
				urlObj._port = _normalizePort(portStr);
			} else {
				urlObj._hostname = _canonicalizeHost(hostPart, urlObj._protocol);
				urlObj._port = "";
			}
		}
		if (urlObj._port && String(Number(urlObj._port)) !== urlObj._port) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (URL._isSpecialProtocol(urlObj._protocol.slice(0, -1)) && hostPart !== "" && (!urlObj._hostname || urlObj._hostname === "xn--" || _hasDisallowedPunycodeLabel(urlObj._hostname))) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (URL._SPECIAL_PROTOCOLS[urlObj._protocol.slice(0, -1)] && urlObj._port === URL._SPECIAL_PROTOCOLS[urlObj._protocol.slice(0, -1)]) urlObj._port = "";
		if (urlObj._port && (Number(urlObj._port) > 65535 || String(Number(urlObj._port)) !== urlObj._port)) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (urlObj._protocol === "file:" && urlObj._port) throw _makeURLError(urlObj.__originalInput, urlObj.__baseStr);
		if (urlObj._protocol === "file:" && urlObj._hostname === "localhost") urlObj._hostname = "";
		urlObj._protocol.slice(0, -1);
	};
	URL._normalizePath = function(path) {
		if (!path) return "/";
		var segments = path.split("/");
		var onlySlashAndDotPath = /^(\/{2,})(?:(?:\.{1,2})\/?)*$/.exec(path);
		var preserveTrailingSlash = path.charAt(path.length - 1) === "/" || _isSingleDotPathSegment(segments[segments.length - 1]) || _isDoubleDotPathSegment(segments[segments.length - 1]);
		var normalized = [];
		for (var i = 0; i < segments.length; i++) {
			var segment = segments[i];
			if (_isSingleDotPathSegment(segment)) continue;
			if (_isDoubleDotPathSegment(segment)) {
				if (normalized.length === 2 && normalized[0] === "" && /^[A-Za-z]:$/.test(normalized[1])) continue;
				if (normalized.length > 1 || normalized.length === 1 && normalized[0] !== "") normalized.pop();
			} else normalized.push(segment);
		}
		var result = normalized.join("/");
		if (result.charAt(0) !== "/") result = "/" + result;
		if (result === "") result = "/";
		if (onlySlashAndDotPath) {
			var parentSegmentMatches = path.match(/\.\.(?=\/|$)/g);
			var preservedSlashCount = onlySlashAndDotPath[1].length - (parentSegmentMatches ? parentSegmentMatches.length : 0);
			if (preservedSlashCount < 1) preservedSlashCount = 1;
			result = new Array(preservedSlashCount + 1).join("/");
		}
		if (preserveTrailingSlash && result.charAt(result.length - 1) !== "/") result += "/";
		return result;
	};
	URL.prototype._parse = function(input, base, baseStr) {
		var isUndefined = typeof input === "undefined";
		var url;
		this._hasEmptyAuthority = false;
		this._username = "";
		this._password = "";
		this._hostname = "";
		this._port = "";
		if (isUndefined) {
			if (!base) throw _makeURLError(input, baseStr);
			if (base._isOpaque) if (typeof base.pathname === "string" && base.pathname.charAt(0) === "/" && base.pathname.lastIndexOf("/") !== -1) url = base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + "undefined";
			else throw _makeURLError(input, baseStr);
			else url = "undefined";
		} else url = _trimUrlInput(input);
		url = _stripAsciiTabAndNewline(url);
		var protocolMatch = URL._PROTO_RE.exec(url);
		var hasScheme = false;
		if (protocolMatch) {
			hasScheme = true;
			this._protocol = protocolMatch[1].toLowerCase() + ":";
			url = protocolMatch[2];
		} else if (base && base.protocol) {
			this._protocol = base.protocol;
			this._isOpaque = false;
		} else throw _makeURLError(input, baseStr);
		var isSpecial = URL._isSpecialProtocol(this._protocol.slice(0, -1));
		if (hasScheme && isSpecial && base && base.protocol !== this._protocol && url.slice(0, 2) !== "//" && (url === "" || url.charAt(0) === "?" || url.charAt(0) === "#")) throw _makeURLError(input, baseStr);
		if (!hasScheme && base && base._isOpaque) {
			url.indexOf("#");
			if (url === "") {
				this._isOpaque = true;
				this._pathname = base.pathname || "";
				this._search = base.search || "";
				this._hash = "";
				return;
			}
			if (url.charAt(0) === "#") {
				this._isOpaque = true;
				this._pathname = base.pathname || "";
				this._search = base.search || "";
				this._hash = url === "#" ? "#" : url.slice(1) ? "#" + _sanitizeFragmentComponent(url.slice(1)) : "";
				return;
			}
			throw _makeURLError(input, baseStr);
		}
		if (!isSpecial) while (url.charCodeAt(0) > 0 && url.charCodeAt(0) <= 32 && url.charCodeAt(0) !== 32) url = url.slice(1);
		if (isSpecial) {
			var _queryPos = url.indexOf("?");
			var _hashPos = url.indexOf("#");
			var _replaceEnd = url.length;
			if (_queryPos !== -1 && _queryPos < _replaceEnd) _replaceEnd = _queryPos;
			if (_hashPos !== -1 && _hashPos < _replaceEnd) _replaceEnd = _hashPos;
			url = url.slice(0, _replaceEnd).replace(/\\/g, "/") + url.slice(_replaceEnd);
		}
		var isSpecialNoFile = isSpecial && this._protocol !== "file:";
		var startsWithSpecialAuthority = url.slice(0, 2) === "//" && (isSpecial || url.charAt(2) !== "/");
		var startsWithEmptyNonSpecialAuthority = !isSpecial && url.slice(0, 3) === "///" && (hasScheme || !!base);
		var hasAuthority = startsWithSpecialAuthority || startsWithEmptyNonSpecialAuthority || isSpecialNoFile && hasScheme && (!base || base.protocol !== this._protocol) && url.slice(0, 2) !== "//";
		if (hasAuthority) {
			if (url.slice(0, 2) === "//") url = url.slice(2);
			else if (url.charAt(0) === "/") url = url.slice(1);
			if (isSpecial && this._protocol !== "file:") while (url.charAt(0) === "/") url = url.slice(1);
			var pathStart = url.indexOf("/");
			var queryStart = url.indexOf("?");
			var hashStart = url.indexOf("#");
			var authorityEnd = url.length;
			if (pathStart !== -1) authorityEnd = pathStart;
			if (queryStart !== -1 && queryStart < authorityEnd) authorityEnd = queryStart;
			if (hashStart !== -1 && hashStart < authorityEnd) authorityEnd = hashStart;
			var authority = url.slice(0, authorityEnd);
			url = url.slice(authorityEnd);
			if (!isSpecial && authority === "") this._hasEmptyAuthority = true;
			else if (isSpecial && this._protocol !== "file:" && authority === "") throw _makeURLError(input, baseStr);
			if (this._protocol === "file:") {
				var decodedAuthority = authority;
				try {
					decodedAuthority = _decode(authority, false);
				} catch (_fileAuthorityDecodeErr) {}
				if (authority !== decodedAuthority && /^[A-Za-z](?:\:|\|)$/.test(decodedAuthority)) throw _makeURLError(input, baseStr);
			}
			if (this._protocol === "file:" && /^[A-Za-z](?:\:|\|)$/.test(authority)) {
				this._hostname = "";
				this._port = "";
				url = "/" + authority.replace("|", ":") + url;
			} else URL._parseAuthority(this, authority);
		} else if (base && isSpecial) {
			if (this._protocol === "file:" && (!hasScheme || /^\/?[A-Za-z](?:\:|\|)(?:\/|$)/.test(url))) {
				this._hostname = base.hostname || "";
				this._port = "";
			} else if (this._protocol !== "file:") {
				this._hostname = base.hostname;
				this._port = base.port;
				this._username = base.username;
				this._password = base.password;
			}
		} else if (base && !isSpecial && base._hostname && !hasAuthority && !hasScheme) {
			this._hostname = base.hostname;
			this._port = base.port;
			this._username = base.username;
			this._password = base.password;
		} else if (base && base._hasEmptyAuthority && this._protocol === base.protocol) this._hasEmptyAuthority = true;
		if (hasScheme) this._isOpaque = !isSpecial && !hasAuthority && url.charAt(0) !== "/";
		var queryIndex = url.indexOf("?");
		var hashIndex = url.indexOf("#");
		var pathEnd = url.length;
		if (queryIndex !== -1 && queryIndex < pathEnd) pathEnd = queryIndex;
		if (hashIndex !== -1 && hashIndex < pathEnd) pathEnd = hashIndex;
		var path = url.slice(0, pathEnd);
		var inheritedPathFromBase = false;
		var isFileWindowsDrivePath = this._protocol === "file:" && path && /^\/?[A-Za-z](?:\:|\|)(?:\/|$)/.test(path);
		if (this._protocol === "file:" && base && typeof base.pathname === "string" && /^\/[A-Za-z]:(?:\/|$)/.test(base.pathname) && path && path.charAt(0) === "/" && !isFileWindowsDrivePath) {
			path = base.pathname.slice(0, 3) + path;
			isFileWindowsDrivePath = true;
		}
		if (isFileWindowsDrivePath) {
			if (path.charAt(0) !== "/") path = "/" + path;
			path = path.replace(/^\/([A-Za-z])\|/, "/$1:");
		}
		if (base && !this._isOpaque && path && path.charAt(0) !== "/" && !isFileWindowsDrivePath) path = base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + path;
		else if (!this._isOpaque && !path && base && !hasAuthority) {
			path = base.pathname;
			inheritedPathFromBase = true;
		}
		if (this._isOpaque) {
			this._pathname = _sanitizeOpaquePathComponent(path || "");
			if (this._pathname.slice(-1) === " ") this._pathname = this._pathname.slice(0, -1) + "%20";
		} else if (path === "" && !isSpecial && (hasAuthority || inheritedPathFromBase && !!this._hostname && base && base.pathname === "")) this._pathname = "";
		else {
			var normalizedPath = URL._normalizePath(_sanitizePathComponent(path || "/"));
			if (this._protocol === "file:" && !hasAuthority && !base && (path.slice(0, 2) === "//" || path.slice(0, 3) === ".//") && normalizedPath.slice(0, 2) !== "//") normalizedPath = "/" + normalizedPath;
			this._pathname = normalizedPath;
		}
		if (queryIndex !== -1 && (hashIndex === -1 || queryIndex < hashIndex)) {
			var queryEnd = hashIndex !== -1 ? hashIndex : url.length;
			var queryValue = url.slice(queryIndex + 1, queryEnd);
			if (queryValue) this._search = "?" + _sanitizeQueryComponent(queryValue, isSpecial);
			else this._search = "?";
		} else if (inheritedPathFromBase && base && !hasAuthority) this._search = base.search || "";
		else this._search = "";
		if (hashIndex !== -1) {
			var fragmentValue = url.slice(hashIndex + 1);
			this._hash = "#" + (fragmentValue ? _sanitizeFragmentComponent(fragmentValue) : "");
		} else this._hash = "";
	};
	URL.prototype._setPathFromString = function(pathname) {
		this._pathname = URL._normalizePath(_sanitizePathComponent(String(pathname)));
		if (this._searchParams) {
			var replacement = new URLSearchParams(this._search);
			this._searchParams._params = replacement._params;
		}
	};
	URL.prototype._syncSearchParams = function() {
		if (!this._searchParams) return;
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
			if (scheme === "blob") try {
				var innerURL = new URL(this.href.slice(5));
				var innerScheme = innerURL.protocol.slice(0, -1);
				if (innerScheme === "file") return innerURL.host ? "file://" + innerURL.host : "file://";
				if (innerScheme === "http" || innerScheme === "https" || innerScheme === "ftp" || innerScheme === "ws" || innerScheme === "wss") return innerURL.origin;
				return "null";
			} catch (e) {
				return "null";
			}
			if (scheme === "file") return "null";
			if (scheme === "http" || scheme === "https" || scheme === "ftp" || scheme === "ws" || scheme === "wss") return this._protocol + "//" + String(this.host).toLowerCase();
			return "null";
		},
		set: function(value) {
			throw new TypeError("Cannot set origin");
		}
	});
	Object.defineProperty(URL.prototype, "protocol", {
		configurable: true,
		get: function() {
			return this._protocol;
		},
		set: function(value) {
			var protocol = _stripProtocolControlChars(value).toLowerCase();
			var colonIndex = protocol.indexOf(":");
			if (colonIndex !== -1) protocol = protocol.slice(0, colonIndex + 1);
			if (protocol.slice(-1) !== ":") protocol += ":";
			if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:$/.test(protocol)) return;
			if (URL._isSpecialProtocol(this._protocol.slice(0, -1)) !== URL._isSpecialProtocol(protocol.slice(0, -1))) return;
			if (protocol !== "file:" && this._protocol === "file:" && (this._hostname === "" || this._hostname === "localhost")) return;
			if (protocol === "file:" && (this._username || this._password || this._port)) return;
			this._protocol = protocol;
			var defaultPort = URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
			if (defaultPort && this._port === defaultPort) this._port = "";
		}
	});
	Object.defineProperty(URL.prototype, "username", {
		configurable: true,
		get: function() {
			return _sanitizeControlComponent(this._username || "");
		},
		set: function(value) {
			if (this._protocol === "file:" || this._protocol === "unix:") return;
			if (!this._hostname) return;
			this._username = _sanitizeUserinfoComponent(value);
		}
	});
	Object.defineProperty(URL.prototype, "password", {
		configurable: true,
		get: function() {
			return _sanitizeControlComponent(this._password || "");
		},
		set: function(value) {
			if (this._protocol === "file:" || this._protocol === "unix:") return;
			if (!this._hostname) return;
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
			if (this._protocol === "file:") {
				var fileHostInput = _sanitizeHostComponent(value, this._protocol);
				if (fileHostInput === null) return;
				fileHostInput = _parseHostInput(fileHostInput, true);
				if (fileHostInput === "") {
					this._hostname = "";
					this._port = "";
					return;
				}
				var fileColonIndex = fileHostInput.lastIndexOf(":");
				if (fileColonIndex !== -1 && fileHostInput.charAt(0) !== "[") {
					if (fileHostInput.slice(fileColonIndex + 1) !== "") return;
					fileHostInput = fileHostInput.slice(0, fileColonIndex);
				}
				try {
					fileHostInput = _decode(fileHostInput, false);
				} catch (_fileHostDecodeErr) {}
				if (_canonicalizeHost(fileHostInput, this._protocol) === "localhost") {
					this._hostname = "";
					this._port = "";
				}
				return;
			}
			var input = _sanitizeHostComponent(value, this._protocol);
			if (input === null) return;
			if (this._isOpaque && this._pathname.charAt(0) !== "/") return;
			var rawInput = String(value);
			var isSpecial = !!URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
			var hostInput = _parseHostInput(input, isSpecial);
			if (hostInput === "") {
				if (!isSpecial && (rawInput !== "" && _stripAsciiTabAndNewline(rawInput) === "" || (this._hostname || this._pathname && this._pathname.slice(0, 2) === "//") && !this._username && !this._password && !this._port)) {
					this._hostname = "";
					this._port = "";
					this._hasEmptyAuthority = true;
				}
				return;
			}
			if (!isSpecial && hostInput.charAt(0) === ":") return;
			if (hostInput.indexOf(" ") !== -1) return;
			if (hostInput.indexOf("@") !== -1) return;
			if (hostInput.indexOf("\\") !== -1 && !isSpecial) return;
			if (hostInput.charAt(0) === "[" && hostInput.indexOf("]") !== -1) {
				var closingBracket = hostInput.indexOf("]");
				var hasPort = hostInput.charAt(closingBracket + 1) === ":";
				var normalizedHost = _normalizeIPv6Host(hostInput.slice(0, closingBracket + 1));
				if (normalizedHost === null) return;
				this._hostname = normalizedHost;
				this._hasEmptyAuthority = false;
				if (hasPort) {
					var port = hostInput.slice(closingBracket + 2);
					var parsedPort = _normalizePort(port);
					if (parsedPort) {
						var numericPort = Number(parsedPort);
						if (!isNaN(numericPort) && numericPort <= 65535) this._port = parsedPort;
					} else if (port === "") this._port = "";
					if (this._port && URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)] && this._port === URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)]) this._port = "";
				} else this._port = "";
			} else {
				var colonIndex = hostInput.lastIndexOf(":");
				if (colonIndex !== -1) {
					if (isSpecial && (hostInput.indexOf("<") !== -1 || hostInput.indexOf(">") !== -1)) return;
					var hostNameValue = _canonicalizeHost(hostInput.slice(0, colonIndex), this._protocol);
					if (isSpecial && (!hostNameValue || hostNameValue === "xn--" || _hasDisallowedPunycodeLabel(hostNameValue))) return;
					this._hostname = hostNameValue;
					this._hasEmptyAuthority = false;
					if (colonIndex < hostInput.length - 1) {
						var portInput = hostInput.slice(colonIndex + 1);
						var parsedPort = _normalizePort(portInput);
						if (parsedPort) {
							var numericPort = Number(parsedPort);
							if (!isNaN(numericPort) && numericPort <= 65535) this._port = parsedPort;
						} else if (portInput === "") this._port = "";
						if (this._port && URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)] && this._port === URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)]) this._port = "";
					}
				} else if (hostInput !== "") {
					if (isSpecial && (hostInput.indexOf("<") !== -1 || hostInput.indexOf(">") !== -1)) return;
					var normalizedNamedHost = _canonicalizeHost(hostInput, this._protocol);
					if (isSpecial && (!normalizedNamedHost || normalizedNamedHost === "xn--" || _hasDisallowedPunycodeLabel(normalizedNamedHost))) return;
					this._hostname = normalizedNamedHost;
					this._hasEmptyAuthority = false;
				} else {
					this._hostname = "";
					this._port = "";
					this._hasEmptyAuthority = true;
				}
			}
		}
	});
	Object.defineProperty(URL.prototype, "hostname", {
		configurable: true,
		get: function() {
			return this._hostname;
		},
		set: function(value) {
			if (this._protocol === "file:") {
				var fileHostname = _sanitizeHostComponent(value, this._protocol);
				if (fileHostname === null) return;
				fileHostname = _parseHostInput(fileHostname, true);
				if (fileHostname === "") {
					this._hostname = "";
					this._port = "";
					return;
				}
				try {
					fileHostname = _decode(fileHostname, false);
				} catch (_fileHostnameDecodeErr) {}
				if (_canonicalizeHost(fileHostname, this._protocol) === "localhost") {
					this._hostname = "";
					this._port = "";
				}
				return;
			}
			var input = _sanitizeHostComponent(value, this._protocol);
			if (input === null) return;
			if (this._isOpaque && this._pathname.charAt(0) !== "/") return;
			var rawInput = String(value);
			var isSpecial = !!URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
			var hostInput = _parseHostInput(input, isSpecial);
			if (!isSpecial && hostInput === "") {
				if (rawInput !== "" && _stripAsciiTabAndNewline(rawInput) === "" || (rawInput === "" || /[\/?#]/.test(rawInput)) && (this._hostname || this._pathname && this._pathname.slice(0, 2) === "//") && !this._username && !this._password && !this._port) {
					this._hostname = "";
					this._port = "";
					this._hasEmptyAuthority = true;
				}
				return;
			}
			if (hostInput === "" || hostInput.indexOf(" ") !== -1) return;
			if (hostInput.indexOf("@") !== -1) return;
			if (!isSpecial && (hostInput.indexOf("#") !== -1 || hostInput.indexOf("/") !== -1 || hostInput.indexOf("?") !== -1)) {
				this._hostname = "";
				this._port = "";
				return;
			}
			if (isSpecial && (hostInput.indexOf(":") !== -1 && hostInput.charAt(0) !== "[" || hostInput.indexOf("<") !== -1 || hostInput.indexOf(">") !== -1)) return;
			if (hostInput.indexOf("\\") !== -1 && !isSpecial) return;
			if (hostInput.charAt(0) === "[") {
				var normalizedHost = _normalizeIPv6Host(hostInput);
				if (normalizedHost === null) return;
				this._hostname = normalizedHost;
				this._hasEmptyAuthority = false;
				return;
			}
			var normalizedHostname = _canonicalizeHost(hostInput, this._protocol);
			if (isSpecial && (!normalizedHostname || normalizedHostname === "xn--" || _hasDisallowedPunycodeLabel(normalizedHostname))) return;
			this._hostname = normalizedHostname;
			this._hasEmptyAuthority = false;
		}
	});
	Object.defineProperty(URL.prototype, "port", {
		configurable: true,
		get: function() {
			return this._port;
		},
		set: function(value) {
			if (this._protocol === "file:" || !this._hostname || this._isOpaque && this._pathname.charAt(0) !== "/") return;
			var port = String(value);
			if (port === "") {
				this._port = "";
				return;
			}
			var strippedPort = _stripAsciiTabAndNewline(port);
			var parsedPort = "";
			var hadNonDigits = false;
			for (var i = 0; i < port.length; i++) {
				var code = port.charCodeAt(i);
				if (code >= 48 && code <= 57) parsedPort += port.charAt(i);
				else if (code === 9 || code === 10 || code === 13) continue;
				else {
					hadNonDigits = true;
					break;
				}
			}
			if (parsedPort === "") {
				if (strippedPort === "") return;
				if (hadNonDigits) return;
				this._port = "";
				return;
			}
			port = parsedPort;
			if (Number(port) > 65535) return;
			var defaultPort = URL._SPECIAL_PROTOCOLS[this._protocol.slice(0, -1)];
			if (!port || port === defaultPort) this._port = "";
			else this._port = port;
		}
	});
	Object.defineProperty(URL.prototype, "pathname", {
		configurable: true,
		get: function() {
			return this._pathname;
		},
		set: function(value) {
			if (this._isOpaque && this._pathname.charAt(0) !== "/") return;
			var pathname = _stripAsciiTabAndNewline(String(value));
			if (URL._isSpecialProtocol(this._protocol.slice(0, -1))) {
				if (pathname === "") pathname = "/";
				pathname = pathname.replace(/\\/g, "/");
				this._pathname = URL._normalizePath(_sanitizePathComponent(pathname));
			} else if (pathname === "") this._pathname = !this._hostname && !this._hasEmptyAuthority ? "/" : "";
			else {
				if (!this._isOpaque && pathname.charAt(0) !== "/") pathname = "/" + pathname;
				pathname = _sanitizePathComponent(pathname);
				this._pathname = URL._normalizePath(pathname);
			}
			if (this._searchParams) {
				var parsedSearch = new URLSearchParams(this._search);
				this._searchParams._params = parsedSearch._params;
			}
		}
	});
	Object.defineProperty(URL.prototype, "search", {
		configurable: true,
		get: function() {
			var search = this._search || "";
			return search === "?" ? "" : search;
		},
		set: function(value) {
			var search = _stripAsciiTabAndNewline(String(value));
			if (!search) this._search = "";
			else if (search === "?") this._search = "?";
			else {
				if (search.charAt(0) === "?") search = search.slice(1);
				this._search = search ? "?" + _sanitizeQueryComponent(search, URL._isSpecialProtocol(this._protocol.slice(0, -1))) : "";
			}
			if (this._searchParams) {
				var parsedSearch = new URLSearchParams(this._search);
				this._searchParams._params = parsedSearch._params;
			}
		}
	});
	Object.defineProperty(URL.prototype, "hash", {
		configurable: true,
		get: function() {
			var hash = this._hash || "";
			return hash === "#" ? "" : hash;
		},
		set: function(value) {
			var hash = _stripAsciiTabAndNewline(String(value));
			if (!hash) {
				this._hash = "";
				return;
			}
			if (hash === "#") {
				this._hash = "#";
				return;
			}
			if (hash.charAt(0) === "#") hash = hash.slice(1);
			this._hash = "#" + (hash ? _sanitizeFragmentComponent(hash) : "");
		}
	});
	URL.prototype.toString = function() {
		var href = this._protocol;
		if (this._protocol === "file:" && !this._hostname) href += "//";
		if (this._hasEmptyAuthority && !this._hostname) href += "//";
		if (!this._hasEmptyAuthority && !this._hostname && !this._isOpaque && !URL._isSpecialProtocol(this._protocol.slice(0, -1)) && (this._pathname === "" || this._pathname === null)) href += "//";
		if (this._hostname) {
			href += "//";
			if (this._username || this._password) {
				if (this._username) {
					href += this._username;
					if (this._password) href += ":" + this._password;
				} else href += ":" + this._password;
				href += "@";
			}
			href += this._hostname;
			if (this._port) href += ":" + this._port;
		} else if (!this._hasEmptyAuthority && !this._isOpaque && !URL._isSpecialProtocol(this._protocol.slice(0, -1)) && typeof this._pathname === "string" && this._pathname.slice(0, 2) === "//") href += "/.";
		href += this._pathname;
		href += this._search;
		href += this._hash;
		return href;
	};
	URL.prototype.toJSON = function() {
		return this.href;
	};
	URL.canParse = function canParse(input, base) {
		if (arguments.length === 0) {
			var _e = /* @__PURE__ */ new TypeError("The \"url\" argument must be specified");
			_e.code = "ERR_MISSING_ARGS";
			throw _e;
		}
		try {
			if (arguments.length === 1) new URL(input);
			else new URL(input, base);
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
		if (!(this instanceof URLSearchParams)) return new URLSearchParams(init);
		this._params = [];
		this._url = null;
		if (init == null) return;
		if (typeof init === "string") {
			var str = init;
			if (str.charAt(0) === "?") str = str.slice(1);
			if (str) {
				var pairs = str.split("&");
				for (var i = 0; i < pairs.length; i++) {
					var pair = pairs[i];
					if (pair === "") continue;
					var eq = pair.indexOf("=");
					if (eq !== -1) this._params.push([_decode(pair.slice(0, eq)), _decode(pair.slice(eq + 1))]);
					else this._params.push([_decode(pair), ""]);
				}
			}
			return;
		}
		if (typeof init === "object" || typeof init === "function") {
			if (typeof DOMException !== "undefined" && init === DOMException.prototype) throw new TypeError("Invalid URLSearchParams initializer");
			if (typeof init === "function" && (typeof DOMException !== "undefined" && init === DOMException || init.name === "DOMException")) {
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
				for (var i = 0; i < constants.length; i++) this._params.push([constants[i], String(i + 1)]);
				return;
			}
			if (typeof Symbol !== "undefined" && typeof init[Symbol.iterator] === "function") {
				var iterator = init[Symbol.iterator]();
				var entry = iterator.next();
				while (!entry.done) {
					var pair = entry.value;
					if (!pair || typeof pair.length !== "number" || pair.length !== 2) throw new TypeError("Invalid URLSearchParams initializer");
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
				if (typeof init === "function" && (key === "length" || key === "name" || key === "prototype" || isNaN(init[key]) || !isFinite(init[key]))) continue;
				if (typeof init === "object" && typeof init[key] === "undefined") continue;
				if (typeof init === "function" && typeof init[key] === "number" && isFinite(init[key])) {
					if (typeof keyToIndex[keyValue] === "number") normalized[keyToIndex[keyValue]][1] = String(init[key]);
					else {
						keyToIndex[keyValue] = normalized.length;
						normalized.push([keyValue, String(init[key])]);
					}
					continue;
				}
				if (typeof keyToIndex[keyValue] === "number") normalized[keyToIndex[keyValue]][1] = _toUSVString(init[key]);
				else {
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
		if (this._url) this._url._updateSearch(this.toString());
	};
	URLSearchParams.prototype.get = function(name) {
		name = _toUSVString(name);
		for (var i = 0; i < this._params.length; i++) if (this._params[i][0] === name) return this._params[i][1];
		return null;
	};
	URLSearchParams.prototype.getAll = function(name) {
		name = _toUSVString(name);
		var result = [];
		for (var i = 0; i < this._params.length; i++) if (this._params[i][0] === name) result.push(this._params[i][1]);
		return result;
	};
	URLSearchParams.prototype.has = function(name, value) {
		name = _toUSVString(name);
		if (typeof value === "undefined") return this.get(name) !== null;
		for (var i = 0; i < this._params.length; i++) if (this._params[i][0] === name && this._params[i][1] === _toUSVString(value)) return true;
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
			} else newParams.push(param);
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
		var hasValue = arguments.length > 1 && value !== void 0;
		value = _toUSVString(value);
		var newParams = [];
		var valueString = String(value);
		for (var i = 0; i < this._params.length; i++) {
			var param = this._params[i];
			if (param[0] !== name) {
				newParams.push(param);
				continue;
			}
			if (hasValue && param[1] !== valueString) newParams.push(param);
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
		return this._params.map(function(pair) {
			return _encodeQueryValue(pair[0]) + "=" + _encodeQueryValue(pair[1]);
		}).join("&");
	};
	URLSearchParams.prototype.forEach = function(callback, thisArg) {
		for (var i = 0; i < this._params.length; i++) callback.call(thisArg, this._params[i][1], this._params[i][0], this);
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
	if (typeof Symbol !== "undefined" && Symbol.iterator) URLSearchParams.prototype[Symbol.iterator] = URLSearchParams.prototype.entries;
	Object.defineProperty(URLSearchParams.prototype, "size", {
		configurable: true,
		enumerable: true,
		get: function() {
			return this._params.length;
		}
	});
	Object.defineProperty(URLSearchParams.prototype, "length", {
		configurable: true,
		enumerable: true,
		get: function() {
			return this._params.length;
		}
	});
	var URLExport = URL;
	var URLSearchParamsExport = URLSearchParams;
	if (typeof globalThis !== "undefined") {
		globalThis.__exactUrlCtor = URLExport;
		globalThis.__exactUrlSearchParamsCtor = URLSearchParamsExport;
		try {
			Object.defineProperty(globalThis, "URL", {
				configurable: true,
				writable: true,
				enumerable: true,
				value: URLExport
			});
		} catch (_setUrlGlobalErr) {
			globalThis.URL = URLExport;
		}
		try {
			Object.defineProperty(globalThis, "URLSearchParams", {
				configurable: true,
				writable: true,
				enumerable: true,
				value: URLSearchParamsExport
			});
		} catch (_setUrlSearchParamsGlobalErr) {
			globalThis.URLSearchParams = URLSearchParamsExport;
		}
	}
	function _coerceUrl(input) {
		if (input == null) throw new TypeError("Expected URL or string");
		if (typeof input === "string") return new URLExport(input);
		if (typeof input === "object") return input;
		throw new TypeError("Expected URL or string");
	}
	function fileURLToPath(path) {
		if (path === null || path === void 0 || typeof path === "boolean" || typeof path === "number" || typeof path === "function" || typeof path === "symbol" || typeof path === "object" && path !== null && typeof path.href !== "string") {
			var typeMsg;
			if (path === null) typeMsg = "null";
			else if (path === void 0) typeMsg = "undefined";
			else if (typeof path === "object") typeMsg = "an instance of " + (path.constructor ? path.constructor.name : "Object");
			else typeMsg = "type " + typeof path + " (" + String(path) + ")";
			var typeErr = /* @__PURE__ */ new TypeError("The \"path\" argument must be of type string or an instance of URL. Received " + typeMsg);
			typeErr.code = "ERR_INVALID_ARG_TYPE";
			throw typeErr;
		}
		var urlObj;
		if (typeof path === "string") try {
			urlObj = new URL(path);
		} catch (e) {
			var parseErr = /* @__PURE__ */ new TypeError("Invalid URL: " + path);
			parseErr.code = "ERR_INVALID_URL";
			throw parseErr;
		}
		else urlObj = path;
		if (!urlObj.protocol || urlObj.protocol !== "file:") {
			var schemeErr = /* @__PURE__ */ new TypeError("The URL must be of scheme file");
			schemeErr.code = "ERR_INVALID_URL_SCHEME";
			throw schemeErr;
		}
		var host = urlObj.hostname || "";
		if (host && host !== "localhost") {
			var hostErr = /* @__PURE__ */ new TypeError("File URL host must be \"localhost\" or empty on this platform");
			hostErr.code = "ERR_INVALID_FILE_URL_HOST";
			throw hostErr;
		}
		var value = urlObj.pathname || "";
		if (value.match(/%2[fF]/)) {
			var pathErr = /* @__PURE__ */ new TypeError("File URL path must not include encoded / characters");
			Object.defineProperty(pathErr, "code", {
				value: "ERR_INVALID_FILE_URL_PATH",
				writable: true,
				enumerable: true,
				configurable: true
			});
			Object.defineProperty(pathErr, "input", {
				value: urlObj,
				writable: true,
				enumerable: true,
				configurable: true
			});
			throw pathErr;
		}
		if (value.match(/%5[cC]/)) {
			var bsErr = /* @__PURE__ */ new TypeError("File URL path must not include encoded \\ characters");
			Object.defineProperty(bsErr, "code", {
				value: "ERR_INVALID_FILE_URL_PATH",
				writable: true,
				enumerable: true,
				configurable: true
			});
			Object.defineProperty(bsErr, "input", {
				value: urlObj,
				writable: true,
				enumerable: true,
				configurable: true
			});
			throw bsErr;
		}
		if (typeof value === "string" && value.length >= 3 && value[0] === "/" && value[2] === ":") value = value.slice(1);
		return decodeURIComponent(value);
	}
	function _encodeFileURLPathChar(ch) {
		var cp = ch.charCodeAt(0);
		if (cp === 37) return "%25";
		if (cp === 63) return "%3F";
		if (cp === 35) return "%23";
		if (cp === 92) return "%5C";
		if (cp === 32) return "%20";
		if (cp === 34) return "%22";
		if (cp === 60) return "%3C";
		if (cp === 62) return "%3E";
		if (cp === 123) return "%7B";
		if (cp === 125) return "%7D";
		if (cp === 124) return "%7C";
		if (cp === 94) return "%5E";
		if (cp === 126) return "%7E";
		if (cp === 91) return "%5B";
		if (cp === 93) return "%5D";
		if (cp === 96) return "%60";
		if (cp < 32 || cp === 127) {
			var hex = cp.toString(16).toUpperCase();
			return "%" + (hex.length < 2 ? "0" + hex : hex);
		}
		if (cp > 126) {
			var bytes = [];
			if (cp < 2048) bytes = [192 | cp >> 6, 128 | cp & 63];
			else if (cp < 65536) bytes = [
				224 | cp >> 12,
				128 | cp >> 6 & 63,
				128 | cp & 63
			];
			else bytes = [
				240 | cp >> 18,
				128 | cp >> 12 & 63,
				128 | cp >> 6 & 63,
				128 | cp & 63
			];
			var r = "";
			for (var bi = 0; bi < bytes.length; bi++) {
				var bh = bytes[bi].toString(16).toUpperCase();
				r += "%" + (bh.length < 2 ? "0" + bh : bh);
			}
			return r;
		}
		return ch;
	}
	function _byteToHex2(b) {
		var s = b.toString(16).toUpperCase();
		return s.length < 2 ? "0" + s : s;
	}
	function _encodeFileURLPath(p) {
		var result = "";
		for (var i = 0; i < p.length; i++) {
			var cp = p.charCodeAt(i);
			if (cp >= 55296 && cp <= 56319 && i + 1 < p.length) {
				var next = p.charCodeAt(i + 1);
				if (next >= 56320 && next <= 57343) {
					var full = (cp - 55296 << 10) + (next - 56320) + 65536;
					var b0 = 240 | full >> 18;
					var b1 = 128 | full >> 12 & 63;
					var b2 = 128 | full >> 6 & 63;
					var b3 = 128 | full & 63;
					result += "%" + _byteToHex2(b0) + "%" + _byteToHex2(b1) + "%" + _byteToHex2(b2) + "%" + _byteToHex2(b3);
					i++;
					continue;
				}
			}
			result += _encodeFileURLPathChar(p.charAt(i));
		}
		return result;
	}
	function _legacyFormat(urlObj) {
		var protocol = urlObj.protocol || "";
		var slashes = urlObj.slashes;
		var auth = urlObj.auth;
		var hostname = urlObj.hostname || "";
		var port = urlObj.port;
		var pathname = urlObj.pathname || "";
		var search = urlObj.search || "";
		var hash = urlObj.hash || "";
		var host = urlObj.host || "";
		if (protocol && protocol.slice(-1) !== ":") protocol += ":";
		var result = protocol;
		var isSpecialProto = /^(https?|ftp|gopher|file):$/i.test(protocol);
		if (slashes === true || slashes !== false && isSpecialProto && (!!(host || hostname) || pathname.charAt(0) === "/")) result += "//";
		if (auth) result += encodeAuth(auth) + "@";
		if (host) result += host;
		else {
			result += hostname;
			if (port) result += ":" + port;
		}
		if (pathname && pathname.charAt(0) !== "/" && (host || hostname || slashes) && result && result.charAt(result.length - 1) !== "/") result += "/";
		result += pathname;
		if (search && search.charAt(0) !== "?") result += "?" + search;
		else result += search;
		if (hash && hash.charAt(0) !== "#") result += "#" + hash;
		else result += hash;
		return result;
	}
	function _legacyResolveHref(urlObj) {
		if (!urlObj.slashes && !urlObj.auth && !urlObj.host && !urlObj.hostname && urlObj.pathname && urlObj.pathname.charAt(0) !== "/") {
			var schemePathHref = urlObj.protocol || "";
			schemePathHref += urlObj.pathname;
			if (urlObj.search) schemePathHref += urlObj.search;
			if (urlObj.hash) schemePathHref += urlObj.hash;
			return schemePathHref;
		}
		if (urlObj.protocol === "file:" && !urlObj.slashes && !urlObj.auth && !urlObj.host && !urlObj.hostname) {
			var fileHref = "file:";
			if (urlObj.pathname) fileHref += urlObj.pathname;
			if (urlObj.search) fileHref += urlObj.search;
			if (urlObj.hash) fileHref += urlObj.hash;
			return fileHref;
		}
		var formatted = _legacyFormat(urlObj);
		if (urlObj.protocol && /^(https?|ftp|gopher|file|ws|wss):$/i.test(urlObj.protocol) && urlObj.slashes && !urlObj.auth && !urlObj.host && !urlObj.hostname && (!urlObj.pathname || urlObj.pathname === "/")) try {
			return new URLExport(formatted).href;
		} catch (_legacyResolveHrefErr) {}
		return formatted;
	}
	function encodeAuth(str) {
		var result = "";
		for (var i = 0; i < str.length; i++) {
			var ch = str.charAt(i);
			var cp = str.charCodeAt(i);
			if (cp < 33 || cp === 127 || ch === "\"" || ch === "<" || ch === ">" || ch === "`" || ch === " " || ch === "{" || ch === "}" || ch === "|" || ch === "\\" || ch === "^" || ch === "~" || ch === "@") {
				var hex = cp.toString(16).toUpperCase();
				result += "%" + (hex.length === 1 ? "0" + hex : hex);
			} else result += ch;
		}
		return result;
	}
	function format(urlObj, options) {
		if (urlObj === null || urlObj === void 0 || typeof urlObj === "boolean" || typeof urlObj === "number" || typeof urlObj === "function" || typeof urlObj === "symbol") {
			var typeMsg;
			if (urlObj === null) typeMsg = "null";
			else if (urlObj === void 0) typeMsg = "undefined";
			else if (typeof urlObj === "function") typeMsg = "function " + (urlObj.name || "");
			else typeMsg = "type " + typeof urlObj + " (" + String(urlObj) + ")";
			var typeErr = /* @__PURE__ */ new TypeError("The \"urlObject\" argument must be one of type object or string. Received " + typeMsg);
			typeErr.code = "ERR_INVALID_ARG_TYPE";
			throw typeErr;
		}
		if (typeof urlObj === "string") try {
			return _legacyFormat(parse(urlObj));
		} catch (e) {
			return urlObj;
		}
		if (urlObj instanceof URL || urlObj instanceof URLExport || urlObj.constructor && urlObj.constructor.name === "URL" && typeof urlObj.searchParams === "object") {
			if (options !== void 0 && options !== null && typeof options !== "object") {
				var optErr = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + typeof options + " (" + String(options) + ")");
				optErr.code = "ERR_INVALID_ARG_TYPE";
				throw optErr;
			}
			var href = urlObj.href;
			if (options) {
				var unicode = options.unicode !== void 0 ? !!options.unicode : false;
				var includeAuth = options.auth !== void 0 ? !!options.auth : true;
				var includeFragment = options.fragment !== void 0 ? !!options.fragment : true;
				var includeSearch = options.search !== void 0 ? !!options.search : true;
				if (unicode && urlObj.hostname) try {
					var punycode = require("punycode");
					if (typeof punycode.toUnicode === "function") {
						var unicodeHost = punycode.toUnicode(urlObj.hostname);
						if (unicodeHost !== urlObj.hostname) href = href.replace(urlObj.hostname, unicodeHost);
					}
				} catch (e) {}
				if (!includeAuth) {
					var userinfo = urlObj.username ? urlObj.password ? urlObj.username + ":" + urlObj.password + "@" : urlObj.username + "@" : "";
					if (userinfo) href = href.replace(userinfo, "");
				}
				if (!includeFragment) {
					var hashIdx = href.indexOf("#");
					if (hashIdx !== -1) href = href.substring(0, hashIdx);
				}
				if (!includeSearch) {
					var searchIdx = href.indexOf("?");
					var hashIdx2 = href.indexOf("#");
					if (searchIdx !== -1) href = href.substring(0, searchIdx) + (hashIdx2 !== -1 ? href.substring(hashIdx2) : "");
				}
			}
			return href;
		}
		if (typeof urlObj === "object") return _legacyFormat(urlObj);
		return String(urlObj);
	}
	function Url() {
		this.protocol = null;
		this.slashes = null;
		this.auth = null;
		this.host = null;
		this.port = null;
		this.hostname = null;
		this.hash = null;
		this.search = null;
		this.query = null;
		this.pathname = null;
		this.path = null;
		this.href = "";
	}
	var _LEGACY_HOST_ENDING = [
		32,
		34,
		60,
		62,
		96
	];
	function _legacyParseHost(hostStr) {
		var out = {
			auth: null,
			host: null,
			hostname: null,
			port: null,
			pathPrefix: ""
		};
		var rest = hostStr;
		var atIdx = rest.lastIndexOf("@");
		if (atIdx !== -1) {
			out.auth = rest.slice(0, atIdx);
			rest = rest.slice(atIdx + 1);
		}
		var hostEnd = rest.length;
		for (var i = 0; i < rest.length; i++) {
			var c = rest.charCodeAt(i);
			if (_LEGACY_HOST_ENDING.indexOf(c) !== -1) {
				hostEnd = i;
				break;
			}
		}
		var hostPart = rest.slice(0, hostEnd);
		out.pathPrefix = rest.slice(hostEnd);
		if (hostPart.charAt(0) === "[") {
			var closeBracket = hostPart.indexOf("]");
			if (closeBracket !== -1) {
				out.hostname = hostPart.slice(1, closeBracket).toLowerCase();
				var afterBracket = hostPart.slice(closeBracket + 1);
				if (afterBracket.charAt(0) === ":") {
					var portStr = afterBracket.slice(1);
					if (portStr) out.port = portStr;
				}
				out.host = hostPart.slice(0, closeBracket + 1).toLowerCase() + (out.port ? ":" + out.port : "");
			}
		} else {
			var colonIdx = hostPart.lastIndexOf(":");
			if (colonIdx !== -1) {
				var portPart = hostPart.slice(colonIdx + 1);
				if (/^\d+$/.test(portPart)) {
					out.hostname = hostPart.slice(0, colonIdx).toLowerCase();
					out.port = portPart;
				} else out.hostname = hostPart.toLowerCase();
			} else out.hostname = hostPart.toLowerCase();
		}
		if (out.host == null) out.host = (out.hostname || "") + (out.port ? ":" + out.port : "");
		if (!out.host) out.host = null;
		if (!out.hostname) out.hostname = null;
		return out;
	}
	function _legacyEncodePath(str) {
		var result = "";
		for (var i = 0; i < str.length; i++) {
			var cp = str.charCodeAt(i);
			if (cp === 34) {
				result += "%22";
				continue;
			}
			if (cp === 32) {
				result += "%20";
				continue;
			}
			if (cp === 60) {
				result += "%3C";
				continue;
			}
			if (cp === 62) {
				result += "%3E";
				continue;
			}
			if (cp === 96) {
				result += "%60";
				continue;
			}
			if (cp === 123) {
				result += "%7B";
				continue;
			}
			if (cp === 125) {
				result += "%7D";
				continue;
			}
			if (cp === 124) {
				result += "%7C";
				continue;
			}
			if (cp === 94) {
				result += "%5E";
				continue;
			}
			if (cp === 92) {
				result += "%5C";
				continue;
			}
			result += str.charAt(i);
		}
		return result;
	}
	var _hostlessStr = {
		"javascript:": true,
		"javascript": true
	};
	function parse(value, parseQueryString, slashesDenoteHost) {
		if (typeof value !== "string") {
			var received;
			if (value == null) received = " Received " + String(value);
			else if (typeof value === "function") received = " Received function " + value.name;
			else if (typeof value === "object") if (value.constructor && value.constructor.name) received = " Received an instance of " + value.constructor.name;
			else received = " Received " + String(value);
			else received = " Received type " + typeof value + " (" + String(value) + ")";
			var err = /* @__PURE__ */ new TypeError("The \"url\" argument must be of type string." + received);
			err.code = "ERR_INVALID_ARG_TYPE";
			throw err;
		}
		var result = new Url();
		result.href = value;
		if (!slashesDenoteHost && /^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(value) && (/^(https?|ftp|file|wss?):(?:\/\/|\\)/i.test(value) || /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(value))) try {
			var _protoEndIdx = value.indexOf("//");
			if (_protoEndIdx !== -1) {
				var _afterSlashes = value.slice(_protoEndIdx + 2);
				var _pathStart = _afterSlashes.search(/[/?#]/);
				if ((_pathStart !== -1 ? _afterSlashes.slice(0, _pathStart) : _afterSlashes).indexOf("\0") !== -1) {
					var _nullErr = /* @__PURE__ */ new TypeError("Invalid URL: " + value);
					_nullErr.code = "ERR_INVALID_URL";
					_nullErr.input = value;
					throw _nullErr;
				}
			}
			var _authAtIdx = value.indexOf("@");
			if (_authAtIdx !== -1) {
				var _protoEnd = value.indexOf("//");
				if (_protoEnd !== -1) {
					var _authPart = value.slice(_protoEnd + 2, _authAtIdx);
					decodeURIComponent(_authPart.replace(/\+/g, "%2B"));
				}
			}
			var u = new URL(value);
			var _rawHostname = u.hostname;
			if (_rawHostname && /["' <>]/.test(_rawHostname)) throw new Error("Invalid hostname");
			result.protocol = u.protocol || null;
			var _protoStr = u.protocol || "";
			var _protoSlashIdx = value.toLowerCase().indexOf(_protoStr.toLowerCase());
			var _firstTwo = (_protoSlashIdx >= 0 ? value.slice(_protoSlashIdx + _protoStr.length) : "").slice(0, 2);
			result.slashes = _firstTwo === "//" || _firstTwo === "\\\\" ? true : null;
			var _hasAuthority = result.slashes === true;
			result.host = u.host ? u.host : _hasAuthority ? u.host : null;
			result.port = u.port || null;
			result.hostname = u.hostname ? u.hostname : _hasAuthority ? u.hostname : null;
			if (typeof result.hostname === "string" && result.hostname.charAt(0) === "[" && result.hostname.charAt(result.hostname.length - 1) === "]") result.hostname = result.hostname.slice(1, -1);
			result.hash = u.hash || null;
			result.search = u.search || null;
			result.pathname = u.pathname || null;
			result.path = (u.pathname || "") + (u.search || "") || null;
			if (u.username || u.password) result.auth = (u.username || "") + (u.password ? ":" + u.password : "");
			result.href = _legacyFormat(result);
			if (parseQueryString) result.query = require("querystring").parse(u.search ? u.search.slice(1) : "");
			else result.query = u.search ? u.search.slice(1) : null;
			return _markLegacyMalformedAuthority(result, value);
		} catch (e) {
			if (e instanceof URIError) throw e;
			if (e && e.code === "ERR_INVALID_URL" && e.input !== void 0) if (_shouldFallbackFromWhatwgInvalidUrlError(value)) _emitLegacyInvalidUrlWarnings(value);
			else throw e;
		}
		var rest = value.trim();
		var protoMatch = /^([a-zA-Z][a-zA-Z0-9+\-.]*):/.exec(rest);
		var proto = null;
		var isSpecial = false;
		if (protoMatch) {
			proto = protoMatch[0].toLowerCase();
			result.protocol = proto;
			rest = rest.slice(proto.length);
			isSpecial = /^(https?|ftp|gopher|file):$/.test(proto);
		}
		var hashIdx = rest.indexOf("#");
		var _hashFragment = null;
		if (hashIdx !== -1) {
			_hashFragment = rest.slice(hashIdx);
			rest = rest.slice(0, hashIdx);
		}
		var _firstTwoLeg = rest.slice(0, 2);
		var hasSlashes = _firstTwoLeg === "//";
		var hasBackslashes = !hasSlashes && isSpecial && _firstTwoLeg === "\\\\";
		if ((hasSlashes || hasBackslashes) && (proto || slashesDenoteHost)) {
			result.slashes = true;
			rest = rest.slice(2);
			if (hasBackslashes) rest = rest.replace(/\\/g, "/");
		} else if (!proto && slashesDenoteHost && rest.slice(0, 2) === "//") {
			result.slashes = true;
			rest = rest.slice(2);
		} else if (isSpecial && rest.charAt(0) === "\\") {
			result.slashes = true;
			rest = "/" + rest.slice(1).replace(/\\/g, "/");
		} else if (proto && !isSpecial && !_hostlessStr[proto]) {
			result.slashes = null;
			var _qIdx3 = rest.indexOf("?");
			if (_qIdx3 !== -1) {
				result.search = rest.slice(_qIdx3);
				if (parseQueryString) result.query = require("querystring").parse(result.search.slice(1));
				else result.query = result.search.slice(1);
				rest = rest.slice(0, _qIdx3);
			}
			var _slashIdx = rest.indexOf("/");
			var _hostStr, _pathStr;
			if (_slashIdx !== -1) {
				_hostStr = rest.slice(0, _slashIdx);
				_pathStr = rest.slice(_slashIdx);
			} else {
				_hostStr = rest;
				_pathStr = null;
			}
			result.host = _hostStr || null;
			result.hostname = _hostStr || null;
			result.pathname = _pathStr || null;
			if (_hashFragment !== null) result.hash = _hashFragment.replace(/\\/g, "%5C");
			result.path = (_pathStr || "") + (result.search || "") || null;
			result.href = proto + (_hostStr || "") + (_pathStr || "") + (result.search || "") + (result.hash || "");
			return _markLegacyMalformedAuthority(result, value);
		}
		if (_hashFragment !== null) result.hash = _hashFragment.replace(/\\/g, "%5C");
		var qIdx = rest.indexOf("?");
		if (qIdx !== -1) {
			result.search = rest.slice(qIdx);
			if (parseQueryString) result.query = require("querystring").parse(result.search.slice(1));
			else result.query = result.search.slice(1);
			rest = rest.slice(0, qIdx);
		}
		if (!result.slashes && proto && !isSpecial) if (!rest) result.pathname = null;
		else if (rest.charAt(0) === "/") {
			result.host = "";
			result.hostname = "";
			result.pathname = rest;
		} else {
			var opaqueSlashIdx = rest.indexOf("/");
			if (opaqueSlashIdx === -1) {
				result.host = rest;
				result.hostname = rest;
				result.pathname = null;
			} else {
				result.host = rest.slice(0, opaqueSlashIdx);
				result.hostname = result.host;
				result.pathname = rest.slice(opaqueSlashIdx);
			}
			result.port = null;
			result.auth = null;
		}
		else if (result.slashes) {
			var pathIdx = rest.indexOf("/");
			var authorityStr, pathStr;
			if (pathIdx !== -1) {
				authorityStr = rest.slice(0, pathIdx);
				pathStr = rest.slice(pathIdx);
			} else {
				authorityStr = rest;
				pathStr = "";
			}
			var hostInfo = _legacyParseHost(authorityStr);
			if (hostInfo.auth) try {
				decodeURIComponent(hostInfo.auth);
			} catch (uriErr) {
				if (uriErr instanceof URIError) throw uriErr;
			}
			result.auth = hostInfo.auth || null;
			var _emptyAuth = authorityStr === "" && !hostInfo.auth;
			result.host = hostInfo.host !== null ? hostInfo.host : _emptyAuth ? "" : null;
			result.hostname = hostInfo.hostname !== null ? hostInfo.hostname : _emptyAuth ? "" : null;
			result.port = hostInfo.port || null;
			var pathFull = _legacyEncodePath(hostInfo.pathPrefix) + pathStr;
			if (!pathFull && isSpecial) pathFull = "/";
			result.pathname = pathFull || null;
		} else result.pathname = rest || null;
		result.path = (result.pathname || "") + (result.search || "") || null;
		var h = proto || "";
		if (result.slashes) h += "//";
		if (result.auth) h += result.auth + "@";
		if (result.host) h += result.host;
		if (result.pathname) h += result.pathname;
		if (result.search) h += result.search;
		if (result.hash) h += result.hash;
		result.href = h || value;
		if (parseQueryString && result.query === null) result.query = require("querystring").parse("");
		return _markLegacyMalformedAuthority(result, value);
	}
	function resolve(from, to) {
		if (!from) return to;
		var resolvedFrom = parse(from, false, true);
		var needsLegacyCanonicalize = resolvedFrom && resolvedFrom.protocol && resolvedFrom.protocol !== "file:" && _slashedProtocol[resolvedFrom.protocol] && resolvedFrom.host === "" && typeof resolvedFrom.pathname === "string" && resolvedFrom.pathname.charAt(0) === "/" && String(from).indexOf(":///") !== -1;
		var resolved = format(resolveObject(resolvedFrom, to));
		return needsLegacyCanonicalize ? format(resolved) : resolved;
	}
	var _slashedProtocol = {
		"http": true,
		"http:": true,
		"https": true,
		"https:": true,
		"ftp": true,
		"ftp:": true,
		"gopher": true,
		"gopher:": true,
		"file": true,
		"file:": true,
		"ws": true,
		"ws:": true,
		"wss": true,
		"wss:": true
	};
	var _hostlessProtocol = {
		"javascript": true,
		"javascript:": true
	};
	function _spliceOne(list, index) {
		for (var i = index, k = i + 1; k < list.length; i++, k++) list[i] = list[k];
		list.pop();
	}
	function _normalizeLegacyPath(pathname, preserveTrailingSlash) {
		pathname = String(pathname || "");
		var segments = pathname.split("/");
		var absolute = pathname.charAt(0) === "/";
		var normalized = [];
		for (var i = 0; i < segments.length; i++) {
			var segment = segments[i];
			var isFirst = i === 0;
			var isLast = i === segments.length - 1;
			if (segment === "") {
				if (isFirst || !isLast) normalized.push("");
				continue;
			}
			if (segment === ".") continue;
			if (segment === "..") {
				var last = normalized.length ? normalized[normalized.length - 1] : null;
				if (last && last !== "..") normalized.pop();
				else if (!absolute) normalized.push("..");
				continue;
			}
			normalized.push(segment);
		}
		if (absolute && normalized[0] !== "") normalized.unshift("");
		if (preserveTrailingSlash && normalized[normalized.length - 1] !== "") normalized.push("");
		if (!normalized.length) return absolute ? "/" : "";
		return normalized.join("/") || (absolute ? "/" : "");
	}
	function _preserveLegacyFileUrlShape(source, result) {
		if (source && result && source.protocol === "file:" && source.slashes === null && source.host === null && result.protocol === "file:" && result.host === "" && result.hostname === "") {
			result.slashes = null;
			result.host = null;
			result.hostname = null;
			result.href = _legacyResolveHref(result);
		}
		return result;
	}
	function resolveObject(source, relative) {
		if (source === "") return relative;
		if (typeof source === "string") source = parse(source, false, true);
		if (!source || typeof source !== "object") return parse(relative, false, true);
		var relativeSource = relative;
		if (typeof relative === "string") relative = parse(relative, false, true);
		else if (!relative || typeof relative !== "object") relative = parse(String(relative), false, true);
		else relativeSource = format(relative);
		if (source.__exactLegacyMalformedAuthority) {
			var malformedSourceHref = String(source.protocol || "") + "///";
			if (source.auth) malformedSourceHref += source.auth + "@";
			malformedSourceHref += source.host || "";
			malformedSourceHref += source.pathname || "";
			malformedSourceHref += source.search || "";
			malformedSourceHref += source.hash || "";
			var malformedRelativeHref = typeof relativeSource === "string" ? relativeSource : format(relative);
			return parse(resolve(malformedSourceHref, malformedRelativeHref), false, false);
		}
		if (relativeSource && relative.protocol && relative.protocol === source.protocol && relativeSource.indexOf(source.protocol) === 0) {
			var relativeRemainder = relativeSource.slice(source.protocol.length);
			if (relativeSource.indexOf(source.protocol + "//") !== 0 && (relativeRemainder === "" || relativeRemainder.charAt(0) === "/" || relativeRemainder.charAt(0) === "?" || relativeRemainder.charAt(0) === "#")) {
				var inheritedRelative = new Url();
				inheritedRelative.protocol = source.protocol;
				inheritedRelative.slashes = source.slashes;
				inheritedRelative.auth = source.auth;
				inheritedRelative.host = source.host;
				inheritedRelative.hostname = source.hostname;
				inheritedRelative.port = source.port;
				var remainderHashIndex = relativeRemainder.indexOf("#");
				var remainderQueryIndex = relativeRemainder.indexOf("?");
				var remainderPathEnd = relativeRemainder.length;
				if (remainderQueryIndex !== -1 && remainderQueryIndex < remainderPathEnd) remainderPathEnd = remainderQueryIndex;
				if (remainderHashIndex !== -1 && remainderHashIndex < remainderPathEnd) remainderPathEnd = remainderHashIndex;
				var rawPathname = relativeRemainder.slice(0, remainderPathEnd);
				var hasExplicitPathname = rawPathname && rawPathname.charAt(0) === "/";
				if (hasExplicitPathname) inheritedRelative.pathname = _normalizeLegacyPath(rawPathname, /(?:\/|^)(?:\.{1,2})\/?$/.test(rawPathname) || rawPathname.slice(-1) === "/");
				else inheritedRelative.pathname = source.pathname;
				inheritedRelative.search = relative.search != null ? relative.search : hasExplicitPathname ? null : source.search;
				inheritedRelative.query = relative.query != null ? relative.query : hasExplicitPathname ? null : source.query;
				inheritedRelative.hash = relative.hash != null ? relative.hash : hasExplicitPathname ? null : source.hash;
				inheritedRelative.path = (inheritedRelative.pathname || "") + (inheritedRelative.search || "") || null;
				inheritedRelative.href = _legacyResolveHref(inheritedRelative);
				return _preserveLegacyFileUrlShape(source, inheritedRelative);
			}
		}
		if (relative.protocol && relative.protocol === source.protocol && !relative.auth && !relative.host && !relative.hostname && relative.slashes && (relative.pathname === "/" || relative.pathname === "" || relative.pathname === null)) {
			var inherited = new Url();
			inherited.protocol = source.protocol;
			inherited.slashes = source.slashes;
			inherited.auth = source.auth;
			inherited.host = source.host;
			inherited.hostname = source.hostname;
			inherited.port = source.port;
			inherited.pathname = source.pathname;
			inherited.search = relative.search != null ? relative.search : source.search;
			inherited.query = relative.query != null ? relative.query : source.query;
			inherited.hash = relative.hash != null ? relative.hash : source.hash;
			inherited.path = (inherited.pathname || "") + (inherited.search || "") || null;
			inherited.href = _legacyResolveHref(inherited);
			return _preserveLegacyFileUrlShape(source, inherited);
		}
		if (!relative.protocol && !relative.host && !relative.hostname && typeof relative.pathname === "string" && relative.pathname.slice(0, 2) === "//" && source.slashes) {
			var netLoc = relative.pathname.slice(2);
			var firstSlash = netLoc.indexOf("/");
			var protocolRelativeHost = firstSlash === -1 ? netLoc : netLoc.slice(0, firstSlash);
			var preserveEmptyProtocolRelativeHost = protocolRelativeHost === "" && source.protocol && URL._isSpecialProtocol(source.protocol.slice(0, -1)) && source.protocol !== "file:";
			var protocolRelative = new Url();
			protocolRelative.protocol = source.protocol;
			protocolRelative.slashes = true;
			protocolRelative.auth = relative.auth || null;
			protocolRelative.host = preserveEmptyProtocolRelativeHost ? "" : protocolRelativeHost || null;
			protocolRelative.hostname = preserveEmptyProtocolRelativeHost ? "" : protocolRelativeHost || null;
			protocolRelative.port = null;
			protocolRelative.pathname = firstSlash === -1 ? /^(https?|ftp|gopher|file|ws|wss):$/i.test(source.protocol || "") ? "/" : null : netLoc.slice(firstSlash);
			protocolRelative.search = relative.search || null;
			protocolRelative.query = relative.query || null;
			protocolRelative.hash = relative.hash || null;
			protocolRelative.path = (protocolRelative.pathname || "") + (protocolRelative.search || "") || null;
			protocolRelative.href = _legacyResolveHref(protocolRelative);
			return _preserveLegacyFileUrlShape(source, protocolRelative);
		}
		var result = new Url();
		var keys = Object.keys(source);
		for (var ki = 0; ki < keys.length; ki++) result[keys[ki]] = source[keys[ki]];
		if (typeof relative === "string") relative = parse(relative, false, true);
		if (!relative || typeof relative !== "object") relative = parse(String(relative), false, true);
		result.hash = relative.hash;
		if (relative.href === "") {
			result.href = _legacyFormat(result);
			return _preserveLegacyFileUrlShape(source, result);
		}
		if (relative.slashes && !relative.protocol) {
			var relKeys = Object.keys(relative);
			for (var rki = 0; rki < relKeys.length; rki++) if (relKeys[rki] !== "protocol") result[relKeys[rki]] = relative[relKeys[rki]];
			if (_slashedProtocol[result.protocol] && result.hostname && !result.pathname) result.path = result.pathname = "/";
			result.href = _legacyFormat(result);
			return result;
		}
		if (relative.protocol && relative.protocol !== result.protocol) {
			if (!_slashedProtocol[relative.protocol]) {
				var rKeys2 = Object.keys(relative);
				for (var ri2 = 0; ri2 < rKeys2.length; ri2++) result[rKeys2[ri2]] = relative[rKeys2[ri2]];
				result.href = _legacyFormat(result);
				return result;
			}
			result.protocol = relative.protocol;
			if (!relative.host && !/^file:?$/.test(relative.protocol) && !_hostlessProtocol[relative.protocol]) {
				var relPath = (relative.pathname || "").split("/");
				while (relPath.length && !(relative.host = relPath.shift()));
				if (!relative.host) relative.host = "";
				if (!relative.hostname) relative.hostname = "";
				if (relPath[0] !== "") relPath.unshift("");
				if (relPath.length < 2) relPath.unshift("");
				result.pathname = relPath.join("/");
			} else result.pathname = relative.pathname;
			result.search = relative.search;
			result.query = relative.query;
			result.host = relative.host || "";
			result.auth = relative.auth;
			result.hostname = relative.hostname || relative.host;
			result.port = relative.port;
			if (result.pathname || result.search) result.path = (result.pathname || "") + (result.search || "");
			result.slashes = result.slashes || relative.slashes;
			result.href = _legacyFormat(result);
			return result;
		}
		var isSourceAbs = !!(result.pathname && result.pathname.charAt(0) === "/");
		var isRelAbs = !!(relative.host || relative.pathname && relative.pathname.charAt(0) === "/");
		var mustEndAbs = isRelAbs || isSourceAbs || result.host && relative.pathname;
		var removeAllDots = mustEndAbs;
		var srcPath = result.pathname && result.pathname.split("/") || [];
		var relPath = relative.pathname && relative.pathname.split("/") || [];
		var noLeadingSlashes = result.protocol && !_slashedProtocol[result.protocol];
		if (noLeadingSlashes) {
			result.hostname = "";
			result.port = null;
			if (result.host) if (srcPath[0] === "") srcPath[0] = result.host;
			else srcPath.unshift(result.host);
			result.host = "";
			if (relative.protocol) {
				relative.hostname = null;
				relative.port = null;
				result.auth = null;
				if (relative.host) if (relPath[0] === "") relPath[0] = relative.host;
				else relPath.unshift(relative.host);
				relative.host = null;
			}
			mustEndAbs = mustEndAbs && (relPath[0] === "" || srcPath[0] === "");
		}
		if (isRelAbs) {
			if (relative.host || relative.host === "") {
				if (result.host !== relative.host) result.auth = null;
				result.host = relative.host;
				result.port = relative.port;
			}
			if (relative.hostname || relative.hostname === "") {
				if (result.hostname !== relative.hostname) result.auth = null;
				result.hostname = relative.hostname;
			}
			result.search = relative.search;
			result.query = relative.query;
			srcPath = relPath;
		} else if (relPath.length) {
			if (!srcPath) srcPath = [];
			srcPath.pop();
			srcPath = srcPath.concat(relPath);
			result.search = relative.search;
			result.query = relative.query;
		} else if (relative.search !== null && relative.search !== void 0) {
			if (noLeadingSlashes) {
				result.hostname = result.host = srcPath.shift();
				var authInHost1 = result.host && result.host.indexOf("@") > 0 ? result.host.split("@") : false;
				if (authInHost1) {
					result.auth = authInHost1.shift();
					result.host = result.hostname = authInHost1.shift();
				}
			}
			result.search = relative.search;
			result.query = relative.query;
			if (result.pathname !== null || result.search !== null) result.path = (result.pathname || "") + (result.search || "");
			result.href = _legacyFormat(result);
			return _preserveLegacyFileUrlShape(source, result);
		}
		if (!srcPath.length) {
			result.pathname = null;
			if (result.search) result.path = "/" + result.search;
			else result.path = null;
			result.href = _legacyFormat(result);
			return result;
		}
		var last = srcPath[srcPath.length - 1];
		var hasTrailingSlash = (result.host || relative.host || srcPath.length > 1) && (last === "." || last === "..") || last === "";
		var up = 0;
		for (var i = srcPath.length - 1; i >= 0; i--) {
			last = srcPath[i];
			if (last === ".") _spliceOne(srcPath, i);
			else if (last === "..") {
				_spliceOne(srcPath, i);
				up++;
			} else if (up) {
				_spliceOne(srcPath, i);
				up--;
			}
		}
		if (!mustEndAbs && !removeAllDots) while (up--) srcPath.unshift("..");
		if (mustEndAbs && srcPath[0] !== "" && (!srcPath[0] || srcPath[0].charAt(0) !== "/")) srcPath.unshift("");
		if (hasTrailingSlash && srcPath.join("/").slice(-1) !== "/") srcPath.push("");
		var isAbsolute = srcPath[0] === "" || srcPath[0] && srcPath[0].charAt(0) === "/";
		if (noLeadingSlashes) {
			result.hostname = result.host = isAbsolute ? "" : srcPath.length ? srcPath.shift() : "";
			var authInHost2 = result.host && result.host.indexOf("@") > 0 ? result.host.split("@") : false;
			if (authInHost2) {
				result.auth = authInHost2.shift();
				result.host = result.hostname = authInHost2.shift();
			}
		}
		mustEndAbs = mustEndAbs || result.host && srcPath.length;
		if (mustEndAbs && !isAbsolute) srcPath.unshift("");
		if (!srcPath.length) {
			result.pathname = null;
			result.path = null;
		} else result.pathname = srcPath.join("/");
		if (result.pathname !== null || result.search !== null) result.path = (result.pathname || "") + (result.search || "");
		result.auth = relative.auth || result.auth;
		result.slashes = result.slashes || relative.slashes;
		result.href = _legacyFormat(result);
		return _preserveLegacyFileUrlShape(source, result);
	}
	function _normalizeLegacyResolveObjectResult(result) {
		if (!result || typeof result !== "object") return result;
		if (result.protocol === "file:" && result.slashes === null && result.host === null && result.hostname === null) {
			result.href = _legacyResolveHref(result);
			return result;
		}
		return parse(format(result), false, true);
	}
	Url.prototype.resolveObject = function(relative) {
		return _normalizeLegacyResolveObjectResult(resolveObject(this, relative));
	};
	URL.createObjectURL = _createObjectURL;
	URL.revokeObjectURL = _revokeObjectURL;
	function urlToHttpOptions(url) {
		if (url === null || typeof url !== "object") {
			var e = /* @__PURE__ */ new TypeError("The \"url\" argument must be of type object. Received type " + typeof url + " (" + (typeof url === "string" ? "'" + url + "'" : String(url)) + ")");
			e.code = "ERR_INVALID_ARG_TYPE";
			throw e;
		}
		var options = {
			protocol: url.protocol,
			hostname: typeof url.hostname === "string" && url.hostname.indexOf("[") === 0 ? url.hostname.slice(1, -1) : url.hostname,
			port: url.port !== "" && url.port !== void 0 ? Number(url.port) : NaN,
			path: (url.pathname || "") + (url.search || ""),
			pathname: url.pathname,
			search: url.search,
			hash: url.hash,
			href: url.href
		};
		if (url.username || url.password) options.auth = (url.username || "") + (url.password ? ":" + url.password : "");
		return options;
	}
	function _domainToUnicode(domain) {
		if (domain.indexOf("xn--") === -1) return domain;
		try {
			var punycode = require("punycode");
			if (typeof punycode.toUnicode === "function") return punycode.toUnicode(domain);
		} catch (e) {}
		return domain;
	}
	module.exports = {
		URL: URLExport,
		URLSearchParams: URLSearchParamsExport,
		Url,
		createObjectURL: _createObjectURL,
		revokeObjectURL: _revokeObjectURL,
		format,
		parse,
		resolve,
		resolveObject: function(source, relative) {
			return _normalizeLegacyResolveObjectResult(resolveObject(source, relative));
		},
		fileURLToPath,
		pathToFileURL: function pathToFileURL(path, options) {
			if (typeof path !== "string") {
				var typeMsg;
				if (path === null) typeMsg = "null";
				else if (path === void 0) typeMsg = "undefined";
				else if (typeof path === "object") typeMsg = "an instance of " + (path && path.constructor ? path.constructor.name : "Object");
				else typeMsg = "type " + typeof path + " (" + String(path) + ")";
				var typeErr = /* @__PURE__ */ new TypeError("The \"path\" argument must be of type string. Received " + typeMsg);
				typeErr.code = "ERR_INVALID_ARG_TYPE";
				throw typeErr;
			}
			var isWin = false;
			if (options && typeof options === "object" && options.windows !== void 0) isWin = !!options.windows;
			else isWin = typeof process !== "undefined" && process.platform === "win32";
			if (isWin) {
				if (path.indexOf("\\\\?\\") === 0) {
					var rest = path.slice(4);
					if (rest.indexOf("UNC\\") === 0) return new URLExport("file://" + _encodeFileURLPath(rest.slice(4).replace(/\\/g, "/")));
					return new URLExport("file:///" + _encodeFileURLPath(rest.replace(/\\/g, "/")));
				}
				if (path.indexOf("\\\\") === 0) {
					var uncPath = path.slice(2).replace(/\\/g, "/");
					if (uncPath.indexOf("/") <= 0) {
						var uncErr = /* @__PURE__ */ new TypeError("File URL path must provide a hostname");
						uncErr.code = "ERR_INVALID_ARG_VALUE";
						throw uncErr;
					}
					return new URLExport("file://" + _encodeFileURLPath(uncPath));
				}
				return new URLExport("file:///" + _encodeFileURLPath(path.replace(/\\/g, "/")));
			}
			var encoded = _encodeFileURLPath(path);
			if (path.charAt(0) === "/") return new URLExport("file://" + encoded);
			var cwd = "/";
			if (typeof process !== "undefined" && typeof process.cwd === "function") cwd = process.cwd();
			if (cwd.charAt(cwd.length - 1) !== "/") cwd += "/";
			return new URLExport("file://" + _encodeFileURLPath(cwd) + encoded);
		},
		canParse: URL.canParse,
		urlToHttpOptions,
		domainToASCII: function domainToASCII(domain) {
			try {
				return new URLExport("http://" + domain).hostname;
			} catch (e) {
				return "";
			}
		},
		domainToUnicode: _domainToUnicode
	};
})();
//#endregion
