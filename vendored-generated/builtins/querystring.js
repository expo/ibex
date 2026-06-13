//#region src/builtins/querystring.js
var qs = {};
qs.escape = function escape(str) {
	if (typeof str !== "string") if (typeof str === "object") str = String(str);
	else str = str + "";
	var len = str.length;
	if (len === 0) return "";
	var out = "";
	var lastPos = 0;
	for (var i = 0; i < len; i++) {
		var c = str.charCodeAt(i);
		if (c < 128) {
			if (__qsNoEscape(c)) continue;
			if (lastPos < i) out += str.slice(lastPos, i);
			lastPos = i + 1;
			out += __qsHex(c);
			continue;
		}
		if (lastPos < i) out += str.slice(lastPos, i);
		if (c < 2048) {
			lastPos = i + 1;
			out += __qsHex(192 | c >> 6) + __qsHex(128 | c & 63);
		} else if (c < 55296 || c >= 57344) {
			lastPos = i + 1;
			out += __qsHex(224 | c >> 12) + __qsHex(128 | c >> 6 & 63) + __qsHex(128 | c & 63);
		} else {
			i++;
			if (i >= len) {
				var err = /* @__PURE__ */ new URIError("URI malformed");
				err.code = "ERR_INVALID_URI";
				throw err;
			}
			var c2 = str.charCodeAt(i) & 1023;
			lastPos = i + 1;
			c = 65536 + ((c & 1023) << 10 | c2);
			out += __qsHex(240 | c >> 18) + __qsHex(128 | c >> 12 & 63) + __qsHex(128 | c >> 6 & 63) + __qsHex(128 | c & 63);
		}
	}
	if (lastPos === 0) return str;
	if (lastPos < len) return out + str.slice(lastPos);
	return out;
};
function __qsNoEscape(c) {
	if (c >= 48 && c <= 57) return true;
	if (c >= 65 && c <= 90) return true;
	if (c >= 97 && c <= 122) return true;
	return c === 33 || c === 39 || c === 40 || c === 41 || c === 42 || c === 45 || c === 46 || c === 95 || c === 126;
}
function __qsHex(byte) {
	var hex = byte.toString(16).toUpperCase();
	return "%" + (hex.length === 1 ? "0" + hex : hex);
}
qs.unescape = function unescape(str) {
	try {
		return decodeURIComponent(str.replace(/\+/g, " "));
	} catch (e) {
		return str;
	}
};
qs.stringify = function stringify(obj, sep, eq, options) {
	sep = sep || "&";
	eq = eq || "=";
	var encode = options && typeof options.encodeURIComponent === "function" ? options.encodeURIComponent : qs.escape;
	if (obj === null || obj === void 0 || typeof obj !== "object") return "";
	var keys = Object.keys(obj);
	var parts = [];
	for (var i = 0; i < keys.length; i++) {
		var key = keys[i];
		var value = obj[key];
		var encodedKey = encode(key);
		if (Array.isArray(value)) for (var j = 0; j < value.length; j++) {
			var item = value[j];
			if (item === null || item === void 0) parts.push(encodedKey + eq);
			else parts.push(encodedKey + eq + encode(String(item)));
		}
		else if (value === null || value === void 0) parts.push(encodedKey + eq);
		else parts.push(encodedKey + eq + encode(String(value)));
	}
	return parts.join(sep);
};
qs.parse = function parse(str, sep, eq, options) {
	sep = sep || "&";
	eq = eq || "=";
	var maxKeys = 1e3;
	if (options && typeof options.maxKeys === "number") maxKeys = options.maxKeys;
	var decode = options && typeof options.decodeURIComponent === "function" ? options.decodeURIComponent : qs.unescape;
	var obj = Object.create(null);
	if (typeof str !== "string" || str.length === 0) return obj;
	var pairs = str.split(sep);
	var len = pairs.length;
	if (maxKeys > 0 && len > maxKeys) len = maxKeys;
	for (var i = 0; i < len; i++) {
		var pair = pairs[i];
		var eqIdx = pair.indexOf(eq);
		var key, value;
		if (eqIdx >= 0) {
			key = decode(pair.substring(0, eqIdx));
			value = decode(pair.substring(eqIdx + eq.length));
		} else {
			key = decode(pair);
			value = "";
		}
		if (key === "") continue;
		if (obj[key] !== void 0) if (Array.isArray(obj[key])) obj[key].push(value);
		else obj[key] = [obj[key], value];
		else obj[key] = value;
	}
	return obj;
};
qs.encode = qs.stringify;
qs.decode = qs.parse;
module.exports = qs;
//#endregion
