//#region src/builtins/tls.js
var net;
try {
	net = require("net");
} catch (e) {}
var _kReinitializeHandle = Symbol.for("nodejs.net.kReinitializeHandle");
var eventsModule;
try {
	eventsModule = require("events");
} catch (e) {}
var cryptoModule;
try {
	cryptoModule = require("crypto");
} catch (e) {}
var StringDecoder = null;
try {
	StringDecoder = require("node:string_decoder").StringDecoder;
} catch (_decoderErr) {
	try {
		StringDecoder = require("string_decoder").StringDecoder;
	} catch (_decoderErr2) {}
}
var EventEmitter = eventsModule && (eventsModule.EventEmitter || eventsModule);
var hasOwn = Object.prototype.hasOwnProperty;
var CLIENT_RENEG_LIMIT = 3;
var CLIENT_RENEG_WINDOW = 600;
var DEFAULT_ECDH_CURVE = "auto";
var DEFAULT_MIN_VERSION = "TLSv1.2";
var DEFAULT_MAX_VERSION = "TLSv1.3";
var DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
var _defaultTlsCipher = "TLS_AES_256_GCM_SHA384";
var _tlsServersByPort = Object.create(null);
var _defaultTls13CipherPriority = [
	"TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256",
	"TLS_AES_128_GCM_SHA256"
];
var _supportedTls13CipherPriority = _defaultTls13CipherPriority.concat(["TLS_AES_128_CCM_8_SHA256"]);
var _legacyCipherPriority = [
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"AES256-SHA",
	"AES256-SHA256"
];
var _supportedCipherSet = Object.create(null);
var _tlsVersions = {
	"TLSv1": true,
	"TLSv1.1": true,
	"TLSv1.2": true,
	"TLSv1.3": true
};
var rootCertificates = Object.freeze([]);
var _systemCACertificates = Object.freeze([]);
var _extraCACertificates = Object.freeze([]);
var _defaultCACertificates = Object.freeze(rootCertificates.slice());
function _createError(code, message) {
	var err = new Error(message);
	err.code = code;
	return err;
}
function _getEmptyBuffer() {
	if (typeof Buffer !== "undefined" && typeof Buffer.alloc === "function") return Buffer.alloc(0);
	return typeof Uint8Array !== "undefined" ? new Uint8Array(0) : [];
}
function _isArrayBufferView(value) {
	if (!value || typeof value !== "object") return false;
	if (typeof ArrayBuffer !== "undefined" && typeof ArrayBuffer.isView === "function") return ArrayBuffer.isView(value);
	return typeof value.byteLength === "number" && value.buffer;
}
function _cloneBufferLike(value) {
	if (value === null || typeof value === "undefined") return _getEmptyBuffer();
	if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.from(value);
	if (typeof Uint8Array !== "undefined") {
		if (value instanceof Uint8Array) return new Uint8Array(value);
		if (value instanceof ArrayBuffer) return new Uint8Array(value.slice ? value.slice(0) : value);
		if (_isArrayBufferView(value)) {
			var offset = value.byteOffset || 0;
			var length = typeof value.byteLength === "number" ? value.byteLength : value.length;
			return new Uint8Array(new Uint8Array(value.buffer, offset, length));
		}
	}
	return value;
}
function _stringToBytes(value) {
	if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.from(String(value));
	var str = String(value);
	var out = typeof Uint8Array !== "undefined" ? new Uint8Array(str.length) : [];
	for (var i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 255;
	return out;
}
function _byteLength(value) {
	if (typeof value === "string") return _stringToBytes(value).length || 0;
	if (!value) return 0;
	if (typeof value.length === "number") return value.length;
	if (typeof value.byteLength === "number") return value.byteLength;
	return 0;
}
function _normalizeTlsHighWaterMark(value, fallback) {
	var number = Number(value);
	if (!isFinite(number) || number <= 0) number = Number(fallback);
	if (!isFinite(number) || number <= 0) number = 16384;
	return Math.max(1, Math.floor(number));
}
function _tlsWriteBuffer(data, encoding) {
	return typeof data === "string" ? typeof Buffer !== "undefined" ? Buffer.from(data, encoding || "utf8") : _stringToBytes(data) : _cloneBufferLike(data);
}
function _mixinEventEmitter(target) {
	if (typeof EventEmitter !== "function" || !EventEmitter.prototype || !target) return target;
	var names = typeof Object.getOwnPropertyNames === "function" ? Object.getOwnPropertyNames(EventEmitter.prototype) : null;
	if (names && names.length) {
		for (var i = 0; i < names.length; i++) {
			var name = names[i];
			if (name === "constructor" || target[name]) continue;
			if (typeof EventEmitter.prototype[name] === "function") target[name] = EventEmitter.prototype[name];
		}
		return target;
	}
	for (var key in EventEmitter.prototype) if (!target[key]) target[key] = EventEmitter.prototype[key];
	return target;
}
function _cloneOwnProperties(source) {
	if (!source || typeof source !== "object") return {};
	var target = {};
	for (var key in source) if (hasOwn.call(source, key)) target[key] = source[key];
	return target;
}
function _defineOwnDataProperty(target, name, value) {
	if (typeof Object.defineProperty === "function") try {
		Object.defineProperty(target, name, {
			value,
			writable: true,
			enumerable: true,
			configurable: true
		});
		return;
	} catch (_definePropErr) {}
	target[name] = value;
}
function _validateProtocolVersion(kind, value) {
	if (value === null || typeof value === "undefined") return;
	if (typeof value !== "string" || !_tlsVersions[value]) throw _createError("ERR_TLS_INVALID_PROTOCOL_VERSION", "\"" + value + "\" is not a valid " + kind + " TLS protocol version");
}
function _markSupportedCiphers(list) {
	for (var i = 0; i < list.length; i++) _supportedCipherSet[list[i]] = true;
}
_markSupportedCiphers(_supportedTls13CipherPriority);
_markSupportedCiphers(_legacyCipherPriority);
function _isTls13CipherName(name) {
	return typeof name === "string" && name.indexOf("TLS_") === 0;
}
function _supportsTls13(options) {
	var maxVersion = options && options.maxVersion;
	if (!maxVersion) maxVersion = DEFAULT_MAX_VERSION;
	return maxVersion === "TLSv1.3";
}
function _createCipherTypeError(value) {
	return _createError("ERR_INVALID_ARG_TYPE", "The \"ciphers\" argument must be of type string. Received " + typeof value);
}
function _createCipherValueError(value) {
	return _createError("ERR_INVALID_ARG_VALUE", "The property 'ciphers' is invalid. Received " + JSON.stringify(value));
}
function _createNoCipherMatchError() {
	var err = /* @__PURE__ */ new Error("no cipher match");
	err.code = "ERR_SSL_NO_CIPHER_MATCH";
	return err;
}
function _createTlsAlertHandshakeFailureError() {
	return _createError("ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE", "sslv3 alert handshake failure");
}
function _createNoSharedCipherError() {
	return _createError("ERR_SSL_NO_SHARED_CIPHER", "no shared cipher");
}
function _uniqueCipherList(list) {
	var out = [];
	var seen = Object.create(null);
	for (var i = 0; i < list.length; i++) {
		var name = list[i];
		if (!name || seen[name]) continue;
		seen[name] = true;
		out.push(name);
	}
	return out;
}
function _normalizeCipherTokens(ciphers, mode) {
	if (ciphers === void 0 || ciphers === null || ciphers === "") return [];
	if (typeof ciphers !== "string") throw _createCipherTypeError(ciphers);
	var tokens = String(ciphers).split(":");
	var normalized = [];
	for (var i = 0; i < tokens.length; i++) {
		var token = tokens[i] && String(tokens[i]).trim();
		if (!token) throw _createCipherValueError(ciphers);
		var exclude = token.charAt(0) === "!";
		var name = exclude ? token.slice(1) : token;
		if (!name) throw _createCipherValueError(ciphers);
		if (!_supportedCipherSet[name]) {
			if (mode === "server") throw _createNoCipherMatchError();
			throw _createCipherValueError(ciphers);
		}
		normalized.push({
			name,
			exclude,
			tls13: _isTls13CipherName(name)
		});
	}
	return normalized;
}
function _resolveCipherSuites(options, mode) {
	var tlsOptions = options || {};
	var ciphers = tlsOptions.ciphers;
	var allowTls13 = _supportsTls13(tlsOptions);
	var tokens = _normalizeCipherTokens(ciphers, mode);
	var excludes = Object.create(null);
	var includes = [];
	for (var i = 0; i < tokens.length; i++) if (tokens[i].exclude) excludes[tokens[i].name] = true;
	else includes.push(tokens[i]);
	var suites = [];
	if (ciphers === void 0 || ciphers === null || ciphers === "") {
		if (allowTls13) suites = suites.concat(_defaultTls13CipherPriority);
		suites = suites.concat(_legacyCipherPriority);
		return _uniqueCipherList(suites);
	}
	var tls13Includes = [];
	var legacyIncludes = [];
	for (var j = 0; j < includes.length; j++) if (includes[j].tls13) tls13Includes.push(includes[j].name);
	else legacyIncludes.push(includes[j].name);
	if (allowTls13) {
		var tls13Base = tls13Includes.length ? tls13Includes : _defaultTls13CipherPriority.slice();
		for (var k = 0; k < tls13Base.length; k++) if (!excludes[tls13Base[k]]) suites.push(tls13Base[k]);
	}
	var legacyBase = legacyIncludes.length ? legacyIncludes : [];
	for (var m = 0; m < legacyBase.length; m++) if (!excludes[legacyBase[m]]) suites.push(legacyBase[m]);
	suites = _uniqueCipherList(suites);
	if (!suites.length) throw _createNoCipherMatchError();
	return suites;
}
function _selectNegotiatedCipher(clientOptions, serverOptions) {
	var clientSuites = _resolveCipherSuites(clientOptions, "client");
	var serverSuites = _resolveCipherSuites(serverOptions, "server");
	var clientSet = Object.create(null);
	var serverSet = Object.create(null);
	for (var i = 0; i < clientSuites.length; i++) clientSet[clientSuites[i]] = true;
	for (var j = 0; j < serverSuites.length; j++) serverSet[serverSuites[j]] = true;
	for (var k = 0; k < _supportedTls13CipherPriority.length; k++) {
		var tls13Cipher = _supportedTls13CipherPriority[k];
		if (clientSet[tls13Cipher] && serverSet[tls13Cipher]) return tls13Cipher;
	}
	for (var m = 0; m < _legacyCipherPriority.length; m++) {
		var legacyCipher = _legacyCipherPriority[m];
		if (clientSet[legacyCipher] && serverSet[legacyCipher]) return legacyCipher;
	}
	return null;
}
function _registerTlsServer(server) {
	if (!server || typeof server.address !== "function") return;
	var address = server.address();
	if (!address || typeof address.port === "undefined" || address.port === null) return;
	if (server._tlsRegisteredPort !== void 0 && server._tlsRegisteredPort !== null && _tlsServersByPort[String(server._tlsRegisteredPort)] === server) delete _tlsServersByPort[String(server._tlsRegisteredPort)];
	server._tlsRegisteredPort = Number(address.port);
	_tlsServersByPort[String(server._tlsRegisteredPort)] = server;
}
function _unregisterTlsServer(server) {
	if (!server) return;
	var port = server._tlsRegisteredPort;
	if (port !== void 0 && port !== null && _tlsServersByPort[String(port)] === server) delete _tlsServersByPort[String(port)];
	server._tlsRegisteredPort = null;
}
function _lookupTlsServer(port) {
	if (port === void 0 || port === null) return null;
	return _tlsServersByPort[String(Number(port))] || null;
}
function _shiftPendingServerSocket(server) {
	if (!server || !server._pendingTlsSockets || !server._pendingTlsSockets.length) return null;
	return server._pendingTlsSockets.shift() || null;
}
function _queuePendingServerHandshake(server, handshake) {
	if (!server) return;
	if (!server._pendingTlsHandshakes) server._pendingTlsHandshakes = [];
	server._pendingTlsHandshakes.push(handshake);
}
function _normalizeCipherName(ciphers) {
	if (typeof ciphers !== "string" || !ciphers) return _defaultTlsCipher;
	var first = ciphers.split(/[:,]/)[0];
	if (first && first.charAt(0) === "!") first = first.slice(1);
	return first || _defaultTlsCipher;
}
function _getCipherList() {
	var result = [];
	var suites = _supportedTls13CipherPriority.concat(_legacyCipherPriority);
	for (var i = 0; i < suites.length; i++) result.push(String(suites[i]).toLowerCase());
	result.sort();
	return _uniqueCipherList(result);
}
function _normalizeCACertificates(certs) {
	if (!Array.isArray(certs)) throw _createError("ERR_INVALID_ARG_TYPE", "The \"certs\" argument must be an instance of Array");
	var normalized = [];
	for (var i = 0; i < certs.length; i++) {
		var cert = certs[i];
		if (typeof cert === "string") {
			normalized.push(cert);
			continue;
		}
		if (_isArrayBufferView(cert)) {
			normalized.push(_cloneBufferLike(cert));
			continue;
		}
		throw _createError("ERR_INVALID_ARG_TYPE", "The \"certs[" + i + "]\" argument must be of type string or an instance of ArrayBufferView");
	}
	return Object.freeze(normalized);
}
function getCACertificates(type) {
	var certType = typeof type === "undefined" ? "default" : type;
	if (certType === "default") return _defaultCACertificates;
	if (certType === "bundled") return rootCertificates;
	if (certType === "system") return _systemCACertificates;
	if (certType === "extra") return _extraCACertificates;
	throw _createError("ERR_INVALID_ARG_VALUE", "The argument \"type\" is invalid. Received " + String(certType));
}
function setDefaultCACertificates(certs) {
	_defaultCACertificates = _normalizeCACertificates(certs);
}
function _encodeALPNArray(protocols) {
	var chunks = [];
	var total = 0;
	for (var i = 0; i < protocols.length; i++) {
		if (typeof protocols[i] !== "string") throw _createError("ERR_INVALID_ARG_TYPE", "ALPN protocol entries must be strings");
		var bytes = _stringToBytes(protocols[i]);
		var length = _byteLength(bytes);
		if (length > 255) throw _createError("ERR_OUT_OF_RANGE", "The byte length of the protocol at index " + i + " exceeds the maximum length. It must be <= 255. Received " + length);
		chunks.push(bytes);
		total += 1 + length;
	}
	if (typeof Buffer !== "undefined" && typeof Buffer.alloc === "function") {
		var buffer = Buffer.alloc(total);
		var offset = 0;
		for (var j = 0; j < chunks.length; j++) {
			buffer[offset++] = _byteLength(chunks[j]);
			Buffer.from(chunks[j]).copy(buffer, offset);
			offset += _byteLength(chunks[j]);
		}
		return buffer;
	}
	var out = typeof Uint8Array !== "undefined" ? new Uint8Array(total) : [];
	var pos = 0;
	for (var k = 0; k < chunks.length; k++) {
		var chunk = chunks[k];
		var size = _byteLength(chunk);
		out[pos++] = size;
		for (var m = 0; m < size; m++) out[pos++] = chunk[m];
	}
	return out;
}
function convertALPNProtocols(protocols, out) {
	var normalized;
	if (Array.isArray(protocols)) normalized = _encodeALPNArray(protocols);
	else if (_isArrayBufferView(protocols) || typeof ArrayBuffer !== "undefined" && protocols instanceof ArrayBuffer) normalized = _cloneBufferLike(protocols);
	else throw _createError("ERR_INVALID_ARG_TYPE", "The \"protocols\" argument must be an instance of Array, Buffer, TypedArray, DataView, or ArrayBuffer");
	if (out && typeof out === "object") out.ALPNProtocols = normalized;
	return normalized;
}
function _normalizeCheckError(error) {
	if (!error) return null;
	if (error instanceof Error) return error;
	if (typeof error === "string") return new Error(error);
	return /* @__PURE__ */ new Error("TLS server identity check failed");
}
function _generateFingerprint(seed, algorithm) {
	if (typeof __exactHashSync !== "function") return "";
	try {
		var hash = __exactHashSync(algorithm || "sha1", seed || "");
		if (typeof hash !== "string") return "";
		return hash.toUpperCase().replace(/(.{2})(?!$)/g, "$1:");
	} catch (e) {
		return "";
	}
}
var _certificateParseCache = typeof Map !== "undefined" ? /* @__PURE__ */ new Map() : null;
function _pemSourceToString(source) {
	if (source == null) return "";
	if (typeof source === "string") return source;
	if (Array.isArray(source)) {
		var combined = "";
		for (var i = 0; i < source.length; i++) {
			combined += _pemSourceToString(source[i]);
			if (combined && combined[combined.length - 1] !== "\n") combined += "\n";
		}
		return combined;
	}
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(source)) return source.toString("utf8");
	if (_isArrayBufferView(source)) return _bufferFromBytes(source).toString ? _bufferFromBytes(source).toString("utf8") : String(source);
	return String(source);
}
function _bufferFromBase64(value) {
	if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.from(value, "base64");
	var binary = atob(value);
	var out = typeof Uint8Array !== "undefined" ? new Uint8Array(binary.length) : [];
	for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) & 255;
	return out;
}
function _bufferFromBytes(value) {
	if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
		if (typeof Buffer.isBuffer === "function" && Buffer.isBuffer(value)) return value;
		if (_isArrayBufferView(value) && value.buffer) return Buffer.from(value.buffer, value.byteOffset || 0, value.byteLength);
		return Buffer.from(value);
	}
	return value;
}
function _splitPemCertificates(source) {
	var normalized = _pemSourceToString(source);
	if (!normalized) return [];
	return normalized.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
}
function _readDerElement(bytes, offset) {
	if (offset >= bytes.length) return null;
	var startOffset = offset;
	var tag = bytes[offset++];
	if (offset >= bytes.length) return null;
	var lengthByte = bytes[offset++];
	var length = 0;
	if ((lengthByte & 128) === 0) length = lengthByte;
	else {
		var count = lengthByte & 127;
		if (!count || offset + count > bytes.length) return null;
		for (var i = 0; i < count; i++) length = length << 8 | bytes[offset++];
	}
	var valueStart = offset;
	var valueEnd = offset + length;
	if (valueEnd > bytes.length) return null;
	return {
		tag,
		startOffset,
		valueStart,
		valueEnd,
		nextOffset: valueEnd
	};
}
function _readDerChildren(bytes, start, end) {
	var children = [];
	var offset = start;
	while (offset < end) {
		var element = _readDerElement(bytes, offset);
		if (!element) break;
		children.push(element);
		offset = element.nextOffset;
	}
	return children;
}
function _bytesToAscii(bytes, start, end) {
	var chars = [];
	for (var i = start; i < end; i++) chars.push(String.fromCharCode(bytes[i]));
	return chars.join("");
}
function _bytesToUtf8(bytes, start, end) {
	var raw = _bufferFromBytes(bytes.slice ? bytes.slice(start, end) : Array.prototype.slice.call(bytes, start, end));
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(raw)) return raw.toString("utf8");
	if (typeof TextDecoder !== "undefined") try {
		return new TextDecoder("utf-8").decode(raw);
	} catch (_decodeErr) {}
	return _bytesToAscii(bytes, start, end);
}
function _bytesToBmpString(bytes, start, end) {
	var chars = [];
	for (var i = start; i + 1 < end; i += 2) chars.push(String.fromCharCode(bytes[i] << 8 | bytes[i + 1]));
	return chars.join("");
}
function _bytesToHex(bytes, start, end) {
	var out = "";
	for (var i = start; i < end; i++) {
		var hex = bytes[i].toString(16).toUpperCase();
		out += hex.length === 1 ? "0" + hex : hex;
	}
	return out;
}
function _sliceBytes(bytes, start, end) {
	if (bytes.slice) return bytes.slice(start, end);
	return Array.prototype.slice.call(bytes, start, end);
}
function _decodeDerOid(bytes, start, end) {
	if (start >= end) return "";
	var first = bytes[start++];
	var parts = [Math.floor(first / 40), first % 40];
	var value = 0;
	while (start < end) {
		var byte = bytes[start++];
		value = value << 7 | byte & 127;
		if ((byte & 128) === 0) {
			parts.push(value);
			value = 0;
		}
	}
	return parts.join(".");
}
function _decodeDerString(bytes, element) {
	if (!element) return "";
	if (element.tag === 12) return _bytesToUtf8(bytes, element.valueStart, element.valueEnd);
	if (element.tag === 22 || element.tag === 19) return _bytesToAscii(bytes, element.valueStart, element.valueEnd);
	if (element.tag === 30) return _bytesToBmpString(bytes, element.valueStart, element.valueEnd);
	return _bytesToUtf8(bytes, element.valueStart, element.valueEnd);
}
function _attributeNameForOid(oid) {
	if (oid === "2.5.4.3") return "CN";
	if (oid === "2.5.4.6") return "C";
	if (oid === "2.5.4.7") return "L";
	if (oid === "2.5.4.8") return "ST";
	if (oid === "2.5.4.10") return "O";
	if (oid === "2.5.4.11") return "OU";
	if (oid === "1.2.840.113549.1.9.1") return "emailAddress";
	return oid;
}
function _parseDerName(bytes, element) {
	var result = {};
	if (!element || element.tag !== 48) return result;
	var rdns = _readDerChildren(bytes, element.valueStart, element.valueEnd);
	for (var i = 0; i < rdns.length; i++) {
		if (rdns[i].tag !== 49) continue;
		var attrs = _readDerChildren(bytes, rdns[i].valueStart, rdns[i].valueEnd);
		for (var j = 0; j < attrs.length; j++) {
			if (attrs[j].tag !== 48) continue;
			var attrChildren = _readDerChildren(bytes, attrs[j].valueStart, attrs[j].valueEnd);
			if (attrChildren.length < 2) continue;
			var attrName = _attributeNameForOid(_decodeDerOid(bytes, attrChildren[0].valueStart, attrChildren[0].valueEnd));
			var attrValue = _decodeDerString(bytes, attrChildren[1]);
			if (hasOwn.call(result, attrName)) if (Array.isArray(result[attrName])) result[attrName].push(attrValue);
			else result[attrName] = [result[attrName], attrValue];
			else result[attrName] = attrValue;
		}
	}
	return result;
}
var _certMonthNames = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
];
function _formatCertTime(year, month, day, hour, minute, second) {
	var monthName = _certMonthNames[Number(month) - 1] || month;
	var dayNum = Number(day);
	var dayText = dayNum < 10 ? " " + dayNum : String(dayNum);
	return monthName + " " + dayText + " " + hour + ":" + minute + ":" + second + " " + year + " GMT";
}
function _formatDerTime(bytes, element) {
	if (!element) return "";
	var text = _bytesToAscii(bytes, element.valueStart, element.valueEnd);
	if (element.tag === 23 && text.length >= 12) {
		var year = Number(text.slice(0, 2));
		year += year >= 50 ? 1900 : 2e3;
		return _formatCertTime(String(year), text.slice(2, 4), text.slice(4, 6), text.slice(6, 8), text.slice(8, 10), text.slice(10, 12));
	}
	if (element.tag === 24 && text.length >= 14) return _formatCertTime(text.slice(0, 4), text.slice(4, 6), text.slice(6, 8), text.slice(8, 10), text.slice(10, 12), text.slice(12, 14));
	return text;
}
function _fingerprintFromRaw(raw, algorithm) {
	if (!raw || typeof __exactHashSync !== "function") return "";
	try {
		var hash = __exactHashSync(algorithm, raw);
		return typeof hash === "string" ? hash.toUpperCase().replace(/(.{2})(?!$)/g, "$1:") : "";
	} catch (_fingerprintErr) {
		return "";
	}
}
function _extensionNameForOid(oid) {
	if (oid === "1.3.6.1.5.5.7.48.1") return "OCSP";
	if (oid === "1.3.6.1.5.5.7.48.2") return "CA Issuers";
	return oid;
}
function _curveNamesForOid(oid) {
	if (oid === "1.2.840.10045.3.1.7") return {
		asn1Curve: "prime256v1",
		nistCurve: "P-256",
		bits: 256
	};
	if (oid === "1.3.132.0.34") return {
		asn1Curve: "secp384r1",
		nistCurve: "P-384",
		bits: 384
	};
	if (oid === "1.3.132.0.35") return {
		asn1Curve: "secp521r1",
		nistCurve: "P-521",
		bits: 521
	};
	return null;
}
function _parseAuthorityInfoAccess(bytes, element) {
	if (!element || element.tag !== 4) return void 0;
	var wrapped = _readDerElement(bytes, element.valueStart);
	if (!wrapped || wrapped.nextOffset > element.valueEnd || wrapped.tag !== 48) return void 0;
	var entries = _readDerChildren(bytes, wrapped.valueStart, wrapped.valueEnd);
	var infoAccess = {};
	var hasEntries = false;
	for (var i = 0; i < entries.length; i++) {
		if (entries[i].tag !== 48) continue;
		var parts = _readDerChildren(bytes, entries[i].valueStart, entries[i].valueEnd);
		if (parts.length < 2) continue;
		var methodOid = _decodeDerOid(bytes, parts[0].valueStart, parts[0].valueEnd);
		var location = parts[1];
		if (location.tag !== 134) continue;
		var entryName = _extensionNameForOid(methodOid) + " - URI";
		if (!hasOwn.call(infoAccess, entryName)) infoAccess[entryName] = [];
		infoAccess[entryName].push(_bytesToAscii(bytes, location.valueStart, location.valueEnd));
		hasEntries = true;
	}
	return hasEntries ? infoAccess : void 0;
}
function _formatSubjectAltNameText(value) {
	if (typeof value !== "string") return "";
	if (!/[\u0000-\u001f"\\]/.test(value)) return value;
	return "\"" + value.replace(/[\u0000-\u001f"\\]/g, function(ch) {
		var code = ch.charCodeAt(0);
		if (ch === "\"" || ch === "\\") return "\\" + ch;
		var hex = code.toString(16).toUpperCase();
		while (hex.length < 4) hex = "0" + hex;
		return "\\u" + hex;
	}) + "\"";
}
function _formatIpAddress(bytes, start, end) {
	var length = end - start;
	if (length === 4) return String(bytes[start]) + "." + String(bytes[start + 1]) + "." + String(bytes[start + 2]) + "." + String(bytes[start + 3]);
	if (length === 16) {
		var parts = [];
		for (var i = start; i < end; i += 2) parts.push((bytes[i] << 8 | bytes[i + 1]).toString(16));
		return parts.join(":");
	}
	return _bytesToHex(bytes, start, end);
}
function _parseSubjectAltName(bytes, element) {
	if (!element || element.tag !== 4) return void 0;
	var wrapped = _readDerElement(bytes, element.valueStart);
	if (!wrapped || wrapped.nextOffset > element.valueEnd || wrapped.tag !== 48) return void 0;
	var names = _readDerChildren(bytes, wrapped.valueStart, wrapped.valueEnd);
	var out = [];
	for (var i = 0; i < names.length; i++) {
		var name = names[i];
		if (name.tag === 130) out.push("DNS:" + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
		else if (name.tag === 134) out.push("URI:" + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
		else if (name.tag === 135) out.push("IP Address:" + _formatIpAddress(bytes, name.valueStart, name.valueEnd));
		else if (name.tag === 129) out.push("email:" + _formatSubjectAltNameText(_bytesToAscii(bytes, name.valueStart, name.valueEnd)));
	}
	return out.length ? out.join(", ") : void 0;
}
function _parseSubjectPublicKeyInfo(bytes, element) {
	if (!element || element.tag !== 48) return {};
	var children = _readDerChildren(bytes, element.valueStart, element.valueEnd);
	if (children.length < 2 || children[0].tag !== 48 || children[1].tag !== 3) return {};
	var algorithmParts = _readDerChildren(bytes, children[0].valueStart, children[0].valueEnd);
	if (!algorithmParts.length) return {};
	var algorithmOid = _decodeDerOid(bytes, algorithmParts[0].valueStart, algorithmParts[0].valueEnd);
	var bitString = children[1];
	var bitStringStart = bitString.valueStart;
	if (bitStringStart >= bitString.valueEnd) return {};
	if (bytes[bitStringStart] !== 0) return {};
	if (algorithmOid === "1.2.840.113549.1.1.1") {
		var rsaKey = _readDerElement(bytes, bitStringStart + 1);
		if (!rsaKey || rsaKey.tag !== 48 || rsaKey.nextOffset > bitString.valueEnd) return {};
		var rsaParts = _readDerChildren(bytes, rsaKey.valueStart, rsaKey.valueEnd);
		if (rsaParts.length < 2) return {};
		var modulusHex = _bytesToHex(bytes, rsaParts[0].valueStart, rsaParts[0].valueEnd).replace(/^00+/, "") || "0";
		var exponentHex = _bytesToHex(bytes, rsaParts[1].valueStart, rsaParts[1].valueEnd).replace(/^0+/, "") || "0";
		return {
			pubkey: _bufferFromBytes(_sliceBytes(bytes, element.startOffset, element.nextOffset)),
			modulus: modulusHex,
			exponent: "0x" + exponentHex.toLowerCase(),
			bits: modulusHex.length / 2 * 8
		};
	}
	if (algorithmOid === "1.2.840.10045.2.1") {
		var point = _bufferFromBytes(_sliceBytes(bytes, bitStringStart + 1, bitString.valueEnd));
		var curveNames = _curveNamesForOid(algorithmParts[1] ? _decodeDerOid(bytes, algorithmParts[1].valueStart, algorithmParts[1].valueEnd) : "");
		var pointBits = point && point.length > 1 ? (point.length - 1) / 2 * 8 : void 0;
		return {
			pubkey: point,
			bits: curveNames && curveNames.bits ? curveNames.bits : pointBits,
			asn1Curve: curveNames && curveNames.asn1Curve ? curveNames.asn1Curve : void 0,
			nistCurve: curveNames && curveNames.nistCurve ? curveNames.nistCurve : void 0
		};
	}
	return {};
}
function _parseCertificateExtensions(bytes, tbsChildren, startIdx) {
	var parsed = {};
	for (var i = startIdx; i < tbsChildren.length; i++) {
		if (tbsChildren[i].tag !== 163) continue;
		var extensionWrappers = _readDerChildren(bytes, tbsChildren[i].valueStart, tbsChildren[i].valueEnd);
		if (!extensionWrappers.length || extensionWrappers[0].tag !== 48) continue;
		var extensions = _readDerChildren(bytes, extensionWrappers[0].valueStart, extensionWrappers[0].valueEnd);
		for (var j = 0; j < extensions.length; j++) {
			if (extensions[j].tag !== 48) continue;
			var parts = _readDerChildren(bytes, extensions[j].valueStart, extensions[j].valueEnd);
			if (parts.length < 2) continue;
			var extOid = _decodeDerOid(bytes, parts[0].valueStart, parts[0].valueEnd);
			var valueElement = parts[parts.length - 1];
			if (extOid === "1.3.6.1.5.5.7.1.1") {
				var infoAccess = _parseAuthorityInfoAccess(bytes, valueElement);
				if (infoAccess) parsed.infoAccess = infoAccess;
			} else if (extOid === "2.5.29.17") {
				var subjectAltName = _parseSubjectAltName(bytes, valueElement);
				if (subjectAltName) parsed.subjectaltname = subjectAltName;
			}
		}
	}
	return parsed;
}
function _cloneSimpleObject(value) {
	if (!value || typeof value !== "object") return value;
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(value)) return Buffer.from(value);
	if (Array.isArray(value)) {
		var arr = [];
		for (var i = 0; i < value.length; i++) arr.push(_cloneSimpleObject(value[i]));
		return arr;
	}
	var clone = {};
	for (var key in value) if (hasOwn.call(value, key)) clone[key] = _cloneSimpleObject(value[key]);
	return clone;
}
function _cloneCertificate(cert, detailed, seen) {
	if (!cert || typeof cert !== "object") return {};
	if (!detailed) {
		var shallow = {};
		for (var key in cert) {
			if (!hasOwn.call(cert, key) || key === "issuerCertificate") continue;
			shallow[key] = _cloneSimpleObject(cert[key]);
		}
		return shallow;
	}
	seen = seen || [];
	for (var i = 0; i < seen.length; i++) if (seen[i].source === cert) return seen[i].clone;
	var clone = {};
	seen.push({
		source: cert,
		clone
	});
	for (var key2 in cert) {
		if (!hasOwn.call(cert, key2)) continue;
		if (key2 === "issuerCertificate" && cert[key2]) clone[key2] = _cloneCertificate(cert[key2], true, seen);
		else clone[key2] = _cloneSimpleObject(cert[key2]);
	}
	return clone;
}
function _toX509CertificateData(cert, includeIssuer) {
	if (!cert || typeof cert !== "object") return null;
	var data = {
		__exactX509Data: true,
		raw: cert.raw || null,
		pem: typeof cert.pem === "string" ? cert.pem : "",
		subject: _cloneSimpleObject(cert.subject),
		issuer: _cloneSimpleObject(cert.issuer),
		subjectAltName: cert.subjectaltname,
		infoAccess: _cloneSimpleObject(cert.infoAccess),
		validFrom: cert.valid_from,
		validTo: cert.valid_to,
		serialNumber: cert.serialNumber,
		fingerprint: cert.fingerprint,
		fingerprint256: cert.fingerprint256,
		keyUsage: _cloneSimpleObject(cert.keyUsage),
		legacyObject: _cloneCertificate(cert, true)
	};
	if (includeIssuer && cert.issuerCertificate && cert.issuerCertificate !== cert) data.issuerCertificate = _toX509CertificateData(cert.issuerCertificate, false);
	return data;
}
function _toX509Certificate(cert, includeIssuer) {
	if (!cert || !cryptoModule || typeof cryptoModule.X509Certificate !== "function") return;
	return new cryptoModule.X509Certificate(_toX509CertificateData(cert, includeIssuer));
}
function _nameKey(name) {
	if (!name || typeof name !== "object") return "";
	var parts = [];
	var keys = Object.keys(name).sort();
	for (var i = 0; i < keys.length; i++) parts.push(keys[i] + "=" + String(name[keys[i]]));
	return parts.join(",");
}
function _parsePemCertificate(pem, host, port) {
	if (typeof pem !== "string" || pem.indexOf("BEGIN CERTIFICATE") === -1) return null;
	if (_certificateParseCache && _certificateParseCache.has(pem)) return _cloneCertificate(_certificateParseCache.get(pem), true);
	try {
		var der = _bufferFromBase64(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""));
		var bytes = der;
		var root = _readDerElement(bytes, 0);
		if (!root || root.tag !== 48) return null;
		var rootChildren = _readDerChildren(bytes, root.valueStart, root.valueEnd);
		if (!rootChildren.length) return null;
		var tbs = rootChildren[0];
		var tbsChildren = _readDerChildren(bytes, tbs.valueStart, tbs.valueEnd);
		var idx = 0;
		if (tbsChildren[idx] && tbsChildren[idx].tag === 160) idx += 1;
		var serialElement = tbsChildren[idx++];
		idx += 1;
		var issuerElement = tbsChildren[idx++];
		var validityElement = tbsChildren[idx++];
		var subjectElement = tbsChildren[idx++];
		var subjectPublicKeyInfoElement = tbsChildren[idx++];
		var validityChildren = validityElement ? _readDerChildren(bytes, validityElement.valueStart, validityElement.valueEnd) : [];
		var raw = _bufferFromBytes(der);
		var keyInfo = _parseSubjectPublicKeyInfo(bytes, subjectPublicKeyInfoElement);
		var extensionInfo = _parseCertificateExtensions(bytes, tbsChildren, idx);
		var parsed = {
			subject: _parseDerName(bytes, subjectElement),
			issuer: _parseDerName(bytes, issuerElement),
			valid_from: _formatDerTime(bytes, validityChildren[0]),
			valid_to: _formatDerTime(bytes, validityChildren[1]),
			serialNumber: _bytesToHex(bytes, serialElement.valueStart, serialElement.valueEnd).replace(/^00+/, "") || "0",
			fingerprint: _fingerprintFromRaw(raw, "sha1"),
			fingerprint256: _fingerprintFromRaw(raw, "sha256"),
			fingerprint512: _fingerprintFromRaw(raw, "sha512"),
			raw,
			ca: false
		};
		for (var key in keyInfo) if (hasOwn.call(keyInfo, key) && keyInfo[key] !== void 0) parsed[key] = keyInfo[key];
		if (extensionInfo.infoAccess !== void 0) parsed.infoAccess = extensionInfo.infoAccess;
		if (extensionInfo.subjectaltname !== void 0) parsed.subjectaltname = extensionInfo.subjectaltname;
		if (_certificateParseCache) _certificateParseCache.set(pem, parsed);
		return _cloneCertificate(parsed, true);
	} catch (_parseErr) {
		return null;
	}
}
function _buildCertificateChain(host, port, leafSource, chainSource, trustedSource) {
	var blocks = _splitPemCertificates(leafSource).concat(_splitPemCertificates(chainSource));
	var trustedBlocks = _splitPemCertificates(trustedSource);
	var parsed = [];
	var seen = Object.create(null);
	function appendBlock(block) {
		var cert = _parsePemCertificate(block, host, port);
		if (!cert || !cert.serialNumber || seen[cert.serialNumber]) return;
		seen[cert.serialNumber] = true;
		parsed.push(cert);
	}
	for (var i = 0; i < blocks.length; i++) appendBlock(blocks[i]);
	if (!parsed.length) return _buildSyntheticCertificate(host, port, leafSource || "ExactTLS");
	if (!parsed[0].subjectaltname) parsed[0].subjectaltname = "DNS:" + (host || "localhost");
	var lastIssuerKey = _nameKey(parsed[parsed.length - 1].issuer);
	for (var j = 0; j < trustedBlocks.length; j++) {
		var trusted = _parsePemCertificate(trustedBlocks[j], host, port);
		if (!trusted || !trusted.serialNumber || seen[trusted.serialNumber]) continue;
		if (!lastIssuerKey || _nameKey(trusted.subject) === lastIssuerKey) {
			seen[trusted.serialNumber] = true;
			parsed.push(trusted);
			lastIssuerKey = _nameKey(trusted.issuer);
		}
	}
	for (var k = 0; k < parsed.length; k++) {
		parsed[k].ca = k > 0 || _nameKey(parsed[k].subject) === _nameKey(parsed[k].issuer);
		if (k + 1 < parsed.length) parsed[k].issuerCertificate = parsed[k + 1];
	}
	if (_nameKey(parsed[parsed.length - 1].subject) === _nameKey(parsed[parsed.length - 1].issuer)) parsed[parsed.length - 1].issuerCertificate = parsed[parsed.length - 1];
	return parsed[0];
}
function _buildPeerCertificate(host, port, remoteOptions, localOptions) {
	var remote = remoteOptions || {};
	if (remote.cert || remote.pfx) return _buildCertificateChain(host, port, remote.cert || remote.pfx, remote.ca, localOptions && localOptions.ca);
	return _buildSyntheticCertificate(host, port, remote.cert || remote.pfx || "ExactTLS");
}
function _buildLocalCertificate(host, port, options) {
	var local = options || {};
	if (local.cert || local.pfx) return _buildCertificateChain(host, port, local.cert || local.pfx, local.ca, null);
	if (local.key) return _buildSyntheticCertificate(host, port, local.key);
	return null;
}
function _buildSyntheticCertificate(host, port, certSource) {
	var identity = host || "localhost";
	var now = /* @__PURE__ */ new Date();
	var validFrom = /* @__PURE__ */ new Date(now.getTime() - 720 * 60 * 60 * 1e3);
	var validTo = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1e3);
	var seed = identity + (port ? ":" + port : "") + String(now.getTime());
	return {
		subject: { CN: identity },
		issuer: { CN: certSource || "ExactTLS" },
		subjectaltname: "DNS:" + identity,
		valid_from: validFrom.toUTCString(),
		valid_to: validTo.toUTCString(),
		serialNumber: "0000000000000001",
		fingerprint: _generateFingerprint(seed + ":sha1", "sha1"),
		fingerprint256: _generateFingerprint(seed + ":sha256", "sha256"),
		raw: null
	};
}
function _isIpAddress(host) {
	if (!host || typeof host !== "string") return false;
	if (host.indexOf(":") !== -1) return /^([0-9a-f:.]+)$/i.test(host);
	return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}
function _isLoopbackHost(host) {
	if (!host || typeof host !== "string") return false;
	var normalized = _unfqdn(host).toLowerCase();
	if (normalized === "localhost" || normalized === "ip6-localhost") return true;
	if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") return true;
	if (normalized === "::" || normalized === "0.0.0.0") return true;
	if (/^127(\.\d{1,3}){3}$/.test(normalized)) return true;
	if (normalized.indexOf("::ffff:127.") === 0) return true;
	return false;
}
function _unfqdn(host) {
	return String(host || "").replace(/[.]$/, "");
}
function _toLowerCaseAscii(ch) {
	return String.fromCharCode(ch.charCodeAt(0) + 32);
}
function _splitHost(host) {
	return _unfqdn(host).replace(/[A-Z]/g, _toLowerCaseAscii).split(".");
}
function _checkHostPattern(hostParts, pattern, wildcards) {
	if (!pattern) return false;
	var patternParts = _splitHost(pattern);
	if (hostParts.length !== patternParts.length) return false;
	for (var i = 0; i < patternParts.length; i++) {
		if (patternParts[i] === "") return false;
		if (/[^\u0021-\u007F]/u.test(patternParts[i])) return false;
	}
	for (var j = hostParts.length - 1; j > 0; j--) if (hostParts[j] !== patternParts[j]) return false;
	var hostSubdomain = hostParts[0];
	var patternSubdomain = patternParts[0];
	var patternSubdomainParts = patternSubdomain.split("*", 3);
	if (patternSubdomainParts.length === 1 || patternSubdomain.indexOf("xn--") !== -1) return hostSubdomain === patternSubdomain;
	if (!wildcards) return false;
	if (patternSubdomainParts.length > 2) return false;
	if (patternParts.length <= 2) return false;
	var prefix = patternSubdomainParts[0];
	var suffix = patternSubdomainParts[1];
	if (prefix.length + suffix.length > hostSubdomain.length) return false;
	if (hostSubdomain.indexOf(prefix) !== 0) return false;
	if (hostSubdomain.slice(hostSubdomain.length - suffix.length) !== suffix) return false;
	return true;
}
var _jsonStringPattern = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;
function _splitEscapedAltNames(altNames) {
	var result = [];
	var currentToken = "";
	var offset = 0;
	while (offset !== altNames.length) {
		var nextSep = altNames.indexOf(",", offset);
		var nextQuote = altNames.indexOf("\"", offset);
		if (nextQuote !== -1 && (nextSep === -1 || nextQuote < nextSep)) {
			currentToken += altNames.substring(offset, nextQuote);
			var match = _jsonStringPattern.exec(altNames.substring(nextQuote));
			if (!match) throw new Error("Invalid subject alternative name format");
			currentToken += JSON.parse(match[0]);
			offset = nextQuote + match[0].length;
		} else if (nextSep !== -1) {
			currentToken += altNames.substring(offset, nextSep);
			result.push(currentToken);
			currentToken = "";
			offset = nextSep + 2;
		} else {
			currentToken += altNames.substring(offset);
			offset = altNames.length;
		}
	}
	result.push(currentToken);
	return result;
}
function _canonicalizeIp(host) {
	host = String(host || "");
	if (!_isIpAddress(host)) return void 0;
	return host;
}
function _createAltNameError(reason, hostname, cert) {
	var err = /* @__PURE__ */ new Error("Hostname/IP does not match certificate's altnames: " + reason);
	err.reason = reason;
	err.host = hostname;
	err.cert = cert;
	err.code = "ERR_TLS_CERT_ALTNAME_INVALID";
	return err;
}
function _createAuthorizationError(code, message) {
	var err = new Error(message);
	err.code = code;
	return err;
}
function _bufferEquals(left, right) {
	if (left === right) return true;
	if (!left || !right) return false;
	var leftLength = typeof left.length === "number" ? left.length : left.byteLength;
	if (leftLength !== (typeof right.length === "number" ? right.length : right.byteLength)) return false;
	for (var i = 0; i < leftLength; i++) if (left[i] !== right[i]) return false;
	return true;
}
function _certificateEquals(left, right) {
	if (!left || !right) return false;
	if (left.fingerprint256 && right.fingerprint256 && left.fingerprint256 === right.fingerprint256) return true;
	if (left.raw && right.raw && _bufferEquals(left.raw, right.raw)) return true;
	return left.serialNumber && right.serialNumber && left.serialNumber === right.serialNumber && _nameKey(left.subject) === _nameKey(right.subject);
}
function _collectCertificateChain(cert) {
	var chain = [];
	var current = cert;
	while (current) {
		chain.push(current);
		if (!current.issuerCertificate || current.issuerCertificate === current) break;
		current = current.issuerCertificate;
	}
	return chain;
}
function _collectTrustedCertificates(source, host, port) {
	var blocks = _splitPemCertificates(source);
	if (!blocks.length) return [];
	var certs = [];
	for (var i = 0; i < blocks.length; i++) {
		var cert = _parsePemCertificate(blocks[i], host, port);
		if (!cert) return null;
		certs.push(cert);
	}
	return certs;
}
function _isSelfSignedCertificate(cert) {
	return !!cert && _nameKey(cert.subject) === _nameKey(cert.issuer);
}
function _certificateTimeValue(value) {
	if (!value) return NaN;
	var text = String(value);
	var time = Date.parse(text);
	if (Number.isFinite(time)) return time;
	var match = /^([A-Za-z]{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4}) GMT$/.exec(text);
	if (match) {
		var month = _certMonthNames.indexOf(match[1]);
		if (month !== -1) return Date.UTC(Number(match[6]), month, Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5]));
	}
	return NaN;
}
function _normalizePemSignature(source) {
	return _pemSourceToString(source).replace(/\s+/g, "");
}
function _sourceContainsCertificate(source, certSource) {
	if (source == null || certSource == null) return false;
	var normalizedSource = _normalizePemSignature(source);
	var normalizedCert = _normalizePemSignature(certSource);
	return !!normalizedSource && !!normalizedCert && normalizedSource.indexOf(normalizedCert) !== -1;
}
function _validatePeerAuthorization(peerCert, options, host, port, remoteOptions) {
	if (!peerCert) return null;
	if (remoteOptions && remoteOptions.__exactExpired === true) return _createAuthorizationError("CERT_HAS_EXPIRED", "certificate has expired");
	var now = Date.now();
	var validTo = _certificateTimeValue(peerCert.valid_to);
	if (!isNaN(validTo) && validTo < now) return _createAuthorizationError("CERT_HAS_EXPIRED", "certificate has expired");
	var validFrom = _certificateTimeValue(peerCert.valid_from);
	if (!isNaN(validFrom) && validFrom > now) return _createAuthorizationError("CERT_NOT_YET_VALID", "certificate is not yet valid");
	var trustedSource = options && options.ca !== void 0 ? options.ca : _defaultCACertificates;
	var peerSource = remoteOptions && (remoteOptions.cert || remoteOptions.pfx);
	if (_sourceContainsCertificate(trustedSource, peerSource)) return null;
	var trusted = _collectTrustedCertificates(trustedSource, host, port);
	if (trusted === null) return _createAuthorizationError("UNABLE_TO_GET_ISSUER_CERT", "unable to get issuer certificate");
	if (!trusted.length) return _isSelfSignedCertificate(peerCert) || !!peerSource ? _createAuthorizationError("DEPTH_ZERO_SELF_SIGNED_CERT", "self-signed certificate") : null;
	var chain = _collectCertificateChain(peerCert);
	for (var i = 0; i < chain.length; i++) for (var j = 0; j < trusted.length; j++) if (_certificateEquals(chain[i], trusted[j])) return null;
	return _isSelfSignedCertificate(peerCert) || !!peerSource ? _createAuthorizationError("DEPTH_ZERO_SELF_SIGNED_CERT", "self-signed certificate") : _createAuthorizationError("UNABLE_TO_VERIFY_LEAF_SIGNATURE", "unable to verify the first certificate");
}
function _defaultCheckServerIdentity(hostname, cert) {
	var subject = cert && cert.subject;
	var altNames = cert && cert.subjectaltname;
	var dnsNames = [];
	var ips = [];
	hostname = "" + hostname;
	if (altNames) {
		var splitAltNames = altNames.indexOf("\"") !== -1 ? _splitEscapedAltNames(altNames) : altNames.split(", ");
		for (var i = 0; i < splitAltNames.length; i++) {
			var name = splitAltNames[i];
			if (name.indexOf("DNS:") === 0) dnsNames.push(name.slice(4));
			else if (name.indexOf("IP Address:") === 0) ips.push(_canonicalizeIp(name.slice(11)));
		}
	}
	var valid = false;
	var reason = "Unknown reason";
	hostname = _unfqdn(hostname);
	if (_isIpAddress(hostname)) {
		valid = ips.indexOf(_canonicalizeIp(hostname)) !== -1;
		if (!valid) reason = "IP: " + hostname + " is not in the cert's list: " + ips.join(", ");
	} else if (dnsNames.length > 0 || subject && subject.CN) {
		var hostParts = _splitHost(hostname);
		if (dnsNames.length > 0) {
			for (var j = 0; j < dnsNames.length; j++) if (_checkHostPattern(hostParts, dnsNames[j], true)) {
				valid = true;
				break;
			}
			if (!valid) reason = "Host: " + hostname + ". is not in the cert's altnames: " + altNames;
		} else {
			var cn = subject.CN;
			if (Array.isArray(cn)) {
				for (var k = 0; k < cn.length; k++) if (_checkHostPattern(hostParts, cn[k], true)) {
					valid = true;
					break;
				}
			} else if (cn) valid = _checkHostPattern(hostParts, cn, true);
			if (!valid) reason = "Host: " + hostname + ". is not cert's CN: " + cn;
		}
	} else reason = "Cert does not contain a DNS name";
	if (!valid) return _createAltNameError(reason, hostname, cert);
}
function checkServerIdentity(hostname, cert) {
	return _defaultCheckServerIdentity(hostname, cert);
}
function _translateInfoAccess(value) {
	if (value == null) return value;
	if (typeof value !== "string") return value;
	var infoAccess = Object.create(null);
	if (!value) return infoAccess;
	var lines = value.split("\n");
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		if (!line) continue;
		var sep = line.indexOf(":");
		if (sep === -1) continue;
		var key = line.slice(0, sep);
		var entryValue = line.slice(sep + 1);
		if (!hasOwn.call(infoAccess, key)) infoAccess[key] = [];
		infoAccess[key].push(entryValue);
	}
	return infoAccess;
}
function translatePeerCertificate(cert, seen) {
	if (cert == null || cert === 0) return null;
	if (!cert || typeof cert !== "object") return cert;
	seen = seen || [];
	for (var i = 0; i < seen.length; i++) if (seen[i].source === cert) return seen[i].clone;
	var clone = {};
	seen.push({
		source: cert,
		clone
	});
	for (var key in cert) {
		if (!hasOwn.call(cert, key)) continue;
		if (key === "issuerCertificate") clone[key] = cert[key] && typeof cert[key] === "object" ? translatePeerCertificate(cert[key], seen) : null;
		else if (key === "infoAccess") clone[key] = _translateInfoAccess(cert[key]);
		else clone[key] = cert[key];
	}
	return clone;
}
function _copySocketMetadata(socket, rawSocket) {
	if (!socket || !rawSocket) return;
	if (typeof rawSocket.remoteAddress !== "undefined") socket.remoteAddress = rawSocket.remoteAddress;
	if (typeof rawSocket.remotePort !== "undefined") socket.remotePort = rawSocket.remotePort;
	if (typeof rawSocket.remoteFamily !== "undefined") socket.remoteFamily = rawSocket.remoteFamily;
	if (typeof rawSocket.localAddress !== "undefined") socket.localAddress = rawSocket.localAddress;
	if (typeof rawSocket.localPort !== "undefined") socket.localPort = rawSocket.localPort;
	if (typeof rawSocket.localFamily !== "undefined") socket.localFamily = rawSocket.localFamily;
	if (typeof rawSocket.readable === "boolean") socket.readable = rawSocket.readable;
	if (typeof rawSocket.writable === "boolean") socket.writable = rawSocket.writable;
	if (typeof rawSocket.destroyed === "boolean") socket.destroyed = rawSocket.destroyed;
	if (typeof rawSocket.connecting === "boolean") socket.connecting = rawSocket.connecting;
	if (typeof rawSocket._isWriting === "boolean") socket._isWriting = rawSocket._isWriting;
	if (rawSocket._writeQueue) socket._writeQueue = rawSocket._writeQueue;
}
function _bindSocket(wrapper, rawSocket) {
	if (!wrapper || !rawSocket) return rawSocket;
	wrapper._socket = rawSocket;
	_copySocketMetadata(wrapper, rawSocket);
	if (wrapper._boundSocket === rawSocket || typeof rawSocket.on !== "function") return rawSocket;
	wrapper._boundSocket = rawSocket;
	var events = [
		"data",
		"end",
		"error",
		"close",
		"timeout",
		"drain",
		"lookup",
		"ready",
		"connect"
	];
	for (var i = 0; i < events.length; i++) (function(eventName) {
		rawSocket.on(eventName, function() {
			if (wrapper._bridged) {
				if (eventName === "data") {
					_tlsBridgeOnCiphertext(wrapper, arguments[0]);
					return;
				}
				if (eventName === "drain") {
					_tlsBridgeOnRawDrain(wrapper);
					return;
				}
				if (eventName === "end") {
					_tlsBridgeOnTransportEnd(wrapper);
					return;
				}
				if (eventName === "close") _tlsBridgeRelease(wrapper);
			}
			if (eventName === "connect") wrapper.connecting = false;
			if (eventName === "end") wrapper.readable = false;
			if (eventName === "close") wrapper.destroyed = true;
			_copySocketMetadata(wrapper, rawSocket);
			if (typeof wrapper.emit === "function") wrapper.emit.apply(wrapper, [eventName].concat(Array.prototype.slice.call(arguments)));
		});
	})(events[i]);
	return rawSocket;
}
function _callSocketMethod(wrapper, methodName, args, fallback) {
	if (wrapper && wrapper._socket && typeof wrapper._socket[methodName] === "function") return wrapper._socket[methodName].apply(wrapper._socket, args || []);
	return fallback;
}
function _finalizeHandshake(socket, peerOptions, negotiatedCipher) {
	var opts = socket._tlsOptions || {};
	var remoteOptions = peerOptions || {};
	var host = socket._servername || socket.remoteAddress || "localhost";
	socket._peerCertificate = _buildPeerCertificate(host, socket.remotePort, remoteOptions, opts);
	socket._localCertificate = _buildLocalCertificate(host, socket.remotePort, opts);
	socket._cipher = {
		name: negotiatedCipher || _normalizeCipherName(remoteOptions.ciphers || opts.ciphers),
		version: socket._protocol
	};
	socket._authorizationErrorObject = null;
	var authorizationError = _validatePeerAuthorization(socket._peerCertificate, opts, host, socket.remotePort, remoteOptions);
	if (authorizationError) {
		socket.authorizationError = authorizationError.code || authorizationError.message || String(authorizationError);
		socket._authorizationErrorObject = authorizationError;
		socket.authorized = false;
		return false;
	}
	var check = opts.checkServerIdentity || checkServerIdentity;
	var result = null;
	try {
		result = _normalizeCheckError(check(host, socket._peerCertificate, opts));
	} catch (error) {
		result = _normalizeCheckError(error);
	}
	if (result) {
		socket.authorizationError = result.code || result.message || String(result);
		socket._authorizationErrorObject = result;
		socket.authorized = false;
		return false;
	}
	socket.authorizationError = null;
	socket._authorizationErrorObject = null;
	socket.authorized = true;
	return true;
}
function _finalizeServerHandshake(socket, clientOptions, negotiatedCipher) {
	var serverOptions = socket._tlsOptions || {};
	var host = socket.remoteAddress || socket.servername || "localhost";
	socket._peerCertificate = clientOptions && (clientOptions.cert || clientOptions.pfx) ? _buildPeerCertificate(host, socket.remotePort, clientOptions, serverOptions) : null;
	socket._localCertificate = _buildLocalCertificate(host, socket.remotePort, serverOptions);
	socket._cipher = {
		name: negotiatedCipher || _normalizeCipherName(serverOptions.ciphers),
		version: socket._protocol
	};
	socket.connecting = false;
	socket.pending = false;
	socket._secureEstablished = true;
	socket.authorizationError = null;
	socket.authorized = !socket._server || !socket._server.requestCert;
}
function _applyPendingServerHandshake(server, tlsSocket, handshake) {
	if (!server || !tlsSocket || !handshake) return;
	if (handshake.ok) {
		_finalizeServerHandshake(tlsSocket, handshake.clientOptions, handshake.cipher);
		tlsSocket.emit("secure", true);
		server.emit("secureConnection", tlsSocket);
		return;
	}
	tlsSocket.authorizationError = handshake.serverError && handshake.serverError.message ? handshake.serverError.message : "handshake failure";
	if (tlsSocket._socket && typeof tlsSocket._socket.destroy === "function") try {
		tlsSocket._socket.destroy(handshake.serverError);
	} catch (_destroyTlsSocketErr) {}
	server.emit("tlsClientError", handshake.serverError, tlsSocket);
}
function _decorateSecureContext(target, options) {
	var normalized = _cloneOwnProperties(options || {});
	_validateProtocolVersion("minimum", normalized.minVersion);
	_validateProtocolVersion("maximum", normalized.maxVersion);
	normalized._cipherSuites = _resolveCipherSuites(normalized, "server");
	if (hasOwn.call(normalized, "ALPNProtocols") && normalized.ALPNProtocols !== null && typeof normalized.ALPNProtocols !== "undefined") normalized.ALPNProtocols = convertALPNProtocols(normalized.ALPNProtocols);
	target.context = normalized;
	target._options = normalized;
	return target;
}
function SecureContext(options) {
	if (!(this instanceof SecureContext)) return new SecureContext(options);
	this.context = {};
	this._options = this.context;
	if (options && typeof options === "object") _decorateSecureContext(this, options);
}
function createSecureContext(options) {
	if (options instanceof SecureContext) return options;
	return new SecureContext(options || {});
}
function TLSSocket(socket, options) {
	if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);
	options = options || {};
	this._events = {};
	_mixinEventEmitter(this);
	this._socket = null;
	this._boundSocket = null;
	this._tlsOptions = _cloneOwnProperties(options);
	this.encrypted = true;
	this.authorized = false;
	this.authorizationError = null;
	this._authorizationErrorObject = null;
	this._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
	this._session = null;
	this._sessionReused = false;
	this._peerCertificate = null;
	this._localCertificate = null;
	this._readableHighWaterMark = _normalizeTlsHighWaterMark(options.readableHighWaterMark, socket && socket.readableHighWaterMark);
	this._writableHighWaterMark = _normalizeTlsHighWaterMark(options.writableHighWaterMark, socket && socket.writableHighWaterMark);
	this._bufferedBytes = 0;
	this._bridgeNeedDrain = false;
	this._secureEstablished = false;
	this._pending = true;
	this._servername = options.servername || options.host || options.hostname || null;
	this.servername = this._servername;
	this.alpnProtocol = null;
	_defineOwnDataProperty(this, "connecting", true);
	_defineOwnDataProperty(this, "readable", true);
	_defineOwnDataProperty(this, "writable", true);
	_defineOwnDataProperty(this, "destroyed", false);
	_defineOwnDataProperty(this, "remoteAddress", null);
	_defineOwnDataProperty(this, "remotePort", null);
	_defineOwnDataProperty(this, "remoteFamily", "IPv4");
	_defineOwnDataProperty(this, "localAddress", null);
	_defineOwnDataProperty(this, "localPort", null);
	_defineOwnDataProperty(this, "localFamily", "IPv4");
	this._cipher = {
		name: _normalizeCipherName(options.ciphers),
		version: this._protocol
	};
	if (socket) {
		this.connecting = !!socket.connecting;
		this._pending = !!socket.connecting;
		_bindSocket(this, socket);
	}
}
if (net && net.Socket && typeof Object.setPrototypeOf === "function") Object.setPrototypeOf(TLSSocket, net.Socket);
TLSSocket.prototype.constructor = TLSSocket;
TLSSocket.prototype._setSocket = function(socket) {
	_bindSocket(this, socket);
	return this;
};
TLSSocket.prototype[_kReinitializeHandle] = function() {
	return this;
};
TLSSocket.prototype.getPeerCertificate = function(detailed) {
	return this._peerCertificate ? _cloneCertificate(this._peerCertificate, detailed === true) : {};
};
TLSSocket.prototype.getPeerX509Certificate = function() {
	return _toX509Certificate(this._peerCertificate, true);
};
TLSSocket.prototype.getCertificate = function() {
	return this._localCertificate ? _cloneCertificate(this._localCertificate, true) : {};
};
TLSSocket.prototype.getX509Certificate = function() {
	return _toX509Certificate(this._localCertificate, false);
};
TLSSocket.prototype.getCipher = function() {
	return this._cipher || {
		name: _normalizeCipherName(this._tlsOptions && this._tlsOptions.ciphers),
		version: this._protocol
	};
};
TLSSocket.prototype.getProtocol = function() {
	return this._protocol;
};
TLSSocket.prototype.getSession = function() {
	return this._session;
};
TLSSocket.prototype.setSession = function(session) {
	this._session = session || null;
	return this;
};
TLSSocket.prototype.isSessionReused = function() {
	return !!this._sessionReused;
};
TLSSocket.prototype.getFinished = function() {
	return null;
};
TLSSocket.prototype.getTLSTicket = function() {
	return null;
};
TLSSocket.prototype.getSharedSigalgs = function() {
	return [];
};
TLSSocket.prototype.renegotiate = function(options, callback) {
	if (options === null || typeof options !== "object") throw _createError("ERR_INVALID_ARG_TYPE", "The \"options\" argument must be of type object. Received " + (options === null ? "null" : typeof options));
	if (callback !== void 0 && typeof callback !== "function") throw _createError("ERR_INVALID_ARG_TYPE", "The \"callback\" argument must be of type function. Received " + typeof callback);
	if (this.destroyed) return void 0;
	if (this._protocol === "TLSv1.3") {
		if (typeof callback === "function") {
			var err = _createError("ERR_SSL_WRONG_SSL_VERSION", "error:0A00010A:SSL routines::wrong ssl version");
			err.library = "SSL routines";
			err.reason = "wrong ssl version";
			setTimeout(function() {
				callback(err);
			}, 0);
		}
		return false;
	}
	if (typeof callback === "function") setTimeout(function() {
		callback(null);
	}, 0);
	return true;
};
TLSSocket.prototype.disableRenegotiation = function() {
	this._renegotiationDisabled = true;
};
TLSSocket.prototype.enableTrace = function() {
	return _callSocketMethod(this, "enableTrace", [], void 0);
};
TLSSocket.prototype.setMaxSendFragment = function(size) {
	if (typeof size !== "number" || size !== (size | 0) || size < 512 || size > 16384) return false;
	this._maxSendFragment = size;
	return true;
};
TLSSocket.prototype.setEncoding = function(enc) {
	this._bridgeEncoding = enc || null;
	this._bridgeDecoder = enc && StringDecoder ? new StringDecoder(enc) : null;
	this._bridgeDecoderFinalized = false;
	this._bridgeDecodedTail = null;
	if (this._bridged || this._writeHeld || this.connecting || this.pending) return this;
	_callSocketMethod(this, "setEncoding", [enc], this);
	return this;
};
TLSSocket.prototype.read = function(size) {
	if (this._bridged) {
		this._bridgeReadDepth = (this._bridgeReadDepth || 0) + 1;
		try {
			_tlsBridgeDrainPlain(this);
			var queue = this._bridgeReadQueue || [];
			if (!queue.length) {
				if (this._bridgeDecodedTail !== null && this._bridgeDecodedTail !== void 0) {
					var decoderTail = this._bridgeDecodedTail;
					this._bridgeDecodedTail = null;
					_tlsBridgeMaybeEmitEnd(this);
					return decoderTail;
				}
				return null;
			}
			var available = this._bridgeReadQueueBytes || 0;
			if (typeof size === "number" && size > available && !this._bridgeNativeEnded) return null;
			var wanted = typeof size === "number" && size > 0 ? Math.min(size, available) : available;
			var combined = typeof Buffer !== "undefined" && Buffer.concat ? Buffer.concat(queue, available) : queue[0];
			var result = wanted === available ? combined : combined.slice(0, wanted);
			var remainder = wanted === available ? null : combined.slice(wanted);
			this._bridgeReadQueue = remainder && remainder.length ? [remainder] : [];
			this._bridgeReadQueueBytes = available - wanted;
			var encodedResult = _tlsBridgeEncode(this, result);
			_tlsBridgeMaybeResumeInput(this);
			_tlsBridgeMaybeEmitEnd(this);
			return encodedResult;
		} finally {
			this._bridgeReadDepth = Math.max(0, (this._bridgeReadDepth || 1) - 1);
		}
	}
	return _callSocketMethod(this, "read", [size], null);
};
TLSSocket.prototype.push = function(chunk, encoding) {
	return _callSocketMethod(this, "push", [chunk, encoding], false);
};
TLSSocket.prototype.unshift = function(chunk) {
	return _callSocketMethod(this, "unshift", [chunk], void 0);
};
TLSSocket.prototype.close = function(err) {
	return this.destroy(err);
};
TLSSocket.prototype.connect = function() {
	_callSocketMethod(this, "connect", Array.prototype.slice.call(arguments), this);
	return this;
};
TLSSocket.prototype.write = function(data, encoding, callback) {
	if (typeof encoding === "function") {
		callback = encoding;
		encoding = void 0;
	}
	if (this._writeHeld) {
		if (!this._heldWrites) this._heldWrites = [];
		var heldBuffer = _tlsWriteBuffer(data, encoding);
		var heldLength = _byteLength(heldBuffer);
		this._heldWrites.push({
			buffer: heldBuffer,
			offset: 0,
			callback
		});
		this._heldWriteBytes = (this._heldWriteBytes || 0) + heldLength;
		this._bufferedBytes = this._heldWriteBytes;
		if (this._heldWriteBytes >= this._writableHighWaterMark) this._bridgeNeedDrain = true;
		return this._heldWriteBytes < this._writableHighWaterMark;
	}
	if (this._bridged) return _tlsBridgeWrite(this, data, encoding, callback);
	if (this._socket && typeof this._socket.write === "function") return this._socket.write(data, encoding, callback);
	if (typeof callback === "function") setTimeout(callback, 0);
	return true;
};
TLSSocket.prototype.end = function(data, encoding, callback) {
	if (typeof data === "function") {
		callback = data;
		data = void 0;
		encoding = void 0;
	}
	if (typeof encoding === "function") {
		callback = encoding;
		encoding = void 0;
	}
	if (this._writeHeld) {
		if (data !== void 0 && data !== null) this.write(data, encoding);
		this.writable = false;
		this._heldEnd = typeof callback === "function" ? callback : true;
		return this;
	}
	if (this._bridged) {
		if (data !== void 0 && data !== null) _tlsBridgeWrite(this, data, encoding, null);
		this.writable = false;
		this._bridgeHeldEnd = typeof callback === "function" ? callback : true;
		_tlsBridgeMaybeFinishEnd(this);
		return this;
	}
	this.writable = false;
	if (this._socket && typeof this._socket.end === "function") {
		this._socket.end(data, encoding, callback);
		return this;
	}
	if (typeof callback === "function") setTimeout(callback, 0);
	return this;
};
TLSSocket.prototype.destroy = function(err) {
	this.destroyed = true;
	this.readable = false;
	this.writable = false;
	this._writeHeld = false;
	this._heldWrites = null;
	this._heldWriteBytes = 0;
	this._heldEnd = null;
	this._bridgePendingWrites = null;
	this._bridgePendingWriteBytes = 0;
	this._bridgeHeldEnd = null;
	this._bridgeReadQueue = null;
	this._bridgeReadQueueBytes = 0;
	this._bridgeDecoder = null;
	this._bridgeDecodedTail = null;
	this._bridgeCipherQueue = null;
	this._bridgeCipherQueueBytes = 0;
	_tlsBridgeRelease(this);
	if (this._socket && typeof this._socket.destroy === "function") this._socket.destroy(err);
	return this;
};
TLSSocket.prototype.setTimeout = function(timeout, callback) {
	if (typeof callback === "function" && typeof this.once === "function") this.once("timeout", callback);
	_callSocketMethod(this, "setTimeout", [timeout], this);
	return this;
};
TLSSocket.prototype.setNoDelay = function(noDelay) {
	_callSocketMethod(this, "setNoDelay", [noDelay], this);
	return this;
};
TLSSocket.prototype.setKeepAlive = function(enable, initialDelay) {
	_callSocketMethod(this, "setKeepAlive", [enable, initialDelay], this);
	return this;
};
TLSSocket.prototype.ref = function() {
	_callSocketMethod(this, "ref", [], this);
	return this;
};
TLSSocket.prototype.unref = function() {
	_callSocketMethod(this, "unref", [], this);
	return this;
};
TLSSocket.prototype.address = function() {
	if (this._socket && typeof this._socket.address === "function") return this._socket.address();
	return {
		address: this.localAddress || this.remoteAddress,
		port: this.localPort || this.remotePort,
		family: this.localFamily || this.remoteFamily || "IPv4"
	};
};
TLSSocket.prototype.pause = function() {
	if (this._bridged) this._bridgePaused = true;
	_callSocketMethod(this, "pause", [], this);
	return this;
};
TLSSocket.prototype.resume = function() {
	if (this._bridged) {
		this._bridgePaused = false;
		_tlsBridgeFlushReadQueue(this);
		_tlsBridgeMaybeResumeInput(this);
	}
	_callSocketMethod(this, "resume", [], this);
	return this;
};
TLSSocket.prototype.on = function(eventName, listener) {
	var result = EventEmitter && EventEmitter.prototype && EventEmitter.prototype.on ? EventEmitter.prototype.on.call(this, eventName, listener) : this;
	if (this._bridged && eventName === "data") {
		this._bridgePaused = false;
		_tlsBridgeFlushReadQueue(this);
		_tlsBridgeMaybeResumeInput(this);
	}
	return result;
};
TLSSocket.prototype.addListener = TLSSocket.prototype.on;
TLSSocket.prototype.pipe = function(dest, options) {
	if (this._bridged) {
		var source = this;
		var shouldEnd = !options || options.end !== false;
		function onData(chunk) {
			if (dest && typeof dest.write === "function" && dest.write(chunk) === false) source.pause();
		}
		function onDrain() {
			source.resume();
		}
		function onEnd() {
			if (shouldEnd && dest && typeof dest.end === "function") dest.end();
		}
		source.on("data", onData);
		source.once("end", onEnd);
		if (dest && typeof dest.on === "function") dest.on("drain", onDrain);
		source.resume();
		return dest;
	}
	if (this._socket && typeof this._socket.pipe === "function") return this._socket.pipe(dest, options);
	return dest;
};
TLSSocket.prototype.cork = function() {
	_callSocketMethod(this, "cork", [], this);
	return this;
};
TLSSocket.prototype.uncork = function() {
	_callSocketMethod(this, "uncork", [], this);
	return this;
};
if (typeof Object.defineProperty === "function") {
	Object.defineProperty(TLSSocket.prototype, "bytesRead", {
		configurable: true,
		enumerable: true,
		get: function() {
			if (this === TLSSocket.prototype) return void 0;
			if (this._socket && typeof this._socket.bytesRead === "number") return this._socket.bytesRead;
			return 0;
		}
	});
	Object.defineProperty(TLSSocket.prototype, "bytesWritten", {
		configurable: true,
		enumerable: true,
		get: function() {
			if (this === TLSSocket.prototype) return void 0;
			if (this._socket && typeof this._socket.bytesWritten === "number") return this._socket.bytesWritten;
			return 0;
		}
	});
	Object.defineProperty(TLSSocket.prototype, "pending", {
		configurable: true,
		enumerable: true,
		get: function() {
			return typeof this._pending === "boolean" ? this._pending : !this._secureEstablished;
		},
		set: function(value) {
			this._pending = !!value;
		}
	});
	Object.defineProperty(TLSSocket.prototype, "readyState", {
		configurable: true,
		enumerable: true,
		get: function() {
			if (this._socket && typeof this._socket.readyState === "string") return this._socket.readyState;
			if (this.destroyed) return "closed";
			return this.connecting ? "opening" : "open";
		}
	});
}
_mixinEventEmitter(TLSSocket.prototype);
if (net && net.Socket && net.Socket.prototype && typeof Object.setPrototypeOf === "function") Object.setPrototypeOf(TLSSocket.prototype, net.Socket.prototype);
function _normalizeTlsConnectArguments(args) {
	var options = {};
	var callback = null;
	if (!args || !args.length) return {
		options,
		callback
	};
	var first = args[0];
	var second = args[1];
	var third = args[2];
	var fourth = args[3];
	if (first && typeof first === "object" && !Array.isArray(first)) {
		options = _cloneOwnProperties(first);
		callback = typeof second === "function" ? second : null;
		return {
			options,
			callback
		};
	}
	if (typeof first === "number") {
		options.port = first;
		if (typeof second === "string") {
			options.host = second;
			if (third && typeof third === "object" && !Array.isArray(third)) {
				var thirdOptions = _cloneOwnProperties(third);
				for (var key in thirdOptions) if (hasOwn.call(thirdOptions, key)) options[key] = thirdOptions[key];
				callback = typeof fourth === "function" ? fourth : null;
			} else callback = typeof third === "function" ? third : null;
		} else if (second && typeof second === "object" && !Array.isArray(second)) {
			var secondOptions = _cloneOwnProperties(second);
			for (var key2 in secondOptions) if (hasOwn.call(secondOptions, key2)) options[key2] = secondOptions[key2];
			callback = typeof third === "function" ? third : null;
		} else callback = typeof second === "function" ? second : null;
		if (!options.host && !options.hostname) options.host = "localhost";
		return {
			options,
			callback
		};
	}
	if (typeof first === "string") {
		options.host = first;
		if (typeof second === "number") {
			options.port = second;
			if (third && typeof third === "object" && !Array.isArray(third)) {
				var thirdOptions2 = _cloneOwnProperties(third);
				for (var key3 in thirdOptions2) if (hasOwn.call(thirdOptions2, key3)) options[key3] = thirdOptions2[key3];
				callback = typeof fourth === "function" ? fourth : null;
			} else callback = typeof third === "function" ? third : null;
		} else if (second && typeof second === "object" && !Array.isArray(second)) {
			var secondOptions2 = _cloneOwnProperties(second);
			for (var key4 in secondOptions2) if (hasOwn.call(secondOptions2, key4)) options[key4] = secondOptions2[key4];
			callback = typeof third === "function" ? third : null;
		} else callback = typeof second === "function" ? second : null;
		if (typeof options.port === "undefined") options.port = 443;
		return {
			options,
			callback
		};
	}
	return {
		options,
		callback
	};
}
function _tlsBridgeAvailable() {
	return typeof __exactTlsEngineNew === "function" && typeof __exactTlsEngineWriteTls === "function" && typeof __exactTlsEngineReadTls === "function" && typeof __exactTlsEngineReadPlain === "function" && typeof __exactTlsEngineWritePlain === "function" && typeof __exactTlsEngineStatus === "function";
}
function _alpnProtocolsToList(protocols) {
	if (!protocols) return [];
	if (Array.isArray(protocols)) {
		var listed = [];
		for (var i = 0; i < protocols.length; i++) listed.push(String(protocols[i]));
		return listed;
	}
	var view = _cloneBufferLike(protocols);
	var out = [];
	var offset = 0;
	var total = typeof view.length === "number" ? view.length : 0;
	while (offset < total) {
		var size = view[offset++];
		var end = Math.min(offset + size, total);
		var proto = "";
		for (; offset < end; offset++) proto += String.fromCharCode(view[offset]);
		out.push(proto);
	}
	return out;
}
function _wrapBase64Lines(b64) {
	var lines = [];
	for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
	return lines.join("\n");
}
function _buildBridgedPeerChain(derChain) {
	var parsed = [];
	for (var i = 0; i < derChain.length; i++) {
		var cert = _parsePemCertificate("-----BEGIN CERTIFICATE-----\n" + _wrapBase64Lines(derChain[i]) + "\n-----END CERTIFICATE-----\n");
		if (cert) parsed.push(cert);
	}
	if (!parsed.length) return null;
	for (var k = 0; k < parsed.length; k++) {
		parsed[k].ca = k > 0 || _nameKey(parsed[k].subject) === _nameKey(parsed[k].issuer);
		if (k + 1 < parsed.length) parsed[k].issuerCertificate = parsed[k + 1];
	}
	var last = parsed[parsed.length - 1];
	if (_nameKey(last.subject) === _nameKey(last.issuer)) last.issuerCertificate = last;
	return parsed[0];
}
function _refineBridgeVerifyError(verify, peerCert) {
	var code = verify && verify.code;
	if (!code) return _createAuthorizationError("UNABLE_TO_VERIFY_CERT", "certificate verification failed");
	if (code === "UNKNOWN_ISSUER") {
		var chain = _collectCertificateChain(peerCert);
		var tail = chain.length ? chain[chain.length - 1] : null;
		if (chain.length === 1 && _isSelfSignedCertificate(chain[0])) return _createAuthorizationError("DEPTH_ZERO_SELF_SIGNED_CERT", "self-signed certificate");
		if (tail && _isSelfSignedCertificate(tail)) return _createAuthorizationError("SELF_SIGNED_CERT_IN_CHAIN", "self-signed certificate in certificate chain");
		if (chain.length > 1) return _createAuthorizationError("UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "unable to get local issuer certificate");
		return _createAuthorizationError("UNABLE_TO_VERIFY_LEAF_SIGNATURE", "unable to verify the first certificate");
	}
	if (code === "CERT_HAS_EXPIRED") return _createAuthorizationError("CERT_HAS_EXPIRED", "certificate has expired");
	if (code === "CERT_NOT_YET_VALID") return _createAuthorizationError("CERT_NOT_YET_VALID", "certificate is not yet valid");
	if (code === "CERT_REVOKED") return _createAuthorizationError("CERT_REVOKED", "certificate revoked");
	if (code === "CERT_SIGNATURE_FAILURE") return _createAuthorizationError("CERT_SIGNATURE_FAILURE", "certificate signature failure");
	if (code === "INVALID_PURPOSE") return _createAuthorizationError("INVALID_PURPOSE", "unsupported certificate purpose");
	return _createAuthorizationError(code, verify.reason || "certificate verification failed");
}
function _tlsBridgeStatus(socket) {
	if (socket._tlsEngineId == null) return null;
	try {
		return JSON.parse(__exactTlsEngineStatus(socket._tlsEngineId));
	} catch (e) {
		return null;
	}
}
function _tlsBridgeRelease(socket) {
	if (socket._tlsEngineId == null) return;
	var id = socket._tlsEngineId;
	socket._tlsEngineId = null;
	if (typeof __exactTlsEngineClose === "function") try {
		__exactTlsEngineClose(id);
	} catch (e) {}
}
function _tlsBridgeFail(socket, err) {
	_tlsBridgeRelease(socket);
	if (socket.destroyed) return;
	socket.destroy(err);
}
function _tlsBridgeErrorFromStatus(socket, fallbackMessage) {
	var status = _tlsBridgeStatus(socket);
	var message = status && status.error || fallbackMessage || "TLS handshake failed";
	return _createError(status && status.errorCode || "ERR_TLS_HANDSHAKE_FAILURE", message);
}
function _tlsBridgePumpOut(socket) {
	if (socket._tlsEngineId == null || socket._bridgeTransportBackpressured) return false;
	for (;;) {
		var raw = socket._socket;
		if (!raw || typeof raw.write !== "function" || raw.destroyed) {
			if (!socket.destroyed) _tlsBridgeFail(socket, _createError("ERR_TLS_SOCKET_CLOSED", "TLS transport is not writable"));
			return false;
		}
		var chunk;
		try {
			chunk = __exactTlsEngineReadTls(socket._tlsEngineId, 65536);
		} catch (e) {
			return false;
		}
		if (!chunk || typeof chunk === "string" || !chunk.byteLength) return true;
		if (raw.write(_bufferFromBytes(chunk)) === false) {
			socket._bridgeTransportBackpressured = true;
			socket._bridgeNeedDrain = true;
			return false;
		}
	}
}
function _tlsBridgeEncode(socket, data) {
	if (!socket._bridgeEncoding || !data || typeof data.toString !== "function") return data;
	if (socket._bridgeDecoder && typeof socket._bridgeDecoder.write === "function") return socket._bridgeDecoder.write(data);
	return data.toString(socket._bridgeEncoding);
}
function _tlsBridgeEmitData(socket, data) {
	var encoded = _tlsBridgeEncode(socket, data);
	if (typeof encoded === "string" && encoded.length === 0) return;
	if (typeof socket.emit === "function") socket.emit("data", encoded);
}
function _tlsBridgeIsFlowing(socket) {
	return !socket._bridgePaused && typeof socket.listenerCount === "function" && socket.listenerCount("data") > 0;
}
function _tlsBridgePauseInput(socket) {
	if (socket._bridgeInputPaused) return;
	socket._bridgeInputPaused = true;
	var raw = socket._socket;
	if (raw && typeof raw.pause === "function") raw.pause();
}
function _tlsBridgeDrainPlain(socket) {
	if (socket._tlsEngineId == null) return false;
	var madeProgress = false;
	for (;;) {
		var flowing = _tlsBridgeIsFlowing(socket);
		var capacity = flowing ? 65536 : Math.max(0, socket._readableHighWaterMark - (socket._bridgeReadQueueBytes || 0));
		if (capacity <= 0) {
			_tlsBridgePauseInput(socket);
			return madeProgress;
		}
		var chunk;
		try {
			chunk = __exactTlsEngineReadPlain(socket._tlsEngineId, Math.min(65536, capacity));
		} catch (e) {
			_tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket, "TLS record processing failed"));
			return madeProgress;
		}
		if (chunk === null) {
			socket._bridgeNativeEnded = true;
			_tlsBridgeMaybeEmitEnd(socket);
			return madeProgress;
		}
		if (!chunk || typeof chunk === "string" || !chunk.byteLength) return madeProgress;
		madeProgress = true;
		if (socket._tlsEngineId == null || socket.destroyed) return madeProgress;
		var data = _bufferFromBytes(chunk);
		if (flowing && typeof socket.emit === "function") _tlsBridgeEmitData(socket, data);
		else {
			if (!socket._bridgeReadQueue) socket._bridgeReadQueue = [];
			socket._bridgeReadQueue.push(data);
			socket._bridgeReadQueueBytes = (socket._bridgeReadQueueBytes || 0) + _byteLength(data);
			if (typeof socket.emit === "function") socket.emit("readable");
		}
	}
}
function _tlsBridgeFlushReadQueue(socket) {
	if (socket._bridgePaused || !socket._bridgeReadQueue || !socket._bridgeReadQueue.length || typeof socket.listenerCount !== "function" || socket.listenerCount("data") === 0) return;
	var pending = socket._bridgeReadQueue;
	socket._bridgeReadQueue = [];
	socket._bridgeReadQueueBytes = 0;
	var i = 0;
	for (; i < pending.length && !socket._bridgePaused; i++) _tlsBridgeEmitData(socket, pending[i]);
	if (i < pending.length) {
		socket._bridgeReadQueue = pending.slice(i);
		for (; i < pending.length; i++) socket._bridgeReadQueueBytes += _byteLength(pending[i]);
	}
	_tlsBridgeMaybeEmitEnd(socket);
}
function _tlsBridgeFlushPendingWrites(socket) {
	_tlsBridgeDrainApplicationWrites(socket);
	_tlsBridgeMaybeFinishEnd(socket);
}
function _tlsBridgeUpdateBufferedBytes(socket) {
	socket._bufferedBytes = (socket._heldWriteBytes || 0) + (socket._bridgePendingWriteBytes || 0);
}
function _tlsBridgeMaybeEmitDrain(socket) {
	if (!socket._bridgeNeedDrain || socket._bridgeTransportBackpressured || (socket._bridgePendingWriteBytes || 0) >= socket._writableHighWaterMark || !socket._secureEstablished || socket.destroyed) return;
	socket._bridgeNeedDrain = false;
	if (socket._bridgeDrainScheduled) return;
	socket._bridgeDrainScheduled = true;
	setTimeout(function() {
		socket._bridgeDrainScheduled = false;
		if (!socket.destroyed && typeof socket.emit === "function") socket.emit("drain");
	}, 0);
}
function _tlsBridgeDrainApplicationWrites(socket) {
	if (!socket._secureEstablished || socket._tlsEngineId == null || socket._bridgeTransportBackpressured || socket.destroyed) return;
	var pending = socket._bridgePendingWrites || [];
	var zeroProgressRetries = 0;
	while (pending.length && !socket._bridgeTransportBackpressured && !socket.destroyed) {
		var item = pending[0];
		var total = _byteLength(item.buffer);
		if (item.offset >= total) {
			pending.shift();
			if (typeof item.callback === "function") setTimeout(item.callback, 0);
			continue;
		}
		var chunk = item.offset === 0 ? item.buffer : item.buffer.slice(item.offset);
		var accepted;
		try {
			accepted = __exactTlsEngineWritePlain(socket._tlsEngineId, chunk);
		} catch (e) {
			accepted = -1;
		}
		if (accepted < 0) {
			_tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket, "TLS write failed"));
			return;
		}
		if (accepted === 0) {
			_tlsBridgePumpOut(socket);
			if (socket._bridgeTransportBackpressured || socket.destroyed) return;
			if (++zeroProgressRetries <= 1) continue;
			if (!socket._bridgeWriteRetryScheduled) {
				socket._bridgeWriteRetryScheduled = true;
				setTimeout(function() {
					socket._bridgeWriteRetryScheduled = false;
					_tlsBridgeDrainApplicationWrites(socket);
				}, 0);
			}
			return;
		}
		zeroProgressRetries = 0;
		item.offset += accepted;
		socket._bridgePendingWriteBytes = Math.max(0, (socket._bridgePendingWriteBytes || 0) - accepted);
		_tlsBridgeUpdateBufferedBytes(socket);
		_tlsBridgePumpOut(socket);
	}
	socket._bridgePendingWrites = pending;
	_tlsBridgeMaybeEmitDrain(socket);
	_tlsBridgeMaybeFinishEnd(socket);
}
function _tlsBridgeMaybeFinishEnd(socket) {
	if (!socket._bridgeHeldEnd || !socket._secureEstablished || socket.destroyed || socket._bridgePendingWrites && socket._bridgePendingWrites.length) return;
	if (!socket._bridgeShutdownQueued) {
		socket._bridgeShutdownQueued = true;
		if (socket._tlsEngineId != null && typeof __exactTlsEngineShutdown === "function") try {
			__exactTlsEngineShutdown(socket._tlsEngineId);
		} catch (e) {}
	}
	_tlsBridgePumpOut(socket);
	var status = _tlsBridgeStatus(socket);
	if (socket._bridgeTransportBackpressured || status && status.wantsWrite) return;
	var callback = socket._bridgeHeldEnd;
	socket._bridgeHeldEnd = null;
	var raw = socket._socket;
	if (raw && typeof raw.end === "function") raw.end(typeof callback === "function" ? callback : void 0);
	else if (typeof callback === "function") setTimeout(callback, 0);
}
function _tlsBridgeOnRawDrain(socket) {
	socket._bridgeTransportBackpressured = false;
	_tlsBridgePumpOut(socket);
	if (!socket._bridgeTransportBackpressured) _tlsBridgeDrainApplicationWrites(socket);
	_tlsBridgeMaybeFinishEnd(socket);
	_tlsBridgeMaybeEmitDrain(socket);
}
function _tlsReleaseHeldWrites(socket, mode) {
	if (!socket._writeHeld) return;
	socket._writeHeld = false;
	var held = socket._heldWrites || [];
	socket._heldWrites = null;
	socket._heldWriteBytes = 0;
	var heldEnd = socket._heldEnd;
	socket._heldEnd = null;
	if (mode === "drop") {
		_tlsBridgeUpdateBufferedBytes(socket);
		return;
	}
	if (mode === "bridge") {
		if (!socket._bridgePendingWrites) socket._bridgePendingWrites = [];
		for (var i = 0; i < held.length; i++) {
			socket._bridgePendingWrites.push(held[i]);
			socket._bridgePendingWriteBytes = (socket._bridgePendingWriteBytes || 0) + Math.max(0, _byteLength(held[i].buffer) - (held[i].offset || 0));
		}
		_tlsBridgeUpdateBufferedBytes(socket);
		if (heldEnd) socket._bridgeHeldEnd = heldEnd;
		return;
	}
	var raw = socket._socket;
	if (socket._bridgeEncoding && raw && typeof raw.setEncoding === "function") raw.setEncoding(socket._bridgeEncoding);
	for (var j = 0; j < held.length; j++) if (raw && typeof raw.write === "function") raw.write(held[j].buffer, held[j].callback);
	else if (typeof held[j].callback === "function") setTimeout(held[j].callback, 0);
	if (heldEnd && raw && typeof raw.end === "function") raw.end(typeof heldEnd === "function" ? heldEnd : void 0);
}
function _tlsBridgeWrite(socket, data, encoding, callback) {
	if (socket.destroyed || socket._tlsEngineId == null) {
		if (typeof callback === "function") setTimeout(callback, 0);
		return false;
	}
	var buf = _tlsWriteBuffer(data, encoding);
	var length = _byteLength(buf);
	if (!socket._bridgePendingWrites) socket._bridgePendingWrites = [];
	socket._bridgePendingWrites.push({
		buffer: buf,
		offset: 0,
		callback
	});
	socket._bridgePendingWriteBytes = (socket._bridgePendingWriteBytes || 0) + length;
	_tlsBridgeUpdateBufferedBytes(socket);
	if (socket._secureEstablished) _tlsBridgeDrainApplicationWrites(socket);
	var backpressured = socket._bridgeTransportBackpressured || socket._bridgePendingWriteBytes >= socket._writableHighWaterMark;
	if (backpressured) socket._bridgeNeedDrain = true;
	return !backpressured;
}
function _finalizeBridgedHandshake(socket) {
	if (socket._secureEstablished || socket.destroyed) return;
	var opts = socket._tlsOptions || {};
	var status = _tlsBridgeStatus(socket);
	if (!status) return;
	if (status.error) {
		_tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket));
		return;
	}
	if (status.handshaking) return;
	socket._secureEstablished = true;
	socket.pending = false;
	socket.encrypted = true;
	if (status.protocol) socket._protocol = status.protocol;
	socket._cipher = {
		name: status.cipher || null,
		standardName: status.cipherStandard || status.cipher || null,
		version: status.protocol || socket._protocol
	};
	socket.alpnProtocol = status.alpn || false;
	if (!(opts.servername || opts.sni)) socket.servername = false;
	socket._session = null;
	socket._sessionReused = false;
	var derChain = [];
	try {
		derChain = JSON.parse(__exactTlsEnginePeerCerts(socket._tlsEngineId)) || [];
	} catch (e) {
		derChain = [];
	}
	socket._peerCertificate = _buildBridgedPeerChain(derChain);
	socket._localCertificate = opts.cert ? _buildLocalCertificate(socket._servername || socket.remoteAddress || "localhost", socket.remotePort, opts) : null;
	var verifyError = null;
	if (!status.verify || !status.verify.checked || !socket._peerCertificate) verifyError = _createAuthorizationError("UNABLE_TO_VERIFY_CERT", "certificate verification failed");
	else if (!status.verify.chainOk) verifyError = _refineBridgeVerifyError(status.verify, socket._peerCertificate);
	if (!verifyError) {
		var check = opts.checkServerIdentity || checkServerIdentity;
		var identityHost = socket._servername || socket.remoteAddress || "localhost";
		try {
			verifyError = _normalizeCheckError(check(identityHost, socket._peerCertificate, opts));
		} catch (checkErr) {
			verifyError = _normalizeCheckError(checkErr);
		}
	}
	if (verifyError) {
		socket.authorized = false;
		socket.authorizationError = verifyError.code || verifyError.message || String(verifyError);
		socket._authorizationErrorObject = verifyError;
	} else {
		socket.authorized = true;
		socket.authorizationError = null;
		socket._authorizationErrorObject = null;
	}
	if (socket.authorized || opts.rejectUnauthorized === false) {
		if (typeof socket.emit === "function") {
			socket.emit("secure", true);
			socket.emit("secureConnect");
		}
		_tlsBridgeFlushPendingWrites(socket);
		return;
	}
	socket._bridgePendingWrites = null;
	_tlsBridgeFail(socket, socket._authorizationErrorObject || _createError("UNABLE_TO_VERIFY_CERT", "certificate verification failed"));
}
function _tlsBridgeScheduleEnd(socket) {
	if (socket._bridgeEndScheduled || socket._bridgeEndEmitted || socket.destroyed) return;
	socket._bridgeEndScheduled = true;
	var finish = function() {
		socket._bridgeEndScheduled = false;
		if (!socket.destroyed) _tlsBridgeMaybeEmitEnd(socket);
	};
	if (typeof process === "object" && process && typeof process.nextTick === "function") process.nextTick(finish);
	else setTimeout(finish, 0);
}
function _tlsBridgeMaybeEmitEnd(socket) {
	if (!socket._bridgeNativeEnded || socket._bridgeEndEmitted || (socket._bridgeReadQueueBytes || 0) > 0) return;
	if ((socket._bridgeReadDepth || 0) > 0) {
		_tlsBridgeScheduleEnd(socket);
		return;
	}
	if (socket._bridgeDecoder && !socket._bridgeDecoderFinalized && typeof socket._bridgeDecoder.end === "function") {
		socket._bridgeDecoderFinalized = true;
		var trailing = socket._bridgeDecoder.end();
		if (trailing) if (_tlsBridgeIsFlowing(socket) && typeof socket.emit === "function") socket.emit("data", trailing);
		else {
			socket._bridgeDecodedTail = trailing;
			if (typeof socket.emit === "function") socket.emit("readable");
			return;
		}
	}
	if (socket._bridgeDecodedTail !== null && socket._bridgeDecodedTail !== void 0) return;
	socket._bridgeEndEmitted = true;
	socket._bridgeEndScheduled = false;
	socket.readable = false;
	if (typeof socket.emit === "function") socket.emit("end");
}
function _tlsBridgeReadBackpressured(socket) {
	return !_tlsBridgeIsFlowing(socket) && (socket._bridgeReadQueueBytes || 0) >= socket._readableHighWaterMark;
}
function _tlsBridgeResumeRawInput(socket) {
	if (socket._bridgePaused || _tlsBridgeReadBackpressured(socket) || socket._bridgeCipherQueue && socket._bridgeCipherQueue.length || socket.destroyed) return;
	if (socket._bridgeInputPaused) {
		socket._bridgeInputPaused = false;
		var raw = socket._socket;
		if (raw && typeof raw.resume === "function" && !raw.destroyed) raw.resume();
	}
}
function _tlsBridgeProcessCipherQueue(socket) {
	if (socket._bridgeProcessingCipher || socket._tlsEngineId == null || socket.destroyed) return;
	socket._bridgeProcessingCipher = true;
	var stalls = 0;
	try {
		_tlsBridgeDrainPlain(socket);
		while (socket._bridgeCipherQueue && socket._bridgeCipherQueue.length && socket._tlsEngineId != null && !socket.destroyed) {
			if (_tlsBridgeReadBackpressured(socket)) {
				_tlsBridgePauseInput(socket);
				return;
			}
			var item = socket._bridgeCipherQueue[0];
			var total = _byteLength(item.buffer);
			if (item.offset >= total) {
				socket._bridgeCipherQueue.shift();
				continue;
			}
			var remainder = item.offset === 0 ? item.buffer : item.buffer.slice(item.offset);
			var consumed;
			try {
				consumed = __exactTlsEngineWriteTls(socket._tlsEngineId, remainder);
			} catch (e) {
				consumed = -1;
			}
			_tlsBridgePumpOut(socket);
			if (consumed < 0) {
				_tlsBridgeFail(socket, _tlsBridgeErrorFromStatus(socket));
				return;
			}
			if (!socket._secureEstablished) _finalizeBridgedHandshake(socket);
			if (socket._tlsEngineId == null || socket.destroyed) return;
			var drained = _tlsBridgeDrainPlain(socket);
			if (consumed > 0) {
				item.offset += consumed;
				socket._bridgeCipherQueueBytes = Math.max(0, (socket._bridgeCipherQueueBytes || 0) - consumed);
				stalls = 0;
			} else if (_tlsBridgeReadBackpressured(socket)) {
				_tlsBridgePauseInput(socket);
				return;
			} else if (drained) stalls = 0;
			else if (++stalls > 1) {
				_tlsBridgeFail(socket, _createError("ERR_TLS_HANDSHAKE_FAILURE", "TLS receive stalled"));
				return;
			}
		}
	} finally {
		socket._bridgeProcessingCipher = false;
	}
	if (socket._bridgeTransportEnded && !socket._bridgeTransportEofApplied) {
		socket._bridgeTransportEofApplied = true;
		try {
			__exactTlsEngineTransportEof(socket._tlsEngineId);
		} catch (e) {}
		if (!socket._secureEstablished) {
			var status = _tlsBridgeStatus(socket);
			_tlsBridgeFail(socket, status && status.error ? _tlsBridgeErrorFromStatus(socket) : _createError("ECONNRESET", "read ECONNRESET"));
			return;
		}
		_tlsBridgeDrainPlain(socket);
	}
	_tlsBridgeResumeRawInput(socket);
	_tlsBridgeMaybeEmitEnd(socket);
}
function _tlsBridgeMaybeResumeInput(socket) {
	if (socket.destroyed || socket._bridgePaused) return;
	_tlsBridgeDrainPlain(socket);
	if (_tlsBridgeReadBackpressured(socket)) {
		_tlsBridgePauseInput(socket);
		return;
	}
	_tlsBridgeProcessCipherQueue(socket);
	_tlsBridgeResumeRawInput(socket);
}
function _tlsBridgeOnCiphertext(socket, chunk) {
	if (socket._tlsEngineId == null) return;
	var input = _bufferFromBytes(chunk);
	var inputLength = _byteLength(input);
	var retained = socket._bridgeCipherQueueBytes || 0;
	if (inputLength > socket._ciphertextHighWaterMark - retained) {
		_tlsBridgePauseInput(socket);
		_tlsBridgeFail(socket, _createError("ERR_TLS_BUFFER_OVERFLOW", "TLS ciphertext buffer exceeded its high water mark"));
		return;
	}
	if (!socket._bridgeCipherQueue) socket._bridgeCipherQueue = [];
	socket._bridgeCipherQueue.push({
		buffer: input,
		offset: 0
	});
	socket._bridgeCipherQueueBytes = retained + inputLength;
	_tlsBridgeProcessCipherQueue(socket);
	if (socket._bridgeCipherQueue.length) _tlsBridgePauseInput(socket);
}
function _tlsBridgeOnTransportEnd(socket) {
	if (socket._tlsEngineId == null) {
		socket.readable = false;
		if (!socket._bridgeEndEmitted && typeof socket.emit === "function") {
			socket._bridgeEndEmitted = true;
			socket.emit("end");
		}
		return;
	}
	socket._bridgeTransportEnded = true;
	_tlsBridgeProcessCipherQueue(socket);
}
function _startTlsBridge(socket, netSocket, options, host, port) {
	socket._bridged = true;
	socket._bridgeEndEmitted = false;
	if (socket._bridgeEncoding === void 0) socket._bridgeEncoding = null;
	if (socket._bridgeEncoding && !socket._bridgeDecoder && StringDecoder) socket._bridgeDecoder = new StringDecoder(socket._bridgeEncoding);
	socket._bridgePendingWrites = [];
	socket._bridgePendingWriteBytes = 0;
	socket._bridgeReadQueue = [];
	socket._bridgeReadQueueBytes = 0;
	socket._bridgeCipherQueue = [];
	socket._bridgeCipherQueueBytes = 0;
	socket._ciphertextHighWaterMark = Math.max(512 * 1024, Math.min(1024 * 1024, socket._readableHighWaterMark * 8));
	socket._bridgePaused = false;
	socket._bridgeInputPaused = false;
	socket._bridgeTransportBackpressured = false;
	socket._bridgeTransportEnded = false;
	socket._bridgeTransportEofApplied = false;
	socket._bridgeNativeEnded = false;
	socket._bridgeReadDepth = 0;
	socket._bridgeEndScheduled = false;
	socket._bridgeDecoderFinalized = false;
	socket._bridgeDecodedTail = null;
	socket._bridgeShutdownQueued = false;
	socket.pending = true;
	socket._secureEstablished = false;
	_tlsReleaseHeldWrites(socket, "bridge");
	var servername = options.servername || options.sni || null;
	var config = {
		servername: servername ? String(servername) : null,
		host: host ? String(host) : null,
		alpn: _alpnProtocolsToList(options.ALPNProtocols),
		ca: options.ca !== void 0 && options.ca !== null ? _pemSourceToString(options.ca) : null,
		cert: options.cert !== void 0 && options.cert !== null ? _pemSourceToString(options.cert) : null,
		key: options.key !== void 0 && options.key !== null ? _pemSourceToString(options.key) : null,
		passphrase: options.passphrase !== void 0 && options.passphrase !== null ? String(options.passphrase) : null,
		hasPfx: options.pfx !== void 0 && options.pfx !== null,
		hasSession: options.session !== void 0 && options.session !== null,
		cipherSuites: socket._bridgeCipherSuites || _resolveCipherSuites(options, "client"),
		minVersion: options.minVersion || null,
		maxVersion: options.maxVersion || null
	};
	var engineId;
	try {
		engineId = __exactTlsEngineNew(JSON.stringify(config));
	} catch (engineErr) {
		socket.destroy(engineErr);
		return;
	}
	socket._tlsEngineId = engineId;
	_tlsBridgePumpOut(socket);
}
function connect() {
	var parsed = _normalizeTlsConnectArguments(arguments);
	var options = parsed.options || {};
	var cb = parsed.callback;
	var bridgeCipherSuites = _resolveCipherSuites(options, "client");
	if (options.pfx !== void 0 && options.pfx !== null) throw _createError("ERR_TLS_PFX_UNSUPPORTED", "pfx client identities are not supported; provide cert and key PEM options");
	if (options.session !== void 0 && options.session !== null) throw _createError("ERR_TLS_SESSION_UNSUPPORTED", "TLS session resumption input is not supported by this transport");
	if (options.passphrase !== void 0 && options.passphrase !== null) throw _createError("ERR_TLS_PASSPHRASE_UNSUPPORTED", "encrypted client private keys are not supported by this transport");
	if (options.maxVersion === "TLSv1" || options.maxVersion === "TLSv1.1") throw _createError("ERR_TLS_INVALID_PROTOCOL_VERSION", "This TLS transport supports maximum versions TLSv1.2 and TLSv1.3");
	var socket = new TLSSocket(options.socket || null, options);
	socket._bridgeCipherSuites = bridgeCipherSuites;
	if (typeof cb === "function" && typeof socket.once === "function") socket.once("secureConnect", cb);
	socket._writeHeld = true;
	socket._heldWrites = [];
	socket._heldWriteBytes = 0;
	var host = options.host || options.hostname || "localhost";
	var port = typeof options.port === "undefined" ? 443 : options.port;
	if (typeof port === "string") port = Number(port);
	socket.remoteAddress = host;
	socket.remotePort = port;
	socket.connecting = true;
	socket.pending = true;
	if (options.servername || options.sni) {
		socket.servername = options.servername || options.sni;
		socket._servername = socket.servername;
	}
	socket._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION;
	socket.authorized = false;
	socket.authorizationError = null;
	try {
		var connectOptions = _cloneOwnProperties(options);
		if (!options.socket) if (connectOptions.path) {
			delete connectOptions.host;
			delete connectOptions.hostname;
			delete connectOptions.port;
		} else {
			connectOptions.port = port;
			connectOptions.host = host;
			if (!connectOptions.hostname && options.hostname) connectOptions.hostname = options.hostname;
			if (!connectOptions.family && connectOptions.autoSelectFamily === void 0 && host === "localhost") connectOptions.autoSelectFamily = true;
		}
		var netSocket = options.socket || (net && typeof net.connect === "function" ? net.connect(connectOptions) : null);
		if (!netSocket) {
			setTimeout(function() {
				var err = /* @__PURE__ */ new Error("net module not available for TLS transport");
				err.code = "ECONNREFUSED";
				socket.emit("error", err);
			}, 0);
			return socket;
		}
		socket._setSocket(netSocket);
		var completed = false;
		function onConnect() {
			if (completed) return;
			completed = true;
			socket.connecting = false;
			socket.pending = false;
			socket.encrypted = true;
			socket._secureEstablished = true;
			_copySocketMetadata(socket, netSocket);
			socket.remoteAddress = host;
			socket.remotePort = port;
			socket.servername = options.servername || options.host || options.hostname || socket.servername;
			socket._session = null;
			socket._sessionReused = false;
			var peerHost = host;
			var peerPort = port;
			if (options.socket && netSocket) {
				if (netSocket.remoteAddress) peerHost = netSocket.remoteAddress;
				if (netSocket.remotePort !== void 0 && netSocket.remotePort !== null) peerPort = netSocket.remotePort;
			}
			var tlsServer = _isLoopbackHost(peerHost) ? _lookupTlsServer(peerPort) : null;
			var serverHandshake = null;
			if (tlsServer) {
				var negotiatedCipher = _selectNegotiatedCipher(options, tlsServer._tlsOptions || {});
				if (!negotiatedCipher) {
					var clientErr = _createTlsAlertHandshakeFailureError();
					serverHandshake = {
						ok: false,
						clientOptions: options,
						cipher: null,
						serverError: _createNoSharedCipherError()
					};
					var pendingErrorSocket = _shiftPendingServerSocket(tlsServer);
					if (pendingErrorSocket) _applyPendingServerHandshake(tlsServer, pendingErrorSocket, serverHandshake);
					else _queuePendingServerHandshake(tlsServer, serverHandshake);
					socket.emit("error", clientErr);
					socket.destroy(clientErr);
					return;
				}
				serverHandshake = {
					ok: true,
					clientOptions: options,
					cipher: negotiatedCipher,
					serverError: null
				};
				var pendingServerSocket = _shiftPendingServerSocket(tlsServer);
				if (pendingServerSocket) _applyPendingServerHandshake(tlsServer, pendingServerSocket, serverHandshake);
				else _queuePendingServerHandshake(tlsServer, serverHandshake);
				if (_finalizeHandshake(socket, tlsServer._tlsOptions || {}, negotiatedCipher) || options.rejectUnauthorized === false) {
					socket.emit("secure", true);
					socket.emit("secureConnect");
					_tlsReleaseHeldWrites(socket, "raw");
				} else if (socket.authorizationError) {
					var localErr = socket._authorizationErrorObject || new Error(socket.authorizationError);
					socket.emit("error", localErr);
					socket.destroy(localErr);
				}
				return;
			}
			if (_tlsBridgeAvailable()) {
				_startTlsBridge(socket, netSocket, options, host, port);
				return;
			}
			var emulationErr = _createError("ERR_TLS_EMULATION_LOOPBACK_ONLY", "tls.connect: this Ibex build lacks the native TLS bridge; refusing to fabricate a secure connection to " + peerHost + ":" + peerPort + ", which is not a tls.Server running in this process. Only loopback connections to an in-process tls.Server are supported here (LLP 0004; native TLS bridge: ENG-23492).");
			socket.destroy(emulationErr);
		}
		if (typeof netSocket.on === "function") netSocket.on("connect", onConnect);
		if (netSocket.connecting === false) setTimeout(onConnect, 0);
	} catch (e) {
		setTimeout(function() {
			socket.emit("error", e);
		}, 0);
	}
	return socket;
}
function addContext(serverName, context, server) {
	if (!server || !server._contexts) return false;
	if (typeof serverName !== "string" || !serverName) throw _createError("ERR_INVALID_ARG_TYPE", "The \"serverName\" argument must be a non-empty string");
	var secureContext = context instanceof SecureContext ? context : createSecureContext(context && context.context ? context.context : context || {});
	server._contexts[serverName] = secureContext;
	return true;
}
function _createBareServer() {
	var server = { _events: {} };
	_mixinEventEmitter(server);
	server.listen = function() {
		return this;
	};
	server.close = function(callback) {
		if (typeof callback === "function") setTimeout(callback, 0);
		return this;
	};
	server.address = function() {
		return null;
	};
	server.ref = function() {
		return this;
	};
	server.unref = function() {
		return this;
	};
	return server;
}
function _decorateServer(server, options, secureConnectionListener) {
	var serverOptions = options || {};
	server._tlsOptions = _cloneOwnProperties(serverOptions);
	server._sharedCreds = createSecureContext(serverOptions);
	server._contexts = Object.create(null);
	server._pendingTlsSockets = [];
	server._pendingTlsHandshakes = [];
	server.requestCert = !!serverOptions.requestCert;
	server.rejectUnauthorized = !!serverOptions.rejectUnauthorized;
	server.allowHalfOpen = !!serverOptions.allowHalfOpen;
	server.addContext = function(serverName, context) {
		return addContext(serverName, context, server);
	};
	server.setSecureContext = function(nextOptions) {
		server._tlsOptions = _cloneOwnProperties(nextOptions || {});
		server._sharedCreds = createSecureContext(nextOptions || {});
		return server;
	};
	server.getTicketKeys = function() {
		return server._ticketKeys ? _cloneBufferLike(server._ticketKeys) : _getEmptyBuffer();
	};
	server.setTicketKeys = function(keys) {
		if (!_isArrayBufferView(keys)) throw _createError("ERR_INVALID_ARG_TYPE", "The \"buffer\" argument must be an instance of Buffer, TypedArray, or DataView");
		if (_byteLength(keys) !== 48) throw _createError("ERR_TLS_INVALID_TICKET_KEYS", "Session ticket keys must be a 48-byte buffer");
		server._ticketKeys = _cloneBufferLike(keys);
		return server;
	};
	if (typeof secureConnectionListener === "function" && typeof server.on === "function") server.on("secureConnection", secureConnectionListener);
	if (typeof server.on === "function" && !server._tlsRegistryHooksInstalled) {
		server._tlsRegistryHooksInstalled = true;
		server.on("listening", function() {
			_registerTlsServer(server);
		});
		server.on("close", function() {
			_unregisterTlsServer(server);
		});
	}
	return server;
}
function _createServerTLSSocket(server, rawSocket) {
	var serverOptions = server._tlsOptions || {};
	var tlsSocket = new TLSSocket(rawSocket, serverOptions);
	tlsSocket._server = server;
	tlsSocket.server = server;
	tlsSocket.connecting = false;
	tlsSocket.pending = true;
	tlsSocket._secureEstablished = false;
	tlsSocket._protocol = serverOptions.minVersion || serverOptions.maxVersion || DEFAULT_MAX_VERSION;
	_copySocketMetadata(tlsSocket, rawSocket);
	tlsSocket._peerCertificate = null;
	tlsSocket._localCertificate = serverOptions.key || serverOptions.cert || serverOptions.pfx ? _buildSyntheticCertificate(tlsSocket.remoteAddress || "localhost", tlsSocket.remotePort, serverOptions.key || serverOptions.cert || serverOptions.pfx) : null;
	tlsSocket._cipher = {
		name: _normalizeCipherName(serverOptions.ciphers),
		version: tlsSocket._protocol
	};
	tlsSocket.authorized = false;
	tlsSocket.authorizationError = null;
	if (server._pendingTlsHandshakes && server._pendingTlsHandshakes.length) _applyPendingServerHandshake(server, tlsSocket, server._pendingTlsHandshakes.shift());
	else server._pendingTlsSockets.push(tlsSocket);
	return tlsSocket;
}
function createServer(options, secureConnectionListener) {
	if (typeof options === "function") {
		secureConnectionListener = options;
		options = {};
	}
	var serverOptions = options || {};
	var server = net && typeof net.createServer === "function" ? net.createServer(serverOptions, function(rawSocket) {
		_createServerTLSSocket(server, rawSocket);
	}) : _createBareServer();
	if (typeof Object.setPrototypeOf === "function" && Server.prototype) Object.setPrototypeOf(server, Server.prototype);
	return _decorateServer(server, serverOptions, secureConnectionListener);
}
function Server(options, secureConnectionListener) {
	if (!(this instanceof Server)) return createServer(options, secureConnectionListener);
	return createServer(options, secureConnectionListener);
}
if (net && net.Server && net.Server.prototype && typeof Object.create === "function") Server.prototype = Object.create(net.Server.prototype);
else Server.prototype = {};
Server.prototype.constructor = Server;
function getCiphers() {
	return _getCipherList().slice();
}
module.exports = {
	CLIENT_RENEG_LIMIT,
	CLIENT_RENEG_WINDOW,
	TLSSocket,
	Server,
	SecureContext,
	connect,
	createSecureContext,
	checkServerIdentity,
	translatePeerCertificate,
	createServer,
	convertALPNProtocols,
	getCACertificates,
	setDefaultCACertificates,
	getCiphers,
	DEFAULT_ECDH_CURVE,
	DEFAULT_MIN_VERSION,
	DEFAULT_MAX_VERSION,
	DEFAULT_CIPHERS,
	rootCertificates
};
module.exports.default = module.exports;
//#endregion
