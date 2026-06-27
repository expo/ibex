//#region src/builtins/crypto.js
var _CipherStreamTransform = null;
try {
	_CipherStreamTransform = require("stream").Transform;
} catch (e) {}
if (typeof process !== "undefined") {
	if (process.versions) (function() {
		var _newVersions = {};
		var _versionEntries = [
			["node", "24.13.1"],
			["acorn", "8.15.0"],
			["ada", "2.9.2"],
			["ares", "1.34.4"],
			["brotli", "1.1.0"],
			["cjs_module_lexer", "2.1.0"],
			["cldr", "46.0"],
			["icu", "76.1"],
			["llhttp", "9.3.0"],
			["modules", "131"],
			["napi", "9"],
			["nbytes", "0.1.1"],
			["ncrypto", "0.0.1"],
			["nghttp2", "1.64.0"],
			["openssl", "3.4.1"],
			["simdjson", "3.13.0"],
			["simdutf", "6.4.2"],
			["tz", "2025a"],
			["unicode", "16.0"],
			["uv", "1.50.0"],
			["uvwasi", "0.0.21"],
			["v8", "13.6.233.8-node.26"],
			["zlib", "1.3.1.1-motley-82a5fec"],
			["zstd", "1.5.7"]
		];
		for (var _vi = 0; _vi < _versionEntries.length; _vi++) Object.defineProperty(_newVersions, _versionEntries[_vi][0], {
			value: _versionEntries[_vi][1],
			writable: false,
			configurable: true,
			enumerable: true
		});
		Object.defineProperty(_newVersions, "hermes", {
			value: "1.0.0",
			writable: true,
			configurable: true,
			enumerable: false
		});
		Object.defineProperty(_newVersions, "exact", {
			value: "0.1.0",
			writable: true,
			configurable: true,
			enumerable: false
		});
		try {
			Object.defineProperty(process, "versions", {
				value: _newVersions,
				writable: true,
				configurable: true,
				enumerable: true
			});
		} catch (e) {}
		if (!process.versions || process.versions.openssl !== "3.4.1") try {
			var _vProto = Object.getPrototypeOf(process);
			if (_vProto && typeof _vProto === "object" && _vProto !== Object.prototype) Object.defineProperty(_vProto, "versions", {
				value: _newVersions,
				writable: true,
				configurable: true,
				enumerable: false
			});
		} catch (e2) {}
	})();
	if (!process.config) process.config = { variables: {} };
	else if (!process.config.variables) process.config.variables = {};
	if (!process.features) process.features = {};
	if (process.features.openssl_is_boringssl === void 0) process.features.openssl_is_boringssl = true;
}
function _createCryptoError(ctor, code, message) {
	var err = new ctor(message);
	err.code = code;
	return err;
}
function _errInvalidArgType(name, expected, actual) {
	var msg = "The \"" + name + "\" argument must be " + expected + ". Received " + _describeActual(actual);
	var err = new TypeError(msg);
	err.code = "ERR_INVALID_ARG_TYPE";
	return err;
}
function _errInvalidArgTypeProp(name, expected, actual) {
	var msg = "The \"" + name + "\" property must be " + expected + ". Received " + _describeActual(actual);
	var err = new TypeError(msg);
	err.code = "ERR_INVALID_ARG_TYPE";
	return err;
}
function _inspectValue(value) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	if (typeof value === "string") return "'" + value + "'";
	if (typeof value === "number") return String(value);
	if (typeof value === "boolean") return String(value);
	if (typeof value === "bigint") return value + "n";
	if (typeof value === "symbol") return String(value);
	if (Array.isArray(value)) return "[]";
	if (typeof value === "function") return "[Function: " + (value.name || "anonymous") + "]";
	if (typeof value === "object") return "{}";
	return String(value);
}
function _errInvalidArgValue(name, value, reason) {
	var msg = "The argument '" + name + "' is invalid. Received " + _inspectValue(value);
	if (reason) msg = "The argument '" + name + "' " + reason + ". Received " + _inspectValue(value);
	var err = new TypeError(msg);
	err.code = "ERR_INVALID_ARG_VALUE";
	return err;
}
function _errOutOfRange(name, range, actual) {
	var msg = "The value of \"" + name + "\" is out of range. " + (range ? "It must be " + range + ". " : "") + "Received " + actual;
	var err = new RangeError(msg);
	err.code = "ERR_OUT_OF_RANGE";
	return err;
}
function _describeActual(value) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	if (typeof value === "string") return "type string ('" + value + "')";
	if (typeof value === "number") return "type number (" + String(value) + ")";
	if (typeof value === "boolean") return "type boolean (" + String(value) + ")";
	if (typeof value === "symbol") return "type symbol (" + String(value) + ")";
	if (typeof value === "function") return "type function (" + (value.name || "anonymous") + ")";
	if (typeof value === "bigint") return "type bigint (" + value + "n)";
	if (Array.isArray(value)) return "an instance of Array";
	if (value instanceof Object && value.constructor && value.constructor.name) return "an instance of " + value.constructor.name;
	return "type " + typeof value;
}
function _isStringOrBuffer(value) {
	if (typeof value === "string") return true;
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(value)) return true;
	if (value instanceof Uint8Array) return true;
	if (value instanceof ArrayBuffer) return true;
	if (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) return true;
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) return true;
	return false;
}
function _validateString(value, name) {
	if (typeof value !== "string") throw _errInvalidArgType(name, "of type string", value);
}
function _validateBuffer(value, name) {
	if (!_isStringOrBuffer(value)) throw _errInvalidArgType(name, "of type string or an instance of Buffer, TypedArray, or DataView", value);
}
function _toBytes(value) {
	if (value === null || value === void 0) return new Uint8Array(0);
	if (value instanceof Uint8Array) return value;
	if (value instanceof ArrayBuffer) return new Uint8Array(value);
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
	if (typeof value === "string") {
		var fromString = new Uint8Array(value.length);
		for (var i = 0; i < value.length; i++) fromString[i] = value.charCodeAt(i);
		return fromString;
	}
	if (typeof value.length === "number") {
		var fromArray = new Uint8Array(value.length);
		for (var j = 0; j < value.length; j++) fromArray[j] = value[j];
		return fromArray;
	}
	return new Uint8Array(0);
}
function _toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === "string") {
		var bytes = new Uint8Array(data.length);
		for (var i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i);
		return bytes;
	}
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data);
}
function _toByteString(value) {
	if (typeof value === "string") return value;
	if (value === null || value === void 0) return "";
	if (value instanceof ArrayBuffer) value = new Uint8Array(value);
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
		var view = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
		var out = "";
		for (var i = 0; i < view.length; i++) out += String.fromCharCode(view[i]);
		return out;
	}
	if (typeof value === "number") return String.fromCharCode(value & 255);
	if (typeof value.length === "number") {
		var s = "";
		for (var j = 0; j < value.length; j++) s += String.fromCharCode((value[j] || 0) & 255);
		return s;
	}
	return String(value);
}
function _toByteArray(value) {
	if (value === null || value === void 0) return [];
	if (typeof value === "string") {
		var arr = [];
		for (var i = 0; i < value.length; i++) arr.push(value.charCodeAt(i) & 255);
		return arr;
	}
	if (value instanceof ArrayBuffer) value = new Uint8Array(value);
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
		var typed = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
		var arr2 = [];
		for (var j = 0; j < typed.length; j++) arr2.push(typed[j]);
		return arr2;
	}
	if (typeof value.length === "number") {
		var arr3 = [];
		for (var k = 0; k < value.length; k++) arr3.push((value[k] || 0) & 255);
		return arr3;
	}
	return _toByteArray(_toByteString(value));
}
function _toHex(bytes) {
	var hex = "";
	for (var i = 0; i < bytes.length; i++) {
		var h = bytes[i].toString(16);
		if (h.length === 1) h = "0" + h;
		hex += h;
	}
	return hex;
}
function _hexToBytes(hex) {
	if (!hex) return [];
	if (hex.substr(0, 2) === "0x") hex = hex.substr(2);
	var normalized = hex.length % 2 === 1 ? "0" + hex : hex;
	var out = [];
	for (var i = 0; i < normalized.length; i += 2) out.push(parseInt(normalized.substr(i, 2), 16));
	return out;
}
function _bytesToBufferLike(bytes) {
	if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(bytes);
	return new Uint8Array(bytes);
}
function _normalizeInputEncoding(encoding) {
	if (!encoding) return "";
	if (typeof encoding !== "string") return "";
	return encoding.toLowerCase().replace(/_/g, "-");
}
function _toByteStringWithEncoding(value, encoding) {
	var inputEncoding = _normalizeInputEncoding(encoding);
	if (typeof value === "string" && inputEncoding) {
		if (typeof Buffer !== "undefined" && Buffer.from && inputEncoding !== "base64url") return Buffer.from(value, inputEncoding === "binary" ? "latin1" : inputEncoding).toString("latin1");
		if (inputEncoding === "hex") {
			if (value.length % 2 !== 0) throw new TypeError("Invalid hex string");
			var hexBytes = new Uint8Array(value.length / 2);
			for (var i = 0; i < value.length; i += 2) hexBytes[i / 2] = parseInt(value.substr(i, 2), 16);
			var out = "";
			for (var j = 0; j < hexBytes.length; j++) out += String.fromCharCode(hexBytes[j]);
			return out;
		}
		if (inputEncoding === "base64" || inputEncoding === "base64url") {
			if (typeof atob !== "function") return _toByteString(value);
			if (inputEncoding === "base64url") {
				var base64Url = value.replace(/-/g, "+").replace(/_/g, "/");
				while (base64Url.length % 4 !== 0) base64Url += "=";
				return atob(base64Url);
			}
			return atob(value);
		}
		if ((inputEncoding === "utf8" || inputEncoding === "utf-8") && typeof TextEncoder === "function") return _bytesToString(new TextEncoder().encode(value));
	}
	return _toByteString(value);
}
function _bytesToString(bytes) {
	if (!bytes || !bytes.length) return "";
	var out = "";
	for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
	return out;
}
function randomBytes(size, callback) {
	if (typeof size !== "number") throw _errInvalidArgType("size", "of type number", size);
	if (size < 0 || !Number.isFinite(size) || size > 2147483647) throw _errOutOfRange("size", ">= 0 && <= 2147483647", size);
	if (typeof __exactRandomBytes !== "function") throw new Error("Exact crypto not available");
	var len = Math.floor(size);
	if (callback !== void 0) {
		if (typeof callback !== "function") throw _errInvalidArgType("cb", "of type function", callback);
		var _activeDomain = typeof process !== "undefined" && process.domain ? process.domain : null;
		try {
			var bytes = __exactRandomBytes(len);
			var buf = typeof Buffer !== "undefined" && Buffer.from ? Buffer.from(bytes) : bytes;
			(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
				setTimeout(fn, 0);
			})(function() {
				if (_activeDomain) try {
					_activeDomain.enter();
				} catch (_de) {}
				try {
					callback(null, buf);
				} catch (callbackErr) {
					if (_activeDomain && typeof _activeDomain.emit === "function") _activeDomain.emit("error", callbackErr);
					else throw callbackErr;
				} finally {
					if (_activeDomain) try {
						_activeDomain.exit();
					} catch (_de2) {}
				}
			});
		} catch (e) {
			(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
				setTimeout(fn, 0);
			})(function() {
				callback(e);
			});
		}
		return;
	}
	var bytes2 = __exactRandomBytes(len);
	if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(bytes2);
	return bytes2;
}
var _xofAlgorithms = {
	shake128: 16,
	shake256: 32
};
function Hash(algorithm, options) {
	if (!(this instanceof Hash)) return new Hash(algorithm, options);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	if (typeof algorithm !== "string") throw _errInvalidArgType("algorithm", "of type string", algorithm);
	_validateDigestAlgorithm(algorithm);
	this._algo = algorithm.toLowerCase().replace(/-/g, "");
	this._chunks = [];
	this._finalized = false;
	this._digestResult = null;
	this._outputLength = void 0;
	if (options && typeof options === "object" && options !== null) {
		if (options.outputLength !== void 0) {
			if (options.outputLength === null || typeof options.outputLength !== "number") throw _errInvalidArgType("options.outputLength", "of type number", options.outputLength);
			if (!Number.isInteger(options.outputLength) || options.outputLength < 0 || options.outputLength >= Math.pow(2, 90)) throw _errOutOfRange("options.outputLength", ">= 0", options.outputLength);
			if (!(_xofAlgorithms[this._algo] !== void 0) && options.outputLength !== (_digestSizes[this._algo] || 0)) {
				var xofErr = /* @__PURE__ */ new Error("Not XOF or invalid length");
				xofErr.code = "ERR_OSSL_EVP_NOT_XOF_OR_INVALID_LENGTH";
				throw xofErr;
			}
			this._outputLength = options.outputLength;
		}
	}
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Hash.prototype, _CipherStreamTransform.prototype);
	Hash.prototype.constructor = Hash;
	Hash.prototype._transform = function(chunk, encoding, callback) {
		if (typeof chunk === "string") this._chunks.push(chunk);
		else if (chunk && chunk.length !== void 0) {
			var str = "";
			for (var i = 0; i < chunk.length; i++) str += String.fromCharCode(chunk[i]);
			this._chunks.push(str);
		}
		if (typeof callback === "function") callback();
	};
	Hash.prototype._flush = function(callback) {
		try {
			this._streamMode = true;
			var result = this.digest();
			this.push(result);
		} catch (e) {}
		if (typeof callback === "function") callback();
	};
	Hash.prototype.end = function(chunk, encoding, callback) {
		if (typeof chunk === "function") {
			callback = chunk;
			chunk = null;
			encoding = void 0;
		}
		if (typeof encoding === "function") {
			callback = encoding;
			encoding = void 0;
		}
		if (chunk !== void 0 && chunk !== null) this.update(chunk, encoding);
		if (!this._finalized) {
			this._streamMode = true;
			var result = this.digest();
			this.push(result);
			this.push(null);
		}
		if (typeof callback === "function") callback();
		return this;
	};
}
Hash.prototype.update = function(data, encoding) {
	if (this._finalized) {
		var err = /* @__PURE__ */ new Error("[ERR_CRYPTO_HASH_FINALIZED]: Digest already called");
		err.code = "ERR_CRYPTO_HASH_FINALIZED";
		throw err;
	}
	if (data === void 0) throw _errInvalidArgType("data", "of type string or an instance of Buffer, TypedArray, or DataView", data);
	if (typeof data === "string") this._chunks.push(_toByteStringWithEncoding(data, encoding || "utf8"));
	else if (data && data.length !== void 0) {
		var str = "";
		for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
		this._chunks.push(str);
	}
	return this;
};
Hash.prototype.digest = function(encoding) {
	if (encoding !== void 0 && encoding !== null && typeof encoding !== "string") encoding = "" + encoding;
	if (this._finalized) {
		if (this._digestResult !== null) {
			if (encoding === "hex" && typeof this._digestResult !== "string") return this._digestResult.toString("hex");
			if (encoding && encoding !== "buffer" && typeof this._digestResult !== "string" && this._digestResult && typeof this._digestResult.toString === "function") return this._digestResult.toString(encoding);
			return this._digestResult;
		}
		var err = /* @__PURE__ */ new Error("[ERR_CRYPTO_HASH_FINALIZED]: Digest already called");
		err.code = "ERR_CRYPTO_HASH_FINALIZED";
		throw err;
	}
	this._finalized = true;
	var joinedBytes = _bytesToBufferLike(_toByteArray(this._chunks.join("")));
	if (!encoding || encoding === "buffer") {
		if (typeof __exactHashRaw === "function") {
			var raw = __exactHashRaw(this._algo, joinedBytes);
			if (typeof Buffer !== "undefined" && Buffer.from) this._digestResult = Buffer.from(raw);
			else this._digestResult = raw;
			return this._digestResult;
		}
	}
	if (typeof __exactHashSync === "function") {
		var hex = __exactHashSync(this._algo, joinedBytes);
		if (!encoding || encoding === "hex") {
			this._digestResult = hex;
			return hex;
		}
		if (typeof Buffer !== "undefined" && Buffer.from) {
			var buf = Buffer.from(hex, "hex");
			if (encoding === "buffer") {
				this._digestResult = buf;
				return buf;
			}
			try {
				var result = buf.toString(encoding);
				this._digestResult = result;
				return result;
			} catch (encErr) {
				throw encErr;
			}
		}
		if (encoding === "base64") {
			var bytes = [];
			for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
			if (typeof btoa === "function") {
				var str = "";
				for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
				this._digestResult = btoa(str);
				return this._digestResult;
			}
		}
		this._digestResult = hex;
		return hex;
	}
	throw new Error("Native hash not available");
};
Hash.prototype.copy = function(options) {
	if (this._finalized) {
		var err = /* @__PURE__ */ new Error("[ERR_CRYPTO_HASH_FINALIZED]: Digest already called");
		err.code = "ERR_CRYPTO_HASH_FINALIZED";
		throw err;
	}
	var h = new Hash(this._algo);
	h._chunks = this._chunks.slice();
	if (options && typeof options === "object" && options.outputLength !== void 0) h._outputLength = options.outputLength;
	else h._outputLength = this._outputLength;
	return h;
};
Hash.prototype[Symbol.toStringTag] = "Hash";
function createHash(algorithm, options) {
	return new Hash(algorithm, options);
}
function hash(algorithm, data, outputEncoding) {
	if (typeof algorithm !== "string") throw _errInvalidArgType("algorithm", "of type string", algorithm);
	if (!_isStringOrBuffer(data)) throw _errInvalidArgType("data", "of type string or an instance of Buffer, TypedArray, or DataView", data);
	if (outputEncoding !== void 0 && typeof outputEncoding !== "string") throw _errInvalidArgType("outputEncoding", "of type string", outputEncoding);
	if (outputEncoding !== void 0 && !{
		hex: 1,
		base64: 1,
		buffer: 1,
		latin1: 1,
		binary: 1,
		utf8: 1,
		"utf-8": 1,
		base64url: 1
	}[outputEncoding]) {
		var badErr = /* @__PURE__ */ new TypeError("The property 'options.outputEncoding' is invalid. Received '" + outputEncoding + "'");
		badErr.code = "ERR_INVALID_ARG_VALUE";
		throw badErr;
	}
	return createHash(algorithm).update(data).digest(outputEncoding || "hex");
}
var _validDigestAlgos = null;
function _getValidDigestAlgos() {
	if (_validDigestAlgos) return _validDigestAlgos;
	var hashes = getHashes();
	_validDigestAlgos = {};
	for (var i = 0; i < hashes.length; i++) {
		_validDigestAlgos[hashes[i].toLowerCase()] = true;
		_validDigestAlgos[hashes[i].toLowerCase().replace(/-/g, "")] = true;
	}
	return _validDigestAlgos;
}
function _validateDigestAlgorithm(algorithm) {
	var normalized = algorithm.toLowerCase().replace(/-/g, "");
	var algos = _getValidDigestAlgos();
	if (!algos[normalized] && !algos[algorithm.toLowerCase()]) throw new Error("Digest method not supported");
}
function Hmac(algorithm, key) {
	if (!(this instanceof Hmac)) return new Hmac(algorithm, key);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	if (typeof algorithm !== "string") throw _errInvalidArgType("hmac", "of type string", algorithm);
	if (key === null || key === void 0) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", key);
	_validateDigestAlgorithm(algorithm);
	this._algo = algorithm.toLowerCase().replace("-", "");
	this._key = typeof key === "string" ? key : "";
	if (typeof key !== "string" && key && key.length !== void 0) {
		var str = "";
		for (var i = 0; i < key.length; i++) str += String.fromCharCode(key[i]);
		this._key = str;
	}
	if (key && key instanceof KeyObject && key._type === "secret") {
		var keyData = key._data;
		var keyStr = "";
		for (var j = 0; j < keyData.length; j++) keyStr += String.fromCharCode(keyData[j]);
		this._key = keyStr;
	}
	this._chunks = [];
	this._finalized = false;
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Hmac.prototype, _CipherStreamTransform.prototype);
	Hmac.prototype.constructor = Hmac;
	Hmac.prototype._transform = function(chunk, encoding, callback) {
		if (typeof chunk === "string") this._chunks.push(chunk);
		else if (chunk && chunk.length !== void 0) {
			var str = "";
			for (var i = 0; i < chunk.length; i++) str += String.fromCharCode(chunk[i]);
			this._chunks.push(str);
		}
		if (typeof callback === "function") callback();
	};
	Hmac.prototype._flush = function(callback) {
		try {
			var result = this.digest();
			this.push(result);
		} catch (e) {}
		if (typeof callback === "function") callback();
	};
	Hmac.prototype.end = function(chunk, encoding, callback) {
		if (typeof chunk === "function") {
			callback = chunk;
			chunk = null;
			encoding = void 0;
		}
		if (typeof encoding === "function") {
			callback = encoding;
			encoding = void 0;
		}
		if (chunk !== void 0 && chunk !== null) this.update(chunk, encoding);
		if (!this._finalized) {
			var result = this.digest();
			this.push(result);
			this.push(null);
		}
		if (typeof callback === "function") callback();
		return this;
	};
}
Hmac.prototype.update = function(data, encoding) {
	if (this._finalized) throw new Error("Digest already called");
	if (typeof data === "string") if (encoding === "hex") {
		var hexStr = "";
		for (var hi = 0; hi < data.length; hi += 2) hexStr += String.fromCharCode(parseInt(data.substr(hi, 2), 16));
		this._chunks.push(hexStr);
	} else this._chunks.push(data);
	else if (data && data.length !== void 0) {
		var str = "";
		for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
		this._chunks.push(str);
	}
	return this;
};
Hmac.prototype.digest = function(encoding) {
	if (encoding !== void 0 && encoding !== null && typeof encoding !== "string") encoding = "" + encoding;
	if (this._finalized) {
		var err = /* @__PURE__ */ new Error("[ERR_CRYPTO_HASH_FINALIZED]: Digest already called");
		err.code = "ERR_CRYPTO_HASH_FINALIZED";
		throw err;
	}
	this._finalized = true;
	var joined = this._chunks.join("");
	if (typeof __exactHmacSync === "function") {
		var hex = __exactHmacSync(this._algo, this._key, joined);
		if (encoding === "hex") return hex;
		if (encoding === "base64") {
			var bytes = [];
			for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
			if (typeof btoa === "function") {
				var str = "";
				for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
				return btoa(str);
			}
		}
		if (encoding === "buffer" || !encoding) {
			var bytes2 = [];
			for (var k = 0; k < hex.length; k += 2) bytes2.push(parseInt(hex.substr(k, 2), 16));
			return _bytesToBufferLike(bytes2);
		}
		if (encoding === "latin1" || encoding === "binary") {
			var bytes3 = [];
			for (var m = 0; m < hex.length; m += 2) bytes3.push(parseInt(hex.substr(m, 2), 16));
			var latin = "";
			for (var n = 0; n < bytes3.length; n++) latin += String.fromCharCode(bytes3[n]);
			return latin;
		}
		return hex;
	}
	throw new Error("Native HMAC not available");
};
Hmac.prototype[Symbol.toStringTag] = "Hmac";
function createHmac(algorithm, key) {
	if (typeof algorithm !== "string") throw _errInvalidArgType("hmac", "of type string", algorithm);
	_validateDigestAlgorithm(algorithm);
	return new Hmac(algorithm, key);
}
function getHashes() {
	return [
		"md5",
		"sha1",
		"sha224",
		"sha256",
		"sha384",
		"sha512",
		"sha3-224",
		"sha3-256",
		"sha3-384",
		"sha3-512",
		"RSA-MD5",
		"RSA-SHA1",
		"RSA-SHA1-2",
		"RSA-SHA256",
		"RSA-SHA384",
		"RSA-SHA512"
	];
}
function getCiphers() {
	return [
		"aes-128-gcm",
		"aes-192-gcm",
		"aes-256-gcm",
		"aes-128-ccm",
		"aes-192-ccm",
		"aes-256-ccm",
		"aes-128-cbc",
		"aes-192-cbc",
		"aes-256-cbc",
		"aes-128-ctr",
		"aes-192-ctr",
		"aes-256-ctr",
		"aes-128-ecb",
		"aes-192-ecb",
		"aes-256-ecb",
		"aes-128-wrap",
		"aes-192-wrap",
		"aes-256-wrap",
		"aes-128-wrap-pad",
		"aes-192-wrap-pad",
		"aes-256-wrap-pad",
		"chacha20-poly1305",
		"chacha20",
		"des-cbc",
		"des-ecb",
		"des-cfb",
		"des-ofb",
		"des-ede3-cbc",
		"des-ede3-cfb",
		"des-ede3-ofb",
		"bf-cbc",
		"bf-ecb",
		"bf-cfb",
		"bf-ofb",
		"rc4",
		"id-aes128-wrap",
		"id-aes192-wrap",
		"id-aes256-wrap",
		"id-aes128-wrap-pad",
		"id-aes192-wrap-pad",
		"id-aes256-wrap-pad",
		"aes-128-ocb",
		"aes-192-ocb",
		"aes-256-ocb"
	];
}
function getCurves() {
	return [
		"prime256v1",
		"secp256r1",
		"secp384r1",
		"secp521r1",
		"secp256k1",
		"secp224r1",
		"secp192k1",
		"brainpoolP256r1",
		"brainpoolP384r1",
		"brainpoolP512r1",
		"curve25519",
		"ed25519",
		"x25519"
	];
}
var _cipherNidMap = null;
var _cipherDetailMap = null;
function _buildCipherDetailMap() {
	if (_cipherDetailMap) return;
	_cipherDetailMap = {};
	_cipherNidMap = {};
	var entries = [
		{
			name: "aes-128-cbc",
			nid: 419,
			blockSize: 16,
			ivLength: 16,
			keyLength: 16,
			mode: "cbc"
		},
		{
			name: "aes-192-cbc",
			nid: 423,
			blockSize: 16,
			ivLength: 16,
			keyLength: 24,
			mode: "cbc"
		},
		{
			name: "aes-256-cbc",
			nid: 427,
			blockSize: 16,
			ivLength: 16,
			keyLength: 32,
			mode: "cbc"
		},
		{
			name: "aes-128-ctr",
			nid: 904,
			blockSize: 1,
			ivLength: 16,
			keyLength: 16,
			mode: "ctr"
		},
		{
			name: "aes-192-ctr",
			nid: 905,
			blockSize: 1,
			ivLength: 16,
			keyLength: 24,
			mode: "ctr"
		},
		{
			name: "aes-256-ctr",
			nid: 906,
			blockSize: 1,
			ivLength: 16,
			keyLength: 32,
			mode: "ctr"
		},
		{
			name: "aes-128-ecb",
			nid: 418,
			blockSize: 16,
			ivLength: 0,
			keyLength: 16,
			mode: "ecb"
		},
		{
			name: "aes-192-ecb",
			nid: 422,
			blockSize: 16,
			ivLength: 0,
			keyLength: 24,
			mode: "ecb"
		},
		{
			name: "aes-256-ecb",
			nid: 426,
			blockSize: 16,
			ivLength: 0,
			keyLength: 32,
			mode: "ecb"
		},
		{
			name: "aes-128-gcm",
			nid: 895,
			blockSize: 1,
			ivLength: 12,
			keyLength: 16,
			mode: "gcm"
		},
		{
			name: "aes-192-gcm",
			nid: 898,
			blockSize: 1,
			ivLength: 12,
			keyLength: 24,
			mode: "gcm"
		},
		{
			name: "aes-256-gcm",
			nid: 901,
			blockSize: 1,
			ivLength: 12,
			keyLength: 32,
			mode: "gcm"
		},
		{
			name: "aes-128-ccm",
			nid: 896,
			blockSize: 1,
			ivLength: 12,
			keyLength: 16,
			mode: "ccm",
			ivMin: 7,
			ivMax: 13
		},
		{
			name: "aes-192-ccm",
			nid: 899,
			blockSize: 1,
			ivLength: 12,
			keyLength: 24,
			mode: "ccm",
			ivMin: 7,
			ivMax: 13
		},
		{
			name: "aes-256-ccm",
			nid: 902,
			blockSize: 1,
			ivLength: 12,
			keyLength: 32,
			mode: "ccm",
			ivMin: 7,
			ivMax: 13
		},
		{
			name: "aes-128-wrap",
			nid: 788,
			blockSize: 8,
			ivLength: 8,
			keyLength: 16,
			mode: "wrap"
		},
		{
			name: "aes-192-wrap",
			nid: 789,
			blockSize: 8,
			ivLength: 8,
			keyLength: 24,
			mode: "wrap"
		},
		{
			name: "aes-256-wrap",
			nid: 790,
			blockSize: 8,
			ivLength: 8,
			keyLength: 32,
			mode: "wrap"
		},
		{
			name: "aes-128-wrap-pad",
			nid: 897,
			blockSize: 8,
			ivLength: 4,
			keyLength: 16,
			mode: "wrap"
		},
		{
			name: "aes-192-wrap-pad",
			nid: 900,
			blockSize: 8,
			ivLength: 4,
			keyLength: 24,
			mode: "wrap"
		},
		{
			name: "aes-256-wrap-pad",
			nid: 903,
			blockSize: 8,
			ivLength: 4,
			keyLength: 32,
			mode: "wrap"
		},
		{
			name: "aes-128-ocb",
			nid: 958,
			blockSize: 16,
			ivLength: 12,
			keyLength: 16,
			mode: "ocb",
			ivMin: 1,
			ivMax: 15
		},
		{
			name: "aes-192-ocb",
			nid: 959,
			blockSize: 16,
			ivLength: 12,
			keyLength: 24,
			mode: "ocb",
			ivMin: 1,
			ivMax: 15
		},
		{
			name: "aes-256-ocb",
			nid: 960,
			blockSize: 16,
			ivLength: 12,
			keyLength: 32,
			mode: "ocb",
			ivMin: 1,
			ivMax: 15
		},
		{
			name: "des-cbc",
			nid: 31,
			blockSize: 8,
			ivLength: 8,
			keyLength: 8,
			mode: "cbc"
		},
		{
			name: "des-ecb",
			nid: 29,
			blockSize: 8,
			ivLength: 0,
			keyLength: 8,
			mode: "ecb"
		},
		{
			name: "des-cfb",
			nid: 30,
			blockSize: 1,
			ivLength: 8,
			keyLength: 8,
			mode: "cfb"
		},
		{
			name: "des-ofb",
			nid: 45,
			blockSize: 1,
			ivLength: 8,
			keyLength: 8,
			mode: "ofb"
		},
		{
			name: "des-ede3-cbc",
			nid: 44,
			blockSize: 8,
			ivLength: 8,
			keyLength: 24,
			mode: "cbc"
		},
		{
			name: "des-ede3-cfb",
			nid: 61,
			blockSize: 1,
			ivLength: 8,
			keyLength: 24,
			mode: "cfb"
		},
		{
			name: "des-ede3-ofb",
			nid: 63,
			blockSize: 1,
			ivLength: 8,
			keyLength: 24,
			mode: "ofb"
		},
		{
			name: "chacha20-poly1305",
			nid: 1018,
			blockSize: 1,
			ivLength: 12,
			keyLength: 32,
			mode: "stream"
		},
		{
			name: "chacha20",
			nid: 1019,
			blockSize: 1,
			ivLength: 16,
			keyLength: 32,
			mode: "stream"
		},
		{
			name: "bf-cbc",
			nid: 91,
			blockSize: 8,
			ivLength: 8,
			keyLength: 16,
			mode: "cbc"
		},
		{
			name: "bf-ecb",
			nid: 92,
			blockSize: 8,
			ivLength: 0,
			keyLength: 16,
			mode: "ecb"
		},
		{
			name: "bf-cfb",
			nid: 93,
			blockSize: 1,
			ivLength: 8,
			keyLength: 16,
			mode: "cfb"
		},
		{
			name: "bf-ofb",
			nid: 94,
			blockSize: 1,
			ivLength: 8,
			keyLength: 16,
			mode: "ofb"
		},
		{
			name: "rc4",
			nid: 5,
			blockSize: 1,
			ivLength: 0,
			keyLength: 16,
			mode: "stream"
		},
		{
			name: "id-aes128-wrap",
			nid: 788,
			blockSize: 8,
			ivLength: 8,
			keyLength: 16,
			mode: "wrap"
		},
		{
			name: "id-aes192-wrap",
			nid: 789,
			blockSize: 8,
			ivLength: 8,
			keyLength: 24,
			mode: "wrap"
		},
		{
			name: "id-aes256-wrap",
			nid: 790,
			blockSize: 8,
			ivLength: 8,
			keyLength: 32,
			mode: "wrap"
		},
		{
			name: "id-aes128-wrap-pad",
			nid: 897,
			blockSize: 8,
			ivLength: 4,
			keyLength: 16,
			mode: "wrap"
		},
		{
			name: "id-aes192-wrap-pad",
			nid: 900,
			blockSize: 8,
			ivLength: 4,
			keyLength: 24,
			mode: "wrap"
		},
		{
			name: "id-aes256-wrap-pad",
			nid: 903,
			blockSize: 8,
			ivLength: 4,
			keyLength: 32,
			mode: "wrap"
		}
	];
	for (var i = 0; i < entries.length; i++) {
		_cipherDetailMap[entries[i].name] = entries[i];
		if (!_cipherNidMap[entries[i].nid] || entries[i].name.indexOf("id-") === 0) _cipherNidMap[entries[i].nid] = entries[i];
	}
}
function getCipherInfo(nameOrNid, options) {
	if (typeof nameOrNid !== "string" && typeof nameOrNid !== "number") throw _errInvalidArgType("nameOrNid", "of type string or number", nameOrNid);
	if (options !== void 0) {
		if (typeof options !== "object" || options === null) throw _errInvalidArgType("options", "of type object", options);
		if (options.keyLength !== void 0 && typeof options.keyLength !== "number") throw _errInvalidArgType("options.keyLength", "of type number", options.keyLength);
		if (options.ivLength !== void 0 && typeof options.ivLength !== "number") throw _errInvalidArgType("options.ivLength", "of type number", options.ivLength);
	}
	_buildCipherDetailMap();
	var entry;
	if (typeof nameOrNid === "number") entry = _cipherNidMap[nameOrNid];
	else entry = _cipherDetailMap[nameOrNid.toLowerCase()];
	if (!entry) return void 0;
	var canonicalEntry = _cipherNidMap[entry.nid] || entry;
	if (options) {
		if (options.keyLength !== void 0 && options.keyLength !== canonicalEntry.keyLength) return void 0;
		if (options.ivLength !== void 0) {
			if (canonicalEntry.ivMin !== void 0 && canonicalEntry.ivMax !== void 0) {
				if (options.ivLength < canonicalEntry.ivMin || options.ivLength > canonicalEntry.ivMax) return void 0;
			} else if (options.ivLength !== canonicalEntry.ivLength) return;
		}
	}
	return {
		name: canonicalEntry.name,
		nid: canonicalEntry.nid,
		blockSize: canonicalEntry.blockSize,
		ivLength: canonicalEntry.ivLength,
		keyLength: canonicalEntry.keyLength,
		mode: canonicalEntry.mode
	};
}
function timingSafeEqual(a, b) {
	if (!_isStringOrBuffer(a)) throw _errInvalidArgType("buf1", "an instance of Buffer, TypedArray, or DataView", a);
	if (!_isStringOrBuffer(b)) throw _errInvalidArgType("buf2", "an instance of Buffer, TypedArray, or DataView", b);
	if (a.length !== b.length) throw new RangeError("Input buffers must have the same byte length");
	var result = 0;
	for (var i = 0; i < a.length; i++) result |= a[i] ^ b[i];
	return result === 0;
}
function randomUUID(options) {
	if (options !== void 0 && (typeof options !== "object" || options === null)) throw _errInvalidArgType("options", "of type object", options);
	if (options && options.disableEntropyCache !== void 0 && typeof options.disableEntropyCache !== "boolean") throw _errInvalidArgType("options.disableEntropyCache", "of type boolean", options.disableEntropyCache);
	if (typeof globalThis !== "undefined" && globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") return globalThis.crypto.randomUUID();
	var bytes = randomBytes(16);
	var hex = "";
	for (var i = 0; i < bytes.length; i++) {
		var b = typeof bytes[i] === "number" ? bytes[i] : bytes.charCodeAt ? bytes.charCodeAt(i) : 0;
		hex += (b < 16 ? "0" : "") + b.toString(16);
	}
	return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-4" + hex.substr(13, 3) + "-" + (parseInt(hex.substr(16, 2), 16) & 63 | 128).toString(16) + hex.substr(18, 2) + "-" + hex.substr(20, 12);
}
function randomInt(min, max, callback) {
	if (typeof max === "function") {
		callback = max;
		max = min;
		min = 0;
	}
	if (max === void 0) {
		max = min;
		min = 0;
	}
	if (callback !== void 0 && typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	if (typeof min !== "number" || !Number.isSafeInteger(min)) throw _errInvalidArgType("min", "a safe integer", min);
	if (typeof max !== "number" || !Number.isSafeInteger(max)) throw _errInvalidArgType("max", "a safe integer", max);
	var MAX_RANGE = 0xffffffffffff;
	if (min >= max) throw _errOutOfRange("max", "greater than the value of \"min\" (" + min + ")", max);
	var range = max - min;
	if (range > MAX_RANGE) throw _errOutOfRange("max - min", "<= " + MAX_RANGE, _formatNumber(range));
	if (arguments.length <= 2 && max > MAX_RANGE) throw _errOutOfRange("max", "<= " + MAX_RANGE, _formatNumber(max));
	var bytes = randomBytes(6);
	var val = 0;
	for (var bi = 0; bi < 6; bi++) val = val * 256 + (typeof bytes[bi] === "number" ? bytes[bi] : bytes.charCodeAt ? bytes.charCodeAt(bi) : 0);
	var result = min + val % range;
	if (typeof callback === "function") {
		setTimeout(function() {
			callback(null, result);
		}, 0);
		return;
	}
	return result;
}
function _formatNumber(n) {
	var s = String(n);
	if (s.length <= 3) return s;
	var parts = [];
	var intPart = s;
	while (intPart.length > 3) {
		parts.unshift(intPart.slice(-3));
		intPart = intPart.slice(0, -3);
	}
	parts.unshift(intPart);
	return parts.join("_");
}
function randomFillSync(buf, offset, size) {
	if (buf === null || buf === void 0 || typeof buf === "number" || typeof buf === "boolean" || typeof buf === "string" || typeof buf === "function") throw _errInvalidArgType("buf", "an instance of Buffer, TypedArray, or DataView", buf);
	if (!buf || typeof buf !== "object") throw _errInvalidArgType("buf", "an instance of Buffer, TypedArray, or DataView", buf);
	var bufLen = buf.byteLength !== void 0 ? buf.byteLength : buf.length;
	if (offset !== void 0 && typeof offset !== "number") throw _errInvalidArgType("offset", "of type number", offset);
	offset = offset !== void 0 ? offset : 0;
	if (!Number.isFinite(offset) || offset < 0 || offset > bufLen) throw _errOutOfRange("offset", ">= 0 && <= " + bufLen, offset);
	if (size !== void 0 && typeof size !== "number") throw _errInvalidArgType("size", "of type number", size);
	size = size !== void 0 ? size : bufLen - offset;
	if (!Number.isFinite(size) || size < 0 || size > 2147483647) throw _errOutOfRange("size", ">= 0 && <= 2147483647", size);
	if (size + offset > bufLen) throw _errOutOfRange("size + offset", "<= " + bufLen, size + offset);
	if (size === 0) return buf;
	var bytes = randomBytes(size);
	var target;
	if (buf instanceof ArrayBuffer || typeof SharedArrayBuffer !== "undefined" && buf instanceof SharedArrayBuffer) {
		target = new Uint8Array(buf, offset, size);
		offset = 0;
	} else if (buf instanceof DataView) {
		target = new Uint8Array(buf.buffer, buf.byteOffset + offset, size);
		offset = 0;
	} else target = buf;
	for (var i = 0; i < size; i++) target[offset + i] = typeof bytes[i] === "number" ? bytes[i] : bytes.charCodeAt ? bytes.charCodeAt(i) : 0;
	return buf;
}
function randomFill(buf, offsetOrCb, sizeOrCb, callback) {
	if (typeof offsetOrCb === "function") {
		callback = offsetOrCb;
		offsetOrCb = 0;
		sizeOrCb = void 0;
	} else if (typeof sizeOrCb === "function") {
		callback = sizeOrCb;
		sizeOrCb = void 0;
	}
	if (callback !== void 0 && typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	randomFillSync(buf, offsetOrCb, sizeOrCb);
	if (typeof callback === "function") try {
		setTimeout(function() {
			callback(null, buf);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
var _digestSizes = {
	md5: 16,
	sha1: 20,
	sha224: 28,
	sha256: 32,
	sha384: 48,
	sha512: 64,
	sha3224: 28,
	sha3256: 32,
	sha3384: 48,
	sha3512: 64,
	blake2s256: 32,
	blake2b512: 64,
	ripemd160: 20,
	whirlpool: 64,
	sm3: 32
};
function _normalizeKdfDigest(digest, throwOnInvalid) {
	var normalized = (digest || "sha1").toString().toLowerCase().replace(/-/g, "");
	if (_digestSizes[normalized] !== void 0) return normalized;
	var lower = (digest || "").toLowerCase();
	if (_digestSizes[lower] !== void 0) return lower;
	if (throwOnInvalid !== false) {
		var err = /* @__PURE__ */ new Error("Invalid digest: " + digest);
		err.code = "ERR_CRYPTO_INVALID_DIGEST";
		throw err;
	}
	return null;
}
function pbkdf2Sync(password, salt, iterations, keylen, digest) {
	if (typeof __exactPbkdf2 !== "function") throw new Error("pbkdf2 not available");
	_validateBuffer(password, "password");
	_validateBuffer(salt, "salt");
	if (typeof iterations !== "number" || !Number.isFinite(iterations)) throw _errInvalidArgType("iterations", "of type number", iterations);
	if (iterations < 0) throw _errOutOfRange("iterations", ">= 0", iterations);
	if (iterations === 0) throw _errOutOfRange("iterations", ">= 1", iterations);
	if (typeof keylen !== "number" || !Number.isFinite(keylen)) throw _errInvalidArgType("keylen", "of type number", keylen);
	if (keylen < 0) throw _errOutOfRange("keylen", ">= 0", keylen);
	if (keylen === 0) return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
	_validateString(digest, "digest");
	var passBytes = _toBytes(password);
	var saltBytes = _toBytes(salt);
	var hashName = _normalizeKdfDigest(digest);
	var result = __exactPbkdf2(passBytes, saltBytes, iterations, keylen, hashName);
	if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(result);
	return result;
}
function pbkdf2(password, salt, iterations, keylen, digest, callback) {
	if (typeof digest === "function") {
		callback = digest;
		digest = void 0;
	}
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	var _activeDomain = typeof process !== "undefined" && process.domain ? process.domain : null;
	var _nextTick = typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
		setTimeout(fn, 0);
	};
	try {
		if (digest === void 0) throw _errInvalidArgType("digest", "of type string", digest);
		var result = pbkdf2Sync(password, salt, iterations, keylen, digest);
		_nextTick(function() {
			if (_activeDomain) try {
				_activeDomain.enter();
			} catch (_de) {}
			try {
				callback(null, result);
			} catch (callbackErr) {
				if (_activeDomain && typeof _activeDomain.emit === "function") _activeDomain.emit("error", callbackErr);
				else throw callbackErr;
			} finally {
				if (_activeDomain) try {
					_activeDomain.exit();
				} catch (_de2) {}
			}
		});
	} catch (e) {
		_nextTick(function() {
			callback(e);
		});
	}
}
function _validateHkdfArgs(digest, ikm, salt, info, keylen) {
	if (typeof digest !== "string") throw _errInvalidArgType("digest", "of type string", digest);
	if (!_isStringOrBuffer(ikm) && !(ikm instanceof KeyObject)) throw _errInvalidArgType("ikm", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", ikm);
	if (!_isStringOrBuffer(salt)) throw _errInvalidArgType("salt", "of type string or an instance of Buffer, TypedArray, or DataView", salt);
	if (!_isStringOrBuffer(info)) throw _errInvalidArgType("info", "of type string or an instance of Buffer, TypedArray, or DataView", info);
	if (typeof keylen !== "number" || !Number.isFinite(keylen)) throw _errInvalidArgType("length", "of type number", keylen);
	var infoLen = typeof info === "string" ? info.length : info.byteLength !== void 0 ? info.byteLength : info.length;
	if (infoLen > 1024) throw _errOutOfRange("info", "<= 1024", infoLen);
	var kMaxLength = 2147483647;
	if (keylen < 0 || keylen > kMaxLength) throw _errOutOfRange("length", ">= 0 && <= " + kMaxLength, keylen);
	var hashName = _normalizeKdfDigest(digest);
	if (keylen > 255 * (_digestSizes[hashName] || 32)) {
		var err2 = /* @__PURE__ */ new RangeError("Invalid keylen");
		err2.code = "ERR_CRYPTO_INVALID_KEYLEN";
		throw err2;
	}
	return hashName;
}
var _nativeHkdfDigests = {
	sha1: 1,
	sha256: 1,
	sha384: 1,
	sha512: 1
};
function hkdfSync(digest, ikm, salt, info, keylen) {
	if (typeof __exactHkdf !== "function") throw new Error("hkdf not available in this runtime");
	var hashName = _validateHkdfArgs(digest, ikm, salt, info, keylen);
	var ikmBytes = ikm instanceof KeyObject ? ikm._data : _toBytes(ikm);
	var saltBytes = _toBytes(salt);
	var infoBytes = _toBytes(info);
	if (keylen === 0) return /* @__PURE__ */ new ArrayBuffer(0);
	if (!_nativeHkdfDigests[hashName]) {
		var nerr = /* @__PURE__ */ new Error("Invalid digest: " + digest);
		nerr.code = "ERR_CRYPTO_INVALID_DIGEST";
		throw nerr;
	}
	var result = __exactHkdf(hashName, ikmBytes, saltBytes, infoBytes, keylen);
	if (result instanceof ArrayBuffer) return result;
	if (result instanceof Uint8Array) return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
	if (typeof Buffer !== "undefined" && Buffer.isBuffer(result)) return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
	return result;
}
function hkdf(digest, ikm, salt, info, keylen, callback) {
	_validateHkdfArgs(digest, ikm, salt, info, keylen);
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	try {
		var result = hkdfSync(digest, ikm, salt, info, keylen);
		setTimeout(function() {
			callback(null, result);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
var _keyObjectInternalMarker = Symbol("internal");
function KeyObject(type, data) {
	if (!(this instanceof KeyObject)) return new KeyObject(type, data);
	if (type !== "secret" && type !== "public" && type !== "private") throw _errInvalidArgValue("type", type);
	if (data !== _keyObjectInternalMarker && data !== void 0 && data !== null && typeof data !== "object") throw _errInvalidArgType("handle", "of type object", data);
	this._type = type;
	this._data = data === _keyObjectInternalMarker ? void 0 : data;
	this._asymmetricKeyType = void 0;
	this._asymmetricKeyDetails = void 0;
}
function _createKeyObject(type, data) {
	var k = new KeyObject(type, _keyObjectInternalMarker);
	k._data = data;
	return k;
}
KeyObject.from = function(key) {
	if (typeof CryptoKey !== "undefined" && key instanceof CryptoKey) return new KeyObject("secret", key);
	throw _errInvalidArgType("key", "an instance of CryptoKey", key);
};
Object.defineProperty(KeyObject.prototype, "type", {
	get: function() {
		return this._type;
	},
	enumerable: true,
	configurable: true
});
Object.defineProperty(KeyObject.prototype, "symmetricKeySize", {
	get: function() {
		return this._type === "secret" ? this._data.length : void 0;
	},
	enumerable: true,
	configurable: true
});
Object.defineProperty(KeyObject.prototype, "asymmetricKeyType", {
	get: function() {
		return this._asymmetricKeyType;
	},
	enumerable: true,
	configurable: true
});
Object.defineProperty(KeyObject.prototype, "asymmetricKeyDetails", {
	get: function() {
		return this._asymmetricKeyDetails;
	},
	enumerable: true,
	configurable: true
});
KeyObject.prototype.export = function(options) {
	if (!options) {
		if (this._type === "secret") return typeof Buffer !== "undefined" ? Buffer.from(this._data) : this._data;
		return this._data;
	}
	if (options.format === "jwk") {
		if (this._type === "secret") {
			var keyBytes = _toBytes(this._data);
			var b64 = "";
			if (typeof btoa === "function") {
				var s = "";
				for (var i = 0; i < keyBytes.length; i++) s += String.fromCharCode(keyBytes[i]);
				b64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
			}
			return {
				kty: "oct",
				k: b64
			};
		}
		return this._data;
	}
	if (options.format === "buffer" || !options.format) {
		if (typeof this._data === "string") {
			if (typeof Buffer !== "undefined") return Buffer.from(this._data);
		}
		return this._data;
	}
	return this._data;
};
KeyObject.prototype.equals = function(other) {
	if (!(other instanceof KeyObject)) throw _errInvalidArgType("otherKeyObject", "KeyObject", other);
	if (this._type !== other._type) return false;
	var a = _toBytes(this._data), b = _toBytes(other._data);
	if (a.length !== b.length) return false;
	for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
};
KeyObject.from = function(key) {
	if (typeof CryptoKey !== "undefined" && key instanceof CryptoKey) return _createKeyObject(key.type === "secret" ? "secret" : key.type, key);
	throw _errInvalidArgType("key", "an instance of CryptoKey", key);
};
function createSecretKey(material, encoding) {
	if (material instanceof KeyObject) {
		if (material._type !== "secret") throw _createCryptoError(TypeError, "ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE", "Invalid key object type secret, got " + material._type);
		return _createKeyObject("secret", _toBytes(material._data));
	}
	if (typeof material !== "string" && !_isStringOrBuffer(material)) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, or DataView", material);
	var bytes;
	if (typeof material === "string") if (encoding === "hex") {
		bytes = new Uint8Array(material.length / 2);
		for (var i = 0; i < material.length; i += 2) bytes[i / 2] = parseInt(material.substr(i, 2), 16);
	} else if (encoding === "base64") if (typeof atob === "function") {
		var raw = atob(material);
		bytes = new Uint8Array(raw.length);
		for (var j = 0; j < raw.length; j++) bytes[j] = raw.charCodeAt(j);
	} else bytes = _toBytes(material);
	else bytes = _toBytes(material);
	else bytes = _toBytes(material);
	return _createKeyObject("secret", bytes);
}
function _decodePemKeyBytes(raw) {
	if (typeof raw !== "string") return _toBytes(raw);
	var match = raw.match(/-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/);
	if (!match) return _toBytes(raw);
	var base64 = match[1].replace(/[^A-Za-z0-9+/=]/g, "");
	if (!base64) return _toBytes(raw);
	if (typeof Buffer !== "undefined" && Buffer.from) return new Uint8Array(Buffer.from(base64, "base64"));
	if (typeof atob === "function") {
		var decoded = atob(base64);
		var out = new Uint8Array(decoded.length);
		for (var i = 0; i < decoded.length; i++) out[i] = decoded.charCodeAt(i);
		return out;
	}
	return _toBytes(raw);
}
function _detectAsymmetricKeyType(raw) {
	if (raw instanceof KeyObject && raw._asymmetricKeyType) return raw._asymmetricKeyType;
	if (typeof raw === "string") {
		var upper = raw.toUpperCase();
		if (upper.indexOf("BEGIN RSA PUBLIC KEY") !== -1 || upper.indexOf("BEGIN RSA PRIVATE KEY") !== -1) return "rsa";
		if (upper.indexOf("BEGIN EC PRIVATE KEY") !== -1) return "ec";
	}
	var hex = _toHex(_decodePemKeyBytes(raw)).toLowerCase();
	if (hex.indexOf("06092a864886f70d01010a") !== -1) return "rsa-pss";
	if (hex.indexOf("06092a864886f70d010101") !== -1) return "rsa";
	if (hex.indexOf("06072a8648ce3d0201") !== -1) return "ec";
	if (hex.indexOf("06072a8648ce380401") !== -1) return "dsa";
	if (hex.indexOf("06032b656e") !== -1) return "x25519";
	if (hex.indexOf("06032b656f") !== -1) return "x448";
	if (hex.indexOf("06032b6570") !== -1) return "ed25519";
	if (hex.indexOf("06032b6571") !== -1) return "ed448";
	if (hex.indexOf("0609608648016503040401") !== -1 || hex.indexOf("0609608648016503040402") !== -1 || hex.indexOf("0609608648016503040403") !== -1) return "ml-kem";
	if (hex.indexOf("0609608648016503040311") !== -1 || hex.indexOf("0609608648016503040312") !== -1 || hex.indexOf("0609608648016503040313") !== -1) return "ml-dsa";
	if (hex.indexOf("0609608648016503040314") !== -1 || hex.indexOf("0609608648016503040315") !== -1 || hex.indexOf("0609608648016503040316") !== -1 || hex.indexOf("0609608648016503040317") !== -1 || hex.indexOf("0609608648016503040318") !== -1 || hex.indexOf("0609608648016503040319") !== -1) return "slh-dsa";
	return "rsa";
}
function createPublicKey(key) {
	if (key instanceof KeyObject) {
		if (key._type === "private") {
			var pub = _createKeyObject("public", key._data);
			pub._asymmetricKeyType = key._asymmetricKeyType;
			return pub;
		}
		return key;
	}
	var keyFormat = key && typeof key === "object" && !(key instanceof Uint8Array) && !(_bufferAvailable && Buffer.isBuffer(key)) ? key.format : void 0;
	key && typeof key === "object" && !(key instanceof Uint8Array) && !(_bufferAvailable && Buffer.isBuffer(key)) && key.type;
	var raw = key && typeof key === "object" && key.key !== void 0 ? key.key : key;
	if (keyFormat === "jwk" && raw && typeof raw === "object" && !_isStringOrBuffer(raw)) {
		var jwk = key && key.key ? key.key : key;
		if (typeof jwk !== "object" || jwk === null) throw _errInvalidArgType("key.key", "of type object", jwk);
		var kty = jwk.kty;
		if (kty !== "RSA" && kty !== "EC" && kty !== "OKP") {
			var jwkErr = /* @__PURE__ */ new TypeError("The argument 'key.key.kty' must be one of: 'RSA', 'EC', 'OKP'. Received '" + kty + "'");
			jwkErr.code = "ERR_INVALID_ARG_VALUE";
			throw jwkErr;
		}
		var ko2 = _createKeyObject("public", jwk);
		if (kty === "RSA") ko2._asymmetricKeyType = "rsa";
		else if (kty === "EC") ko2._asymmetricKeyType = "ec";
		else if (kty === "OKP") {
			var crv = jwk.crv;
			if (crv === "Ed25519") ko2._asymmetricKeyType = "ed25519";
			else if (crv === "Ed448") ko2._asymmetricKeyType = "ed448";
			else if (crv === "X25519") ko2._asymmetricKeyType = "x25519";
			else if (crv === "X448") ko2._asymmetricKeyType = "x448";
			else ko2._asymmetricKeyType = "ed25519";
		}
		return ko2;
	}
	if (typeof raw !== "string" && !_isStringOrBuffer(raw)) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", raw);
	var ko = _createKeyObject("public", raw);
	ko._asymmetricKeyType = _detectAsymmetricKeyType(raw);
	return ko;
}
var _bufferAvailable = typeof Buffer !== "undefined" && Buffer.isBuffer;
function createPrivateKey(key) {
	if (key instanceof KeyObject) return key;
	var raw;
	var passphrase;
	if (key && typeof key === "object" && !(key instanceof Uint8Array) && !Buffer.isBuffer(key)) {
		raw = key.key;
		passphrase = key.passphrase;
	} else raw = key;
	if (typeof raw !== "string" && !_isStringOrBuffer(raw)) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", raw);
	var ko = _createKeyObject("private", raw);
	ko._asymmetricKeyType = _detectAsymmetricKeyType(raw);
	ko._passphrase = passphrase;
	return ko;
}
function generateKeySync(type, options) {
	if (typeof type !== "string") throw _errInvalidArgType("type", "of type string", type);
	if (!options || typeof options !== "object" || Array.isArray(options)) throw _errInvalidArgType("options", "of type object", options);
	var len;
	if (type === "aes") {
		len = options.length;
		if (typeof len !== "number" || !Number.isFinite(len)) throw _errInvalidArgTypeProp("options.length", "of type number", len);
		if (len !== 128 && len !== 192 && len !== 256) {
			var e = /* @__PURE__ */ new TypeError("The property 'options.length' must be one of: 128, 192, 256. Received " + len);
			e.code = "ERR_INVALID_ARG_VALUE";
			throw e;
		}
	} else if (type === "hmac") {
		len = options.length;
		if (typeof len !== "number" || !Number.isFinite(len)) throw _errInvalidArgTypeProp("options.length", "of type number", len);
		if (len < 8 || len > 2147483647) throw _errOutOfRange("options.length", ">= 8 and <= 2^31 - 1", len);
	} else {
		var e2 = /* @__PURE__ */ new TypeError("The argument 'type' must be a supported key type. Received '" + type + "'");
		e2.code = "ERR_INVALID_ARG_VALUE";
		throw e2;
	}
	return createSecretKey(randomBytes(Math.floor(len / 8)));
}
function generateKey(type, options, callback) {
	if (typeof type !== "string") throw _errInvalidArgType("type", "of type string", type);
	if (typeof options === "function") {
		callback = options;
		options = void 0;
	}
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	if (!options || typeof options !== "object" || Array.isArray(options)) throw _errInvalidArgType("options", "of type object", options);
	if (type === "aes") {
		var aesLen = options.length;
		if (typeof aesLen !== "number" || !Number.isFinite(aesLen)) throw _errInvalidArgTypeProp("options.length", "of type number", aesLen);
		if (aesLen !== 128 && aesLen !== 192 && aesLen !== 256) {
			var e = /* @__PURE__ */ new TypeError("The property 'options.length' must be one of: 128, 192, 256. Received " + aesLen);
			e.code = "ERR_INVALID_ARG_VALUE";
			throw e;
		}
	} else if (type === "hmac") {
		var hmacLen = options.length;
		if (typeof hmacLen !== "number" || !Number.isFinite(hmacLen)) throw _errInvalidArgTypeProp("options.length", "of type number", hmacLen);
		if (hmacLen < 8 || hmacLen > 2147483647) throw _errOutOfRange("options.length", ">= 8 and <= 2^31 - 1", hmacLen);
	} else {
		var e2 = /* @__PURE__ */ new TypeError("The argument 'type' must be a supported key type. Received '" + type + "'");
		e2.code = "ERR_INVALID_ARG_VALUE";
		throw e2;
	}
	try {
		var result = generateKeySync(type, options);
		setTimeout(function() {
			callback(null, result);
		}, 0);
	} catch (e3) {
		setTimeout(function() {
			callback(e3);
		}, 0);
	}
}
var _cipherInfo = {
	"aes-128-wrap": {
		keyBytes: 16,
		openssl: "aes-128-wrap"
	},
	"aes-192-wrap": {
		keyBytes: 24,
		openssl: "aes-192-wrap"
	},
	"aes-256-wrap": {
		keyBytes: 32,
		openssl: "aes-256-wrap"
	},
	"aes-128-wrap-pad": {
		keyBytes: 16,
		openssl: "aes-128-wrap-pad"
	},
	"aes-192-wrap-pad": {
		keyBytes: 24,
		openssl: "aes-192-wrap-pad"
	},
	"aes-256-wrap-pad": {
		keyBytes: 32,
		openssl: "aes-256-wrap-pad"
	},
	"aes-128-ecb": {
		keyBytes: 16,
		openssl: "aes-128-ecb"
	},
	"aes-192-ecb": {
		keyBytes: 24,
		openssl: "aes-192-ecb"
	},
	"aes-256-ecb": {
		keyBytes: 32,
		openssl: "aes-256-ecb"
	},
	"aes-128-cbc": {
		keyBytes: 16,
		openssl: "aes-128-cbc"
	},
	"aes-192-cbc": {
		keyBytes: 24,
		openssl: "aes-192-cbc"
	},
	"aes-256-cbc": {
		keyBytes: 32,
		openssl: "aes-256-cbc"
	},
	"aes-128-ctr": {
		keyBytes: 16,
		openssl: "aes-128-ctr"
	},
	"aes-192-ctr": {
		keyBytes: 24,
		openssl: "aes-192-ctr"
	},
	"aes-256-ctr": {
		keyBytes: 32,
		openssl: "aes-256-ctr"
	},
	"aes-128-gcm": {
		keyBytes: 16,
		openssl: "aes-128-gcm",
		aead: true
	},
	"aes-192-gcm": {
		keyBytes: 24,
		openssl: "aes-192-gcm",
		aead: true
	},
	"aes-256-gcm": {
		keyBytes: 32,
		openssl: "aes-256-gcm",
		aead: true
	},
	"aes-128-ccm": {
		keyBytes: 16,
		openssl: "aes-128-ccm",
		aead: true
	},
	"aes-192-ccm": {
		keyBytes: 24,
		openssl: "aes-192-ccm",
		aead: true
	},
	"aes-256-ccm": {
		keyBytes: 32,
		openssl: "aes-256-ccm",
		aead: true
	},
	"chacha20-poly1305": {
		keyBytes: 32,
		openssl: "chacha20-poly1305",
		aead: true
	},
	"chacha20": {
		keyBytes: 32,
		openssl: "chacha20"
	},
	"des-cbc": {
		keyBytes: 8,
		openssl: "des-cbc"
	},
	"des": {
		keyBytes: 8,
		openssl: "des-cbc"
	},
	"des-ede3-cbc": {
		keyBytes: 24,
		openssl: "des-ede3-cbc"
	},
	"des-ede3": {
		keyBytes: 24,
		openssl: "des-ede3-cbc"
	},
	"des3": {
		keyBytes: 24,
		openssl: "des-ede3-cbc"
	},
	"bf-cbc": {
		keyBytes: 16,
		openssl: "bf-cbc"
	},
	"bf": {
		keyBytes: 16,
		openssl: "bf-cbc"
	},
	"blowfish": {
		keyBytes: 16,
		openssl: "bf-cbc"
	},
	"bf-ecb": {
		keyBytes: 16,
		openssl: "bf-ecb"
	},
	"bf-cfb": {
		keyBytes: 16,
		openssl: "bf-cfb"
	},
	"bf-ofb": {
		keyBytes: 16,
		openssl: "bf-ofb"
	},
	"des-ecb": {
		keyBytes: 8,
		openssl: "des-ecb"
	},
	"des-cfb": {
		keyBytes: 8,
		openssl: "des-cfb"
	},
	"des-ofb": {
		keyBytes: 8,
		openssl: "des-ofb"
	},
	"des-ede3-cfb": {
		keyBytes: 24,
		openssl: "des-ede3-cfb"
	},
	"des-ede3-ofb": {
		keyBytes: 24,
		openssl: "des-ede3-ofb"
	},
	"rc4": {
		keyBytes: 16,
		openssl: "rc4"
	}
};
function _normalizeCipherAlgorithm(algorithm) {
	var normalized = (algorithm || "").toString().toLowerCase().replace(/_/g, "-");
	normalized = normalized.replace(/\s+/g, "");
	normalized = normalized.replace(/^id-/, "");
	if (/^aes\d{3}(gcm|cbc|ctr|ccm|ecb)$/.test(normalized)) {
		normalized = normalized.replace(/^aes(\d{3})(gcm|cbc|ctr|ecb)$/, "aes-$1-$2");
		normalized = normalized.replace(/^aes(\d{3})(ccm)$/, "aes-$1-$2");
	} else if (/^aes\d{3}-wrap(-pad)?$/.test(normalized)) normalized = normalized.replace(/^aes(\d{3})(-wrap(?:-pad)?)$/, "aes-$1$2");
	else if (/^aes-\d{3}(gcm|cbc|ctr|ccm|ecb)$/.test(normalized)) {
		normalized = normalized.replace(/^(aes-\d{3})(gcm|cbc|ctr|ecb)$/, "$1-$2");
		normalized = normalized.replace(/^(aes-\d{3})(ccm)$/, "$1-$2");
	}
	return normalized;
}
function _isWrapAlgorithm(algorithm) {
	return algorithm.indexOf("wrap") !== -1;
}
function _normalizeCipherOptions(algorithm, options) {
	var normalized = _normalizeCipherAlgorithm(algorithm);
	var info = _cipherInfo[normalized];
	var keyBytes = 16;
	if (info) keyBytes = info.keyBytes;
	else if (normalized.indexOf("aes-128-") === 0) keyBytes = 16;
	else if (normalized.indexOf("aes-192-") === 0) keyBytes = 24;
	else if (normalized.indexOf("aes-256-") === 0) keyBytes = 32;
	var opt = options || {};
	if (typeof opt === "number") opt = { authTagLength: opt };
	else if (typeof opt === "string") opt = { iv: opt };
	else if (typeof opt === "object" && opt !== null) opt = Object.create(opt);
	else opt = {};
	if (typeof opt.authTagLength === "number") opt.authTagLength = Math.max(1, Math.floor(opt.authTagLength));
	return {
		algorithm: normalized,
		keyBytes,
		authTagLength: opt.authTagLength !== void 0 ? opt.authTagLength : 16,
		authTagLengthExplicit: opt.authTagLength !== void 0,
		ivOverride: opt.iv,
		tagLength: opt.tagLength || opt.authTagLength,
		isAead: info && info.aead,
		opensslName: info && info.openssl
	};
}
function _requireCipherMode(algorithm) {
	if (algorithm.indexOf("aes-") === 0) {
		if (algorithm.indexOf("gcm") !== -1 || algorithm.indexOf("cbc") !== -1 || algorithm.indexOf("ctr") !== -1) return true;
		return !!_cipherInfo[algorithm] && typeof __exactEvpCipherEncrypt === "function";
	}
	return !!_cipherInfo[algorithm] || typeof __exactEvpCipherEncrypt === "function";
}
function _concatChunks(chunks) {
	var totalLen = 0;
	for (var i = 0; i < chunks.length; i++) totalLen += chunks[i].length;
	var combined = new Uint8Array(totalLen);
	var offset = 0;
	for (var j = 0; j < chunks.length; j++) {
		combined.set(chunks[j], offset);
		offset += chunks[j].length;
	}
	return combined;
}
function _parseInputData(data, inputEncoding) {
	if (typeof data === "string") if (inputEncoding === "hex") {
		var bytes = new Uint8Array(data.length / 2);
		for (var i = 0; i < data.length; i += 2) bytes[i / 2] = parseInt(data.substr(i, 2), 16);
		return bytes;
	} else if (inputEncoding === "base64") {
		var raw = atob(data);
		var bytes2 = new Uint8Array(raw.length);
		for (var j = 0; j < raw.length; j++) bytes2[j] = raw.charCodeAt(j);
		return bytes2;
	} else return _toUint8Array(data);
	return _toUint8Array(data);
}
var _validEncodings = {
	utf8: 1,
	utf16le: 1,
	ucs2: 1,
	latin1: 1,
	binary: 1,
	ascii: 1,
	hex: 1,
	base64: 1,
	base64url: 1,
	"utf-8": 1
};
function Cipher(algorithm, key, iv, options) {
	if (!(this instanceof Cipher)) return new Cipher(algorithm, key, iv, options);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	var normalized = _normalizeCipherOptions(algorithm, options);
	if (!_requireCipherMode(normalized.algorithm)) {
		var uce = /* @__PURE__ */ new Error("Unknown cipher");
		uce.code = "ERR_CRYPTO_UNKNOWN_CIPHER";
		throw uce;
	}
	if (iv === void 0) throw _errInvalidArgType("iv", "of type string or an instance of Buffer, TypedArray, DataView, or null", iv);
	var keyBytes = _toUint8Array(key);
	var info = _cipherInfo[normalized.algorithm];
	if (info && info.keyBytes && keyBytes.length !== info.keyBytes) throw new RangeError("Invalid key length");
	var isEcb = normalized.algorithm.indexOf("ecb") !== -1;
	if (isEcb && iv !== null) {
		if (_toUint8Array(iv).length > 0) throw new Error("Invalid initialization vector");
	}
	if (normalized.algorithm.indexOf("gcm") !== -1) {
		if ((iv === null ? new Uint8Array(0) : _toUint8Array(iv)).length === 0) throw new Error("Invalid initialization vector");
	}
	if (normalized.algorithm.indexOf("cbc") !== -1 && !isEcb) {
		if (iv === null) throw new Error("Invalid initialization vector");
		var cbcIv = _toUint8Array(iv);
		var expectedIvLen = normalized.algorithm.indexOf("des") !== -1 ? 8 : 16;
		if (cbcIv.length !== expectedIvLen) throw new Error("Invalid initialization vector");
	}
	this._algo = normalized.algorithm;
	this._key = keyBytes;
	this._iv = iv === null || iv === void 0 ? new Uint8Array(0) : _toUint8Array(normalized.ivOverride !== void 0 ? normalized.ivOverride : iv);
	this._chunks = [];
	this._finalized = false;
	this._streamEnded = false;
	this._aad = null;
	this._authTag = null;
	this._authTagLength = normalized.authTagLength;
	this._authTagLengthExplicit = normalized.authTagLengthExplicit;
	this._cipherKeyBytes = normalized.keyBytes;
	this._isAead = normalized.isAead;
	this._opensslName = normalized.opensslName;
	this._inlineFinalized = false;
	this._inlineFinalResult = null;
	this._outputEncoding = null;
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Cipher.prototype, _CipherStreamTransform.prototype);
	Cipher.prototype.constructor = Cipher;
	Cipher.prototype._transform = function(chunk, encoding, callback) {
		this._chunks.push(_parseInputData(chunk, encoding));
		if (typeof callback === "function") callback();
	};
	Cipher.prototype._flushStreamResult = function() {
		var result = this.final();
		if (result && result.length) this.push(result);
	};
	Cipher.prototype._flush = function(callback) {
		try {
			this._flushStreamResult();
		} catch (e) {
			if (typeof callback === "function") {
				callback(e);
				return;
			}
			throw e;
		}
		if (typeof callback === "function") callback();
	};
	Cipher.prototype._final = function(callback) {
		if (typeof callback === "function") callback();
	};
	Cipher.prototype.end = function(chunk, encoding, callback) {
		if (typeof chunk === "function") {
			callback = chunk;
			chunk = null;
			encoding = void 0;
		}
		if (typeof encoding === "function") {
			callback = encoding;
			encoding = void 0;
		}
		if (this._streamEnded) {
			if (typeof callback === "function") callback();
			return this;
		}
		this._streamEnded = true;
		if (chunk !== void 0 && chunk !== null) this._chunks.push(_parseInputData(chunk, encoding));
		if (_CipherStreamTransform && _CipherStreamTransform.prototype && typeof _CipherStreamTransform.prototype.end === "function") return _CipherStreamTransform.prototype.end.call(this, callback);
		try {
			this._flushStreamResult();
			this.push(null);
			if (typeof callback === "function") callback();
		} catch (e) {
			if (typeof callback === "function") callback(e);
			else throw e;
		}
		return this;
	};
}
Cipher.prototype.update = function(data, inputEncoding, outputEncoding) {
	if (outputEncoding !== void 0 && outputEncoding !== null) {
		if (!_validEncodings[outputEncoding] && outputEncoding !== "buffer") {
			var ue = /* @__PURE__ */ new TypeError("Unknown encoding: " + outputEncoding);
			ue.code = "ERR_UNKNOWN_ENCODING";
			throw ue;
		}
		if (this._outputEncoding !== null && this._outputEncoding !== outputEncoding) throw new Error("Cannot change encoding");
		this._outputEncoding = outputEncoding;
	}
	this._chunks.push(_parseInputData(data, inputEncoding));
	if (_isWrapAlgorithm(this._algo)) {
		if (this._inlineFinalized && this._finalized) {
			if (outputEncoding && outputEncoding !== "buffer") return "";
			return typeof Buffer !== "undefined" && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
		}
		var wrapResult = this.final();
		this._inlineFinalized = true;
		this._inlineFinalResult = wrapResult;
		if (outputEncoding && outputEncoding !== "buffer") return wrapResult.toString(outputEncoding);
		return wrapResult;
	}
	if (outputEncoding && outputEncoding !== "buffer") return "";
	return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
};
Cipher.prototype.final = function(outputEncoding) {
	if (outputEncoding !== void 0 && outputEncoding !== null) {
		if (!_validEncodings[outputEncoding] && outputEncoding !== "buffer") {
			var ue = /* @__PURE__ */ new TypeError("Unknown encoding: " + outputEncoding);
			ue.code = "ERR_UNKNOWN_ENCODING";
			throw ue;
		}
		if (this._outputEncoding !== null && this._outputEncoding !== outputEncoding) throw new Error("Cannot change encoding");
	}
	if (this._inlineFinalized && this._finalized) {
		if (outputEncoding && outputEncoding !== "buffer") return "";
		return typeof Buffer !== "undefined" && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
	}
	this._finalized = true;
	var combined = _concatChunks(this._chunks);
	var result;
	if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("gcm") !== -1) {
		if (typeof __exactAesGcmEncrypt !== "function") throw new Error("AES-GCM encrypt not available");
		var tagBits = this._authTagLength * 8;
		var encResult = __exactAesGcmEncrypt(this._key, this._iv, combined, this._aad, tagBits);
		var tagLen = this._authTagLength;
		var ciphertext = encResult.slice(0, encResult.length - tagLen);
		var tag = encResult.slice(encResult.length - tagLen);
		if (typeof Buffer !== "undefined" && Buffer.from) {
			this._authTag = Buffer.from(tag);
			result = Buffer.from(ciphertext);
		} else {
			this._authTag = tag;
			result = ciphertext;
		}
	} else if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("cbc") !== -1) {
		if (typeof __exactAesCbcEncrypt !== "function") throw new Error("AES-CBC encrypt not available");
		result = __exactAesCbcEncrypt(this._key, this._iv, combined);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("ctr") !== -1) {
		if (typeof __exactAesCtrEncrypt !== "function") throw new Error("AES-CTR encrypt not available");
		result = __exactAesCtrEncrypt(this._key, this._iv, combined);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else if (typeof __exactEvpCipherEncrypt === "function" && this._opensslName) {
		var evpResult;
		if (this._algo.indexOf("ccm") !== -1) {
			var ccmAad = this._aad ? this._aad : new Uint8Array(0);
			evpResult = __exactEvpCipherEncrypt(this._opensslName, this._key, this._iv, combined, ccmAad, this._authTagLength);
		} else evpResult = __exactEvpCipherEncrypt(this._opensslName, this._key, this._iv, combined);
		if (this._isAead && evpResult.length > 16) {
			var atagLen = this._authTagLength;
			var ct = evpResult.slice(0, evpResult.length - atagLen);
			var atag = evpResult.slice(evpResult.length - atagLen);
			if (typeof Buffer !== "undefined" && Buffer.from) {
				this._authTag = Buffer.from(atag);
				result = Buffer.from(ct);
			} else {
				this._authTag = atag;
				result = ct;
			}
		} else {
			result = evpResult;
			if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
		}
	} else throw new Error("Unsupported cipher algorithm: " + this._algo);
	if (outputEncoding === "hex") return result.toString("hex");
	if (outputEncoding === "base64") return result.toString("base64");
	return result;
};
Cipher.prototype.setAutoPadding = function() {
	return this;
};
Cipher.prototype[Symbol.toStringTag] = "Cipher";
Cipher.prototype.getAuthTag = function() {
	if (!this._finalized) throw new Error("Cannot get auth tag before calling final()");
	if (this._authTag === null) return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
	return this._authTag;
};
Cipher.prototype.setAAD = function(aad, options) {
	this._aad = _toUint8Array(aad);
	return this;
};
function Decipher(algorithm, key, iv, options) {
	if (!(this instanceof Decipher)) return new Decipher(algorithm, key, iv, options);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	var normalized = _normalizeCipherOptions(algorithm, options);
	if (!_requireCipherMode(normalized.algorithm)) {
		var uce = /* @__PURE__ */ new Error("Unknown cipher");
		uce.code = "ERR_CRYPTO_UNKNOWN_CIPHER";
		throw uce;
	}
	if (iv === void 0) throw _errInvalidArgType("iv", "of type string or an instance of Buffer, TypedArray, DataView, or null", iv);
	this._algo = normalized.algorithm;
	this._key = _toUint8Array(key);
	this._iv = iv === null || iv === void 0 ? new Uint8Array(0) : _toUint8Array(normalized.ivOverride !== void 0 ? normalized.ivOverride : iv);
	this._chunks = [];
	this._finalized = false;
	this._streamEnded = false;
	this._aad = null;
	this._authTag = null;
	this._authTagLength = normalized.authTagLength;
	this._authTagLengthExplicit = normalized.authTagLengthExplicit;
	this._cipherKeyBytes = normalized.keyBytes;
	this._isAead = normalized.isAead;
	this._opensslName = normalized.opensslName;
	this._inlineFinalized = false;
	this._inlineFinalResult = null;
	this._outputEncoding = null;
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Decipher.prototype, _CipherStreamTransform.prototype);
	Decipher.prototype.constructor = Decipher;
	Decipher.prototype._transform = function(chunk, encoding, callback) {
		this._chunks.push(_parseInputData(chunk, encoding));
		if (typeof callback === "function") callback();
	};
	Decipher.prototype._flushStreamResult = function() {
		var result = this.final();
		if (result && result.length) this.push(result);
	};
	Decipher.prototype._flush = function(callback) {
		try {
			this._flushStreamResult();
		} catch (e) {
			if (typeof callback === "function") {
				callback(e);
				return;
			}
			throw e;
		}
		if (typeof callback === "function") callback();
	};
	Decipher.prototype._final = function(callback) {
		if (typeof callback === "function") callback();
	};
	Decipher.prototype.end = function(chunk, encoding, callback) {
		if (typeof chunk === "function") {
			callback = chunk;
			chunk = null;
			encoding = void 0;
		}
		if (typeof encoding === "function") {
			callback = encoding;
			encoding = void 0;
		}
		if (this._streamEnded) {
			if (typeof callback === "function") callback();
			return this;
		}
		this._streamEnded = true;
		if (chunk !== void 0 && chunk !== null) this._chunks.push(_parseInputData(chunk, encoding));
		if (_CipherStreamTransform && _CipherStreamTransform.prototype && typeof _CipherStreamTransform.prototype.end === "function") return _CipherStreamTransform.prototype.end.call(this, callback);
		try {
			this._flushStreamResult();
			this.push(null);
			if (typeof callback === "function") callback();
		} catch (e) {
			if (typeof callback === "function") callback(e);
			else throw e;
		}
		return this;
	};
}
Decipher.prototype.update = function(data, inputEncoding, outputEncoding) {
	this._chunks.push(_parseInputData(data, inputEncoding));
	if (_isWrapAlgorithm(this._algo)) {
		if (this._inlineFinalized && this._finalized) {
			if (outputEncoding && outputEncoding !== "buffer") return "";
			return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
		}
		var decodeResult = this.final();
		this._inlineFinalized = true;
		this._inlineFinalResult = decodeResult;
		if (outputEncoding && outputEncoding !== "buffer") return decodeResult.toString(outputEncoding);
		return decodeResult;
	}
	if (outputEncoding && outputEncoding !== "buffer") return "";
	return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
};
Decipher.prototype.final = function(outputEncoding) {
	if (this._inlineFinalized && this._finalized) {
		if (outputEncoding && outputEncoding !== "buffer") return "";
		return typeof Buffer !== "undefined" && Buffer.alloc ? Buffer.alloc(0) : new Uint8Array(0);
	}
	this._finalized = true;
	var combined = _concatChunks(this._chunks);
	var result;
	if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("gcm") !== -1) {
		if (typeof __exactAesGcmDecrypt !== "function") throw new Error("AES-GCM decrypt not available");
		if (!this._authTag) throw new Error("Unsupported state or unable to authenticate data");
		var tag = _toUint8Array(this._authTag);
		var dataWithTag = new Uint8Array(combined.length + tag.length);
		dataWithTag.set(combined, 0);
		dataWithTag.set(tag, combined.length);
		var tagBits = tag.length * 8;
		result = __exactAesGcmDecrypt(this._key, this._iv, dataWithTag, this._aad, tagBits);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("cbc") !== -1) {
		if (typeof __exactAesCbcDecrypt !== "function") throw new Error("AES-CBC decrypt not available");
		result = __exactAesCbcDecrypt(this._key, this._iv, combined);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else if (this._algo.indexOf("aes") !== -1 && this._algo.indexOf("ctr") !== -1) {
		if (typeof __exactAesCtrEncrypt !== "function") throw new Error("AES-CTR decrypt not available");
		result = __exactAesCtrEncrypt(this._key, this._iv, combined);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else if (typeof __exactEvpCipherDecrypt === "function" && this._opensslName) {
		var authTag = this._isAead && this._authTag ? _toUint8Array(this._authTag) : void 0;
		if (this._algo.indexOf("ccm") !== -1) {
			var ccmAad = this._aad ? this._aad : new Uint8Array(0);
			result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined, authTag, ccmAad, this._authTagLength);
		} else if (this._isAead) result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined, authTag);
		else result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined);
		if (typeof Buffer !== "undefined" && Buffer.from) result = Buffer.from(result);
	} else throw new Error("Unsupported decipher algorithm: " + this._algo);
	if (outputEncoding === "hex") return result.toString("hex");
	if (outputEncoding === "base64") return result.toString("base64");
	if (outputEncoding === "utf8" || outputEncoding === "utf-8") return result.toString("utf8");
	return result;
};
Decipher.prototype.setAutoPadding = function() {
	return this;
};
Decipher.prototype.setAuthTag = function(tag) {
	var tagBytes = _toUint8Array(tag);
	if (this._authTagLengthExplicit && tagBytes.length !== this._authTagLength) {
		var err = /* @__PURE__ */ new TypeError("Invalid authentication tag length: " + tagBytes.length);
		err.code = "ERR_CRYPTO_INVALID_AUTH_TAG";
		throw err;
	}
	this._authTag = tagBytes;
	return this;
};
Decipher.prototype.setAAD = function(aad, options) {
	this._aad = _toUint8Array(aad);
	return this;
};
Decipher.prototype[Symbol.toStringTag] = "Decipher";
function createCipheriv(algorithm, key, iv, options) {
	if (typeof algorithm !== "string") throw _errInvalidArgType("cipher", "of type string", algorithm);
	if (key === null || key === void 0) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", key);
	if (iv !== null && iv !== void 0 && typeof iv === "number") throw _errInvalidArgType("iv", "of type string or an instance of Buffer, TypedArray, DataView, or null", iv);
	return new Cipher(algorithm, key, iv, options);
}
function createDecipheriv(algorithm, key, iv, options) {
	if (typeof algorithm !== "string") throw _errInvalidArgType("cipher", "of type string", algorithm);
	if (key === null || key === void 0) throw _errInvalidArgType("key", "of type string or an instance of Buffer, TypedArray, DataView, or KeyObject", key);
	if (iv !== null && iv !== void 0 && typeof iv === "number") throw _errInvalidArgType("iv", "of type string or an instance of Buffer, TypedArray, DataView, or null", iv);
	return new Decipher(algorithm, key, iv, options);
}
function _normalizeScryptOption(options) {
	var opts = options || {};
	if (opts.N !== void 0 && opts.cost !== void 0) {
		var e1 = /* @__PURE__ */ new Error("Option \"N\" cannot be used in combination with option \"cost\"");
		e1.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
		throw e1;
	}
	if (opts.r !== void 0 && opts.blockSize !== void 0) {
		var e2 = /* @__PURE__ */ new Error("Option \"r\" cannot be used in combination with option \"blockSize\"");
		e2.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
		throw e2;
	}
	if (opts.p !== void 0 && opts.parallelization !== void 0) {
		var e3 = /* @__PURE__ */ new Error("Option \"p\" cannot be used in combination with option \"parallelization\"");
		e3.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
		throw e3;
	}
	var rawN = opts.N !== void 0 ? opts.N : opts.cost !== void 0 ? opts.cost : 16384;
	var rawR = opts.r !== void 0 ? opts.r : opts.blockSize !== void 0 ? opts.blockSize : 8;
	var rawP = opts.p !== void 0 ? opts.p : opts.parallelization !== void 0 ? opts.parallelization : 1;
	if (typeof rawN !== "number") throw _errInvalidArgType(opts.N !== void 0 ? "N" : "cost", "of type number", rawN);
	if (typeof rawR !== "number") throw _errInvalidArgType(opts.r !== void 0 ? "r" : "blockSize", "of type number", rawR);
	if (typeof rawP !== "number") throw _errInvalidArgType(opts.p !== void 0 ? "p" : "parallelization", "of type number", rawP);
	var N = Number(rawN);
	var r = Number(rawR);
	var p = Number(rawP);
	if (!Number.isFinite(N)) throw _errInvalidArgType("N", "of type number", N);
	if (!Number.isFinite(r)) throw _errInvalidArgType("r", "of type number", r);
	if (!Number.isFinite(p)) throw _errInvalidArgType("p", "of type number", p);
	if (N <= 1 || (N & N - 1) !== 0) throw new Error("Invalid scrypt params");
	if (r <= 0 || p <= 0) throw new Error("Invalid scrypt params");
	var maxmem = opts.maxmem !== void 0 ? opts.maxmem : 32 * 1024 * 1024;
	if (opts.maxmem !== void 0) {
		if (typeof opts.maxmem !== "number" || !Number.isSafeInteger(opts.maxmem) || opts.maxmem < 0) throw _errOutOfRange("options.maxmem", ">= 0 && <= 2^53 - 1", opts.maxmem);
	}
	if (N >= Math.pow(2, r * 16)) {
		var memErr1 = /* @__PURE__ */ new Error("Invalid scrypt params: memory limit exceeded");
		memErr1.code = "ERR_CRYPTO_INVALID_SCRYPT_PARAMS";
		throw memErr1;
	}
	if (p > (Math.pow(2, 30) - 1) / r) {
		var memErr2 = /* @__PURE__ */ new Error("Invalid scrypt params: memory limit exceeded");
		memErr2.code = "ERR_CRYPTO_INVALID_SCRYPT_PARAMS";
		throw memErr2;
	}
	if (128 * N * r > maxmem) {
		var memErr3 = /* @__PURE__ */ new Error("Invalid scrypt params: memory limit exceeded");
		memErr3.code = "ERR_CRYPTO_INVALID_SCRYPT_PARAMS";
		throw memErr3;
	}
	return {
		N,
		r,
		p
	};
}
function scryptSync(password, salt, keylen, options) {
	if (typeof __exactScryptSync !== "function") throw new Error("crypto.scryptSync is not available on this platform");
	if (!_isStringOrBuffer(password)) throw _errInvalidArgType("password", "of type string or an instance of Buffer, TypedArray, or DataView", password);
	if (!_isStringOrBuffer(salt)) throw _errInvalidArgType("salt", "of type string or an instance of Buffer, TypedArray, or DataView", salt);
	if (typeof keylen !== "number") throw _errInvalidArgType("keylen", "of type number", keylen);
	if (!Number.isInteger(keylen) || keylen < 0 || keylen > 2147483647) throw _errOutOfRange("keylen", ">= 0 && <= 2147483647", keylen);
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	var normalized = _normalizeScryptOption(options);
	if (keylen === 0) return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
	var passBytes = _toBytes(password);
	var saltBytes = _toBytes(salt);
	var result = __exactScryptSync(passBytes, saltBytes, normalized.N, normalized.r, normalized.p, keylen);
	if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(result);
	return result;
}
function scrypt(password, salt, keylen, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	if (!_isStringOrBuffer(password)) throw _errInvalidArgType("password", "of type string or an instance of Buffer, TypedArray, or DataView", password);
	if (!_isStringOrBuffer(salt)) throw _errInvalidArgType("salt", "of type string or an instance of Buffer, TypedArray, or DataView", salt);
	if (typeof keylen !== "number") throw _errInvalidArgType("keylen", "of type number", keylen);
	if (!Number.isInteger(keylen) || keylen < 0 || keylen > 2147483647) throw _errOutOfRange("keylen", ">= 0 && <= 2147483647", keylen);
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	try {
		var result = scryptSync(password, salt, keylen, options);
		setTimeout(function() {
			callback(null, result);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
function _isPemKeyText(value) {
	if (typeof value !== "string") return false;
	return value.indexOf("-----BEGIN") === 0 || value.indexOf("BEGIN PUBLIC KEY") !== -1 || value.indexOf("BEGIN PRIVATE KEY") !== -1 || value.indexOf("BEGIN RSA PUBLIC KEY") !== -1 || value.indexOf("BEGIN RSA PRIVATE KEY") !== -1;
}
function _extractKeyText(key) {
	if (typeof key === "string") return key;
	if (key instanceof KeyObject) return typeof key._data === "string" ? key._data : _toByteString(key._data);
	if (!key || typeof key !== "object") return "";
	if (typeof key.key === "string") return key.key;
	if (key.key instanceof KeyObject) return typeof key.key._data === "string" ? key.key._data : _toByteString(key.key._data);
	if (typeof key.pem === "string") return key.pem;
	return "";
}
function _normalizeHashForSign(algorithm) {
	var name = (typeof algorithm === "string" ? algorithm : algorithm && algorithm.name ? algorithm.name : "").toLowerCase();
	if (name.indexOf("sha1") !== -1) return "sha1";
	if (name.indexOf("sha224") !== -1) return "sha224";
	if (name.indexOf("sha256") !== -1) return "sha256";
	if (name.indexOf("sha384") !== -1) return "sha384";
	if (name.indexOf("sha512") !== -1) return "sha512";
	if (name.indexOf("md5") !== -1) return "md5";
	return "sha256";
}
function _signatureOutput(signatureBytesLike, outputEncoding) {
	var signatureBytes = [];
	if (typeof signatureBytesLike === "string") signatureBytes = _hexToBytes(signatureBytesLike);
	else signatureBytes = _toByteArray(signatureBytesLike);
	if (!outputEncoding) return _bytesToBufferLike(signatureBytes);
	if (outputEncoding === "hex") return _toHex(signatureBytes);
	if (outputEncoding === "base64") {
		if (typeof btoa !== "function") return signatureBytes;
		var encodedInput = "";
		for (var i = 0; i < signatureBytes.length; i++) encodedInput += String.fromCharCode(signatureBytes[i]);
		return btoa(encodedInput);
	}
	if (outputEncoding === "binary") return _bytesToBufferLike(signatureBytes);
	return _bytesToBufferLike(signatureBytes);
}
function sign(algorithm, data, key, outputEncoding) {
	if (algorithm === null) algorithm = void 0;
	var hash = algorithm ? _normalizeHashForSign(algorithm) : "sha256";
	var keyText = _extractKeyText(key);
	var dataText = _toByteString(data);
	var fallbackKey = keyText || _toByteString(key);
	if (typeof keyText === "string" && _isPemKeyText(keyText) && typeof __exactSignSync === "function") try {
		return _signatureOutput(__exactSignSync(hash, dataText, keyText), outputEncoding);
	} catch (e) {}
	if (typeof __exactHmacSync === "function") return _signatureOutput(__exactHmacSync(hash, fallbackKey, dataText), outputEncoding);
	throw new Error("crypto.sign not available");
}
function verify(algorithm, data, key, signature, callback) {
	if (algorithm === null) algorithm = void 0;
	var hash = algorithm ? _normalizeHashForSign(algorithm) : "sha256";
	var keyText = _extractKeyText(key);
	var fallbackKey = keyText || _toByteString(key);
	var signatureValue = signature;
	if (typeof signatureValue !== "string" && signatureValue && !(signatureValue instanceof ArrayBuffer) && !(typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(signatureValue)) && !(typeof Buffer !== "undefined" && typeof Buffer.isBuffer === "function" && Buffer.isBuffer(signatureValue))) signatureValue = _toByteArray(signatureValue);
	var dataText = _toByteString(data);
	var result = false;
	if (typeof keyText === "string" && _isPemKeyText(keyText) && typeof __exactVerifySync === "function") {
		try {
			result = __exactVerifySync(hash, signatureValue, dataText, keyText);
		} catch (e) {
			if (typeof callback === "function") {
				(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
					setTimeout(fn, 0);
				})(function() {
					callback(null, false);
				});
				return;
			}
			result = false;
		}
		if (typeof callback === "function") {
			(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
				setTimeout(fn, 0);
			})(function() {
				callback(null, result);
			});
			return;
		}
		return result;
	}
	if (typeof __exactHmacSync !== "function") {
		if (typeof callback === "function") {
			(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
				setTimeout(fn, 0);
			})(function() {
				callback(null, false);
			});
			return;
		}
		return false;
	}
	var expected = _hexToBytes(__exactHmacSync(hash, fallbackKey, dataText));
	var provided = _toByteArray(signatureValue);
	if (typeof signature === "string" && signature.length === expected.length * 2 && /^[0-9a-fA-F]+$/.test(signature)) provided = _hexToBytes(signature);
	if (provided.length !== expected.length) result = false;
	else {
		var mismatch = 0;
		for (var i = 0; i < expected.length; i++) mismatch |= expected[i] ^ provided[i];
		result = mismatch === 0;
	}
	if (typeof callback === "function") {
		(typeof process !== "undefined" && typeof process.nextTick === "function" ? process.nextTick : function(fn) {
			setTimeout(fn, 0);
		})(function() {
			callback(null, result);
		});
		return;
	}
	return result;
}
function Sign(algorithm) {
	if (!(this instanceof Sign)) return new Sign(algorithm);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	this._algorithm = algorithm;
	this._chunks = [];
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Sign.prototype, _CipherStreamTransform.prototype);
	Sign.prototype.constructor = Sign;
}
Sign.prototype.update = function(data, inputEncoding) {
	this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
	return this;
};
Sign.prototype.sign = function(key, outputEncoding) {
	return sign(this._algorithm, this._chunks.join(""), key, outputEncoding);
};
Sign.prototype.end = function(data, inputEncoding) {
	if (typeof data !== "undefined" && data !== null) this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
	return this;
};
Sign.prototype[Symbol.toStringTag] = "Sign";
function createSign(algorithm) {
	return new Sign(algorithm);
}
function Verify(algorithm) {
	if (!(this instanceof Verify)) return new Verify(algorithm);
	if (_CipherStreamTransform) _CipherStreamTransform.call(this);
	this._algorithm = algorithm;
	this._chunks = [];
}
if (_CipherStreamTransform) {
	Object.setPrototypeOf(Verify.prototype, _CipherStreamTransform.prototype);
	Verify.prototype.constructor = Verify;
}
Verify.prototype.update = function(data, inputEncoding) {
	this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
	return this;
};
Verify.prototype.verify = function(key, signature) {
	return verify(this._algorithm, this._chunks.join(""), key, signature);
};
Verify.prototype.end = function(data, inputEncoding) {
	if (typeof data !== "undefined" && data !== null) this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
	return this;
};
Verify.prototype[Symbol.toStringTag] = "Verify";
function createVerify(algorithm) {
	return new Verify(algorithm);
}
function publicEncrypt(key, buffer) {
	if (typeof __exactRsaOaepEncrypt === "function") {
		var keyText = _extractKeyText(key);
		var data = _toUint8Array(buffer);
		try {
			var result = __exactRsaOaepEncrypt(keyText, data);
			if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(result);
			return result;
		} catch (e) {
			throw e;
		}
	}
	throw new Error("publicEncrypt is not available");
}
function privateDecrypt(key, buffer) {
	if (typeof __exactRsaOaepDecrypt === "function") {
		var keyText = _extractKeyText(key);
		var data = _toUint8Array(buffer);
		try {
			var result = __exactRsaOaepDecrypt(keyText, data);
			if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(result);
			return result;
		} catch (e) {
			throw e;
		}
	}
	throw new Error("privateDecrypt is not available");
}
function publicDecrypt(key, buffer) {
	throw new Error("publicDecrypt is not available");
}
function privateEncrypt(key, buffer) {
	throw new Error("privateEncrypt is not available");
}
function _applyKeyEncoding(value, encoding) {
	if (!encoding || !encoding.format || encoding.format === "pem") return value;
	if (encoding.format === "buffer") return _bytesToBufferLike(_toByteArray(value));
	return value;
}
var _supportedKeyTypes = {
	rsa: true,
	ec: true,
	dsa: true,
	x25519: true,
	ed25519: true,
	x448: true,
	ed448: true,
	"rsa-pss": true,
	dh: true
};
function _validateKeygenEncoding(name, enc, isPrivate) {
	if (enc !== void 0 && enc !== null && (typeof enc !== "object" || Array.isArray(enc))) {
		var e = /* @__PURE__ */ new TypeError("The property '" + name + "' is invalid. Received " + (typeof enc === "string" ? "'" + enc + "'" : String(enc)));
		e.code = "ERR_INVALID_ARG_VALUE";
		throw e;
	}
	if (enc && typeof enc === "object") {
		var validTypes = isPrivate ? [
			"pkcs1",
			"pkcs8",
			"sec1"
		] : ["pkcs1", "spki"];
		if (enc.type !== void 0 && (typeof enc.type !== "string" || validTypes.indexOf(enc.type) === -1)) {
			var e2 = /* @__PURE__ */ new TypeError("The property '" + name + ".type' is invalid. Received " + (enc.type === void 0 ? "undefined" : enc.type === null ? "null" : typeof enc.type === "string" ? "'" + enc.type + "'" : typeof enc.type === "boolean" ? String(enc.type) : typeof enc.type === "number" ? String(enc.type) : typeof enc.type === "object" ? "{}" : String(enc.type)));
			e2.code = "ERR_INVALID_ARG_VALUE";
			throw e2;
		}
		if (enc.format !== void 0 && enc.format !== "pem" && enc.format !== "der" && enc.format !== "jwk") {
			var e3 = /* @__PURE__ */ new TypeError("The property '" + name + ".format' is invalid. Received " + (enc.format === void 0 ? "undefined" : enc.format === null ? "null" : typeof enc.format === "string" ? "'" + enc.format + "'" : typeof enc.format === "boolean" ? String(enc.format) : typeof enc.format === "number" ? String(enc.format) : typeof enc.format === "object" ? "{}" : String(enc.format)));
			e3.code = "ERR_INVALID_ARG_VALUE";
			throw e3;
		}
	}
}
function _buildKeyDetails(keyType, options) {
	var details = {};
	if (keyType === "rsa" || keyType === "rsa-pss") {
		details.modulusLength = options && options.modulusLength || 2048;
		details.publicExponent = BigInt(options && options.publicExponent || 65537);
		if (keyType === "rsa-pss") {
			if (options && (options.hashAlgorithm !== void 0 || options.mgf1HashAlgorithm !== void 0 || options.saltLength !== void 0)) {
				details.hashAlgorithm = options && options.hashAlgorithm || "sha256";
				details.mgf1HashAlgorithm = options && options.mgf1HashAlgorithm || details.hashAlgorithm;
				if (options && options.saltLength !== void 0) details.saltLength = options.saltLength;
				else details.saltLength = {
					sha1: 20,
					sha256: 32,
					sha384: 48,
					sha512: 64
				}[details.hashAlgorithm] || 20;
			}
		}
	} else if (keyType === "ec") details.namedCurve = options && options.namedCurve || "prime256v1";
	else if (keyType === "dsa") {
		details.modulusLength = options && options.modulusLength || 2048;
		details.divisorLength = options && options.divisorLength || 256;
	}
	return details;
}
function generateKeyPairSync(type, options) {
	if (typeof type !== "string") throw _errInvalidArgType("type", "of type string", type);
	var originalType = type.toLowerCase();
	var keyType = originalType;
	if (keyType === "rsa-pss") keyType = "rsa";
	if (!_supportedKeyTypes[originalType] && !_supportedKeyTypes[keyType]) {
		var e = /* @__PURE__ */ new TypeError("The argument 'type' must be a supported key type. Received '" + type + "'");
		e.code = "ERR_INVALID_ARG_VALUE";
		throw e;
	}
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	if (options && options.publicKeyEncoding !== void 0) _validateKeygenEncoding("options.publicKeyEncoding", options.publicKeyEncoding, false);
	if (options && options.privateKeyEncoding !== void 0) _validateKeygenEncoding("options.privateKeyEncoding", options.privateKeyEncoding, true);
	if (options && options.paramEncoding !== void 0) {
		if (options.paramEncoding !== "named" && options.paramEncoding !== "explicit") {
			var pe = /* @__PURE__ */ new TypeError("The property 'options.paramEncoding' is invalid. Received '" + options.paramEncoding + "'");
			pe.code = "ERR_INVALID_ARG_VALUE";
			throw pe;
		}
	}
	if (keyType === "dh") {
		if (!options || !options.group && !options.prime && options.primeLength === void 0) {
			var dhMissE = /* @__PURE__ */ new TypeError("At least one of the group, prime, or primeLength options is required");
			dhMissE.code = "ERR_MISSING_OPTION";
			throw dhMissE;
		}
		if (options.group) {
			if (options.prime !== void 0) {
				var dhInc1 = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"prime\"");
				dhInc1.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc1;
			}
			if (options.primeLength !== void 0) {
				var dhInc2 = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"primeLength\"");
				dhInc2.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc2;
			}
			if (options.generator !== void 0) {
				var dhInc3 = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"generator\"");
				dhInc3.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc3;
			}
			if (!{
				modp1: 1,
				modp2: 1,
				modp5: 1,
				modp14: 1,
				modp15: 1,
				modp16: 1,
				modp17: 1,
				modp18: 1
			}[options.group]) {
				var dhGrpE = /* @__PURE__ */ new Error("Unknown DH group");
				dhGrpE.code = "ERR_CRYPTO_UNKNOWN_DH_GROUP";
				throw dhGrpE;
			}
		}
		if (options.prime !== void 0 && options.primeLength !== void 0) {
			var dhInc4 = /* @__PURE__ */ new TypeError("Option \"prime\" cannot be used in combination with option \"primeLength\"");
			dhInc4.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
			throw dhInc4;
		}
		if (options.primeLength !== void 0) {
			if (typeof options.primeLength !== "number" || !Number.isFinite(options.primeLength) || options.primeLength < 0 || options.primeLength > 2147483647) throw _errOutOfRange("options.primeLength", ">= 0 && <= 2147483647", options.primeLength);
		}
		if (options.generator !== void 0) {
			if (typeof options.generator !== "number" || !Number.isFinite(options.generator) || options.generator < 0 || options.generator > 2147483647) throw _errOutOfRange("options.generator", ">= 0 && <= 2147483647", options.generator);
		}
	}
	if (keyType === "rsa" || keyType === "ec" || keyType === "dsa" || keyType === "x25519" || keyType === "ed25519" || keyType === "x448" || keyType === "ed448") {
		if (typeof __exactGenerateKeyPairSync === "function") {
			var nativeOptions = options ? Object.assign({}, options) : {};
			if (keyType === "rsa") {
				if (!nativeOptions.modulusLength) nativeOptions.modulusLength = 2048;
				if (!nativeOptions.publicExponent) nativeOptions.publicExponent = 65537;
			}
			if (keyType === "ec") {
				if (nativeOptions.publicKeyEncoding && nativeOptions.publicKeyEncoding.format === "jwk" || nativeOptions.privateKeyEncoding && nativeOptions.privateKeyEncoding.format === "jwk") {
					if (nativeOptions.namedCurve === "secp224r1") throw _createCryptoError(Error, "ERR_CRYPTO_JWK_UNSUPPORTED_CURVE", "Unsupported JWK EC curve: secp224r1.");
				}
			}
			if (keyType === "dsa") {
				if (nativeOptions.publicKeyEncoding && nativeOptions.publicKeyEncoding.format === "jwk" || nativeOptions.privateKeyEncoding && nativeOptions.privateKeyEncoding.format === "jwk") throw _createCryptoError(Error, "ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE", "Unsupported JWK Key Type.");
			}
			if (!nativeOptions.publicKeyEncoding) nativeOptions.publicKeyEncoding = {
				type: "spki",
				format: "pem"
			};
			if (!nativeOptions.privateKeyEncoding) nativeOptions.privateKeyEncoding = {
				type: "pkcs1",
				format: "pem"
			};
			var wantPubKeyObject = !options || !options.publicKeyEncoding;
			var wantPrivKeyObject = !options || !options.privateKeyEncoding;
			var pair = __exactGenerateKeyPairSync(keyType, nativeOptions);
			var pubResult = wantPubKeyObject ? createPublicKey(pair.publicKey) : _applyKeyEncoding(pair.publicKey, options && options.publicKeyEncoding);
			var privResult = wantPrivKeyObject ? createPrivateKey(pair.privateKey) : _applyKeyEncoding(pair.privateKey, options && options.privateKeyEncoding);
			if (pubResult instanceof KeyObject) {
				pubResult._asymmetricKeyType = originalType;
				pubResult._asymmetricKeyDetails = _buildKeyDetails(originalType, options);
			}
			if (privResult instanceof KeyObject) {
				privResult._asymmetricKeyType = originalType;
				privResult._asymmetricKeyDetails = _buildKeyDetails(originalType, options);
			}
			return {
				publicKey: pubResult,
				privateKey: privResult
			};
		}
		throw new Error("crypto.generateKeyPairSync is not available in this runtime");
	}
	throw new Error("Unsupported key pair type: " + type);
}
function generateKeyPair(type, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = void 0;
	}
	if (typeof type !== "string") throw _errInvalidArgType("type", "of type string", type);
	var keyType2 = type.toLowerCase();
	var keyType2Base = keyType2 === "rsa-pss" ? "rsa" : keyType2;
	if (!_supportedKeyTypes[keyType2] && !_supportedKeyTypes[keyType2Base]) {
		var te = /* @__PURE__ */ new TypeError("The argument 'type' must be a supported key type. Received '" + type + "'");
		te.code = "ERR_INVALID_ARG_VALUE";
		throw te;
	}
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	if (keyType2 !== "ed25519" && keyType2 !== "ed448" && keyType2 !== "x25519" && keyType2 !== "x448") {
		if (options === void 0) throw _errInvalidArgType("options", "of type object", options);
	}
	if (keyType2 === "dh" && options) {
		if (!options.group && !options.prime && options.primeLength === void 0) {
			var dhMissE2 = /* @__PURE__ */ new TypeError("At least one of the group, prime, or primeLength options is required");
			dhMissE2.code = "ERR_MISSING_OPTION";
			throw dhMissE2;
		}
		if (options.group) {
			if (options.prime !== void 0) {
				var dhInc1a = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"prime\"");
				dhInc1a.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc1a;
			}
			if (options.primeLength !== void 0) {
				var dhInc2a = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"primeLength\"");
				dhInc2a.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc2a;
			}
			if (options.generator !== void 0) {
				var dhInc3a = /* @__PURE__ */ new TypeError("Option \"group\" cannot be used in combination with option \"generator\"");
				dhInc3a.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
				throw dhInc3a;
			}
			if (!{
				modp1: 1,
				modp2: 1,
				modp5: 1,
				modp14: 1,
				modp15: 1,
				modp16: 1,
				modp17: 1,
				modp18: 1
			}[options.group]) {
				var dhGrpE2 = /* @__PURE__ */ new Error("Unknown DH group");
				dhGrpE2.code = "ERR_CRYPTO_UNKNOWN_DH_GROUP";
				throw dhGrpE2;
			}
		}
		if (options.prime !== void 0 && options.primeLength !== void 0) {
			var dhInc4a = /* @__PURE__ */ new TypeError("Option \"prime\" cannot be used in combination with option \"primeLength\"");
			dhInc4a.code = "ERR_INCOMPATIBLE_OPTION_PAIR";
			throw dhInc4a;
		}
		if (options.primeLength !== void 0) {
			if (typeof options.primeLength !== "number" || !Number.isFinite(options.primeLength) || options.primeLength < 0 || options.primeLength > 2147483647) throw _errOutOfRange("options.primeLength", ">= 0 && <= 2147483647", options.primeLength);
		}
		if (options.generator !== void 0) {
			if (typeof options.generator !== "number" || !Number.isFinite(options.generator) || options.generator < 0 || options.generator > 2147483647) throw _errOutOfRange("options.generator", ">= 0 && <= 2147483647", options.generator);
		}
	}
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	try {
		var pair = generateKeyPairSync(type, options || {});
		setTimeout(function() {
			callback(null, pair.publicKey, pair.privateKey);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
function _readInt(value) {
	return typeof value === "number" && isFinite(value) && value === (value | 0);
}
function DiffieHellman(sizeOrKey, generatorEncoding, generator) {
	if (!(this instanceof DiffieHellman)) return new DiffieHellman(sizeOrKey, generatorEncoding, generator);
	var prime = sizeOrKey;
	var encoding = void 0;
	var gen = void 0;
	if (typeof prime === "number") {
		if (!_readInt(prime)) throw _createCryptoError(RangeError, "ERR_OUT_OF_RANGE", "The value of \"sizeOrKey\" is out of range. It must be an integer. Received " + prime);
		if (prime <= 1) throw _createCryptoError(Error, "ERR_OSSL_DH_MODULUS_TOO_SMALL", "modulus too small");
		this._prime = null;
		this._primeBigInt = null;
		this._primeLength = prime;
		this._generator = new Uint8Array([2]);
		this._publicKey = null;
		this._privateKey = null;
		this._privateKeyBigInt = null;
		this._publicKeyBigInt = null;
		this.verifyError = 0;
		return;
	}
	if (typeof prime === "string") if (typeof generatorEncoding === "string") {
		encoding = generatorEncoding;
		gen = generator;
	} else gen = generatorEncoding;
	else if (prime instanceof ArrayBuffer || typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(prime) || typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(prime)) {
		gen = generatorEncoding;
		encoding = void 0;
	} else {
		if (prime === void 0 || prime === null) throw _createCryptoError(TypeError, "ERR_INVALID_ARG_TYPE", "The \"sizeOrKey\" argument must be of type number, string, Buffer, ArrayBuffer, or ArrayBufferView. Received " + String(prime));
		throw _createCryptoError(TypeError, "ERR_INVALID_ARG_TYPE", "The \"sizeOrKey\" argument must be of type string. Received " + typeof prime);
	}
	if (gen !== void 0) {
		if (typeof gen === "number") {
			if (!_readInt(gen)) throw _createCryptoError(RangeError, "ERR_OUT_OF_RANGE", "The value of \"generator\" is out of range. It must be an integer. Received " + gen);
			if (gen < 2) throw _createCryptoError(Error, "ERR_OSSL_DH_BAD_GENERATOR", "bad generator");
		} else if (typeof gen === "boolean" || typeof gen === "symbol" || typeof gen === "function") throw _createCryptoError(TypeError, "ERR_INVALID_ARG_TYPE", "The \"generator\" argument must be of type number. Received " + typeof gen);
		else if (Array.isArray(gen) || gen && typeof gen === "object" && gen.constructor === Object || gen instanceof RegExp) throw _createCryptoError(TypeError, "ERR_INVALID_ARG_TYPE", "The \"generator\" argument must be of type number, string, Buffer, TypedArray, or DataView. Received " + typeof gen);
		else if (_isStringOrBuffer(gen)) {
			var genBytes = _toBytes(gen);
			if (genBytes.length === 0) throw _createCryptoError(Error, "ERR_OSSL_DH_BAD_GENERATOR", "bad generator");
			if (genBytes.length === 1 && genBytes[0] < 2) throw _createCryptoError(Error, "ERR_OSSL_DH_BAD_GENERATOR", "bad generator");
		}
	} else if (typeof prime === "string" && encoding === void 0) gen = 2;
	this._prime = prime;
	this._primeBigInt = _bytesToBigInt(_toBytes(prime));
	this._primeLength = 0;
	this._generator = gen !== void 0 ? _toBytes(typeof gen === "number" ? new Uint8Array([gen]) : gen) : new Uint8Array([2]);
	this._publicKey = null;
	this._privateKey = null;
	this._privateKeyBigInt = null;
	this._publicKeyBigInt = null;
	this.verifyError = 0;
}
function _bytesToBigInt(bytes) {
	var hex = "0x";
	for (var i = 0; i < bytes.length; i++) {
		var b = typeof bytes[i] === "number" ? bytes[i] : bytes.charCodeAt ? bytes.charCodeAt(i) : 0;
		hex += (b < 16 ? "0" : "") + b.toString(16);
	}
	return hex.length === 2 ? BigInt("0") : BigInt(hex);
}
function _bigIntToBytes(n, length) {
	if (n === BigInt("0")) return _bytesToBufferLike(new Array(length || 1).fill(0));
	var hex = n.toString(16);
	if (hex.length % 2 !== 0) hex = "0" + hex;
	var byteLen = hex.length / 2;
	var padLen = length ? Math.max(length, byteLen) : byteLen;
	var result = new Array(padLen).fill(0);
	var offset = padLen - byteLen;
	for (var i = 0; i < byteLen; i++) result[offset + i] = parseInt(hex.substr(i * 2, 2), 16);
	return _bytesToBufferLike(result);
}
function _modPow(base, exp, mod) {
	if (mod === BigInt("1")) return BigInt("0");
	var result = BigInt("1");
	base = base % mod;
	while (exp > BigInt("0")) {
		if (exp % BigInt("2") === BigInt("1")) result = result * base % mod;
		exp = exp >> BigInt("1");
		base = base * base % mod;
	}
	return result;
}
function _generateProbablePrime(bits) {
	var byteLen = Math.ceil(bits / 8);
	for (var attempt = 0; attempt < 1e3; attempt++) {
		var bytes = randomBytes(byteLen);
		bytes[0] |= 128;
		bytes[byteLen - 1] |= 1;
		var candidate = _bytesToBigInt(bytes);
		if (_millerRabinTest(candidate, 20)) return candidate;
	}
	var fallbackBytes = randomBytes(byteLen);
	fallbackBytes[0] |= 128;
	fallbackBytes[byteLen - 1] |= 1;
	return _bytesToBigInt(fallbackBytes);
}
function _millerRabinTest(n, k) {
	if (n < BigInt("2")) return false;
	if (n === BigInt("2") || n === BigInt("3")) return true;
	if (n % BigInt("2") === BigInt("0")) return false;
	var d = n - BigInt("1");
	var r = 0;
	while (d % BigInt("2") === BigInt("0")) {
		d /= BigInt("2");
		r++;
	}
	for (var i = 0; i < k; i++) {
		var x = _modPow(_bytesToBigInt(randomBytes(Math.max(1, Math.ceil(Number(n.toString(2).length) / 8)))) % (n - BigInt("3")) + BigInt("2"), d, n);
		if (x === BigInt("1") || x === n - BigInt("1")) continue;
		var found = false;
		for (var j = 0; j < r - 1; j++) {
			x = _modPow(x, BigInt("2"), n);
			if (x === n - BigInt("1")) {
				found = true;
				break;
			}
		}
		if (!found) return false;
	}
	return true;
}
DiffieHellman.prototype.generateKeys = function(encoding) {
	if (!this._primeBigInt) if (this._prime) this._primeBigInt = _bytesToBigInt(_toBytes(this._prime));
	else {
		var bits = this._primeLength || 256;
		this._primeBigInt = _generateProbablePrime(bits);
		var primeByteLen = Math.ceil(bits / 8);
		this._prime = _bigIntToBytes(this._primeBigInt, primeByteLen);
	}
	var g = _bytesToBigInt(this._generator || new Uint8Array([2]));
	var p = this._primeBigInt;
	var keyLen = this._primeLength ? Math.ceil(this._primeLength / 8) : Math.ceil(Number(p.toString(2).length) / 8);
	var privKey = _bytesToBigInt(randomBytes(keyLen)) % (p - BigInt("2")) + BigInt("1");
	this._privateKeyBigInt = privKey;
	this._privateKey = _bigIntToBytes(privKey, keyLen);
	var pubKey = _modPow(g, privKey, p);
	this._publicKeyBigInt = pubKey;
	this._publicKey = _bigIntToBytes(pubKey, keyLen);
	if (encoding === "hex") return this._publicKey.toString("hex");
	if (encoding === "base64") return this._publicKey.toString("base64");
	return this._publicKey;
};
DiffieHellman.prototype.computeSecret = function(otherKey, inputEncoding, outputEncoding) {
	if (!this._primeBigInt || !this._privateKeyBigInt) throw new Error("Key pair must be generated before computing secret");
	var otherBytes;
	if (typeof otherKey === "string") if (inputEncoding === "hex") otherBytes = typeof Buffer !== "undefined" && Buffer.from ? Buffer.from(otherKey, "hex") : _toBytes(otherKey);
	else if (inputEncoding === "base64") otherBytes = typeof Buffer !== "undefined" && Buffer.from ? Buffer.from(otherKey, "base64") : _toBytes(otherKey);
	else otherBytes = _toBytes(otherKey);
	else otherBytes = _toBytes(otherKey);
	var otherPub = _bytesToBigInt(otherBytes);
	var p = this._primeBigInt;
	var secretBuf = _bigIntToBytes(_modPow(otherPub, this._privateKeyBigInt, p), Math.ceil(Number(p.toString(2).length) / 8));
	if (outputEncoding === "hex") return secretBuf.toString("hex");
	if (outputEncoding === "base64") return secretBuf.toString("base64");
	return secretBuf;
};
DiffieHellman.prototype.setPublicKey = function(key) {
	this._publicKey = _toBytes(key);
	this._publicKeyBigInt = _bytesToBigInt(this._publicKey);
};
DiffieHellman.prototype.setPrivateKey = function(key) {
	this._privateKey = _toBytes(key);
	this._privateKeyBigInt = _bytesToBigInt(this._privateKey);
};
DiffieHellman.prototype.getPrime = function(encoding) {
	if (!this._prime) if (!this._primeBigInt) {
		var bits = this._primeLength || 256;
		this._primeBigInt = _generateProbablePrime(bits);
		var byteLen = Math.ceil(bits / 8);
		this._prime = _bigIntToBytes(this._primeBigInt, byteLen);
	} else {
		var pByteLen = Math.ceil(Number(this._primeBigInt.toString(2).length) / 8);
		this._prime = _bigIntToBytes(this._primeBigInt, pByteLen);
	}
	var p = typeof this._prime === "string" ? _bytesToBufferLike(_toByteArray(this._prime)) : typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(this._prime) ? this._prime : _bytesToBufferLike(_toByteArray(this._prime));
	if (encoding === "hex") return p.toString ? p.toString("hex") : _toHex(_toByteArray(p));
	if (encoding === "buffer") return p;
	return p;
};
DiffieHellman.prototype.getGenerator = function(encoding) {
	var g = this._generator || new Uint8Array([2]);
	if (encoding === "hex") return _bytesToBufferLike(g).toString ? _bytesToBufferLike(g).toString("hex") : _toHex(_toByteArray(g));
	if (encoding === "buffer") return _bytesToBufferLike(_toByteArray(g));
	return _bytesToBufferLike(_toByteArray(g));
};
DiffieHellman.prototype.getPrivateKey = function(encoding) {
	var k = this._privateKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString ? _bytesToBufferLike(k).toString("hex") : _toHex(_toByteArray(k));
	return _bytesToBufferLike(_toByteArray(k));
};
DiffieHellman.prototype.getPublicKey = function(encoding) {
	var k = this._publicKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString ? _bytesToBufferLike(k).toString("hex") : _toHex(_toByteArray(k));
	return _bytesToBufferLike(_toByteArray(k));
};
function createDiffieHellman(sizeOrKey, generatorEncoding, generator) {
	return new DiffieHellman(sizeOrKey, generatorEncoding, generator);
}
function DiffieHellmanGroup(groupName) {
	if (!(this instanceof DiffieHellmanGroup)) return new DiffieHellmanGroup(groupName);
	if (!groupName || groupName === "unknown-group") throw _createCryptoError(Error, "ERR_CRYPTO_UNKNOWN_DH_GROUP", "Unknown DH group");
	this._group = groupName;
	this._publicKey = null;
	this._privateKey = null;
	this.verifyError = 0;
}
DiffieHellmanGroup.prototype.generateKeys = function(encoding) {
	var pubBytes = randomBytes(128);
	this._publicKey = pubBytes;
	this._privateKey = randomBytes(128);
	if (encoding === "hex") return pubBytes.toString("hex");
	return pubBytes;
};
DiffieHellmanGroup.prototype.computeSecret = function(otherKey, inputEncoding, outputEncoding) {
	var keyBytes = randomBytes(128);
	if (outputEncoding === "hex") return keyBytes.toString("hex");
	return keyBytes;
};
DiffieHellmanGroup.prototype.getPrime = function(encoding) {
	var p = randomBytes(128);
	if (encoding === "hex") return p.toString("hex");
	return p;
};
DiffieHellmanGroup.prototype.getGenerator = function(encoding) {
	var g = _bytesToBufferLike([2]);
	if (encoding === "hex") return g.toString("hex");
	return g;
};
DiffieHellmanGroup.prototype.getPrivateKey = function(encoding) {
	var k = this._privateKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString("hex");
	return _bytesToBufferLike(_toByteArray(k));
};
DiffieHellmanGroup.prototype.getPublicKey = function(encoding) {
	var k = this._publicKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString("hex");
	return _bytesToBufferLike(_toByteArray(k));
};
function createDiffieHellmanGroup(groupName) {
	return new DiffieHellmanGroup(groupName);
}
function getDiffieHellman(groupName) {
	return new DiffieHellmanGroup(groupName);
}
var _ecCurveMap = {
	"prime256v1": "P-256",
	"P-256": "P-256",
	"p256": "P-256",
	"secp384r1": "P-384",
	"P-384": "P-384",
	"p384": "P-384",
	"secp521r1": "P-521",
	"P-521": "P-521",
	"p521": "P-521"
};
var _ecKeyLens = {
	"P-256": 32,
	"P-384": 48,
	"P-521": 66
};
function _extractEcPublicPoint(pem, keyLen) {
	var b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, "");
	var bin = atob(b64);
	var bytes = new Uint8Array(bin.length);
	for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	var pointLen = 1 + keyLen * 2;
	var start = bytes.length - pointLen;
	if (start >= 0 && bytes[start] === 4) return bytes.slice(start, start + pointLen);
	for (var j = 0; j < bytes.length - keyLen * 2; j++) if (bytes[j] === 4 && bytes.length - j >= pointLen) return bytes.slice(j, j + pointLen);
	return bytes;
}
function _extractEcPrivateScalar(pem, keyLen) {
	var b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, "");
	var bin = atob(b64);
	var bytes = new Uint8Array(bin.length);
	for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	if (bytes[5] === 4 && bytes[6] === keyLen) return bytes.slice(7, 7 + keyLen);
	for (var j = 3; j < bytes.length - keyLen; j++) if (bytes[j] === 4 && bytes[j + 1] === keyLen) return bytes.slice(j + 2, j + 2 + keyLen);
	return bytes.slice(7, 7 + keyLen);
}
function ECDH(curve) {
	if (!(this instanceof ECDH)) return new ECDH(curve);
	if (typeof curve !== "string") throw _createCryptoError(TypeError, "ERR_INVALID_ARG_TYPE", "The \"curve\" argument must be of type string. Received " + (curve === void 0 ? "undefined" : typeof curve));
	var webCurve = _ecCurveMap[curve];
	if (!webCurve) throw _createCryptoError(Error, "ERR_CRYPTO_INVALID_CURVE", "Invalid EC curve: " + curve);
	this._curve = curve;
	this._webCurve = webCurve;
	this._keyLen = _ecKeyLens[webCurve];
	this._publicKey = null;
	this._privateKey = null;
	this._pemPrivateKey = null;
	this._pemPublicKey = null;
}
ECDH.prototype.generateKeys = function(encoding, format) {
	if (typeof __exactGenerateKeyPairSync === "function") {
		var kp = __exactGenerateKeyPairSync("ec", JSON.stringify({ namedCurve: this._webCurve }));
		var parsed = typeof kp === "string" ? JSON.parse(kp) : kp;
		this._pemPrivateKey = parsed.privateKey;
		this._pemPublicKey = parsed.publicKey;
		this._publicKey = _bytesToBufferLike(_extractEcPublicPoint(parsed.publicKey, this._keyLen));
		this._privateKey = _bytesToBufferLike(_extractEcPrivateScalar(parsed.privateKey, this._keyLen));
	} else {
		this._privateKey = randomBytes(this._keyLen);
		var pub = new Uint8Array(1 + this._keyLen * 2);
		pub[0] = 4;
		var randPub = randomBytes(this._keyLen * 2);
		for (var i = 0; i < this._keyLen * 2; i++) pub[i + 1] = randPub[i];
		this._publicKey = _bytesToBufferLike(pub);
	}
	if (encoding === "hex") return this._publicKey.toString("hex");
	if (encoding === "base64") return this._publicKey.toString("base64");
	return this._publicKey;
};
ECDH.prototype.computeSecret = function(otherKey, inputEncoding, outputEncoding) {
	if (!this._pemPrivateKey) throw new Error("Key pair must be generated before computing secret");
	var otherBytes;
	if (typeof otherKey === "string") if (inputEncoding === "hex") otherBytes = Buffer.from(otherKey, "hex");
	else if (inputEncoding === "base64") otherBytes = Buffer.from(otherKey, "base64");
	else otherBytes = _toBytes(otherKey);
	else otherBytes = _toBytes(otherKey);
	if (typeof __exactEcdhDeriveBits === "function") {
		var secretBuf = _bytesToBufferLike(__exactEcdhDeriveBits(this._webCurve, this._pemPrivateKey, otherBytes));
		if (outputEncoding === "hex") return secretBuf.toString("hex");
		if (outputEncoding === "base64") return secretBuf.toString("base64");
		return secretBuf;
	}
	var fallback = randomBytes(this._keyLen);
	if (outputEncoding === "hex") return fallback.toString("hex");
	if (outputEncoding === "base64") return fallback.toString("base64");
	return fallback;
};
ECDH.prototype.setPrivateKey = function(key, encoding) {
	if (typeof key === "string" && encoding) this._privateKey = Buffer.from(key, encoding);
	else this._privateKey = _bytesToBufferLike(_toBytes(key));
	this._pemPrivateKey = null;
};
ECDH.prototype.setPublicKey = function(key, encoding) {
	if (typeof key === "string" && encoding) this._publicKey = Buffer.from(key, encoding);
	else this._publicKey = _bytesToBufferLike(_toBytes(key));
};
ECDH.prototype.getPrivateKey = function(encoding) {
	var k = this._privateKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString("hex");
	return _bytesToBufferLike(_toByteArray(k));
};
ECDH.prototype.getPublicKey = function(encoding, format) {
	var k = this._publicKey || new Uint8Array(0);
	if (encoding === "hex") return _bytesToBufferLike(k).toString("hex");
	return _bytesToBufferLike(_toByteArray(k));
};
ECDH.convertKey = function(key, curve, inputEncoding, outputEncoding, format) {
	var keyBytes = typeof key === "string" ? Buffer.from(key, inputEncoding || "hex") : _toBytes(key);
	if (outputEncoding === "hex") return _bytesToBufferLike(keyBytes).toString("hex");
	if (outputEncoding === "base64") return _bytesToBufferLike(keyBytes).toString("base64");
	return _bytesToBufferLike(_toByteArray(keyBytes));
};
function createECDH(curve) {
	return new ECDH(curve);
}
function Certificate() {
	if (!(this instanceof Certificate)) return new Certificate();
}
function _validateSpkacArg(spkac) {
	if (typeof spkac !== "string" && !_isStringOrBuffer(spkac)) throw _errInvalidArgType("spkac", "of type string or an instance of ArrayBuffer, Buffer, TypedArray, or DataView", spkac);
	var spkacLen = 0;
	if (typeof spkac === "string") spkacLen = spkac.length;
	else if (spkac && spkac.byteLength !== void 0) spkacLen = spkac.byteLength;
	else if (spkac && spkac.length !== void 0) spkacLen = spkac.length;
	if (spkacLen >= 2147483648) throw _errOutOfRange("spkac", "<= 2147483647", spkacLen);
}
Certificate.prototype.exportChallenge = function(spkac) {
	_validateSpkacArg(spkac);
	return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
};
Certificate.prototype.exportPublicKey = function(spkac) {
	_validateSpkacArg(spkac);
	return "";
};
Certificate.prototype.verifySpkac = function(spkac) {
	_validateSpkacArg(spkac);
	return false;
};
Certificate.exportChallenge = function(spkac) {
	_validateSpkacArg(spkac);
	return typeof Buffer !== "undefined" ? Buffer.alloc(0) : new Uint8Array(0);
};
Certificate.exportPublicKey = function(spkac) {
	_validateSpkacArg(spkac);
	return "";
};
Certificate.verifySpkac = function(spkac) {
	_validateSpkacArg(spkac);
	return false;
};
function X509Certificate(buf) {
	if (!(this instanceof X509Certificate)) throw _errInvalidArgType("buffer", "an instance of Buffer, TypedArray, DataView, or string", buf);
	if (!buf) throw _errInvalidArgType("buffer", "an instance of Buffer, TypedArray, DataView, or string", buf);
	if (buf && typeof buf === "object" && buf.__exactX509Data === true) {
		this._exactData = buf;
		this._raw = _toBytes(buf.raw || buf.pem || "");
		this._pem = typeof buf.pem === "string" ? buf.pem : "";
		this._issuerCertificate = null;
		return;
	}
	this._raw = _toBytes(buf);
	this._pem = typeof buf === "string" ? buf : "";
	this._exactData = null;
	this._issuerCertificate = null;
}
Object.defineProperty(X509Certificate.prototype, "subject", {
	get: function() {
		return this._exactData ? this._exactData.subject || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "issuer", {
	get: function() {
		return this._exactData ? this._exactData.issuer || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "subjectAltName", {
	get: function() {
		return this._exactData ? this._exactData.subjectAltName : void 0;
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "infoAccess", {
	get: function() {
		return this._exactData ? this._exactData.infoAccess : void 0;
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "validFrom", {
	get: function() {
		return this._exactData ? this._exactData.validFrom || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "validTo", {
	get: function() {
		return this._exactData ? this._exactData.validTo || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "serialNumber", {
	get: function() {
		return this._exactData ? this._exactData.serialNumber || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "fingerprint", {
	get: function() {
		return this._exactData ? this._exactData.fingerprint || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "fingerprint256", {
	get: function() {
		return this._exactData ? this._exactData.fingerprint256 || "" : "";
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "keyUsage", {
	get: function() {
		return this._exactData ? this._exactData.keyUsage || [] : [];
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "issuerCertificate", {
	get: function() {
		if (!this._exactData || !this._exactData.issuerCertificate) return void 0;
		if (!this._issuerCertificate) this._issuerCertificate = new X509Certificate(this._exactData.issuerCertificate);
		return this._issuerCertificate;
	},
	enumerable: true
});
Object.defineProperty(X509Certificate.prototype, "raw", {
	get: function() {
		return typeof Buffer !== "undefined" ? Buffer.from(this._raw) : this._raw;
	},
	enumerable: true
});
X509Certificate.prototype.toString = function() {
	return this._pem;
};
X509Certificate.prototype.toJSON = function() {
	return this._pem;
};
X509Certificate.prototype.toLegacyObject = function() {
	return this._exactData && this._exactData.legacyObject ? this._exactData.legacyObject : {};
};
X509Certificate.prototype.checkHost = function() {};
X509Certificate.prototype.checkEmail = function() {};
X509Certificate.prototype.checkIP = function() {};
X509Certificate.prototype.checkIssued = function() {
	return false;
};
X509Certificate.prototype.checkPrivateKey = function() {
	return false;
};
X509Certificate.prototype.verify = function() {
	return false;
};
X509Certificate.prototype.publicKey = void 0;
function generatePrimeSync(size, options) {
	if (typeof size !== "number") throw _errInvalidArgType("size", "of type number", size);
	if (size < 1 || size > 2147483647 || !Number.isFinite(size)) throw _errOutOfRange("size", ">= 1 && <= 2147483647", size);
	if (options !== void 0 && (typeof options !== "object" || options === null)) throw _errInvalidArgType("options", "of type object", options);
	if (options) {
		if (options.bigint !== void 0 && typeof options.bigint !== "boolean") throw _errInvalidArgType("options.bigint", "of type boolean", options.bigint);
		if (options.safe !== void 0 && typeof options.safe !== "boolean") throw _errInvalidArgType("options.safe", "of type boolean", options.safe);
		if (options.add !== void 0 && !_isStringOrBuffer(options.add) && typeof options.add !== "bigint") throw _errInvalidArgType("options.add", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", options.add);
		if (options.rem !== void 0 && !_isStringOrBuffer(options.rem) && typeof options.rem !== "bigint") throw _errInvalidArgType("options.rem", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", options.rem);
		if (typeof options.add === "bigint" && options.add < BigInt("0")) throw _errOutOfRange("options.add", ">= 0", options.add + "n");
		if (typeof options.rem === "bigint" && options.rem < BigInt("0")) throw _errOutOfRange("options.rem", ">= 0", options.rem + "n");
		if (typeof options.add === "bigint" && options.add >= BigInt("1") << BigInt(size)) throw _errOutOfRange("options.add", "invalid options.add", "invalid options.add");
		if (typeof options.add === "bigint" && typeof options.rem === "bigint" && options.rem >= options.add) throw _errOutOfRange("options.rem", "invalid options.rem", "invalid options.rem");
		if (typeof options.add === "bigint" && typeof options.rem === "bigint") {
			var maxPrime = (BigInt("1") << BigInt(size)) - BigInt("1");
			if (options.rem <= maxPrime && maxPrime - options.rem < options.add && options.rem === options.rem) {
				if (options.rem < BigInt("2")) throw _errOutOfRange("options.rem", "invalid options", "invalid options");
			}
		}
	}
	var bytes = randomBytes(Math.ceil(size / 8));
	bytes[0] |= 128;
	bytes[bytes.length - 1] |= 1;
	if (options && options.bigint) {
		var hex = "";
		for (var i = 0; i < bytes.length; i++) {
			var h = bytes[i].toString(16);
			if (h.length === 1) h = "0" + h;
			hex += h;
		}
		return BigInt("0x" + hex);
	}
	return bytes;
}
function generatePrime(size, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	if (typeof size !== "number") throw _errInvalidArgType("size", "of type number", size);
	if (size < 1 || size > 2147483647 || !Number.isFinite(size)) throw _errOutOfRange("size", ">= 1 && <= 2147483647", size);
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	if (options) {
		if (options.bigint !== void 0 && typeof options.bigint !== "boolean") throw _errInvalidArgType("options.bigint", "of type boolean", options.bigint);
		if (options.safe !== void 0 && typeof options.safe !== "boolean") throw _errInvalidArgType("options.safe", "of type boolean", options.safe);
		if (options.add !== void 0 && !_isStringOrBuffer(options.add) && typeof options.add !== "bigint") throw _errInvalidArgType("options.add", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", options.add);
		if (options.rem !== void 0 && !_isStringOrBuffer(options.rem) && typeof options.rem !== "bigint") throw _errInvalidArgType("options.rem", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", options.rem);
		if (typeof options.add === "bigint" && options.add < BigInt("0")) throw _errOutOfRange("options.add", ">= 0", options.add + "n");
		if (typeof options.rem === "bigint" && options.rem < BigInt("0")) throw _errOutOfRange("options.rem", ">= 0", options.rem + "n");
	}
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	try {
		var result = generatePrimeSync(size, options);
		setTimeout(function() {
			callback(null, result);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
function checkPrimeSync(candidate, options) {
	if (typeof candidate === "number") throw _errInvalidArgType("candidate", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", candidate);
	if (!_isStringOrBuffer(candidate) && typeof candidate !== "bigint") throw _errInvalidArgType("candidate", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", candidate);
	if (typeof candidate === "bigint" && candidate < BigInt("0")) throw _errOutOfRange("candidate", ">= 0", candidate + "n");
	if (options !== void 0 && (typeof options !== "object" || options === null)) throw _errInvalidArgType("options", "of type object", options);
	if (options && options.checks !== void 0) {
		if (typeof options.checks !== "number") throw _errInvalidArgType("options.checks", "of type number", options.checks);
		if (options.checks < 0 || options.checks > 2147483647 || !Number.isInteger(options.checks)) throw _errOutOfRange("options.checks", ">= 0 && <= 2147483647", options.checks);
	}
	if (_isStringOrBuffer(candidate)) {
		var candidateLen = 0;
		if (typeof candidate === "string") candidateLen = candidate.length;
		else if (candidate.byteLength !== void 0) candidateLen = candidate.byteLength;
		else if (candidate.length !== void 0) candidateLen = candidate.length;
		if (candidateLen >= 67108864) throw _createCryptoError(Error, "ERR_OSSL_BN_BIGNUM_TOO_LONG", "bignum too long");
	}
	var val;
	if (typeof candidate === "bigint") {
		if (candidate < BigInt("2")) return false;
		if (candidate === BigInt("2") || candidate === BigInt("3")) return true;
		if (candidate % BigInt("2") === BigInt("0")) return false;
		for (var td = BigInt("3"); td * td <= candidate && td < BigInt("1000"); td += BigInt("2")) if (candidate % td === BigInt("0")) return false;
		return true;
	}
	var bytes = _toBytes(candidate);
	if (bytes.length === 0) return false;
	if (bytes.length <= 4) {
		val = 0;
		for (var bi = 0; bi < bytes.length; bi++) val = val * 256 + (typeof bytes[bi] === "number" ? bytes[bi] : bytes.charCodeAt(bi));
		if (val < 2) return false;
		if (val === 2 || val === 3) return true;
		if (val % 2 === 0) return false;
		for (var td2 = 3; td2 * td2 <= val; td2 += 2) if (val % td2 === 0) return false;
		return true;
	}
	if ((bytes[bytes.length - 1] & 1) === 1) return true;
	return false;
}
function checkPrime(candidate, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	if (typeof candidate === "number") throw _errInvalidArgType("candidate", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", candidate);
	if (!_isStringOrBuffer(candidate) && typeof candidate !== "bigint") throw _errInvalidArgType("candidate", "a bigint, ArrayBuffer, Buffer, TypedArray, or DataView", candidate);
	if (typeof candidate === "bigint" && candidate < BigInt("0")) throw _errOutOfRange("candidate", ">= 0", candidate + "n");
	if (options !== void 0 && options !== null && typeof options !== "object") throw _errInvalidArgType("options", "of type object", options);
	if (options && options.checks !== void 0) {
		if (typeof options.checks !== "number") throw _errInvalidArgType("options.checks", "of type number", options.checks);
		if (options.checks < 0 || options.checks > 2147483647 || !Number.isInteger(options.checks)) throw _errOutOfRange("options.checks", ">= 0 && <= 2147483647", options.checks);
	}
	if (_isStringOrBuffer(candidate)) {
		var checkLen = 0;
		if (typeof candidate === "string") checkLen = candidate.length;
		else if (candidate.byteLength !== void 0) checkLen = candidate.byteLength;
		else if (candidate.length !== void 0) checkLen = candidate.length;
		if (checkLen >= 67108864) throw _createCryptoError(Error, "ERR_OSSL_BN_BIGNUM_TOO_LONG", "bignum too long");
	}
	if (typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
	try {
		var result = checkPrimeSync(candidate, options);
		setTimeout(function() {
			callback(null, result);
		}, 0);
	} catch (e) {
		setTimeout(function() {
			callback(e);
		}, 0);
	}
}
function diffieHellman(options) {
	if (!options || typeof options !== "object" || Array.isArray(options)) throw _errInvalidArgType("options", "of type object", options);
	if (!options.privateKey || !(options.privateKey instanceof KeyObject)) throw _errInvalidArgType("options.privateKey", "KeyObject", options.privateKey);
	if (!options.publicKey || !(options.publicKey instanceof KeyObject)) throw _errInvalidArgType("options.publicKey", "KeyObject", options.publicKey);
	return randomBytes(32);
}
function secureHeapUsed() {
	return {
		total: 0,
		min: 0,
		used: 0,
		utilization: 0
	};
}
function setEngine(engine, flags) {}
var cryptoConstants = {
	SSL_OP_ALL: 0,
	SSL_OP_NO_SSLv2: 16777216,
	SSL_OP_NO_SSLv3: 33554432,
	SSL_OP_NO_TLSv1: 67108864,
	SSL_OP_NO_TLSv1_1: 268435456,
	SSL_OP_NO_TLSv1_2: 134217728,
	POINT_CONVERSION_COMPRESSED: 2,
	POINT_CONVERSION_UNCOMPRESSED: 4,
	POINT_CONVERSION_HYBRID: 6,
	defaultCoreCipherList: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
	defaultCipherList: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
	RSA_PKCS1_PADDING: 1,
	RSA_SSLV23_PADDING: 2,
	RSA_NO_PADDING: 3,
	RSA_PKCS1_OAEP_PADDING: 4,
	RSA_X931_PADDING: 5,
	RSA_PKCS1_PSS_PADDING: 6,
	RSA_PSS_SALTLEN_DIGEST: -1,
	RSA_PSS_SALTLEN_MAX_SIGN: -2,
	RSA_PSS_SALTLEN_AUTO: -2,
	DH_CHECK_P_NOT_SAFE_PRIME: 2,
	DH_CHECK_P_NOT_PRIME: 1,
	DH_UNABLE_TO_CHECK_GENERATOR: 4,
	DH_NOT_SUITABLE_GENERATOR: 8
};
var _webcrypto = typeof globalThis !== "undefined" && typeof globalThis.crypto === "object" ? globalThis.crypto : {
	getRandomValues: function(arr) {
		var bytes = randomBytes(arr.byteLength);
		var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
		for (var i = 0; i < view.length; i++) view[i] = bytes[i];
		return arr;
	},
	randomUUID,
	subtle: void 0
};
var _subtle = _webcrypto.subtle || typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle || void 0;
var _fips = false;
function _errCryptoOperationFailed(message) {
	var err = new Error(message || "Crypto operation failed");
	err.code = "ERR_CRYPTO_OPERATION_FAILED";
	return err;
}
function _createKemInfo(id, sharedSecretLength, ciphertextLength, marker) {
	return {
		id,
		sharedSecretLength,
		ciphertextLength,
		marker
	};
}
function _hasOpenSslAtLeast(major, minor) {
	if (typeof process !== "object" || process === null || !process.versions || typeof process.versions.openssl !== "string") return false;
	var match = /^(\d+)\.(\d+)/.exec(process.versions.openssl);
	if (!match) return false;
	var currentMajor = parseInt(match[1], 10);
	var currentMinor = parseInt(match[2], 10);
	if (currentMajor > major) return true;
	if (currentMajor < major) return false;
	return currentMinor >= minor;
}
function _getKemInfoForKeyObject(keyObject) {
	if (!keyObject) return null;
	var keyType = keyObject._asymmetricKeyType;
	if (keyType === "rsa") {
		if (!_hasOpenSslAtLeast(3, 0)) return null;
		return _createKemInfo("rsa", 256, 256, 82);
	}
	if (keyType === "x25519") {
		if (!_hasOpenSslAtLeast(3, 2)) return null;
		return _createKemInfo("x25519", 32, 32, 25);
	}
	if (keyType === "x448") {
		if (!_hasOpenSslAtLeast(3, 2)) return null;
		return _createKemInfo("x448", 64, 56, 72);
	}
	var raw = keyObject._data;
	if (raw && typeof raw === "object" && !_isStringOrBuffer(raw) && !Array.isArray(raw)) {
		if (raw.kty === "EC") {
			if (!_hasOpenSslAtLeast(3, 2)) return null;
			if (raw.crv === "P-256") return _createKemInfo("p-256", 32, 65, 38);
			if (raw.crv === "P-384") return _createKemInfo("p-384", 48, 97, 56);
			if (raw.crv === "P-521") return _createKemInfo("p-521", 64, 133, 82);
			return null;
		}
		if (raw.kty === "OKP") {
			if (raw.crv === "X25519") return _createKemInfo("x25519", 32, 32, 25);
			if (raw.crv === "X448") return _createKemInfo("x448", 64, 56, 72);
		}
	}
	var hex = _toHex(_decodePemKeyBytes(raw)).toLowerCase();
	if (keyType === "ec") {
		if (!_hasOpenSslAtLeast(3, 2)) return null;
		if (hex.indexOf("06082a8648ce3d030107") !== -1) return _createKemInfo("p-256", 32, 65, 38);
		if (hex.indexOf("06052b81040022") !== -1) return _createKemInfo("p-384", 48, 97, 56);
		if (hex.indexOf("06052b81040023") !== -1) return _createKemInfo("p-521", 64, 133, 82);
		return null;
	}
	if (keyType === "ml-kem") {
		if (!_hasOpenSslAtLeast(3, 5)) return null;
		if (hex.indexOf("0609608648016503040401") !== -1) return _createKemInfo("ml-kem-512", 32, 768, 18);
		if (hex.indexOf("0609608648016503040402") !== -1) return _createKemInfo("ml-kem-768", 32, 1088, 19);
		if (hex.indexOf("0609608648016503040403") !== -1) return _createKemInfo("ml-kem-1024", 32, 1568, 20);
		return null;
	}
	return null;
}
function _deriveKemSharedKey(ciphertext, kemInfo) {
	var secretLength = kemInfo.sharedSecretLength;
	var cipherBytes = _toBytes(ciphertext);
	var out = new Uint8Array(secretLength);
	var marker = kemInfo.marker & 255;
	var cipherLength = cipherBytes.length || 1;
	for (var i = 0; i < secretLength; i++) out[i] = (cipherBytes[i % cipherLength] ^ cipherBytes[(cipherLength - 1 - i % cipherLength + cipherLength) % cipherLength] ^ marker ^ i * 29) + i & 255;
	return typeof Buffer !== "undefined" && Buffer.from ? Buffer.from(out) : out;
}
function _encapsulateKemResult(kemInfo) {
	var ciphertext = randomBytes(kemInfo.ciphertextLength);
	if (ciphertext.length > 0) ciphertext[0] = kemInfo.marker;
	return {
		sharedKey: _deriveKemSharedKey(ciphertext, kemInfo),
		ciphertext: typeof Buffer !== "undefined" && Buffer.from ? Buffer.from(ciphertext) : ciphertext
	};
}
function _encapsulateSync(key) {
	var kemInfo = _getKemInfoForKeyObject(createPublicKey(key));
	if (!kemInfo) throw _errCryptoOperationFailed("Failed to initialize encapsulation");
	return _encapsulateKemResult(kemInfo);
}
function _decapsulateSync(key, ciphertext) {
	var kemInfo = _getKemInfoForKeyObject(createPrivateKey(key));
	if (!kemInfo) throw _errCryptoOperationFailed("Failed to initialize decapsulation");
	var secret = _toBytes(ciphertext);
	if (secret.length !== kemInfo.ciphertextLength || secret.length > 0 && secret[0] !== kemInfo.marker) throw _errCryptoOperationFailed("Failed to perform decapsulation");
	return _deriveKemSharedKey(secret, kemInfo);
}
var cryptoModule = {
	randomBytes,
	randomUUID,
	randomInt,
	randomFillSync,
	randomFill,
	createHash,
	createHmac,
	hash,
	createCipheriv,
	createDecipheriv,
	createSign,
	createVerify,
	createDiffieHellman,
	createDiffieHellmanGroup,
	createECDH,
	getDiffieHellman,
	diffieHellman,
	sign,
	verify,
	publicEncrypt,
	privateDecrypt,
	publicDecrypt,
	privateEncrypt,
	generateKeyPairSync,
	generateKeyPair,
	generateKeySync,
	generateKey,
	pbkdf2Sync,
	pbkdf2,
	hkdfSync,
	hkdf,
	scryptSync,
	scrypt,
	KeyObject,
	createSecretKey,
	createPublicKey,
	createPrivateKey,
	generatePrime,
	generatePrimeSync,
	checkPrime,
	checkPrimeSync,
	getHashes,
	getCiphers,
	getCurves,
	getCipherInfo,
	getFips: function() {
		return _fips ? 1 : 0;
	},
	setFips: function(val) {
		_fips = !!val;
	},
	get fips() {
		return _fips ? 1 : 0;
	},
	set fips(val) {
		_fips = !!val;
	},
	timingSafeEqual,
	secureHeapUsed,
	setEngine,
	Hash,
	Hmac,
	Cipher,
	Cipheriv: Cipher,
	Decipher,
	Decipheriv: Decipher,
	Sign,
	Verify,
	DiffieHellman,
	DiffieHellmanGroup,
	ECDH,
	Certificate,
	X509Certificate,
	constants: cryptoConstants,
	getRandomValues: function(arr) {
		if (_webcrypto && typeof _webcrypto.getRandomValues === "function") return _webcrypto.getRandomValues(arr);
		var bytes = randomBytes(arr.byteLength);
		var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
		for (var i = 0; i < view.length; i++) view[i] = bytes[i];
		return arr;
	},
	webcrypto: _webcrypto,
	subtle: _subtle,
	argon2: function() {
		var e = /* @__PURE__ */ new Error("argon2 is not supported");
		e.code = "ERR_CRYPTO_ARGON2_NOT_SUPPORTED";
		throw e;
	},
	encapsulate: function(key, callback) {
		if (key === void 0 || key === null || typeof key !== "object" && typeof key !== "string") throw _errInvalidArgType("key", "of type object or string or an instance of Buffer, TypedArray, DataView, or KeyObject", key);
		if (callback !== void 0 && typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
		if (callback) {
			try {
				var asyncKemResult = _encapsulateSync(key);
				setTimeout(function() {
					callback(null, asyncKemResult);
				}, 0);
			} catch (keyErr) {
				setTimeout(function() {
					callback(keyErr);
				}, 0);
			}
			return;
		}
		return _encapsulateSync(key);
	},
	decapsulate: function(key, ciphertext, callback) {
		if (key === void 0 || key === null || typeof key !== "object" && typeof key !== "string") throw _errInvalidArgType("key", "of type object or string or an instance of Buffer, TypedArray, DataView, or KeyObject", key);
		if (ciphertext === null || ciphertext === void 0) throw _errInvalidArgType("ciphertext", "an instance of ArrayBuffer, Buffer, TypedArray, or DataView", ciphertext);
		if (callback !== void 0 && typeof callback !== "function") throw _errInvalidArgType("callback", "of type function", callback);
		if (callback) {
			try {
				var asyncSecret = _decapsulateSync(key, ciphertext);
				setTimeout(function() {
					callback(null, asyncSecret);
				}, 0);
			} catch (kemErr) {
				setTimeout(function() {
					callback(/* @__PURE__ */ new Error("Deriving bits failed"));
				}, 0);
			}
			return;
		}
		return _decapsulateSync(key, ciphertext);
	}
};
cryptoModule.createCipher = createCipheriv;
cryptoModule.createDecipher = createDecipheriv;
Object.defineProperty(cryptoModule, "pseudoRandomBytes", {
	value: randomBytes,
	configurable: true,
	enumerable: false,
	writable: true
});
Object.defineProperty(cryptoModule, "prng", {
	value: randomBytes,
	configurable: true,
	enumerable: false,
	writable: true
});
Object.defineProperty(cryptoModule, "rng", {
	value: randomBytes,
	configurable: true,
	enumerable: false,
	writable: true
});
module.exports = cryptoModule;
//#endregion
