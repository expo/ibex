//#region src/builtins/fs.js
var g = globalThis;
var _exactFsInitialized = false;
var _streamModule = null;
var _exactPrivateBuiltinBridges = typeof __exactPrivateBuiltinBridges === "object" && __exactPrivateBuiltinBridges ? __exactPrivateBuiltinBridges : null;
var _exactFsMutationGuard = _exactPrivateBuiltinBridges && typeof _exactPrivateBuiltinBridges.fsMutationGuard === "function" ? _exactPrivateBuiltinBridges.fsMutationGuard : typeof g.__exactFsMutationGuard === "function" ? g.__exactFsMutationGuard : null;
var _exactGetVirtualCwd = _exactPrivateBuiltinBridges && typeof _exactPrivateBuiltinBridges.getVirtualCwd === "function" ? _exactPrivateBuiltinBridges.getVirtualCwd : typeof g.__exactGetCwd === "function" ? g.__exactGetCwd : null;
function ensureExactFs() {
	if (_exactFsInitialized) return;
	if (typeof g.__exactEnsureFs === "function") try {
		g.__exactEnsureFs();
	} catch (e) {}
	_exactFsInitialized = true;
}
function _guardClosedFsMutation(operation, path, dest) {
	if (typeof _exactFsMutationGuard !== "function") throw _makeFsError({ code: "EPERM" }, operation, path, dest);
	try {
		_exactFsMutationGuard(operation);
	} catch (err) {
		throw _makeFsError(err, operation, path, dest);
	}
}
function _getStreamModule() {
	if (_streamModule) return _streamModule;
	_streamModule = require("node:stream");
	return _streamModule;
}
function _fsInvalidArgType(name, expected, actual) {
	var received;
	if (actual === null) received = "null";
	else if (actual === void 0) received = "undefined";
	else if (Array.isArray(actual)) received = "an instance of Array";
	else if (typeof actual === "function") received = actual.name ? "function " + actual.name : "function ";
	else if (typeof actual === "object") received = "an instance of " + (actual.constructor && actual.constructor.name ? actual.constructor.name : "Object");
	else if (typeof actual === "string") received = "type string (" + actual + ")";
	else if (typeof actual === "number") received = "type number (" + actual + ")";
	else if (typeof actual === "boolean") received = "type boolean (" + actual + ")";
	else if (typeof actual === "symbol") received = "type symbol (" + String(actual) + ")";
	else received = "type " + typeof actual;
	var expectedText = String(expected);
	var requirement = expectedText.indexOf("an instance of ") === 0 ? expectedText : "of type " + expectedText;
	var err = /* @__PURE__ */ new TypeError("The \"" + name + "\" argument must be " + requirement + ". Received " + received);
	err.code = "ERR_INVALID_ARG_TYPE";
	err.toString = function() {
		return "TypeError [ERR_INVALID_ARG_TYPE]: " + this.message;
	};
	return err;
}
function _fsOutOfRange(name, received, min, max) {
	var message;
	if (min === null) message = "The value of \"" + name + "\" is out of range. It must be an integer. Received " + received;
	else message = "The value of \"" + name + "\" is out of range. It must be >= " + min + " && <= " + max + ". Received " + received;
	var err = new RangeError(message);
	err.code = "ERR_OUT_OF_RANGE";
	return err;
}
function _validateInt(name, value, min, max) {
	if (typeof value !== "number" || !Number.isFinite(value) || value % 1 !== 0) throw _fsOutOfRange(name, value, null, null);
	if (value < min || value > max) throw _fsOutOfRange(name, value, min, max);
}
function _validateUidOrGid(name, value) {
	if (typeof value !== "number") throw _fsInvalidArgType(name, "number", value);
	if (!Number.isInteger(value)) throw _fsOutOfRange(name, value, null, null);
	if (value < -1 || value > 4294967295) throw _fsOutOfRange(name, value, -1, 4294967295);
}
function _validateUint32(name, value) {
	if ((name === "uid" || name === "gid") && value === -1) {
		if (typeof value !== "number") throw _fsInvalidArgType(name, "number", value);
		if (!Number.isInteger(value)) throw _fsOutOfRange(name, value, null, null);
		return;
	}
	if (typeof value !== "number") throw _fsInvalidArgType(name, "number", value);
	if (!Number.isInteger(value)) throw _fsOutOfRange(name, value, null, null);
	if (value < 0 || value > 4294967295) throw _fsOutOfRange(name, value, 0, 4294967295);
}
function _fsInvalidArgValue(name, value, reason) {
	var received;
	if (typeof value === "string") received = "'" + value + "'";
	else if (value === void 0) received = "undefined";
	else if (value === null) received = "null";
	else received = String(value);
	var err = /* @__PURE__ */ new TypeError("The argument \"" + name + "\" must be " + reason + ". Received " + received);
	err.code = "ERR_INVALID_ARG_VALUE";
	return err;
}
var _VALID_SYMLINK_TYPES = {
	dir: true,
	file: true,
	junction: true
};
function _validateSymlinkType(type) {
	if (type === void 0) return;
	if (typeof type !== "string" || !_VALID_SYMLINK_TYPES[type]) throw _fsInvalidArgValue("type", type, "one of: 'dir', 'file', 'junction', or undefined");
}
function _normalizeRmError(err, path, recursive) {
	if (!err || typeof err !== "object") return err;
	if (err.syscall === "rmdir" || err.syscall === "unlink") {
		err.syscall = "rm";
		if (typeof err.message === "string") err.message = err.message.replace(/, (?:rmdir|unlink) /, ", rm ");
	}
	if (recursive && typeof process === "object" && process !== null && process.platform === "darwin" && err.code === "EACCES" && path) {
		var entries = null;
		try {
			entries = readdirSync(path);
		} catch (_e) {}
		if (entries && entries.length > 0) {
			err.code = "ENOTEMPTY";
			err.path = path;
			err.message = "ENOTEMPTY: directory not empty, rm '" + path + "'";
		}
	}
	return err;
}
function _makeRmDirError(path) {
	var err = /* @__PURE__ */ new Error("ERR_FS_EISDIR: Path is a directory: rm returned EISDIR (is a directory) " + path);
	err.code = "ERR_FS_EISDIR";
	err.syscall = "rm";
	err.path = path;
	if (_uvErrnoMap.EISDIR !== void 0) err.errno = -_uvErrnoMap.EISDIR;
	return err;
}
function _coerceMode(mode) {
	if (typeof mode === "number") return mode;
	if (typeof mode === "string") {
		var normalized = mode;
		if (normalized.slice(0, 2).toLowerCase() === "0o") normalized = normalized.slice(2);
		if (normalized.length === 0) return 0;
		for (var i = 0; i < normalized.length; i++) {
			var code = normalized.charCodeAt(i);
			if (code < 48 || code > 55) throw _fsInvalidArgValue("mode", mode, "a 32-bit unsigned integer or an octal string");
		}
		return parseInt(normalized, 8);
	}
	throw _fsInvalidArgType("mode", "number", mode);
}
function _validateFd(fd) {
	if (typeof fd !== "number") throw _fsInvalidArgType("fd", "number", fd);
	_validateInt("fd", fd, -1, 2147483647);
}
function _validateFdNonNegative(fd) {
	if (typeof fd !== "number") throw _fsInvalidArgType("fd", "number", fd);
	_validateInt("fd", fd, 0, 2147483647);
}
function _getFdOrPath(path, propName) {
	if (typeof path === "number") return {
		fd: path,
		path: void 0
	};
	if (path && typeof path === "object" && typeof path.fd === "number") return {
		fd: path.fd,
		path: void 0
	};
	_validatePath(path, propName);
	return {
		fd: null,
		path: _pathToString(path)
	};
}
function _isPathBufferView(path) {
	if (typeof Buffer !== "undefined" && Buffer.isBuffer(path)) return true;
	if (typeof ArrayBuffer !== "undefined" && typeof ArrayBuffer.isView === "function") return ArrayBuffer.isView(path);
	return false;
}
function _pathBufferViewToUint8Array(path) {
	if (typeof Buffer !== "undefined" && Buffer.isBuffer(path)) return path;
	if (_isPathBufferView(path)) return new Uint8Array(path.buffer, path.byteOffset || 0, path.byteLength);
	return null;
}
function _pathBufferViewToString(path) {
	var bytes = _pathBufferViewToUint8Array(path);
	if (!bytes) return String(path);
	if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
		var _copy = Buffer.alloc(bytes.byteLength);
		_copy.set(new Uint8Array(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength));
		return _copy.toString();
	}
	var out = "";
	for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
	return out;
}
function _validatePath(path, propName) {
	path = _coercePathFromURL(path, propName);
	if (path && typeof path === "object" && typeof path.href === "string" && path.protocol === "file:") return;
	if (typeof path !== "string" && !_isPathBufferView(path)) throw _fsInvalidArgType(propName || "path", "string or an instance of Buffer or URL", path);
	if (typeof path === "string" && path.indexOf("\0") !== -1) {
		var err = /* @__PURE__ */ new TypeError("The argument \"" + (propName || "path") + "\" must be a string, Uint8Array, or URL without null bytes. Received " + JSON.stringify(path));
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
	var pathBytes = _pathBufferViewToUint8Array(path);
	if (pathBytes) for (var i = 0; i < pathBytes.length; i++) {
		if (pathBytes[i] !== 0) continue;
		var err = /* @__PURE__ */ new TypeError("The argument \"" + (propName || "path") + "\" must be a string, Uint8Array, or URL without null bytes. Received " + JSON.stringify(_pathBufferViewToString(path)));
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
}
function _coercePathFromURL(path, propName) {
	if (!path || typeof path !== "object") return path;
	if (typeof path.href !== "string" || typeof path.protocol !== "string") return path;
	if (path.protocol !== "file:") {
		var schemeErr = /* @__PURE__ */ new TypeError("The URL must be of scheme file");
		schemeErr.code = "ERR_INVALID_URL_SCHEME";
		throw schemeErr;
	}
	var isWindows = typeof process === "object" && process !== null && process.platform === "win32";
	if (!isWindows && path.hostname && path.hostname !== "localhost") {
		var hostErr = /* @__PURE__ */ new TypeError("File URL host must be \"localhost\" or empty on non-Windows platforms");
		hostErr.code = "ERR_INVALID_FILE_URL_HOST";
		throw hostErr;
	}
	var pathname = path.pathname;
	if (!pathname) {
		var err = /* @__PURE__ */ new TypeError("The URL must have a pathname");
		if (propName) err.name = "TypeError";
		throw err;
	}
	if (/%2f/i.test(pathname) || isWindows && /%5c/i.test(pathname)) {
		var pathErr = /* @__PURE__ */ new TypeError("File URL path must not include encoded path separators");
		pathErr.code = "ERR_INVALID_FILE_URL_PATH";
		throw pathErr;
	}
	var decoded = decodeURIComponent(pathname);
	if (decoded.indexOf("\0") !== -1) {
		var nullErr = /* @__PURE__ */ new TypeError("The argument \"" + (propName || "path") + "\" must be a string, Uint8Array, or URL without null bytes. Received " + JSON.stringify(decoded));
		nullErr.code = "ERR_INVALID_ARG_VALUE";
		throw nullErr;
	}
	return decoded;
}
function _emitFsDeprecation(code, message) {
	if (typeof process === "object" && process !== null && typeof process.emitWarning === "function") process.emitWarning(message, "DeprecationWarning", code);
}
function _isBufferLike(value) {
	if (!value) return false;
	if (typeof Buffer !== "undefined" && Buffer.isBuffer(value)) return true;
	if (typeof ArrayBuffer !== "undefined" && typeof ArrayBuffer.isView === "function") {
		if (ArrayBuffer.isView(value)) return true;
	}
	if (typeof value === "object" && value !== null) {
		if (typeof value.byteLength === "number" && typeof value.byteOffset === "number" && typeof value.buffer === "object") return true;
		if (typeof value.byteLength === "number" && typeof value.length === "number" && value.constructor && typeof value.constructor.BYTES_PER_ELEMENT === "number") return true;
		var typeTag = Object.prototype.toString.call(value);
		if (typeTag !== "[object Array]" && typeTag.indexOf("Array") !== -1) return true;
		if (typeTag === "[object DataView]") return true;
	}
	return false;
}
function _bufferLikeLength(value) {
	if (!value) return 0;
	if (typeof value.length === "number") return value.length;
	if (typeof value.byteLength === "number") return value.byteLength;
	return 0;
}
function _describeBufferLike(value) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	var name = value.constructor && value.constructor.name ? value.constructor.name : "Object";
	var length = _bufferLikeLength(value);
	return name + "(" + length + ") []";
}
function _throwEmptyBufferError(name, value) {
	var err = /* @__PURE__ */ new TypeError("The argument '" + name + "' is empty and cannot be written. Received " + _describeBufferLike(value));
	err.code = "ERR_INVALID_ARG_VALUE";
	return err;
}
function _validateCopyFileMode(mode) {
	if (typeof mode !== "number") {
		var err = /* @__PURE__ */ new TypeError("mode must be int32 or null/undefined");
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	_validateInt("mode", mode, 0, 7);
}
function _validateAccessMode(mode) {
	if (mode === void 0 || mode === null) return 0;
	if (typeof mode !== "number") {
		var err = /* @__PURE__ */ new TypeError("mode must be int32 or null/undefined");
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	_validateInt("mode", mode, 0, 7);
	return mode;
}
function _validateReadSyncLength(length, bufferLength) {
	if (typeof length === "undefined" || length === null) return bufferLength;
	if (typeof length !== "number" || !Number.isFinite(length) || length % 1 !== 0) throw _fsInvalidArgType("length", "number", length);
	if (length < 0) {
		var negativeLengthErr = /* @__PURE__ */ new RangeError("The value of \"length\" is out of range. It must be >= 0. Received " + length);
		negativeLengthErr.code = "ERR_OUT_OF_RANGE";
		throw negativeLengthErr;
	}
	if (length > bufferLength) {
		var lengthTooLargeErr = /* @__PURE__ */ new RangeError("The value of \"length\" is out of range. It must be <= " + bufferLength + ". Received " + length);
		lengthTooLargeErr.code = "ERR_OUT_OF_RANGE";
		throw lengthTooLargeErr;
	}
	return length;
}
function _normalizeTruncateLen(len) {
	if (len === void 0) return 0;
	if (typeof len !== "number") throw _fsInvalidArgType("len", "number", len);
	if (!Number.isFinite(len) || len % 1 !== 0) throw _fsOutOfRange("len", len, null, null);
	return len < 0 ? 0 : len;
}
function _validateReadWritePosition(name, position) {
	if (position === void 0 || position === null) return -1;
	if (typeof position === "bigint") {
		if (position < -BigInt("1") || position > BigInt(Number.MAX_SAFE_INTEGER)) throw _fsOutOfRange(name, position, -1, Number.MAX_SAFE_INTEGER);
		return Number(position);
	}
	if (typeof position !== "number") throw _fsInvalidArgType(name, "bigint or integer", position);
	if (!Number.isFinite(position) || position % 1 !== 0) throw _fsOutOfRange(name, position, null, null);
	if (position < -1 || position > Number.MAX_SAFE_INTEGER) throw _fsOutOfRange(name, position, -1, Number.MAX_SAFE_INTEGER);
	return position;
}
function _normalizeFsReadArgs(buffer, offset, length, position) {
	if (!_isBufferLike(buffer)) throw _fsInvalidArgType("buffer", "an instance of Buffer, TypedArray, or DataView", buffer);
	var targetBuffer = toUint8Array(buffer);
	var bufferLen = targetBuffer.length;
	var off = _validateOffset("offset", offset === void 0 || offset === null ? 0 : offset, bufferLen);
	if (bufferLen === 0 && typeof length === "number" && Number.isFinite(length) && length !== 0) throw _throwEmptyBufferError("buffer", buffer);
	return {
		buffer,
		targetBuffer,
		offset: off,
		length: _validateReadSyncLength(length, bufferLen - off),
		position: _validateReadWritePosition("position", position)
	};
}
function _isFsReadOptionsObject(value, allowUndefined) {
	if (value === null) return true;
	if (value === void 0) return !!allowUndefined;
	return typeof value === "object" && !Array.isArray(value) && !_isBufferLike(value);
}
function _validateOffset(name, offset, bufferLength) {
	if (typeof offset !== "number") throw _fsInvalidArgType(name, "number", offset);
	if (!Number.isFinite(offset) || offset % 1 !== 0) throw _fsOutOfRange(name, offset, null, null);
	if (offset < 0 || offset > bufferLength) throw _fsOutOfRange(name, offset, 0, bufferLength);
	return offset;
}
function _validateCallback(cb) {
	if (typeof cb !== "function") throw _fsInvalidArgType("callback", "function", cb);
}
function _deferFsCallback(callback) {
	if (typeof setImmediate === "function") setImmediate(callback);
	else setTimeout(callback, 0);
}
function _deferFsWriteCallback(callback) {
	if (typeof process !== "undefined" && process && typeof process.nextTick === "function") {
		process.nextTick(callback);
		return;
	}
	_deferFsCallback(callback);
}
function _pathToString(path) {
	if (typeof path === "string") return _resolvePathFromCwd(path);
	if (_isPathBufferView(path)) return _pathBufferViewToString(path);
	if (path && typeof path === "object" && typeof path.href === "string" && path.protocol === "file:") return _coercePathFromURL(path);
	return _resolvePathFromCwd(String(path));
}
function _isAbsolutePath(path) {
	if (!path || typeof path !== "string") return false;
	return path.charAt(0) === "/" || path.charAt(1) === ":" || path.indexOf("\\\\") === 0;
}
function _normalizePathSegments(parts) {
	var out = [];
	for (var i = 0; i < parts.length; i++) {
		var segment = parts[i];
		if (!segment || segment === ".") continue;
		if (segment === "..") {
			if (out.length > 0) out.pop();
		} else out.push(segment);
	}
	return out;
}
function _currentProcessCwd() {
	if (typeof _exactGetVirtualCwd === "function") {
		var nativeCwd = _exactGetVirtualCwd();
		if (typeof nativeCwd === "string" && nativeCwd.length > 0) return nativeCwd;
	}
	return "/";
}
function _resolvePathFromCwd(path) {
	if (!_isAbsolutePath(path)) {
		var cwd = _currentProcessCwd();
		if (!cwd) cwd = "/";
		var isWindows = typeof process === "object" && process !== null && process.platform === "win32";
		var separator = isWindows ? "\\" : "/";
		var normalizedCwd = cwd.replace(/[\\/]+/g, separator);
		var normalizedPath = path.replace(/[\\/]+/g, separator);
		var root = isWindows && normalizedCwd.charAt(1) === ":" ? normalizedCwd.slice(0, 2) : separator;
		var cwdRemainder = isWindows && root !== separator ? normalizedCwd.slice(2) : normalizedCwd;
		if (cwdRemainder.charAt(0) === separator) cwdRemainder = cwdRemainder.slice(1);
		var cwdParts = cwdRemainder.split(separator);
		var pathParts = normalizedPath.split(separator);
		if (root === separator && cwdRemainder === separator && cwdParts.length === 1) cwdParts = [];
		var combined = _normalizePathSegments(cwdParts.concat(pathParts));
		if (path === "." && combined.length === 0) return root === separator ? separator : root + separator;
		if (isWindows && root !== separator) return root + separator + combined.join(separator);
		return separator + combined.join(separator);
	}
	return path;
}
function _mapVendoredNodeTestPath(path) {
	if (typeof path !== "string") return path;
	var absolute = _resolvePathFromCwd(path);
	var cwd = _resolvePathFromCwd(".");
	var testPrefix = cwd + "/test/";
	if (absolute.indexOf(testPrefix) !== 0) return path;
	var relative = absolute.slice(testPrefix.length);
	var mapped = null;
	if (relative.indexOf("parallel/") === 0) mapped = pathJoin(cwd, "test/compat/fixtures/node/" + relative);
	else if (relative.indexOf("common/") === 0) mapped = pathJoin(cwd, "test/compat/fixtures/node/" + relative);
	else if (relative.indexOf("fixtures/") === 0) mapped = pathJoin(cwd, "test/compat/fixtures/node/" + relative);
	if (mapped && existsSync(mapped)) return mapped;
	return path;
}
function _getFirstMissingPath(targetPath) {
	var normalized = targetPath.replace(/\\\\/g, "/");
	var parts = normalized.split("/");
	var current = normalized.charAt(0) === "/" ? "/" : "";
	for (var i = 0; i < parts.length; i++) {
		var part = parts[i];
		if (!part) continue;
		current = current === "/" ? "/" + part : current ? current + "/" + part : part;
		try {
			var stat = statSync(current);
			if (!stat || typeof stat.isDirectory !== "function" || !stat.isDirectory()) return current;
		} catch (err) {
			if (err && err.code === "ENOENT") return current;
			throw err;
		}
	}
}
function _dirnamePath(value) {
	var lastSlash = value.lastIndexOf("/");
	var lastBackslash = value.lastIndexOf("\\");
	var sepIndex = Math.max(lastSlash, lastBackslash);
	if (sepIndex === -1) return ".";
	if (sepIndex === 0) return "/";
	return value.slice(0, sepIndex);
}
function _nativeMkdirPath(value) {
	return value;
}
function _fsInvalidArgTypeProperty(propName, expected, actual) {
	var err = _fsInvalidArgType(propName, expected, actual);
	err.message = err.message.replace(" argument", " property");
	if (typeof actual === "string") err.message = err.message.replace("type string (" + actual + ")", "type string ('" + actual.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "')");
	return err;
}
var _uvErrnoMap = {
	"EACCES": 13,
	"EBADF": 9,
	"EBUSY": 16,
	"EEXIST": 17,
	"EFAULT": 14,
	"EFBIG": 27,
	"EINVAL": 22,
	"EIO": 5,
	"EISDIR": 21,
	"ELOOP": 40,
	"EMFILE": 24,
	"ENAMETOOLONG": 63,
	"ENOENT": 2,
	"ENOMEM": 12,
	"ENOSPC": 28,
	"ENOSYS": 78,
	"ENOTDIR": 20,
	"ENOTEMPTY": 66,
	"EPERM": 1,
	"ERANGE": 34,
	"EROFS": 30,
	"ESPIPE": 29,
	"EXDEV": 18,
	"ETXTBSY": 26,
	"UNKNOWN": 4094
};
var _uvErrnoMessage = {
	"EACCES": "permission denied",
	"EBADF": "bad file descriptor",
	"EBUSY": "resource busy or locked",
	"EEXIST": "file already exists",
	"EFAULT": "bad address in system call argument",
	"EFBIG": "file too large",
	"EINVAL": "invalid argument",
	"EIO": "i/o error",
	"EISDIR": "illegal operation on a directory",
	"ELOOP": "too many symbolic links encountered",
	"EMFILE": "too many open files",
	"ENAMETOOLONG": "name too long",
	"ENOENT": "no such file or directory",
	"ENOMEM": "not enough memory",
	"ENOSPC": "no space left on device",
	"ENOSYS": "function not implemented",
	"ENOTDIR": "not a directory",
	"ENOTEMPTY": "directory not empty",
	"EPERM": "operation not permitted",
	"ERANGE": "result too large",
	"EROFS": "read-only file system",
	"ESPIPE": "invalid seek",
	"EXDEV": "cross-device link not permitted",
	"ETXTBSY": "text file is busy"
};
function _uvCodeFromErrno(errno) {
	if (typeof errno !== "number" || Number.isNaN(errno)) return null;
	var normalized = Math.abs(errno);
	for (var code in _uvErrnoMap) if (Object.prototype.hasOwnProperty.call(_uvErrnoMap, code) && _uvErrnoMap[code] === normalized) return code;
	return null;
}
function _extractFsCode(message) {
	if (typeof message !== "string") return null;
	var match = message.match(/^([A-Z][A-Z0-9_]+):/);
	return match ? match[1] : null;
}
function _getFsErrorCode(err) {
	if (!err || typeof err !== "object") return null;
	if (typeof err.code === "string") return err.code;
	return _extractFsCode(err.message) || _uvCodeFromErrno(err.errno);
}
function _makeFsThisError(name) {
	var err = /* @__PURE__ */ new TypeError("The \"" + name + "\" property was accessed on an object that is not a Dir.");
	err.code = "ERR_INVALID_THIS";
	return err;
}
function _makeDirError(code, message, path) {
	var err = /* @__PURE__ */ new Error(code + ": " + message + (path ? " '" + path + "'" : ""));
	err.code = code;
	if (path) err.path = path;
	return err;
}
function _makeDirClosedError(path) {
	return _makeDirError("ERR_DIR_CLOSED", "Directory handle is closed", path);
}
function _makeDirConcurrentOperationError(path) {
	return _makeDirError("ERR_DIR_CONCURRENT_OPERATION", "Directory handle is busy", path);
}
function _buildFsErrorMessage(code, syscall, pathValue, destValue) {
	var out = code + ": " + (_uvErrnoMessage[code] || "unknown error") + ", " + syscall;
	if (pathValue !== void 0) out += " '" + pathValue + "'";
	if (destValue !== void 0) out += " -> '" + destValue + "'";
	return out;
}
function _makeFsError(err, syscall, path, dest) {
	err = err || {};
	var sourceMessage = typeof err.message === "string" ? err.message : String(err);
	var code = typeof err.code === "string" ? err.code : null;
	if (!code || !Object.prototype.hasOwnProperty.call(_uvErrnoMessage, code)) code = _extractFsCode(sourceMessage) || _uvCodeFromErrno(err.errno);
	var resolvedSyscall = syscall;
	var resolvedPath = path;
	var resolvedDest = dest;
	if (resolvedSyscall === void 0 && typeof err.syscall === "string") resolvedSyscall = err.syscall;
	if (resolvedPath === void 0 && err.path !== void 0) resolvedPath = err.path;
	if (resolvedDest === void 0 && err.dest !== void 0) resolvedDest = err.dest;
	var message = sourceMessage;
	if (code && _uvErrnoMessage[code] && resolvedSyscall) message = _buildFsErrorMessage(code, resolvedSyscall, resolvedPath, resolvedDest);
	var fsErr = new Error(message);
	var resolvedFilename = err.filename !== void 0 ? err.filename : resolvedPath;
	if (code) fsErr.code = code;
	if (resolvedSyscall) fsErr.syscall = resolvedSyscall;
	if (resolvedPath !== void 0) fsErr.path = resolvedPath;
	if (resolvedFilename !== void 0) fsErr.filename = resolvedFilename;
	if (resolvedDest !== void 0) fsErr.dest = resolvedDest;
	if (typeof err.errno === "number" && !Number.isNaN(err.errno)) fsErr.errno = err.errno >= 0 ? -err.errno : err.errno;
	else if (code && _uvErrnoMap[code] !== void 0) fsErr.errno = -_uvErrnoMap[code];
	else if (err.code && _uvErrnoMap[err.code] !== void 0) fsErr.errno = -_uvErrnoMap[err.code];
	else fsErr.errno = -_uvErrnoMap.UNKNOWN;
	return fsErr;
}
function _makeUnsupportedFsError(syscall, path) {
	return _makeFsError({ code: "ENOSYS" }, syscall, path);
}
function _parseFsOpenFlags(flags) {
	if (typeof flags !== "string") {
		var err = /* @__PURE__ */ new TypeError("The flags argument must be a string or a number. Received " + (flags === null ? "null" : typeof flags));
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
	if (flags.length === 0) {
		var emptyErr = /* @__PURE__ */ new TypeError("The flags argument must be a valid flags string. Received " + JSON.stringify(flags));
		emptyErr.code = "ERR_INVALID_ARG_VALUE";
		throw emptyErr;
	}
	var hasPlus = flags.indexOf("+") !== -1;
	if (flags.indexOf("+") !== flags.lastIndexOf("+")) {
		var plusErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
		plusErr.code = "ERR_INVALID_ARG_VALUE";
		throw plusErr;
	}
	if (hasPlus && flags.indexOf("+") !== flags.length - 1) {
		var plusPosErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
		plusPosErr.code = "ERR_INVALID_ARG_VALUE";
		throw plusPosErr;
	}
	var flagChars = hasPlus ? flags.slice(0, -1) : flags;
	var hasSync = false;
	var hasExclusive = false;
	var modeFlags = "";
	for (var i = 0; i < flagChars.length; i++) {
		var ch = flagChars.charAt(i);
		if (ch === "s") {
			if (hasSync) {
				var syncErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
				syncErr.code = "ERR_INVALID_ARG_VALUE";
				throw syncErr;
			}
			hasSync = true;
		} else if (ch === "x") {
			if (hasExclusive) {
				var exclusiveErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
				exclusiveErr.code = "ERR_INVALID_ARG_VALUE";
				throw exclusiveErr;
			}
			hasExclusive = true;
		} else if (ch === "r" || ch === "w" || ch === "a") {
			if (modeFlags.length >= 1) {
				var modeErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
				modeErr.code = "ERR_INVALID_ARG_VALUE";
				throw modeErr;
			}
			modeFlags = ch;
		} else {
			var charErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
			charErr.code = "ERR_INVALID_ARG_VALUE";
			throw charErr;
		}
	}
	if (modeFlags.length !== 1 || hasExclusive && modeFlags === "r") {
		var invalidErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(flags));
		invalidErr.code = "ERR_INVALID_ARG_VALUE";
		throw invalidErr;
	}
	var result = 0;
	if (modeFlags === "r") result = constants.O_RDONLY;
	else if (modeFlags === "w") result = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC;
	else result = constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND;
	if (hasPlus) result = result & ~constants.O_WRONLY | constants.O_RDWR;
	if (hasExclusive) result |= constants.O_EXCL;
	if (hasSync) result |= constants.O_SYNC;
	return result;
}
var _validEncodings = [
	"utf8",
	"utf-8",
	"ascii",
	"binary",
	"base64",
	"base64url",
	"ucs2",
	"ucs-2",
	"utf16le",
	"utf-16le",
	"latin1",
	"hex",
	"buffer"
];
function _assertEncoding(encoding) {
	if (encoding && _validEncodings.indexOf(encoding.toLowerCase()) === -1) {
		var err = /* @__PURE__ */ new TypeError("The argument 'encoding' is invalid encoding. Received '" + encoding + "'");
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
}
function _validateStringWriteEncoding(data, encoding) {
	if (typeof data !== "string" || !encoding) return;
	if (String(encoding).toLowerCase().replace("-", "") !== "hex") return;
	if (data.length % 2 !== 0 || /[^0-9a-f]/i.test(data)) {
		var err = /* @__PURE__ */ new TypeError("The argument 'encoding' is invalid for data of length " + data.length + ". Received '" + encoding + "'");
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
}
function _validateFlushOption(value) {
	if (value === void 0 || value === null || typeof value === "boolean") return;
	throw _fsInvalidArgType("options.flush", "boolean", value);
}
function _makeAbortError() {
	var err = /* @__PURE__ */ new Error("The operation was aborted");
	err.name = "AbortError";
	err.code = "ABORT_ERR";
	if (arguments.length > 0) err.cause = arguments[0];
	return err;
}
function _makeFileTooLargeError(size) {
	var err = /* @__PURE__ */ new RangeError("File size (" + size + ") is greater than 2 GiB");
	err.code = "ERR_FS_FILE_TOO_LARGE";
	return err;
}
function _fsAsyncNative(name) {
	ensureExactFs();
	var fn = g[name];
	return typeof fn === "function" ? fn : null;
}
function _asyncFsError(err, syscall, path, dest) {
	if (err && err.code === "ERR_FS_FILE_TOO_LARGE") return _makeFileTooLargeError(err.size);
	return _makeFsError(err, err && typeof err.syscall === "string" ? err.syscall : syscall, path, dest);
}
function _asyncFdOp(native, op, fd, x, y) {
	return native(op, fd, x, y).then(void 0, function(err) {
		throw _asyncFsError(err, op === "futimes" ? "futime" : op);
	});
}
function _asyncOpen(native, path, flags, mode) {
	_validatePath(path);
	var p = _pathToString(path);
	return native(p, _normalizeOpenFlagsValue(flags), _normalizeOpenModeValue(mode)).then(function(fd) {
		return fd;
	}, function(err) {
		throw _asyncFsError(err, "open", p);
	});
}
function _asyncClose(native, fd) {
	_validateFd(fd);
	return native(fd).then(void 0, function(err) {
		throw _asyncFsError(err, "close");
	});
}
function _wrapOwnedBytesAsBuffer(bytes) {
	if (typeof Buffer !== "undefined" && Buffer.from && bytes && !Buffer.isBuffer(bytes) && bytes.buffer && typeof bytes.byteOffset === "number" && typeof bytes.length === "number") try {
		return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length);
	} catch (e) {}
	return wrapBuffer(bytes);
}
function _asyncReadFileImpl(native, pathOrFd, readOptions) {
	var encoding = readOptions.encoding;
	var signal = readOptions.signal;
	var isFd = typeof pathOrFd === "number";
	var target;
	if (isFd) target = pathOrFd;
	else {
		_validatePath(pathOrFd);
		target = _pathToString(pathOrFd);
	}
	var flags = _normalizeOpenFlagsValue(readOptions.flag || readOptions.flags || "r");
	var mode = _normalizeOpenModeValue(readOptions.mode);
	return native(target, flags, mode).then(function(bytes) {
		if (signal && signal.aborted === true) throw _makeAbortError(signal.reason);
		if (encoding) return decodeBytes(bytes, encoding);
		return _wrapOwnedBytesAsBuffer(bytes);
	}, function(err) {
		throw _asyncFsError(err, isFd ? "read" : "open", isFd ? void 0 : target);
	});
}
function _asyncWriteFileImpl(native, targetInfo, data, writeOptions, defaultFlag) {
	var bytes = toUint8Array(data, writeOptions.encoding);
	var flush = writeOptions.flush === true;
	if (targetInfo.fd !== null && targetInfo.fd !== void 0) return native(targetInfo.fd, bytes, null, 438, flush).then(void 0, function(err) {
		throw _asyncFsError(err, "write", targetInfo.path || void 0);
	});
	var p = targetInfo.path;
	return native(p, bytes, _normalizeOpenFlagsValue(writeOptions.flag || writeOptions.flags || defaultFlag), _normalizeOpenModeValue(writeOptions.mode), flush).then(void 0, function(err) {
		throw _asyncFsError(err, "open", p);
	});
}
function _asyncStatImpl(native, target, kind, statOptions) {
	return native(target, kind).then(function(json) {
		return _makeStats(json, statOptions);
	}, function(err) {
		throw _asyncFsError(err, kind, typeof target === "string" ? target : void 0);
	});
}
function _asyncReadIntoBuffer(native, fd, buffer, offset, length, position) {
	var readArgs = _normalizeFsReadArgs(buffer, offset, length, position);
	return native(fd, readArgs.length, readArgs.position).then(function(data) {
		if (data.length > 0) if (!readArgs.targetBuffer.__isExactBuffer && typeof readArgs.targetBuffer.set === "function") readArgs.targetBuffer.set(data, readArgs.offset);
		else for (var i = 0; i < data.length; i++) readArgs.targetBuffer[readArgs.offset + i] = data[i];
		return data.length;
	}, function(err) {
		throw _asyncFsError(err, "read");
	});
}
function _asyncWriteFromArgs(native, fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
	var writeArgs = _prepareWriteArgs(bufferOrString, offsetOrPosition, lengthOrEncoding, position);
	return native(fd, writeArgs.bytes, writeArgs.position).then(void 0, function(err) {
		throw _asyncFsError(err, "write");
	});
}
function _validateVectoredIoArgs(fd, buffers, position) {
	_validateFd(fd);
	if (!Array.isArray(buffers)) throw _fsInvalidArgType("buffers", "Array", buffers);
	for (var i = 0; i < buffers.length; i++) if (!_isBufferLike(buffers[i])) throw _fsInvalidArgType("buffers[" + i + "]", "string or an instance of Buffer, TypedArray, or DataView", buffers[i]);
	if (position !== void 0 && position !== null && typeof position !== "number") throw _fsInvalidArgType("position", "number", position);
	return typeof position === "number" ? position : -1;
}
function _rawByteViewForBufferLike(value) {
	if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return new Uint8Array(value);
	if (value && value.buffer && typeof value.byteLength === "number") {
		var offset = typeof value.byteOffset === "number" ? value.byteOffset : 0;
		try {
			return new Uint8Array(value.buffer, offset, value.byteLength);
		} catch (e) {}
	}
	return null;
}
function _bufferLikeByteLength(value) {
	if (!value) return 0;
	if (typeof value.byteLength === "number") return value.byteLength;
	return _bufferLikeLength(value);
}
function _copyReadvBytesIntoBuffers(data, buffers) {
	var copied = 0;
	for (var i = 0; i < buffers.length && copied < data.length; i++) {
		var target = buffers[i];
		var length = Math.min(_bufferLikeByteLength(target), data.length - copied);
		if (length <= 0) continue;
		var raw = _rawByteViewForBufferLike(target);
		if (raw && typeof raw.set === "function" && typeof data.subarray === "function") raw.set(data.subarray(copied, copied + length));
		else for (var k = 0; k < length; k++) target[k] = data[copied + k];
		copied += length;
	}
}
function _asyncReadvIntoBuffers(native, fd, buffers, position) {
	return native(fd, buffers, _validateVectoredIoArgs(fd, buffers, position)).then(function(data) {
		if (data.length > 0) _copyReadvBytesIntoBuffers(data, buffers);
		return data.length;
	}, function(err) {
		throw _asyncFsError(err, "readv");
	});
}
function _asyncWritevFromBuffers(native, fd, buffers, position) {
	return native(fd, buffers, _validateVectoredIoArgs(fd, buffers, position)).then(void 0, function(err) {
		throw _asyncFsError(err, "writev");
	});
}
function _asyncFsPathOp(native, op, args, syscall, path, dest) {
	var nativeArgs = [op];
	for (var i = 0; i < args.length; i++) nativeArgs.push(args[i]);
	return native.apply(null, nativeArgs).then(void 0, function(err) {
		throw _asyncFsError(err, syscall, path, dest);
	});
}
function _deferFsPromiseCallback(promise, callback) {
	promise.then(function(value) {
		_deferFsCallback(function() {
			if (value === void 0) callback(null);
			else callback(null, value);
		});
	}, function(err) {
		_deferFsCallback(function() {
			callback(err);
		});
	});
	return true;
}
function _readdirEntriesFromNativePayload(payload, options) {
	var encoding = (typeof options === "string" ? { encoding: options } : options || {}).encoding;
	var rawEntries = JSON.parse(payload).sort();
	if (encoding === "buffer") return rawEntries.map(function(e) {
		return toUint8Array(e);
	});
	if (typeof encoding === "string" && encoding !== "utf8" && encoding !== "utf-8") return rawEntries.map(function(e) {
		return decodeBytes(toUint8Array(e), encoding);
	});
	return rawEntries;
}
function _asyncReaddirSimple(native, path, options) {
	var opts = typeof options === "string" ? { encoding: options } : options || {};
	var p = _pathToString(path);
	if (opts.withFileTypes || opts.recursive) return _asyncBuildDirEntries(native, p, opts).then(function(entries) {
		if (opts.withFileTypes) return entries;
		var traversalRoot = p.replace(/[\\/]+$/, "") || p;
		return entries.map(function(entry) {
			var relativeParent = entry.path === traversalRoot ? "" : entry.path.slice(traversalRoot.length).replace(/^[\\/]+/, "");
			return (relativeParent ? relativeParent + "/" : "") + entry.name;
		});
	});
	return _asyncFsPathOp(native, "readdir", [p], "scandir", p).then(function(payload) {
		return _readdirEntriesFromNativePayload(payload, opts);
	});
}
function _withTraversalSlot(limiter, work) {
	return new Promise(function(resolve, reject) {
		function start() {
			limiter.active += 1;
			Promise.resolve().then(work).then(resolve, reject).finally(function() {
				limiter.active -= 1;
				if (limiter.queue.length) limiter.queue.shift()();
			});
		}
		if (limiter.active < limiter.limit) start();
		else limiter.queue.push(start);
	});
}
function _boundedAsyncMap(items, limit, mapper) {
	var results = new Array(items.length), next = 0;
	function worker() {
		var index = next++;
		if (index >= items.length) return Promise.resolve();
		return Promise.resolve(mapper(items[index], index)).then(function(value) {
			results[index] = value;
			return worker();
		});
	}
	var workers = [];
	for (var i = 0; i < Math.min(limit, items.length); i++) workers.push(worker());
	return Promise.all(workers).then(function() {
		return results;
	});
}
function _asyncBuildDirEntries(native, path, options, limiter) {
	limiter = limiter || {
		active: 0,
		limit: 32,
		queue: []
	};
	var statNative = _fsAsyncNative("__exactFsStatAsync");
	return _withTraversalSlot(limiter, function() {
		return _asyncFsPathOp(native, "readdir", [path], "scandir", path);
	}).then(function(payload) {
		return _boundedAsyncMap(_readdirEntriesFromNativePayload(payload, options), 32, function(name) {
			var fullPath = pathJoin(path, name);
			return (statNative ? _withTraversalSlot(limiter, function() {
				return _asyncStatImpl(statNative, fullPath, "lstat", {});
			}) : Promise.resolve().then(function() {
				try {
					return lstatSync(fullPath);
				} catch (_) {
					return null;
				}
			})).then(function(stat) {
				var entry = new Dirent(_normalizeDirEntryName(name, options && options.encoding), path, stat);
				entry.path = path;
				if (options && options.recursive && stat && stat.isDirectory()) return _asyncBuildDirEntries(native, fullPath, options, limiter).then(function(nested) {
					return [entry].concat(nested);
				});
				return [entry];
			}, function() {
				var entry = new Dirent(_normalizeDirEntryName(name, options && options.encoding), path, null);
				entry.path = path;
				return [entry];
			});
		}).then(function(groups) {
			var result = [];
			for (var i = 0; i < groups.length; i++) result = result.concat(groups[i]);
			return result;
		});
	});
}
function _asyncMkdirSimple(native, path, options) {
	var recursive = false;
	var mode;
	if (typeof options === "object" && options !== null) {
		_validateMkdirRecursiveOption(options);
		recursive = options.recursive === true;
		mode = options.mode;
	} else if (typeof options === "string" || typeof options === "number") mode = options;
	if (mode !== void 0) mode = _coerceMode(mode) & 511;
	if (recursive) _guardClosedFsMutation("mkdir", path);
	var p = _pathToString(path);
	return _asyncFsPathOp(native, "mkdir", [
		_nativeMkdirPath(p),
		null,
		recursive ? 1 : 0,
		mode === void 0 ? -1 : mode
	], "mkdir", p).then(function(createdPath) {
		return recursive && createdPath ? createdPath : void 0;
	});
}
function _asyncMkdtempResult(native, prefix, options) {
	_validatePath(prefix, "prefix");
	_validateEncodingOption(options);
	_guardClosedFsMutation("mkdtemp", prefix);
	var prefixPath = _pathToString(prefix);
	var rawPrefix = typeof prefix === "string" ? prefix : typeof Buffer !== "undefined" && Buffer.isBuffer(prefix) ? prefix.toString() : null;
	return _asyncFsPathOp(native, "mkdtemp", [prefixPath], "mkdtemp", prefix).then(function(createdPath) {
		return {
			actualPath: createdPath,
			publicPath: rawPrefix !== null && !_isAbsolutePath(rawPrefix) ? relativePathFromCwd(createdPath) : createdPath
		};
	});
}
function _normalizeWatchOptions(options) {
	if (options === void 0 || options === null) return {};
	if (typeof options === "string") {
		_assertEncoding(options);
		return { encoding: options };
	}
	if (typeof options !== "object") throw _fsInvalidArgType("options", "string or an object", options);
	_validateEncodingOption(options);
	if (options.recursive !== void 0 && typeof options.recursive !== "boolean") throw _fsInvalidArgType("options.recursive", "boolean", options.recursive);
	if (options.persistent !== void 0 && typeof options.persistent !== "boolean") throw _fsInvalidArgType("options.persistent", "boolean", options.persistent);
	if (options.signal !== void 0 && options.signal !== null && (typeof options.signal !== "object" || typeof options.signal.addEventListener !== "function")) throw _fsInvalidArgType("options.signal", "AbortSignal", options.signal);
	return _extend({}, options);
}
function _normalizeWatchFileOptions(path, options) {
	options = _normalizeWatchOptions(options);
	if (options.signal && options.signal.aborted === true) throw _makeAbortError(options.signal.reason);
	if (options.maxQueue !== void 0) {
		if (typeof options.maxQueue !== "number") throw _fsInvalidArgTypeProperty("options.maxQueue", "number", options.maxQueue);
		if (!Number.isFinite(options.maxQueue) || options.maxQueue % 1 !== 0) throw _fsInvalidArgValue("options.maxQueue", options.maxQueue, "a number");
		if (options.maxQueue < 0) throw _fsInvalidArgValue("options.maxQueue", options.maxQueue, "a non-negative number");
	}
	if (options.overflow !== void 0) {
		if (options.overflow !== "error" && options.overflow !== "ignore") throw _fsInvalidArgValue("options.overflow", options.overflow, "one of \"ignore\", \"error\"");
	}
	return options;
}
function _checkForAbortedSignal(options) {
	if (options && typeof options === "object" && options.signal && options.signal.aborted === true) throw _makeAbortError();
}
function _normalizeWriteOptions(options) {
	if (options === void 0 || options === null) return {};
	if (typeof options === "string") {
		_assertEncoding(options);
		return { encoding: options };
	}
	if (typeof options !== "object") throw _fsInvalidArgType("options", "string or an object", options);
	_validateEncodingOption(options);
	_validateFlushOption(options.flush);
	_checkForAbortedSignal(options);
	return _extend({}, options);
}
function _normalizeReadFileOptions(options, allowSignal) {
	if (options === void 0 || options === null) return {};
	if (typeof options === "string") {
		_assertEncoding(options);
		return { encoding: options };
	}
	if (typeof options !== "object") throw _fsInvalidArgType("options", "string or an object", options);
	_validateEncodingOption(options);
	if (allowSignal && options.signal !== void 0 && options.signal !== null && (typeof options.signal !== "object" || typeof options.signal.addEventListener !== "function")) throw _fsInvalidArgType("options.signal", "AbortSignal", options.signal);
	return _extend({}, options);
}
function _validateEncodingOption(options) {
	var encoding = typeof options === "string" ? options : options && options.encoding;
	if (encoding === void 0 || encoding === null) return;
	if (typeof encoding !== "string") {
		var err = /* @__PURE__ */ new TypeError("The argument '" + encoding + "' is invalid encoding. Received 'encoding'");
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
	_assertEncoding(encoding);
}
function _validateMkdirRecursiveOption(options) {
	if (options && typeof options === "object" && options.recursive !== void 0 && typeof options.recursive !== "boolean") {
		var err = _fsInvalidArgType("options.recursive", "boolean", options.recursive);
		err.message = err.message.replace(" argument", " property");
		throw err;
	}
}
function _isAsyncIterable(value) {
	if (!value || typeof value !== "object") return false;
	if (typeof Symbol === "undefined" || !Symbol.asyncIterator) return false;
	return typeof value[Symbol.asyncIterator] === "function";
}
function _isSyncIterable(value) {
	if (!value || typeof value !== "object") return false;
	if (typeof Symbol === "undefined" || !Symbol.iterator) return false;
	return typeof value[Symbol.iterator] === "function";
}
function _coerceWriteFileChunk(value, encoding) {
	if (typeof value === "string" || _isBufferLike(value) || typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return toUint8Array(value, encoding);
	throw _fsInvalidArgType("data", "string or an instance of Buffer, TypedArray, or DataView", value);
}
function _writeFileFromSyncIterable(fd, iterable, encoding) {
	var iterator = iterable[Symbol.iterator]();
	while (true) {
		var step = iterator.next();
		if (step.done) break;
		_writeAllSync(fd, _coerceWriteFileChunk(step.value, encoding), -1);
	}
}
function _writeFileFromAsyncIterable(fd, iterable, encoding) {
	var iterator = iterable[Symbol.asyncIterator]();
	return Promise.resolve().then(function readNext() {
		return Promise.resolve(iterator.next()).then(function(step) {
			if (!step || step.done) return;
			_writeAllSync(fd, _coerceWriteFileChunk(step.value, encoding), -1);
			return readNext();
		});
	});
}
function _writeFileToDescriptor(fd, data, options) {
	var encoding = options && options.encoding;
	if (_isAsyncIterable(data)) return _writeFileFromAsyncIterable(fd, data, encoding);
	if (_isSyncIterable(data) && typeof data !== "string" && !_isBufferLike(data)) {
		_writeFileFromSyncIterable(fd, data, encoding);
		if (options && options.flush === true) _callFsyncSync(fd);
		return Promise.resolve();
	}
	_writeAllSync(fd, _coerceWriteFileChunk(data, encoding), -1);
	if (options && options.flush === true) _callFsyncSync(fd);
	return Promise.resolve();
}
function _promisesWriteFile(target, data, options) {
	var writeOptions;
	try {
		writeOptions = _normalizeWriteOptions(options);
	} catch (err) {
		return Promise.reject(err);
	}
	var targetInfo = _getFdOrPath(target, "path");
	var signal = writeOptions && writeOptions.signal;
	if (signal && signal.aborted === true) return Promise.reject(_makeAbortError());
	var asyncNative = _fsAsyncNative("__exactFsWriteFileAsync");
	if (asyncNative) try {
		return _asyncWriteFileImpl(asyncNative, targetInfo, data, writeOptions, "w").then(function() {
			if (signal && signal.aborted === true) throw _makeAbortError(signal.reason);
		});
	} catch (err) {
		if (err && typeof err.code === "string" && err.code.indexOf("ERR_") === 0) return Promise.reject(err);
		return Promise.reject(_makeFsError(err, "open", targetInfo.path));
	}
	var fd = targetInfo.fd;
	var needsClose = false;
	if (fd === null) {
		fd = openSync(targetInfo.path, writeOptions.flag || writeOptions.flags || "w", writeOptions.mode);
		needsClose = true;
	}
	return _writeFileToDescriptor(fd, data, writeOptions).then(function() {
		if (needsClose) closeSync(fd);
	}, function(err) {
		if (needsClose) try {
			closeSync(fd);
		} catch (e) {}
		throw err;
	});
}
function _validateFsOptions(optionName, value, requiredMethods) {
	if (value === void 0) return;
	if (value === null || typeof value !== "object") throw _fsInvalidArgTypeProperty(optionName, "Object", value);
	for (var i = 0; i < requiredMethods.length; i++) {
		var method = requiredMethods[i];
		var actual = value[method];
		if (actual === void 0) continue;
		if (typeof actual !== "function") throw _fsInvalidArgTypeProperty(optionName + "." + method, "function", actual);
	}
}
function _getCurrentExport(name) {
	return typeof module !== "undefined" && module.exports && module.exports[name] || null;
}
function _callOpenSync(path, flags, mode) {
	var fn = _getCurrentExport("openSync");
	if (typeof fn === "function" && fn !== openSync) return fn(path, flags, mode);
	return openSync(path, flags, mode);
}
function _callCloseSync(fd) {
	var fn = _getCurrentExport("closeSync");
	if (typeof fn === "function" && fn !== closeSync) return fn(fd);
	return closeSync(fd);
}
function _callWriteSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
	var fn = _getCurrentExport("writeSync");
	if (typeof fn === "function" && fn !== writeSync) return fn(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position);
	return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position);
}
function _coercePartialWriteError(err, bytesWritten) {
	if (!(bytesWritten > 0) || !err || typeof err !== "object") return err;
	var message = typeof err.message === "string" ? err.message : "";
	if ((typeof err.code === "string" ? err.code : "") !== "UNKNOWN" && message.indexOf("unknown error, write") === -1) return err;
	var writeErr = /* @__PURE__ */ new Error("EFBIG: file too large, write");
	writeErr.code = "EFBIG";
	writeErr.errno = -_uvErrnoMap.EFBIG;
	writeErr.syscall = "write";
	return writeErr;
}
function _writeAllSync(fd, bytes, position) {
	var offset = 0;
	var currentPosition = position;
	while (offset < bytes.length) {
		var written;
		try {
			written = _callWriteSync(fd, bytes, offset, bytes.length - offset, currentPosition);
		} catch (err) {
			if (_getFsErrorCode(err) === "EINTR") continue;
			throw _coercePartialWriteError(err, offset);
		}
		if (typeof written !== "number" || written <= 0) {
			var err = /* @__PURE__ */ new Error("write returned zero bytes");
			err.code = "EIO";
			throw err;
		}
		offset += written;
		if (typeof currentPosition === "number" && currentPosition >= 0) currentPosition += written;
	}
}
var _exactInternalFsBinding;
var _exactDefaultWriteFileUtf8;
function _getInternalFsBinding() {
	if (_exactInternalFsBinding !== void 0) return _exactInternalFsBinding;
	var binding = null;
	try {
		var testBinding = require("internal/test/binding");
		if (testBinding && typeof testBinding.internalBinding === "function") binding = testBinding.internalBinding("fs");
	} catch (_err) {}
	if (binding && _exactDefaultWriteFileUtf8 === void 0) _exactDefaultWriteFileUtf8 = binding.writeFileUtf8;
	_exactInternalFsBinding = binding;
	return binding;
}
function _shouldUseSyncUtf8FastPath(data, options) {
	if (typeof data !== "string") return false;
	if (options && options.flush === true) return false;
	var encoding = options && options.encoding;
	return encoding === void 0 || encoding === null || encoding === "utf8" || encoding === "utf-8";
}
function _hasCustomSyncUtf8FastPath(binding) {
	return !!(binding && typeof binding.writeFileUtf8 === "function" && binding.writeFileUtf8 !== _exactDefaultWriteFileUtf8);
}
function _callFsync(fd, callback) {
	var fn = _getCurrentExport("fsync");
	if (typeof fn === "function") return fn(fd, callback);
	return fsync(fd, callback);
}
function _callFsyncSync(fd) {
	var fn = _getCurrentExport("fsyncSync");
	if (typeof fn === "function") return fn(fd);
	return fsyncSync(fd);
}
function toUint8Array(data, encoding) {
	if (typeof data === "string") {
		if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.from(data, encoding || "utf8");
		if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(data);
		var buf = new Uint8Array(data.length * 3);
		var offset = 0;
		for (var i = 0; i < data.length; i++) {
			var code = data.charCodeAt(i);
			if (code < 128) buf[offset++] = code;
			else if (code < 2048) {
				buf[offset++] = 192 | code >> 6;
				buf[offset++] = 128 | code & 63;
			} else {
				buf[offset++] = 224 | code >> 12;
				buf[offset++] = 128 | code >> 6 & 63;
				buf[offset++] = 128 | code & 63;
			}
		}
		return buf.slice(0, offset);
	}
	if (data instanceof Uint8Array) return data;
	if (typeof ArrayBuffer !== "undefined") {
		if (data instanceof ArrayBuffer) return new Uint8Array(data);
		if (typeof ArrayBuffer.isView === "function" && ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength);
	}
	return new Uint8Array(data);
}
function decodeBytes(bytes, encoding) {
	if (!encoding || encoding === "buffer") return bytes;
	var enc = encoding.toLowerCase().replace("-", "");
	if (enc === "utf8" || enc === "utf-8") enc = "utf8";
	if (enc === "utf8") {
		if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
			var _copy = Buffer.alloc(bytes.byteLength);
			_copy.set(new Uint8Array(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength));
			return _copy.toString("utf8");
		}
		if (typeof TextDecoder !== "undefined") try {
			return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
		} catch (_utf8DecodeErr) {
			return new TextDecoder("utf-8").decode(bytes);
		}
		var result = "";
		for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
		return result;
	}
	if (enc === "utf16le" || enc === "ucs2") {
		if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
			var utf16Copy = Buffer.alloc(bytes.byteLength);
			utf16Copy.set(new Uint8Array(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength));
			return utf16Copy.toString("utf16le");
		}
		if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-16le").decode(bytes);
	}
	if (enc === "ascii" || enc === "latin1" || enc === "binary") {
		var result = "";
		for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
		return result;
	}
	if (enc === "hex") {
		var result = "";
		for (var i = 0; i < bytes.length; i++) result += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
		return result;
	}
	if (enc === "base64") {
		var binary = "";
		for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
		return typeof btoa === "function" ? btoa(binary) : binary;
	}
	if (typeof TextDecoder !== "undefined") return new TextDecoder(encoding).decode(bytes);
	var result = "";
	for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
	return result;
}
function wrapBuffer(bytes) {
	if (typeof Buffer !== "undefined" && Buffer.from) return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
	bytes.toString = function(encoding, start, end) {
		var slice = start !== void 0 || end !== void 0 ? bytes.slice(start || 0, end) : bytes;
		if (!encoding) return decodeBytes(slice, "utf8");
		return decodeBytes(slice, encoding);
	};
	return bytes;
}
function _encodeFsPathResult(value, options) {
	var encoding = typeof options === "string" ? options : options && options.encoding;
	if (!encoding || encoding === "utf8" || encoding === "utf-8") return value;
	if (encoding === "buffer") {
		if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.from(value);
		return toUint8Array(value);
	}
	return decodeBytes(toUint8Array(value), encoding);
}
function _throwIfReadFileTooLarge(stat) {
	if (stat && typeof stat.size === "number" && stat.size > 2147483647) throw _makeFileTooLargeError(stat.size);
}
function readFileSync(path, options) {
	var readOptions = _normalizeReadFileOptions(options, false);
	if (typeof path === "number") {
		ensureExactFs();
		var encoding = readOptions.encoding;
		try {
			_throwIfReadFileTooLarge(fstatSync(path));
		} catch (sizeErr) {
			if (sizeErr && sizeErr.code === "ERR_FS_FILE_TOO_LARGE") throw sizeErr;
		}
		var chunks = [];
		var buf = new Uint8Array(65536);
		var bytesRead;
		do {
			bytesRead = readSync(path, buf, 0, buf.length, -1);
			if (bytesRead > 0) chunks.push(buf.slice(0, bytesRead));
		} while (bytesRead > 0);
		var totalLen = 0;
		for (var ci = 0; ci < chunks.length; ci++) totalLen += chunks[ci].length;
		var result = new Uint8Array(totalLen);
		var pos = 0;
		for (var cj = 0; cj < chunks.length; cj++) {
			result.set(chunks[cj], pos);
			pos += chunks[cj].length;
		}
		if (encoding) return decodeBytes(result, encoding);
		return wrapBuffer(result);
	}
	_validatePath(path);
	ensureExactFs();
	var p = _pathToString(path);
	var encoding = readOptions.encoding;
	var fd;
	try {
		fd = openSync(p, readOptions.flag || readOptions.flags || "r", readOptions.mode);
	} catch (e) {
		throw _makeFsError(e, "open", p);
	}
	try {
		_throwIfReadFileTooLarge(fstatSync(fd));
		var chunks = [];
		var fileBuffer = new Uint8Array(65536);
		var fileBytesRead;
		do {
			fileBytesRead = readSync(fd, fileBuffer, 0, fileBuffer.length, -1);
			if (fileBytesRead > 0) chunks.push(fileBuffer.slice(0, fileBytesRead));
		} while (fileBytesRead > 0);
		var totalLen = 0;
		for (var fileChunkIndex = 0; fileChunkIndex < chunks.length; fileChunkIndex++) totalLen += chunks[fileChunkIndex].length;
		var fileResult = new Uint8Array(totalLen);
		var filePos = 0;
		for (var fileChunk = 0; fileChunk < chunks.length; fileChunk++) {
			fileResult.set(chunks[fileChunk], filePos);
			filePos += chunks[fileChunk].length;
		}
		if (encoding) return decodeBytes(fileResult, encoding);
		return wrapBuffer(fileResult);
	} catch (e) {
		if (e && typeof e.code === "string" && e.code.indexOf("ERR_") === 0) throw e;
		throw _makeFsError(e, "read", p);
	} finally {
		try {
			closeSync(fd);
		} catch (_ignore) {}
	}
}
function writeFileSync(path, data, options) {
	_validateWriteData(data);
	var writeOptions = _normalizeWriteOptions(options);
	if (typeof path === "number") {
		ensureExactFs();
		_writeAllSync(path, toUint8Array(data, writeOptions.encoding), -1);
		if (writeOptions.flush === true) _callFsyncSync(path);
		return;
	}
	_validatePath(path);
	ensureExactFs();
	var p = _pathToString(path);
	if (_shouldUseSyncUtf8FastPath(data, writeOptions)) {
		var binding = _getInternalFsBinding();
		if (_hasCustomSyncUtf8FastPath(binding)) return binding.writeFileUtf8(p, data, writeOptions.flag || writeOptions.flags || "w", writeOptions.mode);
	}
	try {
		var writeData = toUint8Array(data, writeOptions.encoding);
		var writeFd = _callOpenSync(p, writeOptions.flag || writeOptions.flags || "w", writeOptions.mode);
	} catch (e) {
		throw _makeFsError(e, "open", p);
	}
	try {
		_writeAllSync(writeFd, writeData, -1);
		if (writeOptions.flush === true) _callFsyncSync(writeFd);
	} catch (e) {
		throw _makeFsError(e, "write", p);
	} finally {
		_callCloseSync(writeFd);
	}
}
function _validateWriteData(data) {
	if (typeof data !== "string" && !_isBufferLike(data)) throw _fsInvalidArgType("data", "string or an instance of Buffer, TypedArray, or DataView", data);
}
function appendFileSync(path, data, options) {
	_validateWriteData(data);
	var writeOptions = _normalizeWriteOptions(options);
	var target = _getFdOrPath(path, "path");
	if (target.fd !== null) {
		ensureExactFs();
		var fdData = toUint8Array(data, writeOptions.encoding);
		_writeAllSync(target.fd, fdData, -1);
		if (writeOptions.flush === true) _callFsyncSync(target.fd);
		return;
	}
	ensureExactFs();
	var p = target.path;
	if (_shouldUseSyncUtf8FastPath(data, writeOptions)) {
		var appendBinding = _getInternalFsBinding();
		if (_hasCustomSyncUtf8FastPath(appendBinding)) return appendBinding.writeFileUtf8(p, data, writeOptions.flag || writeOptions.flags || "a", writeOptions.mode);
	}
	try {
		var appendData = toUint8Array(data, writeOptions.encoding);
		var appendFallbackFd = _callOpenSync(p, writeOptions.flag || writeOptions.flags || "a", writeOptions.mode);
	} catch (e) {
		throw _makeFsError(e, "open", p);
	}
	try {
		_writeAllSync(appendFallbackFd, appendData, -1);
		if (writeOptions.flush === true) _callFsyncSync(appendFallbackFd);
	} catch (e) {
		throw _makeFsError(e, "write", p);
	} finally {
		_callCloseSync(appendFallbackFd);
	}
}
function _coerceStatsValue(raw, useBigInt) {
	if (useBigInt) {
		if (typeof raw === "bigint") return raw;
		return BigInt(raw || 0);
	}
	return raw || 0;
}
var _internalFsUtilsBigIntStats;
function _getInternalBigIntStats() {
	if (_internalFsUtilsBigIntStats === void 0) {
		var ctor = null;
		try {
			var fsUtils = require("internal/fs/utils");
			if (fsUtils && typeof fsUtils.BigIntStats === "function") ctor = fsUtils.BigIntStats;
		} catch (e) {}
		_internalFsUtilsBigIntStats = ctor;
	}
	return _internalFsUtilsBigIntStats;
}
function _coerceToBigInt(raw) {
	if (typeof raw === "bigint") return raw;
	if (typeof raw === "number" && !isNaN(raw)) return BigInt(raw);
	return BigInt("0");
}
function _coerceStatsMillisecondsToBigInt(msValue, nsValue) {
	if (typeof nsValue === "bigint") return nsValue / BigInt("1000000");
	if (typeof nsValue === "number" && !isNaN(nsValue)) return BigInt(Math.floor(nsValue / 1e6));
	if (typeof msValue === "bigint") return msValue;
	if (typeof msValue === "number" && !isNaN(msValue)) return BigInt(Math.floor(msValue));
	return BigInt("0");
}
function _coerceStatsMilliseconds(msValue, nsValue, useBigInt) {
	if (useBigInt) return _coerceStatsMillisecondsToBigInt(msValue, nsValue);
	if (typeof nsValue === "bigint") return Number(nsValue / BigInt("1000000"));
	if (typeof nsValue === "number" && !isNaN(nsValue)) return Math.floor(nsValue / 1e6);
	if (typeof msValue === "number" && !isNaN(msValue)) return Math.floor(msValue);
	return msValue || 0;
}
function _coalesceStatsField(value, fallback) {
	return value === void 0 || value === null ? fallback : value;
}
function _makeBigIntStats(raw) {
	var ctor = _getInternalBigIntStats();
	if (typeof ctor !== "function") return new Stats(raw || {}, true);
	if (typeof ctor.prototype.isFile !== "function") Object.defineProperties(ctor.prototype, {
		isFile: {
			value: Stats.prototype.isFile,
			configurable: true,
			writable: true
		},
		isDirectory: {
			value: Stats.prototype.isDirectory,
			configurable: true,
			writable: true
		},
		isSymbolicLink: {
			value: Stats.prototype.isSymbolicLink,
			configurable: true,
			writable: true
		},
		isBlockDevice: {
			value: Stats.prototype.isBlockDevice,
			configurable: true,
			writable: true
		},
		isCharacterDevice: {
			value: Stats.prototype.isCharacterDevice,
			configurable: true,
			writable: true
		},
		isFIFO: {
			value: Stats.prototype.isFIFO,
			configurable: true,
			writable: true
		},
		isSocket: {
			value: Stats.prototype.isSocket,
			configurable: true,
			writable: true
		}
	});
	var safe = raw || {};
	var mt = safe.mtime_ms || safe.mtimeMs || 0;
	var at = safe.atime_ms || safe.atimeMs || mt;
	var ct = safe.ctime_ms || safe.ctimeMs || mt;
	var bt = safe.birthtime_ms || safe.birthtimeMs || mt;
	var atNs = safe.atime_ns || safe.atimeNs || 0;
	var mtNs = safe.mtime_ns || safe.mtimeNs || 0;
	var ctNs = safe.ctime_ns || safe.ctimeNs || 0;
	var btNs = safe.birthtime_ns || safe.birthtimeNs || 0;
	var stats = new ctor(_coerceToBigInt(safe.dev), _coerceToBigInt(safe.mode), _coerceToBigInt(_coalesceStatsField(safe.nlink, 1)), _coerceToBigInt(safe.uid), _coerceToBigInt(safe.gid), _coerceToBigInt(safe.rdev), _coerceToBigInt(_coalesceStatsField(safe.blksize, 4096)), _coerceToBigInt(safe.ino), _coerceToBigInt(safe.size), _coerceToBigInt(safe.blocks), _coerceStatsMillisecondsToBigInt(at, atNs), _coerceStatsMillisecondsToBigInt(mt, mtNs), _coerceStatsMillisecondsToBigInt(ct, ctNs), _coerceStatsMillisecondsToBigInt(bt, btNs), _coerceToBigInt(atNs), _coerceToBigInt(mtNs), _coerceToBigInt(ctNs), _coerceToBigInt(btNs));
	stats._isFile = !!safe.is_file;
	stats._isDir = !!safe.is_dir;
	stats._isSymlink = !!safe.is_symlink;
	stats._isChrDev = !!safe.is_char_device;
	stats._isBlkDev = !!safe.is_block_device;
	stats._isFifo = !!safe.is_fifo;
	stats._isSock = !!safe.is_socket;
	return stats;
}
function _coerceStatsDate(raw) {
	return new Date(raw || 0);
}
function Stats(raw, useBigInt) {
	var toValue = useBigInt ? _coerceStatsValue : function(v) {
		return v || 0;
	};
	this.dev = toValue(raw.dev);
	this.ino = toValue(raw.ino);
	this.mode = toValue(raw.mode);
	this.nlink = toValue(_coalesceStatsField(raw.nlink, 1));
	this.uid = toValue(raw.uid);
	this.gid = toValue(raw.gid);
	this.rdev = toValue(raw.rdev);
	this.size = toValue(raw.size);
	this.blksize = toValue(_coalesceStatsField(raw.blksize, 4096));
	this.blocks = toValue(raw.blocks);
	var mt = raw.mtime_ms || raw.mtimeMs || 0;
	var at = raw.atime_ms || raw.atimeMs || mt;
	var ct = raw.ctime_ms || raw.ctimeMs || mt;
	var bt = raw.birthtime_ms || raw.birthtimeMs || mt;
	var atNs = raw.atime_ns || raw.atimeNs || 0;
	var mtNs = raw.mtime_ns || raw.mtimeNs || 0;
	var ctNs = raw.ctime_ns || raw.ctimeNs || 0;
	var btNs = raw.birthtime_ns || raw.birthtimeNs || 0;
	this.atimeMs = _coerceStatsMilliseconds(at, atNs, useBigInt);
	this.mtimeMs = _coerceStatsMilliseconds(mt, mtNs, useBigInt);
	this.ctimeMs = _coerceStatsMilliseconds(ct, ctNs, useBigInt);
	this.birthtimeMs = _coerceStatsMilliseconds(bt, btNs, useBigInt);
	this.atimeNs = toValue(atNs);
	this.mtimeNs = toValue(mtNs);
	this.ctimeNs = toValue(ctNs);
	this.birthtimeNs = toValue(btNs);
	this.atime = _coerceStatsDate(Number(at));
	this.mtime = _coerceStatsDate(Number(mt));
	this.ctime = _coerceStatsDate(Number(ct));
	this.birthtime = _coerceStatsDate(Number(bt));
	this._isFile = !!raw.is_file;
	this._isDir = !!raw.is_dir;
	this._isSymlink = !!raw.is_symlink;
	this._isChrDev = !!raw.is_char_device;
	this._isBlkDev = !!raw.is_block_device;
	this._isFifo = !!raw.is_fifo;
	this._isSock = !!raw.is_socket;
}
Stats.prototype.isFile = function() {
	return this._isFile;
};
Stats.prototype.isDirectory = function() {
	return this._isDir;
};
Stats.prototype.isSymbolicLink = function() {
	return this._isSymlink;
};
Stats.prototype.isBlockDevice = function() {
	return this._isBlkDev;
};
Stats.prototype.isCharacterDevice = function() {
	return this._isChrDev;
};
Stats.prototype.isFIFO = function() {
	return this._isFifo;
};
Stats.prototype.isSocket = function() {
	return this._isSock;
};
function _makeStats(json, opts) {
	var raw = JSON.parse(json);
	return _extractStatOptions(opts).bigint ? _makeBigIntStats(raw) : new Stats(raw, false);
}
function _coerceStatOptions(options) {
	if (options === void 0 || options === null) return {};
	if (typeof options !== "object") throw _fsInvalidArgType("options", "Object", options);
	return options;
}
function _extractStatOptions(options) {
	var opts = _coerceStatOptions(options);
	return {
		bigint: !!opts.bigint,
		throwIfNoEntry: opts.throwIfNoEntry === false ? false : true
	};
}
function StatFs(raw, useBigInt) {
	var toBigInt = useBigInt ? function(v) {
		return BigInt(v);
	} : function(v) {
		return Number(v);
	};
	this.type = toBigInt(raw.type || 0);
	this.bsize = toBigInt(raw.bsize || 0);
	this.blocks = toBigInt(raw.blocks || 0);
	this.bfree = toBigInt(raw.bfree || 0);
	this.bavail = toBigInt(raw.bavail || 0);
	this.files = toBigInt(raw.files || 0);
	this.ffree = toBigInt(raw.ffree || 0);
}
function statSync(path, options) {
	_validatePath(path);
	ensureExactFs();
	_coerceStatOptions(options);
	var p = _pathToString(path);
	var opts = _extractStatOptions(options);
	try {
		return _makeStats(g.__exactStat(p), opts);
	} catch (e) {
		if (opts.throwIfNoEntry === false && _getFsErrorCode(e) === "ENOENT") return;
		throw _makeFsError(e, "stat", p);
	}
}
function lstatSync(path, options) {
	_validatePath(path);
	ensureExactFs();
	_coerceStatOptions(options);
	var p = _pathToString(path);
	var opts = _extractStatOptions(options);
	try {
		return _makeStats(g.__exactLstat(p), opts);
	} catch (e) {
		if (opts.throwIfNoEntry === false && _getFsErrorCode(e) === "ENOENT") return;
		throw _makeFsError(e, "lstat", p);
	}
}
function Dirent(name, parentPath, stat) {
	var hasTypeCode = typeof parentPath === "number" && stat === void 0;
	this.name = name;
	this.parentPath = hasTypeCode ? "" : parentPath === void 0 ? "" : parentPath;
	this.path = this.parentPath;
	this._stat = hasTypeCode ? null : stat;
	this._type = hasTypeCode ? parentPath : 0;
}
function _direntTypeMatches(dirent, expectedType) {
	return dirent._type === expectedType;
}
Dirent.prototype.isFile = function() {
	return this._stat ? this._stat.isFile() : _direntTypeMatches(this, constants.UV_DIRENT_FILE);
};
Dirent.prototype.isDirectory = function() {
	return this._stat ? this._stat.isDirectory() : _direntTypeMatches(this, constants.UV_DIRENT_DIR);
};
Dirent.prototype.isSymbolicLink = function() {
	return this._stat ? this._stat.isSymbolicLink() : _direntTypeMatches(this, constants.UV_DIRENT_LINK);
};
Dirent.prototype.isBlockDevice = function() {
	return this._stat ? this._stat.isBlockDevice() : _direntTypeMatches(this, constants.UV_DIRENT_BLOCK);
};
Dirent.prototype.isCharacterDevice = function() {
	return this._stat ? this._stat.isCharacterDevice() : _direntTypeMatches(this, constants.UV_DIRENT_CHAR);
};
Dirent.prototype.isFIFO = function() {
	return this._stat ? this._stat.isFIFO() : _direntTypeMatches(this, constants.UV_DIRENT_FIFO);
};
Dirent.prototype.isSocket = function() {
	return this._stat ? this._stat.isSocket() : _direntTypeMatches(this, constants.UV_DIRENT_SOCKET);
};
function _normalizeDirEntryName(name, encoding) {
	if (encoding === "buffer") {
		if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.isBuffer(name) ? name : Buffer.from(name);
		return toUint8Array(name);
	}
	return name;
}
function _buildDirEntries(path, options) {
	var recursive = options && options.recursive;
	var encoding = options && options.encoding;
	var list = [];
	var dirPath = _pathToString(path);
	var raw = readdirSync(dirPath, {
		withFileTypes: false,
		encoding
	});
	for (var i = 0; i < raw.length; i++) {
		var name = raw[i];
		var fullPath = pathJoin(dirPath, name);
		var stat = null;
		try {
			stat = lstatSync(fullPath);
		} catch (e) {}
		var entry = new Dirent(_normalizeDirEntryName(name, encoding), dirPath, stat);
		entry.path = dirPath;
		list.push(entry);
		if (recursive && stat && typeof stat.isDirectory === "function" && stat.isDirectory()) {
			var nested = _buildDirEntries(fullPath, options);
			for (var j = 0; j < nested.length; j++) list.push(nested[j]);
		}
	}
	return list;
}
function Dir(path, options) {
	if (arguments.length === 0) {
		var missingArgsErr = /* @__PURE__ */ new TypeError("The \"path\" argument must be specified");
		missingArgsErr.code = "ERR_MISSING_ARGS";
		throw missingArgsErr;
	}
	this._path = path;
	this._entries = _buildDirEntries(path, options || {});
	this._index = 0;
	this._closed = false;
	this._closing = false;
	this._asyncReads = 0;
	this._closeCallbacks = [];
}
function _dirFromEntries(path, entries) {
	var dir = Object.create(Dir.prototype);
	dir._path = path;
	dir._entries = entries;
	dir._index = 0;
	dir._closed = false;
	dir._closing = false;
	dir._asyncReads = 0;
	dir._closeCallbacks = [];
	return dir;
}
Object.defineProperty(Dir.prototype, "path", {
	get: function() {
		if (!(this instanceof Dir)) throw _makeFsThisError("path");
		return this._path;
	},
	set: function(value) {
		if (!(this instanceof Dir)) throw _makeFsThisError("path");
		this._path = value;
	},
	configurable: true
});
function _ensureDirReadableState(dir) {
	if (dir._closed) throw _makeDirClosedError(dir._path);
	if (dir._asyncReads > 0) throw _makeDirConcurrentOperationError(dir._path);
	if (dir._closing) throw _makeDirClosedError(dir._path);
}
function _completeDirClose(dir, error) {
	dir._closed = true;
	dir._closing = false;
	var callbacks = dir._closeCallbacks || [];
	dir._closeCallbacks = [];
	if (!error) {
		for (var i = 0; i < callbacks.length; i++) _deferFsCallback((function(cb) {
			return function() {
				cb(null);
			};
		})(callbacks[i]));
		return;
	}
	for (var j = 0; j < callbacks.length; j++) _deferFsCallback((function(cb, e) {
		return function() {
			cb(e);
		};
	})(callbacks[j], error));
}
function _drainDirReadResult(dir, callback, err, value) {
	dir._asyncReads -= 1;
	if (!dir._closed && dir._closing && dir._asyncReads === 0) _completeDirClose(dir, null);
	_deferFsCallback(function() {
		callback(err, value);
	});
}
Dir.prototype.readSync = function() {
	_ensureDirReadableState(this);
	if (this._index >= this._entries.length) return null;
	return this._entries[this._index++];
};
Dir.prototype._nextEntry = function() {
	if (this._index >= this._entries.length) return null;
	return this._entries[this._index++];
};
Dir.prototype.read = function(callback) {
	if (typeof callback === "undefined") {
		var self = this;
		return new Promise(function(resolve, reject) {
			try {
				self.read(function(err, value) {
					if (err) reject(err);
					else resolve(value);
				});
			} catch (err) {
				reject(err);
			}
		});
	}
	_validateCallback(callback);
	if (this._closed || this._closing) return _deferFsCallback(function() {
		callback(_makeDirClosedError(this._path));
	}.bind(this));
	this._asyncReads += 1;
	_deferFsCallback(function() {
		var err = null;
		var value = null;
		try {
			value = this._nextEntry();
		} catch (e) {
			err = e;
		}
		_drainDirReadResult(this, callback, err, value);
	}.bind(this));
};
Dir.prototype.close = function(callback) {
	if (typeof callback === "undefined") {
		var self = this;
		return new Promise(function(resolve, reject) {
			try {
				self.close(function(err) {
					if (err) reject(err);
					else resolve();
				});
			} catch (err) {
				reject(err);
			}
		});
	}
	if (callback !== void 0 && callback !== null) _validateCallback(callback);
	if (this._closed || this._closing) {
		if (typeof callback === "function") _deferFsCallback(function() {
			callback(_makeDirClosedError(this._path));
		}.bind(this));
		return;
	}
	this._closing = true;
	if (typeof callback === "function") this._closeCallbacks.push(callback);
	if (this._asyncReads === 0) _completeDirClose(this, null);
};
Dir.prototype.closeSync = function() {
	if (this._closed || this._closing) throw _makeDirClosedError(this._path);
	if (this._asyncReads > 0) throw _makeDirConcurrentOperationError(this._path);
	this._closed = true;
};
Dir.prototype[Symbol.asyncIterator] = function() {
	var self = this;
	return {
		next: function() {
			return Promise.resolve().then(function() {
				var value;
				try {
					value = self.readSync();
				} catch (e) {
					return {
						done: true,
						value: void 0
					};
				}
				if (value === null) return { done: true };
				return {
					done: false,
					value
				};
			});
		},
		return: function() {
			return new Promise(function(resolve, reject) {
				try {
					self.close(function(err) {
						if (err) reject(err);
						else resolve({ done: true });
					});
				} catch (e) {
					if (e && e.code) reject(e);
					else reject(_makeDirConcurrentOperationError(self._path));
				}
			});
		}
	};
};
function opendirSync(path, options) {
	_validatePath(path);
	if (options && typeof options === "object") {
		if (options.encoding) _validateEncodingOption(options.encoding);
		if (Object.prototype.hasOwnProperty.call(options, "bufferSize")) {
			if (typeof options.bufferSize !== "number") throw _fsInvalidArgType("bufferSize", "number", options.bufferSize);
			_validateInt("bufferSize", options.bufferSize, 1, 2147483647);
		}
	}
	return new Dir(path, options);
}
function opendir(path, options, cb) {
	var opts, callback;
	if (typeof options === "function") {
		callback = options;
		options = {};
	} else {
		opts = options;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) return _deferFsPromiseCallback(_asyncBuildDirEntries(native, _pathToString(path), opts || {}).then(function(entries) {
		return _dirFromEntries(path, entries);
	}), callback);
	wrapCallback(function() {
		return opendirSync(path, opts);
	}, callback, "opendir", _pathToString(path));
}
function readdirSync(path, options) {
	_validatePath(path);
	_validateEncodingOption(options);
	ensureExactFs();
	try {
		var p = _pathToString(path);
		var opts = typeof options === "string" ? { encoding: options } : options || {};
		var withFileTypes = !!opts.withFileTypes;
		var recursive = !!opts.recursive;
		var encoding = opts.encoding;
		var rawEntries = JSON.parse(g.__exactReaddir(p)).sort();
		var entries = rawEntries;
		if (encoding === "buffer") entries = rawEntries.map(function(e) {
			return toUint8Array(e);
		});
		else if (typeof encoding === "string" && encoding !== "utf8" && encoding !== "utf-8") entries = rawEntries.map(function(e) {
			return decodeBytes(toUint8Array(e), encoding);
		});
		if (!withFileTypes && !recursive) return entries;
		if (withFileTypes) {
			var dirents = [];
			for (var i = 0; i < entries.length; i++) {
				var fullPath = p + "/" + rawEntries[i];
				var st;
				try {
					st = lstatSync(fullPath);
				} catch (e) {
					st = null;
				}
				dirents.push(new Dirent(entries[i], p, st));
			}
			if (recursive) {
				var more = [];
				for (var j = 0; j < dirents.length; j++) if (dirents[j].isDirectory()) {
					var sub = readdirSync(p + "/" + rawEntries[j], {
						withFileTypes: true,
						recursive: true
					});
					for (var k = 0; k < sub.length; k++) more.push(sub[k]);
				}
				dirents = dirents.concat(more);
			}
			return dirents;
		}
		if (recursive) {
			var all = entries.slice();
			for (var ri = 0; ri < entries.length; ri++) {
				var rFullPath = p + "/" + rawEntries[ri];
				try {
					if (lstatSync(rFullPath).isDirectory()) {
						var rSub = readdirSync(rFullPath, { recursive: true });
						for (var rk = 0; rk < rSub.length; rk++) all.push(entries[ri] + "/" + rSub[rk]);
					}
				} catch (e) {}
			}
			return all;
		}
		return entries;
	} catch (e) {
		if (e && e.name === "RangeError" && e.message === "Maximum call stack size exceeded") throw e;
		throw _makeFsError(e, "scandir", p);
	}
}
function cpSync(src, dest, options) {
	_validatePath(src, "src");
	_validatePath(dest, "dest");
	_guardClosedFsMutation("cp", src, dest);
	options = options || {};
	var filter = options.filter;
	var recursive = !!options.recursive;
	var dereference = !!options.dereference;
	var errorOnExist = !!options.errorOnExist;
	var force = options.force !== false;
	var preserveTimestamps = !!options.preserveTimestamps;
	var srcPath = _pathToString(src);
	var destPath = _pathToString(dest);
	if (typeof filter !== "undefined" && typeof filter !== "function") throw _fsInvalidArgType("filter", "function", filter);
	if (typeof options.mode === "number") _validateUint32("mode", options.mode);
	if (typeof options.verbatimSymlinks !== "undefined" && typeof options.verbatimSymlinks !== "boolean") throw _fsInvalidArgType("verbatimSymlinks", "boolean", options.verbatimSymlinks);
	function shouldSkip(srcItem, destItem) {
		if (!filter) return false;
		return filter(srcItem, destItem) === false;
	}
	function _makeCpSpecialFileError(st, destination) {
		var code, message;
		if (typeof st.isSocket === "function" && st.isSocket()) {
			code = "ERR_FS_CP_SOCKET";
			message = "Cannot copy a socket file: " + destination;
		} else if (typeof st.isFIFO === "function" && st.isFIFO()) {
			code = "ERR_FS_CP_FIFO_PIPE";
			message = "Cannot copy a FIFO pipe: " + destination;
		} else {
			code = "ERR_FS_CP_UNKNOWN";
			message = "Cannot copy an unknown file type: " + destination;
		}
		var err = new Error(message);
		err.code = code;
		return err;
	}
	function copyOne(source, destination, atRoot) {
		if (filter && shouldSkip(source, destination)) return;
		var st = lstatSync(source);
		if (st.isSymbolicLink()) {
			if (dereference) {
				copyOne(realpathSync(source), destination, atRoot);
				return;
			}
			return symlinkSync(readlinkSync(source), destination);
		}
		if (st.isDirectory()) {
			if (!recursive) {
				var err = /* @__PURE__ */ new Error("EISDIR: illegal operation on a directory, copyfile '" + source + "' -> '" + destination + "'");
				err.code = "EISDIR";
				err.errno = _uvErrnoMap.EISDIR;
				throw err;
			}
			if (filter && shouldSkip(source, destination)) return;
			if (force && !existsSync(destination)) mkdirSync(destination, { recursive: true });
			else if (!existsSync(destination)) mkdirSync(destination, { recursive: true });
			else if (!lstatSync(destination).isDirectory()) {
				if (errorOnExist) {
					var err = /* @__PURE__ */ new Error("EEXIST: file already exists, mkdir '" + destination + "'");
					err.code = "EEXIST";
					err.errno = _uvErrnoMap.EEXIST;
					throw err;
				}
				rmSync(destination, {
					recursive: true,
					force: true
				});
				mkdirSync(destination);
			}
			var list = readdirSync(source, { withFileTypes: true });
			for (var i = 0; i < list.length; i++) {
				var childName = list[i].name;
				copyOne(pathJoin(source, childName), pathJoin(destination, childName), false);
			}
			return;
		}
		if (st.isFile() || st.isCharacterDevice() || st.isBlockDevice()) {
			var destExists = existsSync(destination);
			if (!force && destExists) {
				if (errorOnExist) {
					var alreadyErr = /* @__PURE__ */ new Error("EEXIST: file already exists, copyFile '" + source + "' -> '" + destination + "'");
					alreadyErr.code = "EEXIST";
					alreadyErr.errno = _uvErrnoMap.EEXIST;
					throw alreadyErr;
				}
				return;
			}
			if (destExists && force) unlinkSync(destination);
			var fd = openSync(source, "r");
			var outFd = openSync(destination, "w");
			try {
				var buf = Buffer.alloc(65536);
				var bytes = readSync(fd, buf, 0, buf.length, -1);
				while (bytes > 0) {
					var offset = 0;
					while (offset < bytes) {
						var written = writeSync(outFd, buf, offset, bytes - offset, -1);
						if (!(written > 0)) {
							var werr = /* @__PURE__ */ new Error("EIO: i/o error, copyfile '" + source + "' -> '" + destination + "'");
							werr.code = "EIO";
							werr.errno = _uvErrnoMap.EIO;
							throw werr;
						}
						offset += written;
					}
					bytes = readSync(fd, buf, 0, buf.length, -1);
				}
			} finally {
				closeSync(fd);
				closeSync(outFd);
			}
			chmodSync(destination, st.mode & 4095);
			if (preserveTimestamps) utimesSync(destination, st.atime, st.mtime);
			return;
		}
		if (atRoot) throw _makeCpSpecialFileError(st, destination);
	}
	copyOne(srcPath, destPath, true);
}
function cp(src, dest, options, cb) {
	if (typeof options === "function") {
		cb = options;
		options = {};
	}
	_validateCallback(cb);
	_deferFsPromiseCallback(_asyncCp(src, dest, options || {}), cb);
}
function _asyncCp(src, dest, options) {
	_validatePath(src, "src");
	_validatePath(dest, "dest");
	_guardClosedFsMutation("cp", src, dest);
	var source = _pathToString(src), destination = _pathToString(dest);
	var filter = options.filter;
	if (filter !== void 0 && typeof filter !== "function") throw _fsInvalidArgType("filter", "function", filter);
	function allowed(s, d) {
		return filter ? Promise.resolve(filter(s, d)).then(function(v) {
			return v !== false;
		}) : Promise.resolve(true);
	}
	function copyOne(s, d) {
		return allowed(s, d).then(function(ok) {
			if (!ok) return;
			return promises.lstat(s).then(function(st) {
				if (st.isSymbolicLink()) {
					if (options.dereference) return promises.realpath(s).then(function(real) {
						return copyOne(real, d);
					});
					return promises.readlink(s).then(function(target) {
						return promises.symlink(target, d);
					});
				}
				if (st.isDirectory()) {
					if (!options.recursive) {
						var e = /* @__PURE__ */ new Error("EISDIR: illegal operation on a directory, copyfile '" + s + "' -> '" + d + "'");
						e.code = "EISDIR";
						throw e;
					}
					return promises.mkdir(d, { recursive: true }).then(function() {
						return promises.readdir(s).then(function(names) {
							return names.reduce(function(chain, name) {
								return chain.then(function() {
									return copyOne(pathJoin(s, name), pathJoin(d, name));
								});
							}, Promise.resolve());
						});
					});
				}
				return promises.stat(d).then(function() {
					return true;
				}, function() {
					return false;
				}).then(function(exists) {
					if (exists && options.force === false) {
						if (options.errorOnExist) {
							var e = /* @__PURE__ */ new Error("EEXIST: file already exists");
							e.code = "EEXIST";
							throw e;
						}
						return;
					}
					return promises.copyFile(s, d, options.mode).then(function() {
						return promises.chmod(d, st.mode & 4095).then(function() {
							return options.preserveTimestamps ? promises.utimes(d, st.atime, st.mtime) : void 0;
						});
					});
				});
			});
		});
	}
	return copyOne(source, destination);
}
function statfsSync(path, options) {
	_validatePath(path);
	_validateEncodingOption(options);
	ensureExactFs();
	var p = _pathToString(path);
	if (!g.__exactStatfs) {
		var err = /* @__PURE__ */ new Error("ENOSYS: statfs is not supported");
		err.code = "ENOSYS";
		err.errno = _uvErrnoMap.ENOSYS;
		throw err;
	}
	try {
		var payload = g.__exactStatfs(p);
		return new StatFs(typeof payload === "string" ? JSON.parse(payload) : payload, options && options.bigint);
	} catch (e) {
		throw _makeFsError(e, "statfs", p);
	}
}
function statfs(path, options, cb) {
	if (typeof options === "function") {
		cb = options;
		options = void 0;
	}
	_validateCallback(cb);
	_validatePath(path);
	_validateEncodingOption(options);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "statfs", [p], "statfs", p).then(function(payload) {
			return new StatFs(typeof payload === "string" ? JSON.parse(payload) : payload, options && options.bigint);
		}), cb);
	}
	wrapCallback(function() {
		return statfsSync(path, options);
	}, cb, "statfs", _pathToString(path));
}
function _patternToRegex(pattern) {
	var escaped = "";
	var i = 0;
	while (i < pattern.length) {
		var ch = pattern.charAt(i);
		if (ch === "\\\\") {
			escaped += "\\\\";
			i += 1;
		} else if (pattern.slice(i, i + 2) === "**") if (pattern.charAt(i + 2) === "/") {
			escaped += "(?:[^/]+/)*?";
			i += 3;
		} else {
			escaped += ".*";
			i += 2;
		}
		else if (ch === "*") {
			escaped += "[^/]*";
			i += 1;
		} else if (ch === "?") {
			escaped += ".";
			i += 1;
		} else if (ch === "[") {
			var close = pattern.indexOf("]", i + 1);
			if (close === -1) {
				escaped += "\\\\[";
				i += 1;
			} else {
				escaped += pattern.slice(i, close + 1);
				i = close + 1;
			}
		} else {
			if (ch === "." || ch === "+" || ch === "^" || ch === "$" || ch === "(" || ch === ")" || ch === "|" || ch === "{" || ch === "}" || ch === "[" || ch === "]" || ch === "\\") escaped += "\\" + ch;
			else escaped += ch;
			i += 1;
		}
	}
	return new RegExp("^" + escaped + "$");
}
function _collectAllEntries(root, prefix, includeFiles, includeDirs) {
	var out = [];
	var stats;
	try {
		stats = statSync(root);
	} catch (_e) {
		return out;
	}
	if (!stats.isDirectory()) {
		out.push(prefix || "");
		return out;
	}
	var entries = readdirSync(root, { withFileTypes: true });
	for (var i = 0; i < entries.length; i++) {
		var child = entries[i];
		var childPrefix = prefix ? prefix + "/" + child.name : child.name;
		if (child.isDirectory()) {
			if (includeDirs) out.push(childPrefix);
			Array.prototype.push.apply(out, _collectAllEntries(pathJoin(root, child.name), childPrefix, includeFiles, includeDirs));
		} else if (includeFiles) out.push(childPrefix);
	}
	return out;
}
function globSync(pattern, options) {
	options = options || {};
	var cwd = options.cwd || _currentProcessCwd();
	_validatePath(cwd, "cwd");
	_validatePath(pattern, "pattern");
	_validateEncodingOption(options);
	var withTypes = !!options.withFileTypes;
	var exclude = options.exclude;
	var regex = _patternToRegex(pattern);
	if (exclude && !Array.isArray(exclude) && typeof exclude !== "function") throw _fsInvalidArgType("exclude", "function or array", exclude);
	var paths = [];
	var all = _collectAllEntries(cwd, "", true, true);
	var excludedPrefixes = [];
	for (var i = 0; i < all.length; i++) {
		var candidate = all[i].replace(/\\\\/g, "/");
		var pruned = false;
		for (var ep = 0; ep < excludedPrefixes.length; ep++) if (candidate.lastIndexOf(excludedPrefixes[ep], 0) === 0) {
			pruned = true;
			break;
		}
		if (pruned) continue;
		var dirent = null;
		if (withTypes) {
			var full = pathJoin(cwd, candidate);
			var stat = null;
			try {
				stat = lstatSync(full);
			} catch (_e) {}
			dirent = new Dirent(candidate, full, stat || null);
		}
		if (exclude) {
			if (Array.isArray(exclude) ? exclude.indexOf(candidate) !== -1 : exclude(withTypes ? dirent : candidate) === true) {
				excludedPrefixes.push(candidate + "/");
				continue;
			}
		}
		if (!regex.test(candidate)) continue;
		if (withTypes) paths.push(dirent);
		else paths.push(candidate);
	}
	if (options.withFileTypes) return paths;
	if (options.encoding === "buffer") return paths.map(function(item) {
		return Buffer.from(item);
	});
	return paths.sort();
}
function glob(pattern, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	_validateCallback(callback);
	options && options.cwd ? options.cwd : _currentProcessCwd();
	if (typeof options === "string") options = { pattern: options };
	_deferFsPromiseCallback(_asyncGlob(pattern, options || {}), callback);
}
function _asyncGlob(pattern, options) {
	var cwd = options.cwd || _currentProcessCwd();
	_validatePath(cwd, "cwd");
	_validatePath(pattern, "pattern");
	_validateEncodingOption(options);
	var regex = _patternToRegex(pattern), out = [];
	function walk(root, prefix) {
		return promises.readdir(root, { withFileTypes: true }).then(function(entries) {
			return entries.reduce(function(chain, entry) {
				return chain.then(function() {
					var candidate = prefix ? prefix + "/" + entry.name : String(entry.name);
					var value = options.withFileTypes ? entry : candidate;
					if (options.exclude && (Array.isArray(options.exclude) ? options.exclude.indexOf(candidate) !== -1 : options.exclude(value) === true)) return;
					if (regex.test(candidate)) out.push(value);
					return entry.isDirectory() ? walk(pathJoin(root, entry.name), candidate) : void 0;
				});
			}, Promise.resolve());
		});
	}
	return walk(_pathToString(cwd), "").then(function() {
		if (!options.withFileTypes) out.sort();
		if (options.encoding === "buffer") return out.map(function(v) {
			return Buffer.from(v);
		});
		return out;
	});
}
function mkdirSync(path, options) {
	_validatePath(path);
	ensureExactFs();
	var recursive = false;
	var mode;
	var firstCreatedPath;
	if (typeof options === "object" && options !== null) {
		_validateMkdirRecursiveOption(options);
		recursive = options.recursive === true;
		mode = options.mode;
	} else if (typeof options === "string" || typeof options === "number") mode = options;
	if (mode !== void 0) mode = _coerceMode(mode) & 511;
	if (recursive) _guardClosedFsMutation("mkdir", path);
	var p = _pathToString(path);
	try {
		if (recursive) firstCreatedPath = _getFirstMissingPath(p);
		if (typeof path === "string" && path.charAt(0) !== "/") try {
			statSync(_currentProcessCwd());
		} catch (cwdErr) {
			if (cwdErr && cwdErr.code === "ENOENT") throw cwdErr;
		}
		g.__exactMkdir(_nativeMkdirPath(p), recursive, mode === void 0 ? -1 : mode);
		if (recursive) return firstCreatedPath;
	} catch (e) {
		throw _makeFsError(e, "mkdir", p);
	}
}
function rmdirSync(path, options) {
	_validatePath(path);
	ensureExactFs();
	_guardClosedFsMutation("rmdir", path);
	var p = _pathToString(path);
	var opts = options;
	if (opts === void 0) opts = {};
	else try {
		var fsUtils = require("internal/fs/utils");
		if (fsUtils && typeof fsUtils.validateRmdirOptions === "function") opts = fsUtils.validateRmdirOptions(opts);
	} catch (_err) {}
	if (opts && opts.recursive === true) try {
		var info = lstatSync(p);
		if (!info || typeof info.isDirectory !== "function" || !info.isDirectory()) {
			g.__exactRmdir(p);
			return;
		}
		_rmSyncInternal(p, {
			recursive: true,
			force: false,
			maxRetries: opts.maxRetries,
			retryDelay: opts.retryDelay
		}, true);
		return;
	} catch (e) {
		throw _makeFsError(e, "rmdir", p);
	}
	try {
		g.__exactRmdir(p);
	} catch (e) {
		throw _makeFsError(e, "rmdir", p);
	}
}
function unlinkSync(path) {
	_validatePath(path);
	ensureExactFs();
	_guardClosedFsMutation("unlink", path);
	var p = _pathToString(path);
	try {
		g.__exactUnlink(p);
	} catch (e) {
		throw _makeFsError(e, "unlink", p);
	}
}
function renameSync(oldPath, newPath) {
	_validatePath(oldPath, "oldPath");
	_validatePath(newPath, "newPath");
	ensureExactFs();
	_guardClosedFsMutation("rename", oldPath, newPath);
	var op = _pathToString(oldPath);
	var np = _pathToString(newPath);
	try {
		g.__exactRename(op, np);
	} catch (e) {
		throw _makeFsError(e, "rename", op, np);
	}
}
function copyFileSync(src, dest, mode) {
	_validatePath(src, "src");
	_validatePath(dest, "dest");
	ensureExactFs();
	_guardClosedFsMutation("copyfile", src, dest);
	var s = _pathToString(src);
	var d = _pathToString(dest);
	if (mode !== void 0 && mode !== null) _validateCopyFileMode(mode);
	try {
		lstatSync(s);
	} catch (err) {
		if (err && err.code === "ENOENT") throw _makeFsError(/* @__PURE__ */ new Error("ENOENT: no such file or directory, copyfile '" + s + "' -> '" + d + "'"), "copyfile", s, d);
		if (err) throw _makeFsError(err, "copyfile", s, d);
	}
	if ((mode & 1) === 1) try {
		lstatSync(d);
		throw _makeFsError(/* @__PURE__ */ new Error("EEXIST: file already exists, copyfile '" + s + "' -> '" + d + "'"), "copyfile", s, d);
	} catch (err) {
		if (err.code !== "ENOENT") throw err;
	}
	try {
		g.__exactCopyFile(s, d, mode || 0);
	} catch (e) {
		throw _makeFsError(e, "copyfile", s, d);
	}
}
function accessSync(path, mode) {
	_validatePath(path);
	ensureExactFs();
	var p = _pathToString(path);
	var validatedMode = _validateAccessMode(mode);
	try {
		g.__exactAccess(p, validatedMode);
	} catch (e) {
		throw _makeFsError(e, "access", p);
	}
}
function chmodSync(path, mode) {
	_validatePath(path);
	ensureExactFs();
	_guardClosedFsMutation("chmod", path);
	var p = _pathToString(path);
	var m = typeof mode === "string" ? parseInt(mode, 8) : mode;
	try {
		g.__exactChmod(p, m);
	} catch (e) {
		throw _makeFsError(e, "chmod", p);
	}
}
function realpathSync(path, options) {
	_validatePath(path);
	_validateEncodingOption(options);
	ensureExactFs();
	var p = _mapVendoredNodeTestPath(_pathToString(path));
	lstatSync(p);
	try {
		return _encodeFsPathResult(g.__exactRealpath(p), options);
	} catch (e) {
		var fsErr = _makeFsError(e, "realpath", p);
		if (fsErr && fsErr.code === "ELOOP") {
			fsErr.syscall = "lstat";
			fsErr.message = _buildFsErrorMessage(fsErr.code, fsErr.syscall, fsErr.path, fsErr.dest);
		}
		throw fsErr;
	}
}
function realpathSyncNative(path) {
	_validatePath(path);
	ensureExactFs();
	var p = _mapVendoredNodeTestPath(_pathToString(path));
	try {
		return g.__exactRealpath(p);
	} catch (e) {
		throw _makeFsError(e, "realpath", p);
	}
}
realpathSync.native = realpathSyncNative;
function _mkdtempDisposableFromPath(pathValue, removePath, returnPromise) {
	var disposalPath = removePath || pathValue;
	var removed = false;
	function removeDisposablePath() {
		_guardClosedFsMutation("rm", disposalPath);
		try {
			_rmSyncInternal(disposalPath, {
				recursive: true,
				force: false
			}, true);
			removed = true;
			return;
		} catch (err) {
			if (err && err.code === "ENOENT") {
				removed = true;
				return;
			}
			removed = false;
			throw err;
		}
	}
	var result = {
		path: pathValue,
		remove: function() {
			if (removed) return returnPromise ? Promise.resolve() : void 0;
			if (returnPromise) try {
				removeDisposablePath();
				return Promise.resolve();
			} catch (err) {
				return Promise.reject(_makeFsError(err, "rm", disposalPath));
			}
			try {
				removeDisposablePath();
			} catch (err) {
				throw _makeFsError(err, "rm", disposalPath);
			}
		}
	};
	if (typeof Symbol !== "undefined" && Symbol.dispose) result[Symbol.dispose] = result.remove;
	if (typeof Symbol !== "undefined" && Symbol.asyncDispose && returnPromise) result[Symbol.asyncDispose] = function() {
		if (removed) return Promise.resolve();
		return new Promise(function(resolve, reject) {
			try {
				removeDisposablePath();
				resolve();
			} catch (err) {
				reject(_makeFsError(err, "rm", disposalPath));
			}
		});
	};
	return result;
}
function _mkdtempResult(prefix, options) {
	_validatePath(prefix, "prefix");
	_validateEncodingOption(options);
	ensureExactFs();
	_guardClosedFsMutation("mkdtemp", prefix);
	var prefixPath = _pathToString(prefix);
	var parent = _dirnamePath(prefixPath);
	var rawPrefix = typeof prefix === "string" ? prefix : typeof Buffer !== "undefined" && Buffer.isBuffer(prefix) ? prefix.toString() : null;
	if (!existsSync(parent)) throw _makeFsError(/* @__PURE__ */ new Error("ENOENT: no such file or directory, mkdtemp '" + prefix + "'"), "mkdtemp", prefix);
	try {
		var createdPath = g.__exactMkdtemp(prefixPath);
		return {
			actualPath: createdPath,
			publicPath: rawPrefix !== null && !_isAbsolutePath(rawPrefix) ? relativePathFromCwd(createdPath) : createdPath
		};
	} catch (e) {
		throw _makeFsError(e, "mkdtemp", prefix);
	}
}
function mkdtempSync(prefix, options) {
	return _mkdtempResult(prefix, options).publicPath;
}
function mkdtempDisposableSync(prefix, options) {
	var tempResult = _mkdtempResult(prefix, options);
	return _mkdtempDisposableFromPath(tempResult.publicPath, tempResult.actualPath, false);
}
function existsSync(path) {
	try {
		if (typeof path !== "string" && !(typeof Buffer !== "undefined" && Buffer.isBuffer(path)) && !(path && typeof path === "object" && path.href !== void 0 && path.protocol !== void 0)) {
			_emitFsDeprecation("DEP0187", "Passing invalid argument types to fs.existsSync is deprecated");
			return false;
		}
		ensureExactFs();
		g.__exactAccess(_pathToString(path), 0);
		return true;
	} catch (e) {
		return false;
	}
}
function wrapCallback(fn, cb, syscall, path) {
	try {
		var result = fn();
		_deferFsCallback(function() {
			if (result === void 0) cb(null);
			else cb(null, result);
		});
	} catch (err) {
		var error = _makeFsError(err, syscall, path);
		_deferFsCallback(function() {
			cb(error);
		});
	}
}
function readFile(path, optOrCb, cb) {
	var opts, callback, readOptions, signal, completed, onAbort;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	if (typeof path !== "number") _validatePath(path);
	readOptions = _normalizeReadFileOptions(opts, true);
	signal = readOptions.signal;
	completed = false;
	if (signal && signal.aborted === true) {
		_deferFsCallback(function() {
			callback(_makeAbortError(signal.reason));
		});
		return;
	}
	onAbort = function() {
		if (completed) return;
		completed = true;
		if (signal && typeof signal.removeEventListener === "function") signal.removeEventListener("abort", onAbort);
		callback(_makeAbortError(signal.reason));
	};
	if (signal && typeof signal.addEventListener === "function") signal.addEventListener("abort", onAbort);
	var finish = function(err, result) {
		if (completed) return;
		completed = true;
		if (signal && typeof signal.removeEventListener === "function") signal.removeEventListener("abort", onAbort);
		if (err) callback(err);
		else callback(null, result);
	};
	var asyncNative = _fsAsyncNative("__exactFsReadFileAsync");
	if (asyncNative) {
		var readPromise;
		try {
			readPromise = _asyncReadFileImpl(asyncNative, path, readOptions);
		} catch (err) {
			_deferFsCallback(function() {
				finish(err);
			});
			return;
		}
		readPromise.then(function(result) {
			finish(null, result);
		}, function(err) {
			finish(err);
		});
		return;
	}
	_deferFsCallback(function() {
		if (completed) return;
		try {
			finish(null, readFileSync(path, readOptions));
		} catch (err) {
			finish(err);
		}
	});
}
function writeFile(path, data, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validateWriteData(data);
	var target = _getFdOrPath(path, "path");
	var writeOptions;
	try {
		writeOptions = _normalizeWriteOptions(opts);
	} catch (err) {
		if (err && err.code === "ABORT_ERR") {
			_deferFsCallback(function() {
				callback(err);
			});
			return;
		}
		throw err;
	}
	if (_routeAsyncWriteFileCallback(target, data, writeOptions, "w", callback)) return;
	if (writeOptions.flush === true) {
		_writeFileWithFlushCallback(target, data, writeOptions, false, callback);
		return;
	}
	wrapCallback(function() {
		writeFileSync(target.path || target.fd, data, writeOptions);
	}, callback, "open", target.path);
}
function _routeAsyncWriteFileCallback(target, data, writeOptions, defaultFlag, callback) {
	var native = _fsAsyncNative("__exactFsWriteFileAsync");
	if (!native) return false;
	var writePromise;
	try {
		writePromise = _asyncWriteFileImpl(native, target, data, writeOptions, defaultFlag);
	} catch (err) {
		var error = _makeFsError(err, "open", target.path);
		_deferFsCallback(function() {
			callback(error);
		});
		return true;
	}
	writePromise.then(function() {
		_deferFsCallback(function() {
			callback(null);
		});
	}, function(err) {
		_deferFsCallback(function() {
			callback(err);
		});
	});
	return true;
}
function appendFile(path, data, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validateWriteData(data);
	var target = _getFdOrPath(path, "path");
	var writeOptions;
	try {
		writeOptions = _normalizeWriteOptions(opts);
	} catch (err) {
		if (err && err.code === "ABORT_ERR") {
			_deferFsCallback(function() {
				callback(err);
			});
			return;
		}
		throw err;
	}
	if (_routeAsyncWriteFileCallback(target, data, writeOptions, "a", callback)) return;
	if (writeOptions.flush === true) {
		_writeFileWithFlushCallback(target, data, writeOptions, true, callback);
		return;
	}
	wrapCallback(function() {
		appendFileSync(target.path || target.fd, data, writeOptions);
	}, callback, "open", target.path);
}
function _routeAsyncStatCallback(path, opts, kind, callback) {
	var native = _fsAsyncNative("__exactFsStatAsync");
	if (!native) return false;
	var statPromise, statOptions;
	try {
		_coerceStatOptions(opts);
		var p = _pathToString(path);
		statOptions = _extractStatOptions(opts);
		statPromise = _asyncStatImpl(native, p, kind, statOptions);
	} catch (err) {
		var error = _makeFsError(err, kind, _pathToString(path));
		_deferFsCallback(function() {
			callback(error);
		});
		return true;
	}
	statPromise.then(function(stats) {
		_deferFsCallback(function() {
			callback(null, stats);
		});
	}, function(err) {
		_deferFsCallback(function() {
			if (statOptions.throwIfNoEntry === false && err && err.code === "ENOENT") {
				callback(null);
				return;
			}
			callback(err);
		});
	});
	return true;
}
function stat(path, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	if (_routeAsyncStatCallback(path, opts, "stat", callback)) return;
	wrapCallback(function() {
		return statSync(path, opts);
	}, callback, "stat", _pathToString(path));
}
function lstat(path, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	if (_routeAsyncStatCallback(path, opts, "lstat", callback)) return;
	wrapCallback(function() {
		return lstatSync(path, opts);
	}, callback, "lstat", _pathToString(path));
}
function readdir(path, optOrCb, cb) {
	var opts = typeof optOrCb === "function" ? void 0 : optOrCb;
	var callback = typeof optOrCb === "function" ? optOrCb : cb;
	_validateCallback(callback);
	_validatePath(path);
	_validateEncodingOption(opts);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var readdirPromise = _asyncReaddirSimple(native, path, opts);
		if (readdirPromise) return _deferFsPromiseCallback(readdirPromise, callback);
	}
	wrapCallback(function() {
		return readdirSync(path, opts);
	}, callback, "scandir", _pathToString(path));
}
function mkdir(path, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	_validateMkdirRecursiveOption(opts);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) return _deferFsPromiseCallback(_asyncMkdirSimple(native, path, opts), callback);
	wrapCallback(function() {
		return mkdirSync(path, opts);
	}, callback, "mkdir", _pathToString(path));
}
function rmdir(path, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	_guardClosedFsMutation("rmdir", path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native && !(opts && opts.recursive === true)) {
		var rmdirPath = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "rmdir", [rmdirPath], "rmdir", rmdirPath), callback);
	}
	wrapCallback(function() {
		rmdirSync(path, opts);
	}, callback, "rmdir", _pathToString(path));
}
function unlink(path, cb) {
	_validateCallback(cb);
	_validatePath(path);
	_guardClosedFsMutation("unlink", path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "unlink", [p], "unlink", p), cb);
	}
	wrapCallback(function() {
		unlinkSync(path);
	}, cb, "unlink", _pathToString(path));
}
function rename(o, n, cb) {
	_validateCallback(cb);
	_validatePath(o, "oldPath");
	_validatePath(n, "newPath");
	_guardClosedFsMutation("rename", o, n);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var op = _pathToString(o);
		var np = _pathToString(n);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "rename", [op, np], "rename", op, np), cb);
	}
	wrapCallback(function() {
		renameSync(o, n);
	}, cb, "rename", _pathToString(o));
}
function copyFile(s, d, modeOrCb, cb) {
	var mode, callback;
	if (typeof modeOrCb === "function") callback = modeOrCb;
	else {
		mode = modeOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(s, "src");
	_validatePath(d, "dest");
	_guardClosedFsMutation("copyfile", s, d);
	if (mode !== void 0 && mode !== null) _validateCopyFileMode(mode);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var sp = _pathToString(s);
		var dp = _pathToString(d);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, (mode & constants.COPYFILE_EXCL) === constants.COPYFILE_EXCL ? "copyfile_excl" : "copyfile", [sp, dp], "copyfile", sp, dp), callback);
	}
	wrapCallback(function() {
		copyFileSync(s, d, mode);
	}, callback, "copyfile", _pathToString(s));
}
function access(path, modeOrCb, cb) {
	var mode, callback;
	if (typeof modeOrCb === "function") callback = modeOrCb;
	else {
		mode = modeOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	var validatedMode = mode !== void 0 && mode !== null ? _validateAccessMode(mode) : 0;
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "access", [
			p,
			null,
			validatedMode
		], "access", p), callback);
	}
	wrapCallback(function() {
		accessSync(path, mode);
	}, callback, "access", _pathToString(path));
}
function chmod(path, mode, cb) {
	_validateCallback(cb);
	_validatePath(path);
	_guardClosedFsMutation("chmod", path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "chmod", [
			p,
			null,
			typeof mode === "string" ? parseInt(mode, 8) : mode
		], "chmod", p), cb);
	}
	wrapCallback(function() {
		chmodSync(path, mode);
	}, cb, "chmod", _pathToString(path));
}
function realpath(path, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(path);
	_validateEncodingOption(opts);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _mapVendoredNodeTestPath(_pathToString(path));
		try {
			lstatSync(p);
		} catch (err) {
			return _deferFsCallback(function() {
				callback(_makeFsError(err, "lstat", p));
			});
		}
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "realpath", [p], "realpath", p).then(function(value) {
			return _encodeFsPathResult(value, opts);
		}), callback);
	}
	wrapCallback(function() {
		return realpathSync(path, opts);
	}, callback, "lstat", _pathToString(path));
}
realpath.native = function(path, callback) {
	_validateCallback(callback);
	_validatePath(path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _mapVendoredNodeTestPath(_pathToString(path));
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "realpath", [p], "realpath", p), callback);
	}
	wrapCallback(function() {
		return realpathSyncNative(path);
	}, callback, "realpath", _pathToString(path));
};
function mkdtemp(prefix, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(prefix, "prefix");
	_validateEncodingOption(opts);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) return _deferFsPromiseCallback(_asyncMkdtempResult(native, prefix, opts).then(function(result) {
		return result.publicPath;
	}), callback);
	wrapCallback(function() {
		return _mkdtempResult(prefix, opts).publicPath;
	}, callback, "mkdtemp", prefix);
}
function mkdtempDisposable(prefix, optOrCb, cb) {
	var opts, callback;
	if (typeof optOrCb === "function") callback = optOrCb;
	else {
		opts = optOrCb;
		callback = cb;
	}
	_validateCallback(callback);
	_validatePath(prefix, "prefix");
	_validateEncodingOption(opts);
	wrapCallback(function() {
		var tempResult = _mkdtempResult(prefix, opts);
		return _mkdtempDisposableFromPath(tempResult.publicPath, tempResult.actualPath, true);
	}, callback, "mkdtemp", prefix);
}
function exists(path, cb) {
	_validateCallback(cb);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		try {
			_validatePath(path);
			var p = _pathToString(path);
			_asyncFsPathOp(native, "access", [
				p,
				null,
				0
			], "access", p).then(function() {
				_deferFsCallback(function() {
					cb(true);
				});
			}, function() {
				_deferFsCallback(function() {
					cb(false);
				});
			});
		} catch (_) {
			_deferFsCallback(function() {
				cb(false);
			});
		}
		return;
	}
	_deferFsCallback(function() {
		try {
			cb(existsSync(path));
		} catch (e) {}
	});
}
function _normalizeOpenFlagsValue(flags) {
	var f = flags === void 0 ? "r" : flags;
	if (typeof f === "number") {
		if (!Number.isFinite(f) || f % 1 !== 0 || f < 0 || f > 2147483647) {
			var invalidNumErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a valid flags string. Received " + JSON.stringify(f));
			invalidNumErr.code = "ERR_INVALID_ARG_VALUE";
			throw invalidNumErr;
		}
		return f;
	}
	if (typeof f === "string") return _parseFsOpenFlags(f);
	var flagsErr = /* @__PURE__ */ new TypeError("The value of \"flags\" is invalid. It must be a string or a number. Received " + JSON.stringify(f));
	flagsErr.code = "ERR_INVALID_ARG_VALUE";
	throw flagsErr;
}
function _normalizeOpenModeValue(mode) {
	if (mode === void 0 || mode === null) return 438;
	if (typeof mode === "number") return mode;
	if (typeof mode === "string") {
		var m = parseInt(mode, 8);
		if (isNaN(m)) {
			var err = /* @__PURE__ */ new TypeError("The argument 'mode' must be a 32-bit unsigned integer or an octal string. Received " + JSON.stringify(mode));
			err.code = "ERR_INVALID_ARG_VALUE";
			throw err;
		}
		return m;
	}
	throw _fsInvalidArgType("mode", "number", mode);
}
function openSync(path, flags, mode) {
	_validatePath(path);
	ensureExactFs();
	var p = _pathToString(path);
	var f = _normalizeOpenFlagsValue(flags);
	var m = _normalizeOpenModeValue(mode);
	try {
		return g.__exactFsOpen(p, f, m);
	} catch (e) {
		throw _makeFsError(e, "open", p);
	}
}
function closeSync(fd) {
	_validateFd(fd);
	ensureExactFs();
	try {
		g.__exactFsClose(fd);
	} catch (e) {
		throw _makeFsError(e, "close");
	}
}
function readSync(fd, buffer, offset, length, position) {
	ensureExactFs();
	_validateFd(fd);
	if (arguments.length === 3) {
		if (!_isFsReadOptionsObject(offset, true)) throw _fsInvalidArgType("options", "object", offset);
		var ropts = offset;
		offset = ropts && ropts.offset === void 0 ? 0 : ropts ? ropts.offset : 0;
		length = ropts ? ropts.length : void 0;
		position = ropts ? ropts.position : void 0;
	}
	var readArgs = _normalizeFsReadArgs(buffer, offset, length, position);
	var targetBuffer = readArgs.targetBuffer;
	var off = readArgs.offset;
	try {
		var data = g.__exactFsRead(fd, readArgs.length, readArgs.position);
		if (buffer && data.length > 0) if (!targetBuffer.__isExactBuffer && typeof targetBuffer.set === "function") targetBuffer.set(data, off);
		else for (var i = 0; i < data.length; i++) targetBuffer[off + i] = data[i];
		return data.length;
	} catch (err) {
		throw _makeFsError(err, "read");
	}
}
function _prepareWriteArgs(bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
	if (typeof bufferOrString !== "string" && typeof offsetOrPosition === "object" && offsetOrPosition !== null) {
		var wopts = offsetOrPosition;
		offsetOrPosition = wopts.offset === void 0 ? 0 : wopts.offset;
		lengthOrEncoding = wopts.length;
		position = wopts.position;
	}
	if (typeof bufferOrString === "string") {
		if (offsetOrPosition !== void 0 && offsetOrPosition !== null && typeof offsetOrPosition !== "number") throw _fsInvalidArgType("position", "bigint or integer", offsetOrPosition);
		var strPos = _validateReadWritePosition("position", offsetOrPosition);
		if (lengthOrEncoding !== void 0 && lengthOrEncoding !== null && typeof lengthOrEncoding === "string") {
			_assertEncoding(lengthOrEncoding);
			_validateStringWriteEncoding(bufferOrString, lengthOrEncoding);
		}
		return {
			bytes: toUint8Array(bufferOrString, lengthOrEncoding),
			position: strPos
		};
	}
	if (!_isBufferLike(bufferOrString)) throw _fsInvalidArgType("buffer", "an instance of Buffer, TypedArray, or DataView", bufferOrString);
	var bytesBuffer = toUint8Array(bufferOrString);
	var bufferLen = bytesBuffer.length;
	var off = _validateOffset("offset", offsetOrPosition === void 0 || offsetOrPosition === null ? 0 : offsetOrPosition, bufferLen);
	var len = typeof lengthOrEncoding === "number" ? lengthOrEncoding : bufferLen - off;
	if (typeof len === "number") {
		if (!Number.isFinite(len) || len % 1 !== 0 || off + len > bufferLen || len < 0) throw _fsOutOfRange("length", len, 0, bufferLen - off);
	} else len = bufferLen - off;
	var pos = _validateReadWritePosition("position", position);
	var slice = bytesBuffer;
	if (off !== 0 || len !== bufferLen) slice = bytesBuffer.subarray(off, off + len);
	return {
		bytes: slice,
		position: pos
	};
}
function writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
	ensureExactFs();
	_validateFd(fd);
	var writeArgs = _prepareWriteArgs(bufferOrString, offsetOrPosition, lengthOrEncoding, position);
	try {
		return g.__exactFsWrite(fd, writeArgs.bytes, writeArgs.position);
	} catch (err) {
		throw _makeFsError(err, "write");
	}
}
function _writeFileWithFlushCallback(target, data, writeOptions, isAppend, callback) {
	var p = target && target.path;
	var fd = target && target.fd;
	var bytes = toUint8Array(data, writeOptions && writeOptions.encoding);
	var done = function(err) {
		_deferFsCallback(function() {
			callback(err);
		});
	};
	if (fd !== null && fd !== void 0) {
		try {
			_writeAllSync(fd, bytes, -1);
		} catch (err) {
			done(_makeFsError(err, "write", p));
			return;
		}
		if (writeOptions && writeOptions.flush === true) _callFsync(fd, function(err) {
			done(err ? _makeFsError(err, "fsync", p) : null);
		});
		else done(null);
		return;
	}
	var flags = writeOptions && (writeOptions.flag || writeOptions.flags) || (isAppend ? "a" : "w");
	var fd = null;
	try {
		fd = openSync(p, flags, writeOptions && writeOptions.mode);
	} catch (err) {
		done(_makeFsError(err, "open", p));
		return;
	}
	try {
		_writeAllSync(fd, bytes, -1);
	} catch (err) {
		try {
			closeSync(fd);
		} catch (_ignore) {}
		done(_makeFsError(err, "write", p));
		return;
	}
	if (writeOptions && writeOptions.flush === true) {
		_callFsync(fd, function(err) {
			if (err) {
				try {
					closeSync(fd);
				} catch (_ignore) {}
				done(_makeFsError(err, "fsync", p));
				return;
			}
			try {
				closeSync(fd);
			} catch (closeErr) {
				done(_makeFsError(closeErr, "close", p));
				return;
			}
			done(null);
		});
		return;
	}
	try {
		closeSync(fd);
	} catch (closeErr) {
		done(_makeFsError(closeErr, "close", p));
		return;
	}
	done(null);
}
function readvSync(fd, buffers, position) {
	_validateFd(fd);
	if (!Array.isArray(buffers)) throw _fsInvalidArgType("buffers", "Array", buffers);
	for (var i = 0; i < buffers.length; i++) if (!_isBufferLike(buffers[i])) throw _fsInvalidArgType("buffers[" + i + "]", "string or an instance of Buffer, TypedArray, or DataView", buffers[i]);
	if (position !== void 0 && position !== null && typeof position !== "number") throw _fsInvalidArgType("position", "number", position);
	if (typeof g.__exactFsReadv === "function") try {
		var pos = typeof position === "number" ? position : -1;
		return g.__exactFsReadv(fd, buffers, pos);
	} catch (err) {
		throw _makeFsError(err, "readv");
	}
	if (buffers.length === 0) return 0;
	var pos = typeof position === "number" ? position : -1;
	var bytesRead = 0;
	for (var i = 0; i < buffers.length; i++) {
		var buffer = buffers[i];
		if (!(typeof Buffer !== "undefined" && Buffer.isBuffer(buffer) || buffer instanceof Uint8Array)) throw _fsInvalidArgType("buffers[" + i + "]", "string or an instance of Buffer, TypedArray, or DataView", buffer);
		var currentPos = pos === -1 ? -1 : pos + bytesRead;
		var read = readSync(fd, buffer, 0, buffer.length, currentPos);
		bytesRead += read;
		if (read < buffer.length) break;
	}
	return bytesRead;
}
function writevSync(fd, buffers, position) {
	_validateFd(fd);
	if (!Array.isArray(buffers)) throw _fsInvalidArgType("buffers", "Array", buffers);
	for (var i = 0; i < buffers.length; i++) if (!_isBufferLike(buffers[i])) throw _fsInvalidArgType("buffers[" + i + "]", "string or an instance of Buffer, TypedArray, or DataView", buffers[i]);
	if (position !== void 0 && position !== null && typeof position !== "number") throw _fsInvalidArgType("position", "number", position);
	if (typeof g.__exactFsWritev === "function" && typeof position === "number") try {
		var pos = position;
		return g.__exactFsWritev(fd, buffers, pos);
	} catch (err) {
		throw _makeFsError(err, "writev");
	}
	if (buffers.length === 0) return 0;
	var pos = typeof position === "number" ? position : -1;
	var bytesWritten = 0;
	for (var i = 0; i < buffers.length; i++) {
		var buffer = buffers[i];
		if (!(typeof Buffer !== "undefined" && Buffer.isBuffer(buffer) || buffer instanceof Uint8Array)) throw _fsInvalidArgType("buffers[" + i + "]", "string or an instance of Buffer, TypedArray, or DataView", buffer);
		var currentPos = pos === -1 ? -1 : pos + bytesWritten;
		var written = writeSync(fd, buffer, 0, buffer.length, currentPos);
		bytesWritten += written;
	}
	return bytesWritten;
}
function readv(fd, buffers, position, callback) {
	if (typeof position === "function") {
		callback = position;
		position = void 0;
	}
	_validateCallback(callback);
	try {
		var asyncNative = _fsAsyncNative("__exactFsReadvAsync");
		if (asyncNative) {
			_asyncReadvIntoBuffers(asyncNative, fd, buffers, position).then(function(bytesRead) {
				_deferFsCallback(function() {
					callback(null, bytesRead, buffers);
				});
			}, function(err) {
				_deferFsCallback(function() {
					callback(err);
				});
			});
			return;
		}
		_validateVectoredIoArgs(fd, buffers, position);
		if (typeof g.__exactFsReadv === "function") {
			var pos = typeof position === "number" ? position : -1;
			g.__exactFsReadv(fd, buffers, pos, function(err, bytesRead) {
				_deferFsCallback(function() {
					if (err) callback(_makeFsError(err, "readv"));
					else callback(null, bytesRead, buffers);
				});
			});
			return;
		}
		var bytesRead = readvSync(fd, buffers, position);
		_deferFsCallback(function() {
			callback(null, bytesRead, buffers);
		});
	} catch (err) {
		var error = _makeFsError(err, "readv");
		_deferFsCallback(function() {
			callback(error);
		});
	}
}
function writev(fd, buffers, position, callback) {
	if (typeof position === "function") {
		callback = position;
		position = void 0;
	}
	_validateCallback(callback);
	try {
		var asyncNative = _fsAsyncNative("__exactFsWritevAsync");
		if (asyncNative) {
			_asyncWritevFromBuffers(asyncNative, fd, buffers, position).then(function(bytesWritten) {
				_deferFsCallback(function() {
					callback(null, bytesWritten, buffers);
				});
			}, function(err) {
				_deferFsCallback(function() {
					callback(err);
				});
			});
			return;
		}
		_validateVectoredIoArgs(fd, buffers, position);
		if (typeof g.__exactFsWritev === "function" && typeof position === "number") {
			var pos = position;
			g.__exactFsWritev(fd, buffers, pos, function(err, bytesWritten) {
				_deferFsCallback(function() {
					if (err) callback(_makeFsError(err, "writev"));
					else callback(null, bytesWritten, buffers);
				});
			});
			return;
		}
		var bytesWritten = writevSync(fd, buffers, position);
		_deferFsCallback(function() {
			callback(null, bytesWritten, buffers);
		});
	} catch (err) {
		var error = _makeFsError(err, "writev");
		_deferFsCallback(function() {
			callback(error);
		});
	}
}
function open(path, flagsOrCb, modeOrCb, cb) {
	var flags, mode, callback;
	if (typeof flagsOrCb === "function") {
		callback = flagsOrCb;
		flags = "r";
		mode = 438;
	} else if (typeof modeOrCb === "function") {
		callback = modeOrCb;
		flags = flagsOrCb;
		mode = 438;
	} else {
		callback = cb;
		flags = flagsOrCb;
		mode = modeOrCb;
	}
	_validateCallback(callback);
	_validatePath(path);
	if (mode !== void 0 && mode !== null && mode !== 438) {
		if (typeof mode === "string") {
			if (isNaN(parseInt(mode, 8))) {
				var err = /* @__PURE__ */ new TypeError("The argument 'mode' must be a 32-bit unsigned integer or an octal string. Received " + JSON.stringify(mode));
				err.code = "ERR_INVALID_ARG_VALUE";
				throw err;
			}
		} else if (typeof mode !== "number") throw _fsInvalidArgType("mode", "number", mode);
	}
	var native = _fsAsyncNative("__exactFsOpenAsync");
	if (native) return _deferFsPromiseCallback(_asyncOpen(native, path, flags, mode), callback);
	wrapCallback(function() {
		return openSync(path, flags, mode);
	}, callback, "open", _pathToString(path));
}
function close(fd, cb) {
	if (typeof cb === "function") {
		var native = _fsAsyncNative("__exactFsCloseAsync");
		if (native) return _deferFsPromiseCallback(_asyncClose(native, fd), cb);
		wrapCallback(function() {
			closeSync(fd);
		}, cb, "close");
	} else if (cb !== void 0) _validateCallback(cb);
	else closeSync(fd);
}
function fsRead(fd, buffer, offset, length, position, cb) {
	var argc = arguments.length;
	var validateCallbackFirst = false;
	var bufferLike = _isBufferLike(buffer);
	_validateFd(fd);
	if (typeof buffer === "function") {
		cb = buffer;
		buffer = Buffer.alloc(16384);
		offset = 0;
		length = buffer.length;
		position = -1;
	} else if (argc <= 3 && _isFsReadOptionsObject(buffer, true)) {
		var opts = buffer;
		cb = offset;
		buffer = opts && opts.buffer !== void 0 ? opts.buffer : Buffer.alloc(16384);
		offset = opts && opts.offset !== void 0 && opts.offset !== null ? opts.offset : 0;
		length = opts && opts.length !== void 0 ? opts.length : _bufferLikeLength(buffer) - offset;
		position = opts && opts.position !== void 0 ? opts.position : -1;
	} else if (bufferLike && argc === 3) {
		cb = offset;
		offset = 0;
		length = _bufferLikeLength(buffer);
		position = -1;
	} else if (bufferLike && argc === 4) {
		cb = length;
		if (!_isFsReadOptionsObject(offset, false)) throw _fsInvalidArgType("options", "object", offset);
		var readOpts = offset;
		offset = readOpts && readOpts.offset !== void 0 && readOpts.offset !== null ? readOpts.offset : 0;
		length = readOpts && readOpts.length !== void 0 ? readOpts.length : _bufferLikeLength(buffer) - offset;
		position = readOpts && readOpts.position !== void 0 ? readOpts.position : -1;
	} else if (bufferLike && argc >= 5) validateCallbackFirst = true;
	else if (typeof position === "function") {
		cb = position;
		position = -1;
	}
	if (validateCallbackFirst) _validateCallback(cb);
	var readArgs = _normalizeFsReadArgs(buffer, offset, length, position);
	if (!validateCallbackFirst) _validateCallback(cb);
	var asyncNative = _fsAsyncNative("__exactFsReadAsync");
	if (asyncNative) {
		_asyncReadIntoBuffer(asyncNative, fd, buffer, offset, length, position).then(function(bytesRead) {
			cb(null, bytesRead, buffer);
		}, function(err) {
			cb(err);
		});
		return;
	}
	try {
		var data = g.__exactFsRead(fd, readArgs.length, readArgs.position);
		if (data.length > 0) if (!readArgs.targetBuffer.__isExactBuffer && typeof readArgs.targetBuffer.set === "function") readArgs.targetBuffer.set(data, readArgs.offset);
		else for (var i = 0; i < data.length; i++) readArgs.targetBuffer[readArgs.offset + i] = data[i];
		_deferFsCallback(function() {
			cb(null, data.length, buffer);
		});
	} catch (err) {
		if (err && typeof err.code === "string" && err.code.indexOf("ERR_") === 0) throw err;
		var error = _makeFsError(err, "read");
		_deferFsCallback(function() {
			cb(error);
		});
	}
}
function fsWrite(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position, cb) {
	if (typeof position === "function") {
		cb = position;
		position = void 0;
	} else if (typeof lengthOrEncoding === "function") if (typeof offsetOrPosition === "number" || typeof offsetOrPosition === "undefined") {
		cb = lengthOrEncoding;
		lengthOrEncoding = void 0;
		position = void 0;
	} else {
		cb = lengthOrEncoding;
		if (typeof offsetOrPosition === "object" && offsetOrPosition !== null) {
			var wopts = offsetOrPosition;
			offsetOrPosition = wopts.offset;
			lengthOrEncoding = wopts.length;
			position = wopts.position;
		} else {
			lengthOrEncoding = void 0;
			position = void 0;
		}
	}
	else if (typeof offsetOrPosition === "function") {
		cb = offsetOrPosition;
		offsetOrPosition = typeof bufferOrString === "string" ? void 0 : 0;
		lengthOrEncoding = typeof bufferOrString === "string" ? void 0 : bufferOrString ? bufferOrString.length : 0;
		position = void 0;
	}
	if (typeof bufferOrString !== "string" && !(typeof Buffer !== "undefined" && Buffer.isBuffer(bufferOrString)) && !(bufferOrString instanceof Uint8Array) && !ArrayBuffer.isView(bufferOrString)) throw _fsInvalidArgType("buffer", "string or an instance of Buffer or Uint8Array", bufferOrString);
	_validateCallback(cb);
	if (typeof bufferOrString !== "string") {
		var bufLen = _bufferLikeLength(bufferOrString);
		var off = offsetOrPosition !== void 0 && offsetOrPosition !== null ? offsetOrPosition : 0;
		var len = lengthOrEncoding !== void 0 && lengthOrEncoding !== null ? lengthOrEncoding : bufLen - off;
		if (typeof off !== "number") throw _fsInvalidArgType("offset", "number", off);
		if (typeof len !== "number") {}
		if (off < 0 || off > bufLen) throw _fsOutOfRange("offset", off, 0, bufLen);
		if (typeof len === "number" && (len < 0 || off + len > bufLen)) throw _fsOutOfRange("length", len, 0, bufLen - off);
	}
	var asyncNative = _fsAsyncNative("__exactFsWriteAsync");
	if (asyncNative) {
		_validateFd(fd);
		_asyncWriteFromArgs(asyncNative, fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position).then(function(written) {
			cb(null, written, bufferOrString);
		}, function(err) {
			cb(err);
		});
		return;
	}
	try {
		var written = writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position);
		_deferFsWriteCallback(function() {
			cb(null, written, bufferOrString);
		});
	} catch (err) {
		if (err && typeof err.code === "string" && err.code.indexOf("ERR_") === 0) throw err;
		var error = _makeFsError(err, "write");
		_deferFsWriteCallback(function() {
			cb(error);
		});
	}
}
function createReadStream(path, options) {
	return new ReadStream(path, options);
}
function ReadStream(path, options) {
	var Stream = _getStreamModule();
	if (!(this instanceof Stream.Readable)) return new ReadStream(path, options);
	return _initReadStream(this, path, options);
}
ReadStream.prototype = Object.create(_getStreamModule().Readable.prototype);
ReadStream.prototype.constructor = ReadStream;
function _initReadStream(rs, path, options) {
	if (options !== void 0 && options !== null && typeof options !== "string" && typeof options !== "object") throw _fsInvalidArgType("options", "string or an object", options);
	_validateEncodingOption(options);
	ensureExactFs();
	var Stream = _getStreamModule();
	var opts = typeof options === "string" ? { encoding: options } : options || {};
	var fsModule = opts.fs || require("fs");
	var useSyncReadFastPath = opts.fs === void 0 && !_fsAsyncNative("__exactFsReadAsync");
	_validateFsOptions("options.fs", opts.fs, [
		"open",
		"close",
		"read"
	]);
	var encoding = opts.encoding || null;
	var start = 0;
	var end = opts.end;
	var allowGrowingSource = opts.start !== void 0 && end === void 0;
	if (opts.start !== void 0) {
		if (typeof opts.start !== "number") throw _fsInvalidArgType("start", "number", opts.start);
		_validateInt("start", opts.start, 0, Number.MAX_SAFE_INTEGER);
		start = opts.start;
	}
	if (end !== void 0) {
		if (typeof end !== "number") throw _fsInvalidArgType("end", "number", end);
		if (end !== Infinity) _validateInt("end", end, 0, Number.MAX_SAFE_INTEGER);
	}
	if (end !== void 0 && end !== Infinity && start > end) {
		var startAfterEnd = _fsOutOfRange("start", start, 0, end);
		startAfterEnd.message = "The value of \"start\" is out of range. It must be <= \"end\" (here: " + end + "). Received " + start;
		throw startAfterEnd;
	}
	var highWaterMark = opts.highWaterMark || opts.bufferSize || 65536;
	var autoClose = opts.autoClose !== false;
	var fdOption = opts.fd;
	var sourceFd = null;
	var sourceHandle = null;
	var sourceIsHandle = false;
	if (fdOption === void 0 || fdOption === null) _validatePath(path, "path");
	else if (typeof fdOption === "object") if (fdOption && typeof fdOption.fd === "number") {
		sourceHandle = fdOption;
		sourceFd = fdOption.fd;
		sourceIsHandle = true;
	} else throw _fsInvalidArgType("fd", "number", fdOption);
	else if (typeof fdOption === "number") sourceFd = fdOption;
	else throw _fsInvalidArgType("fd", "number", fdOption);
	if (typeof sourceFd === "number" && sourceFd !== null && sourceFd !== void 0) _validateFd(sourceFd);
	if (!rs._exactReadStreamInitialized) {
		Stream.Readable.call(rs, {
			highWaterMark,
			autoDestroy: autoClose,
			emitClose: autoClose
		});
		rs._exactReadStreamInitialized = true;
	}
	if (encoding) rs.setEncoding(encoding);
	rs.path = fdOption === void 0 || fdOption === null || path !== null && path !== void 0 ? path : void 0;
	rs.start = start;
	rs.end = end;
	rs.autoClose = autoClose;
	rs.readable = true;
	rs.bytesRead = 0;
	rs.closed = false;
	rs.destroyed = false;
	rs.fd = null;
	rs.pending = true;
	rs._position = start;
	rs._end = end;
	rs._autoClose = autoClose;
	function closeOpenDescriptor(fdToClose, callback) {
		if (typeof fdToClose !== "number") {
			if (typeof callback === "function") _deferFsCallback(callback);
			return;
		}
		var closeSyncFn = typeof fsModule.closeSync === "function" ? fsModule.closeSync : closeSync;
		var closeFn = typeof fsModule.close === "function" ? fsModule.close : null;
		var done = function() {
			rs._openFd = null;
			rs.fd = null;
			if (typeof callback === "function") _deferFsCallback(callback);
		};
		try {
			if (typeof closeFn === "function") {
				closeFn.call(fsModule, fdToClose, function() {
					done();
				});
				return;
			}
			if (typeof closeSyncFn === "function") {
				closeSyncFn(fdToClose);
				done();
				return;
			}
		} catch (e) {}
		done();
	}
	function closeFd() {
		if (rs.closed) return;
		rs.destroyed = true;
		rs.closed = true;
		var afterClose = function() {
			rs.fd = null;
			rs.emit("close");
		};
		if (!sourceIsHandle) {
			if (typeof rs._openFd === "number" && rs._shouldAutoClose) {
				closeOpenDescriptor(rs._openFd, afterClose);
				return;
			}
		} else if (sourceHandle && typeof sourceHandle.close === "function") {
			try {
				var handleCloseResult = sourceHandle.close();
				if (handleCloseResult && typeof handleCloseResult.then === "function") {
					handleCloseResult.then(afterClose, afterClose);
					return;
				}
			} catch (e) {}
			afterClose();
			return;
		}
		afterClose();
	}
	rs._openFd = sourceFd;
	rs._opened = sourceFd !== null;
	rs._shouldAutoClose = sourceIsHandle ? false : rs._autoClose;
	rs._opening = false;
	rs._readyEmitted = false;
	rs._sawShortRead = false;
	rs._waitingForGrowth = false;
	rs._growthRetries = 0;
	if (rs._opened) {
		rs.pending = false;
		rs._readyEmitted = true;
		_deferFsCallback(function() {
			rs.emit("ready");
		});
	}
	function markReady() {
		if (!rs.pending) return;
		rs.pending = false;
		rs._readyEmitted = true;
		rs.emit("ready");
	}
	function ensureOpen() {
		if (rs.closed || rs.destroyed || rs._opened || rs._opening) return;
		rs._opening = true;
		if (sourceIsHandle || sourceFd !== null) {
			rs._opening = false;
			return;
		}
		try {
			var openSyncFn = typeof fsModule.openSync === "function" ? fsModule.openSync : openSync;
			var openFn = typeof fsModule.open === "function" ? fsModule.open : null;
			if (!openFn && !openSyncFn) throw new Error("open is not a function");
			if (openFn) {
				openFn.call(fsModule, path, opts.flags || "r", opts.mode || 438, function(err, fd) {
					rs._opening = false;
					if (err) {
						rs.emit("error", _makeFsError(err, "open", path));
						if (autoClose) closeFd();
						return;
					}
					if (rs.closed || rs.destroyed) {
						if (typeof fd === "number" && rs._shouldAutoClose) closeOpenDescriptor(fd);
						return;
					}
					rs._openFd = fd;
					rs._opened = true;
					rs._shouldAutoClose = rs._autoClose;
					rs.fd = rs._openFd;
					rs.emit("open", rs._openFd);
					markReady();
					rs._read();
				});
				return;
			}
			rs._openFd = openSyncFn(path, opts.flags || "r", opts.mode || 438);
			if (rs.closed || rs.destroyed) {
				closeOpenDescriptor(rs._openFd);
				rs._opened = false;
				rs._opening = false;
				return;
			}
			rs._opened = true;
			rs._shouldAutoClose = rs._autoClose;
			rs.fd = rs._openFd;
			rs.emit("open", rs._openFd);
			markReady();
			rs._read();
		} catch (err) {
			rs._opening = false;
			rs.emit("error", err);
			if (autoClose) closeFd();
			return;
		}
		rs._opening = false;
	}
	if (!rs._opened) _deferFsCallback(ensureOpen);
	rs._read = function() {
		if (rs.destroyed || rs.closed) return;
		if (typeof rs._reading === "boolean" && rs._reading) return;
		rs._reading = true;
		try {
			if (!rs._opened) {
				ensureOpen();
				if (!rs._opened) {
					rs._reading = false;
					return;
				}
			}
			if (sourceIsHandle && sourceHandle && sourceHandle.fd === null) {
				rs._reading = false;
				rs.push(null);
				return;
			}
			rs.fd = rs._openFd || sourceFd;
			var chunkSize = highWaterMark;
			if (end !== void 0) {
				var remaining = end - rs._position + 1;
				if (remaining <= 0) {
					rs._reading = false;
					rs.push(null);
					if (autoClose) closeFd();
					return;
				}
				if (remaining < chunkSize) chunkSize = remaining;
			}
			var buf = new Uint8Array(chunkSize);
			var readDone = function(err, bytesRead, data) {
				rs._reading = false;
				if (err) {
					rs.emit("error", err);
					if (autoClose) closeFd();
					return;
				}
				if (bytesRead <= 0) {
					if (allowGrowingSource && rs._sawShortRead && !rs._waitingForGrowth && rs._growthRetries < 8) {
						rs._waitingForGrowth = true;
						rs._growthRetries += 1;
						setTimeout(function() {
							rs._waitingForGrowth = false;
							if (!rs.destroyed && !rs.closed) rs._read();
						}, 1);
						return;
					}
					rs.push(null);
					if (autoClose) closeFd();
					return;
				}
				rs._waitingForGrowth = false;
				rs._growthRetries = 0;
				rs.bytesRead += bytesRead;
				rs._position += bytesRead;
				rs._sawShortRead = allowGrowingSource && bytesRead < chunkSize;
				var chunk = data ? data.slice(0, bytesRead) : buf.slice(0, bytesRead);
				var shouldContinue = rs.push(wrapBuffer(chunk));
				if (rs._sawShortRead && !rs.destroyed && !rs.closed) {
					rs._waitingForGrowth = true;
					setTimeout(function() {
						rs._waitingForGrowth = false;
						if (!rs.destroyed && !rs.closed) rs._read();
					}, 1);
					return;
				}
				if (shouldContinue && !rs.destroyed && !rs.closed) if (rs._sawShortRead) setTimeout(function() {
					rs._read();
				}, 1);
				else if (typeof queueMicrotask === "function") queueMicrotask(function() {
					rs._read();
				});
				else rs._read();
			};
			if (sourceIsHandle && sourceHandle && typeof sourceHandle.read === "function") sourceHandle.read(buf, 0, chunkSize, rs._position, readDone);
			else if (useSyncReadFastPath) try {
				readDone(null, readSync(rs.fd, buf, 0, chunkSize, rs._position), buf);
			} catch (readErr) {
				readDone(readErr);
			}
			else {
				var readFn = typeof fsModule.read === "function" ? fsModule.read : fsRead;
				var readArgs = [
					rs.fd,
					buf,
					0,
					chunkSize,
					rs._position
				];
				readFn.apply(fsModule, readArgs.concat(readDone));
			}
		} catch (err) {
			rs.emit("error", err);
			if (autoClose) closeFd();
		}
	};
	rs.open = function() {
		if (rs._opened || rs._opening || rs.closed) return rs;
		ensureOpen();
		return rs;
	};
	rs.close = function() {
		if (!rs.closed) {
			rs.destroyed = true;
			closeFd();
		}
	};
	rs.destroy = function() {
		if (rs.destroyed) return rs;
		rs.destroyed = true;
		closeFd();
		return rs;
	};
	rs.on("error", function() {
		if (!autoClose) return;
		rs.destroyed = true;
		closeFd();
	});
	if (sourceIsHandle && sourceHandle && typeof sourceHandle.on === "function") sourceHandle.on("close", rs.close);
	return rs;
}
function createWriteStream(path, options) {
	return new WriteStream(path, options);
}
function WriteStream(path, options) {
	var Stream = _getStreamModule();
	if (!(this instanceof Stream.Writable)) return new WriteStream(path, options);
	return _initWriteStream(this, path, options);
}
WriteStream.prototype = Object.create(_getStreamModule().Writable.prototype);
WriteStream.prototype.constructor = WriteStream;
Object.defineProperty(WriteStream.prototype, "autoClose", {
	configurable: true,
	enumerable: true,
	get: function() {
		if (!(this instanceof WriteStream)) {
			var err = /* @__PURE__ */ new TypeError("Value of \"this\" must be of type WriteStream");
			err.code = "ERR_INVALID_THIS";
			throw err;
		}
		return this._shouldAutoClose;
	},
	set: function(value) {
		if (!(this instanceof WriteStream)) {
			var err = /* @__PURE__ */ new TypeError("Value of \"this\" must be of type WriteStream");
			err.code = "ERR_INVALID_THIS";
			throw err;
		}
		this._shouldAutoClose = value !== false;
	}
});
function _initWriteStream(ws, path, options) {
	var opts = _normalizeWriteOptions(options);
	_validateEncodingOption(opts);
	_validateFlushOption(opts.flush);
	ensureExactFs();
	var Stream = _getStreamModule();
	var fsModule = opts.fs || require("fs");
	_validateFsOptions("options.fs", opts.fs, [
		"open",
		"close",
		"write",
		"writev"
	]);
	var flags = opts.flags || "w";
	var mode = opts.mode || 438;
	var encoding = opts.encoding || "utf8";
	var autoClose = opts.autoClose !== false;
	var start = null;
	var openError = null;
	var fdOption = opts.fd;
	var fd = null;
	var opened = false;
	var opening = false;
	var fileHandle = null;
	var usingHandle = false;
	var pendingWrites = [];
	var processingWrite = false;
	if (opts.start !== void 0) {
		if (typeof opts.start !== "number") throw _fsInvalidArgType("start", "number", opts.start);
		_validateInt("start", opts.start, 0, Number.MAX_SAFE_INTEGER);
		start = opts.start;
	}
	if (fdOption !== void 0 && fdOption !== null) if (typeof fdOption === "number") {
		fd = fdOption;
		opened = true;
		if (typeof _validateFd === "function") _validateFd(fd);
	} else if (typeof fdOption === "object" && typeof fdOption.fd === "number") {
		fd = fdOption.fd;
		opened = true;
		fileHandle = fdOption;
		usingHandle = true;
		if (typeof _validateFd === "function") _validateFd(fd);
	} else throw _fsInvalidArgType("fd", "number", fdOption);
	else _validatePath(path, "path");
	if (!ws._exactWriteStreamInitialized) {
		Stream.Writable.call(ws, { emitClose: autoClose });
		ws._exactWriteStreamInitialized = true;
	}
	if (encoding) ws.setDefaultEncoding(encoding);
	ws.path = path;
	ws.fd = fd;
	ws.closed = false;
	ws._closed = false;
	ws.destroyed = false;
	ws.pending = !opened;
	ws.bytesWritten = 0;
	ws._encoding = encoding;
	ws._shouldAutoClose = autoClose;
	ws._shouldWriteAt = typeof start === "number" ? start : null;
	ws._readyEmitted = false;
	ws._flush = opts.flush === true;
	ws._writeErrorClosed = false;
	ws._emitClose = function() {
		if (ws.closed || ws._closed) return;
		ws.closed = true;
		ws._closed = true;
		ws.fd = null;
		ws.emit("close");
	};
	function closeWriteFd(callback) {
		if (!autoClose || fd === null) {
			if (typeof callback === "function") _deferFsCallback(callback);
			return;
		}
		var closeSyncFn = typeof fsModule.closeSync === "function" ? fsModule.closeSync : closeSync;
		var closeFn = typeof fsModule.close === "function" ? fsModule.close : null;
		var done = function(err) {
			var closeErr = err ? _makeFsError(err, "close", path) : null;
			fd = null;
			ws.fd = null;
			if (typeof callback === "function") _deferFsCallback(function() {
				callback(closeErr);
			});
		};
		if (usingHandle && fileHandle && typeof fileHandle.close === "function") {
			try {
				var handleCloseResult = fileHandle.close();
				if (handleCloseResult && typeof handleCloseResult.then === "function") {
					handleCloseResult.then(function() {
						done();
					}, function(err) {
						done(err);
					});
					return;
				}
			} catch (_ignore) {
				try {
					if (typeof closeSyncFn === "function") closeSyncFn(fd);
				} catch (_ignored) {}
			}
			done();
			return;
		}
		try {
			if (typeof closeFn === "function") {
				closeFn.call(fsModule, fd, function(err) {
					done(err);
				});
				return;
			}
			if (typeof closeSyncFn === "function") {
				closeSyncFn(fd);
				done();
			} else done();
		} catch (err) {
			done(err);
		}
	}
	function makeWriteError(err, operation) {
		if (!err) return _makeFsError(/* @__PURE__ */ new Error((operation || "write") + " failed"), operation || "write", path);
		if (typeof err.code === "string") {
			if (err.code === "ABORT_ERR" || err.code.indexOf("ERR_STREAM_") === 0) return err;
			return _makeFsError(err, operation || "write", path);
		}
		if (err instanceof Error) return err;
		return _makeFsError(err, operation || "write", path);
	}
	function emitWriteError(err, callback, operation) {
		var writeErr = makeWriteError(err, operation);
		if (ws._writableState) ws._writableState.autoDestroy = false;
		if (!ws._writeErrorClosed && autoClose) {
			ws._writeErrorClosed = true;
			closeWriteFd(function(closeErr) {
				if (closeErr) ws.emit("error", closeErr);
				ws._emitClose();
				if (typeof callback === "function") callback(writeErr);
				ws.emit("error", writeErr);
			});
			return;
		}
		if (typeof callback === "function") callback(writeErr);
		ws.emit("error", writeErr);
	}
	function normalizeWritePosition() {
		return typeof ws._shouldWriteAt === "number" ? ws._shouldWriteAt : null;
	}
	function failPendingWrites(err) {
		var next;
		while (next = pendingWrites.shift()) emitWriteError(err, next.callback, "open");
		processingWrite = false;
	}
	function setOpened(newFd) {
		if (ws.destroyed || ws.closed || ws._closed) {
			opening = false;
			if (typeof newFd === "number") try {
				if (typeof fsModule.close === "function") fsModule.close.call(fsModule, newFd, function() {});
				else if (typeof fsModule.closeSync === "function") fsModule.closeSync(newFd);
				else closeSync(newFd);
			} catch (_ignore) {}
			return;
		}
		openError = null;
		if (!opened && typeof _validateFd === "function") _validateFd(newFd);
		opened = true;
		opening = false;
		fd = newFd;
		ws.fd = fd;
		if (typeof start === "number") ws._shouldWriteAt = start;
		ws.emit("open", fd);
		if (!ws._readyEmitted) {
			ws._readyEmitted = true;
			ws.pending = false;
			ws.emit("ready");
		}
		drainPendingWrites();
	}
	function ensureOpen() {
		if (opened || ws.closed || ws.destroyed || opening) return;
		var openSyncFn = typeof fsModule.openSync === "function" ? fsModule.openSync : openSync;
		var openFn = typeof fsModule.open === "function" ? fsModule.open : null;
		if (!fdOption && !openFn && !openSyncFn) {
			var openFnError = makeWriteError(/* @__PURE__ */ new Error("open is not a function"), "open");
			openError = openFnError;
			ws.emit("error", openFnError);
			failPendingWrites(openFnError);
			return;
		}
		opening = true;
		if (openFn) {
			openFn.call(fsModule, path, flags, mode, function(err, openedFd) {
				if (err) {
					opening = false;
					openError = makeWriteError(err, "open");
					failPendingWrites(err);
					ws.emit("error", openError);
					return;
				}
				setOpened(openedFd);
			});
			return;
		}
		try {
			setOpened(openSyncFn.call(fsModule, path, flags, mode));
		} catch (err) {
			opening = false;
			openError = makeWriteError(err, "open");
			failPendingWrites(err);
			ws.emit("error", openError);
		}
	}
	function performWrite(chunk, enc, callback) {
		var bytes = toUint8Array(chunk, enc || encoding);
		var position = normalizeWritePosition();
		var writeSyncFn = typeof fsModule.writeSync === "function" ? fsModule.writeSync : writeSync;
		var writeFn = typeof fsModule.write === "function" ? fsModule.write : null;
		var done = function(err, written) {
			if (err) {
				emitWriteError(err, callback, "write");
				return;
			}
			var writtenBytes = typeof written === "number" ? written : bytes.length;
			if (typeof position === "number") ws._shouldWriteAt += writtenBytes;
			ws.bytesWritten += writtenBytes;
			if (typeof callback === "function") callback();
		};
		if (usingHandle && fileHandle && typeof fileHandle.write === "function") {
			try {
				var handleResult = fileHandle.write(bytes, 0, bytes.length, position);
				if (handleResult && typeof handleResult.then === "function") {
					handleResult.then(function(result) {
						if (typeof result === "object" && result !== null && typeof result.bytesWritten === "number") {
							done(null, result.bytesWritten);
							return;
						}
						done(null, bytes.length);
					}).catch(function(err) {
						done(err);
					});
					return;
				}
				if (typeof handleResult === "number") done(null, handleResult);
				else done();
				return;
			} catch (err) {
				done(err);
			}
			return;
		}
		if (typeof writeFn === "function") {
			try {
				writeFn.call(fsModule, fd, bytes, 0, bytes.length, position, function(err, written) {
					done(err, written);
				});
			} catch (err) {
				done(err);
			}
			return;
		}
		try {
			done(null, writeSyncFn.call(fsModule, fd, bytes, 0, bytes.length, position === null ? -1 : position));
		} catch (err) {
			done(err);
		}
	}
	function buffersFromChunks(chunks) {
		var buffers = new Array(chunks.length);
		for (var i = 0; i < chunks.length; i++) {
			var chunk = chunks[i];
			buffers[i] = toUint8Array(chunk.chunk, chunk.encoding || encoding);
		}
		return buffers;
	}
	function sumBufferLengths(buffers) {
		var total = 0;
		for (var i = 0; i < buffers.length; i++) total += buffers[i].length;
		return total;
	}
	function performWritev(chunks, callback) {
		var buffers = buffersFromChunks(chunks);
		var position = normalizeWritePosition();
		var writeSyncFn = typeof fsModule.writeSync === "function" ? fsModule.writeSync : writeSync;
		var done = function(err, written) {
			if (err) {
				emitWriteError(err, callback, "writev");
				return;
			}
			var writtenBytes = typeof written === "number" ? written : sumBufferLengths(buffers);
			if (typeof position === "number") ws._shouldWriteAt += writtenBytes;
			ws.bytesWritten += writtenBytes;
			if (typeof callback === "function") callback();
		};
		if (opts.fs === void 0 && _fsAsyncNative("__exactFsWriteAsync")) {
			var writtenTotalAsync = 0;
			var nextIndex = 0;
			var writeNext = function() {
				if (nextIndex >= buffers.length) {
					done(null, writtenTotalAsync);
					return;
				}
				var chunkBuf = buffers[nextIndex];
				nextIndex += 1;
				var chunkOffset = position === null ? -1 : position + writtenTotalAsync;
				try {
					fsWrite(fd, chunkBuf, 0, chunkBuf.length, chunkOffset, function(err, written) {
						if (err) {
							done(err);
							return;
						}
						writtenTotalAsync += typeof written === "number" ? written : chunkBuf.length;
						writeNext();
					});
				} catch (err) {
					done(err);
				}
			};
			writeNext();
			return;
		}
		try {
			var writtenTotal = 0;
			for (var i = 0; i < buffers.length; i++) {
				var buf = buffers[i];
				var currentOffset = position === null ? -1 : position + writtenTotal;
				writtenTotal += writeSyncFn.call(fsModule, fd, buf, 0, buf.length, currentOffset);
			}
			done(null, writtenTotal);
		} catch (err) {
			done(err);
		}
	}
	function drainPendingWrites() {
		if (processingWrite || !opened || ws.closed || ws.destroyed) return;
		var next = pendingWrites.shift();
		if (!next) return;
		processingWrite = true;
		var finishWrite = function(err) {
			processingWrite = false;
			if (typeof next.callback === "function") next.callback(err);
			drainPendingWrites();
		};
		if (next.type === "write") {
			performWrite(next.chunk, next.encoding, finishWrite);
			return;
		}
		performWritev(next.chunks, finishWrite);
	}
	function enqueueWrite(type, payload, callback) {
		if (ws.closed || ws._closed) {
			var closedErr = /* @__PURE__ */ new Error("write after end");
			closedErr.code = "ERR_STREAM_WRITE_AFTER_END";
			if (ws._writableState) {
				ws._writableState.autoDestroy = false;
				ws._writableState.errored = closedErr;
				ws._writableState.errorEmitted = true;
			}
			ws.errored = closedErr;
			if (typeof callback === "function") _deferFsCallback(function() {
				callback(closedErr);
			});
			return;
		}
		if (ws.destroyed) {
			var destroyedErr = /* @__PURE__ */ new Error("Cannot call write after a stream was destroyed");
			destroyedErr.code = "ERR_STREAM_DESTROYED";
			if (ws._writableState) {
				ws._writableState.autoDestroy = false;
				ws._writableState.errored = destroyedErr;
				ws._writableState.errorEmitted = true;
			}
			ws.errored = destroyedErr;
			if (typeof callback === "function") _deferFsCallback(function() {
				callback(destroyedErr);
			});
			return;
		}
		pendingWrites.push({
			type,
			chunk: payload && payload.chunk ? payload.chunk : null,
			encoding: payload && payload.encoding,
			chunks: payload && payload.chunks ? payload.chunks : null,
			callback
		});
		if (!opened) {
			if (!opening) ensureOpen();
			return;
		}
		if (!processingWrite) drainPendingWrites();
	}
	if (!opened && !fdOption) _deferFsCallback(ensureOpen);
	else if (opened && !ws._readyEmitted) {
		ws._readyEmitted = true;
		ws.pending = false;
		ws.emit("ready");
	}
	ws._write = function(chunk, enc, callback) {
		enqueueWrite("write", {
			chunk,
			encoding: enc
		}, callback);
	};
	ws._writev = function(chunks, callback) {
		enqueueWrite("writev", { chunks }, callback);
	};
	ws._final = function(callback) {
		if (typeof callback !== "function") callback = function() {};
		var finish = function(err) {
			if (err) {
				callback(err);
				return;
			}
			if (autoClose) {
				closeWriteFd(function(closeErr) {
					if (closeErr) {
						callback(closeErr);
						return;
					}
					ws._emitClose();
					callback();
				});
				return;
			}
			callback();
		};
		var flushAndClose = function() {
			if (!autoClose || !ws._flush || typeof fd !== "number") {
				finish();
				return;
			}
			_callFsync(fd, function(err) {
				if (err) {
					callback(err);
					return;
				}
				finish();
			});
		};
		if (!opened && !fdOption) {
			ensureOpen();
			var waitForOpen = function() {
				if (opening) {
					_deferFsCallback(waitForOpen);
					return;
				}
				if (openError) {
					callback(openError);
					return;
				}
				if (processingWrite) {
					_deferFsCallback(waitForOpen);
					return;
				}
				flushAndClose();
			};
			waitForOpen();
			return;
		}
		flushAndClose();
	};
	ws.destroy = function(err) {
		if (ws.destroyed) return ws;
		ws.destroyed = true;
		if (err) ws.emit("error", err);
		if (autoClose) closeWriteFd(function() {
			ws._emitClose();
		});
		else ws._emitClose();
		return ws;
	};
	ws.open = function() {
		if (opened) {
			if (!ws._readyEmitted) {
				ws._readyEmitted = true;
				ws.pending = false;
				ws.emit("ready");
			}
			return ws;
		}
		ensureOpen();
		return ws;
	};
	ws.close = function(callback) {
		if (typeof callback === "function") {
			if (ws.closed || ws._closed) {
				_deferFsCallback(callback);
				return ws;
			}
			ws.once("close", callback);
			if (!autoClose) ws._emitClose();
			else closeWriteFd(function(err) {
				if (err) ws.emit("error", err);
				ws._emitClose();
			});
			return ws;
		}
		if (autoClose && !ws.closed && !ws._closed) {
			closeWriteFd(function() {
				ws._emitClose();
			});
			return ws;
		}
		ws._emitClose();
		return ws;
	};
	return ws;
}
function FSWatcher() {
	this._events = {};
	this._closed = false;
	this._stopped = false;
	this._unrefed = false;
}
FSWatcher.prototype.on = function(ev, fn) {
	if (!this._events[ev]) this._events[ev] = [];
	this._events[ev].push(fn);
	return this;
};
FSWatcher.prototype.addListener = FSWatcher.prototype.on;
FSWatcher.prototype.emit = function(ev) {
	var a = [].slice.call(arguments, 1);
	var l = this._events[ev] || [];
	for (var i = 0; i < l.length; i++) l[i].apply(this, a);
	return l.length > 0;
};
FSWatcher.prototype.once = function(ev, fn) {
	var self = this;
	function w() {
		self.removeListener(ev, w);
		fn.apply(this, arguments);
	}
	w.listener = fn;
	this.on(ev, w);
	return this;
};
FSWatcher.prototype.removeListener = function(ev, fn) {
	var l = this._events[ev];
	if (l) {
		var n = [];
		for (var i = 0; i < l.length; i++) if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]);
		this._events[ev] = n;
	}
	return this;
};
FSWatcher.prototype.off = function(ev, fn) {
	return this.removeListener(ev, fn);
};
FSWatcher.prototype.close = function() {
	if (this._closed) return this;
	this._closed = true;
	if (this._onSignalAbort && this._signal && typeof this._signal.removeEventListener === "function") this._signal.removeEventListener("abort", this._onSignalAbort);
	if (this._stop) this._stop();
	else if (this._timer) clearInterval(this._timer);
	this.emit("close");
	return this;
};
FSWatcher.prototype.stop = function() {
	if (this._stopped) return this;
	this._stopped = true;
	this.close();
	_deferFsCallback((function() {
		if (this._stopped) this.emit("stop");
	}).bind(this));
	return this;
};
function _setWatcherTimerRef(timer, shouldRef) {
	if (timer === void 0 || timer === null) return;
	if (typeof timer === "object") {
		var method = shouldRef ? timer.ref : timer.unref;
		if (typeof method === "function") {
			method.call(timer);
			return;
		}
	}
	var control = shouldRef ? g.__exactTimerRef : g.__exactTimerUnref;
	if (typeof control === "function") control(timer);
}
FSWatcher.prototype.ref = function() {
	this._unrefed = false;
	if (this._start) this._start();
	if (this._timer) _setWatcherTimerRef(this._timer, true);
	return this;
};
FSWatcher.prototype.unref = function() {
	this._unrefed = true;
	if (this._timer) _setWatcherTimerRef(this._timer, false);
	return this;
};
FSWatcher.prototype.listenerCount = function(ev) {
	return this._events[ev] ? this._events[ev].length : 0;
};
function pathBasename(filePath) {
	var slash = filePath.lastIndexOf("/");
	var backslash = filePath.lastIndexOf("\\");
	if (backslash > slash) slash = backslash;
	if (slash === -1) return filePath;
	return filePath.slice(slash + 1);
}
function pathJoin(base, child) {
	if (!base) return child;
	var last = base.charAt(base.length - 1);
	if (last === "/" || last === "\\") return base + child;
	return base + "/" + child;
}
function relativePathFromCwd(path) {
	if (!_isAbsolutePath(path)) return path;
	var cwd = _resolvePathFromCwd(".");
	if (path === cwd) return ".";
	if (cwd === "/") return path.slice(1);
	if (path.indexOf(cwd + "/") === 0) return path.slice(cwd.length + 1);
	return path;
}
function _watchEventPath(filename, encoding, recursive) {
	if (filename === null || filename === void 0) return watchFilename(filename, encoding);
	return watchFilename(recursive ? filename : pathBasename(filename), encoding);
}
function watchFilename(filename, encoding) {
	if (filename === null || filename === void 0) return filename;
	if (typeof encoding === "string") encoding = encoding.toLowerCase();
	if (encoding === "buffer") {
		if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") return Buffer.from(filename);
		return toUint8Array(filename);
	}
	if (!encoding || encoding === "utf8" || encoding === "utf-8") return filename;
	if (encoding === "hex") {
		var bytes = toUint8Array(filename);
		var hex = "";
		for (var i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
		return hex;
	}
	return decodeBytes(toUint8Array(filename), encoding);
}
function buildWatchFileStateAsync(filename) {
	return promises.stat(filename).then(function(stat) {
		return {
			mtime: stat.mtimeMs || 0,
			ctime: stat.ctimeMs || 0,
			size: stat.size || 0,
			ino: Number(stat.ino) || 0
		};
	}, function() {
		return null;
	});
}
function buildWatchDirStateAsync(dirname, recursive, prefix) {
	return Promise.all([promises.stat(dirname), promises.readdir(dirname)]).then(function(values) {
		var dirStat = values[0];
		var files = values[1];
		var entries = { __meta: { mtime: dirStat.mtimeMs || 0 } };
		return _boundedAsyncMap(files, 32, function(file) {
			var fullPath = pathJoin(dirname, file);
			var key = prefix ? prefix + "/" + file : file;
			return promises.lstat(fullPath).then(function(stat) {
				var row = {
					isDirectory: typeof stat.isDirectory === "function" && stat.isDirectory(),
					mtime: stat.mtimeMs || 0,
					size: stat.size || 0
				};
				entries[key] = row;
				if (!recursive || !row.isDirectory) return;
				return buildWatchDirStateAsync(fullPath, true, key).then(function(children) {
					if (!children) return;
					for (var child in children) if (child !== "__meta") entries[child] = children[child];
				});
			}, function() {});
		}).then(function() {
			return entries;
		});
	}, function() {
		return null;
	});
}
function emitWatchDirectoryChanges(watcher, encoding, prevState, nextState) {
	var changed = false;
	if (!prevState) prevState = {};
	if (!nextState) nextState = {};
	for (var key in nextState) {
		if (key === "__meta") continue;
		if (!prevState[key]) {
			watcher.emit("change", "rename", _watchEventPath(key, encoding, watcher._recursive));
			changed = true;
			continue;
		}
		if (!nextState[key].isDirectory && !prevState[key].isDirectory && (nextState[key].mtime !== prevState[key].mtime || nextState[key].size !== prevState[key].size)) {
			watcher.emit("change", "change", _watchEventPath(key, encoding, watcher._recursive));
			changed = true;
		}
	}
	for (var key2 in prevState) {
		if (key2 === "__meta") continue;
		if (!nextState[key2]) {
			watcher.emit("change", "rename", _watchEventPath(key2, encoding, watcher._recursive));
			changed = true;
		}
	}
	return changed;
}
function makeZeroStats(bigint) {
	return !!bigint ? _makeBigIntStats({
		dev: 0,
		ino: 0,
		mode: 0,
		nlink: 0,
		uid: 0,
		gid: 0,
		rdev: 0,
		size: 0,
		blksize: 0,
		blocks: 0,
		atimeMs: 0,
		mtimeMs: 0,
		ctimeMs: 0,
		birthtimeMs: 0,
		atimeNs: 0,
		mtimeNs: 0,
		ctimeNs: 0,
		birthtimeNs: 0
	}) : new Stats({}, false);
}
function watch(filename, options, listener) {
	if (typeof options === "function") {
		listener = options;
		options = {};
	}
	options = _normalizeWatchOptions(options);
	if (listener && typeof listener !== "function") _validateCallback(listener);
	_validatePath(filename, "filename");
	_guardClosedFsMutation("watch", filename);
	var watcher = new FSWatcher();
	watcher._filename = _pathToString(filename);
	watcher._signal = options.signal;
	watcher._handle = { onchange: function(code, errorName, pathValue) {
		var errCode = errorName || _uvCodeFromErrno(code);
		var err = _makeFsError({
			errno: code,
			code: typeof errCode === "string" ? errCode : void 0,
			path: pathValue,
			filename: pathValue,
			syscall: "watch"
		}, "watch", pathValue);
		watcher.emit("error", err);
		watcher.close();
	} };
	watcher._onSignalAbort = function() {
		watcher.close();
	};
	if (watcher._signal && typeof watcher._signal.addEventListener === "function") watcher._signal.addEventListener("abort", watcher._onSignalAbort);
	if (watcher._signal && watcher._signal.aborted === true) {
		_deferFsCallback(function() {
			watcher.close();
		});
		return watcher;
	}
	var encoding = options.encoding || "utf8";
	if (listener) watcher.on("change", listener);
	var stat;
	var targetIsDirectory = false;
	try {
		stat = statSync(watcher._filename);
		targetIsDirectory = !!(stat && stat.isDirectory && stat.isDirectory());
	} catch (e) {
		throw _makeFsError(e, "watch", watcher._filename);
	}
	if (targetIsDirectory) {
		watcher._isDirectory = true;
		watcher._recursive = !!options.recursive;
		watcher._prevState = null;
		watcher._polling = false;
		var directoryInterval = options.interval || 25;
		watcher._poll = function() {
			if (watcher._closed || watcher._stopped || watcher._polling) return;
			watcher._polling = true;
			buildWatchDirStateAsync(watcher._filename, watcher._recursive).then(function(nextState) {
				if (watcher._closed || watcher._stopped) return;
				if (!nextState) {
					watcher.emit("change", "rename", watchFilename(pathBasename(watcher._filename), encoding));
					watcher._prevState = {};
					return;
				}
				if (watcher._prevState === null) {
					watcher._prevState = nextState;
					return;
				}
				if (!emitWatchDirectoryChanges(watcher, encoding, watcher._prevState, nextState) && watcher._prevState && nextState.__meta && watcher._prevState.__meta && nextState.__meta.mtime !== watcher._prevState.__meta.mtime) watcher.emit("change", "rename", null);
				watcher._prevState = nextState;
			}).finally(function() {
				watcher._polling = false;
			});
		};
		watcher._pollInterval = directoryInterval;
		watcher._start = function() {
			if (watcher._timer || watcher._closed || watcher._stopped) return;
			watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
			if (watcher._unrefed) _setWatcherTimerRef(watcher._timer, false);
		};
		watcher._stop = function() {
			if (watcher._timer) {
				clearInterval(watcher._timer);
				watcher._timer = null;
			}
		};
		watcher._start();
		watcher._poll();
	} else {
		var lastFileState = null;
		watcher._polling = false;
		var fileInterval = options.interval || 25;
		watcher._poll = function() {
			if (watcher._closed || watcher._polling) return;
			watcher._polling = true;
			buildWatchFileStateAsync(watcher._filename).then(function(nextFileState) {
				if (watcher._closed) return;
				if (!nextFileState) {
					if (lastFileState) {
						lastFileState = null;
						watcher.emit("change", "rename", watchFilename(pathBasename(watcher._filename), encoding));
					}
					return;
				}
				if (!lastFileState || nextFileState.mtime !== lastFileState.mtime || nextFileState.ctime !== lastFileState.ctime || nextFileState.size !== lastFileState.size || nextFileState.ino !== lastFileState.ino) {
					if (lastFileState) watcher.emit("change", "change", watchFilename(pathBasename(watcher._filename), encoding));
					lastFileState = nextFileState;
				}
			}).finally(function() {
				watcher._polling = false;
			});
		};
		watcher._pollInterval = fileInterval;
		watcher._start = function() {
			if (watcher._timer || watcher._closed || watcher._stopped) return;
			watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
			if (watcher._unrefed) _setWatcherTimerRef(watcher._timer, false);
		};
		watcher._stop = function() {
			if (watcher._timer) {
				clearInterval(watcher._timer);
				watcher._timer = null;
			}
		};
		watcher._start();
		watcher._poll();
	}
	if (options.persistent === false) watcher.unref();
	return watcher;
}
function _promisesWatch(path, options) {
	options = _normalizeWatchFileOptions(path, options);
	var signal = options && options.signal;
	var syncWatcher = watch(path, options);
	var queue = [];
	var pendingResolve = null;
	var pendingReject = null;
	var closed = false;
	var abortError = null;
	function onChange(eventType, filename) {
		if (closed) return;
		var payload = {
			eventType,
			filename
		};
		if (pendingResolve) {
			var resolveNext = pendingResolve;
			pendingResolve = null;
			pendingReject = null;
			resolveNext({
				done: false,
				value: payload
			});
		} else queue.push(payload);
	}
	function closeWatch() {
		if (closed) return;
		closed = true;
		syncWatcher.removeListener("change", onChange);
		syncWatcher.close();
		if (signal && typeof signal.removeEventListener === "function") signal.removeEventListener("abort", onSignalAbort);
		if (pendingResolve) {
			var resolvePending = pendingResolve;
			var rejectPending = pendingReject;
			pendingResolve = null;
			pendingReject = null;
			if (abortError) rejectPending(abortError);
			else resolvePending({ done: true });
		}
	}
	function onSignalAbort() {
		abortError = _makeAbortError(signal && signal.reason);
		closeWatch();
	}
	if (signal && typeof signal.addEventListener === "function") signal.addEventListener("abort", onSignalAbort);
	syncWatcher.on("change", onChange);
	return {
		next: function() {
			if (closed) {
				if (abortError) return Promise.reject(abortError);
				return Promise.resolve({ done: true });
			}
			if (queue.length > 0) return Promise.resolve({
				done: false,
				value: queue.shift()
			});
			return new Promise(function(resolve, reject) {
				pendingResolve = resolve;
				pendingReject = reject;
			});
		},
		return: function() {
			closeWatch();
			return Promise.resolve({ done: true });
		},
		[Symbol.asyncIterator]: function() {
			return this;
		}
	};
}
var _watchedFiles = {};
function watchFile(filename, options, listener) {
	if (typeof options === "function") {
		listener = options;
		options = {};
	}
	options = options || {};
	options = _normalizeWatchFileOptions(filename, options);
	if (!listener) throw _fsInvalidArgType("listener", "function", listener);
	if (typeof listener !== "function") _validateCallback(listener);
	_validatePath(filename, "filename");
	_guardClosedFsMutation("watchFile", filename);
	var resolvedFilename = _pathToString(filename);
	var statOptions = { bigint: options.bigint };
	var watcher = _watchedFiles[resolvedFilename];
	if (!watcher) {
		watcher = new FSWatcher();
		watcher._filename = resolvedFilename;
		watcher._listeners = [];
		watcher._initialized = false;
		watcher._hadInitialStat = false;
		watcher._timer = null;
		watcher._statOptions = statOptions;
		watcher._prevExists = false;
		watcher._prev = makeZeroStats(watcher._statOptions.bigint);
		watcher._polling = false;
		var statNative = _fsAsyncNative("__exactFsStatAsync");
		function asyncWatchStat() {
			return statNative ? _asyncStatImpl(statNative, resolvedFilename, "stat", _extractStatOptions(watcher._statOptions)) : Promise.resolve().then(function() {
				return statSync(resolvedFilename, watcher._statOptions);
			});
		}
		asyncWatchStat().then(function(initial) {
			watcher._prev = initial;
			watcher._prevExists = true;
			watcher._hadInitialStat = true;
		}, function() {
			watcher._prevExists = false;
			if (!watcher._closed) watcher.emit("change", watcher._prev, watcher._prev);
		});
		var watchFileInterval = options.interval || 5007;
		watcher._poll = function() {
			if (watcher._closed || watcher._stopped) return;
			if (watcher._polling) return;
			watcher._polling = true;
			asyncWatchStat().then(function(curr) {
				finish(curr, true);
			}, function() {
				finish(makeZeroStats(watcher._statOptions.bigint), false);
			});
			function finish(curr, currExists) {
				watcher._polling = false;
				if (watcher._closed || watcher._stopped) return;
				if (!watcher._initialized) watcher._initialized = true;
				if (watcher._prevExists !== currExists || (curr.mtimeMs || 0) !== (watcher._prev.mtimeMs || 0) || (curr.size || 0) !== (watcher._prev.size || 0)) watcher.emit("change", curr, watcher._prev);
				watcher._prev = curr;
				watcher._prevExists = currExists;
			}
		};
		watcher._pollInterval = watchFileInterval;
		watcher._start = function() {
			if (watcher._timer || watcher._closed || watcher._stopped) return;
			watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
			if (watcher._unrefed) _setWatcherTimerRef(watcher._timer, false);
		};
		watcher._stop = function() {
			if (watcher._timer) {
				clearInterval(watcher._timer);
				watcher._timer = null;
			}
		};
		watcher._start();
		if (options.persistent === false) watcher.unref();
		_watchedFiles[resolvedFilename] = watcher;
	}
	if (listener) {
		var wrapped = function(curr, prev) {
			listener(curr, prev);
		};
		wrapped._exactListener = listener;
		watcher._listeners.push(wrapped);
		watcher.on("change", wrapped);
	}
	return watcher;
}
function unwatchFile(filename) {
	_validatePath(filename, "filename");
	var resolvedFilename = _pathToString(filename);
	var watcher = _watchedFiles[resolvedFilename];
	if (!watcher) return;
	if (!watcher._listeners) watcher._listeners = [];
	if (arguments.length > 1 && arguments[1] !== void 0) {
		if (typeof arguments[1] !== "function") _validateCallback(arguments[1]);
		var listener = arguments[1];
		var next = [];
		var removed = false;
		for (var i = 0; i < watcher._listeners.length; i++) {
			var entry = watcher._listeners[i];
			if (!removed && entry._exactListener === listener) {
				watcher.removeListener("change", entry);
				removed = true;
				continue;
			}
			next.push(entry);
		}
		watcher._listeners = next;
		if (watcher._listeners.length === 0) {
			watcher.stop();
			delete _watchedFiles[resolvedFilename];
		}
		return;
	}
	watcher.stop();
	delete _watchedFiles[resolvedFilename];
}
function symlinkSync(target, path, type) {
	var t = _coercePathFromURL(target, "target");
	_validatePath(t, "target");
	_validatePath(path, "path");
	_validateSymlinkType(type);
	ensureExactFs();
	_guardClosedFsMutation("symlink", target, path);
	var p = _pathToString(path);
	var targetPath = typeof t === "string" ? t : Buffer.isBuffer(t) ? t.toString() : _coercePathFromURL(t, "target");
	var linkPath = "" + p;
	try {
		if (typeof g.__exactSymlink === "function") return g.__exactSymlink(targetPath, linkPath);
		throw new Error("ENOSYS: symlink not available");
	} catch (e) {
		throw _makeFsError(e, "symlink", targetPath, linkPath);
	}
}
function symlink(target, path, type, cb) {
	if (typeof type === "function") {
		cb = type;
		type = void 0;
	}
	_validateCallback(cb);
	_validatePath(target, "target");
	_validatePath(path, "path");
	_validateSymlinkType(type);
	_guardClosedFsMutation("symlink", target, path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var t = _coercePathFromURL(target, "target");
		var targetPath = typeof t === "string" ? t : Buffer.isBuffer(t) ? t.toString() : _coercePathFromURL(t, "target");
		var linkPath = "" + _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "symlink", [targetPath, linkPath], "symlink", targetPath, linkPath), cb);
	}
	wrapCallback(function() {
		symlinkSync(target, path, type);
	}, cb, "symlink");
}
function linkSync(existingPath, newPath) {
	_validatePath(existingPath, "existingPath");
	_validatePath(newPath, "newPath");
	ensureExactFs();
	_guardClosedFsMutation("link", existingPath, newPath);
	var ep = _pathToString(existingPath);
	var np = _pathToString(newPath);
	try {
		if (typeof g.__exactLink === "function") return g.__exactLink(ep, np);
		throw new Error("ENOSYS: link not available");
	} catch (e) {
		throw _makeFsError(e, "link", ep, np);
	}
}
function link(existingPath, newPath, cb) {
	_validateCallback(cb);
	_validatePath(existingPath, "existingPath");
	_validatePath(newPath, "newPath");
	_guardClosedFsMutation("link", existingPath, newPath);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var ep = _pathToString(existingPath);
		var np = _pathToString(newPath);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "link", [ep, np], "link", ep, np), cb);
	}
	wrapCallback(function() {
		linkSync(existingPath, newPath);
	}, cb, "link");
}
function readlinkSync(path, options) {
	_validatePath(path, "path");
	_validateEncodingOption(options);
	ensureExactFs();
	var p = _pathToString(path);
	try {
		if (typeof g.__exactReadlink === "function") return g.__exactReadlink(p);
		throw new Error("ENOSYS: readlink not available");
	} catch (e) {
		throw _makeFsError(e, "readlink", p);
	}
}
function readlink(path, options, cb) {
	if (typeof options === "function") {
		cb = options;
		options = void 0;
	}
	_validateCallback(cb);
	_validatePath(path, "path");
	_validateEncodingOption(options);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "readlink", [p], "readlink", p).then(function(value) {
			return _encodeFsPathResult(value, options);
		}), cb);
	}
	wrapCallback(function() {
		return readlinkSync(path, options);
	}, cb, "readlink", _pathToString(path));
}
function truncateSync(path, len) {
	if (typeof path === "number") return ftruncateSync(path, len);
	_validatePath(path);
	len = _normalizeTruncateLen(len);
	ensureExactFs();
	var p = _pathToString(path);
	try {
		if (typeof g.__exactTruncate === "function") return g.__exactTruncate(p, len);
		throw new Error("ENOSYS: truncate not available");
	} catch (e) {
		throw _makeFsError(e, "truncate", p);
	}
}
function truncate(path, len, cb) {
	if (typeof len === "function") {
		cb = len;
		len = void 0;
	}
	if (typeof path === "number") return ftruncate(path, len, cb);
	_validatePath(path);
	len = _normalizeTruncateLen(len);
	_validateCallback(cb);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "truncate", [
			p,
			null,
			len
		], "truncate", p), cb);
	}
	wrapCallback(function() {
		truncateSync(path, len);
	}, cb, "truncate", _pathToString(path));
}
function chownSync(path, uid, gid) {
	_validatePath(path);
	_validateUidOrGid("uid", uid);
	_validateUidOrGid("gid", gid);
	_guardClosedFsMutation("chown", path);
	if (uid === -1 && gid === -1) return;
	ensureExactFs();
	var p = _pathToString(path);
	try {
		if (typeof g.__exactChown === "function") return g.__exactChown(p, uid, gid);
	} catch (e) {
		throw _makeFsError(e, "chown", p);
	}
	throw _makeUnsupportedFsError("chown", p);
}
function chown(path, uid, gid, cb) {
	_validateCallback(cb);
	_validatePath(path);
	_validateUidOrGid("uid", uid);
	_validateUidOrGid("gid", gid);
	_guardClosedFsMutation("chown", path);
	if (uid === -1 && gid === -1) return _deferFsCallback(function() {
		cb(null);
	});
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "chown", [
			p,
			null,
			uid,
			gid
		], "chown", p), cb);
	}
	wrapCallback(function() {
		chownSync(path, uid, gid);
	}, cb, "chown", _pathToString(path));
}
function lchownSync(path, uid, gid) {
	_validatePath(path);
	_validateUidOrGid("uid", uid);
	_validateUidOrGid("gid", gid);
	_guardClosedFsMutation("lchown", path);
	if (uid === -1 && gid === -1) return;
	ensureExactFs();
	var p = _pathToString(path);
	try {
		if (typeof g.__exactLchown === "function") return g.__exactLchown(p, uid, gid);
	} catch (e) {
		throw _makeFsError(e, "lchown", p);
	}
	throw _makeUnsupportedFsError("lchown", p);
}
function _toUnixTimestamp(time) {
	if (time instanceof Date) return time.getTime() / 1e3;
	if (typeof time === "string") {
		var parsed = Number(time);
		if (!Number.isFinite(parsed)) throw _fsInvalidArgType("time", "Date or finite number or numeric string", time);
		return parsed;
	}
	if (typeof time === "number") {
		if (!Number.isFinite(time)) throw _fsInvalidArgType("time", "Date or finite number or numeric string", time);
		return time;
	}
	throw _fsInvalidArgType("time", "Date or finite number or numeric string", time);
}
function utimesSync(path, atime, mtime) {
	_validatePath(path);
	ensureExactFs();
	_guardClosedFsMutation("utime", path);
	var p = _pathToString(path);
	var at = _toUnixTimestamp(atime);
	var mt = _toUnixTimestamp(mtime);
	try {
		if (typeof g.__exactUtimes === "function") return g.__exactUtimes(p, at, mt);
	} catch (e) {
		throw _makeFsError(e, "utime", p);
	}
	throw _makeUnsupportedFsError("utime", p);
}
function utimes(path, atime, mtime, cb) {
	_validateCallback(cb);
	_validatePath(path);
	_guardClosedFsMutation("utime", path);
	var at = _toUnixTimestamp(atime);
	var mt = _toUnixTimestamp(mtime);
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "utime", [
			p,
			null,
			at,
			mt
		], "utime", p), cb);
	}
	wrapCallback(function() {
		utimesSync(path, atime, mtime);
	}, cb, "utime", _pathToString(path));
}
function _rmSyncInternal(path, options, preserveOriginalError) {
	ensureExactFs();
	_validatePath(path, "path");
	_guardClosedFsMutation("rm", path);
	if (typeof options === "boolean") options = {
		recursive: true,
		force: true
	};
	else options = options || {};
	var recursive = !!(options && options.recursive);
	var force = !!(options && options.force);
	var maxRetries = options && typeof options.maxRetries === "number" && options.maxRetries > 0 ? Math.floor(options.maxRetries) : 0;
	function removeEntry(targetPath, isDirectory) {
		try {
			if (isDirectory) rmdirSync(targetPath);
			else unlinkSync(targetPath);
			return;
		} catch (err) {
			if (!force || !err || err.code !== "EACCES" && err.code !== "EPERM") throw err;
			chmodSync(targetPath, isDirectory ? 511 : 438);
			if (isDirectory) rmdirSync(targetPath);
			else unlinkSync(targetPath);
		}
	}
	function performRemove() {
		var info = lstatSync(path);
		if (typeof info.isDirectory === "function" ? info.isDirectory() : info.is_dir) {
			if (!recursive) throw _makeRmDirError(path);
			if (recursive) {
				var entries;
				if (force) try {
					chmodSync(path, 511);
				} catch (_ignore) {}
				try {
					entries = readdirSync(path);
				} catch (e2) {
					if (force && e2 && (e2.code === "EACCES" || e2.code === "EPERM")) {
						chmodSync(path, 511);
						entries = readdirSync(path);
					} else throw e2;
				}
				for (var i = 0; i < entries.length; i++) rmSync(pathJoin(path, entries[i]), options);
			}
			removeEntry(path, true);
		} else removeEntry(path, false);
	}
	function shouldRetryRm(err) {
		if (!err || typeof err.code !== "string") return false;
		return err.code === "EBUSY" || err.code === "EMFILE" || err.code === "ENFILE" || err.code === "ENOTEMPTY" || err.code === "EPERM";
	}
	for (var attempt = 0;; attempt++) try {
		performRemove();
		return;
	} catch (e) {
		if (force && e && (e.code === "ENOENT" || e.code === "ENOTDIR")) return;
		if (attempt < maxRetries && shouldRetryRm(e)) continue;
		throw preserveOriginalError ? e : _normalizeRmError(e, path, recursive);
	}
}
function rmSync(path, options) {
	return _rmSyncInternal(path, options, false);
}
function rm(path, options, cb) {
	if (typeof options === "function") {
		cb = options;
		options = {};
	}
	_validateCallback(cb);
	_validatePath(path, "path");
	_deferFsPromiseCallback(_asyncRm(path, options || {}), cb);
}
function _asyncRm(path, options) {
	_validatePath(path, "path");
	_guardClosedFsMutation("rm", path);
	if (typeof options === "boolean") options = {
		recursive: true,
		force: true
	};
	options = options || {};
	var p = _pathToString(path), force = options.force === true, recursive = options.recursive === true;
	var maxRetries = typeof options.maxRetries === "number" && options.maxRetries > 0 ? Math.floor(options.maxRetries) : 0;
	var retryDelay = typeof options.retryDelay === "number" && options.retryDelay >= 0 ? options.retryDelay : 100;
	function removeOne(target) {
		return promises.lstat(target).then(function(st) {
			if (!st.isDirectory() || st.isSymbolicLink()) return promises.unlink(target);
			if (!recursive) throw _makeRmDirError(target);
			return promises.readdir(target).then(function(names) {
				return names.reduce(function(chain, name) {
					return chain.then(function() {
						return removeOne(pathJoin(target, name));
					});
				}, Promise.resolve());
			}).then(function() {
				return promises.rmdir(target);
			});
		}, function(err) {
			if (force && err && (err.code === "ENOENT" || err.code === "ENOTDIR")) return;
			throw err;
		});
	}
	function attempt(n) {
		return removeOne(p).catch(function(err) {
			if (force && err && (err.code === "ENOENT" || err.code === "ENOTDIR")) return;
			if (!(err && (err.code === "EBUSY" || err.code === "EMFILE" || err.code === "ENFILE" || err.code === "ENOTEMPTY" || err.code === "EPERM")) || n >= maxRetries) throw _normalizeRmError(err, p, recursive);
			return new Promise(function(resolve) {
				setTimeout(resolve, retryDelay * (n + 1));
			}).then(function() {
				return attempt(n + 1);
			});
		});
	}
	return attempt(0);
}
function _resolveAsync(value) {
	return function() {
		try {
			return Promise.resolve(value());
		} catch (err) {
			return Promise.reject(err);
		}
	};
}
function _fileHandleErrorFromClosed() {
	var err = /* @__PURE__ */ new Error("ERR_FS_FILE_CLOSED: FileHandle is already closed");
	err.code = "ERR_FS_FILE_CLOSED";
	return err;
}
var _fileHandlePromiseStates = typeof WeakMap === "function" ? /* @__PURE__ */ new WeakMap() : null;
function _fileHandlePromiseState(handle) {
	var state = _fileHandlePromiseStates && _fileHandlePromiseStates.get(handle);
	if (!state) {
		var err = /* @__PURE__ */ new TypeError("Illegal FileHandle receiver");
		err.code = "ERR_INVALID_THIS";
		throw err;
	}
	return state;
}
function _fileHandlePromiseOpenFd(handle) {
	var state = _fileHandlePromiseState(handle);
	if (state.closed || state.fd === null) throw _fileHandleErrorFromClosed();
	return state.fd;
}
function FileHandlePromise(fd, path, flags) {
	if (!_fileHandlePromiseStates || typeof Object.defineProperty !== "function") throw new Error("FileHandle requires WeakMap-backed private state");
	var state = {
		fd: typeof fd === "number" ? fd : null,
		closed: false,
		closing: null
	};
	_fileHandlePromiseStates.set(this, state);
	Object.defineProperty(this, "fd", {
		enumerable: true,
		configurable: false,
		get: function() {
			return state.fd;
		},
		set: function() {
			throw new TypeError("FileHandle.fd is read-only");
		}
	});
	Object.defineProperty(this, "_closed", {
		enumerable: false,
		configurable: false,
		get: function() {
			return state.closed;
		},
		set: function() {
			throw new TypeError("FileHandle close state is private");
		}
	});
	this.path = path;
	this.flags = flags || "r";
}
FileHandlePromise.prototype._ensureOpen = function() {
	_fileHandlePromiseOpenFd(this);
};
FileHandlePromise.prototype.close = function() {
	var state = _fileHandlePromiseState(this);
	if (state.closed || state.fd === null) return Promise.reject(_fileHandleErrorFromClosed());
	if (state.closing) return state.closing;
	var closeResult = _resolveAsync(function() {
		var native = _fsAsyncNative("__exactFsCloseAsync");
		return native ? _asyncClose(native, state.fd) : closeSync(state.fd);
	})();
	var closing = Promise.resolve(closeResult).then(function(result) {
		if (state.closing === closing) {
			state.closed = true;
			state.fd = null;
			state.closing = null;
		}
		return result;
	}, function(err) {
		if (state.closing === closing) state.closing = null;
		throw err;
	});
	state.closing = closing;
	return closing;
};
if (typeof Symbol !== "undefined" && typeof Symbol.asyncDispose === "symbol") FileHandlePromise.prototype[Symbol.asyncDispose] = function() {
	return this.close();
};
else FileHandlePromise.prototype.asyncDispose = function() {
	return this.close();
};
FileHandlePromise.prototype.read = function(buffer, offset, length, position) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		if (typeof buffer === "object" && buffer !== null && buffer.length !== void 0) {
			var off = typeof offset === "number" ? offset : 0;
			var len = typeof length === "number" ? length : buffer.length - off;
			var pos = position === void 0 || position === null ? -1 : position;
			var native = _fsAsyncNative("__exactFsReadAsync");
			if (native) return _asyncReadIntoBuffer(native, fd, buffer, off, len, pos).then(function(bytesRead) {
				return {
					bytesRead,
					buffer
				};
			});
			return {
				bytesRead: readSync(fd, buffer, off, len, pos),
				buffer
			};
		}
		throw _fsInvalidArgType("buffer", "string or an instance of Buffer or Uint8Array", buffer);
	})();
};
FileHandlePromise.prototype.write = function(buffer, offset, length, position) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var off = typeof offset === "number" ? offset : 0;
		var len = typeof length === "number" ? length : buffer.length - off;
		var pos = position === void 0 || position === null ? -1 : position;
		var native = _fsAsyncNative("__exactFsWriteAsync");
		if (native) return _asyncWriteFromArgs(native, fd, buffer, off, len, pos).then(function(bytesWritten) {
			return {
				bytesWritten,
				buffer
			};
		});
		return {
			bytesWritten: writeSync(fd, buffer, off, len, pos),
			buffer
		};
	})();
};
FileHandlePromise.prototype.readv = function(buffers, position) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsReadvAsync");
		if (native) return _asyncReadvIntoBuffers(native, fd, buffers, position).then(function(bytesRead) {
			return {
				bytesRead,
				buffers
			};
		});
		return {
			bytesRead: readvSync(fd, buffers, position),
			buffers
		};
	})();
};
FileHandlePromise.prototype.writev = function(buffers, position) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsWritevAsync");
		if (native) return _asyncWritevFromBuffers(native, fd, buffers, position).then(function(bytesWritten) {
			return {
				bytesWritten,
				buffers
			};
		});
		return {
			bytesWritten: writevSync(fd, buffers, position),
			buffers
		};
	})();
};
FileHandlePromise.prototype.readFile = function(options) {
	var handle = this;
	return _resolveAsync(function() {
		return _promisesReadFileWithSignal(_fileHandlePromiseOpenFd(handle), options);
	})();
};
FileHandlePromise.prototype.writeFile = function(data, options) {
	var handle = this;
	return _resolveAsync(function() {
		return _promisesWriteFile(_fileHandlePromiseOpenFd(handle), data, options);
	})();
};
FileHandlePromise.prototype.appendFile = function(data, options) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsWriteFileAsync");
		if (native) {
			_validateWriteData(data);
			var writeOptions = _normalizeWriteOptions(options);
			return _asyncWriteFileImpl(native, {
				fd,
				path: handle.path
			}, data, writeOptions, "a").then(function() {});
		}
		appendFileSync(fd, data, options);
	})();
};
FileHandlePromise.prototype.createReadStream = function(options) {
	_fileHandlePromiseOpenFd(this);
	var fileOptions = options ? _extend(options, {
		fd: this,
		autoClose: false
	}) : {
		fd: this,
		autoClose: false
	};
	return createReadStream(this.path, fileOptions);
};
FileHandlePromise.prototype.createWriteStream = function(options) {
	_fileHandlePromiseOpenFd(this);
	var fileOptions = options ? _extend(options, {
		fd: this,
		autoClose: false
	}) : {
		fd: this,
		autoClose: false
	};
	return createWriteStream(this.path, fileOptions);
};
FileHandlePromise.prototype.truncate = function(len) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		len = _normalizeTruncateLen(len);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "ftruncate", fd, len) : ftruncateSync(fd, len);
	})();
};
FileHandlePromise.prototype.sync = function() {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "fsync", fd) : _callFsyncSync(fd);
	})();
};
FileHandlePromise.prototype.datasync = function() {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "fdatasync", fd) : fdatasyncSync(fd);
	})();
};
FileHandlePromise.prototype.readLines = function() {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsReadFileAsync");
		var contents = native ? _asyncReadFileImpl(native, fd, { encoding: "utf8" }) : readFileSync(fd, "utf8");
		return Promise.resolve(contents).then(function(text) {
			var lines = text.split("\n");
			if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
			return _makeAsyncIteratorFromArray(lines);
		});
	})();
};
FileHandlePromise.prototype.stat = function(options) {
	var handle = this;
	return _resolveAsync(function() {
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsStatAsync");
		if (native) {
			_coerceStatOptions(options);
			return _asyncStatImpl(native, fd, "fstat", _extractStatOptions(options));
		}
		return fstatSync(fd, options);
	})();
};
FileHandlePromise.prototype.chmod = function(mode) {
	var handle = this;
	return _resolveAsync(function() {
		mode = _coerceMode(mode);
		_validateUint32("mode", mode);
		_guardClosedFsMutation("fchmod");
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "fchmod", fd, mode) : fchmodSync(fd, mode);
	})();
};
FileHandlePromise.prototype.chown = function(uid, gid) {
	var handle = this;
	return _resolveAsync(function() {
		_validateUidOrGid("uid", uid);
		_validateUidOrGid("gid", gid);
		_guardClosedFsMutation("fchown");
		if (uid === -1 && gid === -1) return;
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "fchown", fd, uid, gid) : fchownSync(fd, uid, gid);
	})();
};
FileHandlePromise.prototype.utimes = function(atime, mtime) {
	var handle = this;
	return _resolveAsync(function() {
		_guardClosedFsMutation("futimes");
		var fd = _fileHandlePromiseOpenFd(handle);
		var native = _fsAsyncNative("__exactFsFdAsync");
		return native ? _asyncFdOp(native, "futimes", fd, _toUnixTimestamp(atime), _toUnixTimestamp(mtime)) : futimesSync(fd, atime, mtime);
	})();
};
function _makeAsyncIteratorFromArray(values) {
	var i = 0;
	return {
		next: function() {
			if (i >= values.length) return Promise.resolve({ done: true });
			var value = values[i++];
			return Promise.resolve({
				done: false,
				value
			});
		},
		return: function() {
			return { done: true };
		},
		[Symbol.asyncIterator]: function() {
			return this;
		}
	};
}
function _makeAsyncIteratorFromPromise(valuesPromise) {
	var iteratorPromise = Promise.resolve(valuesPromise).then(_makeAsyncIteratorFromArray);
	return {
		next: function() {
			return iteratorPromise.then(function(it) {
				return it.next();
			});
		},
		return: function() {
			return iteratorPromise.then(function(it) {
				return it.return();
			});
		},
		[Symbol.asyncIterator]: function() {
			return this;
		}
	};
}
function _extend(target, source) {
	if (!source) return target;
	var keys = Object.keys(source);
	for (var i = 0; i < keys.length; i++) target[keys[i]] = source[keys[i]];
	return target;
}
function _promisesReadFileWithSignal(pathOrFd, options) {
	var opts = _normalizeReadFileOptions(options, true);
	if (opts.signal && opts.signal.aborted === true) throw _makeAbortError(opts.signal.reason);
	var native = _fsAsyncNative("__exactFsReadFileAsync");
	if (native) return _asyncReadFileImpl(native, pathOrFd, opts);
	return readFileSync(pathOrFd, options);
}
function _promisesStatViaAsync(path, options, kind) {
	var native = _fsAsyncNative("__exactFsStatAsync");
	if (!native) return kind === "lstat" ? lstatSync(path, options) : statSync(path, options);
	_validatePath(path);
	_coerceStatOptions(options);
	var statOptions = _extractStatOptions(options);
	return _asyncStatImpl(native, _pathToString(path), kind, statOptions).then(void 0, function(err) {
		if (statOptions.throwIfNoEntry === false && err && err.code === "ENOENT") return;
		throw err;
	});
}
var promises = {
	readFile: function(p, o) {
		return _resolveAsync(function() {
			return _promisesReadFileWithSignal(p, o);
		})();
	},
	writeFile: function(p, d, o) {
		return _promisesWriteFile(p, d, o);
	},
	appendFile: function(p, d, o) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsWriteFileAsync");
			if (native) {
				_validateWriteData(d);
				var writeOptions = _normalizeWriteOptions(o);
				return _asyncWriteFileImpl(native, _getFdOrPath(p, "path"), d, writeOptions, "a").then(function() {});
			}
			appendFileSync(p, d, o);
		})();
	},
	stat: function(p, o) {
		return _resolveAsync(function() {
			return _promisesStatViaAsync(p, o, "stat");
		})();
	},
	lstat: function(p, o) {
		return _resolveAsync(function() {
			return _promisesStatViaAsync(p, o, "lstat");
		})();
	},
	readdir: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p);
			_validateEncodingOption(o);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var promise = _asyncReaddirSimple(native, p, o);
				if (promise) return promise;
			}
			return readdirSync(p, o);
		})();
	},
	mkdir: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p);
			_validateMkdirRecursiveOption(o);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) return _asyncMkdirSimple(native, p, o);
			return mkdirSync(p, o);
		})();
	},
	rmdir: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p);
			_guardClosedFsMutation("rmdir", p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native && !(o && o.recursive === true)) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "rmdir", [pathString], "rmdir", pathString);
			}
			rmdirSync(p, o);
		})();
	},
	unlink: function(p) {
		return _resolveAsync(function() {
			_validatePath(p);
			_guardClosedFsMutation("unlink", p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "unlink", [pathString], "unlink", pathString);
			}
			unlinkSync(p);
		})();
	},
	rename: function(o, n) {
		return _resolveAsync(function() {
			_validatePath(o, "oldPath");
			_validatePath(n, "newPath");
			_guardClosedFsMutation("rename", o, n);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var op = _pathToString(o);
				var np = _pathToString(n);
				return _asyncFsPathOp(native, "rename", [op, np], "rename", op, np);
			}
			renameSync(o, n);
		})();
	},
	copyFile: function(s, d, m) {
		return _resolveAsync(function() {
			_validatePath(s, "src");
			_validatePath(d, "dest");
			_guardClosedFsMutation("copyfile", s, d);
			if (m !== void 0 && m !== null) _validateCopyFileMode(m);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var sp = _pathToString(s);
				var dp = _pathToString(d);
				return _asyncFsPathOp(native, (m & constants.COPYFILE_EXCL) === constants.COPYFILE_EXCL ? "copyfile_excl" : "copyfile", [sp, dp], "copyfile", sp, dp);
			}
			copyFileSync(s, d, m);
		})();
	},
	access: function(p, m) {
		return _resolveAsync(function() {
			_validatePath(p);
			var mode = _validateAccessMode(m);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "access", [
					pathString,
					null,
					mode
				], "access", pathString);
			}
			accessSync(p, m);
		})();
	},
	chmod: function(p, m) {
		return _resolveAsync(function() {
			_validatePath(p);
			_guardClosedFsMutation("chmod", p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "chmod", [
					pathString,
					null,
					typeof m === "string" ? parseInt(m, 8) : m
				], "chmod", pathString);
			}
			chmodSync(p, m);
		})();
	},
	realpath: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p);
			_validateEncodingOption(o);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _mapVendoredNodeTestPath(_pathToString(p));
				lstatSync(pathString);
				return _asyncFsPathOp(native, "realpath", [pathString], "realpath", pathString).then(function(value) {
					return _encodeFsPathResult(value, o);
				});
			}
			return realpathSync(p, o);
		})();
	},
	mkdtemp: function(p, o) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) return _asyncMkdtempResult(native, p, o).then(function(result) {
				return result.publicPath;
			});
			return mkdtempSync(p, o);
		})();
	},
	rm: function(p, o) {
		return _resolveAsync(function() {
			return _asyncRm(p, o || {});
		})();
	},
	cp: function(s, d, o) {
		return _resolveAsync(function() {
			return _asyncCp(s, d, o || {});
		})();
	},
	glob: function(pattern, o) {
		return _makeAsyncIteratorFromPromise(_asyncGlob(pattern, o || {}));
	},
	statfs: function(path, o) {
		return _resolveAsync(function() {
			_validatePath(path);
			_validateEncodingOption(o);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var p = _pathToString(path);
				return _asyncFsPathOp(native, "statfs", [p], "statfs", p).then(function(payload) {
					return new StatFs(typeof payload === "string" ? JSON.parse(payload) : payload, o && o.bigint);
				});
			}
			return statfsSync(path, o);
		})();
	},
	readv: function(fd, buffers, position) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsReadvAsync");
			if (native) return _asyncReadvIntoBuffers(native, fd, buffers, position).then(function(bytesRead) {
				return {
					bytesRead,
					buffers
				};
			});
			return {
				bytesRead: readvSync(fd, buffers, position),
				buffers
			};
		})();
	},
	writev: function(fd, buffers, position) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsWritevAsync");
			if (native) return _asyncWritevFromBuffers(native, fd, buffers, position).then(function(bytesWritten) {
				return {
					bytesWritten,
					buffers
				};
			});
			return {
				bytesWritten: writevSync(fd, buffers, position),
				buffers
			};
		})();
	},
	fdatasync: function(fd) {
		return _resolveAsync(function() {
			_validateFd(fd);
			var native = _fsAsyncNative("__exactFsFdAsync");
			return native ? _asyncFdOp(native, "fdatasync", fd) : fdatasyncSync(fd);
		})();
	},
	fsync: function(fd) {
		return _resolveAsync(function() {
			_validateFd(fd);
			var native = _fsAsyncNative("__exactFsFdAsync");
			return native ? _asyncFdOp(native, "fsync", fd) : fsyncSync(fd);
		})();
	},
	fstat: function(fd) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsStatAsync");
			if (native) {
				_validateFd(fd);
				return _asyncStatImpl(native, fd, "fstat", _extractStatOptions(void 0));
			}
			return fstatSync(fd);
		})();
	},
	watch: function(p, o) {
		return _promisesWatch(p, o);
	},
	read: function(fd, buffer, offset, length, position) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsReadAsync");
			if (native) {
				_validateFd(fd);
				return _asyncReadIntoBuffer(native, fd, buffer, offset, length, position).then(function(bytesRead) {
					return {
						bytesRead,
						buffer
					};
				});
			}
			return {
				bytesRead: readSync(fd, buffer, offset, length, position),
				buffer
			};
		})();
	},
	write: function(fd, bufferOrString, offset, length, position) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsWriteAsync");
			if (native) {
				_validateFd(fd);
				return _asyncWriteFromArgs(native, fd, bufferOrString, offset, length, position).then(function(written) {
					return {
						bytesWritten: written,
						buffer: bufferOrString
					};
				});
			}
			return {
				bytesWritten: writeSync(fd, bufferOrString, offset, length, position),
				buffer: bufferOrString
			};
		})();
	},
	open: function(p, f, m) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsOpenAsync");
			return native ? _asyncOpen(native, p, f, m).then(function(fd) {
				return new FileHandlePromise(fd, _pathToString(p), f);
			}) : new FileHandlePromise(openSync(p, f, m), _pathToString(p), f);
		})();
	},
	truncate: function(p, l) {
		return _resolveAsync(function() {
			if (typeof p === "number") {
				ftruncateSync(p, l);
				return;
			}
			_validatePath(p);
			var len = _normalizeTruncateLen(l);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "truncate", [
					pathString,
					null,
					len
				], "truncate", pathString);
			}
			truncateSync(p, len);
		})();
	},
	lchown: function(p, u, gi) {
		return _resolveAsync(function() {
			_validatePath(p);
			_validateUidOrGid("uid", u);
			_validateUidOrGid("gid", gi);
			_guardClosedFsMutation("lchown", p);
			if (u === -1 && gi === -1) return;
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "lchown", [
					pathString,
					null,
					u,
					gi
				], "lchown", pathString);
			}
			lchownSync(p, u, gi);
		})();
	},
	chown: function(p, u, gi) {
		return _resolveAsync(function() {
			_validatePath(p);
			_validateUidOrGid("uid", u);
			_validateUidOrGid("gid", gi);
			_guardClosedFsMutation("chown", p);
			if (u === -1 && gi === -1) return;
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "chown", [
					pathString,
					null,
					u,
					gi
				], "chown", pathString);
			}
			chownSync(p, u, gi);
		})();
	},
	utimes: function(p, a, m) {
		return _resolveAsync(function() {
			_validatePath(p);
			_guardClosedFsMutation("utime", p);
			var at = _toUnixTimestamp(a);
			var mt = _toUnixTimestamp(m);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "utime", [
					pathString,
					null,
					at,
					mt
				], "utime", pathString);
			}
			utimesSync(p, a, m);
		})();
	},
	lutimes: function(p, a, m) {
		return _resolveAsync(function() {
			_validatePath(p);
			_guardClosedFsMutation("lutimes", p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			var pathString = _pathToString(p);
			return native ? _asyncFsPathOp(native, "lutime", [
				pathString,
				null,
				_toUnixTimestamp(a),
				_toUnixTimestamp(m)
			], "lutimes", pathString) : lutimesSync(p, a, m);
		})();
	},
	lchmod: function(p, m) {
		return _resolveAsync(function() {
			_validatePath(p);
			m = _coerceMode(m);
			_validateUint32("mode", m);
			_guardClosedFsMutation("lchmod", p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			var pathString = _pathToString(p);
			return native ? _asyncFsPathOp(native, "lchmod", [
				pathString,
				null,
				m
			], "lchmod", pathString) : lchmodSync(p, m);
		})();
	},
	opendir: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			var pathString = _pathToString(p);
			return native ? _asyncBuildDirEntries(native, pathString, o || {}).then(function(entries) {
				return _dirFromEntries(p, entries);
			}) : opendirSync(p, o);
		})();
	},
	close: function(fd) {
		return _resolveAsync(function() {
			var native = _fsAsyncNative("__exactFsCloseAsync");
			return native ? _asyncClose(native, fd) : closeSync(fd);
		})();
	},
	symlink: function(t, p, ty) {
		return _resolveAsync(function() {
			var target = _coercePathFromURL(t, "target");
			_validatePath(target, "target");
			_validatePath(p, "path");
			_validateSymlinkType(ty);
			_guardClosedFsMutation("symlink", t, p);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var targetPath = typeof target === "string" ? target : Buffer.isBuffer(target) ? target.toString() : _coercePathFromURL(target, "target");
				var linkPath = "" + _pathToString(p);
				return _asyncFsPathOp(native, "symlink", [targetPath, linkPath], "symlink", targetPath, linkPath);
			}
			symlinkSync(t, p, ty);
		})();
	},
	link: function(e, n) {
		return _resolveAsync(function() {
			_validatePath(e, "existingPath");
			_validatePath(n, "newPath");
			_guardClosedFsMutation("link", e, n);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var ep = _pathToString(e);
				var np = _pathToString(n);
				return _asyncFsPathOp(native, "link", [ep, np], "link", ep, np);
			}
			linkSync(e, n);
		})();
	},
	readlink: function(p, o) {
		return _resolveAsync(function() {
			_validatePath(p, "path");
			_validateEncodingOption(o);
			var native = _fsAsyncNative("__exactFsPathAsync");
			if (native) {
				var pathString = _pathToString(p);
				return _asyncFsPathOp(native, "readlink", [pathString], "readlink", pathString).then(function(value) {
					return _encodeFsPathResult(value, o);
				});
			}
			return readlinkSync(p, o);
		})();
	},
	fchmod: function(fd, m) {
		return _resolveAsync(function() {
			_validateFdNonNegative(fd);
			m = _coerceMode(m);
			_validateUint32("mode", m);
			_guardClosedFsMutation("fchmod");
			var native = _fsAsyncNative("__exactFsFdAsync");
			return native ? _asyncFdOp(native, "fchmod", fd, m) : fchmodSync(fd, m);
		})();
	},
	fchown: function(fd, u, g) {
		return _resolveAsync(function() {
			_validateFdNonNegative(fd);
			_validateUidOrGid("uid", u);
			_validateUidOrGid("gid", g);
			_guardClosedFsMutation("fchown");
			if (u === -1 && g === -1) return;
			var native = _fsAsyncNative("__exactFsFdAsync");
			return native ? _asyncFdOp(native, "fchown", fd, u, g) : fchownSync(fd, u, g);
		})();
	},
	ftruncate: function(fd, l) {
		return _resolveAsync(function() {
			_validateFd(fd);
			l = _normalizeTruncateLen(l);
			var native = _fsAsyncNative("__exactFsFdAsync");
			return native ? _asyncFdOp(native, "ftruncate", fd, l) : ftruncateSync(fd, l);
		})();
	},
	FileHandle: FileHandlePromise,
	constants
};
var constants = Object.create(null);
constants.F_OK = 0;
constants.R_OK = 4;
constants.W_OK = 2;
constants.X_OK = 1;
var _fsPlatform = typeof process !== "undefined" && process.platform || "darwin";
constants.O_RDONLY = 0;
constants.O_WRONLY = 1;
constants.O_RDWR = 2;
if (_fsPlatform === "linux" || _fsPlatform === "android") {
	var _fsArch = typeof process !== "undefined" && process.arch || "arm64";
	var _fsLinuxX86 = _fsArch === "x64" || _fsArch === "ia32";
	constants.O_CREAT = 64;
	constants.O_EXCL = 128;
	constants.O_NOCTTY = 256;
	constants.O_TRUNC = 512;
	constants.O_APPEND = 1024;
	constants.O_NONBLOCK = 2048;
	constants.O_DSYNC = 4096;
	constants.O_DIRECT = _fsLinuxX86 ? 16384 : 65536;
	constants.O_DIRECTORY = _fsLinuxX86 ? 65536 : 16384;
	constants.O_NOFOLLOW = _fsLinuxX86 ? 131072 : 32768;
	constants.O_NOATIME = 262144;
	constants.O_SYNC = 1052672;
} else {
	constants.O_CREAT = 512;
	constants.O_EXCL = 2048;
	constants.O_NOCTTY = 131072;
	constants.O_TRUNC = 1024;
	constants.O_APPEND = 8;
	constants.O_NONBLOCK = 4;
	constants.O_DSYNC = 4194304;
	constants.O_DIRECTORY = 1048576;
	constants.O_NOFOLLOW = 256;
	constants.O_SYNC = 128;
	constants.O_SYMLINK = 2097152;
}
constants.S_IFMT = 61440;
constants.S_IFREG = 32768;
constants.S_IFDIR = 16384;
constants.S_IFCHR = 8192;
constants.S_IFBLK = 24576;
constants.S_IFIFO = 4096;
constants.S_IFLNK = 40960;
constants.S_IFSOCK = 49152;
constants.S_IRWXU = 448;
constants.S_IRUSR = 256;
constants.S_IWUSR = 128;
constants.S_IXUSR = 64;
constants.S_IRWXG = 56;
constants.S_IRGRP = 32;
constants.S_IWGRP = 16;
constants.S_IXGRP = 8;
constants.S_IRWXO = 7;
constants.S_IROTH = 4;
constants.S_IWOTH = 2;
constants.S_IXOTH = 1;
constants.UV_FS_SYMLINK_DIR = 1;
constants.UV_FS_SYMLINK_JUNCTION = 2;
constants.UV_DIRENT_UNKNOWN = 0;
constants.UV_DIRENT_FILE = 1;
constants.UV_DIRENT_DIR = 2;
constants.UV_DIRENT_LINK = 3;
constants.UV_DIRENT_FIFO = 4;
constants.UV_DIRENT_SOCKET = 5;
constants.UV_DIRENT_CHAR = 6;
constants.UV_DIRENT_BLOCK = 7;
constants.UV_FS_O_FILEMAP = 0;
constants.UV_FS_COPYFILE_EXCL = 1;
constants.COPYFILE_EXCL = 1;
constants.UV_FS_COPYFILE_FICLONE = 2;
constants.COPYFILE_FICLONE = 2;
constants.UV_FS_COPYFILE_FICLONE_FORCE = 4;
constants.COPYFILE_FICLONE_FORCE = 4;
promises.constants = constants;
function fchmod(fd, mode, callback) {
	_validateFdNonNegative(fd);
	mode = _coerceMode(mode);
	_validateUint32("mode", mode);
	if (callback !== void 0 && typeof callback !== "function") _validateCallback(callback);
	ensureExactFs();
	_guardClosedFsMutation("fchmod");
	if (typeof callback === "function") {
		var asyncNative = _fsAsyncNative("__exactFsFdAsync");
		if (asyncNative) return _deferFsPromiseCallback(_asyncFdOp(asyncNative, "fchmod", fd, mode), callback);
		if (typeof g.__exactFsFchmod === "function") g.__exactFsFchmod(fd, mode, function(err) {
			_deferFsCallback(function() {
				if (err) callback(_makeFsError(err, "fchmod"));
				else callback(null);
			});
		});
		else wrapCallback(function() {
			fchmodSync(fd, mode);
		}, callback, "fchmod");
		return;
	}
	return fchmodSync(fd, mode);
}
function fchmodSync(fd, mode) {
	_validateFdNonNegative(fd);
	mode = _coerceMode(mode);
	_validateUint32("mode", mode);
	ensureExactFs();
	_guardClosedFsMutation("fchmod");
	try {
		if (typeof g.__exactFsFchmodSync === "function") return g.__exactFsFchmodSync(fd, mode);
	} catch (e) {
		throw _makeFsError(e, "fchmod");
	}
	if (typeof g.__exactFsFchmodSync !== "function") {
		var err = /* @__PURE__ */ new Error("fchmod is not supported");
		err.code = "ENOSYS";
		throw err;
	}
}
function fchown(fd, uid, gid, callback) {
	_validateFdNonNegative(fd);
	if (typeof uid !== "number") throw _fsInvalidArgType("uid", "number", uid);
	_validateUidOrGid("uid", uid);
	if (typeof gid !== "number") throw _fsInvalidArgType("gid", "number", gid);
	_validateUidOrGid("gid", gid);
	if (callback !== void 0 && typeof callback !== "function") _validateCallback(callback);
	_guardClosedFsMutation("fchown");
	if (uid === -1 && gid === -1) {
		if (typeof callback === "function") _deferFsCallback(function() {
			callback(null);
		});
		return;
	}
	ensureExactFs();
	if (typeof callback === "function") {
		var asyncNative = _fsAsyncNative("__exactFsFdAsync");
		if (asyncNative) return _deferFsPromiseCallback(_asyncFdOp(asyncNative, "fchown", fd, uid, gid), callback);
		if (typeof g.__exactFsFchown === "function") g.__exactFsFchown(fd, uid, gid, function(err) {
			_deferFsCallback(function() {
				if (err) callback(_makeFsError(err, "fchown"));
				else callback(null);
			});
		});
		else wrapCallback(function() {
			fchownSync(fd, uid, gid);
		}, callback, "fchown");
		return;
	}
	if (typeof g.__exactFsFchownSync === "function") try {
		return g.__exactFsFchownSync(fd, uid, gid);
	} catch (e) {
		throw _makeFsError(e, "fchown");
	}
	if (typeof g.__exactFsFchown === "function") return g.__exactFsFchown(fd, uid, gid, function() {});
	var err = /* @__PURE__ */ new Error("fchown is not supported");
	err.code = "ENOSYS";
	throw err;
}
function fchownSync(fd, uid, gid) {
	_validateFdNonNegative(fd);
	if (typeof uid !== "number") throw _fsInvalidArgType("uid", "number", uid);
	_validateUidOrGid("uid", uid);
	if (typeof gid !== "number") throw _fsInvalidArgType("gid", "number", gid);
	_validateUidOrGid("gid", gid);
	_guardClosedFsMutation("fchown");
	if (uid === -1 && gid === -1) return;
	ensureExactFs();
	try {
		if (typeof g.__exactFsFchownSync === "function") return g.__exactFsFchownSync(fd, uid, gid);
	} catch (e) {
		throw _makeFsError(e, "fchown");
	}
	var err = /* @__PURE__ */ new Error("fchown is not supported");
	err.code = "ENOSYS";
	throw err;
}
function ftruncate(fd, len, callback) {
	if (typeof len === "function") {
		callback = len;
		len = void 0;
	}
	_validateFd(fd);
	len = _normalizeTruncateLen(len);
	_validateCallback(callback);
	ensureExactFs();
	var native = _fsAsyncNative("__exactFsFdAsync");
	if (native) return _deferFsPromiseCallback(_asyncFdOp(native, "ftruncate", fd, len), callback);
	try {
		ftruncateSync(fd, len);
		_deferFsCallback(function() {
			callback(null);
		});
	} catch (e) {
		var err = _makeFsError(e, "ftruncate");
		_deferFsCallback(function() {
			callback(err);
		});
	}
}
function ftruncateSync(fd, len) {
	_validateFd(fd);
	len = _normalizeTruncateLen(len);
	ensureExactFs();
	try {
		if (typeof g.__exactFsFtruncateSync === "function") return g.__exactFsFtruncateSync(fd, len);
	} catch (e) {
		throw _makeFsError(e, "ftruncate");
	}
	throw _makeUnsupportedFsError("ftruncate");
}
function fdatasync(fd, callback) {
	_validateFd(fd);
	_validateCallback(callback);
	ensureExactFs();
	var native = _fsAsyncNative("__exactFsFdAsync");
	if (native) return _deferFsPromiseCallback(_asyncFdOp(native, "fdatasync", fd), callback);
	try {
		fdatasyncSync(fd);
		_deferFsCallback(function() {
			callback(null);
		});
	} catch (e) {
		var err = _makeFsError(e, "fdatasync");
		_deferFsCallback(function() {
			callback(err);
		});
	}
}
function fdatasyncSync(fd) {
	_validateFd(fd);
	ensureExactFs();
	try {
		if (typeof g.__exactFsFdatasyncSync === "function") return g.__exactFsFdatasyncSync(fd);
	} catch (e) {
		throw _makeFsError(e, "fdatasync");
	}
	throw _makeUnsupportedFsError("fdatasync");
}
function fsync(fd, callback) {
	_validateFd(fd);
	_validateCallback(callback);
	ensureExactFs();
	var native = _fsAsyncNative("__exactFsFdAsync");
	if (native) return _deferFsPromiseCallback(_asyncFdOp(native, "fsync", fd), callback);
	try {
		fsyncSync(fd);
		_deferFsCallback(function() {
			callback(null);
		});
	} catch (e) {
		var err = _makeFsError(e, "fsync");
		_deferFsCallback(function() {
			callback(err);
		});
	}
}
function fsyncSync(fd) {
	_validateFd(fd);
	ensureExactFs();
	try {
		if (typeof g.__exactFsFsyncSync === "function") return g.__exactFsFsyncSync(fd);
	} catch (e) {
		throw _makeFsError(e, "fsync");
	}
	throw _makeUnsupportedFsError("fsync");
}
function fstat(fd, opts, callback) {
	if (typeof opts === "function") {
		callback = opts;
		opts = {};
	}
	_validateFd(fd);
	_validateCallback(callback);
	ensureExactFs();
	var native = _fsAsyncNative("__exactFsStatAsync");
	if (native) {
		var statPromise;
		try {
			_coerceStatOptions(opts);
			statPromise = _asyncStatImpl(native, fd, "fstat", _extractStatOptions(opts));
		} catch (e) {
			var error = _makeFsError(e, "fstat");
			_deferFsCallback(function() {
				callback(error);
			});
			return;
		}
		statPromise.then(function(stats) {
			_deferFsCallback(function() {
				callback(null, stats);
			});
		}, function(err) {
			_deferFsCallback(function() {
				callback(err);
			});
		});
		return;
	}
	try {
		var result = fstatSync(fd, opts);
		_deferFsCallback(function() {
			callback(null, result);
		});
	} catch (e) {
		var err = _makeFsError(e, "fstat");
		_deferFsCallback(function() {
			callback(err);
		});
	}
}
function fstatSync(fd, opts) {
	_validateFd(fd);
	ensureExactFs();
	_coerceStatOptions(opts);
	var statOptions = _extractStatOptions(opts);
	try {
		if (typeof g.__exactFsFstatSync === "function") return _makeStats(g.__exactFsFstatSync(fd), statOptions);
		var err = /* @__PURE__ */ new Error("ENOSYS: fstatSync is not supported");
		err.code = "ENOSYS";
		throw err;
	} catch (e) {
		throw _makeFsError(e, "fstat");
	}
}
function futimes(fd, atime, mtime, callback) {
	_validateFdNonNegative(fd);
	_validateCallback(callback);
	ensureExactFs();
	_guardClosedFsMutation("futimes");
	var native = _fsAsyncNative("__exactFsFdAsync");
	if (native) return _deferFsPromiseCallback(_asyncFdOp(native, "futimes", fd, _toUnixTimestamp(atime), _toUnixTimestamp(mtime)), callback);
	try {
		futimesSync(fd, atime, mtime);
		_deferFsCallback(function() {
			callback(null);
		});
	} catch (e) {
		var err = _makeFsError(e, "futime");
		if (err && typeof err.message === "string") err.message = err.message.replace("futimes", "futime");
		_deferFsCallback(function() {
			callback(err);
		});
	}
}
function futimesSync(fd, atime, mtime) {
	_validateFdNonNegative(fd);
	ensureExactFs();
	_guardClosedFsMutation("futimes");
	try {
		if (typeof g.__exactFsFutimesSync === "function") {
			var at = _toUnixTimestamp(atime);
			var mt = _toUnixTimestamp(mtime);
			g.__exactFsFutimesSync(fd, at, mt);
			return;
		}
	} catch (e) {
		var err = _makeFsError(e, "futime");
		if (err && typeof err.message === "string") err.message = err.message.replace("futimes", "futime");
		throw err;
	}
	throw _makeUnsupportedFsError("futime");
}
function lchmod(path, mode, callback) {
	_validatePath(path);
	mode = _coerceMode(mode);
	_validateUint32("mode", mode);
	_validateCallback(callback);
	_guardClosedFsMutation("lchmod", path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	var p = _pathToString(path);
	if (native) return _deferFsPromiseCallback(_asyncFsPathOp(native, "lchmod", [
		p,
		null,
		mode
	], "lchmod", p), callback);
	return wrapCallback(function() {
		lchmodSync(path, mode);
	}, callback, "lchmod", p);
}
function lchmodSync(path, mode) {
	_validatePath(path);
	mode = _coerceMode(mode);
	_validateUint32("mode", mode);
	ensureExactFs();
	_guardClosedFsMutation("lchmod", path);
	var p = _pathToString(path);
	try {
		if (typeof g.__exactLchmod === "function") {
			g.__exactLchmod(p, mode);
			return;
		}
		if (typeof g.__exactLchmodSync === "function") {
			g.__exactLchmodSync(p, mode);
			return;
		}
	} catch (e) {
		throw _makeFsError(e, "lchmod", p);
	}
	var err = /* @__PURE__ */ new Error("ENOSYS: lchmod is not supported");
	err.code = "ENOSYS";
	throw err;
}
function lchown(path, uid, gid, callback) {
	_validatePath(path);
	_validateUidOrGid("uid", uid);
	_validateUidOrGid("gid", gid);
	_validateCallback(callback);
	_guardClosedFsMutation("lchown", path);
	if (uid === -1 && gid === -1) return _deferFsCallback(function() {
		callback(null);
	});
	var native = _fsAsyncNative("__exactFsPathAsync");
	if (native) {
		var p = _pathToString(path);
		return _deferFsPromiseCallback(_asyncFsPathOp(native, "lchown", [
			p,
			null,
			uid,
			gid
		], "lchown", p), callback);
	}
	wrapCallback(function() {
		lchownSync(path, uid, gid);
	}, callback, "lchown", _pathToString(path));
}
function lutimes(path, atime, mtime, callback) {
	_validatePath(path);
	_validateCallback(callback);
	_guardClosedFsMutation("lutimes", path);
	var native = _fsAsyncNative("__exactFsPathAsync");
	var p = _pathToString(path), at = _toUnixTimestamp(atime), mt = _toUnixTimestamp(mtime);
	if (native) return _deferFsPromiseCallback(_asyncFsPathOp(native, "lutime", [
		p,
		null,
		at,
		mt
	], "lutimes", p), callback);
	wrapCallback(function() {
		lutimesSync(path, atime, mtime);
	}, callback, "lutimes", p);
}
function lutimesSync(path, atime, mtime) {
	_validatePath(path);
	ensureExactFs();
	_guardClosedFsMutation("lutimes", path);
	var p = _pathToString(path);
	var at = _toUnixTimestamp(atime);
	var mt = _toUnixTimestamp(mtime);
	try {
		if (typeof g.__exactLutimes === "function") {
			g.__exactLutimes(p, at, mt);
			return;
		}
		if (typeof g.__exactLutimesSync === "function") {
			g.__exactLutimesSync(p, at, mt);
			return;
		}
	} catch (e) {
		throw _makeFsError(e, "lutime", p);
	}
	var err = /* @__PURE__ */ new Error("ENOSYS: lutimes is not supported");
	err.code = "ENOSYS";
	throw err;
}
module.exports = {
	readFile,
	readFileSync,
	writeFile,
	writeFileSync,
	appendFile,
	appendFileSync,
	stat,
	statSync,
	lstat,
	lstatSync,
	readdir,
	readdirSync,
	mkdir,
	mkdirSync,
	rmdir,
	rmdirSync,
	unlink,
	unlinkSync,
	rename,
	renameSync,
	copyFile,
	copyFileSync,
	access,
	accessSync,
	chmod,
	chmodSync,
	realpath,
	realpathSync,
	mkdtempDisposable,
	mkdtempDisposableSync,
	mkdtemp,
	mkdtempSync,
	exists,
	existsSync,
	open,
	openSync,
	close,
	closeSync,
	read: fsRead,
	readSync,
	write: fsWrite,
	writeSync,
	createReadStream,
	createWriteStream,
	ReadStream,
	WriteStream,
	watch,
	watchFile,
	unwatchFile,
	FSWatcher,
	Stats,
	Dir,
	Dirent,
	symlink,
	symlinkSync,
	link,
	linkSync,
	cp,
	cpSync,
	readlink,
	readlinkSync,
	glob,
	globSync,
	truncate,
	truncateSync,
	statfs,
	statfsSync,
	chown,
	chownSync,
	utimes,
	utimesSync,
	rm,
	rmSync,
	fchmod,
	fchmodSync,
	fchown,
	fchownSync,
	ftruncate,
	ftruncateSync,
	fdatasync,
	fdatasyncSync,
	fsync,
	fsyncSync,
	fstat,
	fstatSync,
	futimes,
	futimesSync,
	readvSync,
	readv,
	writevSync,
	writev,
	lchmod,
	lchmodSync,
	lchown,
	lchownSync,
	lutimes,
	lutimesSync,
	opendir,
	opendirSync,
	_toUnixTimestamp,
	promises,
	constants
};
[
	"F_OK",
	"R_OK",
	"W_OK",
	"X_OK"
].forEach(function(name) {
	Object.defineProperty(module.exports, name, {
		get: function() {
			_emitFsDeprecation("DEP0176", "fs." + name + " is deprecated, use fs.constants." + name + " instead");
			return constants[name];
		},
		set: function() {
			throw new TypeError("Cannot assign to read only property '" + name + "' of object '#<Object>'");
		},
		enumerable: false,
		configurable: false
	});
});
//#endregion
