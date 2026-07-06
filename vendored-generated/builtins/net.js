//#region src/builtins/net.js
var _swallowDebugLog = null;
function _swallowDebug(msg, err) {
	if (_swallowDebugLog === null) try {
		_swallowDebugLog = require("util").debuglog("net");
	} catch (_swallowInitErr) {
		_swallowDebugLog = function() {};
	}
	_swallowDebugLog(msg, err);
}
var EventEmitter;
var StringDecoder = null;
var _rejectionSymbol = typeof Symbol === "function" && typeof Symbol.for === "function" ? Symbol.for("nodejs.rejection") : null;
var _assertListenerArgument = null;
try {
	EventEmitter = require("events");
} catch (e) {
	EventEmitter = function() {
		this._events = {};
	};
	_assertListenerArgument = function(listener, argName) {
		if (typeof listener !== "function") {
			var type = listener === void 0 ? "undefined" : listener === null ? "null" : typeof listener;
			throw new TypeError("The \"" + argName + "\" argument must be of type function. Received " + type);
		}
	};
	EventEmitter.prototype._on = function(e, fn) {
		if (!this._events[e]) this._events[e] = [];
		this._events[e].push(fn);
		return this;
	};
	EventEmitter.prototype.on = function(e, fn) {
		_assertListenerArgument(fn, "listener");
		return EventEmitter.prototype._on.call(this, e, fn);
	};
	EventEmitter.prototype.emit = function(e) {
		var a = [].slice.call(arguments, 1);
		var l = this._events[e] || [];
		for (var i = 0; i < l.length; i++) l[i].apply(this, a);
		return l.length > 0;
	};
	EventEmitter.prototype.once = function(e, fn) {
		_assertListenerArgument(fn, "listener");
		var self = this;
		function w() {
			self.removeListener(e, w);
			fn.apply(this, arguments);
		}
		w.listener = fn;
		this.on(e, w);
		return this;
	};
	EventEmitter.prototype.removeListener = function(e, fn) {
		var l = this._events[e];
		if (l) {
			var n = [];
			for (var i = 0; i < l.length; i++) if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]);
			this._events[e] = n;
		}
		return this;
	};
	EventEmitter.prototype.removeAllListeners = function(e) {
		if (e) delete this._events[e];
		else this._events = {};
		return this;
	};
	EventEmitter.prototype.addListener = function(e, fn) {
		_assertListenerArgument(fn, "listener");
		return EventEmitter.prototype.on.call(this, e, fn);
	};
	EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
	EventEmitter.prototype.listeners = function(e) {
		return (this._events[e] || []).slice();
	};
	EventEmitter.prototype.listenerCount = function(e) {
		return (this._events[e] || []).length;
	};
	EventEmitter.prototype.prependListener = function(e, fn) {
		_assertListenerArgument(fn, "listener");
		if (!this._events[e]) this._events[e] = [];
		this._events[e].unshift(fn);
		return this;
	};
}
if (!_assertListenerArgument) _assertListenerArgument = function(listener, argName) {
	if (typeof listener !== "function") {
		var type = listener === void 0 ? "undefined" : listener === null ? "null" : typeof listener;
		throw new TypeError("The \"" + argName + "\" argument must be of type function. Received " + type);
	}
};
try {
	StringDecoder = require("node:string_decoder").StringDecoder;
} catch (_stringDecoderErr) {
	try {
		StringDecoder = require("string_decoder").StringDecoder;
	} catch (_stringDecoderErr2) {}
}
function _normalizePort(port) {
	if (port === void 0 || port === null) return 0;
	if (typeof port === "string") {
		var trimmed = port.trim();
		if (trimmed.length === 0) return 0;
		var n = Number(trimmed);
		if (isNaN(n) || n < 0 || n > 65535 || n !== n >>> 0) {
			var err = /* @__PURE__ */ new RangeError("The \"port\" option should be >= 0 and < 65536. Received " + JSON.stringify(port));
			err.code = "ERR_SOCKET_BAD_PORT";
			throw err;
		}
		return n >>> 0;
	}
	if (typeof port !== "number") return 0;
	if (port < 0 || port > 65535 || port !== port >>> 0) {
		var err2 = /* @__PURE__ */ new RangeError("The \"port\" option should be >= 0 and < 65536. Received " + port);
		err2.code = "ERR_SOCKET_BAD_PORT";
		throw err2;
	}
	return port >>> 0;
}
function _validateConnectPort(port) {
	if (port === void 0 || port === null) {
		var err = /* @__PURE__ */ new TypeError("The \"port\" option must be of type number or string. Received " + (port === null ? "null" : "undefined"));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (typeof port === "boolean") {
		var err2 = /* @__PURE__ */ new TypeError("The \"port\" option must be of type number or string. Received type boolean");
		err2.code = "ERR_INVALID_ARG_TYPE";
		throw err2;
	}
	if (Array.isArray(port)) {
		var err3 = /* @__PURE__ */ new TypeError("The \"port\" option must be of type number or string. Received an instance of Array");
		err3.code = "ERR_INVALID_ARG_TYPE";
		throw err3;
	}
	if (typeof port === "object") {
		var err4 = /* @__PURE__ */ new TypeError("The \"port\" option must be of type number or string. Received an instance of Object");
		err4.code = "ERR_INVALID_ARG_TYPE";
		throw err4;
	}
	var p = typeof port === "string" ? Number(port) : port;
	if (typeof port === "string" && port.trim().length === 0) {
		var err5 = /* @__PURE__ */ new RangeError("The \"port\" option should be >= 0 and < 65536. Received " + JSON.stringify(port));
		err5.code = "ERR_SOCKET_BAD_PORT";
		throw err5;
	}
	if (isNaN(p) || p < 0 || p > 65535 || p !== p >>> 0) {
		var err6 = /* @__PURE__ */ new RangeError("The \"port\" option should be >= 0 and < 65536. Received " + port);
		err6.code = "ERR_SOCKET_BAD_PORT";
		throw err6;
	}
	return p >>> 0;
}
var _hasTcp = typeof __exactTcpConnect === "function";
var _hasAsyncTcpConnect = typeof __exactTcpConnectStart === "function" && typeof __exactTcpConnectPoll === "function";
var _CONNECT_POLL_INTERVAL_MS = 1;
var _hasUnix = typeof __exactUnixConnect === "function";
var _internalBinding = null;
try {
	var _internalTestBinding = require("internal/test/binding");
	if (_internalTestBinding && typeof _internalTestBinding.internalBinding === "function") _internalBinding = _internalTestBinding.internalBinding;
} catch (e) {}
var _normalizedArgsSymbol = Symbol.for("nodejs.net.normalizedArgs");
var _kReinitializeHandle = Symbol.for("nodejs.net.kReinitializeHandle");
var kTimeout = Symbol.for("kTimeout");
function _readExecArgvNumericFlag(flag) {
	var execArgv = typeof process !== "undefined" && Array.isArray(process.execArgv) ? process.execArgv : Array.isArray(globalThis.__exactExecArgv) ? globalThis.__exactExecArgv : [];
	for (var i = 0; i < execArgv.length; i++) {
		var arg = String(execArgv[i]);
		if (arg.indexOf(flag + "=") !== 0) continue;
		var value = Number(arg.slice(flag.length + 1));
		if (isFinite(value)) return value;
	}
	return null;
}
function _resolveDefaultAutoSelectFamilyAttemptTimeout() {
	var configured = _readExecArgvNumericFlag("--network-family-autoselection-attempt-timeout");
	if (!isFinite(configured) || configured == null || configured <= 0) return 2500;
	configured = Math.floor(configured) * 10;
	return configured < 10 ? 10 : configured;
}
function _getFastLocalhostConnectCandidates(family, autoSelectFamily) {
	if (family === 4) return [{
		address: "127.0.0.1",
		family: 4
	}];
	if (family === 6) return [{
		address: "::1",
		family: 6
	}];
	if (autoSelectFamily) return [{
		address: "::1",
		family: 6
	}, {
		address: "127.0.0.1",
		family: 4
	}];
	return [{
		address: "127.0.0.1",
		family: 4
	}];
}
var _defaultAutoSelectFamilyAttemptTimeout = _resolveDefaultAutoSelectFamilyAttemptTimeout();
var _defaultAutoSelectFamily = false;
var _boundTcpServers = [];
function _getExactNativeWrapState() {
	return typeof globalThis === "object" && globalThis.__exactNativeWrapState || null;
}
function _getRegisteredFdHandle(fd) {
	var state = _getExactNativeWrapState();
	if (!state || !state.byFd || typeof fd !== "number") return null;
	return state.byFd[fd] || null;
}
function _unwrapHandle(handle) {
	if (handle && handle._exactHandle !== void 0) return handle._exactHandle;
	return handle;
}
function _updateSocketTimeoutHandleState(socket) {
	if (!socket) return;
	if (socket.destroyed || socket.connecting || socket._timeoutMs <= 0) {
		socket[kTimeout] = null;
		return;
	}
	if (!socket[kTimeout] || typeof socket[kTimeout] !== "object") {
		socket[kTimeout] = {
			_idleTimeout: socket._timeoutMs,
			refresh: function() {
				return this;
			},
			ref: function() {
				return this;
			},
			unref: function() {
				return this;
			}
		};
		return;
	}
	socket[kTimeout]._idleTimeout = socket._timeoutMs;
}
function _makeSocketHandle(handle, kind, fd, path) {
	var binding = null;
	var Wrap = null;
	var handleType = 0;
	var wrapKind = kind === "pipe" ? "pipe" : "tcp";
	if (typeof _internalBinding === "function") try {
		binding = _internalBinding(wrapKind === "pipe" ? "pipe_wrap" : "tcp_wrap");
	} catch (_bindingErr) {}
	if (binding) {
		Wrap = wrapKind === "pipe" ? binding.Pipe : binding.TCP;
		if (binding.constants && typeof binding.constants.SOCKET === "number") handleType = binding.constants.SOCKET;
	}
	if (typeof Wrap === "function") {
		var wrap = new Wrap(handleType);
		if (typeof wrap._setExactHandle === "function") {
			wrap._setExactHandle(handle == null ? null : handle, fd, wrapKind, path || null);
			return wrap;
		}
	}
	var socketHandle = {
		_exactHandle: handle == null ? null : handle,
		_exactKind: wrapKind,
		_refed: true,
		fd: typeof fd === "number" ? fd : typeof handle === "number" ? handle : -1,
		setNoDelay: function(noDelay) {
			if (!_hasTcp) return;
			if (socketHandle._exactHandle == null) return;
			try {
				__exactTcpSetNoDelay(socketHandle._exactHandle, noDelay ? 1 : 0);
			} catch (e) {}
		},
		setKeepAlive: function(enable, delay) {
			if (!_hasTcp) return;
			if (socketHandle._exactHandle == null) return;
			if (typeof delay !== "number" || !isFinite(delay)) delay = 0;
			try {
				if (__exactTcpSetKeepAlive.length >= 3) __exactTcpSetKeepAlive(socketHandle._exactHandle, enable !== false ? 1 : 0, delay);
				else __exactTcpSetKeepAlive(socketHandle._exactHandle, enable !== false ? 1 : 0);
			} catch (e) {}
		},
		close: function() {
			if (!_hasTcp) return;
			if (socketHandle._exactHandle == null) return;
			try {
				__exactTcpClose(socketHandle._exactHandle);
			} catch (e) {}
			socketHandle._exactHandle = null;
			socketHandle._refed = false;
		},
		ref: function() {
			socketHandle._refed = true;
			return socketHandle;
		},
		unref: function() {
			socketHandle._refed = false;
			return socketHandle;
		},
		hasRef: function() {
			return socketHandle._refed !== false;
		},
		onconnection: null
	};
	return socketHandle;
}
function _makeServerHandle(nativeHandle, kind, path) {
	var handle = _makeSocketHandle(nativeHandle, kind, void 0, path || null);
	if (handle && typeof handle === "object") handle._exactServerHandle = true;
	return handle;
}
function _setHandleExactValue(handle, nativeHandle, fd, kind, path) {
	if (!handle) return;
	if (typeof handle._setExactHandle === "function") {
		handle._setExactHandle(nativeHandle, fd, kind, path || null);
		return;
	}
	handle._exactHandle = nativeHandle;
	if (kind) handle._exactKind = kind;
	if (typeof fd === "number") handle.fd = fd;
}
function _setSocketHandle(target, nativeHandle) {
	if (!target) return;
	var handle = target && target._handle ? target._handle : target;
	var wrapKind = target && target._isUnix ? "pipe" : handle && handle._exactKind || "tcp";
	var fd = handle && typeof handle.fd === "number" && handle.fd >= 0 ? handle.fd : void 0;
	if (handle && (handle._exactHandle !== void 0 || typeof handle._setExactHandle === "function")) {
		_setHandleExactValue(handle, nativeHandle, fd, wrapKind, target._socketPath || null);
		return handle;
	}
	var newHandle = { _exactHandle: null };
	_setHandleExactValue(newHandle, nativeHandle, fd, wrapKind, target._socketPath || null);
	if (target && target._handle !== void 0) target._handle = newHandle;
	return newHandle;
}
function _shutdownSocketWrite(socket) {
	if (!_hasTcp || !socket) return;
	var nativeHandle = _unwrapHandle(socket._handle);
	if (nativeHandle == null) return;
	if (typeof __exactTcpShutdown !== "function") return;
	try {
		__exactTcpShutdown(nativeHandle, 1);
	} catch (e) {
		_swallowDebug("tcp shutdown(write) failed", e);
	}
}
function _hasMatchingIPv6OnlyServer(host, port) {
	if (!host || !port) return false;
	if (isIP(host) !== 4) return false;
	for (var i = 0; i < _boundTcpServers.length; i++) {
		var server = _boundTcpServers[i];
		if (Number(server.port) !== Number(port)) continue;
		if (server && server.ipv6Only && isIP(server.host) === 6) return true;
	}
	return false;
}
function setDefaultAutoSelectFamily(enabled) {
	_defaultAutoSelectFamily = enabled === true;
	return _defaultAutoSelectFamily;
}
function getDefaultAutoSelectFamily() {
	return _defaultAutoSelectFamily;
}
function _registerTcpServer(server) {
	_boundTcpServers.push(server);
}
function _unregisterTcpServer(server) {
	for (var i = 0; i < _boundTcpServers.length; i++) {
		var entry = _boundTcpServers[i];
		if (entry === server || entry && server && entry.port === server.port && entry.host === server.host && entry.ipv6Only === server.ipv6Only) {
			_boundTcpServers.splice(i, 1);
			return;
		}
	}
}
function _normalizeLookupResults(result) {
	if (result == null) return [];
	if (Array.isArray(result)) return result;
	return [result];
}
function _addressFamilyToName(family) {
	if (family === 4 || family === "4" || typeof family === "string" && family.toLowerCase() === "ipv4") return "IPv4";
	if (family === 6 || family === "6" || typeof family === "string" && family.toLowerCase() === "ipv6") return "IPv6";
	return null;
}
function _parseLookupFamily(value) {
	if (value === 4 || value === "4") return 4;
	if (value === 6 || value === "6") return 6;
	if (value === void 0 || value === null) return 0;
	if (typeof value === "string") {
		var lowered = value.toLowerCase();
		if (lowered === "ipv4") return 4;
		if (lowered === "ipv6") return 6;
		return parseInt(value, 10) || 0;
	}
	return value || 0;
}
function _toIntDelay(value, defaultValue) {
	if (!isFinite(value)) return defaultValue;
	value = Math.floor(value / 1e3);
	if (value < 0) return 0;
	return value;
}
function _createConnectError(code, address, port, syscall) {
	var suffix = address + ":" + port;
	var err = /* @__PURE__ */ new Error(syscall + " " + code + " " + suffix);
	err.code = code;
	err.errno = code;
	err.syscall = syscall;
	return err;
}
function _createConnectErrorFromRaw(err, address, port) {
	if (_isGetAddrInfoError(err)) return _createGetAddrInfoError(address);
	var message = err && err.message ? String(err.message) : String(err);
	var lower = message.toLowerCase();
	var code = "ECONNREFUSED";
	if (lower.indexOf("cannot assign requested address") !== -1 || message.indexOf("EADDRNOTAVAIL") !== -1) code = "EADDRNOTAVAIL";
	else if (lower.indexOf("address already in use") !== -1 || message.indexOf("EADDRINUSE") !== -1) code = "EADDRINUSE";
	else if (lower.indexOf("network is unreachable") !== -1 || message.indexOf("ENETUNREACH") !== -1) code = "ENETUNREACH";
	else if (lower.indexOf("permission denied") !== -1 || message.indexOf("EACCES") !== -1) code = "EACCES";
	else if (lower.indexOf("timed out") !== -1 || message.indexOf("ETIMEDOUT") !== -1) code = "ETIMEDOUT";
	return _createConnectError(code, address, port, "connect");
}
function _uvConnectCodeToErrno(code) {
	if (code === -101) return "ENETUNREACH";
	if (code === -111) return "ECONNREFUSED";
	return "ECONNREFUSED";
}
function _isGetAddrInfoError(err) {
	if (!err || !err.message) return false;
	return String(err.message).indexOf("getaddrinfo") === 0 || String(err.message).indexOf("getaddrinfo failed") !== -1;
}
function _createGetAddrInfoError(host) {
	var err = /* @__PURE__ */ new Error("getaddrinfo ENOTFOUND " + host);
	err.code = "ENOTFOUND";
	err.errno = "ENOTFOUND";
	err.syscall = "getaddrinfo";
	err.hostname = host;
	return err;
}
function _createInvalidIPAddressError(address) {
	var err = /* @__PURE__ */ new TypeError("Invalid IP address: " + address);
	err.code = "ERR_INVALID_IP_ADDRESS";
	return err;
}
function _createInvalidAddressFamilyError(family, host, port) {
	var err = /* @__PURE__ */ new Error("Invalid address family: " + family + " " + host + ":" + port);
	err.code = "ERR_INVALID_ADDRESS_FAMILY";
	err.host = host;
	err.port = port;
	return err;
}
function _validateLookupOption(lookup) {
	if (lookup === void 0) return;
	if (typeof lookup === "function") return;
	var err = /* @__PURE__ */ new TypeError("The \"options.lookup\" property must be of type function. Received " + typeof lookup);
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function _validateConnectPath(path) {
	if (path === void 0) return;
	if (typeof path === "string") return;
	var err = /* @__PURE__ */ new TypeError("The \"options.path\" property must be of type string. Received type " + typeof path);
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function _validateHintsOption(hints) {
	if (hints === void 0) return;
	var dns;
	try {
		dns = require("dns");
	} catch (e) {}
	var validMask = 3328;
	if (dns) {
		var dnsMask = 0;
		if (typeof dns.ADDRCONFIG === "number") dnsMask |= dns.ADDRCONFIG;
		if (typeof dns.V4MAPPED === "number") dnsMask |= dns.V4MAPPED;
		if (typeof dns.ALL === "number") dnsMask |= dns.ALL;
		if (dnsMask !== 0) validMask = dnsMask;
	}
	if (typeof hints !== "number" || hints < 0 || validMask && (hints & ~validMask) !== 0) {
		var err = /* @__PURE__ */ new TypeError("The argument 'hints' is invalid. Received " + hints);
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
}
function _validateLocalAddressOption(localAddress) {
	if (localAddress === void 0) return;
	if (typeof localAddress !== "string" || isIP(localAddress) === 0) throw _createInvalidIPAddressError(localAddress);
}
function _validateLocalPortOption(localPort) {
	if (localPort === void 0) return;
	if (typeof localPort !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"options.localPort\" property must be of type number. Received type " + typeof localPort);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	_validateConnectPort(localPort);
}
function _hasConflictingLocalBind(localAddress, localPort) {
	if (!localPort) return false;
	for (var i = 0; i < _boundTcpServers.length; i++) {
		var server = _boundTcpServers[i];
		if (!server || Number(server._port) !== Number(localPort)) continue;
		var serverHost = server._host || server.host;
		if (!serverHost && typeof server.address === "function") {
			var address = server.address();
			if (address && typeof address === "object") serverHost = address.address;
		}
		if (!localAddress) return true;
		if (!serverHost || serverHost === localAddress || serverHost === "0.0.0.0" || serverHost === "::" || serverHost === "::0") return true;
	}
	return false;
}
function _createUnixConnectError(rawError, path) {
	var message = rawError && rawError.message ? String(rawError.message) : String(rawError);
	var lower = message.toLowerCase();
	var code = "ECONNREFUSED";
	if (message.indexOf("EINVAL") !== -1 || lower.indexOf("invalid argument") !== -1 || lower.indexOf("path too long") !== -1) code = "EINVAL";
	else if (message.indexOf("EACCES") !== -1 || lower.indexOf("permission denied") !== -1) code = "EACCES";
	else if (message.indexOf("ENOENT") !== -1 || lower.indexOf("no such file") !== -1) code = "ENOENT";
	else if (message.indexOf("ENOTSOCK") !== -1 || lower.indexOf("not a socket") !== -1 || lower.indexOf("socket operation on non-socket") !== -1) code = "ENOTSOCK";
	var err = /* @__PURE__ */ new Error("connect " + code + " " + path);
	err.code = code;
	err.errno = code;
	err.syscall = "connect";
	err.address = path;
	err.path = path;
	return err;
}
function _createListenError(rawError, address, port, path) {
	var message = rawError && rawError.message ? String(rawError.message) : String(rawError);
	var lower = message.toLowerCase();
	var code = "EADDRINUSE";
	var detail = "address already in use";
	if (message.indexOf("EINVAL") !== -1 || lower.indexOf("invalid argument") !== -1 || lower.indexOf("path too long") !== -1) {
		code = "EINVAL";
		detail = "invalid argument";
	} else if (lower.indexOf("no such file") !== -1 || message.indexOf("ENOENT") !== -1) {
		code = "ENOENT";
		detail = "no such file or directory";
	} else if (lower.indexOf("cannot assign requested address") !== -1 || message.indexOf("EADDRNOTAVAIL") !== -1) {
		code = "EADDRNOTAVAIL";
		detail = "address not available";
	} else if (lower.indexOf("permission denied") !== -1 || message.indexOf("EACCES") !== -1) {
		code = "EACCES";
		detail = "permission denied";
	} else if (lower.indexOf("address already in use") !== -1 || message.indexOf("EADDRINUSE") !== -1) {
		code = "EADDRINUSE";
		detail = "address already in use";
	}
	var suffix = path || (address || "0.0.0.0") + ":" + (port || 0);
	var err = /* @__PURE__ */ new Error("listen " + code + ": " + detail + " " + suffix);
	err.code = code;
	err.errno = code;
	err.syscall = "listen";
	err.address = path || address;
	if (!path) err.port = port;
	return err;
}
function _setTimerRefState(timer, refed) {
	if (!timer || typeof timer !== "object") return;
	try {
		if (refed === false) {
			if (typeof timer.unref === "function") timer.unref();
		} else if (typeof timer.ref === "function") timer.ref();
	} catch (e) {}
}
function _setHandleRefState(handle, refed) {
	if (!handle) return;
	try {
		if (typeof handle.hasRef === "function") {
			var alreadyRefed = handle.hasRef();
			if (refed === false && alreadyRefed === false) return;
			if (refed !== false && alreadyRefed === true) return;
		}
		if (refed === false) {
			if (typeof handle.unref === "function") handle.unref();
		} else if (typeof handle.ref === "function") handle.ref();
	} catch (e) {}
}
function _scheduleTimer(callback, delay, owner) {
	var timer = setTimeout(callback, delay);
	if (owner && owner._unrefed) _setTimerRefState(timer, false);
	return timer;
}
function _scheduleCallback(callback) {
	if (typeof callback !== "function") return;
	var args = Array.prototype.slice.call(arguments, 1);
	if (typeof process !== "undefined" && typeof process.nextTick === "function") {
		process.nextTick(function() {
			callback.apply(null, args);
		});
		return;
	}
	setTimeout(function() {
		callback.apply(null, args);
	}, 0);
}
function _applyUnixListenMode(path, readableAll, writableAll) {
	if (!path || process.platform === "win32" || !readableAll && !writableAll) return;
	var mode = 384;
	if (readableAll) mode |= 36;
	if (writableAll) mode |= 18;
	if (typeof __exactChmod === "function") {
		__exactChmod(path, mode);
		return;
	}
	require("fs").chmodSync(path, mode);
}
function _normalizeSocketIOError(err, syscall) {
	if (!err) return err;
	if (err.code) {
		if (!err.syscall && syscall) err.syscall = syscall;
		if ((!err.message || err.message === String(err.code)) && syscall) err.message = syscall + " " + err.code;
		return err;
	}
	var lower = (err && err.message ? String(err.message) : String(err)).toLowerCase();
	var code = null;
	if (lower.indexOf("connection reset by peer") !== -1) code = "ECONNRESET";
	else if (lower.indexOf("broken pipe") !== -1) code = "EPIPE";
	else if (lower.indexOf("bad file descriptor") !== -1) code = "EBADF";
	if (!code) return err;
	var mappedMessage = syscall ? syscall + " " + code : code;
	var mapped = new Error(mappedMessage);
	mapped.code = code;
	mapped.errno = code;
	if (syscall) mapped.syscall = syscall;
	return mapped;
}
function _schedulePausedSocketPoll(socket, poll) {
	socket._pollTimer = _scheduleTimer(poll, 10, socket);
	_setTimerRefState(socket._pollTimer, false);
}
function _getSocketPollDelay(socket, readData) {
	if (readData) return 0;
	if (!socket || !socket._lastActivity) return 1;
	return Date.now() - socket._lastActivity <= 16 ? 0 : 1;
}
function _emitAsyncSocketError(socket, err, callback) {
	_scheduleTimer(function() {
		if (typeof callback === "function") {
			callback(err);
			if (err && (err.code === "ERR_STREAM_DESTROYED" || err.code === "ERR_STREAM_WRITE_AFTER_END" || err.code === "EPIPE" && socket && socket._autoEndedFromPeer === true)) return;
		}
		socket.emit("error", err);
	}, 0, socket);
}
function _cancelPendingConnect(socket) {
	if (!socket) return;
	if (socket._connectPollTimer != null) {
		clearTimeout(socket._connectPollTimer);
		socket._connectPollTimer = null;
	}
	if (socket._pendingConnectHandle != null) {
		if (_hasTcp) try {
			__exactTcpClose(socket._pendingConnectHandle);
		} catch (e) {}
		socket._pendingConnectHandle = null;
	}
}
function _finishTcpConnectSuccess(selfRef, nativeHandle, address, family) {
	selfRef.remoteAddress = address;
	if (family) selfRef.remoteFamily = _addressFamilyToName(family);
	_setSocketHandle(selfRef._handle, nativeHandle);
	_setHandleRefState(selfRef._handle, !selfRef._unrefed);
	selfRef.connecting = false;
	selfRef._connected = true;
	selfRef.pending = false;
	selfRef.readyState = "open";
	selfRef._updateAddressInfo();
	if (selfRef._noDelay !== void 0) selfRef.setNoDelay(selfRef._noDelay);
	if (selfRef._keepAlive !== void 0 && selfRef._keepAlive) selfRef.setKeepAlive(true, _toIntDelay(selfRef._keepAliveInitialDelay, 0));
	selfRef._startPolling();
	selfRef._drainWriteQueue();
	if (selfRef.destroyed) return;
	_updateSocketTimeoutHandleState(selfRef);
	selfRef.emit("connect");
	selfRef.emit("ready");
}
function _pollTcpConnect(socket, nativeHandle, onConnected, onFailed) {
	socket._pendingConnectHandle = nativeHandle;
	function pollConnect() {
		socket._connectPollTimer = null;
		if (socket.destroyed || socket._abortPending || typeof process !== "undefined" && process._exactExiting) {
			if (socket._pendingConnectHandle === nativeHandle) {
				try {
					__exactTcpClose(nativeHandle);
				} catch (e) {}
				socket._pendingConnectHandle = null;
			}
			return;
		}
		var status;
		try {
			status = __exactTcpConnectPoll(nativeHandle);
		} catch (pollErr) {
			try {
				__exactTcpClose(nativeHandle);
			} catch (e) {}
			socket._pendingConnectHandle = null;
			onFailed(pollErr);
			return;
		}
		if (status === 1) {
			socket._pendingConnectHandle = null;
			onConnected();
			return;
		}
		socket._connectPollTimer = _scheduleTimer(pollConnect, _CONNECT_POLL_INTERVAL_MS, socket);
	}
	socket._connectPollTimer = _scheduleTimer(pollConnect, 0, socket);
}
function _shouldTreatResetAsEof(socket, err) {
	return !!(socket && err && err.code === "ECONNRESET" && (socket._ended === true || socket._closeAfterEnd === true || socket._allowResetAsEof === true || socket._autoEndedFromPeer === true));
}
function _createAbortError() {
	var err = /* @__PURE__ */ new Error("The operation was aborted");
	err.code = "ABORT_ERR";
	err.name = "AbortError";
	return err;
}
function _isAbortSignal(value) {
	return !!value && typeof value === "object" && typeof value.aborted === "boolean" && typeof value.addEventListener === "function" && typeof value.removeEventListener === "function";
}
function _validateAbortSignal(signal) {
	if (signal === void 0) return;
	if (_isAbortSignal(signal)) return;
	var signalValue = typeof signal === "string" ? "'" + signal + "'" : typeof signal;
	var err = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received " + signalValue);
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function _detachSocketAbortListener(socket) {
	if (!socket || !socket._abortSignal || !socket._abortListener) return;
	try {
		socket._abortSignal.removeEventListener("abort", socket._abortListener);
	} catch (e) {}
	socket._abortSignal = null;
	socket._abortListener = null;
}
function _attachSocketAbortSignal(socket, signal) {
	if (signal === void 0) return true;
	_validateAbortSignal(signal);
	if (socket._abortSignal === signal && socket._abortListener) return !socket._abortPending;
	_detachSocketAbortListener(socket);
	socket._abortPending = false;
	if (signal.aborted) {
		socket._abortPending = true;
		_scheduleTimer(function() {
			if (!socket.destroyed) socket.destroy(_createAbortError());
		}, 0, socket);
		return false;
	}
	socket._abortSignal = signal;
	socket._abortListener = function() {
		_detachSocketAbortListener(socket);
		socket._abortPending = true;
		_scheduleTimer(function() {
			if (!socket.destroyed) socket.destroy(_createAbortError());
		}, 0, socket);
	};
	signal.addEventListener("abort", socket._abortListener, { once: true });
	return true;
}
function _describeAcceptedSocket(nativeHandle, server) {
	var info = {
		localAddress: server && server._host ? server._host : "0.0.0.0",
		localPort: server && server._port ? server._port : 0,
		localFamily: server && server.ipv6Only ? "IPv6" : "IPv4",
		remoteAddress: null,
		remotePort: null,
		remoteFamily: null
	};
	if (!_hasTcp || nativeHandle == null) return info;
	try {
		var local = __exactTcpLocalAddr(nativeHandle);
		if (local) {
			var localInfo = JSON.parse(local);
			info.localAddress = localInfo.address;
			info.localPort = localInfo.port;
			info.localFamily = localInfo.family;
		}
	} catch (e) {}
	try {
		var remote = __exactTcpRemoteAddr(nativeHandle);
		if (remote) {
			var remoteInfo = JSON.parse(remote);
			info.remoteAddress = remoteInfo.address;
			info.remotePort = remoteInfo.port;
			info.remoteFamily = remoteInfo.family;
		}
	} catch (e) {}
	return info;
}
function _normalizeWritableHighWaterMark(options) {
	var highWaterMark = options && options.writableHighWaterMark;
	if (highWaterMark == null && options) highWaterMark = options.highWaterMark;
	if (typeof highWaterMark !== "number" || !isFinite(highWaterMark) || highWaterMark < 0) return 65536;
	return Math.floor(highWaterMark);
}
function _normalizeReadableHighWaterMark(options) {
	var highWaterMark = options && options.readableHighWaterMark;
	if (highWaterMark == null && options) highWaterMark = options.highWaterMark;
	if (typeof highWaterMark !== "number" || !isFinite(highWaterMark) || highWaterMark < 0) return 65536;
	return Math.floor(highWaterMark);
}
function _createSocketWriteError(socket) {
	var err;
	if (socket && socket.destroyed) {
		err = /* @__PURE__ */ new Error("Cannot call write after a stream was destroyed");
		err.code = "ERR_STREAM_DESTROYED";
		return err;
	}
	if (socket && socket._readEnded) {
		err = /* @__PURE__ */ new Error("This socket has been ended by the other party");
		err.code = "EPIPE";
		return err;
	}
	err = /* @__PURE__ */ new Error("write after end");
	err.code = "ERR_STREAM_WRITE_AFTER_END";
	return err;
}
function _isLocalTestAddress(address) {
	var ipType = isIP(address);
	if (ipType === 4) {
		var parts = String(address).split(".");
		var first = Number(parts[0]);
		var second = Number(parts[1]);
		if (first === 127 || first === 10 || first === 192 && second === 168) return true;
		if (first === 172 && second >= 16 && second <= 31) return true;
		if (first === 169 && second === 254) return true;
		return false;
	}
	if (ipType === 6) {
		var normalized = String(address).toLowerCase();
		return normalized === "::1" || normalized.indexOf("fe80:") === 0 || normalized.indexOf("fc") === 0 || normalized.indexOf("fd") === 0;
	}
	return false;
}
function _scheduleSocketAutoEnd(socket) {
	if (!socket || socket.destroyed || socket._autoEnding || socket._ended || !socket.writable) return;
	socket._autoEnding = true;
	_scheduleTimer(function() {
		try {
			if (!socket.destroyed && !socket._ended && socket.writable) {
				socket._autoEndedFromPeer = true;
				socket.end();
			}
		} finally {
			socket._autoEnding = false;
		}
	}, 0, socket);
}
function _handleSocketEOF(socket) {
	if (!socket || socket.destroyed) return;
	if (socket._decoder && typeof socket._decoder.end === "function") {
		var trailing = socket._decoder.end();
		if (trailing) if (socket._isFlowing()) socket.emit("data", trailing);
		else {
			socket._appendToReadBuffer(trailing);
			socket.emit("readable");
		}
	}
	socket._readEnded = true;
	socket.readable = false;
	socket.readyState = socket.writable ? "writeOnly" : "closed";
	socket.emit("end");
	if (!socket.allowHalfOpen) {
		if (socket._closeAfterEnd || socket._isWriting || socket._writeQueue && socket._writeQueue.length > 0) return;
		if (!socket.destroyed && socket.writable) {
			_scheduleSocketAutoEnd(socket);
			return;
		}
		if (!socket.destroyed) socket.destroy();
		return;
	}
}
function _resetSocketForConnect(socket) {
	if (!socket) return;
	if (socket._pollTimer != null) {
		clearTimeout(socket._pollTimer);
		socket._pollTimer = null;
	}
	_cancelPendingConnect(socket);
	if (socket._drainTimer != null) {
		clearTimeout(socket._drainTimer);
		socket._drainTimer = null;
	}
	socket._drainImmediateQueued = false;
	if (socket._drainEventTimer != null) {
		clearTimeout(socket._drainEventTimer);
		socket._drainEventTimer = null;
	}
	socket.destroyed = false;
	socket.readable = true;
	socket.writable = true;
	socket.connecting = false;
	socket._connected = false;
	socket.remoteAddress = null;
	socket.remotePort = null;
	socket.remoteFamily = null;
	socket._requestedAddress = null;
	socket._requestedPort = null;
	socket.localAddress = null;
	socket.localPort = null;
	socket.localFamily = null;
	socket.bytesRead = 0;
	socket._bytesWritten = 0;
	socket._handle = _makeSocketHandle(null);
	socket._writeQueue = [];
	socket._bufferedBytes = 0;
	socket._isWriting = false;
	socket._closeAfterEnd = false;
	socket._ended = false;
	socket._autoEndedFromPeer = false;
	socket._readEnded = false;
	socket._needDrain = false;
	socket._drainImmediateQueued = false;
	socket._finishEmitted = false;
	socket._readBuffer = [];
	socket._readBufferLength = 0;
	socket._readBackpressured = false;
	socket._onreadEOF = false;
	socket._isUnix = false;
	socket._socketPath = null;
	socket._customHandle = false;
	socket._customReadStarted = false;
	socket._decoder = socket._encoding && StringDecoder ? new StringDecoder(socket._encoding) : null;
	socket.pending = true;
	socket.readyState = "closed";
}
function Socket(options) {
	if (!(this instanceof Socket)) return new Socket(options);
	options = options || {};
	if (typeof options !== "object" || Array.isArray(options)) {
		if (typeof options === "number") options = { fd: options };
		else if (typeof options === "string") options = {};
		if (typeof options !== "object" || Array.isArray(options)) options = {};
	}
	if (options.fd !== void 0 && options.fd !== null) {
		if (typeof options.fd !== "number") {
			var fdErr = /* @__PURE__ */ new TypeError("The \"options.fd\" property must be of type number. Received type " + typeof options.fd);
			fdErr.code = "ERR_INVALID_ARG_TYPE";
			throw fdErr;
		}
		if (options.fd < 0) {
			var fdRangeErr = /* @__PURE__ */ new RangeError("The value of \"options.fd\" is out of range. It must be >= 0. Received " + options.fd);
			fdRangeErr.code = "ERR_OUT_OF_RANGE";
			throw fdRangeErr;
		}
	}
	this.readable = true;
	this.writable = true;
	this.destroyed = false;
	this.connecting = false;
	this._connected = false;
	this.remoteAddress = null;
	this.remotePort = null;
	this.remoteFamily = null;
	this._requestedAddress = null;
	this._requestedPort = null;
	this.localAddress = null;
	this.localPort = null;
	this.localFamily = null;
	this.bytesRead = 0;
	this._bytesWritten = 0;
	this.timeout = 0;
	this._timeoutMs = 0;
	this._timeoutTimer = null;
	this._lastActivity = 0;
	this._timeoutEmitted = false;
	this[kTimeout] = null;
	this._handle = _makeSocketHandle(null);
	this._pollTimer = null;
	this._connectPollTimer = null;
	this._pendingConnectHandle = null;
	this._drainTimer = null;
	this._drainEventTimer = null;
	this._drainImmediateQueued = false;
	this._writeQueue = [];
	this._bufferedBytes = 0;
	this._writeBufferCache = Object.create(null);
	this._isWriting = false;
	this._closeAfterEnd = false;
	this._ended = false;
	this._autoEndedFromPeer = false;
	this._readEnded = false;
	this._needDrain = false;
	this._finishEmitted = false;
	this._writableHighWaterMark = _normalizeWritableHighWaterMark(options);
	this._readableHighWaterMark = _normalizeReadableHighWaterMark(options);
	this._paused = false;
	this._readBackpressured = false;
	this._encoding = null;
	this._decoder = null;
	this._events = {};
	this._readBuffer = [];
	this._readBufferLength = 0;
	this._onread = options.onread || null;
	this._onreadEOF = false;
	this._isUnix = false;
	this._socketPath = null;
	this._corked = 0;
	this._server = null;
	this.server = null;
	this.allowHalfOpen = options.allowHalfOpen === true;
	this._unrefed = false;
	this._abortSignal = null;
	this._abortListener = null;
	this._abortPending = false;
	this._customHandle = false;
	this._customReadStarted = false;
	this._deferReadableStart = false;
	this.pending = true;
	this.readyState = "closed";
	if (typeof EventEmitter === "function" && EventEmitter.prototype) {
		for (var k in EventEmitter.prototype) if (!this[k]) this[k] = EventEmitter.prototype[k];
	}
	if (!this.allowHalfOpen) {
		var self = this;
		this.on("end", function _onSocketEnd() {
			if (!self.allowHalfOpen) _scheduleSocketAutoEnd(self);
		});
	}
	if (options._isUnix) {
		this._isUnix = true;
		this._socketPath = options._socketPath || null;
	}
	if (options.handle != null) {
		this._handle = options.handle;
		this._customHandle = !(this._handle && this._handle._exactHandle !== void 0);
		this._connected = true;
		this.connecting = false;
		this.pending = false;
		this.readyState = "open";
		if (options.readable === false) this.readable = false;
		if (options.writable === false) this.writable = false;
		if (!this._customHandle) {
			this._updateAddressInfo();
			_setHandleRefState(this._handle, !this._unrefed);
		}
	} else if (options._handle != null) {
		this._handle = _makeSocketHandle(options._handle);
		this._connected = true;
		this.connecting = false;
		this.pending = false;
		this.readyState = "open";
		this._updateAddressInfo();
		_setHandleRefState(this._handle, !this._unrefed);
		this._startPolling();
	} else if (typeof options.fd === "number" && options.fd >= 0) {
		var fdHandle;
		var registeredFdHandle = _getRegisteredFdHandle(options.fd);
		if (registeredFdHandle && registeredFdHandle._exactHandle != null) fdHandle = _makeSocketHandle(registeredFdHandle._exactHandle, registeredFdHandle._exactKind || "tcp", options.fd, registeredFdHandle._exactPath || null);
		else if (typeof __exactTcpFromFd === "function") {
			try {
				fdHandle = __exactTcpFromFd(options.fd);
			} catch (_fdErr) {
				fdHandle = null;
			}
			fdHandle = _makeSocketHandle(fdHandle, "tcp", options.fd, null);
		} else fdHandle = _makeSocketHandle(null, "tcp", options.fd, null);
		this._handle = fdHandle;
		this._connected = true;
		this.connecting = false;
		this.pending = false;
		this.readyState = "open";
		if (options.readable !== false) this.readable = true;
		if (options.writable !== false) this.writable = true;
		this._deferReadableStart = options.readable !== false;
		_setHandleRefState(this._handle, !this._unrefed);
	}
	if (options.signal !== void 0) _attachSocketAbortSignal(this, options.signal);
}
function _maybeActivateDeferredReadableSocket(socket, eventName) {
	if (!socket || socket.destroyed || socket._customHandle || !socket._deferReadableStart) return;
	if (eventName !== "data" && eventName !== "readable" && eventName !== "end") return;
	socket._deferReadableStart = false;
	socket.resume();
}
function _flushBufferedReadDataToFlowingConsumer(socket) {
	if (!socket || socket.destroyed || !socket._isFlowing() || socket._readBufferLength === 0) return;
	var buffered = socket._consumeReadBuffer();
	if (buffered == null || !buffered.length) return;
	socket._emitFlowingData(buffered);
}
function _scheduleFlushBufferedReadData(socket, eventName) {
	if (eventName !== "data") return;
	if (!socket || socket.destroyed || socket._readBufferLength === 0 || !socket._isFlowing()) return;
	_scheduleCallback(_flushBufferedReadDataToFlowingConsumer, socket);
}
Socket.prototype.__defineGetter__("bytesWritten", function() {
	if (!this || !Object.prototype.hasOwnProperty.call(this, "_bytesWritten")) return;
	return this._bytesWritten || 0;
});
Socket.prototype.__defineSetter__("bytesWritten", function(v) {
	this._bytesWritten = v;
});
Socket.prototype.__defineGetter__("_connecting", function() {
	return this.connecting;
});
Socket.prototype.__defineSetter__("_connecting", function(v) {
	this.connecting = v;
});
Socket.prototype.__defineGetter__("bufferSize", function() {
	if (this.destroyed) return void 0;
	return this._bufferedBytes || 0;
});
Socket.prototype.__defineGetter__("writableLength", function() {
	return this.bufferSize || 0;
});
Socket.prototype.__defineGetter__("writableHighWaterMark", function() {
	return this._writableHighWaterMark;
});
Socket.prototype.__defineGetter__("readableHighWaterMark", function() {
	return this._readableHighWaterMark;
});
Socket.prototype.__defineGetter__("writableNeedDrain", function() {
	return !!this._needDrain;
});
Socket.prototype.__defineGetter__("writableCorked", function() {
	return this._corked || 0;
});
Socket.prototype.__defineGetter__("writableEnded", function() {
	return this._ended === true;
});
function toBufferData(data, encoding) {
	if (data == null) return null;
	if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) return data;
	if (typeof Buffer !== "undefined" && typeof ArrayBuffer !== "undefined" && typeof ArrayBuffer.isView === "function" && ArrayBuffer.isView(data)) {
		var _copy = Buffer.alloc(data.byteLength);
		_copy.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
		return _copy;
	}
	if (typeof data === "string") {
		if (typeof Buffer !== "undefined") return Buffer.from(data, encoding || "utf8");
		return data;
	}
	return typeof Buffer !== "undefined" ? Buffer.from(String(data), "utf8") : String(data);
}
var _LARGE_STRING_WRITE_CHUNK_CHARS = 4 * 1024 * 1024;
var _DEFERRED_STRING_WRITE_THRESHOLD = 256 * 1024;
var _MAX_WRITE_PASS_BYTES = 1024 * 1024;
var _SOCKET_READ_CHUNK_BYTES = 256 * 1024;
var _deferredUtf8TextEncoder = null;
function _normalizeWriteEncoding(encoding) {
	if (!encoding) return "utf8";
	var normalized = String(encoding).toLowerCase();
	if (normalized === "utf-8") return "utf8";
	if (normalized === "binary") return "latin1";
	return normalized;
}
function _canQueueDeferredString(data, encoding) {
	if (typeof data !== "string") return false;
	if (data.length < _DEFERRED_STRING_WRITE_THRESHOLD) return false;
	var normalized = _normalizeWriteEncoding(encoding);
	return normalized === "utf8" || normalized === "ascii" || normalized === "latin1";
}
function _nextDeferredStringChunkEnd(str, start, encoding) {
	var end = start + _LARGE_STRING_WRITE_CHUNK_CHARS;
	if (end >= str.length) return str.length;
	if (_normalizeWriteEncoding(encoding) === "utf8") {
		var prev = str.charCodeAt(end - 1);
		if (prev >= 55296 && prev <= 56319) {
			var next = str.charCodeAt(end);
			if (next >= 56320 && next <= 57343) end -= 1;
		}
	}
	return end > start ? end : start + 1;
}
function _createWriteQueueItem(data, encoding, callback) {
	if (_canQueueDeferredString(data, encoding)) return {
		callback,
		deferredString: data,
		deferredEncoding: _normalizeWriteEncoding(encoding),
		deferredIndex: 0,
		deferredChunk: null,
		deferredOffset: 0,
		deferredQueuedLength: data.length
	};
	var queuedData = null;
	if (typeof data === "string") queuedData = Buffer.from(data, encoding || "utf8");
	else queuedData = toBufferData(data, encoding);
	if (queuedData == null) queuedData = Buffer.alloc(0);
	return {
		data: queuedData,
		offset: 0,
		callback
	};
}
function _queuedWriteItemLength(item) {
	if (!item) return 0;
	if (item.data) return item.data.length - (item.offset || 0);
	if (!item.deferredString) return 0;
	var total = item.deferredQueuedLength || 0;
	if (item.deferredChunk) total += item.deferredChunk.length - (item.deferredOffset || 0);
	return total;
}
function _advanceDeferredWriteChunk(item) {
	if (!item || !item.deferredString) return false;
	if (item.deferredChunk && item.deferredOffset < item.deferredChunk.length) return true;
	if (item.deferredIndex >= item.deferredString.length) {
		item.deferredChunk = null;
		item.deferredOffset = 0;
		return false;
	}
	var end = _nextDeferredStringChunkEnd(item.deferredString, item.deferredIndex, item.deferredEncoding);
	var slice = item.deferredString.slice(item.deferredIndex, end);
	item.deferredIndex = end;
	item.deferredQueuedLength = item.deferredString.length - item.deferredIndex;
	if (item.deferredEncoding === "utf8" && typeof __exactStringToUtf8Bytes === "function") item.deferredChunk = __exactStringToUtf8Bytes(slice);
	else if (item.deferredEncoding === "utf8" && typeof TextEncoder === "function") {
		if (_deferredUtf8TextEncoder == null) _deferredUtf8TextEncoder = new TextEncoder();
		item.deferredChunk = _deferredUtf8TextEncoder.encode(slice);
	} else item.deferredChunk = Buffer.from(slice, item.deferredEncoding || "utf8");
	item.deferredOffset = 0;
	return item.deferredChunk.length > 0 || item.deferredIndex < item.deferredString.length;
}
function _isQueuedWriteItemComplete(item) {
	if (!item) return true;
	if (item.data) return (item.offset || 0) >= item.data.length;
	return !item.deferredString || item.deferredIndex >= item.deferredString.length && (!item.deferredChunk || item.deferredOffset >= item.deferredChunk.length);
}
Socket.prototype._appendToReadBuffer = function(data) {
	if (data == null) return;
	if (!data.length) return;
	var bufferData = toBufferData(data);
	if (bufferData == null || !bufferData.length) return;
	this._readBuffer.push(bufferData);
	this._readBufferLength += bufferData.length;
};
Socket.prototype._isFlowing = function() {
	return typeof this.listenerCount === "function" && this.listenerCount("data") > 0;
};
Socket.prototype._isReadBufferOverHighWaterMark = function() {
	return !this._isFlowing() && this._readBufferLength >= this._readableHighWaterMark;
};
Socket.prototype._emitFlowingData = function(data) {
	if (this._encoding) {
		var encodedChunk = this._decoder && typeof this._decoder.write === "function" ? this._decoder.write(toBufferData(data)) : toBufferData(data).toString(this._encoding);
		if (encodedChunk && encodedChunk.length) this.emit("data", encodedChunk);
	} else if (typeof Buffer !== "undefined") this.emit("data", toBufferData(data));
	else this.emit("data", data);
};
Socket.prototype._deliverInboundData = function(data) {
	if (this._isFlowing()) {
		this._emitFlowingData(data);
		return;
	}
	this._appendToReadBuffer(data);
	this.emit("readable");
};
Socket.prototype._consumeReadBuffer = function(size) {
	if (this._readBufferLength === 0) return null;
	if (typeof size !== "number" || size <= 0) {
		var allData = Buffer.concat(this._readBuffer, this._readBufferLength);
		this._readBuffer = [];
		this._readBufferLength = 0;
		return allData;
	}
	if (size >= this._readBufferLength) return this._consumeReadBuffer();
	var remaining = size;
	var parts = [];
	while (remaining > 0 && this._readBuffer.length > 0) {
		var chunk = this._readBuffer[0];
		if (chunk.length <= remaining) {
			this._readBuffer.shift();
			this._readBufferLength -= chunk.length;
			parts.push(chunk);
			remaining -= chunk.length;
		} else {
			parts.push(chunk.slice(0, remaining));
			this._readBuffer[0] = chunk.slice(remaining);
			this._readBufferLength -= remaining;
			remaining = 0;
		}
	}
	return parts.length === 1 ? parts[0] : Buffer.concat(parts, size - remaining);
};
Socket.prototype._drainWriteQueue = function() {
	if (this._drainTimer != null) {
		clearTimeout(this._drainTimer);
		this._drainTimer = null;
	}
	var nativeHandle = _unwrapHandle(this._handle);
	if (this._isWriting || nativeHandle == null || this.destroyed) return;
	if (this._corked) return;
	this._isWriting = true;
	var wroteBudget = 0;
	var shouldYieldSoon = false;
	while (this._writeQueue.length > 0 && !this.destroyed && nativeHandle != null) {
		var item = this._writeQueue[0];
		if (_isQueuedWriteItemComplete(item)) {
			var completeLength = _queuedWriteItemLength(item);
			if (completeLength > 0) {
				this._bufferedBytes -= completeLength;
				if (this._bufferedBytes < 0) this._bufferedBytes = 0;
			}
			this._writeQueue.shift();
			if (item.callback) _scheduleCallback(item.callback);
			continue;
		}
		var remaining = null;
		if (item.data) remaining = item.data.slice(item.offset);
		else {
			var pendingLengthBeforeAdvance = _queuedWriteItemLength(item);
			if (!_advanceDeferredWriteChunk(item)) {
				var pendingLength = _queuedWriteItemLength(item);
				if (pendingLength > 0) {
					this._bufferedBytes -= pendingLength;
					if (this._bufferedBytes < 0) this._bufferedBytes = 0;
				}
				this._writeQueue.shift();
				if (item.callback) _scheduleCallback(item.callback);
				continue;
			}
			var pendingLengthAfterAdvance = _queuedWriteItemLength(item);
			if (pendingLengthAfterAdvance !== pendingLengthBeforeAdvance) {
				this._bufferedBytes += pendingLengthAfterAdvance - pendingLengthBeforeAdvance;
				if (this._bufferedBytes < 0) this._bufferedBytes = 0;
			}
			remaining = typeof item.deferredChunk.subarray === "function" ? item.deferredChunk.subarray(item.deferredOffset) : item.deferredChunk.slice(item.deferredOffset);
		}
		var written = 0;
		try {
			written = __exactTcpWrite(nativeHandle, remaining);
		} catch (err) {
			var writeErr = err instanceof Error ? err : new Error(String(err));
			writeErr.code = "EPIPE";
			this._isWriting = false;
			this._writeQueue = [];
			this._bufferedBytes = 0;
			if (item.callback) _scheduleCallback(item.callback, writeErr);
			this.destroy(writeErr);
			return;
		}
		if (written === 0) break;
		wroteBudget += written;
		this._bufferedBytes -= written;
		if (this._bufferedBytes < 0) this._bufferedBytes = 0;
		if (item.data) item.offset += written;
		else item.deferredOffset += written;
		this._lastActivity = Date.now();
		this._timeoutEmitted = false;
		if (_isQueuedWriteItemComplete(item)) {
			this._writeQueue.shift();
			if (item.callback) _scheduleCallback(item.callback);
		}
		if (wroteBudget >= _MAX_WRITE_PASS_BYTES) {
			shouldYieldSoon = true;
			break;
		}
	}
	this._isWriting = false;
	if (this._writeQueue.length === 0) {
		if (this._closeAfterEnd) {
			this._closeAfterEnd = false;
			if (!this._finishEmitted) {
				this._finishEmitted = true;
				this.emit("finish");
			}
			_shutdownSocketWrite(this);
			this.writable = false;
			this._needDrain = false;
			if (this._drainEventTimer != null) {
				clearTimeout(this._drainEventTimer);
				this._drainEventTimer = null;
			}
			this.readyState = this.readable ? "readOnly" : "closed";
			if ((this._readEnded || !this.readable) && !this.destroyed) {
				var closingSelf = this;
				_scheduleTimer(function() {
					if (!closingSelf.destroyed) closingSelf.destroy();
				}, 0, closingSelf);
			}
			return;
		}
		if (this._needDrain && this._drainEventTimer == null) {
			this._needDrain = false;
			var self = this;
			this._drainEventTimer = _scheduleTimer(function() {
				self._drainEventTimer = null;
				if (!self.destroyed && self.writable && !self._ended) self.emit("drain");
			}, 0, this);
		}
		return;
	}
	var self = this;
	self._drainTimer = _scheduleTimer(function() {
		self._drainTimer = null;
		self._drainWriteQueue();
	}, shouldYieldSoon ? 0 : 1, self);
};
function _scheduleWriteQueueDrain(socket, delay) {
	if (!socket || socket.destroyed || socket._isWriting || socket._corked) return;
	if ((delay == null || delay <= 0) && typeof process !== "undefined" && typeof process.nextTick === "function") {
		if (socket._drainImmediateQueued) return;
		socket._drainImmediateQueued = true;
		process.nextTick(function() {
			socket._drainImmediateQueued = false;
			if (socket.destroyed || socket._isWriting || socket._corked) return;
			socket._drainWriteQueue();
		});
		return;
	}
	if (socket._drainTimer != null) return;
	socket._drainTimer = _scheduleTimer(function() {
		socket._drainTimer = null;
		socket._drainWriteQueue();
	}, delay == null ? 0 : delay, socket);
}
Socket.prototype._resolveOnreadBuffer = function() {
	if (!this._onread || !this._onread.buffer) return null;
	var buffer = this._onread.buffer;
	return typeof buffer === "function" ? buffer() : buffer;
};
Socket.prototype._notifyOnreadEOF = function() {
	if (this._onreadEOF) return true;
	if (!this._onread || typeof this._onread.callback !== "function") {
		this._onreadEOF = true;
		return true;
	}
	if (this._paused) return false;
	var buffer = this._resolveOnreadBuffer();
	this._onreadEOF = true;
	var cbResult = this._onread.callback.call(this, 0, buffer);
	if (cbResult === false) this._paused = true;
	return cbResult !== false;
};
Socket.prototype._processOnreadBuffer = function() {
	if (!this._onread || !this._onread.callback || this._readBufferLength === 0) return true;
	var data = this._consumeReadBuffer();
	if (data === null || !data.length) return true;
	var onread = this._onread;
	var offset = 0;
	var remaining = data.length;
	while (remaining > 0) {
		var buffer = this._resolveOnreadBuffer();
		if (!buffer || !buffer.length) {
			onread.callback.call(this, 0, buffer);
			return false;
		}
		var nread = remaining < buffer.length ? remaining : buffer.length;
		var sourceEnd = offset + nread;
		if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(data) && Buffer.isBuffer(buffer) && typeof data.copy === "function") data.copy(buffer, 0, offset, sourceEnd);
		else if (buffer && typeof buffer.set === "function" && data && typeof data.subarray === "function") buffer.set(data.subarray(offset, sourceEnd), 0);
		else for (var i = 0; i < nread; i++) buffer[i] = data[offset + i];
		offset = sourceEnd;
		remaining = data.length - offset;
		var cbResult = onread.callback.call(this, nread, buffer);
		if (cbResult === false) this._paused = true;
		if (cbResult === false || this._paused) {
			if (remaining > 0) this._appendToReadBuffer(data.slice(offset));
			return false;
		}
	}
	return true;
};
Socket.prototype._updateAddressInfo = function() {
	var nativeHandle = _unwrapHandle(this._handle);
	if (nativeHandle == null) return;
	if (this._isUnix) {
		this.remoteFamily = "Unix";
		return;
	}
	if (!_hasTcp) return;
	try {
		var remote = __exactTcpRemoteAddr(nativeHandle);
		if (remote) {
			var r = JSON.parse(remote);
			this.remoteAddress = r.address;
			this.remotePort = r.port;
			this.remoteFamily = r.family;
		}
	} catch (e) {}
	try {
		var local = __exactTcpLocalAddr(nativeHandle);
		if (local) {
			var l = JSON.parse(local);
			this.localAddress = l.address;
			this.localPort = l.port;
			this.localFamily = l.family;
		}
	} catch (e) {}
};
Socket.prototype._startPolling = function() {
	if (this._pollTimer != null || this.destroyed) return;
	var self = this;
	self._lastActivity = Date.now();
	self._timeoutEmitted = false;
	function poll() {
		if (self.destroyed) return;
		var nativeHandle = _unwrapHandle(self._handle);
		if (nativeHandle == null) {
			self._pollTimer = null;
			return;
		}
		if (self._onread) {
			var readOnreadData = false;
			if (self._paused) {
				_schedulePausedSocketPoll(self, poll);
				return;
			}
			if (!self._processOnreadBuffer()) {
				_schedulePausedSocketPoll(self, poll);
				return;
			}
			try {
				while (true) {
					var onreadData = __exactTcpRead(nativeHandle, _SOCKET_READ_CHUNK_BYTES);
					if (onreadData === null) {
						self._pollTimer = null;
						self._readEnded = true;
						if (!self._notifyOnreadEOF()) {
							_schedulePausedSocketPoll(self, poll);
							return;
						}
						_handleSocketEOF(self);
						return;
					}
					if (!onreadData.length) break;
					readOnreadData = true;
					self._lastActivity = Date.now();
					self._timeoutEmitted = false;
					self.bytesRead += onreadData.length;
					self._appendToReadBuffer(onreadData);
					if (!self._processOnreadBuffer()) {
						_schedulePausedSocketPoll(self, poll);
						return;
					}
				}
			} catch (e) {
				self._pollTimer = null;
				if (!self.destroyed) {
					var onreadErr = _normalizeSocketIOError(e, "read");
					if (_shouldTreatResetAsEof(self, onreadErr)) {
						self._readEnded = true;
						if (!self._notifyOnreadEOF()) {
							_schedulePausedSocketPoll(self, poll);
							return;
						}
						_handleSocketEOF(self);
						return;
					}
					self.destroy(onreadErr);
				}
				return;
			}
			if (self._timeoutMs > 0 && !self._timeoutEmitted && Date.now() - self._lastActivity >= self._timeoutMs) {
				self._timeoutEmitted = true;
				self.emit("timeout");
			}
			self._pollTimer = _scheduleTimer(poll, _getSocketPollDelay(self, readOnreadData), self);
			return;
		}
		if (self._paused) {
			_schedulePausedSocketPoll(self, poll);
			return;
		}
		if (self._isReadBufferOverHighWaterMark()) {
			self._readBackpressured = true;
			_schedulePausedSocketPoll(self, poll);
			return;
		}
		self._readBackpressured = false;
		try {
			var readData = false;
			while (true) {
				if (self._isReadBufferOverHighWaterMark()) {
					self._readBackpressured = true;
					break;
				}
				var data = __exactTcpRead(nativeHandle, _SOCKET_READ_CHUNK_BYTES);
				if (data === null) {
					self._pollTimer = null;
					_handleSocketEOF(self);
					return;
				}
				if (!data.length) break;
				readData = true;
				self._lastActivity = Date.now();
				self._timeoutEmitted = false;
				self.bytesRead += data.length;
				self._deliverInboundData(data);
				if (self._paused) {
					_schedulePausedSocketPoll(self, poll);
					return;
				}
			}
			if (self._readBackpressured) {
				_schedulePausedSocketPoll(self, poll);
				return;
			}
		} catch (e) {
			self._pollTimer = null;
			if (!self.destroyed) {
				var readErr = _normalizeSocketIOError(e, "read");
				if (_shouldTreatResetAsEof(self, readErr)) {
					_handleSocketEOF(self);
					return;
				}
				self.destroy(readErr);
			}
			return;
		}
		if (self._timeoutMs > 0 && !self._timeoutEmitted && Date.now() - self._lastActivity >= self._timeoutMs) {
			self._timeoutEmitted = true;
			self.emit("timeout");
		}
		self._pollTimer = _scheduleTimer(poll, _getSocketPollDelay(self, readData), self);
	}
	self._pollTimer = _scheduleTimer(poll, 0, self);
};
Socket.prototype.connect = function(options, connectListener) {
	if (typeof options === "number") {
		var port = options;
		var host = arguments[1] || "localhost";
		if (typeof arguments[1] === "function") {
			connectListener = arguments[1];
			host = "localhost";
		} else if (typeof arguments[2] === "function") connectListener = arguments[2];
		options = {
			port,
			host
		};
	} else if (typeof options === "string") options = { path: options };
	else if (Array.isArray(options)) if (options[_normalizedArgsSymbol] === true) {
		connectListener = connectListener || options[1];
		options = options[0] || {};
	} else {
		var arrErr = /* @__PURE__ */ new TypeError("The \"options\" or \"port\" or \"path\" argument must be specified");
		arrErr.code = "ERR_MISSING_ARGS";
		throw arrErr;
	}
	else if (typeof options === "boolean" || options === null) {
		var boolTypeErr = /* @__PURE__ */ new TypeError("The \"options\" or \"port\" or \"path\" argument must be of type string or number or object. Received type " + (options === null ? "null" : typeof options));
		boolTypeErr.code = "ERR_INVALID_ARG_TYPE";
		throw boolTypeErr;
	}
	options = options || {};
	if (this.connecting && !this.destroyed) {
		var alreadyConnectingErr = /* @__PURE__ */ new Error("Socket is already connecting");
		alreadyConnectingErr.code = "ERR_SOCKET_CONNECTING";
		throw alreadyConnectingErr;
	}
	if (options.address !== void 0 && options.address !== null && options.host === void 0 && options.hostname === void 0 && options.path === void 0) options = Object.assign({}, options, { host: options.address });
	var hasCustomConnectHandle = this._handle && this._handle._exactHandle === void 0 && typeof this._handle.connect === "function";
	if (this.destroyed || this._handle == null && !this.connecting || !hasCustomConnectHandle && this.readyState === "closed" && !this.connecting && !this._connected) _resetSocketForConnect(this);
	if (!_attachSocketAbortSignal(this, options.signal)) {
		this.connecting = false;
		this.pending = false;
		this.readyState = "closed";
		return this;
	}
	if (!options.path && options.port === void 0 && options.port !== 0) {
		if (typeof options.port === "undefined") {
			var missingErr = /* @__PURE__ */ new TypeError("The \"options\" or \"port\" or \"path\" argument must be specified");
			missingErr.code = "ERR_MISSING_ARGS";
			throw missingErr;
		}
	}
	if (options.autoSelectFamily !== void 0 && typeof options.autoSelectFamily !== "boolean") {
		var asfErr = /* @__PURE__ */ new TypeError("The \"options.autoSelectFamily\" property must be of type boolean. Received type " + typeof options.autoSelectFamily);
		asfErr.code = "ERR_INVALID_ARG_TYPE";
		throw asfErr;
	}
	if (options.autoSelectFamilyAttemptTimeout !== void 0) {
		var asft = options.autoSelectFamilyAttemptTimeout;
		if (typeof asft !== "number") {
			var asftTypeErr = /* @__PURE__ */ new TypeError("The \"options.autoSelectFamilyAttemptTimeout\" property must be of type number");
			asftTypeErr.code = "ERR_INVALID_ARG_TYPE";
			throw asftTypeErr;
		}
		if (asft <= 0 || !isFinite(asft)) {
			var asftRangeErr = /* @__PURE__ */ new RangeError("The value of \"options.autoSelectFamilyAttemptTimeout\" is out of range. It must be > 0. Received " + asft);
			asftRangeErr.code = "ERR_OUT_OF_RANGE";
			throw asftRangeErr;
		}
	}
	if (options.host !== void 0 && typeof options.host !== "string") {
		var hostErr = /* @__PURE__ */ new TypeError("The \"options.host\" property must be of type string. Received type " + typeof options.host);
		hostErr.code = "ERR_INVALID_ARG_TYPE";
		throw hostErr;
	}
	var invalidOpts = [
		"objectMode",
		"readableObjectMode",
		"writableObjectMode"
	];
	for (var oi = 0; oi < invalidOpts.length; oi++) if (options[invalidOpts[oi]]) {
		var optErr = /* @__PURE__ */ new TypeError("The property 'options." + invalidOpts[oi] + "' is not supported. Received " + options[invalidOpts[oi]]);
		optErr.code = "ERR_INVALID_ARG_VALUE";
		throw optErr;
	}
	if (!options.path && options.port !== void 0) options.port = _validateConnectPort(options.port);
	_validateConnectPath(options.path);
	_validateLookupOption(options.lookup);
	_validateHintsOption(options.hints);
	_validateLocalAddressOption(options.localAddress);
	_validateLocalPortOption(options.localPort);
	this.connecting = true;
	this.pending = true;
	this.readyState = "opening";
	this.autoSelectFamilyAttemptedAddresses = void 0;
	if (connectListener) this.once("connect", connectListener);
	if (Object.prototype.hasOwnProperty.call(options, "noDelay")) this._noDelay = options.noDelay;
	if (Object.prototype.hasOwnProperty.call(options, "keepAlive")) this._keepAlive = options.keepAlive;
	if (Object.prototype.hasOwnProperty.call(options, "keepAliveInitialDelay")) this._keepAliveInitialDelay = options.keepAliveInitialDelay;
	if (options.path) {
		this._isUnix = true;
		this._socketPath = options.path;
		this.remoteFamily = "Unix";
		if (!_hasUnix) {
			var self = this;
			setTimeout(function() {
				var err = /* @__PURE__ */ new Error("Unix sockets not supported: native __exactUnixConnect not available");
				err.code = "ECONNREFUSED";
				self.destroy(err);
			}, 0);
			return this;
		}
		var self = this;
		setTimeout(function() {
			if (self.destroyed) return;
			try {
				var unixHandle = __exactUnixConnect(self._socketPath);
				_setSocketHandle(self._handle, unixHandle);
				_setHandleRefState(self._handle, !self._unrefed);
				self.connecting = false;
				self._connected = true;
				self.pending = false;
				self.readyState = "open";
				self._updateAddressInfo();
				self._startPolling();
				_updateSocketTimeoutHandleState(self);
				self.emit("connect");
				self.emit("ready");
			} catch (e) {
				var err = _createUnixConnectError(e, self._socketPath);
				self.destroy(err);
			}
		}, 0);
		return this;
	}
	this._requestedPort = options.port;
	this._requestedAddress = options.host || options.hostname || "localhost";
	this.remotePort = void 0;
	this.remoteAddress = void 0;
	if (options.localAddress) this.localAddress = options.localAddress;
	if (options.localPort) this.localPort = options.localPort;
	if (options.family) this._family = options.family;
	this.remoteFamily = void 0;
	if (hasCustomConnectHandle) {
		var self = this;
		setTimeout(function() {
			if (self.destroyed) return;
			var connectResult;
			try {
				connectResult = self._handle.connect({}, self._requestedAddress, self._requestedPort);
			} catch (err) {
				self.destroy(err);
				return;
			}
			if (typeof connectResult === "number" && connectResult !== 0) {
				var connectErr = _createConnectError(_uvConnectCodeToErrno(connectResult), self._requestedAddress, self._requestedPort, "connect");
				self.destroy(connectErr);
				return;
			}
			self.connecting = false;
			self._connected = true;
			self.pending = false;
			self.readyState = "open";
			if (typeof self._handle.readStart === "function") try {
				self._handle.readStart();
			} catch (_customReadStartErr) {
				_swallowDebug("custom handle readStart failed", _customReadStartErr);
			}
			_updateSocketTimeoutHandleState(self);
			self.emit("connect");
			self.emit("ready");
		}, 0);
		return this;
	}
	if (!_hasTcp) {
		var self = this;
		setTimeout(function() {
			var err = /* @__PURE__ */ new Error("TCP sockets not supported: native __exactTcpConnect not available");
			err.code = "ECONNREFUSED";
			self.destroy(err);
		}, 0);
		return this;
	}
	var self = this;
	var lookup = options.lookup;
	var customLookup = typeof lookup === "function";
	var resolver = lookup;
	if (!customLookup && isIP(self._requestedAddress) === 0) try {
		var dns = require("dns");
		if (dns && typeof dns.lookup === "function") resolver = dns.lookup;
	} catch (e) {}
	if (_hasConflictingLocalBind(options.localAddress, options.localPort)) {
		_scheduleTimer(function() {
			var bindErr = _createConnectError("EADDRINUSE", self._requestedAddress, self._requestedPort, "connect");
			self.destroy(bindErr);
		}, 0, self);
		return this;
	}
	var autoSelectFamily = options.autoSelectFamily;
	if (autoSelectFamily === void 0) {
		autoSelectFamily = _defaultAutoSelectFamily;
		if (autoSelectFamily === false && !options.family && self._requestedAddress === "localhost") autoSelectFamily = true;
	}
	if (autoSelectFamily === void 0) autoSelectFamily = false;
	if (autoSelectFamily) self.autoSelectFamilyAttemptedAddresses = [];
	var lookupFamily = _parseLookupFamily(options.family);
	var attempts = [{
		address: self._requestedAddress,
		family: lookupFamily
	}];
	function _normalizeCandidate(raw, fallbackFamily) {
		if (!raw) return null;
		if (typeof raw === "string") return {
			address: raw,
			family: fallbackFamily
		};
		if (typeof raw === "object" && typeof raw.address === "string") return {
			address: raw.address,
			family: raw.family != null ? _parseLookupFamily(raw.family) : fallbackFamily
		};
		return null;
	}
	function _startTcpConnect(selfRef, attemptList, shouldAutoSelect) {
		var attemptErrors = [];
		var idx = 0;
		var connected = false;
		function nextAttempt() {
			if (connected) return;
			if (selfRef.destroyed || selfRef._abortPending) return;
			if (typeof process !== "undefined" && process._exactExiting) return;
			if (idx >= attemptList.length) {
				if (connected) return;
				if (selfRef.destroyed || selfRef._abortPending) return;
				if (attemptErrors.length === 0) {
					selfRef.connecting = false;
					selfRef.pending = false;
					selfRef.readyState = "closed";
					return;
				}
				var finalErr = attemptErrors[attemptErrors.length - 1];
				if (shouldAutoSelect && attemptErrors.length > 1) {
					if (typeof AggregateError === "function") finalErr = new AggregateError(attemptErrors, "Unable to connect");
					else finalErr = /* @__PURE__ */ new Error("Unable to connect");
					finalErr.errors = attemptErrors;
				}
				selfRef.destroy(finalErr);
				return;
			}
			var target = _normalizeCandidate(attemptList[idx], lookupFamily);
			idx++;
			if (!target || !target.address) {
				nextAttempt();
				return;
			}
			var address = target.address;
			var family = target.family;
			if (selfRef.autoSelectFamilyAttemptedAddresses) selfRef.autoSelectFamilyAttemptedAddresses.push(address + ":" + selfRef._requestedPort);
			if (shouldAutoSelect && customLookup && !_isLocalTestAddress(address)) {
				attemptErrors.push(_createConnectError("ECONNREFUSED", address, selfRef._requestedPort, "connect"));
				nextAttempt();
				return;
			}
			if (options.blockList && typeof options.blockList.check === "function") {
				var ipType = isIPv6(address) ? "ipv6" : "ipv4";
				if (options.blockList.check(address, ipType)) {
					var blockErr = /* @__PURE__ */ new Error("IP blocked: " + address);
					blockErr.code = "ERR_IP_BLOCKED";
					selfRef.destroy(blockErr);
					return;
				}
			}
			if (isIP(address) === 4 && _hasMatchingIPv6OnlyServer(address, selfRef._requestedPort)) {
				attemptErrors.push(_createConnectError("ECONNREFUSED", address, selfRef._requestedPort, "connect"));
				nextAttempt();
				return;
			}
			var localAddressArg = options.localAddress === void 0 ? null : options.localAddress;
			var localPortArg = options.localPort === void 0 ? null : options.localPort;
			if (_hasAsyncTcpConnect) {
				var startHandle;
				try {
					startHandle = __exactTcpConnectStart(address, selfRef._requestedPort, localAddressArg, localPortArg);
				} catch (startErr) {
					if (selfRef.destroyed || selfRef._abortPending) return;
					attemptErrors.push(_createConnectErrorFromRaw(startErr, address, selfRef._requestedPort));
					nextAttempt();
					return;
				}
				if (selfRef.destroyed || selfRef._abortPending) {
					try {
						__exactTcpClose(startHandle);
					} catch (e) {}
					return;
				}
				_pollTcpConnect(selfRef, startHandle, function onConnectPollDone() {
					if (selfRef.destroyed || selfRef._abortPending) {
						try {
							__exactTcpClose(startHandle);
						} catch (e) {}
						return;
					}
					connected = true;
					_finishTcpConnectSuccess(selfRef, startHandle, address, family);
				}, function onConnectPollFailed(pollErr) {
					if (selfRef.destroyed || selfRef._abortPending) return;
					attemptErrors.push(_createConnectErrorFromRaw(pollErr, address, selfRef._requestedPort));
					nextAttempt();
				});
				return;
			}
			try {
				var nativeHandle = __exactTcpConnect(address, selfRef._requestedPort, localAddressArg, localPortArg);
				if (selfRef.destroyed) {
					try {
						__exactTcpClose(nativeHandle);
					} catch (e) {}
					return;
				}
				connected = true;
				_finishTcpConnectSuccess(selfRef, nativeHandle, address, family);
				return;
			} catch (err) {
				if (selfRef.destroyed || selfRef._abortPending) return;
				var connErr = _createConnectErrorFromRaw(err, address, selfRef._requestedPort);
				attemptErrors.push(connErr);
				nextAttempt();
				return;
			}
		}
		nextAttempt();
	}
	setTimeout(function() {
		if (self.destroyed) return;
		if (!customLookup && self._requestedAddress === "localhost") {
			var localhostCandidates = _getFastLocalhostConnectCandidates(lookupFamily, autoSelectFamily);
			if (localhostCandidates.length > 0) {
				var firstLocalhostCandidate = localhostCandidates[0];
				self.emit("lookup", null, firstLocalhostCandidate.address, firstLocalhostCandidate.family || lookupFamily || isIP(firstLocalhostCandidate.address), self._requestedAddress);
				_startTcpConnect(self, localhostCandidates, autoSelectFamily);
				return;
			}
		}
		if (typeof resolver === "function") {
			var lookupOptions = { family: lookupFamily };
			if (options.hints !== void 0) lookupOptions.hints = options.hints;
			if (options.verbatim !== void 0) lookupOptions.verbatim = options.verbatim;
			if (autoSelectFamily) lookupOptions.all = true;
			if (options.all !== void 0) lookupOptions.all = options.all;
			try {
				resolver(self._requestedAddress, lookupOptions, function(err, lookupResult, candidateFamily) {
					if (err) {
						self.emit("lookup", err, void 0, void 0, self._requestedAddress);
						self.destroy(err);
						return;
					}
					if (candidateFamily != null) lookupFamily = _parseLookupFamily(candidateFamily);
					var normalized = _normalizeLookupResults(lookupResult).map(function(entry) {
						return _normalizeCandidate(entry, lookupFamily);
					}).filter(Boolean);
					for (var ni = 0; ni < normalized.length; ni++) {
						var normalizedFamily = normalized[ni].family;
						if (normalizedFamily != null && normalizedFamily !== 0 && normalizedFamily !== 4 && normalizedFamily !== 6) {
							self.destroy(_createInvalidAddressFamilyError(normalizedFamily, self._requestedAddress, self._requestedPort));
							return;
						}
					}
					if (autoSelectFamily && normalized.length > 1) {
						var ipv6Candidates = [];
						var ipv4Candidates = [];
						for (var ni = 0; ni < normalized.length; ni++) {
							var candidate = normalized[ni];
							if (!candidate) continue;
							if ((candidate.family || isIP(candidate.address)) === 6) ipv6Candidates.push(candidate);
							else ipv4Candidates.push(candidate);
						}
						var firstFamily = (normalized[0].family || isIP(normalized[0].address)) === 6 ? 6 : 4;
						normalized = [];
						var alternateCount = ipv6Candidates.length > ipv4Candidates.length ? ipv6Candidates.length : ipv4Candidates.length;
						for (var ai = 0; ai < alternateCount; ai++) if (firstFamily === 6) {
							if (ai < ipv6Candidates.length) normalized.push(ipv6Candidates[ai]);
							if (ai < ipv4Candidates.length) normalized.push(ipv4Candidates[ai]);
						} else {
							if (ai < ipv4Candidates.length) normalized.push(ipv4Candidates[ai]);
							if (ai < ipv6Candidates.length) normalized.push(ipv6Candidates[ai]);
						}
					}
					if (autoSelectFamily === false && normalized.length > 0) normalized = [normalized[0]];
					if (normalized.length === 0) {
						self.destroy(_createInvalidIPAddressError(self._requestedAddress));
						return;
					}
					var first = normalized[0];
					if (first) self.emit("lookup", null, first.address, first.family || lookupFamily || isIP(first.address), self._requestedAddress);
					if (options.blockList && typeof options.blockList.check === "function") for (var bi = 0; bi < normalized.length; bi++) {
						var addr = normalized[bi].address;
						var blType = isIPv6(addr) ? "ipv6" : "ipv4";
						if (options.blockList.check(addr, blType)) {
							var blockErr = /* @__PURE__ */ new Error("IP blocked: " + addr);
							blockErr.code = "ERR_IP_BLOCKED";
							self.destroy(blockErr);
							return;
						}
					}
					_startTcpConnect(self, normalized, autoSelectFamily);
				});
			} catch (err) {
				self.destroy(err);
			}
			return;
		}
		_startTcpConnect(self, attempts, autoSelectFamily);
	}, 0);
	return this;
};
Socket.prototype.write = function(data, encoding, callback) {
	if (typeof encoding === "function") {
		callback = encoding;
		encoding = void 0;
	}
	if (data === null) {
		var nullErr = /* @__PURE__ */ new TypeError("May not write null values to stream");
		nullErr.code = "ERR_STREAM_NULL_VALUES";
		throw nullErr;
	}
	if (typeof data === "string" && encoding === "buffer") {
		var bufferArgErr = /* @__PURE__ */ new TypeError("Second argument must be a buffer");
		bufferArgErr.code = "ERR_INVALID_ARG_TYPE";
		throw bufferArgErr;
	}
	if (typeof data !== "string" && !Buffer.isBuffer(data) && !(typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(data))) {
		var typeErr = /* @__PURE__ */ new TypeError("The \"chunk\" argument must be of type string or an instance of Buffer, TypedArray, or DataView." + _invalidArgTypeHelper(data));
		typeErr.code = "ERR_INVALID_ARG_TYPE";
		throw typeErr;
	}
	if (!this.writable || this.destroyed) {
		var err = _createSocketWriteError(this);
		_emitAsyncSocketError(this, err, callback);
		return false;
	}
	if (_unwrapHandle(this._handle) == null) {
		if (this.connecting) {
			var queuedItem = _createWriteQueueItem(data, encoding, callback);
			this._writeQueue.push(queuedItem);
			this._bufferedBytes += _queuedWriteItemLength(queuedItem);
			this._bytesWritten += _queuedWriteItemLength(queuedItem);
			var pendingBufferedLength = this.bufferSize;
			if (pendingBufferedLength >= this._writableHighWaterMark) this._needDrain = true;
			return pendingBufferedLength < this._writableHighWaterMark;
		}
		var err2;
		if (this._handle != null) {
			err2 = /* @__PURE__ */ new Error("write EBADF");
			err2.code = "EBADF";
		} else {
			err2 = /* @__PURE__ */ new Error("Socket is closed");
			err2.code = "ERR_SOCKET_CLOSED";
		}
		_emitAsyncSocketError(this, err2, callback);
		return false;
	}
	var writeItem = _createWriteQueueItem(data, encoding, callback);
	this._writeQueue.push(writeItem);
	this._bufferedBytes += _queuedWriteItemLength(writeItem);
	this._bytesWritten += _queuedWriteItemLength(writeItem);
	var shouldReturnFalse = this.bufferSize >= this._writableHighWaterMark;
	if (shouldReturnFalse) this._needDrain = true;
	if (!this._isWriting && !this._corked) _scheduleWriteQueueDrain(this, 0);
	return !shouldReturnFalse;
};
function _invalidArgTypeHelper(input) {
	if (input == null) return " Received " + input;
	if (typeof input === "function") return " Received function " + (input.name || "anonymous");
	if (typeof input === "object") {
		if (input.constructor && input.constructor.name) return " Received an instance of " + input.constructor.name;
		return " Received " + String(input);
	}
	return " Received type " + typeof input + " (" + String(input) + ")";
}
Socket.prototype.end = function(data, encoding, callback) {
	if (typeof data === "function") {
		callback = data;
		data = void 0;
	}
	if (typeof encoding === "function") {
		callback = encoding;
		encoding = void 0;
	}
	if (data != null) this.write(data, encoding);
	if (!this._autoEnding) this._autoEndedFromPeer = false;
	this._ended = true;
	this._needDrain = false;
	if (this._drainEventTimer != null) {
		clearTimeout(this._drainEventTimer);
		this._drainEventTimer = null;
	}
	this.writable = false;
	if (this.connecting) this.readyState = "opening";
	else this.readyState = this.readable ? "readOnly" : "closed";
	if (callback) this.once("finish", callback);
	if (this.connecting || _unwrapHandle(this._handle) != null || this._writeQueue.length > 0) {
		this._closeAfterEnd = true;
		_scheduleWriteQueueDrain(this, 0);
	} else if (!this._finishEmitted) {
		var self = this;
		_scheduleTimer(function() {
			if (!self._finishEmitted) {
				self._finishEmitted = true;
				self.emit("finish");
			}
		}, 0, this);
	}
	return this;
};
Socket.prototype.destroy = function(err) {
	if (this.destroyed) return this;
	var wasConnecting = this.connecting;
	_detachSocketAbortListener(this);
	this._abortPending = false;
	this.destroyed = true;
	this.readable = false;
	this.writable = false;
	this.connecting = false;
	this.readyState = "closed";
	this.pending = false;
	if (this._pollTimer != null) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	if (this._drainTimer != null) {
		clearTimeout(this._drainTimer);
		this._drainTimer = null;
	}
	if (this._drainEventTimer != null) {
		clearTimeout(this._drainEventTimer);
		this._drainEventTimer = null;
	}
	if (this._timeoutTimer != null) {
		clearTimeout(this._timeoutTimer);
		this._timeoutTimer = null;
	}
	this[kTimeout] = null;
	if (this._writeQueue.length) {
		var endErr;
		if (err instanceof Error) endErr = err;
		else if (!err && wasConnecting) if (this._suppressCloseBeforeConnectError) endErr = null;
		else {
			endErr = /* @__PURE__ */ new Error("Socket closed before the connection was established");
			endErr.code = "ERR_SOCKET_CLOSED_BEFORE_CONNECTION";
		}
		else endErr = new Error(err ? String(err) : "Socket destroyed");
		for (var i = 0; i < this._writeQueue.length; i++) {
			var queued = this._writeQueue[i];
			if (queued.callback) setTimeout(function(cb, error) {
				cb(error);
			}, 0, queued.callback, endErr);
		}
		this._writeQueue = [];
		this._bufferedBytes = 0;
		this._isWriting = false;
	}
	this._suppressCloseBeforeConnectError = false;
	_cancelPendingConnect(this);
	var nativeHandle = _unwrapHandle(this._handle);
	if (nativeHandle != null && _hasTcp) try {
		__exactTcpClose(nativeHandle);
	} catch (e) {}
	this._handle = null;
	if (err) this.emit("error", err);
	var self = this;
	_scheduleCallback(function(hadErr) {
		self.emit("close", hadErr);
	}, !!err);
	return this;
};
Socket.prototype.close = Socket.prototype.destroy;
Socket.prototype.resetAndDestroy = function() {
	if (this._handle != null && _hasTcp) {
		var nativeHandle = _unwrapHandle(this._handle);
		if (nativeHandle != null && typeof __exactTcpReset === "function") try {
			__exactTcpReset(nativeHandle);
		} catch (e) {}
	}
	return this.destroy();
};
Socket.prototype.setTimeout = function(timeout, callback) {
	if (typeof timeout !== "number") {
		var typeErr = /* @__PURE__ */ new TypeError("The \"msecs\" argument must be of type number. Received type " + typeof timeout);
		typeErr.code = "ERR_INVALID_ARG_TYPE";
		throw typeErr;
	}
	if (timeout < 0 || !isFinite(timeout)) {
		var rangeErr = /* @__PURE__ */ new RangeError("The value of \"msecs\" is out of range. It must be a non-negative finite number. Received " + timeout);
		rangeErr.code = "ERR_OUT_OF_RANGE";
		throw rangeErr;
	}
	this.timeout = timeout || 0;
	this._timeoutMs = timeout || 0;
	this._timeoutEmitted = false;
	if (timeout > 0) this._lastActivity = Date.now();
	if (callback !== void 0) {
		if (typeof callback !== "function") {
			var cbErr = /* @__PURE__ */ new TypeError("The \"callback\" argument must be of type function. Received type " + typeof callback);
			cbErr.code = "ERR_INVALID_ARG_TYPE";
			throw cbErr;
		}
		if (timeout > 0) this.once("timeout", callback);
		else this.removeListener("timeout", callback);
	}
	_updateSocketTimeoutHandleState(this);
	return this;
};
Socket.prototype.read = function(size) {
	var result = this._consumeReadBuffer(typeof size === "number" ? size : void 0);
	if (this._readBackpressured && !this._isReadBufferOverHighWaterMark()) {
		this._readBackpressured = false;
		if (!this.destroyed && !this._paused && !this._customHandle && _unwrapHandle(this._handle) != null) {
			if (this._pollTimer != null) {
				clearTimeout(this._pollTimer);
				this._pollTimer = null;
			}
			this._startPolling();
		}
	}
	return result;
};
Socket.prototype.on = function(eventName, listener) {
	var result = EventEmitter.prototype.on.call(this, eventName, listener);
	_maybeActivateDeferredReadableSocket(this, eventName);
	_scheduleFlushBufferedReadData(this, eventName);
	return result;
};
Socket.prototype.addListener = function(eventName, listener) {
	var result = EventEmitter.prototype.addListener.call(this, eventName, listener);
	_maybeActivateDeferredReadableSocket(this, eventName);
	_scheduleFlushBufferedReadData(this, eventName);
	return result;
};
Socket.prototype.prependListener = function(eventName, listener) {
	var result = EventEmitter.prototype.prependListener.call(this, eventName, listener);
	_maybeActivateDeferredReadableSocket(this, eventName);
	_scheduleFlushBufferedReadData(this, eventName);
	return result;
};
Socket.prototype.push = function(chunk, encoding) {
	if (chunk === null) {
		_handleSocketEOF(this);
		return false;
	}
	var pushData = toBufferData(chunk, encoding);
	if (pushData == null || !pushData.length) return !this._paused;
	this.bytesRead += pushData.length;
	this._lastActivity = Date.now();
	this._timeoutEmitted = false;
	if (this._onread) {
		this._appendToReadBuffer(pushData);
		if (!this._paused) this._processOnreadBuffer();
		return !this._paused;
	}
	this._deliverInboundData(pushData);
	return !this._paused;
};
Socket.prototype.unshift = function(chunk) {
	if (chunk == null) return;
	var unshiftData = toBufferData(chunk);
	if (unshiftData == null || !unshiftData.length) return;
	this._readBuffer.unshift(unshiftData);
	this._readBufferLength += unshiftData.length;
};
Socket.prototype.setNoDelay = function(noDelay) {
	this._noDelay = noDelay !== false;
	if (_unwrapHandle(this._handle) != null && _hasTcp) try {
		this._handle.setNoDelay(noDelay !== false);
	} catch (e) {}
	return this;
};
Socket.prototype.setKeepAlive = function(enable, delay) {
	this._keepAlive = enable !== false;
	this._keepAliveInitialDelay = delay || 0;
	if (_unwrapHandle(this._handle) != null && _hasTcp) try {
		this._handle.setKeepAlive(enable, delay);
	} catch (e) {}
	return this;
};
Socket.prototype.ref = function() {
	this._unrefed = false;
	_setHandleRefState(this._handle, true);
	_setTimerRefState(this._pollTimer, true);
	_setTimerRefState(this._drainTimer, true);
	_setTimerRefState(this._drainEventTimer, true);
	_setTimerRefState(this._timeoutTimer, true);
	return this;
};
Socket.prototype.unref = function() {
	this._unrefed = true;
	_setHandleRefState(this._handle, false);
	_setTimerRefState(this._pollTimer, false);
	_setTimerRefState(this._drainTimer, false);
	_setTimerRefState(this._drainEventTimer, false);
	_setTimerRefState(this._timeoutTimer, false);
	return this;
};
Socket.prototype.address = function() {
	if (this._isUnix) return this._socketPath;
	if (this._handle != null && _hasTcp) {
		var nativeHandle = _unwrapHandle(this._handle);
		if (nativeHandle == null) return {
			address: this.localAddress,
			port: this.localPort,
			family: this.localFamily || this.remoteFamily || "IPv4"
		};
		try {
			var info = __exactTcpLocalAddr(nativeHandle);
			if (info) return JSON.parse(info);
		} catch (e) {}
	}
	return {
		address: this.localAddress,
		port: this.localPort,
		family: this.remoteFamily || "IPv4"
	};
};
Socket.prototype.pause = function() {
	var wasPaused = this._paused === true;
	this._paused = true;
	_setTimerRefState(this._pollTimer, false);
	if (this._customHandle && this._customReadStarted && this._handle && typeof this._handle.readStop === "function") try {
		this._handle.readStop();
		this._customReadStarted = false;
	} catch (_pauseReadStopErr) {}
	if (!wasPaused) this.emit("pause");
	return this;
};
Socket.prototype.resume = function() {
	var wasPaused = this._paused === true;
	this._paused = false;
	this._deferReadableStart = false;
	if (this._pollTimer != null) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	if (this._customHandle && !this._customReadStarted && this._handle && typeof this._handle.readStart === "function") {
		this._customReadStarted = true;
		var self = this;
		this._handle.onread = function(nread, buffer) {
			if (self.destroyed) return;
			var bytes = nread;
			if (bytes == null && typeof globalThis === "object" && globalThis.__exactStreamWrapState) bytes = globalThis.__exactStreamWrapState[globalThis.__exactStreamWrapReadBytesOrErrorIndex || 0];
			var eof = typeof globalThis === "object" && globalThis.__exactUvEOFValue !== void 0 ? globalThis.__exactUvEOFValue : -4095;
			if (bytes === eof || bytes === null) {
				_handleSocketEOF(self);
				return;
			}
			if (typeof bytes === "number" && bytes > 0 && buffer) {
				var data = buffer;
				if (typeof Buffer !== "undefined" && !Buffer.isBuffer(data)) data = Buffer.from(buffer.slice ? buffer.slice(0, bytes) : buffer);
				self._deliverInboundData(data);
			}
		};
		try {
			this._handle.readStart();
		} catch (err) {
			this.destroy(err);
		}
	}
	if (!this.destroyed && _unwrapHandle(this._handle) != null && this._pollTimer == null && !this._customHandle) this._startPolling();
	if (wasPaused) this.emit("resume");
	_scheduleFlushBufferedReadData(this, "data");
	return this;
};
Socket.prototype.pipe = function(dest, options) {
	var self = this;
	self.on("data", function(chunk) {
		if (dest.write(chunk) === false && typeof self.pause === "function") self.pause();
	});
	dest.on("drain", function() {
		if (typeof self.resume === "function") self.resume();
	});
	self.on("end", function() {
		if (!options || options.end !== false) {
			if (dest.end) dest.end();
		}
	});
	return dest;
};
Socket.prototype.setEncoding = function(enc) {
	this._encoding = enc;
	this._decoder = enc && StringDecoder ? new StringDecoder(enc) : null;
	return this;
};
Socket.prototype.cork = function() {
	this._corked += 1;
};
Socket.prototype.uncork = function() {
	if (this._corked > 0) this._corked -= 1;
	if (this._corked === 0 && this._writeQueue.length > 0 && !this._isWriting) _scheduleWriteQueueDrain(this, 0);
};
function Server(options, connectionListener) {
	if (!(this instanceof Server)) return new Server(options, connectionListener);
	if (typeof options === "function") {
		connectionListener = options;
		options = {};
	}
	if (options !== void 0 && options !== null && typeof options !== "object") {
		var typeErr = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + typeof options);
		typeErr.code = "ERR_INVALID_ARG_TYPE";
		throw typeErr;
	}
	options = options || {};
	this._events = {};
	this.listening = false;
	this.maxConnections = null;
	this._handle = null;
	this._acceptTimer = null;
	this._connections = 0;
	this._closing = false;
	this._workers = [];
	this._isUnix = false;
	this._socketPath = null;
	this._listenToken = 0;
	this._listeningPending = false;
	this._readableAll = false;
	this._writableAll = false;
	this.ipv6Only = false;
	this.allowHalfOpen = options.allowHalfOpen || false;
	this.pauseOnConnect = options.pauseOnConnect || false;
	this.noDelay = options.noDelay;
	this.keepAlive = options.keepAlive;
	this.keepAliveInitialDelay = options.keepAliveInitialDelay || 0;
	this.blockList = options.blockList || null;
	this.captureRejections = options.captureRejections === true;
	this._connectionKey = null;
	this._unrefed = false;
	this._unref = false;
	if (typeof EventEmitter === "function" && EventEmitter.prototype) {
		for (var k in EventEmitter.prototype) if (!this[k]) this[k] = EventEmitter.prototype[k];
	}
	if (connectionListener) this.on("connection", connectionListener);
}
Server.prototype.listen = function(port, host, backlog, callback) {
	if ((this.listening || this._listeningPending) && !this._closing) {
		var alreadyListeningErr = /* @__PURE__ */ new Error("Listen method has been called more than once without closing.");
		alreadyListeningErr.code = "ERR_SERVER_ALREADY_LISTEN";
		throw alreadyListeningErr;
	}
	if (typeof port === "function") {
		callback = port;
		port = 0;
		host = void 0;
		backlog = void 0;
	} else if (port === void 0) port = 0;
	if (typeof host === "function") {
		callback = host;
		host = void 0;
		backlog = void 0;
	}
	if (typeof backlog === "function") {
		callback = backlog;
		backlog = void 0;
	}
	var unixPath = null;
	var directHandle = null;
	var invalidListenFd = null;
	var readableAll = false;
	var writableAll = false;
	var self = this;
	if (typeof port === "string" && !isFinite(Number(port))) {
		unixPath = port;
		port = void 0;
	} else if (typeof port === "boolean") {
		var invalidErr = /* @__PURE__ */ new TypeError("The argument 'options' is invalid. Received " + port);
		invalidErr.code = "ERR_INVALID_ARG_VALUE";
		throw invalidErr;
	} else if (typeof port === "object" && port !== null) {
		var opts = port;
		if (opts._exactHandle !== void 0) {
			directHandle = opts;
			opts = {};
		}
		if (opts.port !== void 0 && typeof opts.port === "boolean") {
			var invalidPortErr = /* @__PURE__ */ new TypeError("The argument 'options' is invalid. Received " + JSON.stringify(opts));
			invalidPortErr.code = "ERR_INVALID_ARG_VALUE";
			throw invalidPortErr;
		}
		if (opts.path !== void 0 && typeof opts.path !== "string") {
			var invalidPathErr = /* @__PURE__ */ new TypeError("The argument 'options' is invalid. Received " + JSON.stringify(opts));
			invalidPathErr.code = "ERR_INVALID_ARG_VALUE";
			throw invalidPathErr;
		}
		if (opts.fd !== void 0 && typeof opts.fd !== "number") {
			var invalidFdErr = /* @__PURE__ */ new TypeError("The argument 'options' is invalid. Received " + JSON.stringify(opts));
			invalidFdErr.code = "ERR_INVALID_ARG_VALUE";
			throw invalidFdErr;
		}
		var hasPort = Object.prototype.hasOwnProperty.call(opts, "port");
		var hasPath = Object.prototype.hasOwnProperty.call(opts, "path");
		var hasExactHandle = !!(opts.handle && opts.handle._exactHandle !== void 0 || opts._handle && opts._handle._exactHandle !== void 0);
		var hasValidFd = typeof opts.fd === "number" && opts.fd >= 0;
		if (!directHandle && !hasPort && !hasPath && !hasValidFd && !hasExactHandle) {
			var missingPropErr = /* @__PURE__ */ new TypeError("The argument 'options' must have the property \"port\" or \"path\". Received " + JSON.stringify(opts));
			missingPropErr.code = "ERR_INVALID_ARG_VALUE";
			throw missingPropErr;
		}
		if (typeof opts.fd === "number" && opts.fd < 0 && (hasPort || hasPath)) {
			var invalidFdRangeErr = /* @__PURE__ */ new TypeError("The argument 'options' is invalid. Received " + JSON.stringify(opts));
			invalidFdRangeErr.code = "ERR_INVALID_ARG_VALUE";
			throw invalidFdRangeErr;
		}
		if (typeof host === "function") {
			callback = host;
			host = void 0;
		}
		if (opts.path) unixPath = opts.path;
		readableAll = opts.readableAll === true;
		writableAll = opts.writableAll === true;
		if (opts.signal !== void 0) {
			if (!(opts.signal instanceof AbortSignal)) {
				var sigErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received " + (typeof opts.signal === "string" ? "'" + opts.signal + "'" : typeof opts.signal));
				sigErr.code = "ERR_INVALID_ARG_TYPE";
				throw sigErr;
			}
			if (opts.signal.aborted) {
				var abortErr = /* @__PURE__ */ new Error("The operation was aborted");
				abortErr.code = "ABORT_ERR";
				var selfRef = this;
				selfRef.on("listening", function() {
					selfRef.close();
				});
				setTimeout(function() {
					if (!selfRef.listening) selfRef.emit("close");
				}, 0);
				return this;
			}
			var selfForAbort = this;
			opts.signal.addEventListener("abort", function() {
				selfForAbort.close();
			}, { once: true });
		}
		if (opts.ipv6Only !== void 0) this.ipv6Only = opts.ipv6Only === true;
		if (opts.reusePort !== void 0) this._reusePort = opts.reusePort === true;
		if (opts.handle && opts.handle._exactHandle !== void 0) directHandle = opts.handle;
		else if (opts._handle && opts._handle._exactHandle !== void 0) directHandle = opts._handle;
		else if (opts.fd !== void 0) {
			var registeredListenHandle = _getRegisteredFdHandle(opts.fd);
			if (registeredListenHandle && registeredListenHandle._exactHandle != null) directHandle = _makeServerHandle(registeredListenHandle._exactHandle, registeredListenHandle._exactKind || (opts.path ? "pipe" : "tcp"), registeredListenHandle._exactPath || opts.path || null);
			else invalidListenFd = opts.fd;
		}
		port = opts.port;
		host = opts.host || host;
		backlog = opts.backlog || backlog;
	}
	if (directHandle && directHandle._exactKind === "pipe" && !unixPath) unixPath = directHandle._exactPath || null;
	this._listeningPending = true;
	var listenToken = ++this._listenToken;
	if (invalidListenFd !== null) {
		_scheduleTimer(function() {
			if (listenToken !== self._listenToken) return;
			self._listeningPending = false;
			var fdErr = /* @__PURE__ */ new Error("listen EINVAL: invalid argument");
			fdErr.code = "EINVAL";
			fdErr.syscall = "listen";
			self.emit("error", fdErr);
		}, 0, self);
		return this;
	}
	if (port !== void 0) _normalizePort(port);
	if (!unixPath && !directHandle) port = _normalizePort(port);
	if (callback) this.once("listening", callback);
	if (directHandle && directHandle._exactHandle != null) {
		this._handle = directHandle;
		this._isUnix = directHandle._exactKind === "pipe";
		this._socketPath = this._isUnix ? directHandle._exactPath || unixPath || null : null;
		this._host = host || "0.0.0.0";
		this.host = this._host;
		if (!this._isUnix) {
			_registerTcpServer(self);
			try {
				var directInfo = __exactTcpLocalAddr(_unwrapHandle(this._handle));
				if (directInfo) {
					var directAddr = JSON.parse(directInfo);
					self._port = directAddr.port;
					self._host = directAddr.address;
					self.host = directAddr.address;
					self._requestedPort = directAddr.port;
					self._connectionKey = (directAddr.family || "IPv4").slice(-1) + ":" + directAddr.address + ":" + directAddr.port;
				}
			} catch (_directInfoErr) {}
		}
		_scheduleTimer(function() {
			if (listenToken !== self._listenToken) return;
			self._listeningPending = false;
			self.listening = true;
			self.emit("listening");
			self._startAccepting();
		}, 0, self);
		return this;
	}
	if (unixPath) {
		this._isUnix = true;
		this._socketPath = unixPath;
		this._readableAll = readableAll;
		this._writableAll = writableAll;
		if (!_hasUnix) {
			this.listening = true;
			setTimeout(function() {
				self.emit("listening");
			}, 0);
			return this;
		}
		try {
			self._handle = _makeServerHandle(__exactUnixListen(self._socketPath, backlog || 128), "pipe", self._socketPath);
			_applyUnixListenMode(self._socketPath, self._readableAll, self._writableAll);
		} catch (e) {
			_scheduleTimer(function() {
				if (listenToken !== self._listenToken) return;
				self._listeningPending = false;
				var err = _createListenError(e, null, null, self._socketPath);
				self.emit("error", err);
			}, 0, self);
			return this;
		}
		_scheduleTimer(function() {
			if (listenToken !== self._listenToken) return;
			self._listeningPending = false;
			self.listening = true;
			self.emit("listening");
			self._startAccepting();
		}, 0, self);
		return this;
	}
	this._port = port || 0;
	this._requestedPort = this._port;
	var listenHosts;
	if (host === void 0 || host === null || host === "") listenHosts = ["::", "0.0.0.0"];
	else listenHosts = [host];
	this._host = listenHosts[0];
	this.host = this._host;
	if (!_hasTcp) {
		this.listening = true;
		setTimeout(function() {
			self.emit("listening");
		}, 0);
		return this;
	}
	try {
		var listenError = null;
		for (var hostIndex = 0; hostIndex < listenHosts.length; hostIndex++) {
			var candidateHost = listenHosts[hostIndex];
			try {
				self._handle = _makeServerHandle(__exactTcpListen(candidateHost, self._port, backlog || 128, self.ipv6Only ? 1 : 0, self._reusePort ? 1 : 0));
				self._host = candidateHost;
				self.host = candidateHost;
				_registerTcpServer(self);
				try {
					var info = __exactTcpLocalAddr(_unwrapHandle(self._handle));
					if (info) {
						var addr = JSON.parse(info);
						self._port = addr.port;
						self._host = addr.address;
						self.host = addr.address;
						self._connectionKey = (addr.family || "IPv4").slice(-1) + ":" + addr.address + ":" + self._requestedPort;
					}
				} catch (e) {}
				listenError = null;
				break;
			} catch (candidateError) {
				listenError = candidateError;
				self._handle = null;
			}
		}
		if (listenError) throw listenError;
	} catch (e) {
		_scheduleTimer(function() {
			if (listenToken !== self._listenToken) return;
			self._listeningPending = false;
			var err = _createListenError(e, self._host, self._port, null);
			self.emit("error", err);
		}, 0, self);
		return this;
	}
	_scheduleTimer(function() {
		if (listenToken !== self._listenToken) return;
		self._listeningPending = false;
		self.listening = true;
		self.emit("listening");
		self._startAccepting();
	}, 0, self);
	return this;
};
Server.prototype._startAccepting = function() {
	if (this._acceptTimer != null) return;
	var self = this;
	var acceptFn = self._isUnix ? __exactUnixAccept : __exactTcpAccept;
	function handleAcceptedClient(clientHandle, acceptedInfo) {
		if (self.maxConnections === 0 || typeof self.maxConnections === "number" && self.maxConnections > 0 && self._connections >= self.maxConnections) {
			var dropInfo = acceptedInfo || _describeAcceptedSocket(clientHandle, self);
			try {
				__exactTcpClose(clientHandle);
			} catch (e) {}
			self.emit("drop", dropInfo);
			return true;
		}
		self._connections++;
		var socketOpts = {
			_handle: clientHandle,
			allowHalfOpen: self.allowHalfOpen || false
		};
		if (self._isUnix) {
			socketOpts._isUnix = true;
			socketOpts._socketPath = self._socketPath;
		}
		var socket = new Socket(socketOpts);
		socket.server = self;
		socket._server = self;
		if (self.noDelay !== void 0) socket.setNoDelay(self.noDelay);
		if (self.keepAlive !== void 0) socket.setKeepAlive(self.keepAlive, self.keepAliveInitialDelay);
		if (self.pauseOnConnect) socket.pause();
		socket.once("close", function() {
			if (socket._server !== self) return;
			self._connections--;
			if (self._connections < 0) self._connections = 0;
			if (self._closing && self._connections === 0) self.emit("close");
		});
		self.emit("connection", socket);
		return true;
	}
	function acceptLoop() {
		if (!self.listening || self._handle == null) return;
		var nativeH = _unwrapHandle(self._handle);
		if (nativeH == null) return;
		try {
			var acceptedAny = false;
			for (var acceptCount = 0; acceptCount < 64; acceptCount++) {
				var clientHandle = acceptFn(nativeH);
				if (clientHandle === -1) break;
				acceptedAny = true;
				var acceptedInfo = null;
				if (self.blockList && typeof self.blockList.check === "function") {
					acceptedInfo = _describeAcceptedSocket(clientHandle, self);
					if (acceptedInfo.remoteAddress) {
						var blockedType = isIPv6(acceptedInfo.remoteAddress) ? "ipv6" : "ipv4";
						if (self.blockList.check(acceptedInfo.remoteAddress, blockedType)) {
							try {
								__exactTcpClose(clientHandle);
							} catch (_blockCloseErr) {}
							continue;
						}
					}
				}
				handleAcceptedClient(clientHandle, acceptedInfo);
			}
		} catch (e) {
			if (self.listening) self.emit("error", e);
			return;
		}
		self._acceptTimer = _scheduleTimer(acceptLoop, acceptedAny ? 0 : 10, self);
	}
	self._acceptTimer = _scheduleTimer(acceptLoop, 0, self);
};
Server.prototype.close = function(callback) {
	if (typeof callback === "function") {
		if (!this.listening) {
			var self = this;
			setTimeout(function() {
				var err = /* @__PURE__ */ new Error("Server is not running.");
				err.code = "ERR_SERVER_NOT_RUNNING";
				callback(err);
			}, 0);
			return this;
		}
		this.once("close", callback);
	}
	this._listenToken++;
	this.listening = false;
	this._listeningPending = false;
	if (this._acceptTimer != null) {
		clearTimeout(this._acceptTimer);
		this._acceptTimer = null;
	}
	if (this._handle != null) {
		if (_hasTcp) try {
			__exactTcpClose(_unwrapHandle(this._handle));
		} catch (e) {}
		_unregisterTcpServer(this);
		this._handle = null;
	}
	if (this._isUnix && this._socketPath) {
		try {
			require("fs").unlinkSync(this._socketPath);
		} catch (e) {
			_swallowDebug("failed to unlink unix socket file", e);
		}
		this._socketPath = null;
	}
	var self = this;
	if (this._connections > 0) this._closing = true;
	else setTimeout(function() {
		self.emit("close");
	}, 0);
	return this;
};
if (typeof Symbol === "function" && Symbol.dispose) Server.prototype[Symbol.dispose] = function() {
	this.close();
};
if (typeof Symbol === "function" && Symbol.asyncDispose) Server.prototype[Symbol.asyncDispose] = function() {
	var self = this;
	return new Promise(function(resolve, reject) {
		try {
			self.close(function(err) {
				if (err) {
					reject(err);
					return;
				}
				resolve();
			});
		} catch (err) {
			reject(err);
		}
	});
};
Server.prototype.address = function() {
	if (this._isUnix) return this._socketPath;
	if (this._handle != null && _hasTcp) try {
		var info = __exactTcpLocalAddr(_unwrapHandle(this._handle));
		if (info) return JSON.parse(info);
	} catch (e) {}
	return {
		address: this._host || "0.0.0.0",
		port: this._port || 0,
		family: "IPv4"
	};
};
Server.prototype.ref = function() {
	this._unrefed = false;
	this._unref = false;
	_setHandleRefState(this._handle, true);
	_setTimerRefState(this._acceptTimer, true);
	if (this.listening && this._handle != null && this._acceptTimer == null) this._startAccepting();
	return this;
};
Server.prototype.unref = function() {
	this._unrefed = true;
	this._unref = true;
	_setHandleRefState(this._handle, false);
	_setTimerRefState(this._acceptTimer, false);
	return this;
};
Server.prototype.getConnections = function(cb) {
	var self = this;
	if (cb) setTimeout(function() {
		cb(null, self._connections || 0);
	}, 0);
	return this;
};
if (_rejectionSymbol) Server.prototype[_rejectionSymbol] = function(err, eventName, socket) {
	if (eventName === "connection" && socket && typeof socket.destroy === "function") {
		socket.destroy(err);
		return;
	}
	this.emit("error", err);
};
function _normalizeArgs(args) {
	if (Array.isArray(args) && args[_normalizedArgsSymbol] === true) return args;
	var options = {};
	var callback = null;
	var list = Array.isArray(args) ? args.slice() : Array.prototype.slice.call(arguments);
	if (list.length === 1 && typeof list[0] === "function") callback = list[0];
	else if (list.length > 0) {
		var first = list[0];
		if (typeof first === "object" && first !== null && !Array.isArray(first)) {
			options = first;
			if (typeof list[1] === "function") callback = list[1];
		} else if (typeof first === "string" && !isFinite(Number(first))) {
			options.path = first;
			if (typeof list[1] === "function") callback = list[1];
		} else if (typeof first !== "undefined") {
			options.port = first;
			if (typeof list[1] === "string") {
				options.host = list[1];
				if (typeof list[2] === "function") callback = list[2];
			} else if (typeof list[1] === "function") callback = list[1];
		}
	}
	var normalized = [options, callback];
	normalized[_normalizedArgsSymbol] = true;
	return normalized;
}
function createConnection(options, connectListener) {
	var normalized = _normalizeArgs(Array.prototype.slice.call(arguments));
	options = normalized[0] || {};
	connectListener = normalized[1];
	if (!options || typeof options === "object" && !options.path && options.port === void 0) {
		var missingErr = /* @__PURE__ */ new TypeError("The \"options\" or \"port\" or \"path\" argument must be specified");
		missingErr.code = "ERR_MISSING_ARGS";
		throw missingErr;
	}
	return new Socket(options).connect(normalized);
}
function createServer(options, connectionListener) {
	return new Server(options, connectionListener);
}
function connect() {
	return createConnection.apply(null, arguments);
}
Socket.prototype[_kReinitializeHandle] = function() {
	return this;
};
function isIP(input) {
	if (typeof input !== "string") try {
		input = String(input);
	} catch (e) {
		return 0;
	}
	if (isIPv4(input)) return 4;
	if (isIPv6(input)) return 6;
	return 0;
}
function isIPv4(input) {
	if (typeof input !== "string") {
		try {
			input = String(input);
		} catch (e) {
			return false;
		}
		if (typeof input !== "string") return false;
	}
	var parts = input.split(".");
	if (parts.length !== 4) return false;
	for (var i = 0; i < 4; i++) {
		if (!/^\d{1,3}$/.test(parts[i])) return false;
		var num = parseInt(parts[i], 10);
		if (num < 0 || num > 255) return false;
		if (parts[i].length > 1 && parts[i][0] === "0") return false;
	}
	return true;
}
function isIPv6(input) {
	if (typeof input !== "string") {
		try {
			input = String(input);
		} catch (e) {
			return false;
		}
		if (typeof input !== "string") return false;
	}
	var zoneIdx = input.indexOf("%");
	if (zoneIdx !== -1) {
		var zone = input.substring(zoneIdx + 1);
		if (zone.length === 0 || !/^[a-zA-Z0-9._~\-]+$/.test(zone)) return false;
		input = input.substring(0, zoneIdx);
	}
	var lastColon = input.lastIndexOf(":");
	if (lastColon !== -1) {
		var tail = input.substring(lastColon + 1);
		if (tail.indexOf(".") !== -1) {
			if (!isIPv4(tail)) return false;
			input = input.substring(0, lastColon) + ":0:0";
		}
	}
	if (input.indexOf(":::") !== -1) return false;
	if (input.charAt(0) === ":" && input.charAt(1) !== ":") return false;
	if (input.charAt(input.length - 1) === ":" && input.charAt(input.length - 2) !== ":") return false;
	var hasDoubleColon = input.indexOf("::") !== -1;
	if (hasDoubleColon) {
		if (input.indexOf("::") !== input.lastIndexOf("::")) return false;
	}
	var parts = input.split(":");
	for (var j = 0; j < parts.length; j++) {
		if (parts[j] === "") continue;
		if (!/^[0-9a-fA-F]{1,4}$/.test(parts[j])) return false;
	}
	if (hasDoubleColon) {
		var nonEmpty = 0;
		for (var k = 0; k < parts.length; k++) if (parts[k] !== "") nonEmpty++;
		return nonEmpty <= 7;
	} else return parts.length === 8;
}
function SocketAddress(options) {
	if (!(this instanceof SocketAddress)) return new SocketAddress(options);
	options = options || {};
	this.address = options.address || "127.0.0.1";
	this.port = options.port || 0;
	this.family = options.family || (isIPv6(this.address) ? "ipv6" : "ipv4");
	this.flowlabel = options.flowlabel || 0;
}
function getDefaultAutoSelectFamilyAttemptTimeout() {
	return _defaultAutoSelectFamilyAttemptTimeout;
}
function setDefaultAutoSelectFamilyAttemptTimeout(milliseconds) {
	if (typeof milliseconds === "number" && isFinite(milliseconds)) {
		if (milliseconds <= 0) {
			var rangeErr = /* @__PURE__ */ new RangeError("The value of \"autoSelectFamilyAttemptTimeout\" is out of range. It must be > 0. Received " + milliseconds);
			rangeErr.code = "ERR_OUT_OF_RANGE";
			throw rangeErr;
		}
		_defaultAutoSelectFamilyAttemptTimeout = milliseconds < 10 ? 10 : milliseconds;
	} else if (arguments.length === 0) _defaultAutoSelectFamilyAttemptTimeout = 2500;
	return _defaultAutoSelectFamilyAttemptTimeout;
}
function BlockList() {
	if (!(this instanceof BlockList)) return new BlockList();
	this._rules = [];
	this.rules = [];
}
BlockList.prototype.addAddress = function(address, type) {
	type = type || (isIPv6(address) ? "ipv6" : "ipv4");
	this._rules.push({
		type: "address",
		address,
		family: type
	});
};
BlockList.prototype.addRange = function(start, end, type) {
	type = type || (isIPv6(start) ? "ipv6" : "ipv4");
	this._rules.push({
		type: "range",
		start,
		end,
		family: type
	});
};
BlockList.prototype.addSubnet = function(address, prefix, type) {
	type = type || (isIPv6(address) ? "ipv6" : "ipv4");
	this._rules.push({
		type: "subnet",
		address,
		prefix,
		family: type
	});
};
BlockList.prototype.check = function(address, type) {
	type = type || (isIPv6(address) ? "ipv6" : "ipv4");
	for (var i = 0; i < this._rules.length; i++) {
		var rule = this._rules[i];
		if (rule.family !== type) continue;
		if (rule.type === "address" && rule.address === address) return true;
		if (rule.type === "range" && address >= rule.start && address <= rule.end) return true;
		if (rule.type === "subnet" && address === rule.address) return true;
	}
	return false;
};
module.exports = {
	Socket,
	Stream: Socket,
	Server,
	createConnection,
	createServer,
	connect,
	_normalizeArgs,
	isIP,
	isIPv4,
	isIPv6,
	BlockList,
	SocketAddress,
	setDefaultAutoSelectFamily,
	getDefaultAutoSelectFamily,
	getDefaultAutoSelectFamilyAttemptTimeout,
	setDefaultAutoSelectFamilyAttemptTimeout
};
module.exports.default = module.exports;
//#endregion
