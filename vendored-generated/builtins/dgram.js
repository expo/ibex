"use strict";
//#region src/builtins/dgram.js
var EventEmitter = require("events");
function _invalidArgTypeHelper(input) {
	if (input == null) return " Received " + input;
	if (typeof input === "function") return " Received function " + (input.name || "anonymous");
	if (typeof input === "object") {
		if (input.constructor && input.constructor.name) return " Received an instance of " + input.constructor.name;
		return " Received " + String(input);
	}
	return " Received type " + typeof input + " (" + JSON.stringify(input) + ")";
}
function _validateBuffer(buffer, name) {
	if (typeof buffer === "string") return;
	if (Buffer.isBuffer(buffer)) return;
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(buffer)) return;
	var err = /* @__PURE__ */ new TypeError("The \"" + (name || "buffer") + "\" argument must be of type string or an instance of Buffer, TypedArray, or DataView." + _invalidArgTypeHelper(buffer));
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function _validateBufferList(list) {
	for (var i = 0; i < list.length; i++) {
		var item = list[i];
		if (typeof item !== "string" && !Buffer.isBuffer(item) && !(typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(item))) {
			var err = /* @__PURE__ */ new TypeError("The \"buffer list arguments\" argument must be of type string or an instance of Buffer, TypedArray, or DataView. Received an instance of Array");
			err.code = "ERR_INVALID_ARG_TYPE";
			throw err;
		}
	}
}
function _validateSendOffsetLength(buffer, offset, length) {
	var bufLen;
	if (typeof buffer === "string") bufLen = Buffer.byteLength(buffer);
	else if (Buffer.isBuffer(buffer)) bufLen = buffer.length;
	else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(buffer)) bufLen = buffer.byteLength;
	else bufLen = buffer.length || 0;
	if (offset < 0 || offset >= bufLen) {
		if (bufLen > 0 || offset > 0) {
			var errOff = /* @__PURE__ */ new RangeError("\"offset\" is outside of buffer bounds");
			errOff.code = "ERR_BUFFER_OUT_OF_BOUNDS";
			throw errOff;
		}
	}
	if (length < 0 || offset + length > bufLen) {
		var errLen = /* @__PURE__ */ new RangeError("\"length\" is outside of buffer bounds");
		errLen.code = "ERR_BUFFER_OUT_OF_BOUNDS";
		throw errLen;
	}
}
function Socket(type, listener) {
	if (!(this instanceof Socket)) return new Socket(type, listener);
	EventEmitter.call(this);
	var opts = {};
	if (typeof type === "string") {} else if (typeof type === "object" && type !== null && !Array.isArray(type) && !(type instanceof String)) {
		opts = type;
		type = opts.type;
	} else {
		var typeErr = /* @__PURE__ */ new TypeError("Bad socket type specified. Valid types are: udp4, udp6");
		typeErr.code = "ERR_SOCKET_BAD_TYPE";
		throw typeErr;
	}
	if (type !== "udp4" && type !== "udp6") {
		var typeErr2 = /* @__PURE__ */ new TypeError("Bad socket type specified. Valid types are: udp4, udp6");
		typeErr2.code = "ERR_SOCKET_BAD_TYPE";
		throw typeErr2;
	}
	if (opts.recvBufferSize !== void 0 && typeof opts.recvBufferSize !== "number") {
		var rbsErr = /* @__PURE__ */ new TypeError("The \"options.recvBufferSize\" property must be of type number." + _invalidArgTypeHelper(opts.recvBufferSize));
		rbsErr.code = "ERR_INVALID_ARG_TYPE";
		throw rbsErr;
	}
	if (opts.sendBufferSize !== void 0 && typeof opts.sendBufferSize !== "number") {
		var sbsErr = /* @__PURE__ */ new TypeError("The \"options.sendBufferSize\" property must be of type number." + _invalidArgTypeHelper(opts.sendBufferSize));
		sbsErr.code = "ERR_INVALID_ARG_TYPE";
		throw sbsErr;
	}
	this.type = type;
	this._handle = -1;
	this._bound = false;
	this._closed = false;
	this._pollTimer = null;
	this._receiving = false;
	this._bindState = 0;
	this._fd = -1;
	this._connected = false;
	this._connectPort = null;
	this._connectAddress = null;
	this._reuseAddr = opts.reuseAddr || false;
	this._recvBufferSize = opts.recvBufferSize || 0;
	this._sendBufferSize = opts.sendBufferSize || 0;
	if (typeof opts.lookup === "function") this.lookup = opts.lookup;
	if (typeof listener === "function") this.on("message", listener);
	if (opts.signal !== void 0) {
		if (!(opts.signal instanceof AbortSignal)) {
			var sigErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received type " + typeof opts.signal);
			sigErr.code = "ERR_INVALID_ARG_TYPE";
			throw sigErr;
		}
		var self = this;
		if (opts.signal.aborted) setTimeout(function() {
			self.close();
		}, 0);
		else opts.signal.addEventListener("abort", function() {
			self.close();
		}, { once: true });
	}
}
Socket.prototype = Object.create(EventEmitter.prototype);
Socket.prototype.constructor = Socket;
Socket.prototype.bind = function(port, address, callback) {
	if (this._closed) throw new Error("Socket is closed");
	if (this._bindState === 2) {
		var boundErr = /* @__PURE__ */ new Error("Socket is already bound");
		boundErr.code = "ERR_SOCKET_ALREADY_BOUND";
		throw boundErr;
	}
	if (typeof port === "function") {
		callback = port;
		port = 0;
		address = void 0;
	}
	if (typeof port === "object" && port !== null) {
		var opts = port;
		callback = address;
		port = opts.port || 0;
		address = opts.address;
	}
	if (typeof address === "function") {
		callback = address;
		address = void 0;
	}
	port = port || 0;
	address = address || (this.type === "udp6" ? "::" : "0.0.0.0");
	if (typeof callback === "function") this.once("listening", callback);
	this._bindState = 1;
	var self = this;
	if (this._handle < 0) try {
		this._handle = globalThis.__exactUdpSocket(this.type);
	} catch (e) {
		this._handle = -1;
	}
	if (this._handle < 0) {
		this._bound = true;
		this._bindState = 2;
		this._address = {
			address,
			port: port || 0,
			family: this.type === "udp6" ? "IPv6" : "IPv4"
		};
		setTimeout(function() {
			self.emit("listening");
		}, 0);
		return this;
	}
	try {
		var result = globalThis.__exactUdpBind(this._handle, address, port);
		var addrInfo = typeof result === "string" ? JSON.parse(result) : result;
		this._bound = true;
		this._bindState = 2;
		this._address = addrInfo;
	} catch (e) {
		this._bindState = 0;
		var bindErr = new Error(e.message || String(e));
		bindErr.code = "EADDRINUSE";
		setTimeout(function() {
			self.emit("error", bindErr);
		}, 0);
		return this;
	}
	this._startRecv();
	setTimeout(function() {
		self.emit("listening");
	}, 0);
	return this;
};
Socket.prototype._startRecv = function() {
	if (this._receiving || this._closed) return;
	this._receiving = true;
	var self = this;
	var pollInterval = 5;
	function poll() {
		if (self._closed) return;
		if (self._handle < 0) return;
		try {
			var result = globalThis.__exactUdpRecv(self._handle);
			if (result) {
				var data = result.data;
				if (typeof Buffer !== "undefined" && data instanceof Uint8Array && !(data instanceof Buffer)) data = Buffer.from(data);
				var rinfo = {
					address: result.address,
					family: result.family,
					port: result.port,
					size: result.size || data.length
				};
				self.emit("message", data, rinfo);
			}
		} catch (e) {
			if (!self._closed) self.emit("error", e);
		}
		if (!self._closed) self._pollTimer = setTimeout(poll, pollInterval);
	}
	this._pollTimer = setTimeout(poll, 0);
};
Socket.prototype.connect = function(port, address, callback) {
	if (this._closed) throw new Error("Socket is closed");
	if (this._connected || this._connectPort !== null) {
		var connErr = /* @__PURE__ */ new Error("Already connected");
		connErr.code = "ERR_SOCKET_DGRAM_IS_CONNECTED";
		throw connErr;
	}
	if (port === void 0 || port === null || port === 0 || typeof port === "number" && (port < 1 || port > 65535 || port !== port >>> 0)) {
		var portErr = /* @__PURE__ */ new RangeError("Port should be > 0 and < 65536. Received " + port + ".");
		portErr.code = "ERR_SOCKET_BAD_PORT";
		throw portErr;
	}
	if (typeof address === "function") {
		callback = address;
		address = void 0;
	}
	address = address || (this.type === "udp6" ? "::1" : "127.0.0.1");
	if (typeof callback === "function") this.once("connect", callback);
	if (!this._bound) {
		this._bindState = 1;
		if (this._handle < 0) try {
			this._handle = globalThis.__exactUdpSocket(this.type);
		} catch (e) {
			this._handle = -1;
		}
		if (this._handle >= 0) try {
			var bindResult = globalThis.__exactUdpBind(this._handle, this.type === "udp6" ? "::" : "0.0.0.0", 0);
			var bindInfo = typeof bindResult === "string" ? JSON.parse(bindResult) : bindResult;
			this._bound = true;
			this._bindState = 2;
			this._address = bindInfo;
			this._startRecv();
		} catch (e) {
			this._bindState = 0;
		}
	}
	this._connected = true;
	this._connectPort = port;
	this._connectAddress = address;
	var self = this;
	setTimeout(function() {
		self.emit("connect");
	}, 0);
};
Socket.prototype.disconnect = function() {
	if (!this._connected) {
		var err = /* @__PURE__ */ new Error("Not connected");
		err.code = "ERR_SOCKET_DGRAM_NOT_CONNECTED";
		throw err;
	}
	this._connected = false;
	this._connectPort = null;
	this._connectAddress = null;
};
Socket.prototype.remoteAddress = function() {
	if (!this._connected) {
		var err = /* @__PURE__ */ new Error("Not connected");
		err.code = "ERR_SOCKET_DGRAM_NOT_CONNECTED";
		throw err;
	}
	return {
		address: this._connectAddress,
		family: this.type === "udp6" ? "IPv6" : "IPv4",
		port: this._connectPort
	};
};
Socket.prototype.send = function(msg, offset, length, port, address, callback) {
	if (this._closed) {
		var err = /* @__PURE__ */ new Error("Not running");
		err.code = "ERR_SOCKET_DGRAM_NOT_RUNNING";
		if (typeof callback === "function") {
			callback(err);
			return;
		}
		throw err;
	}
	if (msg === void 0) _validateBuffer(msg, "buffer");
	if (Array.isArray(msg)) _validateBufferList(msg);
	else if (typeof msg !== "string" && !Buffer.isBuffer(msg) && !(typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(msg))) _validateBuffer(msg, "buffer");
	if (typeof length === "string" || typeof length === "undefined" || typeof length === "function") {
		callback = port;
		address = length;
		port = offset;
		offset = 0;
		if (typeof msg === "string") length = Buffer.byteLength(msg);
		else if (Array.isArray(msg)) {
			length = 0;
			for (var ai = 0; ai < msg.length; ai++) if (typeof msg[ai] === "string") length += Buffer.byteLength(msg[ai]);
			else if (msg[ai]) length += msg[ai].length || msg[ai].byteLength || 0;
		} else if (msg) length = msg.length || msg.byteLength || 0;
		else length = 0;
	} else if (typeof offset === "number" && typeof length === "number") {
		if (this._connected && (typeof port === "number" || typeof address === "string")) {
			var connErr = /* @__PURE__ */ new Error("Already connected");
			connErr.code = "ERR_SOCKET_DGRAM_IS_CONNECTED";
			throw connErr;
		}
		if (!Array.isArray(msg)) _validateSendOffsetLength(msg, offset, length);
		if (Buffer.isBuffer(msg)) msg = msg.slice(offset, offset + length);
		else if (typeof msg === "string") msg = msg.substring(offset, offset + length);
		else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(msg)) {
			var _copy = Buffer.alloc(length);
			_copy.set(new Uint8Array(msg.buffer, msg.byteOffset + offset, length));
			msg = _copy;
		}
		offset = 0;
	}
	if (this._connected && (typeof port === "number" || typeof address === "string")) {
		var connErr2 = /* @__PURE__ */ new Error("Already connected");
		connErr2.code = "ERR_SOCKET_DGRAM_IS_CONNECTED";
		throw connErr2;
	}
	if (this._connected) {
		if (typeof address === "function") {
			callback = address;
			address = void 0;
		}
		if (typeof port === "function") {
			callback = port;
			port = void 0;
		}
		port = port || this._connectPort;
		address = address || this._connectAddress;
	}
	if (!this._connected) {
		if (typeof port !== "number" || port < 0 || port > 65535) {
			if (typeof port === "number" && (port < 0 || port > 65535 || port === 0)) {
				var portErr = /* @__PURE__ */ new RangeError("\"port\" argument should be >= 0 and < 65536. Received " + port);
				portErr.code = "ERR_SOCKET_BAD_PORT";
				throw portErr;
			}
		}
	}
	if (!this._bound && this._handle < 0) try {
		this._handle = globalThis.__exactUdpSocket(this.type);
		var bindResult = globalThis.__exactUdpBind(this._handle, this.type === "udp6" ? "::" : "0.0.0.0", 0);
		var bindInfo = typeof bindResult === "string" ? JSON.parse(bindResult) : bindResult;
		this._bound = true;
		this._bindState = 2;
		this._address = bindInfo;
		this._startRecv();
	} catch (e) {}
	if (this._handle < 0) try {
		this._handle = globalThis.__exactUdpSocket(this.type);
	} catch (e) {}
	var sendData = msg;
	if (typeof msg === "string") sendData = typeof Buffer !== "undefined" ? Buffer.from(msg) : msg;
	else if (Array.isArray(msg)) {
		var parts = [];
		for (var pi = 0; pi < msg.length; pi++) if (typeof msg[pi] === "string") parts.push(Buffer.from(msg[pi]));
		else if (Buffer.isBuffer(msg[pi])) parts.push(msg[pi]);
		else if (msg[pi] && typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(msg[pi])) {
			var _partCopy = Buffer.alloc(msg[pi].byteLength);
			_partCopy.set(new Uint8Array(msg[pi].buffer, msg[pi].byteOffset, msg[pi].byteLength));
			parts.push(_partCopy);
		}
		sendData = parts.length > 0 ? Buffer.concat(parts) : Buffer.alloc(0);
	}
	var self = this;
	try {
		if (this._handle >= 0 && typeof globalThis.__exactUdpSend === "function") globalThis.__exactUdpSend(this._handle, sendData, port, address || "127.0.0.1");
		var bytesSent = sendData ? sendData.length || sendData.byteLength || 0 : 0;
		if (typeof callback === "function") setTimeout(function() {
			callback(null, bytesSent);
		}, 0);
	} catch (e) {
		if (typeof callback === "function") setTimeout(function() {
			callback(e);
		}, 0);
		else self.emit("error", e);
	}
};
Socket.prototype.sendto = function(msg, offset, length, port, address, callback) {
	if (typeof offset !== "number") {
		var offErr = /* @__PURE__ */ new TypeError("The \"offset\" argument must be of type number." + _invalidArgTypeHelper(offset));
		offErr.code = "ERR_INVALID_ARG_TYPE";
		throw offErr;
	}
	if (typeof length !== "number") {
		var lenErr = /* @__PURE__ */ new TypeError("The \"length\" argument must be of type number." + _invalidArgTypeHelper(length));
		lenErr.code = "ERR_INVALID_ARG_TYPE";
		throw lenErr;
	}
	if (typeof port !== "number") {
		var portErr = /* @__PURE__ */ new TypeError("The \"port\" argument must be of type number." + _invalidArgTypeHelper(port));
		portErr.code = "ERR_INVALID_ARG_TYPE";
		throw portErr;
	}
	if (typeof address !== "string") {
		var addrErr = /* @__PURE__ */ new TypeError("The \"address\" argument must be of type string." + _invalidArgTypeHelper(address));
		addrErr.code = "ERR_INVALID_ARG_TYPE";
		throw addrErr;
	}
	_validateBuffer(msg, "buffer");
	this.send(msg, offset, length, port, address, callback);
};
Socket.prototype.close = function(callback) {
	if (this._closed) return this;
	this._closed = true;
	if (this._pollTimer) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	if (this._handle >= 0) {
		try {
			if (typeof globalThis.__exactUdpClose === "function") globalThis.__exactUdpClose(this._handle);
		} catch (e) {}
		this._handle = -1;
	}
	var self = this;
	if (typeof callback === "function") this.once("close", callback);
	setTimeout(function() {
		self.emit("close");
	}, 0);
	return this;
};
Socket.prototype.address = function() {
	if (!this._bound || this._closed) throw new Error("getsockname EBADF");
	if (this._address) return this._address;
	if (this._handle >= 0 && typeof globalThis.__exactUdpAddress === "function") {
		var result = globalThis.__exactUdpAddress(this._handle);
		if (typeof result === "string") result = JSON.parse(result);
		return result;
	}
	return this._address || {
		address: "0.0.0.0",
		port: 0,
		family: "IPv4"
	};
};
Socket.prototype.setRecvBufferSize = function(size) {
	if (!this._bound) throw new Error("setRecvBufferSize EBADF");
	return this;
};
Socket.prototype.setSendBufferSize = function(size) {
	if (!this._bound) throw new Error("setSendBufferSize EBADF");
	return this;
};
Socket.prototype.getRecvBufferSize = function() {
	if (!this._bound) throw new Error("getRecvBufferSize EBADF");
	return this._recvBufferSize || 65536;
};
Socket.prototype.getSendBufferSize = function() {
	if (!this._bound) throw new Error("getSendBufferSize EBADF");
	return this._sendBufferSize || 65536;
};
Socket.prototype.setTTL = function(ttl) {
	if (typeof ttl !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"ttl\" argument must be of type number." + _invalidArgTypeHelper(ttl));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (!this._bound) throw new Error("setTTL EBADF");
	if (ttl < 1 || ttl > 255) throw new Error("setTTL EINVAL");
	if (this._handle >= 0 && typeof globalThis.__exactUdpSetTTL === "function") try {
		globalThis.__exactUdpSetTTL(this._handle, ttl);
	} catch (e) {}
	return ttl;
};
Socket.prototype.setMulticastTTL = function(ttl) {
	if (typeof ttl !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"ttl\" argument must be of type number." + _invalidArgTypeHelper(ttl));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (!this._bound) throw new Error("setMulticastTTL EBADF");
	if (ttl < 0 || ttl > 255) throw new Error("setMulticastTTL EINVAL");
	if (this._handle >= 0 && typeof globalThis.__exactUdpSetMulticastTTL === "function") try {
		globalThis.__exactUdpSetMulticastTTL(this._handle, ttl);
	} catch (e) {}
	return ttl;
};
Socket.prototype.setMulticastLoopback = function(flag) {
	if (!this._bound) throw new Error("setMulticastLoopback EBADF");
	return flag;
};
Socket.prototype.setMulticastInterface = function(multicastInterface) {
	if (!this._bound) throw new Error("setMulticastInterface EBADF");
	if (typeof multicastInterface !== "string") {
		var err = /* @__PURE__ */ new TypeError("The \"multicastInterface\" argument must be of type string");
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
};
Socket.prototype.addMembership = function(multicastAddress, multicastInterface) {
	if (!this._bound) this.bind(0);
	if (this._handle >= 0 && typeof globalThis.__exactUdpAddMembership === "function") try {
		globalThis.__exactUdpAddMembership(this._handle, multicastAddress, multicastInterface || "");
	} catch (e) {}
};
Socket.prototype.dropMembership = function(multicastAddress, multicastInterface) {
	if (this._handle >= 0 && typeof globalThis.__exactUdpDropMembership === "function") try {
		globalThis.__exactUdpDropMembership(this._handle, multicastAddress, multicastInterface || "");
	} catch (e) {}
};
Socket.prototype.addSourceSpecificMembership = function(sourceAddress, groupAddress, multicastInterface) {
	if (!this._bound) throw new Error("addSourceSpecificMembership EBADF");
};
Socket.prototype.dropSourceSpecificMembership = function(sourceAddress, groupAddress, multicastInterface) {
	if (!this._bound) throw new Error("dropSourceSpecificMembership EBADF");
};
Socket.prototype.setBroadcast = function(flag) {
	if (!this._bound) throw new Error("setBroadcast EBADF");
	if (this._handle >= 0 && typeof globalThis.__exactUdpSetBroadcast === "function") try {
		globalThis.__exactUdpSetBroadcast(this._handle, flag ? 1 : 0);
	} catch (e) {}
};
Socket.prototype.ref = function() {
	this._unrefed = false;
	return this;
};
Socket.prototype.unref = function() {
	this._unrefed = true;
	if (this._pollTimer) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	return this;
};
Socket.prototype._fromFd = function(fd) {
	this._fd = fd;
	if (typeof globalThis.__exactUdpFromFd === "function") this._handle = globalThis.__exactUdpFromFd(fd);
	this._bound = true;
	this._bindState = 2;
	if (this._handle >= 0 && typeof globalThis.__exactUdpAddress === "function") {
		var addrJson = globalThis.__exactUdpAddress(this._handle);
		if (addrJson) this._address = typeof addrJson === "string" ? JSON.parse(addrJson) : addrJson;
	}
	this._startRecv();
	return this;
};
Socket.prototype._getFd = function() {
	if (this._handle >= 0 && typeof globalThis.__exactUdpGetFd === "function") return globalThis.__exactUdpGetFd(this._handle);
	return this._fd;
};
function createSocket(type, callback) {
	return new Socket(type, callback);
}
module.exports = {
	createSocket,
	Socket
};
module.exports.default = module.exports;
//#endregion
