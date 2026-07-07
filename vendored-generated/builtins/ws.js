//#region src/builtins/ws.js
var _swallowDebugLog = null;
function _swallowDebug(msg, err) {
	if (_swallowDebugLog === null) try {
		_swallowDebugLog = require("util").debuglog("ws");
	} catch (_swallowInitErr) {
		_swallowDebugLog = function() {};
	}
	_swallowDebugLog(msg, err);
}
var g = globalThis;
var _exactNetInitialized = false;
function ensureExactNet() {
	if (_exactNetInitialized) return;
	if (typeof g.__exactEnsureNet === "function") try {
		g.__exactEnsureNet();
	} catch (e) {}
	_exactNetInitialized = true;
}
ensureExactNet();
var EventEmitter = require("events");
function _hasTcpSupport() {
	return typeof __exactTcpListen === "function" && typeof __exactTcpAccept === "function" && typeof __exactTcpRead === "function" && typeof __exactTcpWrite === "function" && typeof __exactTcpClose === "function";
}
function _unwrapTcpHandle(handle) {
	if (typeof handle === "number") return handle;
	if (handle && typeof handle._exactHandle === "number") return handle._exactHandle;
	return null;
}
function _releaseServerSocket(socket) {
	if (!socket || typeof socket !== "object") return;
	if (socket._headersTimeoutId != null) {
		clearTimeout(socket._headersTimeoutId);
		socket._headersTimeoutId = null;
	}
	if (socket._requestTimeoutId != null) {
		clearTimeout(socket._requestTimeoutId);
		socket._requestTimeoutId = null;
	}
	socket._headersTimeoutAt = null;
	socket._requestTimeoutAt = null;
	socket._requestTimeoutArmed = false;
	socket.parser = null;
	socket._httpMessage = null;
	var netServer = socket._server;
	if (netServer && typeof netServer._connections === "number") {
		netServer._connections--;
		if (netServer._connections < 0) netServer._connections = 0;
		if (netServer._closing && netServer._connections === 0) setTimeout(function() {
			netServer.emit("close");
		}, 0);
	}
	var httpServer = socket._httpServer;
	if (httpServer && httpServer._sockets && typeof httpServer._sockets.delete === "function") httpServer._sockets.delete(socket);
	socket.server = null;
	socket._server = null;
	socket._httpServer = null;
}
function _detachSocketTcpHandle(socket) {
	if (typeof socket === "number") return socket;
	if (!socket) return null;
	var tcpHandle = _unwrapTcpHandle(socket._handle);
	if (tcpHandle == null) return null;
	if (socket._pollTimer != null) {
		clearTimeout(socket._pollTimer);
		socket._pollTimer = null;
	}
	_releaseServerSocket(socket);
	if (socket._handle && typeof socket._handle === "object" && socket._handle._exactHandle !== void 0) socket._handle._exactHandle = null;
	else socket._handle = null;
	socket.destroyed = true;
	return tcpHandle;
}
function _requestMatchesServerPath(server, req) {
	if (!server || !server._path) return true;
	if (!req || typeof req.url !== "string") return false;
	return req.url.split("?")[0] === String(server._path).split("?")[0];
}
function _rejectUpgrade(tcpHandle) {
	if (tcpHandle == null) return;
	try {
		__exactTcpWrite(tcpHandle, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
	} catch (_writeRejectErr) {}
	try {
		__exactTcpClose(tcpHandle);
	} catch (_closeRejectErr) {}
}
var OPCODE_CONTINUATION = 0;
var OPCODE_TEXT = 1;
var OPCODE_BINARY = 2;
var OPCODE_CLOSE = 8;
var OPCODE_PING = 9;
var OPCODE_PONG = 10;
var WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var READY_CONNECTING = 0;
var READY_OPEN = 1;
var READY_CLOSING = 2;
var READY_CLOSED = 3;
var DEFAULT_MAX_PAYLOAD = 100 * 1024 * 1024;
var CLOSE_CODE_MESSAGE_TOO_BIG = 1009;
function hexToRaw(hex) {
	var raw = "";
	for (var i = 0; i < hex.length; i += 2) raw += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
	return raw;
}
function _toBinaryString(data) {
	if (typeof data === "string") return data;
	if (!data || typeof data.length !== "number") return "";
	if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(data)) return data.toString("binary");
	var out = "";
	for (var i = 0; i < data.length; i++) out += String.fromCharCode(data[i] & 255);
	return out;
}
function computeAcceptKey(key) {
	var input = key + WS_GUID;
	if (typeof __exactHashSync === "function") {
		var raw = hexToRaw(__exactHashSync("sha1", input));
		if (typeof btoa === "function") return btoa(raw);
	}
	try {
		return require("crypto").createHash("sha1").update(input).digest("base64");
	} catch (e) {
		_swallowDebug("sha1 fallback failed; returning empty accept key", e);
	}
	return "";
}
function encodeFrame(opcode, payload, fin) {
	if (fin === void 0) fin = true;
	var payloadU8;
	if (typeof payload === "string") if (typeof TextEncoder !== "undefined") payloadU8 = new TextEncoder().encode(payload);
	else {
		var tmp = [];
		for (var si = 0; si < payload.length; si++) {
			var c = payload.charCodeAt(si);
			if (c < 128) tmp.push(c);
			else if (c < 2048) tmp.push(192 | c >> 6, 128 | c & 63);
			else tmp.push(224 | c >> 12, 128 | c >> 6 & 63, 128 | c & 63);
		}
		payloadU8 = Uint8Array.from(tmp);
	}
	else if (payload instanceof Uint8Array) payloadU8 = payload;
	else if (Array.isArray(payload)) payloadU8 = Uint8Array.from(payload);
	else payloadU8 = /* @__PURE__ */ new Uint8Array(0);
	var len = payloadU8.length;
	var header = [];
	header.push((fin ? 128 : 0) | opcode & 15);
	if (len < 126) header.push(len);
	else if (len < 65536) {
		header.push(126);
		header.push(len >>> 8 & 255);
		header.push(len & 255);
	} else {
		header.push(127);
		header.push(0);
		header.push(0);
		header.push(0);
		header.push(0);
		header.push(len >>> 24 & 255);
		header.push(len >>> 16 & 255);
		header.push(len >>> 8 & 255);
		header.push(len & 255);
	}
	var frame = new Uint8Array(header.length + len);
	for (var hi = 0; hi < header.length; hi++) frame[hi] = header[hi];
	if (len > 0) frame.set(payloadU8, header.length);
	return frame;
}
function _parseFrame(bytes, start, end) {
	var avail = end - start;
	if (avail < 2) return null;
	var b0 = bytes[start];
	var b1 = bytes[start + 1];
	var fin = (b0 & 128) !== 0;
	var opcode = b0 & 15;
	var masked = (b1 & 128) !== 0;
	var payloadLen = b1 & 127;
	var headerLen = 2;
	if (payloadLen === 126) {
		if (avail < 4) return null;
		payloadLen = bytes[start + 2] << 8 | bytes[start + 3];
		headerLen = 4;
	} else if (payloadLen === 127) {
		if (avail < 10) return null;
		payloadLen = bytes[start + 6] * 16777216 + bytes[start + 7] * 65536 + bytes[start + 8] * 256 + bytes[start + 9];
		headerLen = 10;
	}
	var maskLen = masked ? 4 : 0;
	var totalLen = headerLen + maskLen + payloadLen;
	if (avail < totalLen) return null;
	var payloadStart = start + headerLen + maskLen;
	var payload = new Uint8Array(payloadLen);
	if (masked) {
		var maskStart = start + headerLen;
		var mask = [
			bytes[maskStart],
			bytes[maskStart + 1],
			bytes[maskStart + 2],
			bytes[maskStart + 3]
		];
		for (var i = 0; i < payloadLen; i++) payload[i] = bytes[payloadStart + i] ^ mask[i & 3];
	} else if (payloadLen > 0) payload.set(bytes.subarray(payloadStart, payloadStart + payloadLen));
	return {
		frame: {
			fin,
			opcode,
			masked,
			payload
		},
		next: start + totalLen
	};
}
function _peekFramePayloadLength(bytes, start, end) {
	var avail = end - start;
	if (avail < 2) return null;
	var payloadLen = bytes[start + 1] & 127;
	if (payloadLen === 126) {
		if (avail < 4) return null;
		return bytes[start + 2] << 8 | bytes[start + 3];
	}
	if (payloadLen === 127) {
		if (avail < 10) return null;
		if (bytes[start + 2] * 16777216 + bytes[start + 3] * 65536 + bytes[start + 4] * 256 + bytes[start + 5] > 0) return Infinity;
		return bytes[start + 6] * 16777216 + bytes[start + 7] * 65536 + bytes[start + 8] * 256 + bytes[start + 9];
	}
	return payloadLen;
}
function WebSocketConnection(tcpHandle, req, options) {
	if (!(this instanceof WebSocketConnection)) return new WebSocketConnection(tcpHandle, req, options);
	this._events = {};
	this._handle = tcpHandle;
	this._readyState = READY_OPEN;
	this._rbuf = null;
	this._rstart = 0;
	this._rend = 0;
	this._pollTimer = null;
	this._fragments = [];
	this._fragmentsTotal = 0;
	this._fragmentOpcode = 0;
	this._maxPayload = options && typeof options.maxPayload === "number" ? options.maxPayload : DEFAULT_MAX_PAYLOAD;
	this.protocol = "";
	this.extensions = "";
	this.bufferedAmount = 0;
	this._req = req || null;
	this._closeFrameSent = false;
	this._closeFrameReceived = false;
	this._binaryType = "nodebuffer";
	if (typeof EventEmitter === "function" && EventEmitter.prototype) {
		for (var k in EventEmitter.prototype) if (!this[k]) this[k] = EventEmitter.prototype[k];
	}
	this._startReading();
}
Object.defineProperty(WebSocketConnection.prototype, "readyState", {
	get: function() {
		return this._readyState;
	},
	enumerable: true
});
Object.defineProperty(WebSocketConnection.prototype, "binaryType", {
	get: function() {
		return this._binaryType;
	},
	set: function(val) {
		this._binaryType = val;
	},
	enumerable: true
});
WebSocketConnection.CONNECTING = READY_CONNECTING;
WebSocketConnection.OPEN = READY_OPEN;
WebSocketConnection.CLOSING = READY_CLOSING;
WebSocketConnection.CLOSED = READY_CLOSED;
WebSocketConnection.prototype.CONNECTING = READY_CONNECTING;
WebSocketConnection.prototype.OPEN = READY_OPEN;
WebSocketConnection.prototype.CLOSING = READY_CLOSING;
WebSocketConnection.prototype.CLOSED = READY_CLOSED;
WebSocketConnection.prototype._startReading = function() {
	if (this._pollTimer != null) return;
	var self = this;
	var MAX_BYTES_PER_TICK = 4 * 1024 * 1024;
	function poll() {
		if (self._readyState === READY_CLOSED || self._handle == null) return;
		var drained = 0;
		try {
			while (drained < MAX_BYTES_PER_TICK) {
				var data = __exactTcpRead(self._handle, 65536);
				if (data === null) {
					self._handleTransportClose();
					return;
				}
				var chunkLen = typeof data === "string" ? data.length : data && data.length || 0;
				if (chunkLen === 0) break;
				self._appendData(data);
				drained += chunkLen;
			}
			if (drained > 0) self._processBuffer();
		} catch (e) {
			if (self._readyState !== READY_CLOSED) {
				self.emit("error", e);
				self._handleTransportClose();
			}
			return;
		}
		if (self._readyState !== READY_CLOSED && self._handle != null) self._pollTimer = setTimeout(poll, 5);
	}
	self._pollTimer = setTimeout(poll, 0);
};
WebSocketConnection.prototype._appendData = function(data) {
	var addLen;
	var isStr = typeof data === "string";
	if (isStr) addLen = data.length;
	else if (data && typeof data.length === "number") addLen = data.length;
	else return;
	if (addLen === 0) return;
	var used = this._rend - this._rstart;
	var buf = this._rbuf;
	var needed = used + addLen;
	if (!buf || needed > buf.length) {
		var cap = buf ? buf.length : 1024;
		while (cap < needed) cap *= 2;
		var nbuf = new Uint8Array(cap);
		if (used > 0) nbuf.set(buf.subarray(this._rstart, this._rend), 0);
		buf = nbuf;
		this._rbuf = buf;
		this._rstart = 0;
		this._rend = used;
	} else if (this._rend + addLen > buf.length) {
		buf.copyWithin(0, this._rstart, this._rend);
		this._rstart = 0;
		this._rend = used;
	}
	if (isStr) {
		var end = this._rend;
		for (var i = 0; i < addLen; i++) buf[end + i] = data.charCodeAt(i) & 255;
	} else buf.set(data, this._rend);
	this._rend += addLen;
};
WebSocketConnection.prototype._processBuffer = function() {
	if (!this._rbuf) return;
	while (this._rstart < this._rend) {
		if (this._maxPayload > 0) {
			var declared = _peekFramePayloadLength(this._rbuf, this._rstart, this._rend);
			if (declared !== null) {
				var projected = declared;
				if ((this._rbuf[this._rstart] & 15) === OPCODE_CONTINUATION) projected += this._fragmentsTotal;
				if (projected > this._maxPayload) {
					this._exceedMaxPayload();
					return;
				}
			}
		}
		var res = _parseFrame(this._rbuf, this._rstart, this._rend);
		if (!res) break;
		this._rstart = res.next;
		this._handleFrame(res.frame);
		if (this._readyState === READY_CLOSED || !this._rbuf) return;
	}
	if (this._rstart >= this._rend) {
		this._rstart = 0;
		this._rend = 0;
	}
};
WebSocketConnection.prototype._handleFrame = function(frame) {
	switch (frame.opcode) {
		case OPCODE_TEXT:
		case OPCODE_BINARY:
			if (this._maxPayload > 0 && frame.payload.length > this._maxPayload) {
				this._exceedMaxPayload();
				break;
			}
			if (frame.fin) {
				if (this._fragments.length > 0) {
					this._fragments = [];
					this._fragmentsTotal = 0;
				}
				this._deliverMessage(frame.opcode, frame.payload);
			} else {
				this._fragments = [frame.payload];
				this._fragmentsTotal = frame.payload.length;
				this._fragmentOpcode = frame.opcode;
			}
			break;
		case OPCODE_CONTINUATION:
			if (this._maxPayload > 0 && this._fragmentsTotal + frame.payload.length > this._maxPayload) {
				this._exceedMaxPayload();
				break;
			}
			this._fragments.push(frame.payload);
			this._fragmentsTotal += frame.payload.length;
			if (frame.fin) {
				var totalLen = 0;
				for (var j = 0; j < this._fragments.length; j++) totalLen += this._fragments[j].length;
				var combined = new Uint8Array(totalLen);
				var offset = 0;
				for (var j = 0; j < this._fragments.length; j++) {
					combined.set(this._fragments[j], offset);
					offset += this._fragments[j].length;
				}
				var op = this._fragmentOpcode;
				this._fragments = [];
				this._fragmentsTotal = 0;
				this._fragmentOpcode = 0;
				this._deliverMessage(op, combined);
			}
			break;
		case OPCODE_CLOSE:
			this._closeFrameReceived = true;
			var code = 1005;
			var reason = "";
			if (frame.payload.length >= 2) {
				code = frame.payload[0] << 8 | frame.payload[1];
				if (frame.payload.length > 2) {
					var reasonBytes = frame.payload.slice(2);
					if (typeof TextDecoder !== "undefined") reason = new TextDecoder().decode(reasonBytes);
					else for (var j = 0; j < reasonBytes.length; j++) reason += String.fromCharCode(reasonBytes[j]);
				}
			}
			if (!this._closeFrameSent) {
				var closePayload = [];
				if (frame.payload.length >= 2) {
					closePayload.push(frame.payload[0]);
					closePayload.push(frame.payload[1]);
				}
				this._sendFrame(OPCODE_CLOSE, closePayload);
				this._closeFrameSent = true;
			}
			this._readyState = READY_CLOSED;
			if (this._pollTimer != null) {
				clearTimeout(this._pollTimer);
				this._pollTimer = null;
			}
			try {
				if (this._handle != null) __exactTcpClose(this._handle);
			} catch (e) {}
			this._handle = null;
			this.emit("close", code, reason);
			break;
		case OPCODE_PING:
			this._sendFrame(OPCODE_PONG, frame.payload);
			this.emit("ping", frame.payload);
			break;
		case OPCODE_PONG:
			this.emit("pong", frame.payload);
			break;
	}
};
WebSocketConnection.prototype._deliverMessage = function(opcode, payload) {
	if (opcode === OPCODE_TEXT) {
		var text;
		if (typeof TextDecoder !== "undefined") text = new TextDecoder().decode(payload);
		else {
			text = "";
			for (var i = 0; i < payload.length; i++) text += String.fromCharCode(payload[i]);
		}
		this.emit("message", text, false);
	} else if (this._binaryType === "arraybuffer") this.emit("message", payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength), true);
	else if (this._binaryType === "fragments") this.emit("message", [payload], true);
	else if (typeof Buffer !== "undefined" && Buffer.from) this.emit("message", Buffer.from(payload), true);
	else this.emit("message", payload, true);
};
WebSocketConnection.prototype._exceedMaxPayload = function() {
	if (this._readyState === READY_CLOSED) return;
	this._fragments = [];
	this._fragmentsTotal = 0;
	this._fragmentOpcode = 0;
	this._rbuf = null;
	this._rstart = 0;
	this._rend = 0;
	var err = /* @__PURE__ */ new RangeError("Max payload size exceeded");
	err.code = "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
	if (typeof this.listenerCount === "function" && this.listenerCount("error") > 0) this.emit("error", err);
	if (!this._closeFrameSent) {
		this._sendFrame(OPCODE_CLOSE, [CLOSE_CODE_MESSAGE_TOO_BIG >> 8 & 255, CLOSE_CODE_MESSAGE_TOO_BIG & 255]);
		this._closeFrameSent = true;
	}
	this._readyState = READY_CLOSED;
	if (this._pollTimer != null) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	try {
		if (this._handle != null) __exactTcpClose(this._handle);
	} catch (e) {}
	this._handle = null;
	this.emit("close", CLOSE_CODE_MESSAGE_TOO_BIG, "Max payload size exceeded");
};
WebSocketConnection.prototype._handleTransportClose = function() {
	if (this._readyState === READY_CLOSED) return;
	this._readyState = READY_CLOSED;
	if (this._pollTimer != null) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	try {
		if (this._handle != null) __exactTcpClose(this._handle);
	} catch (e) {}
	this._handle = null;
	this.emit("close", 1006, "");
};
WebSocketConnection.prototype._sendFrame = function(opcode, payload) {
	if (this._handle == null) return;
	var frame = encodeFrame(opcode, payload);
	try {
		__exactTcpWrite(this._handle, frame);
	} catch (e) {
		this.emit("error", e);
	}
};
WebSocketConnection.prototype.send = function(data, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	options = options || {};
	if (this._readyState !== READY_OPEN) {
		var err = /* @__PURE__ */ new Error("WebSocket is not open: readyState " + this._readyState);
		if (typeof callback === "function") {
			callback(err);
			return;
		}
		throw err;
	}
	var opcode;
	var payload;
	if (typeof data === "string") {
		opcode = options.binary ? OPCODE_BINARY : OPCODE_TEXT;
		payload = data;
	} else if (data instanceof Uint8Array) {
		opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
		payload = data;
	} else if (data instanceof ArrayBuffer) {
		opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
		payload = new Uint8Array(data);
	} else if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(data)) {
		opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
		payload = new Uint8Array(data.buffer || data, data.byteOffset || 0, data.length);
	} else if (data == null) {
		opcode = OPCODE_TEXT;
		payload = "";
	} else {
		opcode = OPCODE_TEXT;
		payload = String(data);
	}
	var fin = options.fin !== false;
	this._sendFrame(opcode, payload, fin);
	if (typeof callback === "function") callback(null);
};
WebSocketConnection.prototype.close = function(code, reason) {
	if (this._readyState === READY_CLOSED || this._readyState === READY_CLOSING) return;
	this._readyState = READY_CLOSING;
	code = code || 1e3;
	reason = reason || "";
	var payload = [];
	payload.push(code >> 8 & 255);
	payload.push(code & 255);
	if (reason) if (typeof TextEncoder !== "undefined") {
		var encoded = new TextEncoder().encode(reason);
		for (var i = 0; i < encoded.length; i++) payload.push(encoded[i]);
	} else for (var i = 0; i < reason.length; i++) payload.push(reason.charCodeAt(i));
	this._closeFrameSent = true;
	this._sendFrame(OPCODE_CLOSE, payload);
	var self = this;
	setTimeout(function() {
		if (self._readyState !== READY_CLOSED) self._handleTransportClose();
	}, 5e3);
};
WebSocketConnection.prototype.ping = function(data, mask, callback) {
	if (typeof data === "function") {
		callback = data;
		data = void 0;
	}
	if (typeof mask === "function") {
		callback = mask;
		mask = void 0;
	}
	if (this._readyState !== READY_OPEN) return;
	this._sendFrame(OPCODE_PING, data || []);
	if (typeof callback === "function") callback(null);
};
WebSocketConnection.prototype.pong = function(data, mask, callback) {
	if (typeof data === "function") {
		callback = data;
		data = void 0;
	}
	if (typeof mask === "function") {
		callback = mask;
		mask = void 0;
	}
	if (this._readyState !== READY_OPEN) return;
	this._sendFrame(OPCODE_PONG, data || []);
	if (typeof callback === "function") callback(null);
};
WebSocketConnection.prototype.terminate = function() {
	if (this._readyState === READY_CLOSED) return;
	this._readyState = READY_CLOSED;
	if (this._pollTimer != null) {
		clearTimeout(this._pollTimer);
		this._pollTimer = null;
	}
	try {
		if (this._handle != null) __exactTcpClose(this._handle);
	} catch (e) {}
	this._handle = null;
	this.emit("close", 1006, "");
};
function WebSocketServer(options, callback) {
	if (!(this instanceof WebSocketServer)) return new WebSocketServer(options, callback);
	options = options || {};
	this._events = {};
	this.clients = /* @__PURE__ */ new Set();
	this._path = options.path || null;
	this._noServer = options.noServer || false;
	this._server = options.server || null;
	this._maxPayload = typeof options.maxPayload === "number" ? options.maxPayload : DEFAULT_MAX_PAYLOAD;
	this._handle = null;
	this._acceptTimer = null;
	this._port = options.port || 0;
	this._host = options.host || "0.0.0.0";
	this._listening = false;
	if (typeof EventEmitter === "function" && EventEmitter.prototype) {
		for (var k in EventEmitter.prototype) if (!this[k]) this[k] = EventEmitter.prototype[k];
	}
	if (typeof callback === "function") this.once("listening", callback);
	if (this._noServer) return;
	if (this._server) {
		var self = this;
		this._server.on("upgrade", function(req, socket, head) {
			self.handleUpgrade(req, socket, head, function(ws) {
				if (ws) self.emit("connection", ws, req);
			});
		});
		this._listening = true;
		var s = this;
		setTimeout(function() {
			s.emit("listening");
		}, 0);
		return;
	}
	if (!_hasTcpSupport()) {
		var self = this;
		setTimeout(function() {
			self.emit("error", /* @__PURE__ */ new Error("TCP not available"));
		}, 0);
		return;
	}
	var self = this;
	setTimeout(function() {
		try {
			self._handle = __exactTcpListen(self._host, self._port, 128);
			try {
				var info = __exactTcpLocalAddr(self._handle);
				if (info) {
					var addr = JSON.parse(info);
					self._port = addr.port;
					self._host = addr.address;
				}
			} catch (e) {}
			self._listening = true;
			self.emit("listening");
			self._startAccepting();
		} catch (e) {
			self.emit("error", e);
		}
	}, 0);
}
WebSocketServer.prototype._startAccepting = function() {
	if (this._acceptTimer != null) return;
	var self = this;
	function acceptLoop() {
		if (!self._listening || self._handle == null) return;
		try {
			var clientHandle = __exactTcpAccept(self._handle);
			if (clientHandle !== -1) self._handleRawConnection(clientHandle);
		} catch (e) {
			if (self._listening) self.emit("error", e);
			return;
		}
		self._acceptTimer = setTimeout(acceptLoop, 10);
	}
	self._acceptTimer = setTimeout(acceptLoop, 0);
};
WebSocketServer.prototype._handleRawConnection = function(tcpHandle) {
	var self = this;
	var buffer = "";
	var attempts = 0;
	var maxAttempts = 200;
	function readHeader() {
		if (attempts++ > maxAttempts) {
			try {
				__exactTcpClose(tcpHandle);
			} catch (e) {}
			return;
		}
		try {
			var data = __exactTcpRead(tcpHandle, 65536);
			if (data === null) {
				try {
					__exactTcpClose(tcpHandle);
				} catch (e) {}
				return;
			}
			data = _toBinaryString(data);
			if (data.length > 0) buffer += data;
			var headerEnd = buffer.indexOf("\r\n\r\n");
			if (headerEnd !== -1) {
				var headerStr = buffer.substring(0, headerEnd);
				var body = buffer.substring(headerEnd + 4);
				var req = parseHttpRequest(headerStr);
				if (req && isUpgradeRequest(req)) self._completeUpgrade(tcpHandle, req, body);
				else {
					var response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
					try {
						__exactTcpWrite(tcpHandle, response);
					} catch (e) {}
					try {
						__exactTcpClose(tcpHandle);
					} catch (e) {}
				}
				return;
			}
		} catch (e) {
			try {
				__exactTcpClose(tcpHandle);
			} catch (e2) {}
			return;
		}
		setTimeout(readHeader, 10);
	}
	readHeader();
};
WebSocketServer.prototype._completeUpgrade = function(tcpHandle, req, remainingData) {
	if (!_requestMatchesServerPath(this, req)) {
		_rejectUpgrade(tcpHandle);
		return;
	}
	var key = req.headers["sec-websocket-key"];
	if (!key) {
		var response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
		try {
			__exactTcpWrite(tcpHandle, response);
		} catch (e) {}
		try {
			__exactTcpClose(tcpHandle);
		} catch (e) {}
		return;
	}
	var responseHeaders = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + computeAcceptKey(key) + "\r\n\r\n";
	try {
		__exactTcpWrite(tcpHandle, responseHeaders);
	} catch (e) {
		try {
			__exactTcpClose(tcpHandle);
		} catch (e2) {}
		return;
	}
	var ws = new WebSocketConnection(tcpHandle, req, { maxPayload: this._maxPayload });
	if (remainingData && remainingData.length > 0) {
		ws._appendData(remainingData);
		ws._processBuffer();
	}
	this.clients.add(ws);
	var self = this;
	ws.on("close", function() {
		self.clients.delete(ws);
	});
	this.emit("connection", ws, req);
};
WebSocketServer.prototype.handleUpgrade = function(req, socket, head, callback) {
	var tcpHandle = null;
	tcpHandle = _detachSocketTcpHandle(socket);
	if (tcpHandle == null) {
		if (typeof callback === "function") callback(null);
		return;
	}
	var headers = {};
	if (req && req.headers) headers = req.headers;
	if (!_requestMatchesServerPath(this, req)) {
		_rejectUpgrade(tcpHandle);
		if (typeof callback === "function") callback(null);
		return;
	}
	var key = headers["sec-websocket-key"];
	if (!key) {
		try {
			__exactTcpClose(tcpHandle);
		} catch (e) {}
		if (typeof callback === "function") callback(null);
		return;
	}
	var responseHeaders = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + computeAcceptKey(key) + "\r\n\r\n";
	try {
		__exactTcpWrite(tcpHandle, responseHeaders);
	} catch (e) {
		try {
			__exactTcpClose(tcpHandle);
		} catch (e2) {}
		if (typeof callback === "function") callback(null);
		return;
	}
	var ws = new WebSocketConnection(tcpHandle, req, { maxPayload: this._maxPayload });
	if (head && head.length > 0 && (typeof head === "string" || head instanceof Uint8Array || typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(head))) {
		ws._appendData(head);
		ws._processBuffer();
	}
	this.clients.add(ws);
	var self = this;
	ws.on("close", function() {
		self.clients.delete(ws);
	});
	if (typeof callback === "function") callback(ws);
};
WebSocketServer.prototype.close = function(callback) {
	if (typeof callback === "function") this.once("close", callback);
	this._listening = false;
	if (this._acceptTimer != null) {
		clearTimeout(this._acceptTimer);
		this._acceptTimer = null;
	}
	if (this._handle != null && _hasTcpSupport()) {
		try {
			__exactTcpClose(this._handle);
		} catch (e) {}
		this._handle = null;
	}
	var clientsArr = [];
	this.clients.forEach(function(ws) {
		clientsArr.push(ws);
	});
	for (var i = 0; i < clientsArr.length; i++) try {
		clientsArr[i].terminate();
	} catch (e) {}
	var self = this;
	setTimeout(function() {
		self.emit("close");
	}, 0);
};
WebSocketServer.prototype.address = function() {
	if (this._handle != null && _hasTcpSupport()) try {
		var info = __exactTcpLocalAddr(this._handle);
		if (info) return JSON.parse(info);
	} catch (e) {}
	return {
		address: this._host || "0.0.0.0",
		port: this._port || 0,
		family: "IPv4"
	};
};
function parseHttpRequest(headerStr) {
	var lines = headerStr.split("\r\n");
	if (lines.length < 1) return null;
	var requestLine = lines[0].split(" ");
	if (requestLine.length < 3) return null;
	var method = requestLine[0];
	var url = requestLine[1];
	var httpVersion = requestLine[2];
	var headers = {};
	for (var i = 1; i < lines.length; i++) {
		var line = lines[i];
		var colonIdx = line.indexOf(":");
		if (colonIdx === -1) continue;
		var name = line.substring(0, colonIdx).trim().toLowerCase();
		headers[name] = line.substring(colonIdx + 1).trim();
	}
	return {
		method,
		url,
		httpVersion,
		headers
	};
}
function isUpgradeRequest(req) {
	return req.headers["upgrade"] && req.headers["upgrade"].toLowerCase() === "websocket" && req.headers["sec-websocket-key"];
}
var WS = WebSocketConnection;
WS.WebSocket = WebSocketConnection;
WS.WebSocketServer = WebSocketServer;
WS.Server = WebSocketServer;
WS.createWebSocketStream = function() {
	throw new Error("createWebSocketStream is not yet implemented");
};
WS.CONNECTING = READY_CONNECTING;
WS.OPEN = READY_OPEN;
WS.CLOSING = READY_CLOSING;
WS.CLOSED = READY_CLOSED;
module.exports = WS;
module.exports.default = WS;
module.exports.WebSocket = WebSocketConnection;
module.exports.WebSocketServer = WebSocketServer;
module.exports.Server = WebSocketServer;
//#endregion
