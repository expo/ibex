//#region src/builtins/worker-threads.js
var isMainThread = true;
var parentPort = null;
var workerData = null;
var threadId = 0;
function MessagePort() {
	this._listeners = {};
	this._remotePort = null;
	this._started = false;
	this._closed = false;
	this._messageListenerCount = 0;
	this._closing = false;
	this._ref = false;
	this._onmessageListener = false;
	this._queue = [];
	this._onmessage = null;
	this._onmessageerror = null;
	var asyncHooks = require("async_hooks");
	this._asyncId = typeof asyncHooks.__nextAsyncId === "function" ? asyncHooks.__nextAsyncId() : 0;
	if (typeof asyncHooks.__emitInit === "function") asyncHooks.__emitInit(this._asyncId, "MESSAGEPORT", 0, this);
}
function hasMessageEventListeners(port) {
	return port && !port._closed && (port._onmessageListener || port._messageListenerCount > 0);
}
Object.defineProperty(MessagePort.prototype, "onmessage", {
	get: function() {
		return this._onmessage;
	},
	set: function(handler) {
		this._onmessageListener = !!handler;
		this._onmessage = handler;
		this.start();
	},
	configurable: true
});
Object.defineProperty(MessagePort.prototype, "onmessageerror", {
	get: function() {
		return this._onmessageerror;
	},
	set: function(handler) {
		this._onmessageerror = handler;
	},
	configurable: true
});
MessagePort.prototype.addEventListener = function(type, callback) {
	if (!callback) return;
	if (type === "message") this._messageListenerCount = (this._messageListenerCount || 0) + 1;
	if (!this._listeners[type]) this._listeners[type] = [];
	this._listeners[type].push(callback);
};
MessagePort.prototype.on = function(type, callback) {
	this.addEventListener(type, callback);
	return this;
};
MessagePort.prototype.removeEventListener = function(type, callback) {
	var list = this._listeners[type];
	if (!list) return;
	var idx = list.indexOf(callback);
	if (idx !== -1) list.splice(idx, 1);
	if (type === "message") this._messageListenerCount = Math.max(0, (this._messageListenerCount || 0) - 1);
};
MessagePort.prototype.off = function(type, callback) {
	this.removeEventListener(type, callback);
	return this;
};
MessagePort.prototype.ref = function() {
	this._ref = true;
	return this;
};
MessagePort.prototype.unref = function() {
	this._ref = false;
	return this;
};
MessagePort.prototype.hasRef = function() {
	if (this._closed) return false;
	return this._ref || hasMessageEventListeners(this);
};
MessagePort.prototype.dispatchEvent = function(event) {
	var list = this._listeners[event.type];
	if (list) {
		var copy = list.slice();
		for (var i = 0; i < copy.length; i++) try {
			copy[i].call(this, event);
		} catch (e) {}
	}
	return true;
};
MessagePort.prototype.postMessage = function(value, transferList) {
	if (this._closed) return;
	var remote = this._remotePort;
	if (!remote || remote._closed) return;
	var clonedData;
	try {
		if (typeof globalThis.structuredClone === "function") clonedData = globalThis.structuredClone(value);
		else clonedData = JSON.parse(JSON.stringify(value));
	} catch (err) {
		var errTarget = remote;
		queueMicrotask(function() {
			if (!errTarget._closed) errTarget._dispatchMessageError(err);
		});
		return;
	}
	if (remote._started) {
		var target = remote;
		queueMicrotask(function() {
			if (!target._closed) target._dispatchMessage(clonedData);
		});
	} else remote._queue.push(clonedData);
};
MessagePort.prototype.start = function() {
	if (this._started) return;
	this._started = true;
	if (this._queue.length > 0) {
		var pending = this._queue.splice(0);
		var self = this;
		for (var i = 0; i < pending.length; i++) (function(data) {
			queueMicrotask(function() {
				if (!self._closed) self._dispatchMessage(data);
			});
		})(pending[i]);
	}
};
MessagePort.prototype.close = function() {
	if (this._closed || this._closing) return;
	this._closing = true;
	var self = this;
	var remote = this._remotePort;
	queueMicrotask(function() {
		self._closed = true;
		self._closing = false;
		if (remote) {
			remote._closed = true;
			remote._closing = false;
		}
		self._queue.length = 0;
		if (remote) remote._queue.length = 0;
		var selfEvent = {
			type: "close",
			target: self,
			currentTarget: self
		};
		var remoteEvent = {
			type: "close",
			target: remote,
			currentTarget: remote
		};
		self.dispatchEvent(selfEvent);
		if (remote) remote.dispatchEvent(remoteEvent);
	});
};
MessagePort.prototype._dispatchMessage = function(data) {
	var event = {
		type: "message",
		data,
		target: this,
		currentTarget: this
	};
	if (this._onmessage) try {
		this._onmessage.call(this, event);
	} catch (e) {}
	this.dispatchEvent(event);
};
MessagePort.prototype._dispatchMessageError = function(error) {
	var event = {
		type: "messageerror",
		data: error,
		target: this,
		currentTarget: this
	};
	if (this._onmessageerror) try {
		this._onmessageerror.call(this, event);
	} catch (e) {}
	this.dispatchEvent(event);
};
Object.defineProperty(MessagePort.prototype, Symbol.toStringTag, {
	value: "MessagePort",
	configurable: true
});
function MessageChannel() {
	this.port1 = new MessagePort();
	this.port2 = new MessagePort();
	this.port1._remotePort = this.port2;
	this.port2._remotePort = this.port1;
}
Object.defineProperty(MessageChannel.prototype, Symbol.toStringTag, {
	value: "MessageChannel",
	configurable: true
});
var _broadcastRegistry = {};
function BroadcastChannel(name) {
	this.name = String(name);
	this._closed = false;
	this._listeners = {};
	this._onmessage = null;
	this._onmessageerror = null;
	if (!_broadcastRegistry[this.name]) _broadcastRegistry[this.name] = [];
	_broadcastRegistry[this.name].push(this);
}
Object.defineProperty(BroadcastChannel.prototype, "onmessage", {
	get: function() {
		return this._onmessage;
	},
	set: function(handler) {
		this._onmessage = handler;
	},
	configurable: true
});
Object.defineProperty(BroadcastChannel.prototype, "onmessageerror", {
	get: function() {
		return this._onmessageerror;
	},
	set: function(handler) {
		this._onmessageerror = handler;
	},
	configurable: true
});
BroadcastChannel.prototype.addEventListener = function(type, callback) {
	if (!callback) return;
	if (!this._listeners[type]) this._listeners[type] = [];
	this._listeners[type].push(callback);
};
BroadcastChannel.prototype.removeEventListener = function(type, callback) {
	var list = this._listeners[type];
	if (!list) return;
	var idx = list.indexOf(callback);
	if (idx !== -1) list.splice(idx, 1);
};
BroadcastChannel.prototype.dispatchEvent = function(event) {
	var list = this._listeners[event.type];
	if (list) {
		var copy = list.slice();
		for (var i = 0; i < copy.length; i++) try {
			copy[i].call(this, event);
		} catch (e) {}
	}
	return true;
};
BroadcastChannel.prototype.postMessage = function(message) {
	if (this._closed) {
		var err = /* @__PURE__ */ new Error("BroadcastChannel is closed");
		err.name = "InvalidStateError";
		throw err;
	}
	var clonedMessage;
	try {
		if (typeof globalThis.structuredClone === "function") clonedMessage = globalThis.structuredClone(message);
		else clonedMessage = JSON.parse(JSON.stringify(message));
	} catch (e) {
		return;
	}
	var channels = _broadcastRegistry[this.name];
	if (!channels) return;
	var self = this;
	for (var i = 0; i < channels.length; i++) (function(channel) {
		if (channel !== self && !channel._closed) queueMicrotask(function() {
			if (!channel._closed) {
				var event = {
					type: "message",
					data: clonedMessage,
					target: channel,
					currentTarget: channel
				};
				if (channel._onmessage) try {
					channel._onmessage.call(channel, event);
				} catch (e) {}
				channel.dispatchEvent(event);
			}
		});
	})(channels[i]);
};
BroadcastChannel.prototype.close = function() {
	if (this._closed) return;
	this._closed = true;
	var channels = _broadcastRegistry[this.name];
	if (channels) {
		var idx = channels.indexOf(this);
		if (idx !== -1) channels.splice(idx, 1);
		if (channels.length === 0) delete _broadcastRegistry[this.name];
	}
};
Object.defineProperty(BroadcastChannel.prototype, Symbol.toStringTag, {
	value: "BroadcastChannel",
	configurable: true
});
function Worker(filename, options) {
	throw new Error("worker_threads.Worker is not supported in this runtime. Use child_process instead.");
}
var SHARE_ENV = Symbol.for("nodejs.worker_threads.SHARE_ENV");
var _envData = {};
function getEnvironmentData(key) {
	return _envData[key];
}
function setEnvironmentData(key, value) {
	if (value === void 0) delete _envData[key];
	else _envData[key] = value;
}
function receiveMessageOnPort(port) {
	if (port && port._queue && port._queue.length > 0) return { message: port._queue.shift() };
}
function moveMessagePortToContext(port, contextifiedSandbox) {
	return port;
}
function markAsUntransferable(obj) {}
function isMarkedAsUntransferable(obj) {
	return false;
}
module.exports = {
	isMainThread,
	parentPort,
	workerData,
	threadId,
	resourceLimits: {},
	Worker,
	MessageChannel,
	MessagePort,
	BroadcastChannel,
	SHARE_ENV,
	getEnvironmentData,
	setEnvironmentData,
	receiveMessageOnPort,
	moveMessagePortToContext,
	markAsUntransferable,
	isMarkedAsUntransferable
};
//#endregion
