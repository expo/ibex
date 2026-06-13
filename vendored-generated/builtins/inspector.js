//#region src/builtins/inspector.js
var EventEmitter;
try {
	EventEmitter = require("events");
} catch (e) {
	EventEmitter = function() {
		this._events = {};
	};
	EventEmitter.prototype.on = function(ev, fn) {
		if (!this._events[ev]) this._events[ev] = [];
		this._events[ev].push(fn);
		return this;
	};
	EventEmitter.prototype.emit = function(ev) {
		var a = [].slice.call(arguments, 1);
		var l = this._events[ev] || [];
		for (var i = 0; i < l.length; i++) l[i].apply(this, a);
	};
	EventEmitter.prototype.removeListener = function() {
		return this;
	};
	EventEmitter.prototype.removeAllListeners = function() {
		return this;
	};
	EventEmitter.prototype.once = function(ev, fn) {
		var self = this;
		function w() {
			self.removeListener(ev, w);
			fn.apply(this, arguments);
		}
		this.on(ev, w);
		return this;
	};
	EventEmitter.prototype.addListener = EventEmitter.prototype.on;
	EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
}
function Session() {
	if (EventEmitter) EventEmitter.call(this);
	this._connected = false;
}
if (EventEmitter && EventEmitter.prototype) {
	Session.prototype = Object.create(EventEmitter.prototype);
	Session.prototype.constructor = Session;
}
Session.prototype.connect = function() {
	this._connected = true;
};
Session.prototype.connectToMainThread = function() {
	this._connected = true;
};
Session.prototype.disconnect = function() {
	this._connected = false;
};
Session.prototype.post = function(method, params, callback) {
	if (typeof params === "function") {
		callback = params;
		params = void 0;
	}
	var err = /* @__PURE__ */ new Error("Inspector is not available in this runtime");
	if (typeof callback === "function") callback(err);
};
function open(port, host, wait) {}
function close() {}
function url() {}
function waitForDebugger() {}
module.exports = {
	Session,
	open,
	close,
	url,
	waitForDebugger
};
//#endregion
