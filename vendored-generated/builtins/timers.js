//#region src/builtins/timers.js
var _setTimeout = globalThis.setTimeout;
var _clearTimeout = globalThis.clearTimeout;
var _setInterval = globalThis.setInterval;
var _clearInterval = globalThis.clearInterval;
var _FuncApply = Function.prototype.apply;
Function.prototype.bind;
var _symbolDispose = typeof Symbol === "function" ? Symbol.dispose || (typeof Symbol.for === "function" ? Symbol.for("nodejs.dispose") : null) : null;
function _validateTimerCallback(callback, name) {
	if (typeof callback !== "function") {
		var err = /* @__PURE__ */ new TypeError("[ERR_INVALID_ARG_TYPE]: The \"" + name + "\" argument must be of type function. Received type " + typeof callback);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
}
function _setTimerReference(handle, shouldRef) {
	if (handle && typeof handle === "object") {
		var method = shouldRef ? handle.ref : handle.unref;
		if (typeof method === "function") {
			method.call(handle);
			return;
		}
	}
	var control = shouldRef ? globalThis.__exactTimerRef : globalThis.__exactTimerUnref;
	if (typeof control === "function" && handle !== void 0 && handle !== null) control(handle);
}
var _nextTimerId = 1;
var _timerById = /* @__PURE__ */ new Map();
function Timeout(callback, delay, args, isRepeat) {
	this._callback = callback;
	this._delay = delay == null ? 1 : delay < 1 ? 1 : delay;
	this._args = args;
	this._isRepeat = isRepeat || false;
	this._repeat = isRepeat ? this._delay : null;
	this._refed = true;
	this._destroyed = false;
	this._closed = false;
	this._idleTimeout = this._delay;
	this._idleStart = Date.now();
	this._id = _nextTimerId++;
	this._onTimeout = callback;
	_timerById.set(this._id, this);
	this._scheduleNative();
}
Timeout.prototype._scheduleNative = function() {
	var self = this;
	if (this._isRepeat) this._nativeHandle = _setInterval(function() {
		_FuncApply.call(self._callback, self, self._args);
	}, this._delay);
	else this._nativeHandle = _setTimeout(function() {
		self._destroyed = true;
		_timerById.delete(self._id);
		_FuncApply.call(self._callback, self, self._args);
	}, this._delay);
	if (!this._refed) _setTimerReference(this._nativeHandle, false);
};
Timeout.prototype.ref = function() {
	this._refed = true;
	_setTimerReference(this._nativeHandle, true);
	return this;
};
Timeout.prototype.unref = function() {
	this._refed = false;
	_setTimerReference(this._nativeHandle, false);
	return this;
};
Timeout.prototype.hasRef = function() {
	return this._refed;
};
Timeout.prototype.refresh = function() {
	if (this._closed) return this;
	if (this._destroyed) {
		this._destroyed = false;
		_timerById.set(this._id, this);
	} else if (this._isRepeat) _clearInterval(this._nativeHandle);
	else _clearTimeout(this._nativeHandle);
	this._scheduleNative();
	return this;
};
Timeout.prototype.close = function() {
	if (this._isRepeat) _clearInterval(this._nativeHandle);
	else _clearTimeout(this._nativeHandle);
	this._destroyed = true;
	this._closed = true;
	_timerById.delete(this._id);
	return this;
};
Timeout.prototype[Symbol.toPrimitive] = function() {
	return this._id;
};
if (_symbolDispose) Timeout.prototype[_symbolDispose] = function() {
	if (!this._destroyed) this.close();
};
function Immediate(callback, args) {
	this._callback = callback;
	this._args = args;
	this._destroyed = false;
	this._id = _nextTimerId++;
	this._refed = true;
	this._onImmediate = callback;
	_timerById.set(this._id, this);
	var self = this;
	this._nativeHandle = _setTimeout(function() {
		self._destroyed = true;
		_timerById.delete(self._id);
		_FuncApply.call(self._callback, self, self._args);
	}, 0);
	if (!this._refed) _setTimerReference(this._nativeHandle, false);
}
Immediate.prototype.ref = function() {
	this._refed = true;
	_setTimerReference(this._nativeHandle, true);
	return this;
};
Immediate.prototype.unref = function() {
	this._refed = false;
	_setTimerReference(this._nativeHandle, false);
	return this;
};
Immediate.prototype.hasRef = function() {
	return this._refed;
};
Immediate.prototype.close = function() {
	_clearTimeout(this._nativeHandle);
	this._destroyed = true;
	_timerById.delete(this._id);
	return this;
};
Immediate.prototype[Symbol.toPrimitive] = function() {
	return this._id;
};
if (_symbolDispose) Immediate.prototype[_symbolDispose] = function() {
	if (!this._destroyed) this.close();
};
function setTimeout$1(callback, delay) {
	_validateTimerCallback(callback, "callback");
	var args = [];
	for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
	if (typeof _setTimeout !== "function") throw new Error("setTimeout is not available");
	return new Timeout(callback, delay, args, false);
}
function clearTimeout$1(handle) {
	if (handle === void 0 || handle === null) return;
	if (typeof handle === "object" && handle !== null) {
		if (typeof handle.close === "function") {
			handle.close();
			return;
		}
		if (handle._nativeHandle !== void 0) {
			if (typeof _clearTimeout === "function") _clearTimeout(handle._nativeHandle);
			handle._destroyed = true;
			if (handle._id !== void 0) _timerById.delete(handle._id);
			return;
		}
	}
	if (typeof handle === "number" || typeof handle === "string") {
		var numId = Number(handle);
		var timerObj = _timerById.get(numId);
		if (timerObj) {
			timerObj.close();
			return;
		}
	}
	if (typeof _clearTimeout === "function") _clearTimeout(handle);
}
function setInterval$1(callback, delay) {
	_validateTimerCallback(callback, "callback");
	var args = [];
	for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
	if (typeof _setInterval !== "function") throw new Error("setInterval is not available");
	return new Timeout(callback, delay, args, true);
}
function clearInterval$1(handle) {
	if (handle === void 0 || handle === null) return;
	if (typeof handle === "object" && handle !== null) {
		if (typeof handle.close === "function") {
			handle.close();
			return;
		}
		if (handle._nativeHandle !== void 0) {
			if (typeof _clearInterval === "function") _clearInterval(handle._nativeHandle);
			handle._destroyed = true;
			if (handle._id !== void 0) _timerById.delete(handle._id);
			return;
		}
	}
	if (typeof handle === "number" || typeof handle === "string") {
		var numId = Number(handle);
		var timerObj = _timerById.get(numId);
		if (timerObj) {
			timerObj.close();
			return;
		}
	}
	if (typeof _clearInterval === "function") _clearInterval(handle);
}
function setImmediate$1(callback) {
	_validateTimerCallback(callback, "callback");
	var args = [];
	for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
	return new Immediate(callback, args);
}
function clearImmediate$1(handle) {
	if (handle === void 0 || handle === null) return;
	if (typeof handle === "object" && handle !== null) {
		if (typeof handle.close === "function") {
			handle.close();
			return;
		}
		if (handle._nativeHandle !== void 0) {
			_clearTimeout(handle._nativeHandle);
			handle._destroyed = true;
			if (handle._id !== void 0) _timerById.delete(handle._id);
			return;
		}
	}
	if (typeof handle === "number" || typeof handle === "string") {
		var numId = Number(handle);
		var timerObj = _timerById.get(numId);
		if (timerObj) {
			timerObj.close();
			return;
		}
	}
	_clearTimeout(handle);
}
var _promisifyCustomSymbol = typeof Symbol === "function" && typeof Symbol.for === "function" ? Symbol.for("nodejs.util.promisify.custom") : null;
if (_promisifyCustomSymbol) {
	Object.defineProperty(setTimeout$1, _promisifyCustomSymbol, {
		get: function() {
			return require("timers/promises").setTimeout;
		},
		configurable: true,
		enumerable: false
	});
	Object.defineProperty(setImmediate$1, _promisifyCustomSymbol, {
		get: function() {
			return require("timers/promises").setImmediate;
		},
		configurable: true,
		enumerable: false
	});
}
var _promisesModule = null;
module.exports = {
	setTimeout: setTimeout$1,
	clearTimeout: clearTimeout$1,
	setInterval: setInterval$1,
	clearInterval: clearInterval$1,
	setImmediate: setImmediate$1,
	clearImmediate: clearImmediate$1,
	Timeout,
	Immediate,
	active: function active(item) {
		if (!item || typeof item._idleTimeout !== "number" || item._idleTimeout < 0) return;
		item._idleStart = Date.now();
		item._idleNext = item._idleNext || item;
		item._idlePrev = item._idlePrev || item;
		if (item._exactActiveHandle) _clearTimeout(item._exactActiveHandle);
		var delay = item._idleTimeout;
		item._exactActiveHandle = _setTimeout(function() {
			item._exactActiveHandle = null;
			if (typeof item._onTimeout === "function") item._onTimeout();
		}, delay);
	},
	_unrefActive: function _unrefActive(item) {
		if (!item || typeof item._idleTimeout !== "number" || item._idleTimeout < 0) return;
		if (item._exactUnrefHandle) _clearTimeout(item._exactUnrefHandle);
		var delay = item._idleTimeout;
		var handle = _setTimeout(function() {
			item._exactUnrefHandle = null;
			if (typeof item._onTimeout === "function") item._onTimeout();
		}, delay);
		item._exactUnrefHandle = handle;
		if (handle && typeof handle === "object" && typeof handle.unref === "function") handle.unref();
		else if (typeof globalThis.__exactTimerUnref === "function" && typeof handle === "number") globalThis.__exactTimerUnref(handle);
	},
	enroll: function enroll(item, msecs) {
		if (typeof msecs !== "number") {
			var err = /* @__PURE__ */ new TypeError("The \"msecs\" argument must be of type number. Received type " + typeof msecs);
			err.code = "ERR_INVALID_ARG_TYPE";
			throw err;
		}
		if (msecs < 0 || !isFinite(msecs)) {
			var err2 = /* @__PURE__ */ new RangeError("The value of \"msecs\" is out of range. It must be a non-negative finite number. Received " + msecs);
			err2.code = "ERR_OUT_OF_RANGE";
			throw err2;
		}
		item._idleTimeout = msecs;
	},
	unenroll: function unenroll(item) {
		item._idleTimeout = -1;
		if (item._exactUnrefHandle) {
			_clearTimeout(item._exactUnrefHandle);
			item._exactUnrefHandle = null;
		}
		if (item._exactActiveHandle) {
			_clearTimeout(item._exactActiveHandle);
			item._exactActiveHandle = null;
		}
	},
	get promises() {
		if (!_promisesModule) _promisesModule = require("timers/promises");
		return _promisesModule;
	}
};
//#endregion
