//#region src/builtins/events.js
var errorMonitorSymbol = Symbol("events.errorMonitor");
var captureRejectionSymbol = typeof Symbol === "function" && typeof Symbol.for === "function" ? Symbol.for("nodejs.rejection") : "__nodejsRejection";
var eventTargetEventsSymbol = typeof Symbol === "function" && typeof Symbol.for === "function" ? Symbol.for("nodejs.internal.event_target.kEvents") : "__nodejs_internal_event_target_kEvents";
var objectToString = Object.prototype.toString;
var __AsyncResource;
var _captureRejections = false;
var _exactDebugEmitListener = typeof process === "object" && process && process.env && process.env.EXACT_DEBUG_EMIT_LISTENER === "1";
try {
	__AsyncResource = require("async_hooks").AsyncResource;
} catch (e) {
	__AsyncResource = null;
}
function _ensureTrackedEventTargetMap(target) {
	if (!target) return null;
	var map = target[eventTargetEventsSymbol];
	if (!map || typeof map.get !== "function") {
		map = /* @__PURE__ */ new Map();
		Object.defineProperty(target, eventTargetEventsSymbol, {
			value: map,
			writable: true,
			configurable: true,
			enumerable: false
		});
	}
	return map;
}
function _trackEventTargetListener(target, type, listener) {
	if (!listener || !type) return;
	var map = _ensureTrackedEventTargetMap(target);
	if (!map) return;
	var listeners = map.get(type);
	if (!listeners) {
		listeners = /* @__PURE__ */ new Set();
		map.set(type, listeners);
	}
	listeners.add(listener);
}
function _untrackEventTargetListener(target, type, listener) {
	if (!target || !type || !listener) return;
	var map = target[eventTargetEventsSymbol];
	if (!map || typeof map.get !== "function") return;
	var listeners = map.get(type);
	if (!listeners || typeof listeners.delete !== "function") return;
	listeners.delete(listener);
	if (listeners.size === 0) map.delete(type);
}
function patchNativeEventTargetTracking() {
	if (typeof EventTarget !== "function" || !EventTarget.prototype) return;
	var proto = EventTarget.prototype;
	if (proto.__exactEventTargetTrackingPatched) return;
	var nativeAdd = proto.addEventListener;
	var nativeRemove = proto.removeEventListener;
	if (typeof nativeAdd !== "function" || typeof nativeRemove !== "function") return;
	Object.defineProperty(proto, "__exactEventTargetTrackingPatched", {
		value: true,
		writable: false,
		configurable: true,
		enumerable: false
	});
	Object.defineProperty(proto, "addEventListener", {
		value: function addEventListener(type, listener, options) {
			var result = nativeAdd.call(this, type, listener, options);
			_trackEventTargetListener(this, type, listener);
			return result;
		},
		writable: true,
		configurable: true,
		enumerable: false
	});
	Object.defineProperty(proto, "removeEventListener", {
		value: function removeEventListener(type, listener, options) {
			var result = nativeRemove.call(this, type, listener, options);
			_untrackEventTargetListener(this, type, listener);
			return result;
		},
		writable: true,
		configurable: true,
		enumerable: false
	});
}
patchNativeEventTargetTracking();
function _safeInspectUnhandledError(value) {
	try {
		var inspected = require("util").inspect(value);
		if (typeof inspected === "string" && inspected.indexOf("revoked Proxy") !== -1 && objectToString.call(value) === "[object Object]") return "[object Object]";
		return inspected;
	} catch (e) {
		return objectToString.call(value);
	}
}
function _invalidArgType(name, value) {
	var type = value === null ? "null" : typeof value;
	var err = /* @__PURE__ */ new TypeError("The \"" + name + "\" argument must be of type object. Received " + (type === "object" && value && value.constructor && value.constructor.name ? "an instance of " + value.constructor.name : type));
	err.code = "ERR_INVALID_ARG_TYPE";
	return err;
}
var _defaultMaxListeners = 10;
function checkListener(listener) {
	if (typeof listener !== "function") {
		var err = /* @__PURE__ */ new TypeError("The \"listener\" argument must be of type function. Received " + (listener === null ? "null" : typeof listener));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
}
function EventEmitter(opts) {
	if (!(this instanceof EventEmitter) && this && this.constructor !== EventEmitter) {}
	EventEmitter.init.call(this, opts);
}
function EventEmitterAsyncResource(type, options) {
	if (!(this instanceof EventEmitterAsyncResource)) return new EventEmitterAsyncResource(type, options);
	EventEmitter.call(this);
	if (__AsyncResource) this._asyncResource = new __AsyncResource(type || "EventEmitterAsyncResource", options || void 0);
	else this._asyncResource = null;
}
EventEmitterAsyncResource.prototype = Object.create(EventEmitter.prototype);
EventEmitterAsyncResource.prototype.constructor = EventEmitterAsyncResource;
EventEmitterAsyncResource.prototype.emit = function emit(eventName) {
	var args = [];
	for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
	if (this._asyncResource && typeof this._asyncResource.runInAsyncScope === "function") return this._asyncResource.runInAsyncScope(function() {
		return EventEmitter.prototype.emit.apply(this, [eventName].concat(args));
	}, this);
	return EventEmitter.prototype.emit.apply(this, [eventName].concat(args));
};
EventEmitter.init = function init(opts) {
	if (this._events === void 0 || this._events === Object.getPrototypeOf(this)._events) this._events = Object.create(null);
	this._maxListeners = this._maxListeners || void 0;
	if (opts && Object.prototype.hasOwnProperty.call(opts, "captureRejections")) this.captureRejections = opts.captureRejections === true;
};
EventEmitter.prototype._events = void 0;
EventEmitter.prototype._maxListeners = void 0;
function _invokeListener(listener, thisArg, args) {
	var argc = args.length;
	if (argc === 0) return listener.call(thisArg);
	if (argc === 1) return listener.call(thisArg, args[0]);
	if (argc === 2) return listener.call(thisArg, args[0], args[1]);
	if (argc === 3) return listener.call(thisArg, args[0], args[1], args[2]);
	if (argc === 4) return listener.call(thisArg, args[0], args[1], args[2], args[3]);
	return listener.apply(thisArg, args);
}
function _scheduleRejection(handler) {
	if (typeof process !== "undefined" && process && typeof process.nextTick === "function") {
		process.nextTick(handler);
		return;
	}
	setTimeout(handler, 0);
}
function _emitPromiseRejection(emitter, err, eventName, args) {
	_scheduleRejection(function() {
		if (emitter && captureRejectionSymbol && typeof emitter[captureRejectionSymbol] === "function") {
			emitter[captureRejectionSymbol].apply(emitter, [err, eventName].concat(args));
			return;
		}
		emitter.emit("error", err);
	});
}
function _maybeCaptureRejection(emitter, result, eventName, args) {
	if (!(emitter && (emitter.captureRejections === true || EventEmitter.captureRejections === true))) return;
	if (!result || typeof result.then !== "function") return;
	result.then(void 0, function(err) {
		_emitPromiseRejection(emitter, err, eventName, args);
	});
}
Object.defineProperty(EventEmitter, "defaultMaxListeners", {
	enumerable: true,
	get: function() {
		return _defaultMaxListeners;
	},
	set: function(val) {
		if (typeof val !== "number" || val < 0 || val !== val) {
			var err;
			if (typeof val !== "number") {
				err = /* @__PURE__ */ new TypeError("The \"defaultMaxListeners\" property must be of type number. Received " + typeof val);
				err.code = "ERR_INVALID_ARG_TYPE";
			} else {
				err = /* @__PURE__ */ new RangeError("The value of \"defaultMaxListeners\" is out of range. It must be a non-negative number. Received " + val);
				err.code = "ERR_OUT_OF_RANGE";
			}
			throw err;
		}
		_defaultMaxListeners = val;
	}
});
Object.defineProperty(EventEmitter, "captureRejections", {
	enumerable: true,
	get: function() {
		return _captureRejections;
	},
	set: function(val) {
		_captureRejections = val === true;
	}
});
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
	if (typeof n !== "number" || n < 0 || n !== n) {
		var err;
		if (typeof n !== "number") {
			err = /* @__PURE__ */ new TypeError("The \"n\" argument must be of type number. Received type " + typeof n);
			err.code = "ERR_INVALID_ARG_TYPE";
		} else {
			err = /* @__PURE__ */ new RangeError("The value of \"n\" is out of range. It must be a non-negative number. Received " + n);
			err.code = "ERR_OUT_OF_RANGE";
		}
		throw err;
	}
	this._maxListeners = n;
	return this;
};
EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
	if (this._maxListeners === void 0) return EventEmitter.defaultMaxListeners;
	return this._maxListeners;
};
function _getMaxListeners(emitter) {
	if (emitter._maxListeners === void 0) return EventEmitter.defaultMaxListeners;
	return emitter._maxListeners;
}
function _addListener(target, eventName, listener, prepend) {
	var events;
	var existing;
	var m;
	checkListener(listener);
	events = target._events;
	if (events === void 0) {
		events = target._events = Object.create(null);
		target._maxListeners = target._maxListeners || void 0;
	}
	if (events.newListener !== void 0) {
		target.emit("newListener", eventName, listener.listener ? listener.listener : listener);
		events = target._events;
	}
	existing = events[eventName];
	if (existing === void 0) events[eventName] = listener;
	else if (typeof existing === "function") events[eventName] = prepend ? [listener, existing] : [existing, listener];
	else if (prepend) existing.unshift(listener);
	else existing.push(listener);
	m = _getMaxListeners(target);
	if (m > 0) {
		var count = typeof events[eventName] === "function" ? 1 : events[eventName] ? events[eventName].length : 0;
		if (count > m && !(Array.isArray(events[eventName]) && events[eventName].warned)) {
			if (Array.isArray(events[eventName])) events[eventName].warned = true;
			var w = /* @__PURE__ */ new Error("Possible EventEmitter memory leak detected. " + count + " " + String(eventName) + " listeners added to [" + (target.constructor ? target.constructor.name : "EventEmitter") + "]. MaxListeners is " + m + ". Use emitter.setMaxListeners() to increase limit");
			w.name = "MaxListenersExceededWarning";
			w.emitter = target;
			w.type = eventName;
			w.count = count;
			if (typeof process !== "undefined" && process !== null && typeof process.emitWarning === "function") process.emitWarning(w);
			else if (typeof console !== "undefined" && typeof console.warn === "function") console.warn(w);
		}
	}
	return target;
}
EventEmitter.prototype.addListener = function addListener(eventName, listener) {
	return _addListener(this, eventName, listener, false);
};
EventEmitter.prototype.on = EventEmitter.prototype.addListener;
EventEmitter.prototype.prependListener = function prependListener(eventName, listener) {
	return _addListener(this, eventName, listener, true);
};
function onceWrapper() {
	if (!this.fired) {
		this.fired = true;
		this.target.removeListener(this.type, this.wrapFn);
		var args = [];
		for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
		return this.listener.apply(this.target, args);
	}
}
function _onceWrap(target, eventName, listener) {
	var state = {
		fired: false,
		target,
		type: eventName,
		listener,
		wrapFn: void 0
	};
	var wrapped = onceWrapper.bind(state);
	wrapped.listener = listener;
	state.wrapFn = wrapped;
	return wrapped;
}
EventEmitter.prototype.once = function once(eventName, listener) {
	checkListener(listener);
	this.on(eventName, _onceWrap(this, eventName, listener));
	return this;
};
EventEmitter.prototype.prependOnceListener = function prependOnceListener(eventName, listener) {
	checkListener(listener);
	this.prependListener(eventName, _onceWrap(this, eventName, listener));
	return this;
};
EventEmitter.prototype.removeListener = function removeListener(eventName, listener) {
	checkListener(listener);
	var events = this._events;
	if (events === void 0) return this;
	var list = events[eventName];
	if (list === void 0) return this;
	if (list === listener || list.listener === listener) {
		delete events[eventName];
		if (events.removeListener) this.emit("removeListener", eventName, list.listener || list);
	} else if (typeof list !== "function") {
		var position = -1;
		for (var i = list.length - 1; i >= 0; i--) if (list[i] === listener || list[i].listener && list[i].listener === listener) {
			position = i;
			break;
		}
		if (position < 0) return this;
		var originalListener = list[position].listener || list[position];
		if (position === 0) list.shift();
		else list.splice(position, 1);
		if (list.length === 1) events[eventName] = list[0];
		if (list.length === 0) delete events[eventName];
		if (events.removeListener) this.emit("removeListener", eventName, originalListener);
	}
	return this;
};
EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
EventEmitter.prototype.removeAllListeners = function removeAllListeners(eventName) {
	var events = this._events;
	if (events === void 0) return this;
	if (events.removeListener === void 0) {
		if (arguments.length === 0) this._events = Object.create(null);
		else if (events[eventName] !== void 0) delete events[eventName];
		return this;
	}
	if (arguments.length === 0) {
		var keys = Object.keys(events);
		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			if (key === "removeListener") continue;
			this.removeAllListeners(key);
		}
		this.removeAllListeners("removeListener");
		this._events = Object.create(null);
		return this;
	}
	var listeners = events[eventName];
	if (typeof listeners === "function") this.removeListener(eventName, listeners);
	else if (listeners !== void 0) for (var i = listeners.length - 1; i >= 0; i--) this.removeListener(eventName, listeners[i]);
	return this;
};
EventEmitter.prototype.emit = function emit(eventName) {
	var events = this._events;
	var doError = eventName === "error";
	if (events !== void 0) {
		if (doError && events[errorMonitorSymbol] !== void 0) {
			var monitorArgs = [];
			for (var k = 1; k < arguments.length; k++) monitorArgs.push(arguments[k]);
			var monitorListeners = events[errorMonitorSymbol];
			if (typeof monitorListeners === "function") _invokeListener(monitorListeners, this, monitorArgs);
			else {
				var monitorCopy = monitorListeners.slice();
				for (var k = 0; k < monitorCopy.length; k++) _invokeListener(monitorCopy[k], this, monitorArgs);
			}
		}
		doError = doError && events.error === void 0;
	} else doError = doError;
	if (doError) {
		var er = arguments.length > 1 ? arguments[1] : void 0;
		if (this.domain && typeof this.domain.emit === "function") {
			if (er === void 0 || er === null || er === false) er = /* @__PURE__ */ new Error("Unhandled error.");
			if (!(er instanceof Error)) this.domain.emit("error", er);
			else this.domain.emit("error", er);
			return false;
		}
		var unhandledErr = er;
		if (!(unhandledErr instanceof Error)) if (unhandledErr === void 0 || unhandledErr === null || unhandledErr === false) unhandledErr = /* @__PURE__ */ new Error("Unhandled error.");
		else {
			var unhandledErrStringified = _safeInspectUnhandledError(unhandledErr);
			unhandledErr = /* @__PURE__ */ new Error("Unhandled error." + (unhandledErr !== void 0 ? " (" + unhandledErrStringified + ")" : ""));
			unhandledErr.code = "ERR_UNHANDLED_ERROR";
			unhandledErr.context = er;
		}
		if (typeof globalThis.__exactUncaughtExceptionHandler === "function") {
			if (globalThis.__exactUncaughtExceptionHandler(unhandledErr)) return false;
		}
		if (unhandledErr instanceof Error) throw unhandledErr;
		throw unhandledErr;
	}
	var handler = events ? events[eventName] : void 0;
	if (handler === void 0) return false;
	var args = [];
	for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
	if (typeof handler === "function") {
		if (_exactDebugEmitListener && typeof handler !== "function") {
			console.error("[stream-debug] emit non-function handler", eventName, typeof handler, handler);
			console.error((/* @__PURE__ */ new Error()).stack);
		}
		_maybeCaptureRejection(this, _invokeListener(handler, this, args), eventName, args);
	} else {
		var current = handler.slice();
		if (_exactDebugEmitListener) {
			for (var i = 0; i < current.length; i++) if (typeof current[i] !== "function") {
				console.error("[stream-debug] emit list non-function handler", eventName, i, typeof current[i], current[i]);
				console.error((/* @__PURE__ */ new Error()).stack);
			}
		}
		for (var i = 0; i < current.length; i++) _maybeCaptureRejection(this, _invokeListener(current[i], this, args), eventName, args);
	}
	return true;
};
EventEmitter.prototype.listeners = function listeners(eventName) {
	var events = this._events;
	if (events === void 0) return [];
	var list = events[eventName];
	if (list === void 0) return [];
	if (typeof list === "function") return [list.listener || list];
	var out = [];
	for (var i = 0; i < list.length; i++) out.push(list[i].listener || list[i]);
	return out;
};
EventEmitter.prototype.rawListeners = function rawListeners(eventName) {
	var events = this._events;
	if (events === void 0) return [];
	var list = events[eventName];
	if (list === void 0) return [];
	if (typeof list === "function") return [list];
	return list.slice();
};
EventEmitter.prototype.listenerCount = function listenerCount(eventName, listener) {
	var events = this._events;
	if (events === void 0) return 0;
	var list = events[eventName];
	if (list === void 0) return 0;
	if (listener !== void 0) {
		var count = 0;
		if (typeof list === "function") {
			if (list === listener || list.listener === listener) count = 1;
		} else for (var i = 0; i < list.length; i++) if (list[i] === listener || list[i].listener && list[i].listener === listener) count++;
		return count;
	}
	if (typeof list === "function") return 1;
	return list.length;
};
EventEmitter.prototype.eventNames = function eventNames() {
	if (this._events === void 0) return [];
	var keys = Reflect.ownKeys(this._events);
	var result = [];
	for (var i = 0; i < keys.length; i++) if (this._events[keys[i]] !== void 0) result.push(keys[i]);
	return result;
};
function once(emitter, eventName, options) {
	return new Promise(function(resolve, reject) {
		if (!(emitter !== null && (typeof emitter === "object" || typeof emitter === "function"))) return reject(_invalidArgType("emitter", emitter));
		if (options !== void 0) {
			if (options === null || typeof options !== "object") return reject(_invalidArgType("options", options));
			if (options.signal !== void 0) {
				if (options.signal === null || typeof options.signal !== "object" && typeof options.signal !== "function" || typeof options.signal.addEventListener !== "function" || typeof options.signal.removeEventListener !== "function") {
					var signalType = options.signal === null ? "null" : typeof options.signal;
					var signalErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an AbortSignal. Received " + (signalType === "object" && options.signal && options.signal.constructor && options.signal.constructor.name ? "an instance of " + options.signal.constructor.name : signalType));
					signalErr.code = "ERR_INVALID_ARG_TYPE";
					return reject(signalErr);
				}
			}
		}
		var signal = options && options.signal;
		var removeSignalListener = null;
		var removeErrorListener = null;
		var cleanup = function() {
			if (typeof removeEventListenerFromEmitter === "function") removeEventListenerFromEmitter();
			if (typeof removeErrorListener === "function") removeErrorListener();
			if (typeof removeSignalListener === "function") removeSignalListener();
			removeEventListenerFromEmitter = null;
			removeErrorListener = null;
			removeSignalListener = null;
			isFinished = true;
		};
		var isFinished = false;
		function onAbort() {
			if (isFinished) return;
			cleanup();
			var reason = signal && signal.reason;
			if (reason === void 0) reason = new (globalThis.DOMException || Error)("The operation was aborted.", "AbortError");
			reject(reason);
		}
		function onError(err) {
			if (isFinished) return;
			cleanup();
			reject(err);
		}
		function resolver() {
			if (isFinished) return;
			cleanup();
			var args = [];
			for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
			resolve(args);
		}
		var removeEventListenerFromEmitter;
		try {
			removeEventListenerFromEmitter = eventTargetAgnosticAddListener(emitter, eventName, resolver, { once: true });
		} catch (err) {
			if (signal) {
				if (signal.aborted) return onAbort();
			}
			return reject(err);
		}
		if (signal) {
			if (signal.aborted) {
				cleanup();
				return onAbort();
			}
			removeSignalListener = eventTargetAgnosticAddListener(signal, "abort", onAbort, { once: true });
		}
		if (eventName !== "error" && typeof emitter.on === "function") removeErrorListener = eventTargetAgnosticAddListener(emitter, "error", onError, { once: true });
	});
}
function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
	if (typeof emitter.on === "function") {
		if (flags && flags.once) emitter.once(name, listener);
		else emitter.on(name, listener);
		return function() {
			if (typeof emitter.removeListener === "function") emitter.removeListener(name, listener);
			else if (typeof emitter.off === "function") emitter.off(name, listener);
		};
	} else if (typeof emitter.addEventListener === "function") {
		function wrapListener(arg) {
			if (flags && flags.once) emitter.removeEventListener(name, wrapListener);
			listener(arg);
		}
		emitter.addEventListener(name, wrapListener, flags);
		return function() {
			emitter.removeEventListener(name, wrapListener, flags);
		};
	}
	var err = _invalidArgType("emitter", emitter);
	err.message = "The \"emitter\" argument must be an instance of EventEmitter";
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function on(emitter, eventName, options) {
	if (!(emitter !== null && (typeof emitter === "object" || typeof emitter === "function"))) throw _invalidArgType("emitter", emitter);
	if (options !== void 0) {
		if (options === null || typeof options !== "object") throw _invalidArgType("options", options);
		if (options.signal !== void 0) {
			if (options.signal === null || typeof options.signal !== "object" && typeof options.signal !== "function" || typeof options.signal.addEventListener !== "function") {
				var signalType = options.signal === null ? "null" : typeof options.signal;
				var signalErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an AbortSignal. Received " + signalType);
				signalErr.code = "ERR_INVALID_ARG_TYPE";
				throw signalErr;
			}
			if (options.signal.aborted) {
				var abortErr = new (typeof DOMException === "function" ? DOMException : Error)("The operation was aborted", "AbortError");
				abortErr.code = "ABORT_ERR";
				throw abortErr;
			}
		}
	}
	var unconsumed = [];
	var waiting = [];
	var done = false;
	var errored = null;
	var signal = options && options.signal;
	var removeSignalListener = null;
	function handler() {
		var args = [];
		for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
		if (waiting.length > 0) waiting.shift().resolve({
			value: args,
			done: false
		});
		else unconsumed.push(args);
	}
	function errorHandler(err) {
		done = true;
		errored = err;
		if (waiting.length > 0) waiting.shift().reject(err);
		while (waiting.length > 0) waiting.shift().resolve({
			value: void 0,
			done: true
		});
		cleanup();
	}
	function cleanup() {
		if (typeof emitter.removeListener === "function") {
			emitter.removeListener(eventName, handler);
			if (eventName !== "error") emitter.removeListener("error", errorHandler);
		} else if (typeof emitter.removeEventListener === "function") emitter.removeEventListener(eventName, eventTargetHandler);
		if (typeof removeSignalListener === "function") {
			removeSignalListener();
			removeSignalListener = null;
		}
	}
	var eventTargetHandler;
	if (typeof emitter.on === "function") {
		emitter.on(eventName, handler);
		if (eventName !== "error") emitter.on("error", errorHandler);
	} else if (typeof emitter.addEventListener === "function") {
		eventTargetHandler = function(event) {
			handler(event);
		};
		emitter.addEventListener(eventName, eventTargetHandler);
	}
	if (signal) {
		var onAbort = function() {
			var abortError = new (typeof DOMException === "function" ? DOMException : Error)("The operation was aborted", "AbortError");
			abortError.code = "ABORT_ERR";
			done = true;
			errored = abortError;
			if (waiting.length > 0) waiting.shift().reject(abortError);
			while (waiting.length > 0) waiting.shift().resolve({
				value: void 0,
				done: true
			});
			cleanup();
		};
		signal.addEventListener("abort", onAbort);
		removeSignalListener = function() {
			signal.removeEventListener("abort", onAbort);
		};
	}
	var iterator = {};
	iterator.next = function() {
		if (unconsumed.length > 0) return Promise.resolve({
			value: unconsumed.shift(),
			done: false
		});
		if (errored) {
			var err = errored;
			errored = null;
			done = true;
			return Promise.reject(err);
		}
		if (done) return Promise.resolve({
			value: void 0,
			done: true
		});
		return new Promise(function(resolve, reject) {
			waiting.push({
				resolve,
				reject
			});
		});
	};
	iterator.return = function() {
		done = true;
		cleanup();
		while (waiting.length > 0) waiting.shift().resolve({
			value: void 0,
			done: true
		});
		return Promise.resolve({
			value: void 0,
			done: true
		});
	};
	iterator.throw = function(err) {
		if (err !== void 0 && !(err instanceof Error)) {
			var typeErr = /* @__PURE__ */ new TypeError("The \"EventEmitter.AsyncIterator\" property must be an instance of Error. Received " + (err === void 0 ? "undefined" : typeof err));
			typeErr.code = "ERR_INVALID_ARG_TYPE";
			throw typeErr;
		}
		errored = err;
		done = true;
		cleanup();
		if (waiting.length > 0) waiting.shift().reject(err);
		while (waiting.length > 0) waiting.shift().resolve({
			value: void 0,
			done: true
		});
		return Promise.resolve({
			value: void 0,
			done: true
		});
	};
	iterator[Symbol.asyncIterator] = function() {
		return iterator;
	};
	return iterator;
}
function getEventListeners(emitter, eventName) {
	if (typeof emitter !== "object" || emitter === null) {
		var err = /* @__PURE__ */ new TypeError("[ERR_INVALID_ARG_TYPE]: The \"emitter\" argument must be an instance of EventEmitter or EventTarget. Received type " + typeof emitter + " (" + String(emitter) + ")");
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (typeof emitter.listeners === "function") return emitter.listeners(eventName);
	if (emitter[eventTargetEventsSymbol] && typeof emitter[eventTargetEventsSymbol].get === "function") {
		var tracked = emitter[eventTargetEventsSymbol].get(eventName);
		if (!tracked) return [];
		return Array.from(tracked);
	}
	if (emitter._listeners && !Array.isArray(emitter._listeners) && emitter._listeners[eventName]) return emitter._listeners[eventName].map(function(l) {
		return l.fn;
	});
	if (eventName === "abort" && Array.isArray(emitter._listeners) && emitter._listeners.length > 0) return emitter._listeners.map(function(l) {
		return l._original || l;
	});
	return [];
}
function _listenerCount(emitter, eventName) {
	if (typeof emitter.listenerCount === "function") return emitter.listenerCount(eventName);
	return EventEmitter.prototype.listenerCount.call(emitter, eventName);
}
function getMaxListeners(emitter) {
	if (typeof emitter.getMaxListeners === "function") return emitter.getMaxListeners();
	if (typeof AbortSignal !== "undefined" && emitter instanceof AbortSignal) return emitter._maxListeners !== void 0 ? emitter._maxListeners : 0;
	return _getMaxListeners(emitter);
}
function setMaxListeners(n) {
	if (typeof n !== "number" || n < 0 || n !== n) {
		var err;
		if (typeof n !== "number") {
			err = /* @__PURE__ */ new TypeError("The \"n\" argument must be of type number. Received type " + typeof n);
			err.code = "ERR_INVALID_ARG_TYPE";
		} else {
			err = /* @__PURE__ */ new RangeError("The value of \"n\" is out of range. It must be a non-negative number. Received " + n);
			err.code = "ERR_OUT_OF_RANGE";
		}
		throw err;
	}
	for (var i = 1; i < arguments.length; i++) {
		var emitter = arguments[i];
		if (emitter === void 0 || emitter === null || typeof emitter !== "object" && typeof emitter !== "function") {
			var argErr = /* @__PURE__ */ new TypeError("The \"eventTargets[" + (i - 1) + "]\" argument must be an instance of EventTarget or EventEmitter");
			argErr.code = "ERR_INVALID_ARG_TYPE";
			throw argErr;
		}
		if (typeof emitter.setMaxListeners === "function") emitter.setMaxListeners(n);
		else emitter._maxListeners = n;
	}
	if (arguments.length <= 1) EventEmitter.defaultMaxListeners = n;
}
EventEmitter.EventEmitter = EventEmitter;
EventEmitter.EventEmitterAsyncResource = EventEmitterAsyncResource;
EventEmitter.once = once;
EventEmitter.on = on;
EventEmitter.getEventListeners = getEventListeners;
EventEmitter.listenerCount = _listenerCount;
EventEmitter.getMaxListeners = getMaxListeners;
EventEmitter.setMaxListeners = setMaxListeners;
EventEmitter.errorMonitor = errorMonitorSymbol;
EventEmitter.captureRejectionSymbol = captureRejectionSymbol;
EventEmitter.init = EventEmitter.init;
module.exports = EventEmitter;
module.exports.__esModule = true;
module.exports.EventEmitter = EventEmitter;
module.exports.EventEmitterAsyncResource = EventEmitterAsyncResource;
module.exports.default = EventEmitter;
module.exports.once = once;
module.exports.on = on;
module.exports.getEventListeners = getEventListeners;
module.exports.listenerCount = _listenerCount;
module.exports.getMaxListeners = getMaxListeners;
module.exports.setMaxListeners = setMaxListeners;
module.exports.errorMonitor = errorMonitorSymbol;
module.exports.defaultMaxListeners = EventEmitter.defaultMaxListeners;
module.exports.captureRejections = EventEmitter.captureRejections;
module.exports.captureRejectionSymbol = captureRejectionSymbol;
//#endregion
