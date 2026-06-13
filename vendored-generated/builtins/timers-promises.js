"use strict";
//#region src/builtins/timers-promises.js
var _nativeSetTimeout = globalThis.setTimeout;
var _nativeClearTimeout = globalThis.clearTimeout;
var _nativeSetInterval = globalThis.setInterval;
var _nativeClearInterval = globalThis.clearInterval;
function createAbortError(signal) {
	var err;
	if (signal && signal.reason !== void 0) {
		if (signal.reason instanceof Error) return signal.reason;
		err = /* @__PURE__ */ new Error("The operation was aborted");
		err.code = "ABORT_ERR";
		err.name = "AbortError";
		err.cause = signal.reason;
		return err;
	}
	err = /* @__PURE__ */ new Error("The operation was aborted");
	err.code = "ABORT_ERR";
	err.name = "AbortError";
	return err;
}
function setTimeoutPromise(delay, value, options) {
	if (delay !== void 0 && delay !== null && typeof delay !== "number") {
		if (typeof delay === "string" || typeof delay === "boolean") {
			var delayErr = /* @__PURE__ */ new TypeError("The \"delay\" argument must be of type number. Received type " + typeof delay);
			delayErr.code = "ERR_INVALID_ARG_TYPE";
			return Promise.reject(delayErr);
		}
	}
	var delayMs = delay == null ? 1 : Math.max(1, Number(delay) | 0);
	if (options !== void 0 && options !== null) {
		if (typeof options !== "object" || Array.isArray(options)) {
			var err = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + (options === null ? "null" : typeof options) + " (" + String(options) + ")");
			err.code = "ERR_INVALID_ARG_TYPE";
			return Promise.reject(err);
		}
		var signal = options.signal;
		if (signal !== void 0) {
			if (signal === null || typeof signal !== "object" || typeof signal.aborted !== "boolean") {
				var sigErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received type " + (signal === null ? "null" : typeof signal));
				sigErr.code = "ERR_INVALID_ARG_TYPE";
				return Promise.reject(sigErr);
			}
		}
		var ref = options.ref;
		if (ref !== void 0 && typeof ref !== "boolean") {
			var refErr = /* @__PURE__ */ new TypeError("The \"options.ref\" property must be of type boolean. Received type " + (ref === null ? "null" : typeof ref));
			refErr.code = "ERR_INVALID_ARG_TYPE";
			return Promise.reject(refErr);
		}
		if (signal && signal.aborted) return Promise.reject(createAbortError(signal));
	}
	var optSignal = options && options.signal;
	var optRef = options && options.ref;
	return new Promise(function(resolve, reject) {
		if (optSignal && optSignal.aborted) return reject(createAbortError(optSignal));
		var handle = _nativeSetTimeout(function() {
			if (optSignal) optSignal.removeEventListener("abort", onAbort);
			resolve(value);
		}, delayMs);
		if (optRef === false && handle && typeof handle.unref === "function") handle.unref();
		function onAbort() {
			if (handle) {
				if (typeof handle.close === "function") handle.close();
				else if (typeof _nativeClearTimeout === "function") _nativeClearTimeout(handle);
			}
			reject(createAbortError(optSignal));
		}
		if (optSignal) optSignal.addEventListener("abort", onAbort, { once: true });
	});
}
function setImmediatePromise(value, options) {
	if (options !== void 0 && options !== null) {
		if (typeof options !== "object" || Array.isArray(options)) {
			var err = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + (options === null ? "null" : typeof options) + " (" + String(options) + ")");
			err.code = "ERR_INVALID_ARG_TYPE";
			return Promise.reject(err);
		}
		var signal = options.signal;
		if (signal !== void 0) {
			if (signal === null || typeof signal !== "object" || typeof signal.aborted !== "boolean") {
				var sigErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received type " + (signal === null ? "null" : typeof signal));
				sigErr.code = "ERR_INVALID_ARG_TYPE";
				return Promise.reject(sigErr);
			}
		}
		var ref = options.ref;
		if (ref !== void 0 && typeof ref !== "boolean") {
			var refErr = /* @__PURE__ */ new TypeError("The \"options.ref\" property must be of type boolean. Received type " + (ref === null ? "null" : typeof ref));
			refErr.code = "ERR_INVALID_ARG_TYPE";
			return Promise.reject(refErr);
		}
	}
	var optSignal = options && options.signal;
	var optRef = options && options.ref;
	if (optSignal && optSignal.aborted) return Promise.reject(createAbortError(optSignal));
	return new Promise(function(resolve, reject) {
		var handle = _nativeSetTimeout(function() {
			if (optSignal) optSignal.removeEventListener("abort", onAbort);
			resolve(value);
		}, 0);
		if (optRef === false && handle && typeof handle.unref === "function") handle.unref();
		function onAbort() {
			if (handle) {
				if (typeof handle.close === "function") handle.close();
				else if (typeof _nativeClearTimeout === "function") _nativeClearTimeout(handle);
			}
			reject(createAbortError(optSignal));
		}
		if (optSignal) optSignal.addEventListener("abort", onAbort, { once: true });
	});
}
function setIntervalIterable(delay, value, options) {
	var optSignal, optRef;
	if (options !== void 0 && options !== null) {
		if (typeof options !== "object" || Array.isArray(options)) {
			var optErr = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type " + (options === null ? "null" : typeof options) + " (" + String(options) + ")");
			optErr.code = "ERR_INVALID_ARG_TYPE";
			return makeEagerRejectIterable(optErr);
		}
		optSignal = options.signal;
		if (optSignal !== void 0) {
			if (optSignal === null || typeof optSignal !== "object" || typeof optSignal.aborted !== "boolean") {
				var sigErr = /* @__PURE__ */ new TypeError("The \"options.signal\" property must be an instance of AbortSignal. Received type " + (optSignal === null ? "null" : typeof optSignal));
				sigErr.code = "ERR_INVALID_ARG_TYPE";
				return makeEagerRejectIterable(sigErr);
			}
		}
		optRef = options.ref;
		if (optRef !== void 0 && typeof optRef !== "boolean") {
			var refErr = /* @__PURE__ */ new TypeError("The \"options.ref\" property must be of type boolean. Received type " + (optRef === null ? "null" : typeof optRef));
			refErr.code = "ERR_INVALID_ARG_TYPE";
			return makeEagerRejectIterable(refErr);
		}
	}
	return makeSetIntervalIterable(delay == null ? 1 : Math.max(1, Number(delay) | 0), value, optSignal, optRef);
}
function makeEagerRejectIterable(err) {
	var obj = {};
	obj[Symbol.asyncIterator] = function() {
		var done = false;
		return {
			next: function() {
				if (done) return Promise.resolve({
					value: void 0,
					done: true
				});
				done = true;
				return Promise.reject(err);
			},
			return: function() {
				done = true;
				return Promise.resolve({
					value: void 0,
					done: true
				});
			}
		};
	};
	return obj;
}
function makeSetIntervalIterable(delayMs, value, signal, ref) {
	var aborted = false;
	var abortError = null;
	var pendingResolve = null;
	var pendingReject = null;
	var handle = null;
	var listenerRemoved = false;
	function cleanup() {
		if (handle) {
			if (_nativeClearInterval) _nativeClearInterval(handle);
			else if (handle.close) handle.close();
			handle = null;
		}
		if (signal && !listenerRemoved) {
			listenerRemoved = true;
			signal.removeEventListener("abort", onAbort);
		}
	}
	function onAbort() {
		aborted = true;
		abortError = createAbortError(signal);
		cleanup();
		if (pendingReject) {
			var rej = pendingReject;
			pendingResolve = null;
			pendingReject = null;
			rej(abortError);
		}
	}
	if (signal) if (signal.aborted) {
		aborted = true;
		abortError = createAbortError(signal);
	} else signal.addEventListener("abort", onAbort, { once: true });
	function scheduleNext() {
		handle = _nativeSetInterval(function() {
			if (pendingResolve) {
				var res = pendingResolve;
				pendingResolve = null;
				pendingReject = null;
				res({
					value,
					done: false
				});
			}
		}, delayMs);
		if (ref === false && handle && typeof handle.unref === "function") handle.unref();
	}
	var obj = {
		next: function() {
			if (aborted) return Promise.reject(abortError);
			return new Promise(function(resolve, reject) {
				if (aborted) return reject(abortError);
				pendingResolve = function(result) {
					if (handle) {
						_nativeClearInterval(handle);
						handle = null;
					}
					resolve(result);
				};
				pendingReject = reject;
				scheduleNext();
			});
		},
		return: function() {
			cleanup();
			return Promise.resolve({
				value: void 0,
				done: true
			});
		}
	};
	obj[Symbol.asyncIterator] = function() {
		return obj;
	};
	return obj;
}
function schedulerYield() {
	return new Promise(function(resolve) {
		_nativeSetTimeout(resolve, 0);
	});
}
function schedulerWait(delay, options) {
	return setTimeoutPromise(delay, void 0, options);
}
function Scheduler() {
	var err = /* @__PURE__ */ new TypeError("Illegal constructor");
	err.code = "ERR_ILLEGAL_CONSTRUCTOR";
	throw err;
}
Scheduler.prototype["yield"] = schedulerYield;
Scheduler.prototype["wait"] = schedulerWait;
var scheduler = Object.create(Scheduler.prototype);
scheduler.constructor = Scheduler;
module.exports = {
	setTimeout: setTimeoutPromise,
	setImmediate: setImmediatePromise,
	setInterval: setIntervalIterable,
	scheduler
};
//#endregion
