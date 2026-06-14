//#region src/builtins/perf-hooks.js
var _perfStart = Date.now();
var _marks = [];
var _measures = [];
var _resources = [];
var _observers = [];
var _isMainThread = true;
try {
	var _workerThreads = require("worker_threads");
	if (_workerThreads && _workerThreads.isMainThread === false) _isMainThread = false;
} catch (_) {
	_isMainThread = true;
}
var _loopSampleTime = Date.now();
var _loopActive = 0;
var _loopIdle = 0;
var _loopInitialized = false;
var _histogramSecret = {};
function _perfNow() {
	if (typeof __exactHrtime === "function") {
		var parts = __exactHrtime();
		if (typeof parts === "string") {
			var p = parts.split(",");
			return parseInt(p[0], 10) * 1e3 + parseInt(p[1], 10) / 1e6;
		}
	}
	return Date.now() - _perfStart;
}
function _invalidArgType(message) {
	var err = new TypeError(message);
	err.code = "ERR_INVALID_ARG_TYPE";
	return err;
}
function _outOfRange(message) {
	var err = new RangeError(message);
	err.code = "ERR_OUT_OF_RANGE";
	return err;
}
function _illegalConstructor() {
	var err = /* @__PURE__ */ new TypeError("Illegal constructor");
	err.code = "ERR_ILLEGAL_CONSTRUCTOR";
	return err;
}
function _syntaxDomException(message) {
	if (typeof DOMException === "function") return new DOMException(message, "SyntaxError");
	var err = new Error(message);
	err.name = "SyntaxError";
	return err;
}
function _dataCloneException(message) {
	if (typeof DOMException === "function") return new DOMException(message || "The object could not be cloned.", "DataCloneError");
	var err = new Error(message || "The object could not be cloned.");
	err.name = "DataCloneError";
	return err;
}
function _cloneDetail(detail) {
	if (detail === void 0 || detail === null) return null;
	if (typeof structuredClone === "function") return structuredClone(detail);
	try {
		return JSON.parse(JSON.stringify(detail));
	} catch (_cloneErr) {
		throw _dataCloneException();
	}
}
function _isObjectLike(value) {
	return value !== null && (typeof value === "object" || typeof value === "function");
}
function _validateObjectOptions(kind, options) {
	if (options === void 0 || options === null) return {};
	if (!_isObjectLike(options)) throw new TypeError("Failed to construct '" + kind + "': parameter 2 is not an object.");
	return options;
}
function _validateTimestampValue(name, value) {
	if (typeof value !== "number" || !isFinite(value) || value < 0) throw new TypeError("Failed to execute '" + name + "': timestamp must be a finite, non-negative number.");
	return value;
}
function _hasOwn(obj, key) {
	return !!obj && Object.prototype.hasOwnProperty.call(obj, key);
}
function _hasMeasureOptionsKeys(value) {
	return _hasOwn(value, "start") || _hasOwn(value, "end") || _hasOwn(value, "duration") || _hasOwn(value, "detail");
}
function _scheduleObserverFlush(observer) {
	if (!observer || observer._flushScheduled || !observer._callback || observer._entryQueue.length === 0) return;
	observer._flushScheduled = true;
	queueMicrotask(function() {
		observer._flushScheduled = false;
		if (!observer._callback || observer._entryQueue.length === 0) return;
		var entries = observer._entryQueue.slice();
		observer._entryQueue.length = 0;
		try {
			observer._callback({
				getEntries: function() {
					return entries.slice();
				},
				getEntriesByName: function(n, type) {
					var result = [];
					for (var j = 0; j < entries.length; j++) if (entries[j].name === n && (!type || entries[j].entryType === type)) result.push(entries[j]);
					return result;
				},
				getEntriesByType: function(t) {
					var result = [];
					for (var j = 0; j < entries.length; j++) if (entries[j].entryType === t) result.push(entries[j]);
					return result;
				}
			}, observer);
		} catch (e) {
			if (typeof queueMicrotask === "function") queueMicrotask(function() {
				throw e;
			});
			else if (typeof setTimeout === "function") setTimeout(function() {
				throw e;
			}, 0);
		}
	});
}
function _freezePrototypeProperty(ctor) {
	if (!ctor || typeof ctor !== "function" && typeof ctor !== "object") return;
	try {
		Object.defineProperty(ctor, "prototype", { writable: false });
	} catch (_err) {}
}
function _setFunctionName(fn, name) {
	if (typeof fn !== "function") return fn;
	try {
		Object.defineProperty(fn, "name", {
			configurable: true,
			value: name
		});
	} catch (_err) {}
	return fn;
}
function _requirePerformanceReceiver(value) {
	if (!(value instanceof Performance)) throw _illegalConstructor();
}
function _requireArgumentCount(actual, required) {
	if (actual < required) throw new TypeError(required + " argument required, but only " + actual + " present.");
}
function _toArray(args) {
	var list = [];
	for (var i = 0; i < args.length; i++) list[i] = args[i];
	return list;
}
function _updateNodeTiming() {
	_nodeTiming.duration = _perfNow();
	_nodeTiming.idleTime = _loopIdle;
	if (!_isMainThread && _nodeTiming.loopStart < _nodeTiming.bootstrapComplete) _nodeTiming.loopStart = _nodeTiming.bootstrapComplete;
}
function _notifyObservers(entry) {
	for (var i = 0; i < _observers.length; i++) {
		var obs = _observers[i];
		if (obs._entryTypes && obs._entryTypes.indexOf(entry.entryType) !== -1) {
			obs._entryQueue.push(entry);
			_scheduleObserverFlush(obs);
		}
	}
}
function _refreshLoopUtilization() {
	var now = Date.now();
	if (!_loopInitialized) {
		_loopInitialized = true;
		_loopSampleTime = now;
		return;
	}
	var delta = now - _loopSampleTime;
	if (delta < 0) delta = 0;
	_loopSampleTime = now;
	if (_loopActive === 0 && _loopIdle === 0 && delta <= 20) _loopIdle += delta;
	else _loopActive += delta;
}
function _normalizeElu(value) {
	if (!value || typeof value !== "object") return null;
	if (typeof value.active !== "number" || typeof value.idle !== "number") return null;
	return {
		active: value.active,
		idle: value.idle
	};
}
function _diffElu(first, second) {
	if (!first || !second) return null;
	var active = first.active - second.active;
	var idle = first.idle - second.idle;
	if (active < 0) active = 0;
	if (idle < 0) idle = 0;
	var total = active + idle;
	return {
		idle,
		active,
		utilization: total === 0 ? 0 : active / total
	};
}
function _currentElu() {
	_refreshLoopUtilization();
	var total = _loopActive + _loopIdle;
	return {
		active: _loopActive,
		idle: _loopIdle,
		utilization: total === 0 ? 0 : _loopActive / total
	};
}
function eventLoopUtilization(start, end) {
	_updateNodeTiming();
	var current = _currentElu();
	if (_isMainThread && _nodeTiming.loopStart === -1 && start && start.active === 0 && start.idle === 0) return {
		idle: 0,
		active: 0,
		utilization: 0
	};
	if (start && end) return _diffElu(_normalizeElu(start), _normalizeElu(end));
	if (start) {
		var base = _normalizeElu(start);
		if (base) return _diffElu(current, base);
	}
	return current;
}
var _allowPerformanceEntryConstruction = false;
function PerformanceEntry() {
	if (!_allowPerformanceEntryConstruction) throw _illegalConstructor();
	var name = arguments[0];
	var entryType = arguments[1];
	var startTime = arguments[2];
	var duration = arguments[3];
	this.name = name;
	this.entryType = entryType;
	this.startTime = startTime;
	this.duration = duration;
}
PerformanceEntry.prototype.toJSON = function() {
	return {
		name: this.name,
		entryType: this.entryType,
		startTime: this.startTime,
		duration: this.duration
	};
};
Object.defineProperty(PerformanceEntry.prototype, Symbol.toStringTag, {
	configurable: true,
	enumerable: false,
	writable: false,
	value: "PerformanceEntry"
});
function PerformanceMark(name) {
	if (!(this instanceof PerformanceMark)) throw _illegalConstructor();
	var options = arguments[1];
	options = _validateObjectOptions("PerformanceMark", options);
	var startTime = options.startTime !== void 0 ? options.startTime : _perfNow();
	if (typeof startTime !== "number") throw _invalidArgType("The \"startTime\" argument must be of type number. Received type " + typeof startTime);
	_validateTimestampValue("mark", startTime);
	_allowPerformanceEntryConstruction = true;
	PerformanceEntry.call(this, String(name), "mark", startTime, 0);
	_allowPerformanceEntryConstruction = false;
	this._detail = _cloneDetail(options.detail);
}
PerformanceMark.prototype = Object.create(PerformanceEntry.prototype);
Object.defineProperty(PerformanceMark.prototype, "constructor", {
	configurable: true,
	enumerable: false,
	writable: true,
	value: PerformanceMark
});
var _performanceMarkDetailGetter = function() {
	if (!(this instanceof PerformanceMark)) throw _illegalConstructor();
	return this._detail;
};
try {
	Object.defineProperty(_performanceMarkDetailGetter, "name", {
		configurable: true,
		value: "get detail"
	});
} catch (_performanceMarkDetailGetterNameErr) {}
Object.defineProperty(PerformanceMark.prototype, "detail", {
	configurable: true,
	enumerable: true,
	get: _performanceMarkDetailGetter
});
Object.defineProperty(PerformanceMark.prototype, Symbol.toStringTag, {
	configurable: true,
	enumerable: false,
	writable: false,
	value: "PerformanceMark"
});
var _performanceMeasureSecret = {};
function PerformanceMeasure() {
	var name = arguments[0];
	var startTime = arguments[1];
	var duration = arguments[2];
	var detail = arguments[3];
	if (arguments[4] !== _performanceMeasureSecret) throw _illegalConstructor();
	_allowPerformanceEntryConstruction = true;
	PerformanceEntry.call(this, name, "measure", startTime, duration);
	_allowPerformanceEntryConstruction = false;
	this._detail = _cloneDetail(detail);
}
PerformanceMeasure.prototype = Object.create(PerformanceEntry.prototype);
Object.defineProperty(PerformanceMeasure.prototype, "constructor", {
	configurable: true,
	enumerable: false,
	writable: true,
	value: PerformanceMeasure
});
var _performanceMeasureDetailGetter = function() {
	if (!(this instanceof PerformanceMeasure)) throw _illegalConstructor();
	return this._detail;
};
try {
	Object.defineProperty(_performanceMeasureDetailGetter, "name", {
		configurable: true,
		value: "get detail"
	});
} catch (_performanceMeasureDetailGetterNameErr) {}
Object.defineProperty(PerformanceMeasure.prototype, "detail", {
	configurable: true,
	enumerable: true,
	get: _performanceMeasureDetailGetter
});
Object.defineProperty(PerformanceMeasure.prototype, Symbol.toStringTag, {
	configurable: true,
	enumerable: false,
	writable: false,
	value: "PerformanceMeasure"
});
var _allowPerformanceResourceTimingConstruction = false;
function PerformanceResourceTiming() {
	var config = arguments[0];
	var secret = arguments[1];
	if (!_allowPerformanceResourceTimingConstruction && secret !== _histogramSecret) throw _illegalConstructor();
	config = config || {};
	_allowPerformanceEntryConstruction = true;
	PerformanceEntry.call(this, config.name || "", "resource", config.startTime || 0, config.duration || 0);
	_allowPerformanceEntryConstruction = false;
	this.initiatorType = config.initiatorType || "";
	this.nextHopProtocol = config.nextHopProtocol || [];
	this.workerStart = config.workerStart || 0;
	this.redirectStart = config.redirectStart || 0;
	this.redirectEnd = config.redirectEnd || 0;
	this.fetchStart = config.fetchStart || 0;
	this.domainLookupStart = config.domainLookupStart || 0;
	this.domainLookupEnd = config.domainLookupEnd || 0;
	this.connectStart = config.connectStart || 0;
	this.connectEnd = config.connectEnd || 0;
	this.secureConnectionStart = config.secureConnectionStart || 0;
	this.requestStart = config.requestStart || 0;
	this.responseStart = config.responseStart || 0;
	this.responseEnd = config.responseEnd || 0;
	this.transferSize = config.transferSize || 0;
	this.encodedBodySize = config.encodedBodySize || 0;
	this.decodedBodySize = config.decodedBodySize || 0;
	this.deliveryType = config.deliveryType || "";
	this.responseStatus = config.responseStatus || 0;
}
PerformanceResourceTiming.prototype = Object.create(PerformanceEntry.prototype);
Object.defineProperty(PerformanceResourceTiming.prototype, "constructor", {
	configurable: true,
	enumerable: false,
	writable: true,
	value: PerformanceResourceTiming
});
PerformanceResourceTiming.prototype.toJSON = function() {
	return {
		name: this.name,
		entryType: this.entryType,
		startTime: this.startTime,
		duration: this.duration,
		initiatorType: this.initiatorType,
		nextHopProtocol: this.nextHopProtocol,
		workerStart: this.workerStart,
		redirectStart: this.redirectStart,
		redirectEnd: this.redirectEnd,
		fetchStart: this.fetchStart,
		domainLookupStart: this.domainLookupStart,
		domainLookupEnd: this.domainLookupEnd,
		connectStart: this.connectStart,
		connectEnd: this.connectEnd,
		secureConnectionStart: this.secureConnectionStart,
		requestStart: this.requestStart,
		responseStart: this.responseStart,
		responseEnd: this.responseEnd,
		transferSize: this.transferSize,
		encodedBodySize: this.encodedBodySize,
		decodedBodySize: this.decodedBodySize,
		responseStatus: this.responseStatus,
		deliveryType: this.deliveryType
	};
};
Object.defineProperty(PerformanceResourceTiming.prototype, Symbol.toStringTag, {
	configurable: true,
	enumerable: false,
	writable: false,
	value: "PerformanceResourceTiming"
});
if (typeof Object.setPrototypeOf === "function") {
	Object.setPrototypeOf(PerformanceMark, PerformanceEntry);
	Object.setPrototypeOf(PerformanceMeasure, PerformanceEntry);
	Object.setPrototypeOf(PerformanceResourceTiming, PerformanceEntry);
}
_freezePrototypeProperty(PerformanceEntry);
_freezePrototypeProperty(PerformanceMark);
_freezePrototypeProperty(PerformanceMeasure);
_freezePrototypeProperty(PerformanceObserver);
_freezePrototypeProperty(PerformanceResourceTiming);
function Performance() {}
Performance.prototype.now = function() {
	_requirePerformanceReceiver(this);
	var t = _perfNow();
	_updateNodeTiming();
	return t;
};
Performance.prototype.timeOrigin = _perfStart;
Performance.prototype.mark = function(name) {
	_requirePerformanceReceiver(this);
	_requireArgumentCount(arguments.length, 1);
	var options = arguments[1];
	_updateNodeTiming();
	if (typeof name === "symbol") throw new TypeError("Cannot convert a Symbol value to a string");
	var entry = new PerformanceMark(name, options);
	_marks.push(entry);
	_notifyObservers(entry);
	return entry;
};
Performance.prototype.measure = function(name) {
	_requirePerformanceReceiver(this);
	_requireArgumentCount(arguments.length, 1);
	var startMarkOrOptions = arguments[1];
	var endMark = arguments[2];
	_updateNodeTiming();
	var startTime = 0;
	var endTime = _perfNow();
	var duration;
	var detail;
	var hasEndArgument = arguments.length > 2;
	function _resolveMarkName(markName) {
		if (_nodeTiming[markName] !== void 0) return _nodeTiming[markName];
		for (var i = _marks.length - 1; i >= 0; i--) if (_marks[i].name === markName) return _marks[i].startTime;
		throw _syntaxDomException("Failed to execute 'measure': The mark '" + markName + "' does not exist.");
	}
	if (startMarkOrOptions && typeof startMarkOrOptions === "object" && !Array.isArray(startMarkOrOptions) && _hasMeasureOptionsKeys(startMarkOrOptions)) {
		var opts = startMarkOrOptions;
		if (hasEndArgument && endMark !== void 0) throw new TypeError("Failed to execute 'measure': end mark must be omitted when measure options are provided.");
		if (_hasOwn(opts, "detail")) detail = opts.detail;
		if (_hasOwn(opts, "start") && opts.start !== void 0) if (typeof opts.start === "string") startTime = _resolveMarkName(opts.start);
		else startTime = _validateTimestampValue("measure", opts.start);
		if (_hasOwn(opts, "end") && opts.end !== void 0) if (typeof opts.end === "string") endTime = _resolveMarkName(opts.end);
		else endTime = _validateTimestampValue("measure", opts.end);
		if (_hasOwn(opts, "duration") && opts.duration !== void 0) {
			duration = _validateTimestampValue("measure", opts.duration);
			if (opts.start !== void 0 && opts.end === void 0) endTime = startTime + duration;
			else if (opts.end !== void 0 && opts.start === void 0) startTime = endTime - duration;
		}
	} else if (typeof startMarkOrOptions === "string") {
		startTime = _resolveMarkName(startMarkOrOptions);
		if (typeof endMark === "string") endTime = _resolveMarkName(endMark);
	} else if (typeof endMark === "string") endTime = _resolveMarkName(endMark);
	if (duration === void 0) duration = endTime - startTime;
	var entry = new PerformanceMeasure(name, startTime, duration, detail, _performanceMeasureSecret);
	_measures.push(entry);
	_notifyObservers(entry);
	return entry;
};
Performance.prototype.getEntries = function() {
	_requirePerformanceReceiver(this);
	return _marks.concat(_measures, _resources).sort(function(a, b) {
		return a.startTime - b.startTime;
	});
};
Performance.prototype.getEntriesByName = function(name) {
	var type = arguments[1];
	_requirePerformanceReceiver(this);
	_requireArgumentCount(arguments.length, 1);
	var all = _marks.concat(_measures, _resources);
	var result = [];
	for (var i = 0; i < all.length; i++) if (all[i].name === name && (!type || all[i].entryType === type)) result.push(all[i]);
	return result.sort(function(a, b) {
		return a.startTime - b.startTime;
	});
};
Performance.prototype.getEntriesByType = function(type) {
	_requirePerformanceReceiver(this);
	_requireArgumentCount(arguments.length, 1);
	var all = _marks.concat(_measures, _resources);
	var result = [];
	for (var i = 0; i < all.length; i++) if (all[i].entryType === type) result.push(all[i]);
	return result.sort(function(a, b) {
		return a.startTime - b.startTime;
	});
};
Performance.prototype.clearMarks = function() {
	var name = arguments[0];
	_requirePerformanceReceiver(this);
	if (typeof name === "symbol") throw new TypeError("Cannot convert a Symbol value to a string");
	if (name === void 0) _marks = [];
	else {
		var nameStr = String(name);
		_marks = _marks.filter(function(m) {
			return m.name !== nameStr;
		});
	}
};
Performance.prototype.clearMeasures = function() {
	var name = arguments[0];
	_requirePerformanceReceiver(this);
	if (name === void 0) _measures = [];
	else _measures = _measures.filter(function(m) {
		return m.name !== name;
	});
};
Performance.prototype.clearResourceTimings = function() {
	_requirePerformanceReceiver(this);
	_resources = [];
};
Performance.prototype.markResourceTiming = function(timingInfo, requestedUrl, initiatorType, customGlobal, cacheMode, bodyInfo, responseStatus, deliveryType) {
	_requirePerformanceReceiver(this);
	var connectionInfo = timingInfo && timingInfo.finalConnectionTimingInfo || {};
	var encodedBodySize = timingInfo && timingInfo.encodedBodySize || 0;
	var duration = 0;
	if (timingInfo && typeof timingInfo.endTime === "number" && typeof timingInfo.startTime === "number") {
		duration = timingInfo.endTime - timingInfo.startTime;
		if (duration < 0) duration = 0;
	}
	var transferSize = cacheMode === "local" ? 0 : encodedBodySize + (encodedBodySize > 0 ? 300 : 0);
	_allowPerformanceResourceTimingConstruction = true;
	var entry = new PerformanceResourceTiming({
		name: requestedUrl,
		startTime: timingInfo && timingInfo.startTime || 0,
		duration,
		initiatorType: initiatorType || "",
		nextHopProtocol: connectionInfo.ALPNNegotiatedProtocol || [],
		workerStart: timingInfo && timingInfo.finalServiceWorkerStartTime || 0,
		redirectStart: timingInfo && timingInfo.redirectStartTime || 0,
		redirectEnd: timingInfo && timingInfo.redirectEndTime || 0,
		fetchStart: timingInfo && timingInfo.postRedirectStartTime || 0,
		domainLookupStart: connectionInfo.domainLookupStartTime || 0,
		domainLookupEnd: connectionInfo.domainLookupEndTime || 0,
		connectStart: connectionInfo.connectionStartTime || 0,
		connectEnd: connectionInfo.connectionEndTime || 0,
		secureConnectionStart: connectionInfo.secureConnectionStartTime || 0,
		requestStart: timingInfo && timingInfo.finalNetworkRequestStartTime || 0,
		responseStart: timingInfo && timingInfo.finalNetworkResponseStartTime || 0,
		responseEnd: timingInfo && timingInfo.endTime || 0,
		transferSize,
		encodedBodySize,
		decodedBodySize: timingInfo && timingInfo.decodedBodySize || 0,
		responseStatus: responseStatus || 0,
		deliveryType: deliveryType || ""
	}, _histogramSecret);
	_allowPerformanceResourceTimingConstruction = false;
	_resources.push(entry);
	_notifyObservers(entry);
	return entry;
};
Performance.prototype.toJSON = function() {
	_requirePerformanceReceiver(this);
	_updateNodeTiming();
	return {
		timeOrigin: this.timeOrigin,
		nodeTiming: this.nodeTiming
	};
};
_setFunctionName(Performance.prototype.now, "now");
_setFunctionName(Performance.prototype.mark, "mark");
_setFunctionName(Performance.prototype.measure, "measure");
_setFunctionName(Performance.prototype.getEntries, "getEntries");
_setFunctionName(Performance.prototype.getEntriesByName, "getEntriesByName");
_setFunctionName(Performance.prototype.getEntriesByType, "getEntriesByType");
_setFunctionName(Performance.prototype.clearMarks, "clearMarks");
_setFunctionName(Performance.prototype.clearMeasures, "clearMeasures");
_setFunctionName(Performance.prototype.clearResourceTimings, "clearResourceTimings");
_setFunctionName(Performance.prototype.markResourceTiming, "markResourceTiming");
_setFunctionName(Performance.prototype.toJSON, "toJSON");
var _nodeTiming = {
	name: "node",
	entryType: "node",
	startTime: 0,
	duration: 0,
	nodeStart: 0,
	v8Start: 1,
	environment: 2,
	loopStart: _isMainThread ? -1 : 4,
	loopExit: -1,
	bootstrapComplete: 3,
	idleTime: 0
};
_updateNodeTiming();
if (typeof process !== "undefined" && process && typeof process.on === "function") process.on("exit", function() {
	_nodeTiming.loopExit = _perfNow();
	_nodeTiming.duration = _perfNow();
	_nodeTiming.idleTime = _loopIdle;
});
function _observeTimerEntry(entryType, name, startTime, endTime) {
	_allowPerformanceEntryConstruction = true;
	var entry = new PerformanceEntry(name, entryType, startTime, endTime - startTime);
	_allowPerformanceEntryConstruction = false;
	_notifyObservers(entry);
}
function _recordHistogram(histogram, value, fnName) {
	if (!histogram) return;
	if (typeof histogram.record === "function") {
		var amount = value || 0;
		try {
			histogram.record(amount);
		} catch (e) {}
	} else if (histogram[fnName] !== void 0 && typeof histogram[fnName] !== "function") throw _invalidArgType("The \"histogram\" option must be an object with a record method.");
}
function _buildConstructedInstance(fn, args) {
	return new (Function.prototype.bind.apply(fn, [null].concat(_toArray(args))))();
}
function timerify(fn, options) {
	if (typeof fn !== "function") throw _invalidArgType("The \"fn\" argument must be of type function. Received type " + (fn === null ? "null" : typeof fn));
	if (options !== void 0 && (options === null || typeof options !== "object" || Array.isArray(options))) throw _invalidArgType("The \"options\" argument must be of type object.");
	var histogram = options && options.histogram;
	if (options && options.histogram !== void 0 && (!histogram || typeof histogram.record !== "function" || typeof histogram.recordDelta !== "function")) throw _invalidArgType("The \"histogram\" option must be of type object.");
	var name = fn.name || "anonymous";
	var wrapped = function() {
		var args = _toArray(arguments);
		var isConstructor = false;
		try {
			isConstructor = this instanceof wrapped;
		} catch (e) {}
		var start = _perfNow();
		var result;
		if (isConstructor) result = _buildConstructedInstance(fn, args);
		else result = fn.apply(this, args);
		var end = _perfNow();
		_observeTimerEntry("function", name, start, end);
		_recordHistogram(histogram, end - start, "record");
		if (result && typeof result.then === "function") return result.then(function(value) {
			_recordHistogram(histogram, _perfNow() - end, "record");
			return value;
		}, function(err) {
			_recordHistogram(histogram, _perfNow() - end, "record");
			throw err;
		});
		return result;
	};
	wrapped.prototype = fn.prototype || {};
	try {
		Object.defineProperty(wrapped, "name", {
			configurable: true,
			value: "timerified " + name
		});
		Object.defineProperty(wrapped, "length", {
			configurable: true,
			value: fn.length
		});
	} catch (_) {
		wrapped.name = "timerified " + name;
		wrapped.length = fn.length;
	}
	return wrapped;
}
function RecordableHistogram(options, secret) {
	if (secret !== _histogramSecret) throw _illegalConstructor();
	if (options === void 0 || options === null) options = {};
	if (typeof options !== "object" || Array.isArray(options)) throw _invalidArgType("The \"options\" argument must be of type object.");
	if (options.lowest !== void 0 && typeof options.lowest !== "number") throw _invalidArgType("The \"options.lowest\" property must be of type number.");
	if (options.highest !== void 0 && typeof options.highest !== "number") throw _invalidArgType("The \"options.highest\" property must be of type number.");
	if (options.figures !== void 0) {
		if (typeof options.figures !== "number" || Math.floor(options.figures) !== options.figures) throw _invalidArgType("The \"options.figures\" property must be an integer.");
		if (options.figures < 1 || options.figures > 5) throw _outOfRange("The value of \"options.figures\" is out of range.");
	}
	this.min = 0x8000000000000000;
	this.minBigInt = BigInt("9223372036854775807");
	this.max = 0;
	this.maxBigInt = BigInt("0");
	this.exceeds = 0;
	this.exceedsBigInt = BigInt("0");
	this.mean = NaN;
	this.stddev = NaN;
	this.count = 0;
	this.countBigInt = BigInt("0");
	this._samples = [];
	this._sum = 0;
	this._sumSquares = 0;
	this._lastValue = null;
}
function _updateStats(hist) {
	if (hist.count === 0) {
		hist.mean = NaN;
		hist.stddev = NaN;
		return;
	}
	hist.mean = hist._sum / hist.count;
	var variance = hist._sumSquares / hist.count - hist.mean * hist.mean;
	if (variance < 0) variance = 0;
	hist.stddev = Math.sqrt(variance);
}
function _validateRecordValue(value) {
	if (typeof value === "number") {
		if (!isFinite(value) || value < 0) throw _invalidArgType("The \"value\" argument must be a safe number");
		if (value <= 0 || value > Number.MAX_SAFE_INTEGER) throw _outOfRange("The \"value\" argument must be in safe range.");
		return {
			value,
			valueBig: BigInt(Math.floor(value))
		};
	}
	if (typeof value === "bigint") {
		if (value <= BigInt("0")) throw _outOfRange("The \"value\" argument must be a bigint > 0.");
		return {
			value: Number(value),
			valueBig: value
		};
	}
	throw _invalidArgType("The \"value\" argument must be of type number.");
}
RecordableHistogram.prototype.record = function(value) {
	if (value === void 0 || value === null) throw _invalidArgType("The \"value\" argument must be of type number.");
	var converted = _validateRecordValue(value);
	var numeric = converted.value;
	this._samples.push(numeric);
	if (this.count === 0) {
		this.min = numeric;
		this.max = numeric;
		this.minBigInt = converted.valueBig;
		this.maxBigInt = converted.valueBig;
	} else {
		if (numeric < this.min) this.min = numeric;
		if (numeric > this.max) this.max = numeric;
		if (converted.valueBig < this.minBigInt) this.minBigInt = converted.valueBig;
		if (converted.valueBig > this.maxBigInt) this.maxBigInt = converted.valueBig;
	}
	this.count += 1;
	this.countBigInt = BigInt(this.count);
	this._sum += numeric;
	this._sumSquares += numeric * numeric;
	this._lastValue = converted.valueBig;
	_updateStats(this);
};
RecordableHistogram.prototype.recordDelta = function() {
	if (this._lastValue === null) return;
	this.record(this._lastValue);
};
RecordableHistogram.prototype.percentile = function(percentileValue) {
	if (typeof percentileValue !== "number") throw _invalidArgType("The \"percentile\" argument must be a number.");
	if (percentileValue < 0 || percentileValue > 100) throw _outOfRange("The \"percentile\" value must be between 0 and 100.");
	if (this.count === 0) return NaN;
	var sorted = this._samples.slice().sort(function(a, b) {
		return a - b;
	});
	return sorted[Math.floor(percentileValue / 100 * (sorted.length - 1))];
};
RecordableHistogram.prototype.percentileBigInt = function(percentileValue) {
	if (typeof percentileValue !== "number") throw _invalidArgType("The \"percentile\" argument must be a number.");
	if (percentileValue < 0 || percentileValue > 100) throw _outOfRange("The \"percentile\" value must be between 0 and 100.");
	if (this.count === 0) return BigInt("0");
	var value = this.percentile(percentileValue);
	return BigInt(Math.floor(value));
};
Object.defineProperty(RecordableHistogram.prototype, "percentiles", {
	enumerable: false,
	get: function() {
		var map = /* @__PURE__ */ new Map();
		if (this.count === 0) {
			map.set(0, this.max);
			map.set(100, this.max);
		} else {
			map.set(0, this.percentile(0));
			map.set(100, this.percentile(100));
		}
		return map;
	}
});
Object.defineProperty(RecordableHistogram.prototype, "percentilesBigInt", {
	enumerable: false,
	get: function() {
		var map = /* @__PURE__ */ new Map();
		if (this.count === 0) {
			map.set(0, this.maxBigInt);
			map.set(100, this.maxBigInt);
		} else {
			map.set(0, this.percentileBigInt(0));
			map.set(100, this.percentileBigInt(100));
		}
		return map;
	}
});
RecordableHistogram.prototype.add = function(other) {
	if (!other || !other._samples) throw _invalidArgType("The \"other\" argument must be a RecordableHistogram");
	for (var i = 0; i < other._samples.length; i++) this.record(other._samples[i]);
};
RecordableHistogram.prototype.recordTime = function() {};
function createHistogram(options) {
	return new RecordableHistogram(options, _histogramSecret);
}
function monitorEventLoopDelay() {
	var histogram = createHistogram();
	var enabled = false;
	var timer = null;
	var last = _perfNow();
	function _tick() {
		var now = _perfNow();
		var delta = now - last;
		if (delta < 0) delta = 0;
		last = now;
		if (delta > 0) {
			try {
				histogram.record(delta * 1e6);
			} catch (_) {}
			_loopIdle += delta;
		}
	}
	Object.defineProperty(histogram, "enable", {
		configurable: true,
		value: function() {
			if (!enabled) {
				enabled = true;
				timer = setInterval(_tick, 10);
				_tick();
			}
			return histogram;
		},
		enumerable: false
	});
	Object.defineProperty(histogram, "disable", {
		configurable: true,
		value: function() {
			if (!enabled) return false;
			enabled = false;
			if (timer) {
				clearInterval(timer);
				timer = null;
			}
			return true;
		},
		enumerable: false
	});
	histogram.min = 0;
	histogram.max = 0;
	histogram.mean = NaN;
	histogram.stddev = NaN;
	histogram.count = 0;
	histogram.exceeds = 0;
	return histogram;
}
function PerformanceObserver(callback) {
	if (typeof callback !== "function") throw _invalidArgType("The \"callback\" argument must be of type function.");
	this._callback = callback;
	this._entryTypes = [];
	this._entryQueue = [];
	this._flushScheduled = false;
}
PerformanceObserver.prototype.observe = function() {
	var options = arguments[0];
	if (!options || typeof options !== "object") throw _invalidArgType("The \"options\" argument must be of type object.");
	if (options.entryTypes) {
		if (!Array.isArray(options.entryTypes)) throw _invalidArgType("The \"entryTypes\" property must be an array.");
		this._entryTypes = options.entryTypes;
	} else if (options.type) this._entryTypes = [options.type];
	if (_observers.indexOf(this) === -1) _observers.push(this);
	if (options.buffered === true) {
		var bufferedEntries = [];
		for (var i = 0; i < this._entryTypes.length; i++) {
			var entryType = this._entryTypes[i];
			if (entryType === "mark") bufferedEntries = bufferedEntries.concat(_marks);
			else if (entryType === "measure") bufferedEntries = bufferedEntries.concat(_measures);
			else if (entryType === "resource") bufferedEntries = bufferedEntries.concat(_resources);
		}
		if (bufferedEntries.length > 0) {
			this._entryQueue = this._entryQueue.concat(bufferedEntries);
			_scheduleObserverFlush(this);
		}
	}
};
PerformanceObserver.prototype.disconnect = function() {
	var idx = _observers.indexOf(this);
	if (idx !== -1) _observers.splice(idx, 1);
	this._entryTypes = [];
};
PerformanceObserver.prototype.takeRecords = function() {
	var entries = this._entryQueue.slice();
	this._entryQueue.length = 0;
	return entries;
};
_setFunctionName(PerformanceObserver.prototype.observe, "observe");
_setFunctionName(PerformanceObserver.prototype.disconnect, "disconnect");
_setFunctionName(PerformanceObserver.prototype.takeRecords, "takeRecords");
PerformanceObserver.supportedEntryTypes = Object.freeze([
	"function",
	"mark",
	"measure",
	"resource"
]);
var performance = new Performance();
performance.nodeTiming = _nodeTiming;
performance.timerify = timerify;
performance.eventLoopUtilization = eventLoopUtilization;
if (typeof globalThis !== "undefined") {
	globalThis.performance = performance;
	globalThis.Performance = Performance;
	globalThis.PerformanceEntry = PerformanceEntry;
	globalThis.PerformanceMark = PerformanceMark;
	globalThis.PerformanceMeasure = PerformanceMeasure;
	globalThis.PerformanceObserver = PerformanceObserver;
	globalThis.PerformanceResourceTiming = PerformanceResourceTiming;
}
module.exports = {
	performance,
	Performance,
	PerformanceEntry,
	PerformanceMark,
	PerformanceMeasure,
	PerformanceObserver,
	PerformanceResourceTiming,
	timerify,
	eventLoopUtilization,
	createHistogram,
	monitorEventLoopDelay,
	constants: {
		NODE_PERFORMANCE_ENTRY_TYPE_GC: "gc",
		NODE_PERFORMANCE_ENTRY_TYPE_HTTP2: "http2",
		NODE_PERFORMANCE_ENTRY_TYPE_MARK: "mark",
		NODE_PERFORMANCE_ENTRY_TYPE_MEASURE: "measure",
		NODE_PERFORMANCE_ENTRY_TYPE_FUNCTION: "function",
		NODE_PERFORMANCE_ENTRY_TYPE_RESOURCE: "resource",
		NODE_PERFORMANCE_ENTRY_TYPE_NODE: "node"
	}
};
//#endregion
