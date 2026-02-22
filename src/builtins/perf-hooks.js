var _perfStart = Date.now();
var _marks = [];
var _measures = [];
var _observers = [];

var _isMainThread = true;
try {
  var _workerThreads = require('worker_threads');
  if (_workerThreads && _workerThreads.isMainThread === false) {
    _isMainThread = false;
  }
} catch (_) {
  _isMainThread = true;
}

var _loopSampleTime = Date.now();
var _loopActive = 0;
var _loopIdle = 0;
var _loopInitialized = false;

var _histogramSecret = {};

function _perfNow() {
  if (typeof __exactHrtime === 'function') {
    var parts = __exactHrtime();
    if (typeof parts === 'string') {
      var p = parts.split(',');
      return (parseInt(p[0], 10) * 1000) + (parseInt(p[1], 10) / 1000000);
    }
  }
  return Date.now() - _perfStart;
}

function _invalidArgType(message) {
  var err = new TypeError(message);
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _outOfRange(message) {
  var err = new RangeError(message);
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _illegalConstructor() {
  var err = new TypeError('Illegal constructor');
  err.code = 'ERR_ILLEGAL_CONSTRUCTOR';
  return err;
}

function _toArray(args) {
  var list = [];
  for (var i = 0; i < args.length; i++) {
    list[i] = args[i];
  }
  return list;
}

function _updateNodeTiming() {
  _nodeTiming.duration = _perfNow();
  _nodeTiming.idleTime = _loopIdle;
  if (!_isMainThread && _nodeTiming.loopStart < _nodeTiming.bootstrapComplete) {
    _nodeTiming.loopStart = _nodeTiming.bootstrapComplete;
  }
}

function _notifyObservers(entry) {
  for (var i = 0; i < _observers.length; i++) {
    var obs = _observers[i];
    if (obs._entryTypes && obs._entryTypes.indexOf(entry.entryType) !== -1) {
      obs._entryQueue.push(entry);
      if (typeof queueMicrotask === 'function' && !obs._flushScheduled) {
        obs._flushScheduled = true;
        queueMicrotask(function() {
          obs._flushScheduled = false;
          if (!obs._callback || obs._entryQueue.length === 0) return;
          var entries = obs._entryQueue.slice();
          obs._entryQueue.length = 0;
          try {
            var list = {
              getEntries: function() { return entries.slice(); },
              getEntriesByName: function(n, type) {
                var result = [];
                for (var j = 0; j < entries.length; j++) {
                  if (entries[j].name === n && (!type || entries[j].entryType === type)) result.push(entries[j]);
                }
                return result;
              },
              getEntriesByType: function(t) {
                var result = [];
                for (var j = 0; j < entries.length; j++) {
                  if (entries[j].entryType === t) result.push(entries[j]);
                }
                return result;
              }
            };
            obs._callback(list, obs);
          } catch (e) {}
        });
      }
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
  if (_loopActive === 0 && _loopIdle === 0 && delta <= 20) {
    _loopIdle += delta;
  } else {
    _loopActive += delta;
  }
}

function _normalizeElu(value) {
  if (!value || typeof value !== 'object') return null;
  if (typeof value.active !== 'number' || typeof value.idle !== 'number') return null;
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
    idle: idle,
    active: active,
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
  if (_isMainThread && _nodeTiming.loopStart === -1 && start && start.active === 0 && start.idle === 0) {
    return { idle: 0, active: 0, utilization: 0 };
  }
  if (start && end) {
    return _diffElu(_normalizeElu(start), _normalizeElu(end));
  }
  if (start) {
    var base = _normalizeElu(start);
    if (base) return _diffElu(current, base);
  }
  return current;
}

function PerformanceEntry(name, entryType, startTime, duration) {
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

function Performance() {}
Performance.prototype.now = function() {
  var t = _perfNow();
  _updateNodeTiming();
  return t;
};
Performance.prototype.timeOrigin = _perfStart;
Performance.prototype.mark = function(name, options) {
  _updateNodeTiming();
  options = options || {};
  var startTime = (options.startTime !== undefined) ? options.startTime : _perfNow();
  var entry = new PerformanceEntry(name, 'mark', startTime, 0);
  if (options.detail !== undefined) entry.detail = options.detail;
  _marks.push(entry);
  _notifyObservers(entry);
  return entry;
};
Performance.prototype.measure = function(name, startMarkOrOptions, endMark) {
  _updateNodeTiming();
  var startTime = 0;
  var endTime = _perfNow();
  var duration;
  var detail;

  if (startMarkOrOptions && typeof startMarkOrOptions === 'object' && !Array.isArray(startMarkOrOptions)) {
    var opts = startMarkOrOptions;
    if (opts.detail !== undefined) detail = opts.detail;

    if (opts.start !== undefined) {
      if (typeof opts.start === 'string') {
        var sm = null;
        for (var i = _marks.length - 1; i >= 0; i--) {
          if (_marks[i].name === opts.start) { sm = _marks[i]; break; }
        }
        if (sm) startTime = sm.startTime;
        else throw new Error("Failed to execute 'measure': The mark '" + opts.start + "' does not exist.");
      } else {
        startTime = opts.start;
      }
    }

    if (opts.end !== undefined) {
      if (typeof opts.end === 'string') {
        var em = null;
        for (var j = _marks.length - 1; j >= 0; j--) {
          if (_marks[j].name === opts.end) { em = _marks[j]; break; }
        }
        if (em) endTime = em.startTime;
        else throw new Error("Failed to execute 'measure': The mark '" + opts.end + "' does not exist.");
      } else {
        endTime = opts.end;
      }
    }

    if (opts.duration !== undefined) {
      duration = opts.duration;
      if (opts.start !== undefined && opts.end === undefined) {
        endTime = startTime + duration;
      } else if (opts.end !== undefined && opts.start === undefined) {
        startTime = endTime - duration;
      }
    }
  } else if (typeof startMarkOrOptions === 'string') {
    var foundStart = null;
    for (var k = _marks.length - 1; k >= 0; k--) {
      if (_marks[k].name === startMarkOrOptions) { foundStart = _marks[k]; break; }
    }
    if (foundStart) startTime = foundStart.startTime;
    else throw new Error("Failed to execute 'measure': The mark '" + startMarkOrOptions + "' does not exist.");

    if (typeof endMark === 'string') {
      var foundEnd = null;
      for (var l = _marks.length - 1; l >= 0; l--) {
        if (_marks[l].name === endMark) { foundEnd = _marks[l]; break; }
      }
      if (foundEnd) endTime = foundEnd.startTime;
      else throw new Error("Failed to execute 'measure': The mark '" + endMark + "' does not exist.");
    }
  }

  if (duration === undefined) {
    duration = endTime - startTime;
  }

  var entry = new PerformanceEntry(name, 'measure', startTime, duration);
  if (detail !== undefined) entry.detail = detail;
  _measures.push(entry);
  _notifyObservers(entry);
  return entry;
};
Performance.prototype.getEntries = function() {
  return _marks.concat(_measures).sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.getEntriesByName = function(name, type) {
  var all = _marks.concat(_measures);
  var result = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].name === name && (!type || all[i].entryType === type)) {
      result.push(all[i]);
    }
  }
  return result.sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.getEntriesByType = function(type) {
  var all = _marks.concat(_measures);
  var result = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].entryType === type) {
      result.push(all[i]);
    }
  }
  return result.sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.clearMarks = function(name) {
  if (name === undefined) {
    _marks = [];
  } else {
    _marks = _marks.filter(function(m) { return m.name !== name; });
  }
};
Performance.prototype.clearMeasures = function(name) {
  if (name === undefined) {
    _measures = [];
  } else {
    _measures = _measures.filter(function(m) { return m.name !== name; });
  }
};
Performance.prototype.toJSON = function() {
  _updateNodeTiming();
  return {
    timeOrigin: this.timeOrigin,
    nodeTiming: this.nodeTiming
  };
};

var _nodeTiming = {
  name: 'node',
  entryType: 'node',
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

if (typeof process !== 'undefined' && process && typeof process.on === 'function') {
  process.on('exit', function() {
    _nodeTiming.loopExit = _perfNow();
    _nodeTiming.duration = _perfNow();
    _nodeTiming.idleTime = _loopIdle;
  });
}

function _observeTimerEntry(entryType, name, startTime, endTime) {
  var entry = new PerformanceEntry(name, entryType, startTime, endTime - startTime);
  _notifyObservers(entry);
}

function _recordHistogram(histogram, value, fnName) {
  if (!histogram) return;
  if (typeof histogram.record === 'function') {
    var amount = value || 0;
    try { histogram.record(amount); } catch (e) {}
  } else if (histogram[fnName] !== undefined && typeof histogram[fnName] !== 'function') {
    throw _invalidArgType('The "histogram" option must be an object with a record method.');
  }
}

function _buildConstructedInstance(fn, args) {
  return new (Function.prototype.bind.apply(fn, [null].concat(_toArray(args))))();
}

function timerify(fn, options) {
  if (typeof fn !== 'function') {
    throw _invalidArgType(
      'The "fn" argument must be of type function. Received type ' + (fn === null ? 'null' : typeof fn)
    );
  }
  if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options))) {
    throw _invalidArgType('The "options" argument must be of type object.');
  }

  var histogram = options && options.histogram;
  if (options && options.histogram !== undefined &&
      (!histogram || typeof histogram.record !== 'function' || typeof histogram.recordDelta !== 'function')) {
    throw _invalidArgType('The "histogram" option must be of type object.');
  }

  var name = fn.name || 'anonymous';
  var wrapped = function() {
    var args = _toArray(arguments);
    var isConstructor = false;
    try { isConstructor = this instanceof wrapped; } catch (e) {}
    var start = _perfNow();
    var result;
    if (isConstructor) {
      result = _buildConstructedInstance(fn, args);
    } else {
      result = fn.apply(this, args);
    }
    var end = _perfNow();
    _observeTimerEntry('function', name, start, end);
    _recordHistogram(histogram, end - start, 'record');

    if (result && typeof result.then === 'function') {
      return result.then(function(value) {
        _recordHistogram(histogram, _perfNow() - end, 'record');
        return value;
      }, function(err) {
        _recordHistogram(histogram, _perfNow() - end, 'record');
        throw err;
      });
    }
    return result;
  };
  wrapped.prototype = fn.prototype || {};

  try {
    Object.defineProperty(wrapped, 'name', {
      configurable: true,
      value: 'timerified ' + name
    });
    Object.defineProperty(wrapped, 'length', {
      configurable: true,
      value: fn.length
    });
  } catch (_) {
    wrapped.name = 'timerified ' + name;
    wrapped.length = fn.length;
  }
  return wrapped;
}

function RecordableHistogram(options, secret) {
  if (secret !== _histogramSecret) throw _illegalConstructor();
  if (options === undefined || options === null) options = {};
  if (typeof options !== 'object' || Array.isArray(options)) {
    throw _invalidArgType('The "options" argument must be of type object.');
  }

  if (options.lowest !== undefined && typeof options.lowest !== 'number') {
    throw _invalidArgType('The "options.lowest" property must be of type number.');
  }
  if (options.highest !== undefined && typeof options.highest !== 'number') {
    throw _invalidArgType('The "options.highest" property must be of type number.');
  }
  if (options.figures !== undefined) {
    if (typeof options.figures !== 'number' || Math.floor(options.figures) !== options.figures) {
      throw _invalidArgType('The "options.figures" property must be an integer.');
    }
    if (options.figures < 1 || options.figures > 5) {
      throw _outOfRange('The value of "options.figures" is out of range.');
    }
  }

  this.min = 9223372036854776000;
  this.minBigInt = 9223372036854775807n;
  this.max = 0;
  this.maxBigInt = 0n;
  this.exceeds = 0;
  this.exceedsBigInt = 0n;
  this.mean = NaN;
  this.stddev = NaN;
  this.count = 0;
  this.countBigInt = 0n;
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
  var variance = (hist._sumSquares / hist.count) - (hist.mean * hist.mean);
  if (variance < 0) variance = 0;
  hist.stddev = Math.sqrt(variance);
}

function _validateRecordValue(value) {
  if (typeof value === 'number') {
    if (!isFinite(value) || value < 0) {
      throw _invalidArgType('The "value" argument must be a safe number');
    }
    if (value > Number.MAX_SAFE_INTEGER) {
      throw _outOfRange('The "value" argument must be in safe range.');
    }
    return { value: value, valueBig: BigInt(Math.floor(value)) };
  }
  if (typeof value === 'bigint') {
    if (value < 0) {
      throw _invalidArgType('The "value" argument must be a bigint >= 0.');
    }
    return { value: Number(value), valueBig: value };
  }
  throw _invalidArgType('The "value" argument must be of type number.');
}

RecordableHistogram.prototype.record = function(value) {
  if (value === undefined || value === null) {
    throw _invalidArgType('The "value" argument must be of type number.');
  }
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
  if (typeof percentileValue !== 'number') {
    throw _invalidArgType('The "percentile" argument must be a number.');
  }
  if (percentileValue < 0 || percentileValue > 100) {
    throw _outOfRange('The "percentile" value must be between 0 and 100.');
  }
  if (this.count === 0) return NaN;
  var sorted = this._samples.slice().sort(function(a, b) { return a - b; });
  var index = Math.floor((percentileValue / 100) * (sorted.length - 1));
  return sorted[index];
};

RecordableHistogram.prototype.percentileBigInt = function(percentileValue) {
  if (typeof percentileValue !== 'number') {
    throw _invalidArgType('The "percentile" argument must be a number.');
  }
  if (percentileValue < 0 || percentileValue > 100) {
    throw _outOfRange('The "percentile" value must be between 0 and 100.');
  }
  if (this.count === 0) return 0n;
  var value = this.percentile(percentileValue);
  return BigInt(Math.floor(value));
};

Object.defineProperty(RecordableHistogram.prototype, 'percentiles', {
  enumerable: false,
  get: function() {
    var map = new Map();
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

Object.defineProperty(RecordableHistogram.prototype, 'percentilesBigInt', {
  enumerable: false,
  get: function() {
    var map = new Map();
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
  if (!other || !other._samples) {
    throw _invalidArgType('The "other" argument must be a RecordableHistogram');
  }
  for (var i = 0; i < other._samples.length; i++) {
    this.record(other._samples[i]);
  }
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
      try { histogram.record(delta * 1000000); } catch (_) {}
      _loopIdle += delta;
    }
  }

  Object.defineProperty(histogram, 'enable', {
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

  Object.defineProperty(histogram, 'disable', {
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
  if (typeof callback !== 'function') {
    var err = _invalidArgType('The "callback" argument must be of type function.');
    throw err;
  }
  this._callback = callback;
  this._entryTypes = [];
  this._entryQueue = [];
  this._flushScheduled = false;
}
PerformanceObserver.prototype.observe = function(options) {
  if (!options || typeof options !== 'object') {
    throw _invalidArgType('The "options" argument must be of type object.');
  }
  if (options.entryTypes) {
    if (!Array.isArray(options.entryTypes)) {
      throw _invalidArgType('The "entryTypes" property must be an array.');
    }
    this._entryTypes = options.entryTypes;
  } else if (options.type) {
    this._entryTypes = [options.type];
  }
  if (_observers.indexOf(this) === -1) {
    _observers.push(this);
  }
};
PerformanceObserver.prototype.disconnect = function() {
  var idx = _observers.indexOf(this);
  if (idx !== -1) _observers.splice(idx, 1);
  this._entryTypes = [];
};
PerformanceObserver.prototype.takeRecords = function() {
  return [];
};
PerformanceObserver.supportedEntryTypes = ['mark', 'measure', 'function'];

var performance = new Performance();
performance.nodeTiming = _nodeTiming;
performance.timerify = timerify;
performance.eventLoopUtilization = eventLoopUtilization;
if (typeof globalThis !== 'undefined' && globalThis.performance) {
  globalThis.performance = performance;
}

module.exports = {
  performance: performance,
  Performance: Performance,
  PerformanceEntry: PerformanceEntry,
  PerformanceObserver: PerformanceObserver,
  timerify: timerify,
  eventLoopUtilization: eventLoopUtilization,
  createHistogram: createHistogram,
  monitorEventLoopDelay: monitorEventLoopDelay,
  constants: {
    NODE_PERFORMANCE_ENTRY_TYPE_GC: 'gc',
    NODE_PERFORMANCE_ENTRY_TYPE_HTTP2: 'http2',
    NODE_PERFORMANCE_ENTRY_TYPE_MARK: 'mark',
    NODE_PERFORMANCE_ENTRY_TYPE_MEASURE: 'measure',
    NODE_PERFORMANCE_ENTRY_TYPE_FUNCTION: 'function',
    NODE_PERFORMANCE_ENTRY_TYPE_RESOURCE: 'resource',
    NODE_PERFORMANCE_ENTRY_TYPE_NODE: 'node'
  }
};
