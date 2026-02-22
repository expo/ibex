var _perfStart = Date.now();
var _marks = [];
var _measures = [];
var _observers = [];

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

function _notifyObservers(entry) {
  for (var i = 0; i < _observers.length; i++) {
    var obs = _observers[i];
    if (obs._entryTypes && obs._entryTypes.indexOf(entry.entryType) !== -1) {
      try {
        var list = {
          getEntries: function() { return [entry]; },
          getEntriesByName: function(n) { return entry.name === n ? [entry] : []; },
          getEntriesByType: function(t) { return entry.entryType === t ? [entry] : []; }
        };
        obs._callback(list, obs);
      } catch (e) {}
    }
  }
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
  return _perfNow();
};
Performance.prototype.timeOrigin = _perfStart;
Performance.prototype.mark = function(name, options) {
  options = options || {};
  var startTime = (options.startTime !== undefined) ? options.startTime : _perfNow();
  var entry = new PerformanceEntry(name, 'mark', startTime, 0);
  if (options.detail !== undefined) entry.detail = options.detail;
  _marks.push(entry);
  _notifyObservers(entry);
  return entry;
};
Performance.prototype.measure = function(name, startMarkOrOptions, endMark) {
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
  return {
    timeOrigin: this.timeOrigin
  };
};

var performance = new Performance();

function PerformanceObserver(callback) {
  this._callback = callback;
  this._entryTypes = [];
}
PerformanceObserver.prototype.observe = function(options) {
  if (options && options.entryTypes) {
    this._entryTypes = options.entryTypes;
  } else if (options && options.type) {
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
PerformanceObserver.supportedEntryTypes = ['mark', 'measure'];

module.exports = {
  performance: performance,
  Performance: Performance,
  PerformanceEntry: PerformanceEntry,
  PerformanceObserver: PerformanceObserver,
  monitorEventLoopDelay: function() {
    return { enable: function() {}, disable: function() {}, percentile: function() { return 0; },
             min: 0, max: 0, mean: 0, stddev: 0, percentiles: new Map() };
  }
};
