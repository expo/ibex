// Capture references to global timer functions at module load time
// so they survive deletion from global scope
var _setTimeout = globalThis.setTimeout;
var _clearTimeout = globalThis.clearTimeout;
var _setInterval = globalThis.setInterval;
var _clearInterval = globalThis.clearInterval;
var _FuncApply = Function.prototype.apply;
var _FuncBind = Function.prototype.bind;

function _validateTimerCallback(callback, name) {
  if (typeof callback !== 'function') {
    var err = new TypeError('[ERR_INVALID_ARG_TYPE]: The "' + name + '" argument must be of type function. Received type ' + typeof callback);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

// Timer wrapper class for ref/unref/refresh/hasRef/Symbol.toPrimitive
var _nextTimerId = 1;

// Map from numeric ID to Timeout/Immediate object for clearTimeout(numericId) support
var _timerById = new Map();

function Timeout(callback, delay, args, isRepeat) {
  this._callback = callback;
  this._delay = delay == null ? 1 : (delay < 1 ? 1 : delay);
  this._args = args;
  this._isRepeat = isRepeat || false;
  this._repeat = isRepeat ? this._delay : null;
  this._refed = true;
  this._destroyed = false;
  this._idleTimeout = this._delay;
  this._idleStart = Date.now();
  this._id = _nextTimerId++;
  this._onTimeout = callback;

  // Register in the ID map for numeric-ID-based clearing
  _timerById.set(this._id, this);

  this._scheduleNative();
}

Timeout.prototype._scheduleNative = function() {
  var self = this;
  if (this._isRepeat) {
    this._nativeHandle = _setInterval(function() {
      // Bind this to the Timeout object; use _FuncApply to be resilient
      // to user monkey-patching of fn.call/fn.apply
      _FuncApply.call(self._callback, self, self._args);
    }, this._delay);
  } else {
    this._nativeHandle = _setTimeout(function() {
      self._destroyed = true;
      _timerById.delete(self._id);
      _FuncApply.call(self._callback, self, self._args);
    }, this._delay);
  }
};

Timeout.prototype.ref = function() {
  this._refed = true;
  return this;
};

Timeout.prototype.unref = function() {
  this._refed = false;
  return this;
};

Timeout.prototype.hasRef = function() {
  return this._refed;
};

Timeout.prototype.refresh = function() {
  if (this._destroyed) return this;
  // Clear old timer and create new one
  if (this._isRepeat) {
    _clearInterval(this._nativeHandle);
  } else {
    _clearTimeout(this._nativeHandle);
  }
  this._scheduleNative();
  return this;
};

Timeout.prototype.close = function() {
  if (this._isRepeat) {
    _clearInterval(this._nativeHandle);
  } else {
    _clearTimeout(this._nativeHandle);
  }
  this._destroyed = true;
  _timerById.delete(this._id);
  return this;
};

Timeout.prototype[Symbol.toPrimitive] = function() {
  return this._id;
};

Timeout.prototype[Symbol.dispose] = function() {
  if (!this._destroyed) {
    this.close();
  }
};

// Immediate wrapper
function Immediate(callback, args) {
  this._callback = callback;
  this._args = args;
  this._destroyed = false;
  this._id = _nextTimerId++;
  this._refed = true;
  this._onImmediate = callback;

  // Register in the ID map
  _timerById.set(this._id, this);

  var self = this;
  this._nativeHandle = _setTimeout(function() {
    self._destroyed = true;
    _timerById.delete(self._id);
    _FuncApply.call(self._callback, self, self._args);
  }, 0);
}

Immediate.prototype.ref = function() {
  this._refed = true;
  return this;
};

Immediate.prototype.unref = function() {
  this._refed = false;
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

Immediate.prototype[Symbol.dispose] = function() {
  if (!this._destroyed) {
    this.close();
  }
};

function setTimeout$1(callback, delay) {
  _validateTimerCallback(callback, 'callback');
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof _setTimeout !== "function") {
    throw new Error("setTimeout is not available");
  }
  return new Timeout(callback, delay, args, false);
}

function clearTimeout$1(handle) {
  if (handle === undefined || handle === null) return;
  // Handle Timeout objects
  if (typeof handle === 'object' && handle !== null) {
    if (typeof handle.close === 'function') {
      handle.close();
      return;
    }
    if (handle._nativeHandle !== undefined) {
      if (typeof _clearTimeout === "function") {
        _clearTimeout(handle._nativeHandle);
      }
      handle._destroyed = true;
      if (handle._id !== undefined) _timerById.delete(handle._id);
      return;
    }
  }
  // Handle numeric ID (from Symbol.toPrimitive or string coercion)
  if (typeof handle === 'number' || typeof handle === 'string') {
    var numId = Number(handle);
    var timerObj = _timerById.get(numId);
    if (timerObj) {
      timerObj.close();
      return;
    }
  }
  // Fall back to native clearTimeout for raw handles
  if (typeof _clearTimeout === "function") {
    _clearTimeout(handle);
  }
}

function setInterval$1(callback, delay) {
  _validateTimerCallback(callback, 'callback');
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof _setInterval !== "function") {
    throw new Error("setInterval is not available");
  }
  return new Timeout(callback, delay, args, true);
}

function clearInterval$1(handle) {
  if (handle === undefined || handle === null) return;
  // Handle Timeout objects
  if (typeof handle === 'object' && handle !== null) {
    if (typeof handle.close === 'function') {
      handle.close();
      return;
    }
    if (handle._nativeHandle !== undefined) {
      if (typeof _clearInterval === "function") {
        _clearInterval(handle._nativeHandle);
      }
      handle._destroyed = true;
      if (handle._id !== undefined) _timerById.delete(handle._id);
      return;
    }
  }
  // Handle numeric ID
  if (typeof handle === 'number' || typeof handle === 'string') {
    var numId = Number(handle);
    var timerObj = _timerById.get(numId);
    if (timerObj) {
      timerObj.close();
      return;
    }
  }
  if (typeof _clearInterval === "function") {
    _clearInterval(handle);
  }
}

function setImmediate$1(callback) {
  _validateTimerCallback(callback, 'callback');
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  return new Immediate(callback, args);
}

function clearImmediate$1(handle) {
  if (handle === undefined || handle === null) return;
  if (typeof handle === 'object' && handle !== null) {
    if (typeof handle.close === 'function') {
      handle.close();
      return;
    }
    if (handle._nativeHandle !== undefined) {
      _clearTimeout(handle._nativeHandle);
      handle._destroyed = true;
      if (handle._id !== undefined) _timerById.delete(handle._id);
      return;
    }
  }
  // Handle numeric ID
  if (typeof handle === 'number' || typeof handle === 'string') {
    var numId = Number(handle);
    var timerObj = _timerById.get(numId);
    if (timerObj) {
      timerObj.close();
      return;
    }
  }
  _clearTimeout(handle);
}

// Add util.promisify.custom so that promisify(timers.setTimeout) ===
// timerPromises.setTimeout (same for setImmediate).
// We need to use a lazy getter since timers/promises requires timers,
// and we don't want circular dep issues at load time.
var _promisifyCustomSymbol = (
  typeof Symbol === 'function' && typeof Symbol.for === 'function'
    ? Symbol.for('nodejs.util.promisify.custom')
    : null
);

if (_promisifyCustomSymbol) {
  Object.defineProperty(setTimeout$1, _promisifyCustomSymbol, {
    get: function() {
      return require('timers/promises').setTimeout;
    },
    configurable: true,
    enumerable: false,
  });
  Object.defineProperty(setImmediate$1, _promisifyCustomSymbol, {
    get: function() {
      return require('timers/promises').setImmediate;
    },
    configurable: true,
    enumerable: false,
  });
}

// Cache the promises sub-module so that timers.promises === require('timers/promises')
var _promisesModule = null;

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1,
  Timeout: Timeout,
  Immediate: Immediate,
  // Deprecated Node.js APIs -- stubs for compat
  active: function active(item) {
    // In Node.js, active() re-activates the timer — it schedules item._onTimeout()
    // after item._idleTimeout ms. Only process items with a valid _idleTimeout.
    if (!item || typeof item._idleTimeout !== 'number' || item._idleTimeout < 0) return;
    item._idleStart = Date.now();
    item._idleNext = item._idleNext || item;
    item._idlePrev = item._idlePrev || item;
    // Cancel any existing active handle
    if (item._exactActiveHandle) {
      _clearTimeout(item._exactActiveHandle);
    }
    var delay = item._idleTimeout;
    item._exactActiveHandle = _setTimeout(function() {
      item._exactActiveHandle = null;
      if (typeof item._onTimeout === 'function') {
        item._onTimeout();
      }
    }, delay);
  },
  _unrefActive: function _unrefActive(item) {
    // Deprecated Node.js API: schedule item._onTimeout() after item._idleTimeout ms.
    // The timer is "unref'd" — won't keep the event loop alive by itself.
    if (!item || typeof item._idleTimeout !== 'number' || item._idleTimeout < 0) return;
    if (item._exactUnrefHandle) {
      _clearTimeout(item._exactUnrefHandle);
    }
    var delay = item._idleTimeout;
    var handle = _setTimeout(function() {
      item._exactUnrefHandle = null;
      if (typeof item._onTimeout === 'function') {
        item._onTimeout();
      }
    }, delay);
    item._exactUnrefHandle = handle;
    // Unref the timer so it doesn't keep the event loop alive on its own
    if (handle && typeof handle === 'object' && typeof handle.unref === 'function') {
      handle.unref();
    } else if (typeof globalThis.__exactTimerUnref === 'function' && typeof handle === 'number') {
      globalThis.__exactTimerUnref(handle);
    }
  },
  enroll: function enroll(item, msecs) {
    if (typeof msecs !== 'number') {
      var err = new TypeError('The "msecs" argument must be of type number. Received type ' + typeof msecs);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (msecs < 0 || !isFinite(msecs)) {
      var err2 = new RangeError('The value of "msecs" is out of range. It must be a non-negative finite number. Received ' + msecs);
      err2.code = 'ERR_OUT_OF_RANGE';
      throw err2;
    }
    item._idleTimeout = msecs;
  },
  unenroll: function unenroll(item) {
    item._idleTimeout = -1;
    // Cancel any pending _unrefActive timer handle
    if (item._exactUnrefHandle) {
      _clearTimeout(item._exactUnrefHandle);
      item._exactUnrefHandle = null;
    }
    // Cancel any pending active timer handle
    if (item._exactActiveHandle) {
      _clearTimeout(item._exactActiveHandle);
      item._exactActiveHandle = null;
    }
  },
  // promises sub-module - use getter to ensure identity with require('timers/promises')
  get promises() {
    if (!_promisesModule) {
      _promisesModule = require('timers/promises');
    }
    return _promisesModule;
  }
};
