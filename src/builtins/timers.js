// Capture references to global timer functions at module load time
// so they survive deletion from global scope
var _setTimeout = globalThis.setTimeout;
var _clearTimeout = globalThis.clearTimeout;
var _setInterval = globalThis.setInterval;
var _clearInterval = globalThis.clearInterval;
var _FuncApply = Function.prototype.apply;
var _FuncCall = Function.prototype.call;

function _validateTimerCallback(callback, name) {
  if (typeof callback !== 'function') {
    var err = new TypeError('[ERR_INVALID_ARG_TYPE]: The "' + name + '" argument must be of type function. Received type ' + typeof callback);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

// Timer wrapper class for ref/unref/refresh/hasRef/Symbol.toPrimitive
var _nextTimerId = 1;

function Timeout(callback, delay, args, isRepeat) {
  this._callback = callback;
  this._delay = delay || 0;
  this._args = args;
  this._isRepeat = isRepeat || false;
  this._refed = true;
  this._destroyed = false;
  this._idleTimeout = this._delay;
  this._id = _nextTimerId++;

  var self = this;
  if (isRepeat) {
    this._nativeHandle = _setInterval(function() {
      _FuncCall.call(_FuncApply, self._callback, null, self._args);
    }, this._delay);
  } else {
    this._nativeHandle = _setTimeout(function() {
      self._destroyed = true;
      _FuncCall.call(_FuncApply, self._callback, null, self._args);
    }, this._delay);
  }
}

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
    var self = this;
    this._nativeHandle = _setInterval(function() {
      _FuncCall.call(_FuncApply, self._callback, null, self._args);
    }, this._delay);
  } else {
    _clearTimeout(this._nativeHandle);
    var self2 = this;
    this._nativeHandle = _setTimeout(function() {
      self2._destroyed = true;
      _FuncCall.call(_FuncApply, self2._callback, null, self2._args);
    }, this._delay);
  }
  return this;
};

Timeout.prototype.close = function() {
  if (this._isRepeat) {
    _clearInterval(this._nativeHandle);
  } else {
    _clearTimeout(this._nativeHandle);
  }
  this._destroyed = true;
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

  var self = this;
  this._nativeHandle = _setTimeout(function() {
    self._destroyed = true;
    _FuncCall.call(_FuncApply, self._callback, null, self._args);
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

Immediate.prototype[Symbol.dispose] = function() {
  if (!this._destroyed) {
    _clearTimeout(this._nativeHandle);
    this._destroyed = true;
  }
};

Immediate.prototype._onImmediate = undefined;

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
      return;
    }
  }
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
    if (handle._nativeHandle !== undefined) {
      _clearTimeout(handle._nativeHandle);
      handle._destroyed = true;
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

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1,
  // Deprecated Node.js APIs -- stubs for compat
  active: function active(item) {
    // In Node.js, active() re-activates the timer and sets linked-list fields.
    // Only process items with a valid (non-negative) _idleTimeout.
    if (item && typeof item._idleTimeout === 'number' && item._idleTimeout >= 0) {
      item._idleStart = Date.now();
      item._idleNext = item._idleNext || item;
      item._idlePrev = item._idlePrev || item;
    }
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
  },
  // promises sub-module
  promises: (typeof require === 'function') ? require('timers/promises') : {}
};
