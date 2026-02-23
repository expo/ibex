// Capture references to global timer functions at module load time
// so they survive deletion from global scope
var _setTimeout = globalThis.setTimeout;
var _clearTimeout = globalThis.clearTimeout;
var _setInterval = globalThis.setInterval;
var _clearInterval = globalThis.clearInterval;

function _validateTimerCallback(callback, name) {
  if (typeof callback !== 'function') {
    var err = new TypeError('[ERR_INVALID_ARG_TYPE]: The "' + name + '" argument must be of type function. Received type ' + typeof callback);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

function setTimeout$1(callback, delay) {
  _validateTimerCallback(callback, 'callback');
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof _setTimeout !== "function") {
    throw new Error("setTimeout is not available");
  }
  return _setTimeout(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearTimeout$1(handle) {
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
  return _setInterval(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearInterval$1(handle) {
  if (typeof _clearInterval === "function") {
    _clearInterval(handle);
  }
}

function setImmediate$1(callback) {
  _validateTimerCallback(callback, 'callback');
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  return setTimeout$1(function() {
    callback.apply(null, args);
  }, 0);
}

function clearImmediate$1(handle) {
  clearTimeout$1(handle);
}

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1,
  // Deprecated Node.js APIs — stubs for compat
  active: function active(item) {
    // In Node.js, timers.active() resets the timer.
    // Stub: no-op for compatibility.
  },
  _unrefActive: function _unrefActive(item) {
    // Deprecated alias for timers.active() with unref behavior.
    // Stub: no-op for compatibility.
  },
  enroll: function enroll(item, msecs) {
    item._idleTimeout = msecs;
  },
  unenroll: function unenroll(item) {
    item._idleTimeout = -1;
  }
};
