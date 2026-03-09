// timers/promises — Node.js-compatible timer promise APIs
'use strict';

var _nativeSetTimeout = globalThis.setTimeout;
var _nativeClearTimeout = globalThis.clearTimeout;
var _nativeSetInterval = globalThis.setInterval;
var _nativeClearInterval = globalThis.clearInterval;

// Validate that 'signal' is an AbortSignal-like object.
function validateAbortSignal(signal, name) {
  if (signal !== undefined && signal !== null) {
    if (typeof signal !== 'object' ||
        typeof signal.aborted !== 'boolean') {
      var err = new TypeError(
        'The "' + name + '" argument must be an instance of AbortSignal. ' +
        'Received type ' + (signal === null ? 'null' : typeof signal)
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
}

// Validate that 'ref' is a boolean.
function validateBoolean(value, name) {
  if (value !== undefined && typeof value !== 'boolean') {
    var err = new TypeError(
      'The "' + name + '" argument must be of type boolean. ' +
      'Received type ' + (value === null ? 'null' : typeof value)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

// Validate that 'options' is an object (if provided and not undefined/null).
function validateOptions(options, name) {
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options)) {
      var err = new TypeError(
        'The "' + name + '" argument must be of type object. ' +
        'Received type ' + (options === null ? 'null' : typeof options) +
        ' (' + String(options) + ')'
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
}

function createAbortError(signal) {
  var err;
  if (signal && signal.reason !== undefined) {
    // AbortSignal.abort(reason) — wrap if reason is not an Error
    if (signal.reason instanceof Error) {
      return signal.reason;
    }
    err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    err.cause = signal.reason;
    return err;
  }
  err = new Error('The operation was aborted');
  err.code = 'ABORT_ERR';
  err.name = 'AbortError';
  return err;
}

// setTimeout(delay[, value[, options]]) → Promise<value>
function setTimeoutPromise(delay, value, options) {
  // Validate delay type (must be undefined/null or coercible to number)
  if (delay !== undefined && delay !== null && typeof delay !== 'number') {
    if (typeof delay === 'string' || typeof delay === 'boolean') {
      var delayErr = new TypeError(
        'The "delay" argument must be of type number. Received type ' + typeof delay
      );
      delayErr.code = 'ERR_INVALID_ARG_TYPE';
      return Promise.reject(delayErr);
    }
  }
  var delayMs = delay == null ? 1 : Math.max(1, Number(delay) | 0);

  // Handle options that are not objects (not undefined/null/object)
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options)) {
      var err = new TypeError(
        'The "options" argument must be of type object. Received type ' +
        (options === null ? 'null' : typeof options) + ' (' + String(options) + ')'
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      return Promise.reject(err);
    }
    // Validate signal
    var signal = options.signal;
    if (signal !== undefined) {
      if (signal === null || typeof signal !== 'object' || typeof signal.aborted !== 'boolean') {
        var sigErr = new TypeError(
          'The "options.signal" property must be an instance of AbortSignal. ' +
          'Received type ' + (signal === null ? 'null' : typeof signal)
        );
        sigErr.code = 'ERR_INVALID_ARG_TYPE';
        return Promise.reject(sigErr);
      }
    }
    // Validate ref
    var ref = options.ref;
    if (ref !== undefined && typeof ref !== 'boolean') {
      var refErr = new TypeError(
        'The "options.ref" property must be of type boolean. ' +
        'Received type ' + (ref === null ? 'null' : typeof ref)
      );
      refErr.code = 'ERR_INVALID_ARG_TYPE';
      return Promise.reject(refErr);
    }
    // If signal is already aborted, reject immediately
    if (signal && signal.aborted) {
      return Promise.reject(createAbortError(signal));
    }
  }

  var optSignal = options && options.signal;
  var optRef = options && options.ref;

  return new Promise(function(resolve, reject) {
    if (optSignal && optSignal.aborted) {
      return reject(createAbortError(optSignal));
    }

    var handle = _nativeSetTimeout(function() {
      if (optSignal) {
        optSignal.removeEventListener('abort', onAbort);
      }
      resolve(value);
    }, delayMs);

    // Handle ref option
    if (optRef === false && handle && typeof handle.unref === 'function') {
      handle.unref();
    }

    function onAbort() {
      if (handle) {
        if (typeof handle.close === 'function') {
          handle.close();
        } else if (typeof _nativeClearTimeout === 'function') {
          _nativeClearTimeout(handle);
        }
      }
      reject(createAbortError(optSignal));
    }

    if (optSignal) {
      optSignal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

// setImmediate([value[, options]]) → Promise<value>
function setImmediatePromise(value, options) {
  // Handle options that are not objects (not undefined/null/object)
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options)) {
      var err = new TypeError(
        'The "options" argument must be of type object. Received type ' +
        (options === null ? 'null' : typeof options) + ' (' + String(options) + ')'
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      return Promise.reject(err);
    }
    // Validate signal
    var signal = options.signal;
    if (signal !== undefined) {
      if (signal === null || typeof signal !== 'object' || typeof signal.aborted !== 'boolean') {
        var sigErr = new TypeError(
          'The "options.signal" property must be an instance of AbortSignal. ' +
          'Received type ' + (signal === null ? 'null' : typeof signal)
        );
        sigErr.code = 'ERR_INVALID_ARG_TYPE';
        return Promise.reject(sigErr);
      }
    }
    // Validate ref
    var ref = options.ref;
    if (ref !== undefined && typeof ref !== 'boolean') {
      var refErr = new TypeError(
        'The "options.ref" property must be of type boolean. ' +
        'Received type ' + (ref === null ? 'null' : typeof ref)
      );
      refErr.code = 'ERR_INVALID_ARG_TYPE';
      return Promise.reject(refErr);
    }
  }

  var optSignal = options && options.signal;
  var optRef = options && options.ref;

  // If signal is already aborted, reject immediately
  if (optSignal && optSignal.aborted) {
    return Promise.reject(createAbortError(optSignal));
  }

  return new Promise(function(resolve, reject) {
    var handle = _nativeSetTimeout(function() {
      if (optSignal) {
        optSignal.removeEventListener('abort', onAbort);
      }
      resolve(value);
    }, 0);

    // Handle ref option
    if (optRef === false && handle && typeof handle.unref === 'function') {
      handle.unref();
    }

    function onAbort() {
      if (handle) {
        if (typeof handle.close === 'function') {
          handle.close();
        } else if (typeof _nativeClearTimeout === 'function') {
          _nativeClearTimeout(handle);
        }
      }
      reject(createAbortError(optSignal));
    }

    if (optSignal) {
      optSignal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

// setInterval(delay[, value[, options]]) → AsyncIterable<value>
// Returns an async iterator that yields `value` every `delay` ms.
function setIntervalIterable(delay, value, options) {
  // Validate options eagerly (type errors surface when iterating)
  var optSignal, optRef;
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options)) {
      // Lazy-reject (throw when .next() is called)
      var optErr = new TypeError(
        'The "options" argument must be of type object. Received type ' +
        (options === null ? 'null' : typeof options) + ' (' + String(options) + ')'
      );
      optErr.code = 'ERR_INVALID_ARG_TYPE';
      return makeEagerRejectIterable(optErr);
    }
    optSignal = options.signal;
    if (optSignal !== undefined) {
      if (optSignal === null || typeof optSignal !== 'object' || typeof optSignal.aborted !== 'boolean') {
        var sigErr = new TypeError(
          'The "options.signal" property must be an instance of AbortSignal. ' +
          'Received type ' + (optSignal === null ? 'null' : typeof optSignal)
        );
        sigErr.code = 'ERR_INVALID_ARG_TYPE';
        return makeEagerRejectIterable(sigErr);
      }
    }
    optRef = options.ref;
    if (optRef !== undefined && typeof optRef !== 'boolean') {
      var refErr = new TypeError(
        'The "options.ref" property must be of type boolean. ' +
        'Received type ' + (optRef === null ? 'null' : typeof optRef)
      );
      refErr.code = 'ERR_INVALID_ARG_TYPE';
      return makeEagerRejectIterable(refErr);
    }
  }

  var delayMs = delay == null ? 1 : Math.max(1, Number(delay) | 0);

  return makeSetIntervalIterable(delayMs, value, optSignal, optRef);
}

function makeEagerRejectIterable(err) {
  var obj = {};
  obj[Symbol.asyncIterator] = function() {
    var done = false;
    return {
      next: function() {
        if (done) return Promise.resolve({ value: undefined, done: true });
        done = true;
        return Promise.reject(err);
      },
      return: function() {
        done = true;
        return Promise.resolve({ value: undefined, done: true });
      }
    };
  };
  return obj;
}

function makeSetIntervalIterable(delayMs, value, signal, ref) {
  // The returned object is BOTH an async iterable AND an async iterator.
  // obj[Symbol.asyncIterator]() returns obj itself, so obj.next() works directly.
  // This matches Node.js's behavior where setInterval returns an object with
  // both the asyncIterator method and the next/return methods.
  var aborted = false;
  var abortError = null;
  var pendingResolve = null;
  var pendingReject = null;
  var handle = null;
  var listenerRemoved = false;

  function cleanup() {
    if (handle) {
      if (_nativeClearInterval) {
        _nativeClearInterval(handle);
      } else if (handle.close) {
        handle.close();
      }
      handle = null;
    }
    if (signal && !listenerRemoved) {
      listenerRemoved = true;
      signal.removeEventListener('abort', onAbort);
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

  if (signal) {
    if (signal.aborted) {
      aborted = true;
      abortError = createAbortError(signal);
    } else {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  }

  function scheduleNext() {
    handle = _nativeSetInterval(function() {
      if (pendingResolve) {
        var res = pendingResolve;
        pendingResolve = null;
        pendingReject = null;
        res({ value: value, done: false });
      }
    }, delayMs);
    if (ref === false && handle && typeof handle.unref === 'function') {
      handle.unref();
    }
  }

  var obj = {
    next: function() {
      if (aborted) {
        return Promise.reject(abortError);
      }
      return new Promise(function(resolve, reject) {
        if (aborted) {
          return reject(abortError);
        }
        pendingResolve = function(result) {
          // After delivering a value, clear the interval handle so a fresh
          // one is scheduled for the next call to .next()
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
      return Promise.resolve({ value: undefined, done: true });
    }
  };

  // Make the object both an async iterable and an async iterator.
  // obj[Symbol.asyncIterator]() returns obj itself.
  obj[Symbol.asyncIterator] = function() {
    return obj;
  };

  return obj;
}

// scheduler.yield() → Promise<void>
// Yields to the microtask/task queue (like setImmediate(0))
function schedulerYield() {
  return new Promise(function(resolve) {
    _nativeSetTimeout(resolve, 0);
  });
}

// scheduler.wait(delay[, options]) → Promise<void>
function schedulerWait(delay, options) {
  return setTimeoutPromise(delay, undefined, options);
}

// Create a Scheduler class with ERR_ILLEGAL_CONSTRUCTOR to match Node.js
function Scheduler() {
  var err = new TypeError('Illegal constructor');
  err.code = 'ERR_ILLEGAL_CONSTRUCTOR';
  throw err;
}
Scheduler.prototype['yield'] = schedulerYield;
Scheduler.prototype['wait'] = schedulerWait;

// Create the singleton scheduler instance via Object.create to bypass constructor check
var scheduler = Object.create(Scheduler.prototype);
scheduler.constructor = Scheduler;

module.exports = {
  setTimeout: setTimeoutPromise,
  setImmediate: setImmediatePromise,
  setInterval: setIntervalIterable,
  scheduler: scheduler,
};
