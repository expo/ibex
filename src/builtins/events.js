// Node.js-compatible EventEmitter implementation
// Matches Node.js internal storage format:
//   - Single listener: _events[name] = fn
//   - Multiple listeners: _events[name] = [fn1, fn2, ...]
//   - Once-wrapped listeners have .listener property

var errorMonitorSymbol = Symbol('events.errorMonitor');

var _defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    var err = new TypeError(
      'The "listener" argument must be of type function. Received ' +
      (listener === null ? 'null' : typeof listener)
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
}

function EventEmitter() {
  if (!(this instanceof EventEmitter) && this && this.constructor !== EventEmitter) {
    // Called via .call() on a foreign object - init it
  }
  EventEmitter.init.call(this);
}

EventEmitter.init = function init(opts) {
  if (this._events === undefined || this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
  }
  this._maxListeners = this._maxListeners || undefined;
};

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return _defaultMaxListeners;
  },
  set: function(val) {
    if (typeof val !== 'number' || val < 0 || val !== val) {
      var err;
      if (typeof val !== 'number') {
        err = new TypeError(
          'The "defaultMaxListeners" property must be of type number. Received ' +
          typeof val
        );
        err.code = 'ERR_INVALID_ARG_TYPE';
      } else {
        err = new RangeError(
          'The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + val
        );
        err.code = 'ERR_OUT_OF_RANGE';
      }
      throw err;
    }
    _defaultMaxListeners = val;
  }
});

EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || n !== n) {
    var err;
    if (typeof n !== 'number') {
      err = new TypeError(
        'The "n" argument must be of type number. Received type ' + typeof n
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
    } else {
      err = new RangeError(
        'The value of "n" is out of range. It must be a non-negative number. Received ' + n
      );
      err.code = 'ERR_OUT_OF_RANGE';
    }
    throw err;
  }
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  if (this._maxListeners === undefined) {
    return EventEmitter.defaultMaxListeners;
  }
  return this._maxListeners;
};

function _getMaxListeners(emitter) {
  if (emitter._maxListeners === undefined) {
    return EventEmitter.defaultMaxListeners;
  }
  return emitter._maxListeners;
}

function _addListener(target, eventName, listener, prepend) {
  var events;
  var existing;
  var m;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._maxListeners = target._maxListeners || undefined;
  }

  // Emit newListener event before adding (Node.js behavior)
  if (events.newListener !== undefined) {
    target.emit('newListener', eventName, listener.listener ? listener.listener : listener);
    // Re-read events in case newListener handler added stuff
    events = target._events;
  }

  existing = events[eventName];

  if (existing === undefined) {
    // First listener for this event
    events[eventName] = listener;
  } else if (typeof existing === 'function') {
    // Going from 1 to 2 listeners
    events[eventName] = prepend ? [listener, existing] : [existing, listener];
  } else {
    // Already an array
    if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }
  }

  // Check for listener leak
  m = _getMaxListeners(target);
  if (m > 0) {
    var count = typeof events[eventName] === 'function' ? 1 :
      (events[eventName] ? events[eventName].length : 0);
    if (count > m && !(Array.isArray(events[eventName]) && events[eventName].warned)) {
      if (Array.isArray(events[eventName])) {
        events[eventName].warned = true;
      }
      // In Node.js this emits a warning via process.emitWarning
      // For now we just set the warned flag
      var w = new Error(
        'Possible EventEmitter memory leak detected. ' +
        count + ' ' + String(eventName) + ' listeners added to [' +
        (target.constructor ? target.constructor.name : 'EventEmitter') +
        ']. MaxListeners is ' + m +
        '. Use emitter.setMaxListeners() to increase limit'
      );
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = eventName;
      w.count = count;
      if (typeof console !== 'undefined' && typeof console.warn === 'function') {
        // Suppress warning output during tests to avoid noise
      }
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
  var state = { fired: false, target: target, type: eventName, listener: listener, wrapFn: undefined };
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
  var events = this._events;
  if (events === undefined) return this;

  var list = events[eventName];
  if (list === undefined) return this;

  if (list === listener || list.listener === listener) {
    // Single listener, remove it
    delete events[eventName];

    if (events.removeListener) {
      this.emit('removeListener', eventName, list.listener || list);
    }
  } else if (typeof list !== 'function') {
    // Array of listeners
    var position = -1;
    for (var i = list.length - 1; i >= 0; i--) {
      if (list[i] === listener || (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0) return this;

    var originalListener = list[position].listener || list[position];

    if (position === 0) {
      list.shift();
    } else {
      list.splice(position, 1);
    }

    if (list.length === 1) {
      events[eventName] = list[0];
    }

    if (list.length === 0) {
      delete events[eventName];
    }

    if (events.removeListener) {
      this.emit('removeListener', eventName, originalListener);
    }
  }

  return this;
};

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners = function removeAllListeners(eventName) {
  var events = this._events;
  if (events === undefined) return this;

  // No removeListener listeners, just clear
  if (events.removeListener === undefined) {
    if (arguments.length === 0) {
      this._events = Object.create(null);
    } else if (events[eventName] !== undefined) {
      delete events[eventName];
    }
    return this;
  }

  // Emit removeListener for all except removeListener itself
  if (arguments.length === 0) {
    var keys = Object.keys(events);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = Object.create(null);
    return this;
  }

  var listeners = events[eventName];
  if (typeof listeners === 'function') {
    this.removeListener(eventName, listeners);
  } else if (listeners !== undefined) {
    for (var i = listeners.length - 1; i >= 0; i--) {
      this.removeListener(eventName, listeners[i]);
    }
  }

  return this;
};

EventEmitter.prototype.emit = function emit(eventName) {
  var events = this._events;
  var doError = (eventName === 'error');

  if (events !== undefined) {
    if (doError && events[errorMonitorSymbol] !== undefined) {
      // Fire errorMonitor listeners first
      var monitorArgs = [];
      for (var k = 1; k < arguments.length; k++) monitorArgs.push(arguments[k]);
      var monitorListeners = events[errorMonitorSymbol];
      if (typeof monitorListeners === 'function') {
        monitorListeners.apply(this, monitorArgs);
      } else {
        var monitorCopy = monitorListeners.slice();
        for (var k = 0; k < monitorCopy.length; k++) {
          monitorCopy[k].apply(this, monitorArgs);
        }
      }
    }
    doError = doError && events.error === undefined;
  } else {
    doError = doError;
  }

  if (doError) {
    var er;
    if (arguments.length > 1) {
      er = arguments[1];
    }
    if (er instanceof Error) {
      throw er;
    }
    var stringifiedEr;
    try {
      stringifiedEr = typeof er === 'object' && er !== null ?
        require('util').inspect(er) : String(er);
    } catch (e) {
      stringifiedEr = '[object Object]';
    }
    var err = new Error('Unhandled error.' + (er !== undefined ? ' (' + stringifiedEr + ')' : ''));
    err.code = 'ERR_UNHANDLED_ERROR';
    err.context = er;
    throw err;
  }

  var handler = events ? events[eventName] : undefined;
  if (handler === undefined) return false;

  var args = [];
  for (var i = 1; i < arguments.length; i++) {
    args.push(arguments[i]);
  }

  if (typeof handler === 'function') {
    handler.apply(this, args);
  } else {
    var current = handler.slice();
    for (var i = 0; i < current.length; i++) {
      current[i].apply(this, args);
    }
  }

  return true;
};

EventEmitter.prototype.listeners = function listeners(eventName) {
  var events = this._events;
  if (events === undefined) return [];
  var list = events[eventName];
  if (list === undefined) return [];
  if (typeof list === 'function') {
    return [list.listener || list];
  }
  var out = [];
  for (var i = 0; i < list.length; i++) {
    out.push(list[i].listener || list[i]);
  }
  return out;
};

EventEmitter.prototype.rawListeners = function rawListeners(eventName) {
  var events = this._events;
  if (events === undefined) return [];
  var list = events[eventName];
  if (list === undefined) return [];
  if (typeof list === 'function') {
    return [list];
  }
  return list.slice();
};

EventEmitter.prototype.listenerCount = function listenerCount(eventName, listener) {
  var events = this._events;
  if (events === undefined) return 0;
  var list = events[eventName];
  if (list === undefined) return 0;

  if (listener !== undefined) {
    // Count only matching listeners
    var count = 0;
    if (typeof list === 'function') {
      if (list === listener || list.listener === listener) count = 1;
    } else {
      for (var i = 0; i < list.length; i++) {
        if (list[i] === listener || (list[i].listener && list[i].listener === listener)) {
          count++;
        }
      }
    }
    return count;
  }

  if (typeof list === 'function') return 1;
  return list.length;
};

EventEmitter.prototype.eventNames = function eventNames() {
  if (this._events === undefined) return [];
  return Reflect.ownKeys(this._events);
};

// Static once
function once(emitter, eventName, options) {
  return new Promise(function(resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(eventName, resolver);
      reject(err);
    }
    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        args.push(arguments[i]);
      }
      resolve(args);
    }
    eventTargetAgnosticAddListener(emitter, eventName, resolver, { once: true });
    if (eventName !== 'error' && typeof emitter.on === 'function') {
      emitter.once('error', errorListener);
    }
  });
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags && flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    emitter.addEventListener(name, function wrapListener(arg) {
      if (flags && flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  }
}

// Static on (async iterator)
function on(emitter, eventName, options) {
  var unconsumed = [];
  var waiting = [];
  var done = false;
  var errored = null;

  function handler() {
    var args = [];
    for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
    if (waiting.length > 0) {
      var resolve = waiting.shift();
      resolve({ value: args, done: false });
    } else {
      unconsumed.push(args);
    }
  }

  function errorHandler(err) {
    errored = err;
    if (waiting.length > 0) {
      var reject = waiting.shift();
      reject(err);
    }
  }

  emitter.on(eventName, handler);
  if (eventName !== 'error') emitter.on('error', errorHandler);

  var iterator = {};
  iterator.next = function() {
    if (unconsumed.length > 0) {
      return Promise.resolve({ value: unconsumed.shift(), done: false });
    }
    if (errored) return Promise.reject(errored);
    if (done) return Promise.resolve({ value: undefined, done: true });
    return new Promise(function(resolve, reject) {
      waiting.push(resolve);
    });
  };
  iterator.return = function() {
    done = true;
    emitter.removeListener(eventName, handler);
    if (eventName !== 'error') emitter.removeListener('error', errorHandler);
    while (waiting.length > 0) {
      waiting.shift()({ value: undefined, done: true });
    }
    return Promise.resolve({ value: undefined, done: true });
  };
  iterator[Symbol.asyncIterator] = function() { return iterator; };
  return iterator;
}

function getEventListeners(emitter, eventName) {
  if (emitter && typeof emitter.listeners === 'function') {
    return emitter.listeners(eventName);
  }
  return [];
}

// Static listenerCount (deprecated in Node.js but still supported)
function _listenerCount(emitter, eventName) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(eventName);
  }
  return EventEmitter.prototype.listenerCount.call(emitter, eventName);
}

// Static getMaxListeners
function getMaxListeners(emitter) {
  if (typeof emitter.getMaxListeners === 'function') {
    return emitter.getMaxListeners();
  }
  return _getMaxListeners(emitter);
}

// Static setMaxListeners
function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || n !== n) {
    var err;
    if (typeof n !== 'number') {
      err = new TypeError(
        'The "n" argument must be of type number. Received type ' + typeof n
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
    } else {
      err = new RangeError(
        'The value of "n" is out of range. It must be a non-negative number. Received ' + n
      );
      err.code = 'ERR_OUT_OF_RANGE';
    }
    throw err;
  }

  // If extra arguments, set on each emitter
  for (var i = 1; i < arguments.length; i++) {
    var emitter = arguments[i];
    if (emitter === undefined || emitter === null ||
        (typeof emitter !== 'object' && typeof emitter !== 'function')) {
      var argErr = new TypeError(
        'The "eventTargets[' + (i - 1) + ']" argument must be an instance of EventTarget or EventEmitter'
      );
      argErr.code = 'ERR_INVALID_ARG_TYPE';
      throw argErr;
    }
    if (typeof emitter.setMaxListeners === 'function') {
      emitter.setMaxListeners(n);
    } else {
      emitter._maxListeners = n;
    }
  }

  // If no emitters, set the default
  if (arguments.length <= 1) {
    EventEmitter.defaultMaxListeners = n;
  }
}

// Assign static properties
EventEmitter.EventEmitter = EventEmitter;
EventEmitter.once = once;
EventEmitter.on = on;
EventEmitter.getEventListeners = getEventListeners;
EventEmitter.listenerCount = _listenerCount;
EventEmitter.getMaxListeners = getMaxListeners;
EventEmitter.setMaxListeners = setMaxListeners;
EventEmitter.errorMonitor = errorMonitorSymbol;
EventEmitter.init = EventEmitter.init;

module.exports = EventEmitter;
module.exports.__esModule = true;
module.exports.EventEmitter = EventEmitter;
module.exports.default = EventEmitter;
module.exports.once = once;
module.exports.on = on;
module.exports.getEventListeners = getEventListeners;
module.exports.listenerCount = _listenerCount;
module.exports.getMaxListeners = getMaxListeners;
module.exports.setMaxListeners = setMaxListeners;
module.exports.errorMonitor = errorMonitorSymbol;
module.exports.defaultMaxListeners = EventEmitter.defaultMaxListeners;
