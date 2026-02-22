function EventEmitter() {
  this._events = Object.create(null);
  this._maxListeners = 10;
}

EventEmitter.prototype._ensure = function(eventName) {
  if (!this._events) this._events = Object.create(null);
  var list = this._events[eventName];
  if (!list) {
    list = [];
    this._events[eventName] = list;
  }
  return list;
};

EventEmitter.prototype.on = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  this._ensure(eventName).push(listener);
  return this;
};

EventEmitter.prototype.addListener = EventEmitter.prototype.on;

EventEmitter.prototype.once = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  var emitter = this;
  var wrapped = function() {
    emitter.removeListener(eventName, wrapped);
    return listener.apply(emitter, arguments);
  };
  wrapped._once = true;
  wrapped._listener = listener;
  this._ensure(eventName).push(wrapped);
  return this;
};

EventEmitter.prototype.prependListener = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  this._ensure(eventName).unshift(listener);
  return this;
};

EventEmitter.prototype.prependOnceListener = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  var emitter = this;
  var wrapped = function() {
    emitter.removeListener(eventName, wrapped);
    return listener.apply(emitter, arguments);
  };
  wrapped._once = true;
  wrapped._listener = listener;
  this._ensure(eventName).unshift(wrapped);
  return this;
};

EventEmitter.prototype.setMaxListeners = function(n) {
  if (typeof n !== 'number' || n < 0 || !isFinite(n)) {
    return this;
  }
  this._maxListeners = Math.floor(n);
  return this;
};

EventEmitter.prototype.getMaxListeners = function() {
  return this._maxListeners;
};

EventEmitter.prototype.removeListener = function(eventName, listener) {
  if (!eventName || !listener) {
    return this;
  }
  var listeners = this._events && this._events[eventName];
  if (!listeners) return this;
  var next = [];
  for (var i = 0; i < listeners.length; i++) {
    var entry = listeners[i];
    if (entry === listener || entry._listener === listener) {
      continue;
    }
    next.push(entry);
  }
  if (next.length) {
    this._events[eventName] = next;
  } else {
    delete this._events[eventName];
  }
  return this;
};

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners = function(eventName) {
  if (!this._events) this._events = Object.create(null);
  if (eventName !== undefined) {
    delete this._events[eventName];
  } else {
    this._events = Object.create(null);
  }
  return this;
};

EventEmitter.prototype.emit = function(eventName) {
  var listeners = this._events && this._events[eventName];
  if (!listeners || !listeners.length) return false;
  var args = [];
  for (var i = 1; i < arguments.length; i++) {
    args.push(arguments[i]);
  }
  var current = listeners.slice();
  for (var i = 0; i < current.length; i++) {
    var listener = current[i];
    listener.apply(this, args);
    if (listener._once) {
      this.removeListener(eventName, listener);
    }
  }
  return true;
};

EventEmitter.prototype.listeners = function(eventName) {
  var listeners = this._events && this._events[eventName];
  if (!listeners) return [];
  var out = [];
  for (var i = 0; i < listeners.length; i++) {
    out.push(listeners[i]._listener || listeners[i]);
  }
  return out;
};

EventEmitter.prototype.rawListeners = function(eventName) {
  var listeners = this._events && this._events[eventName];
  return listeners ? listeners.slice() : [];
};

EventEmitter.prototype.listenerCount = function(eventName) {
  var listeners = this._events && this._events[eventName];
  return listeners ? listeners.length : 0;
};

EventEmitter.prototype.eventNames = function() {
  if (!this._events) return [];
  var out = [];
  for (var key in this._events) {
    if (Object.prototype.hasOwnProperty.call(this._events, key)) {
      out.push(key);
    }
  }
  return out;
};

function once(emitter, eventName) {
  return new Promise(function(resolve, reject) {
    if (!emitter || typeof emitter.once !== "function") {
      reject(new TypeError("Expected an emitter with once()"));
      return;
    }
    emitter.once(eventName, function() {
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        args.push(arguments[i]);
      }
      resolve(args);
    });
  });
}

function on(emitter, eventName) {
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

EventEmitter.EventEmitter = EventEmitter;
EventEmitter.once = once;
EventEmitter.on = on;
EventEmitter.getEventListeners = getEventListeners;
EventEmitter.defaultMaxListeners = 10;

module.exports = EventEmitter;
module.exports.__esModule = true;
module.exports.EventEmitter = EventEmitter;
module.exports.default = EventEmitter;
module.exports.once = once;
module.exports.on = on;
module.exports.getEventListeners = getEventListeners;
