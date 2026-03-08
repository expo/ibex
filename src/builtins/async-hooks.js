var _hooksEnabled = false;
var _noop = function() {};
var _idCounter = 1;
var _activeHooks = [];
var _resourceFinalizer = typeof FinalizationRegistry === 'function'
  ? new FinalizationRegistry(function(asyncId) {
      __emitDestroy(asyncId);
    })
  : null;

/* ------------------------------------------------------------------ */
/*  Global async context tracking                                      */
/* ------------------------------------------------------------------ */

var _allInstances = [];

function _captureContext() {
  var ctx = [];
  for (var i = 0; i < _allInstances.length; i++) {
    var als = _allInstances[i];
    ctx.push({ als: als, store: als._store });
  }
  return ctx;
}

function _restoreContext(ctx) {
  var prev = _captureContext();
  for (var i = 0; i < ctx.length; i++) {
    ctx[i].als._store = ctx[i].store;
  }
  return prev;
}

var _fnApply = Function.prototype.apply;

function _wrapCallback(fn) {
  if (typeof fn !== 'function') return fn;
  var captured = _captureContext();
  return function() {
    var prev = _restoreContext(captured);
    try {
      return _fnApply.call(fn, this, arguments);
    } finally {
      _restoreContext(prev);
    }
  };
}

function _wrapPromiseCallback(fn) {
  if (typeof fn !== 'function') return fn;
  var captured = _captureContext();
  return function() {
    var prev = _restoreContext(captured);
    try {
      return _fnApply.call(fn, undefined, arguments);
    } finally {
      _restoreContext(prev);
    }
  };
}

/* ------------------------------------------------------------------ */
/*  Patch Promise.prototype.then / catch / finally                     */
/* ------------------------------------------------------------------ */
(function() {
  if (typeof Promise === 'undefined') return;

  var origThen = Promise.prototype.then;
  Promise.prototype.then = function(onFulfilled, onRejected) {
    return origThen.call(
      this,
      typeof onFulfilled === 'function' ? _wrapPromiseCallback(onFulfilled) : onFulfilled,
      typeof onRejected  === 'function' ? _wrapPromiseCallback(onRejected)  : onRejected
    );
  };

  if (typeof Promise.prototype['catch'] === 'function') {
    var origCatch = Promise.prototype['catch'];
    Promise.prototype['catch'] = function(onRejected) {
      return origCatch.call(
        this,
        typeof onRejected === 'function' ? _wrapPromiseCallback(onRejected) : onRejected
      );
    };
  }

  if (typeof Promise.prototype['finally'] === 'function') {
    var origFinally = Promise.prototype['finally'];
    Promise.prototype['finally'] = function(onFinally) {
      return origFinally.call(
        this,
        typeof onFinally === 'function' ? _wrapPromiseCallback(onFinally) : onFinally
      );
    };
  }
})();

/* ------------------------------------------------------------------ */
/*  Patch setTimeout / setInterval / queueMicrotask                    */
/* ------------------------------------------------------------------ */
(function() {
  if (typeof globalThis === 'undefined') return;

  if (typeof globalThis.setTimeout === 'function') {
    var origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = function(fn) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      if (typeof fn === 'function') {
        args.unshift(_wrapCallback(fn));
      } else {
        args.unshift(fn);
      }
      return origSetTimeout.apply(globalThis, args);
    };
  }

  if (typeof globalThis.setInterval === 'function') {
    var origSetInterval = globalThis.setInterval;
    globalThis.setInterval = function(fn) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      if (typeof fn === 'function') {
        args.unshift(_wrapCallback(fn));
      } else {
        args.unshift(fn);
      }
      return origSetInterval.apply(globalThis, args);
    };
  }

  if (typeof globalThis.queueMicrotask === 'function') {
    var origQueueMicrotask = globalThis.queueMicrotask;
    globalThis.queueMicrotask = function(fn) {
      if (typeof fn === 'function') {
        return origQueueMicrotask.call(globalThis, _wrapCallback(fn));
      }
      return origQueueMicrotask.call(globalThis, fn);
    };
  }
})();

/* ------------------------------------------------------------------ */
/*  createHook (stub - keeps existing API surface)                     */
/* ------------------------------------------------------------------ */
function createHook(callbacks) {
  callbacks = callbacks || {};
  var hook = {
    _callbacks: callbacks,
    _enabled: false
  };
  return {
    enable: function() {
      if (!hook._enabled) {
        hook._enabled = true;
        _activeHooks.push(callbacks);
      }
      _hooksEnabled = true;
      return this;
    },
    disable: function() {
      if (hook._enabled) {
        hook._enabled = false;
        var idx = _activeHooks.indexOf(callbacks);
        if (idx !== -1) _activeHooks.splice(idx, 1);
      }
      if (_activeHooks.length === 0) _hooksEnabled = false;
      return this;
    },
    _callbacks: callbacks
  };
}

function __nextAsyncId() {
  return _idCounter++;
}

function __emitInit(asyncId, type, triggerAsyncId, resource) {
  if (!_hooksEnabled) return;
  var i;
  for (i = 0; i < _activeHooks.length; i++) {
    var callbacks = _activeHooks[i];
    if (callbacks && typeof callbacks.init === 'function') {
      try {
        callbacks.init(asyncId, type, triggerAsyncId, resource);
      } catch (e) {}
    }
  }
}

function __emitDestroy(asyncId) {
  if (!_hooksEnabled) return;
  var i;
  for (i = 0; i < _activeHooks.length; i++) {
    var callbacks = _activeHooks[i];
    if (callbacks && typeof callbacks.destroy === 'function') {
      try {
        callbacks.destroy(asyncId);
      } catch (e) {}
    }
  }
}

function __getHooksEnabled() {
  return _hooksEnabled;
}

function executionAsyncId() {
  return 0;
}

function triggerAsyncId() {
  return 0;
}

/* ------------------------------------------------------------------ */
/*  AsyncResource                                                      */
/* ------------------------------------------------------------------ */
function AsyncResource(type, options) {
  this.type = type || 'AsyncResource';
  this._asyncId = _idCounter++;
  this._triggerAsyncId = (options && typeof options.triggerAsyncId === 'number')
    ? options.triggerAsyncId
    : executionAsyncId();
  this._context = _captureContext();
  this._destroyed = false;
  __emitInit(this._asyncId, this.type, this._triggerAsyncId);
  if (_resourceFinalizer) {
    _resourceFinalizer.register(this, this._asyncId);
  }
}

AsyncResource.prototype.runInAsyncScope = function(fn, thisArg) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  var prev = _restoreContext(this._context);
  try {
    return fn.apply(thisArg || this, args);
  } finally {
    _restoreContext(prev);
  }
};
AsyncResource.prototype.emitDestroy = function() {
  if (this._destroyed) return;
  this._destroyed = true;
  __emitDestroy(this._asyncId);
};
AsyncResource.prototype.emitBefore = _noop;
AsyncResource.prototype.emitAfter = _noop;
AsyncResource.prototype.asyncId = function() {
  return this._asyncId;
};
AsyncResource.prototype.triggerAsyncId = function() {
  return this._triggerAsyncId;
};
AsyncResource.prototype.bind = function(fn, thisArg) {
  var resource = this;
  var bound = function() {
    var a = [];
    for (var i = 0; i < arguments.length; i++) a.push(arguments[i]);
    return resource.runInAsyncScope.apply(resource, [fn, thisArg || resource].concat(a));
  };
  bound.asyncResource = resource;
  return bound;
};

AsyncResource.bind = function(fn, type, thisArg) {
  type = type || fn.name || 'bound-anonymous-fn';
  var resource = new AsyncResource(type);
  return resource.bind(fn, thisArg);
};

/* ------------------------------------------------------------------ */
/*  AsyncLocalStorage                                                  */
/* ------------------------------------------------------------------ */
function AsyncLocalStorage() {
  this._enabled = false;
  this._store = undefined;
  _allInstances.push(this);
}

AsyncLocalStorage.prototype.enable = function() {
  this._enabled = true;
};

AsyncLocalStorage.prototype.disable = function() {
  this._enabled = false;
  this._store = undefined;
  var idx = _allInstances.indexOf(this);
  if (idx !== -1) _allInstances.splice(idx, 1);
};

AsyncLocalStorage.prototype.enterWith = function(store) {
  this._store = store;
  this._enabled = true;
  if (_allInstances.indexOf(this) === -1) {
    _allInstances.push(this);
  }
};

AsyncLocalStorage.prototype.run = function(store, callback) {
  var previous = this._store;
  this._store = store;
  this._enabled = true;
  if (_allInstances.indexOf(this) === -1) {
    _allInstances.push(this);
  }
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  try {
    return callback.apply(null, args);
  } finally {
    this._store = previous;
  }
};

AsyncLocalStorage.prototype.exit = function(callback) {
  var previous = this._store;
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  try {
    this._store = undefined;
    return callback.apply(null, args);
  } finally {
    this._store = previous;
  }
};

AsyncLocalStorage.prototype.getStore = function() {
  if (!this._enabled) return undefined;
  return this._store;
};

AsyncLocalStorage.prototype.snapshot = function() {
  var captured = _captureContext();
  return function(fn) {
    var args = [];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    var prev = _restoreContext(captured);
    try {
      return fn.apply(null, args);
    } finally {
      _restoreContext(prev);
    }
  };
};

AsyncLocalStorage.bind = function(fn) {
  return _wrapCallback(fn);
};

AsyncLocalStorage.snapshot = function() {
  var captured = _captureContext();
  return function(fn) {
    var args = [];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    var prev = _restoreContext(captured);
    try {
      return fn.apply(null, args);
    } finally {
      _restoreContext(prev);
    }
  };
};

module.exports = {
  createHook: createHook,
  __nextAsyncId: __nextAsyncId,
  __emitInit: __emitInit,
  __getHooksEnabled: __getHooksEnabled,
  executionAsyncId: executionAsyncId,
  triggerAsyncId: triggerAsyncId,
  AsyncResource: AsyncResource,
  AsyncLocalStorage: AsyncLocalStorage
};
