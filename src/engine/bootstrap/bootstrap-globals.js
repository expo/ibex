(function() {
  // Helper: define a lazy getter that initializes on first access
  function defineLazyGlobal(prop, init) {
    Object.defineProperty(globalThis, prop, {
      configurable: true, enumerable: true,
      get: function() {
        delete globalThis[prop];
        var val = init();
        if (val !== undefined && globalThis[prop] === undefined) {
          globalThis[prop] = val;
        }
        return globalThis[prop];
      }
    });
  }

  // Buffer — lazy, from require('buffer')
  defineLazyGlobal('Buffer', function() {
    try {
      var buf = globalThis.require('buffer');
      if (buf && buf.Buffer) { return buf.Buffer; }
    } catch(e) {}
    return undefined;
  });

  // URL — lazy, from require('url')
  if (typeof globalThis.URL === 'undefined') {
    defineLazyGlobal('URL', function() {
      try {
        var urlMod = globalThis.require('url');
        if (urlMod) {
          // Also install URLSearchParams eagerly while we have the module
          if (urlMod.URLSearchParams && typeof globalThis.URLSearchParams === 'undefined') {
            globalThis.URLSearchParams = urlMod.URLSearchParams;
          }
          if (urlMod.URL) { return urlMod.URL; }
        }
      } catch(e) {}
      return undefined;
    });
  }

  // URLSearchParams — lazy, from require('url')
  if (typeof globalThis.URLSearchParams === 'undefined') {
    defineLazyGlobal('URLSearchParams', function() {
      try {
        var urlMod = globalThis.require('url');
        if (urlMod) {
          // Also install URL eagerly while we have the module
          if (urlMod.URL && typeof globalThis.URL === 'undefined') {
            globalThis.URL = urlMod.URL;
          }
          if (urlMod.URLSearchParams) { return urlMod.URLSearchParams; }
        }
      } catch(e) {}
      return undefined;
    });
  }

  // DOMException polyfill — lazy (needed by AbortController, so define first)
  if (typeof globalThis.DOMException === 'undefined') {
    defineLazyGlobal('DOMException', function() {
      function DOMException(message, name) {
        this.message = message || '';
        this.name = name || 'Error';
        if (this.code === undefined && this.name === 'InvalidCharacterError') {
          this.code = 5;
        }
      }
      DOMException.prototype = Object.create(Error.prototype);
      DOMException.prototype.constructor = DOMException;
      return DOMException;
    });
  }

  // btoa() support — Hermes' built-in implementation throws a plain Error in
  // some Unicode cases without the legacy INVALID_CHARACTER_ERR code. Wrap it so
  // compatibility tests observe the expected DOMException shape.
  var __exactNativeBtoa = (typeof globalThis.btoa === 'function') ? globalThis.btoa : null;
  var __exactNativeAtob = (typeof globalThis.atob === 'function') ? globalThis.atob : null;

  function __exactInvalidCharacterError() {
    if (typeof globalThis.DOMException === 'function') {
      var err = new globalThis.DOMException(
        'The string to be encoded contains characters outside of the Latin1 range.',
        'InvalidCharacterError'
      );
      if (err.code === undefined) err.code = 5;
      return err;
    }
    var fallback = new Error('The string to be encoded contains characters outside of the Latin1 range.');
    fallback.name = 'InvalidCharacterError';
    fallback.code = 5;
    return fallback;
  }

  function __exactAtobInvalidCharacterError() {
    if (typeof globalThis.DOMException === 'function') {
      var err = new globalThis.DOMException('The string to be decoded is not correctly encoded.', 'InvalidCharacterError');
      if (err.code === undefined) err.code = 5;
      return err;
    }
    var fallback = new Error('The string to be decoded is not correctly encoded.');
    fallback.name = 'InvalidCharacterError';
    fallback.code = 5;
    return fallback;
  }

  globalThis.atob = function() {
    var input = String(arguments[0]);

    if (!__exactNativeAtob) {
      throw __exactAtobInvalidCharacterError();
    }

    try {
      return __exactNativeAtob(input);
    } catch (err) {
      throw __exactAtobInvalidCharacterError();
    }
  };

  // Replace btoa definition after atob to ensure both helpers are available.
  globalThis.btoa = function() {
    var input = String(arguments[0]);
    for (var i = 0; i < input.length; i++) {
      if (input.charCodeAt(i) > 255) {
        throw __exactInvalidCharacterError();
      }
    }
    if (__exactNativeBtoa) {
      try {
        return __exactNativeBtoa(input);
      } catch (err) {
        throw __exactInvalidCharacterError();
      }
    }

    // Fallback manual implementation (for environments that lack btoa entirely).
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' ;
    var output = '';
    for (var j = 0; j < input.length; j += 3) {
      var c1 = input.charCodeAt(j);
      var c2 = j + 1 < input.length ? input.charCodeAt(j + 1) : NaN;
      var c3 = j + 2 < input.length ? input.charCodeAt(j + 2) : NaN;

      output += chars[c1 >> 2];
      output += chars[((c1 & 3) << 4) | (isNaN(c2) ? 0 : (c2 >> 4))];
      output += isNaN(c2) ? '=' : chars[((c2 & 15) << 2) | (isNaN(c3) ? 0 : (c3 >> 6))];
      output += isNaN(c3) ? '=' : chars[c3 & 63];
    }
    return output;
  };

  // Timer callback validation helper (Node.js throws ERR_INVALID_ARG_TYPE)
  function _validateTimerCallback(callback, name) {
    if (typeof callback !== 'function') {
      var err = new TypeError(
        'The "callback" argument must be of type function. Received ' +
        (callback === null ? 'null' : typeof callback)
      );
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }

  // Clamp delay: negative or non-numeric → 0 (matches Node.js and Web Platform behavior)
  function _clampDelay(delay) {
    var d = Number(delay);
    return (d > 0) ? d : 0;
  }

  var __exactEventTargetKEvents = Symbol.for('nodejs.internal.event_target.kEvents');
  var __exactEventTargetKWeakHandler = Symbol.for('nodejs.internal.event_target.kWeakHandler');

  function __ensureEventTargetEventMap(target) {
    if (!target[__exactEventTargetKEvents]) {
      target[__exactEventTargetKEvents] = new Map();
    }
    return target[__exactEventTargetKEvents];
  }

  function __addEventTargetEventListener(target, type, listener) {
    var map = __ensureEventTargetEventMap(target);
    var listeners = map.get(type);
    if (!listeners) {
      listeners = new Set();
      map.set(type, listeners);
    }
    listeners.add(listener);
  }

  function __removeEventTargetEventListener(target, type, listener) {
    var map = target[__exactEventTargetKEvents];
    if (!map) return;
    var listeners = map.get(type);
    if (!listeners) return;
    listeners.delete(listener);
    if (listeners.size === 0) map.delete(type);
  }

  // Wrap native setTimeout with callback validation and delay clamping
  if (typeof globalThis.setTimeout === 'function') {
    var _nativeSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = function(callback, delay) {
      _validateTimerCallback(callback, 'setTimeout');
      var d = _clampDelay(delay);
      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      if (args.length > 0) {
        return _nativeSetTimeout(function() { callback.apply(null, args); }, d);
      }
      return _nativeSetTimeout(callback, d);
    };
  }

  // Wrap native setInterval with callback validation and delay clamping
  if (typeof globalThis.setInterval === 'function') {
    var _nativeSetInterval = globalThis.setInterval;
    globalThis.setInterval = function(callback, delay) {
      _validateTimerCallback(callback, 'setInterval');
      var d = _clampDelay(delay);
      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      if (args.length > 0) {
        return _nativeSetInterval(function() { callback.apply(null, args); }, d);
      }
      return _nativeSetInterval(callback, d);
    };
  }

  // setImmediate / clearImmediate — lazy (Node.js global)
  if (typeof globalThis.setImmediate === 'undefined') {
    defineLazyGlobal('setImmediate', function() {
      var impl = function(callback) {
        _validateTimerCallback(callback, 'setImmediate');
        var args = [];
        for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
        return globalThis.setTimeout(function() { callback.apply(null, args); }, 0);
      };
      // Also install clearImmediate eagerly
      globalThis.clearImmediate = function(handle) {
        globalThis.clearTimeout(handle);
      };
      return impl;
    });
  }
  if (typeof globalThis.clearImmediate === 'undefined') {
    defineLazyGlobal('clearImmediate', function() {
      // Trigger setImmediate lazy init which installs both
      void globalThis.setImmediate;
      if (globalThis.clearImmediate) return globalThis.clearImmediate;
      return function(handle) { globalThis.clearTimeout(handle); };
    });
  }

  // AbortController / AbortSignal — lazy (Web API)
  if (typeof globalThis.AbortController === 'undefined') {
      function _initAbort() {
      function AbortSignal() {
        this.aborted = false;
        this.reason = undefined;
        this.onabort = null;
        this._listeners = [];
        this[__exactEventTargetKEvents] = new Map();
      }
      // Internal abort helper — shared by AbortController, timeout(), and any()
      AbortSignal.prototype._abort = function(reason) {
        if (this.aborted) return;
        this.aborted = true;
        this.reason = reason;
        var event = { type: 'abort', target: this, currentTarget: this,
                      bubbles: false, cancelable: false, isTrusted: true,
                      timeStamp: Date.now(), preventDefault: function() {},
                      stopPropagation: function() {},
                      stopImmediatePropagation: function() {} };
        // Call onabort handler property first
        if (typeof this.onabort === 'function') {
          try { this.onabort.call(this, event); } catch(e) {}
        }
        // Then fire addEventListener listeners
        var listeners = this._listeners.slice();
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](event); } catch(e) {}
        }
      };
      AbortSignal.prototype.addEventListener = function(type, listener, options) {
        if (type === 'abort') {
          var once = options && typeof options === 'object' && !!options.once;
          if (once) {
            var self = this;
            var wrapped = function(e) {
              self.removeEventListener(type, wrapped);
              listener(e);
            };
            wrapped._original = listener;
            this._listeners.push(wrapped);
            __addEventTargetEventListener(this, type, wrapped);
          } else {
            this._listeners.push(listener);
            __addEventTargetEventListener(this, type, listener);
          }
        }
      };
      AbortSignal.prototype.removeEventListener = function(type, listener) {
        if (type === 'abort') {
          var idx = this._listeners.indexOf(listener);
          if (idx === -1) {
            // Check for once-wrapped listeners
            for (var i = 0; i < this._listeners.length; i++) {
              if (this._listeners[i]._original === listener) {
                idx = i;
                break;
              }
            }
          }
          if (idx !== -1) {
            var removed = this._listeners.splice(idx, 1)[0];
            __removeEventTargetEventListener(this, type, removed);
          }
        }
      };
      AbortSignal.prototype.dispatchEvent = function(event) {
        if (!event || event.type !== 'abort') return true;
        event.target = this;
        event.currentTarget = this;
        if (typeof this.onabort === 'function') {
          try { this.onabort.call(this, event); } catch(e) {}
        }
        var listeners = this._listeners.slice();
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](event); } catch(e) {}
        }
        return true;
      };
      AbortSignal.prototype.throwIfAborted = function() {
        if (this.aborted) throw this.reason;
      };
      AbortSignal.abort = function(reason) {
        var s = new AbortSignal();
        s.aborted = true;
        s.reason = reason !== undefined ? reason : new (globalThis.DOMException || Error)('The operation was aborted.', 'AbortError');
        return s;
      };
      AbortSignal.timeout = function(ms) {
        var s = new AbortSignal();
        globalThis.setTimeout(function() {
          s._abort(new (globalThis.DOMException || Error)('The operation was aborted due to timeout.', 'TimeoutError'));
        }, ms);
        return s;
      };
      AbortSignal.any = function(signals) {
        var s = new AbortSignal();
        if (!signals || signals.length === 0) return s;
        // If any signal is already aborted, return an immediately aborted signal
        for (var i = 0; i < signals.length; i++) {
          if (signals[i].aborted) {
            s.aborted = true;
            s.reason = signals[i].reason;
            return s;
          }
        }
        // Listen for abort on all source signals
        var onAbort = function() {
          if (s.aborted) return;
          for (var i = 0; i < signals.length; i++) {
            if (signals[i].aborted) {
              s._abort(signals[i].reason);
              break;
            }
          }
        };
        for (var i = 0; i < signals.length; i++) {
          signals[i].addEventListener('abort', onAbort, { once: true });
        }
        return s;
      };
      function AbortController() {
        this.signal = new AbortSignal();
      }
      AbortController.prototype.abort = function(reason) {
        var r = reason !== undefined ? reason : new (globalThis.DOMException || Error)('The operation was aborted.', 'AbortError');
        this.signal._abort(r);
      };
      globalThis.AbortController = AbortController;
      globalThis.AbortSignal = AbortSignal;
    }
    defineLazyGlobal('AbortController', function() {
      _initAbort();
      return globalThis.AbortController;
    });
    defineLazyGlobal('AbortSignal', function() {
      _initAbort();
      return globalThis.AbortSignal;
    });
  }

  // structuredClone — lazy (Web API)
  if (typeof globalThis.structuredClone === 'undefined') {
    defineLazyGlobal('structuredClone', function() {
      var _DOMException = globalThis.DOMException || (function() {
        function DOMException(message, name) {
          Error.call(this, message);
          this.message = message || '';
          this.name = name || 'Error';
        }
        DOMException.prototype = Object.create(Error.prototype);
        DOMException.prototype.constructor = DOMException;
        return DOMException;
      })();

      function _structuredClone(value) {
        var originals = [];
        var clones = [];

        function _clone(v) {
          if (v === null || v === undefined) return v;
          var t = typeof v;
          if (t === 'boolean' || t === 'string' || t === 'number' || t === 'bigint') return v;

          if (t === 'symbol' || t === 'function') {
            throw new _DOMException('The object could not be cloned.', 'DataCloneError');
          }

          // Cycle detection
          for (var i = 0; i < originals.length; i++) {
            if (originals[i] === v) return clones[i];
          }

          var result;

          // Date
          if (v instanceof Date) {
            result = new Date(v.getTime());
            originals.push(v); clones.push(result);
            return result;
          }

          // RegExp
          if (v instanceof RegExp) {
            result = new RegExp(v.source, v.flags);
            originals.push(v); clones.push(result);
            return result;
          }

          // Error types
          if (v instanceof Error) {
            var Ctor = v.constructor;
            if (typeof Ctor !== 'function') Ctor = Error;
            try {
              result = v.hasOwnProperty('message') ? new Ctor(v.message) : new Ctor();
            } catch (e) {
              result = v.hasOwnProperty('message') ? new Error(v.message) : new Error();
            }
            if (result.name !== v.name) result.name = v.name;
            originals.push(v); clones.push(result);
            if ('cause' in v) {
              try { Object.defineProperty(result, 'cause', { value: _clone(v.cause), writable: true, enumerable: false, configurable: true }); } catch(e) { result.cause = _clone(v.cause); }
            }
            if (v.stack !== undefined) result.stack = v.stack;
            return result;
          }

          // Boolean wrapper
          if (v instanceof Boolean) {
            result = new Boolean(v.valueOf());
            originals.push(v); clones.push(result);
            return result;
          }

          // Number wrapper
          if (v instanceof Number) {
            result = new Number(v.valueOf());
            originals.push(v); clones.push(result);
            return result;
          }

          // String wrapper
          if (v instanceof String) {
            result = new String(v.valueOf());
            originals.push(v); clones.push(result);
            return result;
          }

          // BigInt wrapper
          if (typeof BigInt !== 'undefined' && t === 'object' && typeof v.valueOf() === 'bigint') {
            result = Object(v.valueOf());
            originals.push(v); clones.push(result);
            return result;
          }

          // ArrayBuffer
          if (typeof ArrayBuffer !== 'undefined' && v instanceof ArrayBuffer) {
            result = v.slice(0);
            originals.push(v); clones.push(result);
            return result;
          }

          // SharedArrayBuffer
          if (typeof SharedArrayBuffer !== 'undefined' && v instanceof SharedArrayBuffer) {
            result = v;
            originals.push(v); clones.push(result);
            return result;
          }

          // DataView
          if (typeof DataView !== 'undefined' && v instanceof DataView) {
            result = new DataView(_clone(v.buffer), v.byteOffset, v.byteLength);
            originals.push(v); clones.push(result);
            return result;
          }

          // TypedArrays
          var _taTypes = ['Int8Array','Uint8Array','Uint8ClampedArray','Int16Array','Uint16Array','Int32Array','Uint32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array'];
          for (var j = 0; j < _taTypes.length; j++) {
            var TA = globalThis[_taTypes[j]];
            if (typeof TA === 'function' && v instanceof TA) {
              result = new TA(_clone(v.buffer), v.byteOffset, v.length);
              originals.push(v); clones.push(result);
              return result;
            }
          }

          // Map
          if (typeof Map !== 'undefined' && v instanceof Map) {
            result = new Map();
            originals.push(v); clones.push(result);
            v.forEach(function(val, key) { result.set(_clone(key), _clone(val)); });
            return result;
          }

          // Set
          if (typeof Set !== 'undefined' && v instanceof Set) {
            result = new Set();
            originals.push(v); clones.push(result);
            v.forEach(function(val) { result.add(_clone(val)); });
            return result;
          }

          // DOMException
          if (typeof _DOMException !== 'undefined' && v instanceof _DOMException) {
            result = new _DOMException(v.message, v.name);
            originals.push(v); clones.push(result);
            return result;
          }

          // Array
          if (Array.isArray(v)) {
            result = new Array(v.length);
            originals.push(v); clones.push(result);
            for (var k = 0; k < v.length; k++) {
              if (k in v) result[k] = _clone(v[k]);
            }
            return result;
          }

          // Plain object
          if (t === 'object') {
            result = {};
            originals.push(v); clones.push(result);
            var keys = Object.keys(v);
            for (var k = 0; k < keys.length; k++) {
              result[keys[k]] = _clone(v[keys[k]]);
            }
            return result;
          }

          throw new _DOMException('The object could not be cloned.', 'DataCloneError');
        }

        return _clone(value);
      }

      return _structuredClone;
    });
  }

  // performance (Web API) — EAGER: used immediately by almost everything
  if (typeof globalThis.performance === 'undefined') {
    var _perfStart = Date.now();
    globalThis.performance = {
      now: function() {
        if (typeof __exactHrtime === 'function') {
          var parts = __exactHrtime();
          if (typeof parts === 'string') {
            var p = parts.split(',');
            return (parseInt(p[0], 10) * 1000) + (parseInt(p[1], 10) / 1000000);
          }
        }
        return Date.now() - _perfStart;
      },
      timeOrigin: _perfStart,
      mark: function() {},
      measure: function() {},
      getEntries: function() { return []; },
      getEntriesByName: function() { return []; },
      getEntriesByType: function() { return []; },
      clearMarks: function() {},
      clearMeasures: function() {}
    };
  }

  // Event / EventTarget / CustomEvent — lazy (Web API)
  if (typeof globalThis.EventTarget === 'undefined') {
    function _initEvents() {
      function EventTarget() {
        this._listeners = {};
        this[__exactEventTargetKEvents] = new Map();
      }
      EventTarget.prototype.addEventListener = function(type, listener, options) {
        var capture = false;
        var once = false;
        if (options === true || options === false) {
          capture = !!options;
        } else if (options && typeof options === 'object') {
          capture = !!options.capture;
          once = !!options.once;
        }
        if (!this._listeners[type]) this._listeners[type] = [];
        var listeners = this._listeners[type];
        for (var i = 0; i < listeners.length; i++) {
          if (listeners[i].fn === listener && listeners[i].capture === capture) {
            return;
          }
        }
        listeners.push({ fn: listener, once: once, capture: capture });
        __addEventTargetEventListener(this, type, listener);
      };
      EventTarget.prototype.removeEventListener = function(type, listener) {
        if (!this._listeners[type]) return;
        this._listeners[type] = this._listeners[type].filter(function(l) { return l.fn !== listener; });
        __removeEventTargetEventListener(this, type, listener);
      };
      EventTarget.prototype.dispatchEvent = function(event) {
        if (!event || !event.type) return true;
        var listeners = this._listeners[event.type];
        event.target = this;
        event.currentTarget = this;
        if (event.srcElement !== undefined) event.srcElement = this;
        if (event.eventPhase !== undefined) event.eventPhase = 2; // AT_TARGET
        if (!listeners || listeners.length === 0) {
          event.eventPhase = 0;
          event.currentTarget = null;
          return !event.defaultPrevented;
        }
        var snapshot = listeners.slice();
        var current = this._listeners[event.type];
        for (var i = 0; i < snapshot.length; i++) {
          if (event._stopImmediatePropagation) break;
          var listener = snapshot[i];
          if (!listener) {
            continue;
          }
          if (listener.once && current) {
            current = current.filter(function(entry) { return entry.fn !== listener.fn || entry.capture !== listener.capture; });
            this._listeners[event.type] = current;
            __removeEventTargetEventListener(this, event.type, listener.fn);
          }
          if (typeof listener.fn === 'function') {
            listener.fn.call(this, event);
          } else if (listener.fn && typeof listener.fn.handleEvent === 'function') {
            listener.fn.handleEvent(event);
          }
        }
        if (current && current.length !== listeners.length) {
          this._listeners[event.type] = current;
        }
        event.eventPhase = 0;
        event.currentTarget = null;
        return !event.defaultPrevented;
      };
      globalThis.EventTarget = EventTarget;

      function Event(type, options) {
        if (arguments.length === 0) {
          throw new TypeError("Failed to construct 'Event': 1 argument required, but only 0 present.");
        }
        this.type = String(type);
        this.bubbles = !!(options && options.bubbles);
        this.cancelable = !!(options && options.cancelable);
        this.composed = !!(options && options.composed);
        this.defaultPrevented = false;
        this.target = null;
        this.currentTarget = null;
        this.srcElement = null;
        this.timeStamp = Date.now();
        this.isTrusted = false;
        this.eventPhase = 0;
        this.returnValue = true;
        this._cancelBubble = false;
        this._stopPropagation = false;
        this._stopImmediatePropagation = false;
      }
      Object.defineProperty(Event.prototype, 'cancelBubble', {
        get: function() { return this._cancelBubble; },
        set: function(v) { if (v) this._cancelBubble = true; },
        enumerable: true, configurable: true
      });
      Event.prototype.composedPath = function() {
        return this.currentTarget ? [this.currentTarget] : [];
      };
      Event.prototype.preventDefault = function() {
        if (this.cancelable) this.defaultPrevented = true;
      };
      Event.prototype.stopPropagation = function() {
        this._cancelBubble = true;
        this._stopPropagation = true;
      };
      Event.prototype.stopImmediatePropagation = function() {
        this._cancelBubble = true;
        this._stopPropagation = true;
        this._stopImmediatePropagation = true;
      };
      Event.NONE = 0;
      Event.CAPTURING_PHASE = 1;
      Event.AT_TARGET = 2;
      Event.BUBBLING_PHASE = 3;
      if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
        Event.prototype[Symbol.toStringTag] = 'Event';
      }
      globalThis.Event = Event;

      function CustomEvent(type, options) {
        if (arguments.length === 0) {
          throw new TypeError("Failed to construct 'CustomEvent': 1 argument required, but only 0 present.");
        }
        if (typeof type === 'symbol') {
          throw new TypeError("Cannot convert a Symbol value to a string");
        }
        if (options !== undefined && options !== null && typeof options !== 'object') {
          var err = new TypeError('The "options" argument must be of type object.' +
            ' Received type ' + typeof options + ' (' + options + ')');
          err.code = 'ERR_INVALID_ARG_TYPE';
          throw err;
        }
        Event.call(this, type, options);
        this.detail = (options && options.detail !== undefined) ? options.detail : null;
      }
      CustomEvent.prototype = Object.create(Event.prototype);
      CustomEvent.prototype.constructor = CustomEvent;
      CustomEvent.NONE = 0;
      CustomEvent.CAPTURING_PHASE = 1;
      CustomEvent.AT_TARGET = 2;
      CustomEvent.BUBBLING_PHASE = 3;
      CustomEvent.length = 1;
      if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
        CustomEvent.prototype[Symbol.toStringTag] = 'CustomEvent';
      }
      globalThis.CustomEvent = CustomEvent;
    }

    defineLazyGlobal('EventTarget', function() {
      _initEvents();
      return globalThis.EventTarget;
    });
    defineLazyGlobal('Event', function() {
      _initEvents();
      return globalThis.Event;
    });
    defineLazyGlobal('CustomEvent', function() {
      _initEvents();
      return globalThis.CustomEvent;
    });
  }

  // Blob / File — lazy (Web API)
  if (typeof globalThis.Blob === 'undefined') {
    function _initBlob() {
      function Blob(parts, options) {
        this._parts = parts || [];
        this.type = (options && options.type) || '';
        var totalSize = 0;
        for (var i = 0; i < this._parts.length; i++) {
          var part = this._parts[i];
          if (typeof part === 'string') totalSize += part.length;
          else if (part instanceof Uint8Array) totalSize += part.length;
          else if (part instanceof ArrayBuffer) totalSize += part.byteLength;
          else if (part && part._parts) totalSize += part.size;
          else totalSize += String(part).length;
        }
        this.size = totalSize;
      }
      Blob.prototype.text = function() {
        var result = '';
        for (var i = 0; i < this._parts.length; i++) {
          var part = this._parts[i];
          if (typeof part === 'string') result += part;
          else if (part instanceof Uint8Array) {
            for (var j = 0; j < part.length; j++) result += String.fromCharCode(part[j]);
          } else result += String(part);
        }
        return Promise.resolve(result);
      };
      Blob.prototype.arrayBuffer = function() {
        var self = this;
        return this.text().then(function(text) {
          var buf = new Uint8Array(text.length);
          for (var i = 0; i < text.length; i++) buf[i] = text.charCodeAt(i);
          return buf.buffer;
        });
      };
      Blob.prototype.slice = function(start, end, contentType) {
        return this.text().then(function(text) {
          return new Blob([text.slice(start, end)], { type: contentType || '' });
        });
      };
      Blob.prototype.stream = function() { return null; };
      globalThis.Blob = Blob;

      function File(parts, name, options) {
        Blob.call(this, parts, options);
        this.name = name;
        this.lastModified = (options && options.lastModified) || Date.now();
      }
      File.prototype = Object.create(Blob.prototype);
      File.prototype.constructor = File;
      globalThis.File = File;
    }

    defineLazyGlobal('Blob', function() {
      _initBlob();
      return globalThis.Blob;
    });
    defineLazyGlobal('File', function() {
      _initBlob();
      return globalThis.File;
    });
  }
})();
