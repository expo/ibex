(function() {
  // Helper: define a lazy getter that initializes on first access
  function defineLazyGlobal(prop, init) {
    var lazyGetter = function() {
      delete globalThis[prop];
      var val = init();
      if (val !== undefined && globalThis[prop] === undefined) {
        globalThis[prop] = val;
      }
      return globalThis[prop];
    };
    Object.defineProperty(lazyGetter, '__ibexLazyGlobalGetter', {
      value: true, writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(globalThis, prop, {
      configurable: true, enumerable: true,
      get: lazyGetter
    });
  }

  function patchArrayBufferBackedBuffer(BufferCtor) {
    if (typeof BufferCtor !== 'function' || BufferCtor.__exactArrayBufferViewPatched) {
      return BufferCtor;
    }

    var nativeFrom = BufferCtor.from;

    function normalizeBufferOffset(value, fallback) {
      if (value === undefined) return fallback;
      var number = Number(value);
      if (number !== number) return fallback;
      if (!isFinite(number)) return number;
      if (number < 0) return Math.ceil(number);
      return Math.floor(number);
    }

    function makeBufferBoundsError(which) {
      var err = new RangeError('"' + which + '" is outside of buffer bounds');
      err.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
      return err;
    }

    function promoteArrayBufferView(value, byteOffset, length) {
      var backing = value;
      if (
        typeof SharedArrayBuffer === 'function' &&
        Object.prototype.toString.call(value) === '[object SharedArrayBuffer]' &&
        value._buffer &&
        Object.prototype.toString.call(value._buffer) === '[object ArrayBuffer]'
      ) {
        backing = value._buffer;
      }

      var totalLength = backing.byteLength >>> 0;
      var offset = normalizeBufferOffset(byteOffset, 0);
      if (!isFinite(offset) || offset < 0 || offset > totalLength) {
        throw makeBufferBoundsError('offset');
      }

      var viewLength;
      if (length === undefined) {
        viewLength = totalLength - offset;
      } else {
        viewLength = normalizeBufferOffset(length, 0);
        if (!isFinite(viewLength) || viewLength < 0 || offset + viewLength > totalLength) {
          throw makeBufferBoundsError('length');
        }
      }

      var view = new Uint8Array(backing, offset, viewLength);
      Object.setPrototypeOf(view, BufferCtor.prototype);
      try {
        Object.defineProperty(view, '__isExactBuffer', {
          value: true,
          configurable: true,
          enumerable: false,
          writable: true
        });
      } catch (err) {
        view.__isExactBuffer = true;
      }
      if (backing !== value) {
        try {
          Object.defineProperty(view, 'buffer', {
            configurable: true,
            enumerable: false,
            get: function() {
              return value;
            }
          });
        } catch (err) {}
      }
      return view;
    }

    BufferCtor.from = function(value, encoding, length) {
      if (typeof ArrayBuffer === 'function' &&
          value instanceof ArrayBuffer &&
          value.constructor === ArrayBuffer) {
        return promoteArrayBufferView(value, encoding, length);
      }
      if (typeof SharedArrayBuffer === 'function' &&
          value instanceof SharedArrayBuffer &&
          value.constructor === SharedArrayBuffer) {
        return promoteArrayBufferView(value, encoding, length);
      }
      return nativeFrom.apply(this, arguments);
    };

    try {
      Object.defineProperty(BufferCtor, '__exactArrayBufferViewPatched', {
        value: true,
        configurable: true,
        enumerable: false,
        writable: false
      });
    } catch (err) {
      BufferCtor.__exactArrayBufferViewPatched = true;
    }
    return BufferCtor;
  }

  function installBufferModuleCompat() {
    if (typeof globalThis.require !== 'function') {
      return null;
    }
    try {
      var bufferModule = globalThis.require('buffer');
      if (bufferModule && bufferModule.Buffer) {
        patchArrayBufferBackedBuffer(bufferModule.Buffer);
      }
      return bufferModule || null;
    } catch (e) {}
    return null;
  }

  // Buffer — override the engine stub with the Node-compatible module version
  Object.defineProperty(globalThis, 'Buffer', {
    configurable: true,
    enumerable: true,
    get: function() {
      var buf = installBufferModuleCompat();
      if (!buf || !buf.Buffer) {
        return undefined;
      }
      try {
        Object.defineProperty(globalThis, 'Buffer', {
          configurable: true,
          enumerable: true,
          writable: true,
          value: buf.Buffer
        });
      } catch (err) {
        globalThis.Buffer = buf.Buffer;
      }
      return buf.Buffer;
    }
  });

  // URL — lazy, from require('url')
  if (typeof globalThis.URL === 'undefined') {
    defineLazyGlobal('URL', function() {
      try {
        var urlMod = globalThis.require('url');
        if (urlMod) {
          // Install both constructors from the same module instance without
          // touching sibling lazy getters, which would recurse back through
          // require('url') before the module finishes initializing.
          if (urlMod.URLSearchParams) {
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
          if (urlMod.URL) {
            globalThis.URL = urlMod.URL;
          }
          if (urlMod.URLSearchParams) { return urlMod.URLSearchParams; }
        }
      } catch(e) {}
      return undefined;
    });
  }

  try {
    if (typeof globalThis.require === 'function') {
      var __exactUrlGlobals = globalThis.require('url');
      if (__exactUrlGlobals) {
        if (typeof __exactUrlGlobals.URL === 'function') {
          Object.defineProperty(globalThis, 'URL', {
            configurable: true,
            writable: true,
            enumerable: true,
            value: __exactUrlGlobals.URL
          });
        }
        if (typeof __exactUrlGlobals.URLSearchParams === 'function') {
          Object.defineProperty(globalThis, 'URLSearchParams', {
            configurable: true,
            writable: true,
            enumerable: true,
            value: __exactUrlGlobals.URLSearchParams
          });
        }
      }
    }
  } catch (_exactUrlGlobalsErr) {}

  function __exactGetSharedArrayBufferBacking(buffer) {
    if (typeof SharedArrayBuffer !== 'function') return null;
    if (!buffer || typeof buffer !== 'object') return null;
    if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') return null;
    if (!buffer._buffer || Object.prototype.toString.call(buffer._buffer) !== '[object ArrayBuffer]') {
      return null;
    }
    return buffer._buffer;
  }

  function __exactNeedsSharedArrayBufferViewPatch() {
    if (typeof SharedArrayBuffer !== 'function' || typeof Uint8Array !== 'function') {
      return false;
    }
    try {
      var probeBuffer = new SharedArrayBuffer(1);
      var probeView = new Uint8Array(probeBuffer);
      return (
        probeView.length === 0 ||
        probeView.byteLength === 0 ||
        Object.prototype.toString.call(probeView.buffer) !== '[object SharedArrayBuffer]'
      );
    } catch (_sharedArrayBufferProbeErr) {
      return false;
    }
  }

  function __exactExposeSharedArrayBufferView(view, originalBuffer) {
    if (!view || !originalBuffer) return view;
    try {
      Object.defineProperty(view, 'buffer', {
        configurable: true,
        enumerable: false,
        get: function() {
          return originalBuffer;
        }
      });
    } catch (_sharedArrayBufferBufferErr) {}
    try {
      Object.defineProperty(view, '__exactSharedArrayBuffer', {
        value: originalBuffer,
        writable: false,
        configurable: true,
        enumerable: false
      });
    } catch (_sharedArrayBufferMarkerErr) {}
    return view;
  }

  function __exactWrapSharedArrayBufferViewCtor(name) {
    var NativeCtor = globalThis[name];
    if (typeof NativeCtor !== 'function' || NativeCtor.__exactSharedArrayBufferWrapped) {
      return;
    }

    function WrappedCtor(buffer, byteOffset, length) {
      if (!(this instanceof WrappedCtor)) {
        throw new TypeError('Constructor ' + name + ' requires "new"');
      }

      var backing = __exactGetSharedArrayBufferBacking(buffer);
      if (backing) {
        var view;
        if (arguments.length <= 1) {
          view = new NativeCtor(backing);
        } else if (arguments.length === 2) {
          view = new NativeCtor(backing, byteOffset);
        } else {
          view = new NativeCtor(backing, byteOffset, length);
        }
        return __exactExposeSharedArrayBufferView(view, buffer);
      }

      if (arguments.length === 0) return new NativeCtor();
      if (arguments.length === 1) return new NativeCtor(buffer);
      if (arguments.length === 2) return new NativeCtor(buffer, byteOffset);
      return new NativeCtor(buffer, byteOffset, length);
    }

    var propNames = Object.getOwnPropertyNames(NativeCtor);
    for (var i = 0; i < propNames.length; i++) {
      var propName = propNames[i];
      if (propName === 'prototype' || propName === 'length' || propName === 'name') {
        continue;
      }
      try {
        Object.defineProperty(WrappedCtor, propName, Object.getOwnPropertyDescriptor(NativeCtor, propName));
      } catch (_sharedArrayBufferCtorPropErr) {}
    }
    WrappedCtor.prototype = NativeCtor.prototype;
    try {
      Object.defineProperty(WrappedCtor.prototype, 'constructor', {
        value: WrappedCtor,
        writable: true,
        configurable: true,
        enumerable: false
      });
    } catch (_sharedArrayBufferCtorErr) {}
    try {
      Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
        value: true,
        writable: false,
        configurable: true,
        enumerable: false
      });
    } catch (_sharedArrayBufferWrappedErr) {}
    globalThis[name] = WrappedCtor;
  }

  function __exactPatchSharedArrayBufferViews() {
    if (!__exactNeedsSharedArrayBufferViewPatch()) {
      return;
    }
    var ctorNames = [
      'Int8Array',
      'Uint8Array',
      'Uint8ClampedArray',
      'Int16Array',
      'Uint16Array',
      'Int32Array',
      'Uint32Array',
      'Float32Array',
      'Float64Array'
    ];
    if (typeof globalThis.Float16Array === 'function') ctorNames.push('Float16Array');
    if (typeof globalThis.BigInt64Array === 'function') ctorNames.push('BigInt64Array');
    if (typeof globalThis.BigUint64Array === 'function') ctorNames.push('BigUint64Array');
    for (var i = 0; i < ctorNames.length; i++) {
      __exactWrapSharedArrayBufferViewCtor(ctorNames[i]);
    }
    __exactWrapSharedArrayBufferViewCtor('DataView');
  }

  __exactPatchSharedArrayBufferViews();

  // DOMException polyfill — lazy (needed by AbortController, so define first)
  if (typeof globalThis.DOMException === 'undefined') {
    defineLazyGlobal('DOMException', function() {
      var legacyCodes = {
        IndexSizeError:1,HierarchyRequestError:3,WrongDocumentError:4,
        InvalidCharacterError:5,NoModificationAllowedError:7,NotFoundError:8,
        NotSupportedError:9,InUseAttributeError:10,InvalidStateError:11,
        SyntaxError:12,InvalidModificationError:13,NamespaceError:14,
        InvalidAccessError:15,TypeMismatchError:17,SecurityError:18,
        NetworkError:19,AbortError:20,URLMismatchError:21,
        QuotaExceededError:22,TimeoutError:23,InvalidNodeTypeError:24,
        DataCloneError:25
      };
      function DOMException(message, name) {
        var err = Error.call(this, message || '');
        this.message = message || '';
        this.name = name || 'Error';
        this.code = legacyCodes[this.name] || 0;
        this.stack = err.stack;
      }
      DOMException.prototype = Object.create(Error.prototype);
      DOMException.prototype.constructor = DOMException;
      DOMException.prototype.toString = function() { return this.name + ': ' + this.message; };
      // Static constants
      DOMException.INDEX_SIZE_ERR = 1;
      DOMException.NOT_FOUND_ERR = 8;
      DOMException.NOT_SUPPORTED_ERR = 9;
      DOMException.INVALID_STATE_ERR = 11;
      DOMException.SYNTAX_ERR = 12;
      DOMException.INVALID_MODIFICATION_ERR = 13;
      DOMException.NAMESPACE_ERR = 14;
      DOMException.SECURITY_ERR = 18;
      DOMException.NETWORK_ERR = 19;
      DOMException.ABORT_ERR = 20;
      DOMException.QUOTA_EXCEEDED_ERR = 22;
      DOMException.TIMEOUT_ERR = 23;
      DOMException.DATA_CLONE_ERR = 25;
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

  // Spec-compliant forgiving-base64 decode (per WHATWG Infra + HTML spec).
  // 1. Remove ASCII whitespace (U+0009, U+000A, U+000C, U+000D, U+0020).
  // 2. If length % 4 == 0, strip up to 2 trailing '=' padding characters.
  // 3. If length % 4 == 1, throw InvalidCharacterError.
  // 4. Validate remaining chars are in the base64 alphabet (A-Z a-z 0-9 + /).
  // 5. Decode the data.
  globalThis.atob = function() {
    var input = String(arguments[0]);

    // Step 1: Remove ASCII whitespace
    var stripped = '';
    for (var i = 0; i < input.length; i++) {
      var cc = input.charCodeAt(i);
      if (cc !== 0x09 && cc !== 0x0A && cc !== 0x0C && cc !== 0x0D && cc !== 0x20) {
        stripped += input.charAt(i);
      }
    }

    // Step 2: Handle padding
    var lastNonPad = stripped.length;
    if (lastNonPad > 0 && stripped.charAt(lastNonPad - 1) === '=') {
      lastNonPad--;
      if (lastNonPad > 0 && stripped.charAt(lastNonPad - 1) === '=') {
        lastNonPad--;
      }
    }
    var unpaddedLen = lastNonPad;
    var paddingLen = stripped.length - lastNonPad;

    // Step 3: If length % 4 == 1, that's invalid
    if (unpaddedLen % 4 === 1) {
      throw __exactAtobInvalidCharacterError();
    }

    // Step 4: Validate chars
    var b64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var b64Lookup = {};
    for (var bi = 0; bi < 64; bi++) {
      b64Lookup[b64Chars.charAt(bi)] = bi;
    }

    for (var vi = 0; vi < unpaddedLen; vi++) {
      if (b64Lookup[stripped.charAt(vi)] === undefined) {
        throw __exactAtobInvalidCharacterError();
      }
    }

    // Reject padding that makes the final quantum invalid
    if (paddingLen > 0) {
      // Padding only valid if it completes a 4-char group
      if ((unpaddedLen + paddingLen) % 4 !== 0) {
        throw __exactAtobInvalidCharacterError();
      }
    }

    // Step 5: Decode
    var output = '';
    for (var di = 0; di < unpaddedLen; di += 4) {
      var a = b64Lookup[stripped.charAt(di)] || 0;
      var b = (di + 1 < unpaddedLen) ? b64Lookup[stripped.charAt(di + 1)] : 0;
      var c = (di + 2 < unpaddedLen) ? b64Lookup[stripped.charAt(di + 2)] : -1;
      var d = (di + 3 < unpaddedLen) ? b64Lookup[stripped.charAt(di + 3)] : -1;

      output += String.fromCharCode((a << 2) | (b >> 4));
      if (c !== -1) {
        output += String.fromCharCode(((b & 15) << 4) | (c >> 2));
      }
      if (d !== -1) {
        output += String.fromCharCode(((c & 3) << 6) | d);
      }
    }
    return output;
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

  // ---------------------------------------------------------------------------
  // Timeout / Immediate wrapper classes (Node.js-compatible timer objects)
  // ---------------------------------------------------------------------------
  var _timerIdCounter = 1;

  // Extract the native timer functions before we overwrite them
  var _nativeSetTimeout = typeof globalThis.setTimeout === 'function' ? globalThis.setTimeout : null;
  var _nativeSetInterval = typeof globalThis.setInterval === 'function' ? globalThis.setInterval : null;
  var _nativeClearTimeout = typeof globalThis.clearTimeout === 'function' ? globalThis.clearTimeout : null;
  var _nativeClearInterval = typeof globalThis.clearInterval === 'function' ? globalThis.clearInterval : null;
  var _nativeSetImmediate = typeof globalThis.setImmediate === 'function' ? globalThis.setImmediate : null;
  var _nativeClearImmediate = typeof globalThis.clearImmediate === 'function' ? globalThis.clearImmediate : null;
  // Native ref/unref control (set by C++ runtime to control event loop keep-alive)
  var _nativeTimerRef = typeof globalThis.__exactTimerRef === 'function' ? globalThis.__exactTimerRef : null;
  var _nativeTimerUnref = typeof globalThis.__exactTimerUnref === 'function' ? globalThis.__exactTimerUnref : null;
  var _symbolDispose = typeof Symbol === 'function'
    ? (Symbol.dispose || (typeof Symbol.for === 'function' ? Symbol.for('nodejs.dispose') : null))
    : null;

  // Helper to extract the native timer id from a Timeout/Immediate or raw id
  function _unwrapTimerId(handle) {
    if (handle === null || handle === undefined) return handle;
    if (typeof handle === 'number') return handle;
    if (typeof handle === 'string') return Number(handle);
    if (handle && typeof handle._nativeId !== 'undefined') return handle._nativeId;
    return handle;
  }

  // --- Timeout class (returned by setTimeout / setInterval) ---
  function Timeout(callback, delay, args, isRepeat) {
    this._id = _timerIdCounter++;
    this._nativeId = null; // set after native scheduling
    this._idleTimeout = delay;
    this._onTimeout = callback;
    this._timerArgs = args;
    this._repeat = isRepeat ? delay : null;
    this._destroyed = false;
    // Distinct from _destroyed: _closed means the timer was cleared/closed
    // and must stay dead; _destroyed alone means a one-shot already fired and
    // can still be reactivated via refresh(). Mirrors src/builtins/timers.js
    // (ENG-22970); this global wrapper missed that fix (ENG-23132).
    this._closed = false;
    this._refed = true;
  }

  Timeout.prototype.ref = function ref() {
    this._refed = true;
    if (_nativeTimerRef && this._nativeId !== null) {
      _nativeTimerRef(this._nativeId);
    }
    return this;
  };

  Timeout.prototype.unref = function unref() {
    this._refed = false;
    if (_nativeTimerUnref && this._nativeId !== null) {
      _nativeTimerUnref(this._nativeId);
    }
    return this;
  };

  Timeout.prototype.hasRef = function hasRef() {
    return this._refed;
  };

  Timeout.prototype.refresh = function refresh() {
    // A cleared/closed timer stays dead (Node: clearTimeout sets
    // _idleTimeout = -1 so refresh() cannot reschedule).
    if (this._closed) return this;
    if (this._destroyed) {
      // One-shot that already fired: Node's refresh() reactivates it —
      // re-register in the id map and reschedule from scratch (ENG-22970).
      this._destroyed = false;
      _timeoutMap[this._id] = this;
    } else if (this._nativeId !== null) {
      // Still pending: cancel the in-flight native timer before rescheduling.
      if (this._repeat) {
        _nativeClearInterval(this._nativeId);
      } else {
        _nativeClearTimeout(this._nativeId);
      }
    }
    var self = this;
    if (this._repeat) {
      this._nativeId = _nativeSetInterval(function() { self._invokeCallback(); }, this._idleTimeout);
    } else {
      this._nativeId = _nativeSetTimeout(function() { self._invokeCallback(); }, this._idleTimeout);
    }
    if (!this._refed && _nativeTimerUnref && this._nativeId !== null) {
      _nativeTimerUnref(this._nativeId);
    }
    return this;
  };

  Timeout.prototype.close = function close() {
    if (!this._closed) {
      this._closed = true;
      this._destroyed = true;
      delete _timeoutMap[this._id];
      if (this._nativeId !== null) {
        if (this._repeat) {
          _nativeClearInterval(this._nativeId);
        } else {
          _nativeClearTimeout(this._nativeId);
        }
      }
    }
    return this;
  };

  Timeout.prototype[Symbol.toPrimitive] = function() {
    return this._id;
  };

  if (_symbolDispose) {
    Timeout.prototype[_symbolDispose] = function() {
      this.close();
    };
  }

  Timeout.prototype._invokeCallback = function _invokeCallback() {
    if (this._destroyed) return;
    var cb = this._onTimeout;
    if (typeof cb !== 'function') return;
    // Mark non-repeating timers as destroyed after firing (they stay
    // refresh()-able until closed) and release their id-map entry here —
    // refresh() reschedules with a native callback that only reaches this
    // method, so cleanup anywhere else leaks refreshed-then-fired timers.
    if (!this._repeat) {
      this._destroyed = true;
      delete _timeoutMap[this._id];
    }
    // Check _idleTimeout: if set to -1, treat as cancelled
    if (this._idleTimeout === -1) {
      this.close();
      return;
    }
    var args = this._timerArgs;
    // Use Function.prototype.call/apply to avoid issues with monkey-patched .call/.apply
    if (args && args.length > 0) {
      Function.prototype.apply.call(cb, this, args);
    } else {
      Function.prototype.call.call(cb, this);
    }
    // After callback, check if _onTimeout was nulled or _idleTimeout set to -1
    if (this._repeat) {
      if (typeof this._onTimeout !== 'function' || this._idleTimeout === -1) {
        this.close();
      }
    }
  };

  // --- Immediate class (returned by setImmediate) ---
  function Immediate(callback, args) {
    this._id = _timerIdCounter++;
    this._nativeId = null;
    this._onImmediate = callback;
    this._immediateArgs = args;
    this._destroyed = false;
    this._refed = true;
  }

  Immediate.prototype.ref = function ref() {
    this._refed = true;
    if (this._nativeId && typeof this._nativeId === 'object' && typeof this._nativeId.ref === 'function') {
      this._nativeId.ref();
    } else if (_nativeTimerRef && this._nativeId !== null) {
      _nativeTimerRef(this._nativeId);
    }
    return this;
  };

  Immediate.prototype.unref = function unref() {
    this._refed = false;
    if (this._nativeId && typeof this._nativeId === 'object' && typeof this._nativeId.unref === 'function') {
      this._nativeId.unref();
    } else if (_nativeTimerUnref && this._nativeId !== null) {
      _nativeTimerUnref(this._nativeId);
    }
    return this;
  };

  Immediate.prototype.hasRef = function hasRef() {
    return this._refed;
  };

  Immediate.prototype.close = function close() {
    if (!this._destroyed) {
      this._destroyed = true;
      if (this._nativeId !== null) {
        if (_nativeClearImmediate) {
          _nativeClearImmediate(this._nativeId);
        } else {
          _nativeClearTimeout(this._nativeId);
        }
      }
    }
    return this;
  };

  Immediate.prototype[Symbol.toPrimitive] = function() {
    return this._id;
  };

  if (_symbolDispose) {
    Immediate.prototype[_symbolDispose] = function() {
      this.close();
    };
  }

  Immediate.prototype._invokeCallback = function _invokeCallback() {
    if (this._destroyed) return;
    this._destroyed = true;
    var cb = this._onImmediate;
    if (typeof cb !== 'function') return;
    var args = this._immediateArgs;
    if (args && args.length > 0) {
      Function.prototype.apply.call(cb, this, args);
    } else {
      Function.prototype.call.call(cb, this);
    }
  };

  // Map from Timeout._id to Timeout instance so clearTimeout(numericId) works
  var _timeoutMap = {};

  // --- Wrap setTimeout ---
  if (_nativeSetTimeout) {
    globalThis.setTimeout = function(callback, delay) {
      _validateTimerCallback(callback, 'setTimeout');
      var d = _clampDelay(delay);
      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      // Capture active domain at schedule time so async callbacks inherit it
      var activeDomain = (typeof process !== 'undefined' && process.domain) ? process.domain : null;
      var wrappedCallback = callback;
      if (activeDomain) {
        wrappedCallback = function() {
          var prevDomain = process.domain;
          process.domain = activeDomain;
          try {
            return Function.prototype.apply.call(callback, this, arguments);
          } catch (e) {
            activeDomain.emit('error', e);
          } finally {
            process.domain = prevDomain;
          }
        };
      }
      var timeout = new Timeout(wrappedCallback, d, args, false);
      _timeoutMap[timeout._id] = timeout;
      timeout._nativeId = _nativeSetTimeout(function() {
        // Map cleanup happens in _invokeCallback so refreshed timers (which
        // reschedule with a different native callback) are cleaned up too.
        timeout._invokeCallback();
      }, d);
      return timeout;
    };
  }

  // --- Wrap setInterval ---
  if (_nativeSetInterval) {
    globalThis.setInterval = function(callback, delay) {
      _validateTimerCallback(callback, 'setInterval');
      var d = _clampDelay(delay);
      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      var timeout = new Timeout(callback, d, args, true);
      _timeoutMap[timeout._id] = timeout;
      timeout._nativeId = _nativeSetInterval(function() {
        // close() (reached via clearInterval or a callback that closes the
        // timer) releases the map entry itself.
        timeout._invokeCallback();
      }, d);
      return timeout;
    };
  }

  // --- Wrap clearTimeout ---
  if (_nativeClearTimeout) {
    globalThis.clearTimeout = function(handle) {
      if (handle === null || handle === undefined) return;
      if (handle instanceof Timeout) {
        handle.close();
        delete _timeoutMap[handle._id];
        return;
      }
      // Handle numeric or string id (from Symbol.toPrimitive)
      var numId = typeof handle === 'string' ? Number(handle) : handle;
      if (typeof numId === 'number' && _timeoutMap[numId]) {
        _timeoutMap[numId].close();
        delete _timeoutMap[numId];
        return;
      }
      // Fallback: pass raw value to native clearTimeout
      _nativeClearTimeout(handle);
    };
  }

  // --- Wrap clearInterval ---
  if (_nativeClearInterval) {
    globalThis.clearInterval = function(handle) {
      if (handle === null || handle === undefined) return;
      if (handle instanceof Timeout) {
        handle.close();
        delete _timeoutMap[handle._id];
        return;
      }
      var numId = typeof handle === 'string' ? Number(handle) : handle;
      if (typeof numId === 'number' && _timeoutMap[numId]) {
        _timeoutMap[numId].close();
        delete _timeoutMap[numId];
        return;
      }
      _nativeClearInterval(handle);
    };
  }

  // --- setImmediate / clearImmediate ---
  if (_nativeSetImmediate) {
    globalThis.setImmediate = function(callback) {
      _validateTimerCallback(callback, 'setImmediate');
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      var imm = new Immediate(callback, args);
      imm._nativeId = _nativeSetImmediate(function() {
        imm._invokeCallback();
      });
      return imm;
    };
    globalThis.clearImmediate = function(handle) {
      if (handle instanceof Immediate) {
        handle.close();
      } else if (_nativeClearImmediate) {
        _nativeClearImmediate(_unwrapTimerId(handle));
      } else {
        _nativeClearTimeout(_unwrapTimerId(handle));
      }
    };
  } else {
    if (typeof globalThis.setImmediate === 'undefined') {
      defineLazyGlobal('setImmediate', function() {
        var impl = function(callback) {
          _validateTimerCallback(callback, 'setImmediate');
          var args = [];
          for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
          var imm = new Immediate(callback, args);
          imm._nativeId = _nativeSetTimeout(function() {
            imm._invokeCallback();
          }, 0);
          return imm;
        };
        // Also install clearImmediate eagerly
        globalThis.clearImmediate = function(handle) {
          if (handle instanceof Immediate) {
            handle.close();
          } else {
            _nativeClearTimeout(_unwrapTimerId(handle));
          }
        };
        return impl;
      });
    }
    if (typeof globalThis.clearImmediate === 'undefined') {
      defineLazyGlobal('clearImmediate', function() {
        // Trigger setImmediate lazy init which installs both
        void globalThis.setImmediate;
        if (globalThis.clearImmediate) return globalThis.clearImmediate;
        return function(handle) {
          if (handle instanceof Immediate) {
            handle.close();
          } else {
            _nativeClearTimeout(_unwrapTimerId(handle));
          }
        };
      });
    }
  }

  // AbortController / AbortSignal — lazy (Web API)
  if (typeof globalThis.AbortController === 'undefined') {
      function _initAbort() {
      function AbortSignal() {
        this.aborted = false;
        this.reason = undefined;
        this.onabort = null;
        this._listeners = [];
        this._dependentSignals = [];
        this._sourceSignals = [this];
        this._isComposite = false;
        this[__exactEventTargetKEvents] = new Map();
      }
      function _createAbortEvent(signal) {
        return {
          type: 'abort',
          target: signal,
          currentTarget: signal,
          bubbles: false,
          cancelable: false,
          isTrusted: true,
          timeStamp: Date.now(),
          preventDefault: function() {},
          stopPropagation: function() {},
          stopImmediatePropagation: function() {}
        };
      }
      function _dispatchAbortEvent(signal) {
        var event = _createAbortEvent(signal);
        if (typeof signal.onabort === 'function') {
          try { signal.onabort.call(signal, event); } catch(e) {}
        }
        var listeners = signal._listeners.slice();
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](event); } catch(e) {}
        }
      }
      function _queueAbort(signal, reason, queue) {
        if (signal.aborted) return;
        signal.aborted = true;
        signal.reason = reason;
        queue.push(signal);
        var dependents = signal._dependentSignals.slice();
        for (var i = 0; i < dependents.length; i++) {
          _queueAbort(dependents[i], reason, queue);
        }
      }
      // Internal abort helper — shared by AbortController, timeout(), and any()
      AbortSignal.prototype._abort = function(reason) {
        if (this.aborted) return;
        var queue = [];
        _queueAbort(this, reason, queue);
        for (var i = 0; i < queue.length; i++) {
          _dispatchAbortEvent(queue[i]);
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
        _dispatchAbortEvent(this);
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
        var handle = globalThis.setTimeout(function() {
          s._abort(new (globalThis.DOMException || Error)('The operation was aborted due to timeout.', 'TimeoutError'));
        }, ms);
        if (handle && typeof handle.unref === 'function') {
          try { handle.unref(); } catch (_err) {}
        }
        return s;
      };
      AbortSignal.any = function(signals) {
        var s = new AbortSignal();
        s._isComposite = true;
        if (!signals || signals.length === 0) return s;
        var sourceSignals = [];
        function addSourceSignal(signal) {
          if (!signal || typeof signal !== 'object') {
            return;
          }
          if (sourceSignals.indexOf(signal) === -1) {
            sourceSignals.push(signal);
          }
        }
        for (var i = 0; i < signals.length; i++) {
          var signal = signals[i];
          if (signal && signal._isComposite && Array.isArray(signal._sourceSignals)) {
            for (var j = 0; j < signal._sourceSignals.length; j++) {
              addSourceSignal(signal._sourceSignals[j]);
            }
          } else {
            addSourceSignal(signal);
          }
        }
        s._sourceSignals = sourceSignals.slice();
        for (var i = 0; i < sourceSignals.length; i++) {
          if (sourceSignals[i].aborted) {
            s.aborted = true;
            s.reason = sourceSignals[i].reason;
            return s;
          }
        }
        for (var i = 0; i < sourceSignals.length; i++) {
          if (sourceSignals[i]._dependentSignals.indexOf(s) === -1) {
            sourceSignals[i]._dependentSignals.push(s);
          }
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

  function __exactCreatePerformanceFallback() {
    var _perfStart = Date.now();
    return {
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

  function __exactLoadPerformanceGlobals() {
    var perf = null;
    try {
      if (typeof globalThis.require === 'function') {
        perf = globalThis.require('node:perf_hooks');
      }
    } catch (e) {}

    if (!perf || typeof perf !== 'object') {
      return null;
    }

    if (typeof perf.Performance === 'function') globalThis.Performance = perf.Performance;
    if (typeof perf.PerformanceEntry === 'function') globalThis.PerformanceEntry = perf.PerformanceEntry;
    if (typeof perf.PerformanceMark === 'function') globalThis.PerformanceMark = perf.PerformanceMark;
    if (typeof perf.PerformanceMeasure === 'function') globalThis.PerformanceMeasure = perf.PerformanceMeasure;
    if (typeof perf.PerformanceObserver === 'function') globalThis.PerformanceObserver = perf.PerformanceObserver;
    if (typeof perf.PerformanceResourceTiming === 'function') {
      globalThis.PerformanceResourceTiming = perf.PerformanceResourceTiming;
    }
    if (perf.performance) {
      globalThis.performance = perf.performance;
      return perf.performance;
    }
    return null;
  }

  if (typeof globalThis.performance === 'undefined') {
    defineLazyGlobal('performance', function() {
      return __exactLoadPerformanceGlobals() || __exactCreatePerformanceFallback();
    });
  }

  if (typeof globalThis.Performance === 'undefined') {
    defineLazyGlobal('Performance', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.Performance;
    });
  }

  if (typeof globalThis.PerformanceEntry === 'undefined') {
    defineLazyGlobal('PerformanceEntry', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.PerformanceEntry;
    });
  }

  if (typeof globalThis.PerformanceMark === 'undefined') {
    defineLazyGlobal('PerformanceMark', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.PerformanceMark;
    });
  }

  if (typeof globalThis.PerformanceMeasure === 'undefined') {
    defineLazyGlobal('PerformanceMeasure', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.PerformanceMeasure;
    });
  }

  if (typeof globalThis.PerformanceObserver === 'undefined') {
    defineLazyGlobal('PerformanceObserver', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.PerformanceObserver;
    });
  }

  if (typeof globalThis.PerformanceResourceTiming === 'undefined') {
    defineLazyGlobal('PerformanceResourceTiming', function() {
      __exactLoadPerformanceGlobals();
      return globalThis.PerformanceResourceTiming;
    });
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
        var passive = false;
        var signal = null;
        if (options === true || options === false) {
          capture = !!options;
        } else if (options !== null && options !== undefined && typeof options === 'object') {
          capture = !!options.capture;
          once = !!options.once;
          passive = !!options.passive;
          if ('signal' in options) {
            var rawSignal = options.signal;
            if (rawSignal === null || (rawSignal !== undefined && !(rawSignal && typeof rawSignal === 'object' && 'aborted' in rawSignal))) {
              throw new TypeError("Failed to execute 'addEventListener': The provided value is not of type 'AbortSignal'.");
            }
            signal = rawSignal || null;
          }
        }
        if (signal && signal.aborted) return;
        if (!this._listeners[type]) this._listeners[type] = [];
        var listeners = this._listeners[type];
        for (var i = 0; i < listeners.length; i++) {
          if (listeners[i].fn === listener && listeners[i].capture === capture) {
            return;
          }
        }
        var entry = { fn: listener, once: once, capture: capture, passive: passive, signal: signal };
        listeners.push(entry);
        __addEventTargetEventListener(this, type, listener);
        if (signal) {
          var self = this;
          var abortHandler = function() {
            self.removeEventListener(type, listener, { capture: capture });
          };
          signal.addEventListener('abort', abortHandler, { once: true });
        }
      };
      EventTarget.prototype.removeEventListener = function(type, listener, options) {
        if (!this._listeners[type]) return;
        var capture = false;
        if (options === true || options === false) {
          capture = !!options;
        } else if (options && typeof options === 'object') {
          capture = !!options.capture;
        }
        this._listeners[type] = this._listeners[type].filter(function(l) {
          return !(l.fn === listener && l.capture === capture);
        });
        __removeEventTargetEventListener(this, type, listener);
      };
      EventTarget.prototype.dispatchEvent = function(event) {
        if (!event || !event.type) return true;
        var listeners = this._listeners[event.type];
        event.target = this;
        event.currentTarget = this;
        if (event.srcElement !== undefined) event.srcElement = this;
        if (event.eventPhase !== undefined) event.eventPhase = 2;
        if (!listeners || listeners.length === 0) {
          event.eventPhase = 0;
          event.currentTarget = null;
          return !event.defaultPrevented;
        }
        var snapshot = listeners.slice();
        var self = this;
        for (var i = 0; i < snapshot.length; i++) {
          if (event._stopImmediatePropagation) break;
          var listener = snapshot[i];
          if (!listener) continue;
          var current = self._listeners[event.type];
          if (!current) break;
          var stillPresent = false;
          for (var j = 0; j < current.length; j++) {
            if (current[j].fn === listener.fn && current[j].capture === listener.capture) {
              stillPresent = true;
              break;
            }
          }
          if (!stillPresent) continue;
          if (listener.once) {
            self._listeners[event.type] = current.filter(function(entry) {
              return !(entry.fn === listener.fn && entry.capture === listener.capture);
            });
            __removeEventTargetEventListener(self, event.type, listener.fn);
          }
          if (listener.passive) {
            event._passive = true;
            try {
              if (typeof listener.fn === 'function') {
                listener.fn.call(self, event);
              } else if (listener.fn && typeof listener.fn.handleEvent === 'function') {
                listener.fn.handleEvent(event);
              }
            } finally {
              event._passive = false;
            }
          } else {
            if (typeof listener.fn === 'function') {
              listener.fn.call(self, event);
            } else if (listener.fn && typeof listener.fn.handleEvent === 'function') {
              listener.fn.handleEvent(event);
            }
          }
        }
        event.eventPhase = 0;
        event.currentTarget = null;
        return !event.defaultPrevented;
      };
      globalThis.EventTarget = EventTarget;

      // Shared isTrusted getter - same function reference across all Event instances (per spec)
      var _isTrustedGetter = function() { return false; };

      function Event(type, options) {
        if (!(this instanceof Event)) {
          throw new TypeError("Failed to construct 'Event': Please use the 'new' operator.");
        }
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
        this.eventPhase = 0;
        this._cancelBubble = false;
        this._stopPropagation = false;
        this._stopImmediatePropagation = false;
        this._passive = false;
        Object.defineProperty(this, 'isTrusted', {
          get: _isTrustedGetter,
          enumerable: true,
          configurable: false
        });
      }
      Object.defineProperty(Event.prototype, 'cancelBubble', {
        get: function() { return this._cancelBubble; },
        set: function(v) { if (v) this._cancelBubble = true; },
        enumerable: true, configurable: true
      });
      Object.defineProperty(Event.prototype, 'returnValue', {
        get: function() { return !this.defaultPrevented; },
        set: function(v) {
          if (v === false && !this._passive) {
            if (this.cancelable) this.defaultPrevented = true;
          }
        },
        enumerable: true, configurable: true
      });
      Event.prototype.composedPath = function() {
        return this.currentTarget ? [this.currentTarget] : [];
      };
      Event.prototype.preventDefault = function() {
        if (this.cancelable && !this._passive) this.defaultPrevented = true;
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
      Event.prototype.initEvent = function(type, bubbles, cancelable) {
        this.type = String(type);
        this.bubbles = !!bubbles;
        this.cancelable = !!cancelable;
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
        if (!(this instanceof CustomEvent)) {
          throw new TypeError("Failed to construct 'CustomEvent': Please use the 'new' operator.");
        }
        if (arguments.length === 0) {
          throw new TypeError("Failed to construct 'CustomEvent': 1 argument required, but only 0 present.");
        }
        if (typeof type === 'symbol') {
          throw new TypeError("Cannot convert a Symbol value to a string");
        }
        if (options !== undefined && options !== null && typeof options !== 'object') {
          var err = new TypeError('The "options" argument must be of type object.' +
            ' Received type ' + typeof options + ' (' + String(options) + ')');
          err.code = 'ERR_INVALID_ARG_TYPE';
          throw err;
        }
        Event.call(this, type, options);
        Object.defineProperty(this, 'detail', {
          value: (options && options.detail !== undefined) ? options.detail : null,
          writable: false,
          enumerable: true,
          configurable: false
        });
      }
      CustomEvent.prototype = Object.create(Event.prototype);
      CustomEvent.prototype.constructor = CustomEvent;
      CustomEvent.NONE = 0;
      CustomEvent.CAPTURING_PHASE = 1;
      CustomEvent.AT_TARGET = 2;
      CustomEvent.BUBBLING_PHASE = 3;
      Object.defineProperty(CustomEvent, 'length', { value: 1, writable: false, configurable: true });
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
      function __blobEncodeString(text) {
        if (typeof TextEncoder === 'function') {
          return new TextEncoder().encode(text);
        }
        var encoded = encodeURIComponent(String(text));
        var bytes = [];
        for (var i = 0; i < encoded.length; i++) {
          var ch = encoded.charAt(i);
          if (ch === '%' && i + 2 < encoded.length) {
            bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
            i += 2;
          } else {
            bytes.push(ch.charCodeAt(0) & 0xff);
          }
        }
        return new Uint8Array(bytes);
      }

      function __blobDecodeBytes(bytes) {
        if (typeof TextDecoder === 'function') {
          return new TextDecoder('utf-8').decode(bytes);
        }
        var out = '';
        for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
        return out;
      }

      function __blobPartToBytes(part) {
        if (typeof part === 'string') return __blobEncodeString(part);
        if (part instanceof Uint8Array) return part;
        if (part instanceof ArrayBuffer) return new Uint8Array(part);
        if (ArrayBuffer.isView(part)) {
          return new Uint8Array(part.buffer, part.byteOffset, part.byteLength);
        }
        if (part && typeof part._getBytes === 'function') {
          return part._getBytes();
        }
        return __blobEncodeString(String(part));
      }

      function Blob(parts, options) {
        this._parts = parts || [];
        var rawType = (options && options.type) || '';
        // Per spec: Blob type must be ASCII-lowercased
        this.type = rawType.toLowerCase();
        var totalSize = 0;
        for (var i = 0; i < this._parts.length; i++) {
          totalSize += __blobPartToBytes(this._parts[i]).length;
        }
        this.size = totalSize;
      }
      Blob.prototype.text = function() {
        return Promise.resolve(__blobDecodeBytes(this._getBytes()));
      };
      Blob.prototype.arrayBuffer = function() {
        var bytes = this._getBytes();
        return Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
      };
      Blob.prototype.json = function() {
        return this.text().then(function(text) {
          return JSON.parse(text);
        });
      };
      Blob.prototype.formData = function() {
        return this.text().then(function(text) {
          var params = new URLSearchParams(text);
          var form = new FormData();
          if (typeof params.forEach === 'function') {
            params.forEach(function(value, key) {
              form.append(key, value);
            });
          }
          return form;
        });
      };
      Blob.prototype.slice = function(start, end, contentType) {
        var bytes = this._getBytes ? this._getBytes() : new Uint8Array(0);
        var size = bytes.length;
        // Normalize start
        var s = start === undefined ? 0 : (start < 0 ? Math.max(size + start, 0) : Math.min(start, size));
        // Normalize end
        var e = end === undefined ? size : (end < 0 ? Math.max(size + end, 0) : Math.min(end, size));
        var span = Math.max(e - s, 0);
        var sliced = span > 0 ? bytes.slice(s, s + span) : new Uint8Array(0);
        return new Blob([sliced], { type: (contentType !== undefined && contentType !== null) ? String(contentType).toLowerCase() : '' });
      };
      Blob.prototype._getBytes = function() {
        var totalSize = this.size;
        var result = new Uint8Array(totalSize);
        var offset = 0;
        for (var i = 0; i < this._parts.length; i++) {
          var partBytes = __blobPartToBytes(this._parts[i]);
          result.set(partBytes, offset);
          offset += partBytes.length;
        }
        return result;
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
