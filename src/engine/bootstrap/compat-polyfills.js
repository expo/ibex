(function() {
  (function patchBase64DomExceptions() {
    var nativeBtoa = typeof globalThis.btoa === 'function' ? globalThis.btoa : null;
    var nativeAtob = typeof globalThis.atob === 'function' ? globalThis.atob : null;

    function invalidCharacterError(message) {
      if (typeof globalThis.DOMException === 'function') {
        return new globalThis.DOMException(message, 'InvalidCharacterError');
      }
      var err = new Error(message);
      err.name = 'InvalidCharacterError';
      err.code = 5;
      return err;
    }

    if (nativeAtob && nativeAtob.__exactDomWrapped !== true) {
      var wrappedAtob = function(input) {
        try {
          return nativeAtob(String(input));
        } catch (_err) {
          throw invalidCharacterError('The string to be decoded is not correctly encoded.');
        }
      };
      Object.defineProperty(wrappedAtob, '__exactDomWrapped', {
        value: true,
        configurable: true,
        enumerable: false,
        writable: false
      });
      globalThis.atob = wrappedAtob;
    }

    if (nativeBtoa && nativeBtoa.__exactDomWrapped !== true) {
      var wrappedBtoa = function(input) {
        var str = String(input);
        for (var i = 0; i < str.length; i++) {
          if (str.charCodeAt(i) > 255) {
            throw invalidCharacterError('The string to be encoded contains characters outside of the Latin1 range.');
          }
        }
        try {
          return nativeBtoa(str);
        } catch (_err) {
          throw invalidCharacterError('The string to be encoded contains characters outside of the Latin1 range.');
        }
      };
      Object.defineProperty(wrappedBtoa, '__exactDomWrapped', {
        value: true,
        configurable: true,
        enumerable: false,
        writable: false
      });
      globalThis.btoa = wrappedBtoa;
    }
  })();

  // Hermes does not support subclassing Date via ES6 `class X extends Date`.
  // The super() call returns a primitive string instead of a Date object, so
  // `this[0] = '1'` inside a subclass constructor throws:
  //   "Cannot create property '0' on string '...'"
  // Fix: wrap the native Date constructor so that `new (class extends Date)`
  // produces a real Date object whose [[Prototype]] is the subclass prototype.
  (function patchDateSubclassing() {
    if (typeof Date === 'undefined') return;
    // Quick probe: try subclassing with ES6 class syntax and see if it works.
    var needsPatch = false;
    try {
      // Use Function() to avoid parse errors in engines that don't support class syntax
      var TestSubFn = Function('Date', 'return class TestDateSub extends Date { constructor() { super(); this[0] = "x"; } }');
      var TestSub = TestSubFn(Date);
      var inst = new TestSub();
      // If inst is not a real object or setting indexed properties failed, we need the patch
      if (typeof inst !== 'object' || inst === null || inst[0] !== 'x') {
        needsPatch = true;
      }
    } catch (e) {
      needsPatch = true;
    }
    if (!needsPatch) return;

    var NativeDate = Date;
    var WrappedDate = function Date() {
      var args = arguments;
      // Called as function (without new) — return a string like native Date()
      if (!(this instanceof WrappedDate)) {
        return NativeDate.apply(null, args);
      }
      // Construct a real NativeDate object
      var d;
      switch (args.length) {
        case 0: d = new NativeDate(); break;
        case 1: d = new NativeDate(args[0]); break;
        case 2: d = new NativeDate(args[0], args[1]); break;
        case 3: d = new NativeDate(args[0], args[1], args[2]); break;
        case 4: d = new NativeDate(args[0], args[1], args[2], args[3]); break;
        case 5: d = new NativeDate(args[0], args[1], args[2], args[3], args[4]); break;
        case 6: d = new NativeDate(args[0], args[1], args[2], args[3], args[4], args[5]); break;
        default: d = new NativeDate(args[0], args[1], args[2], args[3], args[4], args[5], args[6]); break;
      }
      // Set the prototype chain to the subclass (or WrappedDate) prototype.
      // `new.target` is not available in Hermes, so use `this.constructor` which
      // is set by the engine when the subclass constructor calls super().
      var proto = (this.constructor && this.constructor !== WrappedDate)
        ? this.constructor.prototype
        : WrappedDate.prototype;
      if (proto && proto !== Object.prototype) {
        Object.setPrototypeOf(d, proto);
      }
      return d; // returning an object from a constructor replaces `this`
    };
    // Copy static methods (Date.now, Date.parse, Date.UTC, etc.)
    var staticKeys = Object.getOwnPropertyNames(NativeDate);
    for (var i = 0; i < staticKeys.length; i++) {
      var key = staticKeys[i];
      if (key === 'prototype' || key === 'length' || key === 'name') continue;
      try {
        var desc = Object.getOwnPropertyDescriptor(NativeDate, key);
        if (desc) Object.defineProperty(WrappedDate, key, desc);
      } catch (e) {}
    }
    // Set up prototype chain
    WrappedDate.prototype = NativeDate.prototype;
    WrappedDate.prototype.constructor = WrappedDate;
    // Make instanceof work: WrappedDate[Symbol.hasInstance] should check NativeDate
    try {
      Object.defineProperty(WrappedDate, Symbol.hasInstance, {
        value: function(inst) { return inst instanceof NativeDate; },
        configurable: true
      });
    } catch (e) {}
    globalThis.Date = WrappedDate;
  })();

  if (typeof Array !== 'undefined' && typeof Array.isArray !== 'function') {
    Array.isArray = function(value) {
      return Object.prototype.toString.call(value) === '[object Array]';
    };
  }

  if (typeof Promise !== 'undefined' && typeof Promise.withResolvers !== 'function') {
    Promise.withResolvers = function() {
      var resolve;
      var reject;
      var promise = new Promise(function(res, rej) {
        resolve = res;
        reject = rej;
      });
      return {
        promise: promise,
        resolve: resolve,
        reject: reject
      };
    };
  }

  if (typeof globalThis.gc === 'function' && globalThis.gc.__exactWrapped !== true) {
    var __exactNativeGc = globalThis.gc;
    var __exactWrappedGc = function() {
      var args = arguments;
      __exactNativeGc.apply(globalThis, args);
      var scheduleExtraGc = null;
      if (typeof globalThis.setImmediate === 'function') {
        scheduleExtraGc = globalThis.setImmediate;
      } else if (typeof process !== 'undefined' && process && typeof process.nextTick === 'function') {
        scheduleExtraGc = process.nextTick;
      }
      if (scheduleExtraGc) {
        scheduleExtraGc(function() {
          try {
            __exactNativeGc.apply(globalThis, args);
          } catch (err) {}
        });
      }
    };
    try {
      Object.defineProperty(__exactWrappedGc, '__exactWrapped', {
        value: true,
        configurable: true,
        enumerable: false,
        writable: false
      });
    } catch (err) {}
    globalThis.gc = __exactWrappedGc;
  }

  function __exactPatchBrokenSharedArrayBuffer() {
    if (typeof globalThis.ArrayBuffer !== 'function' || typeof globalThis.SharedArrayBuffer !== 'function') {
      return;
    }
    var needsViewPatch = false;
    try {
      var probe = new globalThis.SharedArrayBuffer(1);
      var probeView = new Uint8Array(probe);
      needsViewPatch = (
        probeView.byteLength === 0 ||
        probeView.length === 0 ||
        Object.prototype.toString.call(probeView.buffer) !== '[object SharedArrayBuffer]'
      );
      if (probe.byteLength === 1 && probeView.byteLength === 1 && !needsViewPatch) {
        return;
      }
    } catch (err) {}

    var NativeArrayBuffer = globalThis.ArrayBuffer;

    function SharedArrayBuffer(byteLength) {
      if (!(this instanceof SharedArrayBuffer)) {
        throw new TypeError('Constructor SharedArrayBuffer requires "new"');
      }
      var length = Number(byteLength);
      if (!isFinite(length) || length < 0) {
        throw new RangeError('Invalid SharedArrayBuffer length');
      }
      length = Math.floor(length);
      var buffer = new NativeArrayBuffer(length);
      try {
        Object.setPrototypeOf(buffer, SharedArrayBuffer.prototype);
      } catch (err) {}
      return buffer;
    }

    SharedArrayBuffer.prototype = Object.create(NativeArrayBuffer.prototype);
    Object.defineProperty(SharedArrayBuffer.prototype, 'constructor', {
      value: SharedArrayBuffer,
      writable: true,
      configurable: true
    });
    if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
      Object.defineProperty(SharedArrayBuffer.prototype, Symbol.toStringTag, {
        value: 'SharedArrayBuffer',
        configurable: true
      });
    }

    try {
      Object.setPrototypeOf(SharedArrayBuffer, globalThis.Function.prototype);
    } catch (err) {}

    try {
      Object.defineProperty(globalThis, 'SharedArrayBuffer', {
        value: SharedArrayBuffer,
        writable: true,
        configurable: true,
        enumerable: true
      });
    } catch (err) {
      globalThis.SharedArrayBuffer = SharedArrayBuffer;
    }
    try {
      SharedArrayBuffer = globalThis.SharedArrayBuffer;
    } catch (err) {}

    function getSharedArrayBufferBacking(buffer) {
      if (!buffer || typeof buffer !== 'object') return null;
      if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') return null;
      if (!buffer._buffer || Object.prototype.toString.call(buffer._buffer) !== '[object ArrayBuffer]') {
        return null;
      }
      return buffer._buffer;
    }

    function exposeSharedArrayBufferView(view, originalBuffer) {
      if (!view || !originalBuffer) return view;
      try {
        Object.defineProperty(view, 'buffer', {
          configurable: true,
          enumerable: false,
          get: function() {
            return originalBuffer;
          }
        });
      } catch (err) {}
      try {
        Object.defineProperty(view, '__exactSharedArrayBuffer', {
          value: originalBuffer,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      return view;
    }

    function wrapSharedArrayBufferViewCtor(name) {
      var NativeCtor = globalThis[name];
      if (typeof NativeCtor !== 'function' || NativeCtor.__exactSharedArrayBufferWrapped) {
        return;
      }

      function WrappedCtor(buffer, byteOffset, length) {
        if (!(this instanceof WrappedCtor)) {
          throw new TypeError('Constructor ' + name + ' requires "new"');
        }

        var backing = getSharedArrayBufferBacking(buffer);
        if (backing) {
          var view;
          if (arguments.length <= 1) {
            view = new NativeCtor(backing);
          } else if (arguments.length === 2) {
            view = new NativeCtor(backing, byteOffset);
          } else {
            view = new NativeCtor(backing, byteOffset, length);
          }
          return exposeSharedArrayBufferView(view, buffer);
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
        } catch (err) {}
      }
      WrappedCtor.prototype = NativeCtor.prototype;
      try {
        Object.defineProperty(WrappedCtor.prototype, 'constructor', {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      try {
        Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      globalThis[name] = WrappedCtor;
    }

    if (needsViewPatch) {
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
      for (var j = 0; j < ctorNames.length; j++) {
        wrapSharedArrayBufferViewCtor(ctorNames[j]);
      }
      wrapSharedArrayBufferViewCtor('DataView');
    }
  }

  function __exactTrimEncodingLabel(label) {
    var start = 0;
    var end = label.length;
    while (start < end) {
      var startCode = label.charCodeAt(start);
      if (startCode === 0x09 || startCode === 0x0A || startCode === 0x0C || startCode === 0x0D || startCode === 0x20) {
        start++;
        continue;
      }
      break;
    }
    while (end > start) {
      var endCode = label.charCodeAt(end - 1);
      if (endCode === 0x09 || endCode === 0x0A || endCode === 0x0C || endCode === 0x0D || endCode === 0x20) {
        end--;
        continue;
      }
      break;
    }
    return label.slice(start, end);
  }

  function __exactPatchTextDecoder() {
    if (typeof globalThis.TextDecoder !== 'function') {
      return;
    }
    var NativeTextDecoder = globalThis.TextDecoder;
    try {
      new NativeTextDecoder('\u000bunicode-1-1-utf-8');
    } catch (err) {
      return;
    }

    function TextDecoder(label, options) {
      var normalizedLabel = label;
      if (arguments.length > 0 && label !== undefined) {
        normalizedLabel = __exactTrimEncodingLabel(String(label)).toLowerCase();
        if (normalizedLabel === '') {
          throw new RangeError('The encoding label provided must be a valid label.');
        }
        for (var i = 0; i < normalizedLabel.length; i++) {
          var code = normalizedLabel.charCodeAt(i);
          if (code <= 0x20 || code >= 0x7f) {
            throw new RangeError('The encoding label provided must be a valid label.');
          }
        }
      }
      return new NativeTextDecoder(normalizedLabel, options);
    }

    TextDecoder.prototype = NativeTextDecoder.prototype;
    try {
      Object.setPrototypeOf(TextDecoder, NativeTextDecoder);
    } catch (err) {}
    try {
      Object.defineProperty(globalThis, 'TextDecoder', {
        value: TextDecoder,
        writable: true,
        configurable: true,
        enumerable: true
      });
    } catch (err) {
      globalThis.TextDecoder = TextDecoder;
    }
    try {
      TextDecoder = globalThis.TextDecoder;
    } catch (err) {}
  }

  function __exactNormalizeFetchInit(init) {
    if (!init || typeof init !== 'object') {
      return init;
    }
    var normalized = {};
    for (var key in init) {
      if (Object.prototype.hasOwnProperty.call(init, key)) {
        normalized[key] = init[key];
      }
    }
    if (
      normalized.body !== undefined &&
      normalized.body !== null &&
      (normalized.method === undefined || normalized.method === null || normalized.method === '')
    ) {
      normalized.method = 'POST';
    }
    if (normalized.headers && typeof globalThis.Headers === 'function' &&
        !(normalized.headers instanceof globalThis.Headers)) {
      try {
        normalized.headers = new globalThis.Headers(normalized.headers);
      } catch (err) {
        normalized.headers = init.headers;
      }
    }
    return normalized;
  }

  function __exactWrapFetchConstructor(name) {
    var NativeCtor = globalThis[name];
    if (typeof NativeCtor !== 'function' || NativeCtor.__exactCompatPatched) {
      return;
    }
    function Wrapped(input, init) {
      return new NativeCtor(input, __exactNormalizeFetchInit(init));
    }
    Wrapped.prototype = NativeCtor.prototype;
    try {
      Object.setPrototypeOf(Wrapped, NativeCtor);
    } catch (err) {}
    Wrapped.__exactCompatPatched = true;
    try {
      Object.defineProperty(globalThis, name, {
        value: Wrapped,
        writable: true,
        configurable: true,
        enumerable: true
      });
    } catch (err) {
      globalThis[name] = Wrapped;
    }
    try {
      if (name === 'Request') {
        Request = globalThis.Request;
      } else if (name === 'Response') {
        Response = globalThis.Response;
      }
    } catch (err) {}
  }

  function __exactPatchFetchConstructors() {
    __exactWrapFetchConstructor('Request');
    __exactWrapFetchConstructor('Response');
  }

  function __exactNormalizeTypedArrayIndex(index, length) {
    if (index === undefined) {
      return 0;
    }
    var value = Number(index);
    if (!isFinite(value) || value === 0) {
      return 0;
    }
    value = value < 0 ? Math.ceil(value) : Math.floor(value);
    if (value < 0) {
      return Math.max(length + value, 0);
    }
    return Math.min(value, length);
  }

  function __exactPatchZeroLengthTypedArraySubarray() {
    var typedArrayNames = [
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
    if (typeof globalThis.BigInt64Array === 'function') typedArrayNames.push('BigInt64Array');
    if (typeof globalThis.BigUint64Array === 'function') typedArrayNames.push('BigUint64Array');

    for (var i = 0; i < typedArrayNames.length; i++) {
      var ctorName = typedArrayNames[i];
      var TypedArrayCtor = globalThis[ctorName];
      if (typeof TypedArrayCtor !== 'function') {
        continue;
      }

      var originalSubarray = TypedArrayCtor.prototype && TypedArrayCtor.prototype.subarray;
      if (typeof originalSubarray !== 'function' || originalSubarray.__exactZeroLengthWrapped) {
        continue;
      }

      (function(Ctor, subarray) {
        var bytesPerElement = Ctor.BYTES_PER_ELEMENT || Ctor.prototype.BYTES_PER_ELEMENT || 1;
        function patchedSubarray(begin, end) {
          var result = subarray.call(this, begin, end);
          if (!result || result.byteLength !== 0 || result.buffer !== this.buffer) {
            return result;
          }

          var length = typeof this.length === 'number'
            ? this.length
            : Math.floor(this.byteLength / bytesPerElement);
          var start = __exactNormalizeTypedArrayIndex(begin, length);
          var finish = end === undefined ? length : __exactNormalizeTypedArrayIndex(end, length);
          if (finish < start) {
            finish = start;
          }
          if (finish !== start) {
            return result;
          }

          var correctedByteOffset = this.byteOffset + start * bytesPerElement;
          try {
            Object.defineProperty(result, 'byteOffset', {
              value: correctedByteOffset,
              configurable: true
            });
            return result;
          } catch (err) {
            return new Ctor(this.buffer, correctedByteOffset, 0);
          }
        }

        try {
          Object.defineProperty(patchedSubarray, '__exactZeroLengthWrapped', {
            value: true,
            configurable: true
          });
        } catch (err) {}

        try {
          Object.defineProperty(Ctor.prototype, 'subarray', {
            value: patchedSubarray,
            writable: true,
            configurable: true,
            enumerable: false
          });
        } catch (err) {
          Ctor.prototype.subarray = patchedSubarray;
        }
      })(TypedArrayCtor, originalSubarray);
    }
  }

  __exactPatchBrokenSharedArrayBuffer();
  __exactPatchZeroLengthTypedArraySubarray();
  __exactPatchTextDecoder();
  __exactPatchFetchConstructors();

  if (typeof Array.prototype.toSorted !== 'function') {
    Object.defineProperty(Array.prototype, 'toSorted', {
      value: function(compareFn) {
        var sorted = this.slice();
        return sorted.sort(compareFn);
      },
      writable: true,
      configurable: true,
      enumerable: false
    });
  }

  if (typeof Array.prototype.toReversed !== 'function') {
    Object.defineProperty(Array.prototype, 'toReversed', {
      value: function() {
        var result = [];
        for (var i = this.length - 1; i >= 0; i--) result.push(this[i]);
        return result;
      },
      writable: true,
      configurable: true,
      enumerable: false
    });
  }

  if (typeof FinalizationRegistry === 'undefined') {
    FinalizationRegistry = function(cleanupCallback) {
      if (!(this instanceof FinalizationRegistry)) {
        throw new TypeError('FinalizationRegistry must be called with new');
      }
      if (typeof cleanupCallback !== 'function') {
        throw new TypeError('FinalizationRegistry requires a callback');
      }
      this._entries = [];
      this._cleanup = cleanupCallback;
    };
    FinalizationRegistry.prototype.register = function(target, heldValue, unregisterToken) {
      if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
        throw new TypeError('FinalizationRegistry target must be an object');
      }
      this._entries.push({
        target: target,
        heldValue: heldValue,
        token: unregisterToken
      });
      return true;
    };
    FinalizationRegistry.prototype.unregister = function(unregisterToken) {
      var removed = false;
      for (var i = this._entries.length - 1; i >= 0; i--) {
        if (this._entries[i].token === unregisterToken) {
          this._entries.splice(i, 1);
          removed = true;
        }
      }
      return removed;
    };
  }

  // @ref LLP 0013#mechanism-3 — no plain-object env snapshot on `process`.
  // A former workaround materialized `process.__exactPlainEnv`, a full copy of
  // the environment, because the old native JSI HostObject `env` silently
  // dropped writes. `process.env` is now a JS Proxy (see exact-global.js) whose
  // `set` trap handles writes and whose reads funnel every key through the
  // capability-checked `__exactGetEnv`/`__exactGetAllEnv` host functions
  // (`env:read:<key>` / `env:read:*`). A plain snapshot would be an UNGATED
  // full-environment surface: any code holding `process` (e.g. a package
  // endowed with `process` for `process.argv`) could read every secret via
  // `process.__exactPlainEnv`, laundering past its `env:read` grant. It had no
  // readers, so it is simply not created — env reads have exactly one gated path.

  function __exactGetSharedArrayBufferBacking(buffer) {
    if (!buffer || typeof buffer !== 'object') {
      return null;
    }
    if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') {
      return null;
    }
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
    } catch (err) {
      return false;
    }
  }

  function __exactExposeSharedArrayBuffer(view, originalBuffer) {
    if (!view || !originalBuffer) {
      return view;
    }
    try {
      Object.defineProperty(view, 'buffer', {
        configurable: true,
        enumerable: false,
        get: function() {
          return originalBuffer;
        }
      });
    } catch (err) {}
    try {
      Object.defineProperty(view, '__exactSharedArrayBuffer', {
        value: originalBuffer,
        writable: false,
        configurable: true,
        enumerable: false
      });
    } catch (err) {}
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
        var patchedView;
        if (arguments.length <= 1) {
          patchedView = new NativeCtor(backing);
        } else if (arguments.length === 2) {
          patchedView = new NativeCtor(backing, byteOffset);
        } else {
          patchedView = new NativeCtor(backing, byteOffset, length);
        }
        return __exactExposeSharedArrayBuffer(patchedView, buffer);
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
      } catch (err) {}
    }
    WrappedCtor.prototype = NativeCtor.prototype;
    try {
      Object.defineProperty(WrappedCtor.prototype, 'constructor', {
        value: WrappedCtor,
        writable: true,
        configurable: true,
        enumerable: false
      });
    } catch (err) {}
    try {
      Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
        value: true,
        writable: false,
        configurable: true,
        enumerable: false
      });
    } catch (err) {}
    globalThis[name] = WrappedCtor;
  }

  function __exactPatchSharedArrayBufferViews() {
    if (!__exactNeedsSharedArrayBufferViewPatch()) {
      return;
    }

    var typedArrayNames = [
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
    if (typeof globalThis.Float16Array === 'function') {
      typedArrayNames.push('Float16Array');
    }
    if (typeof globalThis.BigInt64Array === 'function') {
      typedArrayNames.push('BigInt64Array');
    }
    if (typeof globalThis.BigUint64Array === 'function') {
      typedArrayNames.push('BigUint64Array');
    }
    for (var i = 0; i < typedArrayNames.length; i++) {
      __exactWrapSharedArrayBufferViewCtor(typedArrayNames[i]);
    }
    __exactWrapSharedArrayBufferViewCtor('DataView');
  }

  __exactPatchSharedArrayBufferViews();

  function __exactInspectExecveValue(value) {
    if (typeof value === 'string') {
      return "'" + value.replace(/\0/g, '\\x00') + "'";
    }
    return String(value);
  }

  function __exactValidateExecveArguments(execPath, args, envObj, hasEnvArgument) {
    if (typeof execPath !== 'string') {
      var execPathError = new TypeError('The "execPath" argument must be of type string. Received type ' + typeof execPath + ' (' + String(execPath) + ')');
      execPathError.code = 'ERR_INVALID_ARG_TYPE';
      throw execPathError;
    }
    if (!Array.isArray(args)) {
      var argsError = new TypeError('The "args" argument must be an instance of Array. Received type ' + typeof args + ' (' + __exactInspectExecveValue(args) + ')');
      argsError.code = 'ERR_INVALID_ARG_TYPE';
      throw argsError;
    }
    for (var __execveIndex = 0; __execveIndex < args.length; __execveIndex++) {
      if (typeof args[__execveIndex] !== 'string' || args[__execveIndex].indexOf('\0') !== -1) {
        var argValueError = new TypeError("The argument 'args[" + __execveIndex + "]' must be a string without null bytes. Received " + __exactInspectExecveValue(args[__execveIndex]));
        argValueError.code = 'ERR_INVALID_ARG_VALUE';
        throw argValueError;
      }
    }
    if (!hasEnvArgument) {
      return;
    }
    if (typeof envObj !== 'object' || envObj === null || Array.isArray(envObj)) {
      var envTypeError = new TypeError('The "env" argument must be of type object. Received type ' + typeof envObj + ' (' + __exactInspectExecveValue(envObj) + ')');
      envTypeError.code = 'ERR_INVALID_ARG_TYPE';
      throw envTypeError;
    }
    var envKeys = Object.keys(envObj);
    for (var __envIndex = 0; __envIndex < envKeys.length; __envIndex++) {
      var envValue = envObj[envKeys[__envIndex]];
      if (typeof envValue !== 'string' || envValue.indexOf('\0') !== -1) {
        var envPairs = [];
        for (var __pairIndex = 0; __pairIndex < envKeys.length; __pairIndex++) {
          envPairs.push(envKeys[__pairIndex] + ': ' + __exactInspectExecveValue(envObj[envKeys[__pairIndex]]));
        }
        var envValueError = new TypeError("The argument 'env' must be an object with string keys and values without null bytes. Received { " + envPairs.join(', ') + ' }');
        envValueError.code = 'ERR_INVALID_ARG_VALUE';
        throw envValueError;
      }
    }
  }

  function __exactPermissionDeniesChildProcess(execArgv) {
    if (!Array.isArray(execArgv)) {
      return false;
    }
    var permissionMode = false;
    var allowChildProcess = false;
    for (var __argIndex = 0; __argIndex < execArgv.length; __argIndex++) {
      var arg = String(execArgv[__argIndex]);
      if (arg === '--permission' || arg.indexOf('--permission=') === 0) {
        permissionMode = true;
        continue;
      }
      if (arg === '--allow-child-process' || arg.indexOf('--allow-child-process=') === 0) {
        allowChildProcess = true;
      }
    }
    return permissionMode && !allowChildProcess;
  }

  function __exactCreateProcessVersions() {
    var versions = {};
    var entries = [
      ['node', '24.13.1'],
      ['acorn', '8.15.0'],
      ['ada', '2.9.2'],
      ['ares', '1.34.4'],
      ['brotli', '1.1.0'],
      ['cjs_module_lexer', '2.1.0'],
      ['cldr', '46.0'],
      ['icu', '76.1'],
      ['llhttp', '9.3.0'],
      ['modules', '131'],
      ['napi', '9'],
      ['nbytes', '0.1.1'],
      ['ncrypto', '0.0.1'],
      ['nghttp2', '1.64.0'],
      ['openssl', '3.4.1'],
      ['simdjson', '3.13.0'],
      ['simdutf', '6.4.2'],
      ['tz', '2025a'],
      ['unicode', '16.0'],
      ['uv', '1.50.0'],
      ['uvwasi', '0.0.21'],
      ['v8', '13.6.233.8-node.26'],
      ['zlib', '1.3.1.1-motley-82a5fec'],
      ['zstd', '1.5.7']
    ];
    for (var __versionIndex = 0; __versionIndex < entries.length; __versionIndex++) {
      Object.defineProperty(versions, entries[__versionIndex][0], {
        value: entries[__versionIndex][1],
        writable: false,
        enumerable: true,
        configurable: true
      });
    }
    return versions;
  }

  function __exactAllowNativesSyntaxEnabled() {
    if (globalThis.__exactAllowNativesSyntax === true) {
      return true;
    }
    if (typeof globalThis.process === 'object' && globalThis.process !== null && Array.isArray(globalThis.process.execArgv)) {
      for (var __execArgvIndex = 0; __execArgvIndex < globalThis.process.execArgv.length; __execArgvIndex++) {
        if (String(globalThis.process.execArgv[__execArgvIndex]) === '--allow-natives-syntax') {
          globalThis.__exactAllowNativesSyntax = true;
          return true;
        }
      }
    }
    return false;
  }

  function __exactMaybeHandleNativesSyntax(source) {
    if (!__exactAllowNativesSyntaxEnabled() || typeof source !== 'string') {
      return { handled: false };
    }
    var trimmed = source.trim();
    var match = /^%([A-Za-z0-9_]+)\(([\s\S]*)\);?$/.exec(trimmed);
    if (!match) {
      return { handled: false };
    }
    var intrinsicName = match[1];
    var argsSource = match[2].trim();
    var args = [];
    if (argsSource.length > 0) {
      args = Function('return [' + argsSource + '];')();
    }
    switch (intrinsicName) {
      case 'PrepareFunctionForOptimization':
      case 'OptimizeFunctionOnNextCall':
      case 'DebugPrint':
        return { handled: true, value: undefined };
      case 'CollectGarbage':
        if (typeof globalThis.gc === 'function') {
          try { globalThis.gc(); } catch (err) {}
        }
        return { handled: true, value: undefined };
      case 'HaveSameMap':
        return { handled: true, value: args.length >= 2 && Object.getPrototypeOf(args[0]) === Object.getPrototypeOf(args[1]) };
      case 'IsSmi':
        return { handled: true, value: typeof args[0] === 'number' && args[0] === (args[0] | 0) };
      case 'GetUndetectable':
        return { handled: true, value: undefined };
      default:
        return { handled: true, value: undefined };
    }
  }

  if (typeof globalThis.eval === 'function' && globalThis.eval.__exactWrappedForNativesSyntax !== true) {
    try {
      var __exactNativeEval = globalThis.eval;
      var __exactCompatEval = function evalCompat(source) {
        var handled = __exactMaybeHandleNativesSyntax(source);
        if (handled.handled) {
          return handled.value;
        }
        return __exactNativeEval.apply(globalThis, arguments);
      };
      __exactCompatEval.__exactWrappedForNativesSyntax = true;
      globalThis.eval = __exactCompatEval;
    } catch (err) {}
  }

  // Ensure process has EventEmitter-style helpers in Node-compat suites.
  // Node fixtures expect `process.on`, `emit`, etc. before any stream API
  // is imported, but stream enhancements are loaded lazily. Eagerly trigger
  // the enhancer here so Node compatibility tests get the standard hooks.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    typeof globalThis.__exactEnsureStreamEnhance === 'function' &&
    (typeof globalThis.process.on !== 'function' ||
      !globalThis.process.config ||
      !globalThis.process.stdin ||
      typeof globalThis.process.stdin.resume !== 'function')
  ) {
    try {
      globalThis.__exactEnsureStreamEnhance();
    } catch (err) {
      // Keep compatibility bootstrap resilient if stream enhancement cannot load.
    }
  }

  // Process streams can still be host-backed accessors in some bootstrap paths.
  // Pin stdout/stderr/stdin on the process object itself so repeated reads
  // return the same stream objects and util's write interception works
  // consistently. Also create a safe prototype shadow for the common copied
  // process object pattern used by Node tests.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    function __exactPatchProcessStreamPrototype() {
      var proto = Object.getPrototypeOf(globalThis.process);
      if (!proto || proto.__exactProcessProtoPatched) {
        return;
      }
      var patchedPrototype = Object.create(proto);
      var needsPrototypePatch = false;

      var keys = ['stdout', 'stderr', 'stdin', 'versions'].concat(Object.keys(globalThis.process));
      for (var i = 0; i < keys.length; i++) {
        var name = keys[i];
        var desc = Object.getOwnPropertyDescriptor(proto, name);
        if (name !== 'versions' && !desc) {
          continue;
        }
        if (
          name !== 'versions' &&
          !desc.get &&
          desc.set === undefined &&
          desc.writable !== false &&
          desc.configurable !== false
        ) {
          continue;
        }
        var stream;
        try {
          stream = globalThis.process[name];
        } catch (err) {
          continue;
        }
        if (stream === undefined) {
          continue;
        }
        try {
          Object.defineProperty(patchedPrototype, name, {
            value: stream,
            writable: true,
            configurable: true,
            enumerable: true
          });
          needsPrototypePatch = true;
        } catch (err) {}
      }

      if (needsPrototypePatch) {
        Object.setPrototypeOf(globalThis.process, patchedPrototype);
        try {
          Object.defineProperty(patchedPrototype, '__exactStreamProtoPatched', {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false
          });
        } catch (err) {}
        try {
          Object.defineProperty(proto, '__exactProcessProtoPatched', {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false
          });
        } catch (err) {}
      }

      try {
        Object.defineProperty(proto, '__exactStreamProtoPatched', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
    }

    function __exactPatchProcessEventEmitterPrototype() {
      var currentProto = Object.getPrototypeOf(globalThis.process);
      if (!currentProto || currentProto.__exactEventEmitterProtoPatched) {
        return;
      }

      var EventsCtor;
      try {
        EventsCtor = require('events');
        EventsCtor = EventsCtor && (EventsCtor.EventEmitter || EventsCtor.default || EventsCtor);
      } catch (err) {
        EventsCtor = null;
      }

      if (typeof EventsCtor !== 'function' || currentProto instanceof EventsCtor) {
        return;
      }

      var patchedProto = Object.create(EventsCtor.prototype);
      var currentDescriptors = Object.getOwnPropertyDescriptors(currentProto);
      delete currentDescriptors.constructor;
      try {
        Object.defineProperties(patchedProto, currentDescriptors);
      } catch (err) {
        var currentKeys = Object.keys(currentDescriptors);
        for (var __descriptorIndex = 0; __descriptorIndex < currentKeys.length; __descriptorIndex++) {
          try {
            Object.defineProperty(patchedProto, currentKeys[__descriptorIndex], currentDescriptors[currentKeys[__descriptorIndex]]);
          } catch (err2) {}
        }
      }

      try {
        Object.defineProperty(patchedProto, 'constructor', {
          value: globalThis.process.constructor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}

      try {
        if (globalThis.process.constructor && globalThis.process.constructor.prototype !== patchedProto) {
          globalThis.process.constructor.prototype = patchedProto;
        }
      } catch (err) {}

      try {
        Object.defineProperty(patchedProto, '__exactEventEmitterProtoPatched', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}

      try {
        Object.setPrototypeOf(globalThis.process, patchedProto);
      } catch (err) {}
    }

    function __exactPinStream(name) {
      var stream = globalThis.process[name];
      if (!stream) return;
      if ((name === 'stdout' || name === 'stderr') && stream.writable === undefined) {
        stream.writable = true;
      }
      Object.defineProperty(globalThis.process, name, {
        value: stream,
        writable: true,
        configurable: true,
        enumerable: true
      });
    }

    function __exactInstallReadableStdinFallback() {
      var stream = globalThis.process.stdin;
      if (!stream || typeof stream !== 'object') return;
      if (typeof stream.destroy !== 'function') {
        stream.destroy = function(err) {
          stream.destroyed = true;
          stream._ended = true;
          stream.readable = false;
          stream.readableEnded = true;
          stream.readableFlowing = false;
          if (stream._pollTimer) {
            clearTimeout(stream._pollTimer);
            stream._pollTimer = 0;
          }
          if (typeof stream.emit === 'function') {
            if (err) stream.emit('error', err);
            stream.emit('close');
          }
          return stream;
        };
      }
      if (typeof stream.resume === 'function') return;
      if (typeof globalThis.__exactStdinRead !== 'function') return;

      stream._encoding = null;
      stream._paused = true;
      stream._ended = false;
      stream._pollTimer = 0;
      stream.readable = true;
      stream.readableEnded = false;
      stream.readableFlowing = null;
      stream.readableLength = 0;
      stream.readableObjectMode = false;

      stream.setEncoding = function(enc) {
        stream._encoding = enc;
        return stream;
      };

      stream.resume = function() {
        stream.readable = true;
        stream._paused = false;
        stream.readableFlowing = true;
        if (!stream._ended && !stream._pollTimer) {
          (function pollStdin() {
            if (stream._paused || stream._ended || stream.destroyed) return;
            var data = globalThis.__exactStdinRead(262144);
            if (data === null) {
              stream._pollTimer = setTimeout(pollStdin, 1);
              return;
            }
            if (data === '') {
              stream._ended = true;
              stream._pollTimer = 0;
              stream.readableEnded = true;
              stream.emit('end');
              stream.emit('close');
              return;
            }
            stream._pollTimer = 0;
            if (stream._encoding && typeof Buffer !== 'undefined' && Buffer.from) {
              data = Buffer.from(data, 'binary').toString(stream._encoding);
            }
            stream.readableLength += data.length || 0;
            stream.emit('data', data);
            stream.readableLength = 0;
            if (!stream._paused && !stream._ended) {
              stream._pollTimer = setTimeout(pollStdin, 0);
            }
          })();
        }
        return stream;
      };

      stream.pause = function() {
        stream._paused = true;
        stream.readableFlowing = false;
        if (stream._pollTimer) {
          clearTimeout(stream._pollTimer);
          stream._pollTimer = 0;
        }
        return stream;
      };

      stream.read = function(size) {
        var data = globalThis.__exactStdinRead(size || 262144);
        if (data === '') return null;
        if (stream._encoding && data && typeof Buffer !== 'undefined' && Buffer.from) {
          return Buffer.from(data, 'binary').toString(stream._encoding);
        }
        return data;
      };

      var originalOn = typeof stream.on === 'function' ? stream.on : null;
      var originalOnce = typeof stream.once === 'function' ? stream.once : null;
      if (originalOn) {
        stream.on = function(event, listener) {
          var result = originalOn.apply(this, arguments);
          if (event === 'data' && !stream._ended && stream._paused) {
            stream.resume();
          }
          return result;
        };
        stream.addListener = stream.on;
      }
      if (originalOnce) {
        stream.once = function(event, listener) {
          var result = originalOnce.apply(this, arguments);
          if (event === 'data' && !stream._ended && stream._paused) {
            stream.resume();
          }
          return result;
        };
      }
      try {
        Object.defineProperty(globalThis.process, 'stdin', {
          value: stream,
          writable: true,
          configurable: true,
          enumerable: true
        });
      } catch (_) {
        globalThis.process.stdin = stream;
      }
    }

    try {
      __exactPatchProcessEventEmitterPrototype();
      __exactPatchProcessStreamPrototype();
      if (!globalThis.process.__exactStreamStabilityPatched) {
        __exactPinStream('stdout');
        __exactPinStream('stderr');
        __exactPinStream('stdin');
        globalThis.process.__exactStreamStabilityPatched = true;
      }
      __exactInstallReadableStdinFallback();
      // Add ref/unref stubs to stdout/stderr/stdin for Node.js compatibility
      var _stdioNames = ['stdout', 'stderr', 'stdin'];
      for (var si = 0; si < _stdioNames.length; si++) {
        var _sio = globalThis.process[_stdioNames[si]];
        if (_sio && typeof _sio === 'object') {
          if (typeof _sio.ref !== 'function') _sio.ref = function() { return this; };
          if (typeof _sio.unref !== 'function') _sio.unref = function() { return this; };
        }
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process stream patching fails.
    }
  }

  // Node/Bun fixtures assume process.config.variables is always available.
  // Normalize it here to avoid runtime crashes when the stream enhancer hasn't
  // run yet or didn't populate this field for some compatibility paths.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      if (globalThis.process.config === undefined || globalThis.process.config === null) {
        globalThis.process.config = { target_defaults: {}, variables: {} };
      } else if (
        typeof globalThis.process.config === 'object' &&
        !globalThis.process.config.variables
      ) {
        globalThis.process.config.variables = {};
      }
      // Freeze process.config to match Node.js behavior (immutable config)
      if (typeof globalThis.process.config === 'object' && globalThis.process.config !== null) {
        try {
          Object.freeze(globalThis.process.config.target_defaults);
          Object.freeze(globalThis.process.config.variables);
          Object.freeze(globalThis.process.config);
        } catch (_) {}
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process/config cannot be patched.
    }
  }

  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      var defaultFeatures = {
        inspector: true,
        debug: false,
        uv: false,
        ipv6: true,
        openssl_is_boringssl: false,
        tls_alpn: false,
        tls_sni: false,
        tls_ocsp: false,
        tls: false,
        cached_builtins: true,
        require_module: false,
        typescript: false,
      };
      if (!globalThis.process.features || typeof globalThis.process.features !== 'object') {
        globalThis.process.features = defaultFeatures;
      } else {
        var dfKeys = Object.keys(defaultFeatures);
        for (var dfi = 0; dfi < dfKeys.length; dfi++) {
          if (globalThis.process.features[dfKeys[dfi]] === undefined) {
            globalThis.process.features[dfKeys[dfi]] = defaultFeatures[dfKeys[dfi]];
          }
        }
      }
    } catch (err) {
      // Keep compatibility bootstrap resilient if process.features cannot be patched.
    }
  }

  function __exactInstallUmaskPolyfill() {
    if (typeof globalThis.process !== 'object' || globalThis.process === null) {
      return;
    }
    var proc = globalThis.process;
    var _nativeUmask = typeof proc.umask === 'function' ? proc.umask : null;
    var _fallbackUmask = 0o022;

    proc.umask = function(mask) {
      if (arguments.length === 0) {
        if (_nativeUmask) return _nativeUmask.call(proc);
        return _fallbackUmask;
      }
      if (typeof mask === 'string') {
        if (!/^[0-7]+$/.test(mask)) {
          var ve = new TypeError("The argument 'mask' is invalid. Received '" + mask + "'");
          ve.code = 'ERR_INVALID_ARG_VALUE';
          throw ve;
        }
        mask = parseInt(mask, 8);
      } else if (typeof mask !== 'number' || (mask !== (mask | 0))) {
        var te = new TypeError('The "mask" argument must be of type number. Received type ' + typeof mask);
        te.code = 'ERR_INVALID_ARG_TYPE';
        throw te;
      }
      mask = mask & 0o7777;
      if (_nativeUmask) {
        return _nativeUmask.call(proc, mask);
      }
      var old = _fallbackUmask;
      _fallbackUmask = mask;
      return old;
    };
  }
  __exactInstallUmaskPolyfill();

  // Wrap process.chdir to produce Node-compatible ENOENT errors with code,
  // syscall, path, and dest properties.  The native C++ chdir throws a plain
  // Error without those fields.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      var __nativeChdir = globalThis.process.chdir;
      var __nativeCwd = globalThis.process.cwd;
      var __cachedCwd = null;
      function __isUsableCwd(value) {
        return typeof value === 'string' && value.length > 0;
      }
      function __readCurrentCwd() {
        var nativeDir;
        try {
          if (typeof __nativeCwd === 'function') {
            nativeDir = __nativeCwd.call(globalThis.process);
          }
        } catch (_) {}
        if (__isUsableCwd(nativeDir) && !(nativeDir === '/' && __cachedCwd && __cachedCwd !== '/')) {
          __cachedCwd = nativeDir;
          return nativeDir;
        }
        try {
          if (typeof __exactGetCwd === 'function') {
            var bridgedDir = __exactGetCwd();
            if (__isUsableCwd(bridgedDir)) {
              __cachedCwd = bridgedDir;
              return bridgedDir;
            }
          }
        } catch (_) {}
        if (__cachedCwd) {
          return __cachedCwd;
        }
        return __isUsableCwd(nativeDir) ? nativeDir : '/';
      }
      function __resolveChdirTarget(directory) {
        if (typeof directory !== 'string' || directory.length === 0) {
          return __readCurrentCwd();
        }
        if (directory.charAt(0) === '/' || /^[A-Za-z]:[\\/]/.test(directory)) {
          return directory;
        }
        var currentDir = __readCurrentCwd();
        if (!currentDir || currentDir === '/') {
          return '/' + directory;
        }
        if (currentDir.charAt(currentDir.length - 1) === '/') {
          return currentDir + directory;
        }
        return currentDir + '/' + directory;
      }
      __cachedCwd = __readCurrentCwd();
      globalThis.process.cwd = function cwd() {
        return __readCurrentCwd();
      };
      globalThis.process.chdir = function chdir(directory) {
        if (typeof directory !== 'string') {
          var te = new TypeError('The "directory" argument must be of type string. Received type ' + typeof directory);
          te.code = 'ERR_INVALID_ARG_TYPE';
          throw te;
        }
        var resolvedDirectory = __resolveChdirTarget(directory);
        try {
          if (typeof __exactSetCwd === 'function') {
            __exactSetCwd(resolvedDirectory);
            __cachedCwd = resolvedDirectory;
            return;
          }
          var currentChdir = globalThis.process && globalThis.process.chdir;
          if (typeof currentChdir === 'function' && currentChdir !== chdir && currentChdir !== __nativeChdir) {
            currentChdir.call(globalThis.process, resolvedDirectory);
            __cachedCwd = resolvedDirectory;
            return;
          }
          if (typeof __nativeChdir === 'function') {
            __nativeChdir.call(globalThis.process, resolvedDirectory);
            __cachedCwd = resolvedDirectory;
            return;
          }
        } catch (e) {
          var currentDir = __readCurrentCwd();
          var syserr = new Error("ENOENT: no such file or directory, chdir '" + currentDir + "' -> '" + directory + "'");
          syserr.code = 'ENOENT';
          syserr.syscall = 'chdir';
          syserr.path = currentDir;
          syserr.dest = directory;
          throw syserr;
        }
      };
    } catch (err) {
      // Keep bootstrap resilient
    }
  }

  // Wrap process.nextTick to validate callback argument
  if (typeof globalThis.process === 'object' && globalThis.process !== null &&
      typeof globalThis.process.nextTick === 'function') {
    try {
      var __nativeNextTick = globalThis.process.nextTick;
      globalThis.process.nextTick = function nextTick(callback) {
        if (typeof callback !== 'function') {
          var te = new TypeError('The "callback" argument must be of type function. Received type ' + typeof callback);
          te.code = 'ERR_INVALID_ARG_TYPE';
          throw te;
        }
        var args = [];
        for (var __nti = 1; __nti < arguments.length; __nti++) args.push(arguments[__nti]);
        if (args.length === 0) return __nativeNextTick.call(globalThis.process, callback);
        return __nativeNextTick.call(globalThis.process, function() { callback.apply(null, args); });
      };
    } catch (err) {}
  }

  // Wrap process.hrtime to validate argument as Array
  if (typeof globalThis.process === 'object' && globalThis.process !== null &&
      typeof globalThis.process.hrtime === 'function') {
    try {
      var __nativeHrtime = globalThis.process.hrtime;
      globalThis.process.hrtime = function hrtime(time) {
        if (time !== undefined && !Array.isArray(time)) {
          var te = new TypeError('The "time" argument must be an instance of Array. Received type ' + typeof time + ' (' + String(time) + ')');
          te.code = 'ERR_INVALID_ARG_TYPE';
          throw te;
        }
        return __nativeHrtime.call(globalThis.process, time);
      };
      if (__nativeHrtime.bigint) {
        globalThis.process.hrtime.bigint = __nativeHrtime.bigint;
      }
    } catch (err) {}
  }

  if (typeof globalThis.URL === 'function') {
    try {
      var __exactObjectURLCounter = 0;
      var __exactObjectURLRegistry = Object.create(null);
      var __nativeCreateObjectURL =
        typeof globalThis.URL.createObjectURL === 'function' ? globalThis.URL.createObjectURL : null;
      var __nativeRevokeObjectURL =
        typeof globalThis.URL.revokeObjectURL === 'function' ? globalThis.URL.revokeObjectURL : null;

      globalThis.URL.createObjectURL = function createObjectURL(object) {
        if (arguments.length === 0) {
          var createErr = new TypeError('The "object" argument must be specified');
          createErr.code = 'ERR_MISSING_ARGS';
          throw createErr;
        }
        if (__nativeCreateObjectURL) {
          return __nativeCreateObjectURL.call(this, object);
        }
        var objectURL = 'blob:exact:' + (++__exactObjectURLCounter);
        __exactObjectURLRegistry[objectURL] = object;
        return objectURL;
      };

      globalThis.URL.revokeObjectURL = function revokeObjectURL(url) {
        if (arguments.length === 0) {
          var revokeErr = new TypeError('The "url" argument must be specified');
          revokeErr.code = 'ERR_MISSING_ARGS';
          throw revokeErr;
        }
        if (__nativeRevokeObjectURL) {
          return __nativeRevokeObjectURL.call(this, url);
        }
        delete __exactObjectURLRegistry[String(url)];
      };
    } catch (err) {}
  }

  // Install process.execve polyfill early so it is available on the global
  // process object without requiring the 'process' module first.
  if (typeof globalThis.process === 'object' && globalThis.process !== null &&
      typeof globalThis.process.execve !== 'function') {
    try {
      globalThis.process.execve = function execve(execPath, args, envObj) {
        __exactValidateExecveArguments(execPath, args, envObj, arguments.length >= 3);

        if (__exactPermissionDeniesChildProcess(globalThis.process.execArgv)) {
          var permissionError = new Error('Access to this API has been restricted');
          permissionError.code = 'ERR_ACCESS_DENIED';
          permissionError.permission = 'ChildProcess';
          permissionError.resource = execPath;
          throw permissionError;
        }

        var childProcess = require('child_process');
        if (!childProcess || typeof childProcess.spawnSync !== 'function') {
          var unavailableError = new TypeError('process.execve is not supported in this runtime');
          unavailableError.code = 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM';
          throw unavailableError;
        }

        var result = childProcess.spawnSync(execPath, args.slice(1), {
          env: arguments.length >= 3 ? envObj : globalThis.process.env,
          stdio: 'inherit'
        });
        if (result && result.error) {
          throw result.error;
        }
        if (typeof globalThis.process.exit === 'function') {
          globalThis.process.exit(result && typeof result.status === 'number' ? result.status : 0);
        }
      };
    } catch (err) {}
  }

  // Node-oriented packages expect `process.versions.node` to exist.
  // In some Hermes runtimes process.versions is a host-managed accessor object
  // that may not include the Node key even though the process object is writable.
  // Normalize it here so later checks and Node compatibility tests can rely on it.
  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      function __exactApplyVersionsPatch(target, patchedVersions) {
        if (!target || typeof target !== 'object') return false;
        try {
          var desc = Object.getOwnPropertyDescriptor(target, 'versions');
          if (!desc) {
            try {
              Object.defineProperty(target, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: false
              });
              return true;
            } catch (err) {}
            try {
              target.versions = patchedVersions;
              return true;
            } catch (err) {}
            return false;
          }
          if (typeof desc.get === 'function' && desc.set === undefined) {
            try {
              Object.defineProperty(target, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: !!desc.enumerable
              });
              return true;
            } catch (err) {}
            try {
              target.versions = patchedVersions;
              return true;
            } catch (err) {}
            return false;
          }
          try {
            Object.defineProperty(target, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: !!desc.configurable,
              enumerable: !!desc.enumerable
            });
            return true;
          } catch (err) {}
          try {
            target.versions = patchedVersions;
            return true;
          } catch (err) {}
        } catch (err) {}
        return false;
      }

      var patchedVersions = __exactCreateProcessVersions();
      try {
        __exactApplyVersionsPatch(globalThis.process, patchedVersions);
      } catch (err) {}

      try {
        var processVersionPrototype = Object.getPrototypeOf(globalThis.process);
        while (
          processVersionPrototype &&
          processVersionPrototype !== Object.prototype &&
          typeof processVersionPrototype === 'object'
        ) {
          if (__exactApplyVersionsPatch(processVersionPrototype, patchedVersions)) {
            break;
          }
          processVersionPrototype = Object.getPrototypeOf(processVersionPrototype);
        }
      } catch (err) {}

      try {
        var versionsOwner = Object.getPrototypeOf(globalThis.process);
        var versionsDescriptor = versionsOwner &&
          Object.getOwnPropertyDescriptor(versionsOwner, 'versions');
        if (
          !versionsDescriptor ||
          typeof versionsDescriptor.get === 'function' ||
          versionsDescriptor.set === undefined ||
          !('value' in versionsDescriptor) ||
          versionsDescriptor.writable !== true
        ) {
          try {
            Object.defineProperty(versionsOwner, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: false
            });
          } catch (err) {
            try {
              var patchedVersionsPrototype = Object.create(versionsOwner);
              Object.defineProperty(patchedVersionsPrototype, 'versions', {
                value: patchedVersions,
                writable: true,
                configurable: true,
                enumerable: false
              });
              Object.setPrototypeOf(globalThis.process, patchedVersionsPrototype);
            } catch (err2) {}
          }
        }
      } catch (err) {}

      try {
        var processVersionsDescriptor = Object.getOwnPropertyDescriptor(
          globalThis.process,
          'versions'
        );
        if (
          !processVersionsDescriptor ||
          typeof processVersionsDescriptor.get === 'function' ||
          !('value' in processVersionsDescriptor) ||
          processVersionsDescriptor.writable !== true ||
          processVersionsDescriptor.enumerable
        ) {
          try {
            Object.defineProperty(globalThis.process, 'versions', {
              value: patchedVersions,
              writable: true,
              configurable: true,
              enumerable: false
            });
          } catch (err) {}
        }
      } catch (err) {}

      if (patchedVersions.node) {
        globalThis.process.version = 'v' + String(patchedVersions.node).replace(/^v/, '');
      }
      // Node compat: set process.release.name to 'node' for compatibility
      // process is a HostObject, so we need Object.defineProperty to override
      try {
        var existingRelease = globalThis.process.release;
        var releaseObj = (existingRelease && typeof existingRelease === 'object') ?
          Object.assign({}, existingRelease, { name: 'node' }) : { name: 'node' };
        // Determine LTS codename based on reported Node version
        var __nodeVer = patchedVersions.node || '';
        var __verParts = String(__nodeVer).split('.');
        var __major = parseInt(__verParts[0], 10);
        var __minor = parseInt(__verParts[1], 10);
        var __ltsMap = [
          [4, 2, 'Argon'], [6, 9, 'Boron'], [8, 9, 'Carbon'],
          [10, 13, 'Dubnium'], [12, 13, 'Erbium'], [14, 15, 'Fermium'],
          [16, 13, 'Gallium'], [18, 12, 'Hydrogen'], [20, 9, 'Iron'],
          [22, 11, 'Jod'], [24, 11, 'Krypton'],
        ];
        for (var __li = 0; __li < __ltsMap.length; __li++) {
          if (__major === __ltsMap[__li][0] && __minor >= __ltsMap[__li][1]) {
            releaseObj.lts = __ltsMap[__li][2];
            break;
          }
        }
        Object.defineProperty(globalThis.process, 'release', {
          value: releaseObj, writable: true, configurable: true, enumerable: true
        });
      } catch (e) {}
    } catch (err) {
      // Keep bootstrap resilient if process version patching fails.
    }
  }

  function __exactNeedsUrlCompatPatch() {
    if (typeof globalThis.URL !== 'function') {
      return false;
    }
    if (typeof globalThis.URLSearchParams !== 'function') {
      return false;
    }

    try {
      var base = new globalThis.URL('http://test@example.net');
      if (base.pathname !== '/') {
        return true;
      }

      var hostOnly = new globalThis.URL('https://username:password@host:8000/path');
      hostOnly.host = '\t' + 'test';
      if (hostOnly.host !== 'test:8000') {
        return true;
      }

      var invalidProtocol = new globalThis.URL('http://test@example.net');
      invalidProtocol.protocol = 'file';
      if (invalidProtocol.href !== 'http://test@example.net/') {
        return true;
      }
      return false;
    } catch (e) {
      return true;
    }
  }

  function __exactNeedsHexDigit(char) {
    return (
      char && char.length === 1 &&
      ((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F') || (char >= 'a' && char <= 'f'))
    );
  }

  function __exactNeedsUserinfoPatch() {
    if (typeof globalThis.URL !== 'function') {
      return false;
    }
    var url = new URL('http://example.net');
    var usernameValue = '\u0000\u0001\t\n\r\u001F !\"#$%&\'()*+,-./09:;<=>?@AZ[\\\\]^_`az{|}~\u007F\u0080\u0081Éé';
    var expectedUsername = '%00%01%09%0A%0D%1F%20!%22%23$%&\'()*+,-.%2F09%3A%3B%3C%3D%3E%3F%40AZ%5B%5C%5D%5E_%60az%7B%7C%7D~%7F%C2%80%C2%81%C3%89%C3%A9';
    url.username = usernameValue;
    return url.username !== expectedUsername;
  }

  function __exactHasExplicitPort(value) {
    value = String(value);
    if (value.charAt(0) === '[') {
      var close = value.indexOf(']');
      return close !== -1 && value.indexOf(':', close + 1) !== -1;
    }
    return value.indexOf(':') !== -1;
  }

  function __exactNeedsRootPath(urlObj) {
    if (!urlObj || typeof urlObj.protocol !== 'string') {
      return false;
    }
    var protocol = urlObj.protocol;
    return protocol === 'http:' || protocol === 'https:' || protocol === 'ftp:' ||
      protocol === 'file:' || protocol === 'ws:' || protocol === 'wss:';
  }

  var __exactPatchedUrlStatics = false;
  function __exactPatchUrlStatics() {
    if (typeof globalThis.URL !== 'function' || typeof globalThis.__exactRequire !== 'function') {
      return;
    }
    try {
      var urlMod = globalThis.__exactRequire('url');
      if (!urlMod || typeof urlMod.URL !== 'function') {
        return;
      }
      if (typeof globalThis.URL === 'function' && globalThis.URL !== urlMod.URL) {
        try {
          Object.defineProperty(globalThis, 'URL', {
            value: urlMod.URL,
            writable: true,
            configurable: true,
            enumerable: true
          });
        } catch (_setUrlErr) {
          globalThis.URL = urlMod.URL;
        }
      }
      if (urlMod.URLSearchParams && globalThis.URLSearchParams !== urlMod.URLSearchParams) {
        try {
          Object.defineProperty(globalThis, 'URLSearchParams', {
            value: urlMod.URLSearchParams,
            writable: true,
            configurable: true,
            enumerable: true
          });
        } catch (_setUrlSearchParamsErr) {
          globalThis.URLSearchParams = urlMod.URLSearchParams;
        }
      }
      __exactPatchedUrlStatics =
        globalThis.URL === urlMod.URL &&
        (!urlMod.URLSearchParams || globalThis.URLSearchParams === urlMod.URLSearchParams);
    } catch (err) {}
  }

  function __exactPatchUrlConstructors() {
    if (typeof globalThis.URL !== 'function' || typeof globalThis.URL.prototype !== 'object') {
      return;
    }

    var urlProto = globalThis.URL.prototype;

    var pathnameDesc = Object.getOwnPropertyDescriptor(urlProto, 'pathname');
    if (pathnameDesc && pathnameDesc.get && !pathnameDesc.get.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'pathname', {
        configurable: true,
        get: function() {
          var value = pathnameDesc.get.call(this);
          if (value === '' && __exactNeedsRootPath(this) && this.host) {
            return '/';
          }
          return value;
        },
        set: pathnameDesc.set
      });
      pathnameDesc.get.__exactCompatPatched = true;
    }

    var protocolDesc = Object.getOwnPropertyDescriptor(urlProto, 'protocol');
    if (protocolDesc && protocolDesc.set && !protocolDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'protocol', {
        configurable: true,
        get: protocolDesc.get,
        set: function(value) {
          var before = String(this.href || '');
          protocolDesc.set.call(this, value);
          if (this.pathname === '' && __exactNeedsRootPath(this) && this.host && String(this.href) === before) {
            this.pathname = '/';
          }
        }
      });
      protocolDesc.set.__exactCompatPatched = true;
    }

    var hostDesc = Object.getOwnPropertyDescriptor(urlProto, 'host');
    if (hostDesc && hostDesc.set && !hostDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'host', {
        configurable: true,
        get: hostDesc.get,
        set: function(value) {
          var raw = String(value);
          if (raw !== '' && this.port && !__exactHasExplicitPort(raw)) {
            hostDesc.set.call(this, raw + ':' + this.port);
            return;
          }
          hostDesc.set.call(this, raw);
        }
      });
      hostDesc.set.__exactCompatPatched = true;
    }

    function __exactIsUserinfoUnescaped(value) {
      var code = value.charCodeAt(0);
      if (code >= 0x30 && code <= 0x39) return true;
      if (code >= 0x41 && code <= 0x5A) return true;
      if (code >= 0x61 && code <= 0x7A) return true;
      if (
        code === 0x21 || code === 0x24 || code === 0x26 || code === 0x27 || code === 0x28 ||
        code === 0x29 || code === 0x2A || code === 0x2B || code === 0x2C || code === 0x2D ||
        code === 0x2E || code === 0x5F || code === 0x7E || code === 0x25
      ) {
        return true;
      }
      return false;
    }

    function __exactSanitizeUserinfo(value) {
      var out = '';
      for (var i = 0; i < value.length; i++) {
        var c = value.charAt(i);
        if (
          c === '%' &&
          __exactNeedsHexDigit(value.charAt(i + 1)) &&
          __exactNeedsHexDigit(value.charAt(i + 2))
        ) {
          out += value.slice(i, i + 3);
          i += 2;
          continue;
        }
        if (__exactIsUserinfoUnescaped(c)) {
          out += c;
        } else {
          out += encodeURIComponent(c);
        }
      }
      return out;
    }

    var usernameDesc = Object.getOwnPropertyDescriptor(urlProto, 'username');
    if (usernameDesc && usernameDesc.set && !usernameDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'username', {
        configurable: true,
        get: usernameDesc.get,
        set: function(value) {
          return usernameDesc.set.call(this, __exactSanitizeUserinfo(String(value)));
        }
      });
      usernameDesc.set.__exactCompatPatched = true;
    }

    var passwordDesc = Object.getOwnPropertyDescriptor(urlProto, 'password');
    if (passwordDesc && passwordDesc.set && !passwordDesc.set.__exactCompatPatched) {
      Object.defineProperty(urlProto, 'password', {
        configurable: true,
        get: passwordDesc.get,
        set: function(value) {
          return passwordDesc.set.call(this, __exactSanitizeUserinfo(String(value)));
        }
      });
      passwordDesc.set.__exactCompatPatched = true;
    }
  }

  function __exactDecodeUrlEncodedFormBody(bodyText) {
    var decoder;
    if (typeof TextDecoder === 'undefined') {
      return String(bodyText);
    }
    try {
      decoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false });
    } catch (err) {
      decoder = new TextDecoder('utf-8');
    }
    return decoder.decode(bodyText);
  }

  // Add Response.json() static method per the Fetch spec.
  // Response.json(data, init?) creates a Response with JSON-serialized body
  // and appropriate Content-Type header.
  function __exactPatchResponseJson() {
    if (typeof globalThis.Response !== 'function') return;
    if (typeof globalThis.Response.json === 'function') return;

    globalThis.Response.json = function(data, init) {
      var body = JSON.stringify(data);
      if (body === undefined) {
        throw new TypeError('The data is not JSON serializable');
      }
      var responseInit = {};
      if (init && typeof init === 'object') {
        if (init.status !== undefined) responseInit.status = init.status;
        if (init.statusText !== undefined) responseInit.statusText = init.statusText;
        if (init.headers !== undefined) responseInit.headers = init.headers;
      }
      var response = new globalThis.Response(body, responseInit);
      // Set Content-Type to application/json if not already set by init.headers
      var hasContentType = false;
      if (init && init.headers) {
        if (init.headers instanceof globalThis.Headers) {
          hasContentType = init.headers.has('content-type');
        } else if (Array.isArray(init.headers)) {
          for (var hi = 0; hi < init.headers.length; hi++) {
            if (String(init.headers[hi][0]).toLowerCase() === 'content-type') {
              hasContentType = true;
              break;
            }
          }
        } else if (typeof init.headers === 'object') {
          var headerKeys = Object.keys(init.headers);
          for (var hk = 0; hk < headerKeys.length; hk++) {
            if (headerKeys[hk].toLowerCase() === 'content-type') {
              hasContentType = true;
              break;
            }
          }
        }
      }
      if (!hasContentType) {
        try { response.headers.set('content-type', 'application/json'); } catch (e) {}
      }
      return response;
    };
  }
  __exactPatchResponseJson();

  function __exactPatchUrlEncodedFormData() {
    if (typeof globalThis.Request !== 'function' || typeof globalThis.Response !== 'function') {
      return;
    }
    if (typeof globalThis.FormData !== 'function' || typeof URLSearchParams === 'undefined') {
      return;
    }
    if (typeof globalThis.FormData.prototype.append !== 'function') {
      return;
    }

    function __exactFindOriginalFormData(proto, current) {
      var cursor = proto;
      while (cursor) {
        var candidate = cursor.formData;
        if (typeof candidate === 'function' && candidate !== current) {
          return candidate;
        }
        cursor = Object.getPrototypeOf(cursor);
      }
      return null;
    }

    var requestProto = globalThis.Request && globalThis.Request.prototype;
    if (requestProto && !(requestProto.formData && requestProto.formData.__exactCompatPatched)) {
      var requestFormData = requestProto.formData;
      requestProto.formData = async function() {
        var contentType = this.headers && typeof this.headers.get === 'function'
          ? this.headers.get('content-type')
          : '';
        var ct = typeof contentType === 'string' ? contentType.toLowerCase() : '';
        // Only intercept for urlencoded content — delegate everything else
        // (multipart, invalid, missing) to the native formData() so that stream
        // errors, content-type validation, and bodyUsed semantics stay correct.
        if (ct.indexOf('application/x-www-form-urlencoded') !== 0) {
          var originalRequestFormData = typeof requestFormData === 'function'
            ? requestFormData
            : __exactFindOriginalFormData(Object.getPrototypeOf(requestProto), requestProto.formData);
          if (typeof originalRequestFormData === 'function') {
            return await originalRequestFormData.call(this);
          }
          throw new TypeError("Failed to execute 'formData': Content-Type is not 'multipart/form-data' or 'application/x-www-form-urlencoded'");
        }
        var bodyBuffer = await this.arrayBuffer();
        var bodyText = __exactDecodeUrlEncodedFormBody(new Uint8Array(bodyBuffer));
        var parsed = new URLSearchParams(bodyText);
        var formData = new FormData();
        if (typeof parsed.forEach === 'function') {
          parsed.forEach(function(value, key) {
            formData.append(key, value);
          });
        }
        return formData;
      };
      requestProto.formData.__exactCompatPatched = true;
    }

    var responseProto = globalThis.Response && globalThis.Response.prototype;
    if (responseProto && !(responseProto.formData && responseProto.formData.__exactCompatPatched)) {
      var responseFormData = responseProto.formData;
      responseProto.formData = async function() {
        var contentType = this.headers && typeof this.headers.get === 'function'
          ? this.headers.get('content-type')
          : '';
        var ct = typeof contentType === 'string' ? contentType.toLowerCase() : '';
        // Only intercept for urlencoded content — delegate everything else
        // (multipart, invalid, missing) to the native formData() so that stream
        // errors, content-type validation, and bodyUsed semantics stay correct.
        if (ct.indexOf('application/x-www-form-urlencoded') !== 0) {
          var originalResponseFormData = typeof responseFormData === 'function'
            ? responseFormData
            : __exactFindOriginalFormData(Object.getPrototypeOf(responseProto), responseProto.formData);
          if (typeof originalResponseFormData === 'function') {
            return await originalResponseFormData.call(this);
          }
          throw new TypeError("Failed to execute 'formData': Content-Type is not 'multipart/form-data' or 'application/x-www-form-urlencoded'");
        }
        var bodyBuffer = await this.arrayBuffer();
        var bodyText = __exactDecodeUrlEncodedFormBody(new Uint8Array(bodyBuffer));
        var parsed = new URLSearchParams(bodyText);
        var formData = new FormData();
        if (typeof parsed.forEach === 'function') {
          parsed.forEach(function(value, key) {
            formData.append(key, value);
          });
        }
        return formData;
      };
      responseProto.formData.__exactCompatPatched = true;
    }
  }

  function __exactNormalizeHeaderInit(headers) {
    if (!headers) {
      return null;
    }
    var pairs = [];
    if (typeof headers.forEach === 'function') {
      headers.forEach(function(value, key) {
        pairs.push([key, value]);
      });
      return pairs;
    }
    if (Array.isArray(headers)) {
      for (var i = 0; i < headers.length; i++) {
        var pair = headers[i];
        if (pair && pair.length >= 2) {
          pairs.push([pair[0], pair[1]]);
        }
      }
      return pairs;
    }
    if (typeof headers === 'object') {
      var keys = Object.keys(headers);
      for (var j = 0; j < keys.length; j++) {
        pairs.push([keys[j], headers[keys[j]]]);
      }
      return pairs;
    }
    return null;
  }

  function __exactPatchFetchHeaderInit() {
    if (typeof globalThis.Headers !== 'function') {
      return;
    }

    function patchCtor(name) {
      var NativeCtor = globalThis[name];
      if (typeof NativeCtor !== 'function' || NativeCtor.__exactHeaderInitPatched) {
        return;
      }

      function WrappedCtor(input, init) {
        if (!(this instanceof WrappedCtor)) {
          return new WrappedCtor(input, init);
        }

        var headerPairs = null;
        var normalizedInit = init;
        if (init && typeof init === 'object' && Object.prototype.hasOwnProperty.call(init, 'headers')) {
          headerPairs = __exactNormalizeHeaderInit(init.headers);
          normalizedInit = {};
          var initKeys = Object.keys(init);
          for (var i = 0; i < initKeys.length; i++) {
            var key = initKeys[i];
            if (key === 'headers') {
              continue;
            }
            normalizedInit[key] = init[key];
          }
        }

        var instance;
        if (arguments.length === 0) {
          instance = new NativeCtor();
        } else if (arguments.length === 1) {
          instance = new NativeCtor(input);
        } else {
          instance = new NativeCtor(input, normalizedInit);
        }

        if (headerPairs && instance && instance.headers && typeof instance.headers.set === 'function') {
          for (var j = 0; j < headerPairs.length; j++) {
            instance.headers.set(headerPairs[j][0], headerPairs[j][1]);
          }
        }
        return instance;
      }

      var propNames = Object.getOwnPropertyNames(NativeCtor);
      for (var i = 0; i < propNames.length; i++) {
        var propName = propNames[i];
        if (propName === 'prototype' || propName === 'length' || propName === 'name') {
          continue;
        }
        try {
          Object.defineProperty(WrappedCtor, propName, Object.getOwnPropertyDescriptor(NativeCtor, propName));
        } catch (err) {}
      }
      WrappedCtor.prototype = NativeCtor.prototype;
      try {
        Object.defineProperty(WrappedCtor.prototype, 'constructor', {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      try {
        Object.defineProperty(WrappedCtor, '__exactHeaderInitPatched', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      globalThis[name] = WrappedCtor;
    }

    patchCtor('Request');
    patchCtor('Response');
  }

  function __exactReapplyCompatPolyfills() {
    __exactPatchFetchConstructors();
    __exactPatchUrlStatics();
    if (__exactNeedsUrlCompatPatch() || __exactNeedsUserinfoPatch()) {
      __exactPatchUrlConstructors();
    }
    __exactPatchUrlEncodedFormData();
    __exactPatchFetchHeaderInit();
    if (
      typeof globalThis.__exactRequire === 'function' &&
      globalThis.Bun &&
      typeof globalThis.Bun === 'object' &&
      typeof globalThis.Bun.serve === 'function'
    ) {
      try {
        var exactRequireCache = globalThis.__exactRequire.cache;
        if (exactRequireCache && exactRequireCache.bun) {
          delete exactRequireCache.bun;
        }
        globalThis.__exactRequire('bun');
      } catch (err) {}
    }
    __exactInstallBunCompatValues();
  }

  function __exactInstallBunCompatValues() {
    function defineCompatValue(target, name, value) {
      if (!target || typeof target !== 'object') return;
      try {
        Object.defineProperty(target, name, {
          value: value,
          configurable: true,
          enumerable: true,
          writable: true,
        });
      } catch (err) {}
    }

    function ensureCompatFs() {
      if (typeof globalThis.__exactEnsureFs === 'function') {
        try { globalThis.__exactEnsureFs(); } catch (err) {}
      }
    }

    function decodeCompatBytes(bytes) {
      if (typeof TextDecoder === 'function') {
        return new TextDecoder('utf-8').decode(bytes);
      }
      var out = '';
      for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
      return out;
    }

    function toCompatBytes(data) {
      if (data instanceof Uint8Array) return data;
      if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) {
        return new Uint8Array(data);
      }
      if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || data.length);
      }
      if (typeof TextEncoder === 'function') {
        return new TextEncoder().encode(String(data));
      }
      var text = String(data);
      var bytes = new Uint8Array(text.length);
      for (var i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
      return bytes;
    }

    function normalizeCompatFilePath(path) {
      if (path && typeof path === 'object') {
        if (typeof path.protocol === 'string' && path.protocol === 'file:' && typeof path.pathname === 'string') {
          return decodeURIComponent(path.pathname);
        }
        if (typeof path.href === 'string' && path.href.indexOf('file:') === 0) {
          if (typeof path.pathname === 'string') {
            return decodeURIComponent(path.pathname);
          }
          return decodeURIComponent(path.href.replace(/^file:\/\//, ''));
        }
      }
      return String(path);
    }

    function compatMimeType(path) {
      var lower = String(path).toLowerCase();
      if (/\.html?$/.test(lower)) return 'text/html;charset=utf-8';
      if (/\.css$/.test(lower)) return 'text/css;charset=utf-8';
      if (/\.m?js$/.test(lower)) return 'text/javascript;charset=utf-8';
      if (/\.json$/.test(lower)) return 'application/json;charset=utf-8';
      if (/\.svg$/.test(lower)) return 'image/svg+xml;charset=utf-8';
      if (/\.txt$/.test(lower)) return 'text/plain;charset=utf-8';
      return 'application/octet-stream';
    }

    function createCompatFile(path, opts) {
      var name = normalizeCompatFilePath(path);
      var file = {
        name: name,
        type: (opts && opts.type) || compatMimeType(name),
        text: function() {
          ensureCompatFs();
          return Promise.resolve().then(function() {
            return decodeCompatBytes(globalThis.__exactReadFile(name));
          });
        },
        json: function() {
          return this.text().then(function(text) { return JSON.parse(text); });
        },
        arrayBuffer: function() {
          ensureCompatFs();
          return Promise.resolve().then(function() {
            var bytes = globalThis.__exactReadFile(name);
            return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
          });
        },
        bytes: function() {
          ensureCompatFs();
          return Promise.resolve().then(function() {
            return globalThis.__exactReadFile(name);
          });
        },
        exists: function() {
          ensureCompatFs();
          return Promise.resolve().then(function() {
            try {
              globalThis.__exactAccess(name, 0);
              return true;
            } catch (err) {
              return false;
            }
          });
        },
        stat: function() {
          ensureCompatFs();
          return Promise.resolve().then(function() {
            try {
              return JSON.parse(globalThis.__exactStat(name));
            } catch (err) {
              return null;
            }
          });
        },
        writer: function() {
          var started = false;
          return {
            write: function(data) {
              ensureCompatFs();
              var bytes = toCompatBytes(data);
              if (!started) {
                globalThis.__exactWriteFile(name, bytes);
                started = true;
              } else if (typeof globalThis.__exactAppendFile === 'function') {
                globalThis.__exactAppendFile(name, bytes);
              }
              return bytes.length;
            },
            end: function() {},
            flush: function() {},
          };
        },
        toString: function() {
          return 'ExactFile("' + name + '")';
        },
      };

      try {
        Object.defineProperty(file, 'size', {
          get: function() {
            ensureCompatFs();
            try { return JSON.parse(globalThis.__exactStat(name)).size; } catch (err) { return 0; }
          },
          configurable: true,
          enumerable: true,
        });
        Object.defineProperty(file, 'lastModified', {
          get: function() {
            ensureCompatFs();
            try { return JSON.parse(globalThis.__exactStat(name)).mtime_ms; } catch (err) { return 0; }
          },
          configurable: true,
          enumerable: true,
        });
      } catch (err) {}

      return file;
    }

    function compatWrite(dest, data) {
      var path = typeof dest === 'string' ? dest : dest && dest.name;
      ensureCompatFs();
      var bytes = toCompatBytes(data);
      return Promise.resolve().then(function() {
        globalThis.__exactWriteFile(path, bytes);
        return bytes.length;
      });
    }

    function compatInspect(obj, opts) {
      var seen = new WeakSet();
      var depth = (opts && opts.depth) || 4;
      var maxBytes = 50;
      function inspectValue(value, level) {
        if (level > depth) return '[...]';
        if (value === null) return 'null';
        if (value === undefined) return 'undefined';
        var type = typeof value;
        if (type === 'string') return JSON.stringify(value);
        if (type === 'number' || type === 'boolean') return String(value);
        if (type === 'function') return '[Function: ' + (value.name || 'anonymous') + ']';
        if (type === 'symbol') return value.toString();
        if (type !== 'object') return String(value);
        if (seen.has(value)) return '[Circular]';
        seen.add(value);
        // Buffer / TypedArray
        if (ArrayBuffer.isView(value) && !(value instanceof DataView)) {
          var isBuffer = (value.constructor && value.constructor.name === 'Buffer') || (typeof Symbol !== 'undefined' && value[Symbol.toStringTag] === 'Buffer');
          if (isBuffer) {
            var hex = [];
            var limit = Math.min(value.length, maxBytes);
            for (var i = 0; i < limit; i++) hex.push(('0' + value[i].toString(16)).slice(-2));
            var tail = value.length > maxBytes ? ' ... ' + (value.length - maxBytes) + ' more bytes' : '';
            return '<Buffer ' + hex.join(' ') + tail + '>';
          }
          var typeName = (value.constructor && value.constructor.name) || 'TypedArray';
          var items = [];
          var arrLimit = Math.min(value.length, 100);
          for (var j = 0; j < arrLimit; j++) items.push(String(value[j]));
          var arrTail = value.length > 100 ? ', ... ' + (value.length - 100) + ' more items' : '';
          return typeName + '(' + value.length + ') [ ' + items.join(', ') + arrTail + ' ]';
        }
        if (Array.isArray(value)) {
          return value.length ? '[ ' + value.map(function(item) { return inspectValue(item, level + 1); }).join(', ') + ' ]' : '[]';
        }
        var keys = Object.keys(value);
        return keys.length ? '{ ' + keys.map(function(key) { return key + ': ' + inspectValue(value[key], level + 1); }).join(', ') + ' }' : '{}';
      }
      return inspectValue(obj, 0);
    }

    defineCompatValue(globalThis.Exact, 'file', createCompatFile);
    defineCompatValue(globalThis.Exact, 'write', compatWrite);
    defineCompatValue(globalThis.Exact, 'inspect', compatInspect);
    defineCompatValue(globalThis.Bun, 'file', createCompatFile);
    defineCompatValue(globalThis.Bun, 'write', compatWrite);
    defineCompatValue(globalThis.Bun, 'inspect', compatInspect);
  }

  globalThis.__exactReapplyCompatPolyfills = __exactReapplyCompatPolyfills;
  __exactReapplyCompatPolyfills();

  if (typeof globalThis.process === 'object' && globalThis.process !== null) {
    try {
      function __exactDefineExecPath(target, value) {
        if (!target || typeof target !== 'object') {
          return false;
        }
        try {
          var desc = Object.getOwnPropertyDescriptor(target, 'execPath');
          if (!desc || !('value' in desc) || desc.writable !== true) {
            Object.defineProperty(target, 'execPath', {
              value: value,
              writable: true,
              configurable: true,
              enumerable: true
            });
            return true;
          }
        } catch (err) {}
        try {
          target.execPath = value;
          return true;
        } catch (err) {}
        return false;
      }

      var __exactExecPathValue = globalThis.process.execPath;
      if (__exactExecPathValue === undefined) {
        __exactExecPathValue = '';
      }
      __exactDefineExecPath(globalThis.process, __exactExecPathValue);
      var __exactProcessProto = Object.getPrototypeOf(globalThis.process);
      if (
        __exactProcessProto &&
        __exactProcessProto !== Object.prototype &&
        __exactProcessProto !== globalThis.process &&
        typeof __exactProcessProto === 'object'
      ) {
        __exactDefineExecPath(__exactProcessProto, __exactExecPathValue);
      }
      if (__exactProcessProto && __exactProcessProto !== Object.prototype && typeof __exactProcessProto === 'object') {
        var processExecPathPrototype = Object.getPrototypeOf(__exactProcessProto);
        while (
          processExecPathPrototype &&
          processExecPathPrototype !== Object.prototype &&
          typeof processExecPathPrototype === 'object'
        ) {
          if (__exactDefineExecPath(processExecPathPrototype, __exactExecPathValue)) {
            break;
          }
          processExecPathPrototype = Object.getPrototypeOf(processExecPathPrototype);
        }
      }
    } catch (err) {}

    // Compatibility helpers expected by a small subset of Node fixture patterns.
    // Exposed globally so rewritten fixture files (created at runtime) still see
    // `ok`/`failed` helpers without requiring '../common'.
    try {
      var __global = (typeof globalThis !== 'undefined') ? globalThis : (typeof global !== 'undefined' ? global : null);
      function __exactBuildCompatFailed(value) {
        if (typeof value === 'function') {
          try {
            return value() === undefined;
          } catch (e) {}
          return false;
        }
        return !value;
      }
      if (__global && typeof globalThis.__exactRequire === 'function') {
        var __exactAssert = globalThis.__exactRequire('assert');
        if (__global && __exactAssert && typeof __exactAssert.ok === 'function') {
          __global.failed = __exactBuildCompatFailed;
          if (typeof __global.badly !== 'function') {
            __global.badly = function() {
              return undefined;
            };
          }
        }
        if (__global && typeof __global.ok !== 'function' && __exactAssert && typeof __exactAssert.ok === 'function') {
          __global.ok = function(value, message) {
            __exactAssert.ok(value, message);
          };
        }
      }
      if (__global && typeof __global.failed !== 'function') {
        __global.failed = __exactBuildCompatFailed;
      }
      if (__global && typeof __global.badly !== 'function') {
        __global.badly = function() {
          return undefined;
        };
      }
      if (__global && typeof __global.ok !== 'function') {
        __global.ok = function(value, message) {
          if (!value) {
            throw new Error(message || 'The expression evaluated to a falsy value');
          }
        };
      }
    } catch (err) {}
  }

  // Child-process IPC bootstrap for exact child runtimes.
  function __exactInstallProcessIpcBootstrap() {
    if (
      typeof globalThis.process !== 'object' ||
      globalThis.process === null ||
      !globalThis.process.env ||
      !globalThis.process.env.EXACT_IPC_FD
    ) {
      return false;
    }
    if (globalThis.process.__exactProcessIpcBootstrapInstalled) {
      return true;
    }
    var exactIpcFd = Number(globalThis.process.env.EXACT_IPC_FD);
    if (isFinite(exactIpcFd) && exactIpcFd >= 0) {
      // Ensure FS host functions are loaded (they are lazily initialized)
      if (typeof globalThis.__exactEnsureFs === 'function') {
        globalThis.__exactEnsureFs();
      }
      var exactIpcBuffer = '';
      var exactIpcConnected = true;
      var exactIpcPollTimer = null;
      var exactIpcKeepAliveTimer = null;
      var exactIpcStartupHoldTimer = null;
      var exactIpcPollActive = true;
      var exactIpcReadPaused = false;
      var exactIpcPollInterval = 10;
      var exactIpcSerialization =
        globalThis.process.env.EXACT_IPC_SERIALIZATION === 'advanced' ? 'advanced' : 'json';

      function exactToString(bytes) {
        if (typeof TextDecoder === 'function') {
          try {
            return new TextDecoder().decode(bytes);
          } catch (err) {}
        }
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
          out += String.fromCharCode(bytes[i]);
        }
        return out;
      }

      function exactIpcGetBufferCtor() {
        if (typeof globalThis.Buffer === 'function' && globalThis.Buffer && typeof globalThis.Buffer.from === 'function') {
          return globalThis.Buffer;
        }
        try {
          if (typeof globalThis.__exactRequire === 'function') {
            return globalThis.__exactRequire('buffer').Buffer;
          }
        } catch (_) {}
        return null;
      }

      function exactIpcBytesToBase64(bytes) {
        var BufferCtor = exactIpcGetBufferCtor();
        if (BufferCtor) {
          if (typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(bytes)) {
            return bytes.toString('base64');
          }
          if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
            return BufferCtor.from(new Uint8Array(bytes)).toString('base64');
          }
          if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(bytes)) {
            return BufferCtor.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
          }
          return BufferCtor.from(String(bytes), 'utf8').toString('base64');
        }
        if (typeof btoa === 'function') {
          var array;
          if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
            array = new Uint8Array(bytes);
          } else if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(bytes)) {
            array = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          } else {
            array = new Uint8Array(0);
          }
          var binary = '';
          for (var i = 0; i < array.length; i++) binary += String.fromCharCode(array[i]);
          return btoa(binary);
        }
        return '';
      }

      function exactIpcBase64ToByteArray(base64) {
        var BufferCtor = exactIpcGetBufferCtor();
        if (BufferCtor) {
          var buf = BufferCtor.from(base64 || '', 'base64');
          var out = new Uint8Array(buf.length);
          out.set(buf);
          return out;
        }
        if (typeof atob === 'function') {
          var binary = atob(base64 || '');
          var bytes = new Uint8Array(binary.length);
          for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
          return bytes;
        }
        return new Uint8Array(0);
      }

      function exactIpcAdvancedTag(type) {
        return { __exactIpcSerialized: true, type: type };
      }

      function exactEncodeAdvancedIpcValue(value, refs) {
        if (value === undefined) return exactIpcAdvancedTag('Undefined');
        if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
        if (typeof value === 'number') {
          if (value !== value) {
            var nanTag = exactIpcAdvancedTag('Number');
            nanTag.value = 'NaN';
            return nanTag;
          }
          if (value === Infinity) {
            var infTag = exactIpcAdvancedTag('Number');
            infTag.value = 'Infinity';
            return infTag;
          }
          if (value === -Infinity) {
            var ninfTag = exactIpcAdvancedTag('Number');
            ninfTag.value = '-Infinity';
            return ninfTag;
          }
          if (value === 0 && 1 / value === -Infinity) {
            var negZeroTag = exactIpcAdvancedTag('Number');
            negZeroTag.value = '-0';
            return negZeroTag;
          }
          return value;
        }
        if (typeof value === 'bigint') {
          var bigIntTag = exactIpcAdvancedTag('BigInt');
          bigIntTag.value = String(value);
          return bigIntTag;
        }
        if (typeof value === 'symbol' || typeof value === 'function') {
          var cloneErr = new TypeError('The object could not be cloned.');
          cloneErr.name = 'DataCloneError';
          throw cloneErr;
        }

        for (var refIndex = 0; refIndex < refs.length; refIndex++) {
          if (refs[refIndex] === value) {
            var refTag = exactIpcAdvancedTag('Ref');
            refTag.id = refIndex;
            return refTag;
          }
        }

        var id = refs.length;
        refs.push(value);
        var BufferCtor = exactIpcGetBufferCtor();

        if (BufferCtor && typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(value)) {
          var bufferTag = exactIpcAdvancedTag('Buffer');
          bufferTag.id = id;
          bufferTag.data = value.toString('base64');
          return bufferTag;
        }
        if (typeof Date !== 'undefined' && value instanceof Date) {
          var dateTag = exactIpcAdvancedTag('Date');
          dateTag.id = id;
          dateTag.value = value.getTime();
          return dateTag;
        }
        if (typeof RegExp !== 'undefined' && value instanceof RegExp) {
          var regexpTag = exactIpcAdvancedTag('RegExp');
          regexpTag.id = id;
          regexpTag.source = value.source;
          regexpTag.flags = value.flags;
          return regexpTag;
        }
        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
          var arrayBufferTag = exactIpcAdvancedTag('ArrayBuffer');
          arrayBufferTag.id = id;
          arrayBufferTag.data = exactIpcBytesToBase64(value);
          return arrayBufferTag;
        }
        if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) {
          var sharedArrayBufferTag = exactIpcAdvancedTag('SharedArrayBuffer');
          sharedArrayBufferTag.id = id;
          sharedArrayBufferTag.data = exactIpcBytesToBase64(new Uint8Array(value));
          return sharedArrayBufferTag;
        }
        if (typeof DataView !== 'undefined' && value instanceof DataView) {
          var dataViewTag = exactIpcAdvancedTag('DataView');
          dataViewTag.id = id;
          dataViewTag.data = exactIpcBytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
          return dataViewTag;
        }
        if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
          var typedArrayTag = exactIpcAdvancedTag('TypedArray');
          typedArrayTag.id = id;
          typedArrayTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Uint8Array';
          typedArrayTag.data = exactIpcBytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
          return typedArrayTag;
        }
        if (typeof Map !== 'undefined' && value instanceof Map) {
          var mapTag = exactIpcAdvancedTag('Map');
          mapTag.id = id;
          mapTag.entries = [];
          value.forEach(function(mapValue, mapKey) {
            mapTag.entries.push([
              exactEncodeAdvancedIpcValue(mapKey, refs),
              exactEncodeAdvancedIpcValue(mapValue, refs)
            ]);
          });
          return mapTag;
        }
        if (typeof Set !== 'undefined' && value instanceof Set) {
          var setTag = exactIpcAdvancedTag('Set');
          setTag.id = id;
          setTag.values = [];
          value.forEach(function(setValue) {
            setTag.values.push(exactEncodeAdvancedIpcValue(setValue, refs));
          });
          return setTag;
        }
        if (value instanceof Error) {
          var errorTag = exactIpcAdvancedTag('Error');
          errorTag.id = id;
          errorTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Error';
          errorTag.name = value.name;
          errorTag.message = value.message;
          if (value.stack !== undefined) errorTag.stack = value.stack;
          if ('cause' in value) errorTag.cause = exactEncodeAdvancedIpcValue(value.cause, refs);
          var errorProps = Object.keys(value);
          if (errorProps.length > 0) {
            errorTag.props = {};
            for (var ep = 0; ep < errorProps.length; ep++) {
              var errorKey = errorProps[ep];
              if (errorKey === 'message' || errorKey === 'stack' || errorKey === 'cause' || errorKey === 'name') continue;
              errorTag.props[errorKey] = exactEncodeAdvancedIpcValue(value[errorKey], refs);
            }
          }
          return errorTag;
        }
        if (Array.isArray(value)) {
          var arrayTag = exactIpcAdvancedTag('Array');
          arrayTag.id = id;
          arrayTag.items = new Array(value.length);
          for (var ai = 0; ai < value.length; ai++) {
            if (Object.prototype.hasOwnProperty.call(value, ai)) {
              arrayTag.items[ai] = exactEncodeAdvancedIpcValue(value[ai], refs);
            } else {
              arrayTag.items[ai] = exactIpcAdvancedTag('Hole');
            }
          }
          return arrayTag;
        }

        var objectTag = exactIpcAdvancedTag('Object');
        objectTag.id = id;
        objectTag.props = {};
        var keys = Object.keys(value);
        for (var ki = 0; ki < keys.length; ki++) {
          var key = keys[ki];
          objectTag.props[key] = exactEncodeAdvancedIpcValue(value[key], refs);
        }
        return objectTag;
      }

      function exactDecodeAdvancedIpcValue(value, refs) {
        if (!value || typeof value !== 'object' || value.__exactIpcSerialized !== true) {
          return value;
        }
        var type = value.type;
        if (type === 'Undefined') return undefined;
        if (type === 'Number') {
          if (value.value === 'NaN') return NaN;
          if (value.value === 'Infinity') return Infinity;
          if (value.value === '-Infinity') return -Infinity;
          if (value.value === '-0') return -0;
          return Number(value.value);
        }
        if (type === 'BigInt') {
          return typeof BigInt === 'function' ? BigInt(value.value) : value.value;
        }
        if (type === 'Hole') {
          return value;
        }
        if (type === 'Ref') {
          return refs[value.id];
        }

        var decoded;
        if (type === 'Buffer') {
          var bufferBytes = exactIpcBase64ToByteArray(value.data);
          var BufferCtor = exactIpcGetBufferCtor();
          decoded = BufferCtor ? BufferCtor.from(bufferBytes) : bufferBytes;
          refs[value.id] = decoded;
          return decoded;
        }
        if (type === 'Date') {
          decoded = new Date(value.value);
          refs[value.id] = decoded;
          return decoded;
        }
        if (type === 'RegExp') {
          decoded = new RegExp(value.source || '', value.flags || '');
          refs[value.id] = decoded;
          return decoded;
        }
        if (type === 'ArrayBuffer' || type === 'SharedArrayBuffer') {
          var bufferData = exactIpcBase64ToByteArray(value.data);
          var bufferTarget;
          if (type === 'SharedArrayBuffer' && typeof SharedArrayBuffer === 'function') {
            bufferTarget = new SharedArrayBuffer(bufferData.byteLength);
            new Uint8Array(bufferTarget).set(bufferData);
          } else {
            bufferTarget = new ArrayBuffer(bufferData.byteLength);
            new Uint8Array(bufferTarget).set(bufferData);
          }
          refs[value.id] = bufferTarget;
          return bufferTarget;
        }
        if (type === 'DataView') {
          var dataViewBytes = exactIpcBase64ToByteArray(value.data);
          var dataViewBuffer = new ArrayBuffer(dataViewBytes.byteLength);
          new Uint8Array(dataViewBuffer).set(dataViewBytes);
          decoded = new DataView(dataViewBuffer);
          refs[value.id] = decoded;
          return decoded;
        }
        if (type === 'TypedArray') {
          var typedArrayBytes = exactIpcBase64ToByteArray(value.data);
          var typedArrayBuffer = new ArrayBuffer(typedArrayBytes.byteLength);
          new Uint8Array(typedArrayBuffer).set(typedArrayBytes);
          var TypedArrayCtor = globalThis[value.ctor];
          if (typeof TypedArrayCtor !== 'function') TypedArrayCtor = Uint8Array;
          decoded = new TypedArrayCtor(typedArrayBuffer);
          refs[value.id] = decoded;
          return decoded;
        }
        if (type === 'Map') {
          decoded = new Map();
          refs[value.id] = decoded;
          var mapEntries = value.entries || [];
          for (var me = 0; me < mapEntries.length; me++) {
            decoded.set(
              exactDecodeAdvancedIpcValue(mapEntries[me][0], refs),
              exactDecodeAdvancedIpcValue(mapEntries[me][1], refs)
            );
          }
          return decoded;
        }
        if (type === 'Set') {
          decoded = new Set();
          refs[value.id] = decoded;
          var setValues = value.values || [];
          for (var sv = 0; sv < setValues.length; sv++) {
            decoded.add(exactDecodeAdvancedIpcValue(setValues[sv], refs));
          }
          return decoded;
        }
        if (type === 'Error') {
          var ErrorCtor = globalThis[value.ctor];
          if (typeof ErrorCtor !== 'function') ErrorCtor = Error;
          try {
            decoded = new ErrorCtor(value.message);
          } catch (_) {
            decoded = new Error(value.message);
          }
          refs[value.id] = decoded;
          if (value.name) decoded.name = value.name;
          if (value.stack !== undefined) decoded.stack = value.stack;
          if (Object.prototype.hasOwnProperty.call(value, 'cause')) {
            decoded.cause = exactDecodeAdvancedIpcValue(value.cause, refs);
          }
          if (value.props) {
            var errorPropKeys = Object.keys(value.props);
            for (var ek = 0; ek < errorPropKeys.length; ek++) {
              decoded[errorPropKeys[ek]] = exactDecodeAdvancedIpcValue(value.props[errorPropKeys[ek]], refs);
            }
          }
          return decoded;
        }
        if (type === 'Array') {
          decoded = new Array(value.items ? value.items.length : 0);
          refs[value.id] = decoded;
          for (var ai2 = 0; value.items && ai2 < value.items.length; ai2++) {
            if (value.items[ai2] && value.items[ai2].__exactIpcSerialized === true && value.items[ai2].type === 'Hole') {
              continue;
            }
            decoded[ai2] = exactDecodeAdvancedIpcValue(value.items[ai2], refs);
          }
          return decoded;
        }
        if (type === 'Object') {
          decoded = {};
          refs[value.id] = decoded;
          var propKeys = value.props ? Object.keys(value.props) : [];
          for (var pk = 0; pk < propKeys.length; pk++) {
            decoded[propKeys[pk]] = exactDecodeAdvancedIpcValue(value.props[propKeys[pk]], refs);
          }
          return decoded;
        }
        return value;
      }

      function exactSerializeIpcPacketData(data, serializationMode) {
        if (serializationMode === 'advanced') {
          return exactEncodeAdvancedIpcValue(data, []);
        }
        return data;
      }

      function exactDeserializeIpcPacketData(data, serializationMode) {
        if (serializationMode === 'advanced') {
          return exactDecodeAdvancedIpcValue(data, []);
        }
        return data;
      }

      function exactBuildIpcPacket(type, data, serializationMode, handleType) {
        var packet = {
          __exactIpc: true,
          type: type,
          data: exactSerializeIpcPacketData(data, serializationMode)
        };
        if (serializationMode === 'advanced') packet.serialization = 'advanced';
        if (handleType) packet.handleType = handleType;
        return JSON.stringify(packet) + '\n';
      }

      function exactEnsureStdioRefUnref() {
        function exactInstallNoopRef(stream, name) {
          if (typeof stream[name] === 'function') return;
          try {
            Object.defineProperty(stream, name, {
              value: function() { return this; },
              writable: true,
              configurable: true,
              enumerable: false
            });
            if (typeof stream[name] === 'function') return;
          } catch (_) {}
          stream[name] = function() { return this; };
        }
        function exactInstallReadableStdin(stream) {
          if (!stream ||
              typeof stream !== 'object' ||
              typeof stream.resume === 'function' ||
              typeof globalThis.__exactStdinRead !== 'function') {
            return;
          }
          stream._encoding = null;
          stream._paused = true;
          stream._ended = false;
          stream._pollTimer = 0;
          stream.readable = true;
          stream.readableEnded = false;
          stream.readableFlowing = null;
          stream.readableLength = 0;
          stream.setEncoding = function(enc) {
            stream._encoding = enc;
            return stream;
          };
          stream.resume = function() {
            stream.readable = true;
            stream._paused = false;
            stream.readableFlowing = true;
            if (!stream._ended && !stream._pollTimer) {
              (function exactPollStdin() {
                if (stream._paused || stream._ended || stream.destroyed) return;
                var data = globalThis.__exactStdinRead(262144);
                if (data === null) {
                  stream._pollTimer = setTimeout(exactPollStdin, 1);
                  return;
                }
                if (data === '') {
                  stream._ended = true;
                  stream._pollTimer = 0;
                  stream.readableEnded = true;
                  if (typeof stream.emit === 'function') {
                    stream.emit('end');
                    stream.emit('close');
                  }
                  return;
                }
                stream._pollTimer = 0;
                if (stream._encoding && typeof Buffer !== 'undefined' && Buffer.from) {
                  data = Buffer.from(data, 'binary').toString(stream._encoding);
                }
                stream.readableLength += data.length || 0;
                if (typeof stream.emit === 'function') {
                  stream.emit('data', data);
                }
                stream.readableLength = 0;
                if (!stream._paused && !stream._ended) {
                  stream._pollTimer = setTimeout(exactPollStdin, 0);
                }
              })();
            }
            return stream;
          };
          stream.pause = function() {
            stream._paused = true;
            stream.readableFlowing = false;
            if (stream._pollTimer) {
              clearTimeout(stream._pollTimer);
              stream._pollTimer = 0;
            }
            return stream;
          };
          stream.read = function(size) {
            var data = globalThis.__exactStdinRead(size || 262144);
            if (data === '') return null;
            if (stream._encoding && data && typeof Buffer !== 'undefined' && Buffer.from) {
              return Buffer.from(data, 'binary').toString(stream._encoding);
            }
            return data;
          };
          if (typeof stream.on === 'function') {
            var exactStdinOn = stream.on;
            stream.on = function(event, listener) {
              var result = exactStdinOn.apply(this, arguments);
              if (event === 'data' && !stream._ended && stream._paused) {
                stream.resume();
              }
              return result;
            };
            stream.addListener = stream.on;
          }
          if (typeof stream.once === 'function') {
            var exactStdinOnce = stream.once;
            stream.once = function(event, listener) {
              var result = exactStdinOnce.apply(this, arguments);
              if (event === 'data' && !stream._ended && stream._paused) {
                stream.resume();
              }
              return result;
            };
          }
        }
        var stdioNames = ['stdout', 'stderr', 'stdin'];
        for (var stdioIndex = 0; stdioIndex < stdioNames.length; stdioIndex++) {
          var stdioStream = globalThis.process[stdioNames[stdioIndex]];
          if (!stdioStream || typeof stdioStream !== 'object') continue;
          var stdioProto = Object.getPrototypeOf(stdioStream);
          if (stdioProto && typeof stdioProto === 'object') {
            exactInstallNoopRef(stdioProto, 'ref');
            exactInstallNoopRef(stdioProto, 'unref');
          }
          exactInstallNoopRef(stdioStream, 'ref');
          exactInstallNoopRef(stdioStream, 'unref');
          if (stdioNames[stdioIndex] === 'stdin') {
            exactInstallReadableStdin(stdioStream);
          }
          try {
            Object.defineProperty(globalThis.process, stdioNames[stdioIndex], {
              value: stdioStream,
              writable: true,
              configurable: true,
              enumerable: true
            });
          } catch (_) {
            try {
              globalThis.process[stdioNames[stdioIndex]] = stdioStream;
            } catch (_) {}
          }
        }
      }

      function exactCreateIpcError(code, message) {
        var err = new Error(message);
        err.code = code;
        return err;
      }

      function exactSetProcessChannel(value) {
        try {
          Object.defineProperty(globalThis.process, 'channel', {
            value: value,
            writable: true,
            configurable: true,
            enumerable: true
          });
          return;
        } catch (_) {}
        try {
          globalThis.process.channel = value;
        } catch (_) {}
      }

      function exactCloseIpc() {
        if (!exactIpcConnected) return;
        exactIpcConnected = false;
        exactIpcPollActive = false;
        if (exactIpcPollTimer) {
          clearTimeout(exactIpcPollTimer);
          exactIpcPollTimer = null;
        }
        if (exactIpcKeepAliveTimer) {
          try { clearInterval(exactIpcKeepAliveTimer); } catch (_) {}
          exactIpcKeepAliveTimer = null;
        }
        if (exactIpcStartupHoldTimer) {
          try { clearTimeout(exactIpcStartupHoldTimer); } catch (_) {}
          exactIpcStartupHoldTimer = null;
        }
        globalThis.process.connected = false;
        exactSetProcessChannel(null);
        var exactChannelHandleKey = globalThis.__exactKChannelHandleKey;
        if (exactChannelHandleKey === undefined) {
          exactChannelHandleKey = '__exactKChannelHandle';
          globalThis.__exactKChannelHandleKey = exactChannelHandleKey;
        }
        globalThis.process[exactChannelHandleKey] = null;
        if (typeof globalThis.__exactFsClose === 'function') {
          try {
            globalThis.__exactFsClose(exactIpcFd);
          } catch (err) {}
        }
        var emitDisconnect = function() {
          globalThis.process.emit('disconnect');
        };
        if (typeof globalThis.setTimeout === 'function') {
          var disconnectTimer = globalThis.setTimeout(emitDisconnect, 0);
          if (disconnectTimer && typeof disconnectTimer.ref === 'function') {
            disconnectTimer.ref();
          }
        } else if (typeof globalThis.process.nextTick === 'function') {
          globalThis.process.nextTick(emitDisconnect);
        } else {
          emitDisconnect();
        }
      }

      var _exactPendingRecvFd = -1;
      function exactMaybeDecodeIpcBuffer() {
        if (!exactIpcBuffer || exactIpcBuffer.charCodeAt(0) !== 34) {
          return;
        }
        try {
          var decodedBuffer = JSON.parse(exactIpcBuffer);
          if (typeof decodedBuffer === 'string') {
            exactIpcBuffer = decodedBuffer;
          }
        } catch (_) {}
      }

      function exactProcessIncomingPackets(rawData, recvFd) {
        if (typeof recvFd === 'number' && recvFd >= 0) {
          _exactPendingRecvFd = recvFd;
        }
        if (!rawData || !rawData.length) return;
        exactIpcBuffer += exactToString(rawData);
        exactMaybeDecodeIpcBuffer();
        while (exactIpcBuffer.length > 0) {
          var lineEnd = exactIpcBuffer.indexOf('\n');
          if (lineEnd < 0) {
            return;
          }
          var line = exactIpcBuffer.slice(0, lineEnd);
          exactIpcBuffer = exactIpcBuffer.slice(lineEnd + 1);
          if (!line) continue;
          var packet;
          try {
            packet = JSON.parse(line);
          } catch (err) { continue; }
          if (typeof packet === 'string') {
            try {
              packet = JSON.parse(packet);
            } catch (err2) {
              exactMaybeDecodeIpcBuffer();
              continue;
            }
          }
          if (!packet || packet.__exactIpc !== true) continue;
          if (packet.type === 'message') {
            // Reconstruct handle from received fd if present
            var handle = null;
            if (packet.handleType && _exactPendingRecvFd >= 0) {
              handle = exactReconstructHandle(packet.handleType, _exactPendingRecvFd);
              _exactPendingRecvFd = -1;
            }
            var packetData = exactDeserializeIpcPacketData(packet.data, packet.serialization);
            if (typeof globalThis.__exactInstallAsyncIpcListenerPatch === 'function') {
              try {
                globalThis.__exactInstallAsyncIpcListenerPatch();
              } catch (_) {}
            }
            if (handle) {
              globalThis.process.emit('message', packetData, handle);
            } else {
              globalThis.process.emit('message', packetData);
            }
            if (typeof globalThis.__exactSyncTrackedIpcListenersAfterDispatch === 'function') {
              try {
                globalThis.__exactSyncTrackedIpcListenersAfterDispatch();
              } catch (_) {}
            }
          } else if (packet.type === 'disconnect') {
            exactCloseIpc();
          }
          exactMaybeDecodeIpcBuffer();
        }
      }

      function exactReconstructHandle(handleType, fd) {
        try {
          if (handleType === 'dgram.Socket' || handleType === 'dgram.Native') {
            var dgram = require('dgram');
            var sock = dgram.createSocket('udp4');
            sock._fromFd(fd);
            return sock;
          }
          var net = require('net');
          if (handleType === 'net.Socket' || handleType === 'net.Native') {
            // Register the raw fd as a native TCP handle, then wrap it
            var recvSocket;
            if (typeof globalThis.__exactTcpFromFd === 'function') {
              var nativeHandle = globalThis.__exactTcpFromFd(fd);
              recvSocket = new net.Socket({ _handle: nativeHandle });
            } else {
              recvSocket = new net.Socket({ fd: fd, readable: true, writable: true });
            }
            // SocketList protocol: notify parent when this socket closes
            // so server._connections is decremented correctly.
            recvSocket.on('close', function() {
              if (globalThis.process && globalThis.process.connected) {
                try {
                  globalThis.process.send({ cmd: 'NODE_SOCKET_CLOSED' });
                } catch(e) {}
              }
            });
            return recvSocket;
          } else if (handleType === 'net.ServerHandle') {
            if (typeof globalThis.__exactTcpFromFd === 'function') {
              var nativeServerHandle = globalThis.__exactTcpFromFd(fd);
              return {
                _exactServerHandle: true,
                _exactHandle: nativeServerHandle,
                fd: fd,
                onconnection: function() {},
                close: function() {
                  try { globalThis.__exactTcpClose(nativeServerHandle); } catch (e) {}
                }
              };
            }
            return {
              _exactServerHandle: true,
              fd: fd,
              onconnection: function() {},
              close: function() {
                try {
                  if (typeof globalThis.__exactFsClose === 'function') {
                    globalThis.__exactFsClose(fd);
                  }
                } catch (_) {}
              }
            };
          } else if (handleType === 'net.Server') {
            if (typeof globalThis.__exactTcpFromFd === 'function') {
              var nativeHandle = globalThis.__exactTcpFromFd(fd);
              var server = net.createServer();
              server._handle = { _exactHandle: nativeHandle, close: function() {
                try { globalThis.__exactTcpClose(nativeHandle); } catch(e) {}
              }};
              server._handle._exactServerHandle = true;
              server.listening = true;
              server._closing = false;
              try {
                if (typeof globalThis.__exactTcpLocalAddr === 'function') {
                  var info = globalThis.__exactTcpLocalAddr(nativeHandle);
                  if (info) {
                    var addr = JSON.parse(info);
                    server._port = addr.port;
                    server._host = addr.address;
                    server.host = addr.address;
                    var familySuffix = (addr.family || 'IPv4').slice(-1);
                    server._connectionKey = familySuffix + ':' + addr.address + ':' + addr.port;
                  }
                }
              } catch (e) {}
              if (typeof server._startAccepting === 'function') {
                server._startAccepting();
              }
              return server;
            }
            var server = net.createServer();
            server._handle = { fd: fd, _exactServerHandle: true };
            server.listening = true;
            return server;
          }
        } catch (e) {}
        return null;
      }

      function exactPollIpc() {
        if (!exactIpcPollActive || !globalThis.process) {
          return;
        }
        if (!exactIpcConnected) {
          return;
        }
        // Read any available data FIRST, before checking for hangup.
        // When the other end closes the pipe, there may still be buffered
        // data in the kernel that we need to drain before closing.
        var hadData = false;
        // Prefer recvmsg to receive SCM_RIGHTS file descriptors
        if (typeof globalThis.__exactIpcRecvMsg === 'function') {
          var recvResult;
          try {
            recvResult = globalThis.__exactIpcRecvMsg(exactIpcFd, 65536);
          } catch (err) {
            exactCloseIpc();
            return;
          }
          if (recvResult && recvResult.data && recvResult.data.length) {
            hadData = true;
            exactProcessIncomingPackets(recvResult.data, recvResult.fd);
          }
        } else if (
          typeof globalThis.__exactFsRead === 'function' &&
          globalThis.__exactFsRead
        ) {
          var chunk;
          try {
            chunk = globalThis.__exactFsRead(exactIpcFd, 65536, -1);
          } catch (err) {
            exactCloseIpc();
            return;
          }
          if (chunk && chunk.length) {
            hadData = true;
            exactProcessIncomingPackets(chunk);
          }
        }
        // Check if IPC fd has been closed (pipe hangup) AFTER draining data.
        // Only close if we got no data this round (all buffered data consumed).
        if (!hadData && typeof globalThis.__exactFdPollHup === 'function') {
          try {
            if (globalThis.__exactFdPollHup(exactIpcFd)) {
              exactCloseIpc();
              return;
            }
          } catch (e) {}
        }
        if (exactIpcPollActive) {
          exactSyncIpcListenerRef();
          exactIpcPollTimer = setTimeout(exactPollIpc, exactIpcPollInterval);
          // Ref/unref based on current channel ref state
          if (exactIpcPollTimer) {
            if (exactIpcChannelRefed) {
              if (typeof exactIpcPollTimer.ref === 'function') exactIpcPollTimer.ref();
            } else {
              if (typeof exactIpcPollTimer.unref === 'function') exactIpcPollTimer.unref();
            }
          }
        }
      }

      globalThis.process.connected = true;
      // IPC channel timer starts unref'd so the process can exit when idle.
      // It is auto-ref'd when 'message'/'disconnect' listeners are added and
      // auto-unref'd when the last such listener is removed.
      var exactIpcChannelRefed = false;
      function exactRefIpcTimer() {
        if (exactIpcChannelRefed) return;
        exactIpcChannelRefed = true;
        if (!exactIpcKeepAliveTimer && typeof setInterval === 'function') {
          exactIpcKeepAliveTimer = setInterval(function() {}, 1000);
        }
        if (exactIpcKeepAliveTimer && typeof exactIpcKeepAliveTimer.ref === 'function') {
          exactIpcKeepAliveTimer.ref();
        }
        if (!exactIpcPollTimer && exactIpcPollActive && typeof setTimeout === 'function') {
          exactIpcPollTimer = setTimeout(exactPollIpc, 0);
        }
        if (exactIpcPollTimer && typeof exactIpcPollTimer.ref === 'function') {
          exactIpcPollTimer.ref();
        } else if (exactIpcPollTimer) {
          // Timer is a raw number (native setTimeout from before wrapper was installed).
          // Cancel it and re-create with the (now-wrapped) setTimeout so we get
          // a proper Timeout object with .ref()/.unref().
          clearTimeout(exactIpcPollTimer);
          exactIpcPollTimer = setTimeout(exactPollIpc, 0);
          if (exactIpcPollTimer && typeof exactIpcPollTimer.ref === 'function') {
            exactIpcPollTimer.ref();
          }
        }
      }
      function exactUnrefIpcTimer() {
        if (!exactIpcChannelRefed) return;
        exactIpcChannelRefed = false;
        if (exactIpcKeepAliveTimer) {
          if (typeof exactIpcKeepAliveTimer.unref === 'function') {
            exactIpcKeepAliveTimer.unref();
          } else {
            try { clearInterval(exactIpcKeepAliveTimer); } catch (_) {}
            exactIpcKeepAliveTimer = null;
          }
        }
        if (exactIpcPollTimer && typeof exactIpcPollTimer.unref === 'function') {
          exactIpcPollTimer.unref();
        }
      }
      function exactHoldIpcStartupWindow() {
        exactRefIpcTimer();
        if (exactIpcStartupHoldTimer) {
          clearTimeout(exactIpcStartupHoldTimer);
          exactIpcStartupHoldTimer = null;
        }
        if (typeof setTimeout !== 'function') {
          return;
        }
        exactIpcStartupHoldTimer = setTimeout(function() {
          exactIpcStartupHoldTimer = null;
          exactSyncIpcListenerRef();
        }, 500);
        if (exactIpcStartupHoldTimer &&
            typeof exactIpcStartupHoldTimer.ref === 'function') {
          exactIpcStartupHoldTimer.ref();
        }
      }
      exactSetProcessChannel({
        fd: exactIpcFd,
        ref: function() { exactRefIpcTimer(); },
        unref: function() { exactUnrefIpcTimer(); }
      });
      exactEnsureStdioRefUnref();
      // Expose kChannelHandle for internal/child_process compatibility
      var kChannelHandle = globalThis.__exactKChannelHandleKey;
      if (kChannelHandle === undefined) {
        kChannelHandle = '__exactKChannelHandle';
        globalThis.__exactKChannelHandleKey = kChannelHandle;
      }
      globalThis.process[kChannelHandle] = {
        readStop: function() {
          exactEnsureStdioRefUnref();
          exactIpcReadPaused = true;
          exactIpcPollActive = false;
          if (exactIpcPollTimer) {
            clearTimeout(exactIpcPollTimer);
            exactIpcPollTimer = null;
          }
          exactRefIpcTimer();
        },
        readStart: function() {
          exactEnsureStdioRefUnref();
          exactIpcReadPaused = false;
          if (!exactIpcPollActive) {
            exactIpcPollActive = true;
            exactPollIpc();
          }
          exactSyncIpcListenerRef();
        }
      };
      function exactSyncIpcListenerRef() {
        if (typeof globalThis.process.listenerCount !== 'function') {
          return;
        }
        try {
          var activeIpcListeners =
            globalThis.process.listenerCount('message') +
            globalThis.process.listenerCount('disconnect');
          if (activeIpcListeners > 0) {
            exactRefIpcTimer();
          } else {
            exactUnrefIpcTimer();
          }
        } catch (_) {}
      }
      function exactInstallProcessIpcListenerWrappers(target, markerName) {
        if (!target || target[markerName]) {
          return;
        }
        function exactDefineMethod(name, fn) {
          try {
            Object.defineProperty(target, name, {
              value: fn,
              writable: true,
              configurable: true,
              enumerable: false
            });
          } catch (_) {
            target[name] = fn;
          }
        }
        function exactShouldTrackIpcListener(self, event) {
          return self === globalThis.process &&
            (event === 'message' || event === 'disconnect');
        }
        if (typeof target.on === 'function') {
          var origOn = target.on;
          exactDefineMethod('on', function(event, listener) {
            var result = origOn.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactRefIpcTimer();
            }
            return result;
          });
        }
        if (typeof target.addListener === 'function') {
          var origAddListener = target.addListener;
          exactDefineMethod('addListener', function(event, listener) {
            var result = origAddListener.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactRefIpcTimer();
            }
            return result;
          });
        }
        if (typeof target.prependListener === 'function') {
          var origPrependListener = target.prependListener;
          exactDefineMethod('prependListener', function(event, listener) {
            var result = origPrependListener.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactRefIpcTimer();
            }
            return result;
          });
        }
        function exactWrapSingleUseListener(originalRegistrar) {
          return function(event, listener) {
            if (exactShouldTrackIpcListener(this, event) &&
                typeof listener === 'function') {
              exactRefIpcTimer();
              var wrappedListener = function() {
                try {
                  return listener.apply(this, arguments);
                } finally {
                  exactSyncIpcListenerRef();
                }
              };
              try {
                wrappedListener.listener = listener;
              } catch (_) {}
              return originalRegistrar.call(this, event, wrappedListener);
            }
            var result = originalRegistrar.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactRefIpcTimer();
            }
            return result;
          };
        }
        if (typeof target.once === 'function') {
          exactDefineMethod('once', exactWrapSingleUseListener(target.once));
        }
        if (typeof target.prependOnceListener === 'function') {
          exactDefineMethod('prependOnceListener',
            exactWrapSingleUseListener(target.prependOnceListener));
        }
        if (typeof target.removeListener === 'function') {
          var origRemoveListener = target.removeListener;
          exactDefineMethod('removeListener', function(event, listener) {
            var result = origRemoveListener.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactSyncIpcListenerRef();
            }
            return result;
          });
        }
        if (typeof target.off === 'function') {
          var origOff = target.off;
          exactDefineMethod('off', function(event, listener) {
            var result = origOff.apply(this, arguments);
            if (exactShouldTrackIpcListener(this, event)) {
              exactSyncIpcListenerRef();
            }
            return result;
          });
        }
        if (typeof target.removeAllListeners === 'function') {
          var origRemoveAllListeners = target.removeAllListeners;
          exactDefineMethod('removeAllListeners', function(event) {
            var result = origRemoveAllListeners.apply(this, arguments);
            if (this === globalThis.process &&
                (event === undefined ||
                 event === 'message' ||
                 event === 'disconnect')) {
              exactSyncIpcListenerRef();
            }
            return result;
          });
        }
        try {
          Object.defineProperty(target, markerName, {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false
          });
        } catch (_) {
          target[markerName] = true;
        }
      }
      exactInstallProcessIpcListenerWrappers(Object.getPrototypeOf(globalThis.process),
        '__exactIpcProcessProtoWrapped');
      exactInstallProcessIpcListenerWrappers(globalThis.process,
        '__exactIpcProcessWrapped');
      exactSyncIpcListenerRef();
      exactHoldIpcStartupWindow();
      globalThis.process.send = function(message, sendHandle, opts, callback) {
        // Validate message argument
        if (message === undefined) {
          var missingErr = new TypeError('The "message" argument must be specified');
          missingErr.code = 'ERR_MISSING_ARGS';
          throw missingErr;
        }
        try {
          if (globalThis.process.channel &&
              typeof globalThis.process.channel.ref === 'function' &&
              typeof globalThis.process.listenerCount === 'function') {
            var sendListenerCount =
              globalThis.process.listenerCount('message') +
              globalThis.process.listenerCount('disconnect');
            if (sendListenerCount > 0) {
              globalThis.process.channel.ref();
            }
          }
        } catch (_) {}
        if (typeof sendHandle === 'function') {
          callback = sendHandle;
          sendHandle = undefined;
          opts = undefined;
        } else if (typeof opts === 'function') {
          callback = opts;
          opts = undefined;
        } else if (opts !== undefined) {
          if (opts === null || typeof opts !== 'object') {
            var optsErr = new TypeError('The "options" argument must be of type object. Received type ' + typeof opts);
            optsErr.code = 'ERR_INVALID_ARG_TYPE';
            throw optsErr;
          }
        }
        if (callback !== undefined && typeof callback !== 'function') {
          var cbErr = new TypeError('The "callback" argument must be of type function. Received type ' + typeof callback);
          cbErr.code = 'ERR_INVALID_ARG_TYPE';
          throw cbErr;
        }
        // Validate sendHandle
        if (sendHandle != null && sendHandle !== false) {
          if (typeof sendHandle !== 'object' && typeof sendHandle !== 'function') {
            var handleErr = new TypeError("This handle type can't be sent");
            handleErr.code = 'ERR_INVALID_HANDLE_TYPE';
            throw handleErr;
          }
        }
        if (!exactIpcConnected) {
          var ipcError = exactCreateIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is closed');
          if (typeof callback === 'function') {
            setTimeout(function() {
              callback(ipcError);
            }, 0);
          }
          return false;
        }
        // Extract fd from sendHandle if present
        var handleFd = -1;
        var handleType = null;
        if (sendHandle != null && sendHandle !== false && typeof sendHandle === 'object') {
          // dgram.Socket: use _getFd() or __exactUdpGetFd
          if (typeof sendHandle._getFd === 'function') {
            handleFd = sendHandle._getFd();
          } else if (typeof sendHandle._handle === 'number' && sendHandle._handle >= 0 && (sendHandle.type === 'udp4' || sendHandle.type === 'udp6')) {
            if (typeof globalThis.__exactUdpGetFd === 'function') handleFd = globalThis.__exactUdpGetFd(sendHandle._handle);
          }
          // Our native handle system: _handle._exactHandle is an ID into g_tcp_sockets
          else if (sendHandle._handle && typeof sendHandle._handle._exactHandle === 'number' && sendHandle._handle._exactHandle > 0 && typeof globalThis.__exactTcpGetFd === 'function') {
            handleFd = globalThis.__exactTcpGetFd(sendHandle._handle._exactHandle);
          } else if (sendHandle._handle && typeof sendHandle._handle.fd === 'number') handleFd = sendHandle._handle.fd;
          else if (typeof sendHandle.fd === 'number') handleFd = sendHandle.fd;
          else if (typeof sendHandle._fd === 'number') handleFd = sendHandle._fd;
          // Determine type
          if (sendHandle.type === 'udp4' || sendHandle.type === 'udp6') {
            handleType = 'dgram.Socket';
          } else if (sendHandle._exactServerHandle === true ||
                     (typeof sendHandle.close === 'function' && typeof sendHandle.onconnection === 'function')) {
            handleType = 'net.ServerHandle';
          } else {
            var hn = sendHandle.constructor && sendHandle.constructor.name;
            if (hn === 'Server') handleType = 'net.Server';
            else handleType = 'net.Socket';
          }
        }
        var packet = exactBuildIpcPacket('message', message, exactIpcSerialization, handleType);
        var written = false;
        if (handleFd >= 0 && typeof globalThis.__exactIpcSendMsg === 'function') {
          try {
            written = globalThis.__exactIpcSendMsg(exactIpcFd, packet, handleFd) > 0;
          } catch (err) {
            written = false;
          }
          // When keepOpen is not set, Node.js detaches the handle from the sender.
          // Don't destroy dgram sockets or servers - they're shared.
          var keepOpen = opts && opts.keepOpen;
          var isDgramHandle = sendHandle && (sendHandle.type === 'udp4' || sendHandle.type === 'udp6');
          var isServerHandle = handleType === 'net.Server' || handleType === 'net.ServerHandle';
          if (written && sendHandle && !keepOpen && !isDgramHandle && !isServerHandle) {
            // Clear server reference but don't decrement _connections
            // (SocketList protocol handles this via NODE_SOCKET_CLOSED)
            if (sendHandle._server) {
              sendHandle._server = null;
              sendHandle.server = null;
            }
            if (sendHandle.parser) sendHandle.parser = null;
            if (sendHandle._httpMessage) sendHandle._httpMessage = null;
            var kt = Symbol.for('kTimeout');
            sendHandle[kt] = null;
            // Detach the handle without emitting 'close'.
            if (sendHandle._pollTimer != null) {
              clearTimeout(sendHandle._pollTimer);
              sendHandle._pollTimer = null;
            }
            if (sendHandle._timeoutTimer != null) {
              clearTimeout(sendHandle._timeoutTimer);
              sendHandle._timeoutTimer = null;
            }
            var nativeH = sendHandle._handle;
            if (nativeH && nativeH._exactHandle !== undefined) {
              nativeH = nativeH._exactHandle;
            }
            if (nativeH != null && typeof globalThis.__exactTcpClose === 'function') {
              try { globalThis.__exactTcpClose(nativeH); } catch(e) {}
            }
            sendHandle._handle = null;
            sendHandle.destroyed = true;
            sendHandle.readable = false;
            sendHandle.writable = false;
          }
        } else if (typeof globalThis.__exactFsWrite === 'function') {
          try {
            written = globalThis.__exactFsWrite(exactIpcFd, packet, -1) > 0;
          } catch (err) {
            written = false;
          }
        }
        if (typeof callback === 'function') {
          setTimeout(function() {
            callback(written ? null : exactCreateIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed'));
          }, 0);
        }
        return written;
      };

      globalThis.process.disconnect = function() {
        if (!exactIpcConnected) {
          throw exactCreateIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
        }
        if (typeof globalThis.__exactFsWrite === 'function' && exactIpcConnected) {
          try {
            var disconnectPacket = exactBuildIpcPacket('disconnect');
            globalThis.__exactFsWrite(exactIpcFd, disconnectPacket, -1);
          } catch (err) {}
        }
        exactCloseIpc();
      };

      exactIpcPollTimer = setTimeout(exactPollIpc, 0);
      // The initial timer is from native setTimeout (returns a number).
      // We can't unref it (no .unref() method), but it fires immediately
      // (timeout=0). The first poll will create a new timer with the wrapped
      // setTimeout (returns Timeout object) which will be properly unref'd.
      try {
        Object.defineProperty(globalThis.process, '__exactProcessIpcBootstrapInstalled', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_) {
        try {
          globalThis.process.__exactProcessIpcBootstrapInstalled = true;
        } catch (_) {}
      }
      return true;
    }
    return false;
  }
  try {
    globalThis.__exactInstallProcessIpcBootstrap = __exactInstallProcessIpcBootstrap;
  } catch (_) {}
  __exactInstallProcessIpcBootstrap();

  // When running compat tests, auto-load bun:test so test/describe/it/expect
  // globals are available even if the test file doesn't explicitly import them.
  // This matches Bun's behavior where these globals are always present.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    globalThis.process.env &&
    globalThis.process.env.EXACT_COMPAT_TEST === '1' &&
    globalThis.process.env.EXACT_TEST_SECTION === 'bun' &&
    Array.isArray(globalThis.process.argv) &&
    globalThis.process.argv.length > 1 &&
    typeof globalThis.__exactRequire === 'function' &&
    typeof globalThis.test !== 'function'
  ) {
    try {
      // Ensure 'global' is defined — bun-adapter.js uses it but it may not
      // be set up this early in bootstrap.
      if (typeof global === 'undefined') {
        globalThis.global = globalThis;
      }
      globalThis.__exactRequire('bun:test');
    } catch (err) {
      // Keep bootstrap resilient if bun:test cannot be loaded.
    }
  }

  // Ensure ReadableStream iteration surfaces match the spec and accept `null`
  // for getReader options in environments where the host implementation expects
  // an options object.
  // Wrap an iterator result object {value, done} to ensure it inherits from
  // Object.prototype. Hermes's native ReadableStream returns null-prototype
  // objects from read(), which breaks WPT tests that use hasOwnProperty.
  var _wrapIterResult = function(result) {
    if (result !== null && typeof result === 'object' && Object.getPrototypeOf(result) === null) {
      return { value: result.value, done: result.done };
    }
    return result;
  };

  // Wrap an async iterator to ensure next()/return()/throw() results have
  // Object.prototype (not null). Creates a wrapper object that delegates
  // to the original iterator but wraps each result with _wrapIterResult.
  var _makeAsyncIterWrapper = function(origIter) {
    if (!origIter || typeof origIter !== 'object') return origIter;
    var origNext = typeof origIter.next === 'function' ? origIter.next.bind(origIter) : null;
    var origReturn = typeof origIter['return'] === 'function' ? origIter['return'].bind(origIter) : null;
    var origThrow = typeof origIter['throw'] === 'function' ? origIter['throw'].bind(origIter) : null;
    // Build a plain object wrapper with correct .name properties
    var originalPrototype = Object.getPrototypeOf(origIter);
    var wrapper = Object.create(originalPrototype || Object.prototype);
    if (origNext) {
      wrapper.next = function next() {
        return origNext().then(_wrapIterResult);
      };
    }
    if (origReturn) {
      wrapper['return'] = function _return(value) {
        return origReturn(value).then(_wrapIterResult);
      };
    }
    if (origThrow) {
      wrapper['throw'] = function _throw(value) {
        return origThrow(value).then(_wrapIterResult);
      };
    }
    var asyncIterKey = typeof Symbol !== 'undefined' && Symbol.asyncIterator ? Symbol.asyncIterator : null;
    if (asyncIterKey) {
      wrapper[asyncIterKey] = function() { return wrapper; };
    }
    wrapper.__exactAsyncIterWrapper = true;
    return wrapper;
  };

  var installReadableStreamIteratorCompat = function () {
    if (
      typeof globalThis.ReadableStream === 'function' &&
      globalThis.ReadableStream &&
      typeof globalThis.ReadableStream.prototype === 'object' &&
      globalThis.ReadableStream.prototype !== null &&
      !globalThis.ReadableStream.prototype.__exactReadableStreamCompatIteratorPatched
    ) {
      var ReadableStream = globalThis.ReadableStream;
      var readableStreamPrototype = ReadableStream.prototype;
      var originalGetReader = readableStreamPrototype.getReader;

      if (typeof originalGetReader === 'function') {
        readableStreamPrototype.getReader = function (options) {
          var reader;
          if (options === null) {
            reader = originalGetReader.call(this);
          } else {
            reader = originalGetReader.call(this, options);
          }
          // Wrap the reader's read() to return proper-prototype objects without
          // becoming thenable via Object.prototype.then interception.
          if (reader && typeof reader.read === 'function' && !reader.__exactReadWrapped) {
            var origRead = reader.read.bind(reader);
            reader.read = function(view, options) {
              return origRead(view, options).then(_wrapIterResult);
            };
            reader.__exactReadWrapped = true;
          }
          return reader;
        };
        readableStreamPrototype.getReader.__exactReadableStreamCompatGetReaderPatched = true;
      }

      ReadableStream.prototype.__exactReadableStreamCompatIteratorPatched = true;
    }
  };

  globalThis.__exactInstallReadableStreamIteratorCompat = installReadableStreamIteratorCompat;

  installReadableStreamIteratorCompat();
  if (
    (!globalThis.ReadableStream ||
      !globalThis.ReadableStream.prototype ||
      !globalThis.ReadableStream.prototype.__exactReadableStreamCompatIteratorPatched) &&
    !globalThis.__exactReadableStreamCompatIteratorPatchScheduled
  ) {
    globalThis.__exactReadableStreamCompatIteratorPatchScheduled = true;
    if (typeof queueMicrotask === 'function') {
      queueMicrotask(installReadableStreamIteratorCompat);
    } else if (typeof setTimeout === 'function') {
      setTimeout(installReadableStreamIteratorCompat, 0);
    }
  }

  // Defensive cleanup: remove any properties that leaked onto Object.prototype
  // during bootstrap (e.g. from setProperty on process.__proto__ when it was
  // Object.prototype). These pollute for...in on all objects.
  try {
    var _objProto = Object.prototype;
    var _pollutedKeys = ['exit', 'abort', 'on', 'emit', 'addListener', 'removeListener',
      'removeAllListeners', 'once', 'listeners', 'listenerCount', 'prependListener',
      'prependOnceListener', 'rawListeners', 'eventNames', 'emitWarning'];
    for (var _pi = 0; _pi < _pollutedKeys.length; _pi++) {
      if (_objProto.hasOwnProperty(_pollutedKeys[_pi])) {
        try { delete _objProto[_pollutedKeys[_pi]]; } catch (e) {}
      }
    }
  } catch (err) {}

  // In-memory Cache API polyfill (CacheStorage / Cache / caches).
  // This provides a spec-compliant in-memory implementation so that WPT tests
  // and application code that use the Cache API can run without a service worker.
  if (typeof globalThis.caches === 'undefined') {
    (function() {
      function Cache() {
        this._entries = []; // [{request: Request, response: Response}]
      }

      Cache.prototype.match = function(request) {
        var url = (typeof request === 'string') ? request : (request && request.url);
        for (var i = 0; i < this._entries.length; i++) {
          var entryUrl = this._entries[i].request.url || this._entries[i].request;
          if (entryUrl === url) {
            return Promise.resolve(this._entries[i].response.clone());
          }
        }
        return Promise.resolve(undefined);
      };

      Cache.prototype.matchAll = function(request) {
        if (!request) {
          var all = [];
          for (var i = 0; i < this._entries.length; i++) {
            all.push(this._entries[i].response.clone());
          }
          return Promise.resolve(all);
        }
        var url = (typeof request === 'string') ? request : (request && request.url);
        var results = [];
        for (var j = 0; j < this._entries.length; j++) {
          var entryUrl = this._entries[j].request.url || this._entries[j].request;
          if (entryUrl === url) {
            results.push(this._entries[j].response.clone());
          }
        }
        return Promise.resolve(results);
      };

      Cache.prototype.put = function(request, response) {
        var req;
        if (typeof request === 'string') {
          req = (typeof globalThis.Request === 'function') ? new globalThis.Request(request) : { url: request };
        } else {
          // Clone the request to detach signals etc.
          req = (typeof request.clone === 'function') ? request.clone() : { url: request.url, method: request.method, headers: request.headers };
        }
        var url = req.url;
        // Replace existing entry with same URL
        for (var i = 0; i < this._entries.length; i++) {
          var entryUrl = this._entries[i].request.url || this._entries[i].request;
          if (entryUrl === url) {
            this._entries[i] = { request: req, response: response.clone() };
            return Promise.resolve();
          }
        }
        this._entries.push({ request: req, response: response.clone() });
        return Promise.resolve();
      };

      Cache.prototype.add = function(request) {
        var cache = this;
        var req = (typeof request === 'string') ? new globalThis.Request(request) : request;
        return globalThis.fetch(req).then(function(response) {
          if (!response.ok) {
            throw new TypeError('Bad response status');
          }
          return cache.put(req, response);
        });
      };

      Cache.prototype.addAll = function(requests) {
        var cache = this;
        var promises = [];
        for (var i = 0; i < requests.length; i++) {
          promises.push(cache.add(requests[i]));
        }
        return Promise.all(promises);
      };

      Cache.prototype['delete'] = function(request) {
        var url = (typeof request === 'string') ? request : (request && request.url);
        for (var i = 0; i < this._entries.length; i++) {
          var entryUrl = this._entries[i].request.url || this._entries[i].request;
          if (entryUrl === url) {
            this._entries.splice(i, 1);
            return Promise.resolve(true);
          }
        }
        return Promise.resolve(false);
      };

      Cache.prototype.keys = function(request) {
        if (request) {
          var url = (typeof request === 'string') ? request : request.url;
          var matched = [];
          for (var i = 0; i < this._entries.length; i++) {
            var entryUrl = this._entries[i].request.url || this._entries[i].request;
            if (entryUrl === url) {
              var r = this._entries[i].request;
              matched.push((typeof r.clone === 'function') ? r.clone() : r);
            }
          }
          return Promise.resolve(matched);
        }
        var all = [];
        for (var j = 0; j < this._entries.length; j++) {
          var rq = this._entries[j].request;
          all.push((typeof rq.clone === 'function') ? rq.clone() : rq);
        }
        return Promise.resolve(all);
      };

      var _cacheStore = {};

      function CacheStorage() {}

      CacheStorage.prototype.open = function(cacheName) {
        var name = String(cacheName);
        if (!_cacheStore[name]) {
          _cacheStore[name] = new Cache();
        }
        return Promise.resolve(_cacheStore[name]);
      };

      CacheStorage.prototype.has = function(cacheName) {
        return Promise.resolve(!!_cacheStore[String(cacheName)]);
      };

      CacheStorage.prototype['delete'] = function(cacheName) {
        var name = String(cacheName);
        if (_cacheStore[name]) {
          delete _cacheStore[name];
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      };

      CacheStorage.prototype.keys = function() {
        return Promise.resolve(Object.keys(_cacheStore));
      };

      CacheStorage.prototype.match = function(request) {
        var keys = Object.keys(_cacheStore);
        var index = 0;
        function tryNext() {
          if (index >= keys.length) return Promise.resolve(undefined);
          return _cacheStore[keys[index++]].match(request).then(function(result) {
            if (result !== undefined) return result;
            return tryNext();
          });
        }
        return tryNext();
      };

      globalThis.caches = new CacheStorage();
      globalThis.CacheStorage = CacheStorage;
      globalThis.Cache = Cache;
    })();
  }
})();
