(function() {
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

  __exactPatchBrokenSharedArrayBuffer();
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

  // Copy process.env to a plain JS object for proper read/write support.
  // The native JSI HostObject silently ignores property overwrites for
  // existing properties. We can't replace process.env or globalThis.process
  // from JS. Instead, store a mutable copy as process.__exactPlainEnv
  // and have builtin modules use it when available.
  if (typeof globalThis.process === 'object' && globalThis.process !== null && globalThis.process.env) {
    (function() {
      var _nativeEnv = globalThis.process.env;
      var _plainEnv = {};
      var keys = Object.keys(_nativeEnv);
      for (var i = 0; i < keys.length; i++) {
        _plainEnv[keys[i]] = '' + _nativeEnv[keys[i]];
      }
      if (typeof globalThis.__exactGetAllEnv === 'function') {
        var all = globalThis.__exactGetAllEnv();
        var allKeys = Object.keys(all);
        for (var j = 0; j < allKeys.length; j++) {
          if (!Object.prototype.hasOwnProperty.call(_plainEnv, allKeys[j])) {
            _plainEnv[allKeys[j]] = '' + all[allKeys[j]];
          }
        }
      }
      globalThis.process.__exactPlainEnv = _plainEnv;
    })();
  }

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

  // Ensure process has EventEmitter-style helpers in Node-compat suites.
  // Node fixtures expect `process.on`, `emit`, etc. before any stream API
  // is imported, but stream enhancements are loaded lazily. Eagerly trigger
  // the enhancer here so Node compatibility tests get the standard hooks.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    typeof globalThis.__exactEnsureStreamEnhance === 'function' &&
    (typeof globalThis.process.on !== 'function' ||
      !globalThis.process.config)
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

    try {
      __exactPatchProcessStreamPrototype();
      if (!globalThis.process.__exactStreamStabilityPatched) {
        __exactPinStream('stdout');
        __exactPinStream('stderr');
        __exactPinStream('stdin');
        globalThis.process.__exactStreamStabilityPatched = true;
      }
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
      globalThis.process.chdir = function chdir(directory) {
        if (typeof directory !== 'string') {
          var te = new TypeError('The "directory" argument must be of type string. Received type ' + typeof directory);
          te.code = 'ERR_INVALID_ARG_TYPE';
          throw te;
        }
        try {
          if (typeof __exactSetCwd === 'function') {
            __exactSetCwd(directory);
            return;
          }
          var currentChdir = globalThis.process && globalThis.process.chdir;
          if (typeof currentChdir === 'function' && currentChdir !== chdir && currentChdir !== __nativeChdir) {
            currentChdir.call(globalThis.process, directory);
            return;
          }
          if (typeof __nativeChdir === 'function') {
            __nativeChdir.call(globalThis.process, directory);
            return;
          }
        } catch (e) {
          var currentDir = '/';
          try { currentDir = typeof __nativeCwd === 'function' ? __nativeCwd.call(globalThis.process) : (typeof __exactGetCwd === 'function' ? __exactGetCwd() : '/'); } catch (_) {}
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

      var processVersions = globalThis.process.versions;
      processVersions = processVersions && typeof processVersions === 'object'
        ? processVersions
        : {};
      var patchedVersions = {
        node: processVersions.node || '24.13.1',
        v8: processVersions.v8 || '0.0.0',
        uv: processVersions.uv || '0.0.0',
        zlib: processVersions.zlib || '1.3.1',
        brotli: processVersions.brotli || '0.0.0',
        ares: processVersions.ares || '0.0.0',
        modules: processVersions.modules || '127',
        nghttp2: processVersions.nghttp2 || '0.0.0',
        napi: processVersions.napi || '9',
        llhttp: processVersions.llhttp || '0.0.0',
        uvwasi: processVersions.uvwasi || '0.0.0',
        unicode: processVersions.unicode || '15.1',
        openssl: processVersions.openssl || '3.0.0',
        hermes: processVersions.hermes || '0.12.0',
        exact: processVersions.exact || '0.1.0'
      };
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

      if (processVersions.node) {
        globalThis.process.version = 'v' + String(processVersions.node).replace(/^v/, '');
      }
      // Node compat: set process.release.name to 'node' for compatibility
      // process is a HostObject, so we need Object.defineProperty to override
      try {
        var existingRelease = globalThis.process.release;
        var releaseObj = (existingRelease && typeof existingRelease === 'object') ?
          Object.assign({}, existingRelease, { name: 'node' }) : { name: 'node' };
        // Determine LTS codename based on reported Node version
        var __nodeVer = processVersions.node || '';
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
        if (typeof contentType === 'string' && contentType.toLowerCase().indexOf('multipart/form-data') === 0) {
          var originalRequestFormData = typeof requestFormData === 'function'
            ? requestFormData
            : __exactFindOriginalFormData(Object.getPrototypeOf(requestProto), requestProto.formData);
          if (typeof originalRequestFormData === 'function') {
            return originalRequestFormData.call(this);
          }
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
        if (typeof contentType === 'string' && contentType.toLowerCase().indexOf('multipart/form-data') === 0) {
          var originalResponseFormData = typeof responseFormData === 'function'
            ? responseFormData
            : __exactFindOriginalFormData(Object.getPrototypeOf(responseProto), responseProto.formData);
          if (typeof originalResponseFormData === 'function') {
            return originalResponseFormData.call(this);
          }
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
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    globalThis.process.env &&
    globalThis.process.env.EXACT_IPC_FD
  ) {
    var exactIpcFd = Number(globalThis.process.env.EXACT_IPC_FD);
    if (isFinite(exactIpcFd) && exactIpcFd >= 0) {
      // Ensure FS host functions are loaded (they are lazily initialized)
      if (typeof globalThis.__exactEnsureFs === 'function') {
        globalThis.__exactEnsureFs();
      }
      var exactIpcBuffer = '';
      var exactIpcConnected = true;
      var exactIpcPollTimer = null;
      var exactIpcPollActive = true;
      var exactIpcPollInterval = 10;

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

      function exactBuildIpcPacket(type, data) {
        return JSON.stringify({ __exactIpc: true, type: type, data: data }) + '\n';
      }

      function exactCreateIpcError(code, message) {
        var err = new Error(message);
        err.code = code;
        return err;
      }

      function exactCloseIpc() {
        if (!exactIpcConnected) return;
        exactIpcConnected = false;
        exactIpcPollActive = false;
        if (exactIpcPollTimer) {
          clearTimeout(exactIpcPollTimer);
          exactIpcPollTimer = null;
        }
        globalThis.process.connected = false;
        globalThis.process.channel = null;
        globalThis.process[Symbol.for('kChannelHandle')] = null;
        if (typeof globalThis.__exactFsClose === 'function') {
          try {
            globalThis.__exactFsClose(exactIpcFd);
          } catch (err) {}
        }
        setTimeout(function() {
          globalThis.process.emit('disconnect');
        }, 0);
      }

      var _exactPendingRecvFd = -1;

      function exactProcessIncomingPackets(rawData, recvFd) {
        if (typeof recvFd === 'number' && recvFd >= 0) {
          _exactPendingRecvFd = recvFd;
        }
        if (!rawData || !rawData.length) return;
        exactIpcBuffer += exactToString(rawData);
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
          if (!packet || packet.__exactIpc !== true) continue;
          if (packet.type === 'message') {
            // Reconstruct handle from received fd if present
            var handle = null;
            if (packet.handleType && _exactPendingRecvFd >= 0) {
              handle = exactReconstructHandle(packet.handleType, _exactPendingRecvFd);
              _exactPendingRecvFd = -1;
            }
            if (handle) {
              globalThis.process.emit('message', packet.data, handle);
            } else {
              globalThis.process.emit('message', packet.data);
            }
          } else if (packet.type === 'disconnect') {
            exactCloseIpc();
          }
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
          } else if (handleType === 'net.Server') {
            if (typeof globalThis.__exactTcpFromFd === 'function') {
              var nativeHandle = globalThis.__exactTcpFromFd(fd);
              var server = net.createServer();
              server._handle = { _exactHandle: nativeHandle, close: function() {
                try { globalThis.__exactTcpClose(nativeHandle); } catch(e) {}
              }};
              return server;
            }
            var server = net.createServer();
            server._handle = { fd: fd };
            try { server.listen({ fd: fd }); } catch (e) {}
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
        if (exactIpcPollTimer && typeof exactIpcPollTimer.unref === 'function') {
          exactIpcPollTimer.unref();
        }
      }
      globalThis.process.channel = {
        fd: exactIpcFd,
        ref: function() { exactRefIpcTimer(); },
        unref: function() { exactUnrefIpcTimer(); }
      };
      // Expose kChannelHandle for internal/child_process compatibility
      var kChannelHandle = Symbol.for('kChannelHandle');
      globalThis.process[kChannelHandle] = {
        readStop: function() {
          exactIpcPollActive = false;
          if (exactIpcPollTimer) {
            clearTimeout(exactIpcPollTimer);
            exactIpcPollTimer = null;
          }
        },
        readStart: function() {
          if (!exactIpcPollActive) {
            exactIpcPollActive = true;
            exactPollIpc();
          }
        }
      };
      // Auto-ref IPC timer when process gets message/disconnect listeners,
      // and auto-unref when all such listeners are removed.
      var exactIpcListenerCount = 0;
      var _origProcessOn = globalThis.process.on;
      var _origProcessOnce = globalThis.process.once;
      var _origProcessRemoveListener = globalThis.process.removeListener;
      if (typeof _origProcessOn === 'function') {
        globalThis.process.on = function(event, listener) {
          var result = _origProcessOn.apply(this, arguments);
          if (event === 'message' || event === 'disconnect') {
            exactIpcListenerCount++;
            exactRefIpcTimer();
          }
          return result;
        };
        globalThis.process.addListener = globalThis.process.on;
      }
      // Hook process.once because EventEmitter.once may not call through
      // process.on (it may call the prototype method directly).
      if (typeof _origProcessOnce === 'function') {
        globalThis.process.once = function(event, listener) {
          if (event === 'message' || event === 'disconnect') {
            exactIpcListenerCount++;
            exactRefIpcTimer();
            var wrappedListener = function() {
              exactIpcListenerCount--;
              if (exactIpcListenerCount <= 0) {
                exactIpcListenerCount = 0;
                exactUnrefIpcTimer();
              }
              return listener.apply(this, arguments);
            };
            return _origProcessOnce.call(this, event, wrappedListener);
          }
          return _origProcessOnce.apply(this, arguments);
        };
      }
      if (typeof _origProcessRemoveListener === 'function') {
        globalThis.process.removeListener = function(event, listener) {
          var result = _origProcessRemoveListener.apply(this, arguments);
          if (event === 'message' || event === 'disconnect') {
            exactIpcListenerCount--;
            if (exactIpcListenerCount <= 0) {
              exactIpcListenerCount = 0;
              exactUnrefIpcTimer();
            }
          }
          return result;
        };
        globalThis.process.off = globalThis.process.removeListener;
      }
      globalThis.process.send = function(message, sendHandle, opts, callback) {
        // Validate message argument
        if (message === undefined) {
          var missingErr = new TypeError('The "message" argument must be specified');
          missingErr.code = 'ERR_MISSING_ARGS';
          throw missingErr;
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
        // Validate sendHandle
        if (sendHandle != null && sendHandle !== false) {
          if (typeof sendHandle !== 'object' && typeof sendHandle !== 'function') {
            var handleErr = new TypeError("This handle type can't be sent");
            handleErr.code = 'ERR_INVALID_HANDLE_TYPE';
            throw handleErr;
          }
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
          } else {
            var hn = sendHandle.constructor && sendHandle.constructor.name;
            if (hn === 'Server') handleType = 'net.Server';
            else handleType = 'net.Socket';
          }
        }
        var pktObj = { __exactIpc: true, type: 'message', data: message };
        if (handleType) pktObj.handleType = handleType;
        var packet = JSON.stringify(pktObj) + '\n';
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
          var isServerHandle = handleType === 'net.Server';
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
    }
  }

  // When running compat tests, auto-load bun:test so test/describe/it/expect
  // globals are available even if the test file doesn't explicitly import them.
  // This matches Bun's behavior where these globals are always present.
  if (
    typeof globalThis.process === 'object' &&
    globalThis.process !== null &&
    globalThis.process.env &&
    globalThis.process.env.EXACT_COMPAT_TEST === '1' &&
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
    var wrapper = Object.create(null);
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
          // Wrap the reader's read() to return proper-prototype objects
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

      // Wrap Symbol.asyncIterator and values() to return iterator wrappers
      // so that next()/return()/throw() results have Object.prototype.
      var asyncIterKey = typeof Symbol !== 'undefined' && Symbol.asyncIterator ? Symbol.asyncIterator : null;
      var originalValues = readableStreamPrototype.values;
      if (typeof originalValues === 'function') {
        readableStreamPrototype.values = function patchedValues(options) {
          var iter;
          if (arguments.length === 0) {
            iter = originalValues.call(this);
          } else {
            iter = originalValues.call(this, options);
          }
          return _makeAsyncIterWrapper(iter);
        };
      }
      if (asyncIterKey && typeof readableStreamPrototype[asyncIterKey] === 'function') {
        var origAsyncIter = readableStreamPrototype[asyncIterKey];
        readableStreamPrototype[asyncIterKey] = function patchedAsyncIterator(options) {
          var iter;
          if (arguments.length === 0) {
            iter = origAsyncIter.call(this);
          } else {
            iter = origAsyncIter.call(this, options);
          }
          return _makeAsyncIterWrapper(iter);
        };
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
})();
