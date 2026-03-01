(function() {
  'use strict';
  var p = globalThis.process;
  var setTimeout = globalThis.setTimeout;
  var clearTimeout = globalThis.clearTimeout;
  if (!p) return;

  // --- Minimal EventEmitter mixin ---
  function addEventEmitter(obj) {
    var listeners = Object.create(null);
    obj.on = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: false });
      return obj;
    };
    obj.addListener = obj.on;
    obj.once = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: true });
      return obj;
    };
    obj.emit = function(event) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      var list = listeners[event];
      if (!list) return false;
      var keep = [];
      for (var j = 0; j < list.length; j++) {
        if (typeof list[j].fn === 'function') {
          list[j].fn.apply(obj, args);
        }
        if (!list[j].once) keep.push(list[j]);
      }
      listeners[event] = keep;
      return true;
    };
    obj.removeListener = function(event, fn) {
      var list = listeners[event];
      if (!list) return obj;
      var keep = [];
      for (var j = 0; j < list.length; j++) {
        if (list[j].fn !== fn) keep.push(list[j]);
      }
      listeners[event] = keep;
      return obj;
    };
    obj.off = obj.removeListener;
    obj.removeAllListeners = function(event) {
      if (event) { listeners[event] = []; } else { listeners = Object.create(null); }
      return obj;
    };
    obj.listenerCount = function(event) {
      return listeners[event] ? listeners[event].length : 0;
    };
    obj.listeners = function(event) {
      var list = listeners[event] || [];
      var result = [];
      for (var j = 0; j < list.length; j++) result.push(list[j].fn);
      return result;
    };
    obj.prependListener = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].unshift({ fn: fn, once: false });
      return obj;
    };
    obj.prependOnceListener = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].unshift({ fn: fn, once: true });
      return obj;
    };
    obj.rawListeners = obj.listeners;
    obj.eventNames = function() {
      var names = [];
      for (var k in listeners) {
        if (listeners[k] && listeners[k].length > 0) names.push(k);
      }
      return names;
    };
    obj.setMaxListeners = function() { return obj; };
    obj.getMaxListeners = function() { return 10; };
  }

  // --- Color depth detection ---
  function getColorDepth(env) {
    env = env || p.env || {};
    if (env.FORCE_COLOR !== undefined) {
      var fc = env.FORCE_COLOR;
      if (fc === '0' || fc === 'false') return 1;
      if (fc === '1' || fc === 'true' || fc === '') return 4;
      if (fc === '2') return 8;
      if (fc === '3') return 24;
    }
    if (env.NO_COLOR !== undefined) return 1;
    if (env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit') return 24;
    if (env.TERM === 'xterm-256color' || env.TERM === 'screen-256color') return 8;
    var term = env.TERM || '';
    if (term === 'dumb') return 1;
    if (term.indexOf('color') !== -1 || term.indexOf('ansi') !== -1 ||
        term.indexOf('xterm') !== -1 || term.indexOf('screen') !== -1 ||
        term.indexOf('vt100') !== -1 || term.indexOf('rxvt') !== -1 ||
        env.COLORTERM) return 4;
    return 1;
  }

  function hasColors(count, env) {
    if (typeof count === 'object' && count !== null) {
      env = count;
      count = 16;
    }
    if (count === undefined) count = 16;
    var depth = getColorDepth(env);
    return Math.pow(2, depth) >= count;
  }

  // --- Enhance writable streams (stdout, stderr) ---
  function enhanceWritable(stream) {
    if (!stream) return;
    var origWrite = stream.write;
    addEventEmitter(stream);

    stream.writable = true;
    stream.writableEnded = false;
    stream.writableFinished = false;
    stream.destroyed = false;

    // Wrap native write to ensure callback support and coerce non-strings
    stream.write = function(chunk, encoding, callback) {
      if (typeof encoding === 'function') {
        callback = encoding;
        encoding = undefined;
      }
      if (typeof chunk !== 'string' && chunk != null) {
        chunk = String(chunk);
      }
      var result = origWrite.call(stream, chunk, encoding, callback);
      return result;
    };

    stream.end = function(chunk, encoding, callback) {
      if (typeof chunk === 'function') {
        callback = chunk;
        chunk = undefined;
        encoding = undefined;
      } else if (typeof encoding === 'function') {
        callback = encoding;
        encoding = undefined;
      }
      if (chunk != null) {
        stream.write(chunk, encoding);
      }
      stream.writable = false;
      stream.writableEnded = true;
      stream.writableFinished = true;
      stream.emit('finish');
      stream.emit('close');
      if (typeof callback === 'function') callback();
      return stream;
    };

    stream._write = function(chunk, encoding, callback) {
      return stream.write(chunk, encoding, callback);
    };

    stream.cork = function() {};
    stream.uncork = function() {};
    stream.setDefaultEncoding = function() { return stream; };

    stream.destroy = function(err) {
      stream.destroyed = true;
      stream.writable = false;
      if (err) stream.emit('error', err);
      stream.emit('close');
      return stream;
    };

    stream.pipe = function() {
      throw new Error('process.stdout cannot be piped to');
    };

    // TTY methods (functional stubs for compatibility)
    stream.clearLine = function(dir, callback) {
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.clearScreenDown = function(callback) {
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.cursorTo = function(x, y, callback) {
      if (typeof y === 'function') { callback = y; }
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.moveCursor = function(dx, dy, callback) {
      if (typeof callback === 'function') callback();
      return true;
    };

    stream.getWindowSize = function() {
      return [stream.columns || 80, stream.rows || 24];
    };

    stream.getColorDepth = function(env) {
      if (!stream.isTTY) return 1;
      return getColorDepth(env);
    };

    stream.hasColors = function(count, env) {
      if (!stream.isTTY) return false;
      return hasColors(count, env);
    };

    // Constructor name for duck-typing checks
    stream.constructor = { name: 'WriteStream' };
  }

  // --- Enhance readable stream (stdin) ---
  function enhanceReadable(stream) {
    if (!stream) return;
    addEventEmitter(stream);

    stream._encoding = null;
    stream._paused = true;
    stream._ended = false;
    stream._pollTimer = 0;

    stream.setEncoding = function(enc) {
      stream._encoding = enc;
      return stream;
    };

    stream.resume = function() {
      stream.readable = true;
      stream._paused = false;
      stream.readableFlowing = true;
      // Start polling for stdin data if we have __exactStdinRead
      if (!stream._ended && typeof __exactStdinRead === 'function' && !stream._pollTimer) {
        (function pollStdin() {
          if (stream._paused || stream._ended || stream.destroyed) return;
          var data = __exactStdinRead(4096);
          if (data === null) {
            // No data available, poll again
            stream._pollTimer = setTimeout(pollStdin, 50);
          } else if (data === '') {
            // EOF
            stream._ended = true;
            stream._pollTimer = 0;
            stream.readableEnded = true;
            stream.emit('end');
            stream.emit('close');
          } else {
            // Got data
            stream.readableLength += data.length;
            stream.emit('data', data);
            stream.readableLength = 0;
            if (!stream._paused && !stream._ended) {
              stream._pollTimer = setTimeout(pollStdin, 10);
            }
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
      if (typeof __exactStdinRead === 'function') {
        var data = __exactStdinRead(size || 4096);
        if (data === '') return null; // EOF
        return data;
      }
      return null;
    };

    stream.pipe = function(dest) {
      stream.on('data', function(chunk) {
        if (dest && typeof dest.write === 'function') {
          var ok = dest.write(chunk);
          if (ok === false) {
            stream.pause();
            dest.once('drain', function() { stream.resume(); });
          }
        }
      });
      stream.on('end', function() {
        if (dest && typeof dest.end === 'function') dest.end();
      });
      return dest;
    };

    stream.unpipe = function() { return stream; };
    stream.unshift = function() {};
    stream.wrap = function() { return stream; };
    stream.destroy = function() {
      stream.readable = false;
      stream.destroyed = true;
      stream._paused = true;
      if (stream._pollTimer) {
        clearTimeout(stream._pollTimer);
        stream._pollTimer = 0;
      }
      stream.emit('close');
      return stream;
    };
    stream.destroyed = false;
    stream.readableEncoding = null;
    stream.readableEnded = false;
    stream.readableFlowing = null;
    stream.readableHighWaterMark = 16384;
    stream.readableLength = 0;
    stream.readableObjectMode = false;

    stream.constructor = { name: 'ReadStream' };

    // Auto-start polling when 'data' listener is added
    var _origStdinOn = stream.on;
    stream.on = function(event, fn) {
      _origStdinOn.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return stream;
    };
    stream.addListener = stream.on;
  }

  // Cache stdout/stderr/stdin as own properties since prototype getters
  // may create new objects on each access
  var _stdout = p.stdout;
  var _stderr = p.stderr;
  var _stdin = p.stdin;
  enhanceWritable(_stdout);
  enhanceWritable(_stderr);
  enhanceReadable(_stdin);
  try {
    Object.defineProperty(p, 'stdout', { value: _stdout, writable: true, configurable: true, enumerable: true });
    Object.defineProperty(p, 'stderr', { value: _stderr, writable: true, configurable: true, enumerable: true });
    Object.defineProperty(p, 'stdin', { value: _stdin, writable: true, configurable: true, enumerable: true });
  } catch(e) {}

  // --- Make process itself an EventEmitter ---
  addEventEmitter(p);

  // process.on('exit') — fire exit hooks before process exits
  var origExit = p.exit;
  if (!origExit || !origExit.__exactHostExit) {
    p.exit = function(code) {
      var currentProcess = (this && this !== null && typeof this === 'object') ? this : p;
      if (!currentProcess) return;
      if (code === undefined) {
        code = currentProcess.exitCode || 0;
      }
      currentProcess._exactExiting = true;
      try { currentProcess.emit('exit', code); } catch(e) {}
      if (origExit) {
        return origExit.call(currentProcess, code);
      }
    };
  }

  // process.exitCode — settable exit code
  if (p.exitCode === undefined) p.exitCode = 0;

  // process.abort()
  p.abort = function() {
    p.exit(134);
  };

  // process.emitWarning()
  p.emitWarning = function(warning, type, code, ctor) {
    var detail;
    if (typeof type === 'object' && type !== null && !Array.isArray(type)) {
      // emitWarning(msg, options)
      code = type.code;
      ctor = type.ctor;
      detail = type.detail;
      type = type.type || 'Warning';
    }
    if (typeof code === 'function') {
      ctor = code;
      code = undefined;
    }
    if (typeof type === 'function') {
      ctor = type;
      type = 'Warning';
      code = undefined;
    }
    // Validate arguments
    if (warning === undefined) {
      var e = new TypeError('The "warning" argument must be of type string or an instance of Error. Received undefined');
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (typeof warning !== 'string' && !(warning instanceof Error)) {
      var e = new TypeError('The "warning" argument must be of type string or an instance of Error. Received type ' + typeof warning);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (type !== undefined && typeof type !== 'string') {
      var e = new TypeError('The "type" argument must be of type string. Received type ' + typeof type);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (code !== undefined && typeof code !== 'string') {
      var e = new TypeError('The "code" argument must be of type string. Received type ' + typeof code);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    var warningObj;
    if (typeof warning === 'string') {
      warningObj = new Error(warning);
      warningObj.name = type || 'Warning';
    } else {
      warningObj = warning;
    }
    if (code) warningObj.code = code;
    if (typeof detail === 'string') warningObj.detail = detail;
    // Emit asynchronously like Node.js
    setTimeout(function() {
      p.emit('warning', warningObj);
    }, 0);
  };

  // process.getActiveResourcesInfo()
  p.getActiveResourcesInfo = function() { return []; };

  // process._getActiveRequests() and process._getActiveHandles()
  p._getActiveRequests = function() { return []; };
  p._getActiveHandles = function() { return []; };

  // process.setUncaughtExceptionCaptureCallback / hasUncaughtExceptionCaptureCallback
  var _uncaughtCaptureCb = null;
  p.setUncaughtExceptionCaptureCallback = function(fn) {
    if (fn !== null && typeof fn !== 'function') {
      var err = new TypeError('The "fn" argument must be one of type function or null. Received type ' + typeof fn);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (fn !== null && _uncaughtCaptureCb !== null) {
      var err2 = new Error('`process.setUncaughtExceptionCaptureCallback()` was called while a capture callback was already active');
      err2.code = 'ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET';
      throw err2;
    }
    _uncaughtCaptureCb = fn;
  };
  p.hasUncaughtExceptionCaptureCallback = function() {
    return _uncaughtCaptureCb !== null;
  };

  // process.features
  if (!p.features) {
    p.features = {
      inspector: false,
      debug: false,
      uv: true,
      ipv6: true,
      tls_alpn: false,
      tls_sni: false,
      tls_ocsp: false,
      tls: false,
    };
  }

  // process.config - frozen object mimicking Node.js build config
  if (!p.config) {
    var _configObj = {
      target_defaults: {},
      variables: {
        v8_enable_i18n_support: 1,
        icu_locales: 'en',
        openssl_is_fips: 0,
        node_module_version: 108,
      },
    };
    Object.freeze(_configObj.target_defaults);
    Object.freeze(_configObj.variables);
    Object.freeze(_configObj);
    p.config = _configObj;
  }

  // process.debugPort
  if (p.debugPort === undefined) {
    p.debugPort = 9229;
  }

  // process.memoryUsage()
  if (!p.memoryUsage) {
    p.memoryUsage = function() {
      return { rss: 0, heapTotal: 0, heapUsed: 0, external: 0, arrayBuffers: 0 };
    };
    p.memoryUsage.rss = function() { return 0; };
  }

  // process.cpuUsage()
  if (!p.cpuUsage) {
    p.cpuUsage = function(prevValue) {
      if (prevValue !== undefined) {
        if (typeof prevValue !== 'object' || prevValue === null || Array.isArray(prevValue)) {
          var e = new TypeError('The "prevValue" argument must be of type object. Received type ' + typeof prevValue + (prevValue !== null ? ' (' + String(prevValue) + ')' : ''));
          e.code = 'ERR_INVALID_ARG_TYPE';
          throw e;
        }
        if (typeof prevValue.user !== 'number') {
          var e = new TypeError('The "prevValue.user" property must be of type number.' + (prevValue.user == null ? ' Received ' + prevValue.user : typeof prevValue.user === 'string' ? ' Received type string (\'' + prevValue.user + '\')' : ' Received type ' + typeof prevValue.user + ' (' + String(prevValue.user) + ')'));
          e.code = 'ERR_INVALID_ARG_TYPE';
          throw e;
        }
        if (typeof prevValue.system !== 'number') {
          var e = new TypeError('The "prevValue.system" property must be of type number.' + (prevValue.system == null ? ' Received ' + prevValue.system : typeof prevValue.system === 'string' ? ' Received type string (\'' + prevValue.system + '\')' : ' Received type ' + typeof prevValue.system + ' (' + String(prevValue.system) + ')'));
          e.code = 'ERR_INVALID_ARG_TYPE';
          throw e;
        }
        if (prevValue.user < 0 || !Number.isFinite(prevValue.user)) {
          var e2 = new RangeError("The property 'prevValue.user' is invalid. Received " + prevValue.user);
          e2.code = 'ERR_INVALID_ARG_VALUE';
          throw e2;
        }
        if (prevValue.system < 0 || !Number.isFinite(prevValue.system)) {
          var e2 = new RangeError("The property 'prevValue.system' is invalid. Received " + prevValue.system);
          e2.code = 'ERR_INVALID_ARG_VALUE';
          throw e2;
        }
      }
      var usage = { user: 0, system: 0 };
      if (prevValue) {
        usage.user = Math.max(0, usage.user - prevValue.user);
        usage.system = Math.max(0, usage.system - prevValue.system);
      }
      return usage;
    };
  }

  // process.resourceUsage()
  if (!p.resourceUsage) {
    p.resourceUsage = function() {
      return {
        userCPUTime: 0, systemCPUTime: 0, maxRSS: 0,
        sharedMemorySize: 0, unsharedDataSize: 0, unsharedStackSize: 0,
        minorPageFault: 0, majorPageFault: 0, swappedOut: 0,
        fsRead: 0, fsWrite: 0, ipcSent: 0, ipcReceived: 0,
        signalsCount: 0, voluntaryContextSwitches: 0, involuntaryContextSwitches: 0,
      };
    };
  }

  // process.uptime()
  if (!p.uptime) {
    var _startTime = Date.now();
    p.uptime = function() {
      return (Date.now() - _startTime) / 1000;
    };
  }

  // process.hrtime() and process.hrtime.bigint()
  if (!p.hrtime) {
    var _hrtimeBase = Date.now();
    p.hrtime = function(prev) {
      var now = Date.now() - _hrtimeBase;
      var secs = Math.floor(now / 1000);
      var nanos = (now % 1000) * 1e6;
      if (prev) {
        var diffSecs = secs - prev[0];
        var diffNanos = nanos - prev[1];
        if (diffNanos < 0) {
          diffSecs -= 1;
          diffNanos += 1e9;
        }
        return [diffSecs, diffNanos];
      }
      return [secs, nanos];
    };
    p.hrtime.bigint = function() {
      var now = Date.now() - _hrtimeBase;
      // BigInt might not be available in all engines
      if (typeof BigInt === 'function') {
        return BigInt(now) * BigInt(1e6);
      }
      return now * 1e6;
    };
  }

  // process.report
  if (!p.report) {
    p.report = {
      writeReport: function() { return ''; },
      getReport: function() { return {}; },
      directory: '',
      filename: '',
      compact: false,
      signal: 'SIGUSR2',
      reportOnFatalError: false,
      reportOnSignal: false,
      reportOnUncaughtException: false,
    };
  }

  // process.allowedNodeEnvironmentFlags
  if (!p.allowedNodeEnvironmentFlags) {
    var _emptyFlags = new Set();
    Object.freeze(_emptyFlags);
    p.allowedNodeEnvironmentFlags = _emptyFlags;
  }

  // process.umask()
  if (!p.umask) {
    var _currentUmask = 0o022;
    p.umask = function(mask) {
      if (mask === undefined) return _currentUmask;
      var old = _currentUmask;
      if (typeof mask === 'string') {
        mask = parseInt(mask, 8);
      }
      if (typeof mask === 'number' && mask === (mask | 0)) {
        _currentUmask = mask & 0o777;
      }
      return old;
    };
  }

  // process.release
  if (!p.release) {
    p.release = {
      name: 'node',
      lts: undefined,
      sourceUrl: '',
      headersUrl: '',
    };
  }

  // --- uncaughtException / unhandledRejection support ---
  // Store a global error handler that the native side can call into.
  // Resolve the current global process at call time to handle cases where the
  // process object is rebound after bootstrap.
  var getProcessForUncaught = function() {
    if (typeof process === 'object' && process !== null) {
      return process;
    }
    return p;
  };
  p._uncaughtExceptionHandler = function(err) {
    var target = getProcessForUncaught();
    if (typeof target.listenerCount === 'function' &&
        target.listenerCount('uncaughtException') > 0 &&
        typeof target.emit === 'function') {
      try {
        target.emit('uncaughtException', err);
        return true; // handled
      } catch (e) {
        // Handler itself threw - fall through to crash
        return false;
      }
    }
    return false; // not handled
  };
  // Expose globally so the native runtime can call it
  globalThis.__exactUncaughtExceptionHandler = p._uncaughtExceptionHandler;

  // unhandledRejection support via Promise rejection tracking
  p._unhandledRejectionHandler = function(reason, promise) {
    if (p.listenerCount('unhandledRejection') > 0) {
      try {
        p.emit('unhandledRejection', reason, promise);
        return true;
      } catch (e) {
        return false;
      }
    }
    return false;
  };
  globalThis.__exactUnhandledRejectionHandler = p._unhandledRejectionHandler;

  // --- Signal handling ---
  // Map signal names to numbers
  var _signals = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGTERM: 15, SIGUSR1: 10, SIGUSR2: 12 };
  var _trappedSignals = {};
  var _signalNames = {};
  var _signalPollEnabled = typeof __exactPollSignal === 'function';
  var _signalPollActive = false;
  var _signalPollTimer = 0;

  if (_signalPollEnabled) {
    for (var _sk in _signals) {
      _signalNames[_signals[_sk]] = _sk;
    }
  }

  function _startSignalPolling() {
    if (!_signalPollEnabled || _signalPollActive) {
      return;
    }

    _signalPollActive = true;

    (function pollSignals() {
      var sig = __exactPollSignal();
      if (sig > 0 && _signalNames[sig]) {
        var name = _signalNames[sig];
        if (p.listenerCount(name) > 0) {
          p.emit(name);
        } else {
          // No listeners, restore default behavior
          if (typeof __exactResetSignal === 'function') {
            __exactResetSignal(sig);
          }
          // Re-raise the signal
          if (p.kill) p.kill(p.pid, sig);
        }
      }

      if (_signalPollActive) {
        _signalPollTimer = setTimeout(pollSignals, 100);
      }
    })();
  }

  var _origOn = p.on;
  p.on = function(event, fn) {
    _origOn.call(p, event, fn);
    // Auto-trap OS signal when first listener is added
    if (_signals[event] && !_trappedSignals[event]) {
      _trappedSignals[event] = true;
      if (typeof __exactTrapSignal === 'function') {
        __exactTrapSignal(_signals[event]);
      }
      if (_signalPollEnabled) {
        _startSignalPolling();
      }
    }
    return p;
  };
  p.addListener = p.on;

  // process.channel — not applicable (no IPC), but stub for compatibility
  p.channel = undefined;
  p.connected = false;
  p.disconnect = function() {};
  p.send = function() { return false; };

  // process.versions — many packages check process.versions.node
  if (!p.versions || !p.versions.node) {
    var compatibilityVersions = {
      node: '24.13.1',
      v8: '0.0.0',
      uv: '0.0.0',
      zlib: '1.3.1',
      brotli: '0.0.0',
      ares: '0.0.0',
      modules: '127',
      nghttp2: '0.0.0',
      napi: '9',
      llhttp: '0.0.0',
      uvwasi: '0.0.0',
      unicode: '15.1',
      openssl: '0.0.0',
      hermes: '0.12.0',
      exact: '0.1.0'
    };
    try {
      Object.defineProperty(p, 'versions', {
        value: compatibilityVersions,
        writable: true,
        enumerable: false,
        configurable: true
      });
    } catch (err) {
      p.versions = compatibilityVersions;
    }
  }

  // process.version
  if (!p.version) p.version = 'v24.13.1';

  // process.execArgv — empty by default
  if (!p.execArgv) p.execArgv = [];

  // process.config stub
  if (!p.config) {
    p.config = { target_defaults: {}, variables: {} };
  }

  // process.features stub
  if (!p.features) {
    p.features = { inspector: true, debug: false, uv: false, ipv6: true, tls_alpn: false, tls_sni: false, tls_ocsp: false, tls: false };
  }

  // process.mainModule (deprecated but still used)
  p.mainModule = undefined;

  // process.binding — stub (deprecated but some old packages use it)
  if (!p.binding) {
    p.binding = function(name) {
      throw new Error("process.binding('" + name + "') is not supported in Exact");
    };
  }

})();
