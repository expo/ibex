(function() {
  'use strict';
  var p = globalThis.process;
  var setTimeout = globalThis.setTimeout;
  var clearTimeout = globalThis.clearTimeout;
  function _getStreamFsModule() {
    if (typeof require !== 'function') return null;
    try {
      var candidate = require('fs');
      return candidate && typeof candidate.writeSync === 'function' ? candidate : null;
    } catch (_) {
      return null;
    }
  }
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
    var _streamFsWriteReady = false;
    addEventEmitter(stream);

    function ensureFsReady() {
      if (_streamFsWriteReady) return;
      if (typeof globalThis === 'object' &&
          globalThis !== null &&
          typeof globalThis.__exactEnsureFs === 'function') {
        try {
          globalThis.__exactEnsureFs();
        } catch (_) {}
      }
      _streamFsWriteReady = true;
    }

    function normalizeWritableChunk(chunk) {
      if (typeof chunk === 'string' || chunk == null) {
        return chunk;
      }
      if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
        return chunk;
      }
      if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
        return chunk;
      }
      if (typeof ArrayBuffer === 'function' && chunk instanceof ArrayBuffer) {
        return new Uint8Array(chunk);
      }
      if (typeof chunk !== 'object') {
        return String(chunk);
      }
      return chunk;
    }

    function writeViaFs(chunk) {
      if ((stream === p.stdout || stream === p.stderr) && typeof origWrite === 'function') {
        return false;
      }
      if (typeof stream.fd !== 'number') {
        return false;
      }

      ensureFsReady();

      var fsMod = _getStreamFsModule();
      if (fsMod && typeof fsMod.writeSync === 'function') {
        fsMod.writeSync(stream.fd, chunk);
        return true;
      }

      var fsHostWrite =
        (typeof globalThis === 'object' &&
        globalThis !== null &&
        typeof globalThis.__exactFsWrite === 'function')
        ? globalThis.__exactFsWrite
        : null;
      if (fsHostWrite) {
        fsHostWrite(stream.fd, chunk, -1);
        return true;
      }

      return false;
    }

    function scheduleWritableDrain() {
      if (stream._exactDrainScheduled) return;
      stream._exactDrainScheduled = true;
      setTimeout(function() {
        stream._exactDrainScheduled = false;
        if (!stream.destroyed && stream.writable && !stream.writableEnded) {
          stream.emit('drain');
        }
      }, 0);
    }

    stream.writable = true;
    stream.writableEnded = false;
    stream.writableFinished = false;
    stream.destroyed = false;
    if (typeof stream.ref !== 'function') {
      stream.ref = function() { return stream; };
    }
    if (typeof stream.unref !== 'function') {
      stream.unref = function() { return stream; };
    }

    // Wrap native write to ensure callback support and coerce non-strings
    // Mark with __exactNativeWrite so console-enhance can detect if write was replaced (hijacked)
    var _exactWriteImpl = function(chunk, encoding, callback) {
      if (typeof encoding === 'function') {
        callback = encoding;
        encoding = undefined;
      }
      // Honor the encoding argument: the fs/native write paths treat strings
      // as UTF-8, so write('aGVsbG8=', 'base64') must be converted to bytes
      // here or the literal base64 text is emitted (ENG-23132).
      if (typeof chunk === 'string' && typeof encoding === 'string' &&
          encoding !== '' && encoding !== 'utf8' && encoding !== 'utf-8') {
        if (typeof Buffer !== 'undefined' && Buffer.from) {
          try {
            chunk = Buffer.from(chunk, encoding);
            encoding = undefined;
          } catch (_) {}
        }
      }
      chunk = normalizeWritableChunk(chunk);
      try {
        if (writeViaFs(chunk)) {
          if (typeof callback === 'function') callback();
          return true;
        }
      } catch (_) {
        try {
          var fallbackResult = origWrite.call(stream, chunk, encoding, callback);
          if (fallbackResult === false) {
            scheduleWritableDrain();
          }
          return fallbackResult;
        } catch (_) {
          if (typeof callback === 'function') callback();
          return false;
        }
      }
      var writeResult = origWrite.call(stream, chunk, encoding, callback);
      if (writeResult === false) {
        scheduleWritableDrain();
      }
      return writeResult;
    };
    _exactWriteImpl.__exactNativeWrite = true;
    stream.write = _exactWriteImpl;

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
          var data = __exactStdinRead(262144);
          if (data === null) {
            // No data available, poll again
            stream._pollTimer = setTimeout(pollStdin, 1);
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
              stream._pollTimer = setTimeout(pollStdin, 0);
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
        var data = __exactStdinRead(size || 262144);
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
    if (typeof stream.ref !== 'function') {
      stream.ref = function() { return stream; };
    }
    if (typeof stream.unref !== 'function') {
      stream.unref = function() { return stream; };
    }
    stream.readableEncoding = null;
    stream.readableEnded = false;
    stream.readableFlowing = null;
    stream.readableHighWaterMark = 16384;
    stream.readableLength = 0;
    stream.readableObjectMode = false;

    stream.constructor = { name: 'ReadStream' };

    // Auto-start polling when 'data' listener is added
    var _origStdinOn = stream.on;
    var _origStdinOnce = stream.once;
    stream.on = function(event, fn) {
      _origStdinOn.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return stream;
    };
    stream.addListener = stream.on;
    stream.once = function(event, fn) {
      _origStdinOnce.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return stream;
    };
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
  try {
    p.stdout = _stdout;
    p.stderr = _stderr;
    p.stdin = _stdin;
  } catch(e) {}

  // --- Make process itself an EventEmitter ---
  addEventEmitter(p);

  try {
    var ProcessEventsCtor = require('events');
    ProcessEventsCtor = ProcessEventsCtor && (ProcessEventsCtor.EventEmitter || ProcessEventsCtor.default || ProcessEventsCtor);
    var processProto = Object.getPrototypeOf(p);
    if (typeof ProcessEventsCtor === 'function' && processProto && !(processProto instanceof ProcessEventsCtor)) {
      var patchedProcessProto = Object.create(ProcessEventsCtor.prototype);
      var processDescriptors = Object.getOwnPropertyDescriptors(processProto);
      delete processDescriptors.constructor;
      try {
        Object.defineProperties(patchedProcessProto, processDescriptors);
      } catch (err) {
        var processDescriptorKeys = Object.keys(processDescriptors);
        for (var pdi = 0; pdi < processDescriptorKeys.length; pdi++) {
          try {
            Object.defineProperty(patchedProcessProto, processDescriptorKeys[pdi], processDescriptors[processDescriptorKeys[pdi]]);
          } catch (err2) {}
        }
      }
      try {
        Object.defineProperty(patchedProcessProto, 'constructor', {
          value: p.constructor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (err) {}
      try {
        if (p.constructor && p.constructor.prototype !== patchedProcessProto) {
          p.constructor.prototype = patchedProcessProto;
        }
      } catch (err) {}
      try {
        Object.setPrototypeOf(p, patchedProcessProto);
      } catch (err) {}
    }
  } catch (err) {}

  // process.on('exit') — fire exit hooks before process exits
  var origExit = p.exit;
  if (!origExit || !origExit.__exactHostExit) {
    p.exit = function(code) {
      var currentProcess = (this && this !== null && typeof this === 'object') ? this : p;
      if (!currentProcess) return;
      if (code === undefined) {
        code = currentProcess.exitCode || 0;
      }
      currentProcess.exitCode = code;
      if (currentProcess._exactExiting) {
        return;
      }
      currentProcess._exactExiting = true;
      try { currentProcess.emit('exit', code); } catch(e) {}
      var finalCode = currentProcess.exitCode || 0;
      if (origExit && origExit.__exactHostExit) {
        return origExit.call(currentProcess, finalCode);
      }
      if (typeof globalThis.__exactExit === 'function') {
        return globalThis.__exactExit(finalCode);
      }
      if (origExit) {
        return origExit.call(currentProcess, finalCode);
      }
    };
  }

  // process.exitCode — settable exit code
  if (p.exitCode === undefined) p.exitCode = 0;

  // process.openStdin() - legacy method that returns process.stdin and resumes it
  p.openStdin = function() {
    p.stdin.resume();
    return p.stdin;
  };

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
      var err = new TypeError('The "fn" argument must be of type function or null. Received type ' + typeof fn + ' (' + String(fn) + ')');
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (fn !== null && _uncaughtCaptureCb !== null) {
      var err2 = new Error('process.setupUncaughtExceptionCapture() was called while a capture callback was already active');
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
      return {
        rss: 1024 * 1024,
        heapTotal: 512 * 1024,
        heapUsed: 256 * 1024,
        external: 0,
        arrayBuffers: 0
      };
    };
  }
  if (typeof p.memoryUsage === 'function' && typeof p.memoryUsage.rss !== 'function') {
    p.memoryUsage.rss = function() {
      var usage = p.memoryUsage();
      if (usage && typeof usage.rss === 'number' && usage.rss > 0) {
        return usage.rss;
      }
      return 1024 * 1024;
    };
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
    if (typeof globalThis.__exactShouldSuppressUnhandledRejection === 'function') {
      try {
        if (globalThis.__exactShouldSuppressUnhandledRejection(reason, promise)) {
          return true;
        }
      } catch (_suppressionErr) {}
    }
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

  // --- Signal handling (ENG-23234) ---
  // ONE live dispatch path: __exactTrapSignal installs the native sigaction,
  // the native self-pipe watcher wakes the event loop through the same
  // cross-thread callback push fetch/WS/HTTP use, and the pushed callback
  // invokes __exactDispatchPendingSignals below to drain pending signal
  // numbers and emit on the *current* globalThis.process (the shared runtime
  // bundle replaces the process object after this file runs). There is no JS
  // poll timer, so signal watching never keeps the process alive (ENG-23132)
  // and dispatch latency is one event-loop wake, not a 100ms poll tick.
  //
  // The name->number map comes from __exactSignalNumbers (compiled kernel
  // constants — the previous hardcoded table used Linux numbers, so trapping
  // SIGUSR2 (12) actually trapped SIGSYS on Darwin). The platform-branched
  // fallback below only serves natives older than that host function.
  // SIGKILL/SIGSTOP are absent everywhere: untrappable by the kernel.
  var _signals = null;
  if (typeof __exactSignalNumbers === 'function') {
    try { _signals = __exactSignalNumbers(); } catch (_) {}
  }
  if (!_signals) {
    var _sigPlatform = (p && p.platform) || 'darwin';
    _signals = (_sigPlatform === 'linux' || _sigPlatform === 'android')
      ? { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
          SIGBUS: 7, SIGFPE: 8, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12,
          SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGCHLD: 17, SIGCONT: 18,
          SIGTSTP: 20, SIGTTIN: 21, SIGTTOU: 22, SIGURG: 23, SIGXCPU: 24,
          SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27, SIGWINCH: 28, SIGIO: 29,
          SIGSYS: 31 }
      : { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
          SIGFPE: 8, SIGBUS: 10, SIGSEGV: 11, SIGSYS: 12, SIGPIPE: 13,
          SIGALRM: 14, SIGTERM: 15, SIGURG: 16, SIGTSTP: 18, SIGCONT: 19,
          SIGCHLD: 20, SIGTTIN: 21, SIGTTOU: 22, SIGIO: 23, SIGXCPU: 24,
          SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27, SIGWINCH: 28, SIGINFO: 29,
          SIGUSR1: 30, SIGUSR2: 31 };
  }
  // Published as the shared table so other layers stop growing hand-copied
  // Linux/Darwin variants (child-process.js's _signalMap predates this).
  globalThis.__exactSignalNumbersMap = _signals;
  var _signalNames = {};
  for (var _sk in _signals) _signalNames[_signals[_sk]] = _sk;

  var _trappedSignals = {};
  // Checked lazily so wiring still works if the trap host functions are
  // installed after this bootstrap evaluates.
  function _signalTrapEnabled() {
    return typeof globalThis.__exactTrapSignal === 'function' &&
           typeof globalThis.__exactPollSignal === 'function';
  }

  // Drain every pending signal delivery. Runs on the runtime thread via the
  // native watcher's pushed callback; also safe to call directly.
  globalThis.__exactDispatchPendingSignals = function() {
    if (typeof __exactPollSignal !== 'function') return;
    for (;;) {
      var sig = 0;
      try { sig = __exactPollSignal(); } catch (_) { return; }
      if (!(sig > 0)) return;
      var name = _signalNames[sig];
      var proc = globalThis.process;
      var hasListener = false;
      if (name && proc && typeof proc.listenerCount === 'function' &&
          typeof proc.emit === 'function') {
        try { hasListener = proc.listenerCount(name) > 0; } catch (_) {}
      }
      if (hasListener) {
        try {
          proc.emit(name, name);
        } catch (emitErr) {
          // A throwing signal handler is an uncaughtException (the caller
          // routes it), but the remaining pending signals must still be
          // dispatched — schedule a follow-up drain before rethrowing.
          try { setTimeout(globalThis.__exactDispatchPendingSignals, 0); } catch (_) {}
          throw emitErr;
        }
      } else {
        // Trap armed but no JS listener (e.g. removed in a race): restore the
        // default disposition and re-deliver so the OS default applies.
        if (name) _trappedSignals[name] = false;
        if (typeof __exactResetSignal === 'function') {
          try { __exactResetSignal(sig); } catch (_) {}
        }
        if (proc && typeof proc.kill === 'function' &&
            typeof proc.pid === 'number' && proc.pid > 0) {
          try { proc.kill(proc.pid, sig); } catch (_) {}
        }
      }
    }
  };

  // Reconcile the native trap for `event` (or all signal names when called
  // with no argument) against the CURRENT process object's listener count:
  // first listener installs the sigaction, last removal restores SIG_DFL so
  // the default disposition (e.g. SIGINT kills) comes back — Node semantics.
  // Called from the wrappers below (legacy path) and from the shared runtime
  // bundle's Process emitter, whichever object ends up as globalThis.process.
  globalThis.__exactSignalWatchSync = function(event) {
    if (!_signalTrapEnabled()) return;
    var proc = globalThis.process;
    if (!proc || typeof proc.listenerCount !== 'function') return;
    var names;
    if (event === undefined) {
      names = [];
      for (var k in _signals) names.push(k);
    } else {
      if (!_signals[event]) return;
      names = [event];
    }
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var num = _signals[name];
      if (!num) continue;
      var want = false;
      try { want = proc.listenerCount(name) > 0; } catch (_) {}
      if (want && !_trappedSignals[name]) {
        _trappedSignals[name] = true;
        try { __exactTrapSignal(num); } catch (_) { _trappedSignals[name] = false; }
      } else if (!want && _trappedSignals[name]) {
        _trappedSignals[name] = false;
        if (typeof __exactResetSignal === 'function') {
          try { __exactResetSignal(num); } catch (_) {}
        }
      }
    }
  };

  var _origOn = p.on;
  p.on = function(event, fn) {
    _origOn.call(p, event, fn);
    if ((event === 'message' || event === 'disconnect') &&
        p.channel && typeof p.channel.ref === 'function') {
      p.channel.ref();
    }
    if (_signals[event]) {
      globalThis.__exactSignalWatchSync(event);
    }
    return p;
  };
  p.addListener = p.on;
  if (typeof p.removeListener === 'function') {
    var _origSignalRemoveListener = p.removeListener;
    p.removeListener = function(event) {
      var result = _origSignalRemoveListener.apply(p, arguments);
      if (_signals[event]) {
        globalThis.__exactSignalWatchSync(event);
      }
      return result;
    };
    if (typeof p.off === 'function') {
      p.off = p.removeListener;
    }
  }
  if (typeof p.removeAllListeners === 'function') {
    var _origSignalRemoveAll = p.removeAllListeners;
    p.removeAllListeners = function(event) {
      var result = _origSignalRemoveAll.apply(p, arguments);
      if (event === undefined) {
        globalThis.__exactSignalWatchSync();
      } else if (_signals[event]) {
        globalThis.__exactSignalWatchSync(event);
      }
      return result;
    };
  }
  if (typeof p.once === 'function') {
    var _origOnce = p.once;
    p.once = function(event, fn) {
      if ((event === 'message' || event === 'disconnect') &&
          p.channel && typeof p.channel.ref === 'function') {
        p.channel.ref();
      }
      var result = _origOnce.call(p, event, fn);
      if (_signals[event]) {
        globalThis.__exactSignalWatchSync(event);
      }
      return result;
    };
  }

  function exactCreateBootstrapIpcError(code, message) {
    var err = new Error(message);
    err.code = code;
    return err;
  }

  function exactBootstrapIpcPacket(type, data) {
    return JSON.stringify({ __exactIpc: true, type: type, data: data }) + '\n';
  }

  // Outbound backpressure queue for the early IPC shim (ENG-23132): the IPC
  // fd is O_NONBLOCK, so a single write can be partial (or 0 on EAGAIN).
  // Treating any `> 0` result as success silently drops the packet tail and
  // corrupts the parent's newline framing. Unsent bytes are queued and
  // flushed in order on a timer and before every later send.
  var exactBootstrapIpcPendingWrites = [];
  var exactBootstrapIpcFlushTimer = 0;

  function exactBootstrapIpcPacketToBytes(packet) {
    if (typeof packet !== 'string') return packet;
    if (typeof Buffer === 'function' && Buffer.from) {
      try { return Buffer.from(packet, 'utf8'); } catch (_) {}
    }
    if (typeof TextEncoder === 'function') {
      try { return new TextEncoder().encode(packet); } catch (_) {}
    }
    return packet;
  }

  function exactBootstrapIpcSlice(bytes, offset) {
    if (!bytes || offset <= 0) return bytes;
    if (typeof bytes.subarray === 'function') return bytes.subarray(offset);
    if (typeof bytes.slice === 'function') return bytes.slice(offset);
    return bytes;
  }

  // Returns bytes written (0 on EAGAIN) or -1 on hard failure.
  function exactBootstrapIpcWriteChunk(fd, chunk) {
    if (typeof globalThis.__exactFsWrite === 'function') {
      try {
        return globalThis.__exactFsWrite(fd, chunk, -1);
      } catch (_) {
        return -1;
      }
    }
    try {
      var fs = require('fs');
      if (fs && typeof fs.writeSync === 'function') {
        return fs.writeSync(fd, chunk);
      }
    } catch (_) {}
    return -1;
  }

  function exactBootstrapFlushIpcWrites() {
    while (exactBootstrapIpcPendingWrites.length > 0) {
      var entry = exactBootstrapIpcPendingWrites[0];
      var total = typeof entry.bytes.byteLength === 'number'
        ? entry.bytes.byteLength
        : entry.bytes.length;
      while (entry.offset < total) {
        var written = exactBootstrapIpcWriteChunk(
          entry.fd, exactBootstrapIpcSlice(entry.bytes, entry.offset));
        if (written < 0) {
          exactBootstrapIpcPendingWrites = [];
          if (exactBootstrapIpcFlushTimer) {
            clearTimeout(exactBootstrapIpcFlushTimer);
            exactBootstrapIpcFlushTimer = 0;
          }
          return false;
        }
        if (!(written > 0)) {
          // EAGAIN: retry shortly; the referenced timer keeps the process
          // alive until queued packets are delivered (Node parity).
          if (!exactBootstrapIpcFlushTimer) {
            exactBootstrapIpcFlushTimer = setTimeout(function() {
              exactBootstrapIpcFlushTimer = 0;
              exactBootstrapFlushIpcWrites();
            }, 2);
          }
          return false;
        }
        entry.offset += written;
      }
      exactBootstrapIpcPendingWrites.shift();
    }
    return true;
  }

  // Returns true when the packet was written or queued for delivery under
  // backpressure; false only when the channel hard-failed and the packet was
  // dropped.
  function exactBootstrapIpcWrite(fd, packet) {
    if (!isFinite(fd) || fd < 0) return false;
    var bytes = exactBootstrapIpcPacketToBytes(packet);
    var total = bytes == null ? 0 :
      (typeof bytes.byteLength === 'number' ? bytes.byteLength : bytes.length);
    if (!total) return true;
    exactBootstrapIpcPendingWrites.push({ fd: fd, bytes: bytes, offset: 0 });
    if (exactBootstrapFlushIpcWrites()) return true;
    // Queue still non-empty: accepted under backpressure. Emptied without
    // success: hard failure.
    return exactBootstrapIpcPendingWrites.length > 0;
  }

  var exactBootstrapIpcDecoder = null;
  function exactBootstrapIpcChunkToString(chunk) {
    if (chunk == null) return '';
    if (typeof chunk === 'string') return chunk;
    // Persistent streaming decode (ENG-23132): a UTF-8 sequence split across
    // two reads must not decode to U+FFFD on each side. Buffers are
    // Uint8Arrays, so they take this path too.
    if (typeof TextDecoder === 'function' &&
        typeof Uint8Array === 'function' &&
        chunk instanceof Uint8Array) {
      try {
        if (exactBootstrapIpcDecoder === null) {
          exactBootstrapIpcDecoder = new TextDecoder('utf-8');
        }
        return exactBootstrapIpcDecoder.decode(chunk, { stream: true });
      } catch (_) {
        exactBootstrapIpcDecoder = null;
      }
    }
    if (typeof Buffer === 'function' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
      return chunk.toString('utf8');
    }
    return String(chunk);
  }

  function exactBootstrapIpcRead(fd) {
    if (!isFinite(fd) || fd < 0) return null;
    if (typeof globalThis.__exactFsRead === 'function') {
      try {
        return globalThis.__exactFsRead(fd, 65536, -1);
      } catch (_) {}
    }
    return null;
  }

  function exactNormalizeBootstrapSendArgs(message, sendHandle, opts, callback) {
    if (message === undefined) {
      var missingErr = new TypeError('The "message" argument must be specified');
      missingErr.code = 'ERR_MISSING_ARGS';
      throw missingErr;
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
        var optsErr = new TypeError('The "options" argument must be of type object. Received ' + opts);
        optsErr.code = 'ERR_INVALID_ARG_TYPE';
        throw optsErr;
      }
    }
    if (callback !== undefined && typeof callback !== 'function') {
      var cbErr = new TypeError('The "callback" argument must be of type function. Received ' + callback);
      cbErr.code = 'ERR_INVALID_ARG_TYPE';
      throw cbErr;
    }
    if (sendHandle != null && sendHandle !== false &&
        typeof sendHandle !== 'object' && typeof sendHandle !== 'function') {
      var handleErr = new TypeError("This handle type can't be sent");
      handleErr.code = 'ERR_INVALID_HANDLE_TYPE';
      throw handleErr;
    }
    return { callback: callback };
  }

  function exactBootstrapSetProcessChannel(target, value) {
    try {
      Object.defineProperty(target, 'channel', {
        value: value,
        writable: true,
        configurable: true,
        enumerable: true
      });
      return;
    } catch (_) {}
    try {
      target.channel = value;
    } catch (_) {}
  }

  // process.channel/process.send are only stubbed when the runtime was not
  // booted with an IPC pipe. Forked child processes get an early shim here,
  // then a fuller implementation later in compat bootstrap. If the compat
  // bootstrap already installed that fuller implementation (stream-enhance
  // loads lazily, so it can run after compat-polyfills), leave it alone —
  // re-installing the early shim would clobber handle passing, advanced
  // serialization, and the listener-tracked channel ref accounting.
  var hasIpcBootstrap = !!(p.env && p.env.EXACT_IPC_FD);
  if (p.__exactProcessIpcBootstrapInstalled) {
    // Fuller IPC implementation already owns process.send/channel.
  } else if (hasIpcBootstrap) {
    var exactBootstrapIpcFd = Number(p.env.EXACT_IPC_FD);
    var exactBootstrapIpcBuffer = '';
    var exactBootstrapIpcPollTimer = 0;
    var exactBootstrapIpcReadPending = false;
    var exactBootstrapIpcPollEnabled = false;
    function exactBootstrapSchedulePoll(delay) {
      if (!p.connected || !exactBootstrapIpcPollEnabled || exactBootstrapIpcReadPending) {
        return;
      }
      if (exactBootstrapIpcPollTimer) {
        clearTimeout(exactBootstrapIpcPollTimer);
      }
      exactBootstrapIpcPollTimer = setTimeout(function() {
        exactBootstrapIpcPollTimer = 0;
        exactBootstrapPollIncoming();
      }, delay);
    }
    function exactBootstrapStartPolling() {
      if (!p.connected || exactBootstrapIpcPollEnabled) {
        return;
      }
      exactBootstrapIpcPollEnabled = true;
      exactBootstrapSchedulePoll(0);
    }
    function exactBootstrapStopPolling() {
      exactBootstrapIpcPollEnabled = false;
      if (exactBootstrapIpcPollTimer) {
        clearTimeout(exactBootstrapIpcPollTimer);
        exactBootstrapIpcPollTimer = 0;
      }
    }
    function exactBootstrapMaybeDecodeBuffer() {
      if (!exactBootstrapIpcBuffer || exactBootstrapIpcBuffer.charCodeAt(0) !== 34) {
        return;
      }
      try {
        var decodedBuffer = JSON.parse(exactBootstrapIpcBuffer);
        if (typeof decodedBuffer === 'string') {
          exactBootstrapIpcBuffer = decodedBuffer;
        }
      } catch (_) {}
    }
    function exactBootstrapEmitDisconnect() {
      if (!p.connected) return;
      p.connected = false;
      if (p.channel) p.channel.connected = false;
      exactBootstrapStopPolling();
      exactBootstrapSetProcessChannel(p, null);
      setTimeout(function() { p.emit('disconnect'); }, 0);
    }
    function exactBootstrapHandleIncomingLine(line) {
      var packet = null;
      if (!line) return;
      try {
        packet = JSON.parse(line);
      } catch (_) {
        return;
      }
      if (typeof packet === 'string') {
        try {
          packet = JSON.parse(packet);
        } catch (_) {
          return;
        }
      }
      if (!packet || packet.__exactIpc !== true) return;
      if (packet.type === 'message') {
        p.emit('message', packet.data);
        return;
      }
      if (packet.type === 'disconnect') {
        exactBootstrapEmitDisconnect();
      }
    }
    function exactBootstrapDrainIncoming(chunk) {
      var newlineIndex;
      var text = exactBootstrapIpcChunkToString(chunk);
      exactBootstrapIpcBuffer += text;
      exactBootstrapMaybeDecodeBuffer();
      while ((newlineIndex = exactBootstrapIpcBuffer.indexOf('\n')) !== -1) {
        var line = exactBootstrapIpcBuffer.slice(0, newlineIndex);
        exactBootstrapIpcBuffer = exactBootstrapIpcBuffer.slice(newlineIndex + 1);
        exactBootstrapHandleIncomingLine(line);
        exactBootstrapMaybeDecodeBuffer();
      }
    }
    function exactBootstrapPollIncoming() {
      if (!p.connected || !exactBootstrapIpcPollEnabled) return;
      var chunk = exactBootstrapIpcRead(exactBootstrapIpcFd);
      if (chunk != null) {
        if (chunk.length) {
          exactBootstrapDrainIncoming(chunk);
        }
        exactBootstrapSchedulePoll(10);
        return;
      }
      try {
        var fs = require('fs');
        var BufferCtor = typeof Buffer === 'function' ? Buffer : null;
        if (fs && BufferCtor && typeof fs.read === 'function') {
          var buf = BufferCtor.alloc(65536);
          exactBootstrapIpcReadPending = true;
          fs.read(exactBootstrapIpcFd, buf, 0, buf.length, null, function(err, bytesRead) {
            exactBootstrapIpcReadPending = false;
            if (!p.connected) return;
            if (!err && bytesRead > 0) {
              exactBootstrapDrainIncoming(buf.subarray(0, bytesRead));
            }
            exactBootstrapSchedulePoll(10);
          });
          return;
        }
      } catch (_) {}
      exactBootstrapSchedulePoll(10);
    }
    p.connected = true;
    exactBootstrapSetProcessChannel(p, {
      fd: exactBootstrapIpcFd,
      connected: true,
      ref: function() {
        exactBootstrapStartPolling();
      },
      unref: function() {
        exactBootstrapStopPolling();
      }
    });
    p.send = function(message, sendHandle, opts, callback) {
      var normalized = exactNormalizeBootstrapSendArgs(message, sendHandle, opts, callback);
      if (!p.connected) {
        var disconnectedErr = exactCreateBootstrapIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is closed');
        if (typeof normalized.callback === 'function') {
          setTimeout(function() { normalized.callback(disconnectedErr); }, 0);
        }
        return false;
      }
      var written = false;
      written = exactBootstrapIpcWrite(
        exactBootstrapIpcFd,
        exactBootstrapIpcPacket('message', message)
      );
      if (typeof normalized.callback === 'function') {
        setTimeout(function() {
          normalized.callback(
            written ? null :
              exactCreateBootstrapIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed')
          );
        }, 0);
      }
      return written;
    };
    p.disconnect = function() {
      if (!p.connected) {
        throw exactCreateBootstrapIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
      }
      exactBootstrapIpcWrite(
        exactBootstrapIpcFd,
        exactBootstrapIpcPacket('disconnect')
      );
      exactBootstrapEmitDisconnect();
    };
  } else {
    exactBootstrapSetProcessChannel(p, undefined);
    p.connected = false;
    p.disconnect = function() {};
    p.send = function() { return false; };
  }

  // process.versions — many packages check process.versions.node
  if (!p.versions || !p.versions.node) {
    var compatibilityVersions = {};
    var versionEntries = [
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
    for (var vi = 0; vi < versionEntries.length; vi++) {
      Object.defineProperty(compatibilityVersions, versionEntries[vi][0], {
        value: versionEntries[vi][1],
        writable: false,
        enumerable: true,
        configurable: true
      });
    }
    Object.defineProperty(compatibilityVersions, 'hermes', {
      value: '1.0.0',
      writable: true,
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(compatibilityVersions, 'exact', {
      value: '0.1.0',
      writable: true,
      enumerable: false,
      configurable: true
    });
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
