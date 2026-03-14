var _uvErrnoMapFallback = {
  EACCES: 13,
  EINVAL: 22,
  ENOENT: 2,
  ENOTDIR: 20
};

var _processCwd = "/";

function _stringifyPathPart(path) {
  if (typeof path === 'string') return path;
  if (Buffer.isBuffer && Buffer.isBuffer(path)) return path.toString();
  return String(path);
}

function _normalizeCwdPath(value) {
  var path = _stringifyPathPart(value);
  if (path.length === 0) return "/";
  if (path.charAt(0) === '/') return path;
  return "/" + path;
}

function _resolveCwd(path) {
  if (typeof path === 'string' && (path.charAt(0) === '/' || /^[A-Za-z]:[\\/]/.test(path))) {
    return path;
  }
  var cwd = typeof process === 'object' && process && typeof process.cwd === 'function' ? process.cwd() : "/";
  if (cwd.charAt(cwd.length - 1) !== '/') {
    return cwd + "/" + path;
  }
  return cwd + path;
}

function _readNativeCwd() {
  if (typeof __exactGetCwd !== 'function') {
    return null;
  }
  try {
    var value = __exactGetCwd();
    if (typeof value === 'string' && value.length > 0) {
      return _normalizeCwdPath(value);
    }
  } catch (_) {}
  return null;
}

function cwd() {
  if (_processCwd && _processCwd !== "/") {
    return _processCwd;
  }
  var nativeCwd = _readNativeCwd();
  if (nativeCwd) {
    _processCwd = nativeCwd;
    return _processCwd;
  }
  if (!_processCwd || _processCwd === "/") {
    _processCwd = "/";
  }
  return _processCwd;
}

function _coerceChdirError(err, path) {
  if (err && typeof err.message === 'string') {
    var message = err.message;
    var lower = message.toLowerCase();
    var code;
    if (lower.indexOf('no such file') !== -1 || lower.indexOf('does not exist') !== -1) {
      code = 'ENOENT';
    } else if (lower.indexOf('permission denied') !== -1) {
      code = 'EACCES';
    } else if (lower.indexOf('not a directory') !== -1) {
      code = 'ENOTDIR';
    }
    if (code) {
      var mapped = new Error(message + " '" + path + "'");
      mapped.code = code;
      var fallbackErrno = _uvErrnoMap && _uvErrnoMap[code];
      if (fallbackErrno === undefined) {
        fallbackErrno = _uvErrnoMapFallback[code];
      }
      if (fallbackErrno !== undefined) {
        mapped.errno = -fallbackErrno;
      }
      mapped.syscall = 'chdir';
      mapped.path = cwd();
      mapped.dest = path;
      return mapped;
    }
  }
  var fallback = new Error('process.chdir failed');
  fallback.code = 'EINVAL';
  fallback.syscall = 'chdir';
  fallback.path = cwd();
  fallback.dest = path;
  return fallback;
}

function chdir(path) {
  if (typeof path !== 'string') {
    var err = new TypeError('The "directory" argument must be of type string. Received type ' + typeof path);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  var resolvedPath = _resolveCwd(path);
  if (typeof __exactSetCwd !== 'function') {
    if (typeof __exactAccess === 'function') {
      try {
        __exactAccess(resolvedPath, 0);
      } catch (e) {
        throw _coerceChdirError(e, resolvedPath);
      }
    }
    _processCwd = resolvedPath;
    return;
  }
  try {
    __exactSetCwd(resolvedPath);
    _processCwd = resolvedPath;
  } catch (e) {
    throw _coerceChdirError(e, resolvedPath);
  }
}

var argv = [];
if (typeof globalThis.__exactArgv === "object" && Array.isArray(globalThis.__exactArgv)) {
  argv = globalThis.__exactArgv;
}

var env = {};
var _umask = 0o022;

if (typeof __exactGetAllEnv === 'function') {
  var allEnv = __exactGetAllEnv();
  if (allEnv && typeof allEnv === 'object') {
    env = allEnv;
  } else {
    env = {};
  }
} else {
  env = {
    get: function(key) {
      if (typeof __exactGetEnv !== 'function') {
        return undefined;
      }
      return __exactGetEnv(key);
    }
  };
}

function _inspectValue(v) {
  if (typeof v === 'string') return "'" + v.replace(/\0/g, '\\x00') + "'";
  return String(v);
}

function _installReadableStdinFallback(proc) {
  if (!proc || typeof proc !== 'object' || !proc.stdin || typeof proc.stdin !== 'object') {
    return;
  }
  var stream = proc.stdin;
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
  if (typeof stream.resume === 'function' || typeof __exactStdinRead !== 'function') {
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
      (function pollStdin() {
        if (stream._paused || stream._ended || stream.destroyed) return;
        var data = __exactStdinRead(4096);
        if (data === null) {
          stream._pollTimer = setTimeout(pollStdin, 25);
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
          stream._pollTimer = setTimeout(pollStdin, 10);
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
    var data = __exactStdinRead(size || 4096);
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
    Object.defineProperty(proc, 'stdin', {
      value: stream,
      writable: true,
      configurable: true,
      enumerable: true
    });
  } catch (_) {
    proc.stdin = stream;
  }
}

function execve(execPath, args, envObj) {
  if (typeof execPath !== 'string') {
    var e = new TypeError('The "execPath" argument must be of type string. Received type ' + typeof execPath + ' (' + String(execPath) + ')');
    e.code = 'ERR_INVALID_ARG_TYPE';
    throw e;
  }
  if (!Array.isArray(args)) {
    var e2 = new TypeError('The "args" argument must be an instance of Array. Received type ' + typeof args + ' (' + _inspectValue(args) + ')');
    e2.code = 'ERR_INVALID_ARG_TYPE';
    throw e2;
  }
  for (var i = 0; i < args.length; i++) {
    if (typeof args[i] !== 'string' || args[i].indexOf('\0') !== -1) {
      var e3 = new TypeError("The argument 'args[" + i + "]' must be a string without null bytes. Received " + _inspectValue(args[i]));
      e3.code = 'ERR_INVALID_ARG_VALUE';
      throw e3;
    }
  }
  if (arguments.length >= 3) {
    if (typeof envObj !== 'object' || envObj === null || Array.isArray(envObj)) {
      var e4 = new TypeError('The "env" argument must be of type object. Received type ' + typeof envObj + ' (' + _inspectValue(envObj) + ')');
      e4.code = 'ERR_INVALID_ARG_TYPE';
      throw e4;
    }
    var keys = Object.keys(envObj);
    for (var j = 0; j < keys.length; j++) {
      var val = envObj[keys[j]];
      if (typeof val !== 'string' || val.indexOf('\0') !== -1) {
        var pairs = [];
        for (var k = 0; k < keys.length; k++) {
          pairs.push(keys[k] + ': ' + _inspectValue(envObj[keys[k]]));
        }
        var e5 = new TypeError("The argument 'env' must be an object with string keys and values without null bytes. Received { " + pairs.join(', ') + ' }');
        e5.code = 'ERR_INVALID_ARG_VALUE';
        throw e5;
      }
    }
  }

  var execArgv = (typeof process === 'object' && process && Array.isArray(process.execArgv)) ? process.execArgv : [];
  var permissionMode = false;
  var allowChildProcess = false;
  for (var ai = 0; ai < execArgv.length; ai++) {
    var execArg = String(execArgv[ai]);
    if (execArg === '--permission' || execArg.indexOf('--permission=') === 0) {
      permissionMode = true;
      continue;
    }
    if (execArg === '--allow-child-process' || execArg.indexOf('--allow-child-process=') === 0) {
      allowChildProcess = true;
    }
  }
  if (permissionMode && !allowChildProcess) {
    var deniedError = new Error('Access to this API has been restricted');
    deniedError.code = 'ERR_ACCESS_DENIED';
    deniedError.permission = 'ChildProcess';
    deniedError.resource = execPath;
    throw deniedError;
  }

  var childProcess = require('child_process');
  if (!childProcess || typeof childProcess.spawnSync !== 'function') {
    var unavailableError = new TypeError('process.execve is not supported in this runtime');
    unavailableError.code = 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM';
    throw unavailableError;
  }

  var result = childProcess.spawnSync(execPath, args.slice(1), {
    env: arguments.length >= 3 ? envObj : process.env,
    stdio: 'inherit'
  });
  if (result && result.error) {
    throw result.error;
  }
  if (typeof process.exit === 'function') {
    process.exit(result && typeof result.status === 'number' ? result.status : 0);
  }
}

// Re-export the full globalThis.process object (which has all the C++ properties)
// with cwd/env/argv as fallback overrides
if (typeof globalThis !== 'undefined' && globalThis.process) {
  var proc = globalThis.process;
  {
    // Replace umask with a closure-based implementation that doesn't rely on `this`.
    // The runtime.js Process class method uses `this._umask` which breaks when called
    // detached (var fn = process.umask; fn()). We use process._umask directly.
    if (typeof proc._umask === 'undefined') {
      proc._umask = _umask;
    }
    proc.umask = function umask(mask) {
      if (arguments.length === 0) {
        return proc._umask;
      }
      if (typeof mask === 'string') {
        if (!/^(0o?)?[0-7]+$/i.test(mask)) {
          var ve = new TypeError("[ERR_INVALID_ARG_VALUE]: The argument 'mask' is invalid. Received '" + mask + "'");
          ve.code = 'ERR_INVALID_ARG_VALUE';
          throw ve;
        }
        var stripped = mask.replace(/^0o/i, '').replace(/^0+(?=\d)/, '');
        mask = parseInt(stripped || '0', 8);
      } else if (typeof mask !== 'number' || (mask !== (mask | 0))) {
        var te = new TypeError('[ERR_INVALID_ARG_TYPE]: The "mask" argument must be of type number. Received type ' + typeof mask);
        te.code = 'ERR_INVALID_ARG_TYPE';
        throw te;
      }
      mask = mask & 0o7777;
      var old = proc._umask;
      proc._umask = mask;
      return old;
    };
  }
  // Ensure our module-level cwd/env/argv are present
  proc.chdir = chdir;
  proc.cwd = cwd;
  if (typeof proc.getuid !== 'function') {
    proc.getuid = function getuid() { return 0; };
  }
  if (typeof proc.getgid !== 'function') {
    proc.getgid = function getgid() { return 0; };
  }
  if (typeof proc.geteuid !== 'function') {
    proc.geteuid = function geteuid() {
      return typeof proc.getuid === 'function' ? proc.getuid() : 0;
    };
  }
  if (typeof proc.getegid !== 'function') {
    proc.getegid = function getegid() {
      return typeof proc.getgid === 'function' ? proc.getgid() : 0;
    };
  }
  if (typeof proc.getgroups !== 'function') {
    proc.getgroups = function getgroups() { return [0]; };
  }
  if (typeof proc.kill !== 'function') {
    var _validSignals = [
      'SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT', 'SIGIOT',
      'SIGBUS', 'SIGFPE', 'SIGKILL', 'SIGUSR1', 'SIGSEGV', 'SIGUSR2', 'SIGPIPE',
      'SIGALRM', 'SIGTERM', 'SIGSTKFLT', 'SIGCHLD', 'SIGCONT', 'SIGSTOP',
      'SIGTSTP', 'SIGTTIN', 'SIGTTOU', 'SIGURG', 'SIGXCPU', 'SIGXFSZ',
      'SIGVTALRM', 'SIGPROF', 'SIGWINCH', 'SIGIO', 'SIGPOLL', 'SIGPWR',
      'SIGSYS', 'SIGUNUSED', 'SIGINFO'
    ];
    proc.kill = function kill(pid, signal) {
      if (typeof pid !== 'number' || pid !== (pid | 0)) {
        var te = new TypeError('The "pid" argument must be of type number. Received type ' + typeof pid);
        te.code = 'ERR_INVALID_ARG_TYPE';
        throw te;
      }
      var sig = signal === undefined ? 'SIGTERM' : signal;
      // Validate signal name
      if (typeof sig === 'string' && sig !== '0' && _validSignals.indexOf(sig) === -1) {
        var ue = new Error('Unknown signal: ' + sig);
        ue.code = 'ERR_UNKNOWN_SIGNAL';
        throw ue;
      }
      if (typeof sig === 'number' && (sig < 0 || sig > 31)) {
        var ue2 = new Error('Unknown signal: ' + sig);
        ue2.code = 'ERR_UNKNOWN_SIGNAL';
        throw ue2;
      }
      // Signal 0 is used to test process existence
      if (sig === 0 || sig === '0') {
        if (pid === proc.pid) return true;
        var e = new Error('kill ESRCH');
        e.code = 'ESRCH';
        e.errno = -3;
        e.syscall = 'kill';
        throw e;
      }
      if (pid === proc.pid) return true;
      var e2 = new Error('kill ESRCH');
      e2.code = 'ESRCH';
      e2.errno = -3;
      e2.syscall = 'kill';
      throw e2;
    };
  }
  if (typeof proc.channel === 'undefined' && !('channel' in proc)) {
    proc.channel = undefined;
  }
  if (!proc.argv || proc.argv.length === 0) proc.argv = argv;
  if (!Array.isArray(proc.execArgv)) proc.execArgv = Array.isArray(globalThis.__exactExecArgv) ? globalThis.__exactExecArgv : [];
  if (!proc.execve) proc.execve = execve;
  _installReadableStdinFallback(proc);

  // Wrap process.env in a Proxy that converts values to strings (Node.js behavior)
  // and supports delete
  if (typeof Proxy === 'function') {
    var _rawEnv = proc.env;
    if (!_rawEnv || (typeof _rawEnv === 'object' && Object.keys(_rawEnv).length === 0)) {
      _rawEnv = env;
    }
    if (!_rawEnv.__exactEnvProxy) {
      var _envProxy = new Proxy(_rawEnv, {
        get: function(target, key) {
          if (key === '__exactEnvProxy') return true;
          return target[key];
        },
        set: function(target, key, value) {
          // Node.js converts all values to strings
          target[key] = String(value);
          return true;
        },
        deleteProperty: function(target, key) {
          delete target[key];
          return true;
        }
      });
      try {
        Object.defineProperty(proc, 'env', {
          value: _envProxy,
          writable: true,
          configurable: true,
          enumerable: true
        });
      } catch (_) {
        proc.env = _envProxy;
      }
    }
  } else {
    if (!proc.env || (typeof proc.env === 'object' && Object.keys(proc.env).length === 0)) proc.env = env;
  }

  // Fix process.version to match Node.js version
  try {
    var _versions = proc.versions;
    if (_versions && _versions.node) {
      Object.defineProperty(proc, 'version', {
        value: 'v' + String(_versions.node).replace(/^v/, ''),
        writable: true, configurable: true, enumerable: true
      });
    }
  } catch (_) {}

  // Fix process.release.name = 'node' with LTS codename
  try {
    var _existingRelease = {};
    try { _existingRelease = proc.release || {}; } catch(_) {}
    var _releaseObj = { name: 'node' };
    if (_existingRelease && typeof _existingRelease === 'object') {
      var _rKeys = Object.keys(_existingRelease);
      for (var _ri = 0; _ri < _rKeys.length; _ri++) {
        if (_rKeys[_ri] !== 'name') _releaseObj[_rKeys[_ri]] = _existingRelease[_rKeys[_ri]];
      }
    }
    var _nodeVer = String((_versions && _versions.node) || '').split('.');
    var _major = parseInt(_nodeVer[0], 10);
    var _minor = parseInt(_nodeVer[1], 10);
    var _ltsMap = [[4,2,'Argon'],[6,9,'Boron'],[8,9,'Carbon'],[10,13,'Dubnium'],[12,13,'Erbium'],[14,15,'Fermium'],[16,13,'Gallium'],[18,12,'Hydrogen'],[20,9,'Iron'],[22,11,'Jod'],[24,11,'Krypton']];
    for (var _li = 0; _li < _ltsMap.length; _li++) {
      if (_major === _ltsMap[_li][0] && _minor >= _ltsMap[_li][1]) {
        _releaseObj.lts = _ltsMap[_li][2];
        break;
      }
    }
    Object.defineProperty(proc, 'release', {
      value: _releaseObj, writable: true, configurable: true, enumerable: true
    });
  } catch (_) {}

  // Wrap process.hrtime with argument validation
  try {
    var _nativeHrtime = proc.hrtime;
    if (typeof _nativeHrtime === 'function' && !_nativeHrtime.__exactWrapped) {
      var _wrappedHrtime = function hrtime(time) {
        if (time !== undefined) {
          if (!Array.isArray(time)) {
            var te2 = new TypeError('The "time" argument must be an instance of Array. Received type ' + typeof time + ' (' + String(time) + ')');
            te2.code = 'ERR_INVALID_ARG_TYPE';
            throw te2;
          }
          if (time.length !== 2) {
            var re2 = new RangeError('The value of "time" is out of range. It must be 2. Received ' + time.length);
            re2.code = 'ERR_OUT_OF_RANGE';
            throw re2;
          }
        }
        return _nativeHrtime.call(proc, time);
      };
      _wrappedHrtime.__exactWrapped = true;
      if (_nativeHrtime.bigint) {
        _wrappedHrtime.bigint = _nativeHrtime.bigint;
      }
      try {
        Object.defineProperty(proc, 'hrtime', {
          value: _wrappedHrtime, writable: true, configurable: true, enumerable: true
        });
      } catch (_) {
        proc.hrtime = _wrappedHrtime;
      }
    }
  } catch (_) {}

  // process.setSourceMapsEnabled stub
  if (typeof proc.setSourceMapsEnabled !== 'function') {
    proc.setSourceMapsEnabled = function setSourceMapsEnabled(val) {
      if (typeof val !== 'boolean') {
        var te3 = new TypeError('[ERR_INVALID_ARG_TYPE]: The "val" argument must be of type boolean. Received type ' + typeof val);
        te3.code = 'ERR_INVALID_ARG_TYPE';
        throw te3;
      }
    };
  }

  // process.hasUncaughtExceptionCaptureCallback / setUncaughtExceptionCaptureCallback
  if (typeof proc.hasUncaughtExceptionCaptureCallback !== 'function') {
    proc.hasUncaughtExceptionCaptureCallback = function() {
      return !!(proc._uncaughtCaptureCb);
    };
  }
  if (typeof proc.setUncaughtExceptionCaptureCallback !== 'function') {
    proc.setUncaughtExceptionCaptureCallback = function(fn) {
      if (fn !== null && typeof fn !== 'function') {
        var te4 = new TypeError('The "fn" argument must be one of type function or null. Received type ' + typeof fn);
        te4.code = 'ERR_INVALID_ARG_TYPE';
        throw te4;
      }
      if (fn !== null && proc._uncaughtCaptureCb) {
        var e7 = new Error('`process.setUncaughtExceptionCaptureCallback()` was called while a capture callback was already active');
        e7.code = 'ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET';
        throw e7;
      }
      proc._uncaughtCaptureCb = fn;
    };
  }

  // Fix process.emitWarning to support noDeprecation, validation, and async emission
  try {
    proc.emitWarning = function emitWarning(warning, typeOrOptions, code, ctor) {
      // Validate warning argument
      if (typeof warning !== 'string' && !(warning instanceof Error)) {
        var te5 = new TypeError('[ERR_INVALID_ARG_TYPE]: The "warning" argument must be of type string or an instance of Error. Received type ' + typeof warning);
        te5.code = 'ERR_INVALID_ARG_TYPE';
        throw te5;
      }
      var type, detail;
      if (typeOrOptions && typeof typeOrOptions === 'object' && !Array.isArray(typeOrOptions) && !(typeOrOptions instanceof Error) && typeof typeOrOptions !== 'function') {
        // Options object form: emitWarning(warning, options)
        type = typeOrOptions.type;
        code = typeOrOptions.code;
        detail = typeOrOptions.detail;
        ctor = typeOrOptions.ctor || ctor;
      } else if (typeof typeOrOptions === 'function') {
        // emitWarning(warning, ctor)
        ctor = typeOrOptions;
        type = undefined;
      } else {
        type = typeOrOptions;
      }
      // If code is a function, it's actually ctor
      if (typeof code === 'function') {
        ctor = code;
        code = undefined;
      }
      // If ctor (4th arg) passed and code is still function, shift
      if (arguments.length >= 4 && typeof arguments[3] === 'function') {
        ctor = arguments[3];
      }
      // Validate type
      if (type !== undefined && typeof type !== 'string') {
        var te6 = new TypeError('[ERR_INVALID_ARG_TYPE]: The "type" argument must be of type string. Received type ' + typeof type);
        te6.code = 'ERR_INVALID_ARG_TYPE';
        throw te6;
      }
      // Validate code
      if (code !== undefined && typeof code !== 'string') {
        var te7 = new TypeError('[ERR_INVALID_ARG_TYPE]: The "code" argument must be of type string. Received type ' + typeof code);
        te7.code = 'ERR_INVALID_ARG_TYPE';
        throw te7;
      }
      if (type === 'DeprecationWarning' && proc.noDeprecation) {
        return;
      }
      var warningObj;
      if (warning instanceof Error) {
        warningObj = warning;
      } else {
        warningObj = new Error(warning);
        warningObj.name = type || 'Warning';
      }
      if (code) warningObj.code = code;
      if (type && warningObj.name !== type) warningObj.name = type;
      if (detail !== undefined) warningObj.detail = detail;
      // Emit asynchronously like Node.js
      if (typeof proc.nextTick === 'function') {
        proc.nextTick(function() {
          if (typeof proc.emit === 'function') {
            proc.emit('warning', warningObj);
          }
        });
      } else {
        try {
          if (typeof proc.emit === 'function') {
            proc.emit('warning', warningObj);
          }
        } catch(_) {}
      }
    };
  } catch (_) {}

  // process.binding('util') support
  try {
    var _origBinding = proc.binding;
    if (typeof _origBinding === 'function' && !_origBinding.__exactPatched) {
      proc.binding = function binding(name) {
        if (name === 'util') {
          var types = {};
          try { types = require('util').types || {}; } catch(_) {}
          return types;
        }
        return _origBinding.call(proc, name);
      };
      proc.binding.__exactPatched = true;
    }
  } catch (_) {}

  // Ensure addListener/removeListener aliases exist (EventEmitter compatibility)
  if (typeof proc.on === 'function' && typeof proc.addListener !== 'function') {
    proc.addListener = proc.on;
  }
  if (typeof proc.removeListener === 'function' && typeof proc.off !== 'function') {
    proc.off = proc.removeListener;
  }

  module.exports = proc;
} else {
  module.exports = { cwd: cwd, env: env, argv: argv };
}
