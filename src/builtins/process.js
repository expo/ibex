var _uvErrnoMapFallback = {
  EACCES: 13,
  EINVAL: 22,
  ENOENT: 2,
  ENOTDIR: 20
};

function cwd() {
  if (typeof __exactGetCwd === 'function') {
    return __exactGetCwd();
  }
  return "/";
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
  if (typeof __exactSetCwd !== 'function') {
    throw new Error("process.chdir is not supported in this runtime");
  }
  try {
    __exactSetCwd(path);
  } catch (e) {
    throw _coerceChdirError(e, path);
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
  var e6 = new Error('Access to this API has been restricted');
  e6.code = 'ERR_ACCESS_DENIED';
  e6.permission = 'ChildProcess';
  e6.resource = execPath;
  throw e6;
}

// Re-export the full globalThis.process object (which has all the C++ properties)
// with cwd/env/argv as fallback overrides
if (typeof globalThis !== 'undefined' && globalThis.process) {
  var proc = globalThis.process;
  {
    var _nativeUmask = typeof proc.umask === 'function' ? proc.umask : null;
    proc.umask = function(mask) {
      if (arguments.length === 0) {
        if (_nativeUmask) return _nativeUmask();
        return _umask;
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
        return _nativeUmask(mask);
      }
      var old = _umask;
      _umask = mask & 0o7777;
      return old;
    };
  }
  // Ensure our module-level cwd/env/argv are present
  proc.chdir = chdir;
  if (!proc.cwd) proc.cwd = cwd;
  if (!proc.env || (typeof proc.env === 'object' && Object.keys(proc.env).length === 0)) proc.env = env;
  if (!proc.argv || proc.argv.length === 0) proc.argv = argv;
  if (!Array.isArray(proc.execArgv)) proc.execArgv = [];
  if (!proc.execve) proc.execve = execve;
  module.exports = proc;
} else {
  module.exports = { cwd: cwd, env: env, argv: argv };
}
