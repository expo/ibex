function cwd() {
  if (typeof __exactGetCwd === 'function') {
    return __exactGetCwd();
  }
  return "/";
}

function chdir(path) {
  if (typeof __exactSetCwd !== 'function') {
    throw new Error("process.chdir is not supported in this runtime");
  }
  if (typeof path !== 'string') {
    throw new TypeError("path must be a string");
  }
  __exactSetCwd(path);
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

// Re-export the full globalThis.process object (which has all the C++ properties)
// with cwd/env/argv as fallback overrides
if (typeof globalThis !== 'undefined' && globalThis.process) {
  var proc = globalThis.process;
  if (typeof proc.umask !== 'function') {
    proc.umask = function(mask) {
      if (arguments.length === 0) {
        return _umask;
      }
      if (typeof mask === 'string') {
        if (!/^\d+$/.test(mask)) {
          throw new TypeError("Bad argument");
        }
        mask = parseInt(mask, 8);
      } else if (typeof mask !== 'number' || (mask !== (mask | 0))) {
        throw new TypeError("Bad argument");
      }
      if (mask < 0 || mask > 0o7777 || !isFinite(mask)) {
        throw new RangeError("Bad argument");
      }
      var old = _umask;
      _umask = mask & 0o7777;
      return old;
    };
  }
  // Ensure our module-level cwd/env/argv are present
  if (!proc.chdir) proc.chdir = chdir;
  if (!proc.cwd) proc.cwd = cwd;
  if (!proc.env || (typeof proc.env === 'object' && Object.keys(proc.env).length === 0)) proc.env = env;
  if (!proc.argv || proc.argv.length === 0) proc.argv = argv;
  if (!Array.isArray(proc.execArgv)) proc.execArgv = [];
  module.exports = proc;
} else {
  module.exports = { cwd: cwd, env: env, argv: argv };
}
