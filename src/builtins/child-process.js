var cp = {};

function _fallbackSpawnCommand(command) {
  if (typeof command !== 'string') {
    return command;
  }
  var procPath = (typeof process !== 'undefined' && process !== null && process.execPath) ? String(process.execPath) : '';
  if (command === procPath && /(^|[\\/])exact/.test(command)) {
    return command;
  }
  return command;
}

function normalizeExecOptions(opts) {
  var o = {};
  if (!opts) return o;
  if (typeof opts === 'string') {
    o.encoding = opts;
    return o;
  }
  if (opts.cwd) o.cwd = String(opts.cwd);
  if (opts.timeout) o.timeout = Number(opts.timeout);
  // Pass large maxBuffer to C++ to prevent C++ truncation - JS handles actual enforcement
  o.maxBuffer = 268435456; // 256MB
  if (opts.encoding !== undefined) o.encoding = opts.encoding;
  if (opts.env) o.env = opts.env;
  if (opts.shell !== undefined) o.shell = opts.shell;
  if (opts.input !== undefined) o.input = opts.input;
  return o;
}

function makeExecError(message, result) {
  var err = new Error(message);
  err.status = result.status;
  err.code = result.status;
  err.cmd = result.cmd || '';
  err.stdout = result.stdout || '';
  err.stderr = result.stderr || '';
  err.signal = null;
  if (result.status < 0) {
    err.signal = 'SIGKILL';
  }
  err.pid = result.pid || 0;
  err.killed = result.error === 'Command timed out';
  return err;
}

function _makeIpcError(code, message) {
  var err = new Error(message);
  err.code = code;
  return err;
}

function _createIpcPacket(type, data) {
  return JSON.stringify({ __exactIpc: true, type: type, data: data }) + '\n';
}

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + input.name;
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
}

function _throwInvalidArgType(name, expected, actual) {
  var err = new TypeError('The "' + name + '" ' + (name.indexOf('.') !== -1 ? 'property' : 'argument') + ' must be ' + expected + '.' + _invalidArgTypeHelper(actual));
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function _throwOutOfRange(name, range, actual) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + range + '. Received ' + String(actual));
  err.code = 'ERR_OUT_OF_RANGE';
  throw err;
}

function _throwUnknownSignal(signal) {
  var err = new TypeError('Unknown signal: ' + signal);
  err.code = 'ERR_UNKNOWN_SIGNAL';
  throw err;
}

var _signalMap = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGIOT: 6, SIGBUS: 10, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 30, SIGSEGV: 11,
  SIGUSR2: 31, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGCHLD: 20,
  SIGCONT: 19, SIGSTOP: 17, SIGTSTP: 18, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 16, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
  SIGWINCH: 28, SIGIO: 23, SIGINFO: 29, SIGSYS: 12
};
var _signalNumbers = {};
for (var _sk in _signalMap) _signalNumbers[_signalMap[_sk]] = _sk;

function _isValidSignal(signal) {
  if (typeof signal === 'number') {
    return Number.isInteger(signal) && signal > 0 && _signalNumbers[signal] !== undefined;
  }
  if (typeof signal === 'string') {
    var upper = signal.toUpperCase();
    return _signalMap[upper] !== undefined;
  }
  return false;
}

function _validateSpawnSyncInput(options) {
  if (options.input != null) {
    if (typeof options.input !== 'string' && !ArrayBuffer.isView(options.input) && !(options.input instanceof ArrayBuffer)) {
      _throwInvalidArgType('options.input', 'of type string or an instance of Buffer, TypedArray, or DataView', options.input);
    }
  }
}

function _validateSpawnSyncOptions(options) {
  if (options.cwd != null && typeof options.cwd !== 'string') {
    if (!(options.cwd instanceof URL)) {
      _throwInvalidArgType('options.cwd', 'of type string, an instance of URL, or undefined', options.cwd);
    }
  }
  if (options.detached != null && typeof options.detached !== 'boolean') {
    _throwInvalidArgType('options.detached', 'of type boolean or undefined', options.detached);
  }
  if (options.uid != null) {
    if (typeof options.uid !== 'number' || !Number.isInteger(options.uid) || options.uid < 0) {
      _throwInvalidArgType('options.uid', 'an int32', options.uid);
    }
  }
  if (options.gid != null) {
    if (typeof options.gid !== 'number' || !Number.isInteger(options.gid) || options.gid < 0) {
      _throwInvalidArgType('options.gid', 'an int32', options.gid);
    }
  }
  if (options.shell != null && typeof options.shell !== 'boolean' && typeof options.shell !== 'string') {
    _throwInvalidArgType('options.shell', 'of type boolean or of type string or undefined', options.shell);
  }
  if (options.argv0 != null && typeof options.argv0 !== 'string') {
    _throwInvalidArgType('options.argv0', 'of type string or undefined', options.argv0);
  }
  if (options.windowsHide != null && typeof options.windowsHide !== 'boolean') {
    _throwInvalidArgType('options.windowsHide', 'of type boolean or undefined', options.windowsHide);
  }
  if (options.windowsVerbatimArguments != null && typeof options.windowsVerbatimArguments !== 'boolean') {
    _throwInvalidArgType('options.windowsVerbatimArguments', 'of type boolean or undefined', options.windowsVerbatimArguments);
  }
  if (options.timeout != null) {
    if (typeof options.timeout !== 'number' || !Number.isFinite(options.timeout) || !Number.isInteger(options.timeout) || options.timeout < 0) {
      _throwOutOfRange('options.timeout', 'a non-negative integer', options.timeout);
    }
  }
  if (options.maxBuffer != null) {
    if (typeof options.maxBuffer !== 'number' || options.maxBuffer !== options.maxBuffer || options.maxBuffer < 0) {
      _throwOutOfRange('options.maxBuffer', 'a non-negative number', options.maxBuffer);
    }
  }
  if (options.killSignal != null) {
    if (typeof options.killSignal !== 'string' && typeof options.killSignal !== 'number') {
      _throwInvalidArgType('options.killSignal', 'of type string or of type number or undefined', options.killSignal);
    }
    if (!_isValidSignal(options.killSignal)) {
      _throwUnknownSignal(options.killSignal);
    }
  }
}

  cp.execSync = function execSync(command, options) {
    if (typeof command !== 'string') {
      throw new TypeError('The "command" argument must be of type string');
    }
    _validateNullBytes(command, 'command');
    _validateOptionsNullBytes(options);
    command = _fallbackSpawnCommand(command);
    var opts = normalizeExecOptions(options);
  var optsJson = JSON.stringify(opts);
  var resultJson = globalThis.__exactExecSync(command, optsJson);
  var result = JSON.parse(resultJson);

  var _Buffer = require('buffer').Buffer;
  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'buffer';

  // Convert stdout/stderr to proper types
  var stdoutBuf = _Buffer.from(result.stdout || '', 'utf8');
  var stderrBuf = _Buffer.from(result.stderr || '', 'utf8');

  // Check maxBuffer enforcement (read from original options, not normalized opts)
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  if (maxBuffer !== Infinity) {
    if (stdoutBuf.length > maxBuffer || stderrBuf.length > maxBuffer) {
      var maxBufErr = new Error('Command failed: ' + command + '\nENOBUFS');
      maxBufErr.code = 'ENOBUFS';
      maxBufErr.errno = -55;
      maxBufErr.status = result.status;
      maxBufErr.stdout = stdoutBuf;
      maxBufErr.stderr = stderrBuf;
      maxBufErr.pid = result.pid || 0;
      maxBufErr.cmd = command;
      throw maxBufErr;
    }
  }

  if (result.error) {
    throw makeExecError(result.error, result);
  }

  if (result.status !== 0) {
    var err = makeExecError(
      'Command failed: ' + command + '\n' + result.stderr,
      result
    );
    throw err;
  }

  if (encoding === 'buffer' || encoding === null) {
    return stdoutBuf;
  }

  return result.stdout;
};

  cp.spawnSync = function spawnSync(command, args, options) {
    if (typeof command !== 'string') {
      _throwInvalidArgType('file', 'of type string', command);
    }
    _validateNullBytes(command, 'command');
    command = _fallbackSpawnCommand(command);
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  // Coerce args to strings (Node.js does this automatically)
  args = args.map(function(a) { return String(a); });
  _validateArgsNullBytes(args);
  if (options == null) options = {};
  _validateOptionsNullBytes(options);
  _validateSpawnSyncInput(options);
  _validateSpawnSyncOptions(options);
  var opts = normalizeExecOptions(options);
  // Pass input to native side if provided
  if (options.input != null) {
    if (typeof options.input === 'string') {
      opts.input = options.input;
    } else if (ArrayBuffer.isView(options.input)) {
      // Convert typed array to string for JSON transport
      var inputBytes = new Uint8Array(options.input.buffer, options.input.byteOffset, options.input.byteLength);
      var inputStr = '';
      for (var ib = 0; ib < inputBytes.length; ib++) inputStr += String.fromCharCode(inputBytes[ib]);
      opts.input = inputStr;
    }
  }
  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawnSync(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: e.message || 'spawnSync failed', status: null, stdout: '', stderr: '' };
  }

  var encoding = (options && options.encoding !== undefined) ? options.encoding : 'buffer';

  var stdoutOutput = result.stdout || '';
  var stderrOutput = result.stderr || '';

  var _Buffer = require('buffer').Buffer;

  if (encoding === 'buffer' || encoding === null) {
    stdoutOutput = typeof stdoutOutput === 'string' ? _Buffer.from(stdoutOutput, 'utf8') : _Buffer.from(stdoutOutput || '');
    stderrOutput = typeof stderrOutput === 'string' ? _Buffer.from(stderrOutput, 'utf8') : _Buffer.from(stderrOutput || '');
  } else if (encoding && encoding !== 'utf8' && encoding !== 'utf-8') {
    // For other encodings, keep as string (best effort)
  }

  var output = [null, stdoutOutput, stderrOutput];

  var spawnResult = {
    pid: result.pid || 0,
    output: output,
    stdout: stdoutOutput,
    stderr: stderrOutput,
    status: result.status,
    signal: null,
    error: undefined
  };

  // Check maxBuffer enforcement
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  if (maxBuffer !== Infinity && !result.error) {
    var stdoutLen = typeof stdoutOutput === 'string' ? stdoutOutput.length : (stdoutOutput ? stdoutOutput.length : 0);
    var stderrLen = typeof stderrOutput === 'string' ? stderrOutput.length : (stderrOutput ? stderrOutput.length : 0);
    if (stdoutLen > maxBuffer || stderrLen > maxBuffer) {
      var maxBufErr = new Error('spawnSync ' + command + ' ENOBUFS');
      maxBufErr.code = 'ENOBUFS';
      maxBufErr.errno = -55;
      maxBufErr.syscall = 'spawnSync ' + command;
      maxBufErr.spawnargs = args;
      maxBufErr.path = command;
      spawnResult.error = maxBufErr;
    }
  }

  if (!spawnResult.error && result.error) {
    var spawnErr = _makeSpawnError(command, 'ENOENT', -2, 'spawnSync ' + command);
    if (result.error.indexOf('not found') !== -1 || result.error.indexOf('No such file') !== -1) {
      spawnErr.code = 'ENOENT';
      spawnErr.errno = -2;
    } else if (result.error.indexOf('Permission denied') !== -1 || result.error.indexOf('EACCES') !== -1) {
      spawnErr.code = 'EACCES';
      spawnErr.errno = -13;
    } else if (result.error.indexOf('timed out') !== -1 || result.error.indexOf('Timed out') !== -1) {
      spawnErr.code = 'ETIMEDOUT';
      spawnErr.errno = -60;
    }
    spawnErr.spawnargs = args;
    spawnResult.error = spawnErr;
  }
  if (result.signal) {
    spawnResult.signal = result.signal;
  } else if (result.status < 0) {
    spawnResult.signal = 'SIGKILL';
  }

  return spawnResult;
};

cp.execFileSync = function execFileSync(file, args, options) {
  if (typeof file !== 'string') {
    _throwInvalidArgType('file', 'of type string', file);
  }
  _validateNullBytes(file, 'file');
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  var result = cp.spawnSync(file, args, options);

  if (result.error) {
    // Attach stdout/stderr to the error object (Node compat)
    if (result.error.stdout === undefined) result.error.stdout = result.stdout;
    if (result.error.stderr === undefined) result.error.stderr = result.stderr;
    if (result.error.status === undefined) result.error.status = result.status;
    if (result.error.pid === undefined) result.error.pid = result.pid;
    throw result.error;
  }

  if (result.status !== 0) {
    var err = makeExecError(
      'Command failed: ' + file + ' ' + args.join(' '),
      { status: result.status, stdout: result.stdout, stderr: result.stderr, pid: result.pid }
    );
    throw err;
  }

  var opts = normalizeExecOptions(options);
  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'buffer';
  if (encoding === 'buffer' || encoding === null) {
    return result.stdout;
  }
  return typeof result.stdout === 'string' ? result.stdout : '';
};

cp.exec = function exec(command, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (!options) options = {};
  _validateNullBytes(command, 'command');
  _validateOptionsNullBytes(options);
  var opts = normalizeExecOptions(options);
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  var encoding = (options && 'encoding' in options) ? options.encoding : 'utf8';
  var useBuffer = !encoding || encoding === 'buffer';
  var child = cp.spawn(command, [], {
    shell: opts.shell !== undefined ? opts.shell : true,
    cwd: opts.cwd,
    env: opts.env
  });
  child._cmd = command;
  var stdoutChunks = [];
  var stderrChunks = [];
  var stdoutLen = 0;
  var stderrLen = 0;
  var killed = false;
  var exited = false;
  var timeoutId = null;

  function exitHandler(code, signal) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    var stdoutStr = stdoutChunks.join('');
    var stderrStr = stderrChunks.join('');
    var stdout = useBuffer ? Buffer.from(stdoutStr) : stdoutStr;
    var stderr = useBuffer ? Buffer.from(stderrStr) : stderrStr;
    if (code !== 0 || killed) {
      var err = makeExecError(
        'Command failed: ' + command + (stderrStr ? '\n' + stderrStr : ''),
        { status: code, stdout: stdout, stderr: stderr, pid: child.pid, cmd: command }
      );
      err.killed = killed || child.killed;
      if (typeof callback === 'function') callback(err, stdout, stderr);
    } else {
      if (typeof callback === 'function') callback(null, stdout, stderr);
    }
  }

  if (child.stdout) {
    child.stdout.on('data', function(chunk) {
      var str = typeof chunk === 'string' ? chunk : String(chunk);
      stdoutLen += str.length;
      if (stdoutLen > maxBuffer) {
        killed = true;
        child.kill();
        return;
      }
      stdoutChunks.push(str);
    });
  }
  if (child.stderr) {
    child.stderr.on('data', function(chunk) {
      var str = typeof chunk === 'string' ? chunk : String(chunk);
      stderrLen += str.length;
      if (stderrLen > maxBuffer) {
        killed = true;
        child.kill();
        return;
      }
      stderrChunks.push(str);
    });
  }

  child.on('close', exitHandler);
  child.on('error', function(err) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    if (typeof callback === 'function') callback(err, '', '');
  });

  if (opts.timeout && opts.timeout > 0) {
    timeoutId = setTimeout(function() {
      killed = true;
      child.kill();
    }, opts.timeout);
  }

  return child;
};

cp.execFile = function execFile(file, args, options, callback) {
  // Flexible argument parsing: execFile(file [,args] [,options] [,callback])
  if (typeof args === 'function') {
    callback = args;
    args = null;
    options = null;
  } else if (typeof args === 'object' && args !== null && !Array.isArray(args)) {
    // args is actually options
    if (typeof options === 'function') {
      callback = options;
    } else if (typeof options === 'string') {
      _throwInvalidArgType('args', 'an instance of Array or undefined', args);
    } else {
      callback = options;
    }
    options = args;
    args = null;
  } else if (args !== null && args !== undefined && !Array.isArray(args)) {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  } else {
    if (typeof options === 'function') {
      callback = options;
      options = null;
    } else if (typeof options === 'string') {
      _throwInvalidArgType('options', 'of type object or undefined', options);
    } else if (Array.isArray(options)) {
      _throwInvalidArgType('options', 'of type object or undefined', options);
    }
  }
  // Validate callback if 4th arg was provided as string
  if (callback !== null && callback !== undefined && typeof callback !== 'function') {
    if (typeof callback === 'string') {
      _throwInvalidArgType('callback', 'of type function or undefined', callback);
    }
  }
  if (!args) args = [];
  if (!options) options = {};
  _validateNullBytes(file, 'file');
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  var opts = normalizeExecOptions(options);
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  var encoding = (options && 'encoding' in options) ? options.encoding : 'utf8';
  var useBuffer = !encoding || encoding === 'buffer';
  var child = cp.spawn(file, args, {
    shell: false,
    cwd: opts.cwd,
    env: opts.env
  });
  child._cmd = file + ' ' + args.join(' ');
  var stdoutChunks = [];
  var stderrChunks = [];
  var stdoutLen = 0;
  var stderrLen = 0;
  var killed = false;
  var exited = false;
  var timeoutId = null;

  function exitHandler(code, signal) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    var stdoutStr = stdoutChunks.join('');
    var stderrStr = stderrChunks.join('');
    var stdout = useBuffer ? Buffer.from(stdoutStr) : stdoutStr;
    var stderr = useBuffer ? Buffer.from(stderrStr) : stderrStr;
    if (code !== 0 || killed) {
      var err = makeExecError(
        'Command failed: ' + file + (stderrStr ? '\n' + stderrStr : ''),
        { status: code, stdout: stdout, stderr: stderr, pid: child.pid, cmd: file + ' ' + args.join(' ') }
      );
      err.killed = killed || child.killed;
      if (typeof callback === 'function') callback(err, stdout, stderr);
    } else {
      if (typeof callback === 'function') callback(null, stdout, stderr);
    }
  }

  if (child.stdout) {
    child.stdout.on('data', function(chunk) {
      var str = typeof chunk === 'string' ? chunk : String(chunk);
      stdoutLen += str.length;
      if (stdoutLen > maxBuffer) {
        killed = true;
        child.kill();
        return;
      }
      stdoutChunks.push(str);
    });
  }
  if (child.stderr) {
    child.stderr.on('data', function(chunk) {
      var str = typeof chunk === 'string' ? chunk : String(chunk);
      stderrLen += str.length;
      if (stderrLen > maxBuffer) {
        killed = true;
        child.kill();
        return;
      }
      stderrChunks.push(str);
    });
  }

  child.on('close', exitHandler);
  child.on('error', function(err) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    if (!err.cmd) err.cmd = file + (args.length ? ' ' + args.join(' ') : '');
    if (typeof callback === 'function') callback(err, '', '');
  });

  if (opts.timeout && opts.timeout > 0) {
    timeoutId = setTimeout(function() {
      killed = true;
      child.kill();
    }, opts.timeout);
  }

  return child;
};

function _normalizeSpawnMode(mode, fallbackMode) {
  var normalized = mode === undefined || mode === null ? fallbackMode : mode;
  if (typeof normalized === 'string') {
    if (normalized === 'ignore' || normalized === 'overlapped' || normalized === 'inherit' || normalized === 'pipe' || normalized === 'ipc') {
      return normalized === 'overlapped' ? 'pipe' : normalized;
    }
  }
  if (normalized === 0) return 'ignore';
  if (normalized === 1) return 'pipe';
  if (normalized === 2) return 'inherit';
  return 'pipe';
}

function _normalizeSpawnOptions(options) {
  var normalized = {
    cwd: options.cwd,
    env: options.env,
    shell: options.shell,
    detached: options.detached
  };
  var stdio = options.stdio;
  if (typeof stdio === 'string') {
    normalized.stdio = [
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe')
    ];
  } else if (typeof stdio === 'number') {
    normalized.stdio = [
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe')
    ];
  } else if (Array.isArray(stdio)) {
    normalized.stdio = [];
    for (var si = 0; si < Math.max(stdio.length, 3); si++) {
      normalized.stdio[si] = _normalizeSpawnMode(stdio[si], 'pipe');
    }
  } else {
    normalized.stdio = ['pipe', 'pipe', 'pipe', 'pipe'];
  }
  return normalized;
}

function _normalizeForkEnv(optionsEnv) {
  var env = {};
  if (typeof process === 'object' && process !== null && process.env) {
    var processEnv = process.env;
    for (var key in processEnv) {
      if (Object.prototype.hasOwnProperty.call(processEnv, key)) {
        var value = processEnv[key];
        if (value !== undefined && value !== null) env[key] = String(value);
      }
    }
  }
  if (optionsEnv && typeof optionsEnv === 'object') {
    for (var key in optionsEnv) {
      if (Object.prototype.hasOwnProperty.call(optionsEnv, key)) {
        var v = optionsEnv[key];
        if (v === undefined || v === null) {
          delete env[key];
        } else {
          env[key] = String(v);
        }
      }
    }
  }
  return env;
}

function _toUtf8String(bytes) {
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

function _toUint8String(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  var str = '';
  var i = 0;
  var len = value.length || 0;
  for (; i < len; i++) {
    var ch = value[i];
    if (typeof ch === 'number') str += String.fromCharCode(ch & 0xff);
    else if (typeof ch === 'string') str += ch;
  }
  return str;
}

// Signal name to number mapping
var signalMap = {
  'SIGHUP': 1, 'SIGINT': 2, 'SIGQUIT': 3, 'SIGILL': 4, 'SIGTRAP': 5,
  'SIGABRT': 6, 'SIGBUS': 7, 'SIGFPE': 8, 'SIGKILL': 9, 'SIGUSR1': 10,
  'SIGSEGV': 11, 'SIGUSR2': 12, 'SIGPIPE': 13, 'SIGALRM': 14, 'SIGTERM': 15
};

// Signal number to name mapping
var signalNames = {};
for (var sn in signalMap) {
  if (signalMap.hasOwnProperty(sn)) signalNames[signalMap[sn]] = sn;
}
if (typeof globalThis.__exactSpawnProcesses !== 'object') {
  globalThis.__exactSpawnProcesses = Object.create(null);
}
if (typeof globalThis.__exactSpawnPump !== 'function') {
  globalThis.__exactSpawnPump = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    var proc = globalThis.__exactSpawnProcesses[String(handle)];
    if (!proc) return;
    if (typeof proc.__pumpFromNative === 'function') {
      proc.__pumpFromNative();
    }
  };
}
if (typeof globalThis.__exactSpawnDispose !== 'function') {
  globalThis.__exactSpawnDispose = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    delete globalThis.__exactSpawnProcesses[String(handle)];
  };
}

// Validation helpers
function _validateNullBytes(value, name) {
  if (typeof value === 'string' && value.indexOf('\0') !== -1) {
    var err = new TypeError('The value of "' + name + '" is invalid. Received ' + JSON.stringify(value));
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
}

function _validateArgsNullBytes(args) {
  if (Array.isArray(args)) {
    for (var i = 0; i < args.length; i++) {
      _validateNullBytes(args[i], 'options.args[' + i + ']');
    }
  }
}

function _validateOptionsNullBytes(options) {
  if (!options) return;
  if (typeof options.cwd === 'string') _validateNullBytes(options.cwd, 'options.cwd');
  if (typeof options.argv0 === 'string') _validateNullBytes(options.argv0, 'options.argv0');
  if (typeof options.shell === 'string') _validateNullBytes(options.shell, 'options.shell');
  if (typeof options.execPath === 'string') _validateNullBytes(options.execPath, 'options.execPath');
  if (Array.isArray(options.execArgv)) {
    for (var i = 0; i < options.execArgv.length; i++) {
      _validateNullBytes(options.execArgv[i], 'options.execArgv[' + i + ']');
    }
  }
  if (options.env && typeof options.env === 'object') {
    var keys = Object.keys(options.env);
    for (var j = 0; j < keys.length; j++) {
      _validateNullBytes(keys[j], 'options.env');
      _validateNullBytes(String(options.env[keys[j]]), 'options.env[\'' + keys[j] + '\']');
    }
  }
}

function _makeSpawnError(command, code, errno, syscall) {
  var msg = syscall + ' ' + code;
  var err = new Error(msg);
  err.code = code;
  err.errno = errno || 0;
  err.syscall = syscall || 'spawn ' + command;
  err.path = command;
  err.spawnargs = [];
  return err;
}

// ChildProcess constructor (extends EventEmitter)
var _EventEmitter;
try { _EventEmitter = require('events'); } catch(e) {
  _EventEmitter = function() { this._events = {}; };
  _EventEmitter.prototype.on = function(ev, fn) { if (!this._events) this._events = {}; if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
  _EventEmitter.prototype.emit = function(ev) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  _EventEmitter.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
  _EventEmitter.prototype.removeListener = function(ev, fn) { if (!this._events) this._events = {}; var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
  _EventEmitter.prototype.removeAllListeners = function(ev) { if (!this._events) this._events = {}; if (ev) delete this._events[ev]; else this._events = {}; return this; };
}

function ChildProcess(handle, pid, stdioModes) {
  _EventEmitter.call(this);
  if (_EventEmitter.prototype) {
    for (var k in _EventEmitter.prototype) {
      if (!this[k]) this[k] = _EventEmitter.prototype[k];
    }
  }
  this._events = this._events || {};
  this._handle = handle !== undefined ? handle : null;
  this.pid = pid !== undefined ? pid : undefined;
  this.exitCode = null;
  this.signalCode = null;
  this.killed = false;
  this.spawnfile = '';
  this.spawnargs = [];
  this._exitHandled = false;
  this._exited = false;
  this._ref = true;
  this._useNativePump = typeof globalThis.__exactSpawnPump === 'function';
  this._pumpInProgress = false;
  var modes = stdioModes || null;
  if (modes) {
    this._ipcMode = modes.ipc === 'ipc';
  } else {
    this._ipcMode = false;
  }
  this._ipcBuffer = '';
  this._ipcQueueSize = 0;
  this._ipcQueueMax = 2;
  this._sendCallbackQueue = [];
  this._sendCallbackDraining = false;
  this._disconnectPending = false;
  this._disconnectEmitted = false;
  this._closeCallback = null;
  this.connected = this._ipcMode;
  this.channel = this._ipcMode ? { fd: 3, connected: true } : null;
  this.stdin = null;
  this.stdout = null;
  this.stderr = null;
  this.stdio = [null, null, null];

  // Only set up streams if modes were provided (i.e., actual spawn, not bare constructor)
  if (!modes) return;

  // Create stdout as a Readable stream
  var Stream = require('stream');
  var self = this;

  if (modes.stdout === 'pipe') {
    this.stdout = new Stream.Readable();
    this.stdout._read = function() {};
  } else {
    this.stdout = null;
  }

  if (modes.stderr === 'pipe') {
    this.stderr = new Stream.Readable();
    this.stderr._read = function() {};
  } else {
    this.stderr = null;
  }

  // Create stdin as a Writable stream
  if (modes.stdin === 'pipe') {
    this.stdin = new Stream.Writable({
      write: function(chunk, encoding, callback) {
        var data = _toUint8String(chunk);
        var ok = globalThis.__exactSpawnWrite(self._handle, data);
        if (typeof callback === 'function') callback(ok ? null : new Error('write failed'));
      }
    });
        // Override end to also close the native stdin pipe
    this.stdin.end = function(chunk, encoding, callback) {
      if (typeof chunk === 'function') { callback = chunk; chunk = null; }
      if (typeof encoding === 'function') { callback = encoding; encoding = null; }
      if (chunk !== undefined && chunk !== null) {
        self.stdin.write(chunk, encoding);
      }
      if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
        globalThis.__exactSpawnCloseStdin(self._handle);
      }
      self.stdin.writableEnded = true;
      self.stdin.writableFinished = true;
      self.stdin.emit('finish');
      self.stdin.emit('close');
      if (typeof callback === 'function') callback();
    };
  } else if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
    globalThis.__exactSpawnCloseStdin(this._handle);
    this.stdin = null;
  } else {
    this.stdin = null;
  }

  this.stdio = [this.stdin, this.stdout, this.stderr];

  function pushStreamData(kind, value, streamMode) {
    if (!value || !value.length) return;
    if (streamMode === 'pipe') {
      if (kind === 'stdout' && self.stdout) self.stdout.push(_toUint8String(value));
      if (kind === 'stderr' && self.stderr) self.stderr.push(_toUint8String(value));
      return;
    }
    if (streamMode === 'inherit') {
      if (kind === 'stdout' && typeof process !== 'undefined' && process.stdout) process.stdout.write(value);
      if (kind === 'stderr' && typeof process !== 'undefined' && process.stderr && process.stderr.write) process.stderr.write(value);
    }
  }

  this.stdio = [this.stdin, this.stdout, this.stderr];
  if (self._useNativePump && self._handle >= 0) {
    globalThis.__exactSpawnProcesses[String(self._handle)] = self;
  }

  function emitDisconnect() {
    if (self._disconnectEmitted) {
      return;
    }
    self._disconnectEmitted = true;
    self.connected = false;
    self._ipcMode = false;
    self.channel = null;
    if (typeof process !== 'undefined' && self._closeCallback) {
      try {
        self._closeCallback();
      } catch (err) {}
      self._closeCallback = null;
    }
    if (typeof setTimeout === 'function') {
      setTimeout(function() {
        self.emit('disconnect');
      }, 0);
    } else {
      self.emit('disconnect');
    }
  }

  function closeIpcChannel() {
    if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
      globalThis.__exactSpawnCloseStdin(self._handle, 'ipc');
    }
    emitDisconnect();
  }

  function drainIpcPackets(rawData) {
    if (!rawData || !rawData.length) {
      return;
    }
    var rawStr = (typeof rawData === 'string') ? rawData : _toUtf8String(rawData);
    self._ipcBuffer += rawStr;
    while (self._ipcBuffer.length > 0) {
      var lineEnd = self._ipcBuffer.indexOf('\n');
      if (lineEnd < 0) {
        return;
      }
      var line = self._ipcBuffer.slice(0, lineEnd);
      self._ipcBuffer = self._ipcBuffer.slice(lineEnd + 1);
      if (!line) {
        continue;
      }
      var packet;
      try {
        packet = JSON.parse(line);
      } catch (err) {
        continue;
      }
      if (!packet || packet.__exactIpc !== true) {
        continue;
      }
      if (packet.type === 'message') {
        self.emit('message', packet.data);
      } else if (packet.type === 'disconnect') {
        closeIpcChannel();
      }
    }
  }

  // Start polling for stdout/stderr, ipc packets and exit status
  var pollInterval = 10; // ms
  var stdoutEnded = false;
  var stderrEnded = false;

  function closeStreams() {
    if (!stdoutEnded) {
      stdoutEnded = true;
      if (self.stdout && self.stdout.push) self.stdout.push(null);
    }
    if (!stderrEnded) {
      stderrEnded = true;
      if (self.stderr && self.stderr.push) self.stderr.push(null);
    }
  }

  function parseSpawnStatus(jsonText) {
    try {
      return JSON.parse(jsonText);
    } catch(e) {
      return { exited: true, exitCode: -1, signal: 0, error: e && e.message ? e.message : 'Invalid spawn status payload' };
    }
  }

  function pollStreams() {
    if (self._pumpInProgress) return;
    if (self._exited && stdoutEnded && stderrEnded) return;
    self._pumpInProgress = true;

    // Poll stdout
    if (!stdoutEnded) {
      var outData = globalThis.__exactSpawnRead(self._handle, 'stdout');
      pushStreamData('stdout', outData, modes.stdout);
      if (modes.stdout === 'pipe' && (!outData || !outData.length)) {
        if (self._exited) stdoutEnded = true;
      }
    }

    // Poll stderr
    if (!stderrEnded) {
      var errData = globalThis.__exactSpawnRead(self._handle, 'stderr');
      pushStreamData('stderr', errData, modes.stderr);
      if (modes.stderr === 'pipe' && (!errData || !errData.length)) {
        if (self._exited) stderrEnded = true;
      }
    }

    if (self._ipcMode && !self._disconnectPending) {
      var ipcData = globalThis.__exactSpawnRead(self._handle, 'ipc');
      drainIpcPackets(ipcData);
    }

    // Poll exit status
    if (!self._exited) {
      var statusJson = globalThis.__exactSpawnPoll(self._handle);
      var status = parseSpawnStatus(statusJson);
      if (status.exited) {
        self._exited = true;
        if (status.error) {
          var statusErr = new Error(status.error);
          self.emit('error', statusErr);
        }

        // Do one final read to drain any remaining data
        var finalOut = globalThis.__exactSpawnRead(self._handle, 'stdout');
        if (finalOut && finalOut.length > 0) {
          pushStreamData('stdout', finalOut, modes.stdout);
        }
        var finalErr = globalThis.__exactSpawnRead(self._handle, 'stderr');
        if (finalErr && finalErr.length > 0) {
          pushStreamData('stderr', finalErr, modes.stderr);
        }
        if (self._ipcMode) {
          var finalIpc = globalThis.__exactSpawnRead(self._handle, 'ipc');
          drainIpcPackets(finalIpc);
          closeIpcChannel();
        }

        // End the streams
        closeStreams();

        if (self._disconnectEmitted) {
          self.channel = null;
        }
        // Set exit info
        if (status.signal > 0) {
          self.signalCode = signalNames[status.signal] || null;
          self.exitCode = null;
        } else {
          self.exitCode = status.exitCode;
          self.signalCode = null;
        }

        self.emit('exit', self.exitCode, self.signalCode);
        // 'close' fires after streams are done
        setTimeout(function() {
          self.emit('close', self.exitCode, self.signalCode);
          if (globalThis.__exactSpawnProcesses) {
            delete globalThis.__exactSpawnProcesses[String(self._handle)];
          }
          if (typeof globalThis.__exactSpawnDispose === 'function') {
            globalThis.__exactSpawnDispose(self._handle);
          }
        }, 0);
        self._pumpInProgress = false;
        return;
      }
    }

    if (!self._useNativePump && self._ref) {
      self._pollTimer = setTimeout(pollStreams, pollInterval);
    }
    self._pumpInProgress = false;
  }

  this.__pumpFromNative = pollStreams;

  if (self._useNativePump && self._handle >= 0) {
    var nativePollFallback = function() {
      if (self._exited) {
        return;
      }
      if (typeof self.__pumpFromNative === 'function') {
        self.__pumpFromNative();
      }
      if (!self._exited && self._ref) {
        self._pollTimer = setTimeout(nativePollFallback, pollInterval);
      }
    };
    // Keep the JS event loop alive until the spawn settles for top-level await cases
    // where no other pending tasks exist.
    if (self._handle >= 0) {
      self._pollTimer = setTimeout(function() {
        if (self._exited) return;
        if (!self._spawnEmitted) { self._spawnEmitted = true; self.emit('spawn'); }
        nativePollFallback();
      }, 0);
    }
  } else {
    // Start polling for stdout/stderr data and exit status.
    var fallbackPoll = function() {
      pollStreams();
      if (!self._exited && self._ref) {
        self._pollTimer = setTimeout(fallbackPoll, pollInterval);
      }
    };
    if (self._handle >= 0) {
      self._pollTimer = setTimeout(function() {
        if (self._exited) return;
        if (!self._spawnEmitted) { self._spawnEmitted = true; self.emit('spawn'); }
        fallbackPoll();
      }, 0);
    }
  }
}

// spawn() method for ChildProcess - validates options and spawns process
ChildProcess.prototype.spawn = function(options) {
  if (options === null || typeof options !== 'object') {
    _throwInvalidArgType('options', 'of type object', options);
  }
  if (options.envPairs !== undefined && !Array.isArray(options.envPairs)) {
    _throwInvalidArgType('options.envPairs', 'an instance of Array', options.envPairs);
  }
  if (options.args !== undefined && !Array.isArray(options.args)) {
    _throwInvalidArgType('options.args', 'an instance of Array', options.args);
  }
  if (typeof options.file !== 'string') {
    _throwInvalidArgType('options.file', 'of type string', options.file);
  }

  // Actually spawn the process
  var command = options.file;
  var args = (options.args || []).map(function(a) { return String(a); });
  var normalizedOptions = _normalizeSpawnOptions(options);
  var opts = {};
  if (normalizedOptions.cwd) opts.cwd = String(normalizedOptions.cwd);
  if (normalizedOptions.shell !== undefined) opts.shell = normalizedOptions.shell;
  if (normalizedOptions.env) opts.env = normalizedOptions.env;
  if (normalizedOptions.detached !== undefined) opts.detached = normalizedOptions.detached;
  if (options.stdio) opts.stdio = normalizedOptions.stdio;

  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawn(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: 'Failed to initialize spawn' };
  }

  if (result.error) {
    var self = this;
    self.spawnfile = command;
    self.spawnargs = [command].concat(args);
    var spawnErrCode = result.error === 'EACCES' ? 'EACCES' : result.error === 'EPERM' ? 'EPERM' : 'ENOENT';
    var spawnErrErrno = result.errno ? -result.errno : -2;
    var spawnErr = _makeSpawnError(command, spawnErrCode, spawnErrErrno, 'spawn ' + command);
    spawnErr.spawnargs = self.spawnargs;
    setTimeout(function() {
      self.emit('error', spawnErr);
      self._exited = true;
      self.exitCode = -1;
      self.emit('close', -1, null);
    }, 0);
    return;
  }

  var stdioCfg = {
    stdin: normalizedOptions.stdio[0],
    stdout: normalizedOptions.stdio[1],
    stderr: normalizedOptions.stdio[2],
    ipc: normalizedOptions.stdio[3]
  };
  this._handle = result.handle;
  this.pid = result.pid;
  this.spawnfile = command;
  this.spawnargs = [command].concat(args);

  // Set up streams now
  this._ipcMode = stdioCfg.ipc === 'ipc';
  this.connected = this._ipcMode;
  this.channel = this._ipcMode ? { fd: 3, connected: true } : null;

  var Stream = require('stream');
  var self2 = this;
  if (stdioCfg.stdout === 'pipe') {
    this.stdout = new Stream.Readable();
    this.stdout._read = function() {};
  }
  if (stdioCfg.stderr === 'pipe') {
    this.stderr = new Stream.Readable();
    this.stderr._read = function() {};
  }
  if (stdioCfg.stdin === 'pipe') {
    this.stdin = new Stream.Writable({
      write: function(chunk, encoding, callback) {
        var data = _toUint8String(chunk);
        var ok = globalThis.__exactSpawnWrite(self2._handle, data);
        if (typeof callback === 'function') callback(ok ? null : new Error('write failed'));
      }
    });
  }
  this.stdio = [this.stdin, this.stdout, this.stderr];

  // Start polling
  if (!globalThis.__exactSpawnProcesses) globalThis.__exactSpawnProcesses = {};
  globalThis.__exactSpawnProcesses[String(result.handle)] = this;
  var self3 = this;
  self3._exited = false;
  self3._ref = true;
  self3._useNativePump = typeof globalThis.__exactSpawnRead === 'function';
  var pollInterval = 50;

  var signalNames2 = { 1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 6: 'SIGABRT', 9: 'SIGKILL', 14: 'SIGALRM', 15: 'SIGTERM' };

  function closeStreams2() {
    if (self3.stdout && typeof self3.stdout.push === 'function') self3.stdout.push(null);
    if (self3.stderr && typeof self3.stderr.push === 'function') self3.stderr.push(null);
    if (self3.stdin && typeof self3.stdin.end === 'function') self3.stdin.end();
  }

  function parseStatus2(jsonText) {
    if (!jsonText) return { exited: false };
    try { return JSON.parse(jsonText); } catch(e) { return { exited: false }; }
  }

  function pollStreams2() {
    if (self3._exited) return;
    // Read stdout
    if (self3.stdout && self3._useNativePump) {
      try {
        var out = globalThis.__exactSpawnRead(self3._handle, 1);
        if (out && out.length > 0) self3.stdout.push(out);
      } catch(e) {}
    }
    // Read stderr
    if (self3.stderr && self3._useNativePump) {
      try {
        var errOut = globalThis.__exactSpawnRead(self3._handle, 2);
        if (errOut && errOut.length > 0) self3.stderr.push(errOut);
      } catch(e) {}
    }
    // Poll exit status
    if (!self3._exited) {
      try {
        var statusJson = globalThis.__exactSpawnPoll(self3._handle);
        var status = parseStatus2(statusJson);
        if (status.exited) {
          self3._exited = true;
          // Do one final read
          if (self3._useNativePump) {
            try {
              var finalOut = globalThis.__exactSpawnRead(self3._handle, 1);
              if (finalOut && finalOut.length > 0 && self3.stdout) self3.stdout.push(finalOut);
            } catch(e) {}
            try {
              var finalErr = globalThis.__exactSpawnRead(self3._handle, 2);
              if (finalErr && finalErr.length > 0 && self3.stderr) self3.stderr.push(finalErr);
            } catch(e) {}
          }
          closeStreams2();
          if (status.signal > 0) {
            self3.signalCode = signalNames2[status.signal] || null;
            self3.exitCode = null;
          } else {
            self3.exitCode = status.exitCode;
            self3.signalCode = null;
          }
          self3.emit('exit', self3.exitCode, self3.signalCode);
          setTimeout(function() {
            self3.emit('close', self3.exitCode, self3.signalCode);
            if (globalThis.__exactSpawnProcesses) {
              delete globalThis.__exactSpawnProcesses[String(self3._handle)];
            }
            if (typeof globalThis.__exactSpawnDispose === 'function') {
              globalThis.__exactSpawnDispose(self3._handle);
            }
          }, 0);
          return;
        }
      } catch(e) {}
    }
    if (!self3._exited && self3._ref) {
      self3._pollTimer = setTimeout(pollStreams2, pollInterval);
    }
  }

  setTimeout(function() { self3.emit('spawn'); }, 0);
  self3._pollTimer = setTimeout(pollStreams2, 0);
};

ChildProcess.prototype.kill = function(signal) {
  if (this._exited) return false;
  var sig;
  if (signal === undefined || signal === null || signal === 0) {
    sig = signal === 0 ? 0 : 15; // SIGTERM default
  } else if (typeof signal === 'string') {
    if (!signalMap.hasOwnProperty(signal)) {
      var err = new TypeError('Unknown signal: ' + signal);
      err.code = 'ERR_UNKNOWN_SIGNAL';
      throw err;
    }
    sig = signalMap[signal];
  } else if (typeof signal === 'number') {
    sig = signal;
  } else {
    sig = 15; // SIGTERM
  }
  if (this._handle === null || this._handle === undefined || this._handle < 0) return false;
  var ok = globalThis.__exactSpawnKill(this._handle, sig);
  if (ok) this.killed = true;
  return ok;
};

ChildProcess.prototype.ref = function() {
  this._ref = true;
  if (this._exited || this._pollTimer || !this._handle) {
    return this;
  }
  var self = this;
  if (this._useNativePump && this._handle >= 0) {
    self._pollTimer = setTimeout(function() {
      self.__pumpFromNative();
    }, 0);
  } else {
    self._pollTimer = setTimeout(function() {
      self.__pumpFromNative();
    }, 0);
  }
  return this;
};

ChildProcess.prototype.unref = function() {
  this._ref = false;
  if (this._pollTimer) {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
  }
  return this;
};

ChildProcess.prototype._finalizeDisconnect = function() {
  if (!this.channel) return;
  this.channel = null;
};

ChildProcess.prototype.send = function(message, sendHandle, opts, callback) {
  if (typeof sendHandle === 'function') {
    callback = sendHandle;
    sendHandle = undefined;
    opts = undefined;
  } else if (typeof opts === 'function') {
    callback = opts;
    opts = undefined;
  }

  if (!this._ipcMode || !this.connected) {
    var disconnectedError = _makeIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is closed');
    if (typeof callback === 'function') {
      setTimeout(function() {
        callback(disconnectedError);
      }, 0);
    } else if (this._events && this._events.error) {
      this.emit('error', disconnectedError);
    }
    return false;
  }

  var returnValue = this._ipcQueueSize < this._ipcQueueMax;
  this._ipcQueueSize++;
  var packet = _createIpcPacket('message', message);
  var writeSuccess = false;
  var writeError = null;
  if (typeof globalThis.__exactSpawnWrite === 'function') {
    writeSuccess = globalThis.__exactSpawnWrite(this._handle, packet, 'ipc');
  }
  if (!writeSuccess) {
    returnValue = false;
    writeError = _makeIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed');
  }

  var self = this;
  var callbackError = writeSuccess ? null : writeError;
  if (typeof callback === 'function') {
    self._sendCallbackQueue.push({ callback: callback, error: callbackError });
    if (!self._sendCallbackDraining) {
      self._sendCallbackDraining = true;
      setTimeout(function() {
        while (self._sendCallbackQueue.length > 0) {
          var entry = self._sendCallbackQueue.shift();
          if (self._ipcQueueSize > 0) {
            self._ipcQueueSize--;
          }
          if (typeof entry.callback === 'function') {
            entry.callback(entry.error);
          }
        }
        self._sendCallbackDraining = false;
      }, 0);
    }
    return returnValue;
  }

  self._sendCallbackQueue.push({ callback: null, error: null });
  if (!self._sendCallbackDraining) {
    self._sendCallbackDraining = true;
    setTimeout(function() {
      while (self._sendCallbackQueue.length > 0) {
        var entry = self._sendCallbackQueue.shift();
        if (self._ipcQueueSize > 0) {
          self._ipcQueueSize--;
        }
        if (typeof entry.callback === 'function') {
          entry.callback(entry.error);
        }
      }
      self._sendCallbackDraining = false;
    }, 0);
  }

  if (!writeSuccess && writeError) {
    setTimeout(function() {
      self.emit('error', writeError);
    }, 0);
  }

  return returnValue;
};

ChildProcess.prototype.disconnect = function() {
  if (!this._ipcMode || !this.connected) {
    throw _makeIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
  }
  this._disconnectPending = true;
  this.connected = false;
  this._ipcMode = false;
  if (typeof globalThis.__exactSpawnWrite === 'function') {
    globalThis.__exactSpawnWrite(this._handle, _createIpcPacket('disconnect'), 'ipc');
  }
  var self = this;
  setTimeout(function() {
    self._disconnectPending = false;
    if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
      globalThis.__exactSpawnCloseStdin(self._handle, 'ipc');
    }
    self.channel = null;
    self.emit('disconnect');
  }, 0);
  return this;
};

cp.ChildProcess = ChildProcess;

cp.spawn = function spawn(command, args, options) {
  if (typeof command !== 'string') {
    _throwInvalidArgType('file', 'of type string', command);
  }
  if (command.length === 0) {
    var valErr = new TypeError('The argument \'file\' cannot be empty. Received \'\'');
    valErr.code = 'ERR_INVALID_ARG_VALUE';
    throw valErr;
  }
  _validateNullBytes(command, 'file');
  // Handle optional args parameter
  if (args != null && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  } else if (args != null && !Array.isArray(args)) {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  }
  if (!args) args = [];
  // Coerce args to strings (Node.js does this automatically)
  args = args.map(function(a) { return String(a); });
  if (options === null || (options !== undefined && typeof options !== 'object') || Array.isArray(options)) {
    _throwInvalidArgType('options', 'of type object or undefined', options);
  }
  if (!options) options = {};
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  // Validate serialization option
  if (options.serialization !== undefined && options.serialization !== 'json' && options.serialization !== 'advanced') {
    var serErr = new TypeError("The property 'options.serialization' must be one of: undefined, 'json', 'advanced'. Received " + require('util').inspect(options.serialization));
    serErr.code = 'ERR_INVALID_ARG_VALUE';
    throw serErr;
  }
  // Validate uid/gid
  if (options.uid != null && (typeof options.uid !== 'number' || !Number.isInteger(options.uid) || options.uid < 0 || options.uid > 2147483647)) {
    _throwInvalidArgType('options.uid', 'an int32', options.uid);
  }
  if (options.gid != null && (typeof options.gid !== 'number' || !Number.isInteger(options.gid) || options.gid < 0 || options.gid > 2147483647)) {
    _throwInvalidArgType('options.gid', 'an int32', options.gid);
  }
  // Check uid/gid permissions - throw EPERM if not root
  if (options.uid != null && typeof process !== 'undefined' && typeof process.getuid === 'function') {
    var currentUid = process.getuid();
    if (currentUid !== 0 && options.uid !== currentUid) {
      var uidErr = new Error('spawn EPERM');
      uidErr.code = 'EPERM';
      uidErr.errno = -1;
      uidErr.syscall = 'spawn';
      throw uidErr;
    }
  }
  if (options.gid != null && typeof process !== 'undefined' && typeof process.getgid === 'function') {
    var currentGid = process.getgid();
    var groups = typeof process.getgroups === 'function' ? process.getgroups() : [];
    if (currentGid !== 0 && !groups.some(function(g) { return g === options.gid; }) && options.gid !== currentGid) {
      var gidErr = new Error('spawn EPERM');
      gidErr.code = 'EPERM';
      gidErr.errno = -1;
      gidErr.syscall = 'spawn';
      throw gidErr;
    }
  }

  var normalizedOptions = _normalizeSpawnOptions(options);
  // Validate only one IPC pipe
  if (normalizedOptions.stdio) {
    var ipcCount = 0;
    for (var si = 0; si < normalizedOptions.stdio.length; si++) {
      if (normalizedOptions.stdio[si] === 'ipc') ipcCount++;
    }
    if (ipcCount > 1) {
      var ipcErr = new Error('Child process can have only one IPC pipe');
      ipcErr.code = 'ERR_IPC_ONE_PIPE';
      ipcErr.name = 'Error';
      throw ipcErr;
    }
  }
  var opts = {};
  if (normalizedOptions.cwd) opts.cwd = String(normalizedOptions.cwd);
  if (normalizedOptions.shell !== undefined) opts.shell = normalizedOptions.shell;
  if (normalizedOptions.env) opts.env = normalizedOptions.env;
  if (normalizedOptions.detached !== undefined) opts.detached = normalizedOptions.detached;
  if (options.stdio) opts.stdio = normalizedOptions.stdio;

  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawn(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: 'Failed to initialize spawn' };
  }

  if (result.error) {
    // Return a ChildProcess that emits error, with stdio set up
    var errStdioCfg = {
      stdin: normalizedOptions.stdio[0],
      stdout: normalizedOptions.stdio[1],
      stderr: normalizedOptions.stdio[2],
      ipc: normalizedOptions.stdio[3]
    };
    var errChild = new ChildProcess(-1, undefined, errStdioCfg);
    errChild.pid = undefined;
    errChild._exited = true; // prevent poll loop from running
    errChild._spawnEmitted = true; // prevent spawn event
    errChild.spawnfile = command;
    errChild.spawnargs = [command].concat(args);
    var errCode = result.error === 'EACCES' ? 'EACCES' : result.error === 'EPERM' ? 'EPERM' : 'ENOENT';
    var errErrno = result.errno ? -result.errno : -2;
    var spawnErr2 = _makeSpawnError(command, errCode, errErrno, 'spawn ' + command);
    spawnErr2.spawnargs = args;
    setTimeout(function() {
      errChild.emit('error', spawnErr2);
      errChild.emit('close', null, null);
    }, 0);
    return errChild;
  }

  var stdioCfg = {
    stdin: normalizedOptions.stdio[0],
    stdout: normalizedOptions.stdio[1],
    stderr: normalizedOptions.stdio[2],
    ipc: normalizedOptions.stdio[3]
  };
  var child = new ChildProcess(result.handle, result.pid, stdioCfg);
  // Set spawnfile and spawnargs based on whether shell was used
  if (opts.shell) {
    var shellBin = typeof opts.shell === 'string' ? opts.shell : '/bin/sh';
    var shellCmd = args.length > 0 ? command + ' ' + args.join(' ') : command;
    child.spawnfile = shellBin;
    child.spawnargs = [shellBin, '-c', shellCmd];
  } else {
    child.spawnfile = command;
    child.spawnargs = [command].concat(args);
  }
  if (opts.detached) {
    child.unref();
  }
  // 'spawn' event is now emitted from the constructor's poll loop start
  return child;
};

cp.fork = function fork(modulePath, args, options) {
  if (typeof modulePath !== 'string') {
    _throwInvalidArgType('modulePath', 'of type string', modulePath);
  }
  _validateNullBytes(modulePath, 'modulePath');
  if (Array.isArray(args)) {
    // args provided as array
  } else if (args != null && typeof args === 'object' && !Array.isArray(args)) {
    options = args;
    args = null;
  } else if (args != null && typeof args !== 'undefined') {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  }
  args = args || [];
  if (options != null && (typeof options !== 'object' || Array.isArray(options))) {
    _throwInvalidArgType('options', 'of type object or undefined', options);
  }
  options = options || {};
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);

  var execPath = _fallbackSpawnCommand(options.execPath || (typeof process !== 'undefined' && process.execPath) || 'node');
  var execArgv = options.execArgv || (typeof process !== 'undefined' && process.execArgv) || [];
  var spawnArgs = execArgv.concat([modulePath]).concat(args);
  var silent = options.silent === true;
  var stdio = options.stdio;
  if (!stdio) {
    stdio = [
      silent ? 'pipe' : 'ignore',
      silent ? 'pipe' : 'ignore',
      silent ? 'pipe' : 'ignore',
      'ipc'
    ];
  } else if (typeof stdio === 'string') {
    stdio = [_normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), 'ipc'];
  } else if (Array.isArray(stdio)) {
    stdio = [
      _normalizeSpawnMode(stdio[0], silent ? 'pipe' : 'ignore'),
      _normalizeSpawnMode(stdio[1], silent ? 'pipe' : 'ignore'),
      _normalizeSpawnMode(stdio[2], silent ? 'pipe' : 'ignore'),
      'ipc'
    ];
  }

  var env = _normalizeForkEnv(options.env);
  env.EXACT_IPC_FD = '3';

  var spawnOptions = {
    cwd: options.cwd,
    env: env,
    stdio: stdio,
    detached: options.detached,
    shell: false
  };

  var child = cp.spawn(execPath, spawnArgs, spawnOptions);
  if (options.detached) {
    child.unref();
  }

  return child;
};

module.exports = cp;
