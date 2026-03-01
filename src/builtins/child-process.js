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
  if (opts.maxBuffer) o.maxBuffer = Number(opts.maxBuffer);
  if (opts.encoding !== undefined) o.encoding = opts.encoding;
  if (opts.env) o.env = opts.env;
  if (opts.shell !== undefined) o.shell = opts.shell;
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

  cp.execSync = function execSync(command, options) {
    if (typeof command !== 'string') {
      throw new TypeError('The "command" argument must be of type string');
    }
    command = _fallbackSpawnCommand(command);
    var opts = normalizeExecOptions(options);
  var optsJson = JSON.stringify(opts);
  var resultJson = globalThis.__exactExecSync(command, optsJson);
  var result = JSON.parse(resultJson);

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

  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';
  if (encoding === 'buffer' || encoding === null) {
    // Return as Buffer-like Uint8Array
    var encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;
    if (encoder) {
      return encoder.encode(result.stdout);
    }
    var buf = new Uint8Array(result.stdout.length);
    for (var i = 0; i < result.stdout.length; i++) {
      buf[i] = result.stdout.charCodeAt(i);
    }
    return buf;
  }

  return result.stdout;
};

  cp.spawnSync = function spawnSync(command, args, options) {
    if (typeof command !== 'string') {
      throw new TypeError('The "command" argument must be of type string');
    }
    command = _fallbackSpawnCommand(command);
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  var opts = normalizeExecOptions(options);
  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var resultJson = globalThis.__exactSpawnSync(command, argsJson, optsJson);
  var result = JSON.parse(resultJson);

  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';

  var stdoutOutput = result.stdout || '';
  var stderrOutput = result.stderr || '';

  if (encoding === 'buffer' || encoding === null) {
    var encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;
    if (encoder) {
      stdoutOutput = encoder.encode(stdoutOutput);
      stderrOutput = encoder.encode(stderrOutput);
    } else {
      var toBuf = function(s) {
        var buf = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
        return buf;
      };
      stdoutOutput = toBuf(stdoutOutput);
      stderrOutput = toBuf(stderrOutput);
    }
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

  if (result.error) {
    spawnResult.error = new Error(result.error);
  }
  if (result.status < 0) {
    spawnResult.signal = 'SIGKILL';
  }

  return spawnResult;
};

cp.execFileSync = function execFileSync(file, args, options) {
  if (typeof file !== 'string') {
    throw new TypeError('The "file" argument must be of type string');
  }
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  var result = cp.spawnSync(file, args, options);

  if (result.error) {
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
  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';
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
  var opts = normalizeExecOptions(options);
  var maxBuffer = opts.maxBuffer || 1024 * 1024;
  var encoding = opts.encoding !== undefined ? opts.encoding : 'utf8';
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
    var stdout = stdoutChunks.join('');
    var stderr = stderrChunks.join('');
    if (code !== 0 || killed) {
      var err = makeExecError(
        'Command failed: ' + command + (stderr ? '\n' + stderr : ''),
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

  if (opts.timeout && opts.timeout > 0) {
    timeoutId = setTimeout(function() {
      killed = true;
      child.kill();
    }, opts.timeout);
  }

  return child;
};

cp.execFile = function execFile(file, args, options, callback) {
  if (typeof args === 'function') {
    callback = args;
    args = [];
    options = {};
  } else if (args && !Array.isArray(args) && typeof args === 'object') {
    callback = options;
    options = args;
    args = [];
  } else if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (!args) args = [];
  if (!options) options = {};
  var opts = normalizeExecOptions(options);
  var maxBuffer = opts.maxBuffer || 1024 * 1024;
  var encoding = opts.encoding !== undefined ? opts.encoding : 'utf8';
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
    var stdout = stdoutChunks.join('');
    var stderr = stderrChunks.join('');
    if (code !== 0 || killed) {
      var err = makeExecError(
        'Command failed: ' + file + (stderr ? '\n' + stderr : ''),
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
    normalized.stdio[0] = _normalizeSpawnMode(stdio[0], 'pipe');
    normalized.stdio[1] = _normalizeSpawnMode(stdio[1], 'pipe');
    normalized.stdio[2] = _normalizeSpawnMode(stdio[2], 'pipe');
    normalized.stdio[3] = _normalizeSpawnMode(stdio[3], 'pipe');
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

// ChildProcess constructor (extends EventEmitter)
function ChildProcess(handle, pid, stdioModes) {
  var EventEmitter;
  try { EventEmitter = require('events'); } catch(e) {
    EventEmitter = function() { this._events = {}; };
    EventEmitter.prototype.on = function(ev, fn) { if (!this._events) this._events = {}; if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
    EventEmitter.prototype.emit = function(ev) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
    EventEmitter.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
    EventEmitter.prototype.removeListener = function(ev, fn) { if (!this._events) this._events = {}; var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
    EventEmitter.prototype.removeAllListeners = function(ev) { if (!this._events) this._events = {}; if (ev) delete this._events[ev]; else this._events = {}; return this; };
  }
  EventEmitter.call(this);
  if (EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  this._events = this._events || {};
  this._handle = handle;
  this.pid = pid;
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
  var modes = stdioModes || {
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
    ipc: 'pipe'
  };
  this._ipcMode = modes.ipc === 'ipc';
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
    self._pollTimer = setTimeout(nativePollFallback, 0);
  } else {
    // Start polling for stdout/stderr data and exit status.
    var fallbackPoll = function() {
      pollStreams();
      if (!self._exited && self._ref) {
        self._pollTimer = setTimeout(fallbackPoll, pollInterval);
      }
    };
    self._pollTimer = setTimeout(fallbackPoll, 0);
  }
}

ChildProcess.prototype.kill = function(signal) {
  if (this._exited) return false;
  var sig;
  if (typeof signal === 'string') {
    sig = signalMap[signal] || 15; // default SIGTERM
  } else if (typeof signal === 'number') {
    sig = signal;
  } else {
    sig = 15; // SIGTERM
  }
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
    throw new TypeError('The "command" argument must be of type string');
  }
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  if (!options) options = {};

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
    // Return a ChildProcess that immediately emits error
    var errChild = new ChildProcess(-1, 0);
    errChild.spawnfile = command;
    errChild.spawnargs = [command].concat(args);
    setTimeout(function() {
      errChild.emit('error', new Error(result.error));
      errChild._exited = true;
      errChild.exitCode = -1;
      errChild.emit('exit', -1, null);
      errChild.emit('close', -1, null);
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
  child.spawnfile = command;
  child.spawnargs = [command].concat(args);
  if (opts.detached) {
    child.unref();
  }
  setTimeout(function() { child.emit('spawn'); }, 0);
  return child;
};

cp.fork = function fork(modulePath, args, options) {
  if (typeof modulePath !== 'string') {
    throw new TypeError('The "modulePath" argument must be of type string');
  }
  if (Array.isArray(args)) {
    // args provided as array
  } else if (typeof args === 'object' && args !== null && !Array.isArray(args)) {
    options = args;
    args = [];
  }
  args = args || [];
  options = options || {};

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
