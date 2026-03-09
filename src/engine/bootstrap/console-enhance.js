(function() {
  if (console.__exactConsoleEnhanced) return;
  console.__exactConsoleEnhanced = true;

  var _nativeLog = console.log;
  var _nativeError = console.error;
  var _clearSequence = '\x1b[1;1H\x1b[0J';
  var _stdoutWriteInProgress = false;
  var _stderrWriteInProgress = false;
  var _utilModuleLoaded = false;
  var _utilModule = null;
  var _diagnosticsModuleLoaded = false;
  var _diagnosticsModule = null;

  function _getUtilModule() {
    if (_utilModuleLoaded) return _utilModule;
    _utilModuleLoaded = true;
    try {
      _utilModule = globalThis.require ? globalThis.require('util') : null;
    } catch (_) {
      _utilModule = null;
    }
    return _utilModule;
  }

  function _getDiagnosticsModule() {
    if (_diagnosticsModuleLoaded) return _diagnosticsModule;
    _diagnosticsModuleLoaded = true;
    try {
      _diagnosticsModule = globalThis.require ? globalThis.require('diagnostics_channel') : null;
    } catch (_) {
      _diagnosticsModule = null;
    }
    return _diagnosticsModule;
  }

  function _isValidStreamWrite(stream, candidate) {
    return stream && typeof stream.write === 'function' && stream.write === candidate;
  }

  // Make a function non-constructible (new f() throws TypeError)
  function _makeNonConstructible(fn) {
    if (typeof Proxy === 'function') {
      var p = new Proxy(fn, {
        construct: function() { throw new TypeError(fn.name + ' is not a constructor'); },
        apply: function(target, thisArg, args) { return target.apply(thisArg, args); }
      });
      return p;
    }
    return fn;
  }

  // Returns true if stream.write is our own stream-enhance write (not hijacked by a test)
  function _isExactNativeWrite(stream) {
    return stream && typeof stream.write === 'function' && stream.write.__exactNativeWrite === true;
  }

  function clearTTY(stream) {
    if (!stream || !stream.isTTY || typeof stream.write !== 'function') {
      return;
    }
    stream.write(_clearSequence);
  }

  // Format arguments using util.format for proper %s, %d, etc. support
  function _formatArgs(args, inspectOpts) {
    if (args.length === 0) return '';
    if (!inspectOpts && args.length === 1 && typeof args[0] === 'string') {
      return args[0];
    }
    try {
      var util = _getUtilModule();
      if (util && typeof util.format === 'function') {
        if (inspectOpts) {
          // Use formatWithOptions if available, otherwise fallback
          if (typeof util.formatWithOptions === 'function') {
            var fArgs = [inspectOpts];
            for (var i = 0; i < args.length; i++) fArgs.push(args[i]);
            return util.formatWithOptions.apply(util, fArgs);
          }
        }
        return util.format.apply(util, args);
      }
    } catch(e) {}
    // Fallback: join with spaces
    var parts = [];
    for (var i = 0; i < args.length; i++) {
      if (typeof args[i] === 'string') {
        parts.push(args[i]);
      } else {
        try {
          parts.push(String(args[i]));
        } catch(e2) {
          parts.push('[object]');
        }
      }
    }
    return parts.join(' ');
  }

  // Write to a stream, applying group indentation per line
  function _streamWrite(stream, msg, groupIndent) {
    if (groupIndent) {
      var lines = msg.split('\n');
      var result = '';
      for (var i = 0; i < lines.length; i++) {
        if (i === lines.length - 1 && lines[i] === '') {
          result += '';
          break;
        }
        result += groupIndent + lines[i] + '\n';
      }
      msg = result;
    }
    if (stream && typeof stream.write === 'function') {
      stream.write(msg);
    }
  }

  function _publishConsoleChannel(methodName, args) {
    if (!methodName || !globalThis.require) return;
    try {
      var diagnostics = _getDiagnosticsModule();
      if (!diagnostics || typeof diagnostics.channel !== 'function') return;
      var channelName = 'console.' + methodName;
      if (typeof diagnostics.hasSubscribers === 'function' &&
          !diagnostics.hasSubscribers(channelName)) {
        return;
      }
      diagnostics.channel(channelName).publish(Array.prototype.slice.call(args));
    } catch (_) {}
  }

  // --- Console constructor ---
  function Console(options, stderr, opts) {
    if (!(this instanceof Console)) {
      return new Console(options, stderr, opts);
    }
    var stdout;
    var ignoreErrors = true;
    var colorMode = 'auto';
    var groupIndentation = 2;
    var inspectOptions;

    if (options && typeof options === 'object' && options.stdout) {
      // options-object form: new Console({ stdout, stderr, ... })
      stdout = options.stdout;
      stderr = options.stderr;
      if (options.ignoreErrors !== undefined) ignoreErrors = options.ignoreErrors;
      if (options.colorMode !== undefined) colorMode = options.colorMode;
      if (options.groupIndentation !== undefined) {
        var gi = options.groupIndentation;
        if (typeof gi !== 'number') {
          var err = new TypeError('The "options.groupIndentation" property must be of type number. Received ' + typeof gi);
          err.code = 'ERR_INVALID_ARG_TYPE';
          throw err;
        }
        if (!Number.isInteger(gi)) {
          var err2 = new RangeError('The value of "options.groupIndentation" is out of range. It must be an integer. Received ' + gi);
          err2.code = 'ERR_OUT_OF_RANGE';
          throw err2;
        }
        if (gi < 0 || gi > 1000) {
          var err3 = new RangeError('The value of "options.groupIndentation" is out of range. It must be >= 0 && <= 1000. Received ' + gi);
          err3.code = 'ERR_OUT_OF_RANGE';
          throw err3;
        }
        groupIndentation = gi;
      }
      if (options.inspectOptions !== undefined) {
        inspectOptions = options.inspectOptions;
      }
    } else {
      stdout = options;
      // Handle 3-arg form: Console(stdout, stderr, ignoreErrors)
      if (typeof opts === 'boolean') {
        ignoreErrors = opts;
      } else if (typeof stderr === 'boolean') {
        // Console(stdout, ignoreErrors) form
        ignoreErrors = stderr;
        stderr = undefined;
      }
    }

    if (!stdout || typeof stdout.write !== 'function') {
      var errMsg = new TypeError('The "stdout" argument must be an instance of WritableStream.');
      errMsg.code = 'ERR_CONSOLE_WRITABLE_STREAM';
      throw errMsg;
    }
    if (stderr !== undefined && stderr !== null && typeof stderr.write !== 'function') {
      var errMsg2 = new TypeError('The "stderr" argument must be an instance of WritableStream.');
      errMsg2.code = 'ERR_CONSOLE_WRITABLE_STREAM';
      throw errMsg2;
    }

    // Validate colorMode
    if (colorMode !== 'auto' && colorMode !== true && colorMode !== false) {
      var util = _getUtilModule();
      var received = util && util.inspect ? util.inspect(colorMode) : String(colorMode);
      var cmErr = new TypeError("The argument 'colorMode' must be one of: 'auto', true, false. Received " + received);
      cmErr.code = 'ERR_INVALID_ARG_VALUE';
      throw cmErr;
    }

    // Validate inspectOptions
    if (inspectOptions !== undefined && !(inspectOptions instanceof Map) && (typeof inspectOptions !== 'object' || inspectOptions === null)) {
      var invalidMsg = 'The "options.inspectOptions" property must be of type object.';
      if (inspectOptions == null) invalidMsg += ' Received ' + inspectOptions;
      else if (typeof inspectOptions === 'function') invalidMsg += ' Received function ' + (inspectOptions.name || '');
      else if (typeof inspectOptions === 'object') invalidMsg += ' Received an instance of ' + (inspectOptions.constructor ? inspectOptions.constructor.name : 'Object');
      else invalidMsg += ' Received type ' + typeof inspectOptions + ' (' + String(inspectOptions) + ')';
      var errInspect = new TypeError(invalidMsg);
      errInspect.code = 'ERR_INVALID_ARG_TYPE';
      throw errInspect;
    }

    // Check colorMode + inspectOptions.colors incompatibility
    // Only throw if colorMode was explicitly passed in options (not the default)
    if (options && typeof options === 'object' && options.stdout && options.colorMode !== undefined &&
        inspectOptions && typeof inspectOptions === 'object' && !(inspectOptions instanceof Map) &&
        inspectOptions.colors !== undefined) {
      var incompatErr = new TypeError('Option "options.inspectOptions.color" cannot be used in combination with option "colorMode"');
      incompatErr.code = 'ERR_INCOMPATIBLE_OPTION_PAIR';
      throw incompatErr;
    }

    this._stdout = stdout;
    this._stderr = stderr || stdout;
    this._times = {};
    this._counts = {};
    this._groupDepth = 0;
    this._groupIndentation = groupIndentation;
    this._ignoreErrors = ignoreErrors;
    this._inspectOptions = inspectOptions;
    this._colorMode = colorMode;

    // When ignoreErrors is true, suppress 'error' events on streams
    if (ignoreErrors) {
      var noop = function() {};
      if (stdout && typeof stdout.on === 'function') {
        try { stdout.on('error', noop); } catch(e) {}
      }
      if (this._stderr !== stdout && this._stderr && typeof this._stderr.on === 'function') {
        try { this._stderr.on('error', noop); } catch(e) {}
      }
    }

    // Bind prototype methods to this instance, but only if not overridden by subclass
    // Use non-constructible wrappers so new c.log() throws TypeError
    var methodNames = ['log', 'debug', 'info', 'dirxml', 'warn', 'error', 'dir',
                       'time', 'timeEnd', 'timeLog', 'trace', 'assert', 'clear',
                       'count', 'countReset', 'group', 'groupCollapsed', 'groupEnd', 'table'];
    for (var mi = 0; mi < methodNames.length; mi++) {
      var mName = methodNames[mi];
      if (this[mName] === Console.prototype[mName]) {
        var bound = this[mName].bind(this);
        Object.defineProperty(bound, 'name', { value: this[mName].name, configurable: true });
        this[mName] = _makeNonConstructible(bound);
      }
    }
  }

  // Helper to get the group indent string
  function _getGroupIndent(self) {
    if (self._groupDepth <= 0) return '';
    var indent = '';
    for (var i = 0; i < self._groupDepth * self._groupIndentation; i++) indent += ' ';
    return indent;
  }

  // Helper to get inspect options for a given stream
  function _getInspectOpts(self, stream) {
    var opts = {};
    if (self._inspectOptions) {
      if (self._inspectOptions instanceof Map) {
        var streamOpts = self._inspectOptions.get(stream);
        if (streamOpts) {
          var sKeys = Object.keys(streamOpts);
          for (var si = 0; si < sKeys.length; si++) opts[sKeys[si]] = streamOpts[sKeys[si]];
        }
      } else {
        var keys = Object.keys(self._inspectOptions);
        for (var ki = 0; ki < keys.length; ki++) opts[keys[ki]] = self._inspectOptions[keys[ki]];
      }
    }
    // Apply colorMode
    if (opts.colors === undefined) {
      if (self._colorMode === true) opts.colors = true;
      else if (self._colorMode === false) opts.colors = false;
      else if (self._colorMode === 'auto') opts.colors = !!(stream && stream.isTTY);
    }
    return opts;
  }

  // Write to a Console's stream with proper indentation and error handling
  function _consoleWrite(self, stream, args, methodName) {
    _publishConsoleChannel(methodName, args);
    var inspectOpts = _getInspectOpts(self, stream);
    var hasOpts = false;
    var optKeys = Object.keys(inspectOpts);
    for (var oi = 0; oi < optKeys.length; oi++) {
      if (inspectOpts[optKeys[oi]] !== undefined) { hasOpts = true; break; }
    }
    var msg = _formatArgs(args, hasOpts ? inspectOpts : undefined) + '\n';
    var indent = _getGroupIndent(self);
    if (self._ignoreErrors) {
      try { _streamWrite(stream, msg, indent); } catch(e) {
        // Re-throw stack overflow (RangeError) even with ignoreErrors
        if (e instanceof RangeError) throw e;
      }
    } else {
      _streamWrite(stream, msg, indent);
    }
  }

  // Define methods on Console.prototype
  Console.prototype.log = function log() { _consoleWrite(this, this._stdout, arguments, 'log'); };
  Console.prototype.debug = function debug() { _consoleWrite(this, this._stdout, arguments, 'debug'); };
  Console.prototype.info = function info() { _consoleWrite(this, this._stdout, arguments, 'info'); };
  Console.prototype.dirxml = function dirxml() { _consoleWrite(this, this._stdout, arguments); };
  Console.prototype.warn = function warn() { _consoleWrite(this, this._stderr, arguments, 'warn'); };
  Console.prototype.error = function error() { _consoleWrite(this, this._stderr, arguments, 'error'); };
  Console.prototype.dir = function dir(obj, options) {
    try {
      var util = _getUtilModule();
      var inspectOpts = _getInspectOpts(this, this._stdout);
      if (options) {
        var oKeys = Object.keys(options);
        for (var oi = 0; oi < oKeys.length; oi++) inspectOpts[oKeys[oi]] = options[oKeys[oi]];
      }
      var s = util && util.inspect ? util.inspect(obj, inspectOpts) : String(obj);
      var msg = s + '\n';
      var indent = _getGroupIndent(this);
      if (this._ignoreErrors) {
        try { _streamWrite(this._stdout, msg, indent); } catch(e) {
          if (e instanceof RangeError) throw e;
        }
      } else {
        _streamWrite(this._stdout, msg, indent);
      }
    } catch(e) {
      if (e instanceof RangeError) throw e;
      if (this._ignoreErrors) return;
      throw e;
    }
  };
  Console.prototype.time = function time(label) {
    this._times[label !== undefined ? '' + label : 'default'] = Date.now();
  };
  Console.prototype.timeEnd = function timeEnd(label) {
    label = label !== undefined ? '' + label : 'default';
    var start = this._times[label];
    if (start !== undefined) {
      var msg = label + ': ' + (Date.now() - start) + 'ms\n';
      var indent = _getGroupIndent(this);
      if (this._ignoreErrors) {
        try { _streamWrite(this._stdout, msg, indent); } catch(e) {
          if (e instanceof RangeError) throw e;
        }
      } else {
        _streamWrite(this._stdout, msg, indent);
      }
      delete this._times[label];
    }
  };
  Console.prototype.timeLog = function timeLog(label) {
    label = label !== undefined ? '' + label : 'default';
    var start = this._times[label];
    if (start !== undefined) {
      var extraArgs = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) extraArgs.push(arguments[i]);
      _consoleWrite(this, this._stdout, extraArgs);
    }
  };
  Console.prototype.trace = function trace() {
    var err = new Error();
    var args = Array.prototype.slice.call(arguments);
    args.push('\n' + (err.stack || ''));
    _consoleWrite(this, this._stderr, args);
  };
  Console.prototype.assert = function assert(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _consoleWrite(this, this._stderr, args);
    }
  };
  Console.prototype.clear = function clear() { clearTTY(this._stdout); };
  Console.prototype.count = function count(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    this._counts[label] = (this._counts[label] || 0) + 1;
    var msg = label + ': ' + this._counts[label] + '\n';
    var indent = _getGroupIndent(this);
    if (this._ignoreErrors) {
      try { _streamWrite(this._stdout, msg, indent); } catch(e) {
        if (e instanceof RangeError) throw e;
      }
    } else {
      _streamWrite(this._stdout, msg, indent);
    }
  };
  Console.prototype.countReset = function countReset(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    this._counts[label] = 0;
  };
  Console.prototype.group = function group() {
    if (arguments.length > 0) _consoleWrite(this, this._stdout, arguments);
    this._groupDepth++;
  };
  Console.prototype.groupCollapsed = function groupCollapsed() {
    if (arguments.length > 0) _consoleWrite(this, this._stdout, arguments);
    this._groupDepth++;
  };
  Console.prototype.groupEnd = function groupEnd() { if (this._groupDepth > 0) this._groupDepth--; };
  Console.prototype.table = function table(data) { _consoleWrite(this, this._stdout, [data]); };

  // Make globalThis.console instanceof Console return true
  if (typeof Symbol !== 'undefined' && Symbol.hasInstance) {
    var _origProto = Console.prototype;
    Object.defineProperty(Console, Symbol.hasInstance, {
      value: function(instance) {
        if (instance === console) return true;
        // Check prototype chain without triggering Symbol.hasInstance recursion
        var proto = instance;
        while (proto != null) {
          if (proto === _origProto) return true;
          proto = Object.getPrototypeOf(proto);
        }
        return false;
      }
    });
  }

  // --- Enhance global console to route through process.stdout.write/process.stderr.write ---
  var _times = {};
  var _counts = {};
  var _groupDepth = 0;
  var _groupIndent = '';

  function _getStdout() {
    return (typeof process === 'object' && process && process.stdout) ? process.stdout : null;
  }
  function _getStderr() {
    return (typeof process === 'object' && process && process.stderr) ? process.stderr : null;
  }


  function _writeStdout(msg) {
    var stdout = _getStdout();
    if (_stdoutWriteInProgress) {
      if (typeof _nativeLog === 'function') _nativeLog.call(console, msg.replace(/\n$/, ''));
      return;
    }

    var encoded = _groupIndent ? msg.split('\n').map(function(line, i, arr) {
      return (i === arr.length - 1 && line === '') ? '' : _groupIndent + line;
    }).join('\n') : msg;

    if (!_isValidStreamWrite(stdout, _writeStdout) && _isExactNativeWrite(stdout)) {
      _stdoutWriteInProgress = true;
      try {
        stdout.write(encoded);
      } finally {
        _stdoutWriteInProgress = false;
      }
      return;
    }
    if (typeof _nativeLog === 'function') {
      _nativeLog.call(console, msg.replace(/\n$/, ''));
    }
  }
  function _writeStderr(msg) {
    var stderr = _getStderr();
    if (_stderrWriteInProgress) {
      if (typeof _nativeError === 'function') {
        _nativeError.call(console, msg.replace(/\n$/, ''));
      }
      return;
    }

    var encoded = _groupIndent ? msg.split('\n').map(function(line, i, arr) {
      return (i === arr.length - 1 && line === '') ? '' : _groupIndent + line;
    }).join('\n') : msg;

    if (!_isValidStreamWrite(stderr, _writeStderr) && _isExactNativeWrite(stderr)) {
      _stderrWriteInProgress = true;
      try {
        stderr.write(encoded);
      } finally {
        _stderrWriteInProgress = false;
      }
    } else if (typeof _nativeError === 'function') {
      _nativeError.call(console, msg.replace(/\n$/, ''));
      return;
    }
    return;
  }

  console.log = function log() {
    _publishConsoleChannel('log', arguments);
    _writeStdout(_formatArgs(arguments) + '\n');
  };
  console.info = function info() {
    _publishConsoleChannel('info', arguments);
    _writeStdout(_formatArgs(arguments) + '\n');
  };
  console.debug = function debug() {
    _publishConsoleChannel('debug', arguments);
    _writeStdout(_formatArgs(arguments) + '\n');
  };
  console.warn = function warn() {
    _publishConsoleChannel('warn', arguments);
    _writeStderr(_formatArgs(arguments) + '\n');
  };
  console.error = function error() {
    _publishConsoleChannel('error', arguments);
    _writeStderr(_formatArgs(arguments) + '\n');
  };
  console.dir = function dir(obj) {
    try {
      var util = globalThis.require ? globalThis.require('util') : null;
      var s = util && util.inspect ? util.inspect(obj) : String(obj);
      _writeStdout(s + '\n');
    } catch(e) {
      _writeStdout('[object]\n');
    }
  };
  console.dirxml = console.log;
  console.trace = function trace() {
    var err = new Error();
    var args = Array.prototype.slice.call(arguments);
    args.push('\n' + (err.stack || ''));
    _writeStderr(_formatArgs(args) + '\n');
  };
  console.time = function time(label) {
    _times[label || 'default'] = Date.now();
  };
  console.timeEnd = function timeEnd(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      _writeStdout(label + ': ' + (Date.now() - start) + 'ms\n');
      delete _times[label];
    }
  };
  console.timeLog = function timeLog(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      var args = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      _writeStdout(_formatArgs(args) + '\n');
    }
  };
  console.count = function count(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    _counts[label] = (_counts[label] || 0) + 1;
    _writeStdout(label + ': ' + _counts[label] + '\n');
  };
  console.countReset = function countReset(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    _counts[label] = 0;
  };
  console.group = function group() {
    if (arguments.length > 0) _writeStdout(_formatArgs(arguments) + '\n');
    _groupDepth++;
    _groupIndent = '';
    for (var i = 0; i < _groupDepth * 2; i++) _groupIndent += ' ';
  };
  console.groupCollapsed = console.group;
  console.groupEnd = function groupEnd() {
    if (_groupDepth > 0) _groupDepth--;
    _groupIndent = '';
    for (var i = 0; i < _groupDepth * 2; i++) _groupIndent += ' ';
  };
  console.table = function table(data) {
    if (Array.isArray(data)) {
      _writeStdout('(index) | Value\n');
      for (var i = 0; i < data.length; i++) {
        if (typeof data[i] === 'object' && data[i] !== null) {
          var keys = Object.keys(data[i]);
          var parts = [];
          for (var k = 0; k < keys.length; k++) parts.push(keys[k] + ': ' + data[i][keys[k]]);
          _writeStdout(i + '       | { ' + parts.join(', ') + ' }\n');
        } else {
          _writeStdout(i + '       | ' + data[i] + '\n');
        }
      }
    } else if (typeof data === 'object' && data !== null) {
      var objKeys = Object.keys(data);
      for (var j = 0; j < objKeys.length; j++) {
        _writeStdout(objKeys[j] + ': ' + data[objKeys[j]] + '\n');
      }
    } else {
      _writeStdout(String(data) + '\n');
    }
  };
  console.assert = function assert(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _writeStderr(_formatArgs(args) + '\n');
    }
  };
  console.clear = function clear() {
    var stream = (typeof process === 'object' ? process.stdout : undefined);
    clearTTY(stream);
  };

  // Make all global console methods non-constructible
  var _globalMethodNames = ['log', 'info', 'debug', 'warn', 'error', 'dir', 'dirxml',
                            'trace', 'time', 'timeEnd', 'timeLog', 'count', 'countReset',
                            'group', 'groupCollapsed', 'groupEnd', 'table', 'assert', 'clear'];
  for (var gmi = 0; gmi < _globalMethodNames.length; gmi++) {
    var gName = _globalMethodNames[gmi];
    if (typeof console[gName] === 'function') {
      console[gName] = _makeNonConstructible(console[gName]);
    }
  }

  console.Console = Console;
})();
