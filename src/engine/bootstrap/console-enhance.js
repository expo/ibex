(function() {
  if (console.__exactConsoleEnhanced) return;
  console.__exactConsoleEnhanced = true;

  var _nativeLog = console.log;
  var _nativeError = console.error;
  var _clearSequence = '\x1b[1;1H\x1b[0J';
  var _stdoutWriteInProgress = false;
  var _stderrWriteInProgress = false;

  function _isValidStreamWrite(stream, candidate) {
    return stream && typeof stream.write === 'function' && stream.write === candidate;
  }

  function clearTTY(stream) {
    if (!stream || !stream.isTTY || typeof stream.write !== 'function') {
      return;
    }
    stream.write(_clearSequence);
  }

  // Format arguments like Node.js util.format: join with spaces, inspect non-strings
  function _formatArgs(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
      if (typeof args[i] === 'string') {
        parts.push(args[i]);
      } else {
        try {
          var util = globalThis.require ? globalThis.require('util') : null;
          parts.push(util && util.inspect ? util.inspect(args[i]) : String(args[i]));
        } catch(e) {
          parts.push(String(args[i]));
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
          // Trailing empty string from final \n — just stop
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
      // Handle (stdout, opts) form where opts is not a stream
      if (stderr && typeof stderr === 'object' && typeof stderr.write !== 'function') {
        opts = stderr;
        stderr = undefined;
      }
      // Handle 3-arg form: Console(stdout, stderr, ignoreErrors)
      if (typeof opts === 'boolean') {
        ignoreErrors = opts;
      }
    }

    if (!stdout || typeof stdout.write !== 'function') {
      var errMsg = new TypeError('The "stdout" argument must be an instance of a writable stream. Received ' + (stdout === undefined ? 'undefined' : typeof stdout));
      errMsg.code = 'ERR_CONSOLE_WRITABLE_STREAM';
      errMsg.message = 'The "stdout" argument must be an instance of WritableStream.';
      throw errMsg;
    }
    if (stderr !== undefined && stderr !== null && typeof stderr.write !== 'function') {
      var errMsg2 = new TypeError('The "stderr" argument must be an instance of a writable stream.');
      errMsg2.code = 'ERR_CONSOLE_WRITABLE_STREAM';
      errMsg2.message = 'The "stderr" argument must be an instance of WritableStream.';
      throw errMsg2;
    }
    if (inspectOptions !== undefined && (typeof inspectOptions !== 'object' || inspectOptions === null)) {
      var invalidMsg = 'The "options.inspectOptions" property must be of type object.';
      if (inspectOptions == null) invalidMsg += ' Received ' + inspectOptions;
      else if (typeof inspectOptions === 'function') invalidMsg += ' Received function ' + (inspectOptions.name || '');
      else if (typeof inspectOptions === 'object') invalidMsg += ' Received an instance of ' + (inspectOptions.constructor ? inspectOptions.constructor.name : 'Object');
      else invalidMsg += ' Received type ' + typeof inspectOptions + ' (' + String(inspectOptions) + ')';
      var errInspect = new TypeError(invalidMsg);
      errInspect.code = 'ERR_INVALID_ARG_TYPE';
      throw errInspect;
    }

    this._stdout = stdout;
    this._stderr = stderr || stdout;
    this._times = {};
    this._counts = {};
    this._groupDepth = 0;
    this._groupIndentation = groupIndentation;
    this._ignoreErrors = ignoreErrors;
    this._inspectOptions = inspectOptions;

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

    var self = this;

    function getGroupIndent() {
      if (self._groupDepth <= 0) return '';
      var indent = '';
      for (var i = 0; i < self._groupDepth * self._groupIndentation; i++) indent += ' ';
      return indent;
    }

    function writeToStream(stream, args) {
      var msg = _formatArgs(args) + '\n';
      var indent = getGroupIndent();
      if (self._ignoreErrors) {
        try { _streamWrite(stream, msg, indent); } catch(e) {}
      } else {
        _streamWrite(stream, msg, indent);
      }
    }

    this.log = function() { writeToStream(self._stdout, arguments); };
    this.debug = this.log;
    this.info = this.log;
    this.dirxml = this.log;
    this.warn = function() { writeToStream(self._stderr, arguments); };
    this.error = this.warn;
    this.dir = function(obj) {
      try {
        var util = globalThis.require ? globalThis.require('util') : null;
        var s = util && util.inspect ? util.inspect(obj) : String(obj);
        writeToStream(self._stdout, [s]);
      } catch(e) {
        writeToStream(self._stdout, [String(obj)]);
      }
    };
    this.time = function(label) { self._times[label || 'default'] = Date.now(); };
    this.timeEnd = function(label) {
      label = label || 'default';
      var start = self._times[label];
      if (start !== undefined) {
        writeToStream(self._stdout, [label + ': ' + (Date.now() - start) + 'ms']);
        delete self._times[label];
      }
    };
    this.timeLog = function(label) {
      label = label || 'default';
      var start = self._times[label];
      if (start !== undefined) {
        var extraArgs = [label + ': ' + (Date.now() - start) + 'ms'];
        for (var i = 1; i < arguments.length; i++) extraArgs.push(arguments[i]);
        writeToStream(self._stdout, extraArgs);
      }
    };
    this.trace = function() {
      var err = new Error();
      var args = Array.prototype.slice.call(arguments);
      args.push('\n' + (err.stack || ''));
      writeToStream(self._stderr, args);
    };
    this.assert = function(condition) {
      if (!condition) {
        var args = Array.prototype.slice.call(arguments, 1);
        if (args.length === 0) args = ['Assertion failed'];
        else args[0] = 'Assertion failed: ' + args[0];
        writeToStream(self._stderr, args);
      }
    };
    this.clear = function() { clearTTY(self._stdout); };
    this.count = function(label) {
      label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
      self._counts[label] = (self._counts[label] || 0) + 1;
      writeToStream(self._stdout, [label + ': ' + self._counts[label]]);
    };
    this.countReset = function(label) {
      label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
      self._counts[label] = 0;
    };
    this.group = function() {
      if (arguments.length > 0) writeToStream(self._stdout, arguments);
      self._groupDepth++;
    };
    this.groupCollapsed = this.group;
    this.groupEnd = function() { if (self._groupDepth > 0) self._groupDepth--; };
    this.table = function(data) { writeToStream(self._stdout, [data]); };
  }

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

    if (!_isValidStreamWrite(stdout, _writeStdout) && stdout && typeof stdout.write === 'function') {
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

    if (!_isValidStreamWrite(stderr, _writeStderr) && stderr && typeof stderr.write === 'function') {
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

  console.log = function() {
    _writeStdout(_formatArgs(arguments) + '\n');
  };
  console.info = console.log;
  console.debug = console.log;
  console.warn = function() {
    _writeStderr(_formatArgs(arguments) + '\n');
  };
  console.error = console.warn;
  console.dir = function(obj) {
    try {
      var util = globalThis.require ? globalThis.require('util') : null;
      var s = util && util.inspect ? util.inspect(obj) : String(obj);
      _writeStdout(s + '\n');
    } catch(e) {
      _writeStdout(String(obj) + '\n');
    }
  };
  console.trace = function() {
    var err = new Error();
    var args = Array.prototype.slice.call(arguments);
    args.push('\n' + (err.stack || ''));
    _writeStderr(_formatArgs(args) + '\n');
  };
  console.time = function(label) {
    _times[label || 'default'] = Date.now();
  };
  console.timeEnd = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      _writeStdout(label + ': ' + (Date.now() - start) + 'ms\n');
      delete _times[label];
    }
  };
  console.timeLog = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      var args = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      _writeStdout(_formatArgs(args) + '\n');
    }
  };
  console.count = function(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    _counts[label] = (_counts[label] || 0) + 1;
    _writeStdout(label + ': ' + _counts[label] + '\n');
  };
  console.countReset = function(label) {
    label = arguments.length === 0 || label === undefined ? 'default' : '' + label;
    _counts[label] = 0;
  };
  console.group = function() {
    if (arguments.length > 0) _writeStdout(_formatArgs(arguments) + '\n');
    _groupDepth++;
    _groupIndent = '';
    for (var i = 0; i < _groupDepth * 2; i++) _groupIndent += ' ';
  };
  console.groupCollapsed = console.group;
  console.groupEnd = function() {
    if (_groupDepth > 0) _groupDepth--;
    _groupIndent = '';
    for (var i = 0; i < _groupDepth * 2; i++) _groupIndent += ' ';
  };
  console.table = function(data) {
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
  console.assert = function(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _writeStderr(_formatArgs(args) + '\n');
    }
  };
  console.clear = function() {
    var stream = (typeof process === 'object' ? process.stdout : undefined);
    clearTTY(stream);
  };

  console.Console = Console;
})();
