(function() {
  var _times = {};
  var _counts = {};
  var _groupDepth = 0;
  var _origLog = console.log;
  var _origError = console.error;

  console.time = function(label) {
    _times[label || 'default'] = Date.now();
  };
  console.timeEnd = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      _origLog.call(console, label + ': ' + (Date.now() - start) + 'ms');
      delete _times[label];
    }
  };
  console.timeLog = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      var args = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      _origLog.apply(console, args);
    }
  };
  console.count = function(label) {
    label = label || 'default';
    _counts[label] = (_counts[label] || 0) + 1;
    _origLog.call(console, label + ': ' + _counts[label]);
  };
  console.countReset = function(label) {
    _counts[label || 'default'] = 0;
  };
  console.group = function() {
    _groupDepth++;
    if (arguments.length > 0) _origLog.apply(console, arguments);
  };
  console.groupCollapsed = console.group;
  console.groupEnd = function() {
    if (_groupDepth > 0) _groupDepth--;
  };
  console.table = function(data) {
    if (Array.isArray(data)) {
      _origLog.call(console, '(index) | Value');
      for (var i = 0; i < data.length; i++) {
        if (typeof data[i] === 'object' && data[i] !== null) {
          var keys = Object.keys(data[i]);
          var parts = [];
          for (var k = 0; k < keys.length; k++) parts.push(keys[k] + ': ' + data[i][keys[k]]);
          _origLog.call(console, i + '       | { ' + parts.join(', ') + ' }');
        } else {
          _origLog.call(console, i + '       | ' + data[i]);
        }
      }
    } else if (typeof data === 'object' && data !== null) {
      var objKeys = Object.keys(data);
      for (var j = 0; j < objKeys.length; j++) {
        _origLog.call(console, objKeys[j] + ': ' + data[objKeys[j]]);
      }
    } else {
      _origLog.call(console, data);
    }
  };
  console.assert = function(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _origError.apply(console, args);
    }
  };
  console.clear = function() {};

  // Console constructor — creates a new console instance that writes to given streams
  function Console(stdout, stderr, opts) {
    if (!(this instanceof Console)) {
      return new Console(stdout, stderr, opts);
    }
    if (!stdout) {
      throw new TypeError('Console expects a writable stream instance');
    }
    // Handle options object as second arg
    if (stderr && typeof stderr === 'object' && !stderr.write) {
      opts = stderr;
      stderr = undefined;
    }
    this._stdout = stdout;
    this._stderr = stderr || stdout;
    this._times = {};
    this._counts = {};
    this._groupDepth = 0;

    var self = this;
    var write = function(stream, args) {
      var msg = '';
      for (var i = 0; i < args.length; i++) {
        if (i > 0) msg += ' ';
        msg += typeof args[i] === 'string' ? args[i] : String(args[i]);
      }
      msg += '\n';
      if (stream && typeof stream.write === 'function') {
        stream.write(msg);
      }
    };

    this.log = function() { write(self._stdout, arguments); };
    this.log.name = 'log';
    this.debug = this.log;
    this.info = this.log;
    this.dirxml = this.log;
    this.warn = function() { write(self._stderr, arguments); };
    this.warn.name = 'warn';
    this.error = this.warn;
    this.dir = function(obj) { write(self._stdout, [typeof obj === 'object' ? JSON.stringify(obj) : String(obj)]); };
    this.dir.name = 'dir';
    this.time = function(label) { self._times[label || 'default'] = Date.now(); };
    this.time.name = 'time';
    this.timeEnd = function(label) {
      label = label || 'default';
      var start = self._times[label];
      if (start !== undefined) {
        write(self._stdout, [label + ': ' + (Date.now() - start) + 'ms']);
        delete self._times[label];
      }
    };
    this.timeEnd.name = 'timeEnd';
    this.timeLog = function(label) {
      label = label || 'default';
      var start = self._times[label];
      if (start !== undefined) {
        var args = [label + ': ' + (Date.now() - start) + 'ms'];
        for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
        write(self._stdout, args);
      }
    };
    this.timeLog.name = 'timeLog';
    this.trace = function() {
      var err = new Error();
      var args = Array.prototype.slice.call(arguments);
      args.push('\n' + (err.stack || ''));
      write(self._stderr, args);
    };
    this.trace.name = 'trace';
    this.assert = function(condition) {
      if (!condition) {
        var args = Array.prototype.slice.call(arguments, 1);
        if (args.length === 0) args = ['Assertion failed'];
        else args[0] = 'Assertion failed: ' + args[0];
        write(self._stderr, args);
      }
    };
    this.assert.name = 'assert';
    this.clear = function() {};
    this.clear.name = 'clear';
    this.count = function(label) {
      label = label || 'default';
      self._counts[label] = (self._counts[label] || 0) + 1;
      write(self._stdout, [label + ': ' + self._counts[label]]);
    };
    this.count.name = 'count';
    this.countReset = function(label) { self._counts[label || 'default'] = 0; };
    this.countReset.name = 'countReset';
    this.group = function() {
      self._groupDepth++;
      if (arguments.length > 0) write(self._stdout, arguments);
    };
    this.group.name = 'group';
    this.groupCollapsed = this.group;
    this.groupEnd = function() { if (self._groupDepth > 0) self._groupDepth--; };
    this.groupEnd.name = 'groupEnd';
    this.table = function(data) { write(self._stdout, [data]); };
    this.table.name = 'table';
  }

  console.Console = Console;
})();
