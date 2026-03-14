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

  function _repeatTableChar(ch, count) {
    var out = '';
    while (count-- > 0) out += ch;
    return out;
  }

  function _getTableStringWidth(str) {
    if (typeof str !== 'string') return 0;
    str = str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
    var width = 0;
    for (var i = 0; i < str.length; i++) {
      var code = str.codePointAt(i);
      if (code > 0xFFFF) i++;
      if ((code >= 0x1100 && code <= 0x115F) ||
          (code >= 0x2E80 && code <= 0xA4CF && code !== 0x303F) ||
          (code >= 0xAC00 && code <= 0xD7A3) ||
          (code >= 0xF900 && code <= 0xFAFF) ||
          (code >= 0xFE10 && code <= 0xFE6F) ||
          (code >= 0xFF01 && code <= 0xFF60) ||
          (code >= 0xFFE0 && code <= 0xFFE6) ||
          (code >= 0x20000 && code <= 0x2FFFD) ||
          (code >= 0x30000 && code <= 0x3FFFD)) {
        width += 2;
      } else if (code >= 0x20) {
        width += 1;
      }
    }
    return width;
  }

  function _padTableCell(value, width) {
    value = String(value);
    var actualWidth = _getTableStringWidth(value);
    if (actualWidth >= width) return value;
    return value + _repeatTableChar(' ', width - actualWidth);
  }

  function _formatTableInspect(value, depth) {
    var util = _getUtilModule();
    if (util && typeof util.inspect === 'function') {
      try {
        return util.inspect(value, {
          colors: false,
          compact: true,
          breakLength: Infinity,
          maxArrayLength: null,
          maxStringLength: null,
          depth: depth
        });
      } catch (_err) {}
    }
    try {
      return String(value);
    } catch (_err2) {
      return '[Object]';
    }
  }

  function _createTableArgTypeError(name, value) {
    var err = new TypeError(
      'The "' + name + '" argument must be an instance of Array. Received type ' +
      typeof value + ' (' + String(value) + ')'
    );
    err.code = 'ERR_INVALID_ARG_TYPE';
    return err;
  }

  function _formatNonTableValue(value) {
    if (typeof value === 'string') return value;
    if (typeof value === 'function') {
      return value.name ? '[Function: ' + value.name + ']' : '[Function (anonymous)]';
    }
    if (typeof value === 'symbol') return String(value);
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    return String(value);
  }

  function _formatTableCellValue(value, depth) {
    if (typeof value === 'function') {
      return value.name ? '[Function: ' + value.name + ']' : '[Function (anonymous)]';
    }
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    if (typeof value === 'string' || typeof value === 'symbol' || typeof value === 'bigint') {
      return _formatTableInspect(value, 0);
    }
    if (typeof value !== 'object') {
      return String(value);
    }
    if (Array.isArray(value)) {
      if (depth > 0) return '[Array]';
      if (value.length === 0) return '[]';
      var items = [];
      var limit = value.length > 3 ? 3 : value.length;
      for (var ai = 0; ai < limit; ai++) {
        items.push(_formatTableCellValue(value[ai], depth + 1));
      }
      if (value.length > 3) {
        var remaining = value.length - 3;
        items.push('... ' + remaining + ' more item' + (remaining === 1 ? '' : 's'));
      }
      return '[ ' + items.join(', ') + ' ]';
    }
    if (_isPlainTableObject(value)) {
      if (depth > 0) return '[Object]';
      var keys = Object.keys(value);
      if (keys.length === 0) return '{}';
      if (keys.length > 2) return '[Object]';
      var parts = [];
      for (var oi = 0; oi < keys.length; oi++) {
        parts.push(keys[oi] + ': ' + _formatTableCellValue(value[keys[oi]], depth + 1));
      }
      return '{ ' + parts.join(', ') + ' }';
    }
    return _formatTableInspect(value, 0);
  }

  function _isTableBuffer(value) {
    return typeof Buffer !== 'undefined' && Buffer && typeof Buffer.isBuffer === 'function' &&
      Buffer.isBuffer(value);
  }

  function _isTableTypedArray(value) {
    return typeof ArrayBuffer !== 'undefined' &&
      typeof ArrayBuffer.isView === 'function' &&
      ArrayBuffer.isView(value) &&
      !(typeof DataView !== 'undefined' && value instanceof DataView);
  }

  function _isTableArrayLike(value) {
    return Array.isArray(value) || _isTableBuffer(value) || _isTableTypedArray(value);
  }

  function _isPlainTableObject(value) {
    if (!value || typeof value !== 'object') return false;
    return Object.prototype.toString.call(value) === '[object Object]';
  }

  function _isTableRowValue(value) {
    return _isTableArrayLike(value) || _isPlainTableObject(value);
  }

  function _normalizeTableColumns(properties) {
    if (properties === undefined) return null;
    if (!Array.isArray(properties)) {
      throw _createTableArgTypeError('properties', properties);
    }
    var normalized = [];
    for (var i = 0; i < properties.length; i++) {
      normalized.push(String(properties[i]));
    }
    return normalized;
  }

  function _renderConsoleTable(indexHeader, rows, columns) {
    var headers = [indexHeader];
    for (var hi = 0; hi < columns.length; hi++) headers.push(columns[hi]);

    var widths = [];
    for (var wi = 0; wi < headers.length; wi++) {
      widths[wi] = _getTableStringWidth(headers[wi]);
    }

    for (var ri = 0; ri < rows.length; ri++) {
      var row = rows[ri];
      var indexText = String(row.index);
      if (_getTableStringWidth(indexText) > widths[0]) {
        widths[0] = _getTableStringWidth(indexText);
      }
      for (var ci = 0; ci < columns.length; ci++) {
        var key = columns[ci];
        var value = '';
        if (row.values && Object.prototype.hasOwnProperty.call(row.values, key)) {
          value = row.values[key];
        }
        value = value == null ? '' : String(value);
        if (_getTableStringWidth(value) > widths[ci + 1]) {
          widths[ci + 1] = _getTableStringWidth(value);
        }
      }
    }

    function border(left, join, right) {
      var out = left;
      for (var bi = 0; bi < widths.length; bi++) {
        out += _repeatTableChar('─', widths[bi] + 2);
        out += bi === widths.length - 1 ? right : join;
      }
      return out;
    }

    function rowLine(values) {
      var out = '│';
      for (var vi = 0; vi < values.length; vi++) {
        out += ' ' + _padTableCell(values[vi], widths[vi]) + ' │';
      }
      return out;
    }

    var lines = [
      border('┌', '┬', '┐'),
      rowLine(headers),
      border('├', '┼', '┤')
    ];
    for (var rj = 0; rj < rows.length; rj++) {
      var rowValues = [String(rows[rj].index)];
      for (var cj = 0; cj < columns.length; cj++) {
        var column = columns[cj];
        var cell = '';
        if (rows[rj].values && Object.prototype.hasOwnProperty.call(rows[rj].values, column)) {
          cell = rows[rj].values[column];
        }
        rowValues.push(cell == null ? '' : String(cell));
      }
      lines.push(rowLine(rowValues));
    }
    lines.push(border('└', '┴', '┘'));
    return lines.join('\n') + '\n';
  }

  function _formatStructuredTable(indexHeader, entries, properties) {
    var rows = [];
    var columns = properties ? properties.slice() : [];
    var seenColumns = Object.create(null);
    var hasValuesColumn = false;

    if (!properties) {
      for (var si = 0; si < columns.length; si++) {
        seenColumns[columns[si]] = true;
      }
    }

    for (var ei = 0; ei < entries.length; ei++) {
      var entry = entries[ei];
      var rowValue = entry[1];
      var values = Object.create(null);

      if (_isTableRowValue(rowValue)) {
        var rowKeys = properties || Object.keys(rowValue);
        for (var ki = 0; ki < rowKeys.length; ki++) {
          var key = String(rowKeys[ki]);
          if (!properties && !seenColumns[key]) {
            seenColumns[key] = true;
            columns.push(key);
          }
          if (Object.prototype.hasOwnProperty.call(rowValue, key)) {
            values[key] = _formatTableCellValue(rowValue[key], 0);
          }
        }
      } else {
        hasValuesColumn = true;
        values.Values = _formatTableCellValue(rowValue, 0);
      }

      rows.push({
        index: entry[0],
        values: values
      });
    }

    if (!properties && hasValuesColumn && !seenColumns.Values) {
      columns.push('Values');
    }

    return _renderConsoleTable(indexHeader, rows, columns);
  }

  function _formatMapTable(map) {
    var rows = [];
    var index = 0;
    map.forEach(function(value, key) {
      var row = Object.create(null);
      row.Key = _formatTableCellValue(key, 0);
      row.Values = _formatTableCellValue(value, 0);
      rows.push({
        index: String(index++),
        values: row
      });
    });
    return _renderConsoleTable('(iteration index)', rows, ['Key', 'Values']);
  }

  function _formatSetTable(set) {
    var rows = [];
    var index = 0;
    set.forEach(function(value) {
      var row = Object.create(null);
      row.Values = _formatTableCellValue(value, 0);
      rows.push({
        index: String(index++),
        values: row
      });
    });
    return _renderConsoleTable('(iteration index)', rows, ['Values']);
  }

  function _formatIterableTable(iterable) {
    var values = [];
    try {
      values = Array.from(iterable);
    } catch (_err) {
      return null;
    }

    var isEntryIterable = values.length > 0;
    for (var i = 0; i < values.length; i++) {
      if (!Array.isArray(values[i]) || values[i].length !== 2) {
        isEntryIterable = false;
        break;
      }
    }

    if (isEntryIterable) {
      var entryRows = [];
      for (var ei = 0; ei < values.length; ei++) {
        var entryRow = Object.create(null);
        entryRow.Key = _formatTableCellValue(values[ei][0], 0);
        entryRow.Values = _formatTableCellValue(values[ei][1], 0);
        entryRows.push({
          index: String(ei),
          values: entryRow
        });
      }
      return _renderConsoleTable('(iteration index)', entryRows, ['Key', 'Values']);
    }

    var structuredEntries = [];
    for (var vi = 0; vi < values.length; vi++) {
      structuredEntries.push([String(vi), values[vi]]);
    }
    return _formatStructuredTable('(iteration index)', structuredEntries, null);
  }

  function _formatConsoleTable(data, properties) {
    properties = _normalizeTableColumns(properties);

    if (data === null || data === undefined || typeof data === 'boolean' ||
        typeof data === 'number' || typeof data === 'bigint' ||
        typeof data === 'string' || typeof data === 'symbol' ||
        typeof data === 'function') {
      return null;
    }

    if (typeof Map === 'function' && data instanceof Map) {
      return _formatMapTable(data);
    }
    if (typeof Set === 'function' && data instanceof Set) {
      return _formatSetTable(data);
    }
    if (_isTableArrayLike(data)) {
      var arrayEntries = [];
      for (var ai = 0; ai < data.length; ai++) {
        arrayEntries.push([String(ai), data[ai]]);
      }
      return _formatStructuredTable('(index)', arrayEntries, properties);
    }
    if (typeof Symbol !== 'undefined' && Symbol.iterator &&
        data && typeof data[Symbol.iterator] === 'function') {
      return _formatIterableTable(data);
    }
    if (_isPlainTableObject(data)) {
      var objectKeys = Object.keys(data);
      var objectEntries = [];
      for (var oi = 0; oi < objectKeys.length; oi++) {
        objectEntries.push([objectKeys[oi], data[objectKeys[oi]]]);
      }
      return _formatStructuredTable('(index)', objectEntries, properties);
    }

    return null;
  }

  function _writeConsoleTable(self, stream, data, properties, methodName) {
    var table = _formatConsoleTable(data, properties);
    if (table === null) {
      _publishConsoleChannel(methodName, [data, properties]);
      var rawValue = _formatNonTableValue(data) + '\n';
      var rawIndent = _getGroupIndent(self);
      if (self._ignoreErrors) {
        try {
          _streamWrite(stream, rawValue, rawIndent);
        } catch (e) {
          if (e instanceof RangeError) throw e;
        }
      } else {
        _streamWrite(stream, rawValue, rawIndent);
      }
      return;
    }
    _publishConsoleChannel(methodName, [data, properties]);
    var indent = _getGroupIndent(self);
    if (self._ignoreErrors) {
      try {
        _streamWrite(stream, table, indent);
      } catch (e) {
        if (e instanceof RangeError) throw e;
      }
    } else {
      _streamWrite(stream, table, indent);
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
  Console.prototype.table = function table(data, properties) {
    _writeConsoleTable(this, this._stdout, data, properties, 'table');
  };

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

    if (stdout && typeof stdout.write === 'function') {
      _stdoutWriteInProgress = true;
      try {
        stdout.write(encoded);
      } catch (e) {
        if (e instanceof RangeError) throw e;
        if (typeof _nativeLog === 'function') {
          _nativeLog.call(console, msg.replace(/\n$/, ''));
        }
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

    if (stderr && typeof stderr.write === 'function') {
      _stderrWriteInProgress = true;
      try {
        stderr.write(encoded);
      } catch (e) {
        if (e instanceof RangeError) throw e;
        if (typeof _nativeError === 'function') {
          _nativeError.call(console, msg.replace(/\n$/, ''));
        }
      } finally {
        _stderrWriteInProgress = false;
      }
      return;
    }
    if (typeof _nativeError === 'function') {
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
  console.table = function table(data, properties) {
    var table = _formatConsoleTable(data, properties);
    if (table === null) {
      _publishConsoleChannel('table', arguments);
      _writeStdout(_formatNonTableValue(data) + '\n');
      return;
    }
    _publishConsoleChannel('table', arguments);
    _writeStdout(table);
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
