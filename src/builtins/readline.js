var EventEmitter = require('events');
var StringDecoder = require('string_decoder').StringDecoder;

var kEscape = '\x1b';
var kHistorySize = 30;
var kEscapeCodeTimeout = 500;
var kMinCrlfDelay = 100;
var KEYPRESS_DECODER = typeof Symbol === 'function' ? Symbol('keypress-decoder') : '__exactKeypressDecoder__';
var KEYPRESS_STATE = typeof Symbol === 'function' ? Symbol('keypress-state') : '__exactKeypressState__';
var KEYPRESS_WRITE_PATCHED = typeof Symbol === 'function' ? Symbol('keypress-write-patched') : '__exactKeypressWritePatched__';
var KEYPRESS_SUPPRESS_WRITE = typeof Symbol === 'function' ? Symbol('keypress-suppress-write') : '__exactKeypressSuppressWrite__';
var internalSymbol = typeof Symbol === 'function' ? Symbol.for('__BUN_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED__') : '__BUN_INTERNALS__';
var ansiPattern = /[\u001B\u009B][[\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\d\/#&.:=?%@~_]+)*|[a-zA-Z\d]+(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?(?:\u0007|\u001B\u005C|\u009C))|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g;

function _typeOf(value) {
  return value === null ? 'null' : typeof value;
}

function _createInvalidArgTypeError(name, expected, value) {
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received type ' + _typeOf(value));
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _createOutOfRangeError(name, range, value) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + range + '. Received ' + String(value));
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _createInvalidArgValueError(name, value) {
  var err = new TypeError('The value of "' + name + '" is invalid. Received ' + String(value));
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _createUseAfterCloseError() {
  var err = new Error('readline was closed');
  err.code = 'ERR_USE_AFTER_CLOSE';
  return err;
}

function _createAbortError(cause) {
  var err = new Error('The operation was aborted');
  err.name = 'AbortError';
  err.code = 'ABORT_ERR';
  if (cause !== undefined) err.cause = cause;
  return err;
}

function stripVTControlCharacters(str) {
  return String(str).replace(ansiPattern, '');
}

function isZeroWidthCodePoint(code) {
  return code <= 0x1F ||
    (code >= 0x7F && code <= 0x9F) ||
    (code >= 0x300 && code <= 0x36F) ||
    (code >= 0x200B && code <= 0x200F) ||
    (code >= 0x20D0 && code <= 0x20FF) ||
    (code >= 0xFE00 && code <= 0xFE0F) ||
    (code >= 0xFE20 && code <= 0xFE2F) ||
    (code >= 0xE0100 && code <= 0xE01EF);
}

function isFullWidthCodePoint(code) {
  return code >= 0x1100 && (
    code <= 0x115f ||
    code === 0x2329 ||
    code === 0x232a ||
    (code >= 0x2e80 && code <= 0x3247 && code !== 0x303f) ||
    (code >= 0x3250 && code <= 0x4dbf) ||
    (code >= 0x4e00 && code <= 0xa4c6) ||
    (code >= 0xa960 && code <= 0xa97c) ||
    (code >= 0xac00 && code <= 0xd7a3) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xfe10 && code <= 0xfe19) ||
    (code >= 0xfe30 && code <= 0xfe6b) ||
    (code >= 0xff01 && code <= 0xff60) ||
    (code >= 0xffe0 && code <= 0xffe6) ||
    (code >= 0x1b000 && code <= 0x1b001) ||
    (code >= 0x1f200 && code <= 0x1f251) ||
    (code >= 0x1f300 && code <= 0x1f64f) ||
    (code >= 0x20000 && code <= 0x3fffd)
  );
}

function getStringWidth(str, removeControlChars) {
  var text = String(str);
  var width = 0;
  var i = 0;
  if (removeControlChars !== false) {
    text = stripVTControlCharacters(text);
  }
  if (typeof text.normalize === 'function') {
    text = text.normalize('NFC');
  }
  while (i < text.length) {
    var code = text.codePointAt(i);
    if (isFullWidthCodePoint(code)) width += 2;
    else if (!isZeroWidthCodePoint(code)) width += 1;
    i += code > 0xFFFF ? 2 : 1;
  }
  return width;
}

function charLengthLeft(str, i) {
  if (i <= 0) return 0;
  if ((i > 1 && str.codePointAt(i - 2) >= 0x10000) || str.codePointAt(i - 1) >= 0x10000) {
    return 2;
  }
  return 1;
}

function charLengthAt(str, i) {
  if (str.length <= i) return 1;
  return str.codePointAt(i) >= 0x10000 ? 2 : 1;
}

function commonPrefix(strings) {
  if (!strings || strings.length === 0) return '';
  if (strings.length === 1) return strings[0];
  var sorted = strings.slice().sort();
  var min = sorted[0];
  var max = sorted[sorted.length - 1];
  var i = 0;
  while (i < min.length && min.charAt(i) === max.charAt(i)) i++;
  return min.slice(0, i);
}

function CSI(strings) {
  var out = kEscape + '[';
  for (var i = 0; i < strings.length; i++) {
    out += strings[i];
    if (i + 1 < arguments.length) out += String(arguments[i + 1]);
  }
  return out;
}
CSI.kEscape = kEscape;
CSI.kClearToLineBeginning = CSI(['1K']);
CSI.kClearToLineEnd = CSI(['0K']);
CSI.kClearLine = CSI(['2K']);
CSI.kClearScreenDown = CSI(['0J']);

function _applyCodeName(code, key) {
  switch (code) {
    case '[P': key.name = 'f1'; break;
    case '[Q': key.name = 'f2'; break;
    case '[R': key.name = 'f3'; break;
    case '[S': key.name = 'f4'; break;
    case 'OP': key.name = 'f1'; break;
    case 'OQ': key.name = 'f2'; break;
    case 'OR': key.name = 'f3'; break;
    case 'OS': key.name = 'f4'; break;
    case '[11~': key.name = 'f1'; break;
    case '[12~': key.name = 'f2'; break;
    case '[13~': key.name = 'f3'; break;
    case '[14~': key.name = 'f4'; break;
    case '[15~': key.name = 'f5'; break;
    case '[17~': key.name = 'f6'; break;
    case '[18~': key.name = 'f7'; break;
    case '[19~': key.name = 'f8'; break;
    case '[20~': key.name = 'f9'; break;
    case '[21~': key.name = 'f10'; break;
    case '[23~': key.name = 'f11'; break;
    case '[24~': key.name = 'f12'; break;
    case '[[A': key.name = 'f1'; break;
    case '[[B': key.name = 'f2'; break;
    case '[[C': key.name = 'f3'; break;
    case '[[D': key.name = 'f4'; break;
    case '[[E': key.name = 'f5'; break;
    case '[A': key.name = 'up'; break;
    case '[B': key.name = 'down'; break;
    case '[C': key.name = 'right'; break;
    case '[D': key.name = 'left'; break;
    case '[E': key.name = 'clear'; break;
    case '[F': key.name = 'end'; break;
    case '[H': key.name = 'home'; break;
    case 'OA': key.name = 'up'; break;
    case 'OB': key.name = 'down'; break;
    case 'OC': key.name = 'right'; break;
    case 'OD': key.name = 'left'; break;
    case 'OE': key.name = 'clear'; break;
    case 'OF': key.name = 'end'; break;
    case 'OH': key.name = 'home'; break;
    case '[1~': key.name = 'home'; break;
    case '[2~': key.name = 'insert'; break;
    case '[3~': key.name = 'delete'; break;
    case '[4~': key.name = 'end'; break;
    case '[5~': key.name = 'pageup'; break;
    case '[6~': key.name = 'pagedown'; break;
    case '[[5~': key.name = 'pageup'; break;
    case '[[6~': key.name = 'pagedown'; break;
    case '[7~': key.name = 'home'; break;
    case '[8~': key.name = 'end'; break;
    case '[a': key.name = 'up'; key.shift = true; break;
    case '[b': key.name = 'down'; key.shift = true; break;
    case '[c': key.name = 'right'; key.shift = true; break;
    case '[d': key.name = 'left'; key.shift = true; break;
    case '[e': key.name = 'clear'; key.shift = true; break;
    case '[2$': key.name = 'insert'; key.shift = true; break;
    case '[3$': key.name = 'delete'; key.shift = true; break;
    case '[5$': key.name = 'pageup'; key.shift = true; break;
    case '[6$': key.name = 'pagedown'; key.shift = true; break;
    case '[7$': key.name = 'home'; key.shift = true; break;
    case '[8$': key.name = 'end'; key.shift = true; break;
    case 'Oa': key.name = 'up'; key.ctrl = true; break;
    case 'Ob': key.name = 'down'; key.ctrl = true; break;
    case 'Oc': key.name = 'right'; key.ctrl = true; break;
    case 'Od': key.name = 'left'; key.ctrl = true; break;
    case 'Oe': key.name = 'clear'; key.ctrl = true; break;
    case '[2^': key.name = 'insert'; key.ctrl = true; break;
    case '[3^': key.name = 'delete'; key.ctrl = true; break;
    case '[5^': key.name = 'pageup'; key.ctrl = true; break;
    case '[6^': key.name = 'pagedown'; key.ctrl = true; break;
    case '[7^': key.name = 'home'; key.ctrl = true; break;
    case '[8^': key.name = 'end'; key.ctrl = true; break;
    case '[Z': key.name = 'tab'; key.shift = true; break;
    case '[200~': key.name = 'paste-start'; break;
    case '[201~': key.name = 'paste-end'; break;
    default: key.name = 'undefined'; break;
  }
}

function _emitDecodedKey(stream, sequence, key, escaped) {
  key.sequence = sequence;
  if (sequence.length !== 0 && (key.name !== undefined || escaped)) {
    stream.emit('keypress', escaped ? undefined : sequence, key);
    return;
  }
  if (charLengthAt(sequence, 0) === sequence.length) {
    stream.emit('keypress', sequence, key);
  }
}

function _decodeKeyAt(str, start) {
  var ch = str.charAt(start);
  var key = { sequence: null, name: undefined, ctrl: false, meta: false, shift: false };
  var escaped = false;
  var s = ch;
  var index = start + 1;
  var code;
  var modifier = 0;
  var cmd;
  var match;

  if (ch === kEscape) {
    escaped = true;
    if (index >= str.length) return { needMore: true, prefix: s };
    ch = str.charAt(index);
    s += ch;
    index += 1;
    if (ch === kEscape) {
      if (index >= str.length) return { needMore: true, prefix: s };
      ch = str.charAt(index);
      s += ch;
      index += 1;
    }
  }

  if (escaped && (ch === 'O' || ch === '[')) {
    code = ch;
    if (ch === 'O') {
      if (index >= str.length) return { needMore: true, prefix: s };
      ch = str.charAt(index);
      s += ch;
      index += 1;
      if (ch >= '0' && ch <= '9') {
        modifier = Number(ch) - 1;
        if (index >= str.length) return { needMore: true, prefix: s };
        ch = str.charAt(index);
        s += ch;
        index += 1;
      }
      code += ch;
    } else {
      if (index >= str.length) return { needMore: true, prefix: s };
      ch = str.charAt(index);
      s += ch;
      index += 1;
      if (ch === '[') {
        code += ch;
        if (index >= str.length) return { needMore: true, prefix: s };
        ch = str.charAt(index);
        s += ch;
        index += 1;
      }
      if (ch >= '0' && ch <= '9') {
        while (index < str.length && ch >= '0' && ch <= '9') {
          ch = str.charAt(index);
          s += ch;
          index += 1;
          if (ch < '0' || ch > '9') break;
        }
      }
      if (ch === ';') {
        if (index >= str.length) return { needMore: true, prefix: s };
        ch = str.charAt(index);
        s += ch;
        index += 1;
        if (ch >= '0' && ch <= '9' && index < str.length) {
          ch = str.charAt(index);
          s += ch;
          index += 1;
        }
      }
      cmd = s.slice(s.lastIndexOf('[') + 1);
      match = /^(?:(\d\d?)(?:;(\d))?([~^$])|(\d{3}~))$/.exec(cmd);
      if (match) {
        if (match[4]) code += match[4];
        else {
          code += match[1] + match[3];
          modifier = Number(match[2] || 1) - 1;
        }
      } else {
        match = /^((\d;)?(\d))?([A-Za-z])$/.exec(cmd);
        if (match) {
          code += match[4];
          modifier = Number(match[3] || 1) - 1;
        } else {
          code += cmd;
        }
      }
    }

    key.ctrl = !!(modifier & 4);
    key.meta = !!(modifier & 10);
    key.shift = !!(modifier & 1);
    key.code = code;
    _applyCodeName(code, key);
    return { consumed: index - start, sequence: s, key: key, escaped: true };
  }

  if (ch === '\r') {
    key.name = 'return';
    key.meta = escaped;
  } else if (ch === '\n') {
    key.name = 'enter';
    key.meta = escaped;
  } else if (ch === '\t') {
    key.name = 'tab';
    key.meta = escaped;
  } else if (ch === '\b' || ch === '\x7f') {
    key.name = 'backspace';
    key.meta = escaped;
  } else if (ch === kEscape) {
    key.name = 'escape';
    key.meta = escaped;
  } else if (ch === ' ') {
    key.name = 'space';
    key.meta = escaped;
  } else if (!escaped && ch <= '\x1a') {
    key.name = String.fromCharCode(ch.charCodeAt(0) + 'a'.charCodeAt(0) - 1);
    key.ctrl = true;
  } else if (/^[0-9A-Za-z]$/.test(ch)) {
    key.name = ch.toLowerCase();
    key.shift = /^[A-Z]$/.test(ch);
    key.meta = escaped;
  } else if (escaped) {
    key.name = ch.length ? undefined : 'escape';
    key.meta = true;
  }

  return { consumed: index - start, sequence: s, key: key, escaped: escaped };
}

function emitKeypressEvents(stream, iface) {
  iface = iface || {};
  if (!stream || stream[KEYPRESS_DECODER]) return;
  stream[KEYPRESS_DECODER] = new StringDecoder('utf8');
  stream[KEYPRESS_STATE] = { pending: '', timeoutId: null };

  function triggerEscape() {
    var state = stream[KEYPRESS_STATE];
    if (!state || !state.pending) return;
    state.pending = '';
    state.timeoutId = null;
    stream.emit('keypress', undefined, {
      sequence: kEscape,
      name: 'escape',
      ctrl: false,
      meta: true,
      shift: false
    });
  }

  function onData(input) {
    var state = stream[KEYPRESS_STATE];
    var string;
    var index = 0;
    string = typeof input === 'string' ? input : stream[KEYPRESS_DECODER].write(input);
    if (!string) return;
    if (state.timeoutId) {
      clearTimeout(state.timeoutId);
      state.timeoutId = null;
    }
    if (state.pending) {
      string = state.pending + string;
      state.pending = '';
    }
    iface._sawKeyPress = charLengthAt(string, 0) === string.length;
    iface.isCompletionEnabled = false;
    while (index < string.length) {
      var parsed = _decodeKeyAt(string, index);
      if (parsed.needMore) {
        state.pending = parsed.prefix || string.slice(index);
        state.timeoutId = setTimeout(triggerEscape, iface.escapeCodeTimeout || kEscapeCodeTimeout);
        index = string.length;
        break;
      }
      index += parsed.consumed;
      if (index === string.length) iface.isCompletionEnabled = true;
      _emitDecodedKey(stream, parsed.sequence, parsed.key, parsed.escaped);
    }
  }

  function onReadable() {
    var chunk;
    if (typeof stream.read !== 'function') return;
    while ((chunk = stream.read()) != null) {
      onData(chunk);
    }
  }

  if (typeof stream.read === 'function') {
    stream.on('readable', onReadable);
  } else {
    stream.on('data', onData);
  }
  if (typeof stream.write === 'function' && !stream[KEYPRESS_WRITE_PATCHED]) {
    var originalWrite = stream.write;
    stream[KEYPRESS_WRITE_PATCHED] = true;
    stream.write = function(chunk) {
      if (!this[KEYPRESS_SUPPRESS_WRITE]) {
        onData(chunk);
      }
      return originalWrite.apply(this, arguments);
    };
  }
}

function _parseConstructorArgs(args) {
  var input = args[0];
  var output = args[1];
  var completer = args[2];
  var terminal = args[3];
  var options;
  if (input && typeof input === 'object' && input.input) {
    options = input;
  } else {
    options = { input: input, output: output, completer: completer, terminal: terminal };
  }
  return options;
}

function Interface() {
  var options;
  if (!(this instanceof Interface)) return new Interface(arguments[0], arguments[1], arguments[2], arguments[3]);
  EventEmitter.call(this);
  options = _parseConstructorArgs(arguments);
  this.input = options.input || (typeof process !== 'undefined' ? process.stdin : null);
  this.output = Object.prototype.hasOwnProperty.call(options, 'output') ? options.output : (typeof process !== 'undefined' ? process.stdout : null);
  this.completer = options.completer;
  this.terminal = options.terminal !== undefined ? !!options.terminal : !!(this.output && this.output.isTTY);
  this._promptStr = options.prompt !== undefined ? String(options.prompt) : '> ';
  this.closed = false;
  this.line = '';
  this._lineBuffer = '';
  this.cursor = 0;
  this.history = options.history === undefined ? [] : options.history;
  this.historyIndex = -1;
  this.historySize = options.historySize === undefined ? kHistorySize : options.historySize;
  this.removeHistoryDuplicates = !!options.removeHistoryDuplicates;
  this.escapeCodeTimeout = kEscapeCodeTimeout;
  this.tabSize = 8;
  this.crlfDelay = Math.max(options.crlfDelay || 100, kMinCrlfDelay);
  this._paused = false;
  this._questionReject = null;
  this._lastTabLine = null;
  this.isCompletionEnabled = true;
  this._sawKeyPress = false;
  if (this.completer !== undefined && typeof this.completer !== 'function') {
    throw _createInvalidArgValueError('completer', this.completer);
  }
  if (!Array.isArray(this.history)) {
    throw _createInvalidArgTypeError('history', 'Array', this.history);
  }
  if (typeof this.historySize !== 'number') {
    throw _createInvalidArgTypeError('historySize', 'number', this.historySize);
  }
  if (!isFinite(this.historySize) || this.historySize < 0) {
    throw _createOutOfRangeError('historySize', '>= 0', this.historySize);
  }
  if (options.tabSize !== undefined) {
    if (typeof options.tabSize !== 'number') {
      throw _createInvalidArgTypeError('tabSize', 'number', options.tabSize);
    }
    if (!isFinite(options.tabSize) || options.tabSize <= 0 || options.tabSize % 1 !== 0) {
      if (options.tabSize % 1 !== 0) {
        throw _createOutOfRangeError('tabSize', 'an integer', options.tabSize);
      }
      throw _createOutOfRangeError('tabSize', '>= 1', options.tabSize);
    }
    this.tabSize = options.tabSize;
  }
  if (options.escapeCodeTimeout !== undefined) {
    if (typeof options.escapeCodeTimeout !== 'number' || !isFinite(options.escapeCodeTimeout)) {
      throw _createInvalidArgValueError('input.escapeCodeTimeout', options.escapeCodeTimeout);
    }
    this.escapeCodeTimeout = options.escapeCodeTimeout;
  }

  var self = this;
  if (this.input && typeof this.input.on === 'function') {
    this._onError = function(err) {
      if (self.closed) return;
      self.emit('error', err);
      self.close();
    };
    this._onClose = function() {
      if (!self.closed) self.close();
    };
    this._onEnd = function() {
      if (self.closed) return;
      if (!self.terminal && self._lineBuffer.length > 0) {
        var remaining = self._lineBuffer;
        self._lineBuffer = '';
        self.line = remaining;
        self.emit('line', remaining);
      }
      self.close();
    };
    if (this.terminal) {
      emitKeypressEvents(this.input, this);
      this._onKeypress = function(s, key) {
        if (self.closed) return;
        self._ttyWrite(s, key);
      };
      this.input.on('keypress', this._onKeypress);
      if (typeof this.input.setRawMode === 'function') this.input.setRawMode(true);
    } else {
      this._onData = function(chunk) {
        if (self.closed) return;
        self._normalWrite(chunk);
      };
      this.input.on('data', this._onData);
    }
    this.input.on('error', this._onError);
    this.input.on('end', this._onEnd);
    this.input.on('close', this._onClose);
    if (typeof this.input.resume === 'function') this.input.resume();
  }
}
Interface.prototype = Object.create(EventEmitter.prototype);
Interface.prototype.constructor = Interface;

Interface.prototype._getColumns = function() {
  if (this.output && typeof this.output.columns === 'number' && isFinite(this.output.columns) && this.output.columns > 0) {
    return this.output.columns;
  }
  if (this.input && typeof this.input.columns === 'number' && isFinite(this.input.columns) && this.input.columns > 0) {
    return this.input.columns;
  }
  return Infinity;
};

Interface.prototype._getDisplayPos = function(str) {
  var offset = 0;
  var rows = 0;
  var col = this._getColumns();
  var text = stripVTControlCharacters(str);
  var i = 0;
  while (i < text.length) {
    var code = text.codePointAt(i);
    var char = String.fromCodePoint(code);
    var width;
    if (char === '\n') {
      rows += !isFinite(col) ? 1 : (Math.ceil(offset / col) || 1);
      offset = 0;
      i += char.length;
      continue;
    }
    if (char === '\t') {
      offset += this.tabSize - (offset % this.tabSize);
      i += char.length;
      continue;
    }
    width = getStringWidth(char, false);
    if (width === 2 && isFinite(col) && col > 0 && (offset + 1) % col === 0) {
      offset += 1;
    }
    offset += width;
    i += char.length;
  }
  if (!isFinite(col) || col <= 0) {
    return { cols: offset, rows: rows };
  }
  var cols = offset % col;
  rows += (offset - cols) / col;
  return { cols: cols, rows: rows };
};

Interface.prototype.getCursorPos = function() {
  return this._getDisplayPos(this._promptStr + this.line.slice(0, this.cursor));
};

Interface.prototype._writeToOutput = function(text) {
  if (this.output && typeof this.output.write === 'function') {
    this.output[KEYPRESS_SUPPRESS_WRITE] = true;
    try {
      this.output.write(String(text));
    } finally {
      this.output[KEYPRESS_SUPPRESS_WRITE] = false;
    }
  }
};

Interface.prototype._refreshLine = function() {
  var cursorPos;
  if (!this.terminal || !this.output || typeof this.output.write !== 'function') return;
  cursorPos = this.getCursorPos();
  this.output.write('\x1b[1G\x1b[0J' + this._promptStr + this.line + '\x1b[' + (cursorPos.cols + 1) + 'G');
};

Interface.prototype._insertString = function(value) {
  var text = String(value);
  this.line = this.line.slice(0, this.cursor) + text + this.line.slice(this.cursor);
  this.cursor += text.length;
  if (this.terminal) this._writeToOutput(text);
};

Interface.prototype._deleteLeft = function() {
  var len;
  if (this.cursor <= 0) return;
  len = charLengthLeft(this.line, this.cursor);
  this.line = this.line.slice(0, this.cursor - len) + this.line.slice(this.cursor);
  this.cursor -= len;
  if (this.terminal) this._refreshLine();
};

Interface.prototype._deleteLineLeft = function() {
  if (this.cursor <= 0) return;
  this.line = this.line.slice(this.cursor);
  this.cursor = 0;
  if (this.terminal) this._refreshLine();
};

Interface.prototype._addHistory = function(line) {
  var index;
  if (!this.terminal || this.historySize <= 0 || !line) return;
  if (this.removeHistoryDuplicates) {
    index = this.history.indexOf(line);
    if (index !== -1) this.history.splice(index, 1);
  } else if (this.history[0] === line) {
    return;
  }
  this.history.unshift(line);
  if (this.history.length > this.historySize) this.history.length = this.historySize;
  this.emit('history', this.history.slice());
};

Interface.prototype._finishLine = function() {
  var line = this.line;
  this._addHistory(line);
  this.line = '';
  this.cursor = 0;
  if (this.terminal) this._writeToOutput('\r\n');
  this.emit('line', line);
};

Interface.prototype._resolveCompletion = function(done) {
  var self = this;
  if (!this.completer) return done([[], this.line]);
  try {
    if (this.completer.length === 2) {
      return this.completer(this.line, function(err, value) {
        if (err) done([[], self.line]);
        else done(value || [[], self.line]);
      });
    }
    var result = this.completer(this.line);
    if (result && typeof result.then === 'function') {
      result.then(function(value) { done(value || [[], self.line]); }, function() { done([[], self.line]); });
      return;
    }
    done(result || [[], self.line]);
  } catch (_) {
    done([[], this.line]);
  }
};

Interface.prototype._showCompletions = function(completions) {
  var cols = this._getColumns();
  var lines;
  if (!this.terminal) return;
  if (!isFinite(cols)) {
    this._writeToOutput('\r\n' + completions.join('\r\n'));
    this._refreshLine();
    return;
  }
  lines = completions.join('\r\n');
  this._writeToOutput('\r\n' + lines + '\r\n');
  this._refreshLine();
};

Interface.prototype._tabComplete = function() {
  var self = this;
  if (!this.completer) {
    this._insertString('\t');
    return;
  }
  this._resolveCompletion(function(result) {
    var completions = Array.isArray(result && result[0]) ? result[0].filter(function(entry) { return entry !== ''; }) : [];
    var completeOn = result && typeof result[1] === 'string' ? result[1] : self.line;
    var prefix = commonPrefix(completions);
    if (prefix && prefix.length > completeOn.length && self.line.indexOf(completeOn, self.cursor - completeOn.length) !== -1) {
      var insert = prefix.slice(completeOn.length);
      self._insertString(insert);
      self._lastTabLine = self.line;
      return;
    }
    if (self._lastTabLine === self.line && completions.length > 0) {
      self._showCompletions(completions);
      return;
    }
    self._lastTabLine = self.line;
  });
};

Interface.prototype._ttyWrite = function(s, key) {
  key = key || {};
  if (key && key.ctrl) {
    if (key.name === 'u') {
      this._deleteLineLeft();
      return;
    }
    if (key.name === 'c' || key.name === 'd') {
      if (typeof this._questionReject === 'function') {
        var reject = this._questionReject;
        this._questionReject = null;
        reject(_createAbortError());
      }
      this.close();
      return;
    }
  }
  if (key && key.name === 'backspace') {
    this._deleteLeft();
    return;
  }
  if (key && key.name === 'tab') {
    this._tabComplete();
    return;
  }
  if (key && (key.name === 'return' || key.name === 'enter')) {
    this._finishLine();
    this._lastTabLine = null;
    return;
  }
  if (typeof s === 'string' && s.length > 0) {
    this._insertString(s);
    this._lastTabLine = null;
  }
};

Interface.prototype._normalWrite = function(chunk) {
  var str = typeof chunk === 'string' ? chunk : (chunk && typeof chunk.toString === 'function' ? chunk.toString('utf8') : String(chunk));
  this._lineBuffer += str;
  var lines = this._lineBuffer.split(/\r\n|[\n\r\x85\u2028\u2029]/);
  this._lineBuffer = lines.pop() || '';
  for (var i = 0; i < lines.length; i++) {
    this.line = lines[i];
    this.cursor = this.line.length;
    this._addHistory(this.line);
    this.emit('line', this.line);
  }
  if (this._lineBuffer) {
    this.line = this._lineBuffer;
    this.cursor = this.line.length;
  }
};

Interface.prototype.setPrompt = function(p) {
  this._promptStr = String(p);
};

Interface.prototype.getPrompt = function() {
  return this._promptStr;
};

Interface.prototype.prompt = function() {
  if (!this.closed) this._writeToOutput(this._promptStr);
};

Interface.prototype.question = function(query, options, cb) {
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  if (this.closed) throw _createUseAfterCloseError();
  if (this.output) this.output.write(String(query));
  var self = this;
  function onLine(answer) {
    self.removeListener('line', onLine);
    if (cb) cb(answer);
  }
  this.on('line', onLine);
};

Interface.prototype.write = function(data, key) {
  var str;
  var i;
  if (this.closed) return;
  if (key) {
    this._ttyWrite(data == null ? '' : String(data), key);
    return;
  }
  if (data == null) return;
  str = String(data);
  if (this.terminal) {
    for (i = 0; i < str.length; i += charLengthAt(str, i)) {
      var ch = str.slice(i, i + charLengthAt(str, i));
      var parsed = _decodeKeyAt(ch, 0);
      this._ttyWrite(parsed.escaped ? undefined : parsed.sequence, parsed.key);
    }
    return;
  }
  this._normalWrite(str);
};

Interface.prototype.close = function() {
  if (this.closed) return;
  this.closed = true;
  if (this.input && typeof this.input.removeListener === 'function') {
    if (this._onData) this.input.removeListener('data', this._onData);
    if (this._onKeypress) this.input.removeListener('keypress', this._onKeypress);
    if (this._onError) this.input.removeListener('error', this._onError);
    if (this._onEnd) this.input.removeListener('end', this._onEnd);
    if (this._onClose) this.input.removeListener('close', this._onClose);
  }
  if (this.terminal && this.input && typeof this.input.setRawMode === 'function') {
    this.input.setRawMode(false);
  }
  if (this.input && typeof this.input.pause === 'function') this.input.pause();
  this.emit('close');
};

Interface.prototype.pause = function() {
  this._paused = true;
  if (this.input && typeof this.input.pause === 'function') this.input.pause();
  this.emit('pause');
  return this;
};

Interface.prototype.resume = function() {
  this._paused = false;
  if (this.input && typeof this.input.resume === 'function') this.input.resume();
  this.emit('resume');
  return this;
};

Interface.prototype[Symbol.asyncIterator] = function() {
  var self = this;
  var done = false;
  var error = null;
  var queue = [];
  var resolve = null;
  var reject = null;
  function emitResult() {
    if (resolve === null) return;
    if (error !== null) {
      var pendingReject = reject;
      resolve = null;
      reject = null;
      pendingReject(error);
      return;
    }
    if (done) {
      var pendingResolve = resolve;
      resolve = null;
      reject = null;
      pendingResolve({ value: undefined, done: true });
      return;
    }
    if (queue.length > 0) {
      var pendingResolve = resolve;
      resolve = null;
      pendingResolve({ value: queue.shift(), done: false });
    }
  }
  self.on('line', function(line) {
    if (resolve) { var r = resolve; resolve = null; r({ value: line, done: false }); }
    else queue.push(line);
  });
  self.on('error', function(err) {
    if (done) return;
    done = true;
    error = err;
    emitResult();
  });
  self.on('close', function() {
    if (done) return;
    done = true;
    emitResult();
  });
  return {
    next: function() {
      if (queue.length > 0) return Promise.resolve({ value: queue.shift(), done: false });
      if (error !== null) return Promise.reject(error);
      if (done) return Promise.resolve({ value: undefined, done: true });
      return new Promise(function(r, rej) { resolve = r; reject = rej; });
    }
  };
};

function PromiseInterface() {
  if (!(this instanceof PromiseInterface)) return new PromiseInterface(arguments[0], arguments[1], arguments[2], arguments[3]);
  Interface.apply(this, arguments);
}
PromiseInterface.prototype = Object.create(Interface.prototype);
PromiseInterface.prototype.constructor = PromiseInterface;
PromiseInterface.prototype.question = function(query, options, cb) {
  if (typeof options === 'function' || typeof cb === 'function') {
    return Interface.prototype.question.call(this, query, options, cb);
  }
  if (this.closed) return Promise.reject(_createUseAfterCloseError());
  var self = this;
  options = options || {};
  return new Promise(function(resolve, reject) {
    var signal = options.signal;
    var settled = false;
    function cleanup() {
      if (signal && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onAbort);
      }
      if (self._questionReject === rejectQuestion) {
        self._questionReject = null;
      }
    }
    function settle(fn, value) {
      if (settled) return;
      settled = true;
      cleanup();
      fn(value);
    }
    function onAbort() {
      settle(reject, _createAbortError(signal.reason));
    }
    function rejectQuestion(err) {
      settle(reject, err);
    }
    if (signal && signal.aborted) {
      reject(_createAbortError(signal.reason));
      return;
    }
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', onAbort);
    }
    self._questionReject = rejectQuestion;
    Interface.prototype.question.call(self, query, options, function(answer) {
      settle(resolve, answer);
    });
  });
};

function createInterface() {
  if (arguments.length === 1 && arguments[0] && typeof arguments[0] === 'object' && arguments[0].input) {
    return new Interface(arguments[0]);
  }
  return new Interface(arguments[0], arguments[1], arguments[2], arguments[3]);
}

var promises = {
  Interface: PromiseInterface,
  createInterface: function() {
    if (arguments.length === 1 && arguments[0] && typeof arguments[0] === 'object' && arguments[0].input) {
      return new PromiseInterface(arguments[0]);
    }
    return new PromiseInterface(arguments[0], arguments[1], arguments[2], arguments[3]);
  }
};

function _validateReadlineCallback(callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    var err = new TypeError('The "callback" argument must be of type function. Received type ' + typeof callback);
    err.code = 'ERR_INVALID_ARG_TYPE';
    err.name = 'TypeError [ERR_INVALID_ARG_TYPE]';
    throw err;
  }
}

function _validateReadlineCoordinate(name, value) {
  if (typeof value === 'number' && value !== value) {
    var err = new TypeError('The value of "' + name + '" is out of range. It must be a valid number. Received NaN');
    err.code = 'ERR_INVALID_ARG_VALUE';
    err.name = 'TypeError [ERR_INVALID_ARG_VALUE]';
    throw err;
  }
}

function clearLine(stream, dir, callback) {
  _validateReadlineCallback(callback);
  if (stream && typeof stream.write === 'function') {
    var code = dir < 0 ? '\x1b[1K' : dir > 0 ? '\x1b[0K' : '\x1b[2K';
    stream.write(code);
  }
  if (typeof callback === 'function') callback(null);
  return true;
}

function clearScreenDown(stream, callback) {
  _validateReadlineCallback(callback);
  if (stream && typeof stream.write === 'function') stream.write('\x1b[0J');
  if (typeof callback === 'function') callback(null);
  return true;
}

function cursorTo(stream, x, y, callback) {
  if (typeof y === 'function') { callback = y; y = undefined; }
  _validateReadlineCallback(callback);
  _validateReadlineCoordinate('x', x);
  _validateReadlineCoordinate('y', y);
  if (typeof x !== 'number') {
    if (typeof y === 'number') {
      var posErr = new TypeError('Cannot set cursor row without setting its column');
      posErr.code = 'ERR_INVALID_CURSOR_POS';
      throw posErr;
    }
    if (typeof callback === 'function') callback(null);
    return true;
  }
  if (typeof y !== 'undefined' && typeof y !== 'number') {
    y = undefined;
  }
  if (stream && typeof stream.write === 'function') {
    if (y !== undefined) stream.write('\x1b[' + (y + 1) + ';' + (x + 1) + 'H');
    else stream.write('\x1b[' + (x + 1) + 'G');
  }
  if (typeof callback === 'function') callback(null);
  return true;
}

function moveCursor(stream, dx, dy, callback) {
  _validateReadlineCallback(callback);
  if (stream && typeof stream.write === 'function') {
    var s = '';
    if (dx > 0) s += '\x1b[' + dx + 'C';
    else if (dx < 0) s += '\x1b[' + (-dx) + 'D';
    if (dy > 0) s += '\x1b[' + dy + 'B';
    else if (dy < 0) s += '\x1b[' + (-dy) + 'A';
    if (s) stream.write(s);
  }
  if (typeof callback === 'function') callback(null);
  return true;
}

// CSI (Control Sequence Introducer) helpers for terminal control

module.exports = {
  createInterface: createInterface,
  Interface: Interface,
  promises: promises,
  clearLine: clearLine,
  clearScreenDown: clearScreenDown,
  cursorTo: cursorTo,
  moveCursor: moveCursor,
  emitKeypressEvents: emitKeypressEvents,
  CSI: CSI
};
module.exports.default = module.exports;

// Bun internals symbol for tests that access CSI and utils via Symbol
module.exports[internalSymbol] = {
  CSI: CSI,
  utils: { getStringWidth: getStringWidth }
};
