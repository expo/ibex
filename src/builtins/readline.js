var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (e) delete this._events[e]; else this._events = {}; return this; };
}

function Interface(options) {
  if (!(this instanceof Interface)) return new Interface(options);
  if (typeof EventEmitter === 'function') {
    EventEmitter.call(this);
    if (EventEmitter.prototype) {
      for (var k in EventEmitter.prototype) {
        if (!this[k]) this[k] = EventEmitter.prototype[k];
      }
    }
  }
  this._events = this._events || {};
  options = options || {};
  this.input = options.input || (typeof process !== 'undefined' ? process.stdin : null);
  this.output = options.output || (typeof process !== 'undefined' ? process.stdout : null);
  this.terminal = options.terminal !== undefined ? options.terminal : false;
  this._promptStr = options.prompt !== undefined ? options.prompt : '> ';
  this.closed = false;
  this.line = '';
  this._lineBuffer = '';
  this.cursor = 0;
  this.history = [];
  this.historyIndex = -1;
  this._paused = false;

  // Listen for data events on the input stream to enable line buffering
  var self = this;
  if (this.input && typeof this.input.on === 'function') {
    this._onData = function(chunk) {
      if (self.closed) return;
      var str = typeof chunk === 'string' ? chunk : (chunk && typeof chunk.toString === 'function' ? chunk.toString('utf8') : String(chunk));
      self._lineBuffer += str;
      var lines = self._lineBuffer.split('\n');
      self._lineBuffer = lines.pop() || '';
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].replace(/\r$/, '');
        self.line = line;
        if (self.history.length === 0 || self.history[0] !== line) {
          self.history.unshift(line);
        }
        self.emit('line', line);
      }
    };
    this._onEnd = function() {
      if (self.closed) return;
      if (self._lineBuffer.length > 0) {
        var remaining = self._lineBuffer.replace(/\r$/, '');
        self._lineBuffer = '';
        self.line = remaining;
        self.emit('line', remaining);
      }
      self.close();
    };
    this._onClose = function() { if (!self.closed) self.close(); };
    this.input.on('data', this._onData);
    this.input.on('end', this._onEnd);
    this.input.on('close', this._onClose);
    if (typeof this.input.resume === 'function') this.input.resume();
  }
}

Interface.prototype.setPrompt = function(p) {
  this._promptStr = p;
};

Interface.prototype.getPrompt = function() {
  return this._promptStr;
};

Interface.prototype.prompt = function(preserveCursor) {
  if (this.output && !this.closed) this.output.write(this._promptStr);
};

Interface.prototype.question = function(query, options, cb) {
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  if (this.output) {
    this.output.write(query);
  }
  // Store callback for next line event
  var self = this;
  this.once('line', function(answer) {
    if (cb) cb(answer);
  });
};

Interface.prototype.write = function(data, key) {
  if (data != null) {
    var str = String(data);
    if (str.indexOf('\n') !== -1 && this._onData) {
      this._onData(str);
    } else {
      this.line += str;
    }
  }
};

Interface.prototype.close = function() {
  if (this.closed) return;
  this.closed = true;
  if (this.input && typeof this.input.removeListener === 'function') {
    if (this._onData) this.input.removeListener('data', this._onData);
    if (this._onEnd) this.input.removeListener('end', this._onEnd);
    if (this._onClose) this.input.removeListener('close', this._onClose);
  }
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
  var queue = [];
  var resolve = null;
  self.on('line', function(line) {
    if (resolve) { var r = resolve; resolve = null; r({ value: line, done: false }); }
    else queue.push(line);
  });
  self.on('close', function() {
    done = true;
    if (resolve) { var r = resolve; resolve = null; r({ value: undefined, done: true }); }
  });
  return {
    next: function() {
      if (queue.length > 0) return Promise.resolve({ value: queue.shift(), done: false });
      if (done) return Promise.resolve({ value: undefined, done: true });
      return new Promise(function(r) { resolve = r; });
    }
  };
};

function createInterface(options) {
  if (typeof options === 'object' && options.input) {
    return new Interface(options);
  }
  // Handle (input, output) positional args
  if (arguments.length >= 1) {
    var opts = {};
    opts.input = arguments[0];
    if (arguments.length >= 2) opts.output = arguments[1];
    return new Interface(opts);
  }
  return new Interface(options || {});
}

// Promises API
var promises = {
  createInterface: function(options) {
    var rl = createInterface(options);
    // Wrap question to return a Promise
    var origQuestion = rl.question;
    rl.question = function(query, options) {
      return new Promise(function(resolve) {
        origQuestion.call(rl, query, options, function(answer) {
          resolve(answer);
        });
      });
    };
    return rl;
  }
};

function clearLine(stream, dir, callback) {
  if (stream && typeof stream.write === 'function') {
    var code = dir < 0 ? '\x1b[1K' : dir > 0 ? '\x1b[0K' : '\x1b[2K';
    stream.write(code);
  }
  if (typeof callback === 'function') callback();
}

function clearScreenDown(stream, callback) {
  if (stream && typeof stream.write === 'function') stream.write('\x1b[0J');
  if (typeof callback === 'function') callback();
}

function cursorTo(stream, x, y, callback) {
  if (typeof y === 'function') { callback = y; y = undefined; }
  if (stream && typeof stream.write === 'function') {
    if (y !== undefined) stream.write('\x1b[' + (y + 1) + ';' + (x + 1) + 'H');
    else stream.write('\x1b[' + (x + 1) + 'G');
  }
  if (typeof callback === 'function') callback();
}

function moveCursor(stream, dx, dy, callback) {
  if (stream && typeof stream.write === 'function') {
    var s = '';
    if (dx > 0) s += '\x1b[' + dx + 'C';
    else if (dx < 0) s += '\x1b[' + (-dx) + 'D';
    if (dy > 0) s += '\x1b[' + dy + 'B';
    else if (dy < 0) s += '\x1b[' + (-dy) + 'A';
    if (s) stream.write(s);
  }
  if (typeof callback === 'function') callback();
}

function emitKeypressEvents(stream, iface) {
  // Stub: no-op that prevents errors when called
}

module.exports = {
  createInterface: createInterface,
  Interface: Interface,
  promises: promises,
  clearLine: clearLine,
  clearScreenDown: clearScreenDown,
  cursorTo: cursorTo,
  moveCursor: moveCursor,
  emitKeypressEvents: emitKeypressEvents
};
module.exports.default = module.exports;
