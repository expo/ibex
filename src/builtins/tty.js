// tty module — provides tty.ReadStream, tty.WriteStream, and tty.isatty
// compatible with Node.js tty API surface.
//
// In the Exact runtime environment (mobile/embedded), actual TTY support is
// not available. The implementation provides the correct API surface so that
// code checking for TTY capabilities (e.g. chalk, ora, ink) doesn't crash,
// while correctly reporting that streams are not TTYs.

var net;
try { net = require('net'); } catch (e) { net = null; }

var EventEmitter;
try { EventEmitter = require('events'); } catch (e) { EventEmitter = null; }

// ─── isatty ──────────────────────────────────────────────────────
// Returns true if the given fd refers to a TTY.
// In the Exact runtime, this always returns false unless globalThis.process
// streams explicitly report isTTY.
function isatty(fd) {
  // Match Node.js behavior: non-number or missing fd returns false
  if (typeof fd !== 'number') return false;
  var p = typeof globalThis !== 'undefined' && globalThis.process;
  if (!p) return false;
  if (fd === 0) return !!(p.stdin && p.stdin.isTTY);
  if (fd === 1) return !!(p.stdout && p.stdout.isTTY);
  if (fd === 2) return !!(p.stderr && p.stderr.isTTY);
  return false;
}

// ─── ReadStream ──────────────────────────────────────────────────
// In Node.js, tty.ReadStream extends net.Socket.
// We provide a lightweight constructor with the same API surface.

function ReadStream(fd, options) {
  if (!(this instanceof ReadStream)) return new ReadStream(fd, options);

  // Call net.Socket constructor if available
  if (net && net.Socket) {
    net.Socket.call(this, Object.assign({}, options, {
      readable: true,
      writable: false
    }));
  } else if (EventEmitter) {
    EventEmitter.call(this);
  }

  this.fd = fd !== undefined ? fd : 0;
  this.isTTY = false;
  this.isRaw = false;
}

// Set up prototype chain: ReadStream -> net.Socket -> EventEmitter
if (net && net.Socket && net.Socket.prototype) {
  ReadStream.prototype = Object.create(net.Socket.prototype);
} else if (EventEmitter && EventEmitter.prototype) {
  ReadStream.prototype = Object.create(EventEmitter.prototype);
} else {
  ReadStream.prototype = {};
}
ReadStream.prototype.constructor = ReadStream;

// setRawMode toggles raw mode on the TTY. In non-TTY environments
// it's a no-op that returns `this` for chaining.
ReadStream.prototype.setRawMode = function setRawMode(mode) {
  this.isRaw = !!mode;
  return this;
};

// ─── WriteStream ─────────────────────────────────────────────────
// In Node.js, tty.WriteStream extends net.Socket.
// We provide a lightweight constructor with the same API surface.

function WriteStream(fd, options) {
  if (!(this instanceof WriteStream)) return new WriteStream(fd, options);

  // Call net.Socket constructor if available
  if (net && net.Socket) {
    net.Socket.call(this, Object.assign({}, options, {
      readable: false,
      writable: true
    }));
  } else if (EventEmitter) {
    EventEmitter.call(this);
  }

  this.fd = fd !== undefined ? fd : 1;
  this.columns = undefined;
  this.rows = undefined;

  // Attempt to get terminal size from environment
  this._refreshSize();
}

// Set up prototype chain: WriteStream -> net.Socket -> EventEmitter
if (net && net.Socket && net.Socket.prototype) {
  WriteStream.prototype = Object.create(net.Socket.prototype);
} else if (EventEmitter && EventEmitter.prototype) {
  WriteStream.prototype = Object.create(EventEmitter.prototype);
} else {
  WriteStream.prototype = {};
}
WriteStream.prototype.constructor = WriteStream;

// isTTY is set on the prototype (Node.js does this too, but instances
// may override). For Exact runtime, streams are not actual TTYs.
// Note: This matches behavior where non-tty WriteStreams still have
// the property but set to false-y. We set it as an instance property
// in the constructor flow rather than on prototype, but we define it
// on prototype as well for duck-typing checks.
Object.defineProperty(WriteStream.prototype, 'isTTY', {
  get: function() {
    // Check if instance has own _isTTY property
    if (Object.prototype.hasOwnProperty.call(this, '_isTTY')) {
      return this._isTTY;
    }
    return false;
  },
  set: function(value) {
    this._isTTY = value;
  },
  configurable: true,
  enumerable: true
});

// _refreshSize attempts to read terminal dimensions from environment.
WriteStream.prototype._refreshSize = function _refreshSize() {
  var env = (typeof globalThis !== 'undefined' && globalThis.process && globalThis.process.env) || {};
  var cols = parseInt(env.COLUMNS, 10);
  var rows = parseInt(env.LINES, 10);
  if (cols > 0) this.columns = cols;
  if (rows > 0) this.rows = rows;
};

// getColorDepth returns the number of colors supported.
// In non-TTY mode we return 1 (monochrome) unless environment hints otherwise.
WriteStream.prototype.getColorDepth = function getColorDepth(env) {
  env = env || ((typeof globalThis !== 'undefined' && globalThis.process && globalThis.process.env) || {});

  // Check for explicit NO_COLOR
  if (env.NO_COLOR !== undefined) return 1;

  // Check for FORCE_COLOR
  if (env.FORCE_COLOR !== undefined) {
    var forceColor = env.FORCE_COLOR;
    if (forceColor === '' || forceColor === 'true' || forceColor === '1') return 4;
    if (forceColor === '2') return 8;
    if (forceColor === '3') return 24;
    if (forceColor === '0' || forceColor === 'false') return 1;
  }

  // Check COLORTERM
  if (env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit') return 24;

  // Check TERM
  var term = env.TERM || '';
  if (term === 'dumb') return 1;
  if (/\-256color$/i.test(term)) return 8;
  if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(term)) return 4;

  // Default: monochrome for non-TTY
  return 1;
};

// hasColors checks if the terminal supports at least `count` colors.
// If called with no arguments, checks for basic color support (>= 2 colors).
WriteStream.prototype.hasColors = function hasColors(count, env) {
  if (typeof count === 'object' && count !== null && !Array.isArray(count)) {
    // hasColors(env) — count is actually env
    env = count;
    count = 16;
  }
  if (count === undefined) count = 16;
  if (typeof count !== 'number' || count < 2) count = 2;
  var depth = this.getColorDepth(env);
  // depth is in bits: 1=2 colors, 4=16 colors, 8=256 colors, 24=16M colors
  return Math.pow(2, depth) >= count;
};

// getWindowSize returns [columns, rows].
WriteStream.prototype.getWindowSize = function getWindowSize() {
  return [this.columns, this.rows];
};

// cursorTo moves the cursor to (x, y). If y is omitted, only x is set.
// Writes ANSI escape sequence. callback is optional.
WriteStream.prototype.cursorTo = function cursorTo(x, y, callback) {
  if (typeof y === 'function') {
    callback = y;
    y = undefined;
  }

  if (typeof x !== 'number') {
    if (typeof callback === 'function') callback();
    return true;
  }

  var data;
  if (typeof y !== 'number') {
    data = '\x1b[' + (x + 1) + 'G';
  } else {
    data = '\x1b[' + (y + 1) + ';' + (x + 1) + 'H';
  }

  if (typeof this.write === 'function') {
    return this.write(data, callback);
  }
  if (typeof callback === 'function') callback();
  return true;
};

// moveCursor moves the cursor relative to current position.
WriteStream.prototype.moveCursor = function moveCursor(dx, dy, callback) {
  if (typeof callback !== 'function' && typeof dy === 'function') {
    callback = dy;
    dy = undefined;
  }
  var data = '';
  if (dx < 0) {
    data += '\x1b[' + (-dx) + 'D';
  } else if (dx > 0) {
    data += '\x1b[' + dx + 'C';
  }
  if (dy < 0) {
    data += '\x1b[' + (-dy) + 'A';
  } else if (dy > 0) {
    data += '\x1b[' + dy + 'B';
  }
  if (data.length === 0) {
    if (typeof callback === 'function') callback();
    return true;
  }
  if (typeof this.write === 'function') {
    return this.write(data, callback);
  }
  if (typeof callback === 'function') callback();
  return true;
};

// clearLine clears the current line.
// dir: -1 = left of cursor, 1 = right of cursor, 0 = entire line
WriteStream.prototype.clearLine = function clearLine(dir, callback) {
  if (typeof dir === 'function') {
    callback = dir;
    dir = 0;
  }
  var code;
  if (dir === -1) {
    code = '\x1b[1K';
  } else if (dir === 1) {
    code = '\x1b[0K';
  } else {
    code = '\x1b[2K';
  }
  if (typeof this.write === 'function') {
    return this.write(code, callback);
  }
  if (typeof callback === 'function') callback();
  return true;
};

// clearScreenDown clears from cursor to end of screen.
WriteStream.prototype.clearScreenDown = function clearScreenDown(callback) {
  if (typeof this.write === 'function') {
    return this.write('\x1b[0J', callback);
  }
  if (typeof callback === 'function') callback();
  return true;
};

module.exports = {
  isatty: isatty,
  ReadStream: ReadStream,
  WriteStream: WriteStream
};
