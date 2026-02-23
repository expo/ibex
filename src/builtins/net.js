var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } w.listener = fn; this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (e) delete this._events[e]; else this._events = {}; return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.listeners = function(e) { return (this._events[e] || []).slice(); };
  EventEmitter.prototype.listenerCount = function(e) { return (this._events[e] || []).length; };
  EventEmitter.prototype.prependListener = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].unshift(fn); return this; };
}

// Check for native TCP support
var _hasTcp = typeof __exactTcpConnect === 'function';
// Check for native Unix socket support
var _hasUnix = typeof __exactUnixConnect === 'function';
var _defaultAutoSelectFamilyAttemptTimeout = 0;

// --- Socket class ---
function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);
  options = options || {};
  this.readable = true;
  this.writable = true;
  this.destroyed = false;
  this.connecting = false;
  this._connected = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.remoteFamily = null;
  this.localAddress = null;
  this.localPort = null;
  this.bytesRead = 0;
  this.bytesWritten = 0;
  this.timeout = 0;
  this._timeoutMs = 0;
  this._timeoutTimer = null;
  this._lastActivity = 0;
  this._handle = null;
  this._pollTimer = null;
  this._drainTimer = null;
  this._writeQueue = [];
  this._isWriting = false;
  this._closeAfterEnd = false;
  this._paused = false;
  this._encoding = null;
  this._events = {};
  this._readBuffer = [];
  this._readBufferLength = 0;
  this._onread = options.onread || null;
  this._onreadEOF = false;
  this._isUnix = false;
  this._socketPath = null;
  this.allowHalfOpen = options.allowHalfOpen || false;
  this.pending = true;
  this.readyState = 'closed';
  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  // Track if this is a Unix socket (set by accepted connections or connect({path}))
  if (options._isUnix) {
    this._isUnix = true;
    this._socketPath = options._socketPath || null;
  }
  // If options._handle is provided, create from existing handle (for accepted connections)
  if (options._handle != null) {
    this._handle = options._handle;
    this._connected = true;
    this.connecting = false;
    this.pending = false;
    this.readyState = 'open';
    this._updateAddressInfo();
    this._startPolling();
  }
}

function toBufferData(data, encoding) {
  if (data == null) return null;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(data)) return data;
  if (typeof data === 'string') {
    if (typeof Buffer !== 'undefined') return Buffer.from(data, encoding || 'utf8');
    return data;
  }
  return typeof Buffer !== 'undefined' ? Buffer.from(String(data), 'utf8') : String(data);
}

Socket.prototype._appendToReadBuffer = function(data) {
  if (data == null) return;
  if (!data.length) return;
  var bufferData = toBufferData(data);
  if (bufferData == null || !bufferData.length) return;
  this._readBuffer.push(bufferData);
  this._readBufferLength += bufferData.length;
};

Socket.prototype._consumeReadBuffer = function(size) {
  if (this._readBufferLength === 0) return null;
  if (typeof size !== 'number' || size <= 0) {
    var allData = Buffer.concat(this._readBuffer, this._readBufferLength);
    this._readBuffer = [];
    this._readBufferLength = 0;
    return allData;
  }
  if (size >= this._readBufferLength) return this._consumeReadBuffer();

  var remaining = size;
  var parts = [];
  while (remaining > 0 && this._readBuffer.length > 0) {
    var chunk = this._readBuffer[0];
    if (chunk.length <= remaining) {
      this._readBuffer.shift();
      this._readBufferLength -= chunk.length;
      parts.push(chunk);
      remaining -= chunk.length;
    } else {
      parts.push(chunk.slice(0, remaining));
      this._readBuffer[0] = chunk.slice(remaining);
      this._readBufferLength -= remaining;
      remaining = 0;
    }
  }
  return parts.length === 1 ? parts[0] : Buffer.concat(parts, size - remaining);
};

Socket.prototype._drainWriteQueue = function() {
  if (this._drainTimer != null) {
    clearTimeout(this._drainTimer);
    this._drainTimer = null;
  }

  if (this._isWriting || this._handle == null || this.destroyed) {
    return;
  }

  this._isWriting = true;
  while (this._writeQueue.length > 0 && !this.destroyed && this._handle != null) {
    var item = this._writeQueue[0];
    if (item.offset >= item.data.length) {
      this._writeQueue.shift();
      if (item.callback) {
        setTimeout(item.callback, 0);
      }
      continue;
    }

    var remaining = item.data.slice(item.offset);
    var written = 0;
    try {
      written = __exactTcpWrite(this._handle, remaining);
    } catch (err) {
      var writeErr = err instanceof Error ? err : new Error(String(err));
      writeErr.code = 'EPIPE';
      this._isWriting = false;
      this._writeQueue = [];
      if (item.callback) {
        setTimeout(function() { item.callback(writeErr); }, 0);
      }
      this.destroy(writeErr);
      return;
    }

    if (written === 0) {
      break;
    }

    item.offset += written;
    this.bytesWritten += written;
    this._lastActivity = Date.now();

    if (item.offset >= item.data.length) {
      this._writeQueue.shift();
      if (item.callback) {
        setTimeout(item.callback, 0);
      }
    }
  }

  this._isWriting = false;
  if (this._writeQueue.length === 0) {
    if (this._closeAfterEnd) {
      this._closeAfterEnd = false;
      this.destroy();
      return;
    }
    var self = this;
    setTimeout(function() {
      self.emit('drain');
    }, 0);
    return;
  }

  var self = this;
  self._drainTimer = setTimeout(function() {
    self._drainTimer = null;
    self._drainWriteQueue();
  }, 1);
};

Socket.prototype._resolveOnreadBuffer = function() {
  if (!this._onread || !this._onread.buffer) return null;
  var buffer = this._onread.buffer;
  return typeof buffer === 'function' ? buffer() : buffer;
};

Socket.prototype._notifyOnreadEOF = function() {
  if (this._onreadEOF) return true;
  if (!this._onread || typeof this._onread.callback !== 'function') {
    this._onreadEOF = true;
    return true;
  }
  if (this._paused) return false;
  var buffer = this._resolveOnreadBuffer();
  this._onreadEOF = true;
  var cbResult = this._onread.callback.call(this, 0, buffer);
  if (cbResult === false) {
    this._paused = true;
  }
  return cbResult !== false;
};

Socket.prototype._processOnreadBuffer = function() {
  if (!this._onread || !this._onread.callback || this._readBufferLength === 0) {
    return true;
  }
  var data = this._consumeReadBuffer();
  if (data === null || !data.length) return true;
  var onread = this._onread;
  var offset = 0;
  var remaining = data.length;
  while (remaining > 0) {
    var buffer = this._resolveOnreadBuffer();
    if (!buffer || !buffer.length) {
      onread.callback.call(this, 0, buffer);
      return false;
    }
    var nread = remaining < buffer.length ? remaining : buffer.length;
    var sourceEnd = offset + nread;
    for (var i = 0; i < nread; i++) {
      buffer[i] = data[offset + i];
    }
    offset = sourceEnd;
    remaining = data.length - offset;

    var cbResult = onread.callback.call(this, nread, buffer);
    if (cbResult === false) {
      this._paused = true;
    }
    if (cbResult === false || this._paused) {
      if (remaining > 0) {
        this._appendToReadBuffer(data.slice(offset));
      }
      return false;
    }
  }
  return true;
};

Socket.prototype._updateAddressInfo = function() {
  if (this._handle == null) return;
  // Unix sockets don't have IP address info
  if (this._isUnix) {
    this.remoteFamily = 'Unix';
    return;
  }
  if (!_hasTcp) return;
  try {
    var remote = __exactTcpRemoteAddr(this._handle);
    if (remote) {
      var r = JSON.parse(remote);
      this.remoteAddress = r.address;
      this.remotePort = r.port;
      this.remoteFamily = r.family;
    }
  } catch(e) {}
  try {
    var local = __exactTcpLocalAddr(this._handle);
    if (local) {
      var l = JSON.parse(local);
      this.localAddress = l.address;
      this.localPort = l.port;
    }
  } catch(e) {}
};

Socket.prototype._startPolling = function() {
  if (this._pollTimer != null || this.destroyed) return;
  var self = this;
  self._lastActivity = Date.now();
  function poll() {
    if (self.destroyed || self._handle == null) return;
    if (self._onread) {
      if (self._paused) {
        self._pollTimer = setTimeout(poll, 10);
        return;
      }
      if (!self._processOnreadBuffer()) {
        self._pollTimer = setTimeout(poll, 10);
        return;
      }
      try {
        var onreadData = __exactTcpRead(self._handle, 65536);
        if (onreadData === null) {
          // EOF
          self._pollTimer = null;
          if (!self._notifyOnreadEOF()) {
            self._pollTimer = setTimeout(poll, 10);
            return;
          }
          self.readable = false;
          self.emit('end');
          if (!self.allowHalfOpen) {
            self.writable = false;
            self.destroy();
          } else {
            self.emit('close', false);
          }
          return;
        }
        if (onreadData.length > 0) {
          self._lastActivity = Date.now();
          self.bytesRead += onreadData.length;
          self._appendToReadBuffer(onreadData);
          if (!self._processOnreadBuffer()) {
            self._pollTimer = setTimeout(poll, 10);
            return;
          }
        }
      } catch(e) {
        self._pollTimer = null;
        if (!self.destroyed) {
          self.destroy(e);
        }
        return;
      }
      // Check idle timeout
      if (self._timeoutMs > 0 && (Date.now() - self._lastActivity) >= self._timeoutMs) {
        self.emit('timeout');
      }
      self._pollTimer = setTimeout(poll, 5);
      return;
    }
    if (self._paused) {
      self._pollTimer = setTimeout(poll, 10);
      return;
    }
    try {
      var data = __exactTcpRead(self._handle, 65536);
      if (data === null) {
        // EOF
        self._pollTimer = null;
        self.readable = false;
        self.emit('end');
        if (!self.allowHalfOpen) {
          self.writable = false;
          self.destroy();
        } else {
          self.emit('close', false);
        }
        return;
      }
      if (data.length > 0) {
        self._lastActivity = Date.now();
        self.bytesRead += data.length;
        self._appendToReadBuffer(data);
        self.emit('readable');
        if (self._encoding) {
          self.emit('data', data);
        } else {
          // Emit as Buffer if available, otherwise string
          if (typeof Buffer !== 'undefined') {
            self.emit('data', toBufferData(data));
          } else {
            self.emit('data', data);
          }
        }
      }
    } catch(e) {
      self._pollTimer = null;
      if (!self.destroyed) {
        self.destroy(e);
      }
      return;
    }
    // Check idle timeout
    if (self._timeoutMs > 0 && (Date.now() - self._lastActivity) >= self._timeoutMs) {
      self.emit('timeout');
    }
    self._pollTimer = setTimeout(poll, 5);
  }
  self._pollTimer = setTimeout(poll, 0);
};

Socket.prototype.connect = function(options, connectListener) {
  if (typeof options === 'number') {
    var port = options;
    var host = arguments[1] || 'localhost';
    if (typeof arguments[1] === 'function') {
      connectListener = arguments[1];
      host = 'localhost';
    } else if (typeof arguments[2] === 'function') {
      connectListener = arguments[2];
    }
    options = { port: port, host: host };
  } else if (typeof options === 'string') {
    // Unix socket path
    options = { path: options };
  } else if (Array.isArray(options)) {
    // IPC connection array form - not supported
    options = {};
  }
  options = options || {};
  this.connecting = true;
  this.pending = true;
  this.readyState = 'opening';

  if (connectListener) this.once('connect', connectListener);

  // Unix domain socket connection
  if (options.path) {
    this._isUnix = true;
    this._socketPath = options.path;
    this.remoteFamily = 'Unix';

    if (!_hasUnix) {
      var self = this;
      setTimeout(function() {
        var err = new Error('Unix sockets not supported: native __exactUnixConnect not available');
        err.code = 'ECONNREFUSED';
        self.connecting = false;
        self.readyState = 'closed';
        self.pending = false;
        self.emit('error', err);
      }, 0);
      return this;
    }

    var self = this;
    setTimeout(function() {
      if (self.destroyed) return;
      try {
        self._handle = __exactUnixConnect(self._socketPath);
        self.connecting = false;
        self._connected = true;
        self.pending = false;
        self.readyState = 'open';
        self._updateAddressInfo();
        self._startPolling();
        self.emit('connect');
        self.emit('ready');
      } catch(e) {
        self.connecting = false;
        self.pending = false;
        self.readyState = 'closed';
        var err = new Error(e.message || String(e));
        err.code = 'ECONNREFUSED';
        self.emit('error', err);
      }
    }, 0);

    return this;
  }

  // TCP connection
  this.remotePort = options.port;
  this.remoteAddress = options.host || options.hostname || 'localhost';
  // Store optional connection params
  if (options.localAddress) this.localAddress = options.localAddress;
  if (options.localPort) this.localPort = options.localPort;
  if (options.family) this._family = options.family;

  if (!_hasTcp) {
    // Fallback: no native TCP support
    var self = this;
    setTimeout(function() {
      var err = new Error('TCP sockets not supported: native __exactTcpConnect not available');
      err.code = 'ECONNREFUSED';
      self.connecting = false;
      self.readyState = 'closed';
      self.pending = false;
      self.emit('error', err);
    }, 0);
    return this;
  }

  var self = this;
  // Use setTimeout to make connect async (non-blocking from JS perspective)
  setTimeout(function() {
    if (self.destroyed) return;
    try {
      self._handle = __exactTcpConnect(self.remoteAddress, self.remotePort);
      self.connecting = false;
      self._connected = true;
      self.pending = false;
      self.readyState = 'open';
      self._updateAddressInfo();
      self._startPolling();
      self.emit('connect');
      self.emit('ready');
    } catch(e) {
      self.connecting = false;
      self.pending = false;
      self.readyState = 'closed';
      var err = new Error(e.message || String(e));
      err.code = 'ECONNREFUSED';
      self.emit('error', err);
    }
  }, 0);

  return this;
};

Socket.prototype.write = function(data, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (!this.writable || this.destroyed) {
    var err = new Error('This socket has been ended by the other party');
    err.code = 'EPIPE';
    if (callback) callback(err);
    return false;
  }
  if (this._handle == null) {
    var err2 = new Error('Socket is not connected');
    err2.code = 'ERR_SOCKET_CLOSED';
    if (callback) callback(err2);
    return false;
  }

  var dataToWrite = toBufferData(data, encoding);
  if (dataToWrite == null) dataToWrite = '';

  this._writeQueue.push({
    data: dataToWrite,
    offset: 0,
    callback: callback,
  });

  if (!this._isWriting) {
    this._drainWriteQueue();
  }

  return this._writeQueue.length === 0;
};

Socket.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (data != null) this.write(data, encoding);
  this.writable = false;
  this.readyState = this.readable ? 'readOnly' : 'closed';
  if (callback) this.once('finish', callback);
  this.emit('finish');
  // If not allowing half-open, close the whole socket
  if (!this.allowHalfOpen && this._handle != null) {
    var self = this;
    self._closeAfterEnd = true;
    if (!self._isWriting && self._writeQueue.length === 0) {
      self.destroy();
    }
  }
  return this;
};

Socket.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  this.destroyed = true;
  this.readable = false;
  this.writable = false;
  this.connecting = false;
  this.readyState = 'closed';
  this.pending = false;
  if (this._pollTimer != null) {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
  }
  if (this._timeoutTimer != null) {
    clearTimeout(this._timeoutTimer);
    this._timeoutTimer = null;
  }
  if (this._writeQueue.length) {
    var endErr = err instanceof Error ? err : new Error(err ? String(err) : 'Socket destroyed');
    for (var i = 0; i < this._writeQueue.length; i++) {
      var queued = this._writeQueue[i];
      if (queued.callback) {
        setTimeout(function(cb, error) {
          cb(error);
        }, 0, queued.callback, endErr);
      }
    }
    this._writeQueue = [];
    this._isWriting = false;
  }
  if (this._handle != null && _hasTcp) {
    try { __exactTcpClose(this._handle); } catch(e) {}
    this._handle = null;
  }
  if (err) this.emit('error', err);
  this.emit('close', !!err);
  return this;
};

Socket.prototype.setTimeout = function(timeout, callback) {
  this._timeoutMs = timeout || 0;
  if (callback) {
    if (timeout > 0) {
      this.once('timeout', callback);
    } else {
      this.removeListener('timeout', callback);
    }
  }
  return this;
};

Socket.prototype.read = function(size) {
  return this._consumeReadBuffer(typeof size === 'number' ? size : undefined);
};

Socket.prototype.unshift = function(chunk) {
  if (chunk == null) return;
  var unshiftData = toBufferData(chunk);
  if (unshiftData == null || !unshiftData.length) return;
  this._readBuffer.unshift(unshiftData);
  this._readBufferLength += unshiftData.length;
};

Socket.prototype.setNoDelay = function(noDelay) {
  if (this._handle != null && _hasTcp) {
    try { __exactTcpSetNoDelay(this._handle, noDelay !== false ? 1 : 0); } catch(e) {}
  }
  return this;
};

Socket.prototype.setKeepAlive = function(enable, delay) {
  if (this._handle != null && _hasTcp) {
    try { __exactTcpSetKeepAlive(this._handle, enable ? 1 : 0); } catch(e) {}
  }
  return this;
};

Socket.prototype.ref = function() { return this; };
Socket.prototype.unref = function() { return this; };

Socket.prototype.address = function() {
  if (this._isUnix) {
    return this._socketPath;
  }
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this.localAddress, port: this.localPort, family: this.remoteFamily || 'IPv4' };
};

Socket.prototype.pause = function() {
  this._paused = true;
  return this;
};

Socket.prototype.resume = function() {
  this._paused = false;
  return this;
};

Socket.prototype.pipe = function(dest, options) {
  var self = this;
  self.on('data', function(chunk) {
    var ok = dest.write(chunk);
    if (ok === false && self.pause) self.pause();
  });
  dest.on('drain', function() {
    if (self.resume) self.resume();
  });
  self.on('end', function() {
    if (!options || options.end !== false) {
      if (dest.end) dest.end();
    }
  });
  return dest;
};

Socket.prototype.setEncoding = function(enc) {
  this._encoding = enc;
  return this;
};

// --- Server class ---
function Server(options, connectionListener) {
  if (!(this instanceof Server)) return new Server(options, connectionListener);
  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
  }
  options = options || {};
  this._events = {};
  this.listening = false;
  this.maxConnections = 0;
  this._handle = null;
  this._acceptTimer = null;
  this._connections = 0;
  this._isUnix = false;
  this._socketPath = null;
  this._listenToken = 0;
  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  if (connectionListener) this.on('connection', connectionListener);
}

Server.prototype.listen = function(port, host, backlog, callback) {
  if (typeof host === 'function') { callback = host; host = undefined; backlog = undefined; }
  if (typeof backlog === 'function') { callback = backlog; backlog = undefined; }
  var unixPath = null;
  var self = this;
  var listenToken = ++this._listenToken;
  if (typeof port === 'string') {
    // server.listen('/tmp/my.sock') - Unix socket path
    unixPath = port;
    port = undefined;
  } else if (typeof port === 'object' && port !== null) {
    // options object
    var opts = port;
    if (opts.path) {
      unixPath = opts.path;
    }
    port = opts.port;
    host = opts.host || host;
    backlog = opts.backlog || backlog;
  }

  if (callback) this.once('listening', callback);

  // Unix domain socket server
  if (unixPath) {
    this._isUnix = true;
    this._socketPath = unixPath;

    if (!_hasUnix) {
      this.listening = true;
      setTimeout(function() { self.emit('listening'); }, 0);
      return this;
    }

    setTimeout(function() {
      if (listenToken !== self._listenToken) return;
      try {
        self._handle = __exactUnixListen(self._socketPath, backlog || 128);
        self.listening = true;
        self.emit('listening');
        self._startAccepting();
      } catch(e) {
        var err = new Error(e.message || String(e));
        err.code = 'EADDRINUSE';
        self.emit('error', err);
      }
    }, 0);
    return this;
  }

  // TCP server
  this._port = port || 0;
  this._host = host || '0.0.0.0';

  if (!_hasTcp) {
    this.listening = true;
    setTimeout(function() { self.emit('listening'); }, 0);
    return this;
  }

  setTimeout(function() {
    if (listenToken !== self._listenToken) return;
    try {
      self._handle = __exactTcpListen(self._host, self._port, backlog || 128);
      // Get actual bound port (useful when port=0)
      try {
        var info = __exactTcpLocalAddr(self._handle);
        if (info) {
          var addr = JSON.parse(info);
          self._port = addr.port;
          self._host = addr.address;
        }
      } catch(e) {}
      self.listening = true;
      self.emit('listening');
      self._startAccepting();
    } catch(e) {
      var err = new Error(e.message || String(e));
      err.code = 'EADDRINUSE';
      self.emit('error', err);
    }
  }, 0);
  return this;
};

Server.prototype._startAccepting = function() {
  if (this._acceptTimer != null) return;
  var self = this;
  var acceptFn = self._isUnix ? __exactUnixAccept : __exactTcpAccept;
  function acceptLoop() {
    if (!self.listening || self._handle == null) return;
    try {
      var clientHandle = acceptFn(self._handle);
      if (clientHandle !== -1) {
        self._connections++;
        var socketOpts = { _handle: clientHandle, allowHalfOpen: false };
        if (self._isUnix) {
          socketOpts._isUnix = true;
          socketOpts._socketPath = self._socketPath;
        }
        var socket = new Socket(socketOpts);
        self.emit('connection', socket);
      }
    } catch(e) {
      if (self.listening) {
        self.emit('error', e);
      }
      return;
    }
    self._acceptTimer = setTimeout(acceptLoop, 10);
  }
  self._acceptTimer = setTimeout(acceptLoop, 0);
};

Server.prototype.close = function(callback) {
  if (callback) this.once('close', callback);
  this._listenToken++;
  this.listening = false;
  if (this._acceptTimer != null) {
    clearTimeout(this._acceptTimer);
    this._acceptTimer = null;
  }
  if (this._handle != null) {
    // Close the fd (works for both TCP and Unix handles since they share g_tcp_sockets)
    if (_hasTcp) {
      try { __exactTcpClose(this._handle); } catch(e) {}
    }
    this._handle = null;
  }
  // Unlink Unix socket file on close
  if (this._isUnix && this._socketPath) {
    try {
      var fs = require('fs');
      fs.unlinkSync(this._socketPath);
    } catch(e) {}
    this._socketPath = null;
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
  return this;
};

Server.prototype.address = function() {
  // Unix socket servers return the path as the address (Node.js convention)
  if (this._isUnix) {
    return this._socketPath;
  }
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this._host || '0.0.0.0', port: this._port || 0, family: 'IPv4' };
};

Server.prototype.ref = function() { return this; };
Server.prototype.unref = function() { return this; };
Server.prototype.getConnections = function(cb) {
  var count = this._connections || 0;
  if (cb) setTimeout(function() { cb(null, count); }, 0);
};

// --- Helper functions ---
function createConnection(options, connectListener) {
  if (typeof options === 'number') {
    var port = options;
    var host = 'localhost';
    if (typeof connectListener === 'string') {
      host = connectListener;
      connectListener = arguments[2];
    }
    options = { port: port, host: host };
  }
  var socket = new Socket(options);
  return socket.connect(options, connectListener);
}

function createServer(options, connectionListener) {
  return new Server(options, connectionListener);
}

function connect() {
  return createConnection.apply(null, arguments);
}

function isIP(input) {
  if (isIPv4(input)) return 4;
  if (isIPv6(input)) return 6;
  return 0;
}

function isIPv4(input) {
  if (typeof input !== 'string') return false;
  var parts = input.split('.');
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return false;
    var num = parseInt(parts[i], 10);
    if (num < 0 || num > 255) return false;
    // Reject leading zeros (e.g. "01")
    if (parts[i].length > 1 && parts[i][0] === '0') return false;
  }
  return true;
}

function isIPv6(input) {
  if (typeof input !== 'string') return false;
  // Strip zone ID (e.g. %eth0, %25eth0)
  var zoneIdx = input.indexOf('%');
  if (zoneIdx !== -1) input = input.substring(0, zoneIdx);
  // Handle embedded IPv4 (last 32 bits as dotted-quad)
  var v4Suffix = false;
  var lastColon = input.lastIndexOf(':');
  if (lastColon !== -1) {
    var tail = input.substring(lastColon + 1);
    if (tail.indexOf('.') !== -1) {
      if (!isIPv4(tail)) return false;
      v4Suffix = true;
      input = input.substring(0, lastColon) + ':0:0';
    }
  }
  // Reject ::: (triple colon)
  if (input.indexOf(':::') !== -1) return false;
  // Reject leading single colon (but not ::)
  if (input.charAt(0) === ':' && input.charAt(1) !== ':') return false;
  // Reject trailing single colon (but not ::)
  if (input.charAt(input.length - 1) === ':' && input.charAt(input.length - 2) !== ':') return false;

  var hasDoubleColon = input.indexOf('::') !== -1;
  if (hasDoubleColon) {
    // Only one :: allowed
    if (input.indexOf('::') !== input.lastIndexOf('::')) return false;
  }
  var parts = input.split(':');
  // Validate each group
  for (var j = 0; j < parts.length; j++) {
    if (parts[j] === '') continue;
    if (!/^[0-9a-fA-F]{1,4}$/.test(parts[j])) return false;
  }
  if (hasDoubleColon) {
    // Count non-empty groups; :: must represent at least 1 group, so non-empty ≤ 7
    var nonEmpty = 0;
    for (var k = 0; k < parts.length; k++) {
      if (parts[k] !== '') nonEmpty++;
    }
    return nonEmpty <= 7;
  } else {
    return parts.length === 8;
  }
}

// --- SocketAddress class ---
function SocketAddress(options) {
  if (!(this instanceof SocketAddress)) return new SocketAddress(options);
  options = options || {};
  this.address = options.address || '127.0.0.1';
  this.port = options.port || 0;
  this.family = options.family || (isIPv6(this.address) ? 'ipv6' : 'ipv4');
  this.flowlabel = options.flowlabel || 0;
}

function getDefaultAutoSelectFamilyAttemptTimeout() {
  return _defaultAutoSelectFamilyAttemptTimeout;
}

function setDefaultAutoSelectFamilyAttemptTimeout(milliseconds) {
  if (typeof milliseconds === 'number' && isFinite(milliseconds)) {
    _defaultAutoSelectFamilyAttemptTimeout = milliseconds;
  } else if (arguments.length === 0) {
    _defaultAutoSelectFamilyAttemptTimeout = 0;
  }
  return _defaultAutoSelectFamilyAttemptTimeout;
}

// --- BlockList class ---
function BlockList() {
  if (!(this instanceof BlockList)) return new BlockList();
  this._rules = [];
}

BlockList.prototype.addAddress = function(address, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'address', address: address, family: type });
};

BlockList.prototype.addRange = function(start, end, type) {
  type = type || (isIPv6(start) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'range', start: start, end: end, family: type });
};

BlockList.prototype.addSubnet = function(address, prefix, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'subnet', address: address, prefix: prefix, family: type });
};

BlockList.prototype.check = function(address, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  for (var i = 0; i < this._rules.length; i++) {
    var rule = this._rules[i];
    if (rule.family !== type) continue;
    if (rule.type === 'address' && rule.address === address) return true;
    // For range and subnet, simplified string comparison (exact IP matching)
    if (rule.type === 'range' && address >= rule.start && address <= rule.end) return true;
    if (rule.type === 'subnet' && address === rule.address) return true;
  }
  return false;
};

  BlockList.prototype.rules = [];

module.exports = {
  Socket: Socket,
  Stream: Socket,
  Server: Server,
  createConnection: createConnection,
  createServer: createServer,
  connect: connect,
  isIP: isIP,
  isIPv4: isIPv4,
  isIPv6: isIPv6,
  BlockList: BlockList,
  SocketAddress: SocketAddress,
  getDefaultAutoSelectFamilyAttemptTimeout: getDefaultAutoSelectFamilyAttemptTimeout,
  setDefaultAutoSelectFamilyAttemptTimeout: setDefaultAutoSelectFamilyAttemptTimeout
};
module.exports.default = module.exports;
