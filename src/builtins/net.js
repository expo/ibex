var EventEmitter;
var _assertListenerArgument = null;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  _assertListenerArgument = function(listener, argName) {
    if (typeof listener !== 'function') {
      var type = listener === undefined ? 'undefined' : listener === null ? 'null' : typeof listener;
      throw new TypeError(
        'The "' + argName + '" argument must be of type function. Received ' + type
      );
    }
  };
  EventEmitter.prototype._on = function(e, fn) {
    if (!this._events[e]) this._events[e] = [];
    this._events[e].push(fn);
    return this;
  };
  EventEmitter.prototype.on = function(e, fn) {
    _assertListenerArgument(fn, 'listener');
    return EventEmitter.prototype._on.call(this, e, fn);
  };
  EventEmitter.prototype.emit = function(e) { var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) {
    _assertListenerArgument(fn, 'listener');
    var self = this;
    function w() { self.removeListener(e, w); fn.apply(this, arguments); }
    w.listener = fn;
    this.on(e, w);
    return this;
  };
  EventEmitter.prototype.removeListener = function(e, fn) { var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (e) delete this._events[e]; else this._events = {}; return this; };
  EventEmitter.prototype.addListener = function(e, fn) {
    _assertListenerArgument(fn, 'listener');
    return EventEmitter.prototype.on.call(this, e, fn);
  };
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.listeners = function(e) { return (this._events[e] || []).slice(); };
  EventEmitter.prototype.listenerCount = function(e) { return (this._events[e] || []).length; };
  EventEmitter.prototype.prependListener = function(e, fn) {
    _assertListenerArgument(fn, 'listener');
    if (!this._events[e]) this._events[e] = [];
    this._events[e].unshift(fn);
    return this;
  };
}

if (!_assertListenerArgument) {
  _assertListenerArgument = function(listener, argName) {
    if (typeof listener !== 'function') {
      var type = listener === undefined ? 'undefined' : listener === null ? 'null' : typeof listener;
      throw new TypeError(
        'The "' + argName + '" argument must be of type function. Received ' + type
      );
    }
  };
}

// Check for native TCP support
var _hasTcp = typeof __exactTcpConnect === 'function';
// Check for native Unix socket support
var _hasUnix = typeof __exactUnixConnect === 'function';
var _defaultAutoSelectFamilyAttemptTimeout = 0;
var _defaultAutoSelectFamily = false;
var _boundTcpServers = [];

function _unwrapHandle(handle) {
  if (handle && handle._exactHandle !== undefined) {
    return handle._exactHandle;
  }
  return handle;
}

function _makeSocketHandle(handle) {
  var socketHandle = {
    _exactHandle: handle == null ? null : handle,
    setNoDelay: function(noDelay) {
      if (!_hasTcp) return;
      if (socketHandle._exactHandle == null) return;
      try {
        __exactTcpSetNoDelay(socketHandle._exactHandle, noDelay ? 1 : 0);
      } catch(e) {}
    },
    setKeepAlive: function(enable, delay) {
      if (!_hasTcp) return;
      if (socketHandle._exactHandle == null) return;
      if (typeof delay !== 'number' || !isFinite(delay)) {
        delay = 0;
      }
      try {
        if (__exactTcpSetKeepAlive.length >= 3) {
          __exactTcpSetKeepAlive(socketHandle._exactHandle, enable !== false ? 1 : 0, delay);
        } else {
          __exactTcpSetKeepAlive(socketHandle._exactHandle, enable !== false ? 1 : 0);
        }
      } catch(e) {}
    },
    close: function() {
      if (!_hasTcp) return;
      if (socketHandle._exactHandle == null) return;
      try { __exactTcpClose(socketHandle._exactHandle); } catch(e) {}
      socketHandle._exactHandle = null;
    }
  };
  return socketHandle;
}

function _setSocketHandle(socket, nativeHandle) {
  if (!socket) return;
  if (socket._exactHandle !== undefined) {
    socket._exactHandle = nativeHandle;
  } else {
    socket._exactHandle = null;
    socket._exactHandle = nativeHandle;
  }
}

function _shutdownSocketWrite(socket) {
  if (!_hasTcp || !socket) return;
  var nativeHandle = _unwrapHandle(socket._handle);
  if (nativeHandle == null) return;
  if (typeof __exactTcpShutdown !== 'function') return;
  try {
    __exactTcpShutdown(nativeHandle, 1);
  } catch(e) {}
}

function _hasMatchingIPv6OnlyServer(host, port) {
  if (!host || !port) return false;
  if (isIP(host) !== 4) return false;
  for (var i = 0; i < _boundTcpServers.length; i++) {
    var server = _boundTcpServers[i];
    if (Number(server.port) !== Number(port)) continue;
    if (server && server.ipv6Only && isIP(server.host) === 6) {
      return true;
    }
  }
  return false;
}

function _normalizeLookupResult(lookupResult) {
  if (lookupResult == null) return null;
  if (Array.isArray(lookupResult)) return lookupResult;
  return [lookupResult];
}

function setDefaultAutoSelectFamily(enabled) {
  _defaultAutoSelectFamily = enabled === true;
  return _defaultAutoSelectFamily;
}

function _registerTcpServer(server) {
  _boundTcpServers.push(server);
}

function _unregisterTcpServer(server) {
  for (var i = 0; i < _boundTcpServers.length; i++) {
    var entry = _boundTcpServers[i];
    if (entry === server || (entry && server && entry.port === server.port && entry.host === server.host && entry.ipv6Only === server.ipv6Only)) {
      _boundTcpServers.splice(i, 1);
      return;
    }
  }
}

function _getAutoSelectFamilyAttemptedAddresses(addresses, port) {
  if (!addresses || !Array.isArray(addresses)) return [];
  var list = [];
  for (var i = 0; i < addresses.length; i++) {
    if (!addresses[i]) continue;
    var record = addresses[i];
    if (typeof record === 'string') {
      list.push(record + ':' + port);
      continue;
    }
    if (typeof record === 'object' && record !== null && typeof record.address === 'string') {
      list.push(record.address + ':' + port);
    }
  }
  return list;
}

function _normalizeLookupResults(result) {
  if (result == null) return [];
  if (Array.isArray(result)) return result;
  return [ result ];
}

function _addressFamilyToName(family) {
  if (family === 4 || family === '4' || (typeof family === 'string' && family.toLowerCase() === 'ipv4')) return 'IPv4';
  if (family === 6 || family === '6' || (typeof family === 'string' && family.toLowerCase() === 'ipv6')) return 'IPv6';
  return null;
}

function _parseLookupFamily(value) {
  if (value === 4 || value === '4') return 4;
  if (value === 6 || value === '6') return 6;
  if (value === undefined || value === null) return 0;
  if (typeof value === 'string') return parseInt(value, 10) || 0;
  return value || 0;
}

function _toIntDelay(value, defaultValue) {
  if (!isFinite(value)) return defaultValue;
  value = Math.floor(value / 1000);
  if (value < 0) return 0;
  return value;
}

function _createConnectError(code, address, port, syscall) {
  var suffix = address + ':' + port;
  var err = new Error(syscall + ' ' + code + ' ' + suffix);
  err.code = code;
  err.errno = code;
  err.syscall = syscall;
  return err;
}

function _isGetAddrInfoError(err) {
  if (!err || !err.message) return false;
  return String(err.message).indexOf('getaddrinfo') === 0 || String(err.message).indexOf('getaddrinfo failed') !== -1;
}

function _createGetAddrInfoError(host) {
  var err = new Error('getaddrinfo ENOTFOUND ' + host);
  err.code = 'ENOTFOUND';
  err.errno = 'ENOTFOUND';
  err.syscall = 'getaddrinfo';
  err.hostname = host;
  return err;
}

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
  this.localFamily = null;
  this.bytesRead = 0;
  this.bytesWritten = 0;
  this.timeout = 0;
  this._timeoutMs = 0;
  this._timeoutTimer = null;
  this._lastActivity = 0;
  this._handle = _makeSocketHandle(null);
  this._pollTimer = null;
  this._drainTimer = null;
  this._writeQueue = [];
  this._writeBufferCache = Object.create(null);
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
    this._handle = _makeSocketHandle(options._handle);
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
  if (typeof Buffer !== 'undefined' && typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
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

  var nativeHandle = _unwrapHandle(this._handle);
  if (this._isWriting || nativeHandle == null || this.destroyed) {
    return;
  }

  this._isWriting = true;
  while (this._writeQueue.length > 0 && !this.destroyed && nativeHandle != null) {
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
      written = __exactTcpWrite(nativeHandle, remaining);
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
      _shutdownSocketWrite(this);
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
  var nativeHandle = _unwrapHandle(this._handle);
  if (nativeHandle == null) return;
  // Unix sockets don't have IP address info
  if (this._isUnix) {
    this.remoteFamily = 'Unix';
    return;
  }
  if (!_hasTcp) return;
  try {
    var remote = __exactTcpRemoteAddr(nativeHandle);
    if (remote) {
      var r = JSON.parse(remote);
      this.remoteAddress = r.address;
      this.remotePort = r.port;
      this.remoteFamily = r.family;
    }
  } catch(e) {}
  try {
    var local = __exactTcpLocalAddr(nativeHandle);
    if (local) {
      var l = JSON.parse(local);
      this.localAddress = l.address;
      this.localPort = l.port;
      this.localFamily = l.family;
    }
  } catch(e) {}
};

Socket.prototype._startPolling = function() {
  if (this._pollTimer != null || this.destroyed) return;
  var self = this;
  self._lastActivity = Date.now();
  function poll() {
    if (self.destroyed) return;
    var nativeHandle = _unwrapHandle(self._handle);
    if (nativeHandle == null) return;
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
          while (true) {
            var onreadData = __exactTcpRead(nativeHandle, 65536);
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
          if (!onreadData.length) {
            break;
          }
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
      while (true) {
        var data = __exactTcpRead(nativeHandle, 65536);
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
        if (!data.length) {
          break;
        }
        self._lastActivity = Date.now();
        self.bytesRead += data.length;
        self._appendToReadBuffer(data);
        self.emit('readable');
        if (self._encoding) {
          self.emit('data', toBufferData(data).toString(self._encoding));
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
  this.autoSelectFamilyAttemptedAddresses = undefined;

  if (connectListener) this.once('connect', connectListener);
  // Track whether the constructor provided explicit noDelay/keepAlive options.
  if (Object.prototype.hasOwnProperty.call(options, 'noDelay')) {
    this._noDelay = options.noDelay;
  } else {
    this._noDelay = undefined;
  }
  if (Object.prototype.hasOwnProperty.call(options, 'keepAlive')) {
    this._keepAlive = options.keepAlive;
  } else {
    this._keepAlive = undefined;
  }
  if (Object.prototype.hasOwnProperty.call(options, 'keepAliveInitialDelay')) {
    this._keepAliveInitialDelay = options.keepAliveInitialDelay;
  } else {
    this._keepAliveInitialDelay = 0;
  }

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
        var unixHandle = __exactUnixConnect(self._socketPath);
        _setSocketHandle(self._handle, unixHandle);
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
  this.remoteFamily = null;
  if (options.family) {
    this.remoteFamily = _addressFamilyToName(options.family);
  }

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
  var lookup = options.lookup;
  var autoSelectFamily = options.autoSelectFamily;
  if (autoSelectFamily === undefined) {
    autoSelectFamily = _defaultAutoSelectFamily;
  }
  if (autoSelectFamily === undefined) autoSelectFamily = false;
  if (autoSelectFamily) self.autoSelectFamilyAttemptedAddresses = [];

  var lookupFamily = _parseLookupFamily(options.family);
  var attempts = [{ address: self.remoteAddress, family: lookupFamily }];

  function _normalizeCandidate(raw, fallbackFamily) {
    if (!raw) return null;
    if (typeof raw === 'string') return { address: raw, family: fallbackFamily };
    if (typeof raw === 'object' && typeof raw.address === 'string') {
      return { address: raw.address, family: raw.family != null ? _parseLookupFamily(raw.family) : fallbackFamily };
    }
    return null;
  }

  function _startTcpConnect(selfRef, attemptList, shouldAutoSelect) {
    var attemptErrors = [];
    var idx = 0;
    function nextAttempt() {
      if (typeof process !== 'undefined' && process._exactExiting) {
        return;
      }
      if (idx >= attemptList.length) {
        selfRef.connecting = false;
        selfRef.pending = false;
        selfRef.readyState = 'closed';
        if (attemptErrors.length === 0) return;
        var finalErr = attemptErrors[attemptErrors.length - 1];
        if (shouldAutoSelect && attemptErrors.length > 1) {
          if (typeof AggregateError === 'function') {
            finalErr = new AggregateError(attemptErrors, 'Unable to connect');
          } else {
            finalErr = new Error('Unable to connect');
          }
          finalErr.errors = attemptErrors;
        }
        selfRef.emit('error', finalErr);
        return;
      }

      var target = _normalizeCandidate(attemptList[idx], lookupFamily);
      idx++;
      if (!target || !target.address) {
        nextAttempt();
        return;
      }

      var address = target.address;
      var family = target.family;
      if (selfRef.autoSelectFamilyAttemptedAddresses) {
        selfRef.autoSelectFamilyAttemptedAddresses.push(address + ':' + selfRef.remotePort);
      }

      if (isIP(address) === 4 && _hasMatchingIPv6OnlyServer(address, selfRef.remotePort)) {
        attemptErrors.push(_createConnectError('ECONNREFUSED', address, selfRef.remotePort, 'connect'));
        nextAttempt();
        return;
      }

      try {
        var nativeHandle = __exactTcpConnect(address, selfRef.remotePort);
        if (selfRef.destroyed) {
          try { __exactTcpClose(nativeHandle); } catch(e) {}
          return;
        }
        selfRef.remoteAddress = address;
        if (family) selfRef.remoteFamily = _addressFamilyToName(family);
        _setSocketHandle(selfRef._handle, nativeHandle);
        selfRef.connecting = false;
        selfRef._connected = true;
        selfRef.pending = false;
        selfRef.readyState = 'open';
        selfRef._updateAddressInfo();
        if (selfRef._noDelay) selfRef.setNoDelay(selfRef._noDelay);
        if (selfRef._keepAlive !== undefined && selfRef._keepAlive) {
          selfRef.setKeepAlive(true, _toIntDelay(selfRef._keepAliveInitialDelay, 0));
        }
        selfRef._startPolling();
        selfRef._drainWriteQueue();
        selfRef.emit('connect');
        selfRef.emit('ready');
      } catch (err) {
        var connErr = _isGetAddrInfoError(err)
          ? _createGetAddrInfoError(address)
          : _createConnectError('ECONNREFUSED', address, selfRef.remotePort, 'connect');
        attemptErrors.push(connErr);
        nextAttempt();
      }
    }
    nextAttempt();
  }

  setTimeout(function() {
    if (typeof lookup === 'function') {
      var lookupOptions = { family: lookupFamily };
      if (options.hints !== undefined) lookupOptions.hints = options.hints;
      if (options.verbatim !== undefined) lookupOptions.verbatim = options.verbatim;
      if (autoSelectFamily) lookupOptions.all = true;
      if (options.all !== undefined) lookupOptions.all = options.all;

      try {
        lookup(self.remoteAddress, lookupOptions, function(err, lookupResult, candidateFamily) {
          if (err) {
            self.connecting = false;
            self.pending = false;
            self.readyState = 'closed';
            self.emit('lookup', err, undefined, undefined, self.remoteAddress);
            self.emit('error', err);
            return;
          }

          if (candidateFamily != null) {
            lookupFamily = _parseLookupFamily(candidateFamily);
          }

          var normalized = _normalizeLookupResults(lookupResult)
            .map(function(entry) {
              return _normalizeCandidate(entry, lookupFamily);
            })
            .filter(Boolean);
          if (autoSelectFamily === false && normalized.length > 0) {
            normalized = [normalized[0]];
          }

          if (normalized.length === 0) {
            normalized = [ { address: self.remoteAddress, family: lookupFamily } ];
          }

          var first = normalized[0];
          if (first) {
            self.emit('lookup', null, first.address, _addressFamilyToName(first.family || lookupFamily), self.remoteAddress);
          }

          if (autoSelectFamily) {
            self.autoSelectFamilyAttemptedAddresses = _getAutoSelectFamilyAttemptedAddresses(normalized, self.remotePort);
          }

          _startTcpConnect(self, normalized, autoSelectFamily);
        });
      } catch (err) {
        self.connecting = false;
        self.pending = false;
        self.readyState = 'closed';
        self.emit('error', err);
      }
      return;
    }

    _startTcpConnect(self, attempts, autoSelectFamily);
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
  if (_unwrapHandle(this._handle) == null) {
    if (this.connecting) {
      var queuedData = null;
      if (typeof data === 'string') {
        var enc = encoding || 'utf8';
        var cacheKey = enc + ':' + data;
        var cached = this._writeBufferCache[cacheKey];
        if (cached == null) {
          cached = Buffer.from(data, enc);
          this._writeBufferCache[cacheKey] = cached;
        }
        queuedData = cached;
      } else {
        queuedData = toBufferData(data, encoding);
      }
      if (queuedData == null) queuedData = '';

      this._writeQueue.push({
        data: queuedData,
        offset: 0,
        callback: callback,
      });

      return false;
    }
    var err2 = new Error('Socket is not connected');
    err2.code = 'ERR_SOCKET_CLOSED';
    if (callback) callback(err2);
    return false;
  }

  var dataToWrite = null;
  if (typeof data === 'string') {
    var enc = encoding || 'utf8';
    var cacheKey = enc + ':' + data;
    var cached = this._writeBufferCache[cacheKey];
    if (cached == null) {
      cached = Buffer.from(data, enc);
      this._writeBufferCache[cacheKey] = cached;
    }
    dataToWrite = cached;
  } else {
    dataToWrite = toBufferData(data, encoding);
  }
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
  if (_unwrapHandle(this._handle) != null) {
    this._closeAfterEnd = true;
    this._drainWriteQueue();
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
  var nativeHandle = _unwrapHandle(this._handle);
  if (nativeHandle != null && _hasTcp) {
    try { __exactTcpClose(nativeHandle); } catch(e) {}
    if (this._handle && this._handle._exactHandle !== undefined) {
      this._handle._exactHandle = null;
    } else {
      this._handle = null;
    }
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
  if (_unwrapHandle(this._handle) != null && _hasTcp) {
    try { this._handle.setNoDelay(noDelay !== false); } catch(e) {}
  }
  return this;
};

Socket.prototype.setKeepAlive = function(enable, delay) {
  if (_unwrapHandle(this._handle) != null && _hasTcp) {
    try { this._handle.setKeepAlive(enable, delay); } catch(e) {}
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
    var nativeHandle = _unwrapHandle(this._handle);
    if (nativeHandle == null) return { address: this.localAddress, port: this.localPort, family: this.localFamily || this.remoteFamily || 'IPv4' };
    try {
      var info = __exactTcpLocalAddr(nativeHandle);
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
    if (ok === false && typeof self.pause === 'function') self.pause();
  });
  dest.on('drain', function() {
    if (typeof self.resume === 'function') self.resume();
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
  this.ipv6Only = false;
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
    if (opts.ipv6Only !== undefined) {
      this.ipv6Only = opts.ipv6Only === true;
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
  this.host = this._host;

  if (!_hasTcp) {
    this.listening = true;
    setTimeout(function() { self.emit('listening'); }, 0);
    return this;
  }

  setTimeout(function() {
    if (listenToken !== self._listenToken) return;
      try {
      self._handle = __exactTcpListen(self._host, self._port, backlog || 128, self.ipv6Only ? 1 : 0);
      _registerTcpServer(self);
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
        if (!self.emit('connection', socket)) {
          socket.end();
        }
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
  if (typeof callback === 'function') {
    _assertListenerArgument(callback, 'callback');
    this.once('close', callback);
  }
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
    _unregisterTcpServer(this);
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
  setDefaultAutoSelectFamily: setDefaultAutoSelectFamily,
  getDefaultAutoSelectFamilyAttemptTimeout: getDefaultAutoSelectFamilyAttemptTimeout,
  setDefaultAutoSelectFamilyAttemptTimeout: setDefaultAutoSelectFamilyAttemptTimeout
};
module.exports.default = module.exports;
