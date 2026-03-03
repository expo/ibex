'use strict';

var EventEmitter = require('events');

function Socket(type, listener) {
  EventEmitter.call(this);
  this.type = typeof type === 'object' ? (type.type || 'udp4') : (type || 'udp4');
  this._handle = -1;
  this._bound = false;
  this._closed = false;
  this._pollTimer = null;
  this._receiving = false;
  this._bindState = 0; // 0=unbound, 1=binding, 2=bound
  this._fd = -1;

  if (typeof type === 'object' && typeof type.lookup === 'function') {
    this.lookup = type.lookup;
  }

  if (typeof listener === 'function') {
    this.on('message', listener);
  }
}

Socket.prototype = Object.create(EventEmitter.prototype);
Socket.prototype.constructor = Socket;

Socket.prototype.bind = function(port, address, callback) {
  if (this._closed) {
    throw new Error('Socket is closed');
  }

  // bind(callback) form
  if (typeof port === 'function') {
    callback = port;
    port = 0;
    address = undefined;
  }
  // bind(options, callback) form
  if (typeof port === 'object' && port !== null) {
    var opts = port;
    callback = address;
    port = opts.port || 0;
    address = opts.address;
  }
  // bind(port, callback) form
  if (typeof address === 'function') {
    callback = address;
    address = undefined;
  }

  port = port || 0;
  address = address || (this.type === 'udp6' ? '::' : '0.0.0.0');

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  var self = this;

  // Create the native UDP socket if not already created (e.g. from fd)
  if (this._handle < 0) {
    this._handle = globalThis.__exactUdpSocket(this.type);
  }

  // Bind
  var result = globalThis.__exactUdpBind(this._handle, address, port);
  var addrInfo = typeof result === 'string' ? JSON.parse(result) : result;
  this._bound = true;
  this._bindState = 2;
  this._address = addrInfo;

  // Start receiving
  this._startRecv();

  // Emit listening asynchronously
  setTimeout(function() {
    self.emit('listening');
  }, 0);

  return this;
};

Socket.prototype._startRecv = function() {
  if (this._receiving || this._closed) return;
  this._receiving = true;
  var self = this;
  var pollInterval = 5;

  function poll() {
    if (self._closed) return;
    try {
      var result = globalThis.__exactUdpRecv(self._handle);
      if (result) {
        var data = result.data;
        // Convert Uint8Array to Buffer if available
        if (typeof Buffer !== 'undefined' && data instanceof Uint8Array && !(data instanceof Buffer)) {
          data = Buffer.from(data);
        }
        var rinfo = {
          address: result.address,
          family: result.family,
          port: result.port,
          size: result.size || data.length
        };
        self.emit('message', data, rinfo);
      }
    } catch (e) {
      if (!self._closed) {
        self.emit('error', e);
      }
    }
    if (!self._closed) {
      self._pollTimer = setTimeout(poll, pollInterval);
    }
  }

  this._pollTimer = setTimeout(poll, 0);
};

Socket.prototype.send = function(msg, offset, length, port, address, callback) {
  if (this._closed) {
    var err = new Error('Not running');
    err.code = 'ERR_SOCKET_DGRAM_NOT_RUNNING';
    if (typeof callback === 'function') {
      callback(err);
      return;
    }
    throw err;
  }

  // Handle different argument forms:
  // send(msg, offset, length, port, address, callback)  -- full form
  // send(msg, port, address, callback)                   -- short form
  // Detect: if 3rd arg (length) is a string, it's the short form (address)
  if (typeof length === 'string' || typeof length === 'undefined' || typeof length === 'function') {
    // Short form: send(msg, port, address, callback)
    callback = port;
    address = length;
    port = offset;
    offset = 0;
    length = msg.length;
  } else {
    // Full form: send(msg, offset, length, port, address, callback)
    // Extract the portion of msg from offset with length
    if (Buffer.isBuffer(msg)) {
      msg = msg.slice(offset, offset + length);
    } else if (typeof msg === 'string') {
      msg = msg.substring(offset, offset + length);
    }
  }

  // Create socket if not yet created
  if (this._handle < 0) {
    this._handle = globalThis.__exactUdpSocket(this.type);
  }

  // Convert msg to something sendable
  var sendData = msg;
  if (typeof msg === 'string') {
    sendData = (typeof Buffer !== 'undefined') ? Buffer.from(msg) : msg;
  } else if (Array.isArray(msg)) {
    // Array of buffers - concatenate
    sendData = Buffer.concat(msg);
  }

  var self = this;
  try {
    globalThis.__exactUdpSend(this._handle, sendData, port, address);
    if (typeof callback === 'function') {
      setTimeout(function() { callback(null); }, 0);
    }
  } catch (e) {
    if (typeof callback === 'function') {
      setTimeout(function() { callback(e); }, 0);
    } else {
      self.emit('error', e);
    }
  }
};

Socket.prototype.close = function(callback) {
  if (this._closed) return this;
  this._closed = true;

  if (this._pollTimer) {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
  }

  if (this._handle >= 0) {
    try {
      globalThis.__exactUdpClose(this._handle);
    } catch (e) {}
    this._handle = -1;
  }

  var self = this;
  if (typeof callback === 'function') {
    this.once('close', callback);
  }
  setTimeout(function() {
    self.emit('close');
  }, 0);

  return this;
};

Socket.prototype.address = function() {
  if (!this._bound || this._closed) {
    throw new Error('getsockname EBADF');
  }
  if (this._address) return this._address;
  var result = globalThis.__exactUdpAddress(this._handle);
  if (typeof result === 'string') result = JSON.parse(result);
  return result;
};

Socket.prototype.setRecvBufferSize = function() { return this; };
Socket.prototype.setSendBufferSize = function() { return this; };
Socket.prototype.setTTL = function() { return this; };
Socket.prototype.setMulticastTTL = function() { return this; };
Socket.prototype.setMulticastLoopback = function() { return this; };
Socket.prototype.addMembership = function() { return this; };
Socket.prototype.dropMembership = function() { return this; };
Socket.prototype.setBroadcast = function() { return this; };
Socket.prototype.ref = function() { return this; };
Socket.prototype.unref = function() { return this; };

// For IPC handle passing: reconstruct a Socket from a raw fd
Socket.prototype._fromFd = function(fd) {
  this._fd = fd;
  this._handle = globalThis.__exactUdpFromFd(fd);
  this._bound = true;
  this._bindState = 2;
  // Get address info
  var addrJson = globalThis.__exactUdpAddress(this._handle);
  if (addrJson) {
    this._address = typeof addrJson === 'string' ? JSON.parse(addrJson) : addrJson;
  }
  this._startRecv();
  return this;
};

// For IPC: get the fd to send
Socket.prototype._getFd = function() {
  if (this._handle >= 0) {
    return globalThis.__exactUdpGetFd(this._handle);
  }
  return this._fd;
};

function createSocket(type, callback) {
  return new Socket(type, callback);
}

module.exports = {
  createSocket: createSocket,
  Socket: Socket
};
module.exports.default = module.exports;
