'use strict';

var EventEmitter = require('events');

// dgram sockets share the native socket registry and its opaque
// runtime/principal owner stamp with net.Socket. Capture the immutable owner
// hook and the EventEmitter entry points before application code can replace
// prototype bindings.
// @ref LLP 0004#retained-native-wrapper-invariant — a retained UDP wrapper is
// not bearer authority for routing, receive disclosure, or lifecycle control.
const _dgramOwnerHost = globalThis.__exactNetOwner;
var _hasNativeDgram = typeof __exactUdpSocket === 'function';
var _dgramEventEmitterOwned = Object.create(null);
[
  'emit', 'on', 'addListener', 'once', 'prependListener',
  'prependOnceListener', 'removeListener', 'off', 'removeAllListeners',
  'listeners', 'rawListeners', 'listenerCount', 'eventNames',
  'getMaxListeners', 'setMaxListeners'
].forEach(function(name) {
  if (EventEmitter.prototype && typeof EventEmitter.prototype[name] === 'function') {
    _dgramEventEmitterOwned[name] = EventEmitter.prototype[name];
  }
});
var _dgramStartRecvOwned = null;
var _dgramCloseOwned = null;

// --- Validation helpers ---
function _validatePort(port) {
  if (port !== undefined && port !== null) {
    var p = typeof port === 'string' ? Number(port) : port;
    if (typeof port !== 'number' && typeof port !== 'string') {
      var err = new RangeError('The "port" argument should be >= 0 and < 65536. Received type ' + typeof port);
      err.code = 'ERR_SOCKET_BAD_PORT';
      throw err;
    }
    if (isNaN(p) || p < 0 || p > 65535 || p !== (p >>> 0)) {
      if (p === 0 && (port === null || port === undefined)) return 0;
      var err2 = new RangeError('The "port" argument should be >= 0 and < 65536. Received ' + port);
      err2.code = 'ERR_SOCKET_BAD_PORT';
      throw err2;
    }
    return p >>> 0;
  }
  return 0;
}

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + (input.name || 'anonymous');
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + JSON.stringify(input) + ')';
}

function _validateBuffer(buffer, name) {
  if (typeof buffer === 'string') return;
  if (Buffer.isBuffer(buffer)) return;
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(buffer)) return;
  var err = new TypeError('The "' + (name || 'buffer') + '" argument must be of type string or an instance of Buffer, TypedArray, or DataView.' + _invalidArgTypeHelper(buffer));
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function _validateBufferList(list) {
  // Validate array of buffers
  for (var i = 0; i < list.length; i++) {
    var item = list[i];
    if (typeof item !== 'string' && !Buffer.isBuffer(item) && !(typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(item))) {
      var err = new TypeError('The "buffer list arguments" argument must be of type string or an instance of Buffer, TypedArray, or DataView. Received an instance of Array');
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
}

function _validateSendOffsetLength(buffer, offset, length) {
  var bufLen;
  if (typeof buffer === 'string') {
    bufLen = Buffer.byteLength(buffer);
  } else if (Buffer.isBuffer(buffer)) {
    bufLen = buffer.length;
  } else if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(buffer)) {
    bufLen = buffer.byteLength;
  } else {
    bufLen = buffer.length || 0;
  }

  if (offset < 0 || offset >= bufLen) {
    if (bufLen > 0 || offset > 0) {
      var errOff = new RangeError('"offset" is outside of buffer bounds');
      errOff.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
      throw errOff;
    }
  }
  if (length < 0 || offset + length > bufLen) {
    var errLen = new RangeError('"length" is outside of buffer bounds');
    errLen.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
    throw errLen;
  }
}

// Apply ref/unref to a poll timer without stopping it. setTimeout returns a
// Timeout wrapper whose ref()/unref() only toggle whether it holds the event
// loop open; the callback keeps firing either way.
function _setTimerRef(timer, refed) {
  if (!timer || typeof timer !== 'object') return;
  try {
    if (refed) {
      if (typeof timer.ref === 'function') timer.ref();
    } else if (typeof timer.unref === 'function') {
      timer.unref();
    }
  } catch (e) {
    // Best effort: timer handles differ across host implementations.
  }
}

var _dgramSocketStates = typeof WeakMap === 'function' ? new WeakMap() : null;

function _assertDgramStateOwner(state, nativeHandle) {
  if (!state) {
    var receiverErr = new TypeError('dgram.Socket method called on an incompatible receiver');
    receiverErr.code = 'ERR_INVALID_THIS';
    throw receiverErr;
  }
  if (state.ownerStamp != null && _dgramOwnerHost) {
    if (typeof nativeHandle === 'number' && nativeHandle >= 0) {
      _dgramOwnerHost('assert', state.ownerStamp, nativeHandle);
    } else {
      _dgramOwnerHost('assert', state.ownerStamp);
    }
    return state;
  }
  if (_hasNativeDgram && state.closed !== true) {
    throw new Error('dgram.Socket owner stamp is unavailable');
  }
  return state;
}

function _dgramStateProjectionDescriptor(state, name) {
  return {
    enumerable: true,
    configurable: false,
    get: function() {
      _assertDgramStateOwner(state);
      return state.values[name];
    },
    set: function(value) {
      _assertDgramStateOwner(state);
      state.values[name] = value;
    }
  };
}

function _dgramEventMethodDescriptor(state, name) {
  return {
    enumerable: false,
    configurable: false,
    get: function() {
      _assertDgramStateOwner(state);
      return _dgramEventEmitterOwned[name];
    },
    set: function() {
      _assertDgramStateOwner(state);
      throw new Error('dgram.Socket event methods are private');
    }
  };
}

function _installDgramEventMethodProjections(socket, state) {
  // Keep every installed public name literal so the CapSec surface inventory
  // can prove the exported Socket shape without trusting a runtime name table.
  Object.defineProperties(socket, {
    emit: _dgramEventMethodDescriptor(state, 'emit'),
    on: _dgramEventMethodDescriptor(state, 'on'),
    addListener: _dgramEventMethodDescriptor(state, 'addListener'),
    once: _dgramEventMethodDescriptor(state, 'once'),
    prependListener: _dgramEventMethodDescriptor(state, 'prependListener'),
    prependOnceListener: _dgramEventMethodDescriptor(state, 'prependOnceListener'),
    removeListener: _dgramEventMethodDescriptor(state, 'removeListener'),
    off: _dgramEventMethodDescriptor(state, 'off'),
    removeAllListeners: _dgramEventMethodDescriptor(state, 'removeAllListeners'),
    listeners: _dgramEventMethodDescriptor(state, 'listeners'),
    rawListeners: _dgramEventMethodDescriptor(state, 'rawListeners'),
    listenerCount: _dgramEventMethodDescriptor(state, 'listenerCount'),
    eventNames: _dgramEventMethodDescriptor(state, 'eventNames'),
    getMaxListeners: _dgramEventMethodDescriptor(state, 'getMaxListeners'),
    setMaxListeners: _dgramEventMethodDescriptor(state, 'setMaxListeners')
  });
}

function _installDgramSocketState(socket) {
  if (!_dgramSocketStates || typeof Object.defineProperty !== 'function') {
    throw new Error('dgram.Socket requires WeakMap-backed private state');
  }
  var state = {
    handle: -1,
    closed: false,
    ownerStamp: _dgramOwnerHost ? _dgramOwnerHost('new') : null,
    values: Object.create(null),
    type: null,
    binding: { bound: false, bindState: 0, address: null },
    route: { connected: false, port: null, address: null, generation: 0 }
  };
  _dgramSocketStates.set(socket, state);
  // EventEmitter.call() and the constructor's type validation run before the
  // owner stamp exists; migrate those few initial values explicitly, then
  // install a statically enumerable set of private-state projections.
  state.values._events = socket._events;
  state.values._eventsCount = socket._eventsCount;
  state.values._maxListeners = socket._maxListeners;
  state.values.type = socket.type;
  try { delete socket._events; } catch (_deleteDgramEventsErr) {
    // The projection descriptors below replace these fields when configurable.
  }
  try { delete socket._eventsCount; } catch (_deleteDgramEventCountErr) {
    // The projection descriptors below replace these fields when configurable.
  }
  try { delete socket._maxListeners; } catch (_deleteDgramMaxListenersErr) {
    // The projection descriptors below replace these fields when configurable.
  }
  try { delete socket.type; } catch (_deleteDgramTypeErr) {
    // The projection descriptors below replace these fields when configurable.
  }
  Object.defineProperties(socket, {
    _events: _dgramStateProjectionDescriptor(state, '_events'),
    _eventsCount: _dgramStateProjectionDescriptor(state, '_eventsCount'),
    _maxListeners: _dgramStateProjectionDescriptor(state, '_maxListeners'),
    type: _dgramStateProjectionDescriptor(state, 'type'),
    lookup: _dgramStateProjectionDescriptor(state, 'lookup'),
    _bound: _dgramStateProjectionDescriptor(state, '_bound'),
    _bindState: _dgramStateProjectionDescriptor(state, '_bindState'),
    _connected: _dgramStateProjectionDescriptor(state, '_connected'),
    _connectPort: _dgramStateProjectionDescriptor(state, '_connectPort'),
    _connectAddress: _dgramStateProjectionDescriptor(state, '_connectAddress'),
    _address: _dgramStateProjectionDescriptor(state, '_address'),
    _pollTimer: _dgramStateProjectionDescriptor(state, '_pollTimer'),
    _unrefed: _dgramStateProjectionDescriptor(state, '_unrefed'),
    _receiving: _dgramStateProjectionDescriptor(state, '_receiving'),
    _fd: _dgramStateProjectionDescriptor(state, '_fd'),
    _reuseAddr: _dgramStateProjectionDescriptor(state, '_reuseAddr'),
    _recvBufferSize: _dgramStateProjectionDescriptor(state, '_recvBufferSize'),
    _sendBufferSize: _dgramStateProjectionDescriptor(state, '_sendBufferSize')
  });
  Object.defineProperty(socket, '_handle', {
    enumerable: false,
    configurable: false,
    get: function() {
      _assertDgramStateOwner(state);
      throw new Error('dgram native handle is private');
    },
    set: function() {
      _assertDgramStateOwner(state);
      throw new Error('dgram native handle is private');
    }
  });
  Object.defineProperty(socket, '_closed', {
    enumerable: false,
    configurable: false,
    get: function() {
      _assertDgramStateOwner(state);
      return state.closed;
    },
    set: function() {
      _assertDgramStateOwner(state);
      throw new Error('dgram close state is private');
    }
  });
  _installDgramEventMethodProjections(socket, state);
  return state;
}

function _dgramState(socket) {
  var state = _dgramSocketStates && _dgramSocketStates.get(socket);
  return _assertDgramStateOwner(state);
}

function _assignDgramHandle(socket, handle) {
  var state = _dgramSocketStates && _dgramSocketStates.get(socket);
  state = _assertDgramStateOwner(state, handle);
  state.handle = handle;
  return handle;
}

function _publishDgramBinding(state, bound, bindState, address) {
  state.binding.bound = bound === true;
  state.binding.bindState = bindState;
  if (address !== undefined) state.binding.address = address;
  state.values._bound = state.binding.bound;
  state.values._bindState = state.binding.bindState;
  state.values._address = state.binding.address;
}

function _publishDgramRoute(state, connected, port, address) {
  state.route.generation += 1;
  state.route.connected = connected === true;
  state.route.port = state.route.connected ? port : null;
  state.route.address = state.route.connected ? address : null;
  state.values._connected = state.route.connected;
  state.values._connectPort = state.route.port;
  state.values._connectAddress = state.route.address;
}

function _runDgramStartRecv(socket) {
  if (!_dgramStartRecvOwned) throw new Error('dgram receive implementation is unavailable');
  return _dgramStartRecvOwned.call(socket);
}

function _runDgramClose(socket) {
  if (!_dgramCloseOwned) throw new Error('dgram close implementation is unavailable');
  return _dgramCloseOwned.call(socket);
}

function Socket(type, listener) {
  if (!(this instanceof Socket)) return new Socket(type, listener);
  EventEmitter.call(this);

  var opts = {};
  if (typeof type === 'string') {
    // Direct string type
  } else if (typeof type === 'object' && type !== null && !Array.isArray(type) && !(type instanceof String)) {
    opts = type;
    type = opts.type;
  } else {
    // null, undefined, boolean, number, array, String object, etc.
    var typeErr = new TypeError('Bad socket type specified. Valid types are: udp4, udp6');
    typeErr.code = 'ERR_SOCKET_BAD_TYPE';
    throw typeErr;
  }

  // Validate type
  if (type !== 'udp4' && type !== 'udp6') {
    var typeErr2 = new TypeError('Bad socket type specified. Valid types are: udp4, udp6');
    typeErr2.code = 'ERR_SOCKET_BAD_TYPE';
    throw typeErr2;
  }

  // Validate recvBufferSize / sendBufferSize
  if (opts.recvBufferSize !== undefined && typeof opts.recvBufferSize !== 'number') {
    var rbsErr = new TypeError('The "options.recvBufferSize" property must be of type number.' + _invalidArgTypeHelper(opts.recvBufferSize));
    rbsErr.code = 'ERR_INVALID_ARG_TYPE';
    throw rbsErr;
  }
  if (opts.sendBufferSize !== undefined && typeof opts.sendBufferSize !== 'number') {
    var sbsErr = new TypeError('The "options.sendBufferSize" property must be of type number.' + _invalidArgTypeHelper(opts.sendBufferSize));
    sbsErr.code = 'ERR_INVALID_ARG_TYPE';
    throw sbsErr;
  }

  this.type = type;
  var privateState = _installDgramSocketState(this);
  privateState.type = type;
  privateState.handle = -1;
  _publishDgramBinding(privateState, false, 0, null);
  privateState.closed = false;
  this._pollTimer = null;
  this._unrefed = false;
  this._receiving = false;
  this._fd = -1;
  _publishDgramRoute(privateState, false, null, null);
  this._reuseAddr = opts.reuseAddr || false;
  this._recvBufferSize = opts.recvBufferSize || 0;
  this._sendBufferSize = opts.sendBufferSize || 0;

  if (typeof opts.lookup === 'function') {
    this.lookup = opts.lookup;
  }

  if (typeof listener === 'function') {
    this.on('message', listener);
  }

  // Handle AbortSignal
  if (opts.signal !== undefined) {
    if (!(opts.signal instanceof AbortSignal)) {
      var sigErr = new TypeError('The "options.signal" property must be an instance of AbortSignal. Received type ' + typeof opts.signal);
      sigErr.code = 'ERR_INVALID_ARG_TYPE';
      throw sigErr;
    }
    var self = this;
    if (opts.signal.aborted) {
      setTimeout(function() { _runDgramClose(self); }, 0);
    } else {
      opts.signal.addEventListener('abort', function() { _runDgramClose(self); }, { once: true });
    }
  }
}

Socket.prototype = Object.create(EventEmitter.prototype);
Socket.prototype.constructor = Socket;

Socket.prototype.bind = function(port, address, callback) {
  var state = _dgramState(this);
  if (state.closed) {
    throw new Error('Socket is closed');
  }

  // Check if already bound
  if (state.binding.bindState === 2) {
    var boundErr = new Error('Socket is already bound');
    boundErr.code = 'ERR_SOCKET_ALREADY_BOUND';
    throw boundErr;
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
  address = address || (state.type === 'udp6' ? '::' : '0.0.0.0');

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  _publishDgramBinding(state, false, 1, null); // binding
  var self = this;

  // Create the native UDP socket if not already created
  if (state.handle < 0) {
    try {
      _assignDgramHandle(this, globalThis.__exactUdpSocket(state.type));
    } catch(e) {
      // If native support not available, create a mock handle. The owner check
      // above has already rejected a foreign caller before reaching this path.
      _assignDgramHandle(this, -1);
    }
  }

  if (state.handle < 0) {
    // No native UDP support - use mock
    _publishDgramBinding(state, true, 2, {
      address: address,
      port: port || 0,
      family: state.type === 'udp6' ? 'IPv6' : 'IPv4'
    });
    setTimeout(function() {
      self.emit('listening');
    }, 0);
    return this;
  }

  // Bind
  try {
    var result = globalThis.__exactUdpBind(state.handle, address, port);
    var addrInfo = typeof result === 'string' ? JSON.parse(result) : result;
    _publishDgramBinding(state, true, 2, addrInfo);
  } catch(e) {
    _publishDgramBinding(state, false, 0, null);
    var bindErr = new Error(e.message || String(e));
    bindErr.code = 'EADDRINUSE';
    setTimeout(function() {
      self.emit('error', bindErr);
    }, 0);
    return this;
  }

  // Start receiving
  _runDgramStartRecv(this);

  // Emit listening asynchronously
  setTimeout(function() {
    self.emit('listening');
  }, 0);

  return this;
};

Socket.prototype._startRecv = function() {
  var state = _dgramState(this);
  if (state.values._receiving || state.closed) return;
  state.values._receiving = true;
  var self = this;
  var pollInterval = 5;

  function poll() {
    _assertDgramStateOwner(state, state.handle);
    if (state.closed || state.handle < 0) return;
    try {
      var result = globalThis.__exactUdpRecv(state.handle);
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
      if (!state.closed) {
        self.emit('error', e);
      }
    }
    if (!state.closed) {
      state.values._pollTimer = setTimeout(poll, pollInterval);
      if (state.values._unrefed) _setTimerRef(state.values._pollTimer, false);
    }
  }

  state.values._pollTimer = setTimeout(poll, 0);
  if (state.values._unrefed) _setTimerRef(state.values._pollTimer, false);
};
_dgramStartRecvOwned = Socket.prototype._startRecv;

Socket.prototype.connect = function(port, address, callback) {
  var state = _dgramState(this);
  if (state.closed) {
    throw new Error('Socket is closed');
  }

  // Check if already connecting/connected
  if (state.route.connected || state.route.port !== null) {
    var connErr = new Error('Already connected');
    connErr.code = 'ERR_SOCKET_DGRAM_IS_CONNECTED';
    throw connErr;
  }

  // Validate port
  if (port === undefined || port === null || port === 0 || (typeof port === 'number' && (port < 1 || port > 65535 || port !== (port >>> 0)))) {
    var portErr = new RangeError('Port should be > 0 and < 65536. Received ' + port + '.');
    portErr.code = 'ERR_SOCKET_BAD_PORT';
    throw portErr;
  }

  if (typeof address === 'function') {
    callback = address;
    address = undefined;
  }

  address = address || (state.type === 'udp6' ? '::1' : '127.0.0.1');

  if (typeof callback === 'function') {
    this.once('connect', callback);
  }

  // Implicit bind if not yet bound
  if (!state.binding.bound) {
    _publishDgramBinding(state, false, 1, null);
    if (state.handle < 0) {
      try {
        _assignDgramHandle(this, globalThis.__exactUdpSocket(state.type));
      } catch(e) {
        _assignDgramHandle(this, -1);
      }
    }
    if (state.handle >= 0) {
      try {
        var bindResult = globalThis.__exactUdpBind(state.handle, state.type === 'udp6' ? '::' : '0.0.0.0', 0);
        var bindInfo = typeof bindResult === 'string' ? JSON.parse(bindResult) : bindResult;
        _publishDgramBinding(state, true, 2, bindInfo);
        _runDgramStartRecv(this);
      } catch(e) {
        // The implicit wildcard bind is a network:listen operation. If it is
        // denied (connect-only grant) do NOT pretend the socket is bound: a
        // connect-only handle must not gain the receive/address/fd authority of
        // a listening socket. send() still works (the kernel binds implicitly on
        // the first datagram and each send re-checks network:connect), while
        // address()/recv/fd stay closed on the capability-less handle.
        // @ref LLP 0013#policy — (ENG-22819)
        _publishDgramBinding(state, false, 0, null);
      }
    }
  }

  _publishDgramRoute(state, true, port, address);
  var routeGeneration = state.route.generation;

  var self = this;
  setTimeout(function() {
    var scheduledState = _dgramState(self);
    if (!scheduledState.route.connected ||
        scheduledState.route.generation !== routeGeneration) return;
    self.emit('connect');
  }, 0);
};

Socket.prototype.disconnect = function() {
  var state = _dgramState(this);
  if (!state.route.connected) {
    var err = new Error('Not connected');
    err.code = 'ERR_SOCKET_DGRAM_NOT_CONNECTED';
    throw err;
  }
  _publishDgramRoute(state, false, null, null);
};

Socket.prototype.remoteAddress = function() {
  var state = _dgramState(this);
  if (!state.route.connected) {
    var err = new Error('Not connected');
    err.code = 'ERR_SOCKET_DGRAM_NOT_CONNECTED';
    throw err;
  }
  return {
    address: state.route.address,
    family: state.type === 'udp6' ? 'IPv6' : 'IPv4',
    port: state.route.port
  };
};

Socket.prototype.send = function(msg, offset, length, port, address, callback) {
  var state = _dgramState(this);
  if (state.closed) {
    var err = new Error('Not running');
    err.code = 'ERR_SOCKET_DGRAM_NOT_RUNNING';
    if (typeof callback === 'function') {
      callback(err);
      return;
    }
    throw err;
  }

  // Validate buffer argument
  if (msg === undefined) {
    _validateBuffer(msg, 'buffer');
  }
  if (Array.isArray(msg)) {
    _validateBufferList(msg);
  } else if (typeof msg !== 'string' && !Buffer.isBuffer(msg) && !(typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(msg))) {
    _validateBuffer(msg, 'buffer');
  }

  // Handle different argument forms:
  // send(msg, offset, length, port, address, callback)  -- full form
  // send(msg, port, address, callback)                   -- short form
  // send(msg, port, callback)                            -- short form without address
  // send(msg, callback) -- connected socket
  // send(msg)           -- connected socket

  // Detect form: if 3rd arg is a string (address) or undefined/function => short form
  if (typeof length === 'string' || typeof length === 'undefined' || typeof length === 'function') {
    // Short form: send(msg, port, address, callback) or send(msg, callback) or send(msg)
    callback = port;
    address = length;
    port = offset;
    offset = 0;
    if (typeof msg === 'string') {
      length = Buffer.byteLength(msg);
    } else if (Array.isArray(msg)) {
      length = 0;
      for (var ai = 0; ai < msg.length; ai++) {
        if (typeof msg[ai] === 'string') length += Buffer.byteLength(msg[ai]);
        else if (msg[ai]) length += msg[ai].length || msg[ai].byteLength || 0;
      }
    } else if (msg) {
      length = msg.length || msg.byteLength || 0;
    } else {
      length = 0;
    }
  } else if (typeof offset === 'number' && typeof length === 'number') {
    // Full form with offset/length
    // Check if connected and port is provided (this means port was actually passed => error if connected)
    if (state.route.connected && (typeof port === 'number' || typeof address === 'string')) {
      var connErr = new Error('Already connected');
      connErr.code = 'ERR_SOCKET_DGRAM_IS_CONNECTED';
      throw connErr;
    }
    // Validate offset and length
    if (!Array.isArray(msg)) {
      _validateSendOffsetLength(msg, offset, length);
    }
    // Extract the portion of msg from offset with length
    if (Buffer.isBuffer(msg)) {
      msg = msg.slice(offset, offset + length);
    } else if (typeof msg === 'string') {
      msg = msg.substring(offset, offset + length);
    } else if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(msg)) {
      var _copy = Buffer.alloc(length);
      _copy.set(new Uint8Array(msg.buffer, msg.byteOffset + offset, length));
      msg = _copy;
    }
    offset = 0;
  }

  // Normalize a trailing callback that argument-form parsing left in the
  // `address` or `port` slot. This MUST run for both connected and unconnected
  // sockets: send(msg, port, cb) parses cb into `address`, and
  // send(msg, offset, length, port, cb) parses cb into `address` as well.
  // Previously this only ran inside the `if (this._connected)` branch below, so
  // an unconnected send never invoked its callback and passed the function
  // object to __exactUdpSend as the destination address.
  if (typeof address === 'function') {
    callback = address;
    address = undefined;
  }
  if (typeof port === 'function') {
    callback = port;
    port = undefined;
  }

  // If connected socket with port/address provided, throw
  if (state.route.connected && (typeof port === 'number' || typeof address === 'string')) {
    var connErr2 = new Error('Already connected');
    connErr2.code = 'ERR_SOCKET_DGRAM_IS_CONNECTED';
    throw connErr2;
  }

  // For connected sockets, use stored address/port
  if (state.route.connected) {
    port = port || state.route.port;
    address = address || state.route.address;
  }

  // Validate port for unconnected sends
  if (!state.route.connected) {
    if (typeof port !== 'number' || port < 0 || port > 65535) {
      if (typeof port === 'number' && (port < 0 || port > 65535 || port === 0)) {
        var portErr = new RangeError('"port" argument should be >= 0 and < 65536. Received ' + port);
        portErr.code = 'ERR_SOCKET_BAD_PORT';
        throw portErr;
      }
    }
  }

  // Implicit bind if not yet bound
  if (!state.binding.bound && state.handle < 0) {
    try {
      _assignDgramHandle(this, globalThis.__exactUdpSocket(state.type));
      var bindResult = globalThis.__exactUdpBind(state.handle, state.type === 'udp6' ? '::' : '0.0.0.0', 0);
      var bindInfo = typeof bindResult === 'string' ? JSON.parse(bindResult) : bindResult;
      _publishDgramBinding(state, true, 2, bindInfo);
      _runDgramStartRecv(this);
    } catch(e) {
      // Continue anyway for mock mode.
    }
  }

  // Create socket if not yet created
  if (state.handle < 0) {
    try {
      _assignDgramHandle(this, globalThis.__exactUdpSocket(state.type));
    } catch(e) {
      // No native support.
    }
  }

  // Convert msg to something sendable
  var sendData = msg;
  if (typeof msg === 'string') {
    sendData = (typeof Buffer !== 'undefined') ? Buffer.from(msg) : msg;
  } else if (Array.isArray(msg)) {
    // Array of buffers - concatenate
    var parts = [];
    for (var pi = 0; pi < msg.length; pi++) {
      if (typeof msg[pi] === 'string') parts.push(Buffer.from(msg[pi]));
      else if (Buffer.isBuffer(msg[pi])) parts.push(msg[pi]);
      else if (msg[pi] && typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(msg[pi])) {
        var _partCopy = Buffer.alloc(msg[pi].byteLength);
        _partCopy.set(new Uint8Array(msg[pi].buffer, msg[pi].byteOffset, msg[pi].byteLength));
        parts.push(_partCopy);
      }
    }
    sendData = parts.length > 0 ? Buffer.concat(parts) : Buffer.alloc(0);
  }

  var self = this;
  try {
    if (state.handle >= 0 && typeof globalThis.__exactUdpSend === 'function') {
      globalThis.__exactUdpSend(state.handle, sendData, port, address || '127.0.0.1');
    }
    var bytesSent = sendData ? (sendData.length || sendData.byteLength || 0) : 0;
    if (typeof callback === 'function') {
      setTimeout(function() { callback(null, bytesSent); }, 0);
    }
  } catch (e) {
    if (typeof callback === 'function') {
      setTimeout(function() { callback(e); }, 0);
    } else {
      self.emit('error', e);
    }
  }
};

Socket.prototype.sendto = function(msg, offset, length, port, address, callback) {
  _dgramState(this);
  // Validate arguments strictly
  if (typeof offset !== 'number') {
    var offErr = new TypeError('The "offset" argument must be of type number.' + _invalidArgTypeHelper(offset));
    offErr.code = 'ERR_INVALID_ARG_TYPE';
    throw offErr;
  }
  if (typeof length !== 'number') {
    var lenErr = new TypeError('The "length" argument must be of type number.' + _invalidArgTypeHelper(length));
    lenErr.code = 'ERR_INVALID_ARG_TYPE';
    throw lenErr;
  }
  if (typeof port !== 'number') {
    var portErr = new TypeError('The "port" argument must be of type number.' + _invalidArgTypeHelper(port));
    portErr.code = 'ERR_INVALID_ARG_TYPE';
    throw portErr;
  }
  if (typeof address !== 'string') {
    var addrErr = new TypeError('The "address" argument must be of type string.' + _invalidArgTypeHelper(address));
    addrErr.code = 'ERR_INVALID_ARG_TYPE';
    throw addrErr;
  }

  // Validate buffer type
  _validateBuffer(msg, 'buffer');

  this.send(msg, offset, length, port, address, callback);
};

Socket.prototype.close = function(callback) {
  var state = _dgramState(this);
  if (state.closed) return this;

  // Native close authenticates the runtime/principal. Do not stop polling,
  // mark closed, or forget the private selector until it succeeds.
  if (state.handle >= 0 && typeof globalThis.__exactUdpClose === 'function') {
    globalThis.__exactUdpClose(state.handle);
  }
  state.closed = true;

  if (state.values._pollTimer) {
    clearTimeout(state.values._pollTimer);
    state.values._pollTimer = null;
  }

  state.handle = -1;

  var self = this;
  if (typeof callback === 'function') {
    this.once('close', callback);
  }
  setTimeout(function() {
    self.emit('close');
  }, 0);

  return this;
};
_dgramCloseOwned = Socket.prototype.close;

Socket.prototype.address = function() {
  var state = _dgramState(this);
  if (!state.binding.bound || state.closed) {
    throw new Error('getsockname EBADF');
  }
  if (state.binding.address) return state.binding.address;
  if (state.handle >= 0 && typeof globalThis.__exactUdpAddress === 'function') {
    var result = globalThis.__exactUdpAddress(state.handle);
    if (typeof result === 'string') result = JSON.parse(result);
    return result;
  }
  return state.binding.address || { address: '0.0.0.0', port: 0, family: 'IPv4' };
};

Socket.prototype.setRecvBufferSize = function(size) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('setRecvBufferSize EBADF');
  }
  return this;
};

Socket.prototype.setSendBufferSize = function(size) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('setSendBufferSize EBADF');
  }
  return this;
};

Socket.prototype.getRecvBufferSize = function() {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('getRecvBufferSize EBADF');
  }
  return this._recvBufferSize || 65536; // return configured or default
};

Socket.prototype.getSendBufferSize = function() {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('getSendBufferSize EBADF');
  }
  return this._sendBufferSize || 65536; // return configured or default
};

Socket.prototype.setTTL = function(ttl) {
  var state = _dgramState(this);
  if (typeof ttl !== 'number') {
    var err = new TypeError('The "ttl" argument must be of type number.' + _invalidArgTypeHelper(ttl));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (!state.binding.bound) {
    throw new Error('setTTL EBADF');
  }
  if (ttl < 1 || ttl > 255) {
    throw new Error('setTTL EINVAL');
  }
  if (state.handle >= 0 && typeof globalThis.__exactUdpSetTTL === 'function') {
    try { globalThis.__exactUdpSetTTL(state.handle, ttl); } catch(e) {
      // Preserve Node's local setter semantics when the reduced host rejects it.
    }
  }
  return ttl;
};

Socket.prototype.setMulticastTTL = function(ttl) {
  var state = _dgramState(this);
  if (typeof ttl !== 'number') {
    var err = new TypeError('The "ttl" argument must be of type number.' + _invalidArgTypeHelper(ttl));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (!state.binding.bound) {
    throw new Error('setMulticastTTL EBADF');
  }
  if (ttl < 0 || ttl > 255) {
    throw new Error('setMulticastTTL EINVAL');
  }
  if (state.handle >= 0 && typeof globalThis.__exactUdpSetMulticastTTL === 'function') {
    try { globalThis.__exactUdpSetMulticastTTL(state.handle, ttl); } catch(e) {
      // Preserve Node's local setter semantics when the reduced host rejects it.
    }
  }
  return ttl;
};

Socket.prototype.setMulticastLoopback = function(flag) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('setMulticastLoopback EBADF');
  }
  return flag;
};

Socket.prototype.setMulticastInterface = function(multicastInterface) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('setMulticastInterface EBADF');
  }
  if (typeof multicastInterface !== 'string') {
    var err = new TypeError('The "multicastInterface" argument must be of type string');
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
};

Socket.prototype.addMembership = function(multicastAddress, multicastInterface) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    // Implicit bind
    this.bind(0);
  }
  state = _dgramState(this);
  if (state.handle >= 0 && typeof globalThis.__exactUdpAddMembership === 'function') {
    try { globalThis.__exactUdpAddMembership(state.handle, multicastAddress, multicastInterface || ''); } catch(e) {
      // Membership support is optional in the reduced UDP host.
    }
  }
};

Socket.prototype.dropMembership = function(multicastAddress, multicastInterface) {
  var state = _dgramState(this);
  if (state.handle >= 0 && typeof globalThis.__exactUdpDropMembership === 'function') {
    try { globalThis.__exactUdpDropMembership(state.handle, multicastAddress, multicastInterface || ''); } catch(e) {
      // Membership support is optional in the reduced UDP host.
    }
  }
};

Socket.prototype.addSourceSpecificMembership = function(sourceAddress, groupAddress, multicastInterface) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('addSourceSpecificMembership EBADF');
  }
};

Socket.prototype.dropSourceSpecificMembership = function(sourceAddress, groupAddress, multicastInterface) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('dropSourceSpecificMembership EBADF');
  }
};

Socket.prototype.setBroadcast = function(flag) {
  var state = _dgramState(this);
  if (!state.binding.bound) {
    throw new Error('setBroadcast EBADF');
  }
  if (state.handle >= 0 && typeof globalThis.__exactUdpSetBroadcast === 'function') {
    try { globalThis.__exactUdpSetBroadcast(state.handle, flag ? 1 : 0); } catch(e) {
      // Broadcast support is optional in the reduced UDP host.
    }
  }
};

Socket.prototype.ref = function() {
  var state = _dgramState(this);
  state.values._unrefed = false;
  _setTimerRef(state.values._pollTimer, true);
  return this;
};

Socket.prototype.unref = function() {
  var state = _dgramState(this);
  state.values._unrefed = true;
  // In Node, unref() only removes the socket's hold on the event loop; it does
  // NOT stop message delivery. Keep the recv poll running (so ref() and ongoing
  // reception still work) but mark the poll timer unref'd so it won't by itself
  // keep the process alive. Clearing the timer here previously killed reception
  // permanently: _receiving stayed true, so ref()/_startRecv() never resumed it.
  _setTimerRef(state.values._pollTimer, false);
  return this;
};

// For IPC handle passing: reconstruct a Socket from a raw fd
Socket.prototype._fromFd = function(fd) {
  var state = _dgramState(this);
  this._fd = fd;
  if (typeof globalThis.__exactUdpFromFd === 'function') {
    _assignDgramHandle(this, globalThis.__exactUdpFromFd(fd));
  }
  _publishDgramBinding(state, true, 2, state.binding.address);
  // Get address info
  if (state.handle >= 0 && typeof globalThis.__exactUdpAddress === 'function') {
    var addrJson = globalThis.__exactUdpAddress(state.handle);
    if (addrJson) {
      _publishDgramBinding(
        state,
        true,
        2,
        typeof addrJson === 'string' ? JSON.parse(addrJson) : addrJson
      );
    }
  }
  _runDgramStartRecv(this);
  return this;
};

// For IPC: get the fd to send
Socket.prototype._getFd = function() {
  var state = _dgramState(this);
  if (state.handle >= 0 && typeof globalThis.__exactUdpGetFd === 'function') {
    return globalThis.__exactUdpGetFd(state.handle);
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
