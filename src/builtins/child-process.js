// ENG-23018: opt-in debug visibility (NODE_DEBUG=child_process) for otherwise-
// swallowed best-effort errors. No-op unless the namespace is enabled, so
// hot paths pay only a guarded function call.
var _swallowDebugLog = null;
function _swallowDebug(msg, err) {
  if (_swallowDebugLog === null) {
    try { _swallowDebugLog = require('util').debuglog('child_process'); } catch (_swallowInitErr) { _swallowDebugLog = function() {}; }
  }
  _swallowDebugLog(msg, err);
}
var cp = {};

function _fallbackSpawnCommand(command) {
  if (typeof command !== 'string') {
    return command;
  }
  var procPath = (typeof process !== 'undefined' && process !== null && process.execPath) ? String(process.execPath) : '';
  if (command === procPath && /(^|[\\/])exact/.test(command)) {
    return command;
  }
  return command;
}

function normalizeExecOptions(opts) {
  var o = {};
  if (!opts) return o;
  if (typeof opts === 'string') {
    o.encoding = opts;
    return o;
  }
  if (opts.cwd) o.cwd = String(opts.cwd);
  if (opts.timeout) o.timeout = Number(opts.timeout);
  // (ENG-23008) maxBuffer is enforced in the native bridge from the caller's real
  // value; do not clamp it to 256MB here (that made native never truncate/kill).
  if (opts.encoding !== undefined) o.encoding = opts.encoding;
  if (opts.env) o.env = opts.env;
  if (opts.shell !== undefined) o.shell = opts.shell;
  if (opts.input !== undefined) o.input = opts.input;
  return o;
}

function makeExecError(message, result) {
  var err = new Error(message);
  err.status = result.status;
  err.code = result.status;
  err.cmd = result.cmd || '';
  err.stdout = result.stdout || '';
  err.stderr = result.stderr || '';
  err.signal = null;
  if (result.status < 0) {
    err.signal = 'SIGKILL';
  }
  err.pid = result.pid || 0;
  err.killed = result.error === 'Command timed out';
  return err;
}

function _makeIpcError(code, message) {
  var err = new Error(message);
  err.code = code;
  return err;
}

function _finalizeSentSocketEntry(entry) {
  if (!entry) return;
  var nativeHandle = entry.nativeHandle;
  if (nativeHandle != null && typeof globalThis.__exactTcpClose === 'function') {
    try { globalThis.__exactTcpClose(nativeHandle); } catch (e) { /* ignored: best-effort close; native handle may already be released */ }
  }
  // Only decrement _connections on the actual server object, not the
  // wrapper entry.  entry.server is null when the sent socket had no
  // associated server (plain net.Socket without _server).
  var server = entry.server;
  if (server && typeof server._connections === 'number') {
    server._connections--;
    if (server._connections < 0) server._connections = 0;
    if (server._closing && server._connections === 0) {
      if (typeof server.emit === 'function') {
        server.emit('close');
      }
    }
  }
}

function _flushSentSocketEntries(queue) {
  if (!queue || queue.length === 0) return;
  while (queue.length > 0) {
    _finalizeSentSocketEntry(queue.shift());
  }
}

function _ipcGetBufferCtor() {
  if (typeof Buffer !== 'undefined' && Buffer && typeof Buffer.from === 'function') {
    return Buffer;
  }
  try {
    return require('buffer').Buffer;
  } catch (_) {
    return null;
  }
}

function _ipcBytesToBase64(bytes) {
  var BufferCtor = _ipcGetBufferCtor();
  if (BufferCtor) {
    if (typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(bytes)) {
      return bytes.toString('base64');
    }
    if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
      return BufferCtor.from(new Uint8Array(bytes)).toString('base64');
    }
    if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(bytes)) {
      return BufferCtor.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
    }
    return BufferCtor.from(String(bytes), 'utf8').toString('base64');
  }
  if (typeof btoa === 'function') {
    var array;
    if (typeof ArrayBuffer !== 'undefined' && bytes instanceof ArrayBuffer) {
      array = new Uint8Array(bytes);
    } else if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(bytes)) {
      array = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    } else {
      array = new Uint8Array(0);
    }
    var binary = '';
    for (var i = 0; i < array.length; i++) binary += String.fromCharCode(array[i]);
    return btoa(binary);
  }
  return '';
}

function _ipcBase64ToByteArray(base64) {
  var BufferCtor = _ipcGetBufferCtor();
  if (BufferCtor) {
    var buf = BufferCtor.from(base64 || '', 'base64');
    var out = new Uint8Array(buf.length);
    out.set(buf);
    return out;
  }
  if (typeof atob === 'function') {
    var binary = atob(base64 || '');
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
    return bytes;
  }
  return new Uint8Array(0);
}

function _ipcAdvancedTag(type) {
  return { __exactIpcSerialized: true, type: type };
}

function _ipcEncodeAdvancedValue(value, refs) {
  if (value === undefined) return _ipcAdvancedTag('Undefined');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (value !== value) {
      var nanTag = _ipcAdvancedTag('Number');
      nanTag.value = 'NaN';
      return nanTag;
    }
    if (value === Infinity) {
      var infTag = _ipcAdvancedTag('Number');
      infTag.value = 'Infinity';
      return infTag;
    }
    if (value === -Infinity) {
      var ninfTag = _ipcAdvancedTag('Number');
      ninfTag.value = '-Infinity';
      return ninfTag;
    }
    if (value === 0 && 1 / value === -Infinity) {
      var negZeroTag = _ipcAdvancedTag('Number');
      negZeroTag.value = '-0';
      return negZeroTag;
    }
    return value;
  }
  if (typeof value === 'bigint') {
    var bigIntTag = _ipcAdvancedTag('BigInt');
    bigIntTag.value = String(value);
    return bigIntTag;
  }
  if (typeof value === 'symbol' || typeof value === 'function') {
    var cloneErr = new TypeError('The object could not be cloned.');
    cloneErr.name = 'DataCloneError';
    throw cloneErr;
  }

  for (var refIndex = 0; refIndex < refs.length; refIndex++) {
    if (refs[refIndex] === value) {
      var refTag = _ipcAdvancedTag('Ref');
      refTag.id = refIndex;
      return refTag;
    }
  }

  var id = refs.length;
  refs.push(value);
  var BufferCtor = _ipcGetBufferCtor();

  if (BufferCtor && typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(value)) {
    var bufferTag = _ipcAdvancedTag('Buffer');
    bufferTag.id = id;
    bufferTag.data = value.toString('base64');
    return bufferTag;
  }
  if (typeof Date !== 'undefined' && value instanceof Date) {
    var dateTag = _ipcAdvancedTag('Date');
    dateTag.id = id;
    dateTag.value = value.getTime();
    return dateTag;
  }
  if (typeof RegExp !== 'undefined' && value instanceof RegExp) {
    var regexpTag = _ipcAdvancedTag('RegExp');
    regexpTag.id = id;
    regexpTag.source = value.source;
    regexpTag.flags = value.flags;
    return regexpTag;
  }
  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    var arrayBufferTag = _ipcAdvancedTag('ArrayBuffer');
    arrayBufferTag.id = id;
    arrayBufferTag.data = _ipcBytesToBase64(value);
    return arrayBufferTag;
  }
  if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) {
    var sharedArrayBufferTag = _ipcAdvancedTag('SharedArrayBuffer');
    sharedArrayBufferTag.id = id;
    sharedArrayBufferTag.data = _ipcBytesToBase64(new Uint8Array(value));
    return sharedArrayBufferTag;
  }
  if (typeof DataView !== 'undefined' && value instanceof DataView) {
    var dataViewTag = _ipcAdvancedTag('DataView');
    dataViewTag.id = id;
    dataViewTag.data = _ipcBytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    return dataViewTag;
  }
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var typedArrayTag = _ipcAdvancedTag('TypedArray');
    typedArrayTag.id = id;
    typedArrayTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Uint8Array';
    typedArrayTag.data = _ipcBytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    return typedArrayTag;
  }
  if (typeof Map !== 'undefined' && value instanceof Map) {
    var mapTag = _ipcAdvancedTag('Map');
    mapTag.id = id;
    mapTag.entries = [];
    value.forEach(function(mapValue, mapKey) {
      mapTag.entries.push([
        _ipcEncodeAdvancedValue(mapKey, refs),
        _ipcEncodeAdvancedValue(mapValue, refs)
      ]);
    });
    return mapTag;
  }
  if (typeof Set !== 'undefined' && value instanceof Set) {
    var setTag = _ipcAdvancedTag('Set');
    setTag.id = id;
    setTag.values = [];
    value.forEach(function(setValue) {
      setTag.values.push(_ipcEncodeAdvancedValue(setValue, refs));
    });
    return setTag;
  }
  if (value instanceof Error) {
    var errorTag = _ipcAdvancedTag('Error');
    errorTag.id = id;
    errorTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Error';
    errorTag.name = value.name;
    errorTag.message = value.message;
    if (value.stack !== undefined) errorTag.stack = value.stack;
    if ('cause' in value) errorTag.cause = _ipcEncodeAdvancedValue(value.cause, refs);
    var errorProps = Object.keys(value);
    if (errorProps.length > 0) {
      errorTag.props = {};
      for (var ep = 0; ep < errorProps.length; ep++) {
        var errorKey = errorProps[ep];
        if (errorKey === 'message' || errorKey === 'stack' || errorKey === 'cause' || errorKey === 'name') continue;
        errorTag.props[errorKey] = _ipcEncodeAdvancedValue(value[errorKey], refs);
      }
    }
    return errorTag;
  }
  if (Array.isArray(value)) {
    var arrayTag = _ipcAdvancedTag('Array');
    arrayTag.id = id;
    arrayTag.items = new Array(value.length);
    for (var ai = 0; ai < value.length; ai++) {
      if (Object.prototype.hasOwnProperty.call(value, ai)) {
        arrayTag.items[ai] = _ipcEncodeAdvancedValue(value[ai], refs);
      } else {
        arrayTag.items[ai] = _ipcAdvancedTag('Hole');
      }
    }
    return arrayTag;
  }

  var objectTag = _ipcAdvancedTag('Object');
  objectTag.id = id;
  objectTag.props = {};
  var keys = Object.keys(value);
  for (var ki = 0; ki < keys.length; ki++) {
    var key = keys[ki];
    objectTag.props[key] = _ipcEncodeAdvancedValue(value[key], refs);
  }
  return objectTag;
}

function _ipcDecodeAdvancedValue(value, refs) {
  if (!value || typeof value !== 'object' || value.__exactIpcSerialized !== true) {
    return value;
  }
  var type = value.type;
  if (type === 'Undefined') return undefined;
  if (type === 'Number') {
    if (value.value === 'NaN') return NaN;
    if (value.value === 'Infinity') return Infinity;
    if (value.value === '-Infinity') return -Infinity;
    if (value.value === '-0') return -0;
    return Number(value.value);
  }
  if (type === 'BigInt') {
    return typeof BigInt === 'function' ? BigInt(value.value) : value.value;
  }
  if (type === 'Hole') {
    return value;
  }
  if (type === 'Ref') {
    return refs[value.id];
  }

  var decoded;
  if (type === 'Buffer') {
    var bufferBytes = _ipcBase64ToByteArray(value.data);
    var BufferCtor = _ipcGetBufferCtor();
    decoded = BufferCtor ? BufferCtor.from(bufferBytes) : bufferBytes;
    refs[value.id] = decoded;
    return decoded;
  }
  if (type === 'Date') {
    decoded = new Date(value.value);
    refs[value.id] = decoded;
    return decoded;
  }
  if (type === 'RegExp') {
    decoded = new RegExp(value.source || '', value.flags || '');
    refs[value.id] = decoded;
    return decoded;
  }
  if (type === 'ArrayBuffer' || type === 'SharedArrayBuffer') {
    var bufferData = _ipcBase64ToByteArray(value.data);
    var bufferTarget;
    if (type === 'SharedArrayBuffer' && typeof SharedArrayBuffer === 'function') {
      bufferTarget = new SharedArrayBuffer(bufferData.byteLength);
      new Uint8Array(bufferTarget).set(bufferData);
    } else {
      bufferTarget = new ArrayBuffer(bufferData.byteLength);
      new Uint8Array(bufferTarget).set(bufferData);
    }
    refs[value.id] = bufferTarget;
    return bufferTarget;
  }
  if (type === 'DataView') {
    var dataViewBytes = _ipcBase64ToByteArray(value.data);
    var dataViewBuffer = new ArrayBuffer(dataViewBytes.byteLength);
    new Uint8Array(dataViewBuffer).set(dataViewBytes);
    decoded = new DataView(dataViewBuffer);
    refs[value.id] = decoded;
    return decoded;
  }
  if (type === 'TypedArray') {
    var typedArrayBytes = _ipcBase64ToByteArray(value.data);
    var typedArrayBuffer = new ArrayBuffer(typedArrayBytes.byteLength);
    new Uint8Array(typedArrayBuffer).set(typedArrayBytes);
    var TypedArrayCtor = typeof globalThis !== 'undefined' ? globalThis[value.ctor] : null;
    if (typeof TypedArrayCtor !== 'function') TypedArrayCtor = Uint8Array;
    decoded = new TypedArrayCtor(typedArrayBuffer);
    refs[value.id] = decoded;
    return decoded;
  }
  if (type === 'Map') {
    decoded = new Map();
    refs[value.id] = decoded;
    var mapEntries = value.entries || [];
    for (var me = 0; me < mapEntries.length; me++) {
      decoded.set(
        _ipcDecodeAdvancedValue(mapEntries[me][0], refs),
        _ipcDecodeAdvancedValue(mapEntries[me][1], refs)
      );
    }
    return decoded;
  }
  if (type === 'Set') {
    decoded = new Set();
    refs[value.id] = decoded;
    var setValues = value.values || [];
    for (var sv = 0; sv < setValues.length; sv++) {
      decoded.add(_ipcDecodeAdvancedValue(setValues[sv], refs));
    }
    return decoded;
  }
  if (type === 'Error') {
    var ErrorCtor = typeof globalThis !== 'undefined' ? globalThis[value.ctor] : null;
    if (typeof ErrorCtor !== 'function') ErrorCtor = Error;
    try {
      decoded = new ErrorCtor(value.message);
    } catch (_) {
      decoded = new Error(value.message);
    }
    refs[value.id] = decoded;
    if (value.name) decoded.name = value.name;
    if (value.stack !== undefined) decoded.stack = value.stack;
    if (Object.prototype.hasOwnProperty.call(value, 'cause')) {
      decoded.cause = _ipcDecodeAdvancedValue(value.cause, refs);
    }
    if (value.props) {
      var errorPropKeys = Object.keys(value.props);
      for (var ek = 0; ek < errorPropKeys.length; ek++) {
        decoded[errorPropKeys[ek]] = _ipcDecodeAdvancedValue(value.props[errorPropKeys[ek]], refs);
      }
    }
    return decoded;
  }
  if (type === 'Array') {
    decoded = new Array(value.items ? value.items.length : 0);
    refs[value.id] = decoded;
    for (var ai2 = 0; value.items && ai2 < value.items.length; ai2++) {
      if (value.items[ai2] && value.items[ai2].__exactIpcSerialized === true && value.items[ai2].type === 'Hole') {
        continue;
      }
      decoded[ai2] = _ipcDecodeAdvancedValue(value.items[ai2], refs);
    }
    return decoded;
  }
  if (type === 'Object') {
    decoded = {};
    refs[value.id] = decoded;
    var propKeys = value.props ? Object.keys(value.props) : [];
    for (var pk = 0; pk < propKeys.length; pk++) {
      decoded[propKeys[pk]] = _ipcDecodeAdvancedValue(value.props[propKeys[pk]], refs);
    }
    return decoded;
  }
  return value;
}

function _ipcSerializePacketData(data, serializationMode) {
  if (serializationMode === 'advanced') {
    return _ipcEncodeAdvancedValue(data, []);
  }
  return data;
}

function _ipcDeserializePacketData(data, serializationMode) {
  if (serializationMode === 'advanced') {
    return _ipcDecodeAdvancedValue(data, []);
  }
  return data;
}

function _createIpcPacket(type, data, handleType, serializationMode) {
  var pkt = { __exactIpc: true, type: type, data: _ipcSerializePacketData(data, serializationMode) };
  if (handleType) pkt.handleType = handleType;
  if (serializationMode === 'advanced') pkt.serialization = 'advanced';
  return JSON.stringify(pkt) + '\n';
}

// (ENG-23231) Parent→child IPC writes go through a byte-accurate outbound
// queue, mirroring the child-side ENG-23132 fix in ipc-listener.js: the IPC
// socket is non-blocking, so a framed packet larger than the kernel send
// buffer comes back as a partial write. Abandoning the tail would leave a
// headless fragment in the pipe that corrupts the child's newline framing.
// Packets are encoded to bytes up front because the native write primitives
// report BYTE counts, and byte offsets diverge from JS string indices for
// multibyte payloads.
function _ipcPacketToBytes(packet) {
  if (typeof Buffer !== 'undefined' && Buffer && typeof Buffer.from === 'function') {
    return Buffer.from(packet, 'utf8');
  }
  if (typeof TextEncoder === 'function') {
    return new TextEncoder().encode(packet);
  }
  return packet;
}

function _ipcPacketLength(packet) {
  if (!packet) return 0;
  if (typeof packet.byteLength === 'number') return packet.byteLength;
  if (typeof packet.length === 'number') return packet.length;
  return 0;
}

function _ipcPacketSlice(packet, offset) {
  if (!packet || offset <= 0) return packet;
  if (typeof packet.subarray === 'function') return packet.subarray(offset);
  if (typeof packet.slice === 'function') return packet.slice(offset);
  return packet;
}

// Extract a native file descriptor from a handle object (net.Socket, net.Server, dgram.Socket, etc.)
function _extractHandleFd(handle) {
  if (!handle) return -1;
  // dgram.Socket: use _getFd() or __exactUdpGetFd
  if (typeof handle._getFd === 'function') {
    var dgramFd = handle._getFd();
    if (dgramFd >= 0) return dgramFd;
  }
  if (typeof handle._handle === 'number' && handle._handle >= 0 && (handle.type === 'udp4' || handle.type === 'udp6')) {
    if (typeof globalThis.__exactUdpGetFd === 'function') {
      var udpFd = globalThis.__exactUdpGetFd(handle._handle);
      if (udpFd >= 0) return udpFd;
    }
  }
  // Our native handle system: _handle._exactHandle is an ID into the native socket table.
  // Use __exactTcpGetFd to get the raw fd from the handle ID.
  if (handle._handle && typeof handle._handle._exactHandle === 'number' && handle._handle._exactHandle > 0) {
    if (typeof globalThis.__exactTcpGetFd === 'function') {
      var rawFd = globalThis.__exactTcpGetFd(handle._handle._exactHandle);
      if (rawFd >= 0) return rawFd;
    }
  }
  // Direct _exactHandle (e.g., raw server handle passed as { _exactHandle: N, close: fn })
  if (typeof handle._exactHandle === 'number' && handle._exactHandle > 0) {
    if (typeof globalThis.__exactTcpGetFd === 'function') {
      var rawFd = globalThis.__exactTcpGetFd(handle._exactHandle);
      if (rawFd >= 0) return rawFd;
    }
  }
  // net.Socket / net.Server store the fd on _handle.fd or _handle._fd
  if (handle._handle) {
    if (typeof handle._handle.fd === 'number' && handle._handle.fd >= 0) return handle._handle.fd;
    if (typeof handle._handle._fd === 'number' && handle._handle._fd >= 0) return handle._handle._fd;
    // Also check _exactHandle directly for server handles
    if (typeof handle._handle === 'number' && handle._handle > 0) {
      if (typeof globalThis.__exactTcpGetFd === 'function') {
        var rawFd = globalThis.__exactTcpGetFd(handle._handle);
        if (rawFd >= 0) return rawFd;
      }
    }
  }
  // Direct fd
  if (typeof handle.fd === 'number' && handle.fd >= 0) return handle.fd;
  if (typeof handle._fd === 'number' && handle._fd >= 0) return handle._fd;
  // Try to get from the internal socket
  if (handle._socket && handle._socket._handle) {
    if (typeof handle._socket._handle.fd === 'number') return handle._socket._handle.fd;
    if (typeof handle._socket._handle._exactHandle === 'number') {
      if (typeof globalThis.__exactTcpGetFd === 'function') {
        var rawFd = globalThis.__exactTcpGetFd(handle._socket._handle._exactHandle);
        if (rawFd >= 0) return rawFd;
      }
    }
  }
  return -1;
}

function _isServerHandleLike(handle) {
  if (!handle || (typeof handle !== 'object' && typeof handle !== 'function')) return false;
  if (handle._exactServerHandle === true) return true;
  return typeof handle.close === 'function' && typeof handle.onconnection === 'function';
}

// Determine the handle type for IPC serialization
function _getHandleType(handle) {
  if (!handle) return null;
  // Check dgram.Socket first (has _getFd method and type like 'udp4')
  if (handle.type === 'udp4' || handle.type === 'udp6') return 'dgram.Socket';
  if (typeof handle._getFd === 'function' && (handle.type === 'udp4' || handle.type === 'udp6')) return 'dgram.Socket';
  if (_isServerHandleLike(handle)) return 'net.ServerHandle';
  var dgram;
  try { dgram = require('dgram'); } catch (e) { /* ignored: optional dgram module; callers guard for null */ }
  if (dgram && dgram.Socket && handle instanceof dgram.Socket) return 'dgram.Socket';
  var net;
  try { net = require('net'); } catch (e) { return null; }
  if (net.Socket && handle instanceof net.Socket) return 'net.Socket';
  if (net.Server && handle instanceof net.Server) return 'net.Server';
  // Fallback: check constructor name
  var name = handle.constructor && handle.constructor.name;
  if (name === 'Socket' || name === 'TCP') return 'net.Socket';
  if (name === 'Server') return 'net.Server';
  return 'net.Socket'; // default to socket
}

// Reconstruct a handle from a received file descriptor
function _reconstructHandle(handleType, fd) {
  var net;
  try { net = require('net'); } catch (e) { return null; }
  if (handleType === 'net.Socket' || handleType === 'net.Native') {
    // Register the raw fd as a native TCP handle, then wrap it
    if (typeof globalThis.__exactTcpFromFd === 'function') {
      var nativeHandle = globalThis.__exactTcpFromFd(fd);
      return new net.Socket({ _handle: nativeHandle });
    }
    return new net.Socket({ fd: fd, readable: true, writable: true });
  } else if (handleType === 'dgram.Socket' || handleType === 'dgram.Native') {
    var dgram;
    try { dgram = require('dgram'); } catch (e) { return null; }
    var sock = dgram.createSocket('udp4');
    sock._fromFd(fd);
    return sock;
  } else if (handleType === 'net.ServerHandle') {
    if (typeof globalThis.__exactTcpFromFd === 'function') {
      var nativeServerHandle = globalThis.__exactTcpFromFd(fd);
      return {
        _exactServerHandle: true,
        _exactHandle: nativeServerHandle,
        fd: fd,
        onconnection: function() {},
        close: function() {
          try { globalThis.__exactTcpClose(nativeServerHandle); } catch (e) { /* ignored: best-effort close of the passed server handle */ }
        }
      };
    }
    return {
      _exactServerHandle: true,
      fd: fd,
      onconnection: function() {},
      close: function() {
        try {
          if (typeof globalThis.__exactFsClose === 'function') {
            globalThis.__exactFsClose(fd);
          }
        } catch (_) { /* ignored: best-effort close of the passed fd */ }
      }
    };
  } else if (handleType === 'net.Server') {
    // Register the raw fd as a native TCP handle for the server
    if (typeof globalThis.__exactTcpFromFd === 'function') {
      var nativeHandle = globalThis.__exactTcpFromFd(fd);
      var server = net.createServer();
      server._handle = { _exactHandle: nativeHandle, close: function() {
        try { globalThis.__exactTcpClose(nativeHandle); } catch (e) { /* ignored: best-effort close of the passed handle */ }
      }};
      server._handle._exactServerHandle = true;
      server.listening = true;
      server._closing = false;
      try {
        if (typeof globalThis.__exactTcpLocalAddr === 'function') {
          var info = globalThis.__exactTcpLocalAddr(nativeHandle);
          if (info) {
            var addr = JSON.parse(info);
            server._port = addr.port;
            server._host = addr.address;
            server.host = addr.address;
            var familySuffix = (addr.family || 'IPv4').slice(-1);
            server._connectionKey = familySuffix + ':' + addr.address + ':' + addr.port;
          }
        }
      } catch (e) { /* ignored: advisory listen-address bookkeeping */ }
      if (typeof server._startAccepting === 'function') {
        server._startAccepting();
      }
      return server;
    }
    var server = net.createServer();
    server._handle = { fd: fd, _exactServerHandle: true };
    server.listening = true;
    return server;
  }
  return null;
}

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + input.name;
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
}

// Lazy-loaded getSystemErrorName for translating negative exit codes
var _getSystemErrorName = null;
try {
  _getSystemErrorName = require('util').getSystemErrorName;
} catch (e) { /* ignored: optional util.getSystemErrorName; errno stays numeric */ }

// Node.js internal errors override toString() to include the code:
// "TypeError [ERR_INVALID_ARG_TYPE]: message..."
// This is needed because assert.throws(fn, /ERR_.../) tests against String(err)
function _addCodeToString(err) {
  if (err.code) {
    var _origName = err.name || 'Error';
    var _origCode = err.code;
    var _origMsg = err.message || '';
    err.toString = function() { return _origName + ' [' + _origCode + ']: ' + _origMsg; };
  }
  return err;
}

function _throwInvalidArgType(name, expected, actual) {
  var err = new TypeError('The "' + name + '" ' + (name.indexOf('.') !== -1 ? 'property' : 'argument') + ' must be ' + expected + '.' + _invalidArgTypeHelper(actual));
  err.code = 'ERR_INVALID_ARG_TYPE';
  _addCodeToString(err);
  throw err;
}

function _throwOutOfRange(name, range, actual) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + range + '. Received ' + String(actual));
  err.code = 'ERR_OUT_OF_RANGE';
  _addCodeToString(err);
  throw err;
}

function _throwUnknownSignal(signal) {
  var err = new TypeError('Unknown signal: ' + signal);
  err.code = 'ERR_UNKNOWN_SIGNAL';
  _addCodeToString(err);
  throw err;
}

function _makeAbortError(reason) {
  var err = new Error('The operation was aborted');
  err.name = 'AbortError';
  err.code = 'ABORT_ERR';
  if (reason !== undefined) {
    err.cause = reason;
  }
  return err;
}

function _execChunkByteLength(chunk, BufferCtor) {
  if (chunk == null) return 0;
  if (typeof chunk === 'string') {
    return BufferCtor ? BufferCtor.byteLength(chunk, 'utf8') : chunk.length;
  }
  if (BufferCtor && typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(chunk)) {
    return chunk.length;
  }
  if (typeof chunk.byteLength === 'number') {
    return chunk.byteLength;
  }
  var stringChunk = String(chunk);
  return BufferCtor ? BufferCtor.byteLength(stringChunk, 'utf8') : stringChunk.length;
}

function _execChunkToBuffer(chunk, BufferCtor) {
  if (!BufferCtor) return chunk;
  if (typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return BufferCtor.from(chunk, 'utf8');
  }
  if (ArrayBuffer.isView && ArrayBuffer.isView(chunk)) {
    return BufferCtor.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (chunk instanceof ArrayBuffer) {
    return BufferCtor.from(new Uint8Array(chunk));
  }
  return BufferCtor.from(String(chunk), 'utf8');
}

function _execCollectStringOutput(chunks, encoding, BufferCtor) {
  var result = '';
  for (var i = 0; i < chunks.length; i++) {
    var chunk = chunks[i];
    if (typeof chunk === 'string') {
      result += chunk;
    } else if (BufferCtor) {
      result += _execChunkToBuffer(chunk, BufferCtor).toString(encoding);
    } else {
      result += String(chunk);
    }
  }
  return result;
}

function _execCollectBufferOutput(chunks, BufferCtor) {
  if (!BufferCtor) {
    return _execCollectStringOutput(chunks, 'utf8', BufferCtor);
  }
  var buffers = new Array(chunks.length);
  for (var i = 0; i < chunks.length; i++) {
    buffers[i] = _execChunkToBuffer(chunks[i], BufferCtor);
  }
  return BufferCtor.concat(buffers);
}

function _execStringEncoding(encoding, validEncodings) {
  if (encoding === null || encoding === undefined || encoding === 'buffer') {
    return 'utf8';
  }
  if (typeof encoding === 'string' && validEncodings && validEncodings[encoding]) {
    return encoding;
  }
  return 'utf8';
}

function _childProcessBufferCtor() {
  if (typeof Buffer !== 'undefined' && Buffer && typeof Buffer.from === 'function') {
    return Buffer;
  }
  try {
    return require('buffer').Buffer;
  } catch (_) {
    return null;
  }
}

function _validateCredentialOption(name, value) {
  if (value == null) return;
  if (typeof value !== 'number') {
    _throwInvalidArgType(name, 'of type number', value);
  }
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0 || value > 2147483647) {
    _throwInvalidArgType(name, 'of type number', value);
  }
}

function _validateNonNegativeIntegerOption(name, value) {
  if (value == null) return;
  if (typeof value !== 'number') {
    _throwOutOfRange(name, 'a non-negative integer', value);
  }
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
    _throwOutOfRange(name, 'a non-negative integer', value);
  }
}

function _validateNonNegativeNumberOption(name, value) {
  if (value == null) return;
  if (typeof value !== 'number') {
    _throwOutOfRange(name, 'a non-negative number', value);
  }
  if (value !== value || value < 0) {
    _throwOutOfRange(name, 'a non-negative number', value);
  }
}

function _validateSignalOption(signal) {
  if (signal != null) {
    // Duck-type check: AbortSignal has 'aborted' property and 'addEventListener' method
    var isAbortSignal = (typeof signal === 'object' && 'aborted' in signal && typeof signal.addEventListener === 'function');
    if (!isAbortSignal) {
      var sigErr = new TypeError('The "options.signal" property must be an instance of AbortSignal.' + _invalidArgTypeHelper(signal));
      sigErr.code = 'ERR_INVALID_ARG_TYPE';
      _addCodeToString(sigErr);
      throw sigErr;
    }
  }
}

// (ENG-23032/ENG-23316) Signal numbers are platform-specific, and they diverge for the
// common ones: e.g. SIGUSR1 is 30 on Darwin but 10 on Linux, SIGBUS is 10 on
// Darwin but 7 on Linux. Prefer the native/global table introduced for signal
// traps, but merge with the local fallback because that native table
// deliberately omits untrappable SIGKILL/SIGSTOP and child.kill still accepts
// them.
var _signalMapDarwinFallback = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGIOT: 6, SIGBUS: 10, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 30, SIGSEGV: 11,
  SIGUSR2: 31, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGCHLD: 20,
  SIGCONT: 19, SIGSTOP: 17, SIGTSTP: 18, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 16, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
  SIGWINCH: 28, SIGIO: 23, SIGINFO: 29, SIGSYS: 12
};
var _signalMapLinuxFallback = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGIOT: 6, SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11,
  SIGUSR2: 12, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGSTKFLT: 16,
  SIGCHLD: 17, SIGCONT: 18, SIGSTOP: 19, SIGTSTP: 20, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 23, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
  SIGWINCH: 28, SIGIO: 29, SIGPOLL: 29, SIGPWR: 30, SIGSYS: 31
};
var _signalPlatform = (typeof process !== 'undefined' && process.platform) || 'darwin';
function _loadSignalMap() {
  var fallback = (_signalPlatform === 'linux' || _signalPlatform === 'android')
    ? _signalMapLinuxFallback
    : _signalMapDarwinFallback;
  var out = {};
  for (var fk in fallback) out[fk] = fallback[fk];
  var nativeMap = null;
  if (typeof globalThis !== 'undefined' && globalThis.__exactSignalNumbersMap) {
    nativeMap = globalThis.__exactSignalNumbersMap;
  } else if (typeof __exactSignalNumbers === 'function') {
    try { nativeMap = __exactSignalNumbers(); } catch (_) { /* ignored: optional native signal table; the platform fallback map stands */ }
  }
  if (nativeMap) {
    for (var nk in nativeMap) {
      if (typeof nativeMap[nk] === 'number') out[nk] = nativeMap[nk];
    }
  }
  return out;
}
var _signalMap = _loadSignalMap();
var _signalNumbers = {};
// First-wins so aliased numbers resolve to the canonical name Node reports for
// an exit (e.g. signal 6 -> SIGABRT, not SIGIOT).
for (var _sk in _signalMap) {
  if (_signalNumbers[_signalMap[_sk]] === undefined) _signalNumbers[_signalMap[_sk]] = _sk;
}
if (typeof globalThis !== 'undefined') {
  globalThis.__exactSignalNumbersMap = globalThis.__exactSignalNumbersMap || _signalMap;
  globalThis.__exactSignalNamesMap = globalThis.__exactSignalNamesMap || _signalNumbers;
}

function _isValidSignal(signal) {
  if (typeof signal === 'number') {
    return Number.isInteger(signal) && signal > 0 && _signalNumbers[signal] !== undefined;
  }
  if (typeof signal === 'string') {
    var upper = signal.toUpperCase();
    return _signalMap[upper] !== undefined;
  }
  return false;
}

function _validateSpawnSyncInput(options) {
  if (options.input != null) {
    if (typeof options.input !== 'string' && !ArrayBuffer.isView(options.input) && !(options.input instanceof ArrayBuffer)) {
      _throwInvalidArgType('options.input', 'of type string or an instance of Buffer, TypedArray, or DataView', options.input);
    }
  }
}

function _validateSpawnSyncOptions(options) {
  if (options.cwd != null && typeof options.cwd !== 'string') {
    if (!(options.cwd instanceof URL)) {
      _throwInvalidArgType('options.cwd', 'of type string, an instance of URL, or undefined', options.cwd);
    }
  }
  if (options.detached != null && typeof options.detached !== 'boolean') {
    _throwInvalidArgType('options.detached', 'of type boolean or undefined', options.detached);
  }
  _validateCredentialOption('options.uid', options.uid);
  _validateCredentialOption('options.gid', options.gid);
  if (options.shell != null && typeof options.shell !== 'boolean' && typeof options.shell !== 'string') {
    _throwInvalidArgType('options.shell', 'of type boolean or of type string or undefined', options.shell);
  }
  if (options.argv0 != null && typeof options.argv0 !== 'string') {
    _throwInvalidArgType('options.argv0', 'of type string', options.argv0);
  }
  if (options.windowsHide != null && typeof options.windowsHide !== 'boolean') {
    _throwInvalidArgType('options.windowsHide', 'of type boolean or undefined', options.windowsHide);
  }
  if (options.windowsVerbatimArguments != null && typeof options.windowsVerbatimArguments !== 'boolean') {
    _throwInvalidArgType('options.windowsVerbatimArguments', 'of type boolean or undefined', options.windowsVerbatimArguments);
  }
  if (options.timeout != null) {
    _validateNonNegativeIntegerOption('options.timeout', options.timeout);
  }
  if (options.maxBuffer != null) {
    _validateNonNegativeNumberOption('options.maxBuffer', options.maxBuffer);
  }
  if (options.killSignal != null) {
    if (typeof options.killSignal !== 'string' && typeof options.killSignal !== 'number') {
      _throwInvalidArgType('options.killSignal', 'of type string or of type number or undefined', options.killSignal);
    }
    if (!_isValidSignal(options.killSignal)) {
      _throwUnknownSignal(options.killSignal);
    }
  }
}

  cp.execSync = function execSync(command, options) {
    if (typeof command !== 'string') {
      throw new TypeError('The "command" argument must be of type string');
    }
    _validateNullBytes(command, 'command');
    _validateOptionsNullBytes(options);
    var opts = normalizeExecOptions(options);
    // (ENG-23485) Forward the caller's full options to spawnSync the way
    // Node's normalizeExecArgs does (notably stdio, but also killSignal,
    // argv0, uid/gid, windowsHide, ...). The previous allowlist silently
    // dropped everything it didn't name, so execSync({stdio:'inherit'})
    // captured output instead of streaming it to the terminal.
    var spawnOptions = {};
    if (options && typeof options === 'object') {
      for (var execOptKey in options) {
        if (Object.prototype.hasOwnProperty.call(options, execOptKey)) {
          spawnOptions[execOptKey] = options[execOptKey];
        }
      }
    }
    // Node's normalizeExecArgs: a custom shell string is honored, anything
    // else (including shell:false) still runs the command through the shell.
    spawnOptions.shell = typeof opts.shell === 'string' ? opts.shell : true;
    if (opts.encoding !== undefined) spawnOptions.encoding = opts.encoding;
    // Node contract: unless the caller specifies stdio, the sync exec family
    // passes the captured child stderr through to the parent's stderr so
    // child error output is visible.
    var inheritStderr = !spawnOptions.stdio;
    var result = cp.spawnSync(command, [], spawnOptions);
    if (inheritStderr) _writeInheritedSyncStderr(result.stderr);

    if (result.error) {
      if (result.error.stdout === undefined) result.error.stdout = result.stdout;
      if (result.error.stderr === undefined) result.error.stderr = result.stderr;
      if (result.error.status === undefined) result.error.status = result.status;
      if (result.error.pid === undefined) result.error.pid = result.pid;
      if (result.error.cmd === undefined) result.error.cmd = command;
      throw result.error;
    }

    if (result.status !== 0) {
      throw makeExecError(
        'Command failed: ' + command + (result.stderr ? '\n' + result.stderr : ''),
        {
          status: result.status,
          stdout: result.stdout,
          stderr: result.stderr,
          pid: result.pid,
          cmd: command,
        }
      );
    }

    // (ENG-23485) Node returns null when stdout was not piped (e.g.
    // stdio:'inherit'/'ignore'), for every encoding.
    if (result.stdout == null) return result.stdout;
    var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'buffer';
    if (encoding === 'buffer' || encoding === null) {
      return result.stdout;
    }
    return typeof result.stdout === 'string' ? result.stdout : '';
  };

  // (ENG-23485) Shared "stderr passthrough" for the sync exec family: when the
  // caller did not specify stdio, Node writes the captured child stderr to the
  // parent's stderr after the child completes (see Node's execSync/execFileSync).
  function _writeInheritedSyncStderr(stderr) {
    if (stderr == null || !stderr.length) return;
    if (typeof process === 'undefined' || !process.stderr ||
        typeof process.stderr.write !== 'function') {
      return;
    }
    try {
      process.stderr.write(stderr);
    } catch (err) { _swallowDebug('sync exec stderr passthrough failed', err); }
  }

  // Internal spawnSync that takes a single normalized opts object.
  // This is the function exposed as internal/child_process.spawnSync.
  // The opts object has already-resolved file/args (shell expansion done by caller).
  function _internalSpawnSync(opts) {
    var file = opts.file;
    var args = opts.args || [];
    var nativeOpts = {};
    if (opts.cwd) nativeOpts.cwd = String(opts.cwd);
    if (opts.timeout) nativeOpts.timeout = Number(opts.timeout);
    // (ENG-23008) Hand the caller's real maxBuffer to the native bridge, which
    // enforces it by bytes and kills the child on overflow. Infinity -> 0 means
    // unlimited; an unset maxBuffer omits the key so native uses Node's 1MB
    // default. killSignal (numeric) tells native which signal to send on kill.
    if (opts.maxBuffer === Infinity) {
      nativeOpts.maxBuffer = 0;
    } else if (typeof opts.maxBuffer === 'number' && isFinite(opts.maxBuffer)) {
      nativeOpts.maxBuffer = Math.floor(opts.maxBuffer);
    }
    if (typeof opts.killSignal === 'number' && opts.killSignal > 0) {
      nativeOpts.killSignal = opts.killSignal;
    }
    // (ENG-23485) Credentials for the child. Serialized BEFORE env on purpose:
    // the native side only trusts a "uid"/"gid" key that appears ahead of the
    // env object, so env values can't smuggle credentials into the parse.
    if (typeof opts.uid === 'number' && opts.uid >= 0) nativeOpts.uid = Math.floor(opts.uid);
    if (typeof opts.gid === 'number' && opts.gid >= 0) nativeOpts.gid = Math.floor(opts.gid);
    if (opts.encoding !== undefined) nativeOpts.encoding = opts.encoding;
    if (opts.envPairs) {
      var envObj = {};
      for (var ei = 0; ei < opts.envPairs.length; ei++) {
        var pair = opts.envPairs[ei];
        var eqIdx = pair.indexOf('=');
        if (eqIdx !== -1) envObj[pair.slice(0, eqIdx)] = pair.slice(eqIdx + 1);
      }
      nativeOpts.env = envObj;
    } else if (opts.env) {
      nativeOpts.env = _flattenEnv(opts.env);
    }
    if (opts.input !== undefined) nativeOpts.input = opts.input;
    if (opts.inputEncoding !== undefined) nativeOpts.inputEncoding = opts.inputEncoding;
    if (opts.argv0 && typeof opts.argv0 === 'string') nativeOpts.argv0 = opts.argv0;
    // Pass stdio mode to native layer
    if (opts.stdio) {
      if (typeof opts.stdio === 'string') {
        nativeOpts.stdio = opts.stdio;
      } else if (Array.isArray(opts.stdio) && opts.stdio.length > 0) {
        // Check if all stdio modes are the same simple string
        var allSame = true;
        var firstMode = opts.stdio[0];
        if (typeof firstMode === 'string') {
          for (var si = 1; si < Math.min(opts.stdio.length, 3); si++) {
            if (opts.stdio[si] !== firstMode) { allSame = false; break; }
          }
          if (allSame && firstMode.indexOf('fd:') !== 0) {
            nativeOpts.stdio = firstMode;
          } else {
            // Pass as array for mixed modes or fd: redirects
            nativeOpts.stdio = opts.stdio;
          }
        } else {
          nativeOpts.stdio = opts.stdio;
        }
      }
    }
    // Do NOT pass shell to native - file/args are already resolved by the caller

    var argsWithoutFile = args.length > 0 ? args.slice(1) : [];
    var argsJson = JSON.stringify(argsWithoutFile);
    var optsJson = JSON.stringify(nativeOpts);
    var result;
    try {
      var resultJson = globalThis.__exactSpawnSync(file, argsJson, optsJson);
      result = JSON.parse(resultJson);
    } catch (e) {
      result = { error: e.message || 'spawnSync failed', status: null, stdout: '', stderr: '' };
    }
    // (ENG-23009) Native returns stdout/stderr base64-encoded so binary output
    // round-trips exactly; decode to Buffers (byte-accurate) here.
    if (result && result.stdioEncoding === 'base64') {
      var B = _childProcessBufferCtor();
      if (B) {
        result.stdout = B.from(result.stdout || '', 'base64');
        result.stderr = B.from(result.stderr || '', 'base64');
      } else {
        result.stdout = _ipcBase64ToByteArray(result.stdout || '');
        result.stderr = _ipcBase64ToByteArray(result.stderr || '');
      }
    }
    return result;
  }

  cp.spawnSync = function spawnSync(command, args, options) {
    if (typeof command !== 'string') {
      _throwInvalidArgType('file', 'of type string', command);
    }
    _validateNullBytes(command, 'command');
    command = _fallbackSpawnCommand(command);
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  // Coerce args to strings (Node.js does this automatically)
  args = args.map(function(a) { return String(a); });
  _validateArgsNullBytes(args);
  if (options == null) options = {};
  _validateOptionsNullBytes(options);
  _validateSpawnSyncInput(options);
  _validateSpawnSyncOptions(options);

  // Resolve shell option - convert shell:true/string to actual file and args
  var file = command;
  var spawnArgs = [command].concat(args);
  var shellValue = options.shell;
  if (shellValue && args.length > 0 && typeof process !== 'undefined' && typeof process.emitWarning === 'function') {
    process.emitWarning(
      'Passing args to a child process with shell option true can lead to security ' +
      'vulnerabilities, as the arguments are not escaped, only concatenated.',
      'DeprecationWarning', 'DEP0190');
  }
  if (shellValue) {
    var shellBin;
    if (typeof shellValue === 'string') {
      shellBin = shellValue;
    } else {
      // Default shells by platform
      var plat = (typeof process !== 'undefined' && process.platform) || 'darwin';
      if (plat === 'win32') {
        shellBin = process.env.comspec || 'cmd.exe';
      } else if (plat === 'android') {
        shellBin = '/system/bin/sh';
      } else {
        shellBin = '/bin/sh';
      }
    }
    var isCmd = /^(?:.*\\)?cmd(?:\.exe)?$/i.test(shellBin);
    var shellFlags = isCmd ? ['/d', '/s', '/c'] : ['-c'];
    var shellCmd = args.length > 0 ? command + ' ' + args.join(' ') : command;
    var outputCmd = isCmd ? '"' + shellCmd + '"' : shellCmd;
    file = shellBin;
    spawnArgs = [shellBin].concat(shellFlags, [outputCmd]);
  }

  // Resolve killSignal to numeric value
  var killSignal = options.killSignal;
  if (typeof killSignal === 'string') {
    var upper = killSignal.toUpperCase();
    if (_signalMap[upper] === undefined) {
      var sigErr = new TypeError('Unknown signal: ' + killSignal);
      sigErr.code = 'ERR_UNKNOWN_SIGNAL';
      throw sigErr;
    }
    killSignal = _signalMap[upper];
  }

  // (ENG-23485) Node contract: a non-negative numeric stdio entry shares that
  // parent fd with the child (stdio:[0,1,2] === 'inherit'); it is not a mode
  // enum. fd === slot is resolved to 'inherit' HERE, in the trusted builtin
  // layer, so every fd:N that reaches the native bridge is a genuinely
  // foreign fd and stays subject to the LLP 0013 fd-ownership check
  // (ENG-22906). Previously numeric entries were skipped by the native parser
  // and every slot fell back to 'pipe'.
  var syncStdio = options.stdio;
  if (Array.isArray(syncStdio)) {
    var mappedSyncStdio = [];
    for (var ssi = 0; ssi < syncStdio.length; ssi++) {
      var syncEntry = syncStdio[ssi];
      if (typeof syncEntry === 'number' && isFinite(syncEntry) && syncEntry >= 0) {
        var syncFdNum = Math.floor(syncEntry);
        mappedSyncStdio[ssi] = syncFdNum === ssi ? 'inherit' : 'fd:' + syncFdNum;
      } else {
        mappedSyncStdio[ssi] = syncEntry;
      }
    }
    syncStdio = mappedSyncStdio;
  }

  // Build internal opts object
  // Default env to process.env if not specified (Node.js behavior - JS-set env vars must propagate)
  var resolvedEnv = options.env !== undefined ? options.env : (typeof process !== 'undefined' ? process.env : undefined);
  resolvedEnv = _prepareExactChildEnv(command, resolvedEnv, options.argv0);
  var internalOpts = {
    file: file,
    args: spawnArgs,
    cwd: options.cwd ? String(options.cwd) : undefined,
    // (ENG-23485) uid/gid were validated above but never handed to the native
    // bridge, so the child silently ran with the parent's credentials.
    uid: options.uid,
    gid: options.gid,
    env: resolvedEnv ? _flattenEnv(resolvedEnv) : undefined,
    timeout: options.timeout ? Number(options.timeout) : undefined,
    encoding: options.encoding,
    maxBuffer: options.maxBuffer,
    killSignal: killSignal,
    shell: shellValue,
    windowsHide: options.windowsHide !== undefined ? !!options.windowsHide : false,
    windowsVerbatimArguments: shellValue ? !!(/^(?:.*\\)?cmd(?:\.exe)?$/i.test(file)) : !!(options.windowsVerbatimArguments),
    argv0: options.argv0,
    stdio: syncStdio,
  };

  // Pass input. (ENG-23009) Encode as base64 so binary bytes reach the child's
  // stdin exactly (a string char >= 0x80 would be UTF-8 re-encoded through the
  // JSON boundary otherwise); the native side base64-decodes before writing.
  if (options.input != null) {
    var _inB = _childProcessBufferCtor();
    var _inputBuf = null;
    if (_inB) {
      if (typeof _inB.isBuffer === 'function' && _inB.isBuffer(options.input)) {
        _inputBuf = options.input;
      } else if (typeof options.input === 'string') {
        _inputBuf = _inB.from(options.input, 'utf8');
      } else if (ArrayBuffer.isView(options.input)) {
        _inputBuf = _inB.from(options.input.buffer, options.input.byteOffset, options.input.byteLength);
      } else if (options.input instanceof ArrayBuffer) {
        _inputBuf = _inB.from(new Uint8Array(options.input));
      }
    }
    if (_inputBuf) {
      internalOpts.input = _inputBuf.toString('base64');
      internalOpts.inputEncoding = 'base64';
    } else if (typeof options.input === 'string') {
      internalOpts.input = options.input;
    }
  }

  // Call internal spawnSync (can be monkey-patched via internal/child_process)
  var _internalFn = _internalSpawnSync;
  try {
    var _icp = require('internal/child_process');
    if (_icp && typeof _icp.spawnSync === 'function') _internalFn = _icp.spawnSync;
  } catch (e) { /* ignored: optional internal/child_process; use the builtin spawnSync */ }
  var result = _internalFn(internalOpts);
  if (!result || typeof result !== 'object') {
    result = { stdout: '', stderr: '', status: null, pid: 0 };
  }

  var encoding = (options && options.encoding !== undefined) ? options.encoding : 'buffer';

  var _Buffer = _childProcessBufferCtor();

  // (ENG-23009) result.stdout/stderr arrive as Buffers (byte-accurate) from the
  // native base64 channel. Convert to the requested encoding directly instead of
  // the old string->Buffer('utf8') round-trip that discarded bytes >= 0x80.
  function _decodeSyncOutput(val) {
    if (_Buffer) {
      var buf;
      if (typeof _Buffer.isBuffer === 'function' && _Buffer.isBuffer(val)) buf = val;
      else if (val == null) buf = _Buffer.alloc(0);
      else if (typeof val === 'string') buf = _Buffer.from(val, 'utf8');
      else buf = _Buffer.from(val);
      if (encoding === 'buffer' || encoding === null || encoding === undefined) return buf;
      return buf.toString(encoding === 'utf-8' ? 'utf8' : encoding);
    }
    if (encoding === 'buffer' || encoding === null || encoding === undefined) return val;
    return typeof val === 'string' ? val : _toUtf8String(val);
  }

  // (ENG-23485) Node returns null for stdout/stderr slots that were not piped
  // (inherit/ignore/fd passthrough) instead of an empty Buffer/string.
  function _syncSlotIsPipe(index) {
    var v;
    if (typeof syncStdio === 'string') v = syncStdio;
    else if (Array.isArray(syncStdio)) v = syncStdio[index];
    else return true;
    if (v === undefined || v === null || v === 'pipe' || v === 'overlapped') return true;
    if (typeof v === 'string') return false; // inherit / ignore / fd:N
    return true;
  }
  var stdoutOutput = _syncSlotIsPipe(1) ? _decodeSyncOutput(result.stdout) : null;
  var stderrOutput = _syncSlotIsPipe(2) ? _decodeSyncOutput(result.stderr) : null;

  var output = [null, stdoutOutput, stderrOutput];

  var spawnResult = {
    pid: result.pid || 0,
    output: output,
    stdout: stdoutOutput,
    stderr: stderrOutput,
    status: result.status,
    signal: null,
    error: undefined
  };

  // (ENG-23008) maxBuffer is now enforced in the native bridge: it counts BYTES,
  // truncates the captured output to maxBuffer, and kills the child with
  // killSignal the moment the limit is exceeded. Surface that overflow as the
  // ENOBUFS error Node reports (the child kill also sets spawnResult.signal via
  // the negative status handling below). No post-hoc UTF-16 length comparison.
  if (result.maxBufferExceeded && !result.error) {
    var maxBufErr = new Error('spawnSync ' + command + ' ENOBUFS');
    maxBufErr.code = 'ENOBUFS';
    maxBufErr.errno = -55;
    maxBufErr.syscall = 'spawnSync ' + command;
    maxBufErr.spawnargs = args;
    maxBufErr.path = command;
    spawnResult.error = maxBufErr;
  }

  if (!spawnResult.error && result.error) {
    // When shell:true is used and the shell ran (status >= 0), the native
    // "error" is from stderr parsing (e.g. "command not found"), not a real
    // spawn failure. The shell itself ran fine. Skip creating a JS error.
    // Exception: timeout errors are always real.
    var isShellSuccess = (shellValue && typeof result.status === 'number' && result.status >= 0);
    var isTimeoutError = (typeof result.error === 'string' &&
      (result.error.indexOf('timed out') !== -1 || result.error.indexOf('Timed out') !== -1));
    if (!isShellSuccess || isTimeoutError) {
      var spawnErr = _makeNativeSpawnError(
        command,
        result,
        'spawnSync ' + command,
        args
      );
      if (result.code) {
        // Native layer supplied a precise platform/capability error.
      } else if (result.error.indexOf('not found') !== -1 || result.error.indexOf('No such file') !== -1) {
        spawnErr.code = 'ENOENT';
        spawnErr.errno = -2;
      } else if (result.error.indexOf('Permission denied') !== -1 || result.error.indexOf('EACCES') !== -1) {
        spawnErr.code = 'EACCES';
        spawnErr.errno = -13;
      } else if (result.error.indexOf('timed out') !== -1 || result.error.indexOf('Timed out') !== -1) {
        spawnErr.code = 'ETIMEDOUT';
        spawnErr.errno = -60;
      }
      spawnResult.error = spawnErr;
    }
  }
  if (result.signal) {
    spawnResult.signal = result.signal;
    spawnResult.status = null;
  } else if (spawnResult.error && spawnResult.error.code === 'ETIMEDOUT') {
    // For timeouts, use the specified killSignal (default SIGTERM)
    var timeoutSig = options.killSignal;
    if (typeof timeoutSig === 'number') {
      spawnResult.signal = _signalNumbers[timeoutSig] || 'SIGTERM';
    } else if (typeof timeoutSig === 'string') {
      spawnResult.signal = timeoutSig.toUpperCase();
    } else {
      spawnResult.signal = 'SIGTERM';
    }
    spawnResult.status = null;
  } else if (result.status < 0) {
    // Negative status means killed by signal
    var sigNum = Math.abs(result.status);
    spawnResult.signal = _signalNumbers[sigNum] || 'SIGKILL';
    spawnResult.status = null;
  }

  return spawnResult;
};

cp.execFileSync = function execFileSync(file, args, options) {
  if (typeof file !== 'string') {
    _throwInvalidArgType('file', 'of type string', file);
  }
  _validateNullBytes(file, 'file');
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  // (ENG-23485) Node contract: unless the caller specifies stdio, the sync
  // exec family passes the captured child stderr through to the parent.
  var inheritStderr = !(options && typeof options === 'object' && options.stdio);
  var result = cp.spawnSync(file, args, options);
  if (inheritStderr) _writeInheritedSyncStderr(result.stderr);

  if (result.error) {
    // Attach stdout/stderr to the error object (Node compat)
    if (result.error.stdout === undefined) result.error.stdout = result.stdout;
    if (result.error.stderr === undefined) result.error.stderr = result.stderr;
    if (result.error.status === undefined) result.error.status = result.status;
    if (result.error.pid === undefined) result.error.pid = result.pid;
    throw result.error;
  }

  if (result.status !== 0) {
    var err = makeExecError(
      'Command failed: ' + file + ' ' + args.join(' '),
      { status: result.status, stdout: result.stdout, stderr: result.stderr, pid: result.pid }
    );
    throw err;
  }

  // (ENG-23485) Node returns null when stdout was not piped.
  if (result.stdout == null) return result.stdout;
  var opts = normalizeExecOptions(options);
  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'buffer';
  if (encoding === 'buffer' || encoding === null) {
    return result.stdout;
  }
  return typeof result.stdout === 'string' ? result.stdout : '';
};

cp.exec = function exec(command, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (!options) options = {};
  _validateNullBytes(command, 'command');
  _validateOptionsNullBytes(options);
  var opts = normalizeExecOptions(options);
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  var encoding = (options && 'encoding' in options) ? options.encoding : 'utf8';
  var _validEncodings = { utf8: 1, utf16le: 1, latin1: 1, ascii: 1, base64: 1, hex: 1, ucs2: 1, binary: 1, 'utf-8': 1 };
  var useBuffer = !encoding || encoding === 'buffer' || !_validEncodings[encoding];
  var stringEncoding = _execStringEncoding(encoding, _validEncodings);
  var killSignal = options.killSignal || 'SIGTERM';
  // Validate signal option early (before spawn) so sync throw propagates
  if (options.signal != null) {
    _validateSignalOption(options.signal);
  }
  var child = cp.spawn(command, [], {
    shell: opts.shell !== undefined ? opts.shell : true,
    cwd: opts.cwd,
    env: opts.env
  });
  child._cmd = command;
  // Set encoding on stdout/stderr so data events emit strings (Node.js exec behavior)
  var stdoutChunks = [];
  var stderrChunks = [];
  var stdoutLen = 0;
  var stderrLen = 0;
  var killed = false;
  var exited = false;
  var timeoutId = null;
  var maxBufferExceeded = null; // track which stream exceeded maxBuffer

  if (!useBuffer) {
    if (child.stdout && typeof child.stdout.setEncoding === 'function') {
      child.stdout.setEncoding(stringEncoding);
    }
    if (child.stderr && typeof child.stderr.setEncoding === 'function') {
      child.stderr.setEncoding(stringEncoding);
    }
  }

  function exitHandler(code, signal) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    var stdoutStr = _execCollectStringOutput(stdoutChunks, stringEncoding, _BufferRef);
    var stderrStr = _execCollectStringOutput(stderrChunks, stringEncoding, _BufferRef);
    // Compute output with proper truncation
    var stdout, stderr;
    if (useBuffer && _BufferRef) {
      // Buffer mode (encoding is null or 'buffer')
      var stdoutHasEnc = child.stdout && child.stdout.readableEncoding;
      var stderrHasEnc = child.stderr && child.stderr.readableEncoding;
      if (stdoutHasEnc) {
        // setEncoding was called - return string, truncate by chars
        stdout = (maxBufferExceeded === 'stdout') ? stdoutStr.slice(0, maxBuffer) : stdoutStr;
      } else {
        // No setEncoding - return Buffer, truncate by bytes
        var stdoutBuf = _execCollectBufferOutput(stdoutChunks, _BufferRef);
        stdout = (maxBufferExceeded === 'stdout' && stdoutBuf.length > maxBuffer) ? stdoutBuf.slice(0, maxBuffer) : stdoutBuf;
      }
      if (stderrHasEnc) {
        stderr = (maxBufferExceeded === 'stderr') ? stderrStr.slice(0, maxBuffer) : stderrStr;
      } else {
        var stderrBuf = _execCollectBufferOutput(stderrChunks, _BufferRef);
        stderr = (maxBufferExceeded === 'stderr' && stderrBuf.length > maxBuffer) ? stderrBuf.slice(0, maxBuffer) : stderrBuf;
      }
    } else {
      // String mode - truncate by characters
      if (maxBufferExceeded === 'stdout' && stdoutStr.length > maxBuffer) {
        stdoutStr = stdoutStr.slice(0, maxBuffer);
      }
      if (maxBufferExceeded === 'stderr' && stderrStr.length > maxBuffer) {
        stderrStr = stderrStr.slice(0, maxBuffer);
      }
      stdout = stdoutStr;
      stderr = stderrStr;
    }
    if (_killError) {
      // If kill() threw an error (e.g. monkey-patched kill), report that error
      if (typeof callback === 'function') callback(_killError, stdout, stderr);
    } else if (maxBufferExceeded) {
      var mbErr = new RangeError(maxBufferExceeded + ' maxBuffer length exceeded');
      mbErr.code = 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
      mbErr.cmd = command;
      mbErr.killed = true;
      mbErr.signal = signal || null;
      if (typeof callback === 'function') callback(mbErr, stdout, stderr);
    } else if (code !== 0 || signal || killed) {
      var err = makeExecError(
        'Command failed: ' + command + (stderrStr ? '\n' + stderrStr : ''),
        { status: signal ? null : code, stdout: stdout, stderr: stderr, pid: child.pid, cmd: command }
      );
      err.killed = killed || child.killed;
      err.signal = signal || null;
      err.code = signal ? null : (code < 0 ? (_getSystemErrorName ? _getSystemErrorName(code) : code) : code);
      if (typeof callback === 'function') callback(err, stdout, stderr);
    } else {
      if (typeof callback === 'function') callback(null, stdout, stderr);
    }
  }

  var _BufferRef = typeof Buffer !== 'undefined' ? Buffer : null;
  var _killError = null;
  if (child.stdout) {
    child.stdout.on('data', function(chunk) {
      stdoutChunks.push(chunk);
      // Always count bytes for maxBuffer (Node.js behavior)
      stdoutLen += _execChunkByteLength(chunk, _BufferRef);
      if (stdoutLen > maxBuffer) {
        if (!maxBufferExceeded) maxBufferExceeded = 'stdout';
        killed = true;
        try { child.kill(killSignal); } catch (e) { _killError = e; }
      }
    });
  }
  if (child.stderr) {
    child.stderr.on('data', function(chunk) {
      stderrChunks.push(chunk);
      stderrLen += _execChunkByteLength(chunk, _BufferRef);
      if (stderrLen > maxBuffer) {
        if (!maxBufferExceeded) maxBufferExceeded = 'stderr';
        killed = true;
        try { child.kill(killSignal); } catch (e) { _killError = e; }
      }
    });
  }

  child.on('close', exitHandler);
  child.on('error', function(err) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    if (typeof callback === 'function') callback(err, '', '');
  });

  if (opts.timeout && opts.timeout > 0) {
    timeoutId = setTimeout(function() {
      killed = true;
      child.kill(killSignal);
    }, opts.timeout);
  }

  // Handle AbortController signal
  if (options.signal) {
    _validateSignalOption(options.signal);
    var execSig = options.signal;
    var _execDoAbort = function() {
      if (!exited) {
        killed = true;
        child.kill(killSignal);
        var abortErr = _makeAbortError(execSig.reason);
        if (typeof callback === 'function') {
          exited = true;
          if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
          callback(abortErr);
        }
      }
    };
    if (execSig.aborted) {
      process.nextTick(_execDoAbort);
    } else {
      execSig.addEventListener('abort', _execDoAbort, { once: true });
      child.on('close', function() {
        execSig.removeEventListener('abort', _execDoAbort);
      });
    }
  }

  return child;
};

// Custom promisify for exec - returns promise with .child property
var _kCustomPromisify = Symbol.for('nodejs.util.promisify.custom');
cp.exec[_kCustomPromisify] = function execPromisified(command, options) {
  var resolve, reject;
  var promise = new Promise(function(res, rej) { resolve = res; reject = rej; });
  var child = cp.exec(command, options, function(err, stdout, stderr) {
    if (err) {
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    } else {
      resolve({ stdout: stdout, stderr: stderr });
    }
  });
  promise.child = child;
  return promise;
};

cp.execFile = function execFile(file, args, options, callback) {
  // Flexible argument parsing: execFile(file [,args] [,options] [,callback])
  if (typeof args === 'function') {
    callback = args;
    args = null;
    options = null;
  } else if (typeof args === 'object' && args !== null && !Array.isArray(args)) {
    // args is actually options
    if (typeof options === 'function') {
      callback = options;
    } else if (typeof options === 'string') {
      _throwInvalidArgType('args', 'an instance of Array or undefined', args);
    } else {
      callback = options;
    }
    options = args;
    args = null;
  } else if (args !== null && args !== undefined && !Array.isArray(args)) {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  } else {
    if (typeof options === 'function') {
      callback = options;
      options = null;
    } else if (typeof options === 'string') {
      _throwInvalidArgType('options', 'of type object or undefined', options);
    } else if (Array.isArray(options)) {
      _throwInvalidArgType('options', 'of type object or undefined', options);
    }
  }
  // Validate callback if 4th arg was provided as string
  if (callback !== null && callback !== undefined && typeof callback !== 'function') {
    if (typeof callback === 'string') {
      _throwInvalidArgType('callback', 'of type function or undefined', callback);
    }
  }
  if (!args) args = [];
  if (!options) options = {};
  _validateNullBytes(file, 'file');
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  var opts = normalizeExecOptions(options);
  var maxBuffer = (options && options.maxBuffer !== undefined) ? options.maxBuffer : 1024 * 1024;
  var encoding = (options && 'encoding' in options) ? options.encoding : 'utf8';
  var _validEncodings2 = { utf8: 1, utf16le: 1, latin1: 1, ascii: 1, base64: 1, hex: 1, ucs2: 1, binary: 1, 'utf-8': 1 };
  var useBuffer = !encoding || encoding === 'buffer' || !_validEncodings2[encoding];
  var stringEncoding = _execStringEncoding(encoding, _validEncodings2);
  var killSignal = options.killSignal || 'SIGTERM';
  // Validate signal option early (before spawn) so sync throw propagates
  if (options.signal != null) {
    _validateSignalOption(options.signal);
  }
  var child = cp.spawn(file, args, {
    shell: options.shell || false,
    cwd: opts.cwd,
    env: opts.env,
    windowsHide: options.windowsHide === true
  });
  child._cmd = file + ' ' + args.join(' ');
  var stdoutChunks = [];
  var stderrChunks = [];
  var stdoutLen = 0;
  var stderrLen = 0;
  var killed = false;
  var exited = false;
  var timeoutId = null;
  var maxBufferExceeded = null;

  if (!useBuffer) {
    if (child.stdout && typeof child.stdout.setEncoding === 'function') {
      child.stdout.setEncoding(stringEncoding);
    }
    if (child.stderr && typeof child.stderr.setEncoding === 'function') {
      child.stderr.setEncoding(stringEncoding);
    }
  }

  function exitHandler(code, signal) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    var stdoutStr = _execCollectStringOutput(stdoutChunks, stringEncoding, _BufferRefEF);
    var stderrStr = _execCollectStringOutput(stderrChunks, stringEncoding, _BufferRefEF);
    // Compute output with proper truncation
    var stdout, stderr;
    if (useBuffer && _BufferRefEF) {
      var stdoutHasEnc = child.stdout && child.stdout.readableEncoding;
      var stderrHasEnc = child.stderr && child.stderr.readableEncoding;
      if (stdoutHasEnc) {
        stdout = (maxBufferExceeded === 'stdout') ? stdoutStr.slice(0, maxBuffer) : stdoutStr;
      } else {
        var stdoutBuf = _execCollectBufferOutput(stdoutChunks, _BufferRefEF);
        stdout = (maxBufferExceeded === 'stdout' && stdoutBuf.length > maxBuffer) ? stdoutBuf.slice(0, maxBuffer) : stdoutBuf;
      }
      if (stderrHasEnc) {
        stderr = (maxBufferExceeded === 'stderr') ? stderrStr.slice(0, maxBuffer) : stderrStr;
      } else {
        var stderrBuf = _execCollectBufferOutput(stderrChunks, _BufferRefEF);
        stderr = (maxBufferExceeded === 'stderr' && stderrBuf.length > maxBuffer) ? stderrBuf.slice(0, maxBuffer) : stderrBuf;
      }
    } else {
      if (maxBufferExceeded === 'stdout' && stdoutStr.length > maxBuffer) {
        stdoutStr = stdoutStr.slice(0, maxBuffer);
      }
      if (maxBufferExceeded === 'stderr' && stderrStr.length > maxBuffer) {
        stderrStr = stderrStr.slice(0, maxBuffer);
      }
      stdout = stdoutStr;
      stderr = stderrStr;
    }
    if (maxBufferExceeded) {
      var mbErr = new RangeError(maxBufferExceeded + ' maxBuffer length exceeded');
      mbErr.code = 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
      mbErr.cmd = file + (args.length ? ' ' + args.join(' ') : '');
      mbErr.killed = true;
      mbErr.signal = signal || null;
      if (typeof callback === 'function') callback(mbErr, stdout, stderr);
    } else if (code !== 0 || signal || killed) {
      var err = makeExecError(
        'Command failed: ' + file + (args.length ? ' ' + args.join(' ') : '') + (stderrStr ? '\n' + stderrStr : ''),
        { status: signal ? null : code, stdout: stdout, stderr: stderr, pid: child.pid, cmd: file + (args.length ? ' ' + args.join(' ') : '') }
      );
      err.killed = killed || child.killed;
      err.signal = signal || null;
      err.code = signal ? null : (code < 0 ? (_getSystemErrorName ? _getSystemErrorName(code) : code) : code);
      if (typeof callback === 'function') callback(err, stdout, stderr);
    } else {
      if (typeof callback === 'function') callback(null, stdout, stderr);
    }
  }

  var _BufferRefEF = typeof Buffer !== 'undefined' ? Buffer : null;
  if (child.stdout) {
    child.stdout.on('data', function(chunk) {
      stdoutChunks.push(chunk);
      // Always count bytes for maxBuffer (Node.js behavior)
      stdoutLen += _execChunkByteLength(chunk, _BufferRefEF);
      if (stdoutLen > maxBuffer) {
        if (!maxBufferExceeded) maxBufferExceeded = 'stdout';
        killed = true;
        child.kill(killSignal);
      }
    });
  }
  if (child.stderr) {
    child.stderr.on('data', function(chunk) {
      stderrChunks.push(chunk);
      stderrLen += _execChunkByteLength(chunk, _BufferRefEF);
      if (stderrLen > maxBuffer) {
        if (!maxBufferExceeded) maxBufferExceeded = 'stderr';
        killed = true;
        child.kill(killSignal);
      }
    });
  }

  child.on('close', exitHandler);
  child.on('error', function(err) {
    if (exited) return;
    exited = true;
    if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
    if (!err.cmd) err.cmd = file + (args.length ? ' ' + args.join(' ') : '');
    if (typeof callback === 'function') callback(err, '', '');
  });

  if (opts.timeout && opts.timeout > 0) {
    timeoutId = setTimeout(function() {
      killed = true;
      child.kill(killSignal);
    }, opts.timeout);
  }

  // Handle AbortController signal
  if (options.signal) {
    _validateSignalOption(options.signal);
    var execFileSig = options.signal;
    var _execFileDoAbort = function() {
      if (!exited) {
        killed = true;
        child.kill(killSignal);
        var abortErr = _makeAbortError(execFileSig.reason);
        if (typeof callback === 'function') {
          exited = true;
          if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
          callback(abortErr);
        }
      }
    };
    if (execFileSig.aborted) {
      process.nextTick(_execFileDoAbort);
    } else {
      execFileSig.addEventListener('abort', _execFileDoAbort, { once: true });
      child.on('close', function() {
        execFileSig.removeEventListener('abort', _execFileDoAbort);
      });
    }
  }

  return child;
};

// Custom promisify for execFile - returns promise with .child property
cp.execFile[_kCustomPromisify] = function execFilePromisified(file, args, options) {
  // Handle flexible args: execFilePromisified(file [,args] [,options])
  if (args != null && typeof args === 'object' && !Array.isArray(args)) {
    options = args;
    args = null;
  }
  var resolve, reject;
  var promise = new Promise(function(res, rej) { resolve = res; reject = rej; });
  var child = cp.execFile(file, args, options, function(err, stdout, stderr) {
    if (err) {
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    } else {
      resolve({ stdout: stdout, stderr: stderr });
    }
  });
  promise.child = child;
  return promise;
};

function _normalizeSpawnMode(mode, fallbackMode) {
  var normalized = mode === undefined || mode === null ? fallbackMode : mode;
  if (typeof normalized === 'string') {
    if (normalized === 'ignore' || normalized === 'overlapped' || normalized === 'inherit' || normalized === 'pipe' || normalized === 'ipc') {
      return normalized === 'overlapped' ? 'pipe' : normalized;
    }
    // (ENG-23485) Preserve already-normalized fd:N entries so re-normalizing
    // (e.g. fork pre-normalizes, then spawn normalizes again) is idempotent
    // instead of squashing them to 'pipe'.
    if (normalized.indexOf('fd:') === 0) {
      return normalized;
    }
  }
  if (typeof normalized === 'number') {
    // (ENG-23485) Node contract: a non-negative numeric stdio entry shares
    // that parent fd with the child (stdio:[0,1,2] === 'inherit'); it is not
    // a mode enum. The old 0->'ignore'/1->'pipe'/2->'inherit' mapping closed
    // the child's stdin and captured its stdout invisibly. Every number goes
    // through the fd:N passthrough; _normalizeSpawnOptions resolves fd:N at
    // its own slot to 'inherit' after the stdio layout is final.
    return 'fd:' + normalized;
  }
  // Stream/Socket object - extract the raw fd
  if (normalized && typeof normalized === 'object') {
    if (normalized._ownerChildProcess && normalized._exactSpawnStream) {
      if (normalized._exactSpawnStream === 'stdout') {
        normalized._ownerChildProcess._exactSuppressStdoutPump = true;
      } else if (normalized._exactSpawnStream === 'stderr') {
        normalized._ownerChildProcess._exactSuppressStderrPump = true;
      }
    }
    var fd = _extractHandleFd(normalized);
    if (fd >= 0) return 'fd:' + fd;
  }
  return 'pipe';
}

function _isSharedReadableSpawnPipe(stream) {
  return !!(stream &&
    typeof stream === 'object' &&
    stream._ownerChildProcess &&
    stream._exactSpawnStream);
}

function _retainSharedReadablePipe(stream) {
  if (!stream || !stream._ownerChildProcess || !stream._exactSpawnStream) {
    return false;
  }
  stream._exactPipeConsumerCount = (stream._exactPipeConsumerCount || 0) + 1;
  if (stream._exactSpawnStream === 'stdout') {
    stream._ownerChildProcess._exactSuppressStdoutPump = true;
  } else if (stream._exactSpawnStream === 'stderr') {
    stream._ownerChildProcess._exactSuppressStderrPump = true;
  }
  return true;
}

function _releaseSharedReadablePipe(stream) {
  if (!stream || !stream._ownerChildProcess || !stream._exactSpawnStream) {
    return;
  }
  if (stream._exactPipeConsumerCount > 0) {
    stream._exactPipeConsumerCount--;
  }
  if (stream._exactPipeConsumerCount > 0) {
    return;
  }
  if (stream._exactSpawnStream === 'stdout') {
    stream._ownerChildProcess._exactSuppressStdoutPump = false;
  } else if (stream._exactSpawnStream === 'stderr') {
    stream._ownerChildProcess._exactSuppressStderrPump = false;
  }
}

function _trackSharedReadablePipeConsumers(stdio, child) {
  if (!Array.isArray(stdio) || !child || typeof child.on !== 'function') {
    return;
  }
  var tracked = [];
  for (var i = 0; i < stdio.length; i++) {
    if (_retainSharedReadablePipe(stdio[i])) {
      tracked.push(stdio[i]);
    }
  }
  if (tracked.length === 0) {
    return;
  }
  var released = false;
  function releaseTracked() {
    if (released) return;
    released = true;
    for (var ti = 0; ti < tracked.length; ti++) {
      _releaseSharedReadablePipe(tracked[ti]);
    }
  }
  child.on('error', releaseTracked);
  child.on('close', releaseTracked);
}

function _setupSharedReadablePipeRelays(relayReadablePipes, child) {
  if (!relayReadablePipes || !child || child._handle == null || child._handle < 0) {
    return;
  }
  if (typeof globalThis.__exactSpawnRead !== 'function' ||
      typeof globalThis.__exactSpawnWrite !== 'function') {
    return;
  }
  var stops = [];
  function stopAll() {
    for (var i = 0; i < stops.length; i++) {
      try {
        stops[i](false);
      } catch (_stopErr) { _swallowDebug('stdio pump stop callback threw', _stopErr); }
    }
    stops.length = 0;
  }
  child.on('error', stopAll);
  child.on('close', stopAll);

  var slots = Object.keys(relayReadablePipes);
  for (var si = 0; si < slots.length; si++) {
    var stdioIndex = Number(slots[si]);
    var source = relayReadablePipes[slots[si]];
    if (!_isSharedReadableSpawnPipe(source)) {
      continue;
    }
    var targetStream = stdioIndex === 0 ? 'stdin' : (stdioIndex >= 4 ? 'extra:' + (stdioIndex - 4) : null);
    if (!targetStream) {
      continue;
    }

    (function(sourceStream, targetName) {
      var owner = sourceStream._ownerChildProcess;
      var ownerStream = sourceStream._exactSpawnStream;
      var timer = null;
      var stopped = false;

      function stopRelay(closeTarget) {
        if (stopped) return;
        stopped = true;
        if (timer != null) {
          clearTimeout(timer);
          timer = null;
        }
        if (closeTarget &&
            targetName === 'stdin' &&
            typeof globalThis.__exactSpawnCloseStdin === 'function') {
          try {
            globalThis.__exactSpawnCloseStdin(child._handle, 'stdin');
          } catch (_closeErr) { /* ignored: best-effort stdin close; child may already have exited */ }
        }
      }

      function schedule(delay) {
        if (stopped || child._exited) return;
        timer = setTimeout(pumpRelay, delay);
      }

      function pumpRelay() {
        timer = null;
        if (stopped || child._exited) {
          return;
        }
        var data = '';
        try {
          data = globalThis.__exactSpawnRead(owner._handle, ownerStream);
        } catch (_relayReadErr) {
          if (owner._exited) {
            stopRelay(targetName === 'stdin');
          } else {
            schedule(10);
          }
          return;
        }

        if (data && data.length > 0) {
          _writeSpawnStream(child._handle, targetName, data, function(writeErr) {
            if (writeErr) {
              stopRelay(targetName === 'stdin');
              return;
            }
            schedule(0);
          });
          return;
        }

        if (owner._exited) {
          stopRelay(targetName === 'stdin');
          return;
        }
        schedule(10);
      }

      stops.push(stopRelay);
      schedule(0);
    })(source, targetStream);
  }
}

// Flatten env object to include inherited (prototype) properties and filter undefined values.
// Node.js includes prototype properties in env and strips undefined values.
function _flattenEnv(env) {
  if (!env || typeof env !== 'object') return env;
  var flat = {};
  for (var key in env) {
    var val = env[key];
    if (val !== undefined) {
      flat[key] = String(val);
    }
  }
  return flat;
}

function _copyEnvObject(envSource) {
  var env = {};
  if (!envSource || typeof envSource !== 'object') return env;
  for (var key in envSource) {
    var value = envSource[key];
    if (value !== undefined) {
      env[key] = String(value);
    }
  }
  return env;
}

function _shouldPropagateExactExecutable(command) {
  if (typeof command !== 'string' || command.length === 0) return false;
  if (typeof process !== 'object' || process === null) return false;
  if (typeof process.execPath === 'string' && process.execPath && command === process.execPath) {
    return true;
  }
  if (process.env && typeof process.env.EXACT_EXECUTABLE === 'string' &&
      process.env.EXACT_EXECUTABLE && command === process.env.EXACT_EXECUTABLE) {
    return true;
  }
  return false;
}

function _prepareExactChildEnv(command, envSource, argv0, forcedExecPath) {
  var env = _copyEnvObject(envSource);
  if (typeof argv0 === 'string') {
    env.EXACT_RAW_ARGV0 = argv0;
  } else {
    delete env.EXACT_RAW_ARGV0;
  }
  if (typeof forcedExecPath === 'string' && forcedExecPath.length > 0) {
    env.EXACT_EXECUTABLE = forcedExecPath;
  } else if (_shouldPropagateExactExecutable(command)) {
    env.EXACT_EXECUTABLE = command;
  }
  return env;
}

function _isExactCliBooleanExecArg(arg) {
  return arg === '--expose-internals' ||
    arg === '--inspect' ||
    arg === '--inspect-wait' ||
    arg === '--inspect-open' ||
    arg === '--inspect-pause' ||
    arg === '--keep-alive';
}

function _isExactCliValueExecArg(arg) {
  return arg === '--stack-size' ||
    arg === '--max-http-header-size' ||
    arg === '--inspect-port' ||
    arg === '--inspect-host';
}

function _isExactCliAssignmentExecArg(arg) {
  return typeof arg === 'string' && (
    arg.indexOf('--stack-size=') === 0 ||
    arg.indexOf('--max-http-header-size=') === 0 ||
    arg.indexOf('--inspect-port=') === 0 ||
    arg.indexOf('--inspect-host=') === 0
  );
}

function _splitExactExecArgv(execArgv) {
  var cliArgs = [];
  var compatArgs = [];
  for (var i = 0; i < execArgv.length; i++) {
    var arg = String(execArgv[i]);
    if (_isExactCliBooleanExecArg(arg) || _isExactCliAssignmentExecArg(arg)) {
      cliArgs.push(arg);
      continue;
    }
    if (_isExactCliValueExecArg(arg)) {
      cliArgs.push(arg);
      if (i + 1 < execArgv.length) {
        cliArgs.push(String(execArgv[i + 1]));
        i++;
      }
      continue;
    }
    compatArgs.push(arg);
  }
  return { cliArgs: cliArgs, compatArgs: compatArgs };
}

function _normalizeSpawnOptions(options, command) {
  // When no env is specified, use process.env (which may have JS-set values
  // not yet reflected in OS environment). This matches Node.js behavior.
  var envSource = options.env !== undefined ? options.env : (typeof process !== 'undefined' ? process.env : undefined);
  var env = _prepareExactChildEnv(command, envSource, options.argv0);
  var normalized = {
    cwd: options.cwd,
    env: _flattenEnv(env),
    shell: options.shell,
    detached: options.detached,
    // (ENG-23485) carry credentials through; they were validated by the
    // callers but never reached the native spawn bridge.
    uid: typeof options.uid === 'number' ? options.uid : undefined,
    gid: typeof options.gid === 'number' ? options.gid : undefined,
    serialization: options.serialization === 'advanced' ? 'advanced' : 'json'
  };
  var stdio = options.stdio;
  if (typeof stdio === 'string') {
    normalized.stdio = [
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe')
    ];
  } else if (typeof stdio === 'number') {
    normalized.stdio = [
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe'),
      _normalizeSpawnMode(stdio, 'pipe')
    ];
  } else if (Array.isArray(stdio)) {
    var rawStdio = [];
    var relayReadablePipes = null;
    for (var si = 0; si < stdio.length; si++) {
      if (_isSharedReadableSpawnPipe(stdio[si])) {
        rawStdio[si] = 'pipe';
        if (!relayReadablePipes) relayReadablePipes = Object.create(null);
        relayReadablePipes[si] = stdio[si];
      } else {
        rawStdio[si] = _normalizeSpawnMode(stdio[si], 'pipe');
      }
    }
    var ipcIndex = rawStdio.indexOf('ipc');
    if (ipcIndex !== -1) {
      normalized.stdio = ['pipe', 'pipe', 'pipe', 'ipc'];
      var compacted = [];
      var compactedRelay = relayReadablePipes ? [] : null;
      for (var ri = 0; ri < rawStdio.length; ri++) {
        if (rawStdio[ri] === 'ipc') continue;
        compacted.push(rawStdio[ri]);
        if (compactedRelay) {
          compactedRelay.push(relayReadablePipes[ri] || null);
        }
      }
      for (var ci = 0; ci < compacted.length; ci++) {
        var targetIndex = ci < 3 ? ci : ci + 1;
        if (ci < 3) {
          normalized.stdio[ci] = compacted[ci];
        } else {
          normalized.stdio[ci + 1] = compacted[ci];
        }
        if (compactedRelay && compactedRelay[ci]) {
          if (!normalized.relayReadablePipes) normalized.relayReadablePipes = Object.create(null);
          normalized.relayReadablePipes[targetIndex] = compactedRelay[ci];
        }
      }
    } else {
      normalized.stdio = [];
      for (var si2 = 0; si2 < Math.max(stdio.length, 3); si2++) {
        if (relayReadablePipes && relayReadablePipes[si2]) {
          normalized.stdio[si2] = 'pipe';
          if (!normalized.relayReadablePipes) normalized.relayReadablePipes = Object.create(null);
          normalized.relayReadablePipes[si2] = relayReadablePipes[si2];
        } else {
          normalized.stdio[si2] = _normalizeSpawnMode(stdio[si2], 'pipe');
        }
      }
    }
  } else {
    normalized.stdio = ['pipe', 'pipe', 'pipe', 'pipe'];
  }
  // (ENG-23485) fd:N where N equals its FINAL slot is exactly 'inherit'
  // (Node: stdio:[0,1,2] === 'inherit'). Resolve the equivalence here, in the
  // trusted builtin layer and after any ipc compaction settles the layout, so
  // every fd:N that reaches the native bridge is a genuinely foreign fd and
  // stays subject to the LLP 0013 fd-ownership check (ENG-22906: spawn
  // authority does not imply raw fd authority).
  for (var fdSlot = 0; fdSlot < normalized.stdio.length; fdSlot++) {
    if (normalized.stdio[fdSlot] === 'fd:' + fdSlot) {
      normalized.stdio[fdSlot] = 'inherit';
    }
  }
  var ipcFd = normalized.stdio.indexOf('ipc');
  if (ipcFd !== -1) {
    env.EXACT_IPC_FD = String(ipcFd);
    if (normalized.serialization === 'advanced') {
      env.EXACT_IPC_SERIALIZATION = 'advanced';
    } else {
      delete env.EXACT_IPC_SERIALIZATION;
    }
  }
  normalized.env = _flattenEnv(env);
  normalized.windowsHide = options.windowsHide !== undefined ? !!options.windowsHide : false;
  return normalized;
}

function _normalizeForkEnv(optionsEnv) {
  var env = {};
  if (typeof process === 'object' && process !== null && process.env) {
    var processEnv = process.env;
    for (var key in processEnv) {
      if (Object.prototype.hasOwnProperty.call(processEnv, key)) {
        var value = processEnv[key];
        if (value !== undefined) env[key] = String(value);
      }
    }
  }
  if (optionsEnv && typeof optionsEnv === 'object') {
    for (var key in optionsEnv) {
      if (Object.prototype.hasOwnProperty.call(optionsEnv, key)) {
        var v = optionsEnv[key];
        if (v === undefined) {
          delete env[key];
        } else {
          env[key] = String(v);
        }
      }
    }
  }
  return env;
}

// (ENG-23485) One shared decoder instead of a fresh TextDecoder per chunk;
// non-streaming decode holds no state between calls, so reuse is safe.
var _sharedUtf8Decoder = null;
function _toUtf8String(bytes) {
  if (typeof TextDecoder === 'function') {
    try {
      if (_sharedUtf8Decoder === null) _sharedUtf8Decoder = new TextDecoder();
      return _sharedUtf8Decoder.decode(bytes);
    } catch (err) {
      // ignored: fall through to the manual utf8 decode
      _sharedUtf8Decoder = null;
    }
  }
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

// (ENG-23485) Persistent streaming UTF-8 decode for the parent-side IPC
// channel, mirroring the child-side ENG-23132 fix in bootstrap/ipc-listener.js:
// a multibyte sequence split across two poll reads must not decode to U+FFFD
// on each side — that corrupted the reassembled JSON line, JSON.parse failed,
// and the packet was silently dropped. '\n' framing is unaffected because a
// newline byte never appears inside a multibyte UTF-8 sequence. One decoder
// per IPC channel so partial tails are never shared between children.
function _makeIpcChunkDecoder() {
  var streamDecoder = null;
  return function _decodeIpcChunk(rawData) {
    if (rawData == null) return '';
    if (typeof rawData === 'string') return rawData;
    if (typeof TextDecoder === 'function' && typeof Uint8Array === 'function' &&
        rawData instanceof Uint8Array) {
      try {
        if (streamDecoder === null) streamDecoder = new TextDecoder('utf-8');
        return streamDecoder.decode(rawData, { stream: true });
      } catch (err) {
        streamDecoder = null;
        _swallowDebug('streaming IPC decode failed; falling back', err);
      }
    }
    return _toUtf8String(rawData);
  };
}

function _toUint8String(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  var str = '';
  var i = 0;
  var len = value.length || 0;
  for (; i < len; i++) {
    var ch = value[i];
    if (typeof ch === 'number') str += String.fromCharCode(ch & 0xff);
    else if (typeof ch === 'string') str += ch;
  }
  return str;
}

// (ENG-23009) Convert raw bytes coming back from the native spawn bridge (now a
// Uint8Array) into a Buffer before pushing to a Readable, so bytes are not
// re-encoded as UTF-8 by the stream layer. Falls back to string handling if the
// native side ever returns a legacy string.
function _bytesToBuffer(value) {
  var B = _childProcessBufferCtor();
  if (B) {
    if (typeof B.isBuffer === 'function' && B.isBuffer(value)) return value;
    if (typeof value === 'string') return B.from(value, 'utf8');
    return B.from(value);
  }
  return value;
}

// (ENG-23009) Normalize any writable payload (Buffer, string, TypedArray,
// ArrayBuffer, byte array) into a Uint8Array of the exact bytes to hand to the
// byte-accurate native write bridge.
function _toByteArray(data) {
  if (data == null) return new Uint8Array(0);
  var B = _childProcessBufferCtor();
  if (B && typeof B.isBuffer === 'function' && B.isBuffer(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof data === 'string') {
    if (B) {
      var b = B.from(data, 'utf8');
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    }
    var arr = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) arr[i] = data.charCodeAt(i) & 0xff;
    return arr;
  }
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  var len = data.length || 0;
  var out = new Uint8Array(len);
  for (var j = 0; j < len; j++) out[j] = data[j] & 0xff;
  return out;
}

var _spawnWriteChunkSize = 32768;

// Break large stdio writes into smaller async chunks so chained child pipes
// don't deadlock while one stage is blocked on the next stage's pipe buffer.
function _writeSpawnStream(handle, streamName, data, callback) {
  if (typeof callback !== 'function') {
    callback = function() {};
  }
  if (handle == null || handle < 0 || typeof globalThis.__exactSpawnWrite !== 'function') {
    callback(new Error('write failed'));
    return;
  }
  // (ENG-23009) Send raw bytes (Uint8Array) rather than a latin1 string so the
  // native bridge does not UTF-8 re-encode bytes >= 0x80 on the way to the pipe.
  var payload = _toByteArray(data);
  var offset = 0;

  function step() {
    if (offset >= payload.length) {
      callback(null);
      return;
    }
    var nextOffset = offset + _spawnWriteChunkSize;
    var chunk = payload.subarray(offset, nextOffset);
    var written = 0;
    try {
      written = globalThis.__exactSpawnWrite(handle, chunk, streamName);
    } catch (err) {
      callback(err);
      return;
    }
    if (written === true) {
      written = chunk.length;
    } else if (written === false || written == null) {
      written = -1;
    }
    if (typeof written !== 'number') {
      written = Number(written);
    }
    if (written < 0 || written !== written) {
      callback(new Error('write failed'));
      return;
    }
    if (written === 0) {
      if (typeof setTimeout === 'function') {
        setTimeout(step, 0);
      } else {
        step();
      }
      return;
    }
    offset += written;
    if (offset >= payload.length) {
      callback(null);
      return;
    }
    if (typeof setTimeout === 'function') {
      setTimeout(step, 0);
    } else {
      step();
    }
  }

  step();
}

// Signal name<->number maps for the async spawn path. Reuse the canonical
// Darwin maps defined above (_signalMap / _signalNumbers) rather than a second,
// divergent copy: the previous literal here used Linux numbering, so on macOS/iOS
// kill('SIGUSR1') sent signal 10 (= SIGBUS, killing the child) and the reverse
// map misreported exit signals. It was also truncated to 15 entries, throwing
// ERR_UNKNOWN_SIGNAL for signals Node accepts (SIGCHLD, SIGCONT, SIGSTOP, ...).
var signalMap = _signalMap;
var signalNames = _signalNumbers;
if (typeof globalThis.__exactSpawnProcesses !== 'object') {
  globalThis.__exactSpawnProcesses = Object.create(null);
}
if (typeof globalThis.__exactSpawnPump !== 'function') {
  globalThis.__exactSpawnPump = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    var proc = globalThis.__exactSpawnProcesses[String(handle)];
    if (!proc) return;
    if (typeof proc.__pumpFromNative === 'function') {
      proc.__pumpFromNative();
    }
  };
}
if (typeof globalThis.__exactSpawnDispose !== 'function') {
  globalThis.__exactSpawnDispose = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    delete globalThis.__exactSpawnProcesses[String(handle)];
  };
}

// (ENG-23032) Idle backoff for the stdout/stderr/exit poller. Without a native
// readiness callback (__exactSpawnPump is a stub) each live child re-polled
// every 2ms for its whole lifetime — ~3 JSI host calls + 2 read() syscalls,
// ~500x/s per child, even when idle, where Node/kqueue is ~0 CPU. Poll fast
// (0ms) immediately after activity, then grow the idle interval geometrically
// up to a cap so an idle child costs little while staying responsive the moment
// bytes flow or it exits.
var _SPAWN_POLL_MIN_MS = 2;
var _SPAWN_POLL_MAX_MS = 32;
function _nextSpawnPollDelay(proc, hadActivity) {
  if (hadActivity) {
    proc._pollBackoff = _SPAWN_POLL_MIN_MS;
    return 0;
  }
  var cur = proc._pollBackoff || _SPAWN_POLL_MIN_MS;
  proc._pollBackoff = Math.min(cur * 2, _SPAWN_POLL_MAX_MS);
  return cur;
}

// Validation helpers
function _validateNullBytes(value, name) {
  if (typeof value === 'string' && value.indexOf('\0') !== -1) {
    var err = new TypeError('The value of "' + name + '" is invalid. Received ' + JSON.stringify(value));
    err.code = 'ERR_INVALID_ARG_VALUE';
    _addCodeToString(err);
    throw err;
  }
}

function _validateArgsNullBytes(args) {
  if (Array.isArray(args)) {
    for (var i = 0; i < args.length; i++) {
      _validateNullBytes(args[i], 'options.args[' + i + ']');
    }
  }
}

function _validateOptionsNullBytes(options) {
  if (!options) return;
  if (typeof options.cwd === 'string') _validateNullBytes(options.cwd, 'options.cwd');
  if (typeof options.argv0 === 'string') _validateNullBytes(options.argv0, 'options.argv0');
  if (typeof options.shell === 'string') _validateNullBytes(options.shell, 'options.shell');
  if (typeof options.execPath === 'string') _validateNullBytes(options.execPath, 'options.execPath');
  if (Array.isArray(options.execArgv)) {
    for (var i = 0; i < options.execArgv.length; i++) {
      _validateNullBytes(options.execArgv[i], 'options.execArgv[' + i + ']');
    }
  }
  if (options.env && typeof options.env === 'object') {
    var keys = Object.keys(options.env);
    for (var j = 0; j < keys.length; j++) {
      _validateNullBytes(keys[j], 'options.env');
      _validateNullBytes(String(options.env[keys[j]]), 'options.env[\'' + keys[j] + '\']');
    }
  }
}

function _makeSpawnError(command, code, errno, syscall) {
  var msg = syscall + ' ' + code;
  var err = new Error(msg);
  err.code = code;
  err.errno = errno || 0;
  err.syscall = syscall || 'spawn ' + command;
  err.path = command;
  err.spawnargs = [];
  return err;
}

function _makeNativeSpawnError(command, result, syscall, fallbackArgs) {
  var code = result && result.code;
  if (!code && result && result.error === 'EACCES') {
    code = 'EACCES';
  } else if (!code && result && result.error === 'EPERM') {
    code = 'EPERM';
  } else if (!code) {
    code = 'ENOENT';
  }
  var errno = result && typeof result.errno === 'number'
    ? result.errno
    : code === 'EACCES'
      ? -13
      : code === 'EPERM'
        ? -1
        : -2;
  var err = _makeSpawnError(command, code, errno, syscall || ('spawn ' + command));
  if (result && typeof result.message === 'string' && result.message.length > 0) {
    err.message = result.message;
  } else if (typeof result.error === 'string' && result.error.length > 0 && result.error !== code) {
    err.message = result.error;
  }
  if (fallbackArgs) {
    err.spawnargs = fallbackArgs;
  }
  if (result && result.platform) {
    err.platform = result.platform;
  }
  return err;
}

// ChildProcess constructor (extends EventEmitter)
var _EventEmitter;
try { _EventEmitter = require('events'); } catch(e) {
  _EventEmitter = function() { this._events = {}; };
  _EventEmitter.prototype.on = function(ev, fn) { if (!this._events) this._events = {}; if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
  _EventEmitter.prototype.emit = function(ev) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  _EventEmitter.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
  _EventEmitter.prototype.removeListener = function(ev, fn) { if (!this._events) this._events = {}; var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
  _EventEmitter.prototype.removeAllListeners = function(ev) { if (!this._events) this._events = {}; if (ev) delete this._events[ev]; else this._events = {}; return this; };
}

function ChildProcess(handle, pid, stdioModes) {
  _EventEmitter.call(this);
  if (_EventEmitter.prototype) {
    for (var k in _EventEmitter.prototype) {
      if (!this[k]) this[k] = _EventEmitter.prototype[k];
    }
  }
  this._events = this._events || {};
  this._handle = handle !== undefined ? handle : null;
  this.pid = pid !== undefined ? pid : undefined;
  this.exitCode = null;
  this.signalCode = null;
  this.killed = false;
  this.spawnfile = '';
  this.spawnargs = [];
  this._exitHandled = false;
  this._exited = false;
  this._ref = true;
  this._useNativePump = typeof globalThis.__exactSpawnPump === 'function';
  this._pumpInProgress = false;
  var modes = stdioModes || null;
  if (modes) {
    this._ipcMode = modes.ipc === 'ipc';
  } else {
    this._ipcMode = false;
  }
  this._ipcBuffer = '';
  this._ipcQueueSize = 0;
  this._ipcQueueMax = 2;
  // (ENG-23231) Outbound IPC byte queue: entries are framed packets encoded
  // to bytes, drained head-first so partial writes resume at their offset.
  this._ipcSendQueue = [];
  this._ipcFlushTimer = null;
  this._disconnectPending = false;
  this._disconnectEmitted = false;
  this._closeCallback = null;
  this._serialization = 'json';
  this.connected = this._ipcMode;
  this.channel = this._ipcMode ? { fd: 3, connected: true } : null;
  this.stdin = null;
  this.stdout = null;
  this.stderr = null;
  this.stdio = [null, null, null];

  // Only set up streams if modes were provided (i.e., actual spawn, not bare constructor)
  if (!modes) return;

  // Create stdout as a Readable stream
  var Stream = require('stream');
  var self = this;

  if (modes.stdout === 'pipe') {
    this.stdout = new Stream.Readable();
    this.stdout._read = function() {};
    this.stdout._handle = { readStart: function() {}, readStop: function() {} };
    this.stdout._ownerChildProcess = this;
    this.stdout._exactSpawnStream = 'stdout';
  } else {
    this.stdout = null;
  }

  if (modes.stderr === 'pipe') {
    this.stderr = new Stream.Readable();
    this.stderr._read = function() {};
    this.stderr._handle = { readStart: function() {}, readStop: function() {} };
    this.stderr._ownerChildProcess = this;
    this.stderr._exactSpawnStream = 'stderr';
  } else {
    this.stderr = null;
  }

  // Create stdin as a Writable stream
  if (modes.stdin === 'pipe') {
    var _stdinClosed = false;
    var _closeStdinPipe = function() {
      if (_stdinClosed) return;
      _stdinClosed = true;
      if (typeof globalThis.__exactSpawnCloseStdin === 'function' &&
          self._handle !== null && self._handle !== undefined && self._handle >= 0) {
        try { globalThis.__exactSpawnCloseStdin(self._handle, 'stdin'); } catch (e) { /* ignored: best-effort stdin close; child may already have exited */ }
      }
    };
    this.stdin = new Stream.Writable({
      write: function(chunk, encoding, callback) {
        _writeSpawnStream(self._handle, 'stdin', chunk, callback);
      },
      final: function(callback) {
        _closeStdinPipe();
        if (typeof callback === 'function') callback();
      },
      destroy: function(err, callback) {
        _closeStdinPipe();
        if (typeof callback === 'function') callback(err || null);
      }
    });
    this.stdin.readable = false;
  } else {
    // For inherit/ignore modes there is no stdin pipe to close.
    this.stdin = null;
  }

  this.stdio = [this.stdin, this.stdout, this.stderr];

  // Populate raw fd on each stream so they can be passed as stdio to other processes
  if (typeof globalThis.__exactSpawnGetFd === 'function' &&
      this._handle !== null && this._handle !== undefined && this._handle >= 0) {
    try {
      if (this.stdin) this.stdin._fd = globalThis.__exactSpawnGetFd(this._handle, 0);
      if (this.stdout) this.stdout._fd = globalThis.__exactSpawnGetFd(this._handle, 1);
      if (this.stderr) this.stderr._fd = globalThis.__exactSpawnGetFd(this._handle, 2);
    } catch (e) { /* ignored: advisory fd bookkeeping for stdio passing */ }
  }

  if (modes.relayReadablePipes && modes.relayReadablePipes[0]) {
    this.stdin = null;
    this.stdio[0] = null;
  }

  function pushStreamData(kind, value, streamMode) {
    if (!value || !value.length) return;
    if (streamMode === 'pipe') {
      // (ENG-23009) Push a Buffer of the raw bytes; pushing a string here would
      // let the Readable re-encode bytes >= 0x80 as UTF-8 and corrupt binary output.
      if (kind === 'stdout' && self.stdout) self.stdout.push(_bytesToBuffer(value));
      if (kind === 'stderr' && self.stderr) self.stderr.push(_bytesToBuffer(value));
      return;
    }
    if (streamMode === 'inherit') {
      if (kind === 'stdout' && typeof process !== 'undefined' && process.stdout) process.stdout.write(_bytesToBuffer(value));
      if (kind === 'stderr' && typeof process !== 'undefined' && process.stderr && process.stderr.write) process.stderr.write(_bytesToBuffer(value));
    }
  }

  this.stdio = [this.stdin, this.stdout, this.stderr];

  // Create streams for extra stdio entries (index 4+)
  if (modes.extra && modes.extra.length > 0) {
    // IPC occupies slot 3 in stdio, push null for it
    this.stdio.push(this._ipcMode ? null : undefined);
    for (var extraIdx = 0; extraIdx < modes.extra.length; extraIdx++) {
      if (modes.extra[extraIdx] === 'pipe') {
        var extraStream = new Stream.Writable({
          write: function(chunk, encoding, callback) {
            _writeSpawnStream(self._handle, 'extra:' + this._extraIndex, chunk, callback);
          }
        });
        extraStream._extraIndex = extraIdx;
        this.stdio.push(extraStream);
      } else {
        this.stdio.push(null);
      }
    }
  }

  if (self._useNativePump && self._handle >= 0) {
    globalThis.__exactSpawnProcesses[String(self._handle)] = self;
  }

  function emitDisconnect() {
    if (self._disconnectEmitted) {
      return;
    }
    self._disconnectEmitted = true;
    self.connected = false;
    self._ipcMode = false;
    self.channel = null;
    // (ENG-23231) Queued sends can no longer be delivered; resolve their
    // callbacks with ERR_IPC_CHANNEL_CLOSED instead of leaving them pending.
    self._failPendingIpcSends(null);
    // Flush remaining transferred sockets whose close notification will
    // never arrive after the child disconnects/exits.
    _flushSentSocketEntries(self._sentSocketServers);
    if (typeof process !== 'undefined' && self._closeCallback) {
      try {
        self._closeCallback();
      } catch (err) { _swallowDebug('close callback threw', err); }
      self._closeCallback = null;
    }
    if (typeof setTimeout === 'function') {
      setTimeout(function() {
        self.emit('disconnect');
      }, 0);
    } else {
      self.emit('disconnect');
    }
  }

  function closeIpcChannel() {
    if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
      globalThis.__exactSpawnCloseStdin(self._handle, 'ipc');
    }
    emitDisconnect();
  }

  // Pending fd received via SCM_RIGHTS, to be attached to next parsed packet
  var _pendingRecvFd = -1;
  // (ENG-23485) Stateful per-channel decoder: multibyte UTF-8 split across
  // poll reads must not decode to U+FFFD per chunk.
  var _decodeIpcChunk = _makeIpcChunkDecoder();

  function drainIpcPackets(rawData, recvFd) {
    if (typeof recvFd === 'number' && recvFd >= 0) {
      _pendingRecvFd = recvFd;
    }
    if (!rawData || !rawData.length) {
      return;
    }
    var rawStr = _decodeIpcChunk(rawData);
    self._ipcBuffer += rawStr;
    while (self._ipcBuffer.length > 0) {
      var lineEnd = self._ipcBuffer.indexOf('\n');
      if (lineEnd < 0) {
        return;
      }
      var line = self._ipcBuffer.slice(0, lineEnd);
      self._ipcBuffer = self._ipcBuffer.slice(lineEnd + 1);
      if (!line) {
        continue;
      }
      var packet;
      try {
        packet = JSON.parse(line);
      } catch (err) {
        continue;
      }
      if (!packet || packet.__exactIpc !== true) {
        continue;
      }
      if (packet.type === 'message') {
        // Handle internal NODE_SOCKET_CLOSED messages from SocketList protocol
        if (packet.data && packet.data.cmd === 'NODE_SOCKET_CLOSED') {
          if (self._sentSocketServers && self._sentSocketServers.length > 0) {
            _finalizeSentSocketEntry(self._sentSocketServers.shift());
          }
          continue; // Don't emit as regular message
        }
        // Reconstruct handle from received fd if present
        var handle = null;
        if (packet.handleType && _pendingRecvFd >= 0) {
          handle = _reconstructHandle(packet.handleType, _pendingRecvFd);
          _pendingRecvFd = -1;
        }
        var packetData = _ipcDeserializePacketData(packet.data, packet.serialization);
        if (handle) {
          self.emit('message', packetData, handle);
        } else {
          self.emit('message', packetData);
        }
      } else if (packet.type === 'disconnect') {
        closeIpcChannel();
      }
    }
  }

  // Start polling for stdout/stderr, ipc packets and exit status
  var pollInterval = 2; // ms
  var stdoutEnded = false;
  var stderrEnded = false;

  function closeStreams() {
    if (!stdoutEnded) {
      stdoutEnded = true;
      if (self.stdout && self.stdout.push) self.stdout.push(null);
    }
    if (!stderrEnded) {
      stderrEnded = true;
      if (self.stderr && self.stderr.push) self.stderr.push(null);
    }
  }

  function parseSpawnStatus(jsonText) {
    try {
      return JSON.parse(jsonText);
    } catch(e) {
      return { exited: true, exitCode: -1, signal: 0, error: e && e.message ? e.message : 'Invalid spawn status payload' };
    }
  }

  function pollStreams() {
    if (self._pumpInProgress) return;
    if (self._exited && stdoutEnded && stderrEnded) return;
    self._pumpInProgress = true;
    var hadActivity = false;

    // Poll stdout
    if (!stdoutEnded && !self._exactSuppressStdoutPump) {
      var outData = globalThis.__exactSpawnRead(self._handle, 'stdout');
      if (outData && outData.length) hadActivity = true;
      pushStreamData('stdout', outData, modes.stdout);
      if (modes.stdout === 'pipe' && (!outData || !outData.length)) {
        if (self._exited) stdoutEnded = true;
      }
    }

    // Poll stderr
    if (!stderrEnded && !self._exactSuppressStderrPump) {
      var errData = globalThis.__exactSpawnRead(self._handle, 'stderr');
      if (errData && errData.length) hadActivity = true;
      pushStreamData('stderr', errData, modes.stderr);
      if (modes.stderr === 'pipe' && (!errData || !errData.length)) {
        if (self._exited) stderrEnded = true;
      }
    }

    if (self._ipcMode && !self._disconnectPending) {
      // Use recvmsg to receive IPC data + optional SCM_RIGHTS fd
      if (typeof globalThis.__exactSpawnRecvMsg === 'function') {
        var ipcResult = globalThis.__exactSpawnRecvMsg(self._handle);
        if (ipcResult) {
          if (ipcResult.data && ipcResult.data.length) hadActivity = true;
          drainIpcPackets(ipcResult.data, ipcResult.fd);
        }
      } else {
        var ipcData = globalThis.__exactSpawnRead(self._handle, 'ipc');
        if (ipcData && ipcData.length) hadActivity = true;
        drainIpcPackets(ipcData);
      }
    }

    // Poll exit status
    if (!self._exited) {
      var statusJson = globalThis.__exactSpawnPoll(self._handle);
      var status = parseSpawnStatus(statusJson);
      if (status.exited) {
        self._exited = true;
        if (status.error) {
          var statusErr = new Error(status.error);
          self.emit('error', statusErr);
        }

        // Do one final read to drain any remaining data
        if (!self._exactSuppressStdoutPump) {
          var finalOut = globalThis.__exactSpawnRead(self._handle, 'stdout');
          if (finalOut && finalOut.length > 0) {
            pushStreamData('stdout', finalOut, modes.stdout);
          }
        }
        if (!self._exactSuppressStderrPump) {
          var finalErr = globalThis.__exactSpawnRead(self._handle, 'stderr');
          if (finalErr && finalErr.length > 0) {
            pushStreamData('stderr', finalErr, modes.stderr);
          }
        }
        if (self._ipcMode) {
          if (typeof globalThis.__exactSpawnRecvMsg === 'function') {
            var finalIpcResult = globalThis.__exactSpawnRecvMsg(self._handle);
            if (finalIpcResult) drainIpcPackets(finalIpcResult.data, finalIpcResult.fd);
          } else {
            var finalIpc = globalThis.__exactSpawnRead(self._handle, 'ipc');
            drainIpcPackets(finalIpc);
          }
          closeIpcChannel();
        }

        // End the streams
        closeStreams();

        if (self._disconnectEmitted) {
          self.channel = null;
        }
        // Set exit info
        if (status.signal > 0) {
          self.signalCode = signalNames[status.signal] || null;
          self.exitCode = null;
        } else {
          self.exitCode = status.exitCode;
          self.signalCode = null;
        }

        self.emit('exit', self.exitCode, self.signalCode);
        // 'close' fires after streams are done
        setTimeout(function() {
          self.emit('close', self.exitCode, self.signalCode);
          if (globalThis.__exactSpawnProcesses) {
            delete globalThis.__exactSpawnProcesses[String(self._handle)];
          }
          if (typeof globalThis.__exactSpawnDispose === 'function') {
            globalThis.__exactSpawnDispose(self._handle);
          }
        }, 0);
        self._pumpInProgress = false;
        return;
      }
    }

    // (ENG-23032) Record activity so the driver loops below back off when idle.
    self._lastPollActivity = hadActivity;
    if (!self._useNativePump && self._ref) {
      self._pollTimer = setTimeout(pollStreams, _nextSpawnPollDelay(self, hadActivity));
    }
    self._pumpInProgress = false;
  }

  this.__pumpFromNative = pollStreams;

  if (self._useNativePump && self._handle >= 0) {
    var nativePollFallback = function() {
      if (self._exited) {
        return;
      }
      if (typeof self.__pumpFromNative === 'function') {
        self.__pumpFromNative();
      }
      if (!self._exited && self._ref) {
        self._pollTimer = setTimeout(nativePollFallback, _nextSpawnPollDelay(self, self._lastPollActivity));
      }
    };
    // Keep the JS event loop alive until the spawn settles for top-level await cases
    // where no other pending tasks exist.
    if (self._handle >= 0) {
      self._pollTimer = setTimeout(function() {
        if (self._exited) return;
        if (!self._spawnEmitted) { self._spawnEmitted = true; self.emit('spawn'); }
        nativePollFallback();
      }, 0);
    }
  } else {
    // Start polling for stdout/stderr data and exit status.
    var fallbackPoll = function() {
      pollStreams();
      if (!self._exited && self._ref) {
        self._pollTimer = setTimeout(fallbackPoll, _nextSpawnPollDelay(self, self._lastPollActivity));
      }
    };
    if (self._handle >= 0) {
      self._pollTimer = setTimeout(function() {
        if (self._exited) return;
        if (!self._spawnEmitted) { self._spawnEmitted = true; self.emit('spawn'); }
        fallbackPoll();
      }, 0);
    }
  }
}

// spawn() method for ChildProcess - validates options and spawns process
ChildProcess.prototype.spawn = function(options) {
  if (options && options.__exactSpyOnlyHook) {
    return;
  }
  if (options === null || typeof options !== 'object') {
    _throwInvalidArgType('options', 'of type object', options);
  }
  if (options.envPairs !== undefined && !Array.isArray(options.envPairs)) {
    _throwInvalidArgType('options.envPairs', 'an instance of Array', options.envPairs);
  }
  if (options.args !== undefined && !Array.isArray(options.args)) {
    _throwInvalidArgType('options.args', 'an instance of Array', options.args);
  }
  if (typeof options.file !== 'string') {
    _throwInvalidArgType('options.file', 'of type string', options.file);
  }

  // Actually spawn the process
  var command = options.file;
  var args = (options.args || []).map(function(a) { return String(a); });
  var normalizedOptions = _normalizeSpawnOptions(options, command);
  var opts = {};
  if (normalizedOptions.cwd) opts.cwd = String(normalizedOptions.cwd);
  if (normalizedOptions.shell !== undefined) opts.shell = normalizedOptions.shell;
  // (ENG-23485) uid/gid serialized BEFORE env: native only trusts a
  // "uid"/"gid" key ahead of the env object so env values can't smuggle
  // credentials into the substring parse.
  if (normalizedOptions.uid !== undefined) opts.uid = Math.floor(normalizedOptions.uid);
  if (normalizedOptions.gid !== undefined) opts.gid = Math.floor(normalizedOptions.gid);
  if (normalizedOptions.env) opts.env = normalizedOptions.env;
  if (normalizedOptions.detached !== undefined) opts.detached = normalizedOptions.detached;
  opts.windowsHide = normalizedOptions.windowsHide;
  opts.stdio = normalizedOptions.stdio;

  if (typeof process !== 'undefined' && process.platform === 'win32' &&
      normalizedOptions.stdio && normalizedOptions.stdio.indexOf('ipc') !== -1 &&
      typeof globalThis.__exactSpawnRecvMsg !== 'function') {
    throw _makeWin32IpcUnsupportedError(command);
  }

  if (typeof process !== 'undefined' && process.platform === 'win32' &&
      typeof globalThis.__exactSpawn !== 'function' &&
      typeof globalThis.__exactSpawnSync === 'function') {
    return _spawnSyncBackedChildProcess(command, args, options, normalizedOptions);
  }

  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawn(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: 'Failed to initialize spawn' };
  }

  if (result.error) {
    var self = this;
    self.spawnfile = command;
    self.spawnargs = [command].concat(args);
    var spawnErr = _makeNativeSpawnError(
      command,
      result,
      'spawn ' + command,
      self.spawnargs
    );
    spawnErr.spawnargs = self.spawnargs;
    setTimeout(function() {
      self.emit('error', spawnErr);
      self._exited = true;
      self.exitCode = -1;
      self.emit('close', -1, null);
    }, 0);
    return;
  }

  var stdioCfg = {
    stdin: normalizedOptions.stdio[0],
    stdout: normalizedOptions.stdio[1],
    stderr: normalizedOptions.stdio[2],
    ipc: normalizedOptions.stdio[3],
    extra: normalizedOptions.stdio.slice(4)
  };
  this._handle = result.handle;
  this.pid = result.pid;
  this.spawnfile = command;
  this.spawnargs = [command].concat(args);

  // Set up streams now
  this._ipcMode = stdioCfg.ipc === 'ipc';
  this.connected = this._ipcMode;
  this.channel = this._ipcMode ? { fd: 3, connected: true } : null;

  var Stream = require('stream');
  var self2 = this;
  if (stdioCfg.stdout === 'pipe') {
    this.stdout = new Stream.Readable();
    this.stdout._read = function() {};
    this.stdout._handle = { readStart: function() {}, readStop: function() {} };
    this.stdout._ownerChildProcess = this;
    this.stdout._exactSpawnStream = 'stdout';
  }
  if (stdioCfg.stderr === 'pipe') {
    this.stderr = new Stream.Readable();
    this.stderr._read = function() {};
    this.stderr._handle = { readStart: function() {}, readStop: function() {} };
    this.stderr._ownerChildProcess = this;
    this.stderr._exactSpawnStream = 'stderr';
  }
  if (stdioCfg.stdin === 'pipe') {
    var stdinClosed = false;
    function closeSpawnStdin() {
      if (stdinClosed) return;
      stdinClosed = true;
      if (typeof globalThis.__exactSpawnCloseStdin === 'function' &&
          self2._handle !== null && self2._handle !== undefined && self2._handle >= 0) {
        try { globalThis.__exactSpawnCloseStdin(self2._handle, 'stdin'); } catch (e) { /* ignored: best-effort stdin close; child may already have exited */ }
      }
    }
    this.stdin = new Stream.Writable({
      write: function(chunk, encoding, callback) {
        _writeSpawnStream(self2._handle, 'stdin', chunk, callback);
      },
      final: function(callback) {
        closeSpawnStdin();
        if (typeof callback === 'function') callback(null);
      },
      destroy: function(err, callback) {
        closeSpawnStdin();
        if (typeof callback === 'function') callback(err || null);
      }
    });
    this.stdin.readable = false;
  }
  this.stdio = [this.stdin, this.stdout, this.stderr];

  // Create streams for extra stdio entries (index 4+)
  if (stdioCfg.extra && stdioCfg.extra.length > 0) {
    // IPC occupies slot 3 in stdio, so push null for it
    this.stdio.push(this._ipcMode ? null : undefined);
    for (var extraIdx = 0; extraIdx < stdioCfg.extra.length; extraIdx++) {
      if (stdioCfg.extra[extraIdx] === 'pipe') {
        var extraStreamIdx = extraIdx;
        var extraStream = new Stream.Writable({
          write: function(chunk, encoding, callback) {
            _writeSpawnStream(self2._handle, 'extra:' + this._extraIndex, chunk, callback);
          }
        });
        extraStream._extraIndex = extraIdx;
        this.stdio.push(extraStream);
      } else {
        this.stdio.push(null);
      }
    }
  }

  // Populate raw fd on each stream so they can be passed as stdio to other processes
  if (typeof globalThis.__exactSpawnGetFd === 'function') {
    if (this.stdin) this.stdin._fd = globalThis.__exactSpawnGetFd(result.handle, 0);
    if (this.stdout) this.stdout._fd = globalThis.__exactSpawnGetFd(result.handle, 1);
    if (this.stderr) this.stderr._fd = globalThis.__exactSpawnGetFd(result.handle, 2);
    for (var ei = 0; ei < (stdioCfg.extra ? stdioCfg.extra.length : 0); ei++) {
      if (this.stdio[ei + 4]) this.stdio[ei + 4]._fd = globalThis.__exactSpawnGetFd(result.handle, ei + 4);
    }
  }

  // Start polling
  if (!globalThis.__exactSpawnProcesses) globalThis.__exactSpawnProcesses = {};
  globalThis.__exactSpawnProcesses[String(result.handle)] = this;
  var self3 = this;
  self3._exited = false;
  self3._ref = true;
  self3._useNativePump = typeof globalThis.__exactSpawnRead === 'function';
  var pollInterval = 2;

  // Reuse the canonical reverse map so exit-signal reporting covers every signal
  // (the previous 7-entry literal returned null for e.g. SIGBUS/SIGSEGV/SIGUSR1).
  var signalNames2 = _signalNumbers;

  // IPC message handling for prototype.spawn path
  var _ipcBuffer2 = '';
  var _pendingRecvFd2 = -1;
  // (ENG-23485) Stateful per-channel decoder: multibyte UTF-8 split across
  // poll reads must not decode to U+FFFD per chunk.
  var _decodeIpcChunk2 = _makeIpcChunkDecoder();

  function emitDisconnect2() {
    if (self3._disconnectEmitted) return;
    self3._disconnectEmitted = true;
    self3.connected = false;
    self3._ipcMode = false;
    self3.channel = null;
    // (ENG-23231) Same as emitDisconnect: fail undeliverable queued sends.
    self3._failPendingIpcSends(null);
    _flushSentSocketEntries(self3._sentSocketServers);
    if (typeof setTimeout === 'function') {
      setTimeout(function() { self3.emit('disconnect'); }, 0);
    } else {
      self3.emit('disconnect');
    }
  }

  function closeIpcChannel2() {
    if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
      globalThis.__exactSpawnCloseStdin(self3._handle, 'ipc');
    }
    emitDisconnect2();
  }

  function drainIpcPackets2(rawData, recvFd) {
    if (typeof recvFd === 'number' && recvFd >= 0) {
      _pendingRecvFd2 = recvFd;
    }
    if (!rawData || !rawData.length) return;
    var rawStr = _decodeIpcChunk2(rawData);
    _ipcBuffer2 += rawStr;
    while (_ipcBuffer2.length > 0) {
      var lineEnd = _ipcBuffer2.indexOf('\n');
      if (lineEnd < 0) return;
      var line = _ipcBuffer2.slice(0, lineEnd);
      _ipcBuffer2 = _ipcBuffer2.slice(lineEnd + 1);
      if (!line) continue;
      var packet;
      try { packet = JSON.parse(line); } catch (err) { continue; }
      if (!packet || packet.__exactIpc !== true) continue;
      if (packet.type === 'message') {
        if (packet.data && packet.data.cmd === 'NODE_SOCKET_CLOSED') {
          if (self3._sentSocketServers && self3._sentSocketServers.length > 0) {
            _finalizeSentSocketEntry(self3._sentSocketServers.shift());
          }
          continue;
        }
        var handle = null;
        if (packet.handleType && _pendingRecvFd2 >= 0) {
          handle = _reconstructHandle(packet.handleType, _pendingRecvFd2);
          _pendingRecvFd2 = -1;
        }
        var packetData = _ipcDeserializePacketData(packet.data, packet.serialization);
        if (handle) {
          self3.emit('message', packetData, handle);
        } else {
          self3.emit('message', packetData);
        }
      } else if (packet.type === 'disconnect') {
        closeIpcChannel2();
      }
    }
  }

  function closeStreams2() {
    if (self3.stdout && typeof self3.stdout.push === 'function') self3.stdout.push(null);
    if (self3.stderr && typeof self3.stderr.push === 'function') self3.stderr.push(null);
    if (self3.stdin && typeof self3.stdin.end === 'function') self3.stdin.end();
  }

  function parseStatus2(jsonText) {
    if (!jsonText) return { exited: false };
    try { return JSON.parse(jsonText); } catch(e) { return { exited: false }; }
  }

  function pollStreams2() {
    if (self3._exited) return;
    var hadActivity = false;
    // Read stdout
    if (self3.stdout && self3._useNativePump && !self3._exactSuppressStdoutPump) {
      try {
        var out = globalThis.__exactSpawnRead(self3._handle, 1);
        if (out && out.length > 0) {
          hadActivity = true;
          self3.stdout.push(_bytesToBuffer(out)); // (ENG-23009) preserve binary bytes
        }
      } catch (e) { _swallowDebug('stdout pump read failed', e); }
    }
    // Read stderr
    if (self3.stderr && self3._useNativePump && !self3._exactSuppressStderrPump) {
      try {
        var errOut = globalThis.__exactSpawnRead(self3._handle, 2);
        if (errOut && errOut.length > 0) {
          hadActivity = true;
          self3.stderr.push(_bytesToBuffer(errOut)); // (ENG-23009) preserve binary bytes
        }
      } catch (e) { _swallowDebug('stderr pump read failed', e); }
    }
    // Poll IPC messages
    if (self3._ipcMode && !self3._disconnectPending) {
      if (typeof globalThis.__exactSpawnRecvMsg === 'function') {
        var ipcResult = globalThis.__exactSpawnRecvMsg(self3._handle);
        if (ipcResult) {
          if (ipcResult.data && ipcResult.data.length) hadActivity = true;
          drainIpcPackets2(ipcResult.data, ipcResult.fd);
        }
      } else {
        var ipcData = globalThis.__exactSpawnRead(self3._handle, 'ipc');
        if (ipcData && ipcData.length) hadActivity = true;
        drainIpcPackets2(ipcData);
      }
    }
    // Poll exit status
    if (!self3._exited) {
      try {
        var statusJson = globalThis.__exactSpawnPoll(self3._handle);
        var status = parseStatus2(statusJson);
        if (status.exited) {
          self3._exited = true;
          // Do one final read
          if (self3._useNativePump) {
            if (!self3._exactSuppressStdoutPump) {
              try {
                var finalOut = globalThis.__exactSpawnRead(self3._handle, 1);
                if (finalOut && finalOut.length > 0 && self3.stdout) self3.stdout.push(_bytesToBuffer(finalOut));
              } catch (e) { _swallowDebug('final stdout read failed', e); }
            }
            if (!self3._exactSuppressStderrPump) {
              try {
                var finalErr = globalThis.__exactSpawnRead(self3._handle, 2);
                if (finalErr && finalErr.length > 0 && self3.stderr) self3.stderr.push(_bytesToBuffer(finalErr));
              } catch (e) { _swallowDebug('final stderr read failed', e); }
            }
          }
          // Final IPC drain
          if (self3._ipcMode) {
            if (typeof globalThis.__exactSpawnRecvMsg === 'function') {
              var finalIpcResult = globalThis.__exactSpawnRecvMsg(self3._handle);
              if (finalIpcResult) drainIpcPackets2(finalIpcResult.data, finalIpcResult.fd);
            } else {
              var finalIpc = globalThis.__exactSpawnRead(self3._handle, 'ipc');
              drainIpcPackets2(finalIpc);
            }
            closeIpcChannel2();
          }
          closeStreams2();
          if (status.signal > 0) {
            self3.signalCode = signalNames2[status.signal] || null;
            self3.exitCode = null;
          } else {
            self3.exitCode = status.exitCode;
            self3.signalCode = null;
          }
          _flushSentSocketEntries(self3._sentSocketServers);
          self3.emit('exit', self3.exitCode, self3.signalCode);
          setTimeout(function() {
            self3.emit('close', self3.exitCode, self3.signalCode);
            if (globalThis.__exactSpawnProcesses) {
              delete globalThis.__exactSpawnProcesses[String(self3._handle)];
            }
            if (typeof globalThis.__exactSpawnDispose === 'function') {
              globalThis.__exactSpawnDispose(self3._handle);
            }
          }, 0);
          return;
        }
      } catch (e) { _swallowDebug('spawn status poll failed', e); }
    }
    if (!self3._exited && self3._ref) {
      self3._pollTimer = setTimeout(pollStreams2, _nextSpawnPollDelay(self3, hadActivity)); // (ENG-23032) back off when idle
    }
  }

  // (ENG-23485) Expose the pump on this path too: ref() and the global
  // __exactSpawnPump dispatcher both call __pumpFromNative, which was only
  // assigned on the constructor path — ref() after unref() threw here.
  this.__pumpFromNative = pollStreams2;

  setTimeout(function() { self3.emit('spawn'); }, 0);
  self3._pollTimer = setTimeout(pollStreams2, 0);
};

var _childProcessPrototypeSpawnImpl = ChildProcess.prototype.spawn;

// (ENG-23485) win32 has no async native spawn yet: this fallback runs the
// child to completion inside spawnSync (the event loop is blocked for the
// child's whole lifetime; stdin writes and kill() can never reach the live
// child) and then replays its buffered output. Warn once so the blocking
// behavior is visible instead of a silent freeze.
var _win32SyncSpawnWarned = false;

function _makeWin32IpcUnsupportedError(command) {
  var err = new Error(
    "child_process IPC (fork / stdio 'ipc') is not supported on Windows: " +
    'the native async spawn backend does not implement IPC yet');
  err.code = 'ENOTSUP';
  err.syscall = 'spawn ' + command;
  return err;
}

function _spawnSyncBackedChildProcess(command, args, options, normalizedOptions) {
  // IPC can never deliver a message to or from a live child under the
  // sync-backed model (fork/'ipc' stdio would silently drop every message),
  // so fail loudly instead.
  var win32Stdio = normalizedOptions && normalizedOptions.stdio;
  if (win32Stdio && typeof win32Stdio.indexOf === 'function' && win32Stdio.indexOf('ipc') !== -1) {
    throw _makeWin32IpcUnsupportedError(command);
  }
  if (!_win32SyncSpawnWarned && typeof process !== 'undefined' &&
      typeof process.emitWarning === 'function') {
    _win32SyncSpawnWarned = true;
    process.emitWarning(
      'child_process async spawn on Windows is emulated with spawnSync: the ' +
      'event loop blocks until the child exits, and stdin/kill() cannot reach ' +
      'the running child.',
      'ExactWarning');
  }
  var stdioCfg = {
    stdin: normalizedOptions.stdio[0],
    stdout: normalizedOptions.stdio[1],
    stderr: normalizedOptions.stdio[2],
    ipc: normalizedOptions.stdio[3],
    extra: normalizedOptions.stdio.slice(4),
    relayReadablePipes: normalizedOptions.relayReadablePipes || null
  };
  var child = new ChildProcess(-1, undefined, stdioCfg);
  child.spawnfile = command;
  child.spawnargs = [command].concat(args || []);
  child._spawnEmitted = true;
  child._serialization = normalizedOptions.serialization || 'json';
  var result;
  try {
    result = cp.spawnSync(command, args || [], options || {});
  } catch (err) {
    setTimeout(function() {
      child._exited = true;
      child.exitCode = -1;
      child.emit('error', err);
      child.emit('close', null, null);
    }, 0);
    return child;
  }
  child.pid = result.pid;
  var BufferCtor = _childProcessBufferCtor();
  function pushReadable(stream, value) {
    if (!stream || typeof stream.push !== 'function') return;
    if (value !== undefined && value !== null && value !== '') {
      var chunk = value;
      if (BufferCtor && !(BufferCtor.isBuffer && BufferCtor.isBuffer(value))) {
        chunk = BufferCtor.from(String(value));
      }
      stream.push(chunk);
    }
    stream.push(null);
  }
  setTimeout(function() {
    child.emit('spawn');
    pushReadable(child.stdout, result.stdout);
    pushReadable(child.stderr, result.stderr);
    child._exited = true;
    child.exitCode = result.status == null ? -1 : result.status;
    child.signalCode = result.signal || null;
    if (result.error) child.emit('error', result.error);
    child.emit('exit', child.exitCode, child.signalCode);
    child.emit('close', child.exitCode, child.signalCode);
  }, 0);
  return child;
}

ChildProcess.prototype.kill = function(signal) {
  if (this._exited) return false;
  var sig;
  if (signal === undefined || signal === null || signal === 0) {
    sig = signal === 0 ? 0 : 15; // SIGTERM default
  } else if (typeof signal === 'string') {
    if (!signalMap.hasOwnProperty(signal)) {
      var err = new TypeError('Unknown signal: ' + signal);
      err.code = 'ERR_UNKNOWN_SIGNAL';
      _addCodeToString(err);
      throw err;
    }
    sig = signalMap[signal];
  } else if (typeof signal === 'number') {
    sig = signal;
  } else {
    sig = 15; // SIGTERM
  }
  if (this._handle === null || this._handle === undefined || this._handle < 0) return false;
  var ok = globalThis.__exactSpawnKill(this._handle, sig);
  if (ok && sig !== 0) this.killed = true;
  return ok;
};

ChildProcess.prototype.ref = function() {
  this._ref = true;
  if (this._exited || this._pollTimer ||
      this._handle === null || this._handle === undefined || this._handle < 0) {
    return this;
  }
  // (ENG-23485) Restart the actual polling loop, not a single one-shot pump.
  // The old one-shot fired the pump once and left the fired timer id in
  // _pollTimer, so stdout/'exit'/'close' never arrived after unref()+ref()
  // and any later ref() was a no-op. The pump itself may reschedule into
  // _pollTimer (prototype.spawn path); only drive again when it did not.
  var self = this;
  function refDrivePoll() {
    self._pollTimer = null;
    if (self._exited || !self._ref) return;
    if (typeof self.__pumpFromNative === 'function') {
      try {
        self.__pumpFromNative();
      } catch (err) { _swallowDebug('ref() pump failed', err); }
    }
    if (!self._exited && self._ref && !self._pollTimer) {
      self._pollTimer = setTimeout(refDrivePoll, _nextSpawnPollDelay(self, self._lastPollActivity));
    }
  }
  this._pollTimer = setTimeout(refDrivePoll, 0);
  return this;
};

ChildProcess.prototype.unref = function() {
  this._ref = false;
  if (this._pollTimer) {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
  }
  return this;
};

ChildProcess.prototype[Symbol.dispose] = function() {
  this.kill();
};

ChildProcess.prototype._finalizeDisconnect = function() {
  if (!this.channel) return;
  this.channel = null;
};

// Write one chunk to the child's IPC socket. Returns the byte count the
// kernel accepted (0 = EAGAIN, retry later) or -1 on a hard failure.
ChildProcess.prototype._ipcWriteChunk = function(chunk, sendFd) {
  var written;
  if (sendFd >= 0 && typeof globalThis.__exactSpawnSendMsg === 'function') {
    written = globalThis.__exactSpawnSendMsg(this._handle, chunk, sendFd);
  } else if (typeof globalThis.__exactSpawnWrite === 'function') {
    written = globalThis.__exactSpawnWrite(this._handle, chunk, 'ipc');
  } else {
    return -1;
  }
  // Defensive: the spawn-unavailable stubs historically returned booleans.
  if (written === true) return _ipcPacketLength(chunk);
  if (written === false) return -1;
  return typeof written === 'number' ? written : -1;
};

// Resolve one queue entry: decrement the in-flight counter and report the
// outcome (callback with err/null; 'error' event when there is no callback),
// asynchronously like Node does. Entries resolve in queue order because each
// completion schedules its own macrotask in FIFO order.
ChildProcess.prototype._completeIpcSendEntry = function(entry, err) {
  var self = this;
  setTimeout(function() {
    if (entry.counted && self._ipcQueueSize > 0) {
      self._ipcQueueSize--;
    }
    if (typeof entry.callback === 'function') {
      entry.callback(err || null);
    } else if (err) {
      self.emit('error', err);
    }
  }, 0);
};

ChildProcess.prototype._failPendingIpcSends = function(err) {
  if (this._ipcFlushTimer) {
    clearTimeout(this._ipcFlushTimer);
    this._ipcFlushTimer = null;
  }
  var queue = this._ipcSendQueue;
  if (!queue || queue.length === 0) return;
  this._ipcSendQueue = [];
  var failure = err || _makeIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed');
  for (var i = 0; i < queue.length; i++) {
    this._completeIpcSendEntry(queue[i], failure);
  }
};

ChildProcess.prototype._scheduleIpcFlush = function() {
  if (this._ipcFlushTimer) return;
  var self = this;
  // Referenced (not unref'd) on purpose: Node guarantees delivery of queued
  // subprocess.send() payloads, so a parent with undelivered packets must not
  // exit. Cleared as soon as the queue drains or the channel dies.
  this._ipcFlushTimer = setTimeout(function() {
    self._ipcFlushTimer = null;
    self._flushIpcSendQueue();
  }, 2);
};

// Drain the outbound queue head-first, preserving packet order. Returns true
// when the queue is empty afterwards; false when a tail remains queued under
// backpressure or the channel hard-failed (entries then observed the error).
ChildProcess.prototype._flushIpcSendQueue = function() {
  var queue = this._ipcSendQueue;
  if (!queue) return true;
  flushLoop: while (queue.length > 0) {
    var entry = queue[0];
    var total = _ipcPacketLength(entry.bytes);
    while (entry.offset < total) {
      var chunk = _ipcPacketSlice(entry.bytes, entry.offset);
      // SCM_RIGHTS handles ride only on the packet's first chunk.
      var sendFd = entry.offset === 0 ? entry.sendFd : -1;
      var written;
      try {
        written = this._ipcWriteChunk(chunk, sendFd);
      } catch (chunkErr) {
        if (entry.offset > 0) {
          // Mid-packet failure: a headless fragment is already in the pipe
          // and the child's framing is unrecoverable.
          this._failPendingIpcSends(chunkErr);
          return false;
        }
        // Nothing of this packet was written (e.g. the fd failed its
        // transferability check before sendmsg) — fail this entry alone and
        // keep the channel usable for the rest of the queue.
        queue.shift();
        this._completeIpcSendEntry(entry, chunkErr);
        continue flushLoop;
      }
      if (written < 0) {
        this._failPendingIpcSends(null);
        return false;
      }
      if (written === 0) {
        this._scheduleIpcFlush();
        return false;
      }
      if (entry.offset === 0 && entry.onFdSent) {
        // The kernel accepted the chunk carrying SCM_RIGHTS, i.e. the fd has
        // been dup'd into the message — the sender's copy may now be
        // detached/closed.
        var hook = entry.onFdSent;
        entry.onFdSent = null;
        try { hook(); } catch (hookErr) { _swallowDebug('IPC onFdSent hook threw', hookErr); }
      }
      entry.offset += written;
    }
    queue.shift();
    this._completeIpcSendEntry(entry, null);
  }
  if (this._ipcFlushTimer) {
    clearTimeout(this._ipcFlushTimer);
    this._ipcFlushTimer = null;
  }
  return true;
};

// Queue-or-write one framed packet. Returns true when the whole queue was
// flushed synchronously; false when (part of) it remains queued — it will
// still be delivered in order — or the channel hard-failed.
ChildProcess.prototype._enqueueIpcPacket = function(packet, sendFd, onFdSent, callback, counted) {
  var entry = {
    bytes: _ipcPacketToBytes(packet),
    offset: 0,
    sendFd: typeof sendFd === 'number' ? sendFd : -1,
    onFdSent: onFdSent || null,
    callback: callback || null,
    counted: !!counted
  };
  if (_ipcPacketLength(entry.bytes) <= 0) {
    this._completeIpcSendEntry(entry, null);
    return true;
  }
  this._ipcSendQueue.push(entry);
  return this._flushIpcSendQueue();
};

ChildProcess.prototype.send = function(message, sendHandle, opts, callback) {
  // Validate message argument
  if (message === undefined) {
    var missingErr = new TypeError('The "message" argument must be specified');
    missingErr.code = 'ERR_MISSING_ARGS';
    _addCodeToString(missingErr);
    throw missingErr;
  }
  if (typeof message === 'symbol') {
    var symErr = new TypeError('The "message" argument must be one of type string, object, number, or boolean. Received type symbol (' + String(message) + ')');
    symErr.code = 'ERR_INVALID_ARG_TYPE';
    _addCodeToString(symErr);
    throw symErr;
  }

  if (typeof sendHandle === 'function') {
    callback = sendHandle;
    sendHandle = undefined;
    opts = undefined;
  } else if (typeof opts === 'function') {
    callback = opts;
    opts = undefined;
  } else if (opts !== undefined) {
    if (opts === null || typeof opts !== 'object') {
      var optsErr = new TypeError('The "options" argument must be of type object.' + _invalidArgTypeHelper(opts));
      optsErr.code = 'ERR_INVALID_ARG_TYPE';
      _addCodeToString(optsErr);
      throw optsErr;
    }
  }

  // Validate callback
  if (callback !== undefined && typeof callback !== 'function') {
    var cbErr = new TypeError('The "callback" argument must be of type function.' + _invalidArgTypeHelper(callback));
    cbErr.code = 'ERR_INVALID_ARG_TYPE';
    _addCodeToString(cbErr);
    throw cbErr;
  }

  // Validate sendHandle - must be an object (net.Socket, net.Server, dgram.Socket handle) or falsy
  // Reject non-object types like strings and numbers (e.g. send('msg', 'meow') → ERR_INVALID_HANDLE_TYPE)
  if (sendHandle != null && sendHandle !== false) {
    if (typeof sendHandle !== 'object' && typeof sendHandle !== 'function') {
      var handleErr = new TypeError('This handle type can\'t be sent');
      handleErr.code = 'ERR_INVALID_HANDLE_TYPE';
      _addCodeToString(handleErr);
      throw handleErr;
    }
  }

  if (!this._ipcMode || !this.connected) {
    var disconnectedError = _makeIpcError('ERR_IPC_CHANNEL_CLOSED', 'Channel closed');
    if (typeof callback === 'function') {
      setTimeout(function() {
        callback(disconnectedError);
      }, 0);
    } else if (this._events && this._events.error) {
      this.emit('error', disconnectedError);
    }
    return false;
  }

  var returnValue = this._ipcQueueSize < this._ipcQueueMax;
  this._ipcQueueSize++;
  var handleFd = -1;
  var handleType = null;
  if (sendHandle != null && sendHandle !== false) {
    handleType = _getHandleType(sendHandle);
    handleFd = _extractHandleFd(sendHandle);
  }
  var packet = _createIpcPacket('message', message, handleType, this._serialization);
  var self = this;

  // (ENG-23231) The packet rides the outbound byte queue: a partial
  // write/EAGAIN queues the unsent tail instead of dropping it, the queue is
  // flushed before later sends and on a retry timer, and the callback fires
  // on actual delivery. An SCM_RIGHTS handle rides the packet's first chunk.
  var useSendMsg = handleFd >= 0 && typeof globalThis.__exactSpawnSendMsg === 'function';
  var onFdSent = null;
  if (useSendMsg) {
    // Runs once the kernel accepts the chunk carrying SCM_RIGHTS (the fd is
    // dup'd into the message at sendmsg time). Detaching the sender's copy
    // any earlier would close the fd while it may still need to be resent
    // after EAGAIN.
    onFdSent = function() {
      // When keepOpen is not set, Node.js detaches the handle from the sender.
      // The fd is dup'd via SCM_RIGHTS so closing sender's copy is safe.
      var keepOpen = opts && opts.keepOpen;
      // Don't destroy dgram sockets or servers after sending - they're shared.
      // Also skip detachment for raw native handles (not proper socket instances).
      var isDgram = handleType === 'dgram.Socket';
      var isServer = handleType === 'net.Server' || handleType === 'net.ServerHandle';
      var net2;
      try { net2 = require('net'); } catch (e) { /* ignored: optional net module; callers guard for null */ }
      var isRawHandle = !isDgram && !isServer && !(net2 && net2.Socket && sendHandle instanceof net2.Socket);
      if (sendHandle && !keepOpen && !isDgram && !isServer && !isRawHandle) {
        var sentSocketEntry = null;
        // Track the server for SocketList-like protocol: don't decrement
        // _connections now; instead wait for NODE_SOCKET_CLOSED from child.
        if (!self._sentSocketServers) self._sentSocketServers = [];
        sentSocketEntry = {
          server: sendHandle._server || null,
          nativeHandle: null
        };
        self._sentSocketServers.push(sentSocketEntry);
        if (sendHandle._server) {
          sendHandle._server = null;
          sendHandle.server = null;
        }
        // Clean up HTTP state if present
        if (sendHandle.parser) sendHandle.parser = null;
        if (sendHandle._httpMessage) sendHandle._httpMessage = null;
        var kTimeout = Symbol.for('kTimeout');
        sendHandle[kTimeout] = null;
        // Detach the handle from the sender without emitting 'close'.
        // The fd was dup'd via SCM_RIGHTS so closing the sender's copy is safe.
        if (sendHandle._pollTimer != null) {
          clearTimeout(sendHandle._pollTimer);
          sendHandle._pollTimer = null;
        }
        if (sendHandle._timeoutTimer != null) {
          clearTimeout(sendHandle._timeoutTimer);
          sendHandle._timeoutTimer = null;
        }
        // Close the native fd
        var nativeHandle = sendHandle._handle;
        if (nativeHandle && nativeHandle._exactHandle !== undefined) {
          nativeHandle = nativeHandle._exactHandle;
        }
        if (nativeHandle != null) {
          sentSocketEntry.nativeHandle = nativeHandle;
        }
        sendHandle._handle = null;
        sendHandle.destroyed = true;
        sendHandle.readable = false;
        sendHandle.writable = false;
      }
    };
  }

  var userCallback = typeof callback === 'function' ? callback : null;
  var fullyFlushed = this._enqueueIpcPacket(
    packet, useSendMsg ? handleFd : -1, onFdSent, userCallback, true);
  return fullyFlushed && returnValue;
};

ChildProcess.prototype.disconnect = function() {
  if (!this._ipcMode || !this.connected) {
    throw _makeIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
  }
  this._disconnectPending = true;
  this.connected = false;
  this._ipcMode = false;
  var self = this;
  var finalized = false;
  var finalize = function() {
    if (finalized) return;
    finalized = true;
    self._disconnectPending = false;
    if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
      globalThis.__exactSpawnCloseStdin(self._handle, 'ipc');
    }
    _flushSentSocketEntries(self._sentSocketServers);
    self.channel = null;
    if (self._disconnectEmitted) return;
    self._disconnectEmitted = true;
    self.emit('disconnect');
  };
  // (ENG-23231) The disconnect packet rides the same outbound queue as
  // messages: writing it directly would splice its bytes into the middle of
  // any queued packet still being flushed and corrupt the child's framing.
  // The channel closes only after everything queued ahead of it has been
  // delivered (or the queue failed, which also resolves the entry).
  if (typeof globalThis.__exactSpawnWrite === 'function' ||
      typeof globalThis.__exactSpawnSendMsg === 'function') {
    this._enqueueIpcPacket(_createIpcPacket('disconnect'), -1, null, finalize, false);
  } else {
    setTimeout(finalize, 0);
  }
  return this;
};

cp.ChildProcess = ChildProcess;

cp.spawn = function spawn(command, args, options) {
  if (typeof command !== 'string') {
    _throwInvalidArgType('file', 'of type string', command);
  }
  if (command.length === 0) {
    var valErr = new TypeError('The argument \'file\' cannot be empty. Received \'\'');
    valErr.code = 'ERR_INVALID_ARG_VALUE';
    _addCodeToString(valErr);
    throw valErr;
  }
  _validateNullBytes(command, 'file');
  // Handle optional args parameter
  if (args != null && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  } else if (args != null && !Array.isArray(args)) {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  }
  if (!args) args = [];
  // Coerce args to strings (Node.js does this automatically)
  args = args.map(function(a) { return String(a); });
  if (options === null || (options !== undefined && typeof options !== 'object') || Array.isArray(options)) {
    _throwInvalidArgType('options', 'of type object or undefined', options);
  }
  if (!options) options = {};
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);
  // Validate timeout option
  if (options.timeout !== undefined && options.timeout !== null) {
    _validateNonNegativeIntegerOption('options.timeout', options.timeout);
  }
  // Validate killSignal option
  if (options.killSignal !== undefined && options.killSignal !== null) {
    if (typeof options.killSignal !== 'string' && typeof options.killSignal !== 'number') {
      var ksErr = new TypeError('The "options.killSignal" property must be of type string or number. Received ' + typeof options.killSignal);
      ksErr.code = 'ERR_INVALID_ARG_TYPE';
      _addCodeToString(ksErr);
      throw ksErr;
    }
    if (typeof options.killSignal === 'string' && !signalMap.hasOwnProperty(options.killSignal)) {
      var uksErr = new TypeError('Unknown signal: ' + options.killSignal);
      uksErr.code = 'ERR_UNKNOWN_SIGNAL';
      _addCodeToString(uksErr);
      throw uksErr;
    }
  }
  // Validate serialization option
  if (options.serialization !== undefined && options.serialization !== 'json' && options.serialization !== 'advanced') {
    var serErr = new TypeError("The property 'options.serialization' must be one of: undefined, 'json', 'advanced'. Received " + require('util').inspect(options.serialization));
    serErr.code = 'ERR_INVALID_ARG_VALUE';
    _addCodeToString(serErr);
    throw serErr;
  }
  // Validate uid/gid
  _validateCredentialOption('options.uid', options.uid);
  _validateCredentialOption('options.gid', options.gid);
  // Check uid/gid permissions - throw EPERM if not root
  if (options.uid != null && typeof process !== 'undefined' && typeof process.getuid === 'function') {
    var currentUid = process.getuid();
    if (currentUid !== 0 && options.uid !== currentUid) {
      var uidErr = new Error('spawn EPERM');
      uidErr.code = 'EPERM';
      uidErr.errno = -1;
      uidErr.syscall = 'spawn';
      throw uidErr;
    }
  }
  if (options.gid != null && typeof process !== 'undefined' && typeof process.getgid === 'function') {
    var currentGid = process.getgid();
    var groups = typeof process.getgroups === 'function' ? process.getgroups() : [];
    if (currentGid !== 0 && !groups.some(function(g) { return g === options.gid; }) && options.gid !== currentGid) {
      var gidErr = new Error('spawn EPERM');
      gidErr.code = 'EPERM';
      gidErr.errno = -1;
      gidErr.syscall = 'spawn';
      throw gidErr;
    }
  }

  // Validate cwd URL
  if (options.cwd && typeof options.cwd === 'object' && options.cwd instanceof URL) {
    if (options.cwd.protocol !== 'file:') {
      throw new TypeError('The URL must be of scheme file');
    }
    if (options.cwd.hostname && options.cwd.hostname !== 'localhost' && options.cwd.hostname !== '') {
      throw new TypeError('File URL host must be "localhost" or empty on ' + process.platform);
    }
    options = Object.assign({}, options, { cwd: options.cwd.pathname });
  }
  if (Array.isArray(options.stdio)) {
    var rawIpcCount = 0;
    for (var rawStdioIndex = 0; rawStdioIndex < options.stdio.length; rawStdioIndex++) {
      if (options.stdio[rawStdioIndex] === 'ipc') rawIpcCount++;
    }
    if (rawIpcCount > 1) {
      var rawIpcErr = new Error('Child process can have only one IPC pipe');
      rawIpcErr.code = 'ERR_IPC_ONE_PIPE';
      rawIpcErr.name = 'Error';
      _addCodeToString(rawIpcErr);
      throw rawIpcErr;
    }
  }
  var normalizedOptions = _normalizeSpawnOptions(options, command);
  if (ChildProcess.prototype.spawn !== _childProcessPrototypeSpawnImpl) {
    try {
      ChildProcess.prototype.spawn.call({}, {
        __exactSpyOnlyHook: true,
        file: command,
        args: args,
        windowsHide: normalizedOptions.windowsHide
      });
    } catch (e) { /* ignored: spy-only hook; a monkey-patched spawn may throw */ }
  }
  // Validate only one IPC pipe
  if (normalizedOptions.stdio) {
    var ipcCount = 0;
    for (var si = 0; si < normalizedOptions.stdio.length; si++) {
      if (normalizedOptions.stdio[si] === 'ipc') ipcCount++;
    }
    if (ipcCount > 1) {
      var ipcErr = new Error('Child process can have only one IPC pipe');
      ipcErr.code = 'ERR_IPC_ONE_PIPE';
      ipcErr.name = 'Error';
      _addCodeToString(ipcErr);
      throw ipcErr;
    }
  }
  var opts = {};
  if (normalizedOptions.cwd) opts.cwd = String(normalizedOptions.cwd);
  if (normalizedOptions.shell !== undefined) opts.shell = normalizedOptions.shell;
  // (ENG-23485) uid/gid serialized BEFORE env: native only trusts a
  // "uid"/"gid" key ahead of the env object so env values can't smuggle
  // credentials into the substring parse.
  if (normalizedOptions.uid !== undefined) opts.uid = Math.floor(normalizedOptions.uid);
  if (normalizedOptions.gid !== undefined) opts.gid = Math.floor(normalizedOptions.gid);
  if (normalizedOptions.env) opts.env = normalizedOptions.env;
  if (normalizedOptions.detached !== undefined) opts.detached = normalizedOptions.detached;
  opts.windowsHide = normalizedOptions.windowsHide;
  opts.stdio = normalizedOptions.stdio;

  if (typeof process !== 'undefined' && process.platform === 'win32' &&
      normalizedOptions.stdio && normalizedOptions.stdio.indexOf('ipc') !== -1 &&
      typeof globalThis.__exactSpawnRecvMsg !== 'function') {
    throw _makeWin32IpcUnsupportedError(command);
  }

  if (typeof process !== 'undefined' && process.platform === 'win32' &&
      typeof globalThis.__exactSpawn !== 'function' &&
      typeof globalThis.__exactSpawnSync === 'function') {
    return _spawnSyncBackedChildProcess(command, args, options, normalizedOptions);
  }

  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawn(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: 'Failed to initialize spawn' };
  }

  if (result.error) {
    // Return a ChildProcess that emits error, with stdio set up
    var errStdioCfg = {
      stdin: normalizedOptions.stdio[0],
      stdout: normalizedOptions.stdio[1],
      stderr: normalizedOptions.stdio[2],
      ipc: normalizedOptions.stdio[3],
      relayReadablePipes: normalizedOptions.relayReadablePipes || null
    };
    var errChild = new ChildProcess(-1, undefined, errStdioCfg);
    errChild.pid = undefined;
    errChild._exited = true; // prevent poll loop from running
    errChild._spawnEmitted = true; // prevent spawn event
    errChild._serialization = normalizedOptions.serialization || 'json';
    errChild.spawnfile = command;
    errChild.spawnargs = [command].concat(args);
    var spawnErr2 = _makeNativeSpawnError(
      command,
      result,
      'spawn ' + command,
      args
    );
    spawnErr2.spawnargs = args;
    _trackSharedReadablePipeConsumers(options.stdio, errChild);
    setTimeout(function() {
      errChild.emit('error', spawnErr2);
      errChild.emit('close', null, null);
    }, 0);
    return errChild;
  }

  var stdioCfg = {
    stdin: normalizedOptions.stdio[0],
    stdout: normalizedOptions.stdio[1],
    stderr: normalizedOptions.stdio[2],
    ipc: normalizedOptions.stdio[3],
    extra: normalizedOptions.stdio.slice(4),
    relayReadablePipes: normalizedOptions.relayReadablePipes || null
  };
  var child = new ChildProcess(result.handle, result.pid, stdioCfg);
  child._serialization = normalizedOptions.serialization || 'json';
  // Set spawnfile and spawnargs based on whether shell was used
  if (normalizedOptions.shell) {
    var shellBin = typeof normalizedOptions.shell === 'string' ? normalizedOptions.shell : '/bin/sh';
    var shellCmd = args.length > 0 ? command + ' ' + args.join(' ') : command;
    child.spawnfile = shellBin;
    child.spawnargs = [shellBin, '-c', shellCmd];
  } else {
    child.spawnfile = command;
    child.spawnargs = [command].concat(args);
  }
  // ENG-23113 — `detached` must NOT auto-unref. In Node, `detached` only
  // controls process-group/session placement (setsid, handled natively); the
  // parent still waits for the child (and its `exit`/`close` fire) UNLESS the
  // caller explicitly invokes `child.unref()`. Auto-unref'ing here let the CLI
  // exit and orphan `spawn('worker', { detached: true })` used as the last
  // statement, and could skip the exit/close handlers.
  _trackSharedReadablePipeConsumers(options.stdio, child);
  _setupSharedReadablePipeRelays(normalizedOptions.relayReadablePipes, child);
  // Handle timeout option
  if (options.timeout && options.timeout > 0) {
    var killSig = options.killSignal || 'SIGTERM';
    child._timeoutTimer = setTimeout(function() {
      child.kill(killSig);
    }, options.timeout);
    child.on('exit', function() {
      if (child._timeoutTimer) { clearTimeout(child._timeoutTimer); child._timeoutTimer = null; }
    });
  }
  // Handle signal (AbortController) option
  if (options.signal) {
    var sig = options.signal;
    var _killSigForAbort = options.killSignal || 'SIGTERM';
    var _doAbort = function() {
      if (!child.killed) {
        child.kill(_killSigForAbort);
        var abortErr = _makeAbortError(sig.reason);
        child.emit('error', abortErr);
      }
    };
    if (sig.aborted) {
      // Already aborted
      process.nextTick(_doAbort);
    } else {
      sig.addEventListener('abort', _doAbort, { once: true });
      child.on('exit', function() {
        sig.removeEventListener('abort', _doAbort);
        if (child._timeoutTimer) { clearTimeout(child._timeoutTimer); child._timeoutTimer = null; }
      });
    }
  }
  // 'spawn' event is now emitted from the constructor's poll loop start
  return child;
};

cp.fork = function fork(modulePath, args, options) {
  if (typeof modulePath !== 'string') {
    _throwInvalidArgType('modulePath', 'of type string', modulePath);
  }
  _validateNullBytes(modulePath, 'modulePath');
  if (Array.isArray(args)) {
    // args provided as array
  } else if (args != null && typeof args === 'object' && !Array.isArray(args)) {
    options = args;
    args = null;
  } else if (args != null && typeof args !== 'undefined') {
    _throwInvalidArgType('args', 'an instance of Array or undefined', args);
  }
  args = args || [];
  if (options != null && (typeof options !== 'object' || Array.isArray(options))) {
    _throwInvalidArgType('options', 'of type object or undefined', options);
  }
  options = options || {};
  _validateArgsNullBytes(args);
  _validateOptionsNullBytes(options);

  // Resolve module path - try adding .js extension like Node.js does
  var _resolvedModule = modulePath;
  try {
    var _fs = require('fs');
    var _pathMod = require('path');
    if (!_pathMod.isAbsolute(_resolvedModule)) {
      _resolvedModule = _pathMod.resolve(options.cwd || (typeof process !== 'undefined' && process.cwd()) || '.', _resolvedModule);
    }
    if (!_fs.existsSync(_resolvedModule)) {
      var _exts = ['.js', '.mjs', '.json', '.node'];
      for (var _ei = 0; _ei < _exts.length; _ei++) {
        if (_fs.existsSync(_resolvedModule + _exts[_ei])) {
          _resolvedModule = _resolvedModule + _exts[_ei];
          break;
        }
      }
    }
  } catch (e) {
    _resolvedModule = modulePath;
  }

  var execPath = _fallbackSpawnCommand(options.execPath || (typeof process !== 'undefined' && process.execPath) || 'node');
  var execArgv = options.execArgv || (typeof process !== 'undefined' && process.execArgv) || [];
  var exactExecArgv = _shouldPropagateExactExecutable(execPath)
    ? _splitExactExecArgv(execArgv)
    : { cliArgs: execArgv, compatArgs: [] };
  var spawnArgs = exactExecArgv.cliArgs.concat([_resolvedModule]).concat(args);
  var silent = options.silent === true;
  var stdio = options.stdio;
  if (!stdio) {
    stdio = [
      silent ? 'pipe' : 'inherit',
      silent ? 'pipe' : 'inherit',
      silent ? 'pipe' : 'inherit',
      'ipc'
    ];
  } else if (typeof stdio === 'string') {
    // Validate string stdio option
    if (stdio !== 'pipe' && stdio !== 'inherit' && stdio !== 'ignore') {
      var strvErr = new TypeError("The property 'options.stdio' is invalid. Received " + require('util').inspect(stdio));
      strvErr.code = 'ERR_INVALID_ARG_VALUE';
      _addCodeToString(strvErr);
      throw strvErr;
    }
    stdio = [_normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), 'ipc'];
  } else if (Array.isArray(stdio)) {
    // Check that the array contains 'ipc'
    var hasIpc = false;
    for (var fi = 0; fi < stdio.length; fi++) {
      if (stdio[fi] === 'ipc') { hasIpc = true; break; }
    }
    if (!hasIpc) {
      var ipcReqErr = new Error("Forked processes must have an IPC channel, missing value 'ipc' in options.stdio");
      ipcReqErr.code = 'ERR_CHILD_PROCESS_IPC_REQUIRED';
      ipcReqErr.name = 'Error';
      _addCodeToString(ipcReqErr);
      throw ipcReqErr;
    }
    // Normalize each entry, keeping ipc entries
    var normalizedStdio = [];
    for (var si = 0; si < Math.max(stdio.length, 3); si++) {
      if (stdio[si] === 'ipc') {
        normalizedStdio[si] = 'ipc';
      } else if (si < 3) {
        normalizedStdio[si] = _normalizeSpawnMode(stdio[si], silent ? 'pipe' : 'inherit');
      } else {
        normalizedStdio[si] = _normalizeSpawnMode(stdio[si], 'pipe');
      }
    }
    stdio = normalizedStdio;
  }

  var env = _normalizeForkEnv(options.env);
  env = _prepareExactChildEnv(execPath, env, options.argv0, execPath);
  if (exactExecArgv.compatArgs.length > 0) {
    env.EXACT_COMPAT_EXEC_ARGV = JSON.stringify(exactExecArgv.compatArgs);
  } else {
    delete env.EXACT_COMPAT_EXEC_ARGV;
  }
  env.EXACT_IPC_FD = '3';

  var spawnOptions = {
    cwd: options.cwd,
    env: env,
    stdio: stdio,
    detached: options.detached,
    shell: false,
    serialization: options.serialization,
    timeout: options.timeout,
    killSignal: options.killSignal,
    signal: options.signal
  };

  var child = cp.spawn(execPath, spawnArgs, spawnOptions);
  child._channel = child.channel;
  // ENG-23113 — like spawn(), fork() must NOT auto-unref on `detached`; only
  // an explicit child.unref() detaches the parent's event loop (Node parity).

  return child;
};

cp.ChildProcess = ChildProcess;
module.exports = cp;

// Wire up internal/child_process to reference the real ChildProcess
try {
  var internalCp = require('internal/child_process');
  if (internalCp) {
    // Always set ChildProcess to our implementation (not just when null)
    internalCp.ChildProcess = ChildProcess;
    if (!internalCp.spawnSync) {
      internalCp.spawnSync = _internalSpawnSync;
    }
  }
} catch (e) { /* ignored: optional internal/child_process wiring */ }
