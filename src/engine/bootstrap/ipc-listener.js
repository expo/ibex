(function() {
  if (typeof process !== 'object' || process === null) return;
  function defineOwnProcessProperty(name, value, enumerable) {
    try {
      Object.defineProperty(process, name, {
        value: value,
        writable: true,
        configurable: true,
        enumerable: !!enumerable,
      });
      return true;
    } catch (_) {}
    try {
      process[name] = value;
      return true;
    } catch (_) {}
    return false;
  }
  function installLateIpcChannel() {
    if (process.channel && typeof process.channel.ref === 'function') return;
    if (!process.connected || !process.env || !process.env.EXACT_IPC_FD) return;
    var ipcFd = Number(process.env.EXACT_IPC_FD);
    if (!isFinite(ipcFd) || ipcFd < 0) return;
    if (typeof globalThis.__exactEnsureFs === 'function') {
      try { globalThis.__exactEnsureFs(); } catch (_) {}
    }
    var ipcBuffer = '';
    var pendingRecvFd = -1;
    var pollTimer = 0;
    var pollEnabled = false;
    var readPending = false;
    var pollInterval = 2;
    var pollReadSize = 262144;
    var serializationMode =
      process.env.EXACT_IPC_SERIALIZATION === 'advanced' ? 'advanced' : 'json';
    function chunkToString(chunk) {
      if (chunk == null) return '';
      if (typeof chunk === 'string') return chunk;
      if (typeof Buffer === 'function' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
        return chunk.toString('utf8');
      }
      if (typeof TextDecoder === 'function' &&
          typeof Uint8Array === 'function' &&
          chunk instanceof Uint8Array) {
        try { return new TextDecoder().decode(chunk); } catch (_) {}
      }
      return String(chunk);
    }
    function getBufferCtor() {
      if (typeof Buffer === 'function' && Buffer && typeof Buffer.from === 'function') {
        return Buffer;
      }
      try {
        if (typeof require === 'function') {
          return require('buffer').Buffer;
        }
      } catch (_) {}
      return null;
    }
    function bytesToBase64(bytes) {
      var BufferCtor = getBufferCtor();
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
    function base64ToByteArray(base64) {
      var BufferCtor = getBufferCtor();
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
    function advancedTag(type) {
      return { __exactIpcSerialized: true, type: type };
    }
    function encodeAdvanced(value, refs) {
      if (value === undefined) return advancedTag('Undefined');
      if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
      if (typeof value === 'number') {
        if (value !== value) {
          var nanTag = advancedTag('Number');
          nanTag.value = 'NaN';
          return nanTag;
        }
        if (value === Infinity) {
          var infTag = advancedTag('Number');
          infTag.value = 'Infinity';
          return infTag;
        }
        if (value === -Infinity) {
          var ninfTag = advancedTag('Number');
          ninfTag.value = '-Infinity';
          return ninfTag;
        }
        if (value === 0 && 1 / value === -Infinity) {
          var negZeroTag = advancedTag('Number');
          negZeroTag.value = '-0';
          return negZeroTag;
        }
        return value;
      }
      if (typeof value === 'bigint') {
        var bigIntTag = advancedTag('BigInt');
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
          var refTag = advancedTag('Ref');
          refTag.id = refIndex;
          return refTag;
        }
      }
      var id = refs.length;
      refs.push(value);
      var BufferCtor = getBufferCtor();
      if (BufferCtor && typeof BufferCtor.isBuffer === 'function' && BufferCtor.isBuffer(value)) {
        var bufferTag = advancedTag('Buffer');
        bufferTag.id = id;
        bufferTag.data = value.toString('base64');
        return bufferTag;
      }
      if (typeof Date !== 'undefined' && value instanceof Date) {
        var dateTag = advancedTag('Date');
        dateTag.id = id;
        dateTag.value = value.getTime();
        return dateTag;
      }
      if (typeof RegExp !== 'undefined' && value instanceof RegExp) {
        var regexpTag = advancedTag('RegExp');
        regexpTag.id = id;
        regexpTag.source = value.source;
        regexpTag.flags = value.flags;
        return regexpTag;
      }
      if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
        var arrayBufferTag = advancedTag('ArrayBuffer');
        arrayBufferTag.id = id;
        arrayBufferTag.data = bytesToBase64(value);
        return arrayBufferTag;
      }
      if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) {
        var sharedArrayBufferTag = advancedTag('SharedArrayBuffer');
        sharedArrayBufferTag.id = id;
        sharedArrayBufferTag.data = bytesToBase64(new Uint8Array(value));
        return sharedArrayBufferTag;
      }
      if (typeof DataView !== 'undefined' && value instanceof DataView) {
        var dataViewTag = advancedTag('DataView');
        dataViewTag.id = id;
        dataViewTag.data = bytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
        return dataViewTag;
      }
      if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
        var typedArrayTag = advancedTag('TypedArray');
        typedArrayTag.id = id;
        typedArrayTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Uint8Array';
        typedArrayTag.data = bytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
        return typedArrayTag;
      }
      if (typeof Map !== 'undefined' && value instanceof Map) {
        var mapTag = advancedTag('Map');
        mapTag.id = id;
        mapTag.entries = [];
        value.forEach(function(mapValue, mapKey) {
          mapTag.entries.push([
            encodeAdvanced(mapKey, refs),
            encodeAdvanced(mapValue, refs)
          ]);
        });
        return mapTag;
      }
      if (typeof Set !== 'undefined' && value instanceof Set) {
        var setTag = advancedTag('Set');
        setTag.id = id;
        setTag.values = [];
        value.forEach(function(setValue) {
          setTag.values.push(encodeAdvanced(setValue, refs));
        });
        return setTag;
      }
      if (value instanceof Error) {
        var errorTag = advancedTag('Error');
        errorTag.id = id;
        errorTag.ctor = value.constructor && value.constructor.name ? value.constructor.name : 'Error';
        errorTag.name = value.name;
        errorTag.message = value.message;
        if (value.stack !== undefined) errorTag.stack = value.stack;
        if ('cause' in value) errorTag.cause = encodeAdvanced(value.cause, refs);
        var errorProps = Object.keys(value);
        if (errorProps.length > 0) {
          errorTag.props = {};
          for (var ep = 0; ep < errorProps.length; ep++) {
            var errorKey = errorProps[ep];
            if (errorKey === 'message' || errorKey === 'stack' || errorKey === 'cause' || errorKey === 'name') continue;
            errorTag.props[errorKey] = encodeAdvanced(value[errorKey], refs);
          }
        }
        return errorTag;
      }
      if (Array.isArray(value)) {
        var arrayTag = advancedTag('Array');
        arrayTag.id = id;
        arrayTag.items = new Array(value.length);
        for (var ai = 0; ai < value.length; ai++) {
          if (Object.prototype.hasOwnProperty.call(value, ai)) {
            arrayTag.items[ai] = encodeAdvanced(value[ai], refs);
          } else {
            arrayTag.items[ai] = advancedTag('Hole');
          }
        }
        return arrayTag;
      }
      var objectTag = advancedTag('Object');
      objectTag.id = id;
      objectTag.props = {};
      var keys = Object.keys(value);
      for (var ki = 0; ki < keys.length; ki++) {
        var key = keys[ki];
        objectTag.props[key] = encodeAdvanced(value[key], refs);
      }
      return objectTag;
    }
    function decodeAdvanced(value, refs) {
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
      if (type === 'Hole') return value;
      if (type === 'Ref') return refs[value.id];
      var decoded;
      if (type === 'Buffer') {
        var bufferBytes = base64ToByteArray(value.data);
        var BufferCtor = getBufferCtor();
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
        var bufferData = base64ToByteArray(value.data);
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
        var dataViewBytes = base64ToByteArray(value.data);
        var dataViewBuffer = new ArrayBuffer(dataViewBytes.byteLength);
        new Uint8Array(dataViewBuffer).set(dataViewBytes);
        decoded = new DataView(dataViewBuffer);
        refs[value.id] = decoded;
        return decoded;
      }
      if (type === 'TypedArray') {
        var typedArrayBytes = base64ToByteArray(value.data);
        var typedArrayBuffer = new ArrayBuffer(typedArrayBytes.byteLength);
        new Uint8Array(typedArrayBuffer).set(typedArrayBytes);
        var TypedArrayCtor = globalThis[value.ctor];
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
            decodeAdvanced(mapEntries[me][0], refs),
            decodeAdvanced(mapEntries[me][1], refs)
          );
        }
        return decoded;
      }
      if (type === 'Set') {
        decoded = new Set();
        refs[value.id] = decoded;
        var setValues = value.values || [];
        for (var sv = 0; sv < setValues.length; sv++) {
          decoded.add(decodeAdvanced(setValues[sv], refs));
        }
        return decoded;
      }
      if (type === 'Error') {
        var ErrorCtor = globalThis[value.ctor];
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
          decoded.cause = decodeAdvanced(value.cause, refs);
        }
        if (value.props) {
          var errorPropKeys = Object.keys(value.props);
          for (var ek = 0; ek < errorPropKeys.length; ek++) {
            decoded[errorPropKeys[ek]] = decodeAdvanced(value.props[errorPropKeys[ek]], refs);
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
          decoded[ai2] = decodeAdvanced(value.items[ai2], refs);
        }
        return decoded;
      }
      if (type === 'Object') {
        decoded = {};
        refs[value.id] = decoded;
        var propKeys = value.props ? Object.keys(value.props) : [];
        for (var pk = 0; pk < propKeys.length; pk++) {
          decoded[propKeys[pk]] = decodeAdvanced(value.props[propKeys[pk]], refs);
        }
        return decoded;
      }
      return value;
    }
    function serializePacketData(data, mode) {
      if (mode === 'advanced') return encodeAdvanced(data, []);
      return data;
    }
    function deserializePacketData(data, mode) {
      if (mode === 'advanced') return decodeAdvanced(data, []);
      return data;
    }
    function buildPacket(type, data, handleType) {
      var packet = {
        __exactIpc: true,
        type: type,
        data: serializePacketData(data, serializationMode)
      };
      if (serializationMode === 'advanced') packet.serialization = 'advanced';
      if (handleType) packet.handleType = handleType;
      return JSON.stringify(packet) + '\n';
    }
    function createIpcError(code, message) {
      var err = new Error(message);
      err.code = code;
      return err;
    }
    function ensureStdioRefUnref() {
      function ensureStream(name) {
        var stream = process[name];
        if (!stream || (typeof stream !== 'object' && typeof stream !== 'function')) {
          return;
        }
        if (typeof stream.ref !== 'function') {
          stream.ref = function() { return stream; };
        }
        if (typeof stream.unref !== 'function') {
          stream.unref = function() { return stream; };
        }
        try {
          Object.defineProperty(process, name, {
            value: stream,
            writable: true,
            configurable: true,
            enumerable: true
          });
        } catch (_) {}
      }
      try {
        ensureStream('stdout');
        ensureStream('stderr');
        ensureStream('stdin');
      } catch (_) {}
    }
    function packetToBytes(packet) {
      var BufferCtor = getBufferCtor();
      if (BufferCtor) {
        return BufferCtor.from(packet, 'utf8');
      }
      if (typeof TextEncoder === 'function') {
        return new TextEncoder().encode(packet);
      }
      return packet;
    }
    function packetLength(packet) {
      if (!packet) return 0;
      if (typeof packet.length === 'number') return packet.length;
      if (typeof packet.byteLength === 'number') return packet.byteLength;
      return 0;
    }
    function packetSlice(packet, offset) {
      if (!packet || offset <= 0) return packet;
      if (typeof packet.subarray === 'function') return packet.subarray(offset);
      if (typeof packet.slice === 'function') return packet.slice(offset);
      return packet;
    }
    function writePacket(packet, sendFd) {
      var packetBytes = packetToBytes(packet);
      var totalLength = packetLength(packetBytes);
      if (totalLength <= 0) return true;
      var offset = 0;
      var firstWrite = true;
      while (offset < totalLength) {
        var chunk = packetSlice(packetBytes, offset);
        var written = 0;
        if (firstWrite && sendFd >= 0) {
          if (typeof globalThis.__exactIpcSendMsg !== 'function') {
            return false;
          }
          try {
            written = globalThis.__exactIpcSendMsg(ipcFd, chunk, sendFd);
          } catch (_) {
            written = 0;
          }
        } else if (typeof globalThis.__exactIpcSendMsg === 'function') {
          try {
            written = globalThis.__exactIpcSendMsg(ipcFd, chunk);
          } catch (_) {
            written = 0;
          }
        } else if (typeof globalThis.__exactFsWrite === 'function') {
          try {
            written = globalThis.__exactFsWrite(ipcFd, chunk, -1);
          } catch (_) {
            written = 0;
          }
        } else {
          return false;
        }
        firstWrite = false;
        if (!(written > 0)) return false;
        offset += written;
      }
      return true;
    }
    function maybeDecodeBuffer() {
      if (!ipcBuffer || ipcBuffer.charCodeAt(0) !== 34) return;
      try {
        var decodedBuffer = JSON.parse(ipcBuffer);
        if (typeof decodedBuffer === 'string') {
          ipcBuffer = decodedBuffer;
        }
      } catch (_) {}
    }
    function emitDisconnect() {
      if (!process.connected) return;
      process.connected = false;
      pollEnabled = false;
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = 0;
      }
      readPending = false;
      if (process.channel) {
        try { process.channel.connected = false; } catch (_) {}
      }
      var channelHandleKey = globalThis.__exactKChannelHandleKey;
      if (channelHandleKey === undefined) {
        channelHandleKey = '__exactKChannelHandle';
        globalThis.__exactKChannelHandleKey = channelHandleKey;
      }
      process[channelHandleKey] = null;
      defineOwnProcessProperty('channel', null, true);
      setTimeout(function() {
        process.emit('disconnect');
      }, 0);
    }
    function reconstructHandle(handleType, fd) {
      try {
        if (handleType === 'dgram.Socket' || handleType === 'dgram.Native') {
          var dgram = require('dgram');
          var sock = dgram.createSocket('udp4');
          sock._fromFd(fd);
          return sock;
        }
        var net = require('net');
        if (handleType === 'net.Socket' || handleType === 'net.Native') {
          var recvSocket;
          if (typeof globalThis.__exactTcpFromFd === 'function') {
            var nativeHandle = globalThis.__exactTcpFromFd(fd);
            recvSocket = new net.Socket({ _handle: nativeHandle });
          } else {
            recvSocket = new net.Socket({ fd: fd, readable: true, writable: true });
          }
          recvSocket.on('close', function() {
            if (process && process.connected) {
              try {
                process.send({ cmd: 'NODE_SOCKET_CLOSED' });
              } catch (_) {}
            }
          });
          return recvSocket;
        }
        if (handleType === 'net.ServerHandle') {
          if (typeof globalThis.__exactTcpFromFd === 'function') {
            var nativeServerHandle = globalThis.__exactTcpFromFd(fd);
            return {
              _exactServerHandle: true,
              _exactHandle: nativeServerHandle,
              fd: fd,
              onconnection: function() {},
              close: function() {
                try { globalThis.__exactTcpClose(nativeServerHandle); } catch (_) {}
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
              } catch (_) {}
            }
          };
        }
        if (handleType === 'net.Server') {
          var server = net.createServer();
          if (typeof globalThis.__exactTcpFromFd === 'function') {
            var nativeServer = globalThis.__exactTcpFromFd(fd);
            server._handle = {
              _exactHandle: nativeServer,
              _exactServerHandle: true,
              close: function() {
                try { globalThis.__exactTcpClose(nativeServer); } catch (_) {}
              }
            };
          } else {
            server._handle = { fd: fd, _exactServerHandle: true };
          }
          server.listening = true;
          server._closing = false;
          if (typeof globalThis.__exactTcpLocalAddr === 'function' && server._handle && server._handle._exactHandle) {
            try {
              var info = globalThis.__exactTcpLocalAddr(server._handle._exactHandle);
              if (info) {
                var addr = JSON.parse(info);
                server._port = addr.port;
                server._host = addr.address;
                server.host = addr.address;
                var familySuffix = (addr.family || 'IPv4').slice(-1);
                server._connectionKey = familySuffix + ':' + addr.address + ':' + addr.port;
              }
            } catch (_) {}
          }
          if (typeof server._startAccepting === 'function') {
            server._startAccepting();
          }
          return server;
        }
      } catch (_) {}
      return null;
    }
    function handleLine(line) {
      var packet = null;
      if (!line) return;
      try {
        packet = JSON.parse(line);
      } catch (_) {
        return;
      }
      if (typeof packet === 'string') {
        try {
          packet = JSON.parse(packet);
        } catch (_) {
          return;
        }
      }
      if (!packet || packet.__exactIpc !== true) return;
      if (packet.type === 'message') {
        var handle = null;
        if (packet.handleType && pendingRecvFd >= 0) {
          handle = reconstructHandle(packet.handleType, pendingRecvFd);
          pendingRecvFd = -1;
        }
        var packetData = deserializePacketData(packet.data, packet.serialization);
        if (handle) {
          process.emit('message', packetData, handle);
        } else {
          process.emit('message', packetData);
        }
        if (typeof globalThis.__exactSyncTrackedIpcListenersAfterDispatch === 'function') {
          try {
            globalThis.__exactSyncTrackedIpcListenersAfterDispatch();
          } catch (_) {}
        }
      } else if (packet.type === 'disconnect') {
        emitDisconnect();
      }
    }
    function processIncomingPackets(chunk, recvFd) {
      var newlineIndex;
      if (typeof recvFd === 'number' && recvFd >= 0) {
        pendingRecvFd = recvFd;
      }
      if (!chunk || !chunk.length) return;
      ipcBuffer += chunkToString(chunk);
      maybeDecodeBuffer();
      while ((newlineIndex = ipcBuffer.indexOf('\n')) !== -1) {
        var line = ipcBuffer.slice(0, newlineIndex);
        ipcBuffer = ipcBuffer.slice(newlineIndex + 1);
        handleLine(line);
        maybeDecodeBuffer();
      }
    }
    function schedulePoll(delay) {
      if (!process.connected || !pollEnabled || readPending) return;
      if (pollTimer) {
        clearTimeout(pollTimer);
      }
      pollTimer = setTimeout(function() {
        pollTimer = 0;
        pollIncoming();
      }, delay);
    }
    function pollIncoming() {
      if (!process.connected || !pollEnabled) return;
      var hadData = false;
      if (typeof globalThis.__exactIpcRecvMsg === 'function') {
        var recvResult;
        try {
          recvResult = globalThis.__exactIpcRecvMsg(ipcFd, pollReadSize);
        } catch (_) {
          emitDisconnect();
          return;
        }
        if (recvResult && recvResult.data && recvResult.data.length) {
          hadData = true;
          processIncomingPackets(recvResult.data, recvResult.fd);
        }
      } else if (typeof globalThis.__exactFsRead === 'function') {
        var readChunk;
        try {
          readChunk = globalThis.__exactFsRead(ipcFd, pollReadSize, -1);
        } catch (_) {
          emitDisconnect();
          return;
        }
        if (readChunk && readChunk.length) {
          hadData = true;
          processIncomingPackets(readChunk);
        }
      } else if (typeof require === 'function') {
        try {
          var fs = require('fs');
          var BufferCtor = typeof Buffer === 'function' ? Buffer : null;
          if (fs && BufferCtor && typeof fs.read === 'function') {
            var buf = BufferCtor.alloc(pollReadSize);
            readPending = true;
            fs.read(ipcFd, buf, 0, buf.length, null, function(err, bytesRead) {
              readPending = false;
              if (!process.connected) return;
              if (!err && bytesRead > 0) {
                processIncomingPackets(buf.subarray(0, bytesRead));
                schedulePoll(0);
                return;
              }
              schedulePoll(pollInterval);
            });
            return;
          }
        } catch (_) {}
      }
      if (!hadData && typeof globalThis.__exactFdPollHup === 'function') {
        try {
          if (globalThis.__exactFdPollHup(ipcFd)) {
            emitDisconnect();
            return;
          }
        } catch (_) {}
      }
      schedulePoll(hadData ? 0 : pollInterval);
    }
    var channelHandleKey = globalThis.__exactKChannelHandleKey;
    if (channelHandleKey === undefined) {
      channelHandleKey = '__exactKChannelHandle';
      globalThis.__exactKChannelHandleKey = channelHandleKey;
    }
    ensureStdioRefUnref();
    process[channelHandleKey] = {
      readStop: function() {
        pollEnabled = false;
        if (pollTimer) {
          clearTimeout(pollTimer);
          pollTimer = 0;
        }
      },
      readStart: function() {
        if (!process.connected || pollEnabled) return;
        pollEnabled = true;
        schedulePoll(0);
      }
    };
    defineOwnProcessProperty('channel', {
      fd: ipcFd,
      connected: true,
      ref: function() {
        if (!process.connected || pollEnabled) return;
        pollEnabled = true;
        schedulePoll(0);
      },
      unref: function() {
        pollEnabled = false;
        if (pollTimer) {
          clearTimeout(pollTimer);
          pollTimer = 0;
        }
      },
    }, true);
    process.send = function(message, sendHandle, opts, callback) {
      if (message === undefined) {
        var missingErr = new TypeError('The "message" argument must be specified');
        missingErr.code = 'ERR_MISSING_ARGS';
        throw missingErr;
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
          var optsErr = new TypeError('The "options" argument must be of type object. Received type ' + typeof opts);
          optsErr.code = 'ERR_INVALID_ARG_TYPE';
          throw optsErr;
        }
      }
      if (callback !== undefined && typeof callback !== 'function') {
        var cbErr = new TypeError('The "callback" argument must be of type function. Received type ' + typeof callback);
        cbErr.code = 'ERR_INVALID_ARG_TYPE';
        throw cbErr;
      }
      if (sendHandle != null && sendHandle !== false) {
        if (typeof sendHandle !== 'object' && typeof sendHandle !== 'function') {
          var handleErr = new TypeError("This handle type can't be sent");
          handleErr.code = 'ERR_INVALID_HANDLE_TYPE';
          throw handleErr;
        }
      }
      if (!process.connected) {
        var ipcError = createIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is closed');
        if (typeof callback === 'function') {
          setTimeout(function() { callback(ipcError); }, 0);
        }
        return false;
      }
      var handleFd = -1;
      var handleType = null;
      if (sendHandle != null && sendHandle !== false && typeof sendHandle === 'object') {
        if (typeof sendHandle._getFd === 'function') {
          handleFd = sendHandle._getFd();
        } else if (typeof sendHandle._handle === 'number' && sendHandle._handle >= 0 &&
                   (sendHandle.type === 'udp4' || sendHandle.type === 'udp6')) {
          if (typeof globalThis.__exactUdpGetFd === 'function') {
            handleFd = globalThis.__exactUdpGetFd(sendHandle._handle);
          }
        } else if (sendHandle._handle &&
                   typeof sendHandle._handle._exactHandle === 'number' &&
                   sendHandle._handle._exactHandle > 0 &&
                   typeof globalThis.__exactTcpGetFd === 'function') {
          handleFd = globalThis.__exactTcpGetFd(sendHandle._handle._exactHandle);
        } else if (sendHandle._handle && typeof sendHandle._handle.fd === 'number') {
          handleFd = sendHandle._handle.fd;
        } else if (typeof sendHandle.fd === 'number') {
          handleFd = sendHandle.fd;
        } else if (typeof sendHandle._fd === 'number') {
          handleFd = sendHandle._fd;
        }
        if (sendHandle.type === 'udp4' || sendHandle.type === 'udp6') {
          handleType = 'dgram.Socket';
        } else if (sendHandle._exactServerHandle === true ||
                   (typeof sendHandle.close === 'function' && typeof sendHandle.onconnection === 'function')) {
          handleType = 'net.ServerHandle';
        } else {
          var handleName = sendHandle.constructor && sendHandle.constructor.name;
          if (handleName === 'Server') handleType = 'net.Server';
          else handleType = 'net.Socket';
        }
      }
      var packet = buildPacket('message', message, handleType);
      var written = writePacket(packet, handleFd);
      if (typeof callback === 'function') {
        setTimeout(function() {
          callback(written ? null : createIpcError('ERR_IPC_CHANNEL_CLOSED', 'IPC channel is closed'));
        }, 0);
      }
      return written;
    };
    process.disconnect = function() {
      if (!process.connected) {
        throw createIpcError('ERR_IPC_DISCONNECTED', 'IPC channel is already disconnected');
      }
      writePacket(buildPacket('disconnect'), -1);
      emitDisconnect();
    };
  }
  try {
    if (typeof globalThis.__exactInstallProcessIpcBootstrap === 'function') {
      globalThis.__exactInstallProcessIpcBootstrap();
    }
  } catch (_) {}
  installLateIpcChannel();
  if (!process.channel || typeof process.channel.ref !== 'function') return;
  if (process.__exactLateIpcListenerPatch) return;
  function refProcessChannel() {
    if (process.channel && typeof process.channel.ref === 'function') {
      process.channel.ref();
      return true;
    }
    return false;
  }
  function unrefProcessChannel() {
    if (process.channel && typeof process.channel.unref === 'function') {
      process.channel.unref();
      return true;
    }
    return false;
  }

  function syncIpcRef() {
    if (typeof process.listenerCount !== 'function') return;
    try {
      var activeListeners =
        process.listenerCount('message') +
        process.listenerCount('disconnect');
      if (activeListeners > 0) {
        refProcessChannel();
      } else {
        unrefProcessChannel();
      }
    } catch (_) {}
  }

  var trackedMessageListeners = 0;
  var trackedDisconnectListeners = 0;
  var originalTrackedListenerCount = null;
  function getTrackedIpcListeners(event) {
    if (event === 'message') return trackedMessageListeners;
    if (event === 'disconnect') return trackedDisconnectListeners;
    return trackedMessageListeners + trackedDisconnectListeners;
  }
  function seedTrackedIpcListeners(originalListenerCount) {
    if (typeof originalListenerCount !== 'function') {
      trackedMessageListeners = 0;
      trackedDisconnectListeners = 0;
      return;
    }
    try {
      trackedMessageListeners = originalListenerCount.call(process, 'message');
      trackedDisconnectListeners = originalListenerCount.call(process, 'disconnect');
      if (trackedMessageListeners < 0) trackedMessageListeners = 0;
      if (trackedDisconnectListeners < 0) trackedDisconnectListeners = 0;
    } catch (_) {
      trackedMessageListeners = 0;
      trackedDisconnectListeners = 0;
    }
  }
  function adjustTrackedIpcListeners(event, delta) {
    if (event === 'message') {
      trackedMessageListeners += delta;
      if (trackedMessageListeners < 0) trackedMessageListeners = 0;
    } else if (event === 'disconnect') {
      trackedDisconnectListeners += delta;
      if (trackedDisconnectListeners < 0) trackedDisconnectListeners = 0;
    }
  }
  function syncTrackedIpcRef() {
    if (getTrackedIpcListeners() > 0) {
      refProcessChannel();
    } else {
      unrefProcessChannel();
    }
  }
  function syncTrackedIpcListenersAfterDispatch() {
    if (typeof originalTrackedListenerCount !== 'function') {
      return;
    }
    try {
      var actualMessageListeners =
        originalTrackedListenerCount.call(process, 'message');
      var actualDisconnectListeners =
        originalTrackedListenerCount.call(process, 'disconnect');
      if (actualMessageListeners < trackedMessageListeners) {
        trackedMessageListeners = actualMessageListeners < 0 ? 0 : actualMessageListeners;
      }
      if (actualDisconnectListeners < trackedDisconnectListeners) {
        trackedDisconnectListeners = actualDisconnectListeners < 0 ? 0 : actualDisconnectListeners;
      }
      syncTrackedIpcRef();
    } catch (_) {}
  }

  function wrapTarget(target, markerName) {
    if (!target || target[markerName]) return;

    function defineMethod(name, fn) {
      try {
        Object.defineProperty(target, name, {
          value: fn,
          writable: true,
          configurable: true,
          enumerable: false,
        });
      } catch (_) {
        try {
          target[name] = fn;
        } catch (_) {}
      }
    }

    function shouldTrack(self, event) {
      return self === process &&
        (event === 'message' || event === 'disconnect');
    }

    if (typeof target.on === 'function') {
      var originalOn = target.on;
      defineMethod('on', function(event, listener) {
        var result = originalOn.apply(this, arguments);
        if (shouldTrack(this, event)) {
          refProcessChannel();
        }
        return result;
      });
    }

    if (typeof target.addListener === 'function') {
      var originalAddListener = target.addListener;
      defineMethod('addListener', function(event, listener) {
        var result = originalAddListener.apply(this, arguments);
        if (shouldTrack(this, event)) {
          refProcessChannel();
        }
        return result;
      });
    }

    if (typeof target.prependListener === 'function') {
      var originalPrependListener = target.prependListener;
      defineMethod('prependListener', function(event, listener) {
        var result = originalPrependListener.apply(this, arguments);
        if (shouldTrack(this, event)) {
          refProcessChannel();
        }
        return result;
      });
    }

    function wrapSingleUseListener(originalRegistrar) {
      return function(event, listener) {
        if (shouldTrack(this, event) && typeof listener === 'function') {
          refProcessChannel();
          var wrappedListener = function() {
            try {
              return listener.apply(this, arguments);
            } finally {
              syncIpcRef();
            }
          };
          try {
            wrappedListener.listener = listener;
          } catch (_) {}
          return originalRegistrar.call(this, event, wrappedListener);
        }
        var result = originalRegistrar.apply(this, arguments);
        if (shouldTrack(this, event)) {
          refProcessChannel();
        }
        return result;
      };
    }

    if (typeof target.once === 'function') {
      defineMethod('once', wrapSingleUseListener(target.once));
    }

    if (typeof target.prependOnceListener === 'function') {
      defineMethod('prependOnceListener',
        wrapSingleUseListener(target.prependOnceListener));
    }

    if (typeof target.removeListener === 'function') {
      var originalRemoveListener = target.removeListener;
      defineMethod('removeListener', function(event, listener) {
        var result = originalRemoveListener.apply(this, arguments);
        if (shouldTrack(this, event)) {
          syncIpcRef();
        }
        return result;
      });
    }

    if (typeof target.off === 'function') {
      var originalOff = target.off;
      defineMethod('off', function(event, listener) {
        var result = originalOff.apply(this, arguments);
        if (shouldTrack(this, event)) {
          syncIpcRef();
        }
        return result;
      });
    }

    if (typeof target.removeAllListeners === 'function') {
      var originalRemoveAllListeners = target.removeAllListeners;
      defineMethod('removeAllListeners', function(event) {
        var result = originalRemoveAllListeners.apply(this, arguments);
        if (this === process &&
            (event === undefined ||
             event === 'message' ||
             event === 'disconnect')) {
          syncIpcRef();
        }
        return result;
      });
    }

    try {
      Object.defineProperty(target, markerName, {
        value: true,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    } catch (_) {
      try {
        target[markerName] = true;
      } catch (_) {}
    }
  }

  wrapTarget(Object.getPrototypeOf(process), '__exactLateIpcProcessProtoWrapped');
  wrapTarget(process, '__exactLateIpcProcessWrapped');
  syncIpcRef();
  try {
    refProcessChannel();
    var startupHold = setTimeout(function() {
      syncIpcRef();
    }, 250);
    if (startupHold && typeof startupHold.ref === 'function') {
      startupHold.ref();
    }
  } catch (_) {}

  function installAsyncIpcListenerPatch() {
      if (process.__exactAsyncIpcListenerPatch) return;

      function trackEvent(event) {
        return event === 'message' || event === 'disconnect';
      }

      var originalListenerCount = typeof process.listenerCount === 'function' ?
        process.listenerCount :
        null;
      if (originalTrackedListenerCount === null) {
        originalTrackedListenerCount = originalListenerCount;
      }
      seedTrackedIpcListeners(originalListenerCount);

      if (typeof process.on === 'function') {
        var asyncOriginalOn = process.on;
        process.on = function(event, listener) {
          var result = asyncOriginalOn.apply(this, arguments);
          if (trackEvent(event)) {
            adjustTrackedIpcListeners(event, 1);
            syncTrackedIpcRef();
          }
          return result;
        };
        process.addListener = process.on;
      }

      if (typeof process.prependListener === 'function') {
        var asyncOriginalPrependListener = process.prependListener;
        process.prependListener = function(event, listener) {
          var result = asyncOriginalPrependListener.apply(this, arguments);
          if (trackEvent(event)) {
            adjustTrackedIpcListeners(event, 1);
            syncTrackedIpcRef();
          }
          return result;
        };
      }

      function wrapSingleUseListener(originalRegistrar) {
        return function(event, listener) {
          if (trackEvent(event) && typeof listener === 'function') {
            adjustTrackedIpcListeners(event, 1);
            syncTrackedIpcRef();
            var wrappedListener = function() {
              try {
                return listener.apply(this, arguments);
              } finally {
                adjustTrackedIpcListeners(event, -1);
                syncTrackedIpcRef();
              }
            };
            try {
              wrappedListener.listener = listener;
            } catch (_) {}
            return originalRegistrar.call(this, event, wrappedListener);
          }
          return originalRegistrar.apply(this, arguments);
        };
      }

      if (typeof process.once === 'function') {
        process.once = wrapSingleUseListener(process.once);
      }
      if (typeof process.prependOnceListener === 'function') {
        process.prependOnceListener =
          wrapSingleUseListener(process.prependOnceListener);
      }

      if (typeof process.removeListener === 'function') {
        var asyncOriginalRemoveListener = process.removeListener;
        process.removeListener = function(event, listener) {
          var result = asyncOriginalRemoveListener.apply(this, arguments);
          if (trackEvent(event)) {
            adjustTrackedIpcListeners(event, -1);
            syncTrackedIpcRef();
          }
          return result;
        };
        process.off = process.removeListener;
      }

      if (typeof process.removeAllListeners === 'function') {
        var asyncOriginalRemoveAllListeners = process.removeAllListeners;
        process.removeAllListeners = function(event) {
          var result = asyncOriginalRemoveAllListeners.apply(this, arguments);
          if (event === undefined) {
            trackedMessageListeners = 0;
            trackedDisconnectListeners = 0;
            syncTrackedIpcRef();
          } else if (trackEvent(event)) {
            if (event === 'message') {
              trackedMessageListeners = 0;
            } else if (event === 'disconnect') {
              trackedDisconnectListeners = 0;
            }
            syncTrackedIpcRef();
          }
          return result;
        };
      }

      if (originalListenerCount) {
        process.listenerCount = function(event) {
          if (trackEvent(event)) {
            return getTrackedIpcListeners(event);
          }
          return originalListenerCount.apply(this, arguments);
        };
      }

      if (Object.prototype.hasOwnProperty.call(process, 'on') &&
          Object.prototype.hasOwnProperty.call(process, 'removeListener')) {
        try {
          Object.defineProperty(process, '__exactAsyncIpcListenerPatch', {
            value: true,
            writable: false,
            configurable: true,
            enumerable: false,
          });
        } catch (_) {
          process.__exactAsyncIpcListenerPatch = true;
        }
      }
      syncTrackedIpcRef();
  }
  try {
    globalThis.__exactInstallAsyncIpcListenerPatch = installAsyncIpcListenerPatch;
    globalThis.__exactSyncTrackedIpcListenersAfterDispatch =
      syncTrackedIpcListenersAfterDispatch;
  } catch (_) {}

  if (typeof process.send === 'function') {
    var originalProcessSend = process.send;
    process.send = function() {
      installAsyncIpcListenerPatch();
      return originalProcessSend.apply(this, arguments);
    };
  }

  try {
    Object.defineProperty(process, '__exactLateIpcListenerPatch', {
      value: true,
      writable: false,
      configurable: true,
      enumerable: false,
    });
  } catch (_) {
    try {
      process.__exactLateIpcListenerPatch = true;
    } catch (_) {}
  }
})();