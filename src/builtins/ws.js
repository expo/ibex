var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events) this._events = {}; if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } w.listener = fn; this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { if (!this._events) this._events = {}; var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (!this._events) this._events = {}; if (e) delete this._events[e]; else this._events = {}; return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.listeners = function(e) { if (!this._events) this._events = {}; return (this._events[e] || []).slice(); };
  EventEmitter.prototype.listenerCount = function(e) { if (!this._events) this._events = {}; return (this._events[e] || []).length; };
}

var _hasTcp = typeof __exactTcpListen === 'function';

// ========================================================
// WebSocket frame constants
// ========================================================
var OPCODE_CONTINUATION = 0x0;
var OPCODE_TEXT = 0x1;
var OPCODE_BINARY = 0x2;
var OPCODE_CLOSE = 0x8;
var OPCODE_PING = 0x9;
var OPCODE_PONG = 0xA;

var WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

var READY_CONNECTING = 0;
var READY_OPEN = 1;
var READY_CLOSING = 2;
var READY_CLOSED = 3;

// ========================================================
// Utility: convert hex string to raw binary string
// ========================================================
function hexToRaw(hex) {
  var raw = '';
  for (var i = 0; i < hex.length; i += 2) {
    raw += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return raw;
}

function _toBinaryString(data) {
  if (typeof data === 'string') return data;
  if (!data || typeof data.length !== 'number') return '';
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    return data.toString('binary');
  }
  var out = '';
  for (var i = 0; i < data.length; i++) {
    out += String.fromCharCode(data[i] & 0xFF);
  }
  return out;
}

// ========================================================
// Utility: compute Sec-WebSocket-Accept value
// ========================================================
function computeAcceptKey(key) {
  var input = key + WS_GUID;
  if (typeof __exactHashSync === 'function') {
    var hex = __exactHashSync('sha1', input);
    var raw = hexToRaw(hex);
    if (typeof btoa === 'function') return btoa(raw);
  }
  // Fallback: if no native hash, try crypto module
  try {
    var crypto = require('crypto');
    return crypto.createHash('sha1').update(input).digest('base64');
  } catch(e) {}
  return '';
}

// ========================================================
// Utility: encode a WebSocket frame (server->client, no mask)
// ========================================================
function encodeFrame(opcode, payload, fin) {
  if (fin === undefined) fin = true;
  var payloadBytes;
  if (typeof payload === 'string') {
    payloadBytes = [];
    if (typeof TextEncoder !== 'undefined') {
      var encoded = new TextEncoder().encode(payload);
      for (var i = 0; i < encoded.length; i++) payloadBytes.push(encoded[i]);
    } else {
      for (var i = 0; i < payload.length; i++) {
        var c = payload.charCodeAt(i);
        if (c < 0x80) {
          payloadBytes.push(c);
        } else if (c < 0x800) {
          payloadBytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
        } else {
          payloadBytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
        }
      }
    }
  } else if (payload instanceof Uint8Array) {
    payloadBytes = [];
    for (var i = 0; i < payload.length; i++) payloadBytes.push(payload[i]);
  } else if (Array.isArray(payload)) {
    payloadBytes = payload;
  } else {
    payloadBytes = [];
  }

  var len = payloadBytes.length;
  var header = [];
  header.push((fin ? 0x80 : 0) | (opcode & 0x0F));

  if (len < 126) {
    header.push(len);
  } else if (len < 65536) {
    header.push(126);
    header.push((len >> 8) & 0xFF);
    header.push(len & 0xFF);
  } else {
    header.push(127);
    header.push(0); header.push(0); header.push(0); header.push(0);
    header.push((len >> 24) & 0xFF);
    header.push((len >> 16) & 0xFF);
    header.push((len >> 8) & 0xFF);
    header.push(len & 0xFF);
  }

  var frame = '';
  for (var i = 0; i < header.length; i++) frame += String.fromCharCode(header[i]);
  for (var i = 0; i < payloadBytes.length; i++) frame += String.fromCharCode(payloadBytes[i]);
  return frame;
}

// ========================================================
// Utility: parse WebSocket frames from a buffer (string of raw bytes)
// ========================================================
function parseFrames(buffer) {
  var frames = [];
  var pos = 0;

  while (pos < buffer.length) {
    if (pos + 2 > buffer.length) break;

    var b0 = buffer.charCodeAt(pos);
    var b1 = buffer.charCodeAt(pos + 1);
    var fin = (b0 & 0x80) !== 0;
    var opcode = b0 & 0x0F;
    var masked = (b1 & 0x80) !== 0;
    var payloadLen = b1 & 0x7F;
    var headerLen = 2;

    if (payloadLen === 126) {
      if (pos + 4 > buffer.length) break;
      payloadLen = (buffer.charCodeAt(pos + 2) << 8) | buffer.charCodeAt(pos + 3);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (pos + 10 > buffer.length) break;
      payloadLen = (buffer.charCodeAt(pos + 6) << 24) |
                   (buffer.charCodeAt(pos + 7) << 16) |
                   (buffer.charCodeAt(pos + 8) << 8) |
                   buffer.charCodeAt(pos + 9);
      headerLen = 10;
    }

    var maskLen = masked ? 4 : 0;
    var totalLen = headerLen + maskLen + payloadLen;
    if (pos + totalLen > buffer.length) break;

    var maskKey = null;
    if (masked) {
      maskKey = [
        buffer.charCodeAt(pos + headerLen),
        buffer.charCodeAt(pos + headerLen + 1),
        buffer.charCodeAt(pos + headerLen + 2),
        buffer.charCodeAt(pos + headerLen + 3)
      ];
    }

    var payloadStart = pos + headerLen + maskLen;
    var payload = new Uint8Array(payloadLen);
    for (var i = 0; i < payloadLen; i++) {
      var byte = buffer.charCodeAt(payloadStart + i);
      if (masked) {
        byte = byte ^ maskKey[i % 4];
      }
      payload[i] = byte;
    }

    frames.push({ fin: fin, opcode: opcode, masked: masked, payload: payload });
    pos += totalLen;
  }

  return { frames: frames, remainder: buffer.substring(pos) };
}

// ========================================================
// WebSocket (server-side connection) - compatible with ws package API
// ========================================================
function WebSocketConnection(tcpHandle, req) {
  if (!(this instanceof WebSocketConnection)) return new WebSocketConnection(tcpHandle, req);
  this._events = {};
  this._handle = tcpHandle;
  this._readyState = READY_OPEN;
  this._buffer = '';
  this._pollTimer = null;
  this._fragments = [];
  this._fragmentOpcode = 0;
  this.protocol = '';
  this.extensions = '';
  this.bufferedAmount = 0;
  this._req = req || null;
  this._closeFrameSent = false;
  this._closeFrameReceived = false;
  this._binaryType = 'nodebuffer';

  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }

  this._startReading();
}

Object.defineProperty(WebSocketConnection.prototype, 'readyState', {
  get: function() { return this._readyState; },
  enumerable: true
});

Object.defineProperty(WebSocketConnection.prototype, 'binaryType', {
  get: function() { return this._binaryType; },
  set: function(val) { this._binaryType = val; },
  enumerable: true
});

WebSocketConnection.CONNECTING = READY_CONNECTING;
WebSocketConnection.OPEN = READY_OPEN;
WebSocketConnection.CLOSING = READY_CLOSING;
WebSocketConnection.CLOSED = READY_CLOSED;

WebSocketConnection.prototype.CONNECTING = READY_CONNECTING;
WebSocketConnection.prototype.OPEN = READY_OPEN;
WebSocketConnection.prototype.CLOSING = READY_CLOSING;
WebSocketConnection.prototype.CLOSED = READY_CLOSED;

WebSocketConnection.prototype._startReading = function() {
  if (this._pollTimer != null) return;
  var self = this;

  function poll() {
    if (self._readyState === READY_CLOSED || self._handle == null) return;
    try {
      var data = __exactTcpRead(self._handle, 65536);
      if (data === null) {
        self._handleTransportClose();
        return;
      }
      data = _toBinaryString(data);
      if (data.length > 0) {
        self._buffer += data;
        self._processBuffer();
      }
    } catch(e) {
      if (self._readyState !== READY_CLOSED) {
        self.emit('error', e);
        self._handleTransportClose();
      }
      return;
    }
    self._pollTimer = setTimeout(poll, 5);
  }
  self._pollTimer = setTimeout(poll, 0);
};

WebSocketConnection.prototype._processBuffer = function() {
  var result = parseFrames(this._buffer);
  this._buffer = result.remainder;

  for (var i = 0; i < result.frames.length; i++) {
    this._handleFrame(result.frames[i]);
  }
};

WebSocketConnection.prototype._handleFrame = function(frame) {
  switch (frame.opcode) {
    case OPCODE_TEXT:
    case OPCODE_BINARY:
      if (frame.fin) {
        if (this._fragments.length > 0) {
          this._fragments = [];
        }
        this._deliverMessage(frame.opcode, frame.payload);
      } else {
        this._fragments = [frame.payload];
        this._fragmentOpcode = frame.opcode;
      }
      break;

    case OPCODE_CONTINUATION:
      this._fragments.push(frame.payload);
      if (frame.fin) {
        var totalLen = 0;
        for (var j = 0; j < this._fragments.length; j++) totalLen += this._fragments[j].length;
        var combined = new Uint8Array(totalLen);
        var offset = 0;
        for (var j = 0; j < this._fragments.length; j++) {
          combined.set(this._fragments[j], offset);
          offset += this._fragments[j].length;
        }
        var op = this._fragmentOpcode;
        this._fragments = [];
        this._fragmentOpcode = 0;
        this._deliverMessage(op, combined);
      }
      break;

    case OPCODE_CLOSE:
      this._closeFrameReceived = true;
      var code = 1005;
      var reason = '';
      if (frame.payload.length >= 2) {
        code = (frame.payload[0] << 8) | frame.payload[1];
        if (frame.payload.length > 2) {
          var reasonBytes = frame.payload.slice(2);
          if (typeof TextDecoder !== 'undefined') {
            reason = new TextDecoder().decode(reasonBytes);
          } else {
            for (var j = 0; j < reasonBytes.length; j++) reason += String.fromCharCode(reasonBytes[j]);
          }
        }
      }
      if (!this._closeFrameSent) {
        var closePayload = [];
        if (frame.payload.length >= 2) {
          closePayload.push(frame.payload[0]);
          closePayload.push(frame.payload[1]);
        }
        this._sendFrame(OPCODE_CLOSE, closePayload);
        this._closeFrameSent = true;
      }
      this._readyState = READY_CLOSED;
      if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
      try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
      this._handle = null;
      this.emit('close', code, reason);
      break;

    case OPCODE_PING:
      this._sendFrame(OPCODE_PONG, frame.payload);
      this.emit('ping', frame.payload);
      break;

    case OPCODE_PONG:
      this.emit('pong', frame.payload);
      break;
  }
};

WebSocketConnection.prototype._deliverMessage = function(opcode, payload) {
  if (opcode === OPCODE_TEXT) {
    var text;
    if (typeof TextDecoder !== 'undefined') {
      text = new TextDecoder().decode(payload);
    } else {
      text = '';
      for (var i = 0; i < payload.length; i++) text += String.fromCharCode(payload[i]);
    }
    this.emit('message', text, false);
  } else {
    if (this._binaryType === 'arraybuffer') {
      this.emit('message', payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength), true);
    } else if (this._binaryType === 'fragments') {
      this.emit('message', [payload], true);
    } else {
      if (typeof Buffer !== 'undefined' && Buffer.from) {
        this.emit('message', Buffer.from(payload), true);
      } else {
        this.emit('message', payload, true);
      }
    }
  }
};

WebSocketConnection.prototype._handleTransportClose = function() {
  if (this._readyState === READY_CLOSED) return;
  this._readyState = READY_CLOSED;
  if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
  try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
  this._handle = null;
  this.emit('close', 1006, '');
};

WebSocketConnection.prototype._sendFrame = function(opcode, payload) {
  if (this._handle == null) return;
  var frame = encodeFrame(opcode, payload);
  try {
    __exactTcpWrite(this._handle, frame);
  } catch(e) {
    this.emit('error', e);
  }
};

WebSocketConnection.prototype.send = function(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  options = options || {};
  if (this._readyState !== READY_OPEN) {
    var err = new Error('WebSocket is not open: readyState ' + this._readyState);
    if (typeof callback === 'function') { callback(err); return; }
    throw err;
  }

  var opcode;
  var payload;

  if (typeof data === 'string') {
    opcode = options.binary ? OPCODE_BINARY : OPCODE_TEXT;
    payload = data;
  } else if (data instanceof Uint8Array) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = data;
  } else if (data instanceof ArrayBuffer) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = new Uint8Array(data);
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = new Uint8Array(data.buffer || data, data.byteOffset || 0, data.length);
  } else if (data == null) {
    opcode = OPCODE_TEXT;
    payload = '';
  } else {
    opcode = OPCODE_TEXT;
    payload = String(data);
  }

  var fin = options.fin !== false;
  this._sendFrame(opcode, payload, fin);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.close = function(code, reason) {
  if (this._readyState === READY_CLOSED || this._readyState === READY_CLOSING) return;
  this._readyState = READY_CLOSING;
  code = code || 1000;
  reason = reason || '';

  var payload = [];
  payload.push((code >> 8) & 0xFF);
  payload.push(code & 0xFF);
  if (reason) {
    if (typeof TextEncoder !== 'undefined') {
      var encoded = new TextEncoder().encode(reason);
      for (var i = 0; i < encoded.length; i++) payload.push(encoded[i]);
    } else {
      for (var i = 0; i < reason.length; i++) payload.push(reason.charCodeAt(i));
    }
  }
  this._closeFrameSent = true;
  this._sendFrame(OPCODE_CLOSE, payload);

  var self = this;
  setTimeout(function() {
    if (self._readyState !== READY_CLOSED) {
      self._handleTransportClose();
    }
  }, 5000);
};

WebSocketConnection.prototype.ping = function(data, mask, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof mask === 'function') { callback = mask; mask = undefined; }
  if (this._readyState !== READY_OPEN) return;
  this._sendFrame(OPCODE_PING, data || []);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.pong = function(data, mask, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof mask === 'function') { callback = mask; mask = undefined; }
  if (this._readyState !== READY_OPEN) return;
  this._sendFrame(OPCODE_PONG, data || []);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.terminate = function() {
  if (this._readyState === READY_CLOSED) return;
  this._readyState = READY_CLOSED;
  if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
  try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
  this._handle = null;
  this.emit('close', 1006, '');
};

// ========================================================
// WebSocket.Server (ws-compatible)
// ========================================================
function WebSocketServer(options, callback) {
  if (!(this instanceof WebSocketServer)) return new WebSocketServer(options, callback);
  options = options || {};
  this._events = {};
  this.clients = new Set();
  this._path = options.path || null;
  this._noServer = options.noServer || false;
  this._server = options.server || null;
  this._handle = null;
  this._acceptTimer = null;
  this._port = options.port || 0;
  this._host = options.host || '0.0.0.0';
  this._listening = false;

  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  if (this._noServer) {
    return;
  }

  if (this._server) {
    var self = this;
    this._server.on('upgrade', function(req, socket, head) {
      self.handleUpgrade(req, socket, head, function(ws) {
        self.emit('connection', ws, req);
      });
    });
    this._listening = true;
    var s = this;
    setTimeout(function() { s.emit('listening'); }, 0);
    return;
  }

  if (!_hasTcp) {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('TCP not available')); }, 0);
    return;
  }

  var self = this;
  setTimeout(function() {
    try {
      self._handle = __exactTcpListen(self._host, self._port, 128);
      try {
        var info = __exactTcpLocalAddr(self._handle);
        if (info) {
          var addr = JSON.parse(info);
          self._port = addr.port;
          self._host = addr.address;
        }
      } catch(e) {}
      self._listening = true;
      self.emit('listening');
      self._startAccepting();
    } catch(e) {
      self.emit('error', e);
    }
  }, 0);
}

WebSocketServer.prototype._startAccepting = function() {
  if (this._acceptTimer != null) return;
  var self = this;

  function acceptLoop() {
    if (!self._listening || self._handle == null) return;
    try {
      var clientHandle = __exactTcpAccept(self._handle);
      if (clientHandle !== -1) {
        self._handleRawConnection(clientHandle);
      }
    } catch(e) {
      if (self._listening) self.emit('error', e);
      return;
    }
    self._acceptTimer = setTimeout(acceptLoop, 10);
  }
  self._acceptTimer = setTimeout(acceptLoop, 0);
};

WebSocketServer.prototype._handleRawConnection = function(tcpHandle) {
  var self = this;
  var buffer = '';
  var attempts = 0;
  var maxAttempts = 200;

  function readHeader() {
    if (attempts++ > maxAttempts) {
      try { __exactTcpClose(tcpHandle); } catch(e) {}
      return;
    }
    try {
      var data = __exactTcpRead(tcpHandle, 65536);
      if (data === null) {
        try { __exactTcpClose(tcpHandle); } catch(e) {}
        return;
      }
      data = _toBinaryString(data);
      if (data.length > 0) {
        buffer += data;
      }
      var headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd !== -1) {
        var headerStr = buffer.substring(0, headerEnd);
        var body = buffer.substring(headerEnd + 4);
        var req = parseHttpRequest(headerStr);
        if (req && isUpgradeRequest(req)) {
          self._completeUpgrade(tcpHandle, req, body);
        } else {
          var response = 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          try { __exactTcpWrite(tcpHandle, response); } catch(e) {}
          try { __exactTcpClose(tcpHandle); } catch(e) {}
        }
        return;
      }
    } catch(e) {
      try { __exactTcpClose(tcpHandle); } catch(e2) {}
      return;
    }
    setTimeout(readHeader, 10);
  }
  readHeader();
};

WebSocketServer.prototype._completeUpgrade = function(tcpHandle, req, remainingData) {
  var key = req.headers['sec-websocket-key'];
  if (!key) {
    var response = 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n';
    try { __exactTcpWrite(tcpHandle, response); } catch(e) {}
    try { __exactTcpClose(tcpHandle); } catch(e) {}
    return;
  }

  var acceptKey = computeAcceptKey(key);
  var responseHeaders = 'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
    '\r\n';

  try {
    __exactTcpWrite(tcpHandle, responseHeaders);
  } catch(e) {
    try { __exactTcpClose(tcpHandle); } catch(e2) {}
    return;
  }

  var ws = new WebSocketConnection(tcpHandle, req);
  if (remainingData && remainingData.length > 0) {
    ws._buffer += remainingData;
    ws._processBuffer();
  }
  this.clients.add(ws);
  var self = this;
  ws.on('close', function() {
    self.clients.delete(ws);
  });
  this.emit('connection', ws, req);
};

WebSocketServer.prototype.handleUpgrade = function(req, socket, head, callback) {
  var tcpHandle = null;

  if (socket && typeof socket._handle === 'number') {
    tcpHandle = socket._handle;
    if (socket._pollTimer != null) {
      clearTimeout(socket._pollTimer);
      socket._pollTimer = null;
    }
    socket._handle = null;
    socket.destroyed = true;
  } else if (typeof socket === 'number') {
    tcpHandle = socket;
  } else if (socket && socket._handle != null) {
    tcpHandle = socket._handle;
    if (socket._pollTimer != null) {
      clearTimeout(socket._pollTimer);
      socket._pollTimer = null;
    }
    socket._handle = null;
  }

  if (tcpHandle == null) {
    if (typeof callback === 'function') callback(null);
    return;
  }

  var headers = {};
  if (req && req.headers) {
    headers = req.headers;
  }

  var key = headers['sec-websocket-key'];
  if (!key) {
    try { __exactTcpClose(tcpHandle); } catch(e) {}
    if (typeof callback === 'function') callback(null);
    return;
  }

  var acceptKey = computeAcceptKey(key);
  var responseHeaders = 'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
    '\r\n';

  try {
    __exactTcpWrite(tcpHandle, responseHeaders);
  } catch(e) {
    try { __exactTcpClose(tcpHandle); } catch(e2) {}
    if (typeof callback === 'function') callback(null);
    return;
  }

  var ws = new WebSocketConnection(tcpHandle, req);
  if (head && head.length > 0) {
    var headStr = '';
    if (typeof head === 'string') {
      headStr = head;
    } else if (head instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(head))) {
      for (var i = 0; i < head.length; i++) headStr += String.fromCharCode(head[i]);
    }
    if (headStr.length > 0) {
      ws._buffer += headStr;
      ws._processBuffer();
    }
  }
  this.clients.add(ws);
  var self = this;
  ws.on('close', function() {
    self.clients.delete(ws);
  });

  if (typeof callback === 'function') callback(ws);
};

WebSocketServer.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._listening = false;
  if (this._acceptTimer != null) {
    clearTimeout(this._acceptTimer);
    this._acceptTimer = null;
  }
  if (this._handle != null && _hasTcp) {
    try { __exactTcpClose(this._handle); } catch(e) {}
    this._handle = null;
  }
  var clientsArr = [];
  this.clients.forEach(function(ws) { clientsArr.push(ws); });
  for (var i = 0; i < clientsArr.length; i++) {
    try { clientsArr[i].terminate(); } catch(e) {}
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
};

WebSocketServer.prototype.address = function() {
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this._host || '0.0.0.0', port: this._port || 0, family: 'IPv4' };
};

// ========================================================
// HTTP request parsing helper
// ========================================================
function parseHttpRequest(headerStr) {
  var lines = headerStr.split('\r\n');
  if (lines.length < 1) return null;

  var requestLine = lines[0].split(' ');
  if (requestLine.length < 3) return null;

  var method = requestLine[0];
  var url = requestLine[1];
  var httpVersion = requestLine[2];

  var headers = {};
  for (var i = 1; i < lines.length; i++) {
    var line = lines[i];
    var colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    var name = line.substring(0, colonIdx).trim().toLowerCase();
    var value = line.substring(colonIdx + 1).trim();
    headers[name] = value;
  }

  return {
    method: method,
    url: url,
    httpVersion: httpVersion,
    headers: headers
  };
}

function isUpgradeRequest(req) {
  return req.headers['upgrade'] &&
         req.headers['upgrade'].toLowerCase() === 'websocket' &&
         req.headers['sec-websocket-key'];
}

// ========================================================
// Exports (ws-package compatible)
// ========================================================
var WS = WebSocketConnection;
WS.WebSocket = WebSocketConnection;
WS.WebSocketServer = WebSocketServer;
WS.Server = WebSocketServer;
WS.createWebSocketStream = function() {
  throw new Error('createWebSocketStream is not yet implemented');
};
WS.CONNECTING = READY_CONNECTING;
WS.OPEN = READY_OPEN;
WS.CLOSING = READY_CLOSING;
WS.CLOSED = READY_CLOSED;

module.exports = WS;
module.exports.default = WS;
module.exports.WebSocket = WebSocketConnection;
module.exports.WebSocketServer = WebSocketServer;
module.exports.Server = WebSocketServer;
