var EventEmitter = require('node:events').EventEmitter;

function resolveHeaderName(value) {
  if (typeof value !== 'string') {
    return String(value || '');
  }
  return value.toLowerCase();
}

function toHttpUrl(options) {
  if (typeof options === "string") {
    return options;
  }
  if (options === null || options === undefined) {
    throw new TypeError("Invalid request target");
  }
  if (typeof options === "object") {
    if (typeof options.toString === "function" && options instanceof Date) {
      return String(options);
    }
    if (typeof options.href === "string") return options.href;
    if (typeof options.url === "string") return options.url;
    var protocol = options.protocol || "http:";
    var hostname = options.hostname || options.host || "localhost";
    var port = options.port ? ":" + options.port : "";
    var path = options.path;
    if (path === undefined) {
      var pathname = options.pathname || "/";
      var search = options.search || "";
      var hash = options.hash || "";
      if (search && search.charAt(0) !== "?") {
        search = "?" + search;
      }
      if (hash && hash.charAt(0) !== '#') {
        hash = '#' + hash;
      }
      path = pathname + search + hash;
    }
    return protocol + "//" + hostname + port + path;
  }
  throw new TypeError("Invalid request target");
}

function toHttpPath(options) {
  if (!options) return "/";
  if (typeof options === "string") return "/";
  return options.path || options.pathname || "/";
}

function toMethod(options) {
  return ((options && options.method) || "GET").toUpperCase();
}

function toHeaders(source) {
  if (!source || typeof source !== "object") return {};
  var out = {};
  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      out[resolveHeaderName(key)] = String(source[key]);
    }
  }
  return out;
}

function parseHeaders(response) {
  var result = {};
  response.headers.forEach(function(value, key) {
    result[key] = value;
  });
  return result;
}

function toBuffer(value) {
  if (value == null) return null;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') {
    if (typeof Buffer !== 'undefined') return Buffer.from(value, 'utf8');
    return value;
  }
  return typeof Buffer !== 'undefined' ? Buffer.from(String(value), 'utf8') : String(value);
}

function isValidMethodStart(byte) {
  return (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || byte === 42;
}

function emitClientError(server, socket, rawPacket, bytesParsed) {
  var raw = toBuffer(rawPacket);
  var err = new Error('Parse Error: Invalid method encountered');
  err.code = 'HPE_INVALID_METHOD';
  err.rawPacket = raw || toBuffer('');
  err.bytesParsed = bytesParsed;
  if (server && typeof server.emit === 'function') {
    server.emit('clientError', err, socket);
  }
}

function parseInvalidClientRequest(server, socket, chunk) {
  if (!chunk || !chunk.length) return;
  if (!socket._exactHttpClientErrorState) return;
  var state = socket._exactHttpClientErrorState;
  if (state.done) return;

  var data = toBuffer(chunk);
  if (!data || !data.length) return;
  if (state.awaitingReplay) {
    emitClientError(server, socket, data, data.length);
    state.done = true;
    return;
  }

  if (isValidMethodStart(data[0])) {
    state.done = true;
    return;
  }

  emitClientError(server, socket, data.slice(0, 1), 1);
  var remaining = data.slice(1);
  if (remaining.length > 0) {
    emitClientError(server, socket, remaining, remaining.length);
    state.done = true;
  } else {
    state.awaitingReplay = true;
  }
}

function setupHttpClientErrorParsing(server, socket) {
  if (!socket || !socket.on) return;
  if (socket._exactHttpClientParserAttached) return;
  socket._exactHttpClientParserAttached = true;
  socket._exactHttpClientErrorState = { done: false, awaitingReplay: false };

  var onData = function(data) {
    parseInvalidClientRequest(server, socket, data);
    if (socket._exactHttpClientErrorState.done) {
      socket.removeListener('data', onData);
    }
  };

  socket.on('data', onData);
  var buffered = socket.read();
  if (buffered && buffered.length) {
    parseInvalidClientRequest(server, socket, buffered);
    if (socket._exactHttpClientErrorState.done) {
      socket.removeListener('data', onData);
    }
  }
}

function IncomingMessage(response) {
  EventEmitter.call(this);
  this.statusCode = response.status;
  this.statusMessage = response.statusText;
  this.headers = parseHeaders(response);
  this.rawHeaders = [];
  for (var key in this.headers) {
    this.rawHeaders.push(key, this.headers[key]);
  }
  this.httpVersion = "1.1";
  this._response = response;
  this._consumed = false;
}
IncomingMessage.prototype = Object.create(EventEmitter.prototype);
IncomingMessage.prototype.constructor = IncomingMessage;

IncomingMessage.prototype._consumeBody = function() {
  if (this._consumed) return;
  this._consumed = true;
  var self = this;
  var response = this._response;
  // Use streaming body if ReadableStream is available
  if (response.body && typeof response.body.getReader === 'function') {
    var reader = response.body.getReader();
    var decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null;
    function pump() {
      reader.read().then(function(result) {
        if (result.done) {
          self.emit("end");
          self.emit("close");
          return;
        }
        var chunk = result.value;
        // Convert Uint8Array to string if we have a decoder
        if (chunk instanceof Uint8Array && decoder) {
          self.emit("data", decoder.decode(chunk, { stream: true }));
        } else {
          self.emit("data", chunk);
        }
        pump();
      }).catch(function(err) {
        self.emit("error", err);
      });
    }
    pump();
  } else {
    // Fallback: buffer entire body
    response
      .text()
      .then(function(text) {
        if (text) self.emit("data", text);
        self.emit("end");
        self.emit("close");
      })
      .catch(function(err) {
        self.emit("error", err);
      });
  }
};
IncomingMessage.prototype.setEncoding = function() { return this; };
IncomingMessage.prototype.pause = function() { return this; };
IncomingMessage.prototype.resume = function() {
  this._consumeBody();
  return this;
};
IncomingMessage.prototype.read = function() {
  return null;
};
IncomingMessage.prototype.destroy = function() {
  this.emit("close");
  return this;
};

function ClientRequest(options, callback) {
  EventEmitter.call(this);
  this.options = options || {};
  this._url = toHttpUrl(this.options);
  this.method = toMethod(this.options);
  this.path = toHttpPath(this.options);
  this.headers = toHeaders(this.options.headers);
  this._bodyParts = [];
  this._ended = false;
  this._sent = false;
  this._closed = false;
  this._aborted = false;
  if (typeof callback === "function") {
    this.once("response", callback);
  }
}
ClientRequest.prototype = Object.create(EventEmitter.prototype);
ClientRequest.prototype.constructor = ClientRequest;

ClientRequest.prototype.setHeader = function(name, value) {
  this.headers[resolveHeaderName(name)] = String(value);
};

ClientRequest.prototype.getHeader = function(name) {
  return this.headers[resolveHeaderName(name)];
};

ClientRequest.prototype.removeHeader = function(name) {
  var key = resolveHeaderName(name);
  var value = this.headers[key];
  delete this.headers[key];
  return value;
};

ClientRequest.prototype.getHeaders = function() {
  var clone = {};
  for (var key in this.headers) {
    if (Object.prototype.hasOwnProperty.call(this.headers, key)) {
      clone[key] = this.headers[key];
    }
  }
  return clone;
};

ClientRequest.prototype.write = function(chunk) {
  if (chunk !== undefined && chunk !== null) {
    this._bodyParts.push(String(chunk));
  }
  return true;
};

ClientRequest.prototype.end = function(chunk) {
  if (this._ended) return;
  if (chunk !== undefined && chunk !== null) {
    this._bodyParts.push(String(chunk));
  }
  this._ended = true;
  this._send();
};

ClientRequest.prototype.destroy = function() {
  this._aborted = true;
  this._closed = true;
  if (this._abortController) {
    try { this._abortController.abort(); } catch(e) {}
  }
  this.emit("close");
  return this;
};
ClientRequest.prototype.abort = ClientRequest.prototype.destroy;

ClientRequest.prototype.setTimeout = function(timeout, callback) {
  if (typeof timeout === 'number' && timeout > 0) {
    var self = this;
    this._timeoutId = setTimeout(function() {
      self.emit('timeout');
    }, timeout);
    if (typeof callback === 'function') {
      this.once('timeout', callback);
    }
  }
  return this;
};

ClientRequest.prototype._send = function() {
  if (this._sent) return;
  this._sent = true;
  var body = this._bodyParts.join("");
  if (typeof fetch !== "function") {
    this.emit("error", new Error("fetch is not available"));
    this.emit("close");
    return;
  }
  var init = {
    method: this.method,
    headers: this.headers
  };
  if (this.method !== "GET" && this.method !== "HEAD") {
    init.body = body;
  }
  // Use AbortController for cancellation support
  if (typeof AbortController !== 'undefined') {
    this._abortController = new AbortController();
    init.signal = this._abortController.signal;
    if (this._aborted) {
      this._abortController.abort();
    }
  }
  var self = this;
  fetch(this._url, init)
    .then(function(response) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      var responseMessage = new IncomingMessage(response);
      self.emit("response", responseMessage);
      responseMessage._consumeBody();
    })
    .catch(function(err) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      if (self._aborted) return;
      self.emit("error", err);
      self.emit("close");
    });
};

function request(options, callback) {
  var requestOptions = options;
  if (typeof options === "string") {
    requestOptions = {
      href: options,
      method: "GET"
    };
  }
  return new ClientRequest(requestOptions, callback);
}

function get(options, callback) {
  var req = request(options, callback);
  req.end();
  return req;
}

function Agent(options) {
  this.options = options || {};
  this.maxSockets = this.options.maxSockets || Infinity;
  this.maxFreeSockets = this.options.maxFreeSockets || 256;
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
}
Agent.prototype.destroy = function() {};
Agent.prototype.getName = function(options) {
  return (options.host || 'localhost') + ':' + (options.port || 80);
};
var globalAgent = new Agent();

var METHODS = ["GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTIONS", "CONNECT", "TRACE"];
var STATUS_CODES = {
  100: "Continue",
  101: "Switching Protocols",
  102: "Processing",
  103: "Early Hints",
  200: "OK",
  201: "Created",
  202: "Accepted",
  203: "Non-Authoritative Information",
  204: "No Content",
  205: "Reset Content",
  206: "Partial Content",
  207: "Multi-Status",
  208: "Already Reported",
  226: "IM Used",
  300: "Multiple Choices",
  301: "Moved Permanently",
  302: "Found",
  303: "See Other",
  304: "Not Modified",
  305: "Use Proxy",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  402: "Payment Required",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  406: "Not Acceptable",
  407: "Proxy Authentication Required",
  408: "Request Timeout",
  409: "Conflict",
  410: "Gone",
  411: "Length Required",
  412: "Precondition Failed",
  413: "Payload Too Large",
  414: "URI Too Long",
  415: "Unsupported Media Type",
  416: "Range Not Satisfiable",
  417: "Expectation Failed",
  418: "I'm a Teapot",
  421: "Misdirected Request",
  422: "Unprocessable Entity",
  423: "Locked",
  424: "Failed Dependency",
  425: "Too Early",
  426: "Upgrade Required",
  428: "Precondition Required",
  429: "Too Many Requests",
  431: "Request Header Fields Too Large",
  451: "Unavailable For Legal Reasons",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
  505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates",
  507: "Insufficient Storage",
  508: "Loop Detected",
  510: "Not Extended",
  511: "Network Authentication Required"
};

// ServerResponse wraps the native HTTP respond functions
function ServerResponse(serverId, requestId) {
  EventEmitter.call(this);
  this.statusCode = 200;
  this.statusMessage = 'OK';
  this._headers = {};
  this._headersSent = false;
  this._finished = false;
  this._streaming = false;
  this._bodyParts = [];
  this._serverId = serverId;
  this._requestId = requestId;
  this.writableEnded = false;
  this.writableFinished = false;
}
ServerResponse.prototype = Object.create(EventEmitter.prototype);
ServerResponse.prototype.constructor = ServerResponse;

ServerResponse.prototype.setHeader = function(name, value) {
  this._headers[resolveHeaderName(name)] = String(value);
  return this;
};
ServerResponse.prototype.getHeader = function(name) {
  return this._headers[resolveHeaderName(name)];
};
ServerResponse.prototype.removeHeader = function(name) {
  delete this._headers[resolveHeaderName(name)];
  return this;
};
ServerResponse.prototype.getHeaders = function() {
  var clone = {};
  for (var k in this._headers) {
    if (Object.prototype.hasOwnProperty.call(this._headers, k)) clone[k] = this._headers[k];
  }
  return clone;
};
ServerResponse.prototype.hasHeader = function(name) {
  return resolveHeaderName(name) in this._headers;
};
ServerResponse.prototype.writeHead = function(statusCode, statusMessage, headers) {
  this.statusCode = statusCode;
  if (typeof statusMessage === 'string') {
    this.statusMessage = statusMessage;
  } else if (typeof statusMessage === 'object' && statusMessage !== null) {
    headers = statusMessage;
  }
  if (headers) {
    for (var k in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, k)) {
        this._headers[resolveHeaderName(k)] = String(headers[k]);
      }
    }
  }
  return this;
};
ServerResponse.prototype._ensureStreaming = function() {
  if (this._streaming) return true;
  if (typeof __exactHttpRespondStream !== 'function') return false;
  var headersJson = JSON.stringify(this._headers);
  var result = __exactHttpRespondStream(this._serverId, this._requestId, this.statusCode, headersJson);
  if (result === 0) { this._streaming = true; this._headersSent = true; return true; }
  return false;
};
ServerResponse.prototype._sendChunk = function(chunk) {
  if (typeof __exactHttpRespondChunk !== 'function') return;
  if (typeof chunk === 'string') {
    var encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
    var bytes = encoder ? encoder.encode(chunk) : null;
    if (bytes) __exactHttpRespondChunk(this._serverId, this._requestId, bytes);
  } else if (chunk) {
    __exactHttpRespondChunk(this._serverId, this._requestId, chunk);
  }
};
ServerResponse.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) callback(new Error('write after end')); return false; }
  if (chunk !== undefined && chunk !== null) {
    var data = typeof chunk === 'string' ? chunk : String(chunk);
    if (this._ensureStreaming()) { this._sendChunk(data); }
    else { this._bodyParts.push(data); }
  }
  if (callback) setTimeout(callback, 0);
  return true;
};
ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) setTimeout(callback, 0); return this; }
  if (chunk !== undefined && chunk !== null) this.write(chunk);
  this._finished = true;
  this.writableEnded = true;
  if (this._streaming) {
    if (typeof __exactHttpRespondEnd === 'function') __exactHttpRespondEnd(this._serverId, this._requestId);
    this.writableFinished = true;
    if (callback) setTimeout(callback, 0);
    this.emit('finish');
    this.emit('close');
  } else {
    this._sendResponse();
    if (callback) setTimeout(callback, 0);
  }
  return this;
};
ServerResponse.prototype._sendResponse = function() {
  var headersJson = JSON.stringify(this._headers);
  var body = this._bodyParts.join('');
  this._headersSent = true;
  if (typeof __exactHttpRespondString === 'function') {
    __exactHttpRespondString(this._serverId, this._requestId, this.statusCode, headersJson, body);
  } else if (typeof __exactHttpRespond === 'function') {
    var encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
    var bodyBytes = encoder ? encoder.encode(body) : null;
    __exactHttpRespond(this._serverId, this._requestId, this.statusCode, headersJson, bodyBytes);
  }
  this.writableFinished = true;
  this.emit('finish');
  this.emit('close');
};
ServerResponse.prototype.setTimeout = function() { return this; };
ServerResponse.prototype.flushHeaders = function() {};

// ServerIncomingMessage for server-side requests
function ServerIncomingMessage(requestData, serverId) {
  EventEmitter.call(this);
  this.method = requestData.method || 'GET';
  this.url = requestData.url || '/';
  this.httpVersion = '1.1';
  this.headers = {};
  this.rawHeaders = [];
  // Body arrives base64-encoded from native bridge, decode it
  var rawBody = requestData.body || '';
  if (rawBody) {
    if (typeof atob === 'function') {
      try { rawBody = atob(rawBody); } catch(e) {}
    } else {
      var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      var lookup = {};
      for (var ci = 0; ci < chars.length; ci++) lookup[chars[ci]] = ci;
      var b64 = rawBody.replace(/[^A-Za-z0-9+\/]/g, '');
      var decoded = '';
      for (var bi = 0; bi < b64.length; bi += 4) {
        var a = lookup[b64[bi]] || 0, b = lookup[b64[bi+1]] || 0;
        var c = lookup[b64[bi+2]] || 0, d = lookup[b64[bi+3]] || 0;
        decoded += String.fromCharCode((a << 2) | (b >> 4));
        if (b64[bi+2] !== '=') decoded += String.fromCharCode(((b & 15) << 4) | (c >> 2));
        if (b64[bi+3] !== '=') decoded += String.fromCharCode(((c & 3) << 6) | d);
      }
      rawBody = decoded;
    }
  }
  this._body = rawBody;
  this._consumed = false;
  this._serverId = serverId || 0;
  this._requestId = requestData.id || 0;
  if (requestData.headers) {
    if (Array.isArray(requestData.headers)) {
      for (var k = 0; k < requestData.headers.length; k++) {
        var pair = requestData.headers[k];
        if (!pair || pair.length < 2) continue;
        var lkPair = resolveHeaderName(pair[0]);
        this.headers[lkPair] = pair[1];
        this.rawHeaders.push(pair[0], pair[1]);
      }
    } else if (typeof requestData.headers === 'object') {
      for (var k in requestData.headers) {
        if (Object.prototype.hasOwnProperty.call(requestData.headers, k)) {
          var lk = resolveHeaderName(k);
          this.headers[lk] = requestData.headers[k];
          this.rawHeaders.push(k, requestData.headers[k]);
        }
      }
    }
  }
  this.complete = false;
  this.socket = { remoteAddress: '127.0.0.1', remotePort: 0 };
}
ServerIncomingMessage.prototype = Object.create(EventEmitter.prototype);
ServerIncomingMessage.prototype.constructor = ServerIncomingMessage;
ServerIncomingMessage.prototype.setEncoding = function() { return this; };
ServerIncomingMessage.prototype.pause = function() { return this; };
ServerIncomingMessage.prototype.resume = function() {
  if (this._consumed) return this;
  this._consumed = true;
  var self = this;
  self.complete = true;
  setTimeout(function() {
    if (self._body) self.emit('data', self._body);
    self.emit('end');
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.read = function() { return null; };
ServerIncomingMessage.prototype.destroy = function() {
  this.emit('close');
  return this;
};

// Server wraps exact:http native server infrastructure
function Server(requestListener) {
  EventEmitter.call(this);
  this._serverId = 0;
  this._listening = false;
  this._closing = false;
  this._requestListener = requestListener || null;
  var self = this;
  if (typeof requestListener === 'function') {
    this.on('request', requestListener);
  }
  this.on('connection', function(socket) {
    setupHttpClientErrorParsing(self, socket);
  });
}
Server.prototype = Object.create(EventEmitter.prototype);
Server.prototype.constructor = Server;

Server.prototype.listen = function(port, hostname, callback) {
  if (typeof port === 'object' && port !== null) {
    var opts = port;
    port = opts.port || 0;
    hostname = opts.host || opts.hostname || '0.0.0.0';
    callback = hostname;
    if (typeof hostname === 'function') {
      callback = hostname;
      hostname = '0.0.0.0';
    }
  }
  if (typeof hostname === 'function') {
    callback = hostname;
    hostname = '0.0.0.0';
  }
  port = port || 0;
  hostname = hostname || '0.0.0.0';

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  if (typeof __exactHttpServe !== 'function') {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('HTTP server not available')); }, 0);
    return this;
  }

  var resultJson = __exactHttpServe(port, hostname);
  var result;
  try { result = JSON.parse(resultJson); } catch(e) {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('Server start failed')); }, 0);
    return this;
  }

  if (result.error) {
    var self = this;
    var errMsg = result.error;
    setTimeout(function() { self.emit('error', new Error(errMsg)); }, 0);
    return this;
  }

  this._serverId = result.id;
  this._port = result.port || port;
  this._hostname = hostname;
  this._listening = true;

  var self = this;
  setTimeout(function() { self.emit('listening'); }, 0);

  // Start request polling loop
  this._pollLoop();
  return this;
};

Server.prototype._pollLoop = function() {
  if (this._closing || !this._listening) return;
  var self = this;

  function poll() {
    if (self._closing || !self._listening) return;

    // Try synchronous poll first
    var json = null;
    if (typeof __exactHttpPoll === 'function') {
      json = __exactHttpPoll(self._serverId);
    }

    if (json) {
      self._handleRequest(json);
      // Continue polling immediately
      setTimeout(poll, 0);
    } else if (typeof __exactHttpWait === 'function') {
      // Async wait
      __exactHttpWait(self._serverId, 1000).then(function(waitJson) {
        if (waitJson) self._handleRequest(waitJson);
        setTimeout(poll, 0);
      }).catch(function() {
        setTimeout(poll, 50);
      });
    } else {
      setTimeout(poll, 50);
    }
  }

  poll();
};

Server.prototype._handleRequest = function(json) {
  var data;
  try { data = JSON.parse(json); } catch(e) { return; }

  var req = new ServerIncomingMessage(data, this._serverId);
  var res = new ServerResponse(this._serverId, data.id || 0);

  // Auto-consume body for data events
  if (req.listenerCount && req.listenerCount('data') > 0) {
    req.resume();
  }

  this.emit('request', req, res);
};

Server.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._closing = true;
  this._listening = false;
  if (typeof __exactHttpClose === 'function' && this._serverId) {
    __exactHttpClose(this._serverId, 0);
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
  return this;
};

Server.prototype.address = function() {
  if (!this._listening) return null;
  if (typeof __exactHttpAddress === 'function') {
    var json = __exactHttpAddress(this._serverId);
    if (json) {
      try { return JSON.parse(json); } catch(e) {}
    }
  }
  return { address: this._hostname || '0.0.0.0', family: 'IPv4', port: this._port || 0 };
};

Server.prototype.setTimeout = function() { return this; };
Server.prototype.ref = function() {
  if (typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 1);
  }
  return this;
};
Server.prototype.unref = function() {
  if (typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 0);
  }
  return this;
};

function createServer(options, requestListener) {
  if (typeof options === 'function') {
    requestListener = options;
    options = {};
  }
  return new Server(requestListener);
}

module.exports = {
  request: request,
  get: get,
  Agent: Agent,
  createServer: createServer,
  Server: Server,
  ServerResponse: ServerResponse,
  IncomingMessage: IncomingMessage,
  ClientRequest: ClientRequest,
  METHODS: METHODS,
  STATUS_CODES: STATUS_CODES,
  globalAgent: globalAgent
};
