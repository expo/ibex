var EventEmitter = require('node:events').EventEmitter;

// Shared symbol for timeout tracking (matches internal/timers)
var kTimeout = Symbol.for('kTimeout');

function resolveHeaderName(value) {
  if (typeof value !== 'string') {
    return String(value || '');
  }
  return value.toLowerCase();
}

// Convert a lowercase header name to HTTP title case (e.g. content-length -> Content-Length)
function toHeaderCase(name) {
  return name.replace(/(?:^|-)([a-z])/g, function(match, letter, offset) {
    return offset === 0 ? letter.toUpperCase() : '-' + letter.toUpperCase();
  });
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

  // Prefer the raw TCP path for plain HTTP to preserve Node-like behavior for
  // local servers (fetch can block loopback requests in this runtime).
  var useFetch = typeof fetch === "function";
  if (useFetch) {
    try {
      var parsedUrl = new URL(this._url);
      if (parsedUrl.protocol === "http:") {
        useFetch = false;
      }
    } catch (_err) {}
  }

  if (useFetch) {
    this._sendViaFetch(body);
  } else {
    this._sendViaTcp(body);
  }
};

ClientRequest.prototype._sendViaFetch = function(body) {
  var init = {
    method: this.method,
    headers: this.headers
  };
  if (this.method !== "GET" && this.method !== "HEAD") {
    init.body = body;
  }
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

ClientRequest.prototype._sendViaTcp = function(body) {
  var net;
  try { net = require('net'); } catch(e) {
    this.emit("error", new Error("Neither fetch nor net module available"));
    this.emit("close");
    return;
  }
  var self = this;
  var options = (this.options && typeof this.options === 'object') ? this.options : {};
  var host = options.hostname || options.host;
  var port = options.port;
  if (!host || !port) {
    try {
      var parsed = new URL(this._url);
      if (!host) host = parsed.hostname;
      if (!port) {
        if (parsed.port) {
          port = Number(parsed.port);
        } else {
          port = parsed.protocol === 'https:' ? 443 : 80;
        }
      }
      if ((!options.path || options.path === '/') && parsed.pathname) {
        this.path = parsed.pathname + (parsed.search || '');
      }
    } catch (_err) {}
  }
  if (!host) host = 'localhost';
  if (!port) port = 80;

  // Build raw HTTP request
  var reqLine = this.method + ' ' + this.path + ' HTTP/1.1\r\n';
  var headerStr = '';
  if (!this.headers['host']) {
    headerStr += 'Host: ' + host + (port !== 80 ? ':' + port : '') + '\r\n';
  }
  for (var k in this.headers) {
    if (Object.prototype.hasOwnProperty.call(this.headers, k)) {
      headerStr += k + ': ' + this.headers[k] + '\r\n';
    }
  }
  if (body && this.method !== 'GET' && this.method !== 'HEAD') {
    var bodyLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
      ? Buffer.byteLength(body) : body.length;
    headerStr += 'content-length: ' + bodyLen + '\r\n';
  }
  if (!this.headers['connection']) {
    headerStr += 'Connection: close\r\n';
  }
  headerStr += '\r\n';

  var rawRequest = reqLine + headerStr;
  if (body && this.method !== 'GET' && this.method !== 'HEAD') {
    rawRequest += body;
  }

  var socket = net.createConnection({ host: host, port: port }, function() {
    socket.write(rawRequest);
  });

  self.socket = socket;

  // Parse HTTP response
  var responseBuffer = '';
  var headersParsed = false;
  var statusCode = 200;
  var statusMessage = 'OK';
  var responseHeaders = {};
  var rawResponseHeaders = [];
  var contentLength = -1;
  var bodyBytesReceived = 0;
  var responseEmitted = false;
  var responseEnded = false;
  var tcpIncoming = null;

  function finishResponse() {
    if (responseEnded) return;
    responseEnded = true;
    if (tcpIncoming) {
      tcpIncoming.emit('end');
      tcpIncoming.emit('close');
    }
    try { socket.destroy(); } catch(e) {}
  }

  socket.on('data', function(chunk) {
    var str = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    responseBuffer += str;

    if (!headersParsed) {
      var headerEnd = responseBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      var headerSection = responseBuffer.substring(0, headerEnd);
      var bodyStart = responseBuffer.substring(headerEnd + 4);
      headersParsed = true;

      var lines = headerSection.split('\r\n');
      if (lines.length > 0) {
        var statusLine = lines[0];
        var statusParts = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)/);
        if (statusParts) {
          statusCode = parseInt(statusParts[1], 10);
          statusMessage = statusParts[2] || '';
        }
      }
      for (var i = 1; i < lines.length; i++) {
        var colonIdx = lines[i].indexOf(':');
        if (colonIdx > 0) {
          var hKey = lines[i].substring(0, colonIdx).trim();
          var hVal = lines[i].substring(colonIdx + 1).trim();
          responseHeaders[hKey.toLowerCase()] = hVal;
          rawResponseHeaders.push(hKey, hVal);
        }
      }
      var cl = responseHeaders['content-length'];
      if (cl !== undefined) contentLength = parseInt(cl, 10) || 0;

      tcpIncoming = new TcpIncomingMessage(statusCode, statusMessage, responseHeaders, rawResponseHeaders);
      self.emit('response', tcpIncoming);
      responseEmitted = true;

      if (bodyStart.length > 0) {
        bodyBytesReceived += bodyStart.length;
        tcpIncoming.emit('data', bodyStart);
      }
      if (contentLength >= 0 && bodyBytesReceived >= contentLength) {
        finishResponse();
      }
    } else if (tcpIncoming) {
      bodyBytesReceived += str.length;
      tcpIncoming.emit('data', str);
      if (contentLength >= 0 && bodyBytesReceived >= contentLength) {
        finishResponse();
      }
    }
  });

  socket.on('end', function() {
    finishResponse();
  });

  socket.on('close', function() {
    if (!responseEmitted) {
      self.emit('close');
    }
    finishResponse();
  });

  socket.on('error', function(err) {
    if (self._timeoutId) clearTimeout(self._timeoutId);
    if (self._aborted) return;
    self.emit('error', err);
    self.emit('close');
  });
};

// TCP-based IncomingMessage for client responses (when fetch not available)
function TcpIncomingMessage(statusCode, statusMessage, headers, rawHeaders) {
  EventEmitter.call(this);
  this.statusCode = statusCode;
  this.statusMessage = statusMessage;
  this.headers = headers;
  this.rawHeaders = rawHeaders || [];
  this.httpVersion = '1.1';
  this._consumed = false;
}
TcpIncomingMessage.prototype = Object.create(EventEmitter.prototype);
TcpIncomingMessage.prototype.constructor = TcpIncomingMessage;
TcpIncomingMessage.prototype.setEncoding = function() { return this; };
TcpIncomingMessage.prototype.pause = function() { return this; };
TcpIncomingMessage.prototype.resume = function() { return this; };
TcpIncomingMessage.prototype.read = function() { return null; };
TcpIncomingMessage.prototype.destroy = function() { this.emit('close'); return this; };

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

// ---------------------------------------------------------------------------
// HTTP/1.1 Request Parser (for net.js-based server)
// ---------------------------------------------------------------------------
function HttpRequestParser() {
  this._buffer = '';
  this._state = 0; // 0=REQUEST_LINE, 1=HEADERS, 2=BODY
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';
  this.onRequest = null;
}

HttpRequestParser.prototype.execute = function(chunk) {
  if (typeof chunk !== 'string') {
    try { chunk = chunk.toString('utf8'); } catch(e) { chunk = String(chunk); }
  }
  this._buffer += chunk;
  this._parse();
};

HttpRequestParser.prototype._parse = function() {
  while (this._buffer.length > 0) {
    if (this._state === 0) {
      var idx = this._buffer.indexOf('\r\n');
      if (idx === -1) return;
      var line = this._buffer.substring(0, idx);
      this._buffer = this._buffer.substring(idx + 2);
      var spaceIdx = line.indexOf(' ');
      if (spaceIdx > 0) {
        this._method = line.substring(0, spaceIdx);
        var rest = line.substring(spaceIdx + 1);
        var spaceIdx2 = rest.lastIndexOf(' ');
        if (spaceIdx2 > 0) {
          this._url = rest.substring(0, spaceIdx2);
          var ver = rest.substring(spaceIdx2 + 1);
          var slashIdx = ver.indexOf('/');
          if (slashIdx >= 0) {
            this._httpVersion = ver.substring(slashIdx + 1);
          }
        } else {
          this._url = rest;
        }
      }
      this._state = 1;
    } else if (this._state === 1) {
      var idx = this._buffer.indexOf('\r\n');
      if (idx === -1) return;
      if (idx === 0) {
        this._buffer = this._buffer.substring(2);
        var cl = this._headers['content-length'];
        if (cl !== undefined) {
          this._contentLength = parseInt(cl, 10) || 0;
        } else {
          this._contentLength = 0;
        }
        if (this._contentLength > 0) {
          this._state = 2;
        } else {
          this._emitRequest();
        }
      } else {
        var headerLine = this._buffer.substring(0, idx);
        this._buffer = this._buffer.substring(idx + 2);
        var colonIdx = headerLine.indexOf(':');
        if (colonIdx > 0) {
          var key = headerLine.substring(0, colonIdx);
          var value = headerLine.substring(colonIdx + 1).trim();
          this._headers[key.toLowerCase()] = value;
          this._rawHeaders.push(key, value);
        }
      }
    } else if (this._state === 2) {
      if (this._buffer.length >= this._contentLength) {
        this._bodyData = this._buffer.substring(0, this._contentLength);
        this._buffer = this._buffer.substring(this._contentLength);
        this._emitRequest();
      } else {
        return;
      }
    }
  }
};

HttpRequestParser.prototype._emitRequest = function() {
  var verParts = this._httpVersion.split('.');
  var reqData = {
    method: this._method,
    url: this._url,
    httpVersion: this._httpVersion,
    httpVersionMajor: verParts[0] !== undefined ? (parseInt(verParts[0], 10) || 1) : 1,
    httpVersionMinor: verParts[1] !== undefined ? parseInt(verParts[1], 10) : 1,
    headers: this._headers,
    rawHeaders: this._rawHeaders,
    body: this._bodyData
  };
  // Reset for next request on same connection
  this._state = 0;
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';

  if (typeof this.onRequest === 'function') {
    this.onRequest(reqData);
  }
};

HttpRequestParser.prototype.close = function() {
  this.onRequest = null;
};

// ---------------------------------------------------------------------------
// ServerResponse - supports both socket mode and native bridge mode
// ---------------------------------------------------------------------------
function ServerResponse(reqOrServerId, requestId) {
  EventEmitter.call(this);
  this.statusCode = 200;
  this.statusMessage = 'OK';
  this._headers = {};
  this._headersSent = false;
  this._finished = false;
  this._streaming = false;
  this._bodyParts = [];
  this.socket = null;
  this.connection = null;
  this.writableEnded = false;
  this.writableFinished = false;

  if (typeof reqOrServerId === 'number') {
    // Native bridge mode (exact:http)
    this._serverId = reqOrServerId;
    this._requestId = requestId || 0;
    this._nativeMode = true;
  } else {
    // Socket mode (Node.js compat)
    this._serverId = 0;
    this._requestId = 0;
    this._nativeMode = false;
    this._req = reqOrServerId || null;
  }
}
ServerResponse.prototype = Object.create(EventEmitter.prototype);
ServerResponse.prototype.constructor = ServerResponse;

ServerResponse.prototype.assignSocket = function(socket) {
  this.socket = socket;
  this.connection = socket;
  if (socket) socket._httpMessage = this;
};

ServerResponse.prototype.detachSocket = function(socket) {
  if (socket) socket._httpMessage = null;
  this.socket = null;
  this.connection = null;
};

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

// Native bridge streaming helpers
ServerResponse.prototype._ensureStreaming = function() {
  if (!this._nativeMode) return false;
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
    if (this._nativeMode && this._ensureStreaming()) {
      this._sendChunk(data);
    } else {
      this._bodyParts.push(data);
    }
  }
  if (callback) setTimeout(callback, 0);
  // Signal backpressure if the underlying socket's write queue is backed up.
  // When backpressure is detected, also pause the socket so it stops reading new
  // requests. This prevents an unbounded flood of pipelined requests from building
  // up in memory. The socket will be resumed when it drains.
  if (this.socket && this.socket._writeQueue && this.socket._writeQueue.length > 0) {
    var self = this;
    var sock = this.socket;
    if (sock._paused !== true) {
      sock._paused = true;
      // Resume reading when the socket drains
      sock.once('drain', function() {
        if (sock._paused) {
          sock._paused = false;
          sock._lastActivity = Date.now();
        }
      });
    }
    return false;
  }
  return true;
};

// Stream a chunk directly to the socket (enables incremental response delivery)
ServerResponse.prototype._streamChunk = function(data, callback) {
  if (!this._headersSent) {
    // Send headers without content-length (streaming mode)
    var statusMsg = this.statusMessage || STATUS_CODES[this.statusCode] || 'Unknown';
    var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';
    for (var k in this._headers) {
      if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
        head += toHeaderCase(k) + ': ' + this._headers[k] + '\r\n';
      }
    }
    head += '\r\n';
    this._headersSent = true;
    this._streaming = true;
    // Write headers + first chunk together
    this.socket.write(head + data, callback ? function() { setTimeout(callback, 0); } : undefined);
  } else {
    this.socket.write(data, callback ? function() { setTimeout(callback, 0); } : undefined);
  }
};

ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) setTimeout(callback, 0); return this; }
  if (chunk !== undefined && chunk !== null) this.write(chunk);
  this._finished = true;
  this.writableEnded = true;

  if (this._nativeMode) {
    if (this._streaming) {
      if (typeof __exactHttpRespondEnd === 'function') __exactHttpRespondEnd(this._serverId, this._requestId);
      this.writableFinished = true;
      if (callback) setTimeout(callback, 0);
      this.emit('finish');
      this.emit('close');
    } else {
      this._sendNativeResponse();
      if (callback) setTimeout(callback, 0);
    }
  } else {
    this._sendSocketResponse();
    if (callback) setTimeout(callback, 0);
  }
  return this;
};

// Native bridge response
ServerResponse.prototype._sendNativeResponse = function() {
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

// Socket-based response (Node.js compat)
ServerResponse.prototype._sendSocketResponse = function() {
  var socket = this.socket;
  if (socket) {
    // Determine connection behavior from request/response headers
    var req = this._req;
    var reqConnection = (req && req.headers && req.headers['connection']) || '';
    var reqTE = (req && req.headers && req.headers['te']) || '';
    // Use != null to properly handle httpVersionMinor === 0 (HTTP/1.0) without falsy coercion
    var httpVersionMajor = (req && req.httpVersionMajor != null) ? req.httpVersionMajor : 1;
    var httpVersionMinor = (req && req.httpVersionMinor != null) ? req.httpVersionMinor : 1;
    var respConnection = this._headers['connection'] || '';
    var reqConnectionLower = reqConnection.toLowerCase();
    var respConnectionLower = respConnection.toLowerCase();

    // For HTTP/1.0, keep-alive is only possible if:
    // 1. Client explicitly sends Connection: keep-alive
    // 2. AND the response body length is known (either via Content-Length or Transfer-Encoding: chunked)
    //    so the client can determine where the response ends without closing the connection.
    // Without framing, HTTP/1.0 clients rely on connection close to detect response end.
    var clientSupportsKeepAlive;
    if (httpVersionMajor === 1 && httpVersionMinor === 0) {
      // HTTP/1.0: only keep-alive if client explicitly requests it
      clientSupportsKeepAlive = reqConnectionLower.indexOf('keep-alive') !== -1;
      // But we also need body-length framing (checked below when we know the response headers)
    } else {
      // HTTP/1.1+: keep-alive unless client says close
      clientSupportsKeepAlive = reqConnectionLower.indexOf('close') === -1;
    }

    // Server can override by setting Connection: close
    var keepAlive = clientSupportsKeepAlive
      && respConnectionLower.indexOf('close') === -1;

    if (!this._headersSent) {
      var body = this._bodyParts.join('');
      var statusMsg = this.statusMessage || STATUS_CODES[this.statusCode] || 'Unknown';
      var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';
      // For HTTP/1.0 keep-alive: check framing BEFORE auto-adding Content-Length.
      // Keep-alive is only allowed if:
      //   1. The server EXPLICITLY set Content-Length or Transfer-Encoding: chunked in
      //      the response headers (set via writeHead/setHeader before end()), OR
      //   2. The client sent TE: chunked in the request.
      // Auto-computed Content-Length (added below) does NOT count because the node.js
      // reference implementation only honors keep-alive if the server explicitly signals
      // that the client can determine the message boundary without closing the connection.
      if (httpVersionMajor === 1 && httpVersionMinor === 0) {
        // Check framing before auto-add (while _headers reflect only explicitly-set headers)
        var hasExplicitFraming = this._headers['content-length'] != null
          || (this._headers['transfer-encoding'] || '').toLowerCase().indexOf('chunked') !== -1;
        var clientSendsTE = reqTE.toLowerCase().indexOf('chunked') !== -1;
        if (!hasExplicitFraming && !clientSendsTE) {
          // No framing: force close regardless of client/server connection preference
          keepAlive = false;
          // Also override any server-set connection header
          if (this._headers['connection']) {
            this._headers['connection'] = 'close';
          }
        }
      }
      if (!this._headers['content-length']) {
        var bodyLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(body) : body.length;
        this._headers['content-length'] = String(bodyLen);
      }
      // Add connection header if not already set
      if (!this._headers['connection']) {
        this._headers['connection'] = keepAlive ? 'keep-alive' : 'close';
      } else {
        // Server pre-set the connection header; use it (framing check above already enforced)
        keepAlive = this._headers['connection'].toLowerCase().indexOf('keep-alive') !== -1;
      }
      for (var k in this._headers) {
        if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
          head += toHeaderCase(k) + ': ' + this._headers[k] + '\r\n';
        }
      }
      head += '\r\n';
      this._headersSent = true;

      if (keepAlive) {
        // Keep-alive: write response and keep socket open for next request.
        // Socket is re-used; mark as idle so server.close() can clean it up.
        try { socket.write(head + body); } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
        // Close connection: write response then gracefully half-close (FIN).
        // Using socket.end() instead of socket.destroy() avoids RST when
        // there is unread data in the receive buffer.
        this.detachSocket(socket);
        socket.parser = null;
        socket[kTimeout] = null;
        try {
          socket.write(head + body, function() {
            try { socket.end(); } catch(e) {
              try { socket.destroy(); } catch(e2) {}
            }
          });
        } catch(e) {
          try { socket.destroy(); } catch(e2) {}
        }
      }
    } else {
      // Headers already sent (streaming mode): send remaining buffered body
      var remainingBody = this._bodyParts.join('');
      // Re-check keep-alive using the connection header already sent in headers
      var streamKeepAlive = (this._headers['connection'] || '').toLowerCase().indexOf('keep-alive') !== -1;
      if (!streamKeepAlive) {
        streamKeepAlive = keepAlive;
      }
      if (streamKeepAlive) {
        // Keep-alive streaming: write remaining body, keep socket open
        try { socket.write(remainingBody || ''); } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
        this.detachSocket(socket);
        socket.parser = null;
        socket[kTimeout] = null;
        try {
          socket.write(remainingBody || '', function() {
            try { socket.end(); } catch(e) {
              try { socket.destroy(); } catch(e2) {}
            }
          });
        } catch(e) {
          try { socket.destroy(); } catch(e2) {}
        }
      }
    }
  }

  this.writableFinished = true;
  this.emit('finish');
  this.emit('close');
};

ServerResponse.prototype.setTimeout = function() { return this; };
ServerResponse.prototype.flushHeaders = function() {};

// ---------------------------------------------------------------------------
// ServerIncomingMessage for server-side requests
// ---------------------------------------------------------------------------
function ServerIncomingMessage(requestData, serverId) {
  EventEmitter.call(this);
  this.method = requestData.method || 'GET';
  this.url = requestData.url || '/';
  this.httpVersion = requestData.httpVersion || '1.1';
  this.httpVersionMajor = requestData.httpVersionMajor != null ? requestData.httpVersionMajor : 1;
  this.httpVersionMinor = requestData.httpVersionMinor != null ? requestData.httpVersionMinor : 1;
  this.headers = {};
  this.rawHeaders = [];
  this.path = requestData.path || requestData.url || '/';
  this.query = requestData.query || '';
  this.socket = null;
  this.connection = null;

  // Parse body - native bridge sends base64, socket mode sends raw
  var rawBody = requestData.body || '';
  if (serverId && rawBody) {
    // Native bridge mode - body is base64 encoded
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
}
ServerIncomingMessage.prototype = Object.create(EventEmitter.prototype);
ServerIncomingMessage.prototype.constructor = ServerIncomingMessage;
ServerIncomingMessage.prototype.setEncoding = function(enc) {
  this._encoding = enc;
  return this;
};
ServerIncomingMessage.prototype.pause = function() { return this; };
ServerIncomingMessage.prototype.resume = function() {
  if (this._consumed) return this;
  this._consumed = true;
  var self = this;
  self.complete = true;
  setTimeout(function() {
    if (self._body) self.emit('data', self._body);
    self.emit('end');
    self.emit('close');
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.read = function() {
  if (this._consumed) return null;
  var body = this._body || null;
  if (body) this._body = '';
  return body;
};
ServerIncomingMessage.prototype.destroy = function() {
  this.emit('close');
  return this;
};
// Auto-resume when 'data' listener is attached
ServerIncomingMessage.prototype.on = function(event, listener) {
  EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'data' && !this._consumed) {
    this.resume();
  }
  return this;
};
ServerIncomingMessage.prototype.addListener = ServerIncomingMessage.prototype.on;

// ---------------------------------------------------------------------------
// Server - built on net.js for real socket access (Node.js compat)
// Falls back to native bridge if net module is not available
// ---------------------------------------------------------------------------
function Server(requestListener) {
  if (!(this instanceof Server)) {
    return new Server(requestListener);
  }
  EventEmitter.call(this);
  this._listening = false;
  this._closing = false;
  this._port = 0;
  this._hostname = '0.0.0.0';
  this._netServer = null;
  // Native bridge fallback
  this._serverId = 0;
  this._useNative = false;
  // Track all active connections for closeAllConnections / closeIdleConnections
  this._sockets = typeof Set === 'function' ? new Set() : null;
  // Server-level timeout state
  this._socketTimeout = 0;
  this._serverTimeoutId = null;

  if (typeof requestListener === 'function') {
    this.on('request', requestListener);
  }

  // Try to create net.js-based server
  var net;
  try { net = require('net'); } catch(e) {}
  if (net && typeof net.createServer === 'function') {
    var self = this;
    this._netServer = net.createServer(function(socket) {
      self._onConnection(socket);
    });
  }
}
Server.prototype = Object.create(EventEmitter.prototype);
Server.prototype.constructor = Server;

Server.prototype._onConnection = function(socket) {
  // Initialize HTTP state on socket
  socket[kTimeout] = null;
  socket.parser = null;
  socket._httpMessage = null;
  socket._isIdle = true;
  socket._httpServer = this;

  var self = this;
  // Track socket so we can close it when server closes
  if (self._sockets) self._sockets.add(socket);

  // Apply server socket timeout if set
  if (self._socketTimeout && typeof socket.setTimeout === 'function') {
    socket.setTimeout(self._socketTimeout, function() {
      self.emit('timeout', socket);
    });
  }

  this.emit('connection', socket);

  var parser = new HttpRequestParser();
  socket.parser = parser;

  socket.on('data', function(chunk) {
    if (socket.parser) parser.execute(chunk);
  });

  socket.on('close', function() {
    socket.parser = null;
    socket[kTimeout] = null;
    if (socket._httpMessage) socket._httpMessage = null;
    if (parser) parser.close();
    if (self._sockets) self._sockets.delete(socket);
  });

  socket.on('error', function() {});

  parser.onRequest = function(reqData) {
    var req = new ServerIncomingMessage(reqData);
    req.socket = socket;
    req.connection = socket;

    var res = new ServerResponse(req);
    res.req = req;
    res.assignSocket(socket);
    socket._isIdle = false;

    // When the response closes, mark socket as idle and close if server is closing
    res.once('close', function() {
      socket._isIdle = true;
      if (self._closing && !socket.destroyed) {
        try { socket.end(); } catch(e) {
          try { socket.destroy(); } catch(e2) {}
        }
      }
    });

    self.emit('request', req, res);
  };
};

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

  this._port = port;
  this._hostname = hostname;

  if (this._netServer) {
    // Use net.js-based server
    var self = this;
    this._netServer.on('error', function(err) {
      self.emit('error', err);
    });
    this._netServer.listen(port, hostname, function() {
      self._listening = true;
      self.emit('listening');
    });
  } else if (typeof __exactHttpServe === 'function') {
    // Fallback to native bridge
    this._useNative = true;
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
    this._listening = true;

    var self = this;
    setTimeout(function() { self.emit('listening'); }, 0);
    this._pollLoop();
  } else {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('HTTP server not available')); }, 0);
  }

  return this;
};

// Native bridge polling (fallback)
Server.prototype._pollLoop = function() {
  if (this._closing || !this._listening || !this._useNative) return;
  var self = this;

  function poll() {
    if (self._closing || !self._listening) return;
    var json = null;
    if (typeof __exactHttpPoll === 'function') {
      json = __exactHttpPoll(self._serverId);
    }
    if (json) {
      self._handleNativeRequest(json);
      setTimeout(poll, 0);
    } else if (typeof __exactHttpWait === 'function') {
      __exactHttpWait(self._serverId, 1000).then(function(waitJson) {
        if (waitJson) self._handleNativeRequest(waitJson);
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

Server.prototype._handleNativeRequest = function(json) {
  var data;
  try { data = JSON.parse(json); } catch(e) { return; }

  var req = new ServerIncomingMessage(data, this._serverId);
  var res = new ServerResponse(this._serverId, data.id || 0);

  if (req.listenerCount && req.listenerCount('data') > 0) {
    req.resume();
  }
  this.emit('request', req, res);
};

Server.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._closing = true;
  this._listening = false;
  // Cancel any pending wall-clock server timeout
  if (this._serverTimeoutId) {
    clearTimeout(this._serverTimeoutId);
    this._serverTimeoutId = null;
  }
  // Close idle keep-alive connections so the event loop can drain
  this.closeIdleConnections();

  var self = this;
  if (this._netServer) {
    this._netServer.close(function() {
      self.emit('close');
    });
  } else if (this._useNative) {
    if (typeof __exactHttpClose === 'function' && this._serverId) {
      __exactHttpClose(this._serverId, 0);
    }
    setTimeout(function() { self.emit('close'); }, 0);
  } else {
    setTimeout(function() { self.emit('close'); }, 0);
  }
  return this;
};

Server.prototype.closeAllConnections = function() {
  if (!this._sockets) return;
  var sockets = [];
  this._sockets.forEach(function(s) { sockets.push(s); });
  for (var i = 0; i < sockets.length; i++) {
    try { sockets[i].destroy(); } catch(e) {}
  }
};

Server.prototype.closeIdleConnections = function() {
  if (!this._sockets) return;
  var sockets = [];
  this._sockets.forEach(function(s) { sockets.push(s); });
  for (var i = 0; i < sockets.length; i++) {
    var sock = sockets[i];
    if (sock._isIdle) {
      try { sock.destroy(); } catch(e) {}
    }
  }
};

Server.prototype.address = function() {
  if (this._netServer && typeof this._netServer.address === 'function') {
    return this._netServer.address();
  }
  if (this._useNative) {
    if (typeof __exactHttpAddress === 'function') {
      var json = __exactHttpAddress(this._serverId);
      if (json) {
        try { return JSON.parse(json); } catch(e) {}
      }
    }
    return { address: this._hostname || '0.0.0.0', family: 'IPv4', port: this._port || 0 };
  }
  return null;
};

Server.prototype.setTimeout = function(msecs, callback) {
  if (typeof msecs === 'function') {
    callback = msecs;
    msecs = undefined;
  }
  if (msecs == null || msecs <= 0) return this;
  var self = this;
  this._socketTimeout = msecs;
  if (typeof callback === 'function') {
    this.on('timeout', callback);
  }
  // Use a wall-clock timer to fire the server timeout after msecs milliseconds.
  // This matches Node.js behavior where server.setTimeout sets a deadline that
  // applies globally. For more granular socket-level idle timeouts, the socket
  // timeout is also applied when connections are created.
  var self = this;
  if (this._serverTimeoutId) clearTimeout(this._serverTimeoutId);
  this._serverTimeoutId = setTimeout(function() {
    self._serverTimeoutId = null;
    // Emit timeout for each connected socket
    if (self._sockets && self._sockets.size > 0) {
      var sockets = [];
      self._sockets.forEach(function(s) { sockets.push(s); });
      for (var i = 0; i < sockets.length; i++) {
        self.emit('timeout', sockets[i]);
      }
    } else {
      self.emit('timeout');
    }
  }, msecs);
  // Also apply socket-level idle timeout for more precise per-socket tracking
  function applyTimeout(socket) {
    if (socket && typeof socket.setTimeout === 'function') {
      socket.setTimeout(msecs, function() {
        self.emit('timeout', socket);
      });
    }
  }
  if (this._sockets) {
    this._sockets.forEach(applyTimeout);
  }
  this._socketTimeoutApplier = applyTimeout;
  return this;
};
Server.prototype.ref = function() {
  if (this._netServer && typeof this._netServer.ref === 'function') {
    this._netServer.ref();
  } else if (this._useNative && typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 1);
  }
  return this;
};
Server.prototype.unref = function() {
  if (this._netServer && typeof this._netServer.unref === 'function') {
    this._netServer.unref();
  } else if (this._useNative && typeof __exactHttpSetRef === 'function' && this._serverId) {
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
  ServerIncomingMessage: ServerIncomingMessage,
  ClientRequest: ClientRequest,
  METHODS: METHODS,
  STATUS_CODES: STATUS_CODES,
  globalAgent: globalAgent,
  kTimeout: kTimeout
};
