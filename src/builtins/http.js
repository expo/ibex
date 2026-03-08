var EventEmitter = require('node:events').EventEmitter;
var Readable = null;
function getReadableCtor() {
  if (Readable) return Readable;
  try {
    var streamModule = require('node:stream');
    if (streamModule && typeof streamModule.Readable === 'function') {
      Readable = streamModule.Readable;
    }
  } catch (_streamErr) {}
  return Readable;
}

function upgradeTcpIncomingMessagePrototype() {
  var ReadableCtor = getReadableCtor();
  if (!ReadableCtor) return null;
  if (TcpIncomingMessage.prototype && TcpIncomingMessage.prototype._usesReadablePrototype) {
    return ReadableCtor;
  }

  var currentProto = TcpIncomingMessage.prototype;
  var nextProto = Object.create(ReadableCtor.prototype);
  if (currentProto) {
    var names = Object.getOwnPropertyNames(currentProto);
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (name === 'constructor') continue;
      Object.defineProperty(nextProto, name, Object.getOwnPropertyDescriptor(currentProto, name));
    }
  }
  Object.defineProperty(nextProto, '_usesReadablePrototype', {
    value: true,
    writable: true,
    configurable: true
  });
  nextProto.constructor = TcpIncomingMessage;
  TcpIncomingMessage.prototype = nextProto;
  return ReadableCtor;
}

// Shared symbol for timeout tracking (matches internal/timers)
var kTimeout = Symbol.for('kTimeout');
var kOutHeaders = Symbol.for('nodejs.http.outHeadersKey');

// Header name validation regex
var HEADER_NAME_RE = /^[\^_`a-zA-Z\-0-9\!#$%&'*+.|~]+$/;

function validateHeaderName(name) {
  if (typeof name !== 'string' || !HEADER_NAME_RE.test(name)) {
    var err = new TypeError('Invalid HTTP header name: "' + name + '"');
    err.code = 'ERR_INVALID_HTTP_TOKEN';
    throw err;
  }
}

function validateHeaderValue(name, value) {
  if (value === undefined) {
    var err = new TypeError('Invalid value "undefined" for header "' + name + '"');
    err.code = 'ERR_HTTP_INVALID_HEADER_VALUE';
    throw err;
  }
}

function resolveHeaderName(value) {
  if (typeof value !== 'string') {
    return String(value || '');
  }
  return value.toLowerCase();
}

function _createHttpAsyncIterator(message, options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    var optionsErr = new TypeError('The "options" argument must be of type object. Received type ' + typeof options + ' (' + options + ')');
    optionsErr.code = 'ERR_INVALID_ARG_TYPE';
    throw optionsErr;
  }

  var queue = [];
  var finishedState;
  var pendingResolve = null;
  var cleanedUp = false;

  function wake() {
    if (!pendingResolve) return;
    var resolve = pendingResolve;
    pendingResolve = null;
    resolve();
  }

  function onData(chunk) {
    queue.push(chunk);
    wake();
  }

  function onEnd() {
    finishedState = null;
    wake();
  }

  function onError(err) {
    finishedState = err || new Error('Stream error');
    wake();
  }

  function onClose() {
    if (finishedState === undefined) {
      finishedState = null;
    }
    wake();
  }

  function cleanup() {
    if (cleanedUp || !message) return;
    cleanedUp = true;
    if (typeof message.off === 'function') {
      message.off('data', onData);
      message.off('end', onEnd);
      message.off('error', onError);
      message.off('close', onClose);
    } else if (typeof message.removeListener === 'function') {
      message.removeListener('data', onData);
      message.removeListener('end', onEnd);
      message.removeListener('error', onError);
      message.removeListener('close', onClose);
    }
  }

  if (message && typeof message.on === 'function') {
    message.on('data', onData);
    message.on('end', onEnd);
    message.on('error', onError);
    message.on('close', onClose);
  }

  if (message && typeof message.resume === 'function') {
    message.resume();
  }

  return {
    next: function() {
      return (async function() {
        while (true) {
          if (queue.length > 0) {
            return { value: queue.shift(), done: false };
          }
          if (finishedState) {
            cleanup();
            throw finishedState;
          }
          if (finishedState === null) {
            cleanup();
            return { value: undefined, done: true };
          }
          await new Promise(function(resolve) {
            pendingResolve = resolve;
          });
        }
      })();
    },
    return: function() {
      cleanup();
      finishedState = null;
      if ((!options || options.destroyOnReturn !== false) && message && typeof message.destroy === 'function' && !message.destroyed) {
        message.destroy();
      }
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      cleanup();
      finishedState = err || new Error('Stream iterator error');
      if (message && typeof message.destroy === 'function' && !message.destroyed) {
        message.destroy(finishedState);
      }
      return Promise.reject(finishedState);
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
}

function _attachHttpAsyncIterator(proto) {
  if (!proto) return;
  proto.iterator = function(options) {
    return _createHttpAsyncIterator(this, options);
  };
  proto[Symbol.asyncIterator] = function(options) {
    return _createHttpAsyncIterator(this, options);
  };
}

// Convert a lowercase header name to HTTP title case (e.g. content-length -> Content-Length)
function toHeaderCase(name) {
  return name.replace(/(?:^|-)([a-z])/g, function(match, letter, offset) {
    return offset === 0 ? letter.toUpperCase() : '-' + letter.toUpperCase();
  });
}

// Headers that should NOT be comma-joined (single value only)
var _singleValueHeaders = {
  'age': true, 'authorization': true, 'content-length': true,
  'content-type': true, 'etag': true, 'expires': true, 'from': true,
  'host': true, 'if-modified-since': true, 'if-unmodified-since': true,
  'last-modified': true, 'location': true, 'max-forwards': true,
  'proxy-authorization': true, 'referer': true, 'retry-after': true,
  'server': true, 'user-agent': true
};

function _invalidArgTypeHelper(input) {
  if (input == null) return ' Received ' + input;
  if (typeof input === 'function') return ' Received function ' + input.name;
  if (typeof input === 'object') {
    if (input.constructor && input.constructor.name) return ' Received an instance of ' + input.constructor.name;
    return ' Received ' + String(input);
  }
  return ' Received type ' + typeof input + ' (' + String(input) + ')';
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
    // Strip port from host if combined
    if (hostname.indexOf(':') !== -1 && hostname.charAt(0) !== '[') {
      var hostParts = hostname.split(':');
      hostname = hostParts[0];
      if (!options.port && hostParts[1]) {
        options.port = hostParts[1];
      }
    }
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

function hasUrlOptionOverrides(options) {
  if (!options || typeof options !== "object") return false;
  return (
    Object.prototype.hasOwnProperty.call(options, "href") ||
    Object.prototype.hasOwnProperty.call(options, "url") ||
    Object.prototype.hasOwnProperty.call(options, "protocol") ||
    Object.prototype.hasOwnProperty.call(options, "hostname") ||
    Object.prototype.hasOwnProperty.call(options, "host") ||
    Object.prototype.hasOwnProperty.call(options, "port") ||
    Object.prototype.hasOwnProperty.call(options, "path") ||
    Object.prototype.hasOwnProperty.call(options, "pathname") ||
    Object.prototype.hasOwnProperty.call(options, "search") ||
    Object.prototype.hasOwnProperty.call(options, "hash")
  );
}

function toMethod(options) {
  return ((options && options.method) || "GET").toUpperCase();
}

function toHeaders(source) {
  if (!source || typeof source !== "object") return {};
  var out = {};
  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      var val = source[key];
      var headerName = resolveHeaderName(key);
      validateHeaderName(String(key));
      if (Array.isArray(val)) {
        if (headerName === 'host') {
          var hostErr = new TypeError('The "options.headers.host" property must be of type string.');
          hostErr.code = 'ERR_INVALID_ARG_TYPE';
          throw hostErr;
        }
        out[headerName] = val.map(function(item) {
          validateHeaderValue(String(key), item);
          return String(item);
        }).join(', ');
      } else {
        validateHeaderValue(String(key), val);
        out[headerName] = String(val);
      }
    }
  }
  return out;
}

function parseHeaders(response) {
  var result = {};
  if (response && response.headers && typeof response.headers.forEach === 'function') {
    response.headers.forEach(function(value, key) {
      result[key] = value;
    });
  }
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

// ---------------------------------------------------------------------------
// IncomingMessage - supports both client responses AND server-side construction
// Node.js: new http.IncomingMessage(socket) — socket is optional
// ---------------------------------------------------------------------------
function IncomingMessage(socketOrResponse) {
  EventEmitter.call(this);

  // If called with a fetch Response object (internal path)
  if (socketOrResponse && typeof socketOrResponse === 'object'
      && typeof socketOrResponse.status === 'number'
      && socketOrResponse.headers && typeof socketOrResponse.headers.forEach === 'function') {
    this.statusCode = socketOrResponse.status;
    this.statusMessage = socketOrResponse.statusText;
    this.headers = parseHeaders(socketOrResponse);
    this.rawHeaders = [];
    for (var key in this.headers) {
      this.rawHeaders.push(key, this.headers[key]);
    }
    this.httpVersion = "1.1";
    this.httpVersionMajor = 1;
    this.httpVersionMinor = 1;
    this.aborted = false;
    this.complete = false;
    this.readable = true;
    this.socket = null;
    this.trailers = {};
    this.rawTrailers = [];
    this.method = null;
    this.url = '';
    this._response = socketOrResponse;
    this._consumed = false;
    return;
  }

  // Standard Node.js IncomingMessage constructor: new IncomingMessage(socket)
  this.socket = socketOrResponse !== undefined ? socketOrResponse : undefined;
  this.httpVersion = '1.1';
  this.httpVersionMajor = 1;
  this.httpVersionMinor = 1;
  this.complete = false;
  this.headers = {};
  this.rawHeaders = [];
  this.trailers = {};
  this.rawTrailers = [];
  this.readable = true;
  this.aborted = false;
  this.statusCode = null;
  this.statusMessage = null;
  this.method = null;
  this.url = '';
  this._consumed = false;
  this._response = null;
  this._body = '';
}
IncomingMessage.prototype = Object.create(EventEmitter.prototype);
IncomingMessage.prototype.constructor = IncomingMessage;

// connection getter/setter mirrors socket
Object.defineProperty(IncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

// _addHeaderLine: used by the parser to add a header to the message
IncomingMessage.prototype._addHeaderLine = function(field, value, dest) {
  var key = field.toLowerCase();
  if (dest === undefined) dest = this.headers;
  if (key === 'set-cookie') {
    // set-cookie is always an array
    if (dest[key] !== undefined) {
      if (Array.isArray(dest[key])) {
        dest[key].push(value);
      } else {
        dest[key] = [dest[key], value];
      }
    } else {
      dest[key] = [value];
    }
  } else if (dest[key] !== undefined) {
    if (_singleValueHeaders[key]) {
      return; // single-value: first wins
    }
    if (key === 'cookie') {
      dest[key] = dest[key] + '; ' + value;
    } else {
      dest[key] = dest[key] + ', ' + value;
    }
  } else {
    dest[key] = value;
  }
};

IncomingMessage.prototype._consumeBody = function() {
  if (this._consumed) return;
  this._consumed = true;
  var self = this;
  var response = this._response;
  if (!response) {
    if (self._body) {
      var body = self._body;
      setTimeout(function() {
        self.emit('data', body);
        self.complete = true;
        self.emit('end');
        self.emit('close');
      }, 0);
    } else {
      setTimeout(function() {
        self.complete = true;
        self.emit('end');
        self.emit('close');
      }, 0);
    }
    return;
  }
  if (response.body && typeof response.body.getReader === 'function') {
    var reader = response.body.getReader();
    var decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null;
    function pump() {
      reader.read().then(function(result) {
        if (result.done) {
          self.complete = true;
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
        self.complete = true;
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
  if (this._response) this._consumeBody();
  return this;
};
IncomingMessage.prototype.read = function() { return null; };
IncomingMessage.prototype.destroy = function(err) {
  if (err) this.emit('error', err);
  this.emit("close");
  return this;
};
IncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  return this;
};
_attachHttpAsyncIterator(IncomingMessage.prototype);

// ---------------------------------------------------------------------------
// ClientRequest
// ---------------------------------------------------------------------------
function ClientRequest(options, callback) {
  EventEmitter.call(this);
  this.options = options || {};
  this._defaultAgent = globalAgent;

  // Validate hostname/host type
  if (this.options.hostname !== undefined && this.options.hostname !== null && typeof this.options.hostname !== 'string') {
    var err = new TypeError('The "options.hostname" property must be of type string or one of undefined or null.' +
      _invalidArgTypeHelper(this.options.hostname));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (this.options.host !== undefined && this.options.host !== null && typeof this.options.host !== 'string') {
    var err = new TypeError('The "options.host" property must be of type string or one of undefined or null.' +
      _invalidArgTypeHelper(this.options.host));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  // Validate method type
  if (this.options.method !== undefined && this.options.method !== null && typeof this.options.method !== 'string') {
    var err = new TypeError('The "options.method" property must be of type string.' +
      _invalidArgTypeHelper(this.options.method));
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  // Validate method is a valid HTTP token
  if (this.options.method !== undefined && this.options.method !== null) {
    var methodStr = String(this.options.method);
    if (methodStr && !HEADER_NAME_RE.test(methodStr)) {
      var mErr = new TypeError('Method must be a valid HTTP token ["' + methodStr + '"]');
      mErr.code = 'ERR_INVALID_HTTP_TOKEN';
      throw mErr;
    }
  }

  var resolvedAgent = this.options.agent;
  if (resolvedAgent === false) {
    resolvedAgent = new Agent();
  } else if (resolvedAgent === null || resolvedAgent === undefined) {
    if (typeof this.options.createConnection !== 'function') {
      resolvedAgent = this._defaultAgent;
    } else {
      resolvedAgent = null;
    }
  } else if (typeof resolvedAgent.addRequest !== 'function') {
    var agentErr = new TypeError('The "options.agent" property must be one of Agent-like Object, undefined, or false.' +
      _invalidArgTypeHelper(resolvedAgent));
    agentErr.code = 'ERR_INVALID_ARG_TYPE';
    throw agentErr;
  }

  this._url = typeof this.options.__exactOriginalUrl === "string"
    ? this.options.__exactOriginalUrl
    : toHttpUrl(this.options);
  this.method = toMethod(this.options);
  this.path = toHttpPath(this.options);
  this.headers = toHeaders(this.options.headers);
  this._headerNames = {};
  if (this.options.headers) {
    for (var hk in this.options.headers) {
      if (Object.prototype.hasOwnProperty.call(this.options.headers, hk)) {
        this._headerNames[hk.toLowerCase()] = hk;
      }
    }
  }
  this._bodyParts = [];
  this._ended = false;
  this._sent = false;
  this._closed = false;
  this._aborted = false;
  this.aborted = false;
  this.headersSent = false;
  this.finished = false;
  this.writableEnded = false;
  this.writableFinished = false;
  this.destroyed = false;
  this.maxHeadersCount = 2000;
  this.reusedSocket = false;
  this.socket = null;
  this.agent = resolvedAgent;
  this.host = this.options.hostname || this.options.host || 'localhost';
  this.protocol = this.options.protocol || (this.agent && this.agent.protocol) || 'http:';
  this.timeout = this.options.timeout;
  this.timeoutCb = null;
  this.res = null;
  this._pendingRawRequest = null;
  this._agentDispatched = false;
  this._pendingSocketDrain = false;
  this._socketDrainListenerAttached = false;
  this._responseEndedBeforeRequestEnd = false;
  this._last = true;
  this.shouldKeepAlive = false;

  if (this.agent) {
    if (!this.agent.keepAlive && !isFinite(this.agent.maxSockets)) {
      this._last = true;
      this.shouldKeepAlive = false;
    } else {
      this._last = false;
      this.shouldKeepAlive = true;
    }
  }

  if (typeof callback === "function") {
    this.once("response", callback);
  }

  if (this.protocol === 'http:' || this.options.socketPath || typeof this.options.createConnection === 'function') {
    this._ensureSocketAssigned();
  }
}
ClientRequest.prototype = Object.create(EventEmitter.prototype);
ClientRequest.prototype.constructor = ClientRequest;

ClientRequest.prototype.setHeader = function(name, value) {
  var lc = resolveHeaderName(name);
  validateHeaderName(String(name));
  if (Array.isArray(value) && lc === 'host') {
    var hostErr = new TypeError('The "options.headers.host" property must be of type string.');
    hostErr.code = 'ERR_INVALID_ARG_TYPE';
    throw hostErr;
  }
  validateHeaderValue(String(name), value);
  this.headers[lc] = Array.isArray(value) ? value.map(String).join(', ') : String(value);
  this._headerNames[lc] = name;
};

ClientRequest.prototype.getHeader = function(name) {
  return this.headers[resolveHeaderName(name)];
};

ClientRequest.prototype.removeHeader = function(name) {
  var key = resolveHeaderName(name);
  var value = this.headers[key];
  delete this.headers[key];
  delete this._headerNames[key];
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

ClientRequest.prototype.getHeaderNames = function() {
  return Object.keys(this.headers);
};

ClientRequest.prototype.getRawHeaderNames = function() {
  var result = [];
  for (var key in this._headerNames) {
    if (Object.prototype.hasOwnProperty.call(this._headerNames, key)) {
      result.push(this._headerNames[key]);
    }
  }
  return result;
};

ClientRequest.prototype.hasHeader = function(name) {
  return resolveHeaderName(name) in this.headers;
};

ClientRequest.prototype.flushHeaders = function() {
  if (!this._ended) {
    this._ended = true;
    this._send();
  }
};

function emitRequestTimeout() {
  var req = this && this._httpMessage;
  if (req) {
    req.emit('timeout');
  }
}

function listenSocketTimeout(req) {
  if (req.timeoutCb) return;
  req.timeoutCb = emitRequestTimeout;
  if (req.socket) {
    req.socket.on('timeout', req.timeoutCb);
  } else {
    req.once('socket', function(socket) {
      socket.on('timeout', req.timeoutCb);
    });
  }
}

function setSocketTimeout(socket, timeout) {
  if (!socket || typeof socket.setTimeout !== 'function') return;
  socket.setTimeout(timeout);
}

function clearSocketTimeoutListener(req, socket) {
  if (!req || !socket || !req.timeoutCb) return;
  socket.removeListener('timeout', req.timeoutCb);
  req.timeoutCb = null;
}

function ReusedHandle(type, handle) {
  this.type = type || 'Socket';
  this.handle = handle;
}

function freeSocketErrorListener() {
  if (typeof this.destroy === 'function') {
    this.destroy();
  }
  if (typeof this.emit === 'function') {
    this.emit('agentRemove');
  }
}

function asyncResetHandle(socket) {
  var handle = socket && socket._handle;
  if (handle && typeof handle.asyncReset === 'function') {
    try {
      handle.asyncReset(new ReusedHandle(
        typeof handle.getProviderType === 'function' ? handle.getProviderType() : 'Socket',
        handle
      ));
    } catch (_asyncResetErr) {}
  }
}

function setRequestSocket(agent, req, socket, options) {
  req.onSocket(socket, options);
  var agentTimeout = agent && agent.options ? agent.options.timeout : undefined;
  if (req.timeout === undefined || req.timeout === null) {
    if (agentTimeout !== undefined) {
      listenSocketTimeout(req);
      setSocketTimeout(socket, agentTimeout);
    }
    return;
  }
  listenSocketTimeout(req);
  setSocketTimeout(socket, req.timeout);
}

function scheduleNextTick(fn) {
  if (typeof process !== 'undefined' && process && typeof process.nextTick === 'function') {
    process.nextTick(fn);
    return;
  }
  setTimeout(fn, 0);
}

ClientRequest.prototype._deferToConnect = function(method, args) {
  var self = this;
  function invoke() {
    if (!self.socket || typeof self.socket[method] !== 'function') return;
    if (self.socket.writable !== false) {
      self.socket[method].apply(self.socket, args);
    }
  }
  function onSocket() {
    if (!self.socket) return;
    if (self.socket.connecting) {
      self.socket.once('connect', invoke);
    } else {
      invoke();
    }
  }
  if (!this.socket) {
    this.once('socket', onSocket);
  } else {
    onSocket();
  }
};

ClientRequest.prototype.onSocket = function(socket, requestOptions, err) {
  var self = this;
  scheduleNextTick(function() {
    if (err) {
      self.destroyed = true;
      if (socket && typeof socket.destroy === 'function') {
        try { socket.destroy(err); } catch (_destroyErr) {}
      }
      self.emit('error', err);
      if (!self._closed) {
        self._closed = true;
        self.emit('close');
      }
      return;
    }
    if (!socket) {
      return;
    }
    self.socket = socket;
    if (self.timeout !== undefined && self.timeout !== null) {
      listenSocketTimeout(self);
      setSocketTimeout(socket, self.timeout);
    } else if (self.agent && self.agent.options && self.agent.options.timeout !== undefined) {
      listenSocketTimeout(self);
      setSocketTimeout(socket, self.agent.options.timeout);
    }
    self._attachToSocket(socket, requestOptions || self.options);
    self.emit('socket', socket);
  });
};

ClientRequest.prototype.setTimeout = function(timeout, callback) {
  if (typeof timeout === 'number' && timeout >= 0) {
    this.timeout = timeout;
    if (callback) {
      this.once('timeout', callback);
    }
    if (timeout === 0) {
      if (this.socket && typeof this.socket.setTimeout === 'function') {
        this.socket.setTimeout(0);
      }
      if (this.socket) {
        clearSocketTimeoutListener(this, this.socket);
      }
      return this;
    }
    listenSocketTimeout(this);
    if (this.socket) {
      setSocketTimeout(this.socket, timeout);
    }
  }
  return this;
};

ClientRequest.prototype.clearTimeout = function(callback) {
  return this.setTimeout(0, callback);
};

ClientRequest.prototype.setNoDelay = function(noDelay) {
  this._deferToConnect('setNoDelay', [noDelay]);
};

ClientRequest.prototype.setSocketKeepAlive = function(enable, initialDelay) {
  this._deferToConnect('setKeepAlive', [enable, initialDelay]);
};

ClientRequest.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (chunk !== undefined && chunk !== null) {
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
      this._bodyParts.push(chunk.toString(encoding || 'utf8'));
    } else {
      this._bodyParts.push(String(chunk));
    }
  }
  if (callback) setTimeout(callback, 0);
  return true;
};

ClientRequest.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._ended || this._aborted) {
    if (callback) setTimeout(callback, 0);
    return this;
  }
  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }
  this._ended = true;
  this.writableEnded = true;
  this.finished = true;
  if (callback) this.once('finish', callback);
  this._send();
  return this;
};

ClientRequest.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  this._aborted = true;
  this.aborted = true;
  this.destroyed = true;
  if (this._abortController) {
    try { this._abortController.abort(); } catch(e) {}
  }
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(); } catch(e) {}
  } else if (!this._closed) {
    this._closed = true;
    if (err) this.emit("error", err);
    this.emit("close");
  }
  return this;
};

ClientRequest.prototype.abort = function() {
  if (this._aborted) return;
  this._aborted = true;
  this.aborted = true;
  var self = this;
  setTimeout(function() {
    self.emit("abort");
  }, 0);
  this.destroy();
};

ClientRequest.prototype._send = function() {
  if (this._sent || this._aborted) return;
  this._sent = true;
  this.headersSent = true;
  var body = this._bodyParts.join("");

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
  var self = this;
  var resolved = this._resolveConnectionOptions();
  var options = resolved.options;
  var host = resolved.host;
  var port = resolved.port;

  // Build raw HTTP request
  var reqLine = this.method + ' ' + this.path + ' HTTP/1.1\r\n';
  var headerStr = '';
  if (!this.headers['host']) {
    headerStr += 'Host: ' + host + (port !== 80 ? ':' + port : '') + '\r\n';
  }
  for (var k in this.headers) {
    if (Object.prototype.hasOwnProperty.call(this.headers, k)) {
      var casedName = this._headerNames[k] || toHeaderCase(k);
      headerStr += casedName + ': ' + this.headers[k] + '\r\n';
    }
  }
  if (body) {
    if (!this.headers['content-length'] && !this.headers['transfer-encoding']) {
      var bodyLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
        ? Buffer.byteLength(body) : body.length;
      headerStr += 'Content-Length: ' + bodyLen + '\r\n';
    }
  }
  if (!this.headers['connection']) {
    headerStr += 'Connection: ' + (this.shouldKeepAlive ? 'keep-alive' : 'close') + '\r\n';
  }
  headerStr += '\r\n';

  var rawRequest = reqLine + headerStr;
  if (body) {
    rawRequest += body;
  }
  this._pendingRawRequest = rawRequest;

  if (this._writePendingRequest) {
    this._writePendingRequest();
    return;
  }

  this._ensureSocketAssigned();
};

ClientRequest.prototype._resolveConnectionOptions = function() {
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
  if (host && host.indexOf(':') !== -1 && host.charAt(0) !== '[') {
    var parts = host.split(':');
    host = parts[0];
    if (!port && parts[1]) port = Number(parts[1]);
  }
  if (!host) host = 'localhost';
  if (!port) port = 80;

  var connectionOptions = {};
  for (var optKey in options) {
    if (Object.prototype.hasOwnProperty.call(options, optKey)) {
      connectionOptions[optKey] = options[optKey];
    }
  }
  if (options.socketPath) {
    connectionOptions.path = options.socketPath;
  } else {
    delete connectionOptions.path;
    connectionOptions.host = host;
    if (options.hostname) {
      connectionOptions.hostname = options.hostname;
    }
    connectionOptions.port = port;
  }

  return {
    host: host,
    port: port,
    options: connectionOptions
  };
};

ClientRequest.prototype._ensureSocketAssigned = function() {
  if (this.socket || this._agentDispatched || this.protocol !== 'http:') return;

  var net;
  try { net = require('net'); } catch (e) {
    this.emit("error", new Error("Neither fetch nor net module available"));
    if (!this._closed) {
      this._closed = true;
      this.emit("close");
    }
    return;
  }

  var resolved = this._resolveConnectionOptions();
  var connectionOptions = resolved.options;
  var self = this;

  if (this.agent && typeof this.agent.addRequest === 'function') {
    if (!this._agentDispatched) {
      this._agentDispatched = true;
      this.agent.addRequest(this, connectionOptions);
    }
    return;
  }

  var createConnection = connectionOptions.createConnection || this.options.createConnection || null;
  if (createConnection) {
    var created = false;
    function oncreate(err, socket) {
      if (created) return;
      created = true;
      self.onSocket(socket, connectionOptions, err);
    }
    try {
      var maybeSocket = createConnection(connectionOptions, oncreate);
      if (maybeSocket) {
        oncreate(null, maybeSocket);
      }
    } catch (createErr) {
      oncreate(createErr);
    }
    return;
  }

  self.onSocket(net.createConnection(connectionOptions), connectionOptions);
};

ClientRequest.prototype._attachToSocket = function(socket, requestOptions) {
  var self = this;
  if (!socket) return;

  var responseBuffer = '';
  var headersParsed = false;
  var statusCode = 200;
  var statusMessage = 'OK';
  var responseHeaders = {};
  var rawResponseHeaders = [];
  var contentLength = -1;
  var isChunked = false;
  var bodyBytesReceived = 0;
  var responseEmitted = false;
  var responseEnded = false;
  var tcpIncoming = null;
  var chunkParserState = 'size';
  var chunkRemaining = 0;
  var chunkBuffer = '';
  var rawRequestWritten = false;
  var socketRetired = false;

  function maybeReleaseSocketAfterFlush() {
    if (self._responseEndedBeforeRequestEnd) {
      retireSocketFromAgent();
      return;
    }
    if (!self._waitingForSocketDrain || !responseEnded) return;
    self._waitingForSocketDrain = false;
    if (self.shouldKeepAlive && tcpIncoming && !tcpIncoming.aborted) {
      releaseSocket();
    }
  }

  function retireSocketFromAgent() {
    if (socketRetired) return;
    socketRetired = true;
    clearSocketTimeoutListener(self, socket);
    cleanupRequestListeners();
    self.destroyed = true;
    if (self.res) {
      self.res.socket = null;
    }
    socket._httpMessage = null;
    if (typeof socket.unref === 'function') {
      socket.unref();
    }
    scheduleNextTick(function() {
      if (typeof socket.emit === 'function') {
        socket.emit('agentRemove');
      }
      if (!self._closed) {
        self._closed = true;
        self.emit('close');
      }
    });
  }

  function cleanupRequestListeners() {
    socket.removeListener('data', onData);
    socket.removeListener('end', onEnd);
    socket.removeListener('close', onClose);
    socket.removeListener('error', onError);
  }

  function releaseSocket() {
    if (!self.agent || !self.shouldKeepAlive || !tcpIncoming || tcpIncoming.aborted ||
        !tcpIncoming.shouldKeepAlive || socket.destroyed || socket.writable === false) {
      if (!socket.destroyed) {
        try {
          if (typeof socket.end === 'function') socket.end();
          else socket.destroy();
        } catch (_endErr) {
          try { socket.destroy(); } catch (_destroyErr) {}
        }
      }
      return;
    }

    if (typeof socket.setTimeout === 'function') {
      socket.setTimeout(self.agent.options && self.agent.options.timeout ? self.agent.options.timeout : 0);
    }
    clearSocketTimeoutListener(self, socket);
    cleanupRequestListeners();
    self.destroyed = true;
    if (self.res) {
      self.res.socket = null;
    }
    if (!self._closed) {
      self._closed = true;
      scheduleNextTick(function() {
        self.emit('close');
        socket.emit('free');
      });
    }
  }

  function finishResponse() {
    if (responseEnded) return;
    responseEnded = true;
    if (tcpIncoming) {
      tcpIncoming._finishResponse();
    }
    self.writableFinished = true;
    self.emit('finish');
  }

  function abortResponse() {
    if (responseEnded) return;
    responseEnded = true;
    if (tcpIncoming) {
      var abortErr = new Error('aborted');
      abortErr.code = 'ECONNRESET';
      tcpIncoming.aborted = true;
      if (typeof tcpIncoming.destroy === 'function') {
        tcpIncoming.destroy(abortErr);
      } else {
        tcpIncoming.emit('error', abortErr);
        tcpIncoming.emit('close');
      }
    } else if (!self._aborted && !socket._hadError) {
      socket._hadError = true;
      var hangupErr = new Error('socket hang up');
      hangupErr.code = 'ECONNRESET';
      self.emit('error', hangupErr);
    }
    if (!self._closed) {
      self._closed = true;
      self.emit('close');
    }
  }

  function processChunkedData(data) {
    chunkBuffer += data;
    while (chunkBuffer.length > 0) {
      if (chunkParserState === 'size') {
        var nlIdx = chunkBuffer.indexOf('\r\n');
        if (nlIdx === -1) return;
        var sizeStr = chunkBuffer.substring(0, nlIdx).split(';')[0].trim();
        chunkRemaining = parseInt(sizeStr, 16);
        chunkBuffer = chunkBuffer.substring(nlIdx + 2);
        if (isNaN(chunkRemaining) || chunkRemaining === 0) {
          finishResponse();
          return;
        }
        chunkParserState = 'data';
      } else if (chunkParserState === 'data') {
        if (chunkBuffer.length < chunkRemaining) {
          if (chunkBuffer.length > 0 && tcpIncoming) {
            var partBuf = (typeof Buffer !== 'undefined') ? Buffer.from(chunkBuffer, 'utf8') : chunkBuffer;
            if (typeof tcpIncoming._pushBodyChunk === 'function') tcpIncoming._pushBodyChunk(partBuf);
            else if (typeof tcpIncoming.push === 'function') tcpIncoming.push(partBuf);
            else tcpIncoming.emit('data', partBuf);
            chunkRemaining -= chunkBuffer.length;
            chunkBuffer = '';
          }
          return;
        }
        var chunkData = chunkBuffer.substring(0, chunkRemaining);
        chunkBuffer = chunkBuffer.substring(chunkRemaining);
        chunkRemaining = 0;
        if (tcpIncoming && chunkData) {
          var chunkDataBuf = (typeof Buffer !== 'undefined') ? Buffer.from(chunkData, 'utf8') : chunkData;
          if (typeof tcpIncoming._pushBodyChunk === 'function') tcpIncoming._pushBodyChunk(chunkDataBuf);
          else if (typeof tcpIncoming.push === 'function') tcpIncoming.push(chunkDataBuf);
          else tcpIncoming.emit('data', chunkDataBuf);
        }
        chunkParserState = 'trailer';
      } else if (chunkParserState === 'trailer') {
        if (chunkBuffer.length < 2) return;
        chunkBuffer = chunkBuffer.substring(2);
        chunkParserState = 'size';
      }
    }
  }

  function onData(chunk) {
    var str = typeof chunk === 'string' ? chunk : chunk.toString('utf8');

    if (!headersParsed) {
      responseBuffer += str;
      var headerEnd = responseBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      var headerSection = responseBuffer.substring(0, headerEnd);
      var bodyStart = responseBuffer.substring(headerEnd + 4);
      headersParsed = true;

      var lines = headerSection.split('\r\n');
      var httpVerMajor = 1;
      var httpVerMinor = 1;
      if (lines.length > 0) {
        var statusLine = lines[0];
        var statusParts = statusLine.match(/^HTTP\/(\d)\.(\d)\s+(\d+)\s*(.*)/);
        if (statusParts) {
          httpVerMajor = parseInt(statusParts[1], 10) || 1;
          httpVerMinor = parseInt(statusParts[2], 10) || 1;
          statusCode = parseInt(statusParts[3], 10);
          statusMessage = statusParts[4] || '';
        }
      }
      for (var i = 1; i < lines.length; i++) {
        var colonIdx = lines[i].indexOf(':');
        if (colonIdx > 0) {
          var hKey = lines[i].substring(0, colonIdx).trim();
          var hVal = lines[i].substring(colonIdx + 1).trim();
          var hKeyLower = hKey.toLowerCase();
          if (responseHeaders[hKeyLower] !== undefined && !_singleValueHeaders[hKeyLower]) {
            responseHeaders[hKeyLower] += ', ' + hVal;
          } else {
            responseHeaders[hKeyLower] = hVal;
          }
          rawResponseHeaders.push(hKey, hVal);
        }
      }
      var cl = responseHeaders['content-length'];
      if (cl !== undefined) contentLength = parseInt(cl, 10) || 0;
      var te = responseHeaders['transfer-encoding'];
      if (te && te.toLowerCase().indexOf('chunked') !== -1) {
        isChunked = true;
      }

      tcpIncoming = new TcpIncomingMessage(statusCode, statusMessage, responseHeaders, rawResponseHeaders);
      tcpIncoming.socket = socket;
      tcpIncoming.req = self;
      tcpIncoming.httpVersionMajor = httpVerMajor;
      tcpIncoming.httpVersionMinor = httpVerMinor;
      tcpIncoming.httpVersion = httpVerMajor + '.' + httpVerMinor;
      self.res = tcpIncoming;
      var connHdr = (responseHeaders['connection'] || '').toLowerCase();
      if (httpVerMajor === 1 && httpVerMinor === 0) {
        tcpIncoming.shouldKeepAlive = connHdr.indexOf('keep-alive') !== -1;
      } else {
        tcpIncoming.shouldKeepAlive = connHdr.indexOf('close') === -1;
      }
      if (self.shouldKeepAlive && !tcpIncoming.shouldKeepAlive) {
        self.shouldKeepAlive = false;
      }

      tcpIncoming.on('end', function() {
        clearSocketTimeoutListener(self, socket);
        if (self.shouldKeepAlive && !tcpIncoming.aborted) {
          if (!self._ended || !self.writableEnded || !self.finished) {
            self._responseEndedBeforeRequestEnd = true;
            return;
          }
          if (self._pendingSocketDrain) {
            self._waitingForSocketDrain = true;
            return;
          }
          releaseSocket();
        } else if (!socket.destroyed) {
          try {
            if (typeof socket.end === 'function') socket.end();
            else socket.destroy();
          } catch (_closeErr) {
            try { socket.destroy(); } catch (_destroyErr) {}
          }
        }
      });
      tcpIncoming.on('timeout', function() {
        self.emit('timeout');
      });

      responseEmitted = true;
      self.emit('response', tcpIncoming);

      if (bodyStart.length > 0) {
        if (isChunked) {
          processChunkedData(bodyStart);
        } else {
          var bodyStartBytes = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
            ? Buffer.byteLength(bodyStart, 'utf8') : bodyStart.length;
          bodyBytesReceived += bodyStartBytes;
          var bodyStartBuf = (typeof Buffer !== 'undefined') ? Buffer.from(bodyStart, 'utf8') : bodyStart;
          if (typeof tcpIncoming._pushBodyChunk === 'function') tcpIncoming._pushBodyChunk(bodyStartBuf);
          else if (typeof tcpIncoming.push === 'function') tcpIncoming.push(bodyStartBuf);
          else tcpIncoming.emit('data', bodyStartBuf);
        }
      }
      if (!isChunked && contentLength >= 0 && bodyBytesReceived >= contentLength) {
        finishResponse();
      }
      if (statusCode === 204 || statusCode === 304 || self.method === 'HEAD') {
        finishResponse();
      }
    } else if (tcpIncoming) {
      if (isChunked) {
        processChunkedData(str);
      } else {
        var strBytes = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(str, 'utf8') : str.length;
        bodyBytesReceived += strBytes;
        var strBuf = (typeof Buffer !== 'undefined') ? Buffer.from(str, 'utf8') : str;
        if (typeof tcpIncoming._pushBodyChunk === 'function') tcpIncoming._pushBodyChunk(strBuf);
        else if (typeof tcpIncoming.push === 'function') tcpIncoming.push(strBuf);
        else tcpIncoming.emit('data', strBuf);
        if (contentLength >= 0 && bodyBytesReceived >= contentLength) {
          finishResponse();
        }
      }
    }
  }

  function onEnd() {
    if (!responseEmitted) {
      abortResponse();
      return;
    }
    if (responseEnded) return;
    if (contentLength >= 0 || isChunked || (tcpIncoming && tcpIncoming.shouldKeepAlive)) {
      abortResponse();
      return;
    }
    finishResponse();
  }

  function onClose() {
    if (!responseEmitted || !responseEnded) {
      abortResponse();
      return;
    }
    if (!self._closed) {
      self._closed = true;
      self.emit('close');
    }
  }

  function onError(err) {
    socket._hadError = true;
    if (self._aborted) return;
    self.emit('error', err);
  }

  socket._httpMessage = self;
  socket.on('data', onData);
  socket.on('end', onEnd);
  socket.on('close', onClose);
  socket.on('error', onError);

  if (self.timeout !== undefined && self.timeout !== null) {
    listenSocketTimeout(self);
    setSocketTimeout(socket, self.timeout);
  } else if (self.agent && self.agent.options && self.agent.options.timeout !== undefined) {
    listenSocketTimeout(self);
    setSocketTimeout(socket, self.agent.options.timeout);
  }

  function writeRawRequest() {
    var rawRequest = self._pendingRawRequest || '';
    if (rawRequestWritten || self.destroyed || self._aborted || !rawRequest) return;
    rawRequestWritten = true;
    self._pendingSocketDrain = true;
    try {
      socket.write(rawRequest, function(writeErr) {
        if (writeErr) {
          socket._hadError = true;
          self.emit('error', writeErr);
          return;
        }
        self._pendingSocketDrain = false;
        maybeReleaseSocketAfterFlush();
      });
    } catch (writeErr) {
      socket._hadError = true;
      self.emit('error', writeErr);
    }
  }
  self._writePendingRequest = writeRawRequest;

  if (socket.connecting) {
    socket.once('connect', writeRawRequest);
  } else {
    writeRawRequest();
  }
};

// TCP-based IncomingMessage for client responses
function TcpIncomingMessage(statusCode, statusMessage, headers, rawHeaders) {
  var ReadableCtor = upgradeTcpIncomingMessagePrototype();
  if (ReadableCtor) {
    ReadableCtor.call(this);
  } else {
    EventEmitter.call(this);
  }
  this.statusCode = statusCode;
  this.statusMessage = statusMessage;
  this.headers = headers;
  this.rawHeaders = rawHeaders || [];
  this.trailers = {};
  this.rawTrailers = [];
  this.httpVersion = '1.1';
  this.httpVersionMajor = 1;
  this.httpVersionMinor = 1;
  this.aborted = false;
  this.complete = false;
  this._consumed = false;
  this.readable = true;
  this.socket = null;
  this.method = null;
  this.url = null;
  // Determine shouldKeepAlive based on HTTP version and Connection header
  var connHeader = (headers && headers['connection']) ? headers['connection'].toLowerCase() : '';
  if (this.httpVersionMajor === 1 && this.httpVersionMinor === 0) {
    this.shouldKeepAlive = connHeader.indexOf('keep-alive') !== -1;
  } else {
    this.shouldKeepAlive = connHeader.indexOf('close') === -1;
  }
  this._httpCloseEmitted = false;
  this._manualChunks = [];
  this._manualReadableScheduled = false;
  this._manualFlowing = false;
  this._manualEnded = false;
  this._manualEndEmitted = false;
}
TcpIncomingMessage.prototype = Object.create((Readable || EventEmitter).prototype);
TcpIncomingMessage.prototype.constructor = TcpIncomingMessage;

Object.defineProperty(TcpIncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

TcpIncomingMessage.prototype._read = function() {};
TcpIncomingMessage.prototype._emitHttpClose = function() {
  if (this._httpCloseEmitted) return;
  this._httpCloseEmitted = true;
  this.emit('close');
};
TcpIncomingMessage.prototype._scheduleManualReadable = function() {
  var self = this;
  if (self._manualReadableScheduled) return;
  self._manualReadableScheduled = true;
  setTimeout(function() {
    self._manualReadableScheduled = false;
    if (self._manualChunks.length > 0 && self.listenerCount && self.listenerCount('readable') > 0) {
      self.emit('readable');
    }
    if (self._manualEnded && self._manualChunks.length === 0) {
      self._emitManualEnd();
    }
  }, 0);
};
TcpIncomingMessage.prototype._emitManualEnd = function() {
  if (this._manualEndEmitted) return;
  this._manualEndEmitted = true;
  this.complete = true;
  this.emit('end');
  this._emitHttpClose();
};
TcpIncomingMessage.prototype._flushManualData = function() {
  var self = this;
  if (!self._manualFlowing && (!self.listenerCount || self.listenerCount('data') === 0)) {
    return;
  }
  self._manualFlowing = true;
  while (self._manualChunks.length > 0) {
    self.emit('data', self._manualChunks.shift());
  }
  if (self._manualEnded && self._manualChunks.length === 0) {
    self._emitManualEnd();
  }
};
TcpIncomingMessage.prototype._pushBodyChunk = function(chunk) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && typeof this.push === 'function') {
    this.push(chunk);
    return;
  }
  if (this._encoding && typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
    chunk = chunk.toString(this._encoding);
  }
  this._manualChunks.push(chunk);
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else {
    this._scheduleManualReadable();
  }
};
TcpIncomingMessage.prototype._finishResponse = function() {
  var ReadableCtor = getReadableCtor();
  this.complete = true;
  if (ReadableCtor && this._readableState && typeof this.push === 'function') {
    if (this._readableState && this._readableState.endEmitted) {
      this._emitHttpClose();
      return;
    }
    this.push(null);
    if (this._readableState && this._readableState.endEmitted) {
      this._emitHttpClose();
    } else {
      var self = this;
      this.once('end', function() {
        self._emitHttpClose();
      });
    }
    return;
  }
  this._manualEnded = true;
  if (this._manualFlowing || (this.listenerCount && this.listenerCount('data') > 0)) {
    this._flushManualData();
  } else if (this._manualChunks.length === 0) {
    this._emitManualEnd();
  } else {
    this._scheduleManualReadable();
  }
};
TcpIncomingMessage.prototype.setEncoding = function(enc) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.setEncoding) {
    ReadableCtor.prototype.setEncoding.call(this, enc);
    return this;
  }
  this._encoding = enc;
  for (var i = 0; i < this._manualChunks.length; i++) {
    var chunk = this._manualChunks[i];
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
      this._manualChunks[i] = chunk.toString(enc);
    }
  }
  return this;
};
TcpIncomingMessage.prototype.pause = function() {
  var ReadableCtor = getReadableCtor();
  this._paused = true;
  this._manualFlowing = false;
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.pause) {
    return ReadableCtor.prototype.pause.call(this);
  }
  return this;
};
TcpIncomingMessage.prototype.resume = function() {
  var ReadableCtor = getReadableCtor();
  this._paused = false;
  this._manualFlowing = true;
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.resume) {
    return ReadableCtor.prototype.resume.call(this);
  }
  this._flushManualData();
  return this;
};
TcpIncomingMessage.prototype.read = function(size) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.read) {
    return ReadableCtor.prototype.read.call(this, size);
  }
  if (this._manualChunks.length === 0) {
    if (this._manualEnded) this._emitManualEnd();
    return null;
  }
  var chunk = this._manualChunks.shift();
  if (this._manualChunks.length === 0 && this._manualEnded) {
    var self = this;
    setTimeout(function() {
      self._emitManualEnd();
    }, 0);
  }
  return chunk;
};
TcpIncomingMessage.prototype.on = function(event, listener) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && typeof this.push === 'function' && typeof ReadableCtor.prototype.on === 'function') {
    return ReadableCtor.prototype.on.call(this, event, listener);
  }
  EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'data') {
    this._manualFlowing = true;
    this._flushManualData();
  } else if (event === 'readable' && this._manualChunks.length > 0) {
    this._scheduleManualReadable();
  } else if (event === 'end' && this._manualEnded && this._manualChunks.length === 0) {
    this._emitManualEnd();
  }
  return this;
};
TcpIncomingMessage.prototype.addListener = TcpIncomingMessage.prototype.on;
TcpIncomingMessage.prototype.pipe = function(dest, options) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.pipe) {
    return ReadableCtor.prototype.pipe.call(this, dest, options);
  }
  var self = this;
  self.on('data', function(chunk) {
    var canWrite = dest.write(chunk);
    if (!canWrite && self.pause) self.pause();
  });
  dest.on('drain', function() { if (self.resume) self.resume(); });
  self.on('end', function() {
    if (!options || options.end !== false) {
      dest.end();
    }
  });
  return dest;
};
TcpIncomingMessage.prototype._destroy = function(err, callback) {
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(); } catch(e) {}
  }
  if (typeof callback === 'function') callback(err || null);
};
TcpIncomingMessage.prototype.destroy = function(err) {
  var ReadableCtor = getReadableCtor();
  if (ReadableCtor && this._readableState && ReadableCtor.prototype.destroy) {
    return ReadableCtor.prototype.destroy.call(this, err);
  }
  if (this.destroyed) return this;
  this.destroyed = true;
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(); } catch(e) {}
  }
  if (err) this.emit('error', err);
  this._emitHttpClose();
  return this;
};
TcpIncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs, callback);
  }
  return this;
};
_attachHttpAsyncIterator(TcpIncomingMessage.prototype);

function request(options, callback) {
  var requestOptions = options;
  if (typeof options === "string") {
    try {
      var parsed = new URL(options);
      requestOptions = {
        __exactOriginalUrl: options,
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : undefined,
        path: parsed.pathname + (parsed.search || ''),
        method: "GET"
      };
    } catch(e) {
      requestOptions = { href: options, method: "GET" };
    }
  } else if (options instanceof URL) {
    requestOptions = {
      protocol: options.protocol,
      hostname: options.hostname,
      port: options.port ? Number(options.port) : undefined,
      path: options.pathname + (options.search || ''),
      method: "GET"
    };
  }
  // Support request(url, options, callback) signature
  if (typeof callback === 'object' && callback !== null) {
    var extraOptions = callback;
    callback = arguments[2];
    if (typeof requestOptions === 'object') {
      for (var k in extraOptions) {
        if (Object.prototype.hasOwnProperty.call(extraOptions, k)) {
          requestOptions[k] = extraOptions[k];
        }
      }
      if (hasUrlOptionOverrides(extraOptions)) {
        delete requestOptions.__exactOriginalUrl;
      }
    }
  }
  return new ClientRequest(requestOptions, callback);
}

function get(options, callback) {
  var req = request(options, callback);
  req.end();
  return req;
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------
function Agent(options) {
  if (!(this instanceof Agent)) {
    return new Agent(options);
  }
  EventEmitter.call(this);
  this.options = options || {};
  this.defaultPort = this.options.defaultPort || 80;
  this.protocol = this.options.protocol || 'http:';
  if (this.options.noDelay === undefined) {
    this.options.noDelay = true;
  }
  this.keepAlive = this.options.keepAlive || false;
  this.keepAliveMsecs = this.options.keepAliveMsecs || 1000;
  this.maxSockets = this.options.maxSockets || Agent.defaultMaxSockets;
  this.maxFreeSockets = this.options.maxFreeSockets || 256;
  this.maxTotalSockets = this.options.maxTotalSockets;
  this.scheduling = this.options.scheduling || 'lifo';
  this.totalSocketCount = 0;
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
  this.agentKeepAliveTimeoutBuffer =
    typeof this.options.agentKeepAliveTimeoutBuffer === 'number' &&
    this.options.agentKeepAliveTimeoutBuffer >= 0 &&
    isFinite(this.options.agentKeepAliveTimeoutBuffer)
      ? this.options.agentKeepAliveTimeoutBuffer
      : 1000;

  if (this.maxTotalSockets !== undefined) {
    if (typeof this.maxTotalSockets !== 'number') {
      var receivedValue = typeof this.maxTotalSockets === 'string'
        ? "'" + this.maxTotalSockets + "'"
        : String(this.maxTotalSockets);
      var maxTotalTypeErr = new TypeError('The "maxTotalSockets" argument must be of type number. Received type ' +
        typeof this.maxTotalSockets + ' (' + receivedValue + ')');
      maxTotalTypeErr.code = 'ERR_INVALID_ARG_TYPE';
      throw maxTotalTypeErr;
    }
    if (this.maxTotalSockets <= 0 || !isFinite(this.maxTotalSockets)) {
      if (this.maxTotalSockets !== Infinity) {
        var maxTotalRangeErr = new RangeError('The value of "maxTotalSockets" is out of range. It must be > 0. Received ' + this.maxTotalSockets);
        maxTotalRangeErr.code = 'ERR_OUT_OF_RANGE';
        throw maxTotalRangeErr;
      }
    }
  } else {
    this.maxTotalSockets = Infinity;
  }

  var self = this;
  this.on('free', function(socket, requestOptions) {
    var name = self.getName(requestOptions);
    if (!socket || socket.writable === false || socket.destroyed) {
      if (socket && typeof socket.destroy === 'function') {
        socket.destroy();
      }
      return;
    }

    var requests = self.requests[name];
    if (requests && requests.length > 0) {
      var nextReq = requests.shift();
      setRequestSocket(self, nextReq, socket, requestOptions);
      if (requests.length === 0) {
        delete self.requests[name];
      }
      return;
    }

    var req = socket._httpMessage;
    if (!req || !req.shouldKeepAlive || !self.keepAlive) {
      socket.destroy();
      return;
    }

    var freeSockets = self.freeSockets[name] || [];
    var freeLen = freeSockets.length;
    var activeLen = self.sockets[name] ? self.sockets[name].length : 0;
    if (self.totalSocketCount > self.maxTotalSockets ||
        activeLen + freeLen > self.maxSockets ||
        freeLen >= self.maxFreeSockets ||
        !self.keepSocketAlive(socket)) {
      socket.destroy();
      return;
    }

    self.freeSockets[name] = freeSockets;
    socket._httpMessage = null;
    self.removeSocket(socket, requestOptions);
    socket.once('error', freeSocketErrorListener);
    freeSockets.push(socket);
  });
}
Agent.prototype = Object.create(EventEmitter.prototype);
Agent.prototype.constructor = Agent;
Agent.defaultMaxSockets = Infinity;

Agent.prototype.destroy = function() {
  var key;
  for (key in this.sockets) {
    var socks = this.sockets[key];
    if (Array.isArray(socks)) {
      for (var i = 0; i < socks.length; i++) {
        try { socks[i].destroy(); } catch(e) {}
      }
    }
  }
  for (key in this.freeSockets) {
    var socks2 = this.freeSockets[key];
    if (Array.isArray(socks2)) {
      for (var j = 0; j < socks2.length; j++) {
        try { socks2[j].destroy(); } catch(e) {}
      }
    }
  }
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
};

Agent.prototype.getName = function(options) {
  if (!options) options = {};
  var name = (options.host || 'localhost') + ':' +
    (options.port || '') + ':' +
    (options.localAddress || '');
  if (options.socketPath) name += ':' + options.socketPath;
  if (options.family === 4 || options.family === 6) {
    if (!options.socketPath) name += ':';
    name += options.family;
  }
  return name;
};

Agent.prototype.addRequest = function(req, options, port, localAddress) {
  if (typeof options === 'string') {
    options = { host: options, port: port, localAddress: localAddress };
  }
  options = Object.assign({}, options || {}, this.options);
  if (options.socketPath) {
    options.path = options.socketPath;
  } else {
    delete options.path;
  }
  var name = this.getName(options);
  this.sockets[name] = this.sockets[name] || [];

  var freeSockets = this.freeSockets[name];
  var socket = null;
  if (freeSockets) {
    while (freeSockets.length > 0 && freeSockets[0].destroyed) {
      freeSockets.shift();
    }
    socket = this.scheduling === 'fifo' ? freeSockets.shift() : freeSockets.pop();
    if (freeSockets.length === 0) {
      delete this.freeSockets[name];
    }
  }

  var freeLen = freeSockets ? freeSockets.length : 0;
  var socketLen = freeLen + this.sockets[name].length;

  if (socket) {
    asyncResetHandle(socket);
    this.reuseSocket(socket, req);
    this.sockets[name].push(socket);
    setRequestSocket(this, req, socket, options);
    return;
  }

  if (socketLen < this.maxSockets && this.totalSocketCount < this.maxTotalSockets) {
    var self = this;
    this.createSocket(req, options, function(err, createdSocket) {
      if (err) {
        req.onSocket(createdSocket, options, err);
        return;
      }
      setRequestSocket(self, req, createdSocket, options);
    });
    return;
  }

  if (!this.requests[name]) {
    this.requests[name] = [];
  }
  req._queuedAgentOptions = options;
  this.requests[name].push(req);
};

Agent.prototype.createConnection = function(options, callback) {
  var net;
  try { net = require('net'); } catch(e) { return null; }
  return net.createConnection(options, callback);
};

function installAgentListeners(agent, socket, options) {
  function onFree() {
    agent.emit('free', socket, options);
  }
  function onClose() {
    agent.totalSocketCount--;
    agent.removeSocket(socket, options);
  }
  function onTimeout() {
    var pools = agent.freeSockets;
    for (var name in pools) {
      if (Object.prototype.hasOwnProperty.call(pools, name) && pools[name].indexOf(socket) !== -1) {
        socket.destroy();
        return;
      }
    }
  }
  function onRemove() {
    agent.totalSocketCount--;
    agent.removeSocket(socket, options);
    socket.removeListener('close', onClose);
    socket.removeListener('free', onFree);
    socket.removeListener('timeout', onTimeout);
    socket.removeListener('agentRemove', onRemove);
  }

  socket.on('free', onFree);
  socket.on('close', onClose);
  socket.on('timeout', onTimeout);
  socket.on('agentRemove', onRemove);
}

Agent.prototype.createSocket = function(req, options, callback) {
  options = Object.assign({}, options || {}, this.options);
  if (options.socketPath) {
    options.path = options.socketPath;
  } else {
    delete options.path;
  }

  var timeout = req.timeout;
  if (timeout === undefined || timeout === null) {
    timeout = this.options.timeout;
  }
  if (timeout !== undefined) {
    options.timeout = timeout;
  }

  var name = this.getName(options);
  var self = this;
  var finished = false;

  function oncreate(err, socket) {
    if (finished) return;
    finished = true;
    if (err) {
      callback(err, socket || null);
      return;
    }
    self.sockets[name] = self.sockets[name] || [];
    self.sockets[name].push(socket);
    self.totalSocketCount++;
    installAgentListeners(self, socket, options);
    callback(null, socket);
  }

  if (this.keepAlive) {
    options.keepAlive = true;
    options.keepAliveInitialDelay = this.keepAliveMsecs;
  }

  var createConnection = options.createConnection;
  if (typeof createConnection === 'function') {
    try {
      var maybeSocket = createConnection(options, oncreate);
      if (maybeSocket) {
        oncreate(null, maybeSocket);
      }
    } catch (err) {
      oncreate(err, null);
    }
    return;
  }

  var newSocket = this.createConnection(options, oncreate);
  if (newSocket) {
    oncreate(null, newSocket);
  }
};

Agent.prototype.removeSocket = function(socket, options) {
  var name = this.getName(options || {});
  var sets = [this.sockets];
  if (!socket.writable) {
    sets.push(this.freeSockets);
  }

  for (var i = 0; i < sets.length; i++) {
    var pool = sets[i];
    if (pool[name]) {
      var index = pool[name].indexOf(socket);
      if (index !== -1) {
        pool[name].splice(index, 1);
        if (pool[name].length === 0) {
          delete pool[name];
        }
      }
    }
  }

  var req = null;
  var reqOptions = null;
  if (this.requests[name] && this.requests[name].length > 0) {
    req = this.requests[name].shift();
    if (this.requests[name].length === 0) {
      delete this.requests[name];
    }
    reqOptions = req._queuedAgentOptions || options;
  } else {
    for (var key in this.requests) {
      if (!Object.prototype.hasOwnProperty.call(this.requests, key) || !this.requests[key] || this.requests[key].length === 0) continue;
      if (this.sockets[key] && this.sockets[key].length > 0) continue;
      req = this.requests[key].shift();
      if (this.requests[key].length === 0) {
        delete this.requests[key];
      }
      reqOptions = req && req._queuedAgentOptions;
      break;
    }
  }

  if (req && reqOptions) {
    var self = this;
    req._queuedAgentOptions = undefined;
    this.createSocket(req, reqOptions, function(err, newSocket) {
      if (err) {
        req.onSocket(newSocket, reqOptions, err);
        return;
      }
      setRequestSocket(self, req, newSocket, reqOptions);
    });
  }
};

Agent.prototype.keepSocketAlive = function(socket) {
  if (typeof socket.setKeepAlive === 'function') {
    socket.setKeepAlive(true, this.keepAliveMsecs);
  }
  if (typeof socket.unref === 'function') {
    socket.unref();
  }

  var agentTimeout = this.options.timeout || 0;
  var canKeepSocketAlive = true;
  if (socket._httpMessage && socket._httpMessage.res && socket._httpMessage.res.headers) {
    var keepAliveHint = socket._httpMessage.res.headers['keep-alive'];
    if (keepAliveHint) {
      var hintMatch = /^timeout=(\d+)/.exec(keepAliveHint);
      if (hintMatch) {
        var hintedTimeout = (parseInt(hintMatch[1], 10) * 1000) - this.agentKeepAliveTimeoutBuffer;
        hintedTimeout = hintedTimeout > 0 ? hintedTimeout : 0;
        if (hintedTimeout === 0) {
          canKeepSocketAlive = false;
        } else if (agentTimeout === 0 || hintedTimeout < agentTimeout) {
          agentTimeout = hintedTimeout;
        }
      }
    }
  }

  if (typeof socket.setTimeout === 'function') {
    socket.setTimeout(agentTimeout);
  }
  return canKeepSocketAlive;
};

Agent.prototype.reuseSocket = function(socket, req) {
  socket.removeListener('error', freeSocketErrorListener);
  req.reusedSocket = true;
  if (typeof socket.ref === 'function') {
    socket.ref();
  }
};

var globalAgent = new Agent();

var METHODS = [
  "ACL", "BIND", "CHECKOUT", "CONNECT", "COPY", "DELETE", "GET", "HEAD",
  "LINK", "LOCK", "M-SEARCH", "MERGE", "MKACTIVITY", "MKCALENDAR",
  "MKCOL", "MOVE", "NOTIFY", "OPTIONS", "PATCH", "POST", "PROPFIND",
  "PROPPATCH", "PURGE", "PUT", "QUERY", "REBIND", "REPORT", "SEARCH",
  "SOURCE", "SUBSCRIBE", "TRACE", "UNBIND", "UNLINK", "UNLOCK",
  "UNSUBSCRIBE"
];

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
  this._state = 0; // 0=REQUEST_LINE, 1=HEADERS, 2=BODY, 3=CHUNKED_SIZE, 4=CHUNKED_DATA, 5=CHUNKED_TRAILER, 6=DISCARD_BODY
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';
  this._isChunked = false;
  this._chunkRemaining = 0;
  this.onRequest = null;
  this.onHeadersComplete = null;
  this.onError = null;
}

var MAX_PREBUFFERED_HTTP_REQUEST_BODY = 1024 * 1024;

function _toHttpParserString(chunk) {
  if (typeof chunk === 'string') {
    return chunk;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) {
    return chunk.toString('latin1');
  }
  if (chunk && typeof chunk === 'object' && typeof Buffer !== 'undefined') {
    try {
      if (ArrayBuffer.isView(chunk)) {
        return Buffer
          .from(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0)
          .toString('latin1');
      }
      if (chunk instanceof ArrayBuffer) {
        return Buffer.from(chunk).toString('latin1');
      }
    } catch (_coerceErr) {}
  }
  try {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(chunk).toString('latin1');
    }
  } catch (_bufferErr) {}
  try {
    return chunk.toString('latin1');
  } catch (_stringErr) {
    return String(chunk);
  }
}

HttpRequestParser.prototype.execute = function(chunk) {
  chunk = _toHttpParserString(chunk);
  this._buffer += chunk;
  this._parse();
};

HttpRequestParser.prototype._emitParseError = function() {
  this._state = 0;
  this._buffer = '';
  this._method = '';
  this._url = '';
  this._httpVersion = '1.1';
  this._headers = {};
  this._rawHeaders = [];
  this._contentLength = 0;
  this._bodyData = '';
  this._isChunked = false;
  this._chunkRemaining = 0;
  if (typeof this.onError === 'function') {
    this.onError();
  }
};

HttpRequestParser.prototype._parse = function() {
  while (this._buffer.length > 0) {
    if (this._state === 0) {
      var idx = this._buffer.indexOf('\r\n');
      if (idx === -1) return;
      var line = this._buffer.substring(0, idx);
      this._buffer = this._buffer.substring(idx + 2);
      var spaceIdx = line.indexOf(' ');
      if (spaceIdx <= 0) {
        this._emitParseError();
        return;
      }
      this._method = line.substring(0, spaceIdx);
      var rest = line.substring(spaceIdx + 1);
      var spaceIdx2 = rest.lastIndexOf(' ');
      if (spaceIdx2 <= 0) {
        this._emitParseError();
        return;
      }
      this._url = rest.substring(0, spaceIdx2);
      var ver = rest.substring(spaceIdx2 + 1);
      if (!/^HTTP\/\d+\.\d+$/.test(ver)) {
        this._emitParseError();
        return;
      }
      this._httpVersion = ver.substring(5);
      this._state = 1;
    } else if (this._state === 1) {
      var idx2 = this._buffer.indexOf('\r\n');
      if (idx2 === -1) return;
      if (idx2 === 0) {
        this._buffer = this._buffer.substring(2);
        if (typeof this.onHeadersComplete === 'function') {
          this.onHeadersComplete();
        }
        // Check for chunked transfer encoding
        var te = this._headers['transfer-encoding'];
        if (te && te.toLowerCase().indexOf('chunked') !== -1) {
          this._isChunked = true;
          this._state = 3;
          continue;
        }
        var cl = this._headers['content-length'];
        if (cl !== undefined) {
          this._contentLength = parseInt(cl, 10) || 0;
        } else {
          this._contentLength = 0;
        }
        if (this._contentLength > MAX_PREBUFFERED_HTTP_REQUEST_BODY) {
          this._emitRequest({
            hasBody: true,
            bodyComplete: false,
            oversizedBody: true,
            deferReset: true
          });
          this._state = 6;
          continue;
        }
        if (this._contentLength > 0) {
          this._state = 2;
        } else {
          this._emitRequest();
        }
      } else {
        var headerLine = this._buffer.substring(0, idx2);
        this._buffer = this._buffer.substring(idx2 + 2);
        var colonIdx = headerLine.indexOf(':');
        if (colonIdx > 0) {
          var key = headerLine.substring(0, colonIdx);
          var value = headerLine.substring(colonIdx + 1).trim();
          var keyLower = key.toLowerCase();
          if (this._headers[keyLower] !== undefined && !_singleValueHeaders[keyLower]) {
            this._headers[keyLower] += ', ' + value;
          } else {
            this._headers[keyLower] = value;
          }
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
    } else if (this._state === 3) {
      // CHUNKED_SIZE
      var nlIdx = this._buffer.indexOf('\r\n');
      if (nlIdx === -1) return;
      var sizeStr = this._buffer.substring(0, nlIdx).split(';')[0].trim();
      this._chunkRemaining = parseInt(sizeStr, 16);
      this._buffer = this._buffer.substring(nlIdx + 2);
      if (isNaN(this._chunkRemaining) || this._chunkRemaining === 0) {
        this._state = 5;
      } else {
        this._state = 4;
      }
    } else if (this._state === 4) {
      // CHUNKED_DATA
      if (this._buffer.length < this._chunkRemaining) {
        this._bodyData += this._buffer;
        this._chunkRemaining -= this._buffer.length;
        this._buffer = '';
        return;
      }
      this._bodyData += this._buffer.substring(0, this._chunkRemaining);
      this._buffer = this._buffer.substring(this._chunkRemaining);
      this._chunkRemaining = 0;
      if (this._buffer.length >= 2) {
        this._buffer = this._buffer.substring(2);
        this._state = 3;
      } else {
        this._state = 3;
        return;
      }
    } else if (this._state === 5) {
      // CHUNKED_TRAILER
      var nlIdx2 = this._buffer.indexOf('\r\n');
      if (nlIdx2 === -1) return;
      if (nlIdx2 === 0) {
        this._buffer = this._buffer.substring(2);
        this._emitRequest();
      } else {
        this._buffer = this._buffer.substring(nlIdx2 + 2);
      }
    } else if (this._state === 6) {
      if (this._buffer.length >= this._contentLength) {
        this._buffer = this._buffer.substring(this._contentLength);
        this._state = 0;
        this._method = '';
        this._url = '';
        this._httpVersion = '1.1';
        this._headers = {};
        this._rawHeaders = [];
        this._contentLength = 0;
        this._bodyData = '';
        this._isChunked = false;
        this._chunkRemaining = 0;
      } else {
        this._contentLength -= this._buffer.length;
        this._buffer = '';
        return;
      }
    }
  }
};

HttpRequestParser.prototype._emitRequest = function(options) {
  options = options || {};
  var verParts = this._httpVersion.split('.');
  var reqData = {
    method: this._method,
    url: this._url,
    httpVersion: this._httpVersion,
    httpVersionMajor: verParts[0] !== undefined ? (parseInt(verParts[0], 10) || 1) : 1,
    httpVersionMinor: verParts[1] !== undefined ? parseInt(verParts[1], 10) : 1,
    headers: this._headers,
    rawHeaders: this._rawHeaders,
    body: this._bodyData,
    hasBody: options.hasBody === true || this._bodyData.length > 0,
    bodyComplete: options.bodyComplete !== false,
    oversizedBody: options.oversizedBody === true
  };
  if (options.deferReset !== true) {
    this._state = 0;
    this._method = '';
    this._url = '';
    this._httpVersion = '1.1';
    this._headers = {};
    this._rawHeaders = [];
    this._contentLength = 0;
    this._bodyData = '';
    this._isChunked = false;
    this._chunkRemaining = 0;
  }

  if (typeof this.onRequest === 'function') {
    this.onRequest(reqData);
  }
};

HttpRequestParser.prototype.close = function() {
  this.onRequest = null;
  this.onError = null;
};

// ---------------------------------------------------------------------------
// ServerResponse
// ---------------------------------------------------------------------------
function ServerResponse(reqOrServerId, requestId) {
  EventEmitter.call(this);
  this.statusCode = 200;
  this.statusMessage = undefined;
  this._headers = {};
  this._headerNames = {};
  this[kOutHeaders] = null;
  this._headersSent = false;
  this._finished = false;
  this._streaming = false;
  this._bodyParts = [];
  this.socket = null;
  this.writableEnded = false;
  this.writableFinished = false;
  this.sendDate = true;

  if (typeof reqOrServerId === 'number') {
    this._serverId = reqOrServerId;
    this._requestId = requestId || 0;
    this._nativeMode = true;
    this._req = null;
  } else {
    this._serverId = 0;
    this._requestId = 0;
    this._nativeMode = false;
    this._req = reqOrServerId || null;
  }
}
ServerResponse.prototype = Object.create(EventEmitter.prototype);
ServerResponse.prototype.constructor = ServerResponse;

// headersSent as getter
Object.defineProperty(ServerResponse.prototype, 'headersSent', {
  get: function() { return this._headersSent; },
  set: function(v) { this._headersSent = v; },
  enumerable: true,
  configurable: true
});

// connection getter/setter
Object.defineProperty(ServerResponse.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

ServerResponse.prototype.assignSocket = function(socket) {
  this.socket = socket;
  if (socket) socket._httpMessage = this;
};

ServerResponse.prototype.detachSocket = function(socket) {
  if (socket) socket._httpMessage = null;
  this.socket = null;
};

ServerResponse.prototype.setHeader = function(name, value) {
  if (typeof name !== 'string') {
    throw new TypeError('Header name must be a valid HTTP token ["' + name + '"]');
  }
  var lc = name.toLowerCase();
  this._headers[lc] = value;
  this._headerNames[lc] = name;
  if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
    this[kOutHeaders] = {};
  }
  this[kOutHeaders][lc] = [name, value];
  return this;
};
ServerResponse.prototype.getHeader = function(name) {
  return this._headers[resolveHeaderName(name)];
};
ServerResponse.prototype.removeHeader = function(name) {
  var lc = resolveHeaderName(name);
  delete this._headers[lc];
  delete this._headerNames[lc];
  if (this[kOutHeaders] && typeof this[kOutHeaders] === 'object') {
    delete this[kOutHeaders][lc];
  }
  return this;
};
ServerResponse.prototype.getHeaders = function() {
  var clone = {};
  for (var k in this._headers) {
    if (Object.prototype.hasOwnProperty.call(this._headers, k)) clone[k] = this._headers[k];
  }
  return clone;
};
ServerResponse.prototype.getHeaderNames = function() {
  return Object.keys(this._headers);
};
ServerResponse.prototype.getRawHeaderNames = function() {
  var result = [];
  for (var k in this._headerNames) {
    if (Object.prototype.hasOwnProperty.call(this._headerNames, k)) {
      result.push(this._headerNames[k]);
    }
  }
  return result;
};
ServerResponse.prototype.hasHeader = function(name) {
  return resolveHeaderName(name) in this._headers;
};

ServerResponse.prototype.writeHead = function(statusCode, statusMessage, headers) {
  if (this._headersSent) return this;
  // Validate status code
  var sc = statusCode;
  if (typeof sc === 'string') sc = Number(sc);
  if (typeof sc !== 'number' || sc !== sc || sc < 100 || sc > 999 || Math.floor(sc) !== sc) {
    var scErr = new RangeError('Invalid status code: ' + String(statusCode === undefined ? 'undefined' : statusCode));
    scErr.code = 'ERR_HTTP_INVALID_STATUS_CODE';
    throw scErr;
  }
  this.statusCode = sc;
  if (typeof statusMessage === 'string') {
    this.statusMessage = statusMessage;
  } else if (typeof statusMessage === 'object' && statusMessage !== null) {
    headers = statusMessage;
  }
  if (headers) {
    if (Array.isArray(headers)) {
      for (var i = 0; i + 1 < headers.length; i += 2) {
        var hName = headers[i];
        var hVal = headers[i + 1];
        var lc = resolveHeaderName(hName);
        this._headers[lc] = hVal;
        this._headerNames[lc] = hName;
        if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
          this[kOutHeaders] = {};
        }
        this[kOutHeaders][lc] = [hName, hVal];
      }
    } else {
      for (var k in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, k)) {
          var lc2 = resolveHeaderName(k);
          this._headers[lc2] = headers[k];
          this._headerNames[lc2] = k;
          if (!this[kOutHeaders] || typeof this[kOutHeaders] !== 'object') {
            this[kOutHeaders] = {};
          }
          this[kOutHeaders][lc2] = [k, headers[k]];
        }
      }
    }
  }
  return this;
};

ServerResponse.prototype._renderHeaders = function() {
  if (this._header) {
    var sentErr = new Error('Cannot render headers after they are sent to the client');
    sentErr.code = 'ERR_HTTP_HEADERS_SENT';
    throw sentErr;
  }
  var source = this[kOutHeaders];
  if (!source || typeof source !== 'object') return {};
  var rendered = {};
  for (var key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    var entry = source[key];
    if (Array.isArray(entry) && entry.length >= 2) {
      rendered[entry[0]] = entry[1];
    }
  }
  return rendered;
};

ServerResponse.prototype.writeContinue = function() {
  if (!this.socket) return;
  try { this.socket.write('HTTP/1.1 100 Continue\r\n\r\n'); } catch(e) {}
};

ServerResponse.prototype.writeProcessing = function() {
  if (!this.socket) return;
  try { this.socket.write('HTTP/1.1 102 Processing\r\n\r\n'); } catch(e) {}
};

ServerResponse.prototype.writeEarlyHints = function(hints, callback) {
  if (!this.socket) { if (callback) callback(); return; }
  var head = 'HTTP/1.1 103 Early Hints\r\n';
  if (hints) {
    for (var k in hints) {
      if (Object.prototype.hasOwnProperty.call(hints, k)) {
        var vals = Array.isArray(hints[k]) ? hints[k] : [hints[k]];
        for (var i = 0; i < vals.length; i++) {
          head += k + ': ' + vals[i] + '\r\n';
        }
      }
    }
  }
  head += '\r\n';
  try { this.socket.write(head, callback); } catch(e) { if (callback) callback(e); }
};

ServerResponse.prototype.addTrailers = function(headers) {
  this._trailers = headers || {};
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
    var data;
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
      data = chunk.toString(encoding || 'utf8');
    } else {
      data = typeof chunk === 'string' ? chunk : String(chunk);
    }
    if (this._nativeMode && this._ensureStreaming()) {
      this._sendChunk(data);
    } else if (this._streaming && this.socket && !this._nativeMode) {
      // Already streaming: use chunked encoding to send data
      if (this._useChunkedEncoding) {
        var chunkLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(data) : data.length;
        try { this.socket.write(chunkLen.toString(16) + '\r\n' + data + '\r\n'); } catch(e) {}
      } else {
        try { this.socket.write(data); } catch(e) {}
      }
    } else if (this.socket && !this._nativeMode) {
      this._send(data);
    } else {
      this._bodyParts.push(data);
    }
  }
  if (callback) setTimeout(callback, 0);
  if (this.socket && this.socket._writeQueue && this.socket._writeQueue.length > 0) {
    return false;
  }
  return true;
};

ServerResponse.prototype._streamChunk = function(data, callback) {
  if (!this._headersSent) {
    var statusMsg = this.statusMessage !== undefined ? this.statusMessage : (STATUS_CODES[this.statusCode] || 'Unknown');
    var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';
    for (var k in this._headers) {
      if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
        var casedName = this._headerNames[k] || toHeaderCase(k);
        head += casedName + ': ' + this._headers[k] + '\r\n';
      }
    }
    head += '\r\n';
    this._headersSent = true;
    this._streaming = true;
    this.socket.write(head + data, callback ? function() { setTimeout(callback, 0); } : undefined);
  } else {
    this.socket.write(data, callback ? function() { setTimeout(callback, 0); } : undefined);
  }
};

ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) setTimeout(callback, 0); return this; }
  if (chunk !== undefined && chunk !== null) {
    if (!this._nativeMode && !this._headersSent && !this._streaming) {
      var data;
      if (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk)) {
        data = chunk.toString(encoding || 'utf8');
      } else {
        data = typeof chunk === 'string' ? chunk : String(chunk);
      }
      this._bodyParts.push(data);
    } else {
      this.write(chunk, encoding);
    }
  }
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

ServerResponse.prototype._sendSocketResponse = function() {
  var socket = this.socket;
  if (socket) {
    var req = this._req;
    var reqConnection = (req && req.headers && req.headers['connection']) || '';
    var reqTE = (req && req.headers && req.headers['te']) || '';
    var httpVersionMajor = (req && req.httpVersionMajor != null) ? req.httpVersionMajor : 1;
    var httpVersionMinor = (req && req.httpVersionMinor != null) ? req.httpVersionMinor : 1;
    var respConnection = this._headers['connection'] || '';
    var reqConnectionLower = reqConnection.toLowerCase();
    var respConnectionLower = (typeof respConnection === 'string') ? respConnection.toLowerCase() : '';

    var clientSupportsKeepAlive;
    if (httpVersionMajor === 1 && httpVersionMinor === 0) {
      clientSupportsKeepAlive = reqConnectionLower.indexOf('keep-alive') !== -1;
    } else {
      clientSupportsKeepAlive = reqConnectionLower.indexOf('close') === -1;
    }

    var keepAlive = clientSupportsKeepAlive
      && respConnectionLower.indexOf('close') === -1;

    if (!this._headersSent) {
      var body = this._bodyParts.join('');
      var statusMsg = this.statusMessage !== undefined ? this.statusMessage : (STATUS_CODES[this.statusCode] || 'Unknown');
      var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';

      if (httpVersionMajor === 1 && httpVersionMinor === 0) {
        var hasExplicitFraming = this._headers['content-length'] != null
          || (this._headers['transfer-encoding'] || '').toString().toLowerCase().indexOf('chunked') !== -1;
        var clientSendsTE = reqTE.toLowerCase().indexOf('chunked') !== -1;
        if (!hasExplicitFraming && !clientSendsTE) {
          keepAlive = false;
          if (this._headers['connection']) {
            this._headers['connection'] = 'close';
          }
        }
      }
      if (this._headers['content-length'] == null &&
          !(this._headers['transfer-encoding'] && this._headers['transfer-encoding'].toString().toLowerCase().indexOf('chunked') !== -1)) {
        if (this.statusCode !== 204 && this.statusCode !== 304) {
          var bodyLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
            ? Buffer.byteLength(body) : body.length;
          this._headers['content-length'] = String(bodyLen);
          this._headerNames['content-length'] = 'Content-Length';
        }
      }
      if (!this._headers['connection']) {
        this._headers['connection'] = keepAlive ? 'keep-alive' : 'close';
        this._headerNames['connection'] = 'Connection';
      } else {
        keepAlive = (typeof this._headers['connection'] === 'string')
          ? this._headers['connection'].toLowerCase().indexOf('keep-alive') !== -1
          : false;
      }
      if (this.sendDate && !this._headers['date']) {
        this._headers['date'] = new Date().toUTCString();
        this._headerNames['date'] = 'Date';
      }
      for (var k in this._headers) {
        if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
          var casedName = this._headerNames[k] || toHeaderCase(k);
          var hVal = this._headers[k];
          if (Array.isArray(hVal)) {
            for (var hi = 0; hi < hVal.length; hi++) {
              head += casedName + ': ' + hVal[hi] + '\r\n';
            }
          } else {
            head += casedName + ': ' + hVal + '\r\n';
          }
        }
      }
      head += '\r\n';
      this._headersSent = true;

      if (keepAlive) {
        try { socket.write(head + body); } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
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
      // Headers already sent (streaming mode)
      var remainingBody = this._bodyParts.join('');
      this._bodyParts = [];
      var streamKeepAlive = (this._headers['connection'] || '').toString().toLowerCase().indexOf('keep-alive') !== -1;
      if (!streamKeepAlive) {
        streamKeepAlive = keepAlive;
      }
      // Send any remaining body and the chunked terminator
      var endData = '';
      if (this._useChunkedEncoding) {
        if (remainingBody) {
          var remLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
            ? Buffer.byteLength(remainingBody) : remainingBody.length;
          endData = remLen.toString(16) + '\r\n' + remainingBody + '\r\n0\r\n\r\n';
        } else {
          endData = '0\r\n\r\n';
        }
      } else {
        endData = remainingBody || '';
      }
      if (streamKeepAlive) {
        try { socket.write(endData); } catch(e) {}
        this.detachSocket(socket);
        socket._httpMessage = null;
        socket._isIdle = true;
      } else {
        this.detachSocket(socket);
        socket.parser = null;
        socket[kTimeout] = null;
        try {
          socket.write(endData, function() {
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

ServerResponse.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs);
  }
  return this;
};

// _send is an internal method that flushes buffered writes to the socket
ServerResponse.prototype._send = function(data) {
  if (data && data.length > 0) {
    this._bodyParts.push(data);
  }
  // In socket mode, flush any pending body parts
  if (this.socket && !this._nativeMode && this._bodyParts.length > 0) {
    var flushed = this._bodyParts.join('');
    this._bodyParts = [];

    // Determine if chunked encoding should be used (HTTP/1.1 only)
    var req = this._req;
    var isHttp10 = req && req.httpVersionMajor === 1 && req.httpVersionMinor === 0;

    if (!this._headersSent) {
      // Start streaming - set connection before transfer-encoding for proper header ordering
      if (!this._headers['connection']) {
        this._headers['connection'] = 'close';
        this._headerNames['connection'] = 'Connection';
      }
      if (!isHttp10 && !this._headers['content-length'] && !this._headers['transfer-encoding']) {
        this._headers['transfer-encoding'] = 'chunked';
        this._headerNames['transfer-encoding'] = 'Transfer-Encoding';
        this._useChunkedEncoding = true;
      }
      var statusMsg = this.statusMessage !== undefined ? this.statusMessage : (STATUS_CODES[this.statusCode] || 'Unknown');
      var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';
      if (this.sendDate && !this._headers['date']) {
        this._headers['date'] = new Date().toUTCString();
        this._headerNames['date'] = 'Date';
      }
      for (var k in this._headers) {
        if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
          var casedName = this._headerNames[k] || toHeaderCase(k);
          var hVal = this._headers[k];
          if (Array.isArray(hVal)) {
            for (var hi = 0; hi < hVal.length; hi++) {
              head += casedName + ': ' + hVal[hi] + '\r\n';
            }
          } else {
            head += casedName + ': ' + hVal + '\r\n';
          }
        }
      }
      head += '\r\n';
      this._headersSent = true;
      this._streaming = true;
      if (this._useChunkedEncoding) {
        var chunkLen = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(flushed) : flushed.length;
        try { this.socket.write(head + chunkLen.toString(16) + '\r\n' + flushed + '\r\n'); } catch(e) {}
      } else {
        try { this.socket.write(head + flushed); } catch(e) {}
      }
    } else {
      // Already streaming
      if (this._useChunkedEncoding) {
        var chunkLen2 = (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function')
          ? Buffer.byteLength(flushed) : flushed.length;
        try { this.socket.write(chunkLen2.toString(16) + '\r\n' + flushed + '\r\n'); } catch(e) {}
      } else {
        try { this.socket.write(flushed); } catch(e) {}
      }
    }
  }
};

ServerResponse.prototype.flushHeaders = function() {
  if (this._headersSent) return;
  if (this.socket && !this._nativeMode) {
    var statusMsg = this.statusMessage !== undefined ? this.statusMessage : (STATUS_CODES[this.statusCode] || 'Unknown');
    var head = 'HTTP/1.1 ' + this.statusCode + ' ' + statusMsg + '\r\n';
    if (this.sendDate && !this._headers['date']) {
      this._headers['date'] = new Date().toUTCString();
      this._headerNames['date'] = 'Date';
    }
    for (var k in this._headers) {
      if (Object.prototype.hasOwnProperty.call(this._headers, k)) {
        var casedName = this._headerNames[k] || toHeaderCase(k);
        var hVal = this._headers[k];
        if (Array.isArray(hVal)) {
          for (var hi = 0; hi < hVal.length; hi++) {
            head += casedName + ': ' + hVal[hi] + '\r\n';
          }
        } else {
          head += casedName + ': ' + hVal + '\r\n';
        }
      }
    }
    head += '\r\n';
    this._headersSent = true;
    this._streaming = true;
    try { this.socket.write(head); } catch(e) {}
  }
};

ServerResponse.prototype.destroy = function(err) {
  if (this._finished) return this;
  this._finished = true;
  this.destroyed = true;
  this.writableEnded = true;
  this.writableFinished = true;
  if (this.socket && !this.socket.destroyed) {
    try { this.socket.destroy(err); } catch(e) {}
  }
  if (err) this.emit('error', err);
  this.emit('close');
  return this;
};

ServerResponse.prototype.cork = function() {};
ServerResponse.prototype.uncork = function() {};

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
  this.trailers = {};
  this.rawTrailers = [];
  this.path = requestData.path || requestData.url || '/';
  this.query = requestData.query || '';
  this.socket = null;
  this.readable = true;

  var rawBody = requestData.body || '';
  if (serverId && rawBody) {
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
      for (var ki = 0; ki < requestData.headers.length; ki++) {
        var pair = requestData.headers[ki];
        if (!pair || pair.length < 2) continue;
        var lkPair = resolveHeaderName(pair[0]);
        this.headers[lkPair] = pair[1];
        this.rawHeaders.push(pair[0], pair[1]);
      }
    } else if (typeof requestData.headers === 'object') {
      for (var kh in requestData.headers) {
        if (Object.prototype.hasOwnProperty.call(requestData.headers, kh)) {
          var lk = resolveHeaderName(kh);
          this.headers[lk] = requestData.headers[kh];
          this.rawHeaders.push(kh, requestData.headers[kh]);
        }
      }
    }
  }
  this.complete = false;
  this.aborted = false;
  this.destroyed = false;
  this._closeEmitted = false;
  this._closeScheduled = false;
}
ServerIncomingMessage.prototype = Object.create(EventEmitter.prototype);
ServerIncomingMessage.prototype.constructor = ServerIncomingMessage;

Object.defineProperty(ServerIncomingMessage.prototype, 'connection', {
  get: function() { return this.socket; },
  set: function(val) { this.socket = val; },
  enumerable: true,
  configurable: true
});

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
    if (self.destroyed) return;
    if (self._body) self.emit('data', self._body);
    self.emit('end');
    if (!self._closeEmitted && !self._closeScheduled) {
      self._closeEmitted = true;
      self.emit('close');
    }
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.read = function() {
  if (this._consumed) return null;
  var readBody = this._body || null;
  if (readBody) this._body = '';
  return readBody;
};
ServerIncomingMessage.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  this.destroyed = true;
  this.readable = false;
  this._closeScheduled = true;
  if (this.complete && err && (err.code === 'ABORT_ERR' || err.name === 'AbortError')) {
    err = null;
  }
  if (!err && !this.complete) {
    err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    this.aborted = true;
  }
  var self = this;
  setTimeout(function() {
    if (err) self.emit('error', err);
    if (!self._closeEmitted) {
      self._closeEmitted = true;
      self.emit('close');
    }
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.setTimeout = function(msecs, callback) {
  if (typeof callback === 'function') this.once('timeout', callback);
  if (this.socket && typeof this.socket.setTimeout === 'function') {
    this.socket.setTimeout(msecs);
  }
  return this;
};

ServerIncomingMessage.prototype.on = function(event, listener) {
  EventEmitter.prototype.on.call(this, event, listener);
  if (event === 'data' && !this._consumed) {
    this.resume();
  }
  return this;
};
ServerIncomingMessage.prototype.addListener = ServerIncomingMessage.prototype.on;
_attachHttpAsyncIterator(ServerIncomingMessage.prototype);

var _defaultHttpHighWaterMark = 16 * 1024;
try {
  var _streamState = require('internal/streams/state');
  if (_streamState && typeof _streamState.getDefaultHighWaterMark === 'function') {
    _defaultHttpHighWaterMark = _streamState.getDefaultHighWaterMark();
  }
} catch (_streamStateErr) {}

function _copyPrototypeMembers(target, ctor) {
  if (!target || !ctor || !ctor.prototype) return;
  var proto = ctor.prototype;
  var names = Object.getOwnPropertyNames(proto);
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (name === 'constructor') continue;
    var descriptor = Object.getOwnPropertyDescriptor(proto, name);
    if (!descriptor) continue;
    try {
      Object.defineProperty(target, name, descriptor);
    } catch (_copyErr) {}
  }
}

function _createServerIncomingMessage(server, requestData, serverId, socket) {
  var req = new ServerIncomingMessage(requestData, serverId);
  var highWaterMark = server && typeof server[kHighWaterMark] === 'number'
    ? server[kHighWaterMark]
    : _defaultHttpHighWaterMark;
  req._readableState = req._readableState || {};
  req._readableState.highWaterMark = highWaterMark;
  if (socket) req.socket = socket;
  if (server && server._incomingMessageCtor && server._incomingMessageCtor !== ServerIncomingMessage) {
    _copyPrototypeMembers(req, server._incomingMessageCtor);
  }
  return req;
}

function _createServerResponse(server, req, serverId, requestId) {
  var res = serverId
    ? new ServerResponse(serverId, requestId || 0)
    : new ServerResponse(req);
  res[kHighWaterMark] = server && typeof server[kHighWaterMark] === 'number'
    ? server[kHighWaterMark]
    : _defaultHttpHighWaterMark;
  if (server && server._serverResponseCtor && server._serverResponseCtor !== ServerResponse) {
    _copyPrototypeMembers(res, server._serverResponseCtor);
  }
  return res;
}

function _destroyHttpTimer(timer) {
  if (!timer) return;
  clearTimeout(timer);
  if (typeof timer.destroy === 'function') {
    try { timer.destroy(); } catch (_destroyTimerErr) {}
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
function Server(options, requestListener) {
  if (!(this instanceof Server)) {
    return new Server(options, requestListener);
  }
  if (typeof options === 'function') {
    requestListener = options;
    options = {};
  }
  options = options || {};
  EventEmitter.call(this);
  this._listening = false;
  this._closing = false;
  this._port = 0;
  this._hostname = '0.0.0.0';
  this._netServer = null;
  this._serverId = 0;
  this._useNative = false;
  this._sockets = typeof Set === 'function' ? new Set() : null;
  this._socketTimeout = 0;
  this._serverTimeoutId = null;
  this[kConnectionsCheckingInterval] = null;
  this.timeout = 0;
  this.keepAliveTimeout = options.keepAliveTimeout != null ? options.keepAliveTimeout : 5000;
  this.maxHeadersCount = options.maxHeadersCount != null ? options.maxHeadersCount : 2000;
  this.requestTimeout = options.requestTimeout != null ? options.requestTimeout : 300000;
  this.headersTimeout = options.headersTimeout != null ? options.headersTimeout : Math.min(60000, this.requestTimeout || 60000);
  this.maxRequestsPerSocket = options.maxRequestsPerSocket != null ? options.maxRequestsPerSocket : 0;
  this.connectionsCheckingInterval =
    options.connectionsCheckingInterval != null ? options.connectionsCheckingInterval : 30000;
  this[kHighWaterMark] = options.highWaterMark != null ? options.highWaterMark : _defaultHttpHighWaterMark;
  this._incomingMessageCtor = options.IncomingMessage || ServerIncomingMessage;
  this._serverResponseCtor = options.ServerResponse || ServerResponse;

  if (this.requestTimeout > 0 && this.headersTimeout > this.requestTimeout) {
    var timeoutRangeErr = new RangeError('The value of "headersTimeout" is out of range. It must be <= requestTimeout. Received ' + this.headersTimeout);
    timeoutRangeErr.code = 'ERR_OUT_OF_RANGE';
    throw timeoutRangeErr;
  }

  if (typeof requestListener === 'function') {
    this.on('request', requestListener);
  }

  var selfTimer = this;
  this.on('listening', function() {
    if (selfTimer[kConnectionsCheckingInterval]) {
      _destroyHttpTimer(selfTimer[kConnectionsCheckingInterval]);
    }
    if (selfTimer.connectionsCheckingInterval > 0) {
      selfTimer[kConnectionsCheckingInterval] = setInterval(function() {}, selfTimer.connectionsCheckingInterval);
      if (selfTimer[kConnectionsCheckingInterval] && typeof selfTimer[kConnectionsCheckingInterval].unref === 'function') {
        selfTimer[kConnectionsCheckingInterval].unref();
      }
    }
  });

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

Object.defineProperty(Server.prototype, 'listening', {
  get: function() { return this._listening; },
  enumerable: true,
  configurable: true
});

Server.prototype._onConnection = function(socket) {
  socket[kTimeout] = null;
  socket.parser = null;
  socket._httpMessage = null;
  socket._isIdle = true;
  socket._httpServer = this;
  socket._headersTimeoutId = null;
  socket._requestTimeoutId = null;
  socket._headersComplete = false;
  socket._requestTimeoutArmed = false;

  var self = this;
  if (self._sockets) self._sockets.add(socket);

  if (self._socketTimeout && typeof socket.setTimeout === 'function') {
    socket.setTimeout(self._socketTimeout, function() {
      self.emit('timeout', socket);
    });
  }

  this.emit('connection', socket);

  var parser = new HttpRequestParser();
  socket.parser = parser;
  function sendBadRequestAndClose() {
    if (socket.destroyed) return;
    try {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    } catch (_writeErr) {
      try { socket.destroy(); } catch (_destroyErr) {}
    }
  }
  function isValidConnectTarget(target) {
    if (typeof target !== 'string' || !target) return false;
    if (/^https?:\/\//i.test(target)) {
      try {
        var targetUrl = new URL(target);
        return !!targetUrl.hostname && !!targetUrl.port;
      } catch (_targetUrlErr) {
        return false;
      }
    }
    if (target.charAt(0) === '[') {
      var bracketEnd = target.indexOf(']');
      if (bracketEnd <= 0 || bracketEnd + 2 >= target.length || target.charAt(bracketEnd + 1) !== ':') {
        return false;
      }
      return /^\d+$/.test(target.substring(bracketEnd + 2));
    }
    var colonIdx = target.lastIndexOf(':');
    if (colonIdx <= 0 || colonIdx === target.length - 1) {
      return false;
    }
    return /^\d+$/.test(target.substring(colonIdx + 1));
  }

  function clearHeadersTimeout() {
    if (socket._headersTimeoutId) {
      _destroyHttpTimer(socket._headersTimeoutId);
      socket._headersTimeoutId = null;
    }
    socket._headersComplete = true;
  }

  function clearRequestTimeout() {
    if (socket._requestTimeoutId) {
      _destroyHttpTimer(socket._requestTimeoutId);
      socket._requestTimeoutId = null;
    }
    socket._requestTimeoutArmed = false;
  }

  function sendRequestTimeout() {
    clearHeadersTimeout();
    clearRequestTimeout();
    if (socket.destroyed) return;
    try {
      socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n');
    } catch (_timeoutWriteErr) {
      try { socket.destroy(); } catch (_timeoutDestroyErr) {}
    }
  }

  function armRequestParsingTimeouts() {
    if (socket.destroyed) return;
    if (!socket._requestTimeoutArmed && self.requestTimeout > 0) {
      socket._requestTimeoutArmed = true;
      socket._requestTimeoutId = setTimeout(sendRequestTimeout, self.requestTimeout);
      if (socket._requestTimeoutId && typeof socket._requestTimeoutId.unref === 'function') {
        socket._requestTimeoutId.unref();
      }
    }
    if (!socket._headersComplete && !socket._headersTimeoutId && self.headersTimeout > 0) {
      socket._headersTimeoutId = setTimeout(sendRequestTimeout, self.headersTimeout);
      if (socket._headersTimeoutId && typeof socket._headersTimeoutId.unref === 'function') {
        socket._headersTimeoutId.unref();
      }
    }
  }

  parser.onError = function() {
    socket.parser = null;
    if (parser) parser.close();
    sendBadRequestAndClose();
  };

  parser.onHeadersComplete = function() {
    clearHeadersTimeout();
    socket._isIdle = false;
  };

  armRequestParsingTimeouts();

  socket.on('data', function(chunk) {
    if (socket._isIdle && !socket._requestTimeoutArmed && !socket.destroyed) {
      socket._headersComplete = false;
      armRequestParsingTimeouts();
    }
    if (socket.parser) parser.execute(chunk);
  });

  var _activeReq = null;
  var _activeRes = null;

  socket.on('close', function() {
    clearHeadersTimeout();
    clearRequestTimeout();
    if (_activeReq && !_activeReq.complete && _activeRes && !_activeRes._finished) {
      _activeReq.aborted = true;
      _activeReq.emit('aborted');
      var abortErr = new Error('aborted');
      abortErr.code = 'ECONNRESET';
      _activeReq.emit('error', abortErr);
      _activeReq = null;
    }
    socket.parser = null;
    socket[kTimeout] = null;
    if (socket._httpMessage) socket._httpMessage = null;
    if (parser) parser.close();
    if (self._sockets) self._sockets.delete(socket);
  });

  socket.on('error', function() {});

  parser.onRequest = function(reqData) {
    clearHeadersTimeout();
    clearRequestTimeout();
    var req = _createServerIncomingMessage(self, reqData, 0, socket);

    if (req.method === 'CONNECT') {
      if (!isValidConnectTarget(req.url)) {
        socket.parser = null;
        if (parser) parser.close();
        sendBadRequestAndClose();
        return;
      }
      socket._isIdle = false;
      socket.parser = null;
      var head = (typeof Buffer !== 'undefined')
        ? Buffer.from(parser && parser._buffer ? parser._buffer : '', 'latin1')
        : (parser && parser._buffer ? parser._buffer : '');
      if (parser) {
        parser._buffer = '';
        parser.close();
      }
      if (self.listenerCount('connect') > 0) {
        self.emit('connect', req, socket, head);
      } else {
        sendBadRequestAndClose();
      }
      return;
    }

    _activeReq = req;

    req.once('end', function() { req.complete = true; if (_activeReq === req) _activeReq = null; });
    if (reqData.bodyComplete !== false) {
      req.complete = true;
    }

    var res = _createServerResponse(self, req);
    res.req = req;
    res.assignSocket(socket);
    _activeRes = res;
    socket._isIdle = false;

    res.once('close', function() {
      socket._isIdle = true;
      if (reqData.oversizedBody && !socket.destroyed) {
        try { socket.destroy(); } catch(e) {}
        return;
      }
      if (self._closing && !socket.destroyed) {
        if (!socket._writeQueue || socket._writeQueue.length === 0) {
          try { socket.destroy(); } catch(e) {}
        }
      }
      if (!socket.destroyed) {
        socket._headersComplete = false;
        clearHeadersTimeout();
        clearRequestTimeout();
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
    var self = this;
    this._netServer.on('error', function(err) {
      self.emit('error', err);
    });
    this._netServer.listen(port, hostname, function() {
      self._listening = true;
      self.emit('listening');
    });
  } else if (typeof __exactHttpServe === 'function') {
    this._useNative = true;
    var resultJson = __exactHttpServe(port, hostname);
    var result;
    try { result = JSON.parse(resultJson); } catch(e) {
      var self2 = this;
      setTimeout(function() { self2.emit('error', new Error('Server start failed')); }, 0);
      return this;
    }

    if (result.error) {
      var self3 = this;
      var errMsg = result.error;
      setTimeout(function() { self3.emit('error', new Error(errMsg)); }, 0);
      return this;
    }

    this._serverId = result.id;
    this._port = result.port || port;
    this._listening = true;

    var self4 = this;
    setTimeout(function() { self4.emit('listening'); }, 0);
    this._pollLoop();
  } else {
    var self5 = this;
    setTimeout(function() { self5.emit('error', new Error('HTTP server not available')); }, 0);
  }

  return this;
};

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

  var req = _createServerIncomingMessage(this, data, this._serverId, null);
  var res = _createServerResponse(this, null, this._serverId, data.id || 0);

  if (req.listenerCount && req.listenerCount('data') > 0) {
    req.resume();
  }
  this.emit('request', req, res);
};

Server.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._closing = true;
  this._listening = false;
  if (this[kConnectionsCheckingInterval]) {
    _destroyHttpTimer(this[kConnectionsCheckingInterval]);
    this[kConnectionsCheckingInterval] = null;
  }
  if (this._serverTimeoutId) {
    clearTimeout(this._serverTimeoutId);
    this._serverTimeoutId = null;
  }
  this.closeIdleConnections();

  var self = this;
  if (this._netServer) {
    this._netServer.close(function() {
      if (self._sockets && self._sockets.size > 0) {
        var remaining = [];
        self._sockets.forEach(function(s) { remaining.push(s); });
        for (var i = 0; i < remaining.length; i++) {
          try { remaining[i].destroy(); } catch(e) {}
        }
      }
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

if (typeof Symbol === 'function' && Symbol.dispose) {
  Server.prototype[Symbol.dispose] = function() {
    this.close();
  };
}

if (typeof Symbol === 'function' && Symbol.asyncDispose) {
  Server.prototype[Symbol.asyncDispose] = function() {
    var self = this;
    return new Promise(function(resolve, reject) {
      try {
        self.close(function() {
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  };
}

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
    if (sock._isIdle && (!sock._writeQueue || sock._writeQueue.length === 0)) {
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
  if (msecs === undefined) msecs = 0;
  this.timeout = msecs;
  if (msecs == null || msecs <= 0) {
    if (this._serverTimeoutId) {
      clearTimeout(this._serverTimeoutId);
      this._serverTimeoutId = null;
    }
    return this;
  }
  var self = this;
  this._socketTimeout = msecs;
  if (typeof callback === 'function') {
    this.on('timeout', callback);
  }
  if (this._serverTimeoutId) clearTimeout(this._serverTimeoutId);
  this._serverTimeoutId = setTimeout(function() {
    self._serverTimeoutId = null;
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
  return new Server(options, requestListener);
}

var internalOptions;
try {
  internalOptions = require('internal/options');
} catch (_err) {
  internalOptions = null;
}
var configuredMaxHeaderSize = internalOptions && typeof internalOptions.getOptionValue === 'function'
  ? internalOptions.getOptionValue('--max-http-header-size')
  : undefined;
var maxHeaderSize = typeof configuredMaxHeaderSize === 'number' && isFinite(configuredMaxHeaderSize) && configuredMaxHeaderSize > 0
  ? configuredMaxHeaderSize
  : 16384;

// Module exports - avoid getter syntax for Hermes compatibility
var _wsGlobal = typeof WebSocket !== 'undefined' ? WebSocket : undefined;
var _ceGlobal = typeof CloseEvent !== 'undefined' ? CloseEvent : undefined;
var _meGlobal = typeof MessageEvent !== 'undefined' ? MessageEvent : undefined;

// _checkIsHttpToken / _checkInvalidHeaderChar helpers for _http_common
function _checkIsHttpToken(val) {
  return typeof val === 'string' && HEADER_NAME_RE.test(val);
}
function _checkInvalidHeaderChar(val) {
  if (typeof val !== 'string') return false;
  for (var i = 0; i < val.length; i++) {
    var ch = val.charCodeAt(i);
    if (ch === 9) continue; // TAB
    if (ch < 32 || ch === 127) return true;
  }
  return false;
}

// Fake HTTPParser for _http_common compatibility
function HTTPParser() {}
HTTPParser.REQUEST = 'REQUEST';
HTTPParser.RESPONSE = 'RESPONSE';
HTTPParser.kOnHeaders = 0;
HTTPParser.kOnHeadersComplete = 1;
HTTPParser.kOnBody = 2;
HTTPParser.kOnMessageComplete = 3;
HTTPParser.kOnExecute = 4;

// parsers free list (stub)
var parsers = { max: 1000, alloc: function() { return new HTTPParser(); }, free: function() {} };

// Internal module symbol exports
var kConnectionsCheckingInterval = Symbol.for('nodejs.http.kConnectionsCheckingInterval');
var kHighWaterMark = Symbol.for('nodejs.http.kHighWaterMark');

module.exports = {
  request: request,
  get: get,
  Agent: Agent,
  createServer: createServer,
  Server: Server,
  ServerResponse: ServerResponse,
  OutgoingMessage: ServerResponse,
  IncomingMessage: IncomingMessage,
  ServerIncomingMessage: ServerIncomingMessage,
  ClientRequest: ClientRequest,
  METHODS: METHODS,
  STATUS_CODES: STATUS_CODES,
  globalAgent: globalAgent,
  kTimeout: kTimeout,
  maxHeaderSize: maxHeaderSize,
  validateHeaderName: validateHeaderName,
  validateHeaderValue: validateHeaderValue,
  WebSocket: _wsGlobal,
  CloseEvent: _ceGlobal,
  MessageEvent: _meGlobal,
  // Internal exports for _http_common, _http_agent, etc.
  _checkIsHttpToken: _checkIsHttpToken,
  _checkInvalidHeaderChar: _checkInvalidHeaderChar,
  HTTPParser: HTTPParser,
  parsers: parsers,
  methods: METHODS,
  kConnectionsCheckingInterval: kConnectionsCheckingInterval,
  kHighWaterMark: kHighWaterMark
};
