var http = require('node:http');
var tls = require('node:tls');

function _copyOwnProperties(source) {
  var out = {};
  if (!source || typeof source !== 'object') return out;
  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      out[key] = source[key];
    }
  }
  return out;
}

function _copyExportDescriptors(target, source) {
  if (!target || !source || typeof Object.getOwnPropertyNames !== 'function') return;
  var names = Object.getOwnPropertyNames(source);
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (name === 'default') continue;
    var descriptor = Object.getOwnPropertyDescriptor(source, name);
    if (!descriptor) continue;
    try {
      Object.defineProperty(target, name, descriptor);
    } catch (_copyErr) {}
  }
}

function Agent(options) {
  if (!(this instanceof Agent)) {
    return new Agent(options);
  }
  var normalized = _copyOwnProperties(options);
  if (normalized.defaultPort === undefined) {
    normalized.defaultPort = 443;
  }
  normalized.protocol = 'https:';
  http.Agent.call(this, normalized);
}

Agent.prototype = Object.create(http.Agent.prototype);
Agent.prototype.constructor = Agent;
Agent.defaultMaxSockets = http.Agent.defaultMaxSockets;

Agent.prototype.createConnection = function(options, callback) {
  var connectOptions = _copyOwnProperties(options);
  if (!connectOptions.servername) {
    connectOptions.servername = connectOptions.host || connectOptions.hostname;
  }
  return tls.connect(connectOptions, callback);
};

var globalAgent = new Agent();

function _normalizeRequestArgs(input, options, callback) {
  if (
    typeof input === 'string' ||
    (typeof URL !== 'undefined' && input instanceof URL)
  ) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    return { input: input, options: _copyOwnProperties(options), callback: callback };
  }

  if (typeof input === 'function') {
    callback = input;
    input = {};
    options = undefined;
  }
  if (!input || typeof input !== 'object') {
    input = {};
  }
  return { input: _copyOwnProperties(input), options: null, callback: callback || options };
}

function _prepareRequestOptions(options) {
  var normalized = _copyOwnProperties(options);
  if (!normalized.protocol) {
    normalized.protocol = 'https:';
  }

  if (normalized.agent === false) {
    delete normalized.agent;
    if (typeof normalized.createConnection !== 'function') {
      normalized.createConnection = function(connectOptions, connectCallback) {
        var tlsOptions = _copyOwnProperties(connectOptions);
        if (!tlsOptions.servername) {
          tlsOptions.servername = tlsOptions.host || tlsOptions.hostname;
        }
        return tls.connect(tlsOptions, connectCallback);
      };
    }
    return normalized;
  }

  if (normalized.agent === undefined || normalized.agent === null) {
    normalized.agent = globalAgent;
  }
  return normalized;
}

function request(input, options, callback) {
  var normalized = _normalizeRequestArgs(input, options, callback);
  if (normalized.options) {
    return http.request(
      normalized.input,
      _prepareRequestOptions(normalized.options),
      normalized.callback
    );
  }
  return http.request(_prepareRequestOptions(normalized.input), normalized.callback);
}

function get(input, options, callback) {
  var req = request(input, options, callback);
  req.end();
  return req;
}

function createServer(options, requestListener) {
  if (typeof options === 'function') {
    requestListener = options;
    options = {};
  }

  var server = http.createServer(requestListener);
  var tlsServer = tls.createServer(options || {}, function(socket) {
    server.emit('secureConnection', socket);
    server._onConnection(socket);
  });
  server._netServer = tlsServer;
  return server;
}

function Server(options, requestListener) {
  if (!(this instanceof Server)) {
    return createServer(options, requestListener);
  }
  return createServer(options, requestListener);
}

Server.prototype = http.Server.prototype;
Server.prototype.constructor = Server;

var exported = {};
_copyExportDescriptors(exported, http);
exported.Agent = Agent;
exported.globalAgent = globalAgent;
exported.request = request;
exported.get = get;
exported.createServer = createServer;
exported.Server = Server;

module.exports = exported;
module.exports.default = module.exports;
