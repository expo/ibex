//#region src/builtins/https.js
var http = require("node:http");
var tls = require("node:tls");
var EventEmitter = require("node:events");
var Buffer = require("node:buffer").Buffer;
function _copyOwnProperties(source) {
	var out = {};
	if (!source || typeof source !== "object") return out;
	for (var key in source) if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
	return out;
}
function _copyExportDescriptors(target, source) {
	if (!target || !source || typeof Object.getOwnPropertyNames !== "function") return;
	var names = Object.getOwnPropertyNames(source);
	for (var i = 0; i < names.length; i++) {
		var name = names[i];
		if (name === "default") continue;
		var descriptor = Object.getOwnPropertyDescriptor(source, name);
		if (!descriptor) continue;
		try {
			Object.defineProperty(target, name, descriptor);
		} catch (_copyErr) {}
	}
}
var _httpsSocketTransportOptionNames = {
	ALPNProtocols: true,
	ca: true,
	cert: true,
	checkServerIdentity: true,
	ciphers: true,
	clientCertEngine: true,
	crl: true,
	dhparam: true,
	ecdhCurve: true,
	family: true,
	hints: true,
	honorCipherOrder: true,
	key: true,
	localAddress: true,
	lookup: true,
	maxVersion: true,
	minVersion: true,
	passphrase: true,
	pfx: true,
	privateKeyEngine: true,
	privateKeyIdentifier: true,
	rejectUnauthorized: true,
	requestOCSP: true,
	secureOptions: true,
	secureProtocol: true,
	servername: true,
	session: true,
	sessionIdContext: true,
	socket: true
};
function _requiresSocketTransport(options) {
	if (!options || typeof options !== "object") return false;
	if (typeof options.createConnection === "function") return true;
	if (options.socketPath || options.path && options.protocol === "unix:") return true;
	for (var key in _httpsSocketTransportOptionNames) {
		if (!Object.prototype.hasOwnProperty.call(_httpsSocketTransportOptionNames, key)) continue;
		if (!Object.prototype.hasOwnProperty.call(options, key)) continue;
		if (options[key] !== void 0 && options[key] !== null) return true;
	}
	return false;
}
function Agent(options) {
	if (!(this instanceof Agent)) return new Agent(options);
	var normalized = _copyOwnProperties(options);
	if (normalized.defaultPort === void 0) normalized.defaultPort = 443;
	normalized.protocol = "https:";
	http.Agent.call(this, normalized);
}
Agent.prototype = Object.create(http.Agent.prototype);
Agent.prototype.constructor = Agent;
Agent.defaultMaxSockets = http.Agent.defaultMaxSockets;
Agent.prototype.createConnection = function(options, callback) {
	var connectOptions = _copyOwnProperties(options);
	if (!connectOptions.servername) connectOptions.servername = connectOptions.host || connectOptions.hostname;
	return tls.connect(connectOptions, callback);
};
var globalAgent = new Agent();
function _isWindowsRuntime() {
	return typeof process !== "undefined" && process && process.platform === "win32";
}
function _canUseNativeFetchTransport(options) {
	return _isWindowsRuntime() && typeof fetch === "function" && (!_requiresSocketTransport(options) || options.agent === globalAgent);
}
function _headersToObject(headers) {
	var out = {};
	if (!headers || typeof headers !== "object") return out;
	for (var key in headers) if (Object.prototype.hasOwnProperty.call(headers, key) && headers[key] !== void 0) out[key] = headers[key];
	return out;
}
function _requestUrlFromInput(input, options) {
	var url;
	if (typeof input === "string" || typeof URL !== "undefined" && input instanceof URL) url = new URL(String(input));
	else url = new URL("https://localhost/");
	options = options || {};
	var host = options.hostname || options.host;
	if (host) {
		host = String(host);
		var colon = host.lastIndexOf(":");
		if (colon > -1 && host.indexOf("]") === -1) {
			url.hostname = host.slice(0, colon);
			if (options.port === void 0) url.port = host.slice(colon + 1);
		} else url.hostname = host;
	}
	if (options.port !== void 0 && options.port !== null) url.port = String(options.port);
	if (options.path !== void 0) {
		var path = String(options.path || "/");
		if (path.charAt(0) !== "/") path = "/" + path;
		url.pathname = path.split("?")[0] || "/";
		var query = path.indexOf("?");
		url.search = query >= 0 ? path.slice(query) : "";
	} else if (options.pathname !== void 0) {
		url.pathname = String(options.pathname || "/");
		if (options.search !== void 0) url.search = String(options.search || "");
	}
	url.protocol = "https:";
	return url.toString();
}
function _nativeFetchRequest(input, options, callback) {
	var req = new EventEmitter();
	var chunks = [];
	var ended = false;
	var destroyed = false;
	var timeoutHandle = null;
	var method = options && options.method || "GET";
	req.writable = true;
	req.destroyed = false;
	req.write = function(chunk, encoding, cb) {
		if (typeof encoding === "function") {
			cb = encoding;
			encoding = void 0;
		}
		if (chunk !== void 0 && chunk !== null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding));
		if (typeof cb === "function") setTimeout(cb, 0);
		return true;
	};
	req.end = function(chunk, encoding, cb) {
		if (typeof chunk === "function") {
			cb = chunk;
			chunk = void 0;
			encoding = void 0;
		} else if (typeof encoding === "function") {
			cb = encoding;
			encoding = void 0;
		}
		if (chunk !== void 0 && chunk !== null) req.write(chunk, encoding);
		if (ended) return req;
		ended = true;
		if (typeof cb === "function") setTimeout(cb, 0);
		var body = chunks.length ? Buffer.concat(chunks) : void 0;
		var init = {
			method,
			headers: _headersToObject(options && options.headers),
			body
		};
		if (!body || method === "GET" || method === "HEAD") delete init.body;
		fetch(_requestUrlFromInput(input, options), init).then(function(response) {
			if (destroyed) return;
			if (timeoutHandle) {
				clearTimeout(timeoutHandle);
				timeoutHandle = null;
			}
			var res = new EventEmitter();
			res.statusCode = response.status;
			res.statusMessage = response.statusText || "";
			res.headers = {};
			if (response.headers && typeof response.headers.forEach === "function") response.headers.forEach(function(value, key) {
				res.headers[String(key).toLowerCase()] = value;
			});
			res.setEncoding = function() {
				return res;
			};
			if (typeof callback === "function") callback(res);
			req.emit("response", res);
			return response.arrayBuffer().then(function(buffer) {
				if (destroyed) return;
				var data = Buffer.from(new Uint8Array(buffer));
				if (data.length) res.emit("data", data);
				res.emit("end");
				req.emit("close");
			});
		}).catch(function(error) {
			if (destroyed) return;
			if (timeoutHandle) {
				clearTimeout(timeoutHandle);
				timeoutHandle = null;
			}
			req.emit("error", error);
			req.emit("close");
		});
		return req;
	};
	req.setTimeout = function(ms, cb) {
		if (timeoutHandle) clearTimeout(timeoutHandle);
		if (typeof cb === "function") req.once("timeout", cb);
		if (ms > 0) timeoutHandle = setTimeout(function() {
			req.emit("timeout");
		}, ms);
		return req;
	};
	req.destroy = function(error) {
		destroyed = true;
		req.destroyed = true;
		if (timeoutHandle) clearTimeout(timeoutHandle);
		if (error) req.emit("error", error);
		req.emit("close");
		return req;
	};
	req.abort = req.destroy;
	req.flushHeaders = function() {};
	req.setHeader = function(name, value) {
		options.headers = options.headers || {};
		options.headers[name] = value;
	};
	req.getHeader = function(name) {
		var headers = options.headers || {};
		return headers[name] || headers[String(name).toLowerCase()];
	};
	req.removeHeader = function(name) {
		if (options.headers) {
			delete options.headers[name];
			delete options.headers[String(name).toLowerCase()];
		}
	};
	return req;
}
function _normalizeRequestArgs(input, options, callback) {
	if (typeof input === "string" || typeof URL !== "undefined" && input instanceof URL) {
		if (typeof options === "function") {
			callback = options;
			options = void 0;
		}
		return {
			input,
			options: _copyOwnProperties(options),
			callback
		};
	}
	if (typeof input === "function") {
		callback = input;
		input = {};
		options = void 0;
	}
	if (!input || typeof input !== "object") input = {};
	return {
		input: _copyOwnProperties(input),
		options: null,
		callback: callback || options
	};
}
function _prepareRequestOptions(options) {
	var normalized = _copyOwnProperties(options);
	if (!normalized.protocol) normalized.protocol = "https:";
	normalized.__exactAllowHttpsProtocol = true;
	if (normalized.agent === false) {
		delete normalized.agent;
		if (_requiresSocketTransport(normalized) && typeof normalized.createConnection !== "function") normalized.createConnection = function(connectOptions, connectCallback) {
			var tlsOptions = _copyOwnProperties(connectOptions);
			if (!tlsOptions.servername) tlsOptions.servername = tlsOptions.host || tlsOptions.hostname;
			return tls.connect(tlsOptions, connectCallback);
		};
		else normalized.__exactSkipDefaultAgent = true;
		return normalized;
	}
	if (normalized.agent === void 0 || normalized.agent === null) if (typeof normalized.createConnection === "function") normalized.__exactSkipDefaultAgent = true;
	else normalized.agent = globalAgent;
	return normalized;
}
function request(input, options, callback) {
	var normalized = _normalizeRequestArgs(input, options, callback);
	if (normalized.options) {
		var preparedOptions = _prepareRequestOptions(normalized.options);
		if (_canUseNativeFetchTransport(preparedOptions)) return _nativeFetchRequest(normalized.input, preparedOptions, normalized.callback);
		return http.request(normalized.input, preparedOptions, normalized.callback);
	}
	var preparedInput = _prepareRequestOptions(normalized.input);
	if (_canUseNativeFetchTransport(preparedInput)) return _nativeFetchRequest(preparedInput, preparedInput, normalized.callback);
	return http.request(preparedInput, normalized.callback);
}
function get(input, options, callback) {
	var req = request(input, options, callback);
	req.end();
	return req;
}
function createServer(options, requestListener) {
	if (typeof options === "function") {
		requestListener = options;
		options = {};
	}
	var server = http.createServer(requestListener);
	var tlsServer = tls.createServer(options || {}, function(socket) {
		if (socket && socket._exactHttpsHttpAttached) return;
		if (socket) socket._exactHttpsHttpAttached = true;
		server.emit("secureConnection", socket);
		server._onConnection(socket);
	});
	if (tlsServer && typeof tlsServer.on === "function") {
		tlsServer.on("listening", function() {
			var address = null;
			if (typeof tlsServer.address === "function") address = tlsServer.address();
			server._listening = true;
			if (address && typeof address === "object") {
				if (address.port != null) server._port = address.port;
				if (address.address) server._hostname = address.address;
			}
		});
		tlsServer.on("close", function() {
			server._listening = false;
		});
	}
	server._netServer = tlsServer;
	return server;
}
function Server(options, requestListener) {
	if (!(this instanceof Server)) return createServer(options, requestListener);
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
//#endregion
