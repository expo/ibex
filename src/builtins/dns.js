function lookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var family = options.family || 0;
  try {
    var json = __exactDnsLookup(hostname, family);
    var results = JSON.parse(json);
    if (results.length === 0) {
      var err = new Error('getaddrinfo ENOTFOUND ' + hostname);
      err.code = 'ENOTFOUND';
      err.hostname = hostname;
      if (callback) setTimeout(function() { callback(err); }, 0);
      return;
    }
    var result = results[0];
    if (options.all) {
      if (callback) setTimeout(function() { callback(null, results); }, 0);
    } else {
      if (callback) setTimeout(function() { callback(null, result.address, result.family); }, 0);
    }
  } catch(e) {
    var err = new Error('getaddrinfo ENOTFOUND ' + hostname);
    err.code = 'ENOTFOUND';
    err.hostname = hostname;
    if (callback) setTimeout(function() { callback(err); }, 0);
  }
}

var _hasDnsResolve = typeof __exactDnsResolve === 'function';
var _hasDnsReverse = typeof __exactDnsReverse === 'function';

function _isValidIpAddress(value, family) {
  if (typeof value !== 'string') return false;
  try {
    var net = require('net');
    if (!net || typeof net.isIP !== 'function') return false;
    var detected = net.isIP(value);
    return family ? detected === family : detected !== 0;
  } catch (_) {
    return false;
  }
}

function _trackResolverCallback(resolver, callback) {
  if (!resolver || typeof callback !== 'function') return callback;
  resolver._pendingQueries = (resolver._pendingQueries || 0) + 1;
  var called = false;
  return function() {
    if (!called) {
      called = true;
      resolver._pendingQueries = Math.max(0, (resolver._pendingQueries || 1) - 1);
    }
    return callback.apply(this, arguments);
  };
}

function _resolveViaQuery(hostname, rrtype, callback) {
  if (!_hasDnsResolve) {
    var err = new Error('DNS record type ' + rrtype + ' requires native resolver');
    err.code = 'ENOTIMP';
    if (callback) setTimeout(function() { callback(err); }, 0);
    return;
  }
  try {
    var json = __exactDnsResolve(hostname, rrtype);
    var records = JSON.parse(json);
    if (callback) setTimeout(function() { callback(null, records); }, 0);
  } catch(e) {
    var err2 = new Error('query' + rrtype + ' ' + (e.message || String(e)));
    err2.code = 'ENOTFOUND';
    err2.hostname = hostname;
    if (callback) setTimeout(function() { callback(err2); }, 0);
  }
}

function resolve(hostname, rrtype, callback) {
  if (typeof rrtype === 'function') {
    callback = rrtype;
    rrtype = 'A';
  }
  if (rrtype === 'A') {
    lookup(hostname, { family: 4, all: true }, function(err, results) {
      if (err) { callback(err); return; }
      var addresses = [];
      for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
      callback(null, addresses);
    });
  } else if (rrtype === 'AAAA') {
    lookup(hostname, { family: 6, all: true }, function(err, results) {
      if (err) { callback(err); return; }
      var addresses = [];
      for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
      callback(null, addresses);
    });
  } else {
    _resolveViaQuery(hostname, rrtype, callback);
  }
}

function resolve4(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  lookup(hostname, { family: 4, all: true }, function(err, results) {
    if (err) { callback(err); return; }
    var addresses = [];
    for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
    callback(null, addresses);
  });
}

function resolve6(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  lookup(hostname, { family: 6, all: true }, function(err, results) {
    if (err) { callback(err); return; }
    var addresses = [];
    for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
    callback(null, addresses);
  });
}

function resolveMx(hostname, callback) {
  _resolveViaQuery(hostname, 'MX', callback);
}

function resolveTxt(hostname, callback) {
  _resolveViaQuery(hostname, 'TXT', callback);
}

function resolveSrv(hostname, callback) {
  _resolveViaQuery(hostname, 'SRV', callback);
}

function resolveNs(hostname, callback) {
  _resolveViaQuery(hostname, 'NS', callback);
}

function resolveCname(hostname, callback) {
  _resolveViaQuery(hostname, 'CNAME', callback);
}

function resolveSoa(hostname, callback) {
  _resolveViaQuery(hostname, 'SOA', function(err, records) {
    if (err) { callback(err); return; }
    // SOA returns a single record, not an array
    callback(null, records && records.length > 0 ? records[0] : null);
  });
}

function resolvePtr(hostname, callback) {
  _resolveViaQuery(hostname, 'PTR', callback);
}

function resolveCaa(hostname, callback) {
  _resolveViaQuery(hostname, 'CAA', callback);
}

function resolveNaptr(hostname, callback) {
  _resolveViaQuery(hostname, 'NAPTR', callback);
}

function reverse(ip, callback) {
  if (!_hasDnsReverse) {
    var err = new Error('dns.reverse requires native resolver');
    err.code = 'ENOTIMP';
    if (callback) setTimeout(function() { callback(err); }, 0);
    return;
  }
  try {
    var json = __exactDnsReverse(ip);
    var hostnames = JSON.parse(json);
    if (callback) setTimeout(function() { callback(null, hostnames); }, 0);
  } catch(e) {
    var err2 = new Error('getHostByAddr ' + (e.message || String(e)));
    err2.code = 'ENOTFOUND';
    if (callback) setTimeout(function() { callback(err2); }, 0);
  }
}

// Promises API
function _promisify1(fn) {
  return function(arg1) {
    return new Promise(function(res, reject) {
      fn(arg1, function(err, result) {
        if (err) reject(err);
        else res(result);
      });
    });
  };
}

var promises = {
  lookup: function(hostname, options) {
    return new Promise(function(resolve, reject) {
      lookup(hostname, options || {}, function(err, address, family) {
        if (err) reject(err);
        else resolve({ address: address, family: family });
      });
    });
  },
  resolve: function(hostname, rrtype) {
    return new Promise(function(res, reject) {
      resolve(hostname, rrtype || 'A', function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolve4: function(hostname, options) {
    return new Promise(function(res, reject) {
      resolve4(hostname, options || {}, function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolve6: function(hostname, options) {
    return new Promise(function(res, reject) {
      resolve6(hostname, options || {}, function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolveMx: _promisify1(resolveMx),
  resolveTxt: _promisify1(resolveTxt),
  resolveSrv: _promisify1(resolveSrv),
  resolveNs: _promisify1(resolveNs),
  resolveCname: _promisify1(resolveCname),
  resolveSoa: _promisify1(resolveSoa),
  resolvePtr: _promisify1(resolvePtr),
  resolveCaa: _promisify1(resolveCaa),
  resolveNaptr: _promisify1(resolveNaptr),
  resolveAny: _promisify1(resolveAny),
  reverse: _promisify1(reverse),
  lookupService: function(address, port) {
    return new Promise(function(res, reject) {
      lookupService(address, port, function(err, hostname, service) {
        if (err) reject(err);
        else res({ hostname: hostname, service: service });
      });
    });
  },
  setDefaultResultOrder: setDefaultResultOrder,
  getDefaultResultOrder: getDefaultResultOrder,
  setServers: setServers,
  getServers: getServers,
  Resolver: Resolver
};

// Default result order
var _defaultResultOrder = 'verbatim';

function setDefaultResultOrder(order) {
  if (order !== 'ipv4first' && order !== 'ipv6first' && order !== 'verbatim') {
    var err = new TypeError('The argument \'order\' must be one of: \'ipv4first\', \'ipv6first\', \'verbatim\'. Received \'' + order + '\'');
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
  _defaultResultOrder = order;
}

function getDefaultResultOrder() {
  return _defaultResultOrder;
}

// Server management (stub)
var _servers = ['127.0.0.1'];

function getServers() {
  return _servers.slice();
}

function setServers(servers) {
  if (!Array.isArray(servers)) {
    var received = servers === null ? 'null' : servers === undefined ? 'undefined' : 'an instance of ' + (servers && servers.constructor ? servers.constructor.name : typeof servers);
    var err = new TypeError('The "servers" argument must be an instance of Array. Received ' + received);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  // Validate server addresses
  for (var i = 0; i < servers.length; i++) {
    if (typeof servers[i] !== 'string') {
      var err = new TypeError('The "servers[' + i + ']" argument must be of type string. Received type ' + typeof servers[i]);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
  _servers = servers.slice();
}

// lookupService stub
function lookupService(address, port, callback) {
  if (typeof address !== 'string') {
    var err = new TypeError('The "address" argument must be of type string. Received type ' + typeof address);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (typeof port !== 'number') {
    var err = new TypeError('The "port" argument must be of type number. Received type ' + typeof port);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (port < 0 || port > 65535 || port % 1 !== 0) {
    var err = new RangeError('The value of "port" is out of range. It must be >= 0 && <= 65535. Received ' + port);
    err.code = 'ERR_SOCKET_BAD_PORT';
    throw err;
  }
  // Basic stub - returns generic names
  if (callback) {
    setTimeout(function() {
      callback(null, address, String(port));
    }, 0);
  }
}

// resolveAny stub
function resolveAny(hostname, callback) {
  _resolveViaQuery(hostname, 'ANY', callback);
}

// Resolver class
function Resolver(options) {
  if (!(this instanceof Resolver)) return new Resolver(options);
  this._servers = _servers.slice();
  this._pendingQueries = 0;
  this._localAddressIPv4 = undefined;
  this._localAddressIPv6 = undefined;
  var self = this;
  this._handle = {
    getServers: function() {
      return self._servers.slice();
    },
    setServers: function(servers) {
      self._servers = servers.slice();
    },
    cancel: function() {
      self._pendingQueries = 0;
    }
  };
  if (options && options.timeout !== undefined) {
    if (typeof options.timeout !== 'number') {
      var err = new TypeError('The "options.timeout" property must be of type number. Received type ' + typeof options.timeout);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (options.timeout < -1 || options.timeout > 2147483647) {
      var err = new RangeError('The value of "options.timeout" is out of range. It must be >= -1 && <= 2147483647. Received ' + options.timeout);
      err.code = 'ERR_OUT_OF_RANGE';
      throw err;
    }
    this._timeout = options.timeout;
  }
  if (options && options.tries !== undefined) {
    if (typeof options.tries !== 'number') {
      var err = new TypeError('The "options.tries" property must be of type number. Received type ' + typeof options.tries);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    this._tries = options.tries;
  }
}

Resolver.prototype.getServers = function() {
  if (this._handle && typeof this._handle.getServers === 'function') {
    var servers = this._handle.getServers();
    return Array.isArray(servers) ? servers.slice() : [];
  }
  return this._servers.slice();
};

Resolver.prototype.setServers = function(servers) {
  if (!Array.isArray(servers)) {
    var err = new TypeError('The "servers" argument must be an instance of Array. Received type ' + typeof servers);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  for (var i = 0; i < servers.length; i++) {
    if (typeof servers[i] !== 'string') {
      var err = new TypeError('The "servers[' + i + ']" argument must be of type string. Received type ' + typeof servers[i]);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
  }
  if (this._pendingQueries > 0) {
    var pendingErr = new Error('c-ares failed to set servers: "There are pending queries." [' + servers.join(', ') + ']');
    pendingErr.code = 'ERR_DNS_SET_SERVERS_FAILED';
    throw pendingErr;
  }
  this._servers = servers.slice();
  if (this._handle && typeof this._handle.setServers === 'function') {
    this._handle.setServers(this._servers);
  }
};

Resolver.prototype.setLocalAddress = function(ipv4, ipv6) {
  if (arguments.length === 0) {
    throw new Error('At least one local address is required');
  }
  if (ipv4 !== undefined && typeof ipv4 !== 'string') {
    var ipv4TypeErr = new TypeError('The "ipv4" argument must be of type string. Received type ' + typeof ipv4);
    ipv4TypeErr.code = 'ERR_INVALID_ARG_TYPE';
    throw ipv4TypeErr;
  }
  if (ipv6 !== undefined && typeof ipv6 !== 'string') {
    var ipv6TypeErr = new TypeError('The "ipv6" argument must be of type string. Received type ' + typeof ipv6);
    ipv6TypeErr.code = 'ERR_INVALID_ARG_TYPE';
    throw ipv6TypeErr;
  }
  if (arguments.length === 1) {
    if (_isValidIpAddress(ipv4, 4)) {
      this._localAddressIPv4 = ipv4;
      return;
    }
    if (_isValidIpAddress(ipv4, 6)) {
      this._localAddressIPv6 = ipv4;
      return;
    }
    throw new Error('The "ipv4" argument must be a valid IP address');
  }
  if (ipv4 !== undefined && !_isValidIpAddress(ipv4, 4)) {
    throw new Error('The "ipv4" argument must be a valid IPv4 address');
  }
  if (ipv6 !== undefined && !_isValidIpAddress(ipv6, 6)) {
    throw new Error('The "ipv6" argument must be a valid IPv6 address');
  }
  if (ipv4 !== undefined) this._localAddressIPv4 = ipv4;
  if (ipv6 !== undefined) this._localAddressIPv6 = ipv6;
};

Resolver.prototype.resolve = function(hostname, rrtype, callback) {
  if (typeof rrtype === 'function') {
    callback = rrtype;
    rrtype = undefined;
  }
  resolve(hostname, rrtype, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolve4 = function(hostname, options, callback) { resolve4(hostname, options, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolve6 = function(hostname, options, callback) { resolve6(hostname, options, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveMx = function(hostname, callback) { resolveMx(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveTxt = function(hostname, callback) { resolveTxt(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveSrv = function(hostname, callback) { resolveSrv(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveNs = function(hostname, callback) { resolveNs(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveCname = function(hostname, callback) { resolveCname(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveSoa = function(hostname, callback) { resolveSoa(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolvePtr = function(hostname, callback) { resolvePtr(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveCaa = function(hostname, callback) { resolveCaa(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveNaptr = function(hostname, callback) { resolveNaptr(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.resolveAny = function(hostname, callback) { resolveAny(hostname, _trackResolverCallback(this, callback)); };
Resolver.prototype.reverse = function(ip, callback) { reverse(ip, _trackResolverCallback(this, callback)); };
Resolver.prototype.cancel = function() {
  this._pendingQueries = 0;
  if (this._handle && typeof this._handle.cancel === 'function') {
    this._handle.cancel();
  }
};

// Error codes
var NODATA = 'ENODATA';
var FORMERR = 'EFORMERR';
var SERVFAIL = 'ESERVFAIL';
var NOTFOUND = 'ENOTFOUND';
var NOTIMP = 'ENOTIMP';
var REFUSED = 'EREFUSED';
var BADQUERY = 'EBADQUERY';
var BADNAME = 'EBADNAME';
var BADFAMILY = 'EBADFAMILY';
var BADRESP = 'EBADRESP';
var CONNREFUSED = 'ECONNREFUSED';
var TIMEOUT = 'ETIMEOUT';
var EOF = 'EOF';
var FILE = 'EFILE';
var NOMEM = 'ENOMEM';
var DESTRUCTION = 'EDESTRUCTION';
var BADSTR = 'EBADSTR';
var BADFLAGS = 'EBADFLAGS';
var NONAME = 'ENONAME';
var BADHINTS = 'EBADHINTS';
var NOTINITIALIZED = 'ENOTINITIALIZED';
var LOADIPHLPAPI = 'ELOADIPHLPAPI';
var ADDRGETNETWORKPARAMS = 'EADDRGETNETWORKPARAMS';
var CANCELLED = 'ECANCELLED';

promises.Resolver = Resolver;
promises.NODATA = NODATA;
promises.FORMERR = FORMERR;
promises.SERVFAIL = SERVFAIL;
promises.NOTFOUND = NOTFOUND;
promises.NOTIMP = NOTIMP;
promises.REFUSED = REFUSED;
promises.BADQUERY = BADQUERY;
promises.BADNAME = BADNAME;
promises.BADFAMILY = BADFAMILY;
promises.BADRESP = BADRESP;
promises.CONNREFUSED = CONNREFUSED;
promises.TIMEOUT = TIMEOUT;
promises.EOF = EOF;
promises.FILE = FILE;
promises.NOMEM = NOMEM;
promises.DESTRUCTION = DESTRUCTION;
promises.BADSTR = BADSTR;
promises.BADFLAGS = BADFLAGS;
promises.NONAME = NONAME;
promises.BADHINTS = BADHINTS;
promises.NOTINITIALIZED = NOTINITIALIZED;
promises.LOADIPHLPAPI = LOADIPHLPAPI;
promises.ADDRGETNETWORKPARAMS = ADDRGETNETWORKPARAMS;
promises.CANCELLED = CANCELLED;

module.exports = {
  lookup: lookup,
  lookupService: lookupService,
  resolve: resolve,
  resolve4: resolve4,
  resolve6: resolve6,
  resolveMx: resolveMx,
  resolveTxt: resolveTxt,
  resolveSrv: resolveSrv,
  resolveNs: resolveNs,
  resolveCname: resolveCname,
  resolveSoa: resolveSoa,
  resolvePtr: resolvePtr,
  resolveCaa: resolveCaa,
  resolveNaptr: resolveNaptr,
  resolveAny: resolveAny,
  reverse: reverse,
  Resolver: Resolver,
  setDefaultResultOrder: setDefaultResultOrder,
  getDefaultResultOrder: getDefaultResultOrder,
  setServers: setServers,
  getServers: getServers,
  promises: promises,
  NODATA: NODATA, FORMERR: FORMERR, SERVFAIL: SERVFAIL, NOTFOUND: NOTFOUND,
  NOTIMP: NOTIMP, REFUSED: REFUSED, BADQUERY: BADQUERY, BADNAME: BADNAME,
  BADFAMILY: BADFAMILY, BADRESP: BADRESP, CONNREFUSED: CONNREFUSED,
  TIMEOUT: TIMEOUT, EOF: EOF, FILE: FILE, NOMEM: NOMEM,
  DESTRUCTION: DESTRUCTION, BADSTR: BADSTR, BADFLAGS: BADFLAGS,
  NONAME: NONAME, BADHINTS: BADHINTS, NOTINITIALIZED: NOTINITIALIZED,
  LOADIPHLPAPI: LOADIPHLPAPI, ADDRGETNETWORKPARAMS: ADDRGETNETWORKPARAMS,
  CANCELLED: CANCELLED
};
module.exports.default = module.exports;
