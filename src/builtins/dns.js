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
  reverse: _promisify1(reverse)
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

module.exports = {
  lookup: lookup,
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
  reverse: reverse,
  promises: promises,
  NODATA: NODATA, FORMERR: FORMERR, SERVFAIL: SERVFAIL, NOTFOUND: NOTFOUND,
  NOTIMP: NOTIMP, REFUSED: REFUSED, BADQUERY: BADQUERY, BADNAME: BADNAME,
  BADFAMILY: BADFAMILY, BADRESP: BADRESP, CONNREFUSED: CONNREFUSED,
  TIMEOUT: TIMEOUT, EOF: EOF, FILE: FILE, NOMEM: NOMEM,
  DESTRUCTION: DESTRUCTION, BADSTR: BADSTR, BADFLAGS: BADFLAGS,
  NONAME: NONAME, BADHINTS: BADHINTS, NOTINITIALIZED: NOTINITIALIZED,
  CANCELLED: CANCELLED
};
module.exports.default = module.exports;
