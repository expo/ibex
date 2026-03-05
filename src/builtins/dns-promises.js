// dns/promises - re-exports dns.promises with error codes
var dns = require('dns');
var promises = dns.promises;
// Copy error codes from dns to promises (Node.js does this)
var codes = ['NODATA', 'FORMERR', 'SERVFAIL', 'NOTFOUND', 'NOTIMP', 'REFUSED',
  'BADQUERY', 'BADNAME', 'BADFAMILY', 'BADRESP', 'CONNREFUSED', 'TIMEOUT',
  'EOF', 'FILE', 'NOMEM', 'DESTRUCTION', 'BADSTR', 'BADFLAGS', 'NONAME',
  'BADHINTS', 'NOTINITIALIZED', 'LOADIPHLPAPI', 'ADDRGETNETWORKPARAMS',
  'CANCELLED'];
for (var i = 0; i < codes.length; i++) {
  if (dns[codes[i]] !== undefined) promises[codes[i]] = dns[codes[i]];
}
module.exports = promises;
