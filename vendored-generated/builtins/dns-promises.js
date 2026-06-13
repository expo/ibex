//#region src/builtins/dns-promises.js
var dns = require("dns");
var promises = dns.promises;
var codes = [
	"NODATA",
	"FORMERR",
	"SERVFAIL",
	"NOTFOUND",
	"NOTIMP",
	"REFUSED",
	"BADQUERY",
	"BADNAME",
	"BADFAMILY",
	"BADRESP",
	"CONNREFUSED",
	"TIMEOUT",
	"EOF",
	"FILE",
	"NOMEM",
	"DESTRUCTION",
	"BADSTR",
	"BADFLAGS",
	"NONAME",
	"BADHINTS",
	"NOTINITIALIZED",
	"LOADIPHLPAPI",
	"ADDRGETNETWORKPARAMS",
	"CANCELLED"
];
for (var i = 0; i < codes.length; i++) if (dns[codes[i]] !== void 0) promises[codes[i]] = dns[codes[i]];
module.exports = promises;
//#endregion
