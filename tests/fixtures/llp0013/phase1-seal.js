// @ref LLP 0013#phase-1 — real-global inventory closure. Under lockdown the lazy
// `__exactEnsure*` installers are eager-installed then deleted (so no host
// surface appears on a frozen global mid-run), and the ambient self-grant
// channel `Exact.setModuleCapabilities` is removed (grants come from the policy
// artifact, not runtime self-declaration). fs must still work — it was installed
// before the seal.
var g = globalThis;

var installersGone =
  typeof g.__exactEnsureFs === "undefined" &&
  typeof g.__exactEnsureHttp === "undefined" &&
  typeof g.__exactEnsureChildProcess === "undefined";
console.log("installers-sealed: " + installersGone);

var selfGrantGone =
  !(g.Exact && typeof g.Exact.setModuleCapabilities === "function") &&
  typeof g.__exactGrantCapability === "undefined";
console.log("self-grant-sealed: " + selfGrantGone);

// Eager install must have happened before the seal: fs still resolves.
var fs = require("fs");
console.log("fs-usable: " + (typeof fs.readFileSync === "function"));
