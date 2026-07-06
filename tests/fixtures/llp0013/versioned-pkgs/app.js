// @ref LLP 0013#resolved-questions — (ENG-22621) — two installed versions of one
// package coexist: the app imports shared-pkg@2.0.0 directly, and uses-old pulls
// in the nested shared-pkg@1.0.0. Each version reads a secret through its own
// frame (a synchronous read attributed to its own principal). The policy pins
// `shared-pkg@1.0.0` with an fs:read deny while granting the bare `shared-pkg`
// selector fs:read, so the two versions receive different treatment.
var direct = require("shared-pkg");
var usesOld = require("uses-old");
var SECRET = process.env.SECRETPATH;

console.log("direct-" + direct.v + ": " + direct.read(SECRET));
console.log("via-old-" + usesOld.readerVersion + ": " + usesOld.read(SECRET));
