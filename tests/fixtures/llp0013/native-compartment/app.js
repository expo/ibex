globalThis.sessionSecret = "ROOT-SESSION-SECRET";
var evil = require("evil-pkg");
console.log("app-process: " + typeof process);
console.log("evil: " + evil.probe());
