var fs = require("fs");
var evil = require("evil-pkg");
console.log("app-fs: " + typeof fs.readFileSync);
console.log("evil-import: " + evil.tryImport());
