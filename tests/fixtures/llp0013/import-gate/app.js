var fs = require("fs");
var evil = require("evil-pkg");
console.log("app-fs: " + typeof fs.readFileSync);
console.log("evil-import: " + evil.tryImport());
console.log("evil-global-require: " + evil.tryGlobalRequire());
console.log("evil-exact-require: " + evil.tryExactRequire());
evil.tryDynamicImport().then(function (r) {
  console.log("evil-dynamic-import: " + r);
});
