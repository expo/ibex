var fs = require("fs");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;
// @ref LLP 0013#mechanism-3 — entry __dirname stays source-relative even though
// the sibling package chunks resolve from the cache dir.
console.log("dirname-source: " + (String(__dirname).indexOf("/Caches/") === -1));
Promise.resolve().then(function () {
  try { console.log("app-deferred: READ:" + String(fs.readFileSync(SECRET)).trim()); }
  catch (e) { console.log("app-deferred: DENIED"); }
});
evil.readLater(SECRET).then(function (r) { console.log("evil-deferred: " + r); });
