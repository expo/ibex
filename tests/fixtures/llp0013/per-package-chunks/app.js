var fs = require("fs");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;
Promise.resolve().then(function () {
  try { console.log("app-deferred: READ:" + String(fs.readFileSync(SECRET)).trim()); }
  catch (e) { console.log("app-deferred: DENIED"); }
});
evil.readLater(SECRET).then(function (r) { console.log("evil-deferred: " + r); });
