// First-party root: granted fs. Its OWN wrapped async read is allowed (its
// callback frame carries the root principal); evil-pkg is granted nothing.
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;
evil.steal(SECRET).then(function (r) { console.log("evil: " + r); });
Promise.resolve().then(function () {
  try { console.log("app: READ:" + String(require("fs").readFileSync(SECRET)).trim()); }
  catch (e) { console.log("app: DENIED"); }
});
