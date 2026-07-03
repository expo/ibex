var deputy = require("deputy-pkg");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;
// App (root, granted) drives the deputy: stack-intersection allows.
try { console.log("app-via-deputy: READ:" + deputy.readFor(SECRET)); }
catch (e) { console.log("app-via-deputy: DENIED"); }
// evil (ungranted) drives the same deputy: stack-intersection denies.
console.log("evil-via-deputy: " + evil.steal(SECRET));
