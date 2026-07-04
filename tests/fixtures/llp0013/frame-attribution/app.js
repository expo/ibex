// First-party application code (the trusted root principal). The app is granted
// fs; evil-pkg is granted nothing. Both read the same secret file through the
// same asynchronous mechanism — a Promise microtask that runs after their
// modules finished evaluating, through the same trusted `fs` deputy — so the
// only thing that can distinguish them at the host boundary is the executing
// frame's package principal. That is exactly what Mechanism 3 provides.
var fs = require("fs");
var evil = require("evil-pkg");
var SECRET = process.env.SECRETPATH;

// The app's own deferred read: attributed to the root Domain, so it succeeds.
Promise.resolve().then(function () {
  try {
    console.log("app-deferred: READ:" + String(fs.readFileSync(SECRET)).trim());
  } catch (e) {
    console.log("app-deferred: DENIED");
  }
});

// evil-pkg's deferred read: identical async shape and API, but the callback
// belongs to evil-pkg's Domain, so it is attributed to evil-pkg and denied.
evil.readLater(SECRET).then(function (result) {
  console.log("evil-deferred: " + result);
});
