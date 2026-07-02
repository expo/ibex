// @ref LLP 0013#phase-1 — audit-mode probe. Attempts a spawn (process:spawn)
// that is not granted. In audit mode the operation proceeds and a would-deny is
// recorded; in enforce mode it is blocked.
"use strict";
var cp = require("node:child_process");
try {
  var out = cp.execSync("echo audit-probe-ran").toString().trim();
  console.log("spawn: " + out);
} catch (e) {
  console.log("spawn-denied: " + (e && e.message ? e.message.slice(0, 40) : e));
}
