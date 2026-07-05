// Root touches fs so the lazily-installed fs host functions — which include
// the __exactIpc* SCM_RIGHTS helpers — are present on globalThis before the
// evil-pkg probe runs (ENG-22883). Root may require fs; evil-pkg (builtins:[])
// cannot, but it can still see the installed natives, which is the point of the
// ownership gate.
require("fs");
var evil = require("evil-pkg");
console.log("selfgrant: " + evil.selfGrant(process.env.SECRETPATH));
console.log("aliases: " + evil.aliases());
console.log("ipcfds: " + evil.ipcFds());
evil.detachedRequire().then(function (r) {
  console.log("detached: " + r);
});
