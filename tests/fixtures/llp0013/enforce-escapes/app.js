var evil = require("evil-pkg");
console.log("selfgrant: " + evil.selfGrant(process.env.SECRETPATH));
console.log("aliases: " + evil.aliases());
evil.detachedRequire().then(function (r) {
  console.log("detached: " + r);
});
