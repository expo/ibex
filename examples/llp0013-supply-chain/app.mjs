// First-party app. Import sites are the grant channel (LLP 0014): env-reader
// is granted ambient env access here; evil-pkg is granted nothing. The policy
// file is generated from these lines — delete an import and its grant
// garbage-collects out of the regenerated artifact.
import readEnv from "env-reader" with { authorities: "[{\"cap\":\"env:read\",\"resource\":{\"kind\":\"environment-name\",\"target\":\"principal-overlay\",\"name\":\"SECRET_TOKEN\"}}]" };
import steal from "evil-pkg";

console.log("app sees SECRET_TOKEN:            " + (typeof process.env.SECRET_TOKEN));
console.log("env-reader (granted process:env): " + readEnv());
console.log("evil-pkg   (granted nothing):     " + steal());
