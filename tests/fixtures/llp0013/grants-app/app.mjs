// First-party root-principal code: import sites are the grant channel
// (@ref LLP 0014#the-grant-channel). env-reader is granted ambient process
// access; evil-pkg gets nothing; image-lib's grant cascades to fast-codec via
// its package.json `ibex.delegates`; the `also:` entry covers tmp-helper.
import readEnv from "env-reader" with { grants: "process:env" };
import processImages from "image-lib" with {
  grants: "fs:read:/tmp/ibex-llp0013/**",
  also: "tmp-helper => fs:read:/tmp/ibex-llp0013/**",
};
import steal from "evil-pkg";
import sneaky from "sneaky-pkg";

console.log("env-reader:  " + readEnv());
console.log("evil-pkg:    " + steal());
console.log("image-lib:   " + processImages());
console.log("sneaky-pkg:  " + sneaky());
