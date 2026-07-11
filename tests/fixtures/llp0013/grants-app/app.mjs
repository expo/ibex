// First-party root-principal code: import sites are the grant channel
// @ref LLP 0014#the-grant-channel — env-reader is granted ambient process
// access; evil-pkg gets nothing; image-lib's grant cascades to fast-codec via
// its package.json `ibex.delegates`; the `also:` entry covers tmp-helper.
import readEnv from "env-reader" with { authorities: "[{\"cap\":\"env:read\",\"resource\":{\"kind\":\"environment-name\",\"target\":\"principal-overlay\",\"name\":\"SECRET_TOKEN\"}}]" };
import processImages from "image-lib" with {
  authorities: "[{\"cap\":\"fs:read\",\"resource\":{\"kind\":\"path-tree\",\"path\":{\"root\":\"absolute\",\"hostBound\":true,\"components\":[{\"encoding\":\"utf8\",\"value\":\"tmp\"},{\"encoding\":\"utf8\",\"value\":\"ibex-llp0013\"}]}}}]",
};
import steal from "evil-pkg";
import sneaky from "sneaky-pkg";

console.log("env-reader:  " + readEnv());
console.log("evil-pkg:    " + steal());
console.log("image-lib:   " + processImages());
console.log("sneaky-pkg:  " + sneaky());
