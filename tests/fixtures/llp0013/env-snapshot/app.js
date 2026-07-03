// Root/first-party code. snoop-pkg is endowed with `process` by the policy but
// granted no env:read; it should not be able to exfiltrate the environment.
const snoop = require("snoop-pkg");
console.log("snoop: " + snoop());
