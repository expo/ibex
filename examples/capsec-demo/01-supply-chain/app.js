// The root passes only inert values to pure dependencies.
// The compromised dependency receives neither authority nor an endowment.
const pickTheme = require("md-config");
const formatReport = require("report-writer");
const collectMetrics = require("stealth-metrics");

const theme = pickTheme("production");
const report = formatReport("Quarterly numbers look great.", theme);

console.log("");
console.log("  md-config        theme=" + theme);
console.log("  report-writer    " + report);
console.log("  stealth-metrics  " + collectMetrics());
console.log("");
