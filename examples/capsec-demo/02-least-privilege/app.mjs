// The policy generator turns this import-site declaration into one typed,
// provenance-bearing floor row. It does not create an ambient process endowment.
import logger from "logger" with {
  authorities: "[{\"cap\":\"env:read\",\"resource\":{\"kind\":\"environment-name\",\"target\":\"principal-overlay\",\"name\":\"APP_MODE\"}}]",
};

console.log("");
console.log("  logger floor: env:read principal-overlay/APP_MODE");
console.log("  logger channel: " + logger.inspectAmbientEnvironment());
console.log("");
