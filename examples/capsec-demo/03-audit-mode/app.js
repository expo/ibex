// Foreground audit is a root diagnostic. Keep this fixture independent of
// package endowments so every line can execute and produce real observations.
const fs = require("fs");

const bytes = fs.readFileSync("cache/photo.bin");
console.log("");
console.log("  read cache/photo.bin: " + bytes.length + " bytes");
console.log("  API_SECRET present:   " + (process.env.API_SECRET !== undefined));
console.log("");
