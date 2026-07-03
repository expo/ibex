// @ref LLP 0013#policy — fs:write must be gated even on the fd-based write path
// (writeFileSync opens with write flags; opening for write requires fs:write,
// not fs:read). First-party root is trusted by default, so the read-only policy
// explicitly denies fs:write to this principal — a denial wins over root trust —
// exercising the write-vs-read distinction at the open boundary.
var fs = require("fs");
var out = process.env.OUTDIR + "/x.txt";
try { fs.writeFileSync(out, "data"); console.log("write: SUCCEEDED"); }
catch (e) { console.log("write: DENIED"); }
try { fs.readFileSync(process.env.READABLE); console.log("read: OK"); }
catch (e) { console.log("read: DENIED"); }
