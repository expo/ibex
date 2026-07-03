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
// ENG-22627 — path-based mutators must also be gated on fs:write, not just the
// fd-based open path. Classify our capability denial ("Permission denied")
// distinctly from an ordinary syscall error.
function probe(label, fn) {
  try { fn(); console.log(label + ": SUCCEEDED"); }
  catch (e) {
    var msg = (e && e.message) || "";
    console.log(label + ": " + (msg.indexOf("Permission denied") !== -1 ? "DENIED" : "ERR"));
  }
}
probe("truncate", function () { fs.truncateSync(out, 0); });
var link = process.env.OUTDIR + "/x.link";
probe("symlink", function () { try { fs.unlinkSync(link); } catch (_) {} fs.symlinkSync(out, link); });
