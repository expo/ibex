// Env-read gating + no plain-object env snapshot. Under `--capsec enforce` this
// principal is denied `env:read` by policy (a denial wins over the default trust
// of first-party root), so every real read path (`process.env.KEY`, gated by the
// native __exactGetEnv) returns undefined. There must also be no plain-object env
// snapshot on `process` that launders past the gate — regression for the removed
// `process.__exactPlainEnv`. @ref LLP 0013#mechanism-3
var out = [];
// The gated read is denied → undefined, never the secret.
var direct;
try {
  direct = process.env.SECRET_TOKEN;
} catch (e) {
  direct = "THREW:" + (e && e.name);
}
out.push("direct=" + (direct === undefined ? "undefined" : direct));
// The former ungated snapshot must not exist.
out.push("snapshot=" + typeof process.__exactPlainEnv);
// Brute-force: scan every own property of `process` for any object that carries
// the secret (a snapshot, a cache, anything).
var leaked = "none";
try {
  Object.getOwnPropertyNames(process).forEach(function (k) {
    var v;
    try {
      v = process[k];
    } catch (e) {
      return;
    }
    if (v && typeof v === "object") {
      try {
        if (v.SECRET_TOKEN) leaked = "via:" + k;
      } catch (e) {}
    }
  });
} catch (e) {}
out.push("scan=" + leaked);
console.log("probe: " + out.join(" "));
