// Steady-state compartment-overhead workload (LLP 0013 Goal 3).
//
// @ref LLP 0013#goals — the A/B this drives: the SAME heavy loop runs with the
// compartment walk inactive vs active. The loop lives HERE, in the root Domain,
// which keeps the real global in BOTH arms, so the only per-opcode difference is
// the `anyCompartmentActive_` branch + `globalForFrame` walk that the carried
// Hermes patch adds to GetGlobalObject / CoerceThisNS / LoadThisNS. There is no
// Proxy-trap confound: root's Domain has no compartment global, so the walk
// resolves straight back to the real global — exactly the always-on cost Goal 3
// budgets at =<1%.
//
// arm-pkg (required below) is what arms the guard under IBEX_COMPARTMENTS=1; the
// require is identical JS in both arms, only the env flag differs.

var armPkg = require("arm-pkg");

var iters = parseInt(process.env.BENCH_ITERS || "12000000", 10);

// Sloppy-mode helper (module bodies compile via `new Function`, i.e. sloppy):
// calling it as a bare `mix(i)` coerces `this` to the global (CoerceThisNS), and
// reading `this` inside is LoadThisNS. It also does several bare-global reads
// (each `Math` reference is a GetGlobalObject + property load) so the affected
// opcodes are dense on the hot path.
function mix(i) {
  var self = this;                          // LoadThisNS (coerced global)
  var a = Math.imul(i | 0, 2654435761);     // GetGlobalObject(Math)
  var b = Math.abs(a >> 5);                 // GetGlobalObject(Math)
  var c = Math.max(a & 0xffff, b & 0xffff); // GetGlobalObject(Math)
  var d = self === undefined ? 0 : 1;       // touch the coerced `this`
  return (a ^ b ^ c ^ d) & 0x7fffffff;
}

var acc = 0;
var t0 = Date.now();
for (var i = 0; i < iters; i++) {
  acc = (acc + mix(i)) & 0x7fffffff;                        // bare call -> CoerceThisNS
  acc ^= (Math.floor(Math.sqrt((i & 0xffff) + 1)) | 0);     // GetGlobalObject(Math)
  acc = (Math.imul(acc, 1000003)) & 0x7fffffff;             // GetGlobalObject(Math)
}
var t1 = Date.now();

// `ms` is the pure in-VM loop time (excludes process boot/lockdown) so the
// harness can report a startup-free steady-state overhead alongside wall-clock.
console.log("BENCH result=" + (acc >>> 0) + " iters=" + iters + " ms=" + (t1 - t0));
console.log("armed=" + (armPkg.processWithheld ? "true" : "false"));
