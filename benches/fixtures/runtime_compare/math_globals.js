// Pure-JS math/global lookup workload that runs on both Hermes shell and Ibex.
var __print =
  typeof print === "function"
    ? print
    : typeof console !== "undefined" && console.log
      ? function (s) { console.log(s); }
      : function () {};

var iters = globalThis.__benchIters || 4000000;
var acc = 0;

function mix(i) {
  var self = this;
  var a = Math.imul(i | 0, 2654435761);
  var b = Math.abs(a >> 5);
  var c = Math.max(a & 0xffff, b & 0xffff);
  var d = self === undefined ? 0 : 1;
  return (a ^ b ^ c ^ d) & 0x7fffffff;
}

for (var i = 0; i < iters; i++) {
  acc = (acc + mix(i)) & 0x7fffffff;
  acc ^= Math.floor(Math.sqrt((i & 0xffff) + 1)) | 0;
  acc = Math.imul(acc, 1000003) & 0x7fffffff;
}

__print("BENCH_RESULT math_globals " + (acc >>> 0));
