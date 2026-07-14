// Promise/microtask workload. The final print also verifies the queue drained.
var __print =
  typeof print === "function"
    ? print
    : typeof console !== "undefined" && console.log
      ? function (s) { console.log(s); }
      : function () {};

var iters = globalThis.__benchIters || 12000;
var acc = 0;
var p = Promise.resolve(0);

for (var i = 0; i < iters; i++) {
  (function (n) {
    p = p.then(function (x) {
      acc = (acc + ((x + n) & 0xffff)) & 0x7fffffff;
      return (x + 1) & 0xffff;
    });
  })(i);
}

p.then(function () {
  __print("BENCH_RESULT promise_chain " + (acc >>> 0));
});
