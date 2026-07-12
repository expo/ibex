// JSON/string workload that avoids Node-only APIs.
var __print =
  typeof print === "function"
    ? print
    : typeof console !== "undefined" && console.log
      ? function (s) { console.log(s); }
      : function () {};

var iters = globalThis.__benchIters || 18000;
var seed = [];

for (var i = 0; i < 120; i++) {
  seed.push({
    id: i,
    label: "record-" + i,
    flags: [i & 1, i & 3, i & 7],
    payload: "alpha:" + i + ":omega",
  });
}

var text = JSON.stringify(seed);
var acc = 0;

for (var j = 0; j < iters; j++) {
  var parsed = JSON.parse(text);
  parsed[j % parsed.length].payload += ":" + j;
  var out = JSON.stringify(parsed[j & 15]);
  acc = (acc + out.length + parsed.length) & 0x7fffffff;
}

__print("BENCH_RESULT json_strings " + (acc >>> 0));
