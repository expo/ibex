// Object/array allocation and property access workload for both engines.
var __print =
  typeof print === "function"
    ? print
    : typeof console !== "undefined" && console.log
      ? function (s) { console.log(s); }
      : function () {};

var iters = globalThis.__benchIters || 280000;
var rows = [];
var acc = 0;

function makeRow(i) {
  return {
    id: i,
    name: "item-" + (i % 1024),
    group: i & 31,
    score: (Math.imul(i, 1103515245) >>> 3) & 0xffff,
  };
}

for (var i = 0; i < iters; i++) {
  rows.push(makeRow(i));
}

for (var j = 0; j < rows.length; j++) {
  var row = rows[j];
  if ((row.group & 3) === 0) {
    acc += row.score ^ row.id;
  } else {
    acc += row.name.length + row.group;
  }
  acc &= 0x7fffffff;
}

rows.sort(function (a, b) {
  return (a.score - b.score) || (a.id - b.id);
});

for (var k = 0; k < rows.length; k += 37) {
  acc ^= rows[k].score;
}

__print("BENCH_RESULT object_arrays " + (acc >>> 0));
