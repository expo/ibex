const route = process.argv[2] === "right" ? "./right.mjs" : "./left.mjs";

const selected = await import(route, {
  with: { "ibex:site": "routes" },
});

console.log(selected.side);
