import path from "node:path";
import commonjs from "./value.cjs";
import { staticValue } from "./static.mjs";

if (process.env.IBEX_TAMPER_SENTINEL === "1") {
  console.log("carrier-evaluated:entry");
}

const route = process.argv[2] === "right" ? "./right.mjs" : "./left.mjs";
const literal = await import("./literal.mjs");
const computed = await import(route, {
  with: { "ibex:site": "routes" },
});

console.log(
  `${path.basename("/tmp/ibex")}:${commonjs.value}:${staticValue}:${literal.literalValue}:${computed.side}`,
);
