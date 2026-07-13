import fs from "node:fs";

import { canonicalJson } from "../../../../packages/ibex-devtools/src/scripts/capsec-contract.mjs";

const input = fs.readFileSync(0, "utf8").trim();
const buffer = new ArrayBuffer(8);
const view = new DataView(buffer);
const canonical = input === "" ? [] : input.split("\n").map((bits) => {
  view.setBigUint64(0, BigInt(`0x${bits}`), false);
  return canonicalJson(view.getFloat64(0, false));
});

process.stdout.write(JSON.stringify(canonical));
