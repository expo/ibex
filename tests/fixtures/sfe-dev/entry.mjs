import path from "node:path";
import { value } from "./value.mjs";

if (process.argv.includes("--async-exit-7")) {
  setTimeout(() => {
    console.log("compiled-lifecycle-flush");
    process.exitCode = 7;
  }, 5);
}

export const answer = path.basename("/tmp/ibex") === "ibex" ? value + 1 : 0;
export const applicationArgs = process.argv.slice(2);
export const capturedEnvironment = process.env.SFE_BASE;
