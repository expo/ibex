import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const generator = path.join(
  repoRoot,
  "packages/ibex-devtools/src/scripts/generate-policy.mjs",
);

export const GENERATED_POLICY_CHECKS = Object.freeze([
  [
    "examples/llp0013-supply-chain/app.mjs",
    "examples/llp0013-supply-chain/ibex-policy.json",
  ],
  [
    "examples/capsec-demo/01-supply-chain/app.js",
    "examples/capsec-demo/01-supply-chain/ibex-policy.json",
  ],
  [
    "examples/capsec-demo/02-least-privilege/app.mjs",
    "examples/capsec-demo/02-least-privilege/ibex-policy.json",
  ],
  [
    "examples/capsec-demo/04-defense-in-depth/app.mjs",
    "examples/capsec-demo/04-defense-in-depth/ibex-policy.json",
  ],
]);

export function checkGeneratedPolicies() {
  for (const [entry, output] of GENERATED_POLICY_CHECKS) {
    execFileSync(
      process.execPath,
      [generator, "--entry", entry, "--out", output, "--mode", "enforce", "--check"],
      { cwd: repoRoot, stdio: "inherit" },
    );
  }
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  checkGeneratedPolicies();
}
