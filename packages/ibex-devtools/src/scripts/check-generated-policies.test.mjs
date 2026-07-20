import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GENERATED_POLICY_CHECKS } from "./check-generated-policies.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

test("generated policy drift covers the LLP example and every rev2 demo policy", () => {
  expect(GENERATED_POLICY_CHECKS).toEqual([
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
});

test("checked portable policy trees retain canonical source bytes", () => {
  for (const [entry] of GENERATED_POLICY_CHECKS) {
    const projectRoot = path.dirname(entry);
    const trackedFiles = execFileSync(
      "git",
      ["ls-files", "-z", "--", projectRoot],
      {
        cwd: repoRoot,
      },
    )
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
    expect(trackedFiles.length).toBeGreaterThan(0);

    const attributes = execFileSync(
      "git",
      ["check-attr", "eol", "--", ...trackedFiles],
      { cwd: repoRoot, encoding: "utf8" },
    );
    for (const file of trackedFiles) {
      expect(attributes).toContain(`${file}: eol: lf`);
    }
  }
});
