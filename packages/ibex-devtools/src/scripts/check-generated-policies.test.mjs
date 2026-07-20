import { expect, test } from "bun:test";
import fs from "node:fs";
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

test("generated policy inputs use canonical LF checkout bytes", () => {
  const attributes = fs.readFileSync(
    path.join(repoRoot, ".gitattributes"),
    "utf8",
  );
  expect(attributes).toContain("examples/**/*.js text eol=lf");
  expect(attributes).toContain("examples/**/*.mjs text eol=lf");
  expect(attributes).toContain("examples/**/*.json text eol=lf");

  for (const sourcePath of [
    "examples/llp0013-supply-chain/app.mjs",
    "examples/llp0013-supply-chain/node_modules/env-reader/index.js",
    "examples/llp0013-supply-chain/node_modules/env-reader/package.json",
  ]) {
    expect(
      fs.readFileSync(path.join(repoRoot, sourcePath), "utf8").includes("\r"),
      sourcePath,
    ).toBe(false);
  }
});
