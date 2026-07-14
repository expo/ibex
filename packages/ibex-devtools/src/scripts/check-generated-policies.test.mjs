import { expect, test } from "bun:test";
import { GENERATED_POLICY_CHECKS } from "./check-generated-policies.mjs";

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
