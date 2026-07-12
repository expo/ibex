import { expect, test } from "bun:test";
import { CONFORMANCE_COMMANDS } from "./capsec-conformance-matrix.mjs";

test("conformance prerequisite matrix covers every product test layer", () => {
  const byId = new Map(CONFORMANCE_COMMANDS.map((entry) => [entry[0], entry.slice(1)]));
  expect([...byId.keys()].sort()).toEqual([
    "all-generated-drift",
    "capsec-contract-drift",
    "capsec-registry-drift",
    "devtools-js-full",
    "generated-policy-drift",
    "hermes-transform-loader-corpora",
    "linked-literate-references",
    "runtime-js-full",
    "rust-default-full",
    "rust-workspace-all-features-all-targets-compile",
    "rust-workspace-all-features-executable-tests",
  ]);
  expect(byId.get("rust-default-full")).toEqual([
    "./scripts/run-tests.sh",
    ["--", "--test-threads=1"],
  ]);
  const executable = byId.get("rust-workspace-all-features-executable-tests");
  expect(executable[0]).toBe("cargo");
  expect(executable[1]).toContain("--all-features");
  expect(executable[1]).not.toContain("--all-targets");
  expect(executable[1]).not.toContain("--benches");
  const compileOnly = byId.get(
    "rust-workspace-all-features-all-targets-compile",
  );
  expect(compileOnly[0]).toBe("cargo");
  expect(compileOnly[1][0]).toBe("check");
  expect(compileOnly[1]).toContain("--all-targets");
  expect(byId.get("devtools-js-full")[1]).toContain("packages/ibex-devtools/src/scripts");
  expect(byId.get("runtime-js-full")[1]).toContain("packages/ibex-runtime-js/src");
});
