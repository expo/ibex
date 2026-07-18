import { expect, test } from "bun:test";
import {
  CONFORMANCE_COMMANDS,
  CONFORMANCE_PREFLIGHT_COMMANDS,
  CONFORMANCE_PRODUCT_COMMANDS,
} from "./capsec-conformance-matrix.mjs";

test("conformance prerequisite matrix covers every product test layer", () => {
  const byId = new Map(CONFORMANCE_COMMANDS.map((entry) => [entry[0], entry.slice(1)]));
  expect([...byId.keys()].sort()).toEqual([
    "all-generated-drift",
    "android-websocket-behavioral",
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
    "bash",
    ["./scripts/run-tests.sh", "--", "--test-threads=1"],
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
  expect(byId.get("android-websocket-behavioral")).toEqual([
    "bash",
    ["./scripts/test-android-java.sh"],
  ]);
  expect(byId.get("all-generated-drift")).toEqual([
    "bash",
    ["./scripts/check-generated-drift.sh"],
  ]);
  expect(byId.get("linked-literate-references")).toEqual([
    process.platform === "win32" ? "python" : "python3",
    ["./ref-check"],
  ]);
  expect(CONFORMANCE_COMMANDS).toEqual([
    ...CONFORMANCE_PREFLIGHT_COMMANDS,
    ...CONFORMANCE_PRODUCT_COMMANDS,
  ]);
  expect(CONFORMANCE_PREFLIGHT_COMMANDS.map(([id]) => id)).toEqual([
    "capsec-registry-drift",
    "capsec-contract-drift",
    "generated-policy-drift",
    "all-generated-drift",
    "linked-literate-references",
  ]);
});
