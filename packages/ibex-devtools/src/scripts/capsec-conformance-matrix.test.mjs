import { expect, test } from "bun:test";
import {
  CONFORMANCE_COMMANDS,
  CONFORMANCE_EXECUTABLE_FEATURES,
  CONFORMANCE_HOST_FEATURES,
  CONFORMANCE_PREFLIGHT_COMMANDS,
  CONFORMANCE_PRODUCT_COMMANDS,
  resolveConformanceMatrixInvocation,
} from "./capsec-conformance-matrix.mjs";

test("conformance prerequisite matrix covers every product test layer", () => {
  const byId = new Map(
    CONFORMANCE_COMMANDS.map((entry) => [entry[0], entry.slice(1)]),
  );
  expect([...byId.keys()].sort()).toEqual([
    "all-generated-drift",
    "android-websocket-behavioral",
    "capsec-contract-drift",
    "capsec-registry-drift",
    "devtools-js-full",
    "generated-policy-drift",
    "hermes-transform-loader-corpora",
    "linked-literate-references",
    "runtime-environment-inventory-drift",
    "runtime-js-full",
    "rust-default-full",
    "rust-workspace-default-openssl-executable-tests",
    "rust-workspace-host-features-all-targets-compile",
  ]);
  expect(byId.get("rust-default-full")).toEqual([
    "bash",
    ["./scripts/run-tests.sh", "--", "--test-threads=1"],
  ]);
  const executable = byId.get(
    "rust-workspace-default-openssl-executable-tests",
  );
  expect(executable[0]).toBe("cargo");
  expect(executable[1]).not.toContain("--no-default-features");
  expect(executable[1]).not.toContain("--all-features");
  expect(executable[1][executable[1].indexOf("--features") + 1]).toBe(
    CONFORMANCE_EXECUTABLE_FEATURES.join(","),
  );
  expect(executable[1]).not.toContain("--all-targets");
  expect(executable[1]).not.toContain("--benches");
  const compileOnly = byId.get(
    "rust-workspace-host-features-all-targets-compile",
  );
  expect(compileOnly[0]).toBe("cargo");
  expect(compileOnly[1][0]).toBe("check");
  expect(compileOnly[1]).toContain("--all-targets");
  expect(byId.get("devtools-js-full")[1]).toContain(
    "packages/ibex-devtools/src/scripts",
  );
  expect(byId.get("runtime-js-full")[1]).toContain(
    "packages/ibex-runtime-js/src",
  );
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

test("host conformance covers every non-Simulator Cargo feature", async () => {
  const manifest = Bun.TOML.parse(await Bun.file("Cargo.toml").text());
  const expected = Object.keys(manifest.features)
    .filter(
      (feature) =>
        feature !== "default" &&
        feature !== "capsec-simulator-performance-observer",
    )
    .sort();
  expect([...CONFORMANCE_HOST_FEATURES].sort()).toEqual(expected);
  expect(CONFORMANCE_EXECUTABLE_FEATURES).toEqual(["openssl-crypto"]);
});

test("Windows registry drift uses the pinned Node oracle", () => {
  const invocation = resolveConformanceMatrixInvocation({
    id: "capsec-registry-drift",
    command: "bun",
    args: ["run", "check:capsec-registry"],
    target: "x86_64-pc-windows-msvc",
    environment: { IBEX_NODE_ORACLE_BIN: "C:\\node\\node.exe" },
    repoRoot: "C:/ibex",
  });
  expect(invocation).toEqual({
    command: "C:\\node\\node.exe",
    args: [
      "C:/ibex/packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs",
      "--check",
    ],
    environmentKeys: ["IBEX_NODE_ORACLE_BIN"],
  });
  expect(() =>
    resolveConformanceMatrixInvocation({
      id: "capsec-registry-drift",
      command: "bun",
      args: ["run", "check:capsec-registry"],
      target: "x86_64-pc-windows-msvc",
      environment: {},
      repoRoot: "C:/ibex",
    }),
  ).toThrow(/IBEX_NODE_ORACLE_BIN/u);
});

test("Windows shell commands use the pinned Git for Windows bash", () => {
  const invocation = resolveConformanceMatrixInvocation({
    id: "all-generated-drift",
    command: "bash",
    args: ["./scripts/check-generated-drift.sh"],
    target: "x86_64-pc-windows-msvc",
    environment: {
      IBEX_GIT_BASH_BIN: "C:\\Program Files\\Git\\bin\\bash.exe",
    },
    repoRoot: "C:/ibex",
  });
  expect(invocation).toEqual({
    command: "C:\\Program Files\\Git\\bin\\bash.exe",
    args: ["./scripts/check-generated-drift.sh"],
    environmentKeys: ["IBEX_GIT_BASH_BIN"],
  });
  expect(() =>
    resolveConformanceMatrixInvocation({
      id: "all-generated-drift",
      command: "bash",
      args: ["./scripts/check-generated-drift.sh"],
      target: "x86_64-pc-windows-msvc",
      environment: {},
      repoRoot: "C:/ibex",
    }),
  ).toThrow(/IBEX_GIT_BASH_BIN/u);
});
