import { expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CONFORMANCE_COMMANDS,
  CONFORMANCE_PREFLIGHT_COMMANDS,
  CONFORMANCE_PRODUCT_COMMANDS,
} from "./capsec-conformance-matrix.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

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

test("OpenSSL-only native test hooks do not become Windows link obligations", () => {
  const nodeHashTest = fs.readFileSync(
    path.join(repoRoot, "tests/crypto_node_hash_name.rs"),
    "utf8",
  );
  const rsaTest = fs.readFileSync(
    path.join(repoRoot, "tests/crypto_rsa_pss.rs"),
    "utf8",
  );

  expect(nodeHashTest).toContain('#![cfg(not(target_os = "windows"))]');
  expect(rsaTest).toContain(
    '#![cfg(all(feature = "openssl-crypto", not(target_os = "windows")))]',
  );
});

test("Windows native smoke uses the directly installed platform surface", () => {
  const engine = fs.readFileSync(path.join(repoRoot, "src/engine/mod.rs"), "utf8");
  const windowsSmoke = engine.slice(
    engine.indexOf("mod windows_native_smoke"),
    engine.indexOf("\n    }\n}", engine.indexOf("mod windows_native_smoke")),
  );

  expect(windowsSmoke).toContain("Host::default_legacy()");
  expect(windowsSmoke).toContain("__exactTcpConnect('127.0.0.1'");
  expect(windowsSmoke).not.toContain("__exactEnsureNet();");
});

test("Windows binary suites preserve process flags and ordinary tool paths", () => {
  const nativeRuntime = fs.readFileSync(
    path.join(repoRoot, "src/engine/hermes_runtime.cc"),
    "utf8",
  );
  const cliRuntime = fs.readFileSync(
    path.join(repoRoot, "src/bin/ibex/runtime.rs"),
    "utf8",
  );

  expect(nativeRuntime).toContain(
    "GetEnvironmentVariableA(env_name, nullptr, 0)",
  );
  expect(cliRuntime).toContain(
    "normalize_windows_tool_path(bundler_script_path()?)",
  );
  expect(cliRuntime).toMatch(
    /let canonical_entry = normalize_windows_tool_path\([\s\S]{0,180}std::fs::canonicalize\(entry\)/,
  );
  expect(cliRuntime).toContain(
    "let canonical_dep = normalize_windows_tool_path(canonical_dep);",
  );
  expect(cliRuntime).toMatch(
    /#\[cfg\(windows\)\][\s\S]{0,600}staged\.sync_all\(\)\?;/,
  );
});

test("Windows REPL runtime tests do not require native Promise unwrapping", () => {
  const repl = fs.readFileSync(
    path.join(repoRoot, "src/bin/ibex/repl/mod.rs"),
    "utf8",
  );
  const testBody = repl.slice(
    repl.indexOf("async fn hermes_commits_last_value_only_after_display_fully_succeeds"),
  );

  expect(testBody).toMatch(
    /#\[cfg\(not\(windows\)\)\][\s\S]{0,1800}Some\("async:44"\)/,
  );
});
