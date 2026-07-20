import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

test("Windows frame attribution uses the opaque patched-Hermes bridge", () => {
  const source = readFileSync(
    path.join(repoRoot, "src/engine/hermes_runtime_fs_windows.cc"),
    "utf8",
  );
  const functionStart = source.indexOf(
    "std::vector<uint64_t> exactCollectTypedPrincipalStack()",
  );
  const functionEnd = source.indexOf(
    "ScopedTypedPrincipalStack::ScopedTypedPrincipalStack",
    functionStart,
  );
  expect(functionStart).toBeGreaterThanOrEqual(0);
  expect(functionEnd).toBeGreaterThan(functionStart);

  const implementation = source.slice(functionStart, functionEnd);
  expect(implementation).toContain("ex_hermes_vm_collect_package_ids(");
  expect(implementation).not.toContain("g_vm_runtime->");
  expect(implementation).not.toContain("HermesRuntime::StackTraceKind");
});
