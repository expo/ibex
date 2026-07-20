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

test("Windows runtime-drive principal scope has external linkage", () => {
  const source = readFileSync(
    path.join(repoRoot, "src/engine/hermes_runtime_fs_windows.cc"),
    "utf8",
  );
  const anonymousNamespaceEnd = source.indexOf("} // namespace");
  const signature =
    "const std::vector<uint64_t>* exactSwapTypedPrincipalStackForRuntimeDrive(\n";
  const definition = source.indexOf(signature);

  expect(anonymousNamespaceEnd).toBeGreaterThanOrEqual(0);
  expect(definition).toBeGreaterThan(anonymousNamespaceEnd);
  expect(source.indexOf(signature, definition + 1)).toBe(-1);
});

test("Windows engine identity names the Hermes DLL instead of an import thunk", () => {
  const source = readFileSync(
    path.join(repoRoot, "src/engine/hermes_runtime.cc"),
    "utf8",
  );
  const helperCalls = source.match(/exactHermesRuntimeImageModule\(\)/gu) ?? [];
  const loadedHelperCalls = source.match(/loadedHermesModule\(\)/gu) ?? [];

  expect(source).toContain("CreateToolhelp32Snapshot(");
  expect(source).toContain("GetLastError() != ERROR_BAD_LENGTH");
  expect(source).toContain("Module32FirstW(snapshot, &entry)");
  expect(source).toContain("Module32NextW(snapshot, &entry)");
  expect(source).toContain('lstrcmpiW(entry.szModule, L"hermesvm.dll")');
  expect(source).toContain("if (selected != nullptr)");
  expect(source).toContain("GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |");
  expect(source).toContain("GET_MODULE_HANDLE_EX_FLAG_PIN");
  expect(source).toContain(
    'GetProcAddress(candidate, "ex_hermes_vm_current_package_id")',
  );
  expect(source).not.toContain('GetModuleHandleA("hermesvm.dll")');
  expect(helperCalls).toHaveLength(2);
  expect(loadedHelperCalls).toHaveLength(3);
});
