// @ref LLP 0001#4-what-ci-must-handle-per-cell — the source fallback follows
// the activated supported MSVC generation instead of pinning a Visual Studio
// installation that a hosted image may no longer contain.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const script = path.join(repoRoot, "scripts", "build-hermes-windows.ps1");

function selectGenerator(version) {
  const env = { ...process.env };
  if (version === null) delete env.VisualStudioVersion;
  else env.VisualStudioVersion = version;
  return spawnSync(
    "pwsh",
    [
      "-NoLogo",
      "-NoProfile",
      "-File",
      script,
      "-PrintCMakeGenerator",
    ],
    { cwd: repoRoot, encoding: "utf8", env },
  );
}

test("selects the exact CMake generator for each supported hosted MSVC major", () => {
  const vs2022 = selectGenerator("17.9");
  assert.equal(vs2022.status, 0, vs2022.stderr);
  assert.equal(vs2022.stdout.trim(), "Visual Studio 17 2022");

  const vs2026 = selectGenerator("18.0");
  assert.equal(vs2026.status, 0, vs2026.stderr);
  assert.equal(vs2026.stdout.trim(), "Visual Studio 18 2026");
});

test("refuses missing, malformed, and unsupported Visual Studio generations", () => {
  for (const version of [
    null,
    "18-preview",
    "18.0-preview",
    "18.0garbage",
    "16.11",
    "19.0",
  ]) {
    const result = selectGenerator(version);
    assert.notEqual(result.status, 0, `unexpectedly accepted ${version}`);
    assert.match(
      `${result.stdout}\n${result.stderr}`,
      /Supported Visual Studio developer environment is required/u,
    );
  }
});
