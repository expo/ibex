// @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check — bytewise
// drift checks require one canonical checkout spelling for every compared file.

import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

const byteComparedRoots = Object.freeze([
  "capsec",
  "packages/ibex-runtime-js/src",
  "src/builtins",
  "vendored-generated",
]);
const byteComparedFiles = Object.freeze([
  "config/oxc-retirement-manifest.json",
  "modules.ts",
  "src/capsec_registry_generated.rs",
  "src/capsec_runtime_projection_generated.rs",
  "src/compiled_environment_profile_generated.rs",
  "src/engine/capsec_registry_generated.h",
  "src/identity_generated.rs",
  "src/module_loader/transform_config_generated.rs",
]);

test("byte-compared generated authorities retain canonical LF checkouts", () => {
  const files = execFileSync(
    "git",
    ["ls-files", "-z", "--", ...byteComparedRoots, ...byteComparedFiles],
    { cwd: repoRoot },
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  expect(files.length).toBeGreaterThan(0);

  const fields = execFileSync("git", ["check-attr", "-z", "--stdin", "eol"], {
    cwd: repoRoot,
    encoding: "utf8",
    input: `${files.join("\0")}\0`,
  })
    .split("\0")
    .filter(Boolean);
  expect(fields).toHaveLength(files.length * 3);
  for (let index = 0; index < fields.length; index += 3) {
    expect(fields[index + 1]).toBe("eol");
    expect(fields[index + 2], fields[index]).toBe("lf");
  }
});
