// Pin every tracked use of the frozen armed-snapshot schema string. Construct
// the value from components so this inventory test does not add itself to the
// inventory it measures.
//
// @ref LLP 0021#a9-appendix--the-scope-digest-join-matrix — M11 requires the
// other armed-snapshot schema pins to remain scope-transparent under Option B.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const armedSchema = ["ibex", "capsec-armed", "1"].join("/");
const excludedPrefixes = ["llp/", "node_modules/", "target/"];

const expected = new Map([
  ["capsec/examples/armed-snapshot.canonical.json", 1],
  ["capsec/examples/digest-bundle.canonical.json", 2],
  ["capsec/registry/policy-rules.json", 1],
  ["capsec/schema/armed-snapshot.schema.json", 1],
  ["crates/capsec-semantics/src/arming.rs", 3],
  ["crates/capsec-semantics/src/canonical.rs", 1],
  ["crates/capsec-semantics/src/digest.rs", 1],
  ["crates/sfe-catalog/src/lib.rs", 1],
  ["crates/sfe-format/src/app_bound.rs", 1],
  ["crates/sfe-format/src/lib.rs", 3],
  ["packages/ibex-devtools/src/scripts/capsec-contract.mjs", 1],
  ["packages/ibex-devtools/src/scripts/generate-capsec-runtime-projection.mjs", 1],
  ["schemas/app-bound-common-v1.schema.json", 1],
  ["schemas/capsec-runtime-projection-v1.schema.json", 1],
  ["schemas/stub-contract-v1.schema.json", 1],
  ["schemas/stub-contract-v3.schema.json", 1],
  ["src/host/portable_target_admission.rs", 1],
  ["vendored-generated/capsec-runtime-projection.canonical.json", 2],
]);

function occurrenceCount(bytes, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = bytes.indexOf(needle, offset)) !== -1) {
    count += 1;
    offset += needle.length;
  }
  return count;
}

test("M11 pins the complete tracked armed-schema string inventory", () => {
  const listed = spawnSync("/usr/bin/git", ["ls-files", "-z"], {
    cwd: repoRoot,
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(listed.status, 0, listed.stderr.toString("utf8"));
  const observed = new Map();
  for (const relativePath of listed.stdout.toString("utf8").split("\0")) {
    if (
      relativePath.length === 0 ||
      excludedPrefixes.some((prefix) => relativePath.startsWith(prefix))
    ) {
      continue;
    }
    const absolutePath = path.join(repoRoot, relativePath);
    const status = fs.lstatSync(absolutePath);
    if (!status.isFile()) continue;
    const count = occurrenceCount(fs.readFileSync(absolutePath), armedSchema);
    if (count !== 0) observed.set(relativePath, count);
  }
  assert.deepEqual([...observed], [...expected]);
});
