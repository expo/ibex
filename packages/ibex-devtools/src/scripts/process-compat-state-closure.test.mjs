import { expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const source = fs.readFileSync(
  path.join(repoRoot, "src/engine/bootstrap/process-compat-fix.js"),
  "utf8",
);
const compatPolyfillsSource = fs.readFileSync(
  path.join(repoRoot, "src/engine/bootstrap/compat-polyfills.js"),
  "utf8",
);
const exactGlobalSource = fs.readFileSync(
  path.join(repoRoot, "src/engine/bootstrap/exact-global.js"),
  "utf8",
);

test("legacy process compatibility keeps diagnostic state private", () => {
  for (const name of [
    "__exactProcessCompatFixRan",
    "__exactProcessCompatFixSawProcess",
    "__exactFinalVersionsFixRan",
    "__exactFinalVersionsObj",
    "__exactFinalVersionsOpenssl",
    "__exactFinalVersionsOpensslAfter",
    "__exactFinalVersionsDefineOK",
    "__exactFinalVersionsSame",
    "__exactFinalVersionsProtoOK",
    "__exactFinalVersionsNewProtoOK",
    "__exactFinalVersionsError",
  ]) {
    expect(source).not.toContain(`globalThis.${name}`);
  }
  expect(source).toContain("var hasProcess = typeof process === 'object'");
});

test("readable-stream retry scheduling stays bootstrap-private", () => {
  expect(compatPolyfillsSource).not.toContain(
    "__exactReadableStreamCompatIteratorPatchScheduled",
  );
  expect(exactGlobalSource).not.toContain(
    "__exactReadableStreamCompatIteratorPatchScheduled",
  );
  expect(compatPolyfillsSource).toContain(
    "var readableStreamIteratorPatchScheduled = false",
  );
});
