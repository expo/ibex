import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import {
  canonicalJson,
  semanticDigest,
} from "../../../../scripts/portable-engine-contract.mjs";
import {
  conformanceRunnerBindingDigest,
  readCanonicalConformanceRunnerSelection,
} from "./capsec-conformance-runner-binding.mjs";

const temporaryRoots = new Set();
const sourceRevision = "a".repeat(40);
const sourceTreeDigest = semanticDigest("ibex:test:source-tree:1", {
  tree: "fixture",
});
const semantic = (character) => `sha256-${character.repeat(43)}`;
const raw = (character) => `sha256-${character.repeat(64)}`;

afterEach(() => {
  for (const root of temporaryRoots) {
    fs.rmSync(root, { recursive: true, force: true });
  }
  temporaryRoots.clear();
});

function fixture() {
  const repoRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-conformance-runner-binding-"),
  );
  temporaryRoots.add(repoRoot);
  const executablePath = path.join(repoRoot, "target/debug/deps/ibex-test");
  fs.mkdirSync(path.dirname(executablePath), { recursive: true });
  fs.writeFileSync(executablePath, "checked runner bytes");
  const selection = {
    schema: "ibex/portable-engine-physical-promotion-conformance-runner/1",
    sourceRevision,
    artifactId: semantic("A"),
    cargoMessagesDigest: raw("a"),
    buildConsumptionDigest: semantic("M"),
    postLinkSetDigest: semantic("Q"),
    postLinkCompletionRawDigest: raw("b"),
    executablePath: "target/debug/deps/ibex-test",
    executableDigest: raw("c"),
    executableSize: fs.statSync(executablePath).size,
    verificationDigest: semantic("U"),
  };
  const selectionPath = path.join(repoRoot, "runner-selection.json");
  const writeSelection = (value, bytes = canonicalJson(value)) => {
    fs.writeFileSync(selectionPath, bytes);
  };
  writeSelection(selection);
  return { repoRoot, selection, selectionPath, writeSelection };
}

test("projects one canonical path-bearing selection into the exact locality-free binding", () => {
  const { repoRoot, selection, selectionPath } = fixture();
  const result = readCanonicalConformanceRunnerSelection({
    selectionPath,
    repoRoot,
    sourceRevision,
    sourceTreeDigest,
  });
  assert.equal(
    result.executablePath,
    path.join(fs.realpathSync(repoRoot), selection.executablePath),
  );
  assert.deepEqual(result.binding, {
    sourceRevision,
    sourceTreeDigest,
    artifactId: selection.artifactId,
    buildConsumptionDigest: selection.buildConsumptionDigest,
    postLinkSetDigest: selection.postLinkSetDigest,
    verificationDigest: selection.verificationDigest,
    testExecutableDigest: selection.executableDigest,
  });
  assert.equal(
    result.bindingDigest,
    conformanceRunnerBindingDigest(result.binding),
  );
  assert.equal(
    Object.keys(result.binding).some((key) => /path/iu.test(key)),
    false,
  );
});

test("refuses noncanonical, incomplete, mixed-source, and local-path selections", () => {
  const { repoRoot, selection, selectionPath, writeSelection } = fixture();
  const read = () =>
    readCanonicalConformanceRunnerSelection({
      selectionPath,
      repoRoot,
      sourceRevision,
      sourceTreeDigest,
    });

  writeSelection(selection, `${JSON.stringify(selection, null, 2)}\n`);
  assert.throws(read, /not exact canonical JSON/u);

  const incomplete = structuredClone(selection);
  delete incomplete.verificationDigest;
  writeSelection(incomplete);
  assert.throws(read, /unknown or missing fields/u);

  writeSelection({ ...selection, sourceRevision: "b".repeat(40) });
  assert.throws(read, /names another source/u);

  writeSelection({ ...selection, executablePath: "/tmp/ibex-test" });
  assert.throws(read, /unsafe executable path/u);

  writeSelection({ ...selection, executableDigest: raw("d"), extra: true });
  assert.throws(read, /unknown or missing fields/u);
});

test("refuses a symlink in place of the canonical selection file", () => {
  const { repoRoot, selection, selectionPath } = fixture();
  const target = path.join(repoRoot, "actual-selection.json");
  fs.writeFileSync(target, canonicalJson(selection));
  fs.unlinkSync(selectionPath);
  fs.symlinkSync(target, selectionPath);
  assert.throws(
    () =>
      readCanonicalConformanceRunnerSelection({
        selectionPath,
        repoRoot,
        sourceRevision,
        sourceTreeDigest,
      }),
    /not one bounded/u,
  );
});
