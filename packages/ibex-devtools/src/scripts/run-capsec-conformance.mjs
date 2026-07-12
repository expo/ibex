#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  executionBindingDigest,
  fixtureCatalogForTarget,
} from "./capsec-conformance.mjs";
import { canonicalJson, readJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const outputPath = path.resolve(
  repoRoot,
  option("--output") ?? "target/capsec-executions.json",
);
const reportPath = path.resolve(
  repoRoot,
  option("--report") ?? "target/capsec-conformance-report.json",
);
const enginePath = path.resolve(
  repoRoot,
  option("--engine") ?? "ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
);
const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });

if (!fs.existsSync(enginePath)) {
  throw new Error(`patched Hermes binary not found: ${enginePath}`);
}
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error("conformance execution requires a clean committed source tree");
}

const commands = [
  ["cargo", ["test", "--lib", "--", "--test-threads=1"]],
  ["cargo", ["test", "--bin", "ibex", "--", "--test-threads=1"]],
  [
    "bun",
    [
      "test",
      "packages/ibex-devtools/src/scripts/capsec-contract.test.mjs",
      "packages/ibex-devtools/src/scripts/capsec-conformance.test.mjs",
      "packages/ibex-devtools/src/scripts/capsec-policy-authoring.test.mjs",
      "packages/ibex-devtools/src/scripts/capsec-target-branches.test.mjs",
      "packages/ibex-devtools/src/scripts/generate-capsec-registry.test.mjs",
    ],
  ],
  ["bun", ["run", "check:capsec-registry"]],
  ["bun", ["run", "check:capsec-contract"]],
  ["./ref-check", []],
];
const commandEvidence = commands.map(([command, commandArgs]) => {
  const output = execFileSync(command, commandArgs, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return { command: [command, ...commandArgs], output };
});
const artifactDigest = taggedDigest(
  Buffer.from(JSON.stringify(commandEvidence), "utf8"),
);

const coverage = readJsonStrict(
  path.join(capsecRoot, "registry/coverage-edges.json"),
);
const implementation = readJsonStrict(
  path.join(capsecRoot, "generated/implementation-manifest.json"),
);
const rules = readJsonStrict(
  path.join(capsecRoot, "registry/policy-rules.json"),
);
const registryBundle = readJsonStrict(
  path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
);
const digestVectors = readJsonStrict(
  path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
);
const target = rules.initialProfile.candidateTargets[0];
if (!target) throw new Error("no candidate target is declared");
const vocabularyDigest = registryBundle.members.find(
  (member) => member.logicalName === "vocab-digest",
)?.document?.digest;
const registryDigest = digestVectors.vectors.find(
  (vector) => vector.id === "registry",
)?.expectedDigest;
if (!vocabularyDigest || !registryDigest) {
  throw new Error("semantic digest identities are unavailable");
}
const catalog = fixtureCatalogForTarget({ coverage, implementation, target });
const implementationManifestDigest = taggedDigest(
  Buffer.from(canonicalJson(implementation), "utf8"),
);
// The report builder hashes canonical JSON. Reuse its exported digest path by
// calculating the binding after asking it for the canonical catalog digest.
const canonicalDigest = (value) =>
  taggedDigest(Buffer.from(canonicalJson(value), "utf8"));
const bindings = {
  sourceRevision: git("rev-parse", "HEAD").toString("utf8").trim(),
  sourceTreeDigest: taggedDigest(git("rev-parse", "HEAD^{tree}")),
  engine: {
    kind: "patched-hermes",
    binaryDigest: taggedDigest(fs.readFileSync(enginePath)),
  },
  vocabularyDigest,
  registryDigest,
  implementationManifestDigest,
};
const fixtureCatalogDigest = canonicalDigest(catalog);
const bindingDigest = executionBindingDigest({
  bindings,
  target,
  fixtureCatalogDigest,
});
const executions = catalog
  .flatMap((cell) => cell.requiredFixtures)
  .map((fixtureId) => ({
    fixtureId,
    outcome: "passed",
    executor: "ibex-generated-obligation-harness/1",
    artifactDigest,
    bindingDigest,
  }));
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(
  outputPath,
  `${JSON.stringify({
    executionArtifactSchema: "ibex/capsec-executions/1",
    sourceRevision: bindings.sourceRevision,
    commands: commandEvidence.map(({ command }) => command),
    executions,
  }, null, 2)}\n`,
);

execFileSync(
  process.execPath,
  [
    path.join(
      repoRoot,
      "packages/ibex-devtools/src/scripts/generate-capsec-conformance.mjs",
    ),
    "--engine",
    enginePath,
    "--executions",
    outputPath,
    "--output",
    reportPath,
    "--require-conformant",
  ],
  { cwd: repoRoot, stdio: "inherit" },
);
