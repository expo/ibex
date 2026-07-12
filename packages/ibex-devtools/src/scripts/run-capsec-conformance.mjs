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
import { CONFORMANCE_COMMANDS } from "./capsec-conformance-matrix.mjs";
import { runObservedCommand } from "./capsec-command-evidence.mjs";
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
const engineArtifactPath = path.resolve(
  repoRoot,
  option("--engine-artifact") ??
    option("--engine") ??
    "ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
);
const probeEnginePath = path.resolve(
  repoRoot,
  option("--probe-engine") ?? "tools/hermes/hermes",
);
const fixtureEvidencePath = option("--fixture-evidence");
const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });

if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(`bound runtime engine artifact not found: ${engineArtifactPath}`);
}
if (!fs.existsSync(probeEnginePath)) {
  throw new Error(`probe executable not found: ${probeEnginePath}`);
}
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error("conformance execution requires a clean committed source tree");
}

const evidenceDirectory = path.join(path.dirname(outputPath), "capsec-suite-evidence");
const commandEvidence = CONFORMANCE_COMMANDS.map(([id, command, commandArgs]) =>
  runObservedCommand({
    id,
    command,
    args: commandArgs,
    cwd: repoRoot,
    evidenceDirectory,
    env: { ...process.env, IBEX_FAIL_ON_STALE_VENDORED: "1" },
  }));

const probePath = path.join(path.dirname(outputPath), "capsec-bound-engine-probe.js");
fs.mkdirSync(path.dirname(probePath), { recursive: true });
const probeMarker = "IBEX_CAPSEC_BOUND_ENGINE_OK";
fs.writeFileSync(probePath, `print(${JSON.stringify(probeMarker)});\n`);
const engineProbe = runObservedCommand({
  id: "probe-engine-execution",
  command: probeEnginePath,
  args: [probePath],
  cwd: repoRoot,
  evidenceDirectory,
});
if (!engineProbe.stdout.tail.split(/\r?\n/u).includes(probeMarker)) {
  throw new Error("probe executable did not execute the structural probe artifact");
}
commandEvidence.push(engineProbe);

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
    binaryDigest: taggedDigest(fs.readFileSync(engineArtifactPath)),
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
let executions = [];
if (fixtureEvidencePath) {
  const fixtureArtifact = readJsonStrict(path.resolve(repoRoot, fixtureEvidencePath));
  if (
    fixtureArtifact.executionArtifactSchema !== "ibex/capsec-executions/1" ||
    fixtureArtifact.sourceRevision !== bindings.sourceRevision ||
    !Array.isArray(fixtureArtifact.executions)
  ) {
    throw new Error("fixture evidence artifact is stale, malformed, or from another revision");
  }
  executions = fixtureArtifact.executions;
}
// A broad suite pass is prerequisite evidence, never a per-obligation pass.
// Only fixture-specific commands carrying their own result marker may enter
// `executions`; buildConformanceReport independently validates those records.
const suiteArtifactDigest = taggedDigest(
  Buffer.from(canonicalJson(commandEvidence), "utf8"),
);
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(
  outputPath,
  `${JSON.stringify({
    executionArtifactSchema: "ibex/capsec-executions/1",
    sourceRevision: bindings.sourceRevision,
    target,
    engine: bindings.engine,
    probeEngine: {
      kind: "prerequisite-probe-only",
      binaryDigest: taggedDigest(fs.readFileSync(probeEnginePath)),
    },
    bindingDigest,
    suiteArtifactDigest,
    commands: commandEvidence,
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
    engineArtifactPath,
    "--executions",
    outputPath,
    "--output",
    reportPath,
    "--require-conformant",
  ],
  { cwd: repoRoot, stdio: "inherit" },
);
