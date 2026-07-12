#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertReportMayAdvertise,
  executionBindingDigest,
  fixtureCatalogForTarget,
} from "./capsec-conformance.mjs";
import { assertRecipeCatalogComplete } from "./capsec-conformance-recipes.mjs";
import { CONFORMANCE_COMMANDS } from "./capsec-conformance-matrix.mjs";
import { runObservedCommand } from "./capsec-command-evidence.mjs";
import { canonicalJson, readJsonStrict } from "./capsec-contract.mjs";
import {
  engineLoaderEnvironment,
  validateLoadedEngineIdentity,
} from "./capsec-engine-identity.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2);
const knownOptions = new Set([
  "--engine-artifact",
  "--fixture-evidence",
  "--output",
  "--report",
]);
const parsedOptions = new Map();
for (let index = 0; index < args.length; index += 2) {
  const name = args[index];
  const value = args[index + 1];
  if (!knownOptions.has(name)) {
    throw new Error(`unknown conformance runner option ${JSON.stringify(name)}`);
  }
  if (parsedOptions.has(name)) {
    throw new Error(`duplicate conformance runner option ${name}`);
  }
  if (typeof value !== "string" || value.startsWith("--")) {
    throw new Error(`conformance runner option ${name} requires a value`);
  }
  parsedOptions.set(name, value);
}
const option = (name) => parsedOptions.get(name);
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
    "ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
);
const fixtureEvidencePath = option("--fixture-evidence");
const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });

if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(`bound runtime engine artifact not found: ${engineArtifactPath}`);
}
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error("conformance execution requires a clean committed source tree");
}
const rules = readJsonStrict(
  path.join(capsecRoot, "registry/policy-rules.json"),
);
const target = rules.initialProfile.candidateTargets[0];
if (!target) throw new Error("no candidate target is declared");

const evidenceDirectory = path.join(path.dirname(outputPath), "capsec-suite-evidence");
fs.mkdirSync(evidenceDirectory, { recursive: true });
const engineBinaryDigest = taggedDigest(fs.readFileSync(engineArtifactPath));
const engineIdentityPath = path.join(
  evidenceDirectory,
  "loaded-engine-identity.json",
);
const engineIdentityAfterPath = path.join(
  evidenceDirectory,
  "loaded-engine-identity-after-suites.json",
);
const exactEngineEnvironment = {
  ...engineLoaderEnvironment(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_ARTIFACT: fs.realpathSync(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_DIGEST: engineBinaryDigest,
  IBEX_FAIL_ON_STALE_VENDORED: "1",
};
const runEngineAttestation = (id, identityPath) => {
  fs.rmSync(identityPath, { force: true });
  return runObservedCommand({
    id,
    command: "cargo",
    args: [
      "test",
      "--bin",
      "ibex",
      "capsec_loaded_engine_identity_attestation",
      "--",
      "--test-threads=1",
      "--nocapture",
    ],
    cwd: repoRoot,
    evidenceDirectory,
    env: {
      ...exactEngineEnvironment,
      IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT: identityPath,
    },
  });
};
const commandEvidence = [
  runEngineAttestation("exact-loaded-engine-attestation", engineIdentityPath),
];
const loadedEngineIdentity = readJsonStrict(engineIdentityPath);
const engineBinding = validateLoadedEngineIdentity({
  identity: loadedEngineIdentity,
  canonicalArtifactPath: fs.realpathSync(engineArtifactPath),
  binaryDigest: engineBinaryDigest,
  target,
});
const recipeCatalogPath = path.join(
  evidenceDirectory,
  "executable-recipes.json",
);
const adapterEvidencePath = path.join(
  evidenceDirectory,
  "typed-adapter-evidence.json",
);
execFileSync(
  process.execPath,
  [
    path.join(
      repoRoot,
      "packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs",
    ),
    "--output",
    recipeCatalogPath,
  ],
  { cwd: repoRoot, stdio: "inherit" },
);
const recipeCatalog = readJsonStrict(recipeCatalogPath);
commandEvidence.push(
  runObservedCommand({
    id: "exact-hermes-typed-adapter-recipes",
    command: "cargo",
    args: [
      "test",
      "--bin",
      "ibex",
      "--features",
      "capsec-conformance-observer",
      "capsec_executable_recipe_adapter_batch",
      "--",
      "--test-threads=1",
      "--nocapture",
    ],
    cwd: repoRoot,
    evidenceDirectory,
    env: {
      ...exactEngineEnvironment,
      IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
      IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT: adapterEvidencePath,
    },
  }),
);
const adapterEvidence = readJsonStrict(adapterEvidencePath);
if (
  adapterEvidence.adapterEvidenceSchema !==
    "ibex/capsec-adapter-probe-evidence/1" ||
  adapterEvidence.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
  canonicalJson(adapterEvidence.loadedEngineIdentity) !==
    canonicalJson(loadedEngineIdentity) ||
  adapterEvidence.summary?.adapterExecutableFixtures !==
    recipeCatalog.summary?.adapterExecutableFixtures ||
  adapterEvidence.summary?.executedCases !==
    adapterEvidence.summary?.passedCases ||
  adapterEvidence.fixtures?.length !==
    recipeCatalog.summary?.adapterExecutableFixtures
) {
  throw new Error(
    "typed adapter evidence is stale, incomplete, or from another loaded engine",
  );
}
commandEvidence.push(...CONFORMANCE_COMMANDS.map(([id, command, commandArgs]) =>
  runObservedCommand({
    id,
    command,
    args: commandArgs,
    cwd: repoRoot,
    evidenceDirectory,
    env: exactEngineEnvironment,
  })));
commandEvidence.push(
  runEngineAttestation(
    "exact-loaded-engine-attestation-after-suites",
    engineIdentityAfterPath,
  ),
);
const loadedEngineIdentityAfter = readJsonStrict(engineIdentityAfterPath);
if (canonicalJson(loadedEngineIdentityAfter) !== canonicalJson(loadedEngineIdentity)) {
  throw new Error("loaded engine identity changed across conformance execution");
}

const coverage = readJsonStrict(
  path.join(capsecRoot, "registry/coverage-edges.json"),
);
const implementation = readJsonStrict(
  path.join(capsecRoot, "generated/implementation-manifest.json"),
);
const registryBundle = readJsonStrict(
  path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
);
const digestVectors = readJsonStrict(
  path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
);
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
  engine: engineBinding,
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
    fixtureArtifact.sourceTreeDigest !== bindings.sourceTreeDigest ||
    canonicalJson(fixtureArtifact.engine) !== canonicalJson(bindings.engine) ||
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
const adapterEvidenceDigest = taggedDigest(fs.readFileSync(adapterEvidencePath));
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(
  outputPath,
  `${JSON.stringify({
    executionArtifactSchema: "ibex/capsec-executions/1",
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    target,
    engine: bindings.engine,
    loadedEngineIdentity,
    bindingDigest,
    suiteArtifactDigest,
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    adapterEvidenceDigest,
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
  ],
  { cwd: repoRoot, stdio: "inherit" },
);
const report = readJsonStrict(reportPath);
// Adapter-only evidence is diagnostic and can never become a fixture pass.
// Fail with the exact residual inventory before considering target promotion.
assertRecipeCatalogComplete(recipeCatalog);
assertReportMayAdvertise(report);
