#!/usr/bin/env node

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — target
// promotion binds public execution to one clean source tree and exact engine.

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
import {
  assertPublicSurfaceExecutionComplete,
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import { CONFORMANCE_COMMANDS } from "./capsec-conformance-matrix.mjs";
import { runObservedCommand } from "./capsec-command-evidence.mjs";
import {
  canonicalJson,
  parseJsonStrict,
  readJsonStrict,
} from "./capsec-contract.mjs";
import {
  engineLoaderEnvironment,
  validateLoadedEngineIdentity,
} from "./capsec-engine-identity.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2).filter((argument) => argument !== "--");
const valueOptions = new Set([
  "--engine-artifact",
  "--fixture-evidence",
  "--public-surface-evidence",
  "--output",
  "--report",
]);
const booleanOptions = new Set(["--expect-incomplete"]);
const parsedOptions = new Map();
const parsedFlags = new Set();
for (let index = 0; index < args.length;) {
  const name = args[index];
  if (booleanOptions.has(name)) {
    if (parsedFlags.has(name)) {
      throw new Error(`duplicate conformance runner option ${name}`);
    }
    parsedFlags.add(name);
    index += 1;
    continue;
  }
  const value = args[index + 1];
  if (!valueOptions.has(name)) {
    throw new Error(`unknown conformance runner option ${JSON.stringify(name)}`);
  }
  if (parsedOptions.has(name)) {
    throw new Error(`duplicate conformance runner option ${name}`);
  }
  if (typeof value !== "string" || value.startsWith("--")) {
    throw new Error(`conformance runner option ${name} requires a value`);
  }
  parsedOptions.set(name, value);
  index += 2;
}
const option = (name) => parsedOptions.get(name);
const expectIncomplete = parsedFlags.has("--expect-incomplete");
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
const publicSurfaceEvidenceInputPath = option("--public-surface-evidence");
const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });
const ownedByCurrentUser = (metadata) =>
  typeof process.getuid !== "function" || metadata.uid === process.getuid();

function readOwnedJson(filePath, label) {
  const pathMetadata = fs.lstatSync(filePath);
  if (
    pathMetadata.isSymbolicLink() ||
    !pathMetadata.isFile() ||
    pathMetadata.nlink !== 1 ||
    !ownedByCurrentUser(pathMetadata)
  ) {
    throw new Error(`${label}: evidence must be an owned regular file`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      !ownedByCurrentUser(opened) ||
      opened.dev !== pathMetadata.dev ||
      opened.ino !== pathMetadata.ino
    ) {
      throw new Error(`${label}: evidence identity changed while opening`);
    }
    const bytes = fs.readFileSync(descriptor);
    const current = fs.lstatSync(filePath);
    if (
      current.isSymbolicLink() ||
      !current.isFile() ||
      current.nlink !== 1 ||
      !ownedByCurrentUser(current) ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino
    ) {
      throw new Error(`${label}: evidence identity changed while reading`);
    }
    return parseJsonStrict(bytes, label);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(`bound runtime engine artifact not found: ${engineArtifactPath}`);
}
const initialSourceRevision = git("rev-parse", "HEAD").toString("utf8").trim();
const initialSourceTree = git("rev-parse", "HEAD^{tree}")
  .toString("utf8")
  .trim();
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error("conformance execution requires a clean committed source tree");
}
const rules = readJsonStrict(
  path.join(capsecRoot, "registry/policy-rules.json"),
);
const target = rules.initialProfile.candidateTargets[0];
if (!target) throw new Error("no candidate target is declared");

const evidenceRoot = path.join(repoRoot, "target");
if (!fs.existsSync(evidenceRoot)) fs.mkdirSync(evidenceRoot, { mode: 0o700 });
const evidenceRootMetadata = fs.lstatSync(evidenceRoot);
if (
  evidenceRootMetadata.isSymbolicLink() ||
  !evidenceRootMetadata.isDirectory()
) {
  throw new Error("conformance evidence root must be a real directory");
}
const realEvidenceRoot = fs.realpathSync(evidenceRoot);
const evidenceRootRelative = path.relative(repoRoot, realEvidenceRoot);
if (
  evidenceRootRelative.startsWith(`..${path.sep}`) ||
  evidenceRootRelative === ".." ||
  path.isAbsolute(evidenceRootRelative)
) {
  throw new Error("conformance evidence root escapes the checkout");
}
const evidenceDirectory = fs.mkdtempSync(
  path.join(realEvidenceRoot, "capsec-suite-evidence-"),
);
fs.chmodSync(evidenceDirectory, 0o700);
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
const loadedEngineIdentity = readOwnedJson(
  engineIdentityPath,
  "loaded engine identity",
);
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
const publicSurfaceEvidencePath = path.join(
  evidenceDirectory,
  "public-surface-executions.json",
);
const publicBatchEvidenceDirectory = path.join(
  evidenceDirectory,
  "public-fixture-batches",
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
const recipeCatalog = readOwnedJson(
  recipeCatalogPath,
  "executable recipe catalog",
);
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
const adapterEvidence = readOwnedJson(
  adapterEvidencePath,
  "typed adapter evidence",
);
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
fs.mkdirSync(publicBatchEvidenceDirectory, { mode: 0o700 });
const publicRecipeCommands = new Map();
for (const recipe of recipeCatalog.recipes) {
  if (recipe.status !== "fully-executable") continue;
  const command = recipe.publicSurfaceProbe?.command;
  if (!Array.isArray(command) || command.length === 0) {
    throw new Error(`${recipe.fixtureId}: fully executable recipe has no command`);
  }
  const key = canonicalJson(command);
  const entry = publicRecipeCommands.get(key) ?? { command, fixtureIds: [] };
  entry.fixtureIds.push(recipe.fixtureId);
  publicRecipeCommands.set(key, entry);
}
const publicBatches = [];
let publicBatchIndex = 0;
for (const { command, fixtureIds } of publicRecipeCommands.values()) {
  const batchId = `public-fixtures-${String(publicBatchIndex).padStart(3, "0")}-${taggedDigest(
    Buffer.from(canonicalJson(command), "utf8"),
  ).slice(7, 19)}`;
  publicBatchIndex += 1;
  const batchOutputPath = path.join(
    publicBatchEvidenceDirectory,
    `${batchId}.json`,
  );
  commandEvidence.push(
    runObservedCommand({
      id: batchId,
      command: command[0],
      args: command.slice(1),
      cwd: repoRoot,
      evidenceDirectory,
      env: {
        ...exactEngineEnvironment,
        IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
        IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT: batchOutputPath,
      },
    }),
  );
  const batch = readOwnedJson(batchOutputPath, `${batchId} evidence`);
  publicBatches.push({ batch, expectedFixtureIds: fixtureIds });
}
const publicExecutions = mergePublicBatchExecutions({
  batches: publicBatches,
  recipeCatalog,
  loadedEngineIdentity,
});
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
const loadedEngineIdentityAfter = readOwnedJson(
  engineIdentityAfterPath,
  "post-suite loaded engine identity",
);
if (canonicalJson(loadedEngineIdentityAfter) !== canonicalJson(loadedEngineIdentity)) {
  throw new Error("loaded engine identity changed across conformance execution");
}
const finalSourceRevision = git("rev-parse", "HEAD").toString("utf8").trim();
const finalSourceTree = git("rev-parse", "HEAD^{tree}").toString("utf8").trim();
if (
  git("status", "--porcelain").toString("utf8").trim() ||
  finalSourceRevision !== initialSourceRevision ||
  finalSourceTree !== initialSourceTree
) {
  throw new Error(
    "conformance suites changed the committed source revision or working tree",
  );
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
  sourceRevision: initialSourceRevision,
  sourceTreeDigest: taggedDigest(Buffer.from(`${initialSourceTree}\n`, "utf8")),
  engine: engineBinding,
  vocabularyDigest,
  registryDigest,
  implementationManifestDigest,
};
const publicSurfaceEvidence = buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision: bindings.sourceRevision,
  sourceTreeDigest: bindings.sourceTreeDigest,
  target,
  engine: bindings.engine,
  coverage,
  executions: publicExecutions,
});
if (publicSurfaceEvidenceInputPath) {
  const suppliedEvidence = readJsonStrict(
    path.resolve(repoRoot, publicSurfaceEvidenceInputPath),
  );
  validatePublicSurfaceExecutionArtifact(suppliedEvidence, {
    recipeCatalog,
    target,
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    engine: bindings.engine,
    coverage,
  });
  if (canonicalJson(suppliedEvidence) !== canonicalJson(publicSurfaceEvidence)) {
    throw new Error(
      "supplied public evidence differs from the evidence executed by this runner",
    );
  }
}
fs.writeFileSync(
  publicSurfaceEvidencePath,
  `${JSON.stringify(publicSurfaceEvidence, null, 2)}\n`,
);
bindings.recipeCatalogDigest = recipeCatalog.recipeCatalogDigest;
bindings.publicSurfaceExecutionDigest =
  publicSurfaceEvidence.publicSurfaceExecutionDigest;
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
    fixtureArtifact.recipeCatalogDigest !== bindings.recipeCatalogDigest ||
    fixtureArtifact.publicSurfaceExecutionDigest !==
      bindings.publicSurfaceExecutionDigest ||
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
    publicSurfaceExecutionDigest:
      publicSurfaceEvidence.publicSurfaceExecutionDigest,
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
    "--recipe-catalog",
    recipeCatalogPath,
    "--public-surface-executions",
    publicSurfaceEvidencePath,
    "--output",
    reportPath,
  ],
  { cwd: repoRoot, stdio: "inherit" },
);
const report = readJsonStrict(reportPath);
// Adapter-only evidence is diagnostic and can never become a fixture pass.
// Fail with the exact residual inventory before considering target promotion.
const promotionRefusals = [];
const checkPromotion = (name, check) => {
  try {
    check();
  } catch (error) {
    promotionRefusals.push({
      check: name,
      message: error instanceof Error ? error.message : String(error),
    });
  }
};
checkPromotion("executable-recipe-catalog", () => {
  assertRecipeCatalogComplete(recipeCatalog);
});
checkPromotion("public-surface-execution", () => {
  assertPublicSurfaceExecutionComplete(publicSurfaceEvidence, recipeCatalog, {
    target,
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    engine: bindings.engine,
    expectedFixtureIds: catalog.flatMap((cell) => cell.requiredFixtures),
  });
});
checkPromotion("conformance-report", () => {
  assertReportMayAdvertise(report);
});

if (!expectIncomplete) {
  if (promotionRefusals.length > 0) {
    throw new Error(
      `CapSec target promotion refused: ${promotionRefusals
        .map(({ check, message }) => `${check}: ${message}`)
        .join("; ")}`,
    );
  }
} else {
  if (promotionRefusals.length === 0 || report.status !== "incomplete") {
    throw new Error(
      "--expect-incomplete requires an incomplete report that refuses target promotion",
    );
  }
  const attestations = readJsonStrict(
    path.join(capsecRoot, "conformance/target-attestations.json"),
  );
  const targetKey = canonicalJson(target);
  if (
    attestations.attestations.some(
      (attestation) => canonicalJson(attestation.target) === targetKey,
    )
  ) {
    throw new Error(
      "the expected-incomplete target is already advertised by a committed attestation",
    );
  }
  const ciStatusPath = path.join(realEvidenceRoot, "capsec-ci-status.json");
  fs.writeFileSync(
    ciStatusPath,
    `${JSON.stringify({
      statusSchema: "ibex/capsec-ci-evidence-status/1",
      expectation: "incomplete-and-unadvertised",
      sourceRevision: bindings.sourceRevision,
      sourceTreeDigest: bindings.sourceTreeDigest,
      target,
      engine: bindings.engine,
      reportStatus: report.status,
      reportPath: path.relative(repoRoot, reportPath),
      executionArtifactPath: path.relative(repoRoot, outputPath),
      promotionRefusals,
    }, null, 2)}\n`,
  );
  console.log(
    `CapSec evidence complete; target remains intentionally unadvertised (${promotionRefusals
      .map(({ check }) => check)
      .join(", ")})`,
  );
}
