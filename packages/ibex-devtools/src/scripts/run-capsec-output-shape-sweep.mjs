#!/usr/bin/env node

// @ref LLP 0023#6-path-bearing-observables — promotion evidence is produced
// only from a clean committed tree, an exact mapped Hermes image, and the
// bidirectionally complete output-shape executor batch.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJson, parseJsonStrict } from "./capsec-contract.mjs";
import {
  engineLoaderEnvironment,
  validateLoadedEngineIdentity,
} from "./capsec-engine-identity.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  buildOutputShapeSweepArtifactFromExecutorBatch,
  buildOutputShapeSweepPlan,
  buildOutputShapeSweepProbes,
  buildVerifiedOutputDispositionEvidence,
} from "./capsec-output-shape-sweep.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const args = process.argv.slice(2).filter((argument) => argument !== "--");
const options = new Map();
for (let index = 0; index < args.length; index += 2) {
  const name = args[index];
  const value = args[index + 1];
  if (!new Set(["--engine-artifact", "--output-directory"]).has(name)) {
    throw new Error(`unknown output-shape runner option ${JSON.stringify(name)}`);
  }
  if (options.has(name)) {
    throw new Error(`duplicate output-shape runner option ${name}`);
  }
  if (typeof value !== "string" || value.startsWith("--")) {
    throw new Error(`output-shape runner option ${name} requires a value`);
  }
  options.set(name, value);
}

const engineArtifactPath = path.resolve(
  repoRoot,
  options.get("--engine-artifact") ??
    "ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
);
const outputDirectory = path.resolve(
  repoRoot,
  options.get("--output-directory") ?? "target/capsec-output-shape-sweep",
);
if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(`bound runtime engine artifact not found: ${engineArtifactPath}`);
}

const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });
const sourceState = () => ({
  revision: git("rev-parse", "HEAD").toString("utf8").trim(),
  tree: git("rev-parse", "HEAD^{tree}").toString("utf8").trim(),
  dirty: git("status", "--porcelain").toString("utf8").trim(),
});
const initialSource = sourceState();
if (initialSource.dirty) {
  throw new Error(
    "output-shape execution requires a clean committed source tree; dirty trees cannot receive a revision binding",
  );
}
if (fs.existsSync(outputDirectory)) {
  throw new Error(
    `output-shape output directory already exists; choose a fresh path: ${outputDirectory}`,
  );
}
fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });

function readOwnedJson(filePath, label) {
  const before = fs.lstatSync(filePath);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.nlink !== 1 ||
    (typeof process.getuid === "function" && before.uid !== process.getuid())
  ) {
    throw new Error(`${label}: expected an owned regular file`);
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
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())
    ) {
      throw new Error(`${label}: file identity changed while opening`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.lstatSync(filePath);
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino
    ) {
      throw new Error(`${label}: file identity changed while reading`);
    }
    return parseJsonStrict(bytes, label);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeNewJson(filePath, value) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

const rules = readOwnedJson(
  path.join(repoRoot, "capsec/registry/policy-rules.json"),
  "CapSec policy rules",
);
const target = rules.initialProfile?.candidateTargets?.[0];
if (!target) throw new Error("no candidate target is declared");
const engineBinaryDigest = taggedDigest(fs.readFileSync(engineArtifactPath));
const exactEngineEnvironment = {
  ...engineLoaderEnvironment(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_ARTIFACT: fs.realpathSync(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_DIGEST: engineBinaryDigest,
  IBEX_FAIL_ON_STALE_VENDORED: "1",
};
const identityBeforePath = path.join(
  outputDirectory,
  "loaded-engine-identity-before.json",
);
const identityAfterPath = path.join(
  outputDirectory,
  "loaded-engine-identity-after.json",
);
const attestEngine = (identityPath) => {
  execFileSync(
    "cargo",
    [
      "test",
      "--bin",
      "ibex",
      "capsec_loaded_engine_identity_attestation",
      "--",
      "--test-threads=1",
      "--nocapture",
    ],
    {
      cwd: repoRoot,
      env: {
        ...exactEngineEnvironment,
        IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT: identityPath,
      },
      stdio: "inherit",
    },
  );
};

attestEngine(identityBeforePath);
const identityBefore = readOwnedJson(
  identityBeforePath,
  "pre-sweep loaded engine identity",
);
const engine = validateLoadedEngineIdentity({
  identity: identityBefore,
  canonicalArtifactPath: fs.realpathSync(engineArtifactPath),
  binaryDigest: engineBinaryDigest,
  target,
});
const catalog = readOwnedJson(
  path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
  "output-shape catalog",
);
const dispositionDataset = readOwnedJson(
  path.join(repoRoot, "capsec/generated/output-dispositions.json"),
  "output-disposition dataset",
);
const coverage = readOwnedJson(
  path.join(repoRoot, "capsec/registry/coverage-edges.json"),
  "coverage registry",
);
const sourceInventory = await discoverRepositorySurfaces(repoRoot);
const probes = buildOutputShapeSweepProbes({
  catalog,
  coverage,
  surfaces: sourceInventory.surfaces,
  target,
});
const bindings = {
  sourceRevision: initialSource.revision,
  sourceTreeDigest: taggedDigest(Buffer.from(`${initialSource.tree}\n`, "utf8")),
  engine,
};
const plan = buildOutputShapeSweepPlan({
  catalog,
  probes,
  ...bindings,
});
const planPath = path.join(outputDirectory, "output-shape-sweep-plan.json");
const batchPath = path.join(outputDirectory, "output-shape-executor-batch.json");
const reportPath = path.join(outputDirectory, "output-shape-executor-report.json");
const artifactPath = path.join(outputDirectory, "output-shape-sweep-artifact.json");
const evidencePath = path.join(
  outputDirectory,
  "output-disposition-evidence.json",
);
writeNewJson(planPath, plan);

execFileSync(
  "cargo",
  [
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_output_shape_sweep_batch",
    "--",
    "--test-threads=1",
    "--nocapture",
  ],
  {
    cwd: repoRoot,
    env: {
      ...exactEngineEnvironment,
      IBEX_CAPSEC_OUTPUT_SHAPE_PLAN: planPath,
      IBEX_CAPSEC_OUTPUT_SHAPE_BATCH_OUTPUT: batchPath,
    },
    stdio: "inherit",
  },
);
const batch = readOwnedJson(batchPath, "output-shape executor batch");
attestEngine(identityAfterPath);
const identityAfter = readOwnedJson(
  identityAfterPath,
  "post-sweep loaded engine identity",
);
if (canonicalJson(identityAfter) !== canonicalJson(identityBefore)) {
  throw new Error("loaded engine identity changed across output-shape execution");
}
const finalSource = sourceState();
if (
  finalSource.dirty ||
  finalSource.revision !== initialSource.revision ||
  finalSource.tree !== initialSource.tree
) {
  throw new Error(
    "output-shape execution changed the committed source revision or working tree",
  );
}

const proofCounts = Object.fromEntries(
  [
    "compiled-registrar",
    "compiled-runtime-return-record",
    "loaded-engine-descriptor",
    "loaded-engine-return-record",
  ].map((kind) => [
    kind,
    plan.rows.filter((row) => row.probe.kind === kind).length,
  ]),
);
let artifact;
try {
  artifact = buildOutputShapeSweepArtifactFromExecutorBatch({ plan, batch });
} catch (error) {
  writeNewJson(reportPath, {
    outputShapeExecutorReportSchema:
      "ibex/capsec-output-shape-executor-report/1",
    status: "unpromotable",
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    engineBinaryDigest: bindings.engine.binaryDigest,
    sweepPlanDigest: plan.sweepPlanDigest,
    proofCounts,
    unexercisableRows: batch.unexercisable ?? [],
    reason: error instanceof Error ? error.message : String(error),
  });
  throw new Error(
    `output-shape sweep is unpromotable; inspect ${reportPath}: ${error instanceof Error ? error.message : error}`,
  );
}
const evidence = buildVerifiedOutputDispositionEvidence({
  catalog,
  dispositionRows: dispositionDataset.rows,
  plan,
  artifact,
  ...bindings,
});
writeNewJson(artifactPath, artifact);
writeNewJson(evidencePath, evidence);
writeNewJson(reportPath, {
  outputShapeExecutorReportSchema:
    "ibex/capsec-output-shape-executor-report/1",
  status: "verified",
  sourceRevision: bindings.sourceRevision,
  sourceTreeDigest: bindings.sourceTreeDigest,
  engineBinaryDigest: bindings.engine.binaryDigest,
  sweepPlanDigest: plan.sweepPlanDigest,
  sweepArtifactDigest: artifact.sweepArtifactDigest,
  proofCounts,
  evidencePath,
});
process.stdout.write(
  `${JSON.stringify({
    status: "verified",
    artifactPath,
    evidencePath,
    reportPath,
    proofCounts,
  })}\n`,
);
