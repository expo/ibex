#!/usr/bin/env node

// @ref LLP 0023#6-path-bearing-observables — promotion evidence is produced
// only from a clean committed tree, an exact mapped Hermes image, and the
// bidirectionally complete output-shape executor batch.
// Host-ABI rows are first partitioned to their dedicated native executor and
// target-absence author. Until every residual is closed and those artifacts
// are composed, this command writes an unpromotable report and stops.

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
import { selectCandidateTarget } from "./capsec-conformance.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { authoredTargetAbsenceOutputBindings } from "./capsec-target-absence-output-templates.mjs";
import { validateCurrentSourceRecipeCatalog } from "./capsec-conformance-recipes.mjs";
import {
  buildOutputShapeSweepExecutionPartition,
  buildOutputShapeSweepPlan,
  buildTargetAbsenceOutputShapeProbes,
  buildVerifiedOutputDispositionEvidence,
  composeOutputShapeSweepArtifactFromDelegatedBatches,
  validateCurrentSourceOutputDispositionArtifacts,
} from "./capsec-output-shape-sweep.mjs";
import { ENVIRONMENT_OUTPUT_SWEEP_NAMES } from "./capsec-environment-output-templates.mjs";
import {
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
} from "./capsec-public-surface-evidence.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const args = process.argv.slice(2).filter((argument) => argument !== "--");
const options = new Map();
for (let index = 0; index < args.length; index += 2) {
  const name = args[index];
  const value = args[index + 1];
  if (
    !new Set([
      "--engine-artifact",
      "--output-directory",
      "--recipe-catalog",
      "--target",
    ]).has(name)
  ) {
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
const recipeCatalogOption = options.get("--recipe-catalog");
if (!recipeCatalogOption) {
  throw new Error(
    "output-shape execution requires --recipe-catalog so platform-only Host ABI rows can be bound to exact target-absence recipes",
  );
}
const recipeCatalogPath = path.resolve(repoRoot, recipeCatalogOption);
if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(`bound runtime engine artifact not found: ${engineArtifactPath}`);
}
if (!fs.existsSync(recipeCatalogPath)) {
  throw new Error(`executable recipe catalog not found: ${recipeCatalogPath}`);
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

const planPath = path.join(outputDirectory, "output-shape-sweep-plan.json");
const genericPlanPath = path.join(
  outputDirectory,
  "output-shape-generic-sweep-plan.json",
);
const batchPath = path.join(outputDirectory, "output-shape-executor-batch.json");
const composedBatchPath = path.join(
  outputDirectory,
  "output-shape-composed-executor-batch.json",
);
const reportPath = path.join(
  outputDirectory,
  "output-shape-executor-report.json",
);
const artifactPath = path.join(
  outputDirectory,
  "output-shape-sweep-artifact.json",
);
const evidencePath = path.join(
  outputDirectory,
  "output-disposition-evidence.json",
);
const partitionPath = path.join(
  outputDirectory,
  "output-shape-execution-partition.json",
);
const hostAbiPlanPath = path.join(
  outputDirectory,
  "host-abi-output-plan.json",
);
const hostAbiBatchPath = path.join(
  outputDirectory,
  "host-abi-output-executor-batch.json",
);
const targetAbsenceBatchPath = path.join(
  outputDirectory,
  "target-absence-public-batch.json",
);
const targetAbsenceExecutionPath = path.join(
  outputDirectory,
  "target-absence-public-executions.json",
);

const rules = readOwnedJson(
  path.join(repoRoot, "capsec/registry/policy-rules.json"),
  "CapSec policy rules",
);
const target = selectCandidateTarget(rules, options.get("--target"));
const engineBinaryDigest = taggedDigest(fs.readFileSync(engineArtifactPath));
const completeCatalog = readOwnedJson(
  path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
  "output-shape catalog",
);
const dispositionDataset = readOwnedJson(
  path.join(repoRoot, "capsec/generated/output-dispositions.json"),
  "output-disposition dataset",
);
const dispositionPolicy = readOwnedJson(
  path.join(repoRoot, "capsec/registry/output-disposition-policy.json"),
  "reviewed output-disposition policy",
);
const trackedDispositionEvidence = readOwnedJson(
  path.join(repoRoot, "capsec/registry/output-disposition-evidence.json"),
  "tracked output-disposition evidence sentinel",
);
const coverage = readOwnedJson(
  path.join(repoRoot, "capsec/registry/coverage-edges.json"),
  "coverage registry",
);
const recipeCatalog = readOwnedJson(
  recipeCatalogPath,
  "executable recipe catalog",
);
const sourceInventory = await discoverRepositorySurfaces(repoRoot);
validateCurrentSourceOutputDispositionArtifacts({
  catalog: completeCatalog,
  dispositionDataset,
  coverage,
  surfaces: sourceInventory.surfaces,
  repoRoot,
  policy: dispositionPolicy,
  trackedEvidence: trackedDispositionEvidence,
});
validateCurrentSourceRecipeCatalog(recipeCatalog, {
  coverage,
  implementation: readOwnedJson(
    path.join(repoRoot, "capsec/generated/implementation-manifest.json"),
    "implementation manifest",
  ),
  inventory: sourceInventory,
  occurrenceExamples: readOwnedJson(
    path.join(
      repoRoot,
      "capsec/examples/effect-occurrences.canonical.json",
    ),
    "effect occurrence examples",
  ),
  selectorExamples: readOwnedJson(
    path.join(
      repoRoot,
      "capsec/examples/authority-selectors.canonical.json",
    ),
    "authority selector examples",
  ),
  capabilityDefinitions: readOwnedJson(
    path.join(repoRoot, "capsec/registry/capability-definitions.json"),
    "capability definitions",
  ),
  target,
});
const targetAbsenceBindings = authoredTargetAbsenceOutputBindings({
  catalog: completeCatalog,
  recipeCatalog,
  coverage,
  target,
}).filter((binding) => binding.key.sourceKind === "host-abi");
const executionPartition = buildOutputShapeSweepExecutionPartition({
  catalog: completeCatalog,
  coverage,
  surfaces: sourceInventory.surfaces,
  target,
  targetAbsenceBindings,
});
const hostAbiResidualReasons = Object.fromEntries(
  [...Map.groupBy(executionPartition.hostAbi.residuals, (row) => row.reason)]
    .map(([reason, rows]) => [reason, rows.length])
    .sort(([left], [right]) => left.localeCompare(right, "en-US")),
);
const partitionSummary = {
  outputShapeExecutionPartitionSchema:
    executionPartition.outputShapeExecutionPartitionSchema,
  completeCatalogKeyDigest: executionPartition.completeCatalogKeyDigest,
  completeCatalogRows: completeCatalog.rows.length,
  genericLoadedJsRows: executionPartition.genericCatalog.rows.length,
  hostAbi: {
    executableRows: executionPartition.hostAbi.rows.length,
    targetAbsenceRows:
      executionPartition.hostAbi.targetAbsenceBindings.length,
    residualRows: executionPartition.hostAbi.residuals.length,
    residualReasons: hostAbiResidualReasons,
  },
};
writeNewJson(partitionPath, partitionSummary);
if (executionPartition.hostAbi.residuals.length > 0) {
  const reason = `complete output evidence is blocked by ${executionPartition.hostAbi.residuals.length} honest Host ABI residual rows`;
  writeNewJson(reportPath, {
    outputShapeExecutorReportSchema:
      "ibex/capsec-output-shape-executor-report/1",
    status: "unpromotable",
    sourceRevision: initialSource.revision,
    sourceTreeDigest: taggedDigest(
      Buffer.from(`${initialSource.tree}\n`, "utf8"),
    ),
    engineBinaryDigest,
    partition: partitionSummary,
    reason,
  });
  throw new Error(
    `output-shape sweep is unpromotable; inspect ${reportPath}: ${reason}`,
  );
}

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
      "--features",
      "capsec-conformance-observer",
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
const bindings = {
  sourceRevision: initialSource.revision,
  sourceTreeDigest: taggedDigest(Buffer.from(`${initialSource.tree}\n`, "utf8")),
  target,
  engine,
};
const genericCatalog = executionPartition.genericCatalog;
const genericPlan = buildOutputShapeSweepPlan({
  catalog: genericCatalog,
  probes: executionPartition.genericProbes,
  ...bindings,
});
const targetAbsenceProbes = buildTargetAbsenceOutputShapeProbes({
  targetAbsenceBindings: executionPartition.hostAbi.targetAbsenceBindings,
  recipeCatalog,
  target,
});
const plan = buildOutputShapeSweepPlan({
  catalog: completeCatalog,
  probes: [
    ...executionPartition.genericProbes,
    ...executionPartition.hostAbi.rows,
    ...targetAbsenceProbes,
  ],
  ...bindings,
});
writeNewJson(planPath, plan);
writeNewJson(genericPlanPath, genericPlan);
const hostAbiSurfaceAccountIds = coverage.edges
  .filter((edge) => edge.surface?.kind === "host-abi")
  .map((edge) => edge.id)
  .sort((left, right) => left.localeCompare(right, "en-US"));
writeNewJson(hostAbiPlanPath, {
  hostAbiOutputPlanSchema: "ibex/capsec-host-abi-output-plan/2",
  profile: "ibex/capsec/1",
  executor: plan.executor,
  sourceRevision: plan.sourceRevision,
  sourceTreeDigest: plan.sourceTreeDigest,
  target: plan.target,
  engine: plan.engine,
  catalogKeyDigest: plan.catalogKeyDigest,
  sweepPlanDigest: plan.sweepPlanDigest,
  compiledRegistrarIds: hostAbiSurfaceAccountIds,
  rows: executionPartition.hostAbi.rows,
});

// Positive-control inputs exist only in the owned Rust executor child. Armed
// process.env must hide them and overlay writes must leave them unchanged; the
// raw random values are never placed in a plan, batch, artifact, or log.
const childHostEnvironmentCanaries = Object.fromEntries(
  ENVIRONMENT_OUTPUT_SWEEP_NAMES.map((name) => [
    name,
    crypto.randomBytes(32).toString("base64url"),
  ]),
);

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
      ...childHostEnvironmentCanaries,
      IBEX_CAPSEC_OUTPUT_SHAPE_PLAN: genericPlanPath,
      IBEX_CAPSEC_OUTPUT_SHAPE_BATCH_OUTPUT: batchPath,
    },
    stdio: "inherit",
  },
);
const batch = readOwnedJson(batchPath, "output-shape executor batch");

execFileSync(
  "cargo",
  [
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer,host-http-server",
    "capsec_host_abi_output_batch",
    "--",
    "--test-threads=1",
    "--nocapture",
  ],
  {
    cwd: repoRoot,
    env: {
      ...exactEngineEnvironment,
      IBEX_CAPSEC_HOST_ABI_OUTPUT_PLAN: hostAbiPlanPath,
      IBEX_CAPSEC_HOST_ABI_OUTPUT_BATCH_OUTPUT: hostAbiBatchPath,
    },
    stdio: "inherit",
  },
);
const hostAbiBatch = readOwnedJson(
  hostAbiBatchPath,
  "Host ABI output executor batch",
);

const targetAbsenceRecipes = recipeCatalog.recipes.filter(
  (recipe) =>
    recipe.publicSurfaceProbe?.kind === "target-absence-probe" &&
    recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
      "ibex/capsec-target-absence-invocation/1",
);
const targetAbsenceFixtureIds = targetAbsenceRecipes
  .map((recipe) => recipe.fixtureId)
  .sort((left, right) => left.localeCompare(right, "en-US"));
const targetAbsenceCommands = [
  ...new Map(
    targetAbsenceRecipes.map((recipe) => [
      canonicalJson(recipe.publicSurfaceProbe.command),
      recipe.publicSurfaceProbe.command,
    ]),
  ).values(),
];
if (targetAbsenceCommands.length !== 1) {
  throw new Error(
    "target-absence output execution requires one exact current-source batch command",
  );
}
const [targetAbsenceCommand] = targetAbsenceCommands;
execFileSync(targetAbsenceCommand[0], targetAbsenceCommand.slice(1), {
  cwd: repoRoot,
  env: {
    ...exactEngineEnvironment,
    IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
    IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT: targetAbsenceBatchPath,
  },
  stdio: "inherit",
});
const targetAbsenceBatch = readOwnedJson(
  targetAbsenceBatchPath,
  "target-absence public executor batch",
);
const targetAbsenceExecutions = mergePublicBatchExecutions({
  batches: [
    {
      batch: targetAbsenceBatch,
      expectedFixtureIds: targetAbsenceFixtureIds,
    },
  ],
  recipeCatalog,
  loadedEngineIdentity: engine,
});
const targetAbsenceExecutionArtifact = buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision: bindings.sourceRevision,
  sourceTreeDigest: bindings.sourceTreeDigest,
  target: bindings.target,
  engine: bindings.engine,
  coverage,
  executions: targetAbsenceExecutions,
});
writeNewJson(targetAbsenceExecutionPath, targetAbsenceExecutionArtifact);

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
let composedBatch;
try {
  ({ artifact, batch: composedBatch } =
    composeOutputShapeSweepArtifactFromDelegatedBatches({
      catalog: completeCatalog,
      plan,
      genericCatalog,
      genericPlan,
      genericBatch: batch,
      hostAbiBatch,
      targetAbsenceProbes,
      targetAbsenceExecutionArtifact,
      recipeCatalog,
      coverage,
    }));
} catch (error) {
  writeNewJson(reportPath, {
    outputShapeExecutorReportSchema:
      "ibex/capsec-output-shape-executor-report/1",
    status: "unpromotable",
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    target: bindings.target,
    loadedEngineIdentity: bindings.engine,
    sweepPlanDigest: plan.sweepPlanDigest,
    proofCounts,
    unexercisableRows: [
      ...(batch.unexercisable ?? []),
      ...(hostAbiBatch.unexercisable ?? []),
    ],
    reason: error instanceof Error ? error.message : String(error),
  });
  throw new Error(
    `output-shape sweep is unpromotable; inspect ${reportPath}: ${error instanceof Error ? error.message : error}`,
  );
}
const evidence = buildVerifiedOutputDispositionEvidence({
  catalog: completeCatalog,
  dispositionRows: dispositionDataset.rows,
  plan,
  artifact,
  ...bindings,
});
writeNewJson(composedBatchPath, composedBatch);
writeNewJson(artifactPath, artifact);
writeNewJson(evidencePath, evidence);
writeNewJson(reportPath, {
  outputShapeExecutorReportSchema:
    "ibex/capsec-output-shape-executor-report/1",
  status: "verified",
  sourceRevision: bindings.sourceRevision,
  sourceTreeDigest: bindings.sourceTreeDigest,
  target: bindings.target,
  loadedEngineIdentity: bindings.engine,
  sweepPlanDigest: plan.sweepPlanDigest,
  sweepArtifactDigest: artifact.sweepArtifactDigest,
  proofCounts,
  componentEvidence: {
    genericBatchPath: batchPath,
    hostAbiBatchPath,
    targetAbsenceExecutionPath,
    composedBatchPath,
  },
  evidencePath,
});
process.stdout.write(
  `${JSON.stringify({
    status: "verified",
    artifactPath,
    evidencePath,
    reportPath,
    composedBatchPath,
    proofCounts,
  })}\n`,
);
