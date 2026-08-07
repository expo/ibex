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
  selectCandidateTarget,
} from "./capsec-conformance.mjs";
import { assertRecipeCatalogComplete } from "./capsec-conformance-recipes.mjs";
import {
  portablePublicSurfaceInvocation,
  publicSurfaceExecutorDescriptor,
} from "./capsec-public-executors.mjs";
import { CAPSEC_SECURE_TEST_FEATURES } from "./capsec-secure-test-command.mjs";
import {
  assertObservedScopeClosure,
  assertPublicSurfaceExecutionComplete,
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import {
  CONFORMANCE_PREFLIGHT_COMMANDS,
  CONFORMANCE_PRODUCT_COMMANDS,
  resolveConformanceMatrixInvocation,
} from "./capsec-conformance-matrix.mjs";
import {
  commandEvidenceIdSuffix,
  createCapsecCommandSupervisor,
  legacyCommandEvidence,
  runObservedCommand,
} from "./capsec-command-evidence.mjs";
import {
  bindConformanceSuitePlan,
  readConformanceSuitePlan,
} from "./capsec-conformance-plan.mjs";
import {
  canonicalJson,
  parseJsonStrict,
  readJsonStrict,
} from "./capsec-contract.mjs";
import {
  conformanceRunnerBindingDigest,
  readCanonicalConformanceRunnerSelection,
} from "./capsec-conformance-runner-binding.mjs";
import {
  engineLoaderEnvironment,
  validateLoadedEngineIdentity,
} from "./capsec-engine-identity.mjs";
import { validatePromotableOutputDispositionEvidence } from "./capsec-output-shape-sweep.mjs";
import {
  buildExactFixtureEvidenceBindingArtifact,
  validateExactFixtureEvidenceArtifact,
} from "./capsec-fixture-evidence.mjs";
import {
  buildInternalInvariantEvidenceBindingArtifact,
  validateInternalInvariantEvidenceArtifact,
} from "./capsec-internal-invariant-execution.mjs";
import { INTERNAL_INVARIANT_EXECUTOR } from "./capsec-internal-invariant-evidence.mjs";
import {
  buildPortableEvidencePlan,
  buildPortableInternalBatchEvidencePlan,
  buildPortablePublicBatchEvidencePlan,
  parsePortableEngineIdentityMarker,
  portableReportSliceBytes,
  validateLivePortableProcess,
} from "./capsec-live-portable-engine-evidence.mjs";
import {
  buildPortablePromotionBundleV2,
  preparePortablePromotionV2,
} from "./capsec-portable-promotion-bundle.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2).filter((argument) => argument !== "--");
const valueOptions = new Set([
  "--engine-artifact",
  "--fixture-evidence",
  "--output-disposition-evidence",
  "--public-surface-evidence",
  "--portable-promotion-output",
  "--portable-promotion-target-cells",
  "--portable-engine-conformance-runner-selection",
  "--output",
  "--report",
  "--target",
]);
const booleanOptions = new Set(["--expect-incomplete"]);
const parsedOptions = new Map();
const parsedFlags = new Set();
for (let index = 0; index < args.length; ) {
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
    throw new Error(
      `unknown conformance runner option ${JSON.stringify(name)}`,
    );
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
const suppliedFixtureEvidencePath = option("--fixture-evidence");
const outputDispositionEvidenceInputPath = option(
  "--output-disposition-evidence",
);
const publicSurfaceEvidenceInputPath = option("--public-surface-evidence");
const portablePromotionOutputInput = option("--portable-promotion-output");
const portablePromotionTargetCellsInput = option(
  "--portable-promotion-target-cells",
);
const conformanceRunnerSelectionInput = option(
  "--portable-engine-conformance-runner-selection",
);
if (
  portablePromotionTargetCellsInput !== undefined &&
  portablePromotionOutputInput === undefined
) {
  throw new Error(
    "--portable-promotion-target-cells is only an optional redundancy check for --portable-promotion-output",
  );
}
const portablePromotionOutputDirectory = portablePromotionOutputInput
  ? path.resolve(repoRoot, portablePromotionOutputInput)
  : null;
const conformanceRunnerRequired =
  portablePromotionOutputDirectory !== null ||
  outputDispositionEvidenceInputPath !== undefined;
if (
  conformanceRunnerRequired
    ? conformanceRunnerSelectionInput === undefined
    : conformanceRunnerSelectionInput !== undefined
) {
  throw new Error(
    "portable output evidence and promotion require exactly one canonical post-link conformance-runner selection",
  );
}
const conformanceRunnerSelectionPath = conformanceRunnerSelectionInput
  ? path.resolve(repoRoot, conformanceRunnerSelectionInput)
  : null;
let portableEngineTestExecutable = null;
let portableEngineTestExecutableDigest = null;
let portableEngineTestExecutableSize = null;
let conformanceRunner = null;
let portableRunnerBindingDigest = null;
const jobStartedAtInput = process.env.IBEX_CAPSEC_JOB_STARTED_AT;
const jobStartedAtMs =
  jobStartedAtInput === undefined
    ? Date.now()
    : /^\d+$/u.test(jobStartedAtInput)
      ? Number(jobStartedAtInput)
      : Date.parse(jobStartedAtInput);
if (!Number.isFinite(jobStartedAtMs)) {
  throw new Error(
    "IBEX_CAPSEC_JOB_STARTED_AT must be epoch milliseconds or ISO-8601",
  );
}
const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) =>
  execFileSync("git", gitArgs, { cwd: repoRoot, timeout: 30_000 });
const EFFECTIVE_UID =
  typeof process.geteuid === "function"
    ? process.geteuid()
    : typeof process.getuid === "function"
      ? process.getuid()
      : null;
const ownedByCurrentUser = (metadata) =>
  EFFECTIVE_UID === null || metadata.uid === EFFECTIVE_UID;

function assertPortableEngineTestExecutable() {
  if (portableEngineTestExecutable === null) return;
  if (!/^sha256-[0-9a-f]{64}$/u.test(portableEngineTestExecutableDigest)) {
    throw new Error("portable engine test executable digest is malformed");
  }
  const targetRoot = fs.realpathSync(path.join(repoRoot, "target"));
  const relative = path.relative(targetRoot, portableEngineTestExecutable);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative) ||
    fs.realpathSync(portableEngineTestExecutable) !==
      portableEngineTestExecutable
  ) {
    throw new Error("portable engine test executable escaped target/ or is redirected");
  }
  const before = fs.lstatSync(portableEngineTestExecutable, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    (EFFECTIVE_UID !== null && before.uid !== BigInt(EFFECTIVE_UID)) ||
    (Number(before.mode & 0o7777n) & 0o111) === 0 ||
    before.size <= 0n ||
    before.size !== BigInt(portableEngineTestExecutableSize) ||
    before.size > 512n * 1024n * 1024n
  ) {
    throw new Error(
      "portable engine test executable is not one bounded owned executable file",
    );
  }
  const descriptor = fs.openSync(
    portableEngineTestExecutable,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      throw new Error("portable engine test executable changed while opening");
    }
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < Number(opened.size)) {
      const length = Math.min(buffer.length, Number(opened.size) - offset);
      const count = fs.readSync(descriptor, buffer, 0, length, offset);
      if (count <= 0) {
        throw new Error("portable engine test executable read ended early");
      }
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(portableEngineTestExecutable, {
      bigint: true,
    });
    for (const current of [after, pathAfter]) {
      if (
        !current.isFile() ||
        current.isSymbolicLink() ||
        current.nlink !== 1n ||
        current.dev !== opened.dev ||
        current.ino !== opened.ino ||
        current.size !== opened.size ||
        current.mtimeNs !== opened.mtimeNs ||
        current.ctimeNs !== opened.ctimeNs
      ) {
        throw new Error("portable engine test executable changed while reading");
      }
    }
    if (`sha256-${hash.digest("hex")}` !== portableEngineTestExecutableDigest) {
      throw new Error(
        "portable engine test executable differs from post-link verified bytes",
      );
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function readOwnedJsonWithBytes(filePath, label) {
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
    return { bytes, value: parseJsonStrict(bytes, label) };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readOwnedJson(filePath, label) {
  return readOwnedJsonWithBytes(filePath, label).value;
}

function writeNewOwnedBytes(filePath, bytes, label) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_WRONLY |
      (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  let opened;
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    opened = fs.fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      !ownedByCurrentUser(opened)
    ) {
      throw new Error(`${label}: opened output is not an owned regular file`);
    }
  } finally {
    fs.closeSync(descriptor);
  }
  const metadata = fs.lstatSync(filePath);
  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    !ownedByCurrentUser(metadata) ||
    metadata.dev !== opened.dev ||
    metadata.ino !== opened.ino
  ) {
    throw new Error(`${label}: output is not an owned regular file`);
  }
}

function writePortablePromotionBundleDirectory(directory, bundle) {
  if (fs.existsSync(directory)) {
    throw new Error(`portable promotion output already exists: ${directory}`);
  }
  fs.mkdirSync(directory, { mode: 0o700 });
  for (const file of bundle.files) {
    if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/u.test(file.logicalName)) {
      throw new Error(
        `portable promotion file has unsafe logical name ${file.logicalName}`,
      );
    }
    writeNewOwnedBytes(
      path.join(directory, `${file.logicalName}.json`),
      file.bytes,
      `portable promotion ${file.logicalName}`,
    );
  }
  writeNewOwnedBytes(
    path.join(directory, "bundle-manifest.json"),
    bundle.manifestBytes,
    "portable promotion bundle manifest",
  );
}

if (!fs.existsSync(engineArtifactPath)) {
  throw new Error(
    `bound runtime engine artifact not found: ${engineArtifactPath}`,
  );
}
const initialSourceRevision = git("rev-parse", "HEAD").toString("utf8").trim();
const initialSourceTree = git("rev-parse", "HEAD^{tree}")
  .toString("utf8")
  .trim();
const initialSourceTreeDigest = taggedDigest(
  Buffer.from(`${initialSourceTree}\n`, "utf8"),
);
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error(
    "conformance execution requires a clean committed source tree",
  );
}
if (conformanceRunnerSelectionPath !== null) {
  const conformanceRunnerState = readCanonicalConformanceRunnerSelection({
    selectionPath: conformanceRunnerSelectionPath,
    repoRoot,
    sourceRevision: initialSourceRevision,
    sourceTreeDigest: initialSourceTreeDigest,
  });
  portableEngineTestExecutable = conformanceRunnerState.executablePath;
  portableEngineTestExecutableDigest =
    conformanceRunnerState.selection.executableDigest;
  portableEngineTestExecutableSize =
    conformanceRunnerState.selection.executableSize;
  conformanceRunner = conformanceRunnerState.binding;
  portableRunnerBindingDigest = conformanceRunnerBindingDigest(
    conformanceRunner,
  );
  assertPortableEngineTestExecutable();
}
const rules = readJsonStrict(
  path.join(capsecRoot, "registry/policy-rules.json"),
);
const target = selectCandidateTarget(rules, option("--target"));
const coverage = readJsonStrict(
  path.join(capsecRoot, "registry/coverage-edges.json"),
);

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
const suitePlan = readConformanceSuitePlan();
const suitePlanBinding = bindConformanceSuitePlan({
  plan: suitePlan,
  sourceRevision: initialSourceRevision,
  sourceTreeDigest: initialSourceTreeDigest,
  target: target.triple,
  engineArtifactDigest: engineBinaryDigest,
});
const suiteAbortController = new AbortController();
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => suiteAbortController.abort(signal));
}
const supervisor = createCapsecCommandSupervisor({
  evidenceDirectory,
  suitePlanBinding,
  executionShard: "full-matrix-sequential",
  jobStartedAtMs,
  outcomePath: path.join(realEvidenceRoot, "capsec-execution-outcome.json"),
  liveStatusPath: path.join(realEvidenceRoot, "capsec-live-status.json"),
  outerBudgetPath: path.join(realEvidenceRoot, "capsec-outer-budget.json"),
  abortSignal: suiteAbortController.signal,
});
process.once("exit", (code) => {
  if (supervisor.finishedAt === null) {
    supervisor.finish(code === 0 ? "success" : "failed");
  }
});
const engineIdentityPath = path.join(
  evidenceDirectory,
  "loaded-engine-identity.json",
);
const engineIdentityAfterPath = path.join(
  evidenceDirectory,
  "loaded-engine-identity-after-evidence.json",
);
const portableEngineIdentityPath = path.join(
  evidenceDirectory,
  "portable-engine-identity.json",
);
const portableEngineIdentityAfterPath = path.join(
  evidenceDirectory,
  "portable-engine-identity-after-evidence.json",
);
const exactEngineEnvironment = {
  ...engineLoaderEnvironment(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_ARTIFACT: fs.realpathSync(engineArtifactPath),
  IBEX_CAPSEC_ENGINE_DIGEST: engineBinaryDigest,
  IBEX_FAIL_ON_STALE_VENDORED: "1",
};
const exactEngineEnvironmentKeys = Object.keys(exactEngineEnvironment).filter(
  (name) =>
    !Object.hasOwn(process.env, name) ||
    process.env[name] !== exactEngineEnvironment[name],
);
const engineTestInvocation = ({
  testName,
  nocapture,
  features = CAPSEC_SECURE_TEST_FEATURES,
}) =>
  portableEngineTestExecutable === null
    ? {
        command: "cargo",
        args: [
          "test",
          "--bin",
          "ibex",
          "--no-default-features",
          "--features",
          features,
          testName,
          "--",
          "--test-threads=1",
          ...(nocapture ? ["--nocapture"] : []),
        ],
      }
    : {
        command: portableEngineTestExecutable,
        args: [
          testName,
          "--test-threads=1",
          ...(nocapture ? ["--nocapture"] : []),
        ],
      };

async function runObservedEngineTest(options) {
  const {
    testName,
    nocapture = false,
    features,
    declaredInputs = [],
    ...commandOptions
  } = options;
  const invocation = engineTestInvocation({ testName, nocapture, features });
  assertPortableEngineTestExecutable();
  const attempt = await runObservedCommand({
    ...commandOptions,
    command: invocation.command,
    args: invocation.args,
    declaredInputs: [
      ...declaredInputs,
      ...(portableRunnerBindingDigest === null
        ? []
        : [
            {
              name: "conformanceRunner",
              digest: portableRunnerBindingDigest,
            },
          ]),
    ],
  });
  assertPortableEngineTestExecutable();
  return attempt;
}

async function runObservedPublicTest(recipeCommand, options) {
  const invocation =
    portableEngineTestExecutable === null
      ? { command: recipeCommand[0], args: recipeCommand.slice(1) }
      : portablePublicSurfaceInvocation(
          recipeCommand,
          portableEngineTestExecutable,
        );
  const { declaredInputs = [], ...commandOptions } = options;
  assertPortableEngineTestExecutable();
  const attempt = await runObservedCommand({
    ...commandOptions,
    command: invocation.command,
    args: invocation.args,
    declaredInputs: [
      ...declaredInputs,
      ...(portableRunnerBindingDigest === null
        ? []
        : [
            {
              name: "conformanceRunner",
              digest: portableRunnerBindingDigest,
            },
          ]),
    ],
  });
  assertPortableEngineTestExecutable();
  return attempt;
}
const runEngineAttestation = async (id, identityPath, portableIdentityPath) => {
  return await runObservedEngineTest({
    supervisor,
    id,
    testName: "capsec_loaded_engine_identity_attestation",
    nocapture: true,
    cwd: repoRoot,
    env: {
      ...exactEngineEnvironment,
      IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT: identityPath,
      IBEX_CAPSEC_PORTABLE_ENGINE_IDENTITY_OUTPUT: portableIdentityPath,
    },
    environmentKeys: [
      ...exactEngineEnvironmentKeys,
      "IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT",
      "IBEX_CAPSEC_PORTABLE_ENGINE_IDENTITY_OUTPUT",
    ],
    declaredInputs: [{ name: "engineArtifact", digest: engineBinaryDigest }],
    expectedOutputs: [identityPath, portableIdentityPath],
  });
};
const runMatrixCommands = async (commands) => {
  const evidence = [];
  for (const [id, command, commandArgs] of commands) {
    const invocation = resolveConformanceMatrixInvocation({
      id,
      command,
      args: commandArgs,
      target: target.triple,
      environment: exactEngineEnvironment,
      repoRoot,
    });
    const attempt = await runObservedCommand({
      supervisor,
      id,
      command: invocation.command,
      args: invocation.args,
      cwd: repoRoot,
      env: exactEngineEnvironment,
      environmentKeys: [
        ...exactEngineEnvironmentKeys,
        ...invocation.environmentKeys,
      ],
      declaredInputs: [
        { name: "suitePlan", digest: suitePlanBinding.suitePlanDigest },
      ],
    });
    evidence.push(legacyCommandEvidence(attempt));
  }
  return evidence;
};
const commandEvidence = await runMatrixCommands(CONFORMANCE_PREFLIGHT_COMMANDS);
commandEvidence.push(
  legacyCommandEvidence(
    await runEngineAttestation(
      "exact-loaded-engine-attestation",
      engineIdentityPath,
      portableEngineIdentityPath,
    ),
  ),
);
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
const portableEngineIdentityBytes = readOwnedJsonWithBytes(
  portableEngineIdentityPath,
  "portable engine identity marker",
).bytes;
const portableEngineIdentity = parsePortableEngineIdentityMarker(
  portableEngineIdentityBytes,
);
const recipeCatalogPath = path.join(
  evidenceDirectory,
  "executable-recipes.json",
);
const scopeArtifactDirectory = path.join(evidenceDirectory, "capsec-scope");
const scopeArtifactPath = path.join(
  scopeArtifactDirectory,
  "capsec-scope.json",
);
const scopeExpansionDiffPath = path.join(
  scopeArtifactDirectory,
  "capsec-scope-expansion-diff.json",
);
const scopeCellMappingPath = path.join(
  scopeArtifactDirectory,
  "capsec-scope-cell-mapping.json",
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
const fixtureEvidenceBindingPath = path.join(
  evidenceDirectory,
  "exact-fixture-evidence-binding.json",
);
const producedFixtureEvidencePath = path.join(
  evidenceDirectory,
  "exact-fixture-evidence.json",
);
const internalInvariantBindingPath = path.join(
  evidenceDirectory,
  "internal-invariant-evidence-binding.json",
);
const internalInvariantEvidencePath = path.join(
  evidenceDirectory,
  "internal-invariant-evidence.json",
);
await runObservedCommand({
  supervisor,
  id: "generate-executable-recipes",
  command: process.execPath,
  args: [
    path.join(
      repoRoot,
      "packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs",
    ),
    "--output",
    recipeCatalogPath,
    "--target",
    target.triple,
    "--scope-output-dir",
    scopeArtifactDirectory,
  ],
  cwd: repoRoot,
  declaredInputs: [
    { name: "sourceTree", digest: initialSourceTreeDigest },
    { name: "suitePlan", digest: suitePlanBinding.suitePlanDigest },
  ],
  expectedOutputs: [
    recipeCatalogPath,
    scopeArtifactPath,
    scopeExpansionDiffPath,
    scopeCellMappingPath,
  ],
});
const recipeCatalog = readOwnedJson(
  recipeCatalogPath,
  "executable recipe catalog",
);
const scopeArtifact = readOwnedJson(
  scopeArtifactPath,
  "generated CapSec scope artifact",
);
if (
  scopeArtifact.scopeSchema !== "ibex/capsec-scope/1" ||
  scopeArtifact.profile !== "ibex/capsec/1" ||
  canonicalJson(scopeArtifact.target) !== canonicalJson(target) ||
  !/^sha256-[A-Za-z0-9_-]{43}$/u.test(scopeArtifact.scopeDigest ?? "") ||
  !Array.isArray(scopeArtifact.expandedCellIds) ||
  scopeArtifact.expandedCellIds.length === 0 ||
  recipeCatalog.summary?.scopeDigest !== scopeArtifact.scopeDigest
) {
  throw new Error(
    "generated recipe catalog and scope artifact have stale or mismatched bindings",
  );
}
const expandedScopeCellIds = new Set(scopeArtifact.expandedCellIds);
commandEvidence.push(
  legacyCommandEvidence(
    await runObservedEngineTest({
      supervisor,
      id: "exact-hermes-typed-adapter-recipes",
      testName: "capsec_executable_recipe_adapter_batch",
      nocapture: true,
      features: CAPSEC_SECURE_TEST_FEATURES,
      cwd: repoRoot,
      env: {
        ...exactEngineEnvironment,
        IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
        IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT: adapterEvidencePath,
      },
      environmentKeys: [
        ...exactEngineEnvironmentKeys,
        "IBEX_CAPSEC_RECIPE_CATALOG",
        "IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT",
      ],
      declaredInputs: [
        {
          name: "recipeCatalog",
          digest: recipeCatalog.recipeCatalogDigest,
        },
        { name: "engineArtifact", digest: engineBinaryDigest },
      ],
      expectedOutputs: [adapterEvidencePath],
    }),
  ),
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
  if (
    recipe.status !== "fully-executable" ||
    !recipe.edgeIds.some((edgeId) => expandedScopeCellIds.has(edgeId))
  ) {
    continue;
  }
  const command = recipe.publicSurfaceProbe?.command;
  if (!Array.isArray(command) || command.length === 0) {
    throw new Error(
      `${recipe.fixtureId}: fully executable recipe has no command`,
    );
  }
  const key = canonicalJson(command);
  const entry = publicRecipeCommands.get(key) ?? { command, fixtureIds: [] };
  entry.fixtureIds.push(recipe.fixtureId);
  publicRecipeCommands.set(key, entry);
}
const publicBatches = [];
let publicBatchIndex = 0;
if (
  publicRecipeCommands.size >
  suitePlan.targets[target.triple].maxPublicFixtureBatches
) {
  throw new Error(
    `suite plan permits ${suitePlan.targets[target.triple].maxPublicFixtureBatches} public fixture batches; catalog requires ${publicRecipeCommands.size}`,
  );
}
for (const { command, fixtureIds } of publicRecipeCommands.values()) {
  const batchId = `public-fixtures-${String(publicBatchIndex).padStart(3, "0")}-${commandEvidenceIdSuffix(
    Buffer.from(canonicalJson(command), "utf8"),
  )}`;
  publicBatchIndex += 1;
  const batchOutputPath = path.join(
    publicBatchEvidenceDirectory,
    `${batchId}.json`,
  );
  commandEvidence.push(
    legacyCommandEvidence(
      await runObservedPublicTest(command, {
        supervisor,
        id: batchId,
        cwd: repoRoot,
        env: {
          ...exactEngineEnvironment,
          IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
          IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT: batchOutputPath,
        },
        environmentKeys: [
          ...exactEngineEnvironmentKeys,
          "IBEX_CAPSEC_RECIPE_CATALOG",
          "IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT",
        ],
        declaredInputs: [
          {
            name: "recipeCatalog",
            digest: recipeCatalog.recipeCatalogDigest,
          },
          { name: "engineArtifact", digest: engineBinaryDigest },
        ],
        expectedOutputs: [batchOutputPath],
      }),
    ),
  );
  const batch = readOwnedJson(batchOutputPath, `${batchId} evidence`);
  publicBatches.push({ batch, expectedFixtureIds: fixtureIds });
}
const publicExecutions = mergePublicBatchExecutions({
  batches: publicBatches,
  recipeCatalog,
  loadedEngineIdentity,
});
// Validate the complete cross-batch envelope before the hour-scale product
// suites. Each shard validates its own runtime record; this step also proves
// that every record still matches the independently authored recipe catalog.
const publicSurfaceEvidence = buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision: initialSourceRevision,
  sourceTreeDigest: initialSourceTreeDigest,
  target,
  engine: engineBinding,
  coverage,
  scopeDigest: scopeArtifact.scopeDigest,
  expandedEdgeIds: scopeArtifact.expandedCellIds,
  closureEdgeIds: scopeArtifact.expandedCellIds,
  executions: publicExecutions,
});
commandEvidence.push(...(await runMatrixCommands(CONFORMANCE_PRODUCT_COMMANDS)));
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
  sourceTreeDigest: initialSourceTreeDigest,
  engine: engineBinding,
  ...(conformanceRunner === null ? {} : { conformanceRunner }),
  vocabularyDigest,
  registryDigest,
  implementationManifestDigest,
};
let validatedOutputDispositionEvidenceState;
let richOutputDispositionEvidenceBytes;
if (outputDispositionEvidenceInputPath) {
  const { bytes, value: outputDispositionEvidence } = readOwnedJsonWithBytes(
    path.resolve(repoRoot, outputDispositionEvidenceInputPath),
    "output-disposition evidence",
  );
  richOutputDispositionEvidenceBytes = bytes;
  validatedOutputDispositionEvidenceState =
    validatePromotableOutputDispositionEvidence({
      catalog: readJsonStrict(
        path.join(capsecRoot, "generated/output-shape-catalog.json"),
      ),
      dispositionRows: readJsonStrict(
        path.join(capsecRoot, "generated/output-dispositions.json"),
      ).rows,
      evidence: outputDispositionEvidence,
      conformanceRunner,
    });
  if (
    validatedOutputDispositionEvidenceState.sourceRevision !==
      bindings.sourceRevision ||
    validatedOutputDispositionEvidenceState.sourceTreeDigest !==
      bindings.sourceTreeDigest ||
    canonicalJson(validatedOutputDispositionEvidenceState.target) !==
      canonicalJson(target) ||
    canonicalJson(validatedOutputDispositionEvidenceState.engine) !==
      canonicalJson(bindings.engine) ||
    canonicalJson(validatedOutputDispositionEvidenceState.conformanceRunner) !==
      canonicalJson(conformanceRunner)
  ) {
    throw new Error(
      "output-disposition evidence source, target, loaded engine, or conformance runner differs from this execution",
    );
  }
  bindings.outputDispositionEvidenceRawContentDigest = taggedDigest(bytes);
}
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
    expandedEdgeIds: scopeArtifact.expandedCellIds,
    closureEdgeIds: scopeArtifact.expandedCellIds,
  });
  if (
    canonicalJson(suppliedEvidence) !== canonicalJson(publicSurfaceEvidence)
  ) {
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
const fixtureEvidenceBinding = buildExactFixtureEvidenceBindingArtifact({
  recipeCatalog,
  fixtureCatalog: catalog,
  bindings,
  target,
  fixtureCatalogDigest,
});
fs.writeFileSync(
  fixtureEvidenceBindingPath,
  `${JSON.stringify(fixtureEvidenceBinding, null, 2)}\n`,
  { flag: "wx", mode: 0o600 },
);
const internalInvariantBinding =
  buildInternalInvariantEvidenceBindingArtifact({
    recipeCatalog,
    fixtureCatalog: catalog,
    bindings,
    target,
    fixtureCatalogDigest,
  });
fs.writeFileSync(
  internalInvariantBindingPath,
  `${JSON.stringify(internalInvariantBinding, null, 2)}\n`,
  { flag: "wx", mode: 0o600 },
);
let fixtureEvidencePath;
if (suppliedFixtureEvidencePath) {
  fixtureEvidencePath = path.resolve(repoRoot, suppliedFixtureEvidencePath);
} else {
  commandEvidence.push(
    legacyCommandEvidence(
      await runObservedEngineTest({
        supervisor,
        id: "exact-fixture-evidence-pilot",
        testName: "capsec_exact_fixture_evidence_batch",
        features: CAPSEC_SECURE_TEST_FEATURES,
        nocapture: true,
        cwd: repoRoot,
        env: {
          ...exactEngineEnvironment,
          IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
          IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING: fixtureEvidenceBindingPath,
          IBEX_CAPSEC_FIXTURE_EVIDENCE_OUTPUT: producedFixtureEvidencePath,
        },
        environmentKeys: [
          ...exactEngineEnvironmentKeys,
          "IBEX_CAPSEC_RECIPE_CATALOG",
          "IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING",
          "IBEX_CAPSEC_FIXTURE_EVIDENCE_OUTPUT",
        ],
        declaredInputs: [
          {
            name: "recipeCatalog",
            digest: recipeCatalog.recipeCatalogDigest,
          },
          { name: "fixtureBinding", digest: bindingDigest },
          { name: "engineArtifact", digest: engineBinaryDigest },
        ],
        expectedOutputs: [producedFixtureEvidencePath],
      }),
    ),
  );
  fixtureEvidencePath = producedFixtureEvidencePath;
}
const fixtureArtifact = readOwnedJson(
  fixtureEvidencePath,
  "Exact fixture evidence",
);
validateExactFixtureEvidenceArtifact(fixtureArtifact, {
  recipeCatalog,
  fixtureCatalog: catalog,
  coverage,
  bindings,
  target,
  fixtureCatalogDigest,
});
commandEvidence.push(
  legacyCommandEvidence(
    await runObservedEngineTest({
      supervisor,
      id: "internal-invariant-evidence",
      testName: "capsec_internal_invariant_evidence_batch",
      features: CAPSEC_SECURE_TEST_FEATURES,
      nocapture: true,
      cwd: repoRoot,
      env: {
        ...exactEngineEnvironment,
        IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
        IBEX_CAPSEC_INTERNAL_INVARIANT_BINDING:
          internalInvariantBindingPath,
        IBEX_CAPSEC_INTERNAL_INVARIANT_EVIDENCE_OUTPUT:
          internalInvariantEvidencePath,
      },
      environmentKeys: [
        ...exactEngineEnvironmentKeys,
        "IBEX_CAPSEC_RECIPE_CATALOG",
        "IBEX_CAPSEC_INTERNAL_INVARIANT_BINDING",
        "IBEX_CAPSEC_INTERNAL_INVARIANT_EVIDENCE_OUTPUT",
      ],
      declaredInputs: [
        {
          name: "recipeCatalog",
          digest: recipeCatalog.recipeCatalogDigest,
        },
        { name: "internalInvariantBinding", digest: bindingDigest },
        { name: "engineArtifact", digest: engineBinaryDigest },
      ],
      expectedOutputs: [internalInvariantEvidencePath],
    }),
  ),
);
const internalInvariantArtifact = readOwnedJson(
  internalInvariantEvidencePath,
  "internal invariant evidence",
);
validateInternalInvariantEvidenceArtifact(internalInvariantArtifact, {
  recipeCatalog,
  fixtureCatalog: catalog,
  bindings,
  target,
  fixtureCatalogDigest,
});
const scopedFixtureIds = new Set(
  recipeCatalog.recipes
    .filter((recipe) =>
      recipe.edgeIds.some((edgeId) => expandedScopeCellIds.has(edgeId)),
    )
    .map((recipe) => recipe.fixtureId),
);
const executions = [
  ...fixtureArtifact.executions,
  ...internalInvariantArtifact.executions,
]
  .filter((execution) => scopedFixtureIds.has(execution.fixtureId))
  .sort((left, right) =>
    left.fixtureId < right.fixtureId
      ? -1
      : left.fixtureId > right.fixtureId
        ? 1
        : 0,
  );
if (
  new Set(executions.map((execution) => execution.fixtureId)).size !==
  executions.length
) {
  throw new Error("fixture and internal invariant evidence overlap");
}
assertObservedScopeClosure(
  { executions },
  scopeArtifact.expandedCellIds,
);
let portableProcessEvidence = {
  portableProcessEvidenceSchema: "ibex/capsec-portable-process-preparation/1",
  status: "legacy-null-marker",
  reason: "the exact build carries the canonical legacy null marker",
};
if (portableEngineIdentity !== null) {
  if (!bindings.outputDispositionEvidenceRawContentDigest) {
    if (portablePromotionOutputDirectory) {
      throw new Error(
        "portable promotion requires verified exact output-disposition evidence",
      );
    }
    portableProcessEvidence = {
      portableProcessEvidenceSchema:
        "ibex/capsec-portable-process-preparation/1",
      status: "incomplete",
      reason:
        "portable process evidence requires exact output-disposition bytes before its acyclic execution binding can be fixed",
    };
  } else {
    // @ref LLP 0035#phase-2--split-runtime-and-publication-identity — a real
    // promotion is explicit, source-derived, exact-byte output; the default
    // portable pilot remains diagnostic and cannot alter checked authority.
    if (portablePromotionOutputDirectory) {
      const suppliedPromotionTargetCellsBytes = portablePromotionTargetCellsInput
        ? readOwnedJsonWithBytes(
            path.resolve(repoRoot, portablePromotionTargetCellsInput),
            "supplied portable promotion target cells",
          ).bytes
        : null;
      const family = target.triple.endsWith("-apple-darwin")
        ? "macos"
        : target.triple.endsWith("-pc-windows-msvc")
          ? "windows"
          : "linux";
      const reviewedSourceBytes = Buffer.from(
        `${JSON.stringify(
          {
            portablePromotionSourceSchema:
              "ibex/capsec-portable-promotion-source/2",
            profile: "ibex/capsec/1",
            sourceRevision: bindings.sourceRevision,
            sourceTreeDigest: bindings.sourceTreeDigest,
            family,
            target,
            engine: portableEngineIdentity,
            vocabularyDigest: bindings.vocabularyDigest,
            registryDigest: bindings.registryDigest,
            executorPolicy: "recipe-public-command",
          },
          null,
          2,
        )}\n`,
        "utf8",
      );
      const portablePromotionPreparation = preparePortablePromotionV2({
        conformanceRunner,
        reviewedSourceBytes,
        coverageBytes: fs.readFileSync(
          path.join(capsecRoot, "registry/coverage-edges.json"),
        ),
        implementationManifestBytes: fs.readFileSync(
          path.join(capsecRoot, "generated/implementation-manifest.json"),
        ),
        targetCellsBytes: suppliedPromotionTargetCellsBytes,
        richRecipeCatalogBytes: fs.readFileSync(recipeCatalogPath),
        richPublicSurfaceExecutionBytes: fs.readFileSync(
          publicSurfaceEvidencePath,
        ),
        richOutputDispositionEvidenceBytes,
        outputShapeCatalogBytes: fs.readFileSync(
          path.join(capsecRoot, "generated/output-shape-catalog.json"),
        ),
        outputDispositionRowsBytes: fs.readFileSync(
          path.join(capsecRoot, "generated/output-dispositions.json"),
        ),
      });
      const portableBindings = {
        sourceRevision: portablePromotionPreparation.source.sourceRevision,
        sourceTreeDigest: portablePromotionPreparation.source.sourceTreeDigest,
        conformanceRunner:
          portablePromotionPreparation.authorityEntry.conformanceRunner,
        target: portablePromotionPreparation.source.target,
        engine: portablePromotionPreparation.source.engine,
        vocabularyDigest:
          portablePromotionPreparation.authorityEntry.vocabularyDigest,
        registryDigest:
          portablePromotionPreparation.authorityEntry.registryDigest,
        implementationManifestDigest:
          portablePromotionPreparation.authorityEntry
            .implementationManifestDigest,
        fixtureCatalogDigest:
          portablePromotionPreparation.authorityEntry.fixtureCatalogDigest,
        targetCellsRawContentDigest:
          portablePromotionPreparation.authorityEntry
            .targetCellsRawContentDigest,
        recipeCatalogDigest:
          portablePromotionPreparation.authorityEntry.recipeCatalogDigest,
        recipeCatalogRawContentDigest:
          portablePromotionPreparation.authorityEntry
            .recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          portablePromotionPreparation.authorityEntry
            .publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          portablePromotionPreparation.authorityEntry
            .publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          portablePromotionPreparation.authorityEntry
            .outputDispositionEvidenceRawContentDigest,
      };
      const portableRecipeByFixture = new Map(
        portablePromotionPreparation.recipeCatalog.recipes.map((recipe) => [
          recipe.fixtureId,
          recipe,
        ]),
      );
      const portableProcesses = [];
      const detachedEvidence = [];
      let portableBatchIndex = 0;
      if (
        publicRecipeCommands.size >
        suitePlan.targets[target.triple].maxPortablePublicFixtureBatches
      ) {
        throw new Error(
          `suite plan permits ${suitePlan.targets[target.triple].maxPortablePublicFixtureBatches} portable public fixture batches; catalog requires ${publicRecipeCommands.size}`,
        );
      }
      for (const { command, fixtureIds } of publicRecipeCommands.values()) {
        const executor = publicSurfaceExecutorDescriptor(command).executor;
        if (
          fixtureIds.some(
            (fixtureId) =>
              portableRecipeByFixture.get(fixtureId)?.executor !== executor,
          )
        ) {
          throw new Error(
            `${executor}: portable recipe executor differs from its source command`,
          );
        }
        const batchId = `portable-public-fixtures-${String(
          portableBatchIndex,
        ).padStart(3, "0")}-${commandEvidenceIdSuffix(
          Buffer.from(canonicalJson(command), "utf8"),
        )}`;
        const processDirectory = path.join(
          evidenceDirectory,
          `portable-public-process-${String(portableBatchIndex + 1).padStart(
            4,
            "0",
          )}`,
        );
        portableBatchIndex += 1;
        fs.mkdirSync(processDirectory, { mode: 0o700 });
        const portablePlanState = buildPortablePublicBatchEvidencePlan({
          bindings: portableBindings,
          evidenceDirectory: processDirectory,
          fixtureIds,
          executor,
          commandId: batchId,
        });
        const portablePlanPath = path.join(
          processDirectory,
          "portable-public-batch-plan.json",
        );
        const portablePlanBytes = Buffer.from(
          `${JSON.stringify(portablePlanState.plan, null, 2)}\n`,
          "utf8",
        );
        writeNewOwnedBytes(
          portablePlanPath,
          portablePlanBytes,
          `${batchId} portable evidence plan`,
        );
        const portableAttempt = await runObservedPublicTest(command, {
          supervisor,
          id: batchId,
          cwd: repoRoot,
          env: {
            ...exactEngineEnvironment,
            IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
            IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN: portablePlanPath,
            IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT:
              portablePlanState.mappedEvidencePath,
          },
          environmentKeys: [
            ...exactEngineEnvironmentKeys,
            "IBEX_CAPSEC_RECIPE_CATALOG",
            "IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN",
            "IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT",
          ],
          declaredInputs: [
            {
              name: "richRecipeCatalog",
              digest: recipeCatalog.recipeCatalogDigest,
            },
            {
              name: "portableRecipeCatalog",
              digest:
                portablePromotionPreparation.recipeCatalog
                  .recipeCatalogDigest,
            },
            {
              name: "portablePublicSurfaceExecution",
              digest:
                portablePromotionPreparation.publicSurfaceExecution
                  .publicSurfaceExecutionDigest,
            },
            {
              name: "portableExecutionBinding",
              digest: portablePlanState.plan.bindingDigest,
            },
            {
              name: "portablePublicBatchPlan",
              digest: taggedDigest(portablePlanBytes),
            },
            { name: "engineArtifact", digest: engineBinaryDigest },
          ],
          expectedOutputs: [
            ...portablePlanState.fixtureOutputs.map((output) => output.path),
            portablePlanState.mappedEvidencePath,
          ],
          injectCommandIdentity: true,
        });
        commandEvidence.push(legacyCommandEvidence(portableAttempt));
        const validatedPortableProcess = validateLivePortableProcess({
          attempt: portableAttempt,
          bindings: portableBindings,
          fixtureOutputs: portablePlanState.fixtureOutputs,
          mappedEvidencePath: portablePlanState.mappedEvidencePath,
        });
        const portableAttemptPath = path.join(
          processDirectory,
          "portable-command-attempt.json",
        );
        writeNewOwnedBytes(
          portableAttemptPath,
          validatedPortableProcess.process.commandAttemptBytes,
          `${batchId} portable command attempt`,
        );
        const portableReportSlicePath = path.join(
          processDirectory,
          "portable-report-slice.json",
        );
        const reportSliceBytes = portableReportSliceBytes(
          validatedPortableProcess.reportSlice,
        );
        writeNewOwnedBytes(
          portableReportSlicePath,
          reportSliceBytes,
          `${batchId} portable report slice`,
        );
        portableProcesses.push(validatedPortableProcess.process);
        detachedEvidence.push({
          reportSlicePath: path.relative(repoRoot, portableReportSlicePath),
          commandAttemptPath: path.relative(repoRoot, portableAttemptPath),
          mappedEvidencePath: path.relative(
            repoRoot,
            portablePlanState.mappedEvidencePath,
          ),
          fixturePaths: portablePlanState.fixtureOutputs.map((output) =>
            path.relative(repoRoot, output.path),
          ),
        });
      }
      const internalFixtureIds = internalInvariantArtifact.executions.map(
        (execution) => execution.fixtureId,
      );
      if (
        internalFixtureIds.length === 0 ||
        internalFixtureIds.some(
          (fixtureId) =>
            portableRecipeByFixture.get(fixtureId)?.executor !==
            INTERNAL_INVARIANT_EXECUTOR,
        )
      ) {
        throw new Error(
          "portable internal invariant fixtures differ from the dedicated recipe executor",
        );
      }
      const internalBatchId = "portable-internal-invariants";
      const internalProcessDirectory = path.join(
        evidenceDirectory,
        "portable-internal-process-0001",
      );
      fs.mkdirSync(internalProcessDirectory, { mode: 0o700 });
      const internalPortablePlanState =
        buildPortableInternalBatchEvidencePlan({
          bindings: portableBindings,
          evidenceDirectory: internalProcessDirectory,
          fixtureIds: internalFixtureIds,
          executor: INTERNAL_INVARIANT_EXECUTOR,
          commandId: internalBatchId,
        });
      const internalPortablePlanPath = path.join(
        internalProcessDirectory,
        "portable-internal-batch-plan.json",
      );
      const internalPortablePlanBytes = Buffer.from(
        `${JSON.stringify(internalPortablePlanState.plan, null, 2)}\n`,
        "utf8",
      );
      writeNewOwnedBytes(
        internalPortablePlanPath,
        internalPortablePlanBytes,
        "portable internal invariant evidence plan",
      );
      const internalPortableAttempt = await runObservedEngineTest({
        supervisor,
        id: internalBatchId,
        testName: "capsec_internal_invariant_evidence_batch",
        features: CAPSEC_SECURE_TEST_FEATURES,
        nocapture: true,
        cwd: repoRoot,
        env: {
          ...exactEngineEnvironment,
          IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
          IBEX_CAPSEC_INTERNAL_INVARIANT_BINDING:
            internalInvariantBindingPath,
          IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN: internalPortablePlanPath,
          IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT:
            internalPortablePlanState.mappedEvidencePath,
        },
        environmentKeys: [
          ...exactEngineEnvironmentKeys,
          "IBEX_CAPSEC_RECIPE_CATALOG",
          "IBEX_CAPSEC_INTERNAL_INVARIANT_BINDING",
          "IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN",
          "IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT",
        ],
        declaredInputs: [
          {
            name: "richRecipeCatalog",
            digest: recipeCatalog.recipeCatalogDigest,
          },
          {
            name: "portableRecipeCatalog",
            digest:
              portablePromotionPreparation.recipeCatalog.recipeCatalogDigest,
          },
          {
            name: "portablePublicSurfaceExecution",
            digest:
              portablePromotionPreparation.publicSurfaceExecution
                .publicSurfaceExecutionDigest,
          },
          {
            name: "internalInvariantBinding",
            digest: internalInvariantBinding.bindingDigest,
          },
          {
            name: "portableExecutionBinding",
            digest: internalPortablePlanState.plan.bindingDigest,
          },
          {
            name: "portableInternalBatchPlan",
            digest: taggedDigest(internalPortablePlanBytes),
          },
          { name: "engineArtifact", digest: engineBinaryDigest },
        ],
        expectedOutputs: [
          ...internalPortablePlanState.fixtureOutputs.map(
            (output) => output.path,
          ),
          internalPortablePlanState.mappedEvidencePath,
        ],
        injectCommandIdentity: true,
      });
      commandEvidence.push(legacyCommandEvidence(internalPortableAttempt));
      const validatedInternalPortableProcess = validateLivePortableProcess({
        attempt: internalPortableAttempt,
        bindings: portableBindings,
        fixtureOutputs: internalPortablePlanState.fixtureOutputs,
        mappedEvidencePath: internalPortablePlanState.mappedEvidencePath,
      });
      const internalPortableAttemptPath = path.join(
        internalProcessDirectory,
        "portable-command-attempt.json",
      );
      writeNewOwnedBytes(
        internalPortableAttemptPath,
        validatedInternalPortableProcess.process.commandAttemptBytes,
        "portable internal invariant command attempt",
      );
      const internalPortableReportSlicePath = path.join(
        internalProcessDirectory,
        "portable-report-slice.json",
      );
      writeNewOwnedBytes(
        internalPortableReportSlicePath,
        portableReportSliceBytes(
          validatedInternalPortableProcess.reportSlice,
        ),
        "portable internal invariant report slice",
      );
      portableProcesses.push(validatedInternalPortableProcess.process);
      detachedEvidence.push({
        reportSlicePath: path.relative(
          repoRoot,
          internalPortableReportSlicePath,
        ),
        commandAttemptPath: path.relative(
          repoRoot,
          internalPortableAttemptPath,
        ),
        mappedEvidencePath: path.relative(
          repoRoot,
          internalPortablePlanState.mappedEvidencePath,
        ),
        fixturePaths: internalPortablePlanState.fixtureOutputs.map((output) =>
          path.relative(repoRoot, output.path),
        ),
      });
      const promotionBundle = buildPortablePromotionBundleV2({
        preparation: portablePromotionPreparation,
        processes: portableProcesses,
      });
      writePortablePromotionBundleDirectory(
        portablePromotionOutputDirectory,
        promotionBundle,
      );
      portableProcessEvidence = {
        portableProcessEvidenceSchema:
          "ibex/capsec-portable-process-preparation/1",
        status: "validated-complete",
        reason:
          "every source-routed public batch and the dedicated internal invariant batch emitted exact detached fixture and mapped-process evidence and the sole Phase-2 promotion validator accepted the complete graph",
        engine: portableEngineIdentity,
        mappedEngineExecutionEvidence:
          promotionBundle.report.bindings.mappedEngineExecutionEvidence,
        executions: promotionBundle.report.executions,
        bundleManifestDigest: promotionBundle.manifest.bundleDigest,
        detachedEvidence,
        promotionBundleDirectory: path.relative(
          repoRoot,
          portablePromotionOutputDirectory,
        ),
        trackedAdvertisementCandidate: path.relative(
          repoRoot,
          path.join(
            portablePromotionOutputDirectory,
            "target-advertisements.json",
          ),
        ),
      };
    } else {
      const targetCellsPath = path.join(
        capsecRoot,
        "registry/target-cells.json",
      );
      const portableBindings = {
        sourceRevision: bindings.sourceRevision,
        sourceTreeDigest: bindings.sourceTreeDigest,
        conformanceRunner,
        target,
        engine: portableEngineIdentity,
        vocabularyDigest: bindings.vocabularyDigest,
        registryDigest: bindings.registryDigest,
        implementationManifestDigest: bindings.implementationManifestDigest,
        fixtureCatalogDigest,
        targetCellsRawContentDigest: taggedDigest(
          fs.readFileSync(targetCellsPath),
        ),
        recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
        recipeCatalogRawContentDigest: taggedDigest(
          fs.readFileSync(recipeCatalogPath),
        ),
        publicSurfaceExecutionDigest:
          publicSurfaceEvidence.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest: taggedDigest(
          fs.readFileSync(publicSurfaceEvidencePath),
        ),
        outputDispositionEvidenceRawContentDigest:
          bindings.outputDispositionEvidenceRawContentDigest,
      };
      const fixtureIds = fixtureEvidenceBinding.fixturePlans.map(
        (plan) => plan.fixtureId,
      );
      const portablePlanState = buildPortableEvidencePlan({
        bindings: portableBindings,
        evidenceDirectory,
        fixtureIds,
      });
      const portablePlanPath = path.join(
        evidenceDirectory,
        "portable-evidence-plan.json",
      );
      const portablePlanBytes = Buffer.from(
        `${JSON.stringify(portablePlanState.plan, null, 2)}\n`,
      );
      writeNewOwnedBytes(
        portablePlanPath,
        portablePlanBytes,
        "portable evidence plan",
      );
      const portableAttempt = await runObservedEngineTest({
        supervisor,
        id: "exact-fixture-evidence-portable-pilot",
        testName: "capsec_exact_fixture_evidence_batch",
        features: CAPSEC_SECURE_TEST_FEATURES,
        nocapture: true,
        cwd: repoRoot,
        env: {
          ...exactEngineEnvironment,
          IBEX_CAPSEC_RECIPE_CATALOG: recipeCatalogPath,
          IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING: fixtureEvidenceBindingPath,
          IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN: portablePlanPath,
          IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT:
            portablePlanState.mappedEvidencePath,
        },
        environmentKeys: [
          ...exactEngineEnvironmentKeys,
          "IBEX_CAPSEC_RECIPE_CATALOG",
          "IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING",
          "IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN",
          "IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT",
        ],
        declaredInputs: [
          {
            name: "recipeCatalog",
            digest: recipeCatalog.recipeCatalogDigest,
          },
          { name: "fixtureBinding", digest: bindingDigest },
          {
            name: "portableExecutionBinding",
            digest: portablePlanState.plan.bindingDigest,
          },
          {
            name: "portableEvidencePlan",
            digest: taggedDigest(portablePlanBytes),
          },
          { name: "engineArtifact", digest: engineBinaryDigest },
        ],
        expectedOutputs: [
          ...portablePlanState.fixtureOutputs.map((output) => output.path),
          portablePlanState.mappedEvidencePath,
        ],
        injectCommandIdentity: true,
      });
      commandEvidence.push(legacyCommandEvidence(portableAttempt));
      const validatedPortableProcess = validateLivePortableProcess({
        attempt: portableAttempt,
        bindings: portableBindings,
        fixtureOutputs: portablePlanState.fixtureOutputs,
        mappedEvidencePath: portablePlanState.mappedEvidencePath,
      });
      const portableAttemptPath = path.join(
        evidenceDirectory,
        "portable-command-attempt.json",
      );
      writeNewOwnedBytes(
        portableAttemptPath,
        validatedPortableProcess.process.commandAttemptBytes,
        "portable command attempt",
      );
      const portableReportSlicePath = path.join(
        evidenceDirectory,
        "portable-report-slice.json",
      );
      const reportSliceBytes = portableReportSliceBytes(
        validatedPortableProcess.reportSlice,
      );
      writeNewOwnedBytes(
        portableReportSlicePath,
        reportSliceBytes,
        "portable report slice",
      );
      portableProcessEvidence = {
        portableProcessEvidenceSchema:
          "ibex/capsec-portable-process-preparation/1",
        status: "validated-incomplete",
        reason:
          "the nine-fixture mapped pilot is v2-ready; full promotion additionally requires a complete source-authored recipe/public catalog and physical execution of every required fixture",
        engine: portableEngineIdentity,
        mappedEngineExecutionEvidence:
          validatedPortableProcess.reportSlice.bindings
            .mappedEngineExecutionEvidence,
        executions: validatedPortableProcess.reportSlice.executions,
        reportSliceRawContentDigest: taggedDigest(reportSliceBytes),
        detachedEvidence: {
          reportSlicePath: path.relative(repoRoot, portableReportSlicePath),
          commandAttemptPath: path.relative(repoRoot, portableAttemptPath),
          mappedEvidencePath: path.relative(
            repoRoot,
            portablePlanState.mappedEvidencePath,
          ),
          fixturePaths: portablePlanState.fixtureOutputs.map((output) =>
            path.relative(repoRoot, output.path),
          ),
        },
      };
    }
  }
}
const sourceRevisionAfterFixtureEvidence = git("rev-parse", "HEAD")
  .toString("utf8")
  .trim();
const sourceTreeAfterFixtureEvidence = git("rev-parse", "HEAD^{tree}")
  .toString("utf8")
  .trim();
if (
  git("status", "--porcelain").toString("utf8").trim() ||
  sourceRevisionAfterFixtureEvidence !== initialSourceRevision ||
  sourceTreeAfterFixtureEvidence !== initialSourceTree
) {
  throw new Error(
    "Exact fixture evidence changed the committed source revision or working tree",
  );
}
commandEvidence.push(
  legacyCommandEvidence(
    await runEngineAttestation(
      "exact-loaded-engine-attestation-after-evidence",
      engineIdentityAfterPath,
      portableEngineIdentityAfterPath,
    ),
  ),
);
const loadedEngineIdentityAfter = readOwnedJson(
  engineIdentityAfterPath,
  "post-evidence loaded engine identity",
);
if (
  canonicalJson(loadedEngineIdentityAfter) !==
  canonicalJson(loadedEngineIdentity)
) {
  throw new Error(
    "loaded engine identity changed across conformance evidence execution",
  );
}
const portableEngineIdentityAfterBytes = readOwnedJsonWithBytes(
  portableEngineIdentityAfterPath,
  "post-evidence portable engine identity marker",
).bytes;
const portableEngineIdentityAfter = parsePortableEngineIdentityMarker(
  portableEngineIdentityAfterBytes,
);
if (canonicalJson(portableEngineIdentityAfter) !== canonicalJson(portableEngineIdentity)) {
  throw new Error(
    "portable engine identity marker changed across conformance evidence execution",
  );
}
// A broad suite pass is prerequisite evidence, never a per-obligation pass.
// Only fixture-specific commands carrying their own result marker may enter
// `executions`; buildConformanceReport independently validates those records.
const suiteArtifactDigest = taggedDigest(
  Buffer.from(canonicalJson(commandEvidence), "utf8"),
);
const adapterEvidenceDigest = taggedDigest(
  fs.readFileSync(adapterEvidencePath),
);
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(
  outputPath,
  `${JSON.stringify(
    {
      executionArtifactSchema: "ibex/capsec-executions/1",
      sourceRevision: bindings.sourceRevision,
      sourceTreeDigest: bindings.sourceTreeDigest,
      target,
      engine: bindings.engine,
      ...(bindings.conformanceRunner === undefined
        ? {}
        : { conformanceRunner: bindings.conformanceRunner }),
      loadedEngineIdentity,
      bindingDigest,
      suiteArtifactDigest,
      recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
      adapterEvidenceDigest,
      publicSurfaceExecutionDigest:
        publicSurfaceEvidence.publicSurfaceExecutionDigest,
      ...(bindings.outputDispositionEvidenceRawContentDigest === undefined
        ? {}
        : {
            outputDispositionEvidenceRawContentDigest:
              bindings.outputDispositionEvidenceRawContentDigest,
          }),
      commands: commandEvidence,
      executions,
      portableProcessEvidence,
    },
    null,
    2,
  )}\n`,
);

const reportGeneratorArgs = [
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
  "--target",
  target.triple,
  "--output",
  reportPath,
];
if (outputDispositionEvidenceInputPath) {
  reportGeneratorArgs.push(
    "--output-disposition-evidence",
    path.resolve(repoRoot, outputDispositionEvidenceInputPath),
  );
}
await runObservedCommand({
  supervisor,
  id: "generate-conformance-report",
  command: process.execPath,
  args: reportGeneratorArgs,
  cwd: repoRoot,
  declaredInputs: [
    { name: "executions", digest: suiteArtifactDigest },
    {
      name: "recipeCatalog",
      digest: recipeCatalog.recipeCatalogDigest,
    },
    {
      name: "publicSurfaceExecutions",
      digest: publicSurfaceEvidence.publicSurfaceExecutionDigest,
    },
  ],
  expectedOutputs: [reportPath],
});
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
  assertRecipeCatalogComplete(recipeCatalog, {
    scopeDigest: scopeArtifact.scopeDigest,
    expandedEdgeIds: scopeArtifact.expandedCellIds,
  });
});
checkPromotion("public-surface-execution", () => {
  assertPublicSurfaceExecutionComplete(publicSurfaceEvidence, recipeCatalog, {
    target,
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    engine: bindings.engine,
    expandedEdgeIds: scopeArtifact.expandedCellIds,
    closureEdgeIds: scopeArtifact.expandedCellIds,
    expectedFixtureIds: catalog
      .filter((cell) => expandedScopeCellIds.has(cell.edgeId))
      .flatMap((cell) => cell.requiredFixtures),
  });
});
checkPromotion("output-disposition-evidence", () => {
  if (!validatedOutputDispositionEvidenceState) {
    throw new Error(
      "target promotion requires verified content-addressed output-disposition evidence",
    );
  }
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
  if (
    !promotionRefusals.some(({ check }) => check === "conformance-report") ||
    report.status !== "incomplete"
  ) {
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
    `${JSON.stringify(
      {
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
      },
      null,
      2,
    )}\n`,
  );
  console.log(
    `CapSec evidence complete; target remains intentionally unadvertised (${promotionRefusals
      .map(({ check }) => check)
      .join(", ")})`,
  );
}
supervisor.finish("success");
