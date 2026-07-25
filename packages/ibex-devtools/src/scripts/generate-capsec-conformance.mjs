#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import { fileURLToPath } from "node:url";
import {
  buildConformanceReport,
  selectCandidateTarget,
  validateConformanceReportSemantics,
} from "./capsec-conformance.mjs";
import { validateRecipeCatalog } from "./capsec-conformance-recipes.mjs";
import {
  validatePublicFixtureRuntimeObservation,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import {
  canonicalJson,
  parseJsonStrict,
  readJsonStrict,
} from "./capsec-contract.mjs";
import { validateLoadedEngineIdentity } from "./capsec-engine-identity.mjs";
import { validateInternalInvariantFixtureExecution } from "./capsec-internal-invariant-execution.mjs";
import { validatePromotableOutputDispositionEvidence } from "./capsec-output-shape-sweep.mjs";

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
  option("--output") ?? "target/capsec-conformance-report.json",
);
const enginePath = path.resolve(
  repoRoot,
  option("--engine") ?? "tools/hermes/hermes",
);
const executionsPath = option("--executions");
const recipeCatalogPath = option("--recipe-catalog");
const publicSurfaceExecutionsPath = option("--public-surface-executions");
const outputDispositionEvidencePath = option(
  "--output-disposition-evidence",
);

const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) =>
  execFileSync("git", gitArgs, { cwd: repoRoot, timeout: 30_000 });
if (!fs.existsSync(enginePath))
  throw new Error(`Hermes engine artifact not found: ${enginePath}`);
if (git("status", "--porcelain").toString("utf8").trim()) {
  throw new Error("conformance generation requires a clean committed source tree");
}
if (!executionsPath || !recipeCatalogPath || !publicSurfaceExecutionsPath) {
  throw new Error(
    "conformance generation requires fixture, recipe, and public-surface execution artifacts from the exact loaded-engine runner",
  );
}
const executionArtifact = readJsonStrict(path.resolve(repoRoot, executionsPath));
if (
  executionArtifact.executionArtifactSchema !== "ibex/capsec-executions/1" ||
  !Array.isArray(executionArtifact.executions)
) {
  throw new Error("execution artifact is malformed");
}
const loadedEngineIdentity = executionArtifact.loadedEngineIdentity;
const engineDigest = taggedDigest(fs.readFileSync(enginePath));

const manifest = readJsonStrict(path.join(capsecRoot, "contract-files.json"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const relativePath of manifest.schemas) {
  ajv.addSchema(readJsonStrict(path.join(capsecRoot, relativePath)));
}

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
const target = selectCandidateTarget(rules, option("--target"));
const engineBinding = validateLoadedEngineIdentity({
  identity: loadedEngineIdentity,
  canonicalArtifactPath: fs.realpathSync(enginePath),
  binaryDigest: engineDigest,
  target,
});
if (
  executionArtifact.sourceRevision !==
    git("rev-parse", "HEAD").toString("utf8").trim() ||
  executionArtifact.sourceTreeDigest !==
    taggedDigest(git("rev-parse", "HEAD^{tree}")) ||
  canonicalJson(executionArtifact.target) !== canonicalJson(target) ||
  canonicalJson(executionArtifact.engine) !== canonicalJson(engineBinding)
) {
  throw new Error(
    "execution artifact source or engine binding differs from this checkout",
  );
}
const recipeCatalog = readJsonStrict(path.resolve(repoRoot, recipeCatalogPath));
validateRecipeCatalog(recipeCatalog, { target });
const publicSurfaceExecutions = readJsonStrict(
  path.resolve(repoRoot, publicSurfaceExecutionsPath),
);
validatePublicSurfaceExecutionArtifact(publicSurfaceExecutions, {
  recipeCatalog,
  target,
  sourceRevision: executionArtifact.sourceRevision,
  sourceTreeDigest: executionArtifact.sourceTreeDigest,
  engine: engineBinding,
  coverage,
});
if (
  executionArtifact.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
  executionArtifact.publicSurfaceExecutionDigest !==
    publicSurfaceExecutions.publicSurfaceExecutionDigest
) {
  throw new Error(
    "fixture execution artifact is not bound to the exact recipe/public-surface evidence",
  );
}
let outputDispositionEvidenceRawContentDigest;
if (outputDispositionEvidencePath) {
  const evidenceBytes = fs.readFileSync(
    path.resolve(repoRoot, outputDispositionEvidencePath),
  );
  const outputDispositionEvidence = parseJsonStrict(
    evidenceBytes,
    "output-disposition evidence artifact",
  );
  const validateOutputDispositionEvidence = ajv.getSchema(
    "https://ibex.dev/capsec/schema/output-disposition-evidence.schema.json",
  );
  if (!validateOutputDispositionEvidence?.(outputDispositionEvidence)) {
    throw new Error(
      `invalid output-disposition evidence artifact: ${ajv.errorsText(validateOutputDispositionEvidence?.errors)}`,
    );
  }
  const evidenceState = validatePromotableOutputDispositionEvidence({
    catalog: readJsonStrict(
      path.join(capsecRoot, "generated/output-shape-catalog.json"),
    ),
    dispositionRows: readJsonStrict(
      path.join(capsecRoot, "generated/output-dispositions.json"),
    ).rows,
    evidence: outputDispositionEvidence,
    conformanceRunner: executionArtifact.conformanceRunner,
  });
  if (
    evidenceState.sourceRevision !== executionArtifact.sourceRevision ||
    evidenceState.sourceTreeDigest !== executionArtifact.sourceTreeDigest ||
    canonicalJson(evidenceState.target) !== canonicalJson(target) ||
    canonicalJson(evidenceState.engine) !== canonicalJson(engineBinding) ||
    canonicalJson(evidenceState.conformanceRunner) !==
      canonicalJson(executionArtifact.conformanceRunner)
  ) {
    throw new Error(
      "output-disposition evidence source, target, loaded engine, or conformance runner differs from this execution",
    );
  }
  outputDispositionEvidenceRawContentDigest = taggedDigest(evidenceBytes);
  if (
    executionArtifact.outputDispositionEvidenceRawContentDigest !==
    outputDispositionEvidenceRawContentDigest
  ) {
    throw new Error(
      "fixture execution artifact is not bound to the exact output-disposition evidence bytes",
    );
  }
} else if (
  executionArtifact.outputDispositionEvidenceRawContentDigest !== undefined
) {
  throw new Error(
    "fixture execution artifact binds output-disposition evidence that was not supplied",
  );
}
const vocabularyDigest = registryBundle.members.find(
  (member) => member.logicalName === "vocab-digest",
)?.document?.digest;
const registryDigest = digestVectors.vectors.find(
  (vector) => vector.id === "registry",
)?.expectedDigest;
if (!vocabularyDigest || !registryDigest)
  throw new Error("semantic digest identities are unavailable");

const executions = executionArtifact.executions;

const report = buildConformanceReport({
  coverage,
  implementation,
  target,
  executions,
  bindings: {
    sourceRevision: git("rev-parse", "HEAD").toString("utf8").trim(),
    sourceTreeDigest: taggedDigest(git("rev-parse", "HEAD^{tree}")),
    engine: {
      ...engineBinding,
    },
    vocabularyDigest,
    registryDigest,
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    publicSurfaceExecutionDigest:
      publicSurfaceExecutions.publicSurfaceExecutionDigest,
    ...(outputDispositionEvidenceRawContentDigest === undefined
      ? {}
      : { outputDispositionEvidenceRawContentDigest }),
  },
  digestContract: rules.digestContract,
  recipeCatalog,
  validateRuntimeObservation: validatePublicFixtureRuntimeObservation,
  validateInternalInvariantExecution:
    validateInternalInvariantFixtureExecution,
});
const validate = ajv.getSchema(
  "https://ibex.dev/capsec/schema/conformance-report.schema.json",
);
if (!validate?.(report))
  throw new Error(
    `invalid conformance report: ${ajv.errorsText(validate?.errors)}`,
  );
validateConformanceReportSemantics(report, {
  coverage,
  implementation,
  target,
  digestContract: rules.digestContract,
  recipeCatalog,
  validateRuntimeObservation: validatePublicFixtureRuntimeObservation,
  validateInternalInvariantExecution:
    validateInternalInvariantFixtureExecution,
});
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(
  JSON.stringify({
    output: path.relative(repoRoot, outputPath),
    status: report.status,
    ...report.summary,
  }),
);
if (args.includes("--require-conformant") && report.status !== "conformant")
  process.exitCode = 1;
