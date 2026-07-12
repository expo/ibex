/**
 * Validate content-addressed evidence that every exact-target recipe invoked
 * its authored public surface and observed the selected enforcement terminal.
 * Typed-adapter probes are deliberately a different schema and are never
 * accepted here.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target promotion requires executed public obligations, not adapter checks.
 */

import crypto from "node:crypto";
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;

function exactKeys(value, keys, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort(compareText)) !==
      canonicalJson([...keys].sort(compareText))
  ) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function evidenceDigest(evidence) {
  const { evidenceDigest: _digest, ...payload } = evidence;
  return taggedDigest(payload);
}

export function computePublicSurfaceExecutionDigest(artifact) {
  const { publicSurfaceExecutionDigest: _digest, ...payload } = artifact;
  return taggedDigest(payload);
}

function executionSummary(recipeCatalog, executions) {
  return {
    requiredFixtures: recipeCatalog.summary.requiredFixtures,
    executableFixtures: recipeCatalog.summary.fullyExecutableFixtures,
    residualFixtures: recipeCatalog.summary.unresolvedFixtures,
    executedFixtures: executions.length,
    passedFixtures: executions.filter((execution) => execution.outcome === "passed")
      .length,
    failedFixtures: executions.filter((execution) => execution.outcome === "failed")
      .length,
    missingFixtures: recipeCatalog.summary.requiredFixtures - executions.length,
  };
}

export function buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
  executions = [],
}) {
  validateRecipeCatalog(recipeCatalog, { target });
  const sortedExecutions = [...executions].sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
  const artifact = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    summary: executionSummary(recipeCatalog, sortedExecutions),
    executions: sortedExecutions,
  };
  artifact.publicSurfaceExecutionDigest =
    computePublicSurfaceExecutionDigest(artifact);
  return validatePublicSurfaceExecutionArtifact(artifact, {
    recipeCatalog,
    target,
    sourceRevision,
    sourceTreeDigest,
    engine,
  });
}

function validateExecution(execution, recipe, engineBinaryDigest) {
  exactKeys(
    execution,
    ["fixtureId", "outcome", "executor", "evidence"],
    `${recipe.fixtureId}: public execution`,
  );
  exactKeys(
    execution.evidence,
    [
      "evidenceSchema",
      "fixtureId",
      "planDigest",
      "engineBinaryDigest",
      "probe",
      "terminalObservedKey",
      "exitCode",
      "resultMarker",
      "observation",
      "evidenceDigest",
    ],
    `${recipe.fixtureId}: public execution evidence`,
  );
  const evidence = execution.evidence;
  if (
    execution.fixtureId !== recipe.fixtureId ||
    evidence.evidenceSchema !==
      "ibex/capsec-public-surface-fixture-evidence/1" ||
    evidence.fixtureId !== recipe.fixtureId ||
    typeof execution.executor !== "string" ||
    execution.executor.length === 0 ||
    /adapter/iu.test(execution.executor) ||
    evidence.planDigest !== recipe.planDigest ||
    evidence.engineBinaryDigest !== engineBinaryDigest ||
    canonicalJson(evidence.probe) !== canonicalJson(recipe.publicSurfaceProbe) ||
    evidence.evidenceDigest !== evidenceDigest(evidence)
  ) {
    throw new Error(
      `${recipe.fixtureId}: adapter-only, stale, or malformed public-surface evidence`,
    );
  }
  const passedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:passed`;
  const failedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:failed`;
  const derivedOutcome =
    evidence.exitCode === 0 && evidence.resultMarker === passedMarker
      ? "passed"
      : evidence.exitCode !== 0 || evidence.resultMarker === failedMarker
        ? "failed"
        : null;
  if (!derivedOutcome || derivedOutcome !== execution.outcome) {
    throw new Error(`${recipe.fixtureId}: public result marker disagrees with outcome`);
  }
  const expectedObservation = {
    ...recipe.expectedObservation,
    result: derivedOutcome,
  };
  if (canonicalJson(evidence.observation) !== canonicalJson(expectedObservation)) {
    throw new Error(`${recipe.fixtureId}: public observation selected the wrong branch`);
  }
  const allowedTerminals =
    recipe.expectedObservation.kind === "target-absence"
      ? [recipe.terminalObservedKey]
      : recipe.route.alternatives.map(
          (alternative) => alternative.terminalObservedKey,
        );
  if (!allowedTerminals.includes(evidence.terminalObservedKey)) {
    throw new Error(`${recipe.fixtureId}: public execution observed an unbound terminal`);
  }
}

export function validatePublicSurfaceExecutionArtifact(
  artifact,
  {
    recipeCatalog,
    target = null,
    sourceRevision = null,
    sourceTreeDigest = null,
    engine = null,
  },
) {
  if (artifact?.adapterEvidenceSchema) {
    throw new Error("adapter-only evidence cannot advertise a target");
  }
  exactKeys(
    artifact,
    [
      "publicSurfaceExecutionSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "recipeCatalogDigest",
      "summary",
      "executions",
      "publicSurfaceExecutionDigest",
    ],
    "public-surface execution artifact",
  );
  if (
    artifact.publicSurfaceExecutionSchema !==
      "ibex/capsec-public-surface-executions/1" ||
    artifact.profile !== "ibex/capsec/1" ||
    !Array.isArray(artifact.executions) ||
    artifact.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
    artifact.publicSurfaceExecutionDigest !==
      computePublicSurfaceExecutionDigest(artifact) ||
    (target && canonicalJson(artifact.target) !== canonicalJson(target)) ||
    (sourceRevision && artifact.sourceRevision !== sourceRevision) ||
    (sourceTreeDigest && artifact.sourceTreeDigest !== sourceTreeDigest) ||
    (engine && canonicalJson(artifact.engine) !== canonicalJson(engine))
  ) {
    throw new Error("public-surface execution artifact has stale or mismatched bindings");
  }
  validateRecipeCatalog(recipeCatalog, { target: artifact.target });
  const recipes = new Map(
    recipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const seen = new Set();
  for (const execution of artifact.executions) {
    const recipe = recipes.get(execution?.fixtureId);
    if (!recipe || seen.has(execution.fixtureId)) {
      throw new Error("public-surface executions contain an unknown or duplicate fixture");
    }
    seen.add(execution.fixtureId);
    validateExecution(execution, recipe, artifact.engine?.binaryDigest);
  }
  if (
    canonicalJson(artifact.executions.map((row) => row.fixtureId)) !==
    canonicalJson([...seen].sort(compareText))
  ) {
    throw new Error("public-surface executions are not in canonical fixture order");
  }
  if (
    canonicalJson(artifact.summary) !==
    canonicalJson(executionSummary(recipeCatalog, artifact.executions))
  ) {
    throw new Error("public-surface execution summary disagrees with its evidence");
  }
  return artifact;
}

export function assertPublicSurfaceExecutionComplete(
  artifact,
  recipeCatalog,
  options = {},
) {
  assertRecipeCatalogComplete(recipeCatalog, {
    target: options.target ?? artifact.target,
    expectedFixtureIds: options.expectedFixtureIds ?? null,
  });
  validatePublicSurfaceExecutionArtifact(artifact, {
    ...options,
    recipeCatalog,
  });
  if (
    artifact.summary.residualFixtures !== 0 ||
    artifact.summary.missingFixtures !== 0 ||
    artifact.summary.failedFixtures !== 0 ||
    artifact.summary.executedFixtures !== artifact.summary.requiredFixtures ||
    artifact.summary.passedFixtures !== artifact.summary.requiredFixtures
  ) {
    throw new Error(
      "public-surface execution artifact cannot advertise with residual, missing, or failed obligations",
    );
  }
}

export function buildPublicFixtureEvidence({
  recipe,
  engineBinaryDigest,
  terminalObservedKey,
  outcome = "passed",
  executor = "ibex-public-surface-harness",
}) {
  const evidence = {
    evidenceSchema: "ibex/capsec-public-surface-fixture-evidence/1",
    fixtureId: recipe.fixtureId,
    planDigest: recipe.planDigest,
    engineBinaryDigest,
    probe: structuredClone(recipe.publicSurfaceProbe),
    terminalObservedKey,
    exitCode: outcome === "passed" ? 0 : 1,
    resultMarker: `ibex-capsec-public-fixture:${recipe.fixtureId}:${outcome}`,
    observation: { ...recipe.expectedObservation, result: outcome },
  };
  evidence.evidenceDigest = evidenceDigest(evidence);
  return {
    fixtureId: recipe.fixtureId,
    outcome,
    executor,
    evidence,
  };
}
