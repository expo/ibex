// Executed evidence for runtime-owned CapSec invariants. A scenario proof may
// cover many fixture rows, but every credited row still carries its own exact
// fixture plan, execution binding, result marker, and artifact digest.
//
// @ref LLP 0036#correctness-owed-the-deliberately-deferred-verification

import crypto from "node:crypto";
import {
  executionBindingDigest,
  fixtureExecutionPlan,
} from "./capsec-conformance.mjs";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  INTERNAL_INVARIANT_COMMAND,
  INTERNAL_INVARIANT_EXECUTOR,
  internalInvariantProofPlan,
} from "./capsec-internal-invariant-evidence.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const exactKeys = (value, keys, label) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort(compareText)) !==
      canonicalJson([...keys].sort(compareText))
  ) {
    throw new Error(`${label}: unexpected or missing fields`);
  }
};

export function internalInvariantEvidenceRecipes(recipeCatalog) {
  const recipes = recipeCatalog.recipes.filter(
    (recipe) => recipe.status === "internally-verified",
  );
  recipes.sort((left, right) => compareText(left.fixtureId, right.fixtureId));
  for (const recipe of recipes) {
    const expectedProof = internalInvariantProofPlan(recipe.scenario);
    if (
      expectedProof === null ||
      canonicalJson(recipe.internalInvariantProof) !==
        canonicalJson(expectedProof) ||
      recipe.publicSurfaceProbe !== null
    ) {
      throw new Error(
        `${recipe.fixtureId}: internal recipe lacks its source-derived proof plan`,
      );
    }
  }
  return recipes;
}

export function internalInvariantExecutionBinding({
  bindings,
  target,
  fixtureCatalogDigest,
}) {
  return {
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(bindings.engine),
    vocabularyDigest: bindings.vocabularyDigest,
    registryDigest: bindings.registryDigest,
    implementationManifestDigest: bindings.implementationManifestDigest,
    fixtureCatalogDigest,
    recipeCatalogDigest: bindings.recipeCatalogDigest,
    publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
  };
}

export function buildInternalInvariantEvidenceBindingArtifact({
  recipeCatalog,
  fixtureCatalog,
  bindings,
  target,
  fixtureCatalogDigest,
}) {
  const recipes = internalInvariantEvidenceRecipes(recipeCatalog);
  const executionBinding = internalInvariantExecutionBinding({
    bindings,
    target,
    fixtureCatalogDigest,
  });
  const fixturePlans = recipes.map((recipe) => {
    const plan = fixtureExecutionPlan(fixtureCatalog, recipe.fixtureId);
    if (!plan || digest(plan) !== recipe.planDigest) {
      throw new Error(
        `${recipe.fixtureId}: internal recipe disagrees with the exact fixture plan`,
      );
    }
    return plan;
  });
  return {
    internalInvariantEvidenceBindingSchema:
      "ibex/capsec-internal-invariant-evidence-binding/1",
    executionBinding,
    bindingDigest: executionBindingDigest({
      bindings,
      target,
      fixtureCatalogDigest,
    }),
    fixturePlans,
  };
}

function validateInternalRuntimeObservation(observation, recipe) {
  exactKeys(
    observation,
    [
      "observationSchema",
      "scenario",
      "mechanism",
      "proofPlanDigest",
      "result",
      "legacyObservationCount",
      "typedDecisions",
    ],
    `${recipe.fixtureId}: internal runtime observation`,
  );
  const proof = recipe.internalInvariantProof;
  if (
    observation.observationSchema !==
      "ibex/capsec-runtime-internal-invariant-observation/1" ||
    observation.scenario !== recipe.scenario ||
    observation.mechanism !== proof.mechanism ||
    observation.proofPlanDigest !== proof.proofPlanDigest ||
    observation.result?.kind !== "callback-security-invariant" ||
    observation.result?.scenario !== recipe.scenario ||
    observation.result?.outcome !== "passed" ||
    observation.legacyObservationCount !== 0 ||
    !Array.isArray(observation.typedDecisions)
  ) {
    throw new Error(
      `${recipe.fixtureId}: internal runtime observation did not execute its proof`,
    );
  }
}

export function validateInternalInvariantFixtureExecution(
  execution,
  {
    recipe,
    plan,
    engineBinaryDigest,
    executionBinding,
    bindingDigest,
  },
) {
  exactKeys(
    execution,
    [
      "fixtureId",
      "outcome",
      "executor",
      "artifactDigest",
      "bindingDigest",
      "evidence",
    ],
    `${recipe.fixtureId}: internal invariant execution`,
  );
  const evidence = execution.evidence;
  exactKeys(
    evidence,
    [
      "evidenceSchema",
      "fixtureId",
      "command",
      "exitCode",
      "resultMarker",
      "planDigest",
      "engineBinaryDigest",
      "fixturePlan",
      "executionBinding",
      "observation",
      "proofPlan",
      "runtimeObservation",
    ],
    `${recipe.fixtureId}: internal invariant evidence`,
  );
  validateInternalRuntimeObservation(evidence.runtimeObservation, recipe);
  const expectedObservation = { ...plan.expectedObservation, result: "passed" };
  if (
    recipe.status !== "internally-verified" ||
    execution.fixtureId !== recipe.fixtureId ||
    execution.outcome !== "passed" ||
    execution.executor !== INTERNAL_INVARIANT_EXECUTOR ||
    execution.bindingDigest !== bindingDigest ||
    evidence.evidenceSchema !==
      "ibex/capsec-internal-invariant-fixture-evidence/1" ||
    evidence.fixtureId !== recipe.fixtureId ||
    canonicalJson(evidence.command) !==
      canonicalJson(INTERNAL_INVARIANT_COMMAND) ||
    evidence.exitCode !== 0 ||
    evidence.resultMarker !==
      `ibex-capsec-internal-invariant:${recipe.fixtureId}:passed` ||
    evidence.planDigest !== recipe.planDigest ||
    evidence.planDigest !== digest(plan) ||
    evidence.engineBinaryDigest !== engineBinaryDigest ||
    canonicalJson(evidence.fixturePlan) !== canonicalJson(plan) ||
    canonicalJson(evidence.executionBinding) !==
      canonicalJson(executionBinding) ||
    canonicalJson(evidence.observation) !==
      canonicalJson(expectedObservation) ||
    canonicalJson(evidence.proofPlan) !==
      canonicalJson(recipe.internalInvariantProof) ||
    execution.artifactDigest !== digest(evidence)
  ) {
    throw new Error(
      `${recipe.fixtureId}: internal invariant evidence is stale or mismatched`,
    );
  }
  return execution;
}

export function validateInternalInvariantEvidenceArtifact(
  artifact,
  {
    recipeCatalog,
    fixtureCatalog,
    bindings,
    target,
    fixtureCatalogDigest,
  },
) {
  exactKeys(
    artifact,
    [
      "internalInvariantExecutionArtifactSchema",
      "executionBinding",
      "bindingDigest",
      "executions",
    ],
    "internal invariant execution artifact",
  );
  const expectedBinding = buildInternalInvariantEvidenceBindingArtifact({
    recipeCatalog,
    fixtureCatalog,
    bindings,
    target,
    fixtureCatalogDigest,
  });
  const recipes = internalInvariantEvidenceRecipes(recipeCatalog);
  const plans = new Map(
    expectedBinding.fixturePlans.map((plan) => [plan.fixtureId, plan]),
  );
  if (
    artifact.internalInvariantExecutionArtifactSchema !==
      "ibex/capsec-internal-invariant-executions/1" ||
    canonicalJson(artifact.executionBinding) !==
      canonicalJson(expectedBinding.executionBinding) ||
    artifact.bindingDigest !== expectedBinding.bindingDigest ||
    !Array.isArray(artifact.executions) ||
    canonicalJson(
      artifact.executions.map((execution) => execution.fixtureId),
    ) !== canonicalJson(recipes.map((recipe) => recipe.fixtureId))
  ) {
    throw new Error(
      "internal invariant evidence is stale, malformed, or incomplete",
    );
  }
  for (let index = 0; index < recipes.length; index += 1) {
    validateInternalInvariantFixtureExecution(artifact.executions[index], {
      recipe: recipes[index],
      plan: plans.get(recipes[index].fixtureId),
      engineBinaryDigest: bindings.engine.binaryDigest,
      executionBinding: expectedBinding.executionBinding,
      bindingDigest: expectedBinding.bindingDigest,
    });
  }
  return artifact;
}
