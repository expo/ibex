// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — only
// independently executed, exact-fixture evidence can reduce report residuals.

import crypto from "node:crypto";
import {
  executionBindingDigest,
  fixtureExecutionPlan,
} from "./capsec-conformance.mjs";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  validatePublicFixtureRuntimeObservation,
} from "./capsec-public-surface-evidence.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value))
    .digest("base64url")}`;

export const EXACT_FIXTURE_EVIDENCE_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_exact_fixture_evidence_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

const EXACT_PILOT_SURFACES = new Map([
  [
    "callback:exact-host-call-async-resolve",
    ["non-capability", "exact-host-call-round-trip"],
  ],
  [
    "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
    ["non-capability", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_resolve_exact_host_call",
    ["non-capability", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_set_exact_host_call_async",
    ["non-capability", "exact-endowment-install"],
  ],
  [
    "host-abi:ex_host_authorize_exact_endowment",
    ["non-capability", "exact-endowment-authorize"],
  ],
  [
    "host-abi:ex_host_prepare_armed_embedder_artifacts",
    ["non-capability", "exact-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
    ["non-capability", "exact-artifact-prepare-round-trip"],
  ],
  [
    "native-op:global:exact.invokeHostAsync",
    ["closed", "exact-unendowed-operation"],
  ],
]);

function exactKeys(value, keys, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort(compareText)) !==
      canonicalJson([...keys].sort(compareText))
  ) {
    throw new Error(`${label}: unexpected or missing fields`);
  }
}

function recipeMechanism(recipe) {
  const invocation = recipe.publicSurfaceProbe?.invocation;
  return (
    invocation?.sourceDescriptor?.executionMechanism ?? invocation?.operation?.kind
  );
}

export function exactFixtureEvidenceRecipes(recipeCatalog) {
  const recipes = recipeCatalog.recipes.filter((recipe) => {
    const expected = EXACT_PILOT_SURFACES.get(recipe.terminalObservedKey);
    return (
      expected !== undefined &&
      recipe.status === "fully-executable" &&
      recipe.scenario === expected[0] &&
      recipeMechanism(recipe) === expected[1]
    );
  });
  recipes.sort((left, right) => compareText(left.fixtureId, right.fixtureId));
  if (
    recipes.length !== EXACT_PILOT_SURFACES.size ||
    new Set(recipes.map((recipe) => recipe.terminalObservedKey)).size !==
      EXACT_PILOT_SURFACES.size
  ) {
    throw new Error(
      "Exact fixture-evidence pilot requires exactly seven source-bound recipes",
    );
  }
  return recipes;
}

export function exactFixtureExecutionBinding({
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

export function buildExactFixtureEvidenceBindingArtifact({
  recipeCatalog,
  fixtureCatalog,
  bindings,
  target,
  fixtureCatalogDigest,
}) {
  const recipes = exactFixtureEvidenceRecipes(recipeCatalog);
  const executionBinding = exactFixtureExecutionBinding({
    bindings,
    target,
    fixtureCatalogDigest,
  });
  const fixturePlans = recipes.map((recipe) => {
    const plan = fixtureExecutionPlan(fixtureCatalog, recipe.fixtureId);
    if (!plan || digest(plan) !== recipe.planDigest) {
      throw new Error(
        `${recipe.fixtureId}: executable recipe disagrees with the exact fixture plan`,
      );
    }
    return plan;
  });
  return {
    fixtureEvidenceBindingSchema: "ibex/capsec-fixture-evidence-binding/1",
    executionBinding,
    bindingDigest: executionBindingDigest({
      bindings,
      target,
      fixtureCatalogDigest,
    }),
    fixturePlans,
  };
}

export function validateExactFixtureEvidenceArtifact(
  artifact,
  {
    recipeCatalog,
    fixtureCatalog,
    coverage,
    bindings,
    target,
    fixtureCatalogDigest,
  },
) {
  exactKeys(
    artifact,
    ["executionArtifactSchema", "executionBinding", "bindingDigest", "executions"],
    "Exact fixture-evidence artifact",
  );
  const expectedBindingArtifact = buildExactFixtureEvidenceBindingArtifact({
    recipeCatalog,
    fixtureCatalog,
    bindings,
    target,
    fixtureCatalogDigest,
  });
  if (
    artifact.executionArtifactSchema !== "ibex/capsec-executions/1" ||
    canonicalJson(artifact.executionBinding) !==
      canonicalJson(expectedBindingArtifact.executionBinding) ||
    artifact.bindingDigest !== expectedBindingArtifact.bindingDigest ||
    !Array.isArray(artifact.executions)
  ) {
    throw new Error(
      "Exact fixture evidence is stale, malformed, or bound to another source/target/engine",
    );
  }

  const recipes = exactFixtureEvidenceRecipes(recipeCatalog);
  const expectedIds = recipes.map((recipe) => recipe.fixtureId);
  const observedIds = artifact.executions.map((execution) => execution?.fixtureId);
  if (
    canonicalJson(observedIds) !== canonicalJson(expectedIds) ||
    new Set(observedIds).size !== expectedIds.length
  ) {
    throw new Error(
      "Exact fixture evidence must contain exactly one canonically ordered record for each pilot fixture",
    );
  }

  const plans = new Map(
    expectedBindingArtifact.fixturePlans.map((plan) => [plan.fixtureId, plan]),
  );
  for (let index = 0; index < artifact.executions.length; index += 1) {
    const execution = artifact.executions[index];
    const recipe = recipes[index];
    const plan = plans.get(recipe.fixtureId);
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
      `${recipe.fixtureId}: Exact fixture execution`,
    );
    exactKeys(
      execution.evidence,
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
        "runtimeObservation",
      ],
      `${recipe.fixtureId}: Exact fixture evidence`,
    );
    const evidence = execution.evidence;
    const runtimeTerminal = validatePublicFixtureRuntimeObservation(
      evidence.runtimeObservation,
      recipe,
      coverage,
    );
    if (
      execution.fixtureId !== recipe.fixtureId ||
      execution.outcome !== "passed" ||
      execution.executor !== "ibex-exact-fixture-evidence-pilot" ||
      execution.bindingDigest !== expectedBindingArtifact.bindingDigest ||
      evidence.evidenceSchema !== "ibex/capsec-fixture-evidence/2" ||
      evidence.fixtureId !== recipe.fixtureId ||
      canonicalJson(evidence.command) !==
        canonicalJson(EXACT_FIXTURE_EVIDENCE_COMMAND) ||
      evidence.exitCode !== 0 ||
      evidence.resultMarker !==
        `ibex-capsec-fixture:${recipe.fixtureId}:passed` ||
      evidence.planDigest !== recipe.planDigest ||
      evidence.planDigest !== digest(plan) ||
      evidence.engineBinaryDigest !== bindings.engine.binaryDigest ||
      canonicalJson(evidence.fixturePlan) !== canonicalJson(plan) ||
      canonicalJson(evidence.executionBinding) !==
        canonicalJson(expectedBindingArtifact.executionBinding) ||
      runtimeTerminal !== recipe.terminalObservedKey ||
      canonicalJson(evidence.observation) !==
        canonicalJson({ ...plan.expectedObservation, result: "passed" }) ||
      execution.artifactDigest !== digest(evidence)
    ) {
      throw new Error(
        `${recipe.fixtureId}: Exact fixture evidence is stale, mismatched, or did not execute its bound mechanism`,
      );
    }
  }
  return artifact;
}
