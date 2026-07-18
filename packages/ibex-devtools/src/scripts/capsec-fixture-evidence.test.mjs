import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  buildConformanceRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import {
  assertReportMayAdvertise,
  buildConformanceReport,
  fixtureCatalogForTarget,
} from "./capsec-conformance.mjs";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  validatePublicFixtureRuntimeObservation,
} from "./capsec-public-surface-evidence.mjs";
import {
  buildExactFixtureEvidenceBindingArtifact,
  EXACT_FIXTURE_EVIDENCE_COMMAND,
  exactFixtureEvidenceRecipes,
  validateExactFixtureEvidenceArtifact,
} from "./capsec-fixture-evidence.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value))
    .digest("base64url")}`;

function exactRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  let result;
  const mechanism =
    invocation.sourceDescriptor?.executionMechanism ?? invocation.operation?.kind;
  if (mechanism === "exact-host-call-round-trip") {
    result = {
      kind: "callback-security-invariant",
      scenario: "non-capability",
      outcome: "passed",
      checks: {
        executionMechanism: mechanism,
        setterInstalled: true,
        immutableCapability: true,
        genericBridgeAbsent: true,
        callbackExecuted: true,
        operationId: 7,
        payloadLength: 3,
        completion: "9,8",
        completionTargetsConsumed: 1,
        completionCallbacksQueued: 1,
        completionCallbacksDelivered: 1,
        singleUseCompletion: true,
      },
    };
  } else if (mechanism === "exact-endowment-install") {
    result = {
      kind: "callback-security-invariant",
      scenario: "non-capability",
      outcome: "passed",
      checks: {
        executionMechanism: mechanism,
        setterInstalled: true,
        immutableCapability: true,
        genericBridgeAbsent: true,
        baselineFinalized: true,
        refreshHookRemoved: true,
        callbackExecuted: false,
      },
    };
  } else if (mechanism === "exact-endowment-authorize") {
    result = {
      kind: "callback-security-invariant",
      scenario: "non-capability",
      outcome: "passed",
      checks: {
        executionMechanism: mechanism,
        contextClaimed: true,
        endowmentAuthorized: true,
        narrowedEndowmentRejected: true,
        contextKind: "app",
        operationIds: [7, 11],
        operationManifestDigest:
          "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA",
      },
    };
  } else if (mechanism === "exact-artifact-prepare-round-trip") {
    result = {
      kind: "callback-security-invariant",
      scenario: "non-capability",
      outcome: "passed",
      checks: {
        executionMechanism: mechanism,
        artifactPrepared: true,
        artifactSchema: "ibex/armed-embedder-artifacts/1",
        nonceFreshened: true,
        digestRebound: true,
        sourceDigest: `sha256-${"H".repeat(43)}`,
        preparedDigest: `sha256-${"I".repeat(43)}`,
        preparedPairAuthenticated: true,
      },
    };
  } else if (mechanism === "exact-unendowed-operation") {
    result = {
      kind: "closed",
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      mechanism,
      errorName: "ClosedSurface",
      errorMessage: invocation.operation.expectedError,
      engineExecuted: true,
      projectCodeExecuted: false,
    };
  } else {
    throw new Error(`unexpected Exact pilot mechanism ${mechanism}`);
  }
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      ...(recipe.scenario === "non-capability"
        ? { scenario: invocation.scenario }
        : {}),
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result,
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

describe("Exact fixture-evidence pilot", () => {
  let context;
  let artifact;

  beforeAll(async () => {
    const coverage = readJson("capsec/registry/coverage-edges.json");
    const implementation = readJson(
      "capsec/generated/implementation-manifest.json",
    );
    const rules = readJson("capsec/registry/policy-rules.json");
    const target = rules.initialProfile.candidateTargets[0];
    const fixtureCatalog = fixtureCatalogForTarget({
      coverage,
      implementation,
      target,
    });
    const recipeCatalog = buildConformanceRecipeCatalog({
      catalog: fixtureCatalog,
      coverage,
      implementation,
      inventory: await discoverRepositorySurfaces(repoRoot),
      occurrenceExamples: readJson(
        "capsec/examples/effect-occurrences.canonical.json",
      ),
      selectorExamples: readJson(
        "capsec/examples/authority-selectors.canonical.json",
      ),
      capabilityDefinitions: readJson(
        "capsec/registry/capability-definitions.json",
      ),
      target,
    });
    const fixtureCatalogDigest = digest(fixtureCatalog);
    const bindings = {
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: `sha256-${"B".repeat(43)}`,
      engine: {
        engineArtifactPath: "/repo/hermesvm",
        kind: "hermes",
        binaryDigest: `sha256-${"C".repeat(43)}`,
        object: { platform: "apple", volume: "dev:1", file: "ino:2" },
        targetArchitecture: target.triple.split("-")[0],
        structuralFeatures: target.features,
      },
      vocabularyDigest: `sha256-${"D".repeat(43)}`,
      registryDigest: `sha256-${"E".repeat(43)}`,
      implementationManifestDigest: digest(implementation),
      recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
      publicSurfaceExecutionDigest: `sha256-${"F".repeat(43)}`,
    };
    const bindingArtifact = buildExactFixtureEvidenceBindingArtifact({
      recipeCatalog,
      fixtureCatalog,
      bindings,
      target,
      fixtureCatalogDigest,
    });
    const plans = new Map(
      bindingArtifact.fixturePlans.map((plan) => [plan.fixtureId, plan]),
    );
    const executions = exactFixtureEvidenceRecipes(recipeCatalog).map(
      (recipe) => {
        const plan = plans.get(recipe.fixtureId);
        const evidence = {
          evidenceSchema: "ibex/capsec-fixture-evidence/2",
          fixtureId: recipe.fixtureId,
          command: EXACT_FIXTURE_EVIDENCE_COMMAND,
          exitCode: 0,
          resultMarker: `ibex-capsec-fixture:${recipe.fixtureId}:passed`,
          planDigest: recipe.planDigest,
          engineBinaryDigest: bindings.engine.binaryDigest,
          fixturePlan: plan,
          executionBinding: bindingArtifact.executionBinding,
          observation: { ...plan.expectedObservation, result: "passed" },
          runtimeObservation: exactRuntimeObservation(recipe),
        };
        return {
          fixtureId: recipe.fixtureId,
          outcome: "passed",
          executor: "ibex-exact-fixture-evidence-pilot",
          artifactDigest: digest(evidence),
          bindingDigest: bindingArtifact.bindingDigest,
          evidence,
        };
      },
    );
    artifact = {
      executionArtifactSchema: "ibex/capsec-executions/1",
      executionBinding: bindingArtifact.executionBinding,
      bindingDigest: bindingArtifact.bindingDigest,
      executions,
    };
    context = {
      recipeCatalog,
      fixtureCatalog,
      coverage,
      implementation,
      bindings,
      target,
      fixtureCatalogDigest,
      digestContract: rules.digestContract,
    };
  }, 60_000);

  test("accepts exactly nine independently bound runtime observations", () => {
    expect(() =>
      validateExactFixtureEvidenceArtifact(artifact, context),
    ).not.toThrow();
    expect(artifact.executions).toHaveLength(9);
  });

  test("credits exactly nine actual fixtures and keeps promotion closed", () => {
    const report = buildConformanceReport({
      coverage: context.coverage,
      implementation: context.implementation,
      target: context.target,
      executions: artifact.executions,
      bindings: context.bindings,
      digestContract: context.digestContract,
      recipeCatalog: context.recipeCatalog,
      validateRuntimeObservation: validatePublicFixtureRuntimeObservation,
    });
    expect(report.status).toBe("incomplete");
    expect(report.summary).toMatchObject({
      cells: 7_109,
      conformantCells: 1,
      incompleteCells: 7_108,
      requiredFixtures: 22_933,
      passedFixtures: 9,
      missingFixtures: 22_924,
      failedFixtures: 0,
    });
    expect(() => assertReportMayAdvertise(report)).toThrow(/incomplete/u);
  });

  test("fails closed on stale source or semantic bindings", () => {
    const stale = structuredClone(artifact);
    stale.executionBinding.sourceRevision = "b".repeat(40);
    expect(() =>
      validateExactFixtureEvidenceArtifact(stale, context),
    ).toThrow(/stale|bound to another/u);

    const stalePublic = structuredClone(artifact);
    stalePublic.executionBinding.publicSurfaceExecutionDigest =
      `sha256-${"Z".repeat(43)}`;
    expect(() =>
      validateExactFixtureEvidenceArtifact(stalePublic, context),
    ).toThrow(/stale|bound to another/u);
  });

  test("fails closed on missing or duplicate fixture evidence", () => {
    const missing = structuredClone(artifact);
    missing.executions.pop();
    expect(() =>
      validateExactFixtureEvidenceArtifact(missing, context),
    ).toThrow(/exactly one/u);

    const duplicate = structuredClone(artifact);
    duplicate.executions[6] = structuredClone(duplicate.executions[0]);
    expect(() =>
      validateExactFixtureEvidenceArtifact(duplicate, context),
    ).toThrow(/exactly one/u);
  });

  test("fails closed on mismatched plan, engine, or runtime observation", () => {
    const wrongPlan = structuredClone(artifact);
    wrongPlan.executions[0].evidence.fixturePlan.terminalObservedKey =
      "callback:wrong";
    expect(() =>
      validateExactFixtureEvidenceArtifact(wrongPlan, context),
    ).toThrow(/stale|mismatched/u);

    const wrongEngine = structuredClone(artifact);
    wrongEngine.executions[0].evidence.engineBinaryDigest =
      `sha256-${"Z".repeat(43)}`;
    expect(() =>
      validateExactFixtureEvidenceArtifact(wrongEngine, context),
    ).toThrow(/stale|mismatched/u);

    const wrongRuntime = structuredClone(artifact);
    wrongRuntime.executions[0].evidence.runtimeObservation.invocation.result.checks.completion =
      "9,8,7";
    expect(() =>
      validateExactFixtureEvidenceArtifact(wrongRuntime, context),
    ).toThrow(/single-use Exact completion route/u);
    wrongRuntime.executions[0].artifactDigest = digest(
      wrongRuntime.executions[0].evidence,
    );
    expect(() =>
      buildConformanceReport({
        coverage: context.coverage,
        implementation: context.implementation,
        target: context.target,
        executions: wrongRuntime.executions,
        bindings: context.bindings,
        digestContract: context.digestContract,
        recipeCatalog: context.recipeCatalog,
        validateRuntimeObservation: validatePublicFixtureRuntimeObservation,
      }),
    ).toThrow(/single-use Exact completion route/u);
  }, 15_000);
});
