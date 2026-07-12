import crypto from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  assertPublicSurfaceExecutionComplete,
  buildPublicFixtureEvidence,
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import {
  computeRecipeCatalogDigest,
  assertRecipeCatalogComplete,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const target = {
  triple: "aarch64-apple-darwin",
  features: ["frame-attribution", "native-lockdown"],
};
const engine = {
  kind: "hermes",
  engineArtifactPath: "/tmp/hermesvm",
  binaryDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  object: { platform: "apple", volume: "dev:1", file: "ino:2" },
  targetArchitecture: "aarch64",
  structuralFeatures: [...target.features],
};
const coverage = {
  edges: [
    {
      id: "edge.terminal",
      surface: { kind: "native-op", name: "__exactPublic" },
    },
  ],
};

function completeCatalog() {
  const recipe = {
    fixtureId: "fixture.public.allow",
    planDigest: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    classification: "effects",
    scenario: "allow",
    edgeIds: ["edge.public"],
    implementationBranchIds: ["edge.public.main"],
    enforcementBranchIds: ["enforcement.public"],
    actionIds: ["sys:read"],
    terminalObservedKey: "native-op:__exactPublic",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "enforcement.public",
    },
    route: {
      surfaceObservedKeys: ["builtin:export:node_test:read"],
      alternatives: [
        {
          terminalObservedKey: "native-op:__exactPublic",
          proofPaths: ["export:read -> __exactPublic"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_test:read",
      command: ["ibex", "capsec-public-fixture", "fixture.public.allow"],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:test",
        exportName: "read",
        sourceDescriptor: {
          kind: "builtin-export",
          sourceKey: "node_test",
          exportName: "read",
          moduleSpecifiers: ["node:test"],
          sourceRef: "src/builtins/test.js#exports:read",
        },
        arguments: [],
        expectedResult: "return",
        expectedTypedStages: ["requested"],
        expectedTypedDecisionCount: 1,
        allowedCoverageEdgeIds: ["edge.terminal", "edge.unselected"],
        expectedActionIds: ["sys:read"],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const descriptor = recipe.publicSurfaceProbe.invocation.sourceDescriptor;
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
    taggedDigest(descriptor);
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { allow: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function runtimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "return", valueType: "string" },
    },
    legacyObservationCount: 0,
    typedDecisions: [
      {
        decisionSet: {
          decisionSetSchema: "ibex/capsec-decision-set/1",
          operationId: "fixture-public",
          atomicityGroup: "edge.terminal.decision",
          combination: "conjunction",
          context: {
            stage: "requested",
            actor: { kind: "root", identity: "project-root" },
            constrainedPrincipals: [
              { kind: "root", identity: "project-root" },
            ],
            presentedHandleIds: [],
          },
          effects: [
            {
              cap: "sys:read",
              effectOwner: { kind: "root", identity: "project-root" },
              resource: {
                kind: "system-info-occurrence",
                requested: { kind: "system-info", name: "platform" },
              },
            },
          ],
        },
        gates: [
          {
            coverageEdgeId: "edge.terminal",
            targetCell: "complete",
            definitionAndEdgePredicatesSatisfied: true,
          },
        ],
        evidence: { outcome: "allow" },
      },
    ],
  };
}

function completeArtifact(catalog = completeCatalog()) {
  return buildPublicSurfaceExecutionArtifact({
    recipeCatalog: catalog,
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    target,
    engine,
    coverage,
    executions: [
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: runtimeObservation(catalog.recipes[0]),
        coverage,
      }),
    ],
  });
}

describe("CapSec public-surface promotion evidence", () => {
  test("merges only exact, engine-bound public fixture batches", () => {
    const catalog = completeCatalog();
    const execution = buildPublicFixtureEvidence({
      recipe: catalog.recipes[0],
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: runtimeObservation(catalog.recipes[0]),
      coverage,
    });
    const batch = {
      publicBatchEvidenceSchema: "ibex/capsec-public-batch-evidence/1",
      recipeCatalogDigest: catalog.recipeCatalogDigest,
      loadedEngineIdentity: engine,
      executions: [execution],
    };
    expect(
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toEqual([execution]);

    expect(() =>
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/duplicate public execution/);
    expect(() =>
      mergePublicBatchExecutions({
        batches: [{ batch: { ...batch, executions: [] }, expectedFixtureIds: [
          catalog.recipes[0].fixtureId,
        ] }],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/missing, duplicates, or adds/);
  });

  test("accepts one exact public invocation for every complete recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog, {
        target,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest:
          "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        engine,
        coverage,
        expectedFixtureIds: ["fixture.public.allow"],
      }),
    ).not.toThrow();
  });

  test("rejects adapter-only evidence explicitly", () => {
    const catalog = completeCatalog();
    expect(() =>
      validatePublicSurfaceExecutionArtifact(
        {
          adapterEvidenceSchema: "ibex/capsec-adapter-probe-evidence/1",
          recipeCatalogDigest: catalog.recipeCatalogDigest,
        },
        { recipeCatalog: catalog },
      ),
    ).toThrow(/adapter-only evidence cannot advertise/);
  });

  test("rejects a nominally complete recipe without an authored public probe", () => {
    const catalog = completeCatalog();
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    expect(() => assertRecipeCatalogComplete(catalog)).toThrow(
      /lacks an exact authored public-surface probe/,
    );
  });

  test("rejects residual or missing public obligations", () => {
    const catalog = completeCatalog();
    catalog.recipes[0].status = "unresolved";
    catalog.recipes[0].residualReasons = [
      "public-surface-invocation-not-authored",
    ];
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.summary.fullyExecutableFixtures = 0;
    catalog.summary.unresolvedFixtures = 1;
    catalog.summary.residualReasons = {
      "public-surface-invocation-not-authored": 1,
    };
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    const artifact = buildPublicSurfaceExecutionArtifact({
      recipeCatalog: catalog,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest:
        "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      target,
      engine,
      coverage,
      executions: [],
    });
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog),
    ).toThrow(/catalog is incomplete/);
  });

  test("rejects a terminal observation not bound by the recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    artifact.executions[0].evidence.terminalObservedKey =
      "native-op:__exactOther";
    expect(() =>
      validatePublicSurfaceExecutionArtifact(artifact, {
        recipeCatalog: catalog,
        coverage,
      }),
    ).toThrow(/digest-mismatched|stale or mismatched/);
  });

  test("rejects a manually supplied terminal label in runtime observations", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].terminalBranchId = "enforcement.public";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown or missing fields/);
  });

  test("derives the terminal from the bound coverage edge, not the static claim", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.unselected.decision";
    observed.typedDecisions[0].gates[0].coverageEdgeId = "edge.unselected";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown coverage edge/);
  });
});
