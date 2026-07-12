import { describe, expect, test } from "bun:test";
import {
  assertPublicSurfaceExecutionComplete,
  buildPublicFixtureEvidence,
  buildPublicSurfaceExecutionArtifact,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import {
  computeRecipeCatalogDigest,
  assertRecipeCatalogComplete,
} from "./capsec-conformance-recipes.mjs";

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
    },
    status: "fully-executable",
    residualReasons: [],
  };
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

function completeArtifact(catalog = completeCatalog()) {
  return buildPublicSurfaceExecutionArtifact({
    recipeCatalog: catalog,
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    target,
    engine,
    executions: [
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        terminalObservedKey: "native-op:__exactPublic",
      }),
    ],
  });
}

describe("CapSec public-surface promotion evidence", () => {
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
      }),
    ).toThrow(/digest-mismatched|stale or mismatched/);
  });
});
