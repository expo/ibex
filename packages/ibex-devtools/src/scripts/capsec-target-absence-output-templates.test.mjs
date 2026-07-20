import crypto from "node:crypto";
import { describe, expect, test } from "bun:test";
import { canonicalJson } from "./capsec-contract.mjs";
import { computeRecipeCatalogDigest } from "./capsec-conformance-recipes.mjs";
import { authoredTargetAbsenceOutputBindings } from "./capsec-target-absence-output-templates.mjs";

const edge = Object.freeze({
  id: "surface.native.op.exactosrelease.test",
  classification: "non-capability",
  surface: { kind: "native-op", name: "__exactOSRelease" },
});

const key = Object.freeze({
  surfaceId: edge.id,
  output: "[[value]]",
  alias: "process.__exactOSRelease",
  mode: "all",
  sourceKind: "native-op",
  returnVariant: "default",
  contextId: "javascript.package-property-read-loaded",
});

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function fixture() {
  const sourceRef =
    "src/engine/hermes_runtime_android.cc#jsi-global-property:process.__exactOSRelease";
  const sourceDescriptor = {
    kind: "target-absent-native-operation",
    surfaceKind: edge.surface.kind,
    surfaceName: edge.surface.name,
    sourceRefs: [sourceRef],
    targetVariants: ["android"],
    sourceMetadata: {
      publicOutputAccess: {
        kind: "property-read",
        alias: key.alias,
      },
    },
    probeMode: {
      kind: "runtime-global-property",
      globalName: "process",
      memberName: "__exactOSRelease",
    },
  };
  const invocation = {
    invocationSchema: "ibex/capsec-target-absence-invocation/1",
    kind: "target-absence",
    surfaceKind: edge.surface.kind,
    surfaceName: edge.surface.name,
    targetTriple: "aarch64-apple-darwin",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    expectedResult: "absent",
    expectedTypedDecisionCount: 0,
    expectedTypedStages: [],
    allowedCoverageEdgeIds: [],
    expectedActionIds: [],
  };
  const recipe = {
    fixtureId: "fixture.target-absent.android-os-release",
    planDigest: `sha256-${"P".repeat(43)}`,
    status: "fully-executable",
    scenario: "absent",
    edgeIds: [edge.id],
    terminalObservedKey: `native-op:${edge.surface.name}`,
    expectedObservation: {
      kind: "target-absence",
      edgeId: edge.id,
    },
    adapterProbe: null,
    residualReasons: [],
    publicSurfaceProbe: {
      kind: "target-absence-probe",
      surfaceObservedKey: `native-op:${edge.surface.name}`,
      invocation,
    },
  };
  const target = { triple: "aarch64-apple-darwin" };
  const recipeCatalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { absent: 1 },
      residualReasons: {},
    },
  };
  recipeCatalog.recipeCatalogDigest =
    computeRecipeCatalogDigest(recipeCatalog);
  return {
    catalog: {
      rows: [
        {
          key: structuredClone(key),
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [`native-op:${edge.surface.name}`],
            sourceRefs: [sourceRef],
          },
          requiredValueProof: "live-value-observation",
        },
      ],
    },
    recipeCatalog,
    coverage: { edges: [structuredClone(edge)] },
    target,
  };
}

function resignRecipeCatalog(value) {
  value.recipeCatalog.recipeCatalogDigest = computeRecipeCatalogDigest(
    value.recipeCatalog,
  );
}

describe("target-absence output projection", () => {
  test("binds an aliased Android process property read to its exact value row", () => {
    const value = fixture();
    expect(authoredTargetAbsenceOutputBindings(value)).toEqual([
      {
        key: structuredClone(key),
        fixtureId: "fixture.target-absent.android-os-release",
        planDigest: `sha256-${"P".repeat(43)}`,
        terminalObservedKey: `native-op:${edge.surface.name}`,
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        sourceDescriptorDigest:
          value.recipeCatalog.recipes[0].publicSurfaceProbe.invocation
            .sourceDescriptorDigest,
      },
    ]);
  });

  test("rejects a fabricated raw return row for the property alias", () => {
    const value = fixture();
    value.catalog.rows[0].key.output = "[[return]]";
    value.catalog.rows[0].key.alias = edge.surface.name;
    expect(() => authoredTargetAbsenceOutputBindings(value)).toThrow(
      /does not name the exact probed surface value/u,
    );
  });

  test("binds every callback output row when the target symbol is absent", () => {
    const value = fixture();
    const invocation =
      value.recipeCatalog.recipes[0].publicSurfaceProbe.invocation;
    delete invocation.sourceDescriptor.sourceMetadata;
    delete invocation.sourceDescriptor.probeMode;
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    resignRecipeCatalog(value);
    value.catalog.rows = ["callback:callback/0", "callback:callback/2"].map(
      (output) => ({
        ...structuredClone(value.catalog.rows[0]),
        key: {
          ...structuredClone(key),
          output,
          alias: edge.surface.name,
        },
      }),
    );

    expect(
      authoredTargetAbsenceOutputBindings(value).map((binding) =>
        binding.key.output,
      ),
    ).toEqual(["callback:callback/0", "callback:callback/2"]);
  });

  test("skips a target-absent surface only when its catalog account is structural-only", () => {
    const value = fixture();
    value.catalog.rows = [];
    value.catalog.surfaceAccounts = [
      {
        surfaceId: edge.id,
        status: "structural-only",
        outputKinds: [],
      },
    ];
    expect(authoredTargetAbsenceOutputBindings(value)).toEqual([]);

    value.catalog.surfaceAccounts[0].status = "output-bearing";
    expect(() => authoredTargetAbsenceOutputBindings(value)).toThrow(
      /structural-only catalog account/u,
    );
  });

  test("rejects source metadata that names a different public property", () => {
    const value = fixture();
    const invocation =
      value.recipeCatalog.recipes[0].publicSurfaceProbe.invocation;
    invocation.sourceDescriptor.sourceMetadata.publicOutputAccess.alias =
      "process.__exactOSVersion";
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    resignRecipeCatalog(value);
    expect(() => authoredTargetAbsenceOutputBindings(value)).toThrow(
      /property-read output binding does not match the absence probe/u,
    );
  });

  test("rejects a schema-less toy catalog and a junk recipe plan digest", () => {
    const schemaLess = fixture();
    delete schemaLess.recipeCatalog.recipeCatalogSchema;
    resignRecipeCatalog(schemaLess);
    expect(() => authoredTargetAbsenceOutputBindings(schemaLess)).toThrow(
      /malformed or digest-mismatched executable recipe catalog/u,
    );

    const junkPlan = fixture();
    junkPlan.recipeCatalog.recipes[0].planDigest = "sha256-test-plan";
    resignRecipeCatalog(junkPlan);
    expect(() => authoredTargetAbsenceOutputBindings(junkPlan)).toThrow(
      /plan digest is malformed/u,
    );
  });

  test("rejects digest, target, and summary tampering at the projector boundary", () => {
    const digestMismatch = fixture();
    digestMismatch.recipeCatalog.recipeCatalogDigest =
      `sha256-${"D".repeat(43)}`;
    expect(() =>
      authoredTargetAbsenceOutputBindings(digestMismatch),
    ).toThrow(/malformed or digest-mismatched executable recipe catalog/u);

    const targetMismatch = fixture();
    targetMismatch.recipeCatalog.target = {
      ...targetMismatch.recipeCatalog.target,
      triple: "x86_64-unknown-linux-gnu",
    };
    resignRecipeCatalog(targetMismatch);
    expect(() => authoredTargetAbsenceOutputBindings(targetMismatch)).toThrow(
      /recipe catalog target differs from the attested target/u,
    );

    const summaryMismatch = fixture();
    summaryMismatch.recipeCatalog.summary.requiredFixtures += 1;
    resignRecipeCatalog(summaryMismatch);
    expect(() => authoredTargetAbsenceOutputBindings(summaryMismatch)).toThrow(
      /recipe catalog summary disagrees with its recipe rows/u,
    );
  });
});
