import crypto from "node:crypto";
import { describe, expect, test } from "bun:test";
import { canonicalJson } from "./capsec-contract.mjs";
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
    recipeCatalog: {
      recipes: [
        {
          fixtureId: "fixture.target-absent.android-os-release",
          planDigest: "sha256-test-plan",
          status: "fully-executable",
          scenario: "absent",
          edgeIds: [edge.id],
          terminalObservedKey: `native-op:${edge.surface.name}`,
          expectedObservation: {
            kind: "target-absence",
            edgeId: edge.id,
          },
          publicSurfaceProbe: {
            kind: "target-absence-probe",
            surfaceObservedKey: `native-op:${edge.surface.name}`,
            invocation,
          },
        },
      ],
    },
    coverage: { edges: [structuredClone(edge)] },
    target: { triple: "aarch64-apple-darwin" },
  };
}

describe("target-absence output projection", () => {
  test("binds an aliased Android process property read to its exact value row", () => {
    const value = fixture();
    expect(authoredTargetAbsenceOutputBindings(value)).toEqual([
      {
        key: structuredClone(key),
        fixtureId: "fixture.target-absent.android-os-release",
        planDigest: "sha256-test-plan",
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

  test("rejects source metadata that names a different public property", () => {
    const value = fixture();
    const invocation =
      value.recipeCatalog.recipes[0].publicSurfaceProbe.invocation;
    invocation.sourceDescriptor.sourceMetadata.publicOutputAccess.alias =
      "process.__exactOSVersion";
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    expect(() => authoredTargetAbsenceOutputBindings(value)).toThrow(
      /property-read output binding does not match the absence probe/u,
    );
  });
});
