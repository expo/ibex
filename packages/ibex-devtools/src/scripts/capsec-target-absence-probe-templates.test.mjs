import { describe, expect, test } from "bun:test";
import { authoredTargetAbsenceProbe } from "./capsec-target-absence-probe-templates.mjs";

const surfaceName = "__exactOSRelease";
const edge = Object.freeze({
  id: "surface.native.op.exactosrelease.test",
  surface: { kind: "native-op", name: surfaceName },
});
const observedKey = `native-op:${surfaceName}`;

function fixture() {
  const sourceRef =
    "src/engine/hermes_runtime_android.cc#jsi-global-property:process.__exactOSRelease";
  return {
    plan: {
      edgeIds: [edge.id],
      terminalObservedKey: observedKey,
      expectedObservation: { kind: "target-absence", edgeId: edge.id },
    },
    scenario: "absent",
    target: { triple: "aarch64-apple-darwin" },
    coverageByEdge: new Map([[edge.id, structuredClone(edge)]]),
    liveByObservedKey: new Map([
      [
        observedKey,
        {
          kind: "native-op",
          name: surfaceName,
          observedKey,
          sourceRefs: [sourceRef],
          metadata: {
            branches: [
              {
                sourceRefs: [sourceRef],
                targetVariant: "android",
              },
            ],
            installationBranches: [
              {
                sourceRefs: [sourceRef],
                targetVariant: "android",
              },
            ],
            exportName: "process.__exactOSRelease",
            globalName: "process",
            memberName: surfaceName,
            publicReadAccessSourceProven: true,
            publicOutputAccess: {
              kind: "property-read",
              alias: "process.__exactOSRelease",
            },
            sourceKey: "native_jsi_global",
            surfaceType: "global-api",
            valueShape: "data",
          },
        },
      ],
    ]),
  };
}

describe("target-absence public probe author", () => {
  test("authors a source-mapped private identifier as its public process property", () => {
    expect(authoredTargetAbsenceProbe(fixture())).toMatchObject({
      kind: "target-absence-probe",
      surfaceObservedKey: observedKey,
      invocation: {
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        kind: "target-absence",
        surfaceKind: "native-op",
        surfaceName,
        targetTriple: "aarch64-apple-darwin",
        sourceDescriptor: {
          kind: "target-absent-native-operation",
          targetVariants: ["android"],
          probeMode: {
            kind: "runtime-global-property",
            globalName: "process",
            memberName: surfaceName,
          },
        },
        sourceDescriptorDigest: expect.stringMatching(/^sha256-/u),
        expectedResult: "absent",
      },
    });
  });

  test("refuses an unbound raw identifier with the same spelling", () => {
    const value = fixture();
    const live = value.liveByObservedKey.get(observedKey);
    delete live.metadata.publicOutputAccess;
    expect(authoredTargetAbsenceProbe(value)).toBeNull();
  });

  test("refuses a source mapping that points at a different property", () => {
    const value = fixture();
    value.liveByObservedKey.get(observedKey).metadata.publicOutputAccess.alias =
      "process.__exactOSVersion";
    expect(authoredTargetAbsenceProbe(value)).toBeNull();
  });
});
