import { describe, expect, test } from "bun:test";
import {
  authoredNonCapabilityBuiltinProbe,
  nonCapabilityBuiltinProbeResidualReason,
} from "./capsec-builtin-public-probe-templates.mjs";

const plan = {
  classification: "non-capability",
  actionIds: [],
};

function probeFor({
  sourceKey = "node_constants",
  exportName = "ENOENT",
  exportIdioms = ["object-binding", "object-source"],
  moduleSpecifiers = ["constants", "node:constants"],
  platformAvailability,
  target = "aarch64-apple-darwin",
  valueShape = "data",
} = {}) {
  const observedKey = `builtin:export:${sourceKey}:${exportName}`;
  return authoredNonCapabilityBuiltinProbe({
    plan,
    scenario: "non-capability",
    target,
    route: {
      surfaceObservedKeys: [observedKey],
      alternatives: [
        { terminalObservedKey: observedKey, proofPaths: [observedKey] },
      ],
      ambiguousCallees: [],
    },
    liveByObservedKey: new Map([
      [
        observedKey,
        {
          observedKey,
          sourceRefs: [`src/builtins/${sourceKey}.js#exports:${exportName}`],
          metadata: {
            sourceKey,
            exportName,
            exportIdioms,
            moduleSpecifiers,
            platformAvailability,
            surfaceType: "export",
            valueShape,
          },
        },
      ],
    ]),
  });
}

describe("source-bound builtin public probes", () => {
  test("reads an own export through the canonical public alias", () => {
    const probe = probeFor();
    expect(probe).toMatchObject({
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_constants:ENOENT",
      invocation: {
        kind: "builtin-export-read",
        moduleSpecifier: "node:constants",
        exportName: "ENOENT",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
        sourceDescriptor: {
          access: { kind: "export-property", path: ["ENOENT"] },
          valueShape: "data",
        },
      },
    });
  });

  test("triggers source-proven root accessors", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Z_OK",
        exportIdioms: ["define-property"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "accessor",
      }).invocation.sourceDescriptor,
    ).toEqual({
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Z_OK",
      exportIdioms: ["define-property"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/node_zlib.js#exports:Z_OK",
      valueShape: "accessor",
      access: { kind: "export-property", path: ["Z_OK"] },
    });
  });

  test("leaves callable and prototype surfaces residual", () => {
    expect(
      probeFor({
        sourceKey: "node_path",
        exportName: "basename",
        moduleSpecifiers: ["node:path", "path"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "data",
      }),
    ).toBeNull();
  });

  test("leaves dynamic tables and non-self routes residual", () => {
    expect(
      probeFor({
        sourceKey: "node_constants",
        exportName: "[[dynamic-table:signal-number-overlay]]",
        exportIdioms: [
          "closed-dynamic-table:signal-number-overlay",
          "table-copy",
        ],
        moduleSpecifiers: ["node:constants"],
      }),
    ).toBeNull();

    const observedKey = "builtin:export:node_path:basename";
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            {
              terminalObservedKey: "native-op:__unexpected",
              proofPaths: ["basename -> __unexpected"],
            },
          ],
          ambiguousCallees: [],
        },
        liveByObservedKey: new Map(),
      }),
    ).toBeNull();
  });

  test("keeps source-proven target-absent constants explicitly residual", () => {
    const surfaceObservedKey = "builtin:export:node_constants:EDQUOT";
    const liveByObservedKey = new Map([
      [
        surfaceObservedKey,
        {
          observedKey: surfaceObservedKey,
          sourceRefs: ["src/builtins/constants.js#exports:EDQUOT"],
          metadata: {
            sourceKey: "node_constants",
            exportName: "EDQUOT",
            exportIdioms: ["object-binding", "object-source", "table-copy"],
            moduleSpecifiers: ["constants", "node:constants"],
            platformAvailability: ["android", "linux"],
            surfaceType: "export",
            valueShape: "data",
          },
        },
      ],
    ]);
    const route = {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBeNull();
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-not-available-on-target");
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-linux-android",
      })?.invocation.sourceDescriptor.platformAvailability,
    ).toEqual(["android", "linux"]);
  });
});
