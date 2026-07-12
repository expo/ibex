import { describe, expect, test } from "bun:test";
import { authoredNonCapabilityBuiltinProbe } from "./capsec-builtin-public-probe-templates.mjs";

const plan = {
  classification: "non-capability",
  actionIds: [],
};

function probeFor({
  sourceKey = "node_path",
  exportName = "basename",
  exportIdioms = ["object-binding", "object-source"],
  moduleSpecifiers = ["node:path", "path"],
} = {}) {
  const observedKey = `builtin:export:${sourceKey}:${exportName}`;
  return authoredNonCapabilityBuiltinProbe({
    plan,
    scenario: "non-capability",
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
            surfaceType: "export",
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
      surfaceObservedKey: "builtin:export:node_path:basename",
      invocation: {
        kind: "builtin-export-read",
        moduleSpecifier: "node:path",
        exportName: "basename",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
        sourceDescriptor: {
          access: { kind: "export-property", path: ["basename"] },
        },
      },
    });
  });

  test("binds source-resolved prototype and inherited access paths", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
      }).invocation.sourceDescriptor.access,
    ).toEqual({
      kind: "prototype-property",
      path: ["Hash", "prototype", "update"],
    });
    expect(
      probeFor({
        sourceKey: "node_buffer",
        exportName: "Buffer.constructor",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["buffer", "node:buffer"],
      }).invocation.sourceDescriptor.access,
    ).toEqual({
      kind: "inherited-prototype-property",
      path: ["Buffer", "prototype", "constructor"],
    });
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
});
