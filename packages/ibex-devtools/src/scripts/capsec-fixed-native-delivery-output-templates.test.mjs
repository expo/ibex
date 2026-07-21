// @ref LLP 0023#6-path-bearing-observables — bounded native delivery
// invocations bind exact callback arguments without inventing callback returns.

import { beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildOutputShapeCatalog,
  canonicalOutputDispositionKey,
} from "./capsec-output-dispositions.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  FIXED_NATIVE_DELIVERY_OUTPUT_INVOCATION_SCHEMA,
  FIXED_NATIVE_DELIVERY_OUTPUT_SOURCE_DESCRIPTOR_KIND,
  authoredFixedNativeDeliveryOutputInvocation,
  validateFixedNativeDeliveryOutputInvocation,
} from "./capsec-fixed-native-delivery-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const names = new Set([
  "__exactDispatchEvent",
  "__exactDispatchStableEvent",
  "__exactModuleEvent",
  "__exactMotionRatedPublish",
  "__exactRunOnJS",
  "__exactScheduleOnAppRuntime",
  "__ibexCapsecContextObserver_",
]);

let cases;

beforeAll(async () => {
  const coverage = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/coverage-edges.json"),
      "utf8",
    ),
  );
  const surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  const surfaceByObservedKey = new Map(
    surfaces.map((surface) => [surface.observedKey, surface]),
  );
  const implementationRows = coverage.edges.map((edge) => {
    const observedKey = `${edge.surface.kind}:${edge.surface.name}`;
    const surface = surfaceByObservedKey.get(observedKey);
    if (!surface) throw new Error(`test inventory lacks ${observedKey}`);
    return {
      edgeId: edge.id,
      observedKey,
      sourceRefs: [...surface.sourceRefs],
    };
  });
  const catalog = buildOutputShapeCatalog({
    coverage,
    implementationRows,
    surfaces,
    repoRoot,
    liveEvidence: {
      status: "unpromotable",
      requiredExecutor: "ibex-public-surface-harness/output-shape-sweep-v3",
      reason: "focused native delivery template fixture",
    },
  });
  const edgeById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  cases = catalog.rows
    .filter((catalogRow) => {
      const edge = edgeById.get(catalogRow.key.surfaceId);
      return names.has(edge.surface.name);
    })
    .map((catalogRow) => {
      const edge = edgeById.get(catalogRow.key.surfaceId);
      const surface = surfaceByObservedKey.get(
        `native-op:${edge.surface.name}`,
      );
      return {
        catalogRow,
        edge,
        surface,
        invocation: authoredFixedNativeDeliveryOutputInvocation({
          catalogRow,
          surface,
          coverageEdge: edge,
        }),
      };
    });
}, 30_000);

describe("fixed native delivery output templates", () => {
  test("authors only the four delivery families with bounded native fixtures", () => {
    expect(cases).toHaveLength(41);
    const authored = cases.filter(({ invocation }) => invocation !== null);
    const sourceOnly = cases.filter(({ invocation }) => invocation === null);
    expect(authored).toHaveLength(21);
    expect(sourceOnly).toHaveLength(20);
    expect(
      Object.fromEntries(
        [...Map.groupBy(authored, ({ edge }) => edge.surface.name)]
          .map(([name, rows]) => [name, rows.length])
          .sort(),
      ),
    ).toEqual({
      __exactMotionRatedPublish: 8,
      __exactRunOnJS: 6,
      __exactScheduleOnAppRuntime: 4,
      __ibexCapsecContextObserver_: 3,
    });
    expect(
      new Set(sourceOnly.map(({ edge }) => edge.surface.name)),
    ).toEqual(
      new Set([
        "__exactDispatchEvent",
        "__exactDispatchStableEvent",
        "__exactModuleEvent",
      ]),
    );

    for (const { catalogRow, edge, surface, invocation } of authored) {
      expect(invocation).toMatchObject({
        invocationSchema: FIXED_NATIVE_DELIVERY_OUTPUT_INVOCATION_SCHEMA,
        kind: "fixed-native-delivery-output",
        coverageEdgeId: edge.id,
        coverageClassification: edge.classification,
        surfaceObservedKey: surface.observedKey,
        sourceDescriptor: {
          kind: FIXED_NATIVE_DELIVERY_OUTPUT_SOURCE_DESCRIPTOR_KIND,
          globalName: edge.surface.name,
        },
        selection: {
          output: catalogRow.key.output,
          alias: catalogRow.key.alias,
          mode: catalogRow.key.mode,
          returnVariant: catalogRow.key.returnVariant,
        },
        completion: { kind: "synchronous-native-driver" },
      });
      expect(
        invocation.sourceDescriptor.implementationSourceRefs,
      ).toContain(invocation.sourceDescriptor.implementationSourceRef);
      expect(
        invocation.sourceDescriptor.implementationSourceRefs,
      ).toContain(invocation.sourceDescriptor.liveFixtureSourceRef);
      expect(() =>
        validateFixedNativeDeliveryOutputInvocation(invocation, {
          catalogKey: catalogRow.key,
          surfaceObservedKey: surface.observedKey,
        }),
      ).not.toThrow();
      expect(canonicalOutputDispositionKey(catalogRow.key)).toBeString();
    }
  }, 30_000);

  test("carries no reviewed result or callback return expectation", () => {
    const encoded = JSON.stringify(
      cases.flatMap(({ invocation }) => (invocation ? [invocation] : [])),
    );
    for (const forbidden of [
      "normalizedValue",
      "expectedResult",
      "expectation",
      "callbackReturn",
    ]) {
      expect(encoded).not.toContain(forbidden);
    }
  });

  test("rejects operation, channel, and live-fixture drift", () => {
    const selected = cases.find(
      ({ edge, invocation }) =>
        edge.surface.name === "__exactRunOnJS" && invocation !== null,
    );
    const wrongOperation = structuredClone(selected.invocation);
    wrongOperation.operation.fixtureId = "unbounded-echo";
    expect(() =>
      validateFixedNativeDeliveryOutputInvocation(wrongOperation, {
        catalogKey: selected.catalogRow.key,
        surfaceObservedKey: selected.surface.observedKey,
      }),
    ).toThrow(/invalid fixed delivery invocation/);

    const wrongChannel = structuredClone(selected);
    wrongChannel.catalogRow.key.output = "[[return]]";
    expect(() =>
      authoredFixedNativeDeliveryOutputInvocation({
        catalogRow: wrongChannel.catalogRow,
        surface: wrongChannel.surface,
        coverageEdge: wrongChannel.edge,
      }),
    ).toThrow(/invalid fixed delivery binding/);

    const missingFixture = structuredClone(selected);
    missingFixture.catalogRow.discovery.sourceRefs =
      missingFixture.catalogRow.discovery.sourceRefs.filter(
        (sourceRef) => !sourceRef.startsWith("src/engine/mod.rs#"),
      );
    expect(() =>
      authoredFixedNativeDeliveryOutputInvocation({
        catalogRow: missingFixture.catalogRow,
        surface: missingFixture.surface,
        coverageEdge: missingFixture.edge,
      }),
    ).toThrow(/lacks implementation or live fixture binding/);
  });
});
