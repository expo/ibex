// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
// sample member success cannot close an unresolved dynamic member universe.
// @ref LLP 0023#6-path-bearing-observables — sentinels and ambient owner keys
// remain structural until every concrete output-bearing member is accounted.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { repoRoot } from "./capsec-contract.mjs";
import {
  authoredDynamicGlobalOutputInvocation,
  DYNAMIC_GLOBAL_OUTPUT_COVERED_FAMILIES,
  DYNAMIC_GLOBAL_OUTPUT_RESIDUAL_FAMILIES,
  dynamicGlobalOutputCatalogBindings,
  dynamicGlobalOutputResidual,
  reviewedDynamicGlobalOutputFamilies,
  validateDynamicGlobalOutputInvocation,
} from "./capsec-dynamic-global-output-templates.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const EXPECTED_RESIDUAL_FAMILIES = [
  "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]",
  "global:Float16Array.[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]",
  "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
  "global:[[dynamic-table:native-global-name]]",
  "global:process.env.[[dynamic-table:env-obj-properties]]",
].sort();

const DOWNGRADED_SAMPLE_FAMILIES = Object.freeze({
  "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]":
    "inherited-base-membership-unclosed",
  "global:Float16Array.[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]":
    "inherited-base-membership-unclosed",
  "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]":
    "prototype-base-membership-unclosed",
});

async function loadReviewedRows() {
  const inventory = await discoverRepositorySurfaces(repoRoot);
  const coverage = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/coverage-edges.json"),
      "utf8",
    ),
  );
  const surfaces = new Map(
    inventory.surfaces.map((surface) => [surface.observedKey, surface]),
  );
  const edges = new Map(
    coverage.edges.map((edge) => [
      `${edge.surface.kind}:${edge.surface.name}`,
      edge,
    ]),
  );
  return EXPECTED_RESIDUAL_FAMILIES.map((familyName) => {
    const observedKey = `native-op:${familyName}`;
    const surface = surfaces.get(observedKey);
    const coverageEdge = edges.get(observedKey);
    if (!surface || !coverageEdge) {
      throw new Error(`missing reviewed dynamic-global family ${familyName}`);
    }
    return { familyName, surface, coverageEdge };
  });
}

const loadedRows = loadReviewedRows();

describe("dynamic-global exhaustive-output review", () => {
  test("keeps all five source-bound residual families and authors no sample probes", async () => {
    expect(DYNAMIC_GLOBAL_OUTPUT_COVERED_FAMILIES).toEqual([]);
    expect(DYNAMIC_GLOBAL_OUTPUT_RESIDUAL_FAMILIES).toEqual(
      EXPECTED_RESIDUAL_FAMILIES,
    );
    expect(dynamicGlobalOutputCatalogBindings()).toEqual([]);

    const rows = await loadedRows;
    expect(rows).toHaveLength(5);
    for (const { familyName, surface, coverageEdge } of rows) {
      expect(surface).toMatchObject({
        kind: "native-op",
        name: familyName,
        observedKey: `native-op:${familyName}`,
        metadata: { surfaceType: "global-api" },
      });
      expect(coverageEdge.surface).toEqual({
        kind: "native-op",
        name: familyName,
      });
      expect(
        authoredDynamicGlobalOutputInvocation({ surface, coverageEdge }),
      ).toBeNull();
      const residual = dynamicGlobalOutputResidual({ surface, coverageEdge });
      expect(residual).toMatchObject({
        familyName,
        status: "residual",
      });
      expect(residual.reasonCode.length).toBeGreaterThan(10);
      expect(residual.reason.length).toBeGreaterThan(40);
      expect(residual.requiredIntegration.length).toBeGreaterThanOrEqual(3);
      expect(() =>
        validateDynamicGlobalOutputInvocation(
          { kind: "sample-must-not-validate" },
          { surface, coverageEdge },
        ),
      ).toThrow(/no exhaustive dynamic-global output invocation/u);
    }
  }, 30_000);

  test("downgrades every former sample because its member universe is not exhaustive", async () => {
    const rows = await loadedRows;
    for (const [familyName, reasonCode] of Object.entries(
      DOWNGRADED_SAMPLE_FAMILIES,
    )) {
      const row = rows.find((candidate) => candidate.familyName === familyName);
      const residual = dynamicGlobalOutputResidual(row);
      expect(residual.reasonCode).toBe(reasonCode);
      expect(residual.requiredIntegration.join(" ")).toMatch(
        /every|complete|exhaustive/iu,
      );
      expect(residual.requiredIntegration.join(" ")).toMatch(/unaccounted/iu);
    }

    const reviewed = reviewedDynamicGlobalOutputFamilies();
    expect(
      reviewed
        .filter(({ familyName }) =>
          Object.hasOwn(DOWNGRADED_SAMPLE_FAMILIES, familyName),
        )
        .map(({ familyName, reasonCode, status }) => ({
          familyName,
          reasonCode,
          status,
        })),
    ).toEqual(
      Object.entries(DOWNGRADED_SAMPLE_FAMILIES)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([familyName, reasonCode]) => ({
          familyName,
          reasonCode,
          status: "residual",
        })),
    );
  }, 30_000);

  test("requires finite concrete accounts without enumerating ambient proxies or marker spellings", () => {
    const reviewed = reviewedDynamicGlobalOutputFamilies();
    expect(reviewed).toHaveLength(5);
    expect(reviewed.every(({ status }) => status === "residual")).toBe(true);
    expect(reviewed.some((row) => Object.hasOwn(row, "operation"))).toBe(false);
    expect(reviewed.some((row) => Object.hasOwn(row, "catalog"))).toBe(false);

    const ambientKinds = new Set(["process-environment-object"]);
    for (const row of reviewed.filter(({ familyKind }) =>
      ambientKinds.has(familyKind),
    )) {
      expect(row.reason).toMatch(/ambient|host|open environment/iu);
      expect(row.requiredIntegration.join(" ")).toMatch(
        /concrete|exact|authorized/iu,
      );
    }

    for (const row of reviewed.filter(
      ({ familyKind }) => familyKind === "native-global-writer-marker",
    )) {
      expect(row.reasonCode).toMatch(/marker-not-value/u);
      expect(row.requiredIntegration.join(" ")).toMatch(
        /never probe|never read|never.*serialize/iu,
      );
    }
  });

  test("fails closed on source, dynamic evidence, and coverage drift", async () => {
    const rows = await loadedRows;
    const bufferRow = rows.find(
      ({ familyName }) =>
        familyName ===
        "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]",
    );
    const sharedArrayBufferRow = rows.find(
      ({ familyName }) =>
        familyName ===
        "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
    );

    expect(() =>
      dynamicGlobalOutputResidual({
        ...bufferRow,
        surface: {
          ...bufferRow.surface,
          sourceRefs: ["fixture#unbound-source"],
        },
      }),
    ).toThrow(/source binding drift/u);
    expect(() =>
      dynamicGlobalOutputResidual({
        ...sharedArrayBufferRow,
        surface: {
          ...sharedArrayBufferRow.surface,
          metadata: {
            ...sharedArrayBufferRow.surface.metadata,
            dynamicNamespaceEvidence: "sha256-drift",
          },
        },
      }),
    ).toThrow(/evidence drift/u);
    expect(() =>
      dynamicGlobalOutputResidual({
        ...bufferRow,
        coverageEdge: {
          ...bufferRow.coverageEdge,
          classification: "effects",
        },
      }),
    ).toThrow(/coverage binding drift/u);

    const unrelated = {
      kind: "native-op",
      name: "global:Unrelated",
      observedKey: "native-op:global:Unrelated",
      sourceRefs: ["fixture#unrelated"],
      metadata: {},
    };
    expect(
      authoredDynamicGlobalOutputInvocation({
        surface: unrelated,
        coverageEdge: null,
      }),
    ).toBeNull();
    expect(
      dynamicGlobalOutputResidual({
        surface: unrelated,
        coverageEdge: null,
      }),
    ).toBeNull();
  }, 30_000);
});
