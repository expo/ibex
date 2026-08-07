// @ref LLP 0035#reports-and-advertisements — target-cell candidates are a
// deterministic projection of reviewed closure and never copy the checked
// unsupported sentinel into promotion evidence.
import { describe, expect, test } from "bun:test";

import { derivePortablePromotionTargetCells } from "./generate-capsec-portable-promotion-target-cells.mjs";
import { portablePromotionJsonBytes } from "./capsec-portable-promotion-bundle.mjs";

const target = {
  triple: "aarch64-apple-darwin",
  features: [
    "hermes-frame-attribution",
    "native-compartments",
    "native-lockdown",
  ],
};

function fixture() {
  return {
    coverage: {
      edges: [
        {
          id: "surface.a",
          classification: "effects",
          effectMode: "fixed",
        },
        {
          id: "surface.b",
          classification: "closed",
          effectMode: "fixed",
        },
        {
          id: "surface.c",
          classification: "non-capability",
          effectMode: "fixed",
        },
        {
          id: "surface.d",
          classification: "effects",
          effectMode: "fixed",
        },
      ],
    },
    fixtureCatalog: [
      {
        edgeId: "surface.a",
        implementationBranchIds: ["branch.a"],
        requiredFixtures: ["fixture.z", "fixture.a"],
      },
      {
        edgeId: "surface.b",
        implementationBranchIds: ["branch.b"],
        requiredFixtures: ["fixture.b"],
      },
      {
        edgeId: "surface.c",
        implementationBranchIds: ["branch.c"],
        requiredFixtures: ["fixture.c"],
      },
      {
        edgeId: "surface.d",
        implementationBranchIds: [],
        requiredFixtures: ["fixture.absent"],
      },
    ],
    inScopeEdgeIds: ["surface.a", "surface.b", "surface.c", "surface.d"],
  };
}

describe("portable promotion target-cell derivation", () => {
  test("derives exact dispositions and canonical fixture membership", () => {
    const input = fixture();
    const result = derivePortablePromotionTargetCells({ ...input, target });
    expect(result.targetCellSchema).toBe("ibex/capsec-target-cells/1");
    expect(result.cells.map((cell) => cell.edgeId)).toEqual([
      "surface.a",
      "surface.b",
      "surface.c",
      "surface.d",
    ]);
    expect(result.cells.map((cell) => cell.disposition)).toEqual([
      "enforced",
      "closed",
      "non-capability",
      "absent",
    ]);
    expect(result.cells[0].fixtures).toEqual(["fixture.a", "fixture.z"]);
    expect(result.cells[3].implementationBranchIds).toEqual([]);
    const bytes = portablePromotionJsonBytes(result);
    expect(bytes.toString("utf8")).toBe(`${JSON.stringify(result, null, 2)}\n`);
    expect(result.cells[0].rationale).toBe(
      "Source-derived scoped physical-promotion candidate; authority requires complete execution evidence.",
    );
  });

  test("refuses unresolved conditional source closure", () => {
    const input = fixture();
    input.coverage.edges[0].effectMode = "conditional-unrefined";
    expect(() =>
      derivePortablePromotionTargetCells({ ...input, target }),
    ).toThrow(/no promotable target disposition/u);
  });

  test("emits unsupported bytes for exactly the uncertified remainder", () => {
    const input = fixture();
    input.inScopeEdgeIds = ["surface.a", "surface.c"];
    const result = derivePortablePromotionTargetCells({ ...input, target });
    expect(result.cells.map((cell) => cell.disposition)).toEqual([
      "enforced",
      "unsupported",
      "non-capability",
      "unsupported",
    ]);
    expect(result.cells[1]).toMatchObject({
      implementationBranchIds: ["branch.b"],
      fixtures: [],
      rationale: "Outside the certified scope; no conformance claim is made.",
    });
    expect(result.cells[3]).toMatchObject({
      implementationBranchIds: [],
      fixtures: [],
    });
  });

  test("refuses a duplicate, empty, or non-inventory scope expansion", () => {
    for (const inScopeEdgeIds of [
      [],
      ["surface.a", "surface.a"],
      ["surface.unknown"],
    ]) {
      const input = fixture();
      input.inScopeEdgeIds = inScopeEdgeIds;
      expect(() =>
        derivePortablePromotionTargetCells({ ...input, target }),
      ).toThrow(/fixture catalog differs from coverage membership/u);
    }
  });

  test("refuses missing, duplicate, and fixture-free edge membership", () => {
    const missing = fixture();
    missing.fixtureCatalog.pop();
    expect(() =>
      derivePortablePromotionTargetCells({ ...missing, target }),
    ).toThrow(/duplicate or incomplete/u);

    const duplicate = fixture();
    duplicate.coverage.edges.push({ ...duplicate.coverage.edges[0] });
    expect(() =>
      derivePortablePromotionTargetCells({ ...duplicate, target }),
    ).toThrow(/duplicate or incomplete/u);

    const fixtureFree = fixture();
    fixtureFree.fixtureCatalog[0].requiredFixtures = [];
    expect(() =>
      derivePortablePromotionTargetCells({ ...fixtureFree, target }),
    ).toThrow(/no required fixture/u);
  });
});
