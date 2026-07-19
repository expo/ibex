import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import {
  buildRestrictedExactProfile,
  loadAndBuildRestrictedExactProfile,
  validateRestrictedExactProfile,
} from "./generate-restricted-exact-profile.mjs";

const coveragePath = path.join(capsecRoot, "registry/coverage-edges.json");
const implementationManifestPath = path.join(
  capsecRoot,
  "generated/implementation-manifest.json",
);
const definitionPath = path.join(
  capsecRoot,
  "registry/restricted-exact-profile-definition.json",
);

function inputs() {
  return {
    coverage: structuredClone(readJsonStrict(coveragePath)),
    definition: structuredClone(readJsonStrict(definitionPath)),
    implementationManifest: structuredClone(readJsonStrict(implementationManifestPath)),
  };
}

describe("LLP 0026 restricted Exact profile projection", () => {
  test("projects every full-registry edge once and advertises nothing", () => {
    const result = loadAndBuildRestrictedExactProfile();
    expect(result.projection.counts.total).toBe(7111);
    expect(result.projection.counts.reachable).toBe(20);
    expect(result.projection.counts.trustedControlPlane).toBe(10);
    expect(result.projection.counts.structurallyAbsent).toBe(7081);
    expect(result.projection.rows).toHaveLength(result.projection.counts.total);
    expect(result.projection.promotionReady).toBe(false);
    expect(result.advertisements.advertisements).toEqual([]);
  });

  test("rejects an added, removed, or duplicated full-registry edge", () => {
    const added = inputs();
    added.coverage.edges.push({
      id: "surface.native.op.injected.mutation.0000000",
      classification: "closed",
      surface: { kind: "native-op", name: "__injectedMutation" },
      cap: "vm:evaluate",
      rationale: "mutation fixture",
    });
    expect(() => buildRestrictedExactProfile(added)).toThrow("source edge count drift");

    const removed = inputs();
    removed.coverage.edges.pop();
    expect(() => buildRestrictedExactProfile(removed)).toThrow("source edge count drift");

    const duplicated = inputs();
    duplicated.coverage.edges.push(structuredClone(duplicated.coverage.edges[0]));
    expect(() => buildRestrictedExactProfile(duplicated)).toThrow("full coverage edge IDs contains duplicates");
  });

  test("rejects disposition overlap and bound surface identity drift", () => {
    const overlap = inputs();
    overlap.definition.trustedControlPlane.splice(
      0,
      0,
      structuredClone(overlap.definition.reachable[0]),
    );
    expect(() => buildRestrictedExactProfile(overlap)).toThrow("disposition overlap");

    const renamed = inputs();
    renamed.definition.reachable[0].surfaceName = "wrong-name";
    expect(() => buildRestrictedExactProfile(renamed)).toThrow("identity drift");
  });

  test("rejects divergence from the source-derived implementation manifest", () => {
    const divergent = inputs();
    divergent.implementationManifest.surfaces.pop();
    expect(() => buildRestrictedExactProfile(divergent)).toThrow(
      "coverage and implementation-manifest edge sets disagree",
    );
  });

  test("rejects caller ordering and any Phase 0 advertisement", () => {
    const reordered = inputs();
    reordered.definition.reachable.reverse();
    expect(() => buildRestrictedExactProfile(reordered)).toThrow("reachable edge IDs must be sorted");

    const advertised = inputs();
    advertised.definition.advertisements = [{ target: "forbidden" }];
    expect(() => buildRestrictedExactProfile(advertised)).toThrow("violates schema");
  });

  test("rejects supplied raw authority bytes that do not match parsed objects", () => {
    const mismatched = inputs();
    mismatched.raw = { definition: fs.readFileSync(definitionPath) };
    mismatched.definition.reachable[0].reason = "mutated after parsing";
    expect(() => buildRestrictedExactProfile(mismatched)).toThrow(
      "definition bytes do not match the supplied object",
    );
  });

  test("detects projection omission and advertisement digest tampering", () => {
    const { projection, advertisements } = loadAndBuildRestrictedExactProfile();
    const coverage = readJsonStrict(coveragePath);
    const omitted = structuredClone(projection);
    omitted.rows.pop();
    omitted.counts.total -= 1;
    omitted.counts.structurallyAbsent -= 1;
    expect(() => validateRestrictedExactProfile(omitted, advertisements, coverage)).toThrow("bijection");

    const tampered = structuredClone(advertisements);
    tampered.projectionRawContentDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(() => validateRestrictedExactProfile(projection, tampered, coverage)).toThrow("exact projection bytes");
  });
});
