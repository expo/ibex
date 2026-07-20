import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import { buildRestrictedExactAbsenceProbePlan } from "./generate-restricted-exact-absence-probe-plan.mjs";

const paths = {
  projection: path.join(capsecRoot, "generated/restricted-exact-profile-projection.json"),
  coverage: path.join(capsecRoot, "registry/coverage-edges.json"),
  implementationManifest: path.join(capsecRoot, "generated/implementation-manifest.json"),
  rootManifest: path.join(capsecRoot, "generated/root-global-disposition-manifest.json"),
};

function inputs() {
  return {
    projection: structuredClone(readJsonStrict(paths.projection)),
    coverage: structuredClone(readJsonStrict(paths.coverage)),
    implementationManifest: structuredClone(readJsonStrict(paths.implementationManifest)),
    rootManifest: structuredClone(readJsonStrict(paths.rootManifest)),
    raw: Object.fromEntries(
      Object.entries(paths).map(([name, file]) => [name, fs.readFileSync(file)]),
    ),
  };
}

describe("LLP 0033 restricted Exact absence probe plan", () => {
  test("assigns source and live probes to every absent edge", () => {
    const plan = buildRestrictedExactAbsenceProbePlan(inputs());
    expect(plan.counts).toEqual({
      edges: 7152,
      sourceInstallProbes: 7366,
      liveReachabilityProbes: 9754,
    });
    expect(plan.edges.every((row) => row.sourceInstall.length > 0)).toBe(true);
    expect(plan.edges.every((row) => row.liveReachability.length > 0)).toBe(true);
    expect(plan.edges.filter((row) => row.liveReachability.some(
      (probe) => probe.routeKind === "descriptor-prefix",
    )).length).toBe(2460);
  });

  test("rejects an absent edge without an implementation branch", () => {
    const mutated = inputs();
    const edgeId = mutated.projection.rows.find((row) => row[1] === "structurally-absent")[0];
    mutated.implementationManifest.surfaces = mutated.implementationManifest.surfaces
      .filter((row) => row.edgeId !== edgeId);
    expect(() => buildRestrictedExactAbsenceProbePlan(mutated)).toThrow(
      `absence probe edge has no implementation branch: ${edgeId}`,
    );
  });

  test("rejects a projection edge missing from source coverage", () => {
    const mutated = inputs();
    const edgeId = mutated.projection.rows.find((row) => row[1] === "structurally-absent")[0];
    mutated.coverage.edges = mutated.coverage.edges.filter((row) => row.id !== edgeId);
    expect(() => buildRestrictedExactAbsenceProbePlan(mutated)).toThrow(
      `absence probe edge is missing from coverage: ${edgeId}`,
    );
  });
});
