import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import {
  buildRestrictedExactAbsenceRouteGraph,
  validateRestrictedExactAbsenceRouteGraph,
} from "./generate-restricted-exact-absence-route-graph.mjs";

const paths = {
  projection: path.join(capsecRoot, "generated/restricted-exact-profile-projection.json"),
  coverage: path.join(capsecRoot, "registry/coverage-edges.json"),
  implementationManifest: path.join(capsecRoot, "generated/implementation-manifest.json"),
  rootManifest: path.join(capsecRoot, "generated/root-global-disposition-manifest.json"),
  probePlan: path.join(capsecRoot, "generated/restricted-exact-absence-probe-plan.json"),
};

function inputs() {
  return {
    ...Object.fromEntries(Object.entries(paths).map(([name, file]) => [name, structuredClone(readJsonStrict(file))])),
    raw: Object.fromEntries(Object.entries(paths).map(([name, file]) => [name, fs.readFileSync(file)])),
  };
}

const baseSource = inputs();
const baseGraph = buildRestrictedExactAbsenceRouteGraph(baseSource);

function fixture() {
  return { source: structuredClone(baseSource), graph: structuredClone(baseGraph) };
}

function validate(graph, source) {
  return validateRestrictedExactAbsenceRouteGraph(graph, source);
}

describe("LLP 0033 restricted Exact absence dominance graph", () => {
  test("binds every absent branch, live route, source file, and target-specific cut set", () => {
    const { graph } = fixture();
    expect(graph.counts).toEqual({
      edges: 7147,
      routes: 7361,
      sourceFiles: 208,
      sourceBindings: 12420,
      liveProbeBindings: 10253,
    });
    expect(graph.routes.every((route) => route.segments[1].expectedTarget === route.observedIdentity)).toBe(true);
    expect(graph.routes.every((route) => route.segments[3].cutsetObservationId.startsWith("cutset."))).toBe(true);
  });

  test("rejects cut-set bypass and a falsified cut-set event", () => {
    const { graph, source } = fixture();
    graph.routes[0].segments.splice(3, 1);
    expect(() => validate(graph, source)).toThrow(/missing a dominance segment/u);
    const second = fixture();
    second.graph.routes[0].segments[3].cutsetObservationId = "cutset.falsified";
    expect(() => validate(second.graph, second.source)).toThrow(/not target-bound/u);
  });

  test("rejects selected-branch and exact-target substitution", () => {
    const { graph, source } = fixture();
    graph.routes[0].branchId = graph.routes[1].branchId;
    expect(() => validate(graph, source)).toThrow(/unknown or cross-edge branch/u);
    const second = fixture();
    second.graph.routes[0].segments[1].expectedTarget = "builtin:swapped";
    expect(() => validate(second.graph, second.source)).toThrow(/target-ignoring route/u);
  });

  test("rejects a new alias or lazy attacker route and a retained callback root", () => {
    const { graph, source } = fixture();
    graph.routes[0].attackerRoots.push("lazy:unclassified-alias");
    graph.routes[0].attackerRoots.sort();
    expect(() => validate(graph, source)).toThrow(/omits or invents an attacker root/u);
    const second = fixture();
    const callbackRoute = second.graph.routes.find((route) => route.observedIdentity.startsWith("callback:"));
    callbackRoute.attackerRoots = callbackRoute.attackerRoots.filter((root) => root !== "__hostCall");
    expect(() => validate(second.graph, second.source)).toThrow(/omits or invents an attacker root/u);
  });

  test("rejects wrong failure boundaries and source-content substitution", () => {
    const { graph, source } = fixture();
    graph.routes[0].segments[3].expectedFailureSegment = graph.routes[0].segments[2].segmentId;
    expect(() => validate(graph, source)).toThrow(/wrong failed segment/u);
    const second = fixture();
    second.graph.routes[0].sourceBindings[0].rawContentDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(() => validate(second.graph, second.source)).toThrow(/not content-bound/u);
  });

  test("rejects a new implementation branch without a generated route", () => {
    const { graph, source } = fixture();
    const original = source.implementationManifest.surfaces.find((branch) => branch.edgeId === graph.routes[0].edgeId);
    source.implementationManifest.surfaces.push({
      ...structuredClone(original),
      branchId: `${original.branchId}.new-alias`,
    });
    expect(() => validate(graph, source)).toThrow(/every current implementation branch/u);
  });

  test("rejects target-applicability confusion", () => {
    const { graph, source } = fixture();
    graph.routes[0].applicability = { classification: "platform-excluded", reason: "forged" };
    expect(() => validate(graph, source)).toThrow(/target applicability disagrees/u);
  });
});
