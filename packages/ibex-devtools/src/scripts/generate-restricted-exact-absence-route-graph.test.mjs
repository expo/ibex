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
      edges: 7193,
      routes: 7407,
      sourceFiles: 208,
      sourceBindings: 12467,
      liveProbeBindings: 10298,
    });
    expect(graph.routes.every((route) => route.sourcePath.at(-1).startsWith("terminal."))).toBe(true);
    expect(graph.routes.every((route) => route.liveCutsetObservationIds.length === 3)).toBe(true);
    expect(graph.topology.terminals).toHaveLength(7193);
    expect(graph.topology.sourceSpans).toHaveLength(5);
  });

  test("computes dominance and rejects a real topology bypass or cycle", () => {
    const bypass = fixture();
    bypass.graph.topology.edges.push({
      from: bypass.graph.topology.sourceRoot,
      to: bypass.graph.topology.terminals[0].nodeId,
      routeClass: "source-selection",
    });
    bypass.graph.topology.edges.sort((left, right) =>
      `${left.from}\0${left.to}`.localeCompare(`${right.from}\0${right.to}`));
    expect(() => validate(bypass.graph, bypass.source)).toThrow(/do not dominate terminal/u);

    const cycle = fixture();
    cycle.graph.topology.edges.push({
      from: cycle.graph.topology.terminals[0].nodeId,
      to: cycle.graph.topology.sourceRoot,
      routeClass: "source-selection",
    });
    cycle.graph.topology.edges.sort((left, right) =>
      `${left.from}\0${left.to}`.localeCompare(`${right.from}\0${right.to}`));
    expect(() => validate(cycle.graph, cycle.source)).toThrow(/contains a cycle/u);
  });

  test("rejects topology branch omission and instrumented source-range drift", () => {
    const branch = fixture();
    branch.graph.topology.terminals[0].branchIds = [];
    expect(() => validate(branch.graph, branch.source)).toThrow(/omits an implementation branch/u);

    const span = fixture();
    span.graph.topology.sourceSpans[0].rawContentDigest =
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(() => validate(span.graph, span.source)).toThrow(/source span drifted/u);
  });

  test("rejects route-level cut-set bypass and a falsified cut-set event", () => {
    const { graph, source } = fixture();
    graph.routes[0].sourcePath.splice(1, 1);
    expect(() => validate(graph, source)).toThrow(/contains a non-edge/u);
    const second = fixture();
    second.graph.routes[0].sourceCutsetObservationIds[0] = "restricted-exact.falsified";
    expect(() => validate(second.graph, second.source)).toThrow(/actual cut-set observations/u);
  });

  test("rejects selected-branch and exact-target substitution", () => {
    const { graph, source } = fixture();
    graph.routes[0].branchId = graph.routes[1].branchId;
    expect(() => validate(graph, source)).toThrow(/unknown or cross-edge branch/u);
    const second = fixture();
    second.graph.routes[0].observedIdentity = "builtin:swapped";
    expect(() => validate(second.graph, second.source)).toThrow(/target disagrees/u);
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

  test("rejects wrong terminal boundaries and source-content substitution", () => {
    const { graph, source } = fixture();
    graph.routes[0].livePath[graph.routes[0].livePath.length - 1] =
      graph.topology.terminals[1].nodeId;
    expect(() => validate(graph, source)).toThrow(/non-edge|exact terminal/u);
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
    expect(() => validate(graph, source)).toThrow(/implementation branch/u);
  });

  test("rejects target-applicability confusion", () => {
    const { graph, source } = fixture();
    graph.routes[0].applicability = { classification: "platform-excluded", reason: "forged" };
    expect(() => validate(graph, source)).toThrow(/target applicability disagrees/u);
  });
});
