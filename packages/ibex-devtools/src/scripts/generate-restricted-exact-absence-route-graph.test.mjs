import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import { validateRestrictedExactAbsenceRouteGraph } from "./generate-restricted-exact-absence-route-graph.mjs";

const paths = {
  projection: path.join(capsecRoot, "generated/restricted-exact-profile-projection.json"),
  coverage: path.join(capsecRoot, "registry/coverage-edges.json"),
  implementationManifest: path.join(capsecRoot, "generated/implementation-manifest.json"),
  rootManifest: path.join(capsecRoot, "generated/root-global-disposition-manifest.json"),
  probePlan: path.join(capsecRoot, "generated/restricted-exact-absence-probe-plan.json"),
};

const source = Object.fromEntries(
  Object.entries(paths).map(([name, file]) => [name, readJsonStrict(file)]),
);
const graph = readJsonStrict(
  path.join(capsecRoot, "generated/restricted-exact-absence-route-graph.json"),
);

function validate() {
  return validateRestrictedExactAbsenceRouteGraph(graph, source);
}

function expectMutation(mutate, pattern) {
  const restore = mutate();
  try {
    expect(validate).toThrow(pattern);
  } finally {
    restore();
  }
}

function branchTopology(route) {
  return graph.topology.branchPaths.find((row) => row.branchId === route.branchId);
}

describe("LLP 0033 restricted Exact executable absence route graph", () => {
  test("binds every absent branch, live route, exact source site, and target-specific cut set", () => {
    expect(graph.counts).toEqual({
      edges: 7194,
      routes: 7408,
      sourceFiles: 208,
      sourceBindings: 12468,
      liveProbeBindings: 10300,
    });
    expect(graph.routeGraphSchema).toBe("ibex/restricted-profile-absence-route-graph/2");
    expect(graph.topology.branchPaths).toHaveLength(7408);
    expect(graph.sourceBindings).toHaveLength(12468);
    expect(graph.topology.sourceSites.length).toBeGreaterThan(26000);
    expect(graph.topology.branchPaths.filter((row) => row.paths.length > 1).length).toBe(633);
    expect(graph.routes.every((route) => route.liveCutsetObservationIds.length === 3)).toBe(true);
    expect(graph.topology.sourceSpans).toHaveLength(5);
    expect(validate()).toBe(graph);
  });

  test("computes per-family dominance and rejects a real bypass or cycle", () => {
    const branch = graph.topology.branchPaths[0];
    expectMutation(() => {
      graph.topology.edges.push([
        branch.routeFamily,
        branch.sourceRoot,
        branch.terminalNodeId,
        ["source-selection"],
        "expose",
        "span:span.profile-selection",
        null,
      ]);
      return () => graph.topology.edges.pop();
    }, /source cut set does not dominate exact terminal/u);

    expectMutation(() => {
      graph.topology.edges.push([
        branch.routeFamily,
        branch.terminalNodeId,
        branch.sourceRoot,
        ["source-selection"],
        "call",
        "span:span.profile-selection",
        null,
      ]);
      return () => graph.topology.edges.pop();
    }, /contains a cycle/u);
  });

  test("rejects branch omission, source-range drift, and a falsified cut-set event", () => {
    expectMutation(() => {
      const removed = graph.topology.branchPaths.shift();
      return () => graph.topology.branchPaths.unshift(removed);
    }, /every implementation branch/u);

    expectMutation(() => {
      const span = graph.topology.sourceSpans[0];
      const prior = span.rawContentDigest;
      span.rawContentDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      return () => { span.rawContentDigest = prior; };
    }, /source span drifted/u);

    expectMutation(() => {
      const route = graph.routes[0];
      const prior = route.sourceCutsetObservationIds[0];
      route.sourceCutsetObservationIds[0] = "restricted-exact.falsified";
      return () => { route.sourceCutsetObservationIds[0] = prior; };
    }, /actual cut-set observations/u);
  });

  test("rejects selected-branch, exact-target, and boundary substitution", () => {
    expectMutation(() => {
      const route = graph.routes[0];
      const prior = route.branchId;
      route.branchId = graph.routes[1].branchId;
      return () => { route.branchId = prior; };
    }, /unknown or cross-edge branch/u);

    expectMutation(() => {
      const route = graph.routes[0];
      const prior = route.observedIdentity;
      route.observedIdentity = "builtin:swapped";
      return () => { route.observedIdentity = prior; };
    }, /target disagrees/u);

    expectMutation(() => {
      const route = graph.routes[0];
      const prior = route.liveBoundary.blockedEdge.to;
      route.liveBoundary.blockedEdge.to = graph.routes[1].liveBoundary.blockedEdge.to;
      return () => { route.liveBoundary.blockedEdge.to = prior; };
    }, /boundary is inferred or disagrees/u);
  });

  test("rejects an invented lazy attacker route and a removed callback root", () => {
    const first = graph.routes[0];
    expectMutation(() => {
      const root = graph.topology.nodes.find((node) => node.nodeId === branchTopology(first).liveRoot);
      root.attackerRoots.push("lazy:unclassified-alias");
      root.attackerRoots.sort();
      return () => {
        root.attackerRoots.splice(root.attackerRoots.indexOf("lazy:unclassified-alias"), 1);
      };
    }, /omits or invents an exact attacker root/u);

    const callbackRoute = graph.routes.find((route) => route.observedIdentity.startsWith("callback:"));
    expectMutation(() => {
      const root = graph.topology.nodes.find((node) => node.nodeId === branchTopology(callbackRoute).liveRoot);
      const index = root.attackerRoots.indexOf("__hostCall");
      root.attackerRoots.splice(index, 1);
      return () => root.attackerRoots.splice(index, 0, "__hostCall");
    }, /omits or invents an exact attacker root/u);
  });

  test("rejects wrong terminal topology and source-content substitution", () => {
    expectMutation(() => {
      const branch = graph.topology.branchPaths[0];
      const prior = branch.terminalNodeId;
      branch.terminalNodeId = graph.topology.branchPaths[1].terminalNodeId;
      return () => { branch.terminalNodeId = prior; };
    }, /branch metadata drifted|non-edge|no exact attacker-root path/u);

    expectMutation(() => {
      const binding = graph.sourceBindings[0];
      const prior = binding.rawContentDigest;
      binding.rawContentDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      return () => { binding.rawContentDigest = prior; };
    }, /not content-bound/u);
  });

  test("rejects a new implementation branch and target-applicability confusion", () => {
    const original = source.implementationManifest.surfaces.find(
      (branch) => branch.edgeId === graph.routes[0].edgeId,
    );
    expectMutation(() => {
      source.implementationManifest.surfaces.push({
        ...structuredClone(original),
        branchId: `${original.branchId}.new-alias`,
      });
      return () => source.implementationManifest.surfaces.pop();
    }, /implementation branch/u);

    expectMutation(() => {
      const route = graph.routes[0];
      const prior = route.applicability;
      route.applicability = { classification: "platform-excluded", reason: "forged" };
      return () => { route.applicability = prior; };
    }, /target applicability disagrees/u);
  });
});
