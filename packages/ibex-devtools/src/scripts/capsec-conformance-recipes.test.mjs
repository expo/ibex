import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
  fixtureScenario,
} from "./capsec-conformance-recipes.mjs";
import { fixtureCatalogForTarget } from "./capsec-conformance.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

describe("exact-target CapSec executable recipes", () => {
  let recipes;

  beforeAll(async () => {
    const coverage = readJson("capsec/registry/coverage-edges.json");
    const implementation = readJson(
      "capsec/generated/implementation-manifest.json",
    );
    const rules = readJson("capsec/registry/policy-rules.json");
    const target = rules.initialProfile.candidateTargets[0];
    const catalog = fixtureCatalogForTarget({
      coverage,
      implementation,
      target,
    });
    recipes = buildConformanceRecipeCatalog({
      catalog,
      coverage,
      implementation,
      inventory: await discoverRepositorySurfaces(repoRoot),
      occurrenceExamples: readJson(
        "capsec/examples/effect-occurrences.canonical.json",
      ),
      selectorExamples: readJson(
        "capsec/examples/authority-selectors.canonical.json",
      ),
      target,
    });
  });

  test("parses fixture scenarios by exact terminal suffix", () => {
    expect(fixtureScenario("branch.logical.none.malformed-branch-facts")).toBe(
      "malformed-branch-facts",
    );
    expect(fixtureScenario("branch.missing-attribution")).toBe(
      "missing-attribution",
    );
    expect(() => fixtureScenario("branch.looks-like-allowing")).toThrow(
      /unknown fixture scenario/,
    );
  });

  test("accounts for every obligation exactly once and reports honest residuals", () => {
    expect(recipes.recipeCatalogSchema).toBe(
      "ibex/capsec-executable-recipes/1",
    );
    expect(recipes.summary.requiredFixtures).toBe(21_606);
    expect(recipes.recipes).toHaveLength(21_606);
    expect(new Set(recipes.recipes.map((recipe) => recipe.fixtureId)).size).toBe(
      21_606,
    );
    expect(recipes.summary.adapterExecutableFixtures).toBe(10_325);
    expect(recipes.summary.fullyExecutableFixtures).toBe(0);
    expect(recipes.summary.unresolvedFixtures).toBe(21_606);
    expect(recipes.summary.residualReasons).toMatchObject({
      "public-surface-invocation-not-authored": 21_497,
      "target-absence-probe-not-authored": 109,
    });
    expect(() => assertRecipeCatalogComplete(recipes)).toThrow(
      /21606\/21606 unresolved/,
    );
  });

  test("preserves cross-module and multiple terminal routes", () => {
    const recipe = recipes.recipes.find(
      (candidate) =>
        candidate.scenario === "allow" &&
        candidate.route.surfaceObservedKeys.includes(
          "builtin:export:node_fs_promises:readFile",
        ),
    );
    expect(recipe).toBeDefined();
    expect(
      recipe.route.alternatives.map((alternative) =>
        alternative.terminalObservedKey,
      ),
    ).toEqual(expect.arrayContaining(["native-op:__exactFsOpen"]));
    expect(
      recipe.route.alternatives.some((alternative) =>
        alternative.proofPaths.some((proofPath) =>
          proofPath.includes("require:node:fs#openSync -> export:openSync"),
        ),
      ),
    ).toBe(true);
  });

  test("models every declared action stage through the typed adapter", () => {
    const multiStage = recipes.recipes.find(
      (recipe) =>
        recipe.scenario === "allow" &&
        recipe.actionIds.length >= 5 &&
        recipe.adapterProbe?.cases.length >= 4,
    );
    expect(multiStage).toBeDefined();
    const observedActions = new Set(
      multiStage.adapterProbe.cases.flatMap((probeCase) => probeCase.actionIds),
    );
    expect([...observedActions].sort()).toEqual(multiStage.actionIds);
    for (const probeCase of multiStage.adapterProbe.cases) {
      const decision = JSON.parse(probeCase.decisionSetJson);
      const gates = JSON.parse(probeCase.gatesJson);
      expect(decision.context.stage).toBe(probeCase.stage);
      expect(decision.effects.map((effect) => effect.cap)).toEqual(
        probeCase.actionIds,
      );
      expect(gates).toHaveLength(decision.effects.length);
    }
  });

  test("keeps malformed ingress as an adapter error with no invented observation", () => {
    const malformed = recipes.recipes.find(
      (recipe) => recipe.scenario === "malformed" && recipe.adapterProbe,
    );
    expect(malformed.adapterProbe.cases).toHaveLength(1);
    expect(() =>
      JSON.parse(malformed.adapterProbe.cases[0].decisionSetJson),
    ).toThrow();
    expect(malformed.adapterProbe.cases[0].expected).toEqual({
      adapter: "error",
      legacyObservations: 0,
      typedObservations: 0,
    });
  });
});

