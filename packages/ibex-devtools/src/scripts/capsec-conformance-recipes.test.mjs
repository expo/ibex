import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
  fixtureScenario,
} from "./capsec-conformance-recipes.mjs";
import {
  fixtureCatalogForTarget,
  fixtureExecutionPlans,
} from "./capsec-conformance.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

describe("exact-target CapSec executable recipes", () => {
  let recipes;
  let expectedFixtureIds;

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
    expectedFixtureIds = fixtureExecutionPlans(catalog).map(
      (plan) => plan.fixtureId,
    );
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
  }, 60_000);

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
    expect(recipes.summary.requiredFixtures).toBe(expectedFixtureIds.length);
    expect(recipes.recipes).toHaveLength(expectedFixtureIds.length);
    expect(
      new Set(recipes.recipes.map((recipe) => recipe.fixtureId)).size,
    ).toBe(expectedFixtureIds.length);
    expect(recipes.recipes.map((recipe) => recipe.fixtureId)).toEqual(
      expectedFixtureIds,
    );
    expect(recipes.summary.adapterExecutableFixtures).toBe(
      recipes.recipes.filter((recipe) => recipe.adapterProbe !== null).length,
    );
    const authoredPublicFixtures = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe !== null,
    ).length;
    expect(authoredPublicFixtures).toBeGreaterThan(0);
    const nativePublicFixtures = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-native-global-invocation/1",
    );
    expect(nativePublicFixtures).toHaveLength(18);
    expect(
      nativePublicFixtures
        .filter(
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.globalName ===
            "__exactTcpConnect",
        )
        .map((recipe) => [
          recipe.publicSurfaceProbe.invocation.globalName,
          recipe.scenario,
        ]),
    ).toEqual([
      ["__exactTcpConnect", "allow"],
      ["__exactTcpConnect", "deny"],
    ]);
    expect(
      nativePublicFixtures.filter(
        (recipe) => recipe.scenario === "non-capability",
      ),
    ).toHaveLength(16);
    expect(
      recipes.summary.residualReasons[
        "native-public-global-removed-by-structural-lockdown"
      ],
    ).toBe(30);
    expect(recipes.summary.fullyExecutableFixtures).toBe(
      authoredPublicFixtures,
    );
    expect(recipes.summary.unresolvedFixtures).toBe(
      expectedFixtureIds.length - authoredPublicFixtures,
    );
    const publicFixtures = recipes.recipes.filter(
      (recipe) => recipe.expectedObservation.kind === "enforcement-branch",
    ).length;
    const absenceFixtures = recipes.recipes.filter(
      (recipe) => recipe.expectedObservation.kind === "target-absence",
    ).length;
    const authoredAbsenceFixtures = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.kind === "target-absence-probe",
    ).length;
    const authoredEnforcementFixtures = recipes.recipes.filter(
      (recipe) =>
        recipe.expectedObservation.kind === "enforcement-branch" &&
        recipe.publicSurfaceProbe !== null,
    ).length;
    expect(
      recipes.summary.residualReasons["public-surface-invocation-not-authored"],
    ).toBe(publicFixtures - authoredEnforcementFixtures);
    expect(
      recipes.summary.residualReasons["target-absence-probe-not-authored"],
    ).toBe(absenceFixtures - authoredAbsenceFixtures);
    expect(publicFixtures + absenceFixtures).toBe(expectedFixtureIds.length);
    expect(() => assertRecipeCatalogComplete(recipes)).toThrow(
      /executable recipe catalog is incomplete/,
    );
  });

  test("authors node:os probes without hand-labeling a native terminal", () => {
    const allow = recipes.recipes.find(
      (recipe) =>
        recipe.scenario === "allow" &&
        recipe.route.surfaceObservedKeys.includes(
          "builtin:export:node_os:cpus",
        ),
    );
    const deny = recipes.recipes.find(
      (recipe) =>
        recipe.scenario === "deny" &&
        recipe.route.surfaceObservedKeys.includes(
          "builtin:export:node_os:cpus",
        ),
    );
    expect(allow.publicSurfaceProbe).toMatchObject({
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_os:cpus",
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:os",
        exportName: "cpus",
        expectedResult: "return",
        expectedTypedDecisionCount: 2,
        expectedTypedStages: ["requested", "commit"],
        expectedActionIds: ["sys:read"],
      },
    });
    expect(deny.publicSurfaceProbe.invocation).toMatchObject({
      expectedResult: "permission-denied",
      expectedTypedDecisionCount: 1,
      expectedTypedStages: ["requested"],
    });
    expect(allow.publicSurfaceProbe.invocation.allowedCoverageEdgeIds).toEqual([
      "surface.native.op.exactgetcpucount.1k05aty",
    ]);
    expect(allow.publicSurfaceProbe.invocation).not.toHaveProperty(
      "terminalObservedKey",
    );
  });

  test("binds native public probes to source-derived JSI descriptors", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactTcpConnect",
    );
    expect(rows).toHaveLength(2);
    for (const recipe of rows) {
      expect(recipe.publicSurfaceProbe.command).toEqual([
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--features",
        "capsec-conformance-observer",
        "capsec_public_native_recipe_batch",
        "--",
        "--test-threads=1",
      ]);
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation).toMatchObject({
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        globalName: "__exactTcpConnect",
        kind: "native-global-function",
        sourceDescriptor: {
          arity: 4,
          globalName: "__exactTcpConnect",
          kind: "native-global-function",
          sourceRef:
            "src/engine/hermes_runtime_net.cc#jsi-global:__exactTcpConnect",
        },
        setup: [{ kind: "tcp-loopback-listener" }],
        allowedCoverageEdgeIds: ["surface.native.op.exacttcpconnect.1cs9rhu"],
        expectedActionIds: ["network:connect"],
      });
      expect(invocation.sourceDescriptorDigest).toMatch(/^sha256-/u);
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow"
          ? ["requested", "candidate", "commit", "repeat"]
          : ["requested"],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "allow" ? 4 : 1,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("authors source-bound reads for non-capability builtin exports", () => {
    const publicReads = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.kind === "builtin-export-read",
    );
    expect(publicReads.length).toBeGreaterThan(1_500);
    expect(
      publicReads.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.route.alternatives.length === 1 &&
          recipe.route.alternatives[0].terminalObservedKey ===
            recipe.publicSurfaceProbe.surfaceObservedKey,
      ),
    ).toBe(true);
    expect(
      publicReads.some(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.access.kind ===
          "prototype-property",
      ),
    ).toBe(true);
    expect(
      publicReads.some((recipe) =>
        recipe.publicSurfaceProbe.surfaceObservedKey.includes(
          "[[dynamic-table:",
        ),
      ),
    ).toBe(false);
  });

  test("binds host ABI target absence to source variants and a runtime lookup", () => {
    const rows = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.kind === "target-absence-probe",
    );
    expect(rows).toHaveLength(56);
    expect(rows.every((recipe) => recipe.scenario === "absent")).toBe(true);
    expect(rows.every((recipe) => recipe.status === "fully-executable")).toBe(
      true,
    );
    const ios = rows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.surfaceName ===
        "ex_hermes_dispatch_event",
    );
    expect(ios.publicSurfaceProbe).toMatchObject({
      surfaceObservedKey: "host-abi:ex_hermes_dispatch_event",
      invocation: {
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        kind: "target-absence",
        targetTriple: "aarch64-apple-darwin",
        sourceDescriptor: {
          kind: "target-absent-host-abi",
          targetVariants: ["ios"],
          sourceMetadata: {
            definitions: expect.any(Array),
          },
          probeMode: {
            kind: "dynamic-symbol",
            symbolName: "ex_hermes_dispatch_event",
          },
        },
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
      },
    });
    expect(ios.publicSurfaceProbe.invocation.sourceDescriptorDigest).toMatch(
      /^sha256-/u,
    );
    expect(ios.publicSurfaceProbe.invocation).not.toHaveProperty(
      "terminalObservedKey",
    );
  });

  test("binds closed startup environment controls to the production entry", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "startup-environment",
    );
    expect(rows).toHaveLength(19);
    expect(rows.every((recipe) => recipe.status === "fully-executable")).toBe(
      true,
    );
    const moduleLoader = rows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.operation.environmentName ===
        "EX_SKIP_STARTUP_MODULE_LOADER",
    );
    expect(moduleLoader.publicSurfaceProbe).toMatchObject({
      kind: "public-surface-invocation",
      surfaceObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
      command: [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--features",
        "capsec-conformance-observer",
        "capsec_public_closed_recipe_batch",
        "--",
        "--test-threads=1",
      ],
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        sourceDescriptor: {
          kind: "closed-startup-environment",
          environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
          sourceRefs: [
            "src/engine/hermes_bootstrap.cc#env_flag_enabled:EX_SKIP_STARTUP_MODULE_LOADER:read",
          ],
        },
        operation: {
          kind: "startup-environment",
          environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
        },
        expectedResult: "closed",
        expectedTypedDecisionCount: 0,
      },
    });
    expect(moduleLoader.residualReasons).toEqual([]);
  });

  test("preserves multiple argument-selected terminal routes", () => {
    const recipe = recipes.recipes.find(
      (candidate) =>
        candidate.scenario === "allow" &&
        candidate.route.surfaceObservedKeys.includes(
          "builtin:export:exact_sqlite:Database.close",
        ),
    );
    expect(recipe).toBeDefined();
    expect(
      recipe.route.alternatives.map(
        (alternative) => alternative.terminalObservedKey,
      ),
    ).toEqual(
      expect.arrayContaining([
        "native-op:__exactSqliteClose",
        "native-op:__exactSqliteExec",
      ]),
    );
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
