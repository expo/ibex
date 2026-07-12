import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
  deriveAdapterActionTemplate,
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
  let capabilityDefinitions;
  let occurrenceExamples;
  let selectorExamples;

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
    capabilityDefinitions = readJson(
      "capsec/registry/capability-definitions.json",
    );
    occurrenceExamples = readJson(
      "capsec/examples/effect-occurrences.canonical.json",
    );
    selectorExamples = readJson(
      "capsec/examples/authority-selectors.canonical.json",
    );
    recipes = buildConformanceRecipeCatalog({
      catalog,
      coverage,
      implementation,
      inventory: await discoverRepositorySurfaces(repoRoot),
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
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
    expect(nativePublicFixtures).toHaveLength(80);
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
        (recipe) =>
          recipe.scenario === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return",
      ),
    ).toHaveLength(22);
    expect(
      nativePublicFixtures.filter(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.expectedResult === "absent",
      ),
    ).toHaveLength(56);
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
      recipes.summary.residualReasons["target-absence-probe-not-authored"] ?? 0,
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
    expect(publicReads.length).toBeGreaterThan(300);
    expect(
      publicReads.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          new Set(["accessor", "data"]).has(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor.valueShape,
          ) &&
          new Set(["export-property", "module-value"]).has(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor.access.kind,
          ) &&
          recipe.route.alternatives.length === 1 &&
          recipe.route.alternatives[0].terminalObservedKey ===
            recipe.publicSurfaceProbe.surfaceObservedKey,
      ),
    ).toBe(true);
    expect(
      publicReads.some((recipe) =>
        recipe.publicSurfaceProbe.invocation.sourceDescriptor.access.kind.includes(
          "prototype",
        ),
      ),
    ).toBe(false);
    expect(
      publicReads.some((recipe) =>
        recipe.publicSurfaceProbe.surfaceObservedKey.includes(
          "[[dynamic-table:",
        ),
      ),
    ).toBe(false);
    expect(
      recipes.summary.residualReasons["builtin-export-not-available-on-target"],
    ).toBe(14);
  });

  test("binds target absence to source variants and exact runtime lookups", () => {
    const rows = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.kind === "target-absence-probe",
    );
    expect(rows).toHaveLength(109);
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
    const androidGlobal = rows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.surfaceName ===
        "__exactAndroidLocation.getPermissionStatus",
    );
    expect(androidGlobal.publicSurfaceProbe).toMatchObject({
      surfaceObservedKey:
        "native-op:__exactAndroidLocation.getPermissionStatus",
      invocation: {
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        kind: "target-absence",
        surfaceKind: "native-op",
        targetTriple: "aarch64-apple-darwin",
        sourceDescriptor: {
          kind: "target-absent-native-operation",
          targetVariants: ["android"],
          sourceMetadata: {
            installationBranches: expect.any(Array),
          },
          probeMode: {
            kind: "runtime-global-property",
            globalName: "__exactAndroidLocation",
            memberName: "getPermissionStatus",
          },
        },
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
      },
    });
    expect(
      androidGlobal.publicSurfaceProbe.invocation.sourceDescriptorDigest,
    ).toMatch(/^sha256-/u);
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

  test("authors bounded normal-return calls for exact non-capability families", () => {
    const publicCalls = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1",
    );
    expect(publicCalls.length).toBeGreaterThan(200);
    expect(
      new Set(
        publicCalls.map(
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey,
        ),
      ),
    ).toEqual(
      new Set([
        "node_assert",
        "node_buffer",
        "node_events",
        "node_path",
        "node_punycode",
        "node_querystring",
        "node_zlib",
      ]),
    );
    expect(
      publicCalls.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.kind === "builtin-export-call" &&
          recipe.publicSurfaceProbe.invocation.expectedResult ===
            "normal-return" &&
          recipe.publicSurfaceProbe.invocation.bodyEntryProof.kind ===
            "normal-return-from-source-call" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount === 0,
      ),
    ).toBe(true);
    expect(
      publicCalls.some((recipe) =>
        recipe.publicSurfaceProbe.invocation.sourceDescriptor.access.kind.includes(
          "prototype",
        ),
      ),
    ).toBe(true);
    expect(
      publicCalls.some(
        (recipe) =>
          recipe.publicSurfaceProbe.surfaceObservedKey ===
          "builtin:export:node_assert:fail",
      ),
    ).toBe(false);
  });

  test("binds reviewed CLI controls and every spelling to production closure", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "cli-control",
    );
    expect(rows).toHaveLength(122);
    expect(rows.every((recipe) => recipe.status === "fully-executable")).toBe(
      true,
    );
    const advisory = rows.find(
      (recipe) =>
        recipe.terminalObservedKey === "cli:option:ibex:capsec_allow_advisory",
    );
    expect(advisory.publicSurfaceProbe.invocation).toMatchObject({
      surfaceKind: "cli",
      sourceDescriptor: {
        kind: "closed-cli-control",
        controlDescriptor: {
          kind: "clap-option",
          commandPath: "ibex",
          argumentId: "capsec_allow_advisory",
          optionSpellings: [
            "--allow-advisory-attribution",
            "--capsec-allow-advisory",
          ],
        },
      },
      operation: {
        kind: "cli-control",
        argumentVectors: [
          expect.objectContaining({
            spelling: "--allow-advisory-attribution",
          }),
          expect.objectContaining({ spelling: "--capsec-allow-advisory" }),
        ],
        expectedRejectionFragments: expect.arrayContaining([
          "rejects legacy allow/deny",
        ]),
      },
    });
    const evalCommand = rows.find(
      (recipe) => recipe.terminalObservedKey === "cli:command:ibex%20eval",
    );
    expect(evalCommand.publicSurfaceProbe.invocation.operation).toMatchObject({
      kind: "cli-control",
      argumentVectors: [
        {
          spelling: "ibex eval",
          args: [
            "eval",
            "globalThis.__IBEX_CAPSEC_CLOSED_CLI_EVALUATED__ = true",
          ],
        },
      ],
      expectedRejectionFragments: [
        "closes ad-hoc evaluation, REPL, and debug commands",
      ],
    });
    expect(
      recipes.recipes.filter(
        (recipe) =>
          recipe.scenario === "closed" &&
          recipe.terminalObservedKey.startsWith("cli:") &&
          recipe.status !== "fully-executable",
      ),
    ).toHaveLength(21);
  });

  test("binds nested native argument producers and exact absence probes", () => {
    const decrypt = recipes.recipes.find(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactAesCbcDecrypt",
    );
    expect(decrypt).toBeDefined();
    const producer = decrypt.publicSurfaceProbe.invocation.arguments[2];
    expect(producer).toMatchObject({
      kind: "native-global-result",
      globalName: "__exactAesCbcEncrypt",
      sourceDescriptor: {
        arity: 3,
        globalName: "__exactAesCbcEncrypt",
        kind: "native-global-function",
      },
    });
    expect(producer.sourceDescriptorDigest).toMatch(/^sha256-/u);

    const targetAbsence = recipes.recipes.find(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactAndroidCameraHostCall" &&
        recipe.expectedObservation.kind === "target-absence",
    );
    expect(targetAbsence).toMatchObject({
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        surfaceObservedKey: "native-op:__exactAndroidCameraHostCall",
        invocation: {
          expectedResult: "absent",
          expectedTypedDecisionCount: 0,
          expectedTypedStages: [],
        },
      },
    });

    const lockdownAbsence = recipes.recipes.find(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__hostCall",
    );
    expect(lockdownAbsence).toMatchObject({
      classification: "closed",
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        invocation: { expectedResult: "absent" },
      },
    });
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

  test("freezes registry-valid derived templates for Rust ingestion", () => {
    const envWrite = deriveAdapterActionTemplate({
      action: "env:write",
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
    });
    expect(envWrite).toEqual(
      readJson(
        "packages/ibex-devtools/src/scripts/fixtures/capsec-derived-env-write-template.json",
      ),
    );

    const stdioWrite = deriveAdapterActionTemplate({
      action: "stdio:write",
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
    });
    expect(stdioWrite.selector.resource.stream).toBe("stderr");
    expect(stdioWrite.occurrence.resource.requested.stream).toBe("stderr");

    const stdioRaw = deriveAdapterActionTemplate({
      action: "stdio:raw",
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
    });
    expect(stdioRaw.selector.resource.source.kind).toBe("terminal");
    expect(stdioRaw.occurrence.resource.requested.source.kind).toBe("terminal");
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
