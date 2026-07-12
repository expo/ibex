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
    // Callback-invariant probes intentionally take precedence for 30 native
    // routes that this harness could otherwise claim structurally.
    expect(nativePublicFixtures).toHaveLength(191);
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
    ).toHaveLength(133);
    expect(
      nativePublicFixtures.filter(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.expectedResult === "absent",
      ),
    ).toHaveLength(26);
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

  test("authors every node:os effect scenario without hand-labeling a native terminal", () => {
    const osRecipes = recipes.recipes.filter((recipe) =>
      recipe.route.surfaceObservedKeys.includes(
        "builtin:export:node_os:cpus",
      ),
    );
    expect(osRecipes.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
    ]);
    expect(osRecipes.every((recipe) => recipe.status === "fully-executable")).toBe(
      true,
    );
    const allow = osRecipes.find((recipe) => recipe.scenario === "allow");
    const deny = osRecipes.find((recipe) => recipe.scenario === "deny");
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
    for (const scenario of [
      "malformed",
      "missing-attribution",
      "wrong-principal",
    ]) {
      expect(
        osRecipes.find((recipe) => recipe.scenario === scenario)
          .publicSurfaceProbe.invocation,
      ).toMatchObject({
        expectedResult: "return",
        expectedTypedDecisionCount: 2,
        expectedTypedStages: ["requested", "commit"],
      });
    }
    expect(allow.publicSurfaceProbe.invocation.allowedCoverageEdgeIds).toEqual([
      "surface.native.op.exactgetcpucount.1k05aty",
    ]);
    expect(allow.publicSurfaceProbe.invocation).not.toHaveProperty(
      "terminalObservedKey",
    );
  });

  test("binds synchronous filesystem metadata probes to an owned logical path", () => {
    for (const exportName of ["lstatSync", "statSync"]) {
      const surface = `builtin:export:node_fs:${exportName}`;
      const effectRecipes = recipes.recipes.filter(
        (recipe) =>
          recipe.route.surfaceObservedKeys.includes(surface) &&
          [
            "allow",
            "deny",
            "malformed",
            "missing-attribution",
            "wrong-principal",
          ].includes(recipe.scenario),
      );
      expect(effectRecipes).toHaveLength(5);
      expect(
        effectRecipes.every((recipe) => recipe.status === "fully-executable"),
      ).toBe(true);
      for (const recipe of effectRecipes) {
        expect(recipe.publicSurfaceProbe).toMatchObject({
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName,
            setup: {
              kind: "filesystem-file",
              logicalPath: {
                root: "project",
                components: [
                  { encoding: "utf8", value: "capsec-stat-fixture.txt" },
                ],
              },
            },
            requiredAuthority: [
              {
                cap: "fs:list",
                resource: { kind: "path-exact" },
              },
            ],
            expectedActionIds: ["fs:list"],
          },
        });
        expect(recipe.residualReasons).not.toContain(
          "ambiguous-static-enforcement-route",
        );
        const denial = recipe.scenario === "deny";
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedStages,
        ).toEqual(
          denial ? ["requested"] : ["requested", "discovery", "repeat"],
        );
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        ).toBe(denial ? 1 : 3);
      }
    }
  });

  test("binds directory enumeration to an owned generation-checked directory", () => {
    const recipesForDirectory = recipes.recipes.filter(
      (recipe) =>
        recipe.route.surfaceObservedKeys.includes(
          "builtin:export:node_fs:readdirSync",
        ) &&
        [
          "allow",
          "deny",
          "malformed",
          "missing-attribution",
          "wrong-principal",
        ].includes(recipe.scenario),
    );
    expect(recipesForDirectory).toHaveLength(5);
    for (const recipe of recipesForDirectory) {
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "readdirSync",
            setup: {
              kind: "filesystem-directory",
              logicalPath: {
                root: "project",
                components: [
                  { encoding: "utf8", value: "capsec-directory-fixture" },
                ],
              },
              entries: [{ kind: "file", name: "entry.txt" }],
            },
            expectedActionIds: ["fs:list"],
          },
        },
      });
      const denial = recipe.scenario === "deny";
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        denial
          ? ["requested"]
          : ["requested", "discovery", "repeat", "repeat"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(denial ? 1 : 4);
    }
  });

  test("source-binds every callback and authority-control invariant", () => {
    const callbackRecipes = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-callback-invariant-invocation/1",
    );
    expect(callbackRecipes).toHaveLength(2_822);
    expect(
      Object.fromEntries(
        [
          "attribution-missing-deny",
          "generation-recheck",
          "principal-restore",
          "snapshot-mismatch-deny",
          "cannot-widen-authority",
          "post-lockdown-invariant",
        ].map((scenario) => [
          scenario,
          callbackRecipes.filter((recipe) => recipe.scenario === scenario)
            .length,
        ]),
      ),
    ).toEqual({
      "attribution-missing-deny": 556,
      "generation-recheck": 556,
      "principal-restore": 556,
      "snapshot-mismatch-deny": 556,
      "cannot-widen-authority": 299,
      "post-lockdown-invariant": 299,
    });
    expect(
      callbackRecipes.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.surfaceObservedKey ===
            recipe.terminalObservedKey,
      ),
    ).toBe(true);
    const snapshot = callbackRecipes.find(
      (recipe) => recipe.scenario === "snapshot-mismatch-deny",
    );
    expect(snapshot.publicSurfaceProbe).toMatchObject({
      kind: "public-surface-invocation",
      command: [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--features",
        "capsec-conformance-observer",
        "capsec_public_callback_invariant_batch",
        "--",
        "--test-threads=1",
      ],
      invocation: {
        kind: "callback-security-invariant",
        expectedResult: "invariant-passed",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        expectedTypedOutcomes: [],
        expectedTypedReasons: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
        sourceDescriptor: {
          kind: "callback-security-invariant",
          scenario: "snapshot-mismatch-deny",
          rationaleId: "callback-attribution-carrier",
          executionMechanism: "cross-snapshot-public-handle-reattenuation",
          auxiliaryDecisionEdgeId: null,
        },
      },
    });
    expect(snapshot.publicSurfaceProbe.invocation.sourceDescriptorDigest).toMatch(
      /^sha256-/u,
    );
    const generation = callbackRecipes.find(
      (recipe) => recipe.scenario === "generation-recheck",
    );
    expect(generation.publicSurfaceProbe.invocation).toMatchObject({
      expectedTypedDecisionCount: 3,
      expectedTypedStages: ["requested", "commit", "requested"],
      expectedTypedOutcomes: ["allow", "allow", "deny"],
      expectedTypedReasons: [
        "dynamic-session",
        "dynamic-session",
        "missing-authority",
      ],
      allowedCoverageEdgeIds: [
        "surface.native.op.exactgetenv.0k6bv7a",
      ],
      expectedActionIds: ["env:read"],
    });
    const control = callbackRecipes.find(
      (recipe) => recipe.scenario === "post-lockdown-invariant",
    );
    expect(control.publicSurfaceProbe.invocation).toMatchObject({
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      expectedTypedOutcomes: [],
      expectedTypedReasons: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
      sourceDescriptor: {
        rationaleId: "authority-control-plane",
        auxiliaryDecisionEdgeId: null,
      },
    });
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
          ? ["requested", "candidate", "commit"]
          : ["requested"],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "allow" ? 3 : 1,
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

  test("imports every exact non-capability builtin module alias", () => {
    const imports = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.kind ===
        "builtin-module-import",
    );
    expect(imports.length).toBeGreaterThan(30);
    expect(
      imports.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.invocationSchema ===
            "ibex/capsec-builtin-module-import-invocation/1" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.kind ===
            "builtin-module-alias" &&
          recipe.route.alternatives[0].terminalObservedKey ===
            recipe.publicSurfaceProbe.surfaceObservedKey,
      ),
    ).toBe(true);
    expect(
      imports.find(
        (recipe) =>
          recipe.publicSurfaceProbe.surfaceObservedKey ===
          "builtin:internal/fs/utils",
      )?.publicSurfaceProbe.invocation.sourceDescriptor.resolutionKind,
    ).toBe("bootstrap-internal");
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
        "node_perf_hooks",
        "node_path",
        "node_punycode",
        "node_querystring",
        "node_stream",
        "node_string_decoder",
        "node_url",
        "node_util",
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

  test("binds readable globals to exact source-derived paths and shapes", () => {
    const recipe = recipes.recipes.find(
      (candidate) =>
        candidate.publicSurfaceProbe?.surfaceObservedKey ===
        "native-op:__exactRuntime",
    );
    expect(recipe).toMatchObject({
      classification: "non-capability",
      scenario: "non-capability",
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        surfaceObservedKey: "native-op:__exactRuntime",
        invocation: {
          invocationSchema: "ibex/capsec-native-global-invocation/1",
          kind: "global-property-read",
          globalName: "__exactRuntime",
          arguments: [],
          requiredFloor: [],
          setup: [],
          expectedResult: "return",
          expectedTypedDecisionCount: 0,
          expectedTypedStages: [],
          expectedActionIds: [],
          sourceDescriptor: {
            kind: "global-property-read",
            sourceKey: "shared_runtime",
            exportName: "__exactRuntime",
            globalName: "__exactRuntime",
            memberKinds: ["assignment"],
            valueShape: "data",
            access: {
              kind: "source-proven-property-path",
              path: ["__exactRuntime"],
            },
          },
        },
      },
    });
    expect(
      recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceRefs,
    ).toEqual([
      "packages/ibex-runtime-js/src/runtime-entry.ts#<module>:globals:__exactRuntime",
    ]);
    expect(
      recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest,
    ).toMatch(/^sha256-/u);
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

    const rsaVerify = recipes.recipes.find(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactVerifySync",
    );
    const publicKey = rsaVerify.publicSurfaceProbe.invocation.arguments[3];
    const privateKey =
      rsaVerify.publicSurfaceProbe.invocation.arguments[1].arguments[2];
    expect(publicKey).toMatchObject({
      kind: "native-global-result-property",
      property: "publicKey",
      globalName: "__exactGenerateKeyPairSync",
      sourceDescriptor: {
        arity: 3,
        globalName: "__exactGenerateKeyPairSync",
        kind: "native-global-function",
      },
    });
    expect(privateKey).toMatchObject({
      kind: "native-global-result-property",
      property: "privateKey",
      globalName: "__exactGenerateKeyPairSync",
    });
    expect(publicKey.arguments).toEqual(privateKey.arguments);
    expect(publicKey.sourceDescriptorDigest).toBe(
      privateKey.sourceDescriptorDigest,
    );

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

  test("supplies owned callbacks and bounded delays to native timers", () => {
    for (const globalName of ["queueMicrotask", "setInterval", "setTimeout"]) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
        scenario: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: `native-op:global:${globalName}`,
          invocation: {
            expectedResult: "return",
            expectedTypedDecisionCount: 0,
            expectedTypedStages: [],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.arguments[0]).toEqual({
        kind: "harness-noop-callback",
      });
      if (globalName !== "queueMicrotask") {
        expect(recipe.publicSurfaceProbe.invocation.arguments[1]).toEqual({
          kind: "json-literal",
          value: 60_000,
        });
      }
    }
  });

  test("creates and consumes owned loopback TCP handles outside observation", () => {
    for (const globalName of [
      "__exactTcpClose",
      "__exactTcpReset",
      "__exactTcpShutdown",
    ]) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
        scenario: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            setup: [
              { kind: "tcp-loopback-listener" },
              {
                kind: "tcp-loopback-client",
                globalName: "__exactTcpConnect",
                sourceDescriptor: {
                  arity: 4,
                  globalName: "__exactTcpConnect",
                  kind: "native-global-function",
                },
              },
            ],
            expectedResult: "return",
            expectedTypedDecisionCount: 0,
            expectedTypedStages: [],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.arguments[0]).toEqual({
        kind: "harness-loopback-client-handle",
      });
      expect(
        recipe.publicSurfaceProbe.invocation.setup[1].sourceDescriptorDigest,
      ).toMatch(/^sha256-/u);
    }
  });

  test("uses exact in-memory SQLite databases for zero-decision status and release", () => {
    for (const [globalName, statement] of [
      ["__exactSqliteClose", false],
      ["__exactSqliteExpandedSql", true],
      ["__exactSqliteFinalize", true],
      ["__exactSqliteInTransaction", false],
    ]) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
        scenario: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            expectedResult: "return",
            expectedTypedDecisionCount: 0,
            expectedTypedStages: [],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.arguments[0]).toEqual({
        kind: statement
          ? "harness-sqlite-statement-handle"
          : "harness-sqlite-database-handle",
      });
      expect(recipe.publicSurfaceProbe.invocation.setup[0]).toMatchObject({
        kind: "sqlite-memory-database",
        globalName: "__exactSqliteOpen",
        sourceDescriptor: {
          arity: 2,
          globalName: "__exactSqliteOpen",
          kind: "native-global-function",
        },
      });
      expect(
        recipe.publicSurfaceProbe.invocation.setup[0].sourceDescriptorDigest,
      ).toMatch(/^sha256-/u);
      if (statement) {
        expect(recipe.publicSurfaceProbe.invocation.setup[1]).toMatchObject({
          kind: "sqlite-memory-statement",
          globalName: "__exactSqlitePrepare",
          sourceDescriptor: {
            arity: 2,
            globalName: "__exactSqlitePrepare",
            kind: "native-global-function",
          },
        });
      }
    }
  });

  test("binds OS-info calls to exact typed selectors and stages", () => {
    const hostname = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactGetHostname",
    );
    expect(hostname).toHaveLength(2);
    expect(hostname.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
    ]);
    for (const recipe of hostname) {
      expect(recipe).toMatchObject({
        actionIds: ["sys:read"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            requiredFloor: [
              {
                cap: "sys:read",
                resource: { kind: "system-info", name: "hostname" },
              },
            ],
            expectedActionIds: ["sys:read"],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow"
          ? ["requested", "commit"]
          : ["requested"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "allow" ? 2 : 1);
    }
  });

  test("keeps bootstrap-internal manifest exports out of public probes", () => {
    const recipe = recipes.recipes.find(
      (candidate) =>
        candidate.scenario === "non-capability" &&
        candidate.route.surfaceObservedKeys.includes(
          "builtin:export:internal_fs_utils:toPathIfFileURL",
        ),
    );
    expect(recipe).toBeDefined();
    expect(recipe.publicSurfaceProbe).toBeNull();
    expect(recipe.residualReasons).toContain(
      "builtin-export-resolves-to-bootstrap-internal",
    );
    expect(recipe.residualReasons).not.toContain(
      "non-capability-no-decision-probe-not-authored",
    );
  });

  test("binds direct system-info calls to exact typed selectors and stages", () => {
    for (const { globalName, name } of [
      { globalName: "__exactGetProcessRSS", name: "memory" },
      { globalName: "__exactGetCwd", name: "cwd" },
    ]) {
      const directSystemInfo = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(directSystemInfo).toHaveLength(2);
      expect(directSystemInfo.map((recipe) => recipe.scenario)).toEqual([
        "allow",
        "deny",
      ]);
      for (const recipe of directSystemInfo) {
        expect(recipe).toMatchObject({
          actionIds: ["sys:read"],
          status: "fully-executable",
          residualReasons: [],
          publicSurfaceProbe: {
            invocation: {
              requiredFloor: [
                {
                  cap: "sys:read",
                  resource: { kind: "system-info", name },
                },
              ],
              expectedActionIds: ["sys:read"],
            },
          },
        });
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedStages,
        ).toEqual(
          recipe.scenario === "allow"
            ? ["requested", "commit"]
            : ["requested"],
        );
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        ).toBe(recipe.scenario === "allow" ? 2 : 1);
      }
    }
  });

  test("binds scalar environment reads to one exact broker-base name", () => {
    const environmentRead = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactGetEnv",
    );
    expect(environmentRead).toHaveLength(2);
    expect(environmentRead.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
    ]);
    for (const recipe of environmentRead) {
      expect(recipe).toMatchObject({
        actionIds: ["env:read"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [{ kind: "json-literal", value: "PATH" }],
            requiredFloor: [
              {
                cap: "env:read",
                resource: {
                  kind: "environment-name",
                  target: "broker-base",
                  name: "PATH",
                },
              },
            ],
            expectedActionIds: ["env:read"],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow"
          ? ["requested", "commit"]
          : ["requested"],
      );
    }
  });

  test("binds direct print to the exact stdout broker and generated stages", () => {
    const print = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "print",
    );
    expect(print).toHaveLength(2);
    expect(print.map((recipe) => recipe.scenario)).toEqual(["allow", "deny"]);
    for (const recipe of print) {
      expect(recipe).toMatchObject({
        actionIds: ["stdio:write"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [
              { kind: "json-literal", value: "ibex-capsec-print" },
            ],
            requiredFloor: [
              {
                cap: "stdio:write",
                resource: {
                  kind: "stdio",
                  stream: "stdout",
                  source: {
                    kind: "broker",
                    identity: "ibex:console:stdout",
                  },
                },
              },
            ],
            expectedActionIds: ["stdio:write"],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow"
          ? ["requested", "commit", "repeat"]
          : ["requested"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "allow" ? 3 : 1);
    }
  });

  test("binds project metadata reads to one stable retained path", () => {
    for (const globalName of ["__exactStat", "__exactLstat", "__exactRealpath"]) {
      const metadataReads = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(metadataReads).toHaveLength(2);
      expect(metadataReads.map((recipe) => recipe.scenario)).toEqual([
        "allow",
        "deny",
      ]);
      for (const recipe of metadataReads) {
        expect(recipe).toMatchObject({
          actionIds: ["fs:list"],
          status: "fully-executable",
          residualReasons: [],
          publicSurfaceProbe: {
            invocation: {
              arguments: [
                { kind: "json-literal", value: "Cargo.toml" },
                { kind: "json-literal", value: null },
              ],
              requiredFloor: [
                {
                  cap: "fs:list",
                  resource: {
                    kind: "path-exact",
                    path: {
                      root: "project",
                      components: [
                        { encoding: "utf8", value: "Cargo.toml" },
                      ],
                    },
                  },
                },
              ],
              expectedActionIds: ["fs:list"],
            },
          },
        });
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedStages,
        ).toEqual(
          recipe.scenario === "allow"
            ? ["requested", "discovery", "repeat"]
            : ["requested"],
        );
      }
    }
  });

  test("composes project lookup and content authority for whole-file reads", () => {
    const readFile = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactReadFile",
    );
    expect(readFile).toHaveLength(2);
    expect(readFile.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
    ]);
    for (const recipe of readFile) {
      expect(recipe).toMatchObject({
        actionIds: ["fs:list", "fs:read"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [
              { kind: "json-literal", value: "Cargo.toml" },
              { kind: "json-literal", value: null },
            ],
            requiredFloor: [
              {
                cap: "fs:list",
                resource: {
                  kind: "path-exact",
                  path: {
                    root: "project",
                    components: [
                      { encoding: "utf8", value: "Cargo.toml" },
                    ],
                  },
                },
              },
              {
                cap: "fs:read",
                resource: {
                  kind: "path-exact",
                  path: {
                    root: "project",
                    components: [
                      { encoding: "utf8", value: "Cargo.toml" },
                    ],
                  },
                },
              },
            ],
          },
        },
      });
      expect(
        recipe.publicSurfaceProbe.invocation.expectedActionIds,
      ).toEqual(
        recipe.scenario === "allow" ? ["fs:list", "fs:read"] : ["fs:list"],
      );
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow"
          ? ["requested", "discovery", "commit", "repeat"]
          : ["requested"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "allow" ? 4 : 1);
    }
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
