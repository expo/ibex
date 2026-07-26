import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
  deriveAdapterActionTemplate,
  fixtureScenario,
  nativeExpectedStageContractViolation,
} from "./capsec-conformance-recipes.mjs";
import { authoredNonCapabilityBuiltinProbe } from "./capsec-builtin-public-probe-templates.mjs";
import { authoredClosedPublicProbe } from "./capsec-closed-probe-templates.mjs";
import { authoredBuiltinPublicProbe } from "./capsec-public-probe-templates.mjs";
import {
  fixtureCatalogForTarget,
  fixtureExecutionPlans,
} from "./capsec-conformance.mjs";
import { validateOccurrenceSemantics } from "./capsec-contract.mjs";
import {
  INTERNAL_INVARIANT_COMMAND,
  INTERNALLY_VERIFIED_SCENARIOS,
  internalInvariantProofPlan,
} from "./capsec-internal-invariant-evidence.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";
import { validateStartupEnvironmentRecipeDescriptor } from "./capsec-public-surface-evidence.mjs";
import { CAPSEC_SECURE_TEST_FEATURES } from "./capsec-secure-test-command.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  authoredTargetAbsenceOutputBindings,
  targetAbsenceDispositionRationale,
} from "./capsec-target-absence-output-templates.mjs";

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
  let inventory;
  let rules;
  let selectorExamples;
  let windowsRecipes;
  let windowsExpectedFixtureIds;

  beforeAll(async () => {
    const coverage = readJson("capsec/registry/coverage-edges.json");
    const implementation = readJson(
      "capsec/generated/implementation-manifest.json",
    );
    rules = readJson("capsec/registry/policy-rules.json");
    const target = rules.initialProfile.candidateTargets.find(
      (candidate) => candidate.triple === "aarch64-apple-darwin",
    );
    const windowsTarget = rules.initialProfile.candidateTargets.find(
      (candidate) => candidate.triple === "x86_64-pc-windows-msvc",
    );
    if (!target || !windowsTarget) {
      throw new Error("expected both exact candidates");
    }
    const catalog = fixtureCatalogForTarget({
      coverage,
      implementation,
      target,
    });
    const windowsCatalog = fixtureCatalogForTarget({
      coverage,
      implementation,
      target: windowsTarget,
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
    inventory = await discoverRepositorySurfaces(repoRoot);
    recipes = buildConformanceRecipeCatalog({
      catalog,
      coverage,
      implementation,
      inventory,
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
      target,
    });
    windowsExpectedFixtureIds = fixtureExecutionPlans(windowsCatalog).map(
      (plan) => plan.fixtureId,
    );
    windowsRecipes = buildConformanceRecipeCatalog({
      catalog: windowsCatalog,
      coverage,
      implementation,
      inventory,
      occurrenceExamples,
      selectorExamples,
      capabilityDefinitions,
      target: windowsTarget,
    });
  }, 60_000);

  test("parses fixture scenarios by exact terminal suffix", () => {
    expect(() =>
      fixtureScenario("branch.logical.none.malformed-branch-facts"),
    ).toThrow(/unknown fixture scenario/);
    expect(fixtureScenario("branch.missing-attribution")).toBe(
      "missing-attribution",
    );
    expect(() => fixtureScenario("branch.looks-like-allowing")).toThrow(
      /unknown fixture scenario/,
    );
  });

  test("keeps every generated Cargo executor out of insecure mode", () => {
    const catalogs = [recipes, windowsRecipes];
    let cargoExecutorCount = 0;
    for (const recipeCatalog of catalogs) {
      for (const recipe of recipeCatalog.recipes) {
        const command = recipe.publicSurfaceProbe?.command;
        if (command?.[0] !== "cargo" || command[1] !== "test") {
          continue;
        }
        cargoExecutorCount += 1;
        expect(command).toContain("--no-default-features");
        expect(command).toContain(CAPSEC_SECURE_TEST_FEATURES);
        expect(command).not.toContain("insecure");
      }
    }
    expect(cargoExecutorCount).toBeGreaterThan(0);
  });

  test("deterministically balances native evidence across two disjoint commands", () => {
    const counts = new Map([
      ["capsec_public_native_primary_batch", 0],
      ["capsec_public_native_secondary_batch", 0],
    ]);
    for (const recipe of recipes.recipes) {
      const invocationSchema =
        recipe.publicSurfaceProbe?.invocation?.invocationSchema;
      if (
        ![
          "ibex/capsec-native-global-invocation/1",
          "ibex/capsec-host-abi-invocation/1",
          "ibex/capsec-module-loader-invocation/1",
        ].includes(invocationSchema)
      ) {
        continue;
      }
      const command = recipe.publicSurfaceProbe.command;
      const testName = command[7];
      expect(counts.has(testName)).toBeTrue();
      counts.set(testName, counts.get(testName) + 1);
    }
    const [primary, secondary] = counts.values();
    expect(primary).toBeGreaterThan(200);
    expect(secondary).toBeGreaterThan(200);
    expect(Math.abs(primary - secondary)).toBeLessThan(60);
  });

  test("binds only the six owned internal invariants to exact secure proofs", () => {
    for (const recipeCatalog of [recipes, windowsRecipes]) {
      const internal = recipeCatalog.recipes.filter(
        (recipe) => recipe.status === "internally-verified",
      );
      expect(
        [...new Set(internal.map((recipe) => recipe.scenario))].sort(),
      ).toEqual([...INTERNALLY_VERIFIED_SCENARIOS]);
      for (const recipe of internal) {
        expect(recipe.publicSurfaceProbe).toBeNull();
        expect(recipe.internalInvariantProof).toEqual(
          internalInvariantProofPlan(recipe.scenario),
        );
        expect(recipe.internalInvariantProof.command).toEqual(
          INTERNAL_INVARIANT_COMMAND,
        );
        expect(recipe.internalInvariantProof.command).toContain(
          "--no-default-features",
        );
        expect(recipe.internalInvariantProof.command).not.toContain("insecure");
      }
      const retiredMalformedFacts = recipeCatalog.recipes.filter(
        (recipe) => recipe.scenario === "malformed-branch-facts",
      );
      expect(retiredMalformedFacts).toHaveLength(0);
    }
  });

  test("keeps all 45 review-bound DNS derived operations residual", () => {
    const reviewId =
      "sha256-161c4e4bf9027d0d3e4f9427954c18529f7ef0bd727be9064fc8f79270a75c75";
    const rows = inventory.surfaces.filter(
      (row) => row.metadata?.dnsPromiseExportShapeReviewId === reviewId,
    );
    expect(rows).toHaveLength(45);
    expect(
      rows.filter(
        (row) => row.metadata.crossSourceExportProjection !== undefined,
      ),
    ).toHaveLength(42);
    expect(
      rows.filter(
        (row) => row.metadata.constructorInstanceProjection !== undefined,
      ),
    ).toHaveLength(3);

    const target = rules.initialProfile.candidateTargets.find(
      (candidate) => candidate.triple === "aarch64-apple-darwin",
    );
    expect(target).toBeDefined();
    const liveByObservedKey = new Map(
      rows.map((row) => [row.observedKey, row]),
    );
    for (const row of rows) {
      const evidence = row.metadata.enforcementRouteEvidence;
      expect(evidence.paths, row.observedKey).toEqual([]);
      expect(evidence.terminals, row.observedKey).toEqual([]);
      expect(evidence.ambiguousCallees, row.observedKey).toHaveLength(1);

      // Give each generic author the strongest synthetic direct route it
      // could accept. Shape projection is still presence evidence only, so no
      // author may turn it into an execution or enforcement claim.
      const route = {
        surfaceObservedKeys: [row.observedKey],
        alternatives: [
          {
            terminalObservedKey: row.observedKey,
            proofPaths: [row.observedKey],
          },
        ],
        ambiguousCallees: [],
      };
      const coverageByObservedKey = new Map([
        [
          row.observedKey,
          {
            id: "synthetic.review-bound-dns-shape",
            observedKey: row.observedKey,
            surface: { kind: row.kind, name: row.name },
            classification: "effects",
            effects: [],
          },
        ],
      ]);
      expect(
        authoredBuiltinPublicProbe({
          plan: {
            classification: "effects",
            actionIds: [],
            edgeIds: ["synthetic.review-bound-dns-shape"],
          },
          scenario: "allow",
          route,
          liveByObservedKey,
          coverageByObservedKey,
        }),
        row.observedKey,
      ).toBeNull();
      expect(
        authoredNonCapabilityBuiltinProbe({
          plan: {
            classification: "non-capability",
            actionIds: [],
            edgeIds: ["synthetic.review-bound-dns-shape"],
          },
          scenario: "non-capability",
          route,
          liveByObservedKey,
          target,
        }),
        row.observedKey,
      ).toBeNull();
      coverageByObservedKey.get(row.observedKey).classification = "closed";
      expect(
        authoredClosedPublicProbe({
          plan: {
            classification: "closed",
            actionIds: [],
            edgeIds: ["synthetic.review-bound-dns-shape"],
            expectedObservation: {
              kind: "enforcement-branch",
              branchId: "synthetic.review-bound-dns-shape",
            },
          },
          scenario: "closed",
          route,
          liveByObservedKey,
          coverageByObservedKey,
          target,
        }),
        row.observedKey,
      ).toBeNull();
    }
  });

  test("bounds native recipe stages to registry and source-bound internal contracts", () => {
    const semanticEffects = [
      { cap: "fs:list", stages: ["requested", "discovery"] },
    ];
    const exactFilesystemEdge = {
      surface: { kind: "native-op", name: "__exactFsPathAsync" },
      effects: semanticEffects,
    };
    expect(
      nativeExpectedStageContractViolation({
        actionIds: ["fs:list"],
        expectedStages: ["requested", "discovery", "repeat"],
        semanticEffects,
        coverageEdges: [exactFilesystemEdge],
      }),
    ).toBeNull();
    expect(
      nativeExpectedStageContractViolation({
        actionIds: ["fs:list"],
        expectedStages: ["requested", "delivery"],
        semanticEffects,
        coverageEdges: [exactFilesystemEdge],
      }),
    ).toMatch(/outside the registry.*delivery/u);
  });

  test("accounts for every obligation exactly once and reports honest residuals", () => {
    expect(recipes.recipeCatalogSchema).toBe(
      "ibex/capsec-executable-recipes/1",
    );
    expect(recipes.summary.requiredFixtures).toBe(23_840);
    // Invocation-time require activation adds source-derived obligations; the
    // six eager dynamic/require-link ABIs remain residual because the
    // production graph deliberately uses deferred call-time links. The net-new
    // WebGPU obligations remain unresolved until their public-surface probes
    // are authored.
    expect(recipes.summary.fullyExecutableFixtures).toBe(2_764);
    // Six internal callback-security invariant scenarios have owning Rust
    // mechanisms. Registry-owned branch-predicate validation is not expanded
    // into a fictitious per-public-surface malformed-input scenario.
    expect(recipes.summary.internallyVerifiedFixtures).toBe(3_136);
    expect(recipes.summary.unresolvedFixtures).toBe(17_940);
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
    // Callback-invariant probes intentionally take precedence for native
    // routes that this harness could otherwise claim structurally. The three
    // Branch-local filesystem closures use the closed-surface harness, while
    // the direct non-recursive mkdir branch adds one native selection proof.
    expect(nativePublicFixtures).toHaveLength(522);
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
      ["__exactTcpConnect", "malformed"],
      ["__exactTcpConnect", "missing-attribution"],
      ["__exactTcpConnect", "wrong-principal"],
    ]);
    expect(
      nativePublicFixtures.filter(
        (recipe) =>
          recipe.scenario === "non-capability" &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return",
      ),
    ).toHaveLength(243);
    expect(
      nativePublicFixtures.filter(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.expectedResult === "absent",
      ),
    ).toHaveLength(41);
    expect(recipes.summary.fullyExecutableFixtures).toBe(
      authoredPublicFixtures,
    );
    expect(recipes.summary.unresolvedFixtures).toBe(
      expectedFixtureIds.length -
        authoredPublicFixtures -
        recipes.summary.internallyVerifiedFixtures,
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

  test("accounts for the Windows candidate without borrowing Apple probes", () => {
    expect(windowsRecipes.target.triple).toBe("x86_64-pc-windows-msvc");
    expect(windowsRecipes.summary.requiredFixtures).toBe(
      windowsExpectedFixtureIds.length,
    );
    expect(windowsRecipes.summary.requiredFixtures).toBe(23_495);
    // Windows gains the same ten zero-decision node_fs constructor/pure-helper
    // proofs, while registrations from build.rs-replaced default translation
    // units remain target-absent instead of borrowing the POSIX branch.
    expect(windowsRecipes.summary.fullyExecutableFixtures).toBe(2_416);
    expect(windowsRecipes.summary.internallyVerifiedFixtures).toBe(3_122);
    expect(windowsRecipes.summary.unresolvedFixtures).toBe(17_957);
    const replacedWindowsCryptoRecipes = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.residualReasons.includes(
          "builtin-export-source-replaced-on-target",
        ),
    );
    expect(replacedWindowsCryptoRecipes).toHaveLength(0);
    const windowsCryptoRecipes = windowsRecipes.recipes.filter((recipe) =>
      recipe.terminalObservedKey.startsWith("builtin:export:exact_crypto:"),
    );
    expect(windowsCryptoRecipes).toHaveLength(201);
    expect(
      windowsCryptoRecipes.filter(
        (recipe) => recipe.status === "fully-executable",
      ),
    ).toHaveLength(95);
    const unavailableWindowsNativeRecipes = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.residualReasons.includes(
          "builtin-export-native-prerequisite-not-installed-on-target",
        ),
    );
    expect(unavailableWindowsNativeRecipes).toHaveLength(49);
    const unavailableWindowsBrotliRecipes =
      unavailableWindowsNativeRecipes.filter((recipe) =>
        recipe.terminalObservedKey.startsWith("builtin:export:node_zlib:"),
      );
    expect(unavailableWindowsBrotliRecipes).toHaveLength(46);
    expect(
      unavailableWindowsBrotliRecipes.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.terminalObservedKey.startsWith(
            "builtin:export:node_zlib:",
          ),
      ),
    ).toBe(true);
    const unavailableWindowsKdfs = unavailableWindowsNativeRecipes.filter(
      (recipe) =>
        [
          "builtin:export:exact_crypto:hkdfSync",
          "builtin:export:exact_crypto:pbkdf2Sync",
          "builtin:export:exact_crypto:scryptSync",
        ].includes(recipe.terminalObservedKey),
    );
    expect(unavailableWindowsKdfs).toHaveLength(3);
    expect(
      unavailableWindowsKdfs.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null,
      ),
    ).toBe(true);
    const unsupportedWindowsFilesystemRecipes = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.actionIds.some((actionId) => actionId.startsWith("fs:")) &&
        recipe.residualReasons.includes(
          "public-surface-filesystem-not-typed-on-target",
        ),
    );
    // The callable Windows filesystem surface remains untyped where it still
    // uses the legacy path oracle. POSIX-only globals instead receive one
    // exact absence fixture and are not counted as ambiguous Windows routes.
    expect(unsupportedWindowsFilesystemRecipes).toHaveLength(156);
    expect(
      unsupportedWindowsFilesystemRecipes.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null,
      ),
    ).toBe(true);
    const typedWindowsWholeFileReads = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactReadFile",
    );
    expect(typedWindowsWholeFileReads).toHaveLength(5);
    expect(
      typedWindowsWholeFileReads.map((recipe) => [
        recipe.scenario,
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        recipe.publicSurfaceProbe.invocation.expectedTypedStages,
      ]),
    ).toEqual([
      ["allow", 4, ["requested", "discovery", "commit", "repeat"]],
      ["deny", 1, ["requested"]],
      ["malformed", 4, ["requested", "discovery", "commit", "repeat"]],
      [
        "missing-attribution",
        4,
        ["requested", "discovery", "commit", "repeat"],
      ],
      [
        "wrong-principal",
        4,
        ["requested", "discovery", "commit", "repeat"],
      ],
    ]);
    const typedWindowsStats = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactStat",
    );
    expect(typedWindowsStats).toHaveLength(5);
    expect(
      typedWindowsStats.map((recipe) => [
        recipe.scenario,
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        recipe.publicSurfaceProbe.invocation.expectedTypedStages,
      ]),
    ).toEqual([
      ["allow", 3, ["requested", "discovery", "repeat"]],
      ["deny", 1, ["requested"]],
      ["malformed", 3, ["requested", "discovery", "repeat"]],
      ["missing-attribution", 3, ["requested", "discovery", "repeat"]],
      ["wrong-principal", 3, ["requested", "discovery", "repeat"]],
    ]);
    const typedWindowsLstats = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactLstat",
    );
    expect(typedWindowsLstats).toHaveLength(5);
    expect(
      typedWindowsLstats.map((recipe) => [
        recipe.scenario,
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        recipe.publicSurfaceProbe.invocation.expectedTypedStages,
      ]),
    ).toEqual([
      ["allow", 3, ["requested", "discovery", "repeat"]],
      ["deny", 1, ["requested"]],
      ["malformed", 3, ["requested", "discovery", "repeat"]],
      ["missing-attribution", 3, ["requested", "discovery", "repeat"]],
      ["wrong-principal", 3, ["requested", "discovery", "repeat"]],
    ]);
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName ===
            "__exactFsOpenAsync" &&
          recipe.scenario === "absent" &&
          recipe.publicSurfaceProbe.kind === "target-absence-probe",
      ),
    ).toHaveLength(1);
    const windowsFsClose = windowsRecipes.recipes.find(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:__exactFsClose" &&
        recipe.scenario === "non-capability",
    );
    expect(windowsFsClose.publicSurfaceProbe).toBeNull();
    expect(windowsFsClose.residualReasons).toContain(
      "native-public-prerequisite-not-typed-on-target",
    );
    const unsupportedWindowsNetworkRecipes = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.actionIds.some((actionId) => actionId.startsWith("network:")) &&
        recipe.residualReasons.includes(
          "public-surface-network-not-typed-on-target",
        ),
    );
    expect(unsupportedWindowsNetworkRecipes).toHaveLength(5);
    expect(
      unsupportedWindowsNetworkRecipes.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.terminalObservedKey === "native-op:__exactTcpConnect",
      ),
    ).toBe(true);
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactTcpConnect",
      ),
    ).toHaveLength(0);
    for (const globalName of [
      "__exactTcpClose",
      "__exactTcpReset",
      "__exactTcpShutdown",
    ]) {
      const recipe = windowsRecipes.recipes.find(
        (candidate) =>
          candidate.terminalObservedKey === `native-op:${globalName}` &&
          candidate.scenario === "non-capability",
      );
      expect(recipe.publicSurfaceProbe).toBeNull();
      expect(recipe.residualReasons).toContain(
        "native-public-prerequisite-not-typed-on-target",
      );
    }
    for (const globalName of ["__exactUdpClose", "__exactUdpSocket"]) {
      const recipe = windowsRecipes.recipes.find(
        (candidate) =>
          candidate.terminalObservedKey === `native-op:${globalName}` &&
          candidate.scenario === "non-capability",
      );
      expect(recipe.publicSurfaceProbe).toBeNull();
      expect(recipe.residualReasons).toContain(
        "native-public-operation-not-installed-on-target",
      );
    }
    const windowsExcludedDefaultGlobals = new Set([
      "__exactAesCbcDecrypt",
      "__exactAesCbcEncrypt",
      "__exactAesCtrEncrypt",
      "__exactAesGcmDecrypt",
      "__exactAesGcmEncrypt",
      "__exactBrotliCompressSync",
      "__exactBrotliDecompressSync",
      "__exactEcdhDeriveBits",
      "__exactEcdsaSign",
      "__exactEcdsaVerify",
      "__exactEd25519Sign",
      "__exactEd25519Verify",
      "__exactEvpCipherDecrypt",
      "__exactEvpCipherEncrypt",
      "__exactExportKeyPkcs8",
      "__exactExportKeySpki",
      "__exactFsCloseAsync",
      "__exactGenerateKeyPairSync",
      "__exactGetProcessRSS",
      "__exactHkdf",
      "__exactImportKeyPkcs8",
      "__exactImportKeySpki",
      "__exactPbkdf2",
      "__exactPerformanceNow",
      "__exactPerformanceTimeOrigin",
      "__exactRsaOaepDecrypt",
      "__exactRsaOaepEncrypt",
      "__exactScryptSync",
      "__exactSignSync",
      "__exactSignalNumbers",
      "__exactVerifySync",
      "__exactX25519DeriveBits",
    ]);
    const windowsExcludedDefaultRecipes = windowsRecipes.recipes.filter(
      (recipe) => {
        const globalName = recipe.terminalObservedKey.replace(
          "native-op:",
          "",
        );
        return windowsExcludedDefaultGlobals.has(globalName);
      },
    );
    expect(windowsExcludedDefaultGlobals.size).toBe(32);
    expect(windowsExcludedDefaultRecipes).toHaveLength(32);
    expect(
      windowsExcludedDefaultRecipes.every(
        (recipe) =>
          recipe.scenario === "absent" &&
          recipe.status === "fully-executable" &&
          recipe.publicSurfaceProbe?.kind === "target-absence-probe" &&
          recipe.residualReasons.length === 0,
      ),
    ).toBe(true);
    const windowsBytesToUtf8 = windowsRecipes.recipes.find(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:__exactBytesToUtf8String" &&
        recipe.scenario === "non-capability",
    );
    expect(windowsBytesToUtf8.status).toBe("fully-executable");
    expect(windowsBytesToUtf8.publicSurfaceProbe).not.toBeNull();
    const windowsAbsenceRecipes = windowsRecipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.kind === "target-absence-probe",
    );
    // The exact Windows plan includes the existing platform exclusions plus
    // every POSIX-only native global omitted by the Windows build.
    expect(windowsAbsenceRecipes).toHaveLength(95);
    expect(
      windowsAbsenceRecipes.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.expectedResult === "absent" &&
          recipe.publicSurfaceProbe.command.some((part) =>
            [
              "capsec_public_native_primary_batch",
              "capsec_public_native_secondary_batch",
            ].includes(part),
          ) &&
          !recipe.publicSurfaceProbe.command.includes(
            "capsec_public_target_absence_batch",
          ),
      ),
    ).toBe(true);
    expect(
      windowsRecipes.recipes.filter((recipe) =>
        recipe.publicSurfaceProbe?.command?.includes(
          "capsec_public_closed_recipe_batch",
        ),
      ),
    ).toHaveLength(680);
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
          "debugger-abi-disabled",
      ),
    ).toHaveLength(18);
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
          "shared-runtime-global-absence",
      ),
    ).toHaveLength(322);
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
          "armed-native-global-absence",
      ),
    ).toHaveLength(11);
  });

  test("authors every node:os effect scenario without hand-labeling a native terminal", () => {
    const osRecipes = recipes.recipes.filter((recipe) =>
      recipe.route.surfaceObservedKeys.includes("builtin:export:node_os:cpus"),
    );
    expect(osRecipes.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
    ]);
    expect(
      osRecipes.every((recipe) => recipe.status === "fully-executable"),
    ).toBe(true);
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
    for (const exportName of [
      "accessSync",
      "existsSync",
      "lstatSync",
      "realpathSync",
      "statfsSync",
      "statSync",
    ]) {
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
        if (exportName === "existsSync") {
          expect(recipe.publicSurfaceProbe.invocation).toMatchObject({
            expectedResult: "boolean-return",
            expectedBooleanValue: recipe.scenario !== "deny",
          });
        }
        expect(recipe.residualReasons).not.toContain(
          "ambiguous-static-enforcement-route",
        );
        if (exportName === "realpathSync") {
          expect(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor
              .auxiliaryDecisionEdges,
          ).toEqual([
            {
              edgeId: "surface.native.op.exactgetcwd.1bhagb7",
              observedKey: "native-op:__exactGetCwd",
              actionIds: ["path:cwd-observe"],
            },
            {
              edgeId: "surface.native.op.exactlstat.1c98s6l",
              observedKey: "native-op:__exactLstat",
              actionIds: ["fs:list"],
            },
          ]);
          expect(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor
              .denialTerminalEdgeId,
          ).toBe("surface.native.op.exactlstat.1c98s6l");
          expect(
            recipe.publicSurfaceProbe.invocation.allowedCoverageEdgeIds,
          ).toEqual([
            "surface.native.op.exactaccess.1a12cmn",
            "surface.native.op.exactensurefs.1dih7no",
            "surface.native.op.exactgetcwd.1bhagb7",
            "surface.native.op.exactlstat.1c98s6l",
            "surface.native.op.exactrealpath.06qb6s2",
          ]);
        } else {
          expect(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor,
          ).not.toHaveProperty("auxiliaryDecisionEdges");
          expect(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor,
          ).not.toHaveProperty("denialTerminalEdgeId");
        }
        const denial = recipe.scenario === "deny";
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedStages,
        ).toEqual(
          denial
            ? exportName === "realpathSync"
              ? ["requested", "commit", "requested"]
              : ["requested"]
            : ["accessSync", "existsSync", "statfsSync"].includes(exportName)
              ? [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "repeat",
                  "repeat",
                ]
              : exportName === "realpathSync"
                ? [
                    "requested",
                    "commit",
                    "requested",
                    "discovery",
                    "requested",
                    "repeat",
                    "requested",
                    "discovery",
                    "requested",
                    "repeat",
                    "repeat",
                    "repeat",
                  ]
                : exportName === "statSync"
                  ? ["requested", "discovery", "requested", "repeat", "repeat"]
                  : ["requested", "discovery", "requested", "repeat"],
        );
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        ).toBe(
          denial
            ? exportName === "realpathSync"
              ? 3
              : 1
            : ["accessSync", "existsSync", "statfsSync"].includes(exportName)
              ? 6
              : exportName === "realpathSync"
                ? 12
                : exportName === "statSync"
                  ? 5
                  : 4,
        );
      }
    }
  });

  test("truncates the exact retained file and denies before mutation", () => {
    const surface = "builtin:export:node_fs:truncateSync";
    const truncateRecipes = recipes.recipes.filter(
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
    expect(truncateRecipes).toHaveLength(5);
    for (const recipe of truncateRecipes) {
      const denial = recipe.scenario === "deny";
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "truncateSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-stat-fixture.txt" },
                  ],
                },
              },
              { kind: "literal-json", value: 2 },
            ],
            setup: {
              kind: "filesystem-file",
              contents: "ibex-capsec-stat-fixture\n",
            },
            requiredAuthority: [
              {
                cap: "fs:write",
                resource: { kind: "path-exact" },
              },
            ],
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: denial ? 5 : 6,
            expectedTypedStages: denial
              ? ["requested", "discovery", "requested", "repeat", "commit"]
              : [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "commit",
                  "repeat",
                ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactfsftruncatesync.0un4ty5",
              "surface.native.op.exacttruncate.13gh223",
            ],
            expectedActionIds: ["fs:write"],
          },
        },
      });
    }
  });

  test("appends to the exact retained file and denies before mutation", () => {
    const surface = "builtin:export:node_fs:appendFileSync";
    const appendRecipes = recipes.recipes.filter(
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
    expect(appendRecipes).toHaveLength(5);
    for (const recipe of appendRecipes) {
      const denial = recipe.scenario === "deny";
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "appendFileSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-stat-fixture.txt" },
                  ],
                },
              },
              {
                kind: "literal-utf8",
                value: "ibex-capsec-write-fixture\n",
              },
            ],
            setup: {
              kind: "filesystem-file",
              contents: "ibex-capsec-stat-fixture\n",
            },
            requiredAuthority: [
              {
                cap: "fs:write",
                resource: { kind: "path-exact" },
              },
            ],
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: denial ? 6 : 7,
            expectedTypedStages: denial
              ? [
                  "requested",
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "commit",
                ]
              : [
                  "requested",
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "commit",
                  "repeat",
                ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactfsclose.0r6l8ou",
              "surface.native.op.exactfsfsyncsync.02nw7ns",
              "surface.native.op.exactfsopen.05ao6wa",
              "surface.native.op.exactfswrite.1locgj1",
            ],
            expectedActionIds: ["fs:write"],
          },
        },
      });
    }
  });

  test("creates only the exact non-recursive directory and denies before creation", () => {
    const surface = "builtin:export:node_fs:mkdirSync";
    const mkdirRecipes = recipes.recipes.filter(
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
    expect(mkdirRecipes).toHaveLength(5);
    for (const recipe of mkdirRecipes) {
      const denial = recipe.scenario === "deny";
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "mkdirSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-created-directory" },
                  ],
                },
              },
              { kind: "literal-json", value: { recursive: false } },
            ],
            setup: {
              kind: "filesystem-absent-directory",
              logicalPath: {
                root: "project",
                components: [
                  { encoding: "utf8", value: "capsec-created-directory" },
                ],
              },
            },
            requiredAuthority: [
              {
                cap: "fs:write",
                resource: { kind: "path-exact" },
              },
            ],
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: 5,
            expectedTypedStages: [
              "requested",
              "discovery",
              "requested",
              "requested",
              "discovery",
            ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactmkdir.021eaz0",
              "surface.native.op.exactstat.1432ztv",
            ],
            expectedActionIds: ["fs:write"],
          },
        },
      });
    }
  });

  test("reads link bytes only after exact fs:read commit and binds the translated result", () => {
    const surface = "builtin:export:node_fs:readlinkSync";
    const readlinkRecipes = recipes.recipes.filter(
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
    expect(readlinkRecipes).toHaveLength(5);
    for (const recipe of readlinkRecipes) {
      const denial = recipe.scenario === "deny";
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "readlinkSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-readlink-fixture" },
                  ],
                },
              },
            ],
            setup: {
              kind: "filesystem-symlink",
              storedTarget: "capsec-readlink-target.txt",
              target: {
                logicalPath: {
                  root: "project",
                  components: [
                    {
                      encoding: "utf8",
                      value: "capsec-readlink-target.txt",
                    },
                  ],
                },
                contents: "ibex-capsec-readlink-target\n",
              },
            },
            requiredAuthority: [
              {
                cap: "fs:read",
                resource: { kind: "path-exact" },
              },
            ],
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: denial ? 5 : 8,
            expectedTypedStages: denial
              ? ["requested", "discovery", "requested", "repeat", "commit"]
              : [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "commit",
                  "discovery",
                  "requested",
                  "repeat",
                ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactreadlink.1p5ozx1",
            ],
            expectedActionIds: ["fs:read"],
          },
        },
      });
      if (denial) {
        expect(
          recipe.publicSurfaceProbe.invocation,
        ).not.toHaveProperty("expectedStringValue");
      } else {
        expect(
          recipe.publicSurfaceProbe.invocation.expectedStringValue,
        ).toBe("capsec-readlink-target.txt");
      }
    }

  });

  test("opens exact files with flag-selected authority and closes every returned descriptor", () => {
    const surface = "builtin:export:node_fs:openSync";
    const openRecipes = recipes.recipes.filter((recipe) =>
      recipe.route.surfaceObservedKeys.includes(surface),
    );
    const branchByActions = new Map([
      [
        JSON.stringify(["fs:list", "fs:read"]),
        { flags: "r", requiredCaps: ["fs:read"] },
      ],
      [
        JSON.stringify(["fs:list", "fs:write"]),
        { flags: "a", requiredCaps: ["fs:write"] },
      ],
      [
        JSON.stringify(["fs:list", "fs:read", "fs:write"]),
        { flags: "r+", requiredCaps: ["fs:read", "fs:write"] },
      ],
    ]);
    const executable = openRecipes.filter(
      (recipe) => recipe.status === "fully-executable",
    );
    const branchSelection = openRecipes.filter(
      (recipe) => recipe.scenario === "branch-selection",
    );
    expect(openRecipes).toHaveLength(18);
    expect(executable).toHaveLength(15);
    expect(branchSelection).toHaveLength(3);

    for (const recipe of executable) {
      const denial = recipe.scenario === "deny";
      const branch = branchByActions.get(JSON.stringify(recipe.actionIds));
      expect(branch).toBeDefined();
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "openSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-stat-fixture.txt" },
                  ],
                },
              },
              { kind: "literal-utf8", value: branch.flags },
            ],
            setup: {
              kind: "filesystem-file",
              contents: "ibex-capsec-stat-fixture\n",
            },
            requiredAuthority: branch.requiredCaps.map((cap) => ({
              cap,
              resource: { kind: "path-exact" },
            })),
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: 6,
            expectedTypedStages: [
              "requested",
              "requested",
              "discovery",
              "requested",
              "repeat",
              "commit",
            ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactfsopen.05ao6wa",
            ],
            expectedActionIds: recipe.actionIds,
          },
        },
      });
      if (denial) {
        expect(recipe.publicSurfaceProbe.invocation).not.toHaveProperty(
          "expectedCleanup",
        );
      } else {
        expect(
          recipe.publicSurfaceProbe.invocation.expectedCleanup,
        ).toBe("closed-fs-file-descriptor");
      }
    }

    for (const recipe of branchSelection) {
      expect(branchByActions.has(JSON.stringify(recipe.actionIds))).toBe(true);
      expect(recipe).toMatchObject({
        status: "unresolved",
        publicSurfaceProbe: null,
      });
      expect(recipe.residualReasons).toContain(
        "conditional-branch-selection-probe-not-authored",
      );
    }

    const windowsReadOpenRows = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactFsOpen" &&
        recipe.fixtureId.includes(".logical.read."),
    );
    expect(windowsReadOpenRows).toHaveLength(6);
    for (const recipe of windowsReadOpenRows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : ["requested", "discovery", "commit"],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 3,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
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
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "repeat",
              "repeat",
              "repeat",
            ],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(denial ? 1 : 7);
    }
  });

  test("materializes and closes an exact empty directory object", () => {
    const surface = "builtin:export:node_fs:opendirSync";
    const directoryRecipes = recipes.recipes.filter(
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
    expect(directoryRecipes).toHaveLength(5);
    for (const recipe of directoryRecipes) {
      const denial = recipe.scenario === "deny";
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: surface,
          invocation: {
            moduleSpecifier: "node:fs",
            exportName: "opendirSync",
            arguments: [
              {
                kind: "filesystem-fixture-path",
                logicalPath: {
                  root: "project",
                  components: [
                    { encoding: "utf8", value: "capsec-directory-fixture" },
                  ],
                },
              },
            ],
            setup: {
              kind: "filesystem-directory",
              entries: [],
            },
            requiredAuthority: [
              {
                cap: "fs:list",
                resource: { kind: "path-exact" },
              },
            ],
            expectedResult: denial ? "permission-denied" : "return",
            expectedTypedDecisionCount: denial ? 1 : 7,
            expectedTypedStages: denial
              ? ["requested"]
              : [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "repeat",
                  "repeat",
                  "repeat",
                ],
            allowedCoverageEdgeIds: [
              "surface.native.op.exactensurefs.1dih7no",
              "surface.native.op.exactlstat.1c98s6l",
              "surface.native.op.exactreaddir.0tg30vk",
            ],
            expectedActionIds: ["fs:list"],
          },
        },
      });
      if (denial) {
        expect(recipe.publicSurfaceProbe.invocation).not.toHaveProperty(
          "expectedCleanup",
        );
      } else {
        expect(
          recipe.publicSurfaceProbe.invocation.expectedCleanup,
        ).toBe("closed-fs-directory");
      }
    }
  });

  test("authors only exact callback mechanisms and residualizes rationale-only carriers", () => {
    const callbackRecipes = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-callback-invariant-invocation/1",
    );
    expect(callbackRecipes).toHaveLength(8);
    expect(
      callbackRecipes.every(
        (recipe) =>
          recipe.scenario === "non-capability" &&
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.kind === "public-surface-invocation" &&
          recipe.publicSurfaceProbe.surfaceObservedKey ===
            recipe.terminalObservedKey,
      ),
    ).toBe(true);

    const rationaleScenarios = [
      "attribution-missing-deny",
      "generation-recheck",
      "principal-restore",
      "snapshot-mismatch-deny",
      "cannot-widen-authority",
      "post-lockdown-invariant",
    ];
    const rationaleOnly = recipes.recipes.filter((recipe) =>
      rationaleScenarios.includes(recipe.scenario),
    );
    expect(rationaleOnly).toHaveLength(3_136);
    expect(
      Object.fromEntries(
        rationaleScenarios.map((scenario) => [
          scenario,
          rationaleOnly.filter((recipe) => recipe.scenario === scenario).length,
        ]),
      ),
    ).toEqual({
      "attribution-missing-deny": 517,
      "generation-recheck": 517,
      "principal-restore": 517,
      "snapshot-mismatch-deny": 517,
      "cannot-widen-authority": 534,
      "post-lockdown-invariant": 534,
    });
    // These are internal callback-security invariant scenarios: attested by
    // internal Rust proofs, not public-surface probes, so they carry the
    // internally-verified status while still recording the residual reason that
    // documents the public-surface gap and having no public probe (LLP 0036).
    expect(
      rationaleOnly.every(
        (recipe) =>
          recipe.status === "internally-verified" &&
          recipe.publicSurfaceProbe === null &&
          recipe.residualReasons.includes(
            `callback-invariant-${recipe.scenario}-probe-not-authored`,
          ),
      ),
    ).toBe(true);
    const arbitraryCarrier = rationaleOnly.find(
      (recipe) =>
        recipe.terminalObservedKey ===
          "host-abi:ex_hermes_structured_session_bind" &&
        recipe.scenario === "cannot-widen-authority",
    );
    expect(arbitraryCarrier).toMatchObject({
      status: "internally-verified",
      publicSurfaceProbe: null,
    });

    const exactMechanisms = new Map([
      ["callback:exact-host-call-async-resolve", "exact-host-call-round-trip"],
      [
        "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
        "exact-host-call-round-trip",
      ],
      [
        "host-abi:ex_hermes_resolve_exact_host_call",
        "exact-host-call-round-trip",
      ],
      [
        "host-abi:ex_hermes_set_exact_host_call_async",
        "exact-endowment-install",
      ],
      [
        "host-abi:ex_host_authorize_exact_endowment",
        "exact-endowment-authorize",
      ],
      [
        "host-abi:ex_host_build_exact_armed_embedder_artifacts",
        "exact-artifact-prepare-round-trip",
      ],
      [
        "host-abi:ex_host_prepare_armed_embedder_artifacts",
        "exact-artifact-prepare-round-trip",
      ],
      [
        "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
        "exact-artifact-prepare-round-trip",
      ],
    ]);
    const exactRows = callbackRecipes.filter(
      (recipe) => recipe.scenario === "non-capability",
    );
    expect(exactRows).toHaveLength(exactMechanisms.size);
    for (const recipe of exactRows) {
      expect(recipe).toMatchObject({
        classification: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        actionIds: [],
        publicSurfaceProbe: {
          invocation: {
            expectedResult: "invariant-passed",
            expectedTypedDecisionCount: 0,
            expectedTypedStages: [],
            expectedTypedOutcomes: [],
            expectedTypedReasons: [],
            allowedCoverageEdgeIds: [],
            expectedActionIds: [],
            sourceDescriptor: {
              scenario: "non-capability",
              proofScope: "source-bound-exact-mechanism",
              surfaceObservedKey: recipe.terminalObservedKey,
              executionMechanism: exactMechanisms.get(
                recipe.terminalObservedKey,
              ),
              auxiliaryDecisionEdgeId: null,
            },
          },
        },
      });
      expect(exactMechanisms.has(recipe.terminalObservedKey)).toBe(true);
    }
  });

  test("binds native public probes to source-derived JSI descriptors", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactTcpConnect",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      expect(recipe.publicSurfaceProbe.command.slice(0, 7)).toEqual([
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--no-default-features",
        "--features",
        "standard,capsec-conformance-observer,openssl-crypto",
      ]);
      expect([
        "capsec_public_native_primary_batch",
        "capsec_public_native_secondary_batch",
      ]).toContain(recipe.publicSurfaceProbe.command[7]);
      expect(recipe.publicSurfaceProbe.command.slice(8)).toEqual([
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
        recipe.scenario === "deny"
          ? ["requested"]
          : ["requested", "candidate", "commit"],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 3,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("keeps asynchronous typed filesystem observations open through quiescence", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" &&
        ["readdir", "realpath"].some((branch) =>
          recipe.fixtureId.includes(`.logical.${branch}.`),
        ),
    );
    expect(rows).toHaveLength(12);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation).toMatchObject({
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: "__exactFsPathAsync",
        sourceDescriptor: {
          arity: 6,
          globalName: "__exactFsPathAsync",
          kind: "native-global-function",
          sourceRef:
            "src/engine/hermes_runtime_fs.cc#jsi-global:__exactFsPathAsync",
        },
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        expectedDenyMessageFragment: "filesystem policy denied",
        expectedActionIds: ["fs:list"],
      });
      expect(invocation.arguments).toHaveLength(6);
      expect(invocation.allowedCoverageEdgeIds).toEqual(
        recipe.fixtureId.includes(".logical.readdir.")
          ? [
              "surface.native.op.exactfspathasync.10cb78b",
              "surface.native.op.exactreaddir.0tg30vk",
            ]
          : [
              "surface.native.op.exactfspathasync.10cb78b",
              "surface.native.op.exactrealpath.06qb6s2",
            ],
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : recipe.fixtureId.includes(".logical.readdir.")
            ? [
                "requested",
                "discovery",
                "requested",
                "repeat",
                "repeat",
                "repeat",
                "repeat",
              ]
            : [
                "requested",
                "discovery",
                "requested",
                "repeat",
                "repeat",
                "repeat",
              ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny"
          ? 1
          : recipe.fixtureId.includes(".logical.readdir.")
            ? 7
            : 6,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("proves async directory creation through retained typed objects and owned cleanup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" &&
        recipe.fixtureId.includes(".logical.mkdir."),
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation).toMatchObject({
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        expectedCleanup: "removed-created-directory",
        expectedDenyMessageFragment: "filesystem policy denied",
        allowedCoverageEdgeIds: [
          "surface.native.op.exactfspathasync.10cb78b",
          "surface.native.op.exactmkdir.021eaz0",
        ],
      });
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.arguments).toHaveLength(6);
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "requested",
              "discovery",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 7,
      );
      expect(invocation.requiredFloor.map((selector) => selector.cap)).toEqual([
        "fs:list",
        "fs:write",
      ]);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("closes armed async mkdtemp before path lookup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:__exactFsPathAsync" &&
        recipe.fixtureId.includes(".logical.mkdtemp."),
    );
    expect(rows).toHaveLength(2);
    const closed = rows.find((recipe) => recipe.scenario === "closed");
    expect(closed).toMatchObject({
      classification: "closed",
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        invocation: {
          operation: {
            kind: "filesystem-unbound-mutation",
            surfaceForm: "native-dispatcher",
            guardOperation: "mkdtemp",
          },
        },
      },
    });
    expect(
      rows.find((recipe) => recipe.scenario === "branch-selection"),
    ).toMatchObject({
      classification: "closed",
      status: "unresolved",
      publicSurfaceProbe: null,
    });
  });

  test("binds async statfs metadata to the retained object", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" && recipe.fixtureId.includes(".logical.statfs."),
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "json-literal", value: "statfs" },
        { kind: "json-literal", value: "Cargo.toml" },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
      ]);
      expect(invocation.allowedCoverageEdgeIds).toEqual([
        "surface.native.op.exactfspathasync.10cb78b",
        "surface.native.op.exactstatfs.151kkzo",
      ]);
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedActionIds).toEqual(["fs:list"]);
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "repeat",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 6,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("truncates only an owned retained file and proves cleanup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" &&
        recipe.fixtureId.includes(".logical.truncate."),
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments.slice(0, 4)).toEqual([
        { kind: "json-literal", value: "truncate" },
        {
          kind: "json-literal",
          value: "target/ibex-capsec-fspathasync-truncate",
        },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 2 },
      ]);
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.allowedCoverageEdgeIds).toEqual([
        "surface.native.op.exactfspathasync.10cb78b",
        "surface.native.op.exacttruncate.13gh223",
      ]);
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 8,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("changes mode only on an owned retained file and proves cleanup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" && recipe.fixtureId.includes(".logical.chmod."),
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments.slice(0, 4)).toEqual([
        { kind: "json-literal", value: "chmod" },
        {
          kind: "json-literal",
          value: "target/ibex-capsec-fspathasync-chmod",
        },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 0o600 },
      ]);
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 8,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("changes timestamps only on an owned retained file and proves cleanup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsPathAsync" && recipe.fixtureId.includes(".logical.utime."),
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "json-literal", value: "utime" },
        {
          kind: "json-literal",
          value: "target/ibex-capsec-fspathasync-utime",
        },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 1 },
        { kind: "json-literal", value: 2 },
        { kind: "json-literal", value: 0 },
      ]);
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 8,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("executes the direct native statfs metadata surface", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactStatfs",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "json-literal", value: "Cargo.toml" },
      ]);
      expect(invocation.expectedActionIds).toEqual(["fs:list"]);
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "repeat",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 6,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("truncates a direct native path through a retained object", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactTruncate",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "json-literal", value: "target/ibex-capsec-truncate" },
        { kind: "json-literal", value: 2 },
      ]);
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 8,
      );
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
    expect(
      windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactTruncate",
      ),
    ).toHaveLength(0);
  });

  test("creates a direct native directory only under an exact owned floor", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactMkdir",
    );
    expect(rows).toHaveLength(6);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        {
          kind: "json-literal",
          value: "target/ibex-capsec-mkdir",
        },
        { kind: "json-literal", value: false },
        { kind: "json-literal", value: -1 },
      ]);
      expect(invocation.expectedCleanup).toBe("removed-created-directory");
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "requested",
              "discovery",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 7,
      );
      expect(invocation.requiredFloor.map((selector) => selector.cap)).toEqual([
        "fs:list",
        "fs:write",
      ]);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("writes a direct native file only under an exact owned floor", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactWriteFile",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments[0]).toEqual({
        kind: "json-literal",
        value: "target/ibex-capsec-write-file",
      });
      expect(invocation.arguments[1]).toMatchObject({
        kind: "native-global-result",
        globalName: "__exactStringToUtf8Bytes",
        sourceDescriptor: {
          arity: 1,
          globalName: "__exactStringToUtf8Bytes",
        },
      });
      expect(invocation.arguments[2]).toEqual({
        kind: "json-literal",
        value: null,
      });
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "requested",
              "discovery",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 9,
      );
      expect(invocation.requiredFloor.map((selector) => selector.cap)).toEqual([
        "fs:list",
        "fs:write",
      ]);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("appends a direct native file only under an exact owned floor", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactAppendFile",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments[0]).toEqual({
        kind: "json-literal",
        value: "target/ibex-capsec-append-file",
      });
      expect(invocation.arguments[1]).toMatchObject({
        kind: "native-global-result",
        globalName: "__exactStringToUtf8Bytes",
        sourceDescriptor: {
          arity: 1,
          globalName: "__exactStringToUtf8Bytes",
        },
      });
      expect(invocation.arguments[2]).toEqual({
        kind: "json-literal",
        value: null,
      });
      expect(invocation.expectedCleanup).toBe("removed-owned-file");
      expect(invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:write"],
      );
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 8,
      );
      expect(invocation.requiredFloor.map((selector) => selector.cap)).toEqual([
        "fs:list",
        "fs:write",
      ]);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("opens and closes exact owned files for every sync and async access branch", () => {
    const branches = new Map([
      [
        "read",
        {
          actionIds: ["fs:list", "fs:read"],
          flags: "r",
          fixture: "ibex-capsec-fsopen-read",
        },
      ],
      [
        "read-write",
        {
          actionIds: ["fs:list", "fs:read", "fs:write"],
          flags: "r+",
          fixture: "ibex-capsec-fsopen-read-write",
        },
      ],
      [
        "write",
        {
          actionIds: ["fs:list", "fs:write"],
          flags: "a",
          fixture: "ibex-capsec-fsopen-write",
        },
      ],
    ]);
    for (const [globalName, async] of [
      ["__exactFsOpen", false],
      ["__exactFsOpenAsync", true],
    ]) {
      const rows = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(rows).toHaveLength(18);
      for (const recipe of rows) {
        const branchEntry = [...branches.entries()].find(([branchId]) =>
          recipe.fixtureId.includes(`.logical.${branchId}.${recipe.scenario}`),
        );
        expect(branchEntry).toBeDefined();
        const [branchId, branch] = branchEntry;
        const fixture = async
          ? branch.fixture.replace("fsopen-", "fsopen-async-")
          : branch.fixture;
        const invocation = recipe.publicSurfaceProbe.invocation;
        expect(invocation.arguments).toEqual([
          {
            kind: "json-literal",
            value: `target/${fixture}`,
          },
          { kind: "json-literal", value: branch.flags },
          { kind: "json-literal", value: 0o666 },
          { kind: "json-literal", value: null },
        ]);
        expect(invocation.completion ?? null).toEqual(
          async
            ? {
                kind: "event-loop-quiescence",
                timeoutMilliseconds: 1_000,
              }
            : null,
        );
        expect(invocation.allowedCoverageEdgeIds).toHaveLength(async ? 2 : 1);
        expect(invocation.expectedCleanup).toBe(
          "closed-fs-file-descriptor-removed-owned-file",
        );
        expect(invocation.expectedActionIds).toEqual(
          recipe.scenario === "deny" ? ["fs:list"] : branch.actionIds,
        );
        expect(invocation.expectedDenyMessageFragment).toBe(
          "filesystem policy denied",
        );
        expect(invocation.expectedTypedStages).toEqual(
          recipe.scenario === "deny"
            ? ["requested"]
            : [
                "requested",
                ...(!async ? ["requested"] : []),
                "discovery",
                "requested",
                "repeat",
                "requested",
                "repeat",
                "commit",
              ],
        );
        expect(invocation.expectedTypedDecisionCount).toBe(
          recipe.scenario === "deny" ? 1 : async ? 7 : 8,
        );
        expect(
          invocation.requiredFloor.map((selector) => selector.cap),
        ).toEqual(branch.actionIds);
        expect(recipe.fixtureId).toContain(`.logical.${branchId}.`);
        expect(recipe.residualReasons).toEqual([]);
        expect(recipe.status).toBe("fully-executable");
      }
    }
  });

  test("reads retained descriptor bytes and closes its source-bound setup", () => {
    for (const catalog of [recipes, windowsRecipes]) {
      const rows = catalog.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactFsRead",
      );
      expect(rows).toHaveLength(4);
      for (const recipe of rows) {
        const invocation = recipe.publicSurfaceProbe.invocation;
        expect(invocation.arguments).toEqual([
          { kind: "harness-fs-file-descriptor" },
          { kind: "json-literal", value: 8 },
          { kind: "json-literal", value: -1 },
        ]);
        expect(invocation.setup).toHaveLength(1);
        expect(invocation.setup[0].globalName).toBe("__exactFsOpen");
        expect(invocation.allowedCoverageEdgeIds).toHaveLength(2);
        expect(
          invocation.requiredFloor.map((selector) => selector.cap),
        ).toEqual(["fs:list", "fs:read"]);
        expect(invocation.expectedTypedStages).toEqual(["repeat"]);
        expect(invocation.expectedTypedDecisionCount).toBe(1);
        expect(invocation.expectedCleanup).toBe(
          "closed-fs-file-descriptor",
        );
        expect(recipe.residualReasons).toEqual([]);
        expect(recipe.status).toBe("fully-executable");
      }
      const denied = catalog.recipes.find(
        (recipe) =>
          recipe.terminalObservedKey === "native-op:__exactFsRead" &&
          recipe.scenario === "deny",
      );
      expect(denied.publicSurfaceProbe).toBeNull();
      expect(denied.residualReasons).toContain(
        "native-public-deny-scenario-not-authored",
      );
    }
  });

  test("reads retained descriptor metadata and closes its source-bound setup", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactFsFstatSync",
    );
    expect(rows).toHaveLength(4);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "harness-fs-file-descriptor" },
      ]);
      expect(invocation.setup).toHaveLength(1);
      expect(invocation.setup[0].globalName).toBe("__exactFsOpen");
      expect(invocation.allowedCoverageEdgeIds).toHaveLength(2);
      expect(invocation.requiredFloor.map((selector) => selector.cap)).toEqual([
        "fs:list",
        "fs:read",
      ]);
      expect(invocation.expectedTypedStages).toEqual(["repeat"]);
      expect(invocation.expectedTypedDecisionCount).toBe(1);
      expect(invocation.expectedCleanup).toBe("closed-fs-file-descriptor");
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
    const windowsRows = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactFsFstatSync",
    );
    expect(windowsRows).toHaveLength(4);
    for (const recipe of windowsRows) {
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual([
        "repeat",
      ]);
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(1);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
    const denied = recipes.recipes.find(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:__exactFsFstatSync" &&
        recipe.scenario === "deny",
    );
    expect(denied.publicSurfaceProbe).toBeNull();
    expect(denied.residualReasons).toContain(
      "native-public-deny-scenario-not-authored",
    );
  });

  test("executes async retained durability without overclaiming metadata", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactFsFdAsync",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      expect(recipe.fixtureId).toContain(".logical.durability-write.");
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation).toMatchObject({
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        globalName: "__exactFsFdAsync",
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        expectedCleanup: "closed-fs-file-descriptor-removed-owned-file",
        expectedActionIds: ["fs:write"],
        expectedTypedStages: ["repeat"],
        expectedTypedDecisionCount: 1,
      });
      expect(invocation.arguments).toEqual([
        {
          kind: "json-literal",
          value: "fsync",
        },
        { kind: "harness-fs-file-descriptor" },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
      ]);
      expect(invocation.setup).toHaveLength(1);
      expect(invocation.setup[0]).toMatchObject({
        kind: "fs-write-file",
        globalName: "__exactFsOpen",
        path: "target/ibex-capsec-fdasync-durability",
      });
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
    const denyRows = recipes.recipes.filter(
      (recipe) =>
        recipe.fixtureId.includes(".exactfsfdasync.") &&
        recipe.scenario === "deny",
    );
    expect(denyRows).toHaveLength(2);
    expect(denyRows.every((recipe) => recipe.status === "unresolved")).toBe(
      true,
    );
    const truncateRows = recipes.recipes.filter(
      (recipe) =>
        recipe.fixtureId.includes(".exactfsfdasync.") &&
        recipe.fixtureId.includes(".logical.truncate."),
    );
    expect(truncateRows).toHaveLength(6);
    expect(truncateRows.every((recipe) => recipe.status === "unresolved")).toBe(
      true,
    );
    const closedMetadataRows = recipes.recipes.filter(
      (recipe) =>
        recipe.fixtureId.includes(".exactfsfdasync.") &&
        ["fchmod", "fchown", "futimes"].some((branch) =>
          recipe.fixtureId.includes(`.logical.${branch}.`),
        ),
    );
    expect(closedMetadataRows).toHaveLength(6);
    expect(
      closedMetadataRows.filter((recipe) => recipe.scenario === "closed"),
    ).toHaveLength(3);
    expect(
      closedMetadataRows
        .filter((recipe) => recipe.scenario === "closed")
        .every((recipe) => recipe.status === "fully-executable"),
    ).toBe(true);
  });

  test("flushes retained writable descriptors and removes their owned files", () => {
    for (const [globalName, path] of [
      ["__exactFsFsyncSync", "target/ibex-capsec-fsync"],
      ["__exactFsFdatasyncSync", "target/ibex-capsec-fdatasync"],
    ]) {
      const rows = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(rows).toHaveLength(4);
      for (const recipe of rows) {
        const invocation = recipe.publicSurfaceProbe.invocation;
        expect(invocation.arguments).toEqual([
          { kind: "harness-fs-file-descriptor" },
        ]);
        expect(invocation.setup).toHaveLength(1);
        expect(invocation.setup[0]).toMatchObject({
          kind: "fs-write-file",
          globalName: "__exactFsOpen",
          path,
        });
        expect(invocation.allowedCoverageEdgeIds).toHaveLength(2);
        expect(
          invocation.requiredFloor.map((selector) => selector.cap),
        ).toEqual(["fs:list", "fs:write"]);
        expect(invocation.expectedActionIds).toEqual(["fs:write"]);
        expect(invocation.expectedTypedStages).toEqual(["repeat"]);
        expect(invocation.expectedTypedDecisionCount).toBe(1);
        expect(invocation.expectedCleanup).toBe(
          "closed-fs-file-descriptor-removed-owned-file",
        );
        expect(recipe.residualReasons).toEqual([]);
        expect(recipe.status).toBe("fully-executable");
      }
      const denied = recipes.recipes.find(
        (recipe) =>
          recipe.terminalObservedKey === `native-op:${globalName}` &&
          recipe.scenario === "deny",
      );
      expect(denied.publicSurfaceProbe).toBeNull();
      expect(denied.residualReasons).toContain(
        "native-public-deny-scenario-not-authored",
      );
      const windowsRows = windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(windowsRows).toHaveLength(0);
      expect(
        windowsRecipes.recipes.find(
          (recipe) =>
            recipe.terminalObservedKey === `native-op:${globalName}` &&
            recipe.scenario === "allow",
        ).residualReasons,
      ).toContain("public-surface-filesystem-not-typed-on-target");
    }
  });

  test("truncates only an exact owned retained file on typed Apple descriptors", () => {
    for (const [globalName, path, extraArguments] of [
      ["__exactFsFtruncateSync", "target/ibex-capsec-ftruncate", [2]],
    ]) {
      const rows = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(rows).toHaveLength(4);
      for (const recipe of rows) {
        const invocation = recipe.publicSurfaceProbe.invocation;
        expect(invocation.arguments).toEqual([
          { kind: "harness-fs-file-descriptor" },
          ...extraArguments.map((value) => ({ kind: "json-literal", value })),
        ]);
        expect(invocation.setup[0]).toMatchObject({
          kind: "fs-write-file",
          globalName: "__exactFsOpen",
          path,
        });
        expect(invocation.allowedCoverageEdgeIds).toHaveLength(2);
        expect(invocation.expectedActionIds).toEqual(["fs:write"]);
        expect(invocation.expectedTypedStages).toEqual(["repeat"]);
        expect(invocation.expectedTypedDecisionCount).toBe(1);
        expect(invocation.expectedCleanup).toBe(
          "closed-fs-file-descriptor-removed-owned-file",
        );
        expect(recipe.residualReasons).toEqual([]);
        expect(recipe.status).toBe("fully-executable");
      }
      const denied = recipes.recipes.find(
        (recipe) =>
          recipe.terminalObservedKey === `native-op:${globalName}` &&
          recipe.scenario === "deny",
      );
      expect(denied.publicSurfaceProbe).toBeNull();
      expect(denied.residualReasons).toContain(
        "native-public-deny-scenario-not-authored",
      );
      const windowsRows = windowsRecipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(windowsRows).toHaveLength(1);
      expect(windowsRows[0]).toMatchObject({
        scenario: "absent",
        status: "fully-executable",
        expectedObservation: { kind: "target-absence" },
        residualReasons: [],
        publicSurfaceProbe: { kind: "target-absence-probe" },
      });
    }
    for (const globalName of ["__exactFsFchmodSync", "__exactFsFutimesSync"]) {
      expect(
        recipes.recipes.filter(
          (recipe) =>
            recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
        ),
      ).toHaveLength(0);
    }
  });

  test("enumerates a direct native directory with retained repeat evidence", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactReaddir",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        {
          kind: "json-literal",
          value: "target/ibex-capsec-readdir",
        },
        { kind: "json-literal", value: null },
      ]);
      expect(invocation.expectedCleanup).toBe("removed-owned-directory");
      expect(invocation.expectedActionIds).toEqual(["fs:list"]);
      expect(invocation.expectedDenyMessageFragment).toBe(
        "filesystem policy denied",
      );
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "requested",
              "repeat",
              "repeat",
              "repeat",
              "repeat",
            ],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 9,
      );
      expect(invocation.requiredFloor).toHaveLength(1);
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }

    const windowsRows = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactReaddir",
    );
    expect(windowsRows).toHaveLength(5);
    for (const recipe of windowsRows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny"
          ? ["requested"]
          : ["requested", "discovery", "repeat"],
      );
      expect(invocation.expectedTypedDecisionCount).toBe(
        recipe.scenario === "deny" ? 1 : 3,
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("executes the typed cached-system-info authorization surface", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactAuthorizeSystemInfo",
    );
    expect(rows).toHaveLength(5);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.arguments).toEqual([
        { kind: "json-literal", value: 11 },
      ]);
      expect(invocation.requiredFloor).toEqual([
        {
          cap: "sys:read",
          resource: { kind: "system-info", name: "platform" },
        },
      ]);
      expect(invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny" ? ["requested"] : ["requested", "commit"],
      );
      expect(recipe.residualReasons).toEqual([]);
      expect(recipe.status).toBe("fully-executable");
    }
  });

  test("binds bounded decompression probes to their complete source arities", () => {
    const expected = new Map([
      ["__exactBrotliDecompressSync", 4],
      ["__exactInflateSync", 6],
    ]);
    const rows = recipes.recipes.filter((recipe) =>
      expected.has(recipe.publicSurfaceProbe?.invocation?.globalName),
    );
    expect(rows).toHaveLength(2);
    for (const recipe of rows) {
      const invocation = recipe.publicSurfaceProbe.invocation;
      expect(invocation.sourceDescriptor.arity).toBe(
        expected.get(invocation.globalName),
      );
      expect(invocation.arguments).toHaveLength(
        expected.get(invocation.globalName),
      );
      expect(invocation.arguments.at(-1)).toEqual({
        kind: "json-literal",
        value: 1024,
      });
      expect(recipe.status).toBe("fully-executable");
      expect(recipe.residualReasons).toEqual([]);
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
          recipe.publicSurfaceProbe.invocation.completion.kind ===
            "event-loop-quiescence" &&
          recipe.publicSurfaceProbe.invocation.completion
            .timeoutMilliseconds === 1_000 &&
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
    const targetAbsentReads = publicReads.filter(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.expectedResult === "absent",
    );
    expect(targetAbsentReads).toHaveLength(14);
    expect(
      targetAbsentReads.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor
            .platformAvailability.length > 0 &&
          !recipe.publicSurfaceProbe.invocation.sourceDescriptor.platformAvailability.includes(
            "darwin",
          ),
      ),
    ).toBe(true);
    expect(
      recipes.summary.residualReasons[
        "builtin-export-not-available-on-target"
      ] ?? 0,
    ).toBe(0);
  });

  test("binds target absence to source variants and exact runtime lookups", () => {
    const rows = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.kind === "target-absence-probe",
    );
    expect(rows).toHaveLength(112);
    expect(rows.every((recipe) => recipe.scenario === "absent")).toBe(true);
    expect(rows.every((recipe) => recipe.status === "fully-executable")).toBe(
      true,
    );
    const outputCatalog = readJson(
      "capsec/generated/output-shape-catalog.json",
    );
    const coverage = readJson("capsec/registry/coverage-edges.json");
    const rules = readJson("capsec/registry/policy-rules.json");
    const target = rules.initialProfile.candidateTargets[0];
    const bindings = authoredTargetAbsenceOutputBindings({
      catalog: outputCatalog,
      recipeCatalog: recipes,
      coverage,
      target,
    });
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
        recipe.terminalObservedKey ===
        "native-op:__exactAndroidLocation.getPermissionStatus",
    );
    expect(androidGlobal.publicSurfaceProbe).toMatchObject({
      surfaceObservedKey:
        "native-op:__exactAndroidLocation.getPermissionStatus",
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: "__exactAndroidLocation.getPermissionStatus",
        sourceDescriptor: {
          kind: "native-global-function",
          globalName: "__exactAndroidLocation.getPermissionStatus",
          sourceRef:
            "src/engine/hermes_runtime_android.cc#jsi-global:__exactAndroidLocation.getPermissionStatus",
        },
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
      },
    });
    expect(
      androidGlobal.publicSurfaceProbe.invocation.sourceDescriptorDigest,
    ).toMatch(/^sha256-/u);
    const iosLayoutTree = rows.find(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:global:exact.getLayoutTree",
    );
    expect(iosLayoutTree.publicSurfaceProbe).toMatchObject({
      surfaceObservedKey: "native-op:global:exact.getLayoutTree",
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: "exact.getLayoutTree",
        sourceDescriptor: {
          kind: "native-global-function",
          globalName: "exact.getLayoutTree",
          sourceRef:
            "src/engine/hermes_runtime_ios.cc#jsi-global:exact.getLayoutTree",
        },
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
      },
    });

    expect(bindings).toHaveLength(115);
    expect(
      bindings.filter((binding) => binding.key.sourceKind === "host-abi"),
    ).toHaveLength(59);
    expect(
      bindings.filter((binding) => binding.key.sourceKind === "native-op"),
    ).toHaveLength(56);
    expect(
      bindings.filter(
        (binding) =>
          binding.invocationSchema ===
          "ibex/capsec-target-absence-invocation/1",
      ),
    ).toHaveLength(93);
    expect(
      bindings.filter(
        (binding) =>
          binding.invocationSchema === "ibex/capsec-native-global-invocation/1",
      ),
    ).toHaveLength(22);

    const policy = readJson("capsec/registry/output-disposition-policy.json");
    const targetAbsentSurfaceIds = new Set(
      bindings.map((binding) => binding.key.surfaceId),
    );
    const targetAbsentDecisions = policy.overrides.filter((decision) =>
      targetAbsentSurfaceIds.has(decision.key.surfaceId),
    );
    const expectedKeys = bindings.map((binding) =>
      canonicalOutputDispositionKey(binding.key),
    );
    const actualKeys = targetAbsentDecisions
      .map((decision) => canonicalOutputDispositionKey(decision.key))
      .sort();
    expect(actualKeys).toEqual(expectedKeys);
    expect(targetAbsentDecisions).toHaveLength(115);
    const bindingByKey = new Map(
      bindings.map((binding) => [
        canonicalOutputDispositionKey(binding.key),
        binding,
      ]),
    );
    expect(
      targetAbsentDecisions.every(
        (decision) =>
          decision.disposition === "absent" &&
          decision.expectation.outcome === "absent" &&
          decision.expectation.normalizedValue === "absent" &&
          decision.rationale ===
            targetAbsenceDispositionRationale(
              bindingByKey.get(canonicalOutputDispositionKey(decision.key)),
            ),
      ),
    ).toBe(true);

    const windowsCryptoId =
      "surface.loader.function.javascript.makewindowscryptomodule.0029u8l";
    expect(targetAbsentSurfaceIds.has(windowsCryptoId)).toBe(false);
    expect(
      policy.overrides.some(
        (decision) =>
          decision.key.surfaceId === windowsCryptoId &&
          decision.disposition === "absent",
      ),
    ).toBe(false);
    const implementation = readJson(
      "capsec/generated/implementation-manifest.json",
    );
    expect(
      implementation.surfaces
        .filter((surface) => surface.edgeId === windowsCryptoId)
        .map((surface) => surface.targetVariant),
    ).toEqual([]);
    const loaderSource = fs.readFileSync(
      path.join(repoRoot, "src/engine/bootstrap/module-loader.js"),
      "utf8",
    );
    expect(loaderSource).not.toContain("function makeWindowsCryptoModule() {");
    expect(loaderSource).not.toContain(
      "internalModules.crypto = makeWindowsCryptoModule();",
    );
    expect(loaderSource).toContain(
      "Public builtins always resolve through the authenticated manifest.",
    );
  });

  test("binds closed startup environment controls to the production entry", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "startup-environment",
    );
    expect(rows).toHaveLength(20);
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
        "--no-default-features",
        "--features",
        "standard,capsec-conformance-observer,openssl-crypto",
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
    for (const environmentName of ["IBEX_COMPARTMENTS", "IBEX_LOCKDOWN"]) {
      const structuralControl = rows.find(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.operation.environmentName ===
          environmentName,
      );
      expect(structuralControl).toMatchObject({
        terminalObservedKey: `startup:env:${environmentName}`,
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          surfaceObservedKey: `startup:env:${environmentName}`,
          invocation: {
            sourceDescriptor: {
              kind: "closed-startup-environment",
              environmentName,
              sourceRefs: [
                `src/engine/hermes_runtime.cc#env_flag_enabled:${environmentName}:read`,
              ],
            },
            operation: { kind: "startup-environment", environmentName },
            expectedResult: "closed",
            expectedTypedDecisionCount: 0,
          },
        },
      });
    }
  });

  test("binds Exact IPC closure to an authenticated unendowed operation", () => {
    const recipe = recipes.recipes.find(
      (candidate) =>
        candidate.fixtureId ===
        "surface.native.op.global.exact.invokehostasync.0b92itq.default.closed",
    );
    expect(recipe).toMatchObject({
      classification: "closed",
      scenario: "closed",
      terminalObservedKey: "native-op:global:exact.invokeHostAsync",
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        surfaceObservedKey: "native-op:global:exact.invokeHostAsync",
        invocation: {
          invocationSchema: "ibex/capsec-closed-surface-invocation/1",
          kind: "closed-surface",
          surfaceKind: "native-op",
          surfaceName: "global:exact.invokeHostAsync",
          sourceDescriptor: {
            kind: "closed-exact-unendowed-operation",
            surfaceObservedKey: "native-op:global:exact.invokeHostAsync",
            globalName: "exact",
            memberName: "invokeHostAsync",
            sourceRefs: [
              "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
            ],
          },
          operation: {
            kind: "exact-unendowed-operation",
            contextKind: "app",
            endowedOperationIds: [7, 11],
            selectedOperationId: 8,
            expectedError: "exact.invokeHostAsync operation is not endowed",
          },
          expectedResult: "closed",
          expectedTypedDecisionCount: 0,
          allowedCoverageEdgeIds: [],
          expectedActionIds: [],
        },
      },
    });
    expect(recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest).toMatch(
      /^sha256-/u,
    );
  });

  test("binds curated structural startup stages to loaded-engine postconditions", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-startup-surface-invocation/1",
    );
    expect(rows).toHaveLength(10);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.surfaceName,
        recipe.publicSurfaceProbe.invocation.operation.postcondition,
      ]),
    ).toEqual([
      ["capability-hardening-seal", "capability-hatches-sealed"],
      ["compartment-registry-install", "compartment-registry-installed"],
      ["eager-native-seal", "lazy-installers-sealed"],
      ["freeze-seal", "freeze-hatches-sealed"],
      ["globals-install", "globals-installed"],
      ["lockdown-install", "lockdown-installed"],
      ["module-loader-install", "module-loader-installed"],
      ["runtime-create", "runtime-created"],
      ["shared-runtime-install", "shared-runtime-installed"],
      ["web-streams-install", "web-streams-installed"],
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceRefs
            .length === 1,
      ),
    ).toBe(true);
  });

  test("promotes only exact absent reads for the three isolated startup environment sources", () => {
    const startupEnvironmentRecipes = recipes.recipes.filter(
      (recipe) =>
        recipe.classification === "effects" &&
        recipe.terminalObservedKey.startsWith("startup:env:"),
    );
    expect(startupEnvironmentRecipes).toHaveLength(670);
    expect(
      startupEnvironmentRecipes.filter(
        (recipe) => recipe.terminalObservedKey === "startup:env:CLICOLOR_FORCE",
      ),
    ).toHaveLength(12);
    const authored = startupEnvironmentRecipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-startup-environment-invocation/1",
    );
    expect(authored).toHaveLength(9);
    expect(
      authored.map((recipe) => [recipe.terminalObservedKey, recipe.scenario]),
    ).toEqual([
      ["startup:env:TZ", "allow"],
      ["startup:env:TZ", "branch-selection"],
      ["startup:env:TZ", "deny"],
      ["startup:env:EXACT_DEBUG_EMIT_LISTENER", "allow"],
      ["startup:env:EXACT_DEBUG_EMIT_LISTENER", "branch-selection"],
      ["startup:env:EXACT_DEBUG_EMIT_LISTENER", "deny"],
      ["startup:env:NODE_DEBUG", "allow"],
      ["startup:env:NODE_DEBUG", "branch-selection"],
      ["startup:env:NODE_DEBUG", "deny"],
    ]);
    const expectedSources = new Map([
      [
        "TZ",
        {
          sourceRef:
            "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
          mechanism: "date-to-string",
          moduleSpecifier: null,
          preloads: [],
        },
      ],
      [
        "EXACT_DEBUG_EMIT_LISTENER",
        {
          sourceRef:
            "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
          mechanism: "event-emitter-emit",
          moduleSpecifier: "node:events",
          preloads: [],
        },
      ],
      [
        "NODE_DEBUG",
        {
          sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
          mechanism: "builtin-module-load",
          moduleSpecifier: "node:http",
          preloads: ["node:events", "node:stream", "node:util"],
        },
      ],
    ]);
    for (const recipe of authored) {
      expect(() =>
        validateStartupEnvironmentRecipeDescriptor(recipe),
      ).not.toThrow();
      const invocation = recipe.publicSurfaceProbe.invocation;
      const name = invocation.operation.environment.name;
      const expected = expectedSources.get(name);
      expect(recipe).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        actionIds: ["env:read"],
      });
      expect(invocation).toMatchObject({
        kind: "startup-environment-source",
        surfaceKind: "startup",
        surfaceName: `env:${name}`,
        expectedResult: "return",
        allowedCoverageEdgeIds: ["surface.native.op.exactgetenv.0k6bv7a"],
        expectedActionIds: ["env:read"],
        expectedResourceNames: [name],
        operation: {
          kind: expected.mechanism,
          moduleSpecifier: expected.moduleSpecifier,
          preloadModuleSpecifiers: expected.preloads,
          environment: { name, presence: "absent" },
        },
      });
      expect(invocation.sourceDescriptor).toMatchObject({
        environmentName: name,
        sourceRef: expected.sourceRef,
        executionMechanism: expected.mechanism,
        selectedBranch: { id: "absent" },
        auxiliaryDecisionEdgeId: "surface.native.op.exactgetenv.0k6bv7a",
      });
      const denial = recipe.scenario === "deny";
      expect(invocation.expectedTypedStages).toEqual(
        denial ? ["requested"] : ["requested", "commit"],
      );
      expect(invocation.expectedTypedOutcomes).toEqual(
        denial ? ["deny"] : ["allow", "allow"],
      );
      expect(invocation.expectedTypedReasons).toEqual(
        denial ? ["principal-denial"] : ["static-floor", "static-floor"],
      );
    }
    expect(
      startupEnvironmentRecipes.filter(
        (recipe) => recipe.status === "unresolved",
      ),
    ).toHaveLength(661);
    for (const environmentName of expectedSources.keys()) {
      const residual = startupEnvironmentRecipes.filter(
        (recipe) =>
          recipe.terminalObservedKey === `startup:env:${environmentName}` &&
          recipe.status === "unresolved",
      );
      expect(residual).toHaveLength(9);
      expect(
        residual.every((recipe) => recipe.publicSurfaceProbe === null),
      ).toBe(true);
    }
  });

  test("leaves legacy extension guards residual without a source-bound executor", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "loader-executable-file",
    );
    expect(rows).toHaveLength(0);
    for (const terminal of [
      "loader:native-addon-module",
      "loader:wasm-module",
    ]) {
      const residual = recipes.recipes.find(
        (recipe) =>
          recipe.terminalObservedKey === terminal &&
          recipe.scenario === "closed",
      );
      expect(residual).toMatchObject({
        status: "unresolved",
        publicSurfaceProbe: null,
        residualReasons: [
          "closed-surface-denial-probe-not-authored",
          "public-surface-invocation-not-authored",
        ],
      });
    }
    for (const terminal of ["loader:kind:native-addon", "loader:kind:wasm"]) {
      const residual = recipes.recipes.find(
        (recipe) => recipe.terminalObservedKey === terminal,
      );
      expect(residual).toMatchObject({
        status: "unresolved",
        publicSurfaceProbe: null,
        residualReasons: [
          "closed-surface-denial-probe-not-authored",
          "public-surface-invocation-not-authored",
        ],
      });
    }
  });

  test("binds every terminal builtin source facet to the authenticated import denial", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "terminal-builtin-import",
    );
    expect(rows).toHaveLength(106);
    expect(
      Object.entries(
        Object.groupBy(
          rows,
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.operation.terminalBuiltinRoot,
        ),
      )
        .map(([root, grouped]) => [root, grouped.length])
        .sort(),
    ).toEqual([
      ["async_hooks", 25],
      ["inspector", 22],
      ["vm", 11],
      ["wasi", 7],
      ["worker_threads", 41],
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceRefs
            .length === 1,
      ),
    ).toBe(true);
    const module = rows.find(
      (recipe) => recipe.terminalObservedKey === "builtin:async_hooks",
    );
    expect(module).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          surfaceKind: "builtin",
          surfaceName: "async_hooks",
          sourceDescriptor: {
            kind: "closed-terminal-builtin",
            sourceKey: "node_async_hooks",
            moduleSpecifiers: ["async_hooks", "node:async_hooks"],
            sourceRefs: ["modules.ts#specifiers:node_async_hooks"],
          },
          operation: {
            kind: "terminal-builtin-import",
            terminalBuiltinRoot: "async_hooks",
            moduleSpecifiers: ["async_hooks", "node:async_hooks"],
            expectedRejectionFragment: "Import denied:",
          },
        },
      },
    });
    const exported = rows.find(
      (recipe) =>
        recipe.terminalObservedKey === "builtin:export:node_vm:runInNewContext",
    );
    expect(exported).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          surfaceName: "export:node_vm:runInNewContext",
          sourceDescriptor: {
            kind: "closed-terminal-builtin",
            sourceKey: "node_vm",
            exportName: "runInNewContext",
            moduleSpecifiers: ["node:vm", "vm"],
            sourceRefs: ["src/builtins/vm.js#exports:runInNewContext"],
          },
        },
      },
    });
  });

  test("binds every wholly and branch-locally closed filesystem mutation to target-local unchanged-state evidence", () => {
    const guardsByTarget = [];
    for (const catalog of [recipes, windowsRecipes]) {
      const rows = catalog.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
          "filesystem-unbound-mutation",
      );
      expect(rows, catalog.target.triple).toHaveLength(
        catalog.target.triple === "aarch64-apple-darwin" ? 93 : 79,
      );
      expect(
        rows.filter(
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.operation.surfaceForm ===
            "builtin-export",
        ),
        catalog.target.triple,
      ).toHaveLength(56);
      expect(
        rows.filter(
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.operation.surfaceForm ===
            "native-global",
        ),
        catalog.target.triple,
      ).toHaveLength(
        catalog.target.triple === "aarch64-apple-darwin" ? 20 : 7,
      );
      expect(
        rows.filter(
          (recipe) =>
            recipe.publicSurfaceProbe.invocation.operation.surfaceForm ===
            "native-dispatcher",
        ),
        catalog.target.triple,
      ).toHaveLength(
        catalog.target.triple === "aarch64-apple-darwin" ? 17 : 16,
      );
      expect(
        rows.every((recipe) => {
          const invocation = recipe.publicSurfaceProbe.invocation;
          return (
            recipe.status === "fully-executable" &&
            recipe.classification === "closed" &&
            recipe.scenario === "closed" &&
            recipe.actionIds.length === 0 &&
            recipe.residualReasons.length === 0 &&
            invocation.expectedTypedDecisionCount === 0 &&
            invocation.expectedTypedStages.length === 0 &&
            invocation.allowedCoverageEdgeIds.length === 0 &&
            invocation.sourceDescriptor.kind ===
              "closed-filesystem-unbound-mutation" &&
            invocation.sourceDescriptor.targetTriple ===
              catalog.target.triple &&
            invocation.operation.targetTriple === catalog.target.triple &&
            invocation.operation.expectedErrorFragment ===
              "operation not permitted" &&
            invocation.operation.expectedErrorCode === "EPERM" &&
            (invocation.operation.surfaceForm !== "builtin-export" ||
              ["node_fs", "node_fs_promises"].includes(
                invocation.operation.sourceKey,
              ))
          );
        }),
        catalog.target.triple,
      ).toBe(true);
      guardsByTarget.push(
        [...new Set(
          rows.map(
            (recipe) =>
              recipe.publicSurfaceProbe.invocation.operation.guardOperation,
          ),
        )].sort(),
      );
    }
    expect(guardsByTarget[0]).toEqual(guardsByTarget[1]);
    expect(
      new Set(
        recipes.recipes
          .filter(
            (recipe) =>
              recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
              "filesystem-unbound-mutation",
          )
          .map(
            (recipe) =>
              recipe.publicSurfaceProbe.invocation.operation.guardOperation,
          ),
      ),
    ).toEqual(
      new Set([
        "chmod",
        "chown",
        "copyfile",
        "copyfile_excl",
        "cp",
        "fchmod",
        "fchown",
        "futimes",
        "lchmod",
        "lchown",
        "link",
        "lutime",
        "lutimes",
        "mkdir",
        "mkdtemp",
        "rename",
        "rm",
        "rmdir",
        "symlink",
        "unlink",
        "utime",
        "watch",
        "watchFile",
      ]),
    );
  });

  test("closes both public SQLite extension-loading exports in memory", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "sqlite-extension-load",
    );
    expect(rows).toHaveLength(2);
    expect(rows.map((recipe) => recipe.terminalObservedKey).sort()).toEqual([
      "builtin:export:exact_sqlite:Database.loadExtension",
      "builtin:export:exact_sqlite:default.loadExtension",
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey ===
            "exact_sqlite" &&
          recipe.publicSurfaceProbe.invocation.operation.methodName ===
            "loadExtension" &&
          recipe.publicSurfaceProbe.invocation.operation.databasePath ===
            ":memory:" &&
          recipe.publicSurfaceProbe.invocation.operation
            .expectedRejectionFragment === "Extension loading not supported",
      ),
    ).toBe(true);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.sourceDescriptor.exportName,
        recipe.publicSurfaceProbe.invocation.operation.constructorExportName,
      ]),
    ).toEqual([
      ["Database.loadExtension", "Database"],
      ["default.loadExtension", "default"],
    ]);
  });

  test("closes both public cr-sqlite enablement exports in memory", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "sqlite-cr-sqlite-enable",
    );
    expect(rows).toHaveLength(2);
    expect(rows.map((recipe) => recipe.terminalObservedKey).sort()).toEqual([
      "builtin:export:exact_sqlite:Database.enableCrSqlite",
      "builtin:export:exact_sqlite:default.enableCrSqlite",
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey ===
            "exact_sqlite" &&
          recipe.publicSurfaceProbe.invocation.operation.methodName ===
            "enableCrSqlite" &&
          recipe.publicSurfaceProbe.invocation.operation.databasePath ===
            ":memory:" &&
          recipe.publicSurfaceProbe.invocation.operation
            .expectedRejectionFragment ===
            "cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support.",
      ),
    ).toBe(true);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.sourceDescriptor.exportName,
        recipe.publicSurfaceProbe.invocation.operation.constructorExportName,
      ]),
    ).toEqual([
      ["Database.enableCrSqlite", "Database"],
      ["default.enableCrSqlite", "default"],
    ]);
  });

  test("binds every debugger ABI facet to the physical no-debugger Apple target", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "debugger-abi-disabled",
    );
    expect(rows).toHaveLength(18);
    expect(
      Object.entries(
        Object.groupBy(
          rows,
          (recipe) => recipe.publicSurfaceProbe.invocation.surfaceKind,
        ),
      )
        .map(([kind, grouped]) => [kind, grouped.length])
        .sort(),
    ).toEqual([
      ["host-abi", 9],
      ["native-op", 9],
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple ===
            "aarch64-apple-darwin",
      ),
    ).toBe(true);
    const host = rows.find(
      (recipe) =>
        recipe.terminalObservedKey === "host-abi:ex_hermes_debugger_eval",
    );
    expect(host).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          surfaceKind: "host-abi",
          surfaceName: "ex_hermes_debugger_eval",
          sourceDescriptor: {
            kind: "closed-debugger-abi",
            selectedSourceRef:
              "src/engine/hermes_runtime_debugger.cc#ex_hermes_debugger_eval",
          },
          operation: {
            kind: "debugger-abi-disabled",
            functionName: "ex_hermes_debugger_eval",
            expectedCallResult: "null-pointer",
          },
        },
      },
    });
    const native = rows.find(
      (recipe) =>
        recipe.terminalObservedKey === "native-op:inspector.debugger-pause",
    );
    expect(native).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          surfaceKind: "native-op",
          surfaceName: "inspector.debugger-pause",
          sourceDescriptor: {
            kind: "closed-debugger-abi",
            sourceMetadata: null,
          },
          operation: {
            kind: "debugger-abi-disabled",
            functionName: "ex_hermes_debugger_pause",
            expectedCallResult: "no-event",
          },
        },
      },
    });
  });

  test("binds every debugger ABI facet to the physical Windows stubs", () => {
    const rows = windowsRecipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "debugger-abi-disabled",
    );
    expect(rows).toHaveLength(18);
    expect(
      rows.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple ===
            "x86_64-pc-windows-msvc" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.selectedSourceRef.startsWith(
            "src/engine/hermes_runtime_platform_windows.cc#",
          ),
      ),
    ).toBe(true);
  });

  test("binds reviewed globals to armed shared-runtime absence", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "shared-runtime-global-absence",
    );
    expect(rows).toHaveLength(322);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple ===
            "aarch64-apple-darwin" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.installationBranches.every(
            (branch) =>
              branch.route === "legacy-bootstrap" ||
              branch.route === "shared-runtime" ||
              branch.route === "composed:legacy-bootstrap+shared-runtime",
          ),
      ),
    ).toBe(true);
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey === "native-op:__exactAllowNativesSyntax",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            kind: "closed-shared-runtime-global-absence",
            globalName: "__exactAllowNativesSyntax",
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "__exactAllowNativesSyntax",
            memberName: null,
          },
        },
      },
    });
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey ===
          "native-op:global:BroadcastChannel.postMessage",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            globalName: "BroadcastChannel",
            memberName: "postMessage",
            sourceMetadata: {
              sourceKey: "shared_runtime",
              installationBranches: [
                { route: "shared-runtime", targetVariant: "all" },
              ],
            },
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "BroadcastChannel",
            memberName: "postMessage",
          },
        },
      },
    });
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey ===
          "native-op:global:IDBTransaction.abort",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            globalName: "IDBTransaction",
            memberName: "abort",
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "IDBTransaction",
            memberName: "abort",
          },
        },
      },
    });
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey ===
          "native-op:global:localStorage.getItem",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            globalName: "localStorage",
            memberName: "getItem",
            sourceMetadata: {
              sourceKey: "shared_runtime",
              installationBranches: [
                {
                  route: "composed:legacy-bootstrap+shared-runtime",
                  routes: ["legacy-bootstrap", "shared-runtime"],
                  targetVariant: "default",
                },
              ],
            },
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "localStorage",
            memberName: "getItem",
          },
        },
      },
    });
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey === "native-op:global:CacheStorage.open",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            globalName: "CacheStorage",
            memberName: "open",
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "CacheStorage",
            memberName: "open",
          },
        },
      },
    });
    expect(
      rows.find(
        (recipe) =>
          recipe.terminalObservedKey ===
          "native-op:global:Exact.accessibility.prefersReducedMotion",
      ),
    ).toMatchObject({
      publicSurfaceProbe: {
        invocation: {
          sourceDescriptor: {
            globalName: "Exact",
            memberName: "accessibility.prefersReducedMotion",
            sourceMetadata: {
              sourceKey: "shared_runtime",
            },
          },
          operation: {
            kind: "shared-runtime-global-absence",
            globalName: "Exact",
            memberName: "accessibility.prefersReducedMotion",
          },
        },
      },
    });
  });

  test("binds reviewed direct native globals to armed runtime absence", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "armed-native-global-absence",
    );
    expect(rows).toHaveLength(18);
    const directRows = rows.filter(
      (recipe) =>
        !recipe.publicSurfaceProbe.invocation.surfaceName.startsWith("global:"),
    );
    expect(
      directRows.map(
        (recipe) => recipe.publicSurfaceProbe.invocation.operation.globalName,
      ),
    ).toEqual([
      "__exactGetGCStats",
      "__exactGetHeapInfo",
      "__exactGetSourceCacheStats",
      "__exactIpcRecvMsg",
      "__exactIpcSendMsg",
      "__exactPollSignal",
      "__exactResetSignal",
    ]);
    const workletRows = rows.filter((recipe) =>
      recipe.publicSurfaceProbe.invocation.surfaceName.startsWith("global:"),
    );
    expect(workletRows.map((recipe) => recipe.terminalObservedKey)).toEqual([
      "native-op:global:measure",
      "native-op:global:scheduleOnAppRuntime",
      "native-op:global:worklet",
      "native-op:global:worklet.capture",
      "native-op:global:worklet.captureGet",
      "native-op:global:worklet.captureSet",
      "native-op:global:worklet.clamp",
      "native-op:global:worklet.lerp",
      "native-op:global:worklet.output",
      "native-op:global:worklet.runOnJS",
      "native-op:global:worklet.sharedValue",
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "closed" &&
          recipe.scenario === "closed" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.kind ===
            "closed-armed-native-global-absence" &&
          Object.hasOwn(
            recipe.publicSurfaceProbe.invocation.operation,
            "memberName",
          ) &&
          recipe.publicSurfaceProbe.invocation.operation.memberName ===
            recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
              .memberName,
      ),
    ).toBe(true);
    expect(
      directRows.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
            .publicInvocation.kind === "native-global-function",
      ),
    ).toBe(true);
    expect(
      workletRows.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
            .installationBranches.length === 1 &&
          ["evaluated-native-script", "native-jsi-global"].includes(
            recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
              .installationBranches[0].route,
          ) &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
            .installationBranches[0].targetVariant === "worklet",
      ),
    ).toBe(true);
  });

  test("executes module-runner authority and trusted-access loader surfaces", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-module-loader-invocation/1",
    );
    expect(rows).toHaveLength(4);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.surfaceName,
        recipe.publicSurfaceProbe.invocation.operation.kind,
        recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceRefs[0],
      ]),
    ).toEqual([
      [
        "module-runner-cache-access",
        "cache-read",
        "src/module_loader/security.rs#authorize_then_access",
      ],
      [
        "module-runner-edge-authorization",
        "authorize-edge",
        "src/module_loader/security.rs#authorize",
      ],
      [
        "module-runner-prepared-carrier-access",
        "prepared-carrier-read",
        "src/module_loader/security.rs#authorize_then_access",
      ],
      [
        "module-runner-trusted-source-acquisition",
        "source-acquisition",
        "src/module_loader/security.rs#authorize_then_access",
      ],
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.residualReasons.length === 0 &&
          recipe.actionIds.length === 0 &&
          recipe.adapterProbe === null &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedStages.length ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedActionIds.length === 0,
      ),
    ).toBe(true);
  });

  test("isolates reviewed effect-bearing module imports and keeps other aliases residual", () => {
    const imports = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-builtin-module-import-invocation/1",
    );
    const expectedAliases = new Map([
      ["node:sys", ["node_util", "surface.builtin.node.sys.1dbdr15"]],
      ["node:util", ["node_util", "surface.builtin.node.util.170qsxo"]],
      [
        "node:util/types",
        ["node_util_types_alias", "surface.builtin.node.util.types.0iem8dy"],
      ],
      ["sys", ["node_util", "surface.builtin.sys.1oe78qz"]],
      ["util", ["node_util", "surface.builtin.util.1isnyze"]],
      [
        "util/types",
        ["util_types_alias", "surface.builtin.util.types.0v4anl8"],
      ],
    ]);
    const expectedScenarios = [
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
    ];
    expect(imports).toHaveLength(30);
    expect(
      new Set(
        imports.map(
          (recipe) => recipe.publicSurfaceProbe.invocation.moduleSpecifier,
        ),
      ),
    ).toEqual(new Set(expectedAliases.keys()));
    expect(
      imports
        .map(
          (recipe) =>
            `${recipe.publicSurfaceProbe.invocation.moduleSpecifier}:${recipe.scenario}`,
        )
        .sort(),
    ).toEqual(
      [...expectedAliases.keys()]
        .flatMap((moduleSpecifier) =>
          expectedScenarios.map(
            (scenario) => `${moduleSpecifier}:${scenario}`,
          ),
        )
        .sort(),
    );
    expect(
      imports.every(
        (recipe) => {
          const invocation = recipe.publicSurfaceProbe.invocation;
          const [sourceKey, carrierEdgeId] = expectedAliases.get(
            invocation.moduleSpecifier,
          );
          const expectedStages =
            recipe.scenario === "deny"
              ? ["requested"]
              : ["requested", "commit"];
          return (
            recipe.classification === "effects" &&
            recipe.status === "fully-executable" &&
            recipe.residualReasons.length === 0 &&
            invocation.invocationSchema ===
              "ibex/capsec-builtin-module-import-invocation/1" &&
            invocation.exportName === undefined &&
            invocation.sourceDescriptor.kind === "builtin-module-alias" &&
            invocation.sourceDescriptor.sourceKey === sourceKey &&
            invocation.sourceDescriptor.carrierEdgeId === carrierEdgeId &&
            invocation.sourceDescriptor.auxiliaryDecisionEdgeId ===
              "surface.native.op.exactgetenv.0k6bv7a" &&
            invocation.sourceDescriptor.sourceMetadata.importReachability ===
              "public" &&
            invocation.expectedResult === "return" &&
            invocation.expectedTypedDecisionCount === expectedStages.length &&
            JSON.stringify(invocation.expectedTypedStages) ===
              JSON.stringify(expectedStages) &&
            recipe.route.alternatives.length === 1 &&
            recipe.route.alternatives[0].terminalObservedKey ===
              recipe.route.surfaceObservedKeys[0] &&
            recipe.route.ambiguousCallees.length === 0
          );
        },
      ),
    ).toBe(true);
    const environmentImports = imports.filter((recipe) =>
      recipe.actionIds.includes("env:read"),
    );
    expect(environmentImports).toHaveLength(30);
    expect(
      environmentImports.every(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.requiredAuthority[0]?.resource
            ?.name === "NODE_DEBUG",
      ),
    ).toBe(true);
    const lazyOrDecisionFreeEffectAliases = recipes.recipes.filter(
      (recipe) =>
        recipe.classification === "effects" &&
        [
          "allow",
          "deny",
          "malformed",
          "missing-attribution",
          "wrong-principal",
        ].includes(recipe.scenario) &&
        [
          "builtin:bun:fs",
          "builtin:bun:fs/promises",
          "builtin:constants",
          "builtin:fs",
          "builtin:fs/promises",
          "builtin:internal/fs/promises",
          "builtin:node:constants",
          "builtin:node:fs",
          "builtin:node:fs/promises",
          "builtin:node:os",
          "builtin:os",
        ].includes(recipe.route.surfaceObservedKeys[0]),
    );
    expect(lazyOrDecisionFreeEffectAliases).toHaveLength(55);
    expect(
      lazyOrDecisionFreeEffectAliases.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.residualReasons.includes(
            "public-surface-invocation-not-authored",
          ),
      ),
    ).toBe(true);
    const aliases = recipes.recipes.filter(
      (recipe) =>
        recipe.classification === "non-capability" &&
        recipe.scenario === "non-capability" &&
        recipe.route.surfaceObservedKeys.length === 1 &&
        recipe.route.surfaceObservedKeys[0].startsWith("builtin:") &&
        !recipe.route.surfaceObservedKeys[0].startsWith("builtin:export:"),
    );
    expect(aliases).toHaveLength(37);
    const reviewedImports = aliases.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
        "ibex/capsec-builtin-module-import-no-effect-invocation/1",
    );
    const expectedReviewedImports = new Map([
      ["buffer", ["node_buffer", "surface.builtin.buffer.1im057c", "object", true]],
      ["bun:sqlite", ["exact_sqlite", "surface.builtin.bun.sqlite.0o8405f", "function", false]],
      ["console", ["node_console", "surface.builtin.console.0n34od3", "object", true]],
      ["dns", ["node_dns", "surface.builtin.dns.1dztj15", "object", true]],
      ["dns/promises", ["node_dns_promises", "surface.builtin.dns.promises.1krunow", "object", true]],
      ["exact:clipboard", ["exact_clipboard", "surface.builtin.exact.clipboard.1v5no11", "object", false]],
      ["exact:http", ["exact_http", "surface.builtin.exact.http.0mrdk21", "object", false]],
      ["exact:sqlite", ["exact_sqlite", "surface.builtin.exact.sqlite.1diouj5", "function", false]],
      ["module", ["node_module", "surface.builtin.module.1uziekq", "object", true]],
      ["node:buffer", ["node_buffer", "surface.builtin.node.buffer.1g4y1x6", "object", true]],
      ["node:console", ["node_console", "surface.builtin.node.console.03x9qzd", "object", true]],
      ["node:dns", ["node_dns", "surface.builtin.node.dns.0nx113j", "object", true]],
      ["node:dns/promises", ["node_dns_promises", "surface.builtin.node.dns.promises.0izp08e", "object", true]],
      ["node:module", ["node_module", "surface.builtin.node.module.1ob4caw", "object", true]],
      ["node:path", ["node_path", "surface.builtin.node.path.06h5xrb", "object", true]],
      ["node:path/posix", ["path_posix_alias", "surface.builtin.node.path.posix.05jc96j", "object", true]],
      ["node:path/win32", ["path_win32_alias", "surface.builtin.node.path.win32.1b5yeev", "object", true]],
      ["node:punycode", ["node_punycode", "surface.builtin.node.punycode.155q5jn", "object", true]],
      ["node:querystring", ["node_querystring", "surface.builtin.node.querystring.1s25i2t", "object", true]],
      ["node:string_decoder", ["node_string_decoder", "surface.builtin.node.string.decoder.1v2dqn6", "function", true]],
      ["node:timers", ["node_timers", "surface.builtin.node.timers.1fi3efa", "object", true]],
      ["node:timers/promises", ["node_timers_promises", "surface.builtin.node.timers.promises.1myq26p", "object", true]],
      ["node:trace_events", ["node_trace_events", "surface.builtin.node.trace.events.0arilkn", "object", true]],
      ["node:v8", ["node_v8", "surface.builtin.node.v8.14wjzpq", "object", true]],
      ["path", ["node_path", "surface.builtin.path.0viej51", "object", true]],
      ["path/posix", ["path_posix_alias", "surface.builtin.path.posix.0m4kknx", "object", true]],
      ["path/win32", ["path_win32_alias", "surface.builtin.path.win32.1i0lfll", "object", true]],
      ["punycode", ["node_punycode", "surface.builtin.punycode.1my8dad", "object", true]],
      ["querystring", ["node_querystring", "surface.builtin.querystring.1jlrk23", "object", true]],
      ["string_decoder", ["node_string_decoder", "surface.builtin.string.decoder.1j9txls", "function", true]],
      ["timers", ["node_timers", "surface.builtin.timers.1g7ah04", "object", true]],
      ["timers/promises", ["node_timers_promises", "surface.builtin.timers.promises.0ptv53r", "object", true]],
      ["trace_events", ["node_trace_events", "surface.builtin.trace.events.0uoh6jh", "object", true]],
      ["v8", ["node_v8", "surface.builtin.v8.0eynzxs", "object", true]],
    ]);
    expect(reviewedImports).toHaveLength(expectedReviewedImports.size);
    expect(
      reviewedImports.every((recipe) => {
        const invocation = recipe.publicSurfaceProbe.invocation;
        const expected = expectedReviewedImports.get(invocation.moduleSpecifier);
        return (
          expected !== undefined &&
          recipe.status === "fully-executable" &&
          recipe.actionIds.length === 0 &&
          recipe.residualReasons.length === 0 &&
          invocation.sourceDescriptor.sourceKey === expected[0] &&
          invocation.sourceDescriptor.carrierEdgeId === expected[1] &&
          invocation.sourceDescriptor.expectedRootType === expected[2] &&
          invocation.sourceDescriptor.sourceMetadata.moduleBuiltin === expected[3] &&
          invocation.exportName === undefined &&
          invocation.arguments.length === 0 &&
          invocation.setup.kind === "none" &&
          invocation.completion.kind === "event-loop-quiescence" &&
          invocation.completion.timeoutMilliseconds === 1_000 &&
          invocation.requiredAuthority.length === 0 &&
          invocation.expectedResult === "return" &&
          invocation.expectedTypedDecisionCount === 0 &&
          invocation.expectedTypedStages.length === 0 &&
          invocation.allowedCoverageEdgeIds.length === 0 &&
          invocation.expectedActionIds.length === 0 &&
          !recipe.route.surfaceObservedKeys[0].includes("getServers") &&
          !recipe.route.surfaceObservedKeys[0].includes("Resolver")
        );
      }),
    ).toBe(true);
    const residualAliases = aliases.filter(
      (recipe) => recipe.publicSurfaceProbe === null,
    );
    expect(
      residualAliases.map((recipe) => recipe.route.surfaceObservedKeys[0]),
    ).toEqual([
      "builtin:internal/fs/utils",
      "builtin:node:stream/consumers",
      "builtin:stream/consumers",
    ]);
    expect(
      residualAliases.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.residualReasons.includes(
            "non-capability-no-decision-probe-not-authored",
          ),
      ),
    ).toBe(true);

    const dnsDefaults = recipes.recipes.filter((recipe) =>
      [
        "builtin:export:node_dns:default",
        "builtin:export:node_dns_promises:default",
      ].includes(recipe.terminalObservedKey),
    );
    expect(dnsDefaults).toHaveLength(2);
    expect(
      dnsDefaults.every(
        (recipe) =>
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.actionIds.length === 0 &&
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.residualReasons.includes(
            "public-surface-invocation-not-authored",
          ),
      ),
    ).toBe(true);
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
        "exact_crypto",
        "node_assert",
        "node_buffer",
        "node_dns",
        "node_events",
        "node_fs",
        "node_http2",
        "node_module",
        "node_net",
        "node_perf_hooks",
        "node_path",
        "node_punycode",
        "node_querystring",
        "node_stream",
        "node_stream_web",
        "node_string_decoder",
        "node_tls",
        "node_url",
        "node_util",
        "node_v8",
        "node_zlib",
      ]),
    );
    expect(
      Object.fromEntries(
        ["exact_crypto", "node_fs", "node_module", "node_net", "node_v8"].map(
          (sourceKey) => [
            sourceKey,
            publicCalls.filter(
              (recipe) =>
                recipe.publicSurfaceProbe.invocation.sourceDescriptor
                  .sourceKey === sourceKey,
            ).length,
          ],
        ),
      ),
    ).toEqual({
      exact_crypto: 97,
      node_fs: 10,
      node_module: 3,
      node_net: 22,
      node_v8: 1,
    });
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
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.completion.kind ===
            "event-loop-quiescence" &&
          recipe.publicSurfaceProbe.invocation.completion
            .timeoutMilliseconds === 1_000,
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
    expect(rows).toHaveLength(114);
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
    // Eval and REPL are authenticated product ingress now, not closed CLI
    // controls. Their 20 parser/command spellings must not be claimed by the
    // production-closure harness.
    const authenticatedIngressCliSurfaces = new Set([
      "cli:argument-parser:ibex:eval_code:utf8-string",
      "cli:argument-parser:ibex:print_eval:utf8-string",
      "cli:command:ibex%20eval",
      "cli:command:ibex%20repl",
      "cli:eval",
      "cli:option:ibex:eval_code:action:Set",
      "cli:option:ibex:eval_code:arity:1:1",
      "cli:option:ibex:eval_code:value-name:CODE",
      "cli:option:ibex:print_eval:action:Set",
      "cli:option:ibex:print_eval:arity:1:1",
      "cli:option:ibex:print_eval:value-name:CODE",
      "cli:option-name:ibex:eval_code:-e",
      "cli:option-name:ibex:eval_code:--eval",
      "cli:option-name:ibex:print_eval:-p",
      "cli:option-name:ibex:print_eval:--print",
      "cli:positional:ibex%20eval:code",
      "cli:positional:ibex%20eval:code:action:Set",
      "cli:positional:ibex%20eval:code:arity:1:1",
      "cli:positional:ibex%20eval:code:value-name:CODE",
      "cli:repl",
    ]);
    expect(
      rows.every(
        (recipe) =>
          !authenticatedIngressCliSurfaces.has(recipe.terminalObservedKey),
      ),
    ).toBe(true);
    const authenticatedIngressRows = recipes.recipes.filter((recipe) =>
      authenticatedIngressCliSurfaces.has(recipe.terminalObservedKey),
    );
    expect(authenticatedIngressRows).toHaveLength(20);
    expect(
      authenticatedIngressRows.every(
        (recipe) =>
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability",
      ),
    ).toBe(true);
    expect(
      rows.filter(
        (recipe) =>
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
            .evidenceType === "cli-default-value",
      ),
    ).toHaveLength(12);
    const unresolvedClosedCli = recipes.recipes.filter(
      (recipe) =>
        recipe.scenario === "closed" &&
        recipe.terminalObservedKey.startsWith("cli:") &&
        recipe.status !== "fully-executable",
    );
    expect(unresolvedClosedCli).toHaveLength(10);
    expect(
      unresolvedClosedCli.find(
        (recipe) =>
          recipe.terminalObservedKey === "cli:command:ibex%20capsec%20audit",
      ),
    ).toMatchObject({
      classification: "closed",
      scenario: "closed",
      publicSurfaceProbe: null,
      status: "unresolved",
      residualReasons: [
        "closed-surface-denial-probe-not-authored",
        "public-surface-invocation-not-authored",
      ],
    });
  });

  test("binds reviewed evaluator identities to real lockdown taming", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "tamed-evaluator",
    );
    expect(rows).toHaveLength(4);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.operation.globalName,
        recipe.publicSurfaceProbe.invocation.operation.accessMode,
      ]),
    ).toEqual([
      ["AsyncFunction", "async-function-constructor"],
      ["eval", "global-eval"],
      ["Function", "global-function"],
      ["GeneratorFunction", "generator-function-constructor"],
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.kind ===
            "closed-tamed-evaluator" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata
            .tamingEvidence === "lockdownJS" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.lockdownTamingDigest.startsWith(
            "sha256-",
          ),
      ),
    ).toBe(true);
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
    expect(recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest).toMatch(
      /^sha256-/u,
    );

    for (const surfaceObservedKey of [
      "native-op:global:CloseEvent.AT_TARGET",
      "native-op:global:WebSocketError.ABORT_ERR",
    ]) {
      const inherited = recipes.recipes.find(
        (candidate) =>
          candidate.scenario === "non-capability" &&
          candidate.publicSurfaceProbe?.surfaceObservedKey ===
            surfaceObservedKey,
      );
      expect(inherited).toMatchObject({
        classification: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            kind: "global-property-read",
            sourceDescriptor: {
              valueShape: "data",
            },
          },
        },
      });
      expect(
        inherited.publicSurfaceProbe.invocation.sourceDescriptor.memberKinds.includes(
          "inherited",
        ),
      ).toBe(true);
      expect(
        inherited.publicSurfaceProbe.invocation.sourceDescriptor.memberKinds.includes(
          "static",
        ),
      ).toBe(true);
    }

    const inheritedStaticReads = recipes.recipes.filter((candidate) => {
      const memberKinds =
        candidate.publicSurfaceProbe?.invocation?.sourceDescriptor?.memberKinds;
      return Array.isArray(memberKinds) && memberKinds.includes("inherited");
    });
    expect(inheritedStaticReads).toHaveLength(57);
    const allowedInheritedKinds = new Set([
      '["inherited","static"]',
      '["inherited","static","static-assignment"]',
    ]);
    expect(
      inheritedStaticReads.every((candidate) => {
        const descriptor =
          candidate.publicSurfaceProbe.invocation.sourceDescriptor;
        return (
          candidate.classification === "non-capability" &&
          candidate.scenario === "non-capability" &&
          candidate.status === "fully-executable" &&
          candidate.residualReasons.length === 0 &&
          descriptor.valueShape === "data" &&
          allowedInheritedKinds.has(JSON.stringify(descriptor.memberKinds))
        );
      }),
    ).toBe(true);

    const prototypeAccessorRows = recipes.recipes.filter((candidate) =>
      candidate.route.surfaceObservedKeys.includes(
        "native-op:global:Intl.Locale.prototype.textInfo",
      ),
    );
    expect(prototypeAccessorRows.length).toBeGreaterThan(0);
    expect(
      prototypeAccessorRows.every(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.kind !==
          "global-property-read",
      ),
    ).toBe(true);
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

    const zlibRows = recipes.recipes.filter((recipe) =>
      [
        "__exactZlibCheckOwner",
        "__exactZlibClose",
        "__exactZlibCreate",
        "__exactZlibParams",
        "__exactZlibWrite",
      ].includes(recipe.publicSurfaceProbe?.invocation?.globalName),
    );
    expect(zlibRows).toHaveLength(5);
    expect(
      zlibRows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0,
      ),
    ).toBe(true);
    expect(
      zlibRows.map(
        (recipe) => recipe.publicSurfaceProbe.invocation.expectedCleanup,
      ),
    ).toEqual([
      "closed-zlib-stream",
      "consumed-zlib-stream",
      "closed-zlib-stream",
      "closed-zlib-stream",
      "closed-zlib-stream",
    ]);
    const zlibWrite = zlibRows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.globalName === "__exactZlibWrite",
    );
    expect(zlibWrite.publicSurfaceProbe.invocation.arguments[0]).toMatchObject({
      kind: "native-global-result",
      globalName: "__exactZlibCreate",
      sourceDescriptor: {
        arity: 5,
        globalName: "__exactZlibCreate",
        kind: "native-global-function",
      },
    });
    const tlsRows = recipes.recipes.filter((recipe) =>
      recipe.publicSurfaceProbe?.invocation?.globalName?.startsWith(
        "__exactTlsEngine",
      ),
    );
    expect(tlsRows).toHaveLength(10);
    expect(
      tlsRows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          typeof recipe.publicSurfaceProbe.invocation.expectedCleanup ===
            "string",
      ),
    ).toBe(true);
    const tlsWrite = tlsRows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.globalName ===
        "__exactTlsEngineWritePlain",
    );
    expect(tlsWrite.publicSurfaceProbe.invocation.arguments).toMatchObject([
      {
        kind: "native-global-result",
        globalName: "__exactTlsEngineNew",
      },
      {
        kind: "native-global-result",
        globalName: "__exactStringToUtf8Bytes",
      },
    ]);
    for (const globalName of ["__exactNetOwner", "__exactTlsOwnerToken"]) {
      expect(
        recipes.recipes.find(
          (recipe) =>
            recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
        ),
      ).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [{ value: "new" }],
            expectedCleanup:
              globalName === "__exactNetOwner"
                ? "none"
                : "closed-tls-owner-token",
          },
        },
      });
    }

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

  test("executes bounded asymmetric and EVP crypto pairs with shared key material", () => {
    const globalNames = [
      "__exactEcdhDeriveBits",
      "__exactEcdsaSign",
      "__exactEcdsaVerify",
      "__exactEd25519Sign",
      "__exactEd25519Verify",
      "__exactEvpCipherDecrypt",
      "__exactEvpCipherEncrypt",
      "__exactExportKeyPkcs8",
      "__exactExportKeySpki",
      "__exactImportKeyPkcs8",
      "__exactImportKeySpki",
      "__exactRsaOaepDecrypt",
      "__exactRsaOaepEncrypt",
      "__exactX25519DeriveBits",
    ];
    const rows = recipes.recipes.filter((recipe) =>
      globalNames.includes(recipe.publicSurfaceProbe?.invocation?.globalName),
    );
    expect(rows.map((recipe) => recipe.terminalObservedKey).sort()).toEqual(
      globalNames.map((name) => `native-op:${name}`).sort(),
    );
    expect(
      rows.every(
        (recipe) =>
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount === 0,
      ),
    ).toBe(true);

    const ecdsaVerify = rows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.globalName ===
        "__exactEcdsaVerify",
    ).publicSurfaceProbe.invocation;
    const ecdsaPublicKey = ecdsaVerify.arguments[2];
    const ecdsaPrivateKey = ecdsaVerify.arguments[3].arguments[2];
    expect(ecdsaPublicKey).toMatchObject({
      kind: "native-global-result-property",
      globalName: "__exactGenerateKeyPairSync",
      property: "publicKey",
    });
    expect(ecdsaPrivateKey).toMatchObject({
      kind: "native-global-result-property",
      globalName: "__exactGenerateKeyPairSync",
      property: "privateKey",
    });
    expect(ecdsaPublicKey.arguments).toEqual(ecdsaPrivateKey.arguments);
    expect(ecdsaPublicKey.sourceDescriptorDigest).toBe(
      ecdsaPrivateKey.sourceDescriptorDigest,
    );

    const rsaDecrypt = rows.find(
      (recipe) =>
        recipe.publicSurfaceProbe.invocation.globalName ===
        "__exactRsaOaepDecrypt",
    ).publicSurfaceProbe.invocation;
    expect(rsaDecrypt.arguments[3]).toMatchObject({
      kind: "native-global-result",
      globalName: "__exactRsaOaepEncrypt",
      sourceDescriptor: {
        arity: 4,
        globalName: "__exactRsaOaepEncrypt",
        kind: "native-global-function",
      },
    });
    expect(rsaDecrypt.arguments[0].arguments).toEqual(
      rsaDecrypt.arguments[3].arguments[0].arguments,
    );
  });

  test("executes bounded authority-control refusals without minting authority", () => {
    const expectedArguments = new Map([
      ["__exactHandleScoped", [0, "fs:read"]],
      ["__exactRevokeHandle", [0]],
      ["__exactPermissionRequest", ["capsec:unknown"]],
      ["__exactPermissionRevoke", ["capsec:unknown"]],
      ["__exactPermissionStatus", ["capsec:unknown"]],
      ["__exactTypedPermissionRequest", [{}]],
      ["__exactTypedPermissionRevoke", ["unknown-grant"]],
      ["__exactTypedHandleMint", [{}]],
      ["__exactTypedHandleRevoke", ["unknown-handle"]],
    ]);
    for (const [globalName, values] of expectedArguments) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName &&
          candidate.scenario === "non-capability",
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
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
      expect(
        recipe.publicSurfaceProbe.invocation.arguments.map(
          (argument) => argument.value,
        ),
      ).toEqual(values);
    }

    const loaderPrivate = recipes.recipes.find(
      (candidate) =>
        candidate.publicSurfaceProbe?.invocation?.globalName ===
        "__exactResolveManifestBuiltinInternal",
    );
    expect(loaderPrivate).toMatchObject({
      classification: "non-capability",
      scenario: "non-capability",
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        invocation: {
          expectedResult: "absent",
          expectedTypedDecisionCount: 0,
          expectedTypedStages: [],
        },
      },
    });
  });

  test("refuses unknown retained HTTP and process ids without external effects", () => {
    const expectedArguments = new Map([
      ["__exactHttpOwner", [0]],
      ["__exactHttpRespondAbort", [0, 0]],
      ["__exactHttpClose", [0, 0]],
      ["__exactHttpSetRef", [0, 0]],
      ["__exactSpawnCloseStdin", [0, "stdin"]],
      ["__exactSpawnDispose", [0]],
    ]);
    for (const [globalName, values] of expectedArguments) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName &&
          candidate.scenario === "non-capability",
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
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
      expect(
        recipe.publicSurfaceProbe.invocation.arguments.map(
          (argument) => argument.value,
        ),
      ).toEqual(values);
    }
  });

  test("closes harness-owned filesystem descriptors outside typed observation", () => {
    for (const globalName of ["__exactFsClose", "__exactFsCloseAsync"]) {
      const recipe = recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName === globalName &&
          candidate.scenario === "non-capability",
      );
      expect(recipe).toMatchObject({
        classification: "non-capability",
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [{ kind: "harness-fs-file-descriptor" }],
            expectedCleanup: "consumed-fs-file-descriptor",
            expectedResult: "return",
            expectedTypedDecisionCount: 0,
            expectedTypedStages: [],
            setup: [
              {
                kind: "fs-read-file",
                globalName: "__exactFsOpen",
                sourceDescriptor: {
                  arity: 4,
                  globalName: "__exactFsOpen",
                  kind: "native-global-function",
                },
              },
            ],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.requiredFloor).toHaveLength(
        2,
      );
    }
  });

  test("executes incomplete authority calls and exact spawn owner refusal without decisions", () => {
    for (const globalName of [
      "__exactCapabilityCheck",
      "__exactCreateHandle",
    ]) {
      expect(
        recipes.recipes.find(
          (candidate) =>
            candidate.publicSurfaceProbe?.invocation?.globalName ===
              globalName && candidate.scenario === "non-capability",
        ),
      ).toMatchObject({
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [],
            expectedResult: "return",
            expectedTypedDecisionCount: 0,
          },
        },
      });
    }
    expect(
      recipes.recipes.find(
        (candidate) =>
          candidate.publicSurfaceProbe?.invocation?.globalName ===
            "__exactSpawnSetReferenced" &&
          candidate.scenario === "non-capability",
      ),
    ).toMatchObject({
      status: "fully-executable",
      residualReasons: [],
      publicSurfaceProbe: {
        invocation: {
          arguments: [{ value: 0 }, { value: false }],
          expectedResult: "invalid-handle",
          expectedTypedDecisionCount: 0,
        },
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

    for (const [globalName, producerName] of [
      ["clearInterval", "setInterval"],
      ["clearTimeout", "setTimeout"],
      ["__exactTimerRef", "setTimeout"],
      ["__exactTimerUnref", "setTimeout"],
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
            arguments: [
              {
                kind: "native-global-result",
                globalName: producerName,
                sourceDescriptor: {
                  arity: 2,
                  globalName: producerName,
                  kind: "native-global-function",
                },
                arguments: [
                  { kind: "harness-noop-callback" },
                  { kind: "json-literal", value: 60_000 },
                ],
              },
            ],
          },
        },
      });
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

  test("executes armed environment enumeration closure without authority", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
          "__exactGetAllEnv" &&
        ["branch-selection", "no-effect"].includes(recipe.scenario) &&
        recipe.actionIds.length === 0,
    );
    expect(rows).toHaveLength(2);
    expect(rows.map((recipe) => recipe.scenario).sort()).toEqual([
      "branch-selection",
      "no-effect",
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.classification === "effects" &&
          recipe.residualReasons.length === 0 &&
          recipe.publicSurfaceProbe.invocation.arguments.length === 0 &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedStages.length === 0,
      ),
    ).toBe(true);
  });

  test("executes exact in-memory SQLite conditional branches without authority", () => {
    const globalNames = [
      "__exactSqliteAll",
      "__exactSqliteExec",
      "__exactSqliteGet",
      "__exactSqliteOpen",
      "__exactSqlitePrepare",
      "__exactSqliteRun",
      "__exactSqliteValues",
    ];
    const rows = recipes.recipes.filter(
      (recipe) =>
        globalNames.includes(
          recipe.publicSurfaceProbe?.invocation?.globalName,
        ) &&
        ["branch-selection", "no-effect"].includes(recipe.scenario) &&
        recipe.fixtureId.includes(".logical.memory."),
    );
    expect(rows).toHaveLength(14);
    expect(
      rows.map((recipe) => [
        recipe.publicSurfaceProbe.invocation.globalName,
        recipe.scenario,
      ]),
    ).toEqual(
      globalNames.flatMap((globalName) => [
        [globalName, "branch-selection"],
        [globalName, "no-effect"],
      ]),
    );
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.actionIds.length === 0 &&
          recipe.adapterProbe === null &&
          recipe.publicSurfaceProbe.invocation.expectedResult === "return" &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedStages.length ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedActionIds.length === 0,
      ),
    ).toBe(true);
  });

  test("executes source-defined SQLite host ABIs on the exact memory branch", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.invocationSchema ===
          "ibex/capsec-host-abi-invocation/1" &&
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
          "sqlite-memory",
    );
    expect(rows).toHaveLength(14);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.classification === "effects" &&
          ["branch-selection", "no-effect"].includes(recipe.scenario) &&
          recipe.fixtureId.includes(".logical.memory.") &&
          recipe.actionIds.length === 0 &&
          recipe.adapterProbe === null &&
          recipe.publicSurfaceProbe.surfaceObservedKey ===
            `host-abi:${recipe.publicSurfaceProbe.invocation.functionName}` &&
          recipe.publicSurfaceProbe.invocation.operation.kind ===
            "sqlite-memory" &&
          recipe.publicSurfaceProbe.invocation.operation.selectedBranch.id ===
            "memory" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.kind ===
            "host-abi-function" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor
            .sourceRefs[0] ===
            `src/host/abi.rs#${recipe.publicSurfaceProbe.invocation.functionName}` &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedTypedStages.length ===
            0 &&
          recipe.publicSurfaceProbe.invocation.expectedActionIds.length === 0,
      ),
    ).toBe(true);
  });

  test("executes source-defined module-runner host ABIs through one real graph", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "module-runner-source-graph",
    );
    expect(rows).toHaveLength(19);
    expect(
      rows.map((recipe) => recipe.publicSurfaceProbe.invocation.functionName),
    ).toEqual([
      "ex_hermes_commonjs_create_record",
      "ex_hermes_commonjs_record_create_esm_adapter",
      "ex_hermes_commonjs_record_declare_export",
      "ex_hermes_commonjs_record_evaluate",
      "ex_hermes_graph_context_create",
      "ex_hermes_graph_context_retain",
      "ex_hermes_module_compile_factory",
      "ex_hermes_module_create_record",
      "ex_hermes_module_load_carrier_factory",
      "ex_hermes_module_pin_generation",
      "ex_hermes_module_record_declare_export",
      "ex_hermes_module_record_instantiate",
      "ex_hermes_module_record_link_dependency",
      "ex_hermes_module_record_link_export",
      "ex_hermes_module_record_link_import",
      "ex_hermes_module_record_poll_evaluation",
      "ex_hermes_module_record_run_declare",
      "ex_hermes_module_record_run_execute",
      "ex_hermes_module_release_handle",
    ]);
    expect(
      rows.every(
        (recipe) =>
          recipe.status === "fully-executable" &&
          recipe.residualReasons.length === 0 &&
          recipe.classification === "non-capability" &&
          recipe.scenario === "non-capability" &&
          recipe.actionIds.length === 0 &&
          recipe.adapterProbe === null &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.kind ===
            "host-abi-function" &&
          recipe.publicSurfaceProbe.invocation.sourceDescriptor
            .sourceRefs[0] ===
            `src/engine/hermes_module_runner.cc#${recipe.publicSurfaceProbe.invocation.functionName}` &&
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount === 0,
      ),
    ).toBe(true);

    const runtimeTeardownOnlyFunctions = [
      "ex_hermes_module_unpin_generation",
    ];
    const nonNativeLifecycleFunctions = [...runtimeTeardownOnlyFunctions];
    const deferredRows = recipes.recipes.filter(
      (recipe) =>
        recipe.scenario === "non-capability" &&
        nonNativeLifecycleFunctions.includes(
          recipe.terminalObservedKey.slice("host-abi:".length),
        ),
    );
    expect(
      [
        ...new Set(
          deferredRows.map((recipe) =>
            recipe.terminalObservedKey.slice("host-abi:".length),
          ),
        ),
      ],
    ).toEqual(nonNativeLifecycleFunctions);
    expect(
      deferredRows.every(
        (recipe) =>
          recipe.status === "unresolved" &&
          recipe.publicSurfaceProbe === null &&
          recipe.residualReasons.includes(
            "public-surface-invocation-not-authored",
          ) &&
          recipe.residualReasons.includes(
            "non-capability-no-decision-probe-not-authored",
          ),
      ),
    ).toBe(true);
  });

  test("closes module namespace inspection on an armed runtime", () => {
    const rows = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.operation?.kind ===
        "module-runner-namespace",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      classification: "closed",
      scenario: "closed",
      status: "fully-executable",
      residualReasons: [],
      terminalObservedKey: "host-abi:ex_hermes_module_record_namespace_json",
      publicSurfaceProbe: {
        surfaceObservedKey: "host-abi:ex_hermes_module_record_namespace_json",
        invocation: {
          invocationSchema: "ibex/capsec-closed-surface-invocation/1",
          kind: "closed-surface",
          surfaceKind: "host-abi",
          surfaceName: "ex_hermes_module_record_namespace_json",
          sourceDescriptor: {
            kind: "closed-module-runner-namespace",
            sourceRefs: [
              "src/engine/hermes_module_runner.cc#ex_hermes_module_record_namespace_json",
            ],
          },
          operation: {
            kind: "module-runner-namespace",
            expectedError:
              "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup",
          },
          expectedResult: "closed",
          expectedTypedDecisionCount: 0,
        },
      },
    });
  });

  test("binds OS-info calls to exact typed selectors and stages", () => {
    const hostname = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName ===
        "__exactGetHostname",
    );
    expect(hostname).toHaveLength(5);
    expect(hostname.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
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
        recipe.scenario === "deny" ? ["requested"] : ["requested", "commit"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "deny" ? 1 : 2);
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

  test("binds direct system-state calls to exact typed selectors and stages", () => {
    for (const { globalName, actionId, resource } of [
      {
        globalName: "__exactGetProcessRSS",
        actionId: "sys:read",
        resource: { kind: "system-info", name: "memory" },
      },
    ]) {
      const directSystemInfo = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(directSystemInfo).toHaveLength(5);
      expect(directSystemInfo.map((recipe) => recipe.scenario)).toEqual([
        "allow",
        "deny",
        "malformed",
        "missing-attribution",
        "wrong-principal",
      ]);
      for (const recipe of directSystemInfo) {
        expect(recipe).toMatchObject({
          actionIds: [actionId],
          status: "fully-executable",
          residualReasons: [],
          publicSurfaceProbe: {
            invocation: {
              requiredFloor: [
                {
                  cap: actionId,
                  resource,
                },
              ],
              expectedActionIds: [actionId],
            },
          },
        });
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedStages,
        ).toEqual(
          recipe.scenario === "deny" ? ["requested"] : ["requested", "commit"],
        );
        expect(
          recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
        ).toBe(recipe.scenario === "deny" ? 1 : 2);
      }
    }
  });

  test("binds the private cwd bridge to its authenticated public facade", () => {
    const privateCwd = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactGetCwd",
    );
    expect(privateCwd).toHaveLength(2);
    expect(privateCwd.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
    ]);
    for (const recipe of privateCwd) {
      expect(recipe).toMatchObject({
        actionIds: ["path:cwd-observe"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            kind: "private-native-facade-function",
            requiredFloor: [
              {
                cap: "path:cwd-observe",
                resource: { kind: "session-state", name: "cwd" },
              },
            ],
            expectedActionIds: ["path:cwd-observe"],
            publicAccess: {
              kind: "captured-private-global-function",
              observedKey: "native-op:global:process.cwd",
              path: ["process", "cwd"],
              privateTerminal: {
                observedKey: "native-op:__exactGetCwd",
                privateConsumer: "trusted-path-process-builtins",
                liveExpectation: "absent",
              },
              expectedDenyMessageFragment: "filesystem policy denied",
            },
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.publicAccessDigest).toMatch(
        /^sha256-/u,
      );
      expect(
        Object.hasOwn(
          recipe.publicSurfaceProbe.invocation,
          "expectedDenyMessageFragment",
        ),
      ).toBe(false);
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "allow" ? ["requested", "commit"] : ["requested"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "allow" ? 2 : 1);
    }
  });

  test("binds armed scalar environment reads to one exact principal overlay name", () => {
    const environmentRead = recipes.recipes.filter(
      (recipe) =>
        recipe.publicSurfaceProbe?.invocation?.globalName === "__exactGetEnv",
    );
    expect(environmentRead).toHaveLength(5);
    expect(environmentRead.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
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
                  target: "principal-overlay",
                  name: "PATH",
                },
              },
            ],
            expectedActionIds: ["env:read"],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario === "deny" ? ["requested"] : ["requested", "commit"],
      );
    }
  });

  test("binds direct print to the exact stdout broker and generated stages", () => {
    const print = recipes.recipes.filter(
      (recipe) => recipe.publicSurfaceProbe?.invocation?.globalName === "print",
    );
    expect(print).toHaveLength(5);
    expect(print.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
    ]);
    for (const recipe of print) {
      expect(recipe).toMatchObject({
        actionIds: ["stdio:write"],
        status: "fully-executable",
        residualReasons: [],
        publicSurfaceProbe: {
          invocation: {
            arguments: [{ kind: "json-literal", value: "ibex-capsec-print" }],
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
        recipe.scenario === "deny"
          ? ["requested"]
          : ["requested", "commit", "repeat"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "deny" ? 1 : 3);
    }
  });

  test("binds project metadata reads to one stable retained path", () => {
    for (const globalName of [
      "__exactStat",
      "__exactLstat",
      "__exactRealpath",
    ]) {
      const metadataReads = recipes.recipes.filter(
        (recipe) =>
          recipe.publicSurfaceProbe?.invocation?.globalName === globalName,
      );
      expect(metadataReads).toHaveLength(5);
      expect(metadataReads.map((recipe) => recipe.scenario)).toEqual([
        "allow",
        "deny",
        "malformed",
        "missing-attribution",
        "wrong-principal",
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
                      components: [{ encoding: "utf8", value: "Cargo.toml" }],
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
          recipe.scenario !== "deny"
            ? globalName === "__exactRealpath"
              ? [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "repeat",
                  "repeat",
                ]
              : globalName === "__exactStat"
                ? ["requested", "discovery", "requested", "repeat", "repeat"]
                : ["requested", "discovery", "requested", "repeat"]
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
    expect(readFile).toHaveLength(5);
    expect(readFile.map((recipe) => recipe.scenario)).toEqual([
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
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
                    components: [{ encoding: "utf8", value: "Cargo.toml" }],
                  },
                },
              },
              {
                cap: "fs:read",
                resource: {
                  kind: "path-exact",
                  path: {
                    root: "project",
                    components: [{ encoding: "utf8", value: "Cargo.toml" }],
                  },
                },
              },
            ],
          },
        },
      });
      expect(recipe.publicSurfaceProbe.invocation.expectedActionIds).toEqual(
        recipe.scenario === "deny" ? ["fs:list"] : ["fs:list", "fs:read"],
      );
      expect(recipe.publicSurfaceProbe.invocation.expectedTypedStages).toEqual(
        recipe.scenario !== "deny"
          ? [
              "requested",
              "discovery",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ]
          : ["requested"],
      );
      expect(
        recipe.publicSurfaceProbe.invocation.expectedTypedDecisionCount,
      ).toBe(recipe.scenario === "deny" ? 1 : 6);
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

  test("projects path facts to their exact adapter stage", () => {
    let pathEffects = 0;
    const discoveryOrLater = new Set([
      "discovery",
      "candidate",
      "commit",
      "delivery",
      "repeat",
      "cleanup",
    ]);
    const commitOrLater = new Set(["commit", "delivery", "repeat", "cleanup"]);
    for (const recipe of recipes.recipes) {
      for (const probeCase of recipe.adapterProbe?.cases ?? []) {
        let decision;
        try {
          decision = JSON.parse(probeCase.decisionSetJson);
        } catch {
          continue;
        }
        for (const effect of decision.effects) {
          if (effect.resource.kind !== "path-occurrence") continue;
          pathEffects += 1;
          if (!discoveryOrLater.has(probeCase.stage)) {
            expect(effect.resource.objectState).toBe("unknown");
            expect(effect.resource.parentObject).toBeUndefined();
            expect(effect.resource.finalObject).toBeUndefined();
            expect(effect.resource.finalObjectGeneration).toBeUndefined();
          } else {
            expect(effect.resource.objectState).not.toBe("unknown");
            expect(effect.resource.parentObject).toBeDefined();
            if (effect.resource.objectState === "existing") {
              expect(effect.resource.finalObject).toBeDefined();
            } else {
              expect(effect.resource.finalObject).toBeUndefined();
            }
          }
          if (commitOrLater.has(probeCase.stage)) {
            expect(effect.resource.retainedHandle).toBeDefined();
          } else {
            expect(effect.resource.retainedHandle).toBeUndefined();
          }
        }
      }
    }
    expect(pathEffects).toBeGreaterThan(0);
  });

  test("emits semantically valid occurrences for every allow adapter case", () => {
    const definitionsById = new Map(
      capabilityDefinitions.definitions.map((definition) => [
        definition.id,
        definition,
      ]),
    );
    let cwdCommitEffects = 0;
    for (const recipe of recipes.recipes) {
      if (recipe.scenario !== "allow") continue;
      for (const probeCase of recipe.adapterProbe?.cases ?? []) {
        const decision = JSON.parse(probeCase.decisionSetJson);
        decision.effects.forEach((effect, effectIndex) => {
          if (
            effect.cap === "path:cwd-mutate" &&
            probeCase.stage === "commit"
          ) {
            cwdCommitEffects += 1;
          }
          expect(() =>
            validateOccurrenceSemantics(
              {
                cap: effect.cap,
                stage: decision.context.stage,
                actor: decision.context.actor,
                effectOwner: effect.effectOwner,
                constrainedPrincipals: decision.context.constrainedPrincipals,
                resource: effect.resource,
              },
              definitionsById,
              rules,
              `${recipe.fixtureId}:${probeCase.stage}:${effectIndex}`,
            ),
          ).not.toThrow();
        });
      }
    }
    expect(cwdCommitEffects).toBe(3);
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
