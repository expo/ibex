// @ref LLP 0023#6-path-bearing-observables — output-shape sweep evidence is
// source/engine bound, bidirectional, and cannot echo reviewed expectations.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildOutputShapeCatalog,
  outputExecutionContextsForRows,
  outputShapeCatalogKeyDigest,
} from "./capsec-output-dispositions.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  OUTPUT_SHAPE_SWEEP_EXECUTOR,
  buildOutputShapeSweepArtifactFromExecutorBatch,
  buildOutputShapeSweepPlan,
  buildOutputShapeSweepProbes,
  buildVerifiedOutputDispositionEvidence,
  outputShapeProbeKindForCatalogRow,
  outputShapeSourceDescriptorDigest,
  sealOutputShapeSweepArtifact,
  validateOutputShapeSweepArtifact,
  validateOutputShapeSweepPlan,
} from "./capsec-output-shape-sweep.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../../..");

const digest = (character) => `sha256-${character.repeat(43)}`;

function key(
  surfaceId,
  output,
  sourceKind = "native-op",
  contextId = sourceKind === "bridge"
    ? "runtime.bootstrap-native-call-loaded"
    : sourceKind === "builtin"
      ? "javascript.package-call-loaded"
      : sourceKind === "native-op"
        ? "javascript.package-property-read-loaded"
        : "javascript.package-call-loaded",
) {
  return {
    surfaceId,
    output,
    alias: `${surfaceId}.${output}`,
    mode: "all",
    sourceKind,
    returnVariant: "default",
    contextId,
  };
}

const keys = [
  key("surface.native.op.private.0000001", "[[return]]"),
  key("surface.builtin.path.resolve.0000002", "[[return]]", "builtin"),
  key("surface.bridge.module.resolve.0000003", "field:path", "bridge"),
];
const structuralSurfaceId = "surface.native.op.structural.only.0000099";
keys[1].alias = "export:node_path:resolve";
keys[0].alias = "global:testPrivateSurface";

function v2Catalog(inputRows, { structuralSurfaceIds = [] } = {}) {
  const rows = inputRows.map((row) => ({
    ...structuredClone(row),
    requiredValueProof: "live-value-observation",
  }));
  const rowsBySurface = Map.groupBy(rows, (row) => row.key.surfaceId);
  const surfaceAccounts = [
    ...[...rowsBySurface.entries()].map(([surfaceId, surfaceRows]) => ({
      surfaceId,
      status: "output-bearing",
      reasonCode: "source-derived-public-output",
      sourceRefs: [
        ...new Set(surfaceRows.flatMap((row) => row.discovery.sourceRefs)),
      ].sort(),
      outputKinds: [
        ...new Set(surfaceRows.map((row) => row.discovery.kind)),
      ].sort(),
    })),
    ...structuralSurfaceIds.map((surfaceId) => ({
      surfaceId,
      status: "structural-only",
      reasonCode: "test-structural-surface",
      sourceRefs: [`src/test.cc#${surfaceId}`],
      outputKinds: [],
    })),
  ].sort((left, right) => left.surfaceId.localeCompare(right.surfaceId));
  const sourceInventoryRows = rows.filter(
    (row) => row.discovery.kind === "source-inventory-surface",
  ).length;
  const structuredRows = rows.length - sourceInventoryRows;
  return {
    outputShapeCatalogSchema: "ibex/capsec-output-shape-catalog/2",
    profile: "ibex/capsec/1",
    discovery: {
      status: "unpromotable",
      method:
        "source-inventory-surface-accounting-plus-source-asserted-structured-outputs",
      requiredExecutor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
      reason: "test catalog awaits loaded-engine observations",
    },
    contexts: outputExecutionContextsForRows(rows),
    surfaceAccounts,
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: surfaceAccounts.length,
      outputBearingSurfaces: rowsBySurface.size,
      structuralOnlySurfaces: structuralSurfaceIds.length,
      unresolvedSurfaces: 0,
      catalogRows: rows.length,
      sourceInventoryRows,
      structuredRows,
    },
    rows,
  };
}

let repositorySweepFixturePromise;
async function repositorySweepFixture() {
  repositorySweepFixturePromise ??= (async () => {
    const readJson = (relative) =>
      JSON.parse(fs.readFileSync(path.join(repoRoot, relative), "utf8"));
    const coverage = readJson("capsec/registry/coverage-edges.json");
    const rules = readJson("capsec/registry/policy-rules.json");
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const sourceByObservedKey = new Map(
      inventory.surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const implementationRows = coverage.edges.map((edge) => {
      const observedKey = `${edge.surface.kind}:${edge.surface.name}`;
      const surface = sourceByObservedKey.get(observedKey);
      if (!surface) throw new Error(`test inventory lacks ${observedKey}`);
      return {
        edgeId: edge.id,
        observedKey,
        sourceRefs: [...surface.sourceRefs],
      };
    });
    const catalog = buildOutputShapeCatalog({
      coverage,
      implementationRows,
      surfaces: inventory.surfaces,
      repoRoot,
      liveEvidence: {
        status: "unpromotable",
        requiredExecutor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
        reason: "test fixture awaits complete loaded-engine observations",
      },
    });
    return {
      catalog,
      coverage,
      surfaces: inventory.surfaces,
      target: rules.initialProfile.candidateTargets[0],
    };
  })();
  return repositorySweepFixturePromise;
}

function fixture() {
  const rows = keys.map((outputKey, index) => ({
    key: structuredClone(outputKey),
    discovery: {
      kind:
        index === 2
          ? "source-asserted-structured-output"
          : "source-inventory-surface",
      sourceRefs: [`src/test-${index}.cc#probe`],
      ...(index === 2 ? {} : { observedKeys: [`test:${index}`] }),
    },
  }));
  const catalog = v2Catalog(rows, {
    structuralSurfaceIds: [structuralSurfaceId],
  });
  const engine = {
    kind: "hermes",
    engineArtifactPath: "/exact/hermes",
    binaryDigest: digest("A"),
    object: { platform: "apple", volume: "dev:1", file: "ino:2" },
    targetArchitecture: "aarch64",
    structuralFeatures: ["session-runtime"],
  };
  const builtinDescriptor = {
    kind: "builtin-export",
    moduleSpecifier: "node:path",
    exportPath: ["resolve"],
    exercise: { kind: "call", arguments: ["output-shape"] },
  };
  const nativeDescriptor = {
    kind: "native-abi-fixture",
    symbol: "ex_test_private_surface",
    variant: "rooted-value",
    exercise: { kind: "descriptor" },
  };
  const resolverDescriptor = {
    kind: "resolver-fixture",
    bridge: "__exactModuleResolve",
    variant: "success",
  };
  const probes = [
    {
      key: structuredClone(keys[0]),
      probe: {
        kind: "loaded-engine-descriptor",
        sourceDescriptor: nativeDescriptor,
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(nativeDescriptor),
      },
    },
    {
      key: structuredClone(keys[1]),
      probe: {
        kind: "loaded-engine-descriptor",
        sourceDescriptor: builtinDescriptor,
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(builtinDescriptor),
      },
    },
    {
      key: structuredClone(keys[2]),
      probe: {
        kind: "loaded-engine-return-record",
        fixtureId: "resolver-success",
        sourceDescriptor: resolverDescriptor,
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(resolverDescriptor),
        recordPath: ["path"],
      },
    },
  ];
  const bindings = {
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: digest("D"),
    engine,
  };
  const plan = buildOutputShapeSweepPlan({ catalog, probes, ...bindings });
  const observations = [
    {
      key: structuredClone(keys[0]),
      observation: { outcome: "return", normalizedValue: "non-path" },
      proof: {
        kind: "loaded-engine-descriptor",
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(nativeDescriptor),
        descriptor: {
          presence: "own",
          descriptorKind: "data",
          valueType: "string",
          enumerable: false,
          configurable: false,
          writable: false,
          hasGetter: false,
          hasSetter: false,
        },
      },
    },
    {
      key: structuredClone(keys[1]),
      observation: {
        outcome: "return",
        normalizedValue: "virtual-absolute",
      },
      proof: {
        kind: "loaded-engine-descriptor",
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(builtinDescriptor),
        descriptor: {
          presence: "own",
          descriptorKind: "data",
          valueType: "function",
          enumerable: true,
          configurable: true,
          writable: true,
          hasGetter: false,
          hasSetter: false,
        },
      },
    },
    {
      key: structuredClone(keys[2]),
      observation: {
        outcome: "typed-return",
        normalizedValue: "ibex/logical-path/1",
      },
      proof: {
        kind: "loaded-engine-return-record",
        fixtureId: "resolver-success",
        sourceDescriptorDigest:
          outputShapeSourceDescriptorDigest(resolverDescriptor),
        recordPath: ["path"],
        rawValueShape: "object",
      },
    },
  ].sort((left, right) =>
    left.key.surfaceId.localeCompare(right.key.surfaceId),
  );
  const artifact = sealOutputShapeSweepArtifact({
    plan,
    loadedEngineIdentity: engine,
    compiledRegistrarIds: [
      ...keys.map((outputKey) => outputKey.surfaceId),
      structuralSurfaceId,
    ].sort(),
    observations,
  });
  const dispositionRows = [
    {
      key: structuredClone(keys[0]),
      disposition: "non-path",
      expectation: { outcome: "return", normalizedValue: "non-path" },
      rationale: "private registrar has no path-bearing return",
    },
    {
      key: structuredClone(keys[1]),
      disposition: "virtual-absolute",
      expectation: {
        outcome: "return",
        normalizedValue: "virtual-absolute",
      },
      rationale: "path.resolve is virtualized",
    },
    {
      key: structuredClone(keys[2]),
      disposition: "typed-logical",
      expectation: {
        outcome: "typed-return",
        normalizedValue: "ibex/logical-path/1",
      },
      rationale: "resolver returns a typed logical path",
    },
  ];
  return {
    artifact,
    bindings,
    catalog,
    dispositionRows,
    observations,
    plan,
    probes,
  };
}

function reseal(artifact) {
  return sealOutputShapeSweepArtifact({
    plan: fixture().plan,
    loadedEngineIdentity: artifact.loadedEngineIdentity,
    compiledRegistrarIds: artifact.compiledRegistrarIds,
    observations: artifact.observations,
  });
}

function executorBatch(value = fixture()) {
  const rawByProof = {
    "loaded-engine-return-record": {
      kind: "return",
      rawValueShape: "object",
      value: { schema: "ibex/logical-path/1" },
      errorCode: null,
    },
  };
  return {
    outputShapeExecutorBatchSchema: "ibex/capsec-output-shape-executor-batch/2",
    profile: "ibex/capsec/1",
    executor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
    sourceRevision: value.plan.sourceRevision,
    sourceTreeDigest: value.plan.sourceTreeDigest,
    catalogKeyDigest: value.plan.catalogKeyDigest,
    sweepPlanDigest: value.plan.sweepPlanDigest,
    loadedEngineIdentity: structuredClone(value.bindings.engine),
    compiledRegistrarIds: [
      ...keys.map((outputKey) => outputKey.surfaceId),
      structuralSurfaceId,
    ].sort(),
    results: value.observations.map((row) => ({
      key: structuredClone(row.key),
      proof: structuredClone(row.proof),
      raw: structuredClone(
        row.proof.kind === "loaded-engine-descriptor"
          ? row.key.surfaceId === keys[0].surfaceId
            ? {
                kind: "return",
                rawValueShape: "string",
                value: "test-private-value",
                errorCode: null,
              }
            : {
                kind: "return",
                rawValueShape: "string",
                value: "/project/output-shape.js",
                errorCode: null,
              }
          : rawByProof[row.proof.kind],
      ),
    })),
    unexercisable: [],
  };
}

describe("output-shape-sweep-v2 evidence contract", () => {
  test("routes and exactly validates the complete builtin-effects tranche", async () => {
    const { catalog, coverage, surfaces, target } =
      await repositorySweepFixture();
    const probes = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces,
      target,
    });
    const effects = probes.filter(
      (row) =>
        row.probe.sourceDescriptor?.kind === "authored-builtin-effects-output",
    );
    expect(effects).toHaveLength(605);
    expect(
      effects.filter(
        (row) => row.probe.sourceDescriptor.invocation.cohort === "registrar",
      ),
    ).toHaveLength(605);
    expect(
      effects.filter(
        (row) =>
          row.probe.sourceDescriptor.invocation.cohort ===
          "descriptor-residual",
      ),
    ).toHaveLength(0);

    const bindings = {
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: digest("D"),
      engine: fixture().bindings.engine,
    };
    expect(
      buildOutputShapeSweepPlan({ catalog, probes, ...bindings }).rows,
    ).toHaveLength(catalog.rows.length);

    const missingBinding = structuredClone(probes);
    const missingBindingRoute = missingBinding.find(
      (row) =>
        row.probe.sourceDescriptor?.kind === "authored-builtin-effects-output",
    );
    delete missingBindingRoute.probe.sourceDescriptor.invocation
      .decisionEvidence;
    missingBindingRoute.probe.sourceDescriptorDigest =
      outputShapeSourceDescriptorDigest(
        missingBindingRoute.probe.sourceDescriptor,
      );
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog,
        probes: missingBinding,
        ...bindings,
      }),
    ).toThrow(/expected exact keys/);

    const missingStages = structuredClone(probes);
    const missingStagesRoute = missingStages.find(
      (row) =>
        row.probe.sourceDescriptor?.kind === "authored-builtin-effects-output",
    );
    missingStagesRoute.probe.sourceDescriptor.invocation.decisionEvidence.typedRoutes[0].actionStages[0].stages =
      [];
    missingStagesRoute.probe.sourceDescriptorDigest =
      outputShapeSourceDescriptorDigest(
        missingStagesRoute.probe.sourceDescriptor,
      );
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog,
        probes: missingStages,
        ...bindings,
      }),
    ).toThrow(/typed action has no exact stages/);

    const wrongNativeBinding = structuredClone(probes);
    const wrongNativeBindingRoute = wrongNativeBinding.find((row) =>
      row.probe.sourceDescriptor?.invocation?.decisionEvidence?.typedRoutes?.some(
        (route) => route.sourceBinding !== null,
      ),
    );
    wrongNativeBindingRoute.probe.sourceDescriptor.invocation.decisionEvidence.typedRoutes.find(
      (route) => route.sourceBinding !== null,
    ).sourceBinding.nativeTerminal = "__exactWrongFilesystemTerminal";
    wrongNativeBindingRoute.probe.sourceDescriptorDigest =
      outputShapeSourceDescriptorDigest(
        wrongNativeBindingRoute.probe.sourceDescriptor,
      );
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog,
        probes: wrongNativeBinding,
        ...bindings,
      }),
    ).toThrow(/invalid native source binding/);
  }, 30_000);

  test("keeps structural registrar accounts separate from live value rows", async () => {
    const { catalog, coverage, surfaces, target } =
      await repositorySweepFixture();
    const probes = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces,
      target,
    });
    const counts = Object.fromEntries(
      [
        "compiled-runtime-return-record",
        "loaded-engine-descriptor",
        "loaded-engine-return-record",
      ].map((kind) => [kind, 0]),
    );
    for (const row of probes) {
      counts[row.probe.kind] += 1;
    }
    expect(Object.values(counts).reduce((sum, count) => sum + count, 0)).toBe(
      catalog.rows.length,
    );
    expect(counts["loaded-engine-descriptor"]).toBeGreaterThan(0);
    expect(counts["loaded-engine-return-record"]).toBeGreaterThan(0);
    expect(JSON.stringify(probes)).not.toContain("compiled-registrar");
    expect(catalog.surfaceAccounts.length).toBeGreaterThan(
      new Set(catalog.rows.map((row) => row.key.surfaceId)).size,
    );
  });

  test("authors probe routes only from catalog, coverage, and live source inventory", () => {
    const value = fixture();
    const coverage = {
      edges: [
        {
          id: keys[0].surfaceId,
          surface: { kind: "native-op", name: "ex_test_private_surface" },
        },
        {
          id: keys[1].surfaceId,
          surface: { kind: "builtin", name: "export:node_path:resolve" },
        },
        {
          id: keys[2].surfaceId,
          surface: { kind: "native-op", name: "__exactModuleResolve" },
        },
      ],
    };
    const surfaces = [
      {
        kind: "native-op",
        name: "ex_test_private_surface",
        observedKey: "native-op:ex_test_private_surface",
        sourceRefs: ["src/test-private.cc#ex_test_private_surface"],
        metadata: {
          surfaceType: "global-api",
          globalName: "testPrivateSurface",
          memberKinds: ["property"],
          valueShape: "string",
        },
      },
      {
        kind: "builtin",
        name: "export:node_path:resolve",
        observedKey: "builtin:export:node_path:resolve",
        sourceRefs: ["src/builtins/path.js#exports:resolve"],
        metadata: {
          surfaceType: "export",
          publicModuleSpecifiers: ["node:path", "path"],
          exportName: "resolve",
          exportIdioms: ["object-source"],
          valueShape: "callable",
        },
      },
      {
        kind: "native-op",
        name: "__exactModuleResolve",
        observedKey: "native-op:__exactModuleResolve",
        sourceRefs: ["src/engine/hermes_runtime.cc#__exactModuleResolve"],
        metadata: {},
      },
    ];
    const probes = buildOutputShapeSweepProbes({
      catalog: value.catalog,
      coverage,
      surfaces,
    });
    expect(probes.map((row) => row.probe.kind).sort()).toEqual([
      "loaded-engine-descriptor",
      "loaded-engine-descriptor",
      "loaded-engine-return-record",
    ]);
    expect(
      probes.find((row) => row.probe.kind === "loaded-engine-descriptor").probe
        .sourceDescriptor,
    ).toMatchObject({
      kind: "builtin-export",
      moduleSpecifiers: ["node:path", "path"],
      exportName: "resolve",
    });
    expect(JSON.stringify(probes)).not.toContain("normalizedValue");
    expect(JSON.stringify(probes)).not.toContain("disposition");
  });

  test("routes safe throw metadata through its bounded loaded-engine ABI fixture", () => {
    const outputKey = {
      surfaceId:
        "surface.native.op.ex.hermes.value.safe.throw.metadata.0000004",
      output: "[[return]]",
      alias: "ex_hermes_value_safe_throw_metadata",
      mode: "private-native",
      sourceKind: "native-op",
      returnVariant: "success",
      contextId: "host.private-native-call-initialized",
    };
    const catalog = v2Catalog([
      {
        key: outputKey,
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: ["native-op:ex_hermes_value_safe_throw_metadata"],
          sourceRefs: [
            "src/engine/hermes_runtime.cc#ex_hermes_value_safe_throw_metadata",
          ],
        },
      },
    ]);
    const coverage = {
      edges: [
        {
          id: outputKey.surfaceId,
          surface: {
            kind: "native-op",
            name: "ex_hermes_value_safe_throw_metadata",
          },
        },
      ],
    };
    const surfaces = [
      {
        kind: "native-op",
        name: "ex_hermes_value_safe_throw_metadata",
        observedKey: "native-op:ex_hermes_value_safe_throw_metadata",
        sourceRefs: [
          "src/engine/hermes_runtime.cc#ex_hermes_value_safe_throw_metadata",
        ],
        metadata: {},
      },
    ];
    expect(
      buildOutputShapeSweepProbes({ catalog, coverage, surfaces })[0].probe,
    ).toEqual({
      kind: "loaded-engine-return-record",
      fixtureId: "safe-throw-metadata",
      sourceDescriptor: {
        kind: "native-abi-fixture",
        symbol: "ex_hermes_value_safe_throw_metadata",
        variant: "rooted-error",
      },
      sourceDescriptorDigest: expect.stringMatching(/^sha256-/),
      recordPath: ["[[return]]"],
    });
  });

  test("routes source-proven native global data through the loaded realm", () => {
    const outputKey = {
      surfaceId: "surface.native.op.exact.access.0000005",
      output: "[[return]]",
      alias: "__exactAccessibilitySnapshot",
      mode: "all",
      sourceKind: "native-op",
      returnVariant: "default",
      contextId: "javascript.package-property-read-loaded",
    };
    const catalog = v2Catalog([
      {
        key: outputKey,
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: ["native-op:__exactAccessibilitySnapshot"],
          sourceRefs: [
            "src/engine/hermes_runtime_android.cc#__exactAccessibilitySnapshot",
          ],
        },
      },
    ]);
    const coverage = {
      edges: [
        {
          id: outputKey.surfaceId,
          surface: {
            kind: "native-op",
            name: "__exactAccessibilitySnapshot",
          },
        },
      ],
    };
    const surfaces = [
      {
        kind: "native-op",
        name: "__exactAccessibilitySnapshot",
        observedKey: "native-op:__exactAccessibilitySnapshot",
        sourceRefs: [
          "src/engine/hermes_runtime_android.cc#__exactAccessibilitySnapshot",
        ],
        metadata: {
          surfaceType: "global-api",
          globalName: "__exactAccessibilitySnapshot",
          memberName: null,
          memberKinds: ["native-root"],
          valueShape: "data",
        },
      },
    ];
    const probe = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces,
    })[0].probe;
    expect(probe.kind).toBe("loaded-engine-descriptor");
    expect(probe.sourceDescriptor).toMatchObject({
      kind: "global-api",
      globalName: "__exactAccessibilitySnapshot",
      memberName: null,
      exercise: { kind: "descriptor" },
    });
  });

  test("does not substitute a callable descriptor for readFileSync output", () => {
    const outputKey = {
      surfaceId: "surface.builtin.node.fs.read.file.sync.0000006",
      output: "[[return]]",
      alias: "export:node_fs:readFileSync",
      mode: "all",
      sourceKind: "builtin",
      returnVariant: "default",
      contextId: "javascript.package-call-loaded",
    };
    const probe = buildOutputShapeSweepProbes({
      catalog: v2Catalog([
        {
          key: outputKey,
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: ["builtin:export:node_fs:readFileSync"],
            sourceRefs: ["modules.ts#sources:node_fs:exports:readFileSync"],
          },
        },
      ]),
      coverage: {
        edges: [
          {
            id: outputKey.surfaceId,
            surface: {
              kind: "builtin",
              name: "export:node_fs:readFileSync",
            },
          },
        ],
      },
      surfaces: [
        {
          kind: "builtin",
          name: "export:node_fs:readFileSync",
          observedKey: "builtin:export:node_fs:readFileSync",
          sourceRefs: ["modules.ts#sources:node_fs:exports:readFileSync"],
          metadata: {
            surfaceType: "export",
            publicModuleSpecifiers: ["node:fs", "fs"],
            exportName: "readFileSync",
            exportIdioms: ["module-exports-object"],
            valueShape: "callable",
          },
        },
      ],
    })[0].probe;
    expect(probe).toMatchObject({
      kind: "loaded-engine-descriptor",
      sourceDescriptor: {
        exercise: {
          kind: "unexercisable",
          reasonCode: "missing-authored-live-invocation",
        },
      },
    });
  });

  test("routes exact non-capability builtin recipes through real return records", () => {
    const outputKey = {
      surfaceId: "surface.builtin.node.path.basename.0000007",
      output: "[[return]]",
      alias: "export:node_path:basename",
      mode: "all",
      sourceKind: "builtin",
      returnVariant: "default",
      contextId: "javascript.package-call-loaded",
    };
    const sourceRef = "src/builtins/path.js#exports:basename";
    const probe = buildOutputShapeSweepProbes({
      catalog: v2Catalog([
        {
          key: outputKey,
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: ["builtin:export:node_path:basename"],
            sourceRefs: [sourceRef],
          },
        },
      ]),
      coverage: {
        edges: [
          {
            id: outputKey.surfaceId,
            classification: "non-capability",
            surface: {
              kind: "builtin",
              name: "export:node_path:basename",
            },
          },
        ],
      },
      surfaces: [
        {
          kind: "builtin",
          name: "export:node_path:basename",
          observedKey: "builtin:export:node_path:basename",
          sourceRefs: [sourceRef],
          metadata: {
            sourceKey: "node_path",
            exportName: "basename",
            exportIdioms: ["object-binding", "object-source"],
            importReachability: "public",
            moduleSpecifiers: ["node:path", "path"],
            publicModuleSpecifiers: ["node:path", "path"],
            surfaceType: "export",
            valueShape: "callable",
          },
        },
      ],
      target: { triple: "aarch64-apple-darwin" },
    })[0].probe;
    expect(probe).toMatchObject({
      kind: "loaded-engine-return-record",
      recordPath: ["[[return]]"],
      sourceDescriptor: {
        kind: "authored-public-builtin-invocation",
        surfaceObservedKey: "builtin:export:node_path:basename",
        invocation: {
          kind: "builtin-export-call",
          moduleSpecifier: "node:path",
          exportName: "basename",
          templateId: "node-path-pure-v1",
        },
      },
    });
    expect(JSON.stringify(probe)).not.toContain("expectedResult");
    expect(JSON.stringify(probe)).not.toContain("normalizedValue");
  });

  test("promotes the exact non-capability/closed builtin residual family into authored routes", () => {
    const outputKey = {
      surfaceId:
        "surface.builtin.node.internal.fs.utils.assert.encoding.0000018",
      output: "[[return]]",
      alias: "export:node_internal_fs_utils:assertEncoding",
      mode: "all",
      sourceKind: "builtin",
      returnVariant: "default",
      contextId: "javascript.package-call-loaded",
    };
    const sourceRef =
      "src/builtins/internal/fs/utils.js#exports:assertEncoding";
    const probe = buildOutputShapeSweepProbes({
      catalog: v2Catalog([
        {
          key: outputKey,
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [
              "builtin:export:node_internal_fs_utils:assertEncoding",
            ],
            sourceRefs: [sourceRef],
          },
        },
      ]),
      coverage: {
        edges: [
          {
            id: outputKey.surfaceId,
            classification: "closed",
            surface: {
              kind: "builtin",
              name: "export:node_internal_fs_utils:assertEncoding",
            },
          },
        ],
      },
      surfaces: [
        {
          kind: "builtin",
          name: "export:node_internal_fs_utils:assertEncoding",
          observedKey: "builtin:export:node_internal_fs_utils:assertEncoding",
          sourceRefs: [sourceRef],
          metadata: {
            sourceKey: "node_internal_fs_utils",
            exportName: "assertEncoding",
            exportIdioms: ["object-binding"],
            importReachability: "bootstrap-internal",
            publicModuleSpecifiers: [],
            surfaceType: "export",
            valueShape: "callable",
          },
        },
      ],
      target: { triple: "aarch64-apple-darwin" },
    })[0].probe;
    expect(probe).toMatchObject({
      kind: "loaded-engine-return-record",
      recordPath: ["[[return]]"],
      sourceDescriptor: {
        kind: "authored-builtin-noncap-closed-output",
        invocation: {
          kind: "builtin-noncap-closed-output",
          route: {
            operation: "unexercisable",
            reasonCode: "bootstrap-shadowed-manifest-export",
          },
        },
      },
    });
  });

  test("routes global accessors through actual Gets and proves closed target absence", () => {
    const definitions = [
      {
        id: "surface.native.global.request.url.0000008",
        name: "global:Request.url",
        globalName: "Request",
        memberName: "url",
        memberKinds: ["prototype-accessor"],
        classification: "non-capability",
        receiver: {
          kind: "construct-global",
          arguments: ["https://example.invalid/ibex"],
        },
      },
      {
        id: "surface.native.global.abort.controller.0000009",
        name: "global:AbortController",
        globalName: "AbortController",
        memberName: null,
        memberKinds: ["define-property"],
        classification: "non-capability",
        receiver: { kind: "global-root" },
      },
      {
        id: "surface.native.global.locale.tag.0000010",
        name: "global:Exact.locale.tag",
        globalName: "Exact",
        memberName: "locale.tag",
        memberKinds: ["object-accessor"],
        classification: "effects",
        receiver: {
          kind: "existing-global",
          receiverGlobalName: "Exact",
        },
      },
      {
        id: "surface.native.global.websocket.tag.0000011",
        name: "global:WebSocket.[[Symbol.toStringTag]]",
        globalName: "WebSocket",
        memberName: "[[Symbol.toStringTag]]",
        memberKinds: ["prototype-accessor"],
        classification: "non-capability",
        receiver: { kind: "global-prototype" },
      },
      {
        id: "surface.native.global.idb.cursor.key.0000012",
        name: "global:IDBCursor.key",
        globalName: "IDBCursor",
        memberName: "key",
        memberKinds: ["prototype-accessor"],
        classification: "closed",
      },
      {
        id: "surface.native.global.idb.request.state.0000013",
        name: "global:IDBRequest.readyState",
        globalName: "IDBRequest",
        memberName: "readyState",
        memberKinds: ["prototype-accessor"],
        classification: "non-capability",
        rootClosed: true,
      },
    ];
    const rows = definitions.map((definition) => ({
      key: {
        surfaceId: definition.id,
        output: "[[return]]",
        alias: definition.name,
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "default",
        contextId: "javascript.package-property-read-loaded",
      },
      discovery: {
        kind: "source-inventory-surface",
        observedKeys: [`native-op:${definition.name}`],
        sourceRefs: [`src/test.js#${definition.globalName}`],
      },
    }));
    const catalog = v2Catalog(rows);
    const coverage = {
      edges: [
        ...definitions.map((definition) => ({
          id: definition.id,
          classification: definition.classification,
          surface: { kind: "native-op", name: definition.name },
        })),
        {
          id: "surface.native.global.idb.request.root.0000014",
          classification: "closed",
          surface: { kind: "native-op", name: "global:IDBRequest" },
        },
      ],
    };
    const surfaces = definitions.map((definition) => ({
      kind: "native-op",
      name: definition.name,
      observedKey: `native-op:${definition.name}`,
      sourceRefs: [`src/test.js#${definition.globalName}`],
      metadata: {
        surfaceType: "global-api",
        valueShape: "accessor",
        globalName: definition.globalName,
        memberName: definition.memberName,
        memberKinds: definition.memberKinds,
      },
    }));
    const probes = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces,
    });
    expect(probes).toHaveLength(definitions.length);
    for (const definition of definitions) {
      const probe = probes.find(
        (row) => row.key.surfaceId === definition.id,
      ).probe;
      if (definition.classification === "closed" || definition.rootClosed) {
        expect(probe).toMatchObject({
          kind: "loaded-engine-descriptor",
          sourceDescriptor: {
            kind: "global-api",
            globalName: definition.globalName,
            memberName: definition.memberName,
            exercise: { kind: "read" },
          },
        });
        continue;
      }
      expect(probe).toMatchObject({
        kind: "loaded-engine-return-record",
        recordPath: ["[[return]]"],
        sourceDescriptor: {
          kind: "authored-global-accessor-get",
          surfaceObservedKey: `native-op:${definition.name}`,
          invocation: {
            invocationSchema: "ibex/capsec-global-accessor-get-invocation/1",
            kind: "global-accessor-get",
            coverageEdgeId: definition.id,
            coverageClassification: definition.classification,
            receiver: definition.receiver,
          },
        },
      });
    }
    const plan = buildOutputShapeSweepPlan({
      catalog,
      probes,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: digest("D"),
      engine: fixture().bindings.engine,
    });
    expect(JSON.stringify(plan)).not.toContain("expectedResult");
    expect(JSON.stringify(plan)).not.toContain("normalizedValue");
  });

  test("routes global callables through exact call recipes rather than descriptors", () => {
    const outputKey = {
      surfaceId: "surface.native.global.url.can.parse.0000012",
      output: "[[return]]",
      alias: "global:URL.canParse",
      mode: "all",
      sourceKind: "native-op",
      returnVariant: "default",
      contextId: "runtime.bootstrap-native-call-loaded",
    };
    const sourceRef = "src/engine/bootstrap/url.js#URL.canParse";
    const catalog = v2Catalog([
      {
        key: outputKey,
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: ["native-op:global:URL.canParse"],
          sourceRefs: [sourceRef],
        },
      },
    ]);
    const probes = buildOutputShapeSweepProbes({
      catalog,
      coverage: {
        edges: [
          {
            id: outputKey.surfaceId,
            classification: "non-capability",
            surface: { kind: "native-op", name: "global:URL.canParse" },
          },
        ],
      },
      surfaces: [
        {
          kind: "native-op",
          name: "global:URL.canParse",
          observedKey: "native-op:global:URL.canParse",
          sourceRefs: [sourceRef],
          metadata: {
            surfaceType: "global-api",
            valueShape: "callable",
            globalName: "URL",
            memberName: "canParse",
            memberKinds: ["static-method"],
          },
        },
      ],
    });
    expect(probes).toHaveLength(1);
    expect(probes[0].probe).toMatchObject({
      kind: "loaded-engine-return-record",
      recordPath: ["[[return]]"],
      sourceDescriptor: {
        kind: "authored-global-callable-invocation",
        surfaceObservedKey: "native-op:global:URL.canParse",
        invocation: {
          invocationSchema: "ibex/capsec-global-callable-invocation/1",
          kind: "global-callable-invocation",
          coverageEdgeId: outputKey.surfaceId,
          coverageClassification: "non-capability",
          route: {
            operation: "call",
            receiver: { kind: "source-member-owner" },
          },
        },
      },
    });
    expect(JSON.stringify(probes)).not.toContain("expectedResult");
    expect(JSON.stringify(probes)).not.toContain("normalizedValue");
  });

  test("keeps expected values out of the plan and promotes only after the join", () => {
    const value = fixture();
    expect(JSON.stringify(value.plan)).not.toContain("normalizedValue");
    expect(JSON.stringify(value.plan)).not.toContain("disposition");
    expect(value.plan.executor).toBe(OUTPUT_SHAPE_SWEEP_EXECUTOR);
    expect(
      validateOutputShapeSweepPlan(value.plan, {
        catalog: value.catalog,
        ...value.bindings,
      }),
    ).toBe(value.plan);
    expect(validateOutputShapeSweepArtifact(value.artifact, value.plan)).toBe(
      value.artifact,
    );

    const evidence = buildVerifiedOutputDispositionEvidence({
      catalog: value.catalog,
      dispositionRows: value.dispositionRows,
      plan: value.plan,
      artifact: value.artifact,
      ...value.bindings,
    });
    expect(evidence.status).toBe("verified");
    expect(evidence.sourceRevision).toBe(value.bindings.sourceRevision);
    expect(evidence.engineBinaryDigest).toBe(
      value.bindings.engine.binaryDigest,
    );
    expect(evidence.observations).toHaveLength(keys.length);
    expect(
      evidence.observations.every(
        (observation) =>
          observation.proofKind === "loaded-engine-descriptor" ||
          observation.proofKind === "loaded-engine-return-record",
      ),
    ).toBe(true);
  });

  test("requires one independently-authored probe for every catalog row", () => {
    const value = fixture();
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes: value.probes.slice(1),
        ...value.bindings,
      }),
    ).toThrow(/not bidirectional.*missing=/);
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes: [...value.probes, structuredClone(value.probes[0])],
        ...value.bindings,
      }),
    ).toThrow(/duplicate canonical output key/);

    const echo = structuredClone(value.probes);
    echo[0].probe.expectation = {
      outcome: "return",
      normalizedValue: "non-path",
    };
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes: echo,
        ...value.bindings,
      }),
    ).toThrow(/must not carry reviewed expected values/);

    const staleDescriptor = structuredClone(value.probes);
    staleDescriptor[1].probe.sourceDescriptor.exportPath = ["join"];
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes: staleDescriptor,
        ...value.bindings,
      }),
    ).toThrow(/source descriptor digest does not match route/);

    const downgraded = structuredClone(value.probes);
    downgraded[2].probe = {
      kind: "compiled-registrar",
      registrarId: keys[2].surfaceId,
    };
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes: downgraded,
        ...value.bindings,
      }),
    ).toThrow(/compiled registrar presence cannot satisfy a value observation/);
  });

  test("rejects stale source and loaded-engine bindings", () => {
    const value = fixture();
    const stalePlan = structuredClone(value.plan);
    stalePlan.sourceRevision = "b".repeat(40);
    expect(() =>
      validateOutputShapeSweepPlan(stalePlan, {
        catalog: value.catalog,
        ...value.bindings,
      }),
    ).toThrow(/stale or mismatched bindings/);

    const wrongEngine = structuredClone(value.artifact);
    wrongEngine.loadedEngineIdentity.binaryDigest = digest("Z");
    expect(() =>
      validateOutputShapeSweepArtifact(wrongEngine, value.plan),
    ).toThrow(/stale or mismatched bindings/);

    const v1Plan = structuredClone(value.plan);
    v1Plan.outputShapeSweepPlanSchema = "ibex/capsec-output-shape-sweep-plan/1";
    v1Plan.executor = "ibex-public-surface-harness/output-shape-sweep-v1";
    expect(() =>
      validateOutputShapeSweepPlan(v1Plan, {
        catalog: value.catalog,
        ...value.bindings,
      }),
    ).toThrow(/stale or mismatched bindings/);

    const v1Batch = executorBatch(value);
    v1Batch.outputShapeExecutorBatchSchema =
      "ibex/capsec-output-shape-executor-batch/1";
    v1Batch.executor = "ibex-public-surface-harness/output-shape-sweep-v1";
    expect(() =>
      buildOutputShapeSweepArtifactFromExecutorBatch({
        plan: value.plan,
        batch: v1Batch,
      }),
    ).toThrow(/stale or mismatched bindings/);

    const v1Artifact = structuredClone(value.artifact);
    v1Artifact.outputShapeSweepArtifactSchema =
      "ibex/capsec-output-shape-sweep-artifact/1";
    v1Artifact.executor = "ibex-public-surface-harness/output-shape-sweep-v1";
    expect(() =>
      validateOutputShapeSweepArtifact(v1Artifact, value.plan),
    ).toThrow(/stale or mismatched bindings/);
  });

  test("joins compiled registrar IDs to every catalog surface account bidirectionally", () => {
    const value = fixture();
    expect(value.plan.surfaceAccountIds).toContain(structuralSurfaceId);
    expect(
      value.plan.rows.some((row) => row.key.surfaceId === structuralSurfaceId),
    ).toBe(false);
    const missing = structuredClone(value.artifact);
    missing.compiledRegistrarIds.pop();
    expect(() =>
      validateOutputShapeSweepArtifact(reseal(missing), value.plan),
    ).toThrow(/registrar IDs do not join.*bidirectionally/);

    const unknown = structuredClone(value.artifact);
    unknown.compiledRegistrarIds.push("surface.unknown.extra.0000004");
    unknown.compiledRegistrarIds.sort();
    expect(() =>
      validateOutputShapeSweepArtifact(reseal(unknown), value.plan),
    ).toThrow(/registrar IDs do not join.*bidirectionally/);
  });

  test("requires exact proof mechanisms and exact observation coverage", () => {
    const value = fixture();
    const wrongProof = structuredClone(value.artifact);
    wrongProof.observations.find(
      (row) => row.proof.kind === "loaded-engine-descriptor",
    ).proof.sourceDescriptorDigest = digest("X");
    expect(() =>
      validateOutputShapeSweepArtifact(reseal(wrongProof), value.plan),
    ).toThrow(/descriptor proof selected another source route/);

    const missing = structuredClone(value.artifact);
    missing.observations.pop();
    expect(() =>
      validateOutputShapeSweepArtifact(reseal(missing), value.plan),
    ).toThrow(/observations is not bidirectional.*missing=/);

    const duplicate = structuredClone(value.artifact);
    duplicate.observations.push(structuredClone(duplicate.observations[0]));
    expect(() =>
      validateOutputShapeSweepArtifact(reseal(duplicate), value.plan),
    ).toThrow(/duplicate canonical output key/);
  });

  test("refuses promotion when an actual normalized value disagrees with policy", () => {
    const value = fixture();
    const mismatch = structuredClone(value.artifact);
    mismatch.observations.find(
      (row) => row.proof.kind === "loaded-engine-descriptor",
    ).observation.normalizedValue = "virtual-relative";
    const artifact = reseal(mismatch);
    expect(() =>
      buildVerifiedOutputDispositionEvidence({
        catalog: value.catalog,
        dispositionRows: value.dispositionRows,
        plan: value.plan,
        artifact,
        ...value.bindings,
      }),
    ).toThrow(/loaded-engine output value mismatch/);
  });

  test("normalizes executor-owned raw values before the independent policy join", () => {
    const value = fixture();
    const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
      plan: value.plan,
      batch: executorBatch(value),
    });
    expect(artifact.observations.map((row) => row.observation)).toEqual(
      value.observations.map((row) => row.observation),
    );
    expect(
      buildVerifiedOutputDispositionEvidence({
        catalog: value.catalog,
        dispositionRows: value.dispositionRows,
        plan: value.plan,
        artifact,
        ...value.bindings,
      }).status,
    ).toBe("verified");
  });

  test("retains an observed path field from a thrown structured record", () => {
    const value = fixture();
    const batch = executorBatch(value);
    const result = batch.results.find(
      (row) => row.proof.kind === "loaded-engine-return-record",
    );
    result.proof.rawValueShape = "string";
    result.raw = {
      kind: "throw",
      rawValueShape: "string",
      value: "/project/missing-output-shape.js",
      errorCode: "ENOENT",
    };
    const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
      plan: value.plan,
      batch,
    });
    expect(
      artifact.observations.find(
        (row) => row.proof.kind === "loaded-engine-return-record",
      ).observation,
    ).toEqual({ outcome: "throw", normalizedValue: "virtual-absolute" });
  });

  test("retains a named source-admission refusal from an unprojected throw", () => {
    const value = fixture();
    const batch = executorBatch(value);
    const result = batch.results.find(
      (row) => row.proof.kind === "loaded-engine-return-record",
    );
    result.proof.rawValueShape = "throw";
    result.raw = {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode: "IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED",
    };
    const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
      plan: value.plan,
      batch,
    });
    expect(
      artifact.observations.find(
        (row) => row.proof.kind === "loaded-engine-return-record",
      ).observation,
    ).toEqual({
      outcome: "throw",
      normalizedValue: "IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED",
    });
  });

  test("normalizes actual throw metadata without inventing an error code", () => {
    for (const { errorCode, errorName, normalizedValue } of [
      {
        errorCode: "ERR_ACTUAL_SOURCE_CODE",
        errorName: "TypeError",
        normalizedValue: "ERR_ACTUAL_SOURCE_CODE",
      },
      {
        errorCode: null,
        errorName: "TypeError",
        normalizedValue: "error-name:TypeError",
      },
      {
        errorCode: null,
        errorName: undefined,
        normalizedValue: "throw-without-code",
      },
    ]) {
      const value = fixture();
      const batch = executorBatch(value);
      const result = batch.results.find(
        (row) => row.proof.kind === "loaded-engine-return-record",
      );
      result.proof.rawValueShape = "throw";
      result.raw = {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode,
        ...(errorName === undefined ? {} : { errorName }),
      };
      const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
        plan: value.plan,
        batch,
      });
      expect(
        artifact.observations.find(
          (row) => row.proof.kind === "loaded-engine-return-record",
        ).observation,
      ).toEqual({ outcome: "throw", normalizedValue });
    }
  });

  test("fails closed on unexercisable rows and raw return-record mismatches", () => {
    const value = fixture();
    const unsupported = executorBatch(value);
    unsupported.unexercisable.push({
      key: structuredClone(keys[2]),
      reason: "fixture did not reach the loaded-engine return record",
    });
    expect(() =>
      buildOutputShapeSweepArtifactFromExecutorBatch({
        plan: value.plan,
        batch: unsupported,
      }),
    ).toThrow(/could not honestly exercise 1 rows/);

    const mismatched = executorBatch(value);
    mismatched.results.find(
      (row) => row.proof.kind === "loaded-engine-return-record",
    ).raw = {
      kind: "return",
      rawValueShape: "string",
      value: "/project/output-shape.js",
      errorCode: null,
    };
    expect(() =>
      buildOutputShapeSweepArtifactFromExecutorBatch({
        plan: value.plan,
        batch: mismatched,
      }),
    ).toThrow(/return-record proof disagrees with raw value shape/);
  });

  test("never plans a value observation from compiled registration", () => {
    const value = fixture();
    const probes = structuredClone(value.probes);
    probes[0].probe = {
      kind: "compiled-registrar",
      registrarId: keys[0].surfaceId,
    };
    expect(() =>
      buildOutputShapeSweepPlan({
        catalog: value.catalog,
        probes,
        ...value.bindings,
      }),
    ).toThrow(/compiled registrar presence cannot satisfy a value observation/);
  });

  test("accepts a compiled product-ingress return only with its authored proof", () => {
    const outputKey = key(
      "surface.cli.authenticated.one.shot.ingress.0000001",
      "[[return]]",
      "cli",
    );
    outputKey.alias = "authenticated-one-shot-ingress";
    const row = {
      key: structuredClone(outputKey),
      discovery: {
        kind: "source-inventory-surface",
        observedKeys: ["cli:authenticated-one-shot-ingress"],
        sourceRefs: ["src/bin/ibex/main.rs#eval_code"],
      },
    };
    const catalog = v2Catalog([row]);
    const coverage = {
      edges: [
        {
          id: outputKey.surfaceId,
          classification: "non-capability",
          surface: {
            kind: "cli",
            name: "authenticated-one-shot-ingress",
          },
        },
      ],
    };
    const surfaces = [
      {
        kind: "cli",
        name: "authenticated-one-shot-ingress",
        observedKey: "cli:authenticated-one-shot-ingress",
        sourceRefs: ["src/bin/ibex/main.rs#eval_code"],
      },
    ];
    const probes = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces,
    });
    expect(probes[0].probe).toMatchObject({
      kind: "compiled-runtime-return-record",
      sourceDescriptor: {
        invocation: {
          operation: { kind: "product-ingress-route-read" },
        },
      },
    });
    const bindings = fixture().bindings;
    const plan = buildOutputShapeSweepPlan({ catalog, probes, ...bindings });
    const raw = {
      kind: "return",
      rawValueShape: "object",
      value: {
        entryKind: "Eval",
        mode: "OneShot",
        owner: "inline-one-shot",
        stdinIsTty: false,
      },
      errorCode: null,
    };
    const probe = plan.rows[0].probe;
    const batch = {
      outputShapeExecutorBatchSchema:
        "ibex/capsec-output-shape-executor-batch/2",
      profile: "ibex/capsec/1",
      executor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
      sourceRevision: plan.sourceRevision,
      sourceTreeDigest: plan.sourceTreeDigest,
      catalogKeyDigest: plan.catalogKeyDigest,
      sweepPlanDigest: plan.sweepPlanDigest,
      loadedEngineIdentity: structuredClone(bindings.engine),
      compiledRegistrarIds: [outputKey.surfaceId],
      results: [
        {
          key: structuredClone(outputKey),
          proof: {
            kind: "compiled-runtime-return-record",
            fixtureId: probe.fixtureId,
            sourceDescriptorDigest: probe.sourceDescriptorDigest,
            recordPath: ["[[return]]"],
            rawValueShape: "object",
          },
          raw,
        },
      ],
      unexercisable: [],
    };
    const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
      plan,
      batch,
    });
    expect(artifact.observations[0].observation).toEqual({
      outcome: "return",
      normalizedValue: "non-path",
    });
  });

  test("selects compiled-runtime evidence only for the exact direct-file adapter", () => {
    const outputKey = key(
      "surface.cli.authenticated.direct.file.ingress.1f71u9t",
      "[[return]]",
      "cli",
    );
    outputKey.alias = "authenticated-direct-file-ingress";
    const exactSourceRef =
      "src/bin/ibex/main.rs#run_file_with_execution_adapter";
    const catalog = v2Catalog([
      {
        key: structuredClone(outputKey),
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: ["cli:authenticated-direct-file-ingress"],
          sourceRefs: [exactSourceRef],
        },
      },
    ]);
    const coverage = {
      edges: [
        {
          id: outputKey.surfaceId,
          classification: "non-capability",
          surface: {
            kind: "cli",
            name: "authenticated-direct-file-ingress",
          },
        },
      ],
    };
    const directSurface = {
      kind: "cli",
      name: "authenticated-direct-file-ingress",
      observedKey: "cli:authenticated-direct-file-ingress",
      sourceRefs: [exactSourceRef],
    };

    const [directProbe] = buildOutputShapeSweepProbes({
      catalog,
      coverage,
      surfaces: [directSurface],
    });
    expect(directProbe.probe).toMatchObject({
      kind: "compiled-runtime-return-record",
      sourceDescriptor: {
        kind: "authored-cli-output",
        invocation: {
          operation: { kind: "product-ingress-route-read" },
          sourceDescriptor: { sourceRefs: [exactSourceRef] },
        },
      },
    });
    expect(directProbe.probe.sourceDescriptorDigest).toBe(
      outputShapeSourceDescriptorDigest(directProbe.probe.sourceDescriptor),
    );

    expect(() =>
      buildOutputShapeSweepProbes({
        catalog,
        coverage,
        surfaces: [
          {
            ...directSurface,
            sourceRefs: ["src/bin/ibex/main.rs#run_file"],
          },
        ],
      }),
    ).toThrow(/retained value row has no live proof route/);
  });

  test("rejects a live function descriptor when no invocation fixture ran", () => {
    const value = fixture();
    const probes = structuredClone(value.probes);
    const route = probes.find((row) => row.key.surfaceId === keys[0].surfaceId);
    route.probe.sourceDescriptor = {
      ...route.probe.sourceDescriptor,
      exercise: { kind: "descriptor" },
      valueShape: "unknown",
    };
    route.probe.sourceDescriptorDigest = outputShapeSourceDescriptorDigest(
      route.probe.sourceDescriptor,
    );
    const plan = buildOutputShapeSweepPlan({
      catalog: value.catalog,
      probes,
      ...value.bindings,
    });
    const batch = executorBatch(value);
    batch.sweepPlanDigest = plan.sweepPlanDigest;
    batch.results.find(
      (row) => row.key.surfaceId === keys[0].surfaceId,
    ).proof.sourceDescriptorDigest = route.probe.sourceDescriptorDigest;
    batch.results.find(
      (row) => row.key.surfaceId === keys[0].surfaceId,
    ).proof.descriptor.valueType = "function";
    expect(() =>
      buildOutputShapeSweepArtifactFromExecutorBatch({ plan, batch }),
    ).toThrow(/substituted property shape for an uninvoked output/);
  });
});
