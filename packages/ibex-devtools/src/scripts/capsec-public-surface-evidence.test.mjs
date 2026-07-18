import crypto from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  assertPublicSurfaceExecutionComplete,
  buildPublicFixtureEvidence,
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
  validatePublicSurfaceExecutionArtifact,
} from "./capsec-public-surface-evidence.mjs";
import {
  computeRecipeCatalogDigest,
  assertRecipeCatalogComplete,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const target = {
  triple: "aarch64-apple-darwin",
  features: ["frame-attribution", "native-lockdown"],
};
const engine = {
  kind: "hermes",
  engineArtifactPath: "/tmp/hermesvm",
  binaryDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  object: { platform: "apple", volume: "dev:1", file: "ino:2" },
  targetArchitecture: "aarch64",
  structuralFeatures: [...target.features],
};
const coverage = {
  edges: [
    {
      id: "edge.terminal",
      surface: { kind: "native-op", name: "__exactPublic" },
    },
    {
      id: "edge.mkdir-worker",
      surface: { kind: "native-op", name: "__exactMkdir" },
    },
    {
      id: "edge.callback-terminal",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactGetEnv" },
      effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
    },
    {
      id: "edge.startup-env-node-debug",
      classification: "effects",
      effectMode: "conditional",
      surface: { kind: "startup", name: "env:NODE_DEBUG" },
      logicalBranches: [
        {
          id: "absent",
          when: [
            {
              fact: "environment.startup.node_debug",
              equals: "absent",
            },
          ],
          effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
        },
        {
          id: "present",
          when: [
            {
              fact: "environment.startup.node_debug",
              equals: "present",
            },
          ],
          effects: [
            { cap: "env:read", stages: ["requested", "commit"] },
            {
              cap: "stdio:write",
              stages: ["requested", "commit", "repeat"],
            },
          ],
        },
      ],
    },
    {
      id: "edge.host-sqlite",
      classification: "effects",
      surface: { kind: "host-abi", name: "ex_host_sqlite_open" },
      logicalBranches: [
        {
          id: "memory",
          when: [{ fact: "sqlite.open.mode", equals: "memory" }],
          effects: [],
        },
      ],
    },
    {
      id: "edge.startup",
      classification: "non-capability",
      surface: { kind: "startup", name: "lockdown-install" },
    },
    {
      id: "edge.exact-closed",
      classification: "closed",
      surface: { kind: "native-op", name: "global:exact.invokeHostAsync" },
    },
    {
      id: "edge.module-runner-namespace-closed",
      classification: "closed",
      surface: {
        kind: "host-abi",
        name: "ex_hermes_module_record_namespace_json",
      },
    },
  ],
};

function completeCatalog() {
  const recipe = {
    fixtureId: "fixture.public.allow",
    planDigest: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    classification: "effects",
    scenario: "allow",
    edgeIds: ["edge.public"],
    implementationBranchIds: ["edge.public.main"],
    enforcementBranchIds: ["enforcement.public"],
    actionIds: ["sys:read"],
    terminalObservedKey: "native-op:__exactPublic",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "enforcement.public",
    },
    route: {
      surfaceObservedKeys: ["builtin:export:node_test:read"],
      alternatives: [
        {
          terminalObservedKey: "native-op:__exactPublic",
          proofPaths: ["export:read -> __exactPublic"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_test:read",
      command: ["ibex", "capsec-public-fixture", "fixture.public.allow"],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:test",
        exportName: "read",
        sourceDescriptor: {
          kind: "builtin-export",
          sourceKey: "node_test",
          exportName: "read",
          moduleSpecifiers: ["node:test"],
          sourceRef: "src/builtins/test.js#exports:read",
        },
        arguments: [],
        expectedResult: "return",
        expectedTypedStages: ["requested"],
        expectedTypedDecisionCount: 1,
        allowedCoverageEdgeIds: ["edge.terminal", "edge.unselected"],
        expectedActionIds: ["sys:read"],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const descriptor = recipe.publicSurfaceProbe.invocation.sourceDescriptor;
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
    taggedDigest(descriptor);
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { allow: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function runtimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "return", valueType: "string" },
    },
    legacyObservationCount: 0,
    typedDecisions: [
      {
        decisionSet: {
          decisionSetSchema: "ibex/capsec-decision-set/1",
          operationId: "fixture-public",
          atomicityGroup: "edge.terminal.decision",
          combination: "conjunction",
          context: {
            stage: "requested",
            actor: { kind: "root", identity: "project-root" },
            constrainedPrincipals: [{ kind: "root", identity: "project-root" }],
            presentedHandleIds: [],
          },
          effects: [
            {
              cap: "sys:read",
              effectOwner: { kind: "root", identity: "project-root" },
              resource: {
                kind: "system-info-occurrence",
                requested: { kind: "system-info", name: "platform" },
              },
            },
          ],
        },
        gates: [
          {
            coverageEdgeId: "edge.terminal",
            targetCell: "complete",
            definitionAndEdgePredicatesSatisfied: true,
          },
        ],
        evidence: { outcome: "allow" },
      },
    ],
  };
}

function completeArtifact(catalog = completeCatalog()) {
  return buildPublicSurfaceExecutionArtifact({
    recipeCatalog: catalog,
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    target,
    engine,
    coverage,
    executions: [
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: runtimeObservation(catalog.recipes[0]),
        coverage,
      }),
    ],
  });
}

function completeNoncapBuiltinCallCatalog() {
  const surfaceObservedKey = "builtin:export:node_path:basename";
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_path",
    exportName: "basename",
    exportIdioms: ["object-binding", "object-source"],
    moduleSpecifiers: ["node:path", "path"],
    sourceRef: "src/builtins/path.js#exports:basename",
    valueShape: "callable",
    access: { kind: "export-property", path: ["basename"] },
  };
  const recipe = {
    fixtureId: "fixture.noncap-builtin.basename",
    planDigest: "sha256-NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.noncap-builtin"],
    implementationBranchIds: ["edge.noncap-builtin.main"],
    enforcementBranchIds: ["edge.noncap-builtin.main"],
    actionIds: [],
    terminalObservedKey: surfaceObservedKey,
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.noncap-builtin.main",
    },
    route: {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_noncap_builtin_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-call-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:path",
        exportName: "basename",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        templateId: "node-path-pure-v1",
        arguments: [{ kind: "json", value: "/ibex/file.txt" }],
        setup: { kind: "root-call" },
        bodyEntryProof: {
          kind: "normal-return-from-source-call",
          resultType: "string",
        },
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        requiredAuthority: [],
        expectedResult: "normal-return",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { "non-capability": 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function noncapBuiltinCallObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "return",
        moduleSpecifier: invocation.moduleSpecifier,
        exportName: invocation.exportName,
        valueType: invocation.bodyEntryProof.resultType,
        dispatchKind: "call",
        bodyEntryProof: invocation.bodyEntryProof.kind,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeNoncapBuiltinAbsenceCatalog() {
  const catalog = completeNoncapBuiltinCallCatalog();
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "builtin:export:node_constants:EDQUOT";
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_constants",
    exportName: "EDQUOT",
    exportIdioms: ["object-binding", "object-source", "table-copy"],
    moduleSpecifiers: ["constants", "node:constants"],
    sourceRef: "src/builtins/constants.js#exports:EDQUOT",
    valueShape: "data",
    platformAvailability: ["android", "linux"],
    access: { kind: "export-property", path: ["EDQUOT"] },
  };
  recipe.fixtureId = "fixture.noncap-builtin.target-absent";
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  recipe.route.alternatives = [
    { terminalObservedKey: surfaceObservedKey, proofPaths: [surfaceObservedKey] },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  recipe.publicSurfaceProbe.invocation = {
    invocationSchema: "ibex/capsec-builtin-export-invocation/1",
    kind: "builtin-export-read",
    moduleSpecifier: "node:constants",
    exportName: "EDQUOT",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    arguments: [],
    setup: { kind: "none" },
    completion: {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
    },
    requiredAuthority: [],
    expectedResult: "absent",
    expectedTypedDecisionCount: 0,
    expectedTypedStages: [],
    allowedCoverageEdgeIds: [],
    expectedActionIds: [],
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function noncapBuiltinAbsenceObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "missing",
        moduleSpecifier: invocation.moduleSpecifier,
        exportName: invocation.exportName,
        segment: invocation.exportName,
        available: ["EACCES", "ENOENT"],
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeAbsenceCatalog() {
  const sourceDescriptor = {
    kind: "target-absent-host-abi",
    surfaceKind: "host-abi",
    surfaceName: "ex_android_initialize",
    sourceRefs: [
      "src/engine/native_android_networking.cc#ex_android_initialize",
    ],
    targetVariants: ["android"],
    sourceMetadata: {
      definitions: [
        {
          language: "c++",
          sourceRef:
            "src/engine/native_android_networking.cc#ex_android_initialize",
          targetVariant: "android",
          unsafe: false,
          weak: false,
        },
      ],
    },
    probeMode: { kind: "dynamic-symbol", symbolName: "ex_android_initialize" },
  };
  const recipe = {
    fixtureId: "fixture.host-abi.absent",
    planDigest: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    classification: "non-capability",
    scenario: "absent",
    edgeIds: ["edge.absent"],
    implementationBranchIds: [],
    enforcementBranchIds: [],
    actionIds: [],
    terminalObservedKey: "host-abi:ex_android_initialize",
    expectedObservation: { kind: "target-absence", edgeId: "edge.absent" },
    route: { surfaceObservedKeys: [], alternatives: [], ambiguousCallees: [] },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "target-absence-probe",
      surfaceObservedKey: "host-abi:ex_android_initialize",
      command: ["ibex", "capsec-public-target-absence"],
      invocation: {
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        kind: "target-absence",
        surfaceKind: "host-abi",
        surfaceName: "ex_android_initialize",
        targetTriple: target.triple,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { absent: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function absenceRuntimeObservation(recipe, symbolPresent = false) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const probeMode = invocation.sourceDescriptor.probeMode;
  const result = {
    kind: "absent",
    surfaceKind: invocation.surfaceKind,
    surfaceName: invocation.surfaceName,
    targetTriple: invocation.targetTriple,
    compiledTargetOs: "macos",
    compiledTargetArch: "aarch64",
    probeMode: probeMode.kind,
    ...(probeMode.kind === "runtime-global-property"
      ? {
          globalName: probeMode.globalName,
          memberName: probeMode.memberName,
          surfacePresent: symbolPresent,
        }
      : {
          symbolName: probeMode.symbolName,
          symbolPresent,
        }),
  };
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      targetTriple: invocation.targetTriple,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result,
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeNativeAbsenceCatalog() {
  const catalog = structuredClone(completeAbsenceCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "target-absent-native-operation",
    surfaceKind: "native-op",
    surfaceName: "__exactAndroidLocation.getPermissionStatus",
    sourceRefs: [
      "src/engine/hermes_runtime_android.cc#jsi-global:__exactAndroidLocation.getPermissionStatus",
    ],
    targetVariants: ["android"],
    sourceMetadata: {
      installationBranches: [
        {
          sourceRefs: [
            "src/engine/hermes_runtime_android.cc#jsi-global:__exactAndroidLocation.getPermissionStatus",
          ],
          targetVariant: "android",
        },
      ],
    },
    probeMode: {
      kind: "runtime-global-property",
      globalName: "__exactAndroidLocation",
      memberName: "getPermissionStatus",
    },
  };
  recipe.fixtureId = "fixture.native-op.absent";
  recipe.terminalObservedKey =
    "native-op:__exactAndroidLocation.getPermissionStatus";
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "__exactAndroidLocation.getPermissionStatus",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedCatalog() {
  const sourceDescriptor = {
    kind: "closed-startup-environment",
    environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
    sourceRefs: [
      "src/engine/hermes_bootstrap.cc#env_flag_enabled:EX_SKIP_STARTUP_MODULE_LOADER:read",
    ],
    sourceMetadata: {
      evidenceType: "static-runtime-environment-control",
      authoredNames: ["EX_SKIP_STARTUP_MODULE_LOADER"],
    },
  };
  const recipe = {
    fixtureId: "fixture.startup.closed",
    planDigest: "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    classification: "closed",
    scenario: "closed",
    edgeIds: ["edge.closed"],
    implementationBranchIds: ["edge.closed.main"],
    enforcementBranchIds: ["edge.closed.main"],
    actionIds: [],
    terminalObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.closed.main",
    },
    route: {
      surfaceObservedKeys: ["startup:env:EX_SKIP_STARTUP_MODULE_LOADER"],
      alternatives: [
        {
          terminalObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
          proofPaths: ["startup:env:EX_SKIP_STARTUP_MODULE_LOADER"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
      command: ["ibex", "capsec-public-closed"],
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceKind: "startup",
        surfaceName: "env:EX_SKIP_STARTUP_MODULE_LOADER",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: {
          kind: "startup-environment",
          environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
        },
        expectedResult: "closed",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { closed: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedCliCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-cli-control",
    surfaceObservedKey: "cli:option-name:ibex:inspect:--inspect",
    sourceRefs: [
      "runtime-surface.json#clapSurface.command:ibex:option:inspect",
    ],
    sourceMetadata: {
      evidenceType: "cli-option-name",
      name: "--inspect",
      routeKind: "primary",
    },
    controlDescriptor: {
      kind: "clap-option",
      commandPath: "ibex",
      argumentId: "inspect",
      optionSpellings: ["--inspect"],
    },
  };
  recipe.fixtureId = "fixture.cli.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "cli",
    surfaceName: "option-name:ibex:inspect:--inspect",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "cli-control",
      argumentVectors: [
        {
          spelling: "--inspect",
          args: ["--inspect", "{ibex-capsec-closed-project-code}"],
        },
      ],
      expectedRejectionFragments: [
        "closes compatibility, inspector",
        "runtime-fidelity overrides",
      ],
      projectCodePlaceholder: "{ibex-capsec-closed-project-code}",
      evaluationMarker:
        "globalThis.__IBEX_CAPSEC_CLOSED_CLI_EVALUATED__ = true",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedLoaderCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-loader-executable-kind",
    loaderKind: "native-addon",
    extension: ".node",
    sourceRefs: ["src/module_loader/mod.rs#resolve_with_oxc"],
    sourceMetadata: null,
  };
  recipe.fixtureId = "fixture.loader.native-addon.closed";
  recipe.terminalObservedKey = "loader:native-addon-module";
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "loader",
    surfaceName: "native-addon-module",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "loader-executable-file",
      loaderKind: "native-addon",
      extension: ".node",
      rejectionFragment: "Native addons are closed",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedTerminalBuiltinCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-terminal-builtin",
    surfaceObservedKey: "builtin:export:node_vm:runInNewContext",
    sourceKey: "node_vm",
    exportName: "runInNewContext",
    moduleSpecifiers: ["node:vm", "vm"],
    sourceRefs: ["src/builtins/vm.js#exports:runInNewContext"],
    sourceMetadata: {
      surfaceType: "export",
      sourceKey: "node_vm",
      exportName: "runInNewContext",
      importReachability: "public",
      publicModuleSpecifiers: ["node:vm", "vm"],
    },
  };
  recipe.fixtureId = "fixture.builtin.vm.run-in-new-context.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "builtin",
    surfaceName: "export:node_vm:runInNewContext",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "terminal-builtin-import",
      terminalBuiltinRoot: "vm",
      moduleSpecifiers: ["node:vm", "vm"],
      expectedRejectionFragment: "Import denied:",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedDebuggerAbiCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const functionName = "ex_hermes_debugger_eval";
  const defaultSourceRef =
    `src/engine/hermes_runtime_debugger.cc#${functionName}`;
  const windowsSourceRef =
    `src/engine/hermes_runtime_platform_windows.cc#${functionName}`;
  const sourceDescriptor = {
    kind: "closed-debugger-abi",
    surfaceObservedKey: `host-abi:${functionName}`,
    functionName,
    selectedSourceRef: defaultSourceRef,
    targetTriple: "aarch64-apple-darwin",
    sourceRefs: [defaultSourceRef, windowsSourceRef],
    sourceMetadata: {
      alternatives: [
        {
          id: "default",
          kind: "alternative",
          sourceRefs: [defaultSourceRef],
          stubDisposition: "not-structurally-proven",
          targetVariant: "default",
        },
        {
          id: "windows",
          kind: "alternative",
          sourceRefs: [windowsSourceRef],
          stubDisposition: "not-structurally-proven",
          targetVariant: "windows",
        },
      ],
      branches: [
        {
          id: "default",
          kind: "alternative",
          sourceRefs: [defaultSourceRef],
          stubDisposition: "not-structurally-proven",
          targetVariant: "default",
        },
        {
          id: "windows",
          kind: "alternative",
          sourceRefs: [windowsSourceRef],
          stubDisposition: "not-structurally-proven",
          targetVariant: "windows",
        },
      ],
      definitions: [
        {
          language: "c++",
          sourceRef: defaultSourceRef,
          targetVariant: "default",
          unsafe: false,
          weak: false,
        },
        {
          language: "c++",
          sourceRef: windowsSourceRef,
          targetVariant: "windows",
          unsafe: false,
          weak: false,
        },
      ],
      provenanceLimitation:
        "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures.",
    },
  };
  recipe.fixtureId = "fixture.debugger.eval.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "host-abi",
    surfaceName: functionName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "debugger-abi-disabled",
      functionName,
      expectedCallResult: "null-pointer",
      expectedError:
        `debugger ABI ${functionName} is unavailable in the no-debugger exact target`,
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedSharedRuntimeGlobalCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceRef =
    "src/engine/bootstrap/module-loader.js#CacheStorage.open";
  const sourceDescriptor = {
    kind: "closed-shared-runtime-global-absence",
    surfaceObservedKey: "native-op:global:CacheStorage.open",
    globalName: "CacheStorage",
    memberName: "open",
    targetTriple: "aarch64-apple-darwin",
    sourceRefs: [sourceRef],
    sourceMetadata: {
      branches: [
        {
          branchKind: "single",
          id: "default",
          kind: "single",
          route: "legacy-bootstrap",
          routes: ["legacy-bootstrap"],
          sourceRefs: [sourceRef],
          targetVariant: "default",
        },
      ],
      exportName: "CacheStorage.open",
      globalName: "CacheStorage",
      installationBranches: [
        {
          branchKind: "single",
          id: "default",
          kind: "single",
          route: "legacy-bootstrap",
          routes: ["legacy-bootstrap"],
          sourceRefs: [sourceRef],
          targetVariant: "default",
        },
      ],
      memberName: "open",
      moduleSpecifiers: [],
      sourceKey: "global_module_loader",
      surfaceType: "global-api",
    },
  };
  recipe.fixtureId = "fixture.shared-runtime.cache-storage-open.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "global:CacheStorage.open",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "shared-runtime-global-absence",
      globalName: "CacheStorage",
      memberName: "open",
      expectedError:
        "armed shared runtime does not expose CacheStorage.open",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedArmedNativeGlobalCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceRefs = [
    "src/engine/hermes_runtime.cc#__exactExit",
    "src/engine/hermes_runtime.cc#jsi-global:__exactExit",
  ];
  const sourceDescriptor = {
    kind: "closed-armed-native-global-absence",
    surfaceObservedKey: "native-op:__exactExit",
    globalName: "__exactExit",
    targetTriple: "aarch64-apple-darwin",
    sourceRefs,
    sourceMetadata: {
      exportName: "__exactExit",
      globalName: "__exactExit",
      installationBranches: [
        {
          route: "native-jsi-global",
          sourceRefs,
          targetVariant: "default",
        },
      ],
      memberKinds: ["native-root"],
      memberName: null,
      publicInvocation: {
        arity: 1,
        globalName: "__exactExit",
        kind: "native-global-function",
        sourceRef: sourceRefs[1],
      },
      sourceKey: "native_jsi_global",
      surfaceType: "global-api",
    },
  };
  recipe.fixtureId = "fixture.armed-native.exact-exit.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "__exactExit",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "armed-native-global-absence",
      globalName: "__exactExit",
      expectedError: "armed runtime does not expose __exactExit",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedExactCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-exact-unendowed-operation",
    surfaceObservedKey: "native-op:global:exact.invokeHostAsync",
    globalName: "exact",
    memberName: "invokeHostAsync",
    sourceRefs: [
      "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
    ],
    sourceMetadata: {
      surfaceType: "global-api",
      sourceKey: "native_jsi_global",
      globalName: "exact",
      memberName: "invokeHostAsync",
      memberKinds: ["native-object-member"],
      exportName: "exact.invokeHostAsync",
    },
  };
  recipe.fixtureId = "fixture.exact.invoke-host-async.closed";
  recipe.edgeIds = ["edge.exact-closed"];
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "global:exact.invokeHostAsync",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "exact-unendowed-operation",
      contextKind: "app",
      operationManifestDigest:
        "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA",
      endowedOperationIds: [7, 11],
      selectedOperationId: 8,
      expectedError: "exact.invokeHostAsync operation is not endowed",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeStartupCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const requiredFacts = [
    "lockdown-flag-pinned",
    "eval-tamed",
    "object-prototype-frozen",
  ];
  const sourceDescriptor = {
    kind: "startup-loaded-engine-postcondition",
    surfaceName: "lockdown-install",
    postcondition: "lockdown-installed",
    requiredFacts,
    sourceRefs: ["src/engine/hermes_runtime.cc#lockdownJS"],
    sourceMetadata: null,
    environment: null,
  };
  Object.assign(recipe, {
    fixtureId: "fixture.startup.lockdown",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.startup"],
    implementationBranchIds: ["edge.startup.main"],
    enforcementBranchIds: ["edge.startup.main"],
    terminalObservedKey: "startup:lockdown-install",
  });
  recipe.expectedObservation.branchId = "edge.startup.main";
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.route.alternatives[0].proofPaths = [recipe.terminalObservedKey];
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    invocationSchema: "ibex/capsec-startup-surface-invocation/1",
    kind: "startup-loaded-engine",
    surfaceKind: "startup",
    surfaceName: "lockdown-install",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "loaded-engine-startup",
      postcondition: "lockdown-installed",
      requiredFacts,
      environment: null,
    },
    expectedResult: "return",
  });
  catalog.summary.byScenario = { "non-capability": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function startupRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        surfaceKind: "startup",
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        postcondition: invocation.operation.postcondition,
        engineExecuted: true,
        projectCodeExecuted: true,
        observedFacts: Object.fromEntries(
          invocation.operation.requiredFacts.map((fact) => [fact, true]),
        ),
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function closedRuntimeObservation(recipe, projectCodeExecuted = false) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const errorMessage =
    invocation.operation.kind === "cli-control"
      ? invocation.operation.expectedRejectionFragments.join("; ")
      : invocation.operation.kind === "loader-executable-file"
        ? invocation.operation.rejectionFragment
        : invocation.operation.kind === "terminal-builtin-import"
          ? invocation.operation.moduleSpecifiers
              .map(
                (specifier) =>
                  `${specifier}: ${invocation.operation.expectedRejectionFragment} '${specifier}'`,
              )
              .join("\n")
        : invocation.operation.kind === "debugger-abi-disabled"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "shared-runtime-global-absence"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "armed-native-global-absence"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "exact-unendowed-operation"
          ? invocation.operation.expectedError
          : "production capability startup rejects closed environment controls: EX_SKIP_STARTUP_MODULE_LOADER";
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "closed",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        errorName: "ClosedSurface",
        errorMessage,
        engineExecuted:
          invocation.operation.kind === "loader-executable-file" ||
          invocation.operation.kind === "terminal-builtin-import" ||
          invocation.operation.kind === "debugger-abi-disabled" ||
          invocation.operation.kind === "shared-runtime-global-absence" ||
          invocation.operation.kind === "armed-native-global-absence" ||
          invocation.operation.kind === "exact-unendowed-operation",
        projectCodeExecuted,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function targetAbsenceCatalog() {
  const recipe = {
    fixtureId: "fixture.native.target.absent",
    planDigest: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    classification: "effects",
    scenario: "absent",
    edgeIds: ["edge.public"],
    implementationBranchIds: [],
    enforcementBranchIds: [],
    actionIds: ["sys:read"],
    terminalObservedKey: "native-op:__exactPlatformOnly",
    expectedObservation: { kind: "target-absence", target },
    route: {
      surfaceObservedKeys: [],
      alternatives: [],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "target-absence-probe",
      surfaceObservedKey: "native-op:__exactPlatformOnly",
      command: [
        "ibex",
        "capsec-public-fixture",
        "fixture.native.target.absent",
      ],
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: "__exactPlatformOnly",
        sourceDescriptor: {
          arity: 0,
          globalName: "__exactPlatformOnly",
          kind: "native-global-function",
          sourceRef: "src/engine/platform.cc#jsi-global:__exactPlatformOnly",
        },
        arguments: [],
        setup: [],
        expectedResult: "absent",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.public"],
        expectedActionIds: ["sys:read"],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
    recipe.publicSurfaceProbe.invocation.sourceDescriptor,
  );
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { absent: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeCallbackCatalog() {
  const catalog = structuredClone(completeCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "callback-security-invariant",
    scenario: "generation-recheck",
    rationaleId: "callback-attribution-carrier",
    surfaceObservedKey: "native-op:__exactCallbackCarrier",
    edgeId: "edge.callback",
    branchId: "edge.callback.main",
    sourceRefs: ["src/engine/hermes_runtime.cc#callback-carrier"],
    coverageEdge: { id: "edge.callback" },
    implementationBranch: { branchId: "edge.callback.main" },
    liveSurface: {
      kind: "native-op",
      name: "__exactCallbackCarrier",
    },
    executionMechanism: "scheduled-public-environment-revocation-recheck",
    auxiliaryDecisionEdgeId: "edge.callback-terminal",
  };
  Object.assign(recipe, {
    fixtureId: "fixture.callback.generation-recheck",
    classification: "non-capability",
    scenario: "generation-recheck",
    edgeIds: ["edge.callback"],
    implementationBranchIds: ["edge.callback.main"],
    enforcementBranchIds: ["edge.callback.main"],
    actionIds: [],
    terminalObservedKey: "native-op:__exactCallbackCarrier",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.callback.main",
    },
    route: {
      surfaceObservedKeys: ["native-op:__exactCallbackCarrier"],
      alternatives: [],
      ambiguousCallees: [],
    },
  });
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey: recipe.terminalObservedKey,
    command: ["cargo", "test", "capsec_public_callback_invariant_batch"],
    invocation: {
      invocationSchema: "ibex/capsec-callback-invariant-invocation/1",
      kind: "callback-security-invariant",
      scenario: recipe.scenario,
      surfaceKind: "native-op",
      surfaceName: "__exactCallbackCarrier",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "invariant-passed",
      expectedTypedDecisionCount: 3,
      expectedTypedStages: ["requested", "commit", "requested"],
      expectedTypedOutcomes: ["allow", "allow", "deny"],
      expectedTypedReasons: [
        "dynamic-session",
        "dynamic-session",
        "missing-authority",
      ],
      allowedCoverageEdgeIds: ["edge.callback-terminal"],
      expectedActionIds: ["env:read"],
    },
  });
  catalog.summary.byScenario = { "generation-recheck": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeExactCallbackCatalog() {
  const catalog = structuredClone(completeCallbackCatalog());
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "callback:exact-host-call-async-resolve";
  const sourceRefs = [
    "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
  ];
  const sourceDescriptor = {
    kind: "callback-security-invariant",
    scenario: "non-capability",
    rationaleId: "callback-attribution-carrier",
    surfaceObservedKey,
    edgeId: "edge.exact-callback",
    branchId: "edge.exact-callback.main",
    sourceRefs,
    coverageEdge: {
      id: "edge.exact-callback",
      classification: "non-capability",
    },
    implementationBranch: {
      branchId: "edge.exact-callback.main",
      sourceRefs,
    },
    liveSurface: {
      observedKey: surfaceObservedKey,
      kind: "callback",
      name: "exact-host-call-async-resolve",
      sourceRefs,
    },
    executionMechanism: "exact-host-call-round-trip",
    auxiliaryDecisionEdgeId: null,
  };
  Object.assign(recipe, {
    fixtureId: "fixture.exact-callback.non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.exact-callback"],
    implementationBranchIds: ["edge.exact-callback.main"],
    enforcementBranchIds: ["edge.exact-callback.main"],
    terminalObservedKey: surfaceObservedKey,
  });
  recipe.expectedObservation.branchId = "edge.exact-callback.main";
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey,
    invocation: {
      invocationSchema: "ibex/capsec-callback-invariant-invocation/1",
      kind: "callback-security-invariant",
      scenario: "non-capability",
      surfaceKind: "callback",
      surfaceName: "exact-host-call-async-resolve",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "invariant-passed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      expectedTypedOutcomes: [],
      expectedTypedReasons: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  });
  catalog.summary.byScenario = { "non-capability": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function exactCallbackRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "callback-security-invariant",
        scenario: "non-capability",
        outcome: "passed",
        checks: {
          executionMechanism: "exact-host-call-round-trip",
          setterInstalled: true,
          immutableCapability: true,
          genericBridgeAbsent: true,
          callbackExecuted: true,
          operationId: 7,
          payloadLength: 3,
          completion: "9,8",
          completionTargetsConsumed: 1,
          completionCallbacksQueued: 1,
          completionCallbacksDelivered: 1,
          singleUseCompletion: true,
        },
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeStartupEnvironmentCatalog(scenario = "allow") {
  const catalog = structuredClone(completeCatalog());
  const recipe = catalog.recipes[0];
  const selectedBranch = structuredClone(
    coverage.edges
      .find((edge) => edge.id === "edge.startup-env-node-debug")
      .logicalBranches.find((branch) => branch.id === "absent"),
  );
  const sourceDescriptor = {
    kind: "startup-environment-source",
    surfaceObservedKey: "startup:env:NODE_DEBUG",
    environmentName: "NODE_DEBUG",
    sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
    liveSourceRefs: [
      "src/builtins/http.js#process.env:NODE_DEBUG:read",
      "src/builtins/util.js#process.env:NODE_DEBUG:read",
    ],
    carrierEdgeId: "edge.startup-env-node-debug",
    implementationBranchIds: ["edge.startup-env-node-debug.main"],
    enforcementBranchIds: ["enforcement.startup-env-node-debug"],
    selectedBranch,
    executionMechanism: "builtin-module-load",
    moduleSpecifier: "node:http",
    preloadModuleSpecifiers: ["node:util"],
    principalMode: scenario === "deny" ? "package-denied" : "root-authorized",
    auxiliaryDecisionEdgeId: "edge.callback-terminal",
  };
  Object.assign(recipe, {
    fixtureId: `fixture.startup.env.node-debug.absent.${scenario}`,
    scenario,
    edgeIds: ["edge.startup-env-node-debug"],
    implementationBranchIds: ["edge.startup-env-node-debug.main"],
    enforcementBranchIds: ["enforcement.startup-env-node-debug"],
    actionIds: ["env:read"],
    terminalObservedKey: "startup:env:NODE_DEBUG",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "enforcement.startup-env-node-debug",
    },
    route: {
      surfaceObservedKeys: ["startup:env:NODE_DEBUG"],
      alternatives: [
        {
          terminalObservedKey: "startup:env:NODE_DEBUG",
          proofPaths: ["startup:env:NODE_DEBUG"],
        },
      ],
      ambiguousCallees: [],
    },
  });
  const denial = scenario === "deny";
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey: recipe.terminalObservedKey,
    command: ["cargo", "test", "capsec_public_startup_environment_batch"],
    invocation: {
      invocationSchema: "ibex/capsec-startup-environment-invocation/1",
      kind: "startup-environment-source",
      scenario,
      surfaceKind: "startup",
      surfaceName: "env:NODE_DEBUG",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "builtin-module-load",
        moduleSpecifier: "node:http",
        preloadModuleSpecifiers: ["node:util"],
        environment: { name: "NODE_DEBUG", presence: "absent" },
        principalMode: sourceDescriptor.principalMode,
      },
      expectedResult: "return",
      expectedTypedDecisionCount: denial ? 1 : 2,
      expectedTypedStages: denial
        ? ["requested"]
        : ["requested", "commit"],
      expectedTypedOutcomes: denial ? ["deny"] : ["allow", "allow"],
      expectedTypedReasons: denial
        ? ["principal-denial"]
        : ["static-floor", "static-floor"],
      allowedCoverageEdgeIds: ["edge.callback-terminal"],
      expectedActionIds: ["env:read"],
      expectedResourceNames: ["NODE_DEBUG"],
    },
  });
  catalog.summary.byScenario = { [scenario]: 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function startupEnvironmentRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const denial = invocation.scenario === "deny";
  const actor = denial
    ? {
        kind: "package",
        name: "image-lib",
        integrity: `sha256-${"A".repeat(43)}`,
        locator: "image-lib@2.4.1",
      }
    : { kind: "root", identity: "project-root" };
  const constrainedPrincipals = denial
    ? [{ kind: "root", identity: "project-root" }, actor]
    : [actor];
  const decision = (stage, index) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `fixture-startup-environment-${stage}`,
      atomicityGroup: "edge.callback-terminal.decision",
      combination: "conjunction",
      context: {
        stage,
        actor,
        constrainedPrincipals,
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: "env:read",
          effectOwner: actor,
          resource: {
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "broker-base",
              name: "NODE_DEBUG",
            },
            valueOrigin: "broker-base",
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: "edge.callback-terminal",
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      outcome: invocation.expectedTypedOutcomes[index],
      evidence: [
        {
          effectIndex: 0,
          principal: actor,
          reason: invocation.expectedTypedReasons[index],
        },
      ],
    },
  });
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        surfaceKind: "startup",
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        moduleSpecifier: invocation.operation.moduleSpecifier,
        environmentName: invocation.operation.environment.name,
        environmentPresence: "absent",
        principalMode: invocation.operation.principalMode,
        engineExecuted: true,
        projectCodeExecuted: true,
        sourceOutcome: denial ? "denied-as-absent" : "source-observed",
        errorName: null,
        errorMessage: null,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: invocation.expectedTypedStages.map(decision),
  };
}

function targetAbsenceObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      globalName: invocation.globalName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "missing", globalName: invocation.globalName },
      executionProof: { kind: "exact-global-absence", bodyEntered: false },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function globalReadCatalog() {
  const recipe = {
    fixtureId: "fixture.global.read.non-capability",
    planDigest: "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.read"],
    implementationBranchIds: ["edge.read.all"],
    enforcementBranchIds: ["edge.read.all"],
    actionIds: [],
    terminalObservedKey: "native-op:global:Exact.version",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.read.all",
    },
    route: {
      surfaceObservedKeys: ["native-op:global:Exact.version"],
      alternatives: [
        {
          terminalObservedKey: "native-op:global:Exact.version",
          proofPaths: ["native-op:global:Exact.version"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "native-op:global:Exact.version",
      command: ["ibex", "capsec-public-fixture", "fixture.global.read"],
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "global-property-read",
        globalName: "Exact",
        sourceDescriptor: {
          kind: "global-property-read",
          sourceKey: "shared_runtime",
          exportName: "Exact.version",
          globalName: "Exact",
          memberKinds: ["object-property"],
          sourceRefs: ["packages/ibex-runtime-js/src/bootstrap.ts#Exact.version"],
          valueShape: "data",
          access: {
            kind: "source-proven-property-path",
            path: ["Exact", "version"],
          },
        },
        arguments: [],
        requiredFloor: [],
        setup: [],
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.read"],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
    recipe.publicSurfaceProbe.invocation.sourceDescriptor,
  );
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { "non-capability": 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function globalReadObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      globalName: invocation.globalName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        globalName: invocation.globalName,
        valueType: "string",
        ownerDepths: [0, 0],
        cleanup: "none",
      },
      executionProof: { kind: "global-property-read", bodyEntered: true },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function callbackRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const auxiliaryEdgeId =
    invocation.sourceDescriptor.auxiliaryDecisionEdgeId;
  const packagePrincipal = {
    kind: "package",
    name: "image-lib",
    integrity: `sha256-${"A".repeat(43)}`,
    locator: "image-lib@2.4.1",
  };
  const generationsBefore = { negative: 0, dynamic: 1, handle: 0 };
  const generationsAfter = { negative: 1, dynamic: 2, handle: 0 };
  const decision = (stage, outcome, reason, suffix, generations) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `fixture-callback-${suffix}`,
      atomicityGroup: `${auxiliaryEdgeId}.decision`,
      combination: "conjunction",
      context: {
        stage,
        actor: packagePrincipal,
        constrainedPrincipals: [packagePrincipal],
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: "env:read",
          effectOwner: packagePrincipal,
          resource: {
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "broker-base",
              name: "PATH",
            },
            valueOrigin: "broker-base",
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: auxiliaryEdgeId,
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      outcome,
      generations,
      evidence: [{ principal: packagePrincipal, reason }],
    },
  });
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "callback-security-invariant",
        scenario: invocation.scenario,
        outcome: "passed",
        checks: {
          callbackExecuted: true,
          actualPrincipal: packagePrincipal,
          generationsBefore,
          generationsAfter,
          generationAdvanced: true,
          scheduledDecisionRechecked: true,
          runtimeNonce: "u64:17",
        },
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [
      decision(
        "requested",
        "allow",
        "dynamic-session",
        "before-requested",
        generationsBefore,
      ),
      decision(
        "commit",
        "allow",
        "dynamic-session",
        "before-commit",
        generationsBefore,
      ),
      decision(
        "requested",
        "deny",
        "missing-authority",
        "after-requested",
        generationsAfter,
      ),
    ],
  };
}

describe("CapSec public-surface promotion evidence", () => {
  test("merges only exact, engine-bound public fixture batches", () => {
    const catalog = completeCatalog();
    const execution = buildPublicFixtureEvidence({
      recipe: catalog.recipes[0],
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: runtimeObservation(catalog.recipes[0]),
      coverage,
    });
    const batch = {
      publicBatchEvidenceSchema: "ibex/capsec-public-batch-evidence/1",
      recipeCatalogDigest: catalog.recipeCatalogDigest,
      loadedEngineIdentity: engine,
      executions: [execution],
    };
    expect(
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toEqual([execution]);

    expect(() =>
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/duplicate public execution/);
    expect(() =>
      mergePublicBatchExecutions({
        batches: [
          {
            batch: { ...batch, executions: [] },
            expectedFixtureIds: [catalog.recipes[0].fixtureId],
          },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/missing, duplicates, or adds/);
  });

  test("accepts one exact public invocation for every complete recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog, {
        target,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        engine,
        coverage,
        expectedFixtureIds: ["fixture.public.allow"],
      }),
    ).not.toThrow();
  });

  test("accepts only the exact zero-decision builtin normal-return proof", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const observed = noncapBuiltinCallObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const [label, mutate, expected] of [
      [
        "result type",
        (value) => {
          value.invocation.result.valueType = "object";
        },
        /exact normal return/,
      ],
      [
        "dispatch",
        (value) => {
          value.invocation.result.dispatchKind = "construct";
        },
        /exact normal return/,
      ],
      [
        "body-entry marker",
        (value) => {
          value.invocation.result.bodyEntryProof = "caller-asserted";
        },
        /exact normal return/,
      ],
      [
        "extra result field",
        (value) => {
          value.invocation.result.synthetic = true;
        },
        /unknown or missing fields/,
      ],
      [
        "missing completion",
        (value) => {
          delete value.invocation.completion;
        },
        /unknown or missing fields/,
      ],
      [
        "unsettled completion",
        (value) => {
          value.invocation.completion.status = "pending";
        },
        /escaped its observation session/,
      ],
      [
        "caller-selected completion timeout",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.completion.timeoutMilliseconds =
            5_000;
        },
        /escaped its observation session/,
      ],
      [
        "unknown setup",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.setup.kind =
            "caller-selected";
        },
        /malformed authored normal-return setup/,
      ],
      [
        "downgraded expectation",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.expectedResult =
            "return";
        },
        /descriptor drift/,
      ],
      [
        "legacy decision",
        (value) => {
          value.legacyObservationCount = 1;
        },
        /malformed runtime public observation/,
      ],
      [
        "typed decision",
        (value) => {
          value.typedDecisions = [{}];
        },
        /malformed runtime public observation/,
      ],
    ]) {
      const tampered = structuredClone(observed);
      const tamperedRecipe = structuredClone(recipe);
      mutate(tampered, tamperedRecipe);
      expect(
        () =>
          buildPublicFixtureEvidence({
            recipe: tamperedRecipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: tampered,
            coverage,
          }),
        label,
      ).toThrow(expected);
    }

    const aliasRecipe = structuredClone(recipe);
    const aliasObservation = structuredClone(observed);
    aliasRecipe.publicSurfaceProbe.invocation.invocationSchema =
      "ibex/capsec-builtin-module-import-invocation/1";
    aliasRecipe.publicSurfaceProbe.invocation.kind = "builtin-module-import";
    aliasObservation.invocation.invocationSchema =
      aliasRecipe.publicSurfaceProbe.invocation.invocationSchema;
    aliasObservation.invocation.kind =
      aliasRecipe.publicSurfaceProbe.invocation.kind;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: aliasRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: aliasObservation,
        coverage,
      }),
    ).toThrow(/unsupported runtime invocation schema/);
  });

  test("accepts source-bound builtin target absence only after a public read", () => {
    const catalog = completeNoncapBuiltinAbsenceCatalog();
    const recipe = catalog.recipes[0];
    const observed = noncapBuiltinAbsenceObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const fabricated = structuredClone(observed);
    fabricated.invocation.result.available.push("EDQUOT");
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: fabricated,
        coverage,
      }),
    ).toThrow(/did not prove source-bound target absence/);

    const availableHere = structuredClone(recipe);
    availableHere.publicSurfaceProbe.invocation.sourceDescriptor.platformAvailability =
      ["darwin", "linux"];
    availableHere.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        availableHere.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const availableObservation = noncapBuiltinAbsenceObservation(availableHere);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: availableHere,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: availableObservation,
        coverage,
      }),
    ).toThrow(/did not prove source-bound target absence/);
  });

  test("accepts exact-target ABI absence only after a runtime symbol lookup", () => {
    const catalog = completeAbsenceCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not prove absence/);
  });

  test("accepts native target absence only after exact runtime inspection", () => {
    const catalog = completeNativeAbsenceCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not prove absence/);
  });

  test("accepts structural startup only with exact loaded-engine postconditions", () => {
    const catalog = completeStartupCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: startupRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const failedFact = startupRuntimeObservation(recipe);
    failedFact.invocation.result.observedFacts["eval-tamed"] = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: failedFact,
        coverage,
      }),
    ).toThrow(/did not prove the startup postcondition/);

    const noProject = startupRuntimeObservation(recipe);
    noProject.invocation.result.projectCodeExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: noProject,
        coverage,
      }),
    ).toThrow(/did not prove the startup postcondition/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.operation.postcondition =
      "runtime-created";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: startupRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/startup runtime invocation descriptor drift/);
  });

  test("accepts a closed surface only when project code did not execute", () => {
    const catalog = completeClosedCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not fail closed/);
  });

  test("accepts CLI closure only with the authored production rejection", () => {
    const catalog = completeClosedCliCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    const wrong = closedRuntimeObservation(recipe);
    wrong.invocation.result.errorMessage = "a parser rejected unrelated syntax";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrong,
        coverage,
      }),
    ).toThrow(/wrong rejection/);
  });

  test("accepts executable-loader closure only after the loaded engine rejects it", () => {
    const catalog = completeClosedLoaderCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    const wrongRejection = closedRuntimeObservation(recipe);
    wrongRejection.invocation.result.errorMessage = "generic syntax error";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongRejection,
        coverage,
      }),
    ).toThrow(/did not fail closed at resolution/);
    const noEngine = closedRuntimeObservation(recipe);
    noEngine.invocation.result.engineExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: noEngine,
        coverage,
      }),
    ).toThrow(/did not fail closed at resolution/);
    const mismatchedKind = structuredClone(recipe);
    mismatchedKind.publicSurfaceProbe.invocation.operation.extension = ".wasm";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: mismatchedKind,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(mismatchedKind),
        coverage,
      }),
    ).toThrow(/executed extension guard/);

    const unexecutedKindFacet = structuredClone(recipe);
    unexecutedKindFacet.terminalObservedKey = "loader:kind:native-addon";
    unexecutedKindFacet.route.surfaceObservedKeys = [
      unexecutedKindFacet.terminalObservedKey,
    ];
    unexecutedKindFacet.route.alternatives[0].terminalObservedKey =
      unexecutedKindFacet.terminalObservedKey;
    unexecutedKindFacet.publicSurfaceProbe.surfaceObservedKey =
      unexecutedKindFacet.terminalObservedKey;
    const kindInvocation = unexecutedKindFacet.publicSurfaceProbe.invocation;
    kindInvocation.surfaceName = "kind:native-addon";
    kindInvocation.sourceDescriptor.sourceRefs = [
      "src/module_loader/mod.rs#kind:native-addon",
    ];
    kindInvocation.sourceDescriptor.sourceMetadata = {
      evidenceType: "loader-kind-branch",
      loaderKind: "native-addon",
      occurrenceCount: 1,
    };
    kindInvocation.sourceDescriptorDigest = taggedDigest(
      kindInvocation.sourceDescriptor,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: unexecutedKindFacet,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(unexecutedKindFacet),
        coverage,
      }),
    ).toThrow(/executed extension guard/);
  });

  test("accepts terminal builtin closure only when every public alias is denied", () => {
    const catalog = completeClosedTerminalBuiltinCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const oneAlias = closedRuntimeObservation(recipe);
    oneAlias.invocation.result.errorMessage =
      "node:vm: Import denied: 'node:vm'";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: oneAlias,
        coverage,
      }),
    ).toThrow(/aliases did not fail closed/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey =
      "node_wasi";
    drifted.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
      drifted.publicSurfaceProbe.invocation.sourceDescriptor,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/authenticated import gate/);
  });

  test("accepts debugger ABI closure only for the physical no-debugger target result", () => {
    const catalog = completeClosedDebuggerAbiCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const wrongTarget = structuredClone(recipe);
    wrongTarget.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple =
      "x86_64-pc-windows-msvc";
    wrongTarget.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongTarget.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongTarget,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongTarget),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const wrongResult = structuredClone(recipe);
    wrongResult.publicSurfaceProbe.invocation.operation.expectedCallResult =
      "no-event";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongResult,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongResult),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const wrongError = closedRuntimeObservation(recipe);
    wrongError.invocation.result.errorMessage = "generic debugger error";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongError,
        coverage,
      }),
    ).toThrow(/no-debugger physical result/);
  });

  test("accepts shared-runtime global closure only for a reviewed legacy-only path", () => {
    const catalog = completeClosedSharedRuntimeGlobalCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const wrongRoute = structuredClone(recipe);
    wrongRoute.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.installationBranches[0].route =
      "shared-runtime";
    wrongRoute.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongRoute.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongRoute,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongRoute),
        coverage,
      }),
    ).toThrow(/reviewed legacy-only path/);

    const present = closedRuntimeObservation(recipe);
    present.invocation.result.engineExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: present,
        coverage,
      }),
    ).toThrow(/not physically absent/);
  });

  test("accepts armed native global closure only for a source-derived JSI path", () => {
    const catalog = completeClosedArmedNativeGlobalCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const inventedSource = structuredClone(recipe);
    inventedSource.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.publicInvocation.sourceRef =
      "src/engine/hermes_runtime.cc#invented";
    inventedSource.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inventedSource.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inventedSource,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(inventedSource),
        coverage,
      }),
    ).toThrow(/source-derived JSI path/);

    const present = closedRuntimeObservation(recipe);
    present.invocation.result.engineExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: present,
        coverage,
      }),
    ).toThrow(/not physically absent/);
  });

  test("accepts Exact closure only for the authenticated unendowed operation", () => {
    const catalog = completeClosedExactCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const endowed = structuredClone(recipe);
    endowed.publicSurfaceProbe.invocation.operation.selectedOperationId = 7;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: endowed,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(endowed),
        coverage,
      }),
    ).toThrow(/authenticated unendowed operation/);

    const wrongError = closedRuntimeObservation(recipe);
    wrongError.invocation.result.errorMessage = "generic IPC failure";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongError,
        coverage,
      }),
    ).toThrow(/did not fail closed before the embedder callback/);
  });

  test("accepts exact source-bound target absence and rejects invented entry proof", () => {
    const catalog = targetAbsenceCatalog();
    const recipe = catalog.recipes[0];
    const observation = targetAbsenceObservation(recipe);
    const execution = buildPublicFixtureEvidence({
      recipe,
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: observation,
      coverage,
    });
    const artifact = buildPublicSurfaceExecutionArtifact({
      recipeCatalog: catalog,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      target,
      engine,
      coverage,
      executions: [execution],
    });
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog, {
        target,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        engine,
        coverage,
        expectedFixtureIds: [recipe.fixtureId],
      }),
    ).not.toThrow();

    const invented = targetAbsenceObservation(recipe);
    invented.invocation.executionProof = {
      kind: "native-return",
      bodyEntered: true,
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: invented,
        coverage,
      }),
    ).toThrow(/execution proof disagrees/);
  });

  test("accepts a source-bound global read and rejects function-return proof", () => {
    const catalog = globalReadCatalog();
    const recipe = catalog.recipes[0];
    const observation = globalReadObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    const inheritedRecipe = structuredClone(recipe);
    inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptor.memberKinds = [
      "inherited",
      "static",
    ];
    inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const inheritedObservation = globalReadObservation(inheritedRecipe);
    inheritedObservation.invocation.result.ownerDepths = [0, 1];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).not.toThrow();
    inheritedObservation.invocation.result.valueType = "function";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).toThrow(/exact property owner chain/);
    inheritedObservation.invocation.result.valueType = "string";
    inheritedObservation.invocation.result.ownerDepths = [0, 0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).toThrow(/exact property owner chain/);

    observation.invocation.executionProof.kind = "native-return";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/execution proof disagrees/);
  });

  test("accepts native async evidence only after authored quiescence", () => {
    const recipe = completeCatalog().recipes[0];
    recipe.terminalObservedKey = "native-op:__exactPublic";
    recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.invocationSchema = "ibex/capsec-native-global-invocation/1";
    invocation.kind = "native-global-function";
    invocation.globalName = "__exactPublic";
    invocation.sourceDescriptor = {
      kind: "native-global-function",
      globalName: "__exactPublic",
      arity: 0,
      sourceRef: "src/engine/hermes_runtime.cc#jsi-global:__exactPublic",
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.arguments = [];
    invocation.requiredFloor = [];
    invocation.setup = [];
    invocation.expectedCleanup = "none";
    invocation.completion = {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
    };
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = runtimeObservation(recipe);
    delete observation.invocation.moduleSpecifier;
    delete observation.invocation.exportName;
    observation.invocation.kind = invocation.kind;
    observation.invocation.globalName = invocation.globalName;
    observation.invocation.result.globalName = invocation.globalName;
    observation.invocation.result.cleanup = "none";
    observation.invocation.executionProof = {
      kind: "native-return",
      bodyEntered: true,
    };
    observation.invocation.completion = {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
      status: "quiescent",
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const wrongCleanup = structuredClone(observation);
    wrongCleanup.invocation.result.cleanup = "closed-unrelated-resource";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongCleanup,
        coverage,
      }),
    ).toThrow(/did not prove its authored cleanup/);

    const pending = structuredClone(observation);
    pending.invocation.completion.status = "pending";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: pending,
        coverage,
      }),
    ).toThrow(/native work escaped its observation session/);

    const missing = structuredClone(observation);
    delete missing.invocation.completion;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missing,
        coverage,
      }),
    ).toThrow(/unknown or missing fields/);
  });

  test("accepts only the exact retained-object invalid-handle refusal", () => {
    const recipe = completeCatalog().recipes[0];
    Object.assign(recipe, {
      classification: "non-capability",
      scenario: "non-capability",
      actionIds: [],
      edgeIds: ["edge.terminal"],
      terminalObservedKey: "native-op:__exactSpawnSetReferenced",
    });
    recipe.route = {
      surfaceObservedKeys: [recipe.terminalObservedKey],
      alternatives: [
        {
          terminalObservedKey: recipe.terminalObservedKey,
          proofPaths: [recipe.terminalObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    Object.assign(invocation, {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactSpawnSetReferenced",
      sourceDescriptor: {
        kind: "native-global-function",
        globalName: "__exactSpawnSetReferenced",
        arity: 2,
        sourceRef:
          "src/engine/hermes_runtime_process.cc#jsi-global:__exactSpawnSetReferenced",
      },
      arguments: [
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: false },
      ],
      requiredFloor: [],
      setup: [],
      expectedResult: "invalid-handle",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      expectedActionIds: [],
      allowedCoverageEdgeIds: ["edge.terminal"],
    });
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: invocation.invocationSchema,
        kind: invocation.kind,
        surfaceObservedKey: recipe.terminalObservedKey,
        globalName: invocation.globalName,
        sourceDescriptorDigest: invocation.sourceDescriptorDigest,
        result: {
          kind: "throw",
          globalName: invocation.globalName,
          errorName: "Error",
          errorMessage: "__exactSpawnSetReferenced: invalid handle",
        },
        executionProof: {
          kind: "retained-object-refusal",
          bodyEntered: true,
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    observation.invocation.result.errorMessage = "unrelated invalid handle";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/exact retained-object refusal/);
  });

  test("binds the native async dispatcher to its exact worker terminal", () => {
    const recipe = completeCatalog().recipes[0];
    recipe.terminalObservedKey = "native-op:__exactFsPathAsync";
    recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
    recipe.route.alternatives = [
      {
        terminalObservedKey: recipe.terminalObservedKey,
        proofPaths: [recipe.terminalObservedKey],
      },
    ];
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    Object.assign(invocation, {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactFsPathAsync",
      sourceDescriptor: {
        kind: "native-global-function",
        globalName: "__exactFsPathAsync",
        arity: 6,
        sourceRef:
          "src/engine/hermes_runtime_fs.cc#jsi-global:__exactFsPathAsync",
      },
      arguments: [
        { kind: "json-literal", value: "mkdir" },
        { kind: "json-literal", value: "target/owned-directory" },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
      ],
      requiredFloor: [],
      setup: [],
      expectedCleanup: "none",
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
      allowedCoverageEdgeIds: ["edge.mkdir-worker"],
    });
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = runtimeObservation(recipe);
    delete observation.invocation.moduleSpecifier;
    delete observation.invocation.exportName;
    Object.assign(observation.invocation, {
      kind: invocation.kind,
      globalName: invocation.globalName,
      result: {
        kind: "return",
        globalName: invocation.globalName,
        valueType: "undefined",
        cleanup: "none",
      },
      executionProof: { kind: "native-return", bodyEntered: true },
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
        status: "quiescent",
      },
    });
    observation.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.mkdir-worker.decision";
    observation.typedDecisions[0].gates[0].coverageEdgeId =
      "edge.mkdir-worker";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const deniedRecipe = structuredClone(recipe);
    deniedRecipe.publicSurfaceProbe.invocation.expectedResult =
      "permission-denied";
    const denied = structuredClone(observation);
    denied.invocation.result = {
      kind: "throw",
      globalName: invocation.globalName,
      errorName: "Error",
      errorMessage: "EACCES: permission denied, mkdir 'target/owned-directory'",
    };
    denied.invocation.executionProof.kind = "typed-permission-denial";
    denied.typedDecisions[0].evidence.outcome = "deny";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: deniedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: denied,
        coverage,
      }),
    ).not.toThrow();

    const wrongWorker = structuredClone(observation);
    wrongWorker.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.terminal.decision";
    wrongWorker.typedDecisions[0].gates[0].coverageEdgeId = "edge.terminal";
    const wrongWorkerRecipe = structuredClone(recipe);
    wrongWorkerRecipe.publicSurfaceProbe.invocation.allowedCoverageEdgeIds = [
      "edge.mkdir-worker",
      "edge.terminal",
    ];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongWorkerRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongWorker,
        coverage,
      }),
    ).toThrow(/source-selected worker/);
  });

  test("accepts a source-bound zero-effect host ABI branch with cleanup", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const selectedBranch = {
      id: "memory",
      when: [{ fact: "sqlite.open.mode", equals: "memory" }],
    };
    const sourceDescriptor = {
      kind: "host-abi-function",
      functionName: "ex_host_sqlite_open",
      sourceRefs: ["src/host/abi.rs#ex_host_sqlite_open"],
      sourceMetadata: {
        definitions: [
          {
            language: "rust",
            sourceRef: "src/host/abi.rs#ex_host_sqlite_open",
            targetVariant: "default",
          },
        ],
      },
      selectedBranch,
    };
    Object.assign(recipe, {
      fixtureId: "fixture.host-sqlite.memory.no-effect",
      scenario: "no-effect",
      edgeIds: ["edge.host-sqlite"],
      actionIds: [],
      terminalObservedKey: "host-abi:ex_host_sqlite_open",
      route: {
        surfaceObservedKeys: ["host-abi:ex_host_sqlite_open"],
        alternatives: [
          {
            terminalObservedKey: "host-abi:ex_host_sqlite_open",
            proofPaths: ["host-abi:ex_host_sqlite_open"],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        functionName: "ex_host_sqlite_open",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "sqlite-memory", selectedBranch },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.host-sqlite"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        surfaceObservedKey: recipe.terminalObservedKey,
        functionName: "ex_host_sqlite_open",
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          functionName: "ex_host_sqlite_open",
          operation: "sqlite-memory",
          cleanup: "released-sqlite-memory-state",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.cleanup = "none";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not prove bounded cleanup/);
  });

  test("accepts exact module-loader authority access with no CapSec decision", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const sourceDescriptor = {
      kind: "module-loader-function",
      surfaceName: "module-runner-cache-access",
      sourceRefs: ["src/module_loader/security.rs#authorize_then_access"],
    };
    Object.assign(recipe, {
      fixtureId: "fixture.module-loader.cache.non-capability",
      classification: "non-capability",
      scenario: "non-capability",
      edgeIds: ["edge.module-loader-cache"],
      actionIds: [],
      terminalObservedKey: "loader:module-runner-cache-access",
      route: {
        surfaceObservedKeys: ["loader:module-runner-cache-access"],
        alternatives: [
          {
            terminalObservedKey: "loader:module-runner-cache-access",
            proofPaths: ["loader:module-runner-cache-access"],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-module-loader-invocation/1",
        kind: "module-loader-authority",
        surfaceName: "module-runner-cache-access",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "cache-read" },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.module-loader-cache"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-module-loader-invocation/1",
        kind: "module-loader-authority",
        surfaceObservedKey: recipe.terminalObservedKey,
        surfaceName: "module-runner-cache-access",
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          surfaceName: "module-runner-cache-access",
          operation: "cache-read",
          accessExecuted: true,
          cleanup: "none",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.accessExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not prove its exact access/);
  });

  test("accepts a source-bound module-runner ABI only when the graph enters it", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const functionName = "ex_hermes_module_compile_factory";
    const sourceDescriptor = {
      kind: "host-abi-function",
      functionName,
      sourceRefs: [`src/engine/hermes_module_runner.cc#${functionName}`],
      sourceMetadata: {
        definitions: [
          {
            language: "c++",
            sourceRef: `src/engine/hermes_module_runner.cc#${functionName}`,
            targetVariant: "default",
          },
        ],
      },
    };
    Object.assign(recipe, {
      fixtureId: "fixture.module-runner.compile.non-capability",
      classification: "non-capability",
      scenario: "non-capability",
      edgeIds: ["edge.module-runner-compile"],
      actionIds: [],
      terminalObservedKey: `host-abi:${functionName}`,
      route: {
        surfaceObservedKeys: [`host-abi:${functionName}`],
        alternatives: [
          {
            terminalObservedKey: `host-abi:${functionName}`,
            proofPaths: [`host-abi:${functionName}`],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        functionName,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "module-runner-source-graph" },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.module-runner-compile"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        surfaceObservedKey: recipe.terminalObservedKey,
        functionName,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          functionName,
          operation: "module-runner-source-graph",
          observedFunctionNames: [functionName],
          cleanup: "released-module-graph",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.observedFunctionNames = [];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not enter the exact host ABI/);
  });

  test("accepts armed module namespace closure only at the exact ABI", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const functionName = "ex_hermes_module_record_namespace_json";
    const surfaceObservedKey = `host-abi:${functionName}`;
    const sourceDescriptor = {
      kind: "closed-module-runner-namespace",
      surfaceObservedKey,
      sourceRefs: [`src/engine/hermes_module_runner.cc#${functionName}`],
      sourceMetadata: {
        definitions: [
          {
            language: "c++",
            sourceRef: `src/engine/hermes_module_runner.cc#${functionName}`,
          },
        ],
      },
    };
    const expectedError =
      "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup";
    Object.assign(recipe, {
      fixtureId: "fixture.module-runner.namespace.closed",
      classification: "closed",
      scenario: "closed",
      edgeIds: ["edge.module-runner-namespace-closed"],
      actionIds: [],
      terminalObservedKey: surfaceObservedKey,
      route: {
        surfaceObservedKeys: [surfaceObservedKey],
        alternatives: [
          { terminalObservedKey: surfaceObservedKey, proofPaths: [surfaceObservedKey] },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_closed_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceKind: "host-abi",
        surfaceName: functionName,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "module-runner-namespace", expectedError },
        expectedResult: "closed",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceObservedKey,
        surfaceKind: "host-abi",
        surfaceName: functionName,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "closed",
          surfaceKind: "host-abi",
          surfaceName: functionName,
          mechanism: "module-runner-namespace",
          errorName: "ClosedSurface",
          errorMessage: expectedError,
          engineExecuted: true,
          projectCodeExecuted: false,
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.errorMessage = "different rejection";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not fail closed/);
  });

  test("accepts callback invariants only with exact typed outcomes and reasons", () => {
    const catalog = completeCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = callbackRuntimeObservation(recipe);
    const execution = buildPublicFixtureEvidence({
      recipe,
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: observed,
      coverage,
    });
    expect(execution.evidence.terminalObservedKey).toBe(
      recipe.publicSurfaceProbe.surfaceObservedKey,
    );

    const wrongReason = structuredClone(observed);
    wrongReason.typedDecisions[2].evidence.evidence[0].reason =
      "dynamic-session";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongReason,
        coverage,
      }),
    ).toThrow(/typed reason disagrees/);

    const wrongCheck = structuredClone(observed);
    wrongCheck.invocation.result.checks.scheduledDecisionRechecked = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongCheck,
        coverage,
      }),
    ).toThrow(/did not prove a post-revocation decision recheck/);

    const legacy = structuredClone(observed);
    legacy.legacyObservationCount = 1;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: legacy,
        coverage,
      }),
    ).toThrow(/malformed runtime public observation/);

    const wrongAuxiliary = structuredClone(recipe);
    wrongAuxiliary.publicSurfaceProbe.invocation.allowedCoverageEdgeIds = [
      "edge.terminal",
    ];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongAuxiliary,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/auxiliary decision is not coverage-bound/);

    const wrongAuxiliaryAction = structuredClone(recipe);
    wrongAuxiliaryAction.publicSurfaceProbe.invocation.expectedActionIds = [
      "fs:read",
    ];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongAuxiliaryAction,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/auxiliary decision is not coverage-bound/);

    const driftedCoverage = structuredClone(coverage);
    driftedCoverage.edges.find(
      (edge) => edge.id === "edge.callback-terminal",
    ).effects[0].cap = "fs:read";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage: driftedCoverage,
      }),
    ).toThrow(/auxiliary decision is not coverage-bound/);
  });

  test("accepts Exact non-capability evidence only from its bound ABI lifecycle", () => {
    const catalog = completeExactCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = exactCallbackRuntimeObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const wrongMechanism = structuredClone(recipe);
    wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptor.executionMechanism =
      "exact-endowment-install";
    wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const wrongMechanismObservation =
      exactCallbackRuntimeObservation(wrongMechanism);
    wrongMechanismObservation.invocation.result.checks.executionMechanism =
      "exact-endowment-install";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongMechanism,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongMechanismObservation,
        coverage,
      }),
    ).toThrow(/not source-bound/);

    const replayWon = structuredClone(observed);
    replayWon.invocation.result.checks.completion = "7";
    replayWon.invocation.result.checks.completionCallbacksDelivered = 2;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: replayWon,
        coverage,
      }),
    ).toThrow(/single-use Exact completion route/);
  });

  test("accepts startup environment carriers only with exact source, resource, and principal evidence", () => {
    for (const scenario of ["allow", "deny", "branch-selection"]) {
      const catalog = completeStartupEnvironmentCatalog(scenario);
      const recipe = catalog.recipes[0];
      const observed = startupEnvironmentRuntimeObservation(recipe);
      const execution = buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      });
      expect(execution.evidence.terminalObservedKey).toBe(
        "startup:env:NODE_DEBUG",
      );
    }

    const catalog = completeStartupEnvironmentCatalog("allow");
    const recipe = catalog.recipes[0];
    const observed = startupEnvironmentRuntimeObservation(recipe);

    const wrongResource = structuredClone(observed);
    wrongResource.typedDecisions[0].decisionSet.effects[0].resource.requested.name =
      "NODE_OPTIONS";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongResource,
        coverage,
      }),
    ).toThrow(/lost its exact resource or principal binding/);

    const wrongActor = structuredClone(observed);
    wrongActor.typedDecisions[0].decisionSet.context.actor = {
      kind: "package",
      name: "image-lib",
      integrity: `sha256-${"B".repeat(43)}`,
      locator: "image-lib@2.4.1",
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongActor,
        coverage,
      }),
    ).toThrow(/typed reason disagrees|exact resource or principal binding/);

    const wrongGate = structuredClone(observed);
    wrongGate.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.startup-env-node-debug.decision";
    wrongGate.typedDecisions[0].gates[0].coverageEdgeId =
      "edge.startup-env-node-debug";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongGate,
        coverage,
      }),
    ).toThrow(/unbound or incomplete typed gate/);

    const wrongResult = structuredClone(observed);
    wrongResult.invocation.result.environmentPresence = "present";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongResult,
        coverage,
      }),
    ).toThrow(/did not prove the startup environment source outcome/);

    const driftedRecipe = structuredClone(recipe);
    driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptor.selectedBranch.when =
      [
        {
          fact: "environment.startup.node_debug",
          equals: "present",
        },
      ];
    driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const driftedObservation = structuredClone(observed);
    driftedObservation.invocation.sourceDescriptorDigest =
      driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: driftedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: driftedObservation,
        coverage,
      }),
    ).toThrow(/startup environment auxiliary decision is not coverage-bound/);

    const wrongAuxiliary = structuredClone(recipe);
    wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptor.auxiliaryDecisionEdgeId =
      "edge.terminal";
    wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const wrongAuxiliaryObservation = structuredClone(observed);
    wrongAuxiliaryObservation.invocation.sourceDescriptorDigest =
      wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptorDigest;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongAuxiliary,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongAuxiliaryObservation,
        coverage,
      }),
    ).toThrow(/startup environment auxiliary decision is not coverage-bound/);
  });

  test("rejects hand-labeled callback terminals", () => {
    const catalog = completeCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = callbackRuntimeObservation(recipe);
    observed.invocation.surfaceObservedKey = "native-op:__exactHandLabel";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/not source-descriptor bound/);
  });

  test("rejects adapter-only evidence explicitly", () => {
    const catalog = completeCatalog();
    expect(() =>
      validatePublicSurfaceExecutionArtifact(
        {
          adapterEvidenceSchema: "ibex/capsec-adapter-probe-evidence/1",
          recipeCatalogDigest: catalog.recipeCatalogDigest,
        },
        { recipeCatalog: catalog },
      ),
    ).toThrow(/adapter-only evidence cannot advertise/);
  });

  test("rejects a nominally complete recipe without an authored public probe", () => {
    const catalog = completeCatalog();
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    expect(() => assertRecipeCatalogComplete(catalog)).toThrow(
      /lacks an exact authored public-surface probe/,
    );
  });

  test("rejects residual or missing public obligations", () => {
    const catalog = completeCatalog();
    catalog.recipes[0].status = "unresolved";
    catalog.recipes[0].residualReasons = [
      "public-surface-invocation-not-authored",
    ];
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.summary.fullyExecutableFixtures = 0;
    catalog.summary.unresolvedFixtures = 1;
    catalog.summary.residualReasons = {
      "public-surface-invocation-not-authored": 1,
    };
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    const artifact = buildPublicSurfaceExecutionArtifact({
      recipeCatalog: catalog,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      target,
      engine,
      coverage,
      executions: [],
    });
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog),
    ).toThrow(/catalog is incomplete/);
  });

  test("rejects a terminal observation not bound by the recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    artifact.executions[0].evidence.terminalObservedKey =
      "native-op:__exactOther";
    expect(() =>
      validatePublicSurfaceExecutionArtifact(artifact, {
        recipeCatalog: catalog,
        coverage,
      }),
    ).toThrow(/digest-mismatched|stale or mismatched/);
  });

  test("rejects a manually supplied terminal label in runtime observations", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].terminalBranchId = "enforcement.public";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown or missing fields/);
  });

  test("derives the terminal from the bound coverage edge, not the static claim", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.unselected.decision";
    observed.typedDecisions[0].gates[0].coverageEdgeId = "edge.unselected";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown coverage edge/);
  });
});
