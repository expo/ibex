import { describe, expect, test } from "bun:test";
import {
  assertReportMayAdvertise,
  buildConformanceReport,
  executionBindingDigest,
  fixtureExecutionPlan,
  fixtureCatalogForTarget,
  selectCandidateTarget,
  validateConformanceReportSemantics,
} from "./capsec-conformance.mjs";
import Ajv2020 from "ajv/dist/2020.js";
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  INTERNAL_INVARIANT_COMMAND,
  INTERNAL_INVARIANT_EXECUTOR,
  internalInvariantProofPlan,
} from "./capsec-internal-invariant-evidence.mjs";
import { validateInternalInvariantFixtureExecution } from "./capsec-internal-invariant-execution.mjs";

const readSchema = (name) =>
  JSON.parse(
    fs.readFileSync(
      new URL(`../../../../capsec/schema/${name}`, import.meta.url),
      "utf8",
    ),
  );

const compileConformanceSchema = (schema) => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addSchema(readSchema("common.schema.json"));
  return ajv.compile(schema);
};

const target = {
  triple: "aarch64-apple-darwin",
  features: ["native-lockdown"],
};
const coverage = {
  edges: [
    {
      id: "edge.one",
      classification: "closed",
      surface: { kind: "native-op", name: "testClosed" },
    },
  ],
};
const implementation = {
  surfaces: [
    {
      edgeId: "edge.one",
      observedKey: "native-op:testClosed",
      branchId: "edge.one.main",
      enforcementBranchId: "edge.one.main",
      enforcementRoute: { terminalObservedKey: "native-op:testClosed" },
      targetVariant: "all",
      targetApplicability: { kind: "all" },
      fixtureObligations: ["edge.one.main.closed"],
    },
  ],
};
const bindings = {
  sourceRevision: "0".repeat(40),
  sourceTreeDigest: `sha256-${"A".repeat(43)}`,
  engine: {
    engineArtifactPath:
      "/repo/ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
    kind: "hermes",
    binaryDigest: `sha256-${"B".repeat(43)}`,
    object: { platform: "apple", volume: "dev:test", file: "ino:test" },
    targetArchitecture: "aarch64",
    structuralFeatures: [...target.features],
  },
  vocabularyDigest: `sha256-${"D".repeat(43)}`,
  registryDigest: `sha256-${"E".repeat(43)}`,
  recipeCatalogDigest: `sha256-${"F".repeat(43)}`,
  publicSurfaceExecutionDigest: `sha256-${"G".repeat(43)}`,
  outputDispositionEvidenceRawContentDigest: `sha256-${"H".repeat(43)}`,
};
const digestContract = {
  domains: { conformance: "ibex:capsec:conformance:1" },
  projections: {
    conformance: {
      inputSchema: "ibex/capsec-conformance/1",
      status: "available",
      members: ["conformance-report-object"],
      omitFields: ["conformanceDigest"],
    },
  },
};
const sha = (value) =>
  `sha256-${crypto.createHash("sha256").update(canonicalJson(value)).digest("base64url")}`;
const fixtureCatalogDigest = sha(
  fixtureCatalogForTarget({ coverage, implementation, target }),
);
const fixturePlan = fixtureExecutionPlan(
  fixtureCatalogForTarget({ coverage, implementation, target }),
  "edge.one.main.closed",
);
const recipeCatalog = {
  recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
  profile: "ibex/capsec/1",
  target,
  recipes: [
    {
      fixtureId: fixturePlan.fixtureId,
      status: "fully-executable",
      planDigest: sha(fixturePlan),
      terminalObservedKey: fixturePlan.terminalObservedKey,
    },
  ],
};
recipeCatalog.recipeCatalogDigest = sha(recipeCatalog);
bindings.recipeCatalogDigest = recipeCatalog.recipeCatalogDigest;
const passExecutionBinding = {
  sourceRevision: bindings.sourceRevision,
  sourceTreeDigest: bindings.sourceTreeDigest,
  target,
  engine: bindings.engine,
  vocabularyDigest: bindings.vocabularyDigest,
  registryDigest: bindings.registryDigest,
  implementationManifestDigest: sha(implementation),
  fixtureCatalogDigest,
  recipeCatalogDigest: bindings.recipeCatalogDigest,
  publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
};
const passEvidence = {
  evidenceSchema: "ibex/capsec-fixture-evidence/2",
  fixtureId: "edge.one.main.closed",
  command: ["bun", "test", "edge-one-closed.test.mjs"],
  exitCode: 0,
  resultMarker: "ibex-capsec-fixture:edge.one.main.closed:passed",
  planDigest: sha(fixturePlan),
  engineBinaryDigest: bindings.engine.binaryDigest,
  fixturePlan,
  executionBinding: passExecutionBinding,
  observation: {
    kind: "enforcement-branch",
    branchId: "edge.one.main",
    result: "passed",
  },
  runtimeObservation: {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: { fixtureId: "edge.one.main.closed" },
    legacyObservationCount: 0,
    typedDecisions: [],
  },
};
const pass = {
  fixtureId: "edge.one.main.closed",
  outcome: "passed",
  executor: "bun:test",
  artifactDigest: sha(passEvidence),
  bindingDigest: executionBindingDigest({
    bindings: {
      ...bindings,
      implementationManifestDigest: sha(implementation),
    },
    target,
    fixtureCatalogDigest,
  }),
  evidence: passEvidence,
};
const validateRuntimeObservation = (observation, recipe) => {
  if (observation?.invocation?.fixtureId !== recipe.fixtureId) {
    throw new Error("test runtime observation did not execute its recipe");
  }
  return recipe.terminalObservedKey;
};
const reportValidation = { recipeCatalog, validateRuntimeObservation };
const buildTestReport = (options) =>
  buildConformanceReport({ ...reportValidation, ...options });

describe("capsec target conformance", () => {
  test("strict schema requires exact output evidence only for a conformant report", () => {
    const schema = readSchema("conformance-report.schema.json");
    const validate = compileConformanceSchema(schema);
    const schemaBindings = {
      ...bindings,
      sourceTreeDigest: sha("source-tree"),
      engine: {
        ...bindings.engine,
        binaryDigest: sha("engine-binary"),
      },
      vocabularyDigest: sha("vocabulary"),
      registryDigest: sha("registry"),
      recipeCatalogDigest: bindings.recipeCatalogDigest,
      publicSurfaceExecutionDigest: sha("public-surface-execution"),
      outputDispositionEvidenceRawContentDigest: sha(
        "output-disposition-evidence",
      ),
    };
    const schemaExecutionBinding = {
      ...passExecutionBinding,
      sourceRevision: schemaBindings.sourceRevision,
      sourceTreeDigest: schemaBindings.sourceTreeDigest,
      engine: schemaBindings.engine,
      vocabularyDigest: schemaBindings.vocabularyDigest,
      registryDigest: schemaBindings.registryDigest,
      recipeCatalogDigest: schemaBindings.recipeCatalogDigest,
      publicSurfaceExecutionDigest: schemaBindings.publicSurfaceExecutionDigest,
    };
    const schemaEvidence = {
      ...pass.evidence,
      engineBinaryDigest: schemaBindings.engine.binaryDigest,
      executionBinding: schemaExecutionBinding,
    };
    const schemaPass = {
      ...pass,
      artifactDigest: sha(schemaEvidence),
      bindingDigest: executionBindingDigest({
        bindings: {
          ...schemaBindings,
          implementationManifestDigest: sha(implementation),
        },
        target,
        fixtureCatalogDigest,
      }),
      evidence: schemaEvidence,
    };
    const incompleteBindings = structuredClone(schemaBindings);
    delete incompleteBindings.outputDispositionEvidenceRawContentDigest;
    const incomplete = buildTestReport({
      coverage,
      implementation,
      target,
      executions: [],
      bindings: incompleteBindings,
      digestContract,
    });
    expect(validate(incomplete)).toBe(true);

    const conformant = buildTestReport({
      coverage,
      implementation,
      target,
      executions: [schemaPass],
      bindings: schemaBindings,
      digestContract,
    });
    expect(validate(conformant)).toBe(true);

    const missingEvidence = structuredClone(conformant);
    delete missingEvidence.bindings.outputDispositionEvidenceRawContentDigest;
    expect(validate(missingEvidence)).toBe(false);
    expect(validate.errors).toContainEqual(
      expect.objectContaining({
        instancePath: "/bindings",
        keyword: "required",
        params: {
          missingProperty: "outputDispositionEvidenceRawContentDigest",
        },
      }),
    );

    const malformedEvidence = structuredClone(conformant);
    malformedEvidence.bindings.outputDispositionEvidenceRawContentDigest =
      "sha256-invalid";
    expect(validate(malformedEvidence)).toBe(false);

    const missingConditionalType = structuredClone(schema);
    delete missingConditionalType.allOf[0].then.properties.bindings.type;
    expect(() => compileConformanceSchema(missingConditionalType)).toThrow(
      /strict mode: missing type "object" for keyword "required"/u,
    );

    const missingConditionalProperty = structuredClone(schema);
    delete missingConditionalProperty.allOf[0].then.properties.bindings
      .properties;
    expect(() => compileConformanceSchema(missingConditionalProperty)).toThrow(
      /strict mode: required property "outputDispositionEvidenceRawContentDigest" is not defined/u,
    );
  });

  test("selects one declared target explicitly once the matrix has multiple candidates", () => {
    const windowsTarget = {
      triple: "x86_64-pc-windows-msvc",
      features: ["native-lockdown"],
    };
    const rules = {
      initialProfile: { candidateTargets: [target, windowsTarget] },
    };
    expect(selectCandidateTarget(rules, windowsTarget.triple)).toEqual(
      windowsTarget,
    );
    expect(() => selectCandidateTarget(rules)).toThrow(/--target is required/);
    expect(() => selectCandidateTarget(rules, "unknown-target")).toThrow(
      /exactly one declared candidate/,
    );
    expect(() =>
      selectCandidateTarget(
        {
          initialProfile: {
            candidateTargets: [
              target,
              { ...target, features: ["native-compartments"] },
            ],
          },
        },
        target.triple,
      ),
    ).toThrow(/exactly one declared candidate/);
    expect(
      selectCandidateTarget({
        initialProfile: { candidateTargets: [target] },
      }),
    ).toEqual(target);
  });

  test("binds each fixture only to the selected branch that owns it", () => {
    const multiBranchImplementation = {
      surfaces: [
        {
          edgeId: "edge.one",
          observedKey: "native-op:testClosed",
          branchId: "edge.one.default",
          enforcementBranchId: "edge.one.default",
          enforcementRoute: { terminalObservedKey: "native-op:testClosed" },
          targetVariant: "default",
          targetApplicability: { kind: "fallback" },
          fixtureObligations: ["edge.one.default.closed"],
        },
        {
          edgeId: "edge.one",
          observedKey: "native-op:testClosed",
          branchId: "edge.one.binary",
          enforcementBranchId: "edge.one.binary",
          enforcementRoute: { terminalObservedKey: "native-op:testClosed" },
          targetVariant: "binary",
          targetApplicability: { kind: "runtime-variant", value: "binary" },
          fixtureObligations: ["edge.one.binary.closed"],
        },
      ],
    };
    const catalog = fixtureCatalogForTarget({
      coverage,
      implementation: multiBranchImplementation,
      target,
    });
    expect(catalog[0].implementationBranchIds).toEqual([
      "edge.one.binary",
      "edge.one.default",
    ]);
    expect(
      fixtureExecutionPlan(catalog, "edge.one.binary.closed"),
    ).toMatchObject({
      implementationBranchIds: ["edge.one.binary"],
      enforcementBranchIds: ["edge.one.binary"],
      expectedObservation: {
        kind: "enforcement-branch",
        branchId: "edge.one.binary",
      },
      terminalObservedKey: "native-op:testClosed",
      classification: "closed",
      actionIds: [],
    });
    expect(
      fixtureExecutionPlan(catalog, "edge.one.default.closed"),
    ).toMatchObject({
      implementationBranchIds: ["edge.one.default"],
      enforcementBranchIds: ["edge.one.default"],
    });
  });

  test("binds mixed closed branches only to their exact target", () => {
    const mixedCoverage = {
      edges: [
        {
          id: "edge.mixed",
          classification: "effects",
          surface: { kind: "native-op", name: "mixed" },
          effects: [{ cap: "fs:write" }],
          effectMode: "conditional",
          logicalBranches: [
            {
              id: "write-apple",
              when: [{ fact: "runtime.target.os", equals: "apple" }],
              effects: [{ cap: "fs:write" }],
            },
            {
              id: "closed-windows",
              when: [{ fact: "runtime.target.os", equals: "windows" }],
              disposition: "closed",
              cap: "fs:unbound-mutation",
              rationale: "closed before lookup",
            },
          ],
        },
      ],
    };
    const mixedImplementation = {
      surfaces: [
        {
          edgeId: "edge.mixed",
          observedKey: "native-op:mixed",
          branchId: "edge.mixed.main",
          enforcementBranchId: "edge.mixed.main",
          enforcementRoute: { terminalObservedKey: "native-op:mixed" },
          targetVariant: "all",
          targetApplicability: { kind: "all" },
          fixtureObligations: [
            "edge.mixed.main.logical.write-apple.allow",
            "edge.mixed.main.logical.closed-windows.closed",
          ],
        },
      ],
    };
    const appleCatalog = fixtureCatalogForTarget({
      coverage: mixedCoverage,
      implementation: mixedImplementation,
      target,
    });
    expect(appleCatalog[0].requiredFixtures).toEqual([
      "edge.mixed.main.logical.write-apple.allow",
    ]);
    expect(appleCatalog[0].fixtureBindings[0]).toMatchObject({
      classifications: ["effects"],
      actionIds: ["fs:write"],
    });

    const windowsCatalog = fixtureCatalogForTarget({
      coverage: mixedCoverage,
      implementation: mixedImplementation,
      target: {
        triple: "x86_64-pc-windows-msvc",
        features: ["native-lockdown"],
      },
    });
    expect(windowsCatalog[0].requiredFixtures).toEqual([
      "edge.mixed.main.logical.closed-windows.closed",
    ]);
    expect(windowsCatalog[0].fixtureBindings[0]).toMatchObject({
      classifications: ["closed"],
      actionIds: [],
    });
  });

  test("inventory obligations without executions remain incomplete", () => {
    const incompleteBindings = structuredClone(bindings);
    delete incompleteBindings.outputDispositionEvidenceRawContentDigest;
    const report = buildTestReport({
      coverage,
      implementation,
      target,
      executions: [],
      bindings: incompleteBindings,
      digestContract,
    });
    expect(report.status).toBe("incomplete");
    expect(report.summary).toMatchObject({
      requiredFixtures: 1,
      passedFixtures: 0,
      missingFixtures: 1,
    });
    expect(report.executions).toEqual([]);
    expect(
      report.bindings.outputDispositionEvidenceRawContentDigest,
    ).toBeUndefined();
    expect(() => assertReportMayAdvertise(report)).toThrow(
      /cannot advertise without .*output-disposition evidence bindings/,
    );
  });

  test("does not turn an internal recipe classification into execution credit", () => {
    const internalCatalog = structuredClone(recipeCatalog);
    internalCatalog.recipes[0].status = "internally-verified";
    delete internalCatalog.recipeCatalogDigest;
    internalCatalog.recipeCatalogDigest = sha(internalCatalog);
    const internalBindings = {
      ...bindings,
      recipeCatalogDigest: internalCatalog.recipeCatalogDigest,
    };
    const report = buildConformanceReport({
      coverage,
      implementation,
      target,
      executions: [],
      bindings: internalBindings,
      digestContract,
      recipeCatalog: internalCatalog,
      validateRuntimeObservation,
    });
    expect(report.status).toBe("incomplete");
    expect(report.summary).toMatchObject({
      requiredFixtures: 1,
      passedFixtures: 0,
      missingFixtures: 1,
    });
    expect(report.executions).toEqual([]);
    expect(report.cells[0].missingFixtures).toEqual([
      "edge.one.main.closed",
    ]);
  });

  test("credits an internal invariant only from executed source-bound evidence", () => {
    const internalCatalog = structuredClone(recipeCatalog);
    const internalRecipe = internalCatalog.recipes[0];
    internalRecipe.status = "internally-verified";
    internalRecipe.scenario = "attribution-missing-deny";
    internalRecipe.internalInvariantProof = internalInvariantProofPlan(
      internalRecipe.scenario,
    );
    delete internalCatalog.recipeCatalogDigest;
    internalCatalog.recipeCatalogDigest = sha(internalCatalog);
    const internalBindings = {
      ...bindings,
      recipeCatalogDigest: internalCatalog.recipeCatalogDigest,
    };
    const internalExecutionBinding = {
      ...passExecutionBinding,
      recipeCatalogDigest: internalCatalog.recipeCatalogDigest,
    };
    const internalBindingDigest = executionBindingDigest({
      bindings: {
        ...internalBindings,
        implementationManifestDigest: sha(implementation),
      },
      target,
      fixtureCatalogDigest,
    });
    const proof = internalRecipe.internalInvariantProof;
    const internalEvidence = {
      evidenceSchema: "ibex/capsec-internal-invariant-fixture-evidence/1",
      fixtureId: internalRecipe.fixtureId,
      command: [...INTERNAL_INVARIANT_COMMAND],
      exitCode: 0,
      resultMarker: `ibex-capsec-internal-invariant:${internalRecipe.fixtureId}:passed`,
      planDigest: internalRecipe.planDigest,
      engineBinaryDigest: bindings.engine.binaryDigest,
      fixturePlan,
      executionBinding: internalExecutionBinding,
      observation: {
        ...fixturePlan.expectedObservation,
        result: "passed",
      },
      proofPlan: proof,
      runtimeObservation: {
        observationSchema:
          "ibex/capsec-runtime-internal-invariant-observation/1",
        scenario: internalRecipe.scenario,
        mechanism: proof.mechanism,
        proofPlanDigest: proof.proofPlanDigest,
        result: {
          kind: "callback-security-invariant",
          scenario: internalRecipe.scenario,
          outcome: "passed",
        },
        legacyObservationCount: 0,
        typedDecisions: [],
      },
    };
    const internalExecution = {
      fixtureId: internalRecipe.fixtureId,
      outcome: "passed",
      executor: INTERNAL_INVARIANT_EXECUTOR,
      artifactDigest: sha(internalEvidence),
      bindingDigest: internalBindingDigest,
      evidence: internalEvidence,
    };
    const report = buildConformanceReport({
      coverage,
      implementation,
      target,
      executions: [internalExecution],
      bindings: internalBindings,
      digestContract,
      recipeCatalog: internalCatalog,
      validateRuntimeObservation,
      validateInternalInvariantExecution:
        validateInternalInvariantFixtureExecution,
    });
    expect(report.status).toBe("conformant");
    expect(report.summary.passedFixtures).toBe(1);

    const tampered = structuredClone(internalExecution);
    tampered.evidence.runtimeObservation.mechanism =
      "catalog-label-without-execution";
    tampered.artifactDigest = sha(tampered.evidence);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [tampered],
        bindings: internalBindings,
        digestContract,
        recipeCatalog: internalCatalog,
        validateRuntimeObservation,
        validateInternalInvariantExecution:
          validateInternalInvariantFixtureExecution,
      }),
    ).toThrow(/did not execute its proof/);
  });

  test("report construction requires recipe-aware runtime validation", () => {
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [],
        bindings,
        digestContract,
        recipeCatalog,
      }),
    ).toThrow(/runtime-observation validator/);
    const tamperedCatalog = structuredClone(recipeCatalog);
    tamperedCatalog.recipes[0].status = "unresolved";
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [],
        bindings,
        digestContract,
        recipeCatalog: tamperedCatalog,
      }),
    ).toThrow(/digest-bound recipe catalog/);
  });

  test("a unique bound passing execution completes its exact cell", () => {
    const report = buildTestReport({
      coverage,
      implementation,
      target,
      executions: [pass],
      bindings,
      digestContract,
    });
    expect(report.status).toBe("conformant");
    expect(report.summary).toMatchObject({
      conformantCells: 1,
      requiredFixtures: 1,
      passedFixtures: 1,
    });
    expect(report.executions).toEqual([pass]);
    expect(() => assertReportMayAdvertise(report)).not.toThrow();
    const unbound = structuredClone(report);
    delete unbound.bindings.publicSurfaceExecutionDigest;
    expect(() => assertReportMayAdvertise(unbound)).toThrow(
      /without recipe, public-surface, and output-disposition evidence bindings/,
    );
    const noOutputEvidence = structuredClone(report);
    delete noOutputEvidence.bindings.outputDispositionEvidenceRawContentDigest;
    expect(() => assertReportMayAdvertise(noOutputEvidence)).toThrow(
      /output-disposition evidence bindings/,
    );
    expect(() =>
      validateConformanceReportSemantics(report, {
        coverage,
        implementation,
        target,
        digestContract,
        ...reportValidation,
      }),
    ).not.toThrow();

    const tampered = structuredClone(report);
    tampered.summary.passedFixtures = 0;
    expect(() =>
      validateConformanceReportSemantics(tampered, {
        coverage,
        implementation,
        target,
        digestContract,
        ...reportValidation,
      }),
    ).toThrow(/derived evidence/);

    const swappedOutputEvidence = structuredClone(report);
    swappedOutputEvidence.bindings.outputDispositionEvidenceRawContentDigest = `sha256-${"I".repeat(43)}`;
    expect(() =>
      validateConformanceReportSemantics(swappedOutputEvidence, {
        coverage,
        implementation,
        target,
        digestContract,
        ...reportValidation,
      }),
    ).toThrow(/execution binding/);

    const noEvidenceBindings = structuredClone(bindings);
    delete noEvidenceBindings.outputDispositionEvidenceRawContentDigest;
    const passWithoutEvidenceBinding = {
      ...pass,
      bindingDigest: executionBindingDigest({
        bindings: {
          ...noEvidenceBindings,
          implementationManifestDigest: sha(implementation),
        },
        target,
        fixtureCatalogDigest,
      }),
    };
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [passWithoutEvidenceBinding],
        bindings: noEvidenceBindings,
        digestContract,
      }),
    ).toThrow(
      /conformant report requires verified output-disposition evidence/,
    );
  });

  test("credits seven fixture records while the residual target remains incomplete", () => {
    const fixtureIds = Array.from(
      { length: 8 },
      (_, index) => `edge.pilot.main.fixture-${index + 1}`,
    );
    const pilotCoverage = {
      edges: [
        {
          id: "edge.pilot",
          classification: "closed",
          surface: { kind: "native-op", name: "pilot" },
        },
      ],
    };
    const pilotImplementation = {
      surfaces: [
        {
          edgeId: "edge.pilot",
          observedKey: "native-op:pilot",
          branchId: "edge.pilot.main",
          enforcementBranchId: "edge.pilot.main",
          enforcementRoute: { terminalObservedKey: "native-op:pilot" },
          targetVariant: "all",
          targetApplicability: { kind: "all" },
          fixtureObligations: fixtureIds,
        },
      ],
    };
    const pilotCatalog = fixtureCatalogForTarget({
      coverage: pilotCoverage,
      implementation: pilotImplementation,
      target,
    });
    const pilotFixtureCatalogDigest = sha(pilotCatalog);
    const pilotImplementationDigest = sha(pilotImplementation);
    const pilotRecipeCatalog = {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
      profile: "ibex/capsec/1",
      target,
      recipes: fixtureIds.slice(0, 7).map((fixtureId) => {
        const plan = fixtureExecutionPlan(pilotCatalog, fixtureId);
        return {
          fixtureId,
          status: "fully-executable",
          planDigest: sha(plan),
          terminalObservedKey: plan.terminalObservedKey,
        };
      }),
    };
    pilotRecipeCatalog.recipeCatalogDigest = sha(pilotRecipeCatalog);
    const pilotBindings = {
      ...bindings,
      recipeCatalogDigest: pilotRecipeCatalog.recipeCatalogDigest,
    };
    const pilotExecutionBinding = {
      sourceRevision: pilotBindings.sourceRevision,
      sourceTreeDigest: pilotBindings.sourceTreeDigest,
      target,
      engine: pilotBindings.engine,
      vocabularyDigest: pilotBindings.vocabularyDigest,
      registryDigest: pilotBindings.registryDigest,
      implementationManifestDigest: pilotImplementationDigest,
      fixtureCatalogDigest: pilotFixtureCatalogDigest,
      recipeCatalogDigest: pilotBindings.recipeCatalogDigest,
      publicSurfaceExecutionDigest: pilotBindings.publicSurfaceExecutionDigest,
    };
    const pilotBindingDigest = executionBindingDigest({
      bindings: {
        ...pilotBindings,
        implementationManifestDigest: pilotImplementationDigest,
      },
      target,
      fixtureCatalogDigest: pilotFixtureCatalogDigest,
    });
    const pilotExecutions = fixtureIds.slice(0, 7).map((fixtureId) => {
      const plan = fixtureExecutionPlan(pilotCatalog, fixtureId);
      const evidence = {
        evidenceSchema: "ibex/capsec-fixture-evidence/2",
        fixtureId,
        command: ["cargo", "test", "fixture-pilot"],
        exitCode: 0,
        resultMarker: `ibex-capsec-fixture:${fixtureId}:passed`,
        planDigest: sha(plan),
        engineBinaryDigest: bindings.engine.binaryDigest,
        fixturePlan: plan,
        executionBinding: pilotExecutionBinding,
        observation: { ...plan.expectedObservation, result: "passed" },
        runtimeObservation: {
          observationSchema: "ibex/capsec-runtime-public-observation/1",
          invocation: { fixtureId },
          legacyObservationCount: 0,
          typedDecisions: [],
        },
      };
      return {
        fixtureId,
        outcome: "passed",
        executor: "fixture-pilot",
        artifactDigest: sha(evidence),
        bindingDigest: pilotBindingDigest,
        evidence,
      };
    });
    const report = buildTestReport({
      coverage: pilotCoverage,
      implementation: pilotImplementation,
      target,
      executions: pilotExecutions,
      bindings: pilotBindings,
      digestContract,
      recipeCatalog: pilotRecipeCatalog,
    });
    expect(report.status).toBe("incomplete");
    expect(report.summary).toMatchObject({
      requiredFixtures: 8,
      passedFixtures: 7,
      missingFixtures: 1,
      failedFixtures: 0,
    });
    expect(report.executions).toHaveLength(7);
    expect(() => assertReportMayAdvertise(report)).toThrow(/incomplete/);
  });

  test("rejects unknown, duplicate, and unbound execution claims", () => {
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [],
        bindings: {
          ...bindings,
          engine: { ...bindings.engine, structuralFeatures: [] },
        },
        digestContract,
      }),
    ).toThrow(/exact loaded Hermes object/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, fixtureId: "invented" }],
        bindings,
        digestContract,
      }),
    ).toThrow(/unknown fixture/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [pass, pass],
        bindings,
        digestContract,
      }),
    ).toThrow(/duplicate execution/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, artifactDigest: undefined }],
        bindings,
        digestContract,
      }),
    ).toThrow(/artifact digest/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, bindingDigest: `sha256-${"Z".repeat(43)}` }],
        bindings,
        digestContract,
      }),
    ).toThrow(/binding/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [
          {
            ...pass,
            artifactDigest: sha({
              ...pass.evidence,
              planDigest: `sha256-${"Z".repeat(43)}`,
            }),
            evidence: {
              ...pass.evidence,
              planDigest: `sha256-${"Z".repeat(43)}`,
            },
          },
        ],
        bindings,
        digestContract,
      }),
    ).toThrow(/exact fixture plan/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [
          {
            ...pass,
            artifactDigest: sha({
              ...pass.evidence,
              observation: {
                ...pass.evidence.observation,
                branchId: "wrong.branch",
              },
            }),
            evidence: {
              ...pass.evidence,
              observation: {
                ...pass.evidence.observation,
                branchId: "wrong.branch",
              },
            },
          },
        ],
        bindings,
        digestContract,
      }),
    ).toThrow(/observed branch\/result/);
    const wrongRuntimeEvidence = {
      ...pass.evidence,
      runtimeObservation: {
        ...pass.evidence.runtimeObservation,
        invocation: { fixtureId: "another.fixture" },
      },
    };
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [
          {
            ...pass,
            artifactDigest: sha(wrongRuntimeEvidence),
            evidence: wrongRuntimeEvidence,
          },
        ],
        bindings,
        digestContract,
      }),
    ).toThrow(/did not execute its recipe/);
    expect(() =>
      buildTestReport({
        coverage,
        implementation,
        target,
        executions: [
          {
            ...pass,
            artifactDigest: sha({ command: ["bun", "test"] }),
            evidence: {
              ...pass.evidence,
              command: ["bun", "test"],
              resultMarker: "generic suite passed",
            },
          },
        ],
        bindings,
        digestContract,
      }),
    ).toThrow(/outcome disagrees/);
  });
});
