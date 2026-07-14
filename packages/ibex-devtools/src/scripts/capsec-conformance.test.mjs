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
import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

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
    engineArtifactPath: "/repo/ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
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

describe("capsec target conformance", () => {
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

  test("inventory obligations without executions remain incomplete", () => {
    const report = buildConformanceReport({
      coverage,
      implementation,
      target,
      executions: [],
      bindings,
      digestContract,
    });
    expect(report.status).toBe("incomplete");
    expect(report.summary).toMatchObject({
      requiredFixtures: 1,
      passedFixtures: 0,
      missingFixtures: 1,
    });
    expect(report.executions).toEqual([]);
    expect(() => assertReportMayAdvertise(report)).toThrow(/incomplete/);
  });

  test("a unique bound passing execution completes its exact cell", () => {
    const report = buildConformanceReport({
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
      /without recipe and public-surface evidence bindings/,
    );
    expect(() =>
      validateConformanceReportSemantics(report, {
        coverage,
        implementation,
        target,
        digestContract,
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
      }),
    ).toThrow(/derived evidence/);
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
    const pilotExecutionBinding = {
      sourceRevision: bindings.sourceRevision,
      sourceTreeDigest: bindings.sourceTreeDigest,
      target,
      engine: bindings.engine,
      vocabularyDigest: bindings.vocabularyDigest,
      registryDigest: bindings.registryDigest,
      implementationManifestDigest: pilotImplementationDigest,
      fixtureCatalogDigest: pilotFixtureCatalogDigest,
      recipeCatalogDigest: bindings.recipeCatalogDigest,
      publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
    };
    const pilotBindingDigest = executionBindingDigest({
      bindings: {
        ...bindings,
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
    const report = buildConformanceReport({
      coverage: pilotCoverage,
      implementation: pilotImplementation,
      target,
      executions: pilotExecutions,
      bindings,
      digestContract,
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
      buildConformanceReport({
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
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, fixtureId: "invented" }],
        bindings,
        digestContract,
      }),
    ).toThrow(/unknown fixture/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [pass, pass],
        bindings,
        digestContract,
      }),
    ).toThrow(/duplicate execution/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, artifactDigest: undefined }],
        bindings,
        digestContract,
      }),
    ).toThrow(/artifact digest/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{ ...pass, bindingDigest: `sha256-${"Z".repeat(43)}` }],
        bindings,
        digestContract,
      }),
    ).toThrow(/binding/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{
          ...pass,
          artifactDigest: sha({ ...pass.evidence, planDigest: `sha256-${"Z".repeat(43)}` }),
          evidence: { ...pass.evidence, planDigest: `sha256-${"Z".repeat(43)}` },
        }],
        bindings,
        digestContract,
      }),
    ).toThrow(/exact fixture plan/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{
          ...pass,
          artifactDigest: sha({
            ...pass.evidence,
            observation: { ...pass.evidence.observation, branchId: "wrong.branch" },
          }),
          evidence: {
            ...pass.evidence,
            observation: { ...pass.evidence.observation, branchId: "wrong.branch" },
          },
        }],
        bindings,
        digestContract,
      }),
    ).toThrow(/observed branch\/result/);
    expect(() =>
      buildConformanceReport({
        coverage,
        implementation,
        target,
        executions: [{
          ...pass,
          artifactDigest: sha({ command: ["bun", "test"] }),
          evidence: {
            ...pass.evidence,
            command: ["bun", "test"],
            resultMarker: "generic suite passed",
          },
        }],
        bindings,
        digestContract,
      }),
    ).toThrow(/outcome disagrees/);
  });
});
