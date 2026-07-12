import { describe, expect, test } from "bun:test";
import {
  assertReportMayAdvertise,
  buildConformanceReport,
  executionBindingDigest,
  fixtureExecutionPlan,
  fixtureCatalogForTarget,
  validateConformanceReportSemantics,
} from "./capsec-conformance.mjs";
import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const target = {
  triple: "aarch64-apple-darwin",
  features: ["native-lockdown"],
};
const coverage = { edges: [{ id: "edge.one", classification: "closed" }] };
const implementation = {
  surfaces: [
    {
      edgeId: "edge.one",
      branchId: "edge.one.main",
      enforcementBranchId: "edge.one.main",
      targetVariant: "all",
      targetApplicability: { kind: "all" },
      fixtureObligations: ["edge.one.main.closed"],
    },
  ],
};
const bindings = {
  sourceRevision: "0".repeat(40),
  sourceTreeDigest: `sha256-${"A".repeat(43)}`,
  engine: { kind: "patched-hermes", binaryDigest: `sha256-${"B".repeat(43)}` },
  vocabularyDigest: `sha256-${"D".repeat(43)}`,
  registryDigest: `sha256-${"E".repeat(43)}`,
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
const passEvidence = {
  evidenceSchema: "ibex/capsec-fixture-evidence/2",
  fixtureId: "edge.one.main.closed",
  command: ["bun", "test", "edge-one-closed.test.mjs"],
  exitCode: 0,
  resultMarker: "ibex-capsec-fixture:edge.one.main.closed:passed",
  planDigest: sha(fixturePlan),
  engineBinaryDigest: bindings.engine.binaryDigest,
  observation: {
    kind: "enforcement-branch",
    branchId: "edge.one.main",
    result: "passed",
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

  test("rejects unknown, duplicate, and unbound execution claims", () => {
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
