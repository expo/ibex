import { describe, expect, test } from "bun:test";

import {
  buildRestrictedTargetReport,
  loadRestrictedReportAuthorities,
  restrictedReportPathForTarget,
  taggedDigest,
  validateRestrictedTargetReport,
} from "./restricted-exact-target-report.mjs";

const authorities = loadRestrictedReportAuthorities();

function fixture() {
  const digest = (name) => taggedDigest(Buffer.from(name, "utf8"));
  const target = authorities.projection.candidateTargets[0];
  const bindings = {
    sourceRevision: "248b913d12e1547ca06162158e20815f7ebc7350",
    sourceTreeDigest: digest("tree"),
    target,
    engine: {
      artifactPath: "ios/Frameworks/hermesvm.framework/hermesvm",
      kind: "hermes",
      binaryDigest: digest("engine"),
      patchIdentity: "exact-engine-test",
      targetArchitecture: "aarch64",
      structuralFeatures: target.features,
    },
    definitionRawContentDigest: taggedDigest(authorities.rawAuthorities.definition),
    projectionRawContentDigest: taggedDigest(authorities.rawAuthorities.projection),
    coverageRawContentDigest: taggedDigest(authorities.rawAuthorities.coverage),
    implementationManifestRawContentDigest: taggedDigest(
      authorities.rawAuthorities.implementationManifest,
    ),
    fixturePlanRawContentDigest: taggedDigest(authorities.rawAuthorities.fixturePlan),
    reportSchemaRawContentDigest: taggedDigest(authorities.rawAuthorities.reportSchema),
  };
  const globalCorpora = authorities.fixturePlan.globalCorpora.map((row) => ({
    id: row.id,
    status: "missing",
    executionIds: [],
  }));
  return {
    ...authorities,
    bindings,
    executions: [],
    globalCorpora,
    independentReview: {
      status: "pending",
      artifactDigest: null,
      unresolvedCritical: 0,
      unresolvedHigh: 0,
    },
  };
}

function observedFixture() {
  const input = fixture();
  const projected = input.projection.rows.find((row) => row[1] === "reachable");
  const edge = input.coverage.edges.find((row) => row.id === projected[0]);
  const observation = {
    edgeId: projected[0],
    kind: "live-invocation",
    outcome: "passed",
    observedIdentity: `${edge.surface.kind}:${edge.surface.name}`,
  };
  const execution = {
    executionId: "execution.one",
    fixtureId: `restricted.live-invocation.${projected[0]}`,
    outcome: "passed",
    command: ["observer"],
    exitCode: 0,
    resultMarker: "PASS",
    artifactDigest: taggedDigest(Buffer.from("one", "utf8")),
    engineBinaryDigest: input.bindings.engine.binaryDigest,
    observations: [observation],
  };
  return { input, observation, execution };
}

describe("LLP 0033 restricted Exact target report", () => {
  test("derives review report paths from the bound target", () => {
    expect(restrictedReportPathForTarget({ triple: "aarch64-apple-darwin" })).toBe(
      "capsec/conformance/restricted-exact-aarch64-apple-darwin-report.json",
    );
    expect(restrictedReportPathForTarget({ triple: "x86_64-unknown-linux-gnu" })).toBe(
      "capsec/conformance/restricted-exact-x86_64-unknown-linux-gnu-report.json",
    );
    expect(() => restrictedReportPathForTarget({ triple: "../../forged" })).toThrow(
      "restricted report target triple is malformed",
    );
  });

  test("keeps every edge incomplete when no per-edge evidence exists", () => {
    const input = fixture();
    const report = buildRestrictedTargetReport(input);
    expect(report.status).toBe("incomplete");
    expect(report.summary.total).toBe(7347);
    expect(report.summary.conformant).toBe(0);
    expect(report.summary.incomplete).toBe(7347);
    expect(report.summary.missingObservations).toBe(14540);
    expect(report.rows.every((row) => row.executionIds.length === 0)).toBe(true);
  }, 15_000);

  test("rejects a fabricated clear-review digest", () => {
    const input = fixture();
    input.independentReview = {
      status: "clear",
      artifactDigest: taggedDigest(Buffer.from("no review artifact exists", "utf8")),
      unresolvedCritical: 0,
      unresolvedHigh: 0,
    };
    expect(() => buildRestrictedTargetReport(input)).toThrow(
      "does not reopen exactly one artifact",
    );
  }, 15_000);

  test("credits only the exact observed edge and evidence kind", () => {
    const input = fixture();
    const projected = input.projection.rows.find((row) => row[1] === "reachable");
    const edge = input.coverage.edges.find((row) => row.id === projected[0]);
    input.executions = [{
      executionId: "execution.reachable.one",
      fixtureId: `restricted.live-invocation.${projected[0]}`,
      outcome: "passed",
      command: ["restricted-observer", projected[0]],
      exitCode: 0,
      resultMarker: "RESTRICTED_OBSERVATION_PASS",
      artifactDigest: taggedDigest(Buffer.from("execution", "utf8")),
      engineBinaryDigest: input.bindings.engine.binaryDigest,
      observations: [{
        edgeId: projected[0],
        kind: "live-invocation",
        outcome: "passed",
        observedIdentity: `${edge.surface.kind}:${edge.surface.name}`,
      }],
    }];
    const report = buildRestrictedTargetReport(input);
    expect(report.summary.conformant).toBe(1);
    expect(report.summary.incomplete).toBe(7346);
    expect(report.summary.passedObservations).toBe(1);
    expect(report.summary.missingObservations).toBe(14539);
  }, 15_000);

  test("requires both source-install and live-reachability for absence", () => {
    const input = fixture();
    const projected = input.projection.rows.find(
      (row) => row[1] === "structurally-absent",
    );
    const edge = input.coverage.edges.find((row) => row.id === projected[0]);
    input.executions = [{
      executionId: "execution.absence.source",
      fixtureId: `restricted.source-install.${projected[0]}`,
      outcome: "passed",
      command: ["restricted-source-closure", projected[0]],
      exitCode: 0,
      resultMarker: "RESTRICTED_SOURCE_ABSENCE_PASS",
      artifactDigest: taggedDigest(Buffer.from("source", "utf8")),
      engineBinaryDigest: input.bindings.engine.binaryDigest,
      observations: [{
        edgeId: projected[0],
        kind: "source-install",
        outcome: "passed",
        observedIdentity: `${edge.surface.kind}:${edge.surface.name}`,
      }],
    }];
    const report = buildRestrictedTargetReport(input);
    const row = report.rows.find((candidate) => candidate.edgeId === projected[0]);
    expect(row.status).toBe("incomplete");
    expect(row.passedEvidenceKinds).toEqual(["source-install"]);
    expect(row.missingEvidenceKinds).toEqual(["live-reachability"]);
  }, 15_000);

  test("rejects duplicate per-edge observations", () => {
    const { input, execution } = observedFixture();
    input.executions = [execution, {
      ...execution,
      executionId: "execution.two",
      artifactDigest: taggedDigest(Buffer.from("two", "utf8")),
    }];
    expect(() => buildRestrictedTargetReport(input)).toThrow("duplicate restricted per-edge");
  }, 15_000);

  test("rejects evidence from a different engine", () => {
    const { input, execution } = observedFixture();
    input.executions = [{
      ...execution,
      engineBinaryDigest: taggedDigest(Buffer.from("other-engine", "utf8")),
    }];
    expect(() => buildRestrictedTargetReport(input)).toThrow("different engine");
  }, 15_000);

  test("rejects observed identity drift", () => {
    const { input, observation, execution } = observedFixture();
    input.executions = [{
      ...execution,
      observations: [{ ...observation, observedIdentity: "native-op:wrong" }],
    }];
    expect(() => buildRestrictedTargetReport(input)).toThrow("identity drift");
  }, 15_000);

  test("rejects a synthesized report summary", () => {
    const valid = buildRestrictedTargetReport(fixture());
    valid.summary.conformant = valid.summary.total;
    expect(() => validateRestrictedTargetReport(valid, fixture())).toThrow(
      /digest mismatch|not derivable/,
    );
  }, 15_000);
});
