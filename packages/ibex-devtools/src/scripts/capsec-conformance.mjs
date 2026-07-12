/**
 * Build an exact-target conformance report from independently recorded fixture
 * executions. Inventory rows define obligations; they never count as results.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target may advertise only when every selected branch obligation passed on
 * the exact source, engine binary, target, and semantic identities.
 */

import crypto from "node:crypto";
import { canonicalJson, computeDomainDigest } from "./capsec-contract.mjs";
import { absenceFixtureForTarget } from "./capsec-fixture-obligations.mjs";
import { applicableImplementationBranchIds } from "./capsec-target-branches.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;

function fixturePlans(catalog) {
  const plans = new Map();
  const fixtureIds = canonicalSet(
    catalog.flatMap((cell) => cell.requiredFixtures),
  );
  for (const fixtureId of fixtureIds) {
    const cells = catalog.filter((cell) =>
      cell.requiredFixtures.includes(fixtureId),
    );
    const edgeIds = canonicalSet(cells.map((cell) => cell.edgeId));
    const implementationBranchIds = canonicalSet(
      cells.flatMap((cell) => cell.implementationBranchIds),
    );
    const enforcementBranchIds = canonicalSet(
      cells.flatMap((cell) => cell.enforcementBranchIds),
    );
    let expectedObservation;
    if (enforcementBranchIds.length === 1) {
      expectedObservation = {
        kind: "enforcement-branch",
        branchId: enforcementBranchIds[0],
      };
    } else if (
      enforcementBranchIds.length === 0 &&
      edgeIds.length === 1 &&
      implementationBranchIds.length === 0
    ) {
      expectedObservation = { kind: "target-absence", edgeId: edgeIds[0] };
    } else {
      throw new Error(
        `${fixtureId}: fixture plan does not identify exactly one observable enforcement branch`,
      );
    }
    plans.set(fixtureId, {
      fixtureId,
      edgeIds,
      implementationBranchIds,
      enforcementBranchIds,
      expectedObservation,
    });
  }
  return plans;
}

export function fixtureExecutionPlan(catalog, fixtureId) {
  return fixturePlans(catalog).get(fixtureId) ?? null;
}

function validateExecutionEvidence(
  execution,
  { plan, engineBinaryDigest },
) {
  const evidence = execution.evidence;
  if (
    evidence?.evidenceSchema !== "ibex/capsec-fixture-evidence/2" ||
    evidence.fixtureId !== execution.fixtureId ||
    !Array.isArray(evidence.command) || evidence.command.length === 0 ||
    !evidence.command.every((part) => typeof part === "string" && part.length > 0) ||
    !Number.isSafeInteger(evidence.exitCode) ||
    typeof evidence.resultMarker !== "string"
  ) {
    throw new Error(`${execution.fixtureId}: malformed fixture-specific evidence`);
  }
  const passedMarker = `ibex-capsec-fixture:${execution.fixtureId}:passed`;
  const failedMarker = `ibex-capsec-fixture:${execution.fixtureId}:failed`;
  const derivedOutcome = evidence.exitCode === 0 && evidence.resultMarker === passedMarker
    ? "passed"
    : evidence.resultMarker === failedMarker || evidence.exitCode !== 0
      ? "failed"
      : null;
  if (!derivedOutcome || execution.outcome !== derivedOutcome) {
    throw new Error(`${execution.fixtureId}: outcome disagrees with executed evidence`);
  }
  if (evidence.planDigest !== digest(plan)) {
    throw new Error(`${execution.fixtureId}: evidence does not bind the exact fixture plan`);
  }
  if (evidence.engineBinaryDigest !== engineBinaryDigest) {
    throw new Error(`${execution.fixtureId}: evidence did not execute the bound engine artifact`);
  }
  const expectedObservation = {
    ...plan.expectedObservation,
    result: derivedOutcome,
  };
  if (canonicalJson(evidence.observation) !== canonicalJson(expectedObservation)) {
    throw new Error(
      `${execution.fixtureId}: observed branch/result disagrees with the fixture plan`,
    );
  }
  if (execution.artifactDigest !== digest(evidence)) {
    throw new Error(`${execution.fixtureId}: artifact digest does not match fixture evidence`);
  }
}

export function executionBindingDigest({
  bindings,
  target,
  fixtureCatalogDigest,
}) {
  return digest({
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    engine: bindings.engine,
    target,
    vocabularyDigest: bindings.vocabularyDigest,
    registryDigest: bindings.registryDigest,
    implementationManifestDigest: bindings.implementationManifestDigest,
    fixtureCatalogDigest,
  });
}

export function fixtureCatalogForTarget({ coverage, implementation, target }) {
  const rowsByEdge = new Map();
  for (const row of implementation.surfaces) {
    const rows = rowsByEdge.get(row.edgeId) ?? [];
    rows.push(row);
    rowsByEdge.set(row.edgeId, rows);
  }
  return coverage.edges.map((edge) => {
    const rows = rowsByEdge.get(edge.id) ?? [];
    const branchIds = applicableImplementationBranchIds(rows, target);
    const selected = branchIds.map((branchId) => {
      const row = rows.find((candidate) => candidate.branchId === branchId);
      if (!row)
        throw new Error(`${edge.id}: selected unknown branch ${branchId}`);
      return row;
    });
    return {
      edgeId: edge.id,
      implementationBranchIds: canonicalSet(branchIds),
      enforcementBranchIds: canonicalSet(
        selected.map((row) => row.enforcementBranchId),
      ),
      requiredFixtures: canonicalSet(
        selected.length === 0
          ? [absenceFixtureForTarget(edge.id, target)]
          : selected.flatMap((row) => row.fixtureObligations),
      ),
    };
  });
}

export function buildConformanceReport({
  coverage,
  implementation,
  target,
  executions,
  bindings,
  digestContract,
}) {
  const catalog = fixtureCatalogForTarget({ coverage, implementation, target });
  const expected = new Set(catalog.flatMap((cell) => cell.requiredFixtures));
  const plans = fixturePlans(catalog);
  const implementationManifestDigest = digest(implementation);
  const fixtureCatalogDigest = digest(catalog);
  const completeBindings = {
    ...bindings,
    implementationManifestDigest,
  };
  const requiredBindingDigest = executionBindingDigest({
    bindings: completeBindings,
    target,
    fixtureCatalogDigest,
  });
  const results = new Map();
  for (const execution of executions) {
    if (!expected.has(execution.fixtureId)) {
      throw new Error(
        `execution references unknown fixture ${execution.fixtureId}`,
      );
    }
    if (results.has(execution.fixtureId)) {
      throw new Error(`duplicate execution for fixture ${execution.fixtureId}`);
    }
    if (
      !execution.executor ||
      !/^sha256-[A-Za-z0-9_-]{43}$/.test(execution.artifactDigest ?? "")
    ) {
      throw new Error(
        `${execution.fixtureId}: execution lacks executor or artifact digest`,
      );
    }
    validateExecutionEvidence(execution, {
      plan: plans.get(execution.fixtureId),
      engineBinaryDigest: bindings.engine.binaryDigest,
    });
    if (execution.bindingDigest !== requiredBindingDigest) {
      throw new Error(
        `${execution.fixtureId}: execution binding does not match report inputs`,
      );
    }
    if (execution.outcome !== "passed" && execution.outcome !== "failed") {
      throw new Error(`${execution.fixtureId}: invalid execution outcome`);
    }
    results.set(execution.fixtureId, execution.outcome);
  }
  const cells = catalog.map((cell) => {
    const passedFixtures = cell.requiredFixtures.filter(
      (id) => results.get(id) === "passed",
    );
    const failedFixtures = cell.requiredFixtures.filter(
      (id) => results.get(id) === "failed",
    );
    const missingFixtures = cell.requiredFixtures.filter(
      (id) => !results.has(id),
    );
    return {
      ...cell,
      status:
        failedFixtures.length === 0 && missingFixtures.length === 0
          ? "conformant"
          : "incomplete",
      passedFixtures,
      missingFixtures,
      failedFixtures,
    };
  });
  const report = {
    conformanceSchema: "ibex/capsec-conformance/1",
    profile: "ibex/capsec/1",
    status: cells.every((cell) => cell.status === "conformant")
      ? "conformant"
      : "incomplete",
    bindings: {
      ...bindings,
      target,
      implementationManifestDigest,
      fixtureCatalogDigest,
    },
    summary: {
      cells: cells.length,
      conformantCells: cells.filter((cell) => cell.status === "conformant")
        .length,
      incompleteCells: cells.filter((cell) => cell.status !== "conformant")
        .length,
      requiredFixtures: expected.size,
      passedFixtures: [...results.values()].filter(
        (outcome) => outcome === "passed",
      ).length,
      missingFixtures: cells.reduce(
        (sum, cell) => sum + cell.missingFixtures.length,
        0,
      ),
      failedFixtures: cells.reduce(
        (sum, cell) => sum + cell.failedFixtures.length,
        0,
      ),
    },
    executions: [...executions].sort((left, right) =>
      compareText(left.fixtureId, right.fixtureId),
    ),
    cells,
  };
  report.conformanceDigest = computeDomainDigest(
    digestContract.domains.conformance,
    report,
    digestContract.projections.conformance.omitFields,
  );
  return report;
}

export function assertReportMayAdvertise(report) {
  if (report.status !== "conformant")
    throw new Error("incomplete conformance report cannot advertise a target");
  if (
    report.summary.incompleteCells !== 0 ||
    report.summary.missingFixtures !== 0 ||
    report.summary.failedFixtures !== 0
  ) {
    throw new Error(
      "conformance summary cannot advertise with incomplete evidence",
    );
  }
  if (report.summary.passedFixtures !== report.summary.requiredFixtures) {
    throw new Error("conformance report did not pass every required fixture");
  }
}

export function validateConformanceReportSemantics(
  report,
  { coverage, implementation, target, digestContract },
) {
  if (canonicalJson(report.bindings?.target) !== canonicalJson(target)) {
    throw new Error(
      "conformance report target does not match requested target",
    );
  }
  const expected = buildConformanceReport({
    coverage,
    implementation,
    target,
    executions: report.executions,
    bindings: {
      sourceRevision: report.bindings.sourceRevision,
      sourceTreeDigest: report.bindings.sourceTreeDigest,
      engine: report.bindings.engine,
      vocabularyDigest: report.bindings.vocabularyDigest,
      registryDigest: report.bindings.registryDigest,
    },
    digestContract,
  });
  if (canonicalJson(report) !== canonicalJson(expected)) {
    throw new Error("conformance report disagrees with derived evidence");
  }
}
