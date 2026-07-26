/**
 * Build an exact-target conformance report from independently recorded fixture
 * executions. Inventory rows define obligations; they never count as results.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target may advertise only when every selected branch obligation passed on
 * the exact source, engine binary, target, and semantic identities.
 */

import crypto from "node:crypto";
import path from "node:path";
import { canonicalJson, computeDomainDigest } from "./capsec-contract.mjs";
import { absenceFixtureForTarget } from "./capsec-fixture-obligations.mjs";
import { applicableImplementationBranchIds } from "./capsec-target-branches.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;

export function selectCandidateTarget(rules, requestedTriple) {
  const candidates = rules?.initialProfile?.candidateTargets;
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error("no candidate target is declared");
  }
  if (requestedTriple === undefined) {
    if (candidates.length !== 1) {
      throw new Error(
        "--target is required when more than one candidate target is declared",
      );
    }
    return candidates[0];
  }
  const matches = candidates.filter(
    (candidate) => candidate?.triple === requestedTriple,
  );
  if (matches.length !== 1) {
    throw new Error(
      `--target ${JSON.stringify(requestedTriple)} must select exactly one declared candidate target`,
    );
  }
  return matches[0];
}

function validateLoadedEngineBinding(engine, target) {
  const object = engine?.object;
  if (
    engine?.kind !== "hermes" ||
    typeof engine.engineArtifactPath !== "string" ||
    !path.isAbsolute(engine.engineArtifactPath) ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(engine.binaryDigest ?? "") ||
    !object ||
    canonicalJson(Object.keys(object).sort()) !==
      canonicalJson(["file", "platform", "volume"]) ||
    !["android", "apple", "unix", "windows"].includes(object.platform) ||
    typeof object.volume !== "string" ||
    object.volume.length === 0 ||
    typeof object.file !== "string" ||
    object.file.length === 0 ||
    typeof engine.targetArchitecture !== "string" ||
    !Array.isArray(engine.structuralFeatures) ||
    engine.targetArchitecture !== target?.triple?.split("-")[0] ||
    canonicalJson(engine.structuralFeatures) !== canonicalJson(target.features)
  ) {
    throw new Error(
      "conformance bindings require the exact loaded Hermes object for the target",
    );
  }
}

function fixturePlans(catalog) {
  const accumulated = new Map();
  for (const cell of catalog) {
    const required = new Set(cell.requiredFixtures);
    const bindings = new Map();
    for (const binding of cell.fixtureBindings) {
      if (bindings.has(binding.fixtureId)) {
        throw new Error(
          `${cell.edgeId}: duplicate fixture binding ${binding.fixtureId}`,
        );
      }
      bindings.set(binding.fixtureId, binding);
    }
    for (const fixtureId of required) {
      const binding = bindings.get(fixtureId);
      if (!binding) {
        throw new Error(
          `${cell.edgeId}: required fixture ${fixtureId} has no branch binding`,
        );
      }
      const entry = accumulated.get(fixtureId) ?? {
        edgeIds: new Set(),
        implementationBranchIds: new Set(),
        enforcementBranchIds: new Set(),
        terminalObservedKeys: new Set(),
        classifications: new Set(),
        actionIds: new Set(),
      };
      entry.edgeIds.add(cell.edgeId);
      for (const branchId of binding.implementationBranchIds) {
        entry.implementationBranchIds.add(branchId);
      }
      for (const branchId of binding.enforcementBranchIds) {
        entry.enforcementBranchIds.add(branchId);
      }
      for (const observedKey of binding.terminalObservedKeys) {
        entry.terminalObservedKeys.add(observedKey);
      }
      for (const classification of binding.classifications) {
        entry.classifications.add(classification);
      }
      for (const actionId of binding.actionIds) {
        entry.actionIds.add(actionId);
      }
      accumulated.set(fixtureId, entry);
    }
    for (const fixtureId of bindings.keys()) {
      if (!required.has(fixtureId)) {
        throw new Error(
          `${cell.edgeId}: fixture binding ${fixtureId} is not a required fixture`,
        );
      }
    }
  }

  const plans = new Map();
  for (const fixtureId of canonicalSet(accumulated.keys())) {
    const entry = accumulated.get(fixtureId);
    const edgeIds = canonicalSet(entry.edgeIds);
    const implementationBranchIds = canonicalSet(entry.implementationBranchIds);
    const enforcementBranchIds = canonicalSet(entry.enforcementBranchIds);
    const terminalObservedKeys = canonicalSet(entry.terminalObservedKeys);
    const classifications = canonicalSet(entry.classifications);
    const actionIds = canonicalSet(entry.actionIds);
    if (terminalObservedKeys.length !== 1 || classifications.length !== 1) {
      throw new Error(
        `${fixtureId}: fixture plan does not identify exactly one terminal surface and classification`,
      );
    }
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
      terminalObservedKey: terminalObservedKeys[0],
      classification: classifications[0],
      actionIds,
      expectedObservation,
    });
  }
  return plans;
}

export function fixtureExecutionPlan(catalog, fixtureId) {
  return fixturePlans(catalog).get(fixtureId) ?? null;
}

export function fixtureExecutionPlans(catalog) {
  return [...fixturePlans(catalog).values()];
}

function validateExecutionEvidence(
  execution,
  {
    plan,
    recipe,
    coverage,
    engineBinaryDigest,
    executionBinding,
    validateRuntimeObservation,
  },
) {
  const evidence = execution.evidence;
  if (
    evidence?.evidenceSchema !== "ibex/capsec-fixture-evidence/2" ||
    evidence.fixtureId !== execution.fixtureId ||
    !Array.isArray(evidence.command) || evidence.command.length === 0 ||
    !evidence.command.every((part) => typeof part === "string" && part.length > 0) ||
    !Number.isSafeInteger(evidence.exitCode) ||
    typeof evidence.resultMarker !== "string" ||
    canonicalJson(evidence.fixturePlan) !== canonicalJson(plan) ||
    canonicalJson(evidence.executionBinding) !==
      canonicalJson(executionBinding) ||
    evidence.runtimeObservation?.observationSchema !==
      "ibex/capsec-runtime-public-observation/1" ||
    !evidence.runtimeObservation.invocation ||
    typeof evidence.runtimeObservation.invocation !== "object" ||
    evidence.runtimeObservation.legacyObservationCount !== 0 ||
    !Array.isArray(evidence.runtimeObservation.typedDecisions)
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
  const runtimeTerminal = validateRuntimeObservation(
    evidence.runtimeObservation,
    recipe,
    coverage,
  );
  if (runtimeTerminal !== plan.terminalObservedKey) {
    throw new Error(
      `${execution.fixtureId}: runtime observation did not execute the fixture terminal`,
    );
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
    recipeCatalogDigest: bindings.recipeCatalogDigest,
    publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
    ...(bindings.outputDispositionEvidenceRawContentDigest === undefined
      ? {}
      : {
          outputDispositionEvidenceRawContentDigest:
            bindings.outputDispositionEvidenceRawContentDigest,
        }),
  });
}

function targetOsForTriple(triple) {
  if (triple.endsWith("-apple-darwin")) return "apple";
  if (triple.endsWith("-pc-windows-msvc")) return "windows";
  return null;
}

function logicalBranchAppliesToTarget(branch, target) {
  const targetConditions = branch.when.filter(
    (condition) => condition.fact === "runtime.target.os",
  );
  if (targetConditions.length === 0) return true;
  const targetOs = targetOsForTriple(target.triple);
  return targetConditions.every((condition) => condition.equals === targetOs);
}

function logicalBranchForFixture(edge, rows, fixtureId) {
  return edge.logicalBranches?.find((branch) =>
    rows.some((row) =>
      fixtureId.startsWith(
        `${row.enforcementBranchId}.logical.${branch.id}.`,
      ),
    ),
  );
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
    const absenceFixture = absenceFixtureForTarget(edge.id, target);
    const allRequiredFixtures = canonicalSet(
      selected.length === 0
        ? [absenceFixture]
        : selected.flatMap((row) => row.fixtureObligations),
    );
    const requiredFixtures = allRequiredFixtures.filter((fixtureId) => {
      const logicalBranch = logicalBranchForFixture(edge, selected, fixtureId);
      return (
        logicalBranch === undefined ||
        logicalBranchAppliesToTarget(logicalBranch, target)
      );
    });
    const fixtureBindings = requiredFixtures.map((fixtureId) => {
      const matchingRows = selected.filter((row) =>
        row.fixtureObligations.includes(fixtureId),
      );
      if (selected.length > 0 && matchingRows.length === 0) {
        throw new Error(
          `${edge.id}: fixture ${fixtureId} has no selected implementation branch`,
        );
      }
      const logicalBranch = logicalBranchForFixture(
        edge,
        matchingRows,
        fixtureId,
      );
      return {
        fixtureId,
        implementationBranchIds: canonicalSet(
          matchingRows.map((row) => row.branchId),
        ),
        enforcementBranchIds: canonicalSet(
          matchingRows.map((row) => row.enforcementBranchId),
        ),
        terminalObservedKeys: canonicalSet(
          matchingRows.length === 0
            ? [`${edge.surface.kind}:${edge.surface.name}`]
            : matchingRows.map(
                (row) =>
                  row.enforcementRoute?.terminalObservedKey ?? row.observedKey,
              ),
        ),
        classifications: [
          logicalBranch?.disposition === "closed"
            ? "closed"
            : edge.classification,
        ],
        actionIds: canonicalSet(
          (logicalBranch?.disposition === "closed"
            ? []
            : (logicalBranch?.effects ?? edge.effects ?? [])
          ).map(
            (effect) => effect.cap,
          ),
        ),
      };
    });
    return {
      edgeId: edge.id,
      implementationBranchIds: canonicalSet(branchIds),
      enforcementBranchIds: canonicalSet(
        selected.map((row) => row.enforcementBranchId),
      ),
      requiredFixtures,
      // This is part of the execution catalog digest, but not repeated in the
      // public per-edge report cell. It prevents one branch's fixture from
      // inheriting every other branch selected for the same target cell.
      fixtureBindings,
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
  recipeCatalog,
  // Injected to avoid the conformance -> public evidence -> recipes ->
  // conformance ESM cycle while still making mechanism-aware validation
  // mandatory for every report-producing caller.
  validateRuntimeObservation,
  validateInternalInvariantExecution,
}) {
  validateLoadedEngineBinding(bindings.engine, target);
  const recipeCatalogPayload = recipeCatalog
    ? (({ recipeCatalogDigest: _digest, ...payload }) => payload)(recipeCatalog)
    : null;
  if (
    recipeCatalog?.recipeCatalogSchema !==
      "ibex/capsec-executable-recipes/1" ||
    recipeCatalog.profile !== "ibex/capsec/1" ||
    recipeCatalog.recipeCatalogDigest !== bindings.recipeCatalogDigest ||
    recipeCatalog.recipeCatalogDigest !== digest(recipeCatalogPayload) ||
    canonicalJson(recipeCatalog.target) !== canonicalJson(target) ||
    !Array.isArray(recipeCatalog.recipes) ||
    typeof validateRuntimeObservation !== "function"
  ) {
    throw new Error(
      "conformance generation requires the exact digest-bound recipe catalog and runtime-observation validator",
    );
  }
  const recipes = new Map();
  for (const recipe of recipeCatalog.recipes) {
    if (
      typeof recipe?.fixtureId !== "string" ||
      recipes.has(recipe.fixtureId)
    ) {
      throw new Error("conformance recipe catalog has a malformed or duplicate fixture");
    }
    recipes.set(recipe.fixtureId, recipe);
  }
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
  const requiredExecutionBinding = {
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    target,
    engine: bindings.engine,
    vocabularyDigest: bindings.vocabularyDigest,
    registryDigest: bindings.registryDigest,
    implementationManifestDigest,
    fixtureCatalogDigest,
    recipeCatalogDigest: bindings.recipeCatalogDigest,
    publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
  };
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
    const recipe = recipes.get(execution.fixtureId);
    const plan = plans.get(execution.fixtureId);
    if (
      !["fully-executable", "internally-verified"].includes(recipe?.status) ||
      recipe.planDigest !== digest(plan)
    ) {
      throw new Error(
        `${execution.fixtureId}: execution has no exact executable recipe`,
      );
    }
    if (
      !execution.executor ||
      !/^sha256-[A-Za-z0-9_-]{43}$/.test(execution.artifactDigest ?? "")
    ) {
      throw new Error(
        `${execution.fixtureId}: execution lacks executor or artifact digest`,
      );
    }
    if (recipe.status === "internally-verified") {
      if (typeof validateInternalInvariantExecution !== "function") {
        throw new Error(
          `${execution.fixtureId}: internal execution has no invariant-evidence validator`,
        );
      }
      validateInternalInvariantExecution(execution, {
        plan,
        recipe,
        engineBinaryDigest: bindings.engine.binaryDigest,
        executionBinding: requiredExecutionBinding,
        bindingDigest: requiredBindingDigest,
      });
    } else {
      validateExecutionEvidence(execution, {
        plan,
        recipe,
        coverage,
        engineBinaryDigest: bindings.engine.binaryDigest,
        executionBinding: requiredExecutionBinding,
        validateRuntimeObservation,
      });
    }
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
  // `internally-verified` is a recipe classification, not execution evidence.
  // The report leaves those fixtures missing until a separately executed,
  // source-bound internal proof is supplied and validated. A digest-bound
  // catalog can name the proof obligation, but cannot satisfy it by itself.
  // @ref LLP 0036#correctness-owed-the-deliberately-deferred-verification
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
    const { fixtureBindings: _fixtureBindings, ...publicCell } = cell;
    return {
      ...publicCell,
      status:
        failedFixtures.length === 0 && missingFixtures.length === 0
          ? "conformant"
          : "incomplete",
      passedFixtures,
      missingFixtures,
      failedFixtures,
    };
  });
  const status = cells.every((cell) => cell.status === "conformant")
    ? "conformant"
    : "incomplete";
  const outputDispositionEvidenceRawContentDigest =
    bindings.outputDispositionEvidenceRawContentDigest;
  if (
    outputDispositionEvidenceRawContentDigest !== undefined &&
    !DIGEST_PATTERN.test(outputDispositionEvidenceRawContentDigest)
  ) {
    throw new Error(
      "conformance report has a malformed output-disposition evidence raw-content digest",
    );
  }
  if (
    status === "conformant" &&
    outputDispositionEvidenceRawContentDigest === undefined
  ) {
    throw new Error(
      "conformant report requires verified output-disposition evidence",
    );
  }
  const report = {
    conformanceSchema: "ibex/capsec-conformance/1",
    profile: "ibex/capsec/1",
    status,
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
  if (
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(
      report.bindings?.recipeCatalogDigest ?? "",
    ) ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(
      report.bindings?.publicSurfaceExecutionDigest ?? "",
    ) ||
    !DIGEST_PATTERN.test(
      report.bindings?.outputDispositionEvidenceRawContentDigest ?? "",
    )
  ) {
    throw new Error(
      "conformance report cannot advertise without recipe, public-surface, and output-disposition evidence bindings",
    );
  }
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
  {
    coverage,
    implementation,
    target,
    digestContract,
    recipeCatalog,
    validateRuntimeObservation,
    validateInternalInvariantExecution,
  },
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
      recipeCatalogDigest: report.bindings.recipeCatalogDigest,
      publicSurfaceExecutionDigest:
        report.bindings.publicSurfaceExecutionDigest,
      ...(report.bindings.outputDispositionEvidenceRawContentDigest ===
      undefined
        ? {}
        : {
            outputDispositionEvidenceRawContentDigest:
              report.bindings.outputDispositionEvidenceRawContentDigest,
          }),
    },
    digestContract,
    recipeCatalog,
    validateRuntimeObservation,
    validateInternalInvariantExecution,
  });
  if (canonicalJson(report) !== canonicalJson(expected)) {
    throw new Error("conformance report disagrees with derived evidence");
  }
}
