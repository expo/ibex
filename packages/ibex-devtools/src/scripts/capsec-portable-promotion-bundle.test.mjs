// @ref LLP 0035#reports-and-advertisements — promotion bundle generation
// preserves detached bytes and refuses partial or ambiguous process closure.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fixtureCatalogForTarget } from "./capsec-conformance.mjs";
import {
  bindRecipeCatalogScope,
  computeRecipeCatalogDigest,
} from "./capsec-conformance-recipes.mjs";
import { computeDomainDigest, parseJsonStrict } from "./capsec-contract.mjs";
import { conformanceRunnerBindingDigest } from "./capsec-conformance-runner-binding.mjs";
import {
  INTERNAL_INVARIANT_EXECUTOR,
  internalInvariantProofPlan,
} from "./capsec-internal-invariant-evidence.mjs";
import { PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS } from "./capsec-public-executors.mjs";
import {
  commandAttemptDigest,
  mappedEngineExecutionEvidenceDigest,
  portableExecutionBindingDigest,
  portableFixtureEvidenceDigest,
  portableOutputDispositionObservationDigest,
  portablePublicSurfaceExecutionDigest,
  portablePublicSurfaceExecutionEvidenceDigest,
  portableRecipeCatalogDigest,
  portableRecipePlanDigest,
  rawContentDigest,
  validatePortablePromotionV2,
} from "./capsec-portable-engine-evidence-contract.mjs";
import {
  buildPortablePromotionBundleV2,
  derivePortablePromotionTargetCells,
  derivePortableOutputDispositionEvidenceV4,
  derivePortablePublicSurfaceExecutionV2,
  derivePortableRecipeCatalogV2,
  preparePortablePromotionFromDerivedArtifactsV2,
} from "./capsec-portable-promotion-bundle.mjs";
import {
  validatePortablePromotionBundleGraph,
  verifyPortablePromotionBundleDirectory,
} from "./verify-capsec-portable-promotion-bundle.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "../../../..");
const vectors = parseJsonStrict(
  fs.readFileSync(
    path.join(
      repoRoot,
      "schemas/vectors/portable-engine-provenance-v1.valid.json",
    ),
  ),
  "portable provenance vectors",
);
const baseEngine = vectors.documents.portableIdentity;
const baseMapped = vectors.documents.mappedInstance;
const clone = (value) => structuredClone(value);
const digest = (character) => `sha256-${character.repeat(43)}`;
const nativeExecutor = PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS.find(
  (descriptor) => descriptor.testName === "capsec_public_native_primary_batch",
);

function exactBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function target() {
  return {
    triple: "aarch64-apple-darwin",
    features: [
      "hermes-frame-attribution",
      "native-compartments",
      "native-lockdown",
    ],
  };
}

function bindRichRecipeCatalogScope(recipeCatalog) {
  const expandedEdgeIds = [
    ...new Set(recipeCatalog.recipes.flatMap((recipe) => recipe.edgeIds)),
  ].sort();
  const scopeDigest = digest("S");
  return {
    expandedEdgeIds,
    scopeDigest,
    catalog: bindRecipeCatalogScope(recipeCatalog, {
      scopeDigest,
      expandedEdgeIds,
    }),
  };
}

function scopeBundle(scopeTarget, edgeIds) {
  const predecessor = { kind: "genesis" };
  const diff = {
    scopeExpansionDiffSchema: "ibex/capsec-scope-expansion-diff/1",
    profile: "ibex/capsec/1",
    target: clone(scopeTarget),
    predecessor,
    previousExpandedCellIds: [],
    currentExpandedCellIds: clone(edgeIds),
    addedCellIds: clone(edgeIds),
    retiredCellIds: [],
    scopeExpansionDiffDigest: digest("A"),
  };
  diff.scopeExpansionDiffDigest = computeDomainDigest(
    "ibex:capsec:scope-expansion-diff:1",
    diff,
    ["scopeExpansionDiffDigest"],
  );
  const mapping = {
    scopeCellMappingSchema: "ibex/capsec-scope-cell-mapping/1",
    profile: "ibex/capsec/1",
    target: clone(scopeTarget),
    predecessor,
    additions: clone(edgeIds),
    retirements: [],
    mappings: [],
    scopeCellMappingDigest: digest("A"),
  };
  mapping.scopeCellMappingDigest = computeDomainDigest(
    "ibex:capsec:scope-cell-mapping:1",
    mapping,
    ["scopeCellMappingDigest"],
  );
  const scope = {
    scopeSchema: "ibex/capsec-scope/1",
    profile: "ibex/capsec/1",
    target: clone(scopeTarget),
    intensionalDefinition: {
      capabilityFamilies: ["fs"],
      surfaceKinds: ["native-op"],
    },
    expandedCellIds: clone(edgeIds),
    closureEdges: edgeIds.map((edgeId) => ({
      fromEdgeId: edgeId,
      toEdgeId: edgeId,
      dependencyKind: "source-derived-route",
      implementationBranchId: "branch.portable.bundle",
      terminalObservedKey: "native-op:portableBundle",
      proofPaths: ["native-op:portableBundle"],
      sourceRefs: ["src/host/mod.rs#portableBundle"],
    })),
    predecessor,
    scopeExpansionDiffDigest: diff.scopeExpansionDiffDigest,
    scopeCellMappingDigest: mapping.scopeCellMappingDigest,
    scopeDigest: digest("A"),
  };
  scope.scopeDigest = computeDomainDigest("ibex:capsec:scope:1", scope, [
    "scopeDigest",
  ]);
  return {
    scopeArtifactBytes: exactBytes(scope),
    scopeExpansionDiffBytes: exactBytes(diff),
    scopeCellMappingBytes: exactBytes(mapping),
  };
}

function source(engine = baseEngine) {
  return {
    portablePromotionSourceSchema: "ibex/capsec-portable-promotion-source/2",
    profile: "ibex/capsec/1",
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: digest("A"),
    family: "macos",
    target: target(),
    engine: clone(engine),
    vocabularyDigest: digest("Q"),
    registryDigest: digest("U"),
    executorPolicy: "recipe-public-command",
  };
}

function conformanceRunner(reviewedSource = source()) {
  return {
    sourceRevision: reviewedSource.sourceRevision,
    sourceTreeDigest: reviewedSource.sourceTreeDigest,
    artifactId: reviewedSource.engine.artifactId,
    buildConsumptionDigest: digest("M"),
    postLinkSetDigest: digest("Q"),
    verificationDigest: digest("U"),
    testExecutableDigest: `sha256-${"e".repeat(64)}`,
  };
}

function sourceClosure() {
  const fixtureId = "fixture.portable.bundle";
  const edgeId = "surface.portable.bundle";
  const branchId = "branch.portable.bundle";
  const enforcementBranchId = "enforcement.portable.bundle";
  const coverage = {
    edges: [
      {
        id: edgeId,
        classification: "effects",
        effectMode: "unconditional",
        surface: { kind: "native-op", name: "portableBundle" },
        effects: [{ cap: "cap.portable.bundle" }],
      },
    ],
  };
  const implementation = {
    surfaces: [
      {
        edgeId,
        branchId,
        targetVariant: "all",
        targetApplicability: { kind: "all" },
        fixtureObligations: [fixtureId],
        enforcementBranchId,
        enforcementRoute: {
          terminalObservedKey: "native-op:portableBundle",
        },
      },
    ],
  };
  const fixtureCatalog = fixtureCatalogForTarget({
    coverage,
    implementation,
    target: target(),
  });
  const targetCells = {
    targetCellSchema: "ibex/capsec-target-cells/1",
    profile: "ibex/capsec/1",
    cells: [
      {
        edgeId,
        target: target(),
        disposition: "enforced",
        implementationBranchIds: [branchId],
        fixtures: [fixtureId],
        rationale: "Detached future-promotion candidate from source closure.",
      },
    ],
  };
  return {
    branchId,
    coverage,
    edgeId,
    enforcementBranchId,
    fixtureCatalog,
    fixtureId,
    inScopeEdgeIds: [edgeId],
    implementation,
    targetCells,
  };
}

function derivedPreparation() {
  const reviewedSource = source();
  const closure = sourceClosure();
  const scoped = scopeBundle(reviewedSource.target, closure.inScopeEdgeIds);
  const recipe = {
    fixtureId: closure.fixtureId,
    status: "fully-executable",
    executor: nativeExecutor.executor,
    planDigest: digest("A"),
  };
  recipe.planDigest = portableRecipePlanDigest(recipe);
  const recipeCatalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/2",
    profile: "ibex/capsec/1",
    target: target(),
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      unresolvedFixtures: 0,
    },
    recipeCatalogDigest: digest("A"),
  };
  const scopeDigest = parseJsonStrict(
    scoped.scopeArtifactBytes,
    "test scope artifact",
  ).scopeDigest;
  recipeCatalog.recipeCatalogDigest =
    portableRecipeCatalogDigest(recipeCatalog, scopeDigest);
  const recipeCatalogBytes = exactBytes(recipeCatalog);
  const publicExecution = {
    fixtureId: closure.fixtureId,
    outcome: "passed",
    executor: nativeExecutor.executor,
    evidenceDigest: digest("A"),
  };
  publicExecution.evidenceDigest =
    portablePublicSurfaceExecutionEvidenceDigest(publicExecution);
  const publicSurface = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/2",
    profile: "ibex/capsec/1",
    sourceRevision: reviewedSource.sourceRevision,
    sourceTreeDigest: reviewedSource.sourceTreeDigest,
    target: target(),
    engine: clone(reviewedSource.engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    recipeCatalogRawContentDigest: rawContentDigest(recipeCatalogBytes),
    summary: {
      requiredFixtures: 1,
      executableFixtures: 1,
      internallyVerifiedFixtures: 0,
      residualFixtures: 0,
      executedFixtures: 1,
      passedFixtures: 1,
      failedFixtures: 0,
      missingFixtures: 0,
    },
    executions: [publicExecution],
    publicSurfaceExecutionDigest: digest("A"),
  };
  publicSurface.publicSurfaceExecutionDigest =
    portablePublicSurfaceExecutionDigest(publicSurface);
  const outputObservation = {
    key: "output.portable.bundle",
    disposition: "non-path",
    proofKind: "compiled-runtime-return-record",
    observationDigest: digest("A"),
  };
  outputObservation.observationDigest =
    portableOutputDispositionObservationDigest(outputObservation);
  const outputDispositions = {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/4",
    profile: "ibex/capsec/1",
    status: "verified",
    sourceRevision: reviewedSource.sourceRevision,
    sourceTreeDigest: reviewedSource.sourceTreeDigest,
    conformanceRunner: conformanceRunner(reviewedSource),
    target: target(),
    engine: clone(reviewedSource.engine),
    summary: { observations: 1 },
    observations: [outputObservation],
  };
  return {
    closure,
    preparation: preparePortablePromotionFromDerivedArtifactsV2({
      reviewedSourceBytes: exactBytes(reviewedSource),
      coverageBytes: exactBytes(closure.coverage),
      implementationManifestBytes: exactBytes(closure.implementation),
      fixtureCatalogBytes: exactBytes(closure.fixtureCatalog),
      ...scoped,
      targetCellsBytes: exactBytes(closure.targetCells),
      recipeCatalogBytes,
      publicSurfaceExecutionBytes: exactBytes(publicSurface),
      outputDispositionEvidenceBytes: exactBytes(outputDispositions),
    }),
  };
}

function portableBindings(preparation) {
  return {
    sourceRevision: preparation.source.sourceRevision,
    sourceTreeDigest: preparation.source.sourceTreeDigest,
    conformanceRunner: clone(preparation.authorityEntry.conformanceRunner),
    target: clone(preparation.source.target),
    engine: clone(preparation.source.engine),
    vocabularyDigest: preparation.authorityEntry.vocabularyDigest,
    registryDigest: preparation.authorityEntry.registryDigest,
    implementationManifestDigest:
      preparation.authorityEntry.implementationManifestDigest,
    fixtureCatalogDigest: preparation.authorityEntry.fixtureCatalogDigest,
    scopeDigest: preparation.scopeDigest,
    targetCellsRawContentDigest:
      preparation.authorityEntry.targetCellsRawContentDigest,
    recipeCatalogDigest: preparation.authorityEntry.recipeCatalogDigest,
    recipeCatalogRawContentDigest:
      preparation.authorityEntry.recipeCatalogRawContentDigest,
    publicSurfaceExecutionDigest:
      preparation.authorityEntry.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest:
      preparation.authorityEntry.publicSurfaceExecutionRawContentDigest,
    outputDispositionEvidenceRawContentDigest:
      preparation.authorityEntry.outputDispositionEvidenceRawContentDigest,
  };
}

function detachedProcess(preparation) {
  const bindingDigest = portableExecutionBindingDigest(
    portableBindings(preparation),
  );
  const fixture = {
    fixtureEvidenceSchema: "ibex/capsec-portable-fixture-evidence/1",
    profile: "ibex/capsec/1",
    sourceRevision: preparation.source.sourceRevision,
    sourceTreeDigest: preparation.source.sourceTreeDigest,
    target: clone(preparation.source.target),
    engine: clone(preparation.source.engine),
    fixtureId: preparation.fixtures[0],
    outcome: "passed",
    executor: preparation.recipeCatalog.recipes[0].executor,
    bindingDigest,
    artifactDigest: digest("A"),
  };
  fixture.artifactDigest = portableFixtureEvidenceDigest(fixture);
  const fixtureBytes = exactBytes(fixture);
  const fixtureRawDigest = rawContentDigest(fixtureBytes);
  const mappedEngine = clone(baseMapped);
  mappedEngine.portable = clone(preparation.source.engine);
  mappedEngine.before.digest = preparation.source.engine.runtimeComponentDigest;
  mappedEngine.after.digest = preparation.source.engine.runtimeComponentDigest;
  mappedEngine.processArchitecture =
    preparation.source.target.triple.split("-")[0];
  mappedEngine.observationDigest = computeDomainDigest(
    "ibex.mapped-engine-instance-identity.v1",
    mappedEngine,
    ["observationDigest"],
  );
  const evidence = {
    mappedEngineExecutionEvidenceSchema:
      "ibex/capsec-mapped-engine-execution-evidence/1",
    profile: "ibex/capsec/1",
    authorityClass: "same-runner-authoritative",
    sourceRevision: preparation.source.sourceRevision,
    sourceTreeDigest: preparation.source.sourceTreeDigest,
    target: clone(preparation.source.target),
    phaseId: "fixture-evidence",
    commandId: "exact-fixture-evidence",
    commandIdentityDigest: digest("E"),
    fixtureIds: [fixture.fixtureId],
    outputDigests: [fixtureRawDigest],
    engine: clone(preparation.source.engine),
    mappedEngine,
    evidenceDigest: digest("A"),
  };
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  const mappedEvidenceBytes = exactBytes(evidence);
  const attempt = {
    schema: "ibex/capsec-command-attempt/1",
    attemptId: "attempt-000001",
    commandId: evidence.commandId,
    commandIdentity: evidence.commandIdentityDigest,
    phase: evidence.phaseId,
    displayedInvocation: ["ibex", "--fixture-evidence"],
    declaredInputs: [
      {
        name: "conformanceRunner",
        digest: conformanceRunnerBindingDigest(
          preparation.authorityEntry.conformanceRunner,
        ),
      },
    ],
    startedAt: "2026-07-20T00:00:00.000Z",
    finishedAt: "2026-07-20T00:00:01.000Z",
    elapsedMs: 1000,
    deadlineMs: 30000,
    gracePeriodMs: 5000,
    classification: "success",
    exitCode: 0,
    signal: null,
    cleanup: { actions: [], cleanupProven: true, escapedDescendants: [] },
    stdout: { bytes: 0, digest: digest("4"), tail: "", truncated: false },
    stderr: { bytes: 0, digest: digest("4"), tail: "", truncated: false },
    outputs: [
      {
        path: "/runner/evidence/fixture.json",
        bytes: fixtureBytes.byteLength,
        digest: fixtureRawDigest,
      },
      {
        path: "/runner/evidence/mapped.json",
        bytes: mappedEvidenceBytes.byteLength,
        digest: rawContentDigest(mappedEvidenceBytes),
      },
    ],
    attemptDigest: digest("A"),
  };
  attempt.attemptDigest = commandAttemptDigest(attempt);
  return {
    mappedEvidenceBytes,
    commandAttemptBytes: exactBytes(attempt),
    outputArtifactBytes: [fixtureBytes],
  };
}

function fixture() {
  const state = derivedPreparation();
  return {
    ...state,
    process: detachedProcess(state.preparation),
  };
}

function copyProcess(process) {
  return {
    mappedEvidenceBytes: Buffer.from(process.mappedEvidenceBytes),
    commandAttemptBytes: Buffer.from(process.commandAttemptBytes),
    outputArtifactBytes: process.outputArtifactBytes.map((value) =>
      Buffer.from(value),
    ),
  };
}

describe("portable promotion bundle generation", () => {
  test("derives candidate cells from source closure without a report", () => {
    const closure = sourceClosure();
    expect(
      derivePortablePromotionTargetCells({
        coverage: closure.coverage,
        implementation: closure.implementation,
        inScopeEdgeIds: closure.inScopeEdgeIds,
        target: target(),
      }),
    ).toEqual({
      targetCellSchema: "ibex/capsec-target-cells/1",
      profile: "ibex/capsec/1",
      cells: [
        {
          edgeId: closure.edgeId,
          target: target(),
          disposition: "enforced",
          implementationBranchIds: [closure.branchId],
          fixtures: [closure.fixtureId],
          rationale:
            "Source-derived scoped physical-promotion candidate; authority requires complete execution evidence.",
        },
      ],
    });
  });

  test("refuses conditional-unrefined candidate cells before execution", () => {
    const closure = sourceClosure();
    closure.coverage.edges[0].effectMode = "conditional-unrefined";
    expect(() =>
      derivePortablePromotionTargetCells({
        coverage: closure.coverage,
        implementation: closure.implementation,
        inScopeEdgeIds: closure.inScopeEdgeIds,
        target: target(),
      }),
    ).toThrow(/conditional-unrefined/u);
  });

  test("refuses a candidate cell with no physical fixture obligation", () => {
    const closure = sourceClosure();
    closure.implementation.surfaces[0].fixtureObligations = [];
    expect(() =>
      derivePortablePromotionTargetCells({
        coverage: closure.coverage,
        implementation: closure.implementation,
        inScopeEdgeIds: closure.inScopeEdgeIds,
        target: target(),
      }),
    ).toThrow(/no required physical fixture/u);
  });

  test("assembles one deterministic exact-byte bundle through the frozen validator", () => {
    const first = fixture();
    const firstBundle = buildPortablePromotionBundleV2({
      preparation: first.preparation,
      processes: [first.process],
    });
    const second = fixture();
    const secondBundle = buildPortablePromotionBundleV2({
      preparation: second.preparation,
      processes: [second.process],
    });
    expect(firstBundle.report.status).toBe("conformant");
    expect(firstBundle.validated.report).toEqual(firstBundle.report);
    expect(firstBundle.manifestBytes).toEqual(secondBundle.manifestBytes);
    expect(firstBundle.files.map((file) => file.rawContentDigest)).toEqual(
      secondBundle.files.map((file) => file.rawContentDigest),
    );
    expect(() => validatePortablePromotionV2(firstBundle.input)).not.toThrow();
  });

  test("reconstructs exact on-disk membership before immutable upload", () => {
    const state = fixture();
    const bundle = buildPortablePromotionBundleV2({
      preparation: state.preparation,
      processes: [state.process],
    });
    const directory = fs.mkdtempSync(
      path.join(fs.realpathSync(os.tmpdir()), "ibex-portable-bundle-"),
    );
    fs.chmodSync(directory, 0o700);
    try {
      for (const file of bundle.files) {
        fs.writeFileSync(
          path.join(directory, `${file.logicalName}.json`),
          file.bytes,
          { mode: 0o600 },
        );
      }
      fs.writeFileSync(
        path.join(directory, "bundle-manifest.json"),
        bundle.manifestBytes,
        { mode: 0o600 },
      );
      const verified = verifyPortablePromotionBundleDirectory({
        directory,
        expectedSourceRevision: bundle.manifest.sourceRevision,
      });
      expect(verified.bundleDigest).toBe(bundle.manifest.bundleDigest);
      expect(verified.validated.report).toEqual(bundle.report);

      const reportPath = path.join(
        directory,
        "portable-conformance-report.json",
      );
      fs.appendFileSync(reportPath, " ");
      expect(() =>
        verifyPortablePromotionBundleDirectory({
          directory,
          expectedSourceRevision: bundle.manifest.sourceRevision,
        }),
      ).toThrow(/byte length mismatch|raw-content digest mismatch/u);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  test("refuses a second scope artifact in the closed bundle graph", () => {
    const state = fixture();
    const bundle = buildPortablePromotionBundleV2({
      preparation: state.preparation,
      processes: [state.process],
    });
    const members = bundle.files.map(({ logicalName, bytes }) => ({
      logicalName,
      bytes,
    }));
    members.push({
      logicalName: "scope-artifact",
      bytes: Buffer.from(state.preparation.scopeArtifactBytes),
    });
    expect(() =>
      validatePortablePromotionBundleGraph({
        manifestBytes: bundle.manifestBytes,
        members,
        expectedSourceRevision: bundle.manifest.sourceRevision,
      }),
    ).toThrow(/exact member set|duplicate/u);
  });

  test("keeps local mapped observations detached from publication bytes", () => {
    const state = fixture();
    const bundle = buildPortablePromotionBundleV2({
      preparation: state.preparation,
      processes: [state.process],
    });
    const publication = Buffer.concat([
      bundle.input.authorityBytes,
      bundle.input.reportBytes,
      bundle.input.attestationCatalogBytes,
      bundle.input.advertisementCatalogBytes,
      bundle.manifestBytes,
    ]).toString("utf8");
    expect(publication).not.toContain("/private/");
    expect(publication).not.toContain("regionStart");
    expect(
      bundle.input.processes[0].mappedEvidenceBytes.toString("utf8"),
    ).toContain("/private/");
  });

  test("refuses missing and duplicate detached process membership", () => {
    const state = fixture();
    expect(() =>
      buildPortablePromotionBundleV2({
        preparation: state.preparation,
        processes: [],
      }),
    ).toThrow(/at least one detached process/u);
    expect(() =>
      buildPortablePromotionBundleV2({
        preparation: state.preparation,
        processes: [copyProcess(state.process), copyProcess(state.process)],
      }),
    ).toThrow(/duplicated/u);
  });

  test("refuses missing, duplicate, and mutated fixture outputs", () => {
    const state = fixture();
    const missing = copyProcess(state.process);
    missing.outputArtifactBytes = [];
    expect(() =>
      buildPortablePromotionBundleV2({
        preparation: state.preparation,
        processes: [missing],
      }),
    ).toThrow(/no fixture outputs/u);

    const duplicate = copyProcess(state.process);
    duplicate.outputArtifactBytes.push(
      Buffer.from(duplicate.outputArtifactBytes[0]),
    );
    expect(() =>
      buildPortablePromotionBundleV2({
        preparation: state.preparation,
        processes: [duplicate],
      }),
    ).toThrow(/duplicated/u);

    const mutated = copyProcess(state.process);
    const artifact = parseJsonStrict(mutated.outputArtifactBytes[0], "fixture");
    artifact.artifactDigest = digest("I");
    mutated.outputArtifactBytes[0] = exactBytes(artifact);
    expect(() =>
      buildPortablePromotionBundleV2({
        preparation: state.preparation,
        processes: [mutated],
      }),
    ).toThrow(
      /fixture artifact digest mismatch|output bytes differ|detached output bytes/u,
    );
  });

  test("source-A unsupported cells cannot enter preparation", () => {
    const state = derivedPreparation();
    const targetCells = clone(state.closure.targetCells);
    targetCells.cells[0].disposition = "unsupported";
    targetCells.cells[0].fixtures = [];
    expect(() =>
      preparePortablePromotionFromDerivedArtifactsV2({
        reviewedSourceBytes: state.preparation.reviewedSourceBytes,
        coverageBytes: exactBytes(state.closure.coverage),
        implementationManifestBytes: exactBytes(state.closure.implementation),
        fixtureCatalogBytes: exactBytes(state.closure.fixtureCatalog),
        scopeArtifactBytes: state.preparation.scopeArtifactBytes,
        scopeExpansionDiffBytes: state.preparation.scopeExpansionDiffBytes,
        scopeCellMappingBytes: state.preparation.scopeCellMappingBytes,
        targetCellsBytes: exactBytes(targetCells),
        recipeCatalogBytes: state.preparation.recipeCatalogBytes,
        publicSurfaceExecutionBytes:
          state.preparation.publicSurfaceExecutionBytes,
        outputDispositionEvidenceBytes:
          state.preparation.outputDispositionEvidenceBytes,
      }),
    ).toThrow(/certified scope partition/u);
  });

  test("accepts unsupported bytes for exactly the scope artifact remainder", () => {
    const state = derivedPreparation();
    const remainderEdgeId = "surface.portable.remainder";
    const coverage = clone(state.closure.coverage);
    coverage.edges.push({
      id: remainderEdgeId,
      classification: "effects",
      effectMode: "conditional-unrefined",
      surface: { kind: "native-op", name: "portableRemainder" },
      effects: [{ cap: "cap.portable.remainder" }],
    });
    coverage.edges.sort((left, right) =>
      Buffer.compare(Buffer.from(left.id), Buffer.from(right.id)),
    );
    const implementation = clone(state.closure.implementation);
    implementation.surfaces.push({
      edgeId: remainderEdgeId,
      branchId: "branch.portable.remainder",
      targetVariant: "all",
      targetApplicability: { kind: "all" },
      fixtureObligations: ["fixture.portable.remainder"],
      enforcementBranchId: "enforcement.portable.remainder",
      enforcementRoute: {
        terminalObservedKey: "native-op:portableRemainder",
      },
    });
    const fixtureCatalog = fixtureCatalogForTarget({
      coverage,
      implementation,
      target: target(),
    });
    const targetCells = clone(state.closure.targetCells);
    targetCells.cells.push({
      edgeId: remainderEdgeId,
      target: target(),
      disposition: "unsupported",
      implementationBranchIds: ["branch.portable.remainder"],
      fixtures: [],
      rationale: "Outside the certified scope; no conformance claim is made.",
    });
    const preparation = preparePortablePromotionFromDerivedArtifactsV2({
      reviewedSourceBytes: state.preparation.reviewedSourceBytes,
      coverageBytes: exactBytes(coverage),
      implementationManifestBytes: exactBytes(implementation),
      fixtureCatalogBytes: exactBytes(fixtureCatalog),
      targetCellsBytes: exactBytes(targetCells),
      recipeCatalogBytes: state.preparation.recipeCatalogBytes,
      publicSurfaceExecutionBytes:
        state.preparation.publicSurfaceExecutionBytes,
      outputDispositionEvidenceBytes:
        state.preparation.outputDispositionEvidenceBytes,
      scopeArtifactBytes: state.preparation.scopeArtifactBytes,
      scopeExpansionDiffBytes: state.preparation.scopeExpansionDiffBytes,
      scopeCellMappingBytes: state.preparation.scopeCellMappingBytes,
    });
    const process = detachedProcess(preparation);
    const bundle = buildPortablePromotionBundleV2({
      preparation,
      processes: [process],
    });
    expect(bundle.report.summary).toMatchObject({
      cells: 2,
      conformantCells: 1,
      incompleteCells: 0,
      uncertifiedCells: 1,
    });
    expect(bundle.report.cells[1]).toMatchObject({
      edgeId: remainderEdgeId,
      status: "uncertified",
      requiredFixtures: ["fixture.portable.remainder"],
      passedFixtures: [],
    });
    expect(bundle.validated.targetCells.cells[1].disposition).toBe(
      "unsupported",
    );
  });

  test("refuses a target-cell subset even when its v2 documents are self-consistent", () => {
    const state = derivedPreparation();
    const extraEdge = {
      id: "edge.portable.extra",
      classification: "effects",
      effectMode: "unconditional",
      surface: { kind: "native-op", name: "portableExtra" },
      effects: [{ cap: "cap.portable.extra" }],
    };
    const coverage = clone(state.closure.coverage);
    coverage.edges.push(extraEdge);
    coverage.edges.sort((left, right) =>
      Buffer.compare(Buffer.from(left.id), Buffer.from(right.id)),
    );
    expect(() =>
      preparePortablePromotionFromDerivedArtifactsV2({
        reviewedSourceBytes: state.preparation.reviewedSourceBytes,
        coverageBytes: exactBytes(coverage),
        implementationManifestBytes: exactBytes(state.closure.implementation),
        fixtureCatalogBytes: exactBytes(state.closure.fixtureCatalog),
        scopeArtifactBytes: state.preparation.scopeArtifactBytes,
        scopeExpansionDiffBytes: state.preparation.scopeExpansionDiffBytes,
        scopeCellMappingBytes: state.preparation.scopeCellMappingBytes,
        targetCellsBytes: state.preparation.targetCellsBytes,
        recipeCatalogBytes: state.preparation.recipeCatalogBytes,
        publicSurfaceExecutionBytes:
          state.preparation.publicSurfaceExecutionBytes,
        outputDispositionEvidenceBytes:
          state.preparation.outputDispositionEvidenceBytes,
      }),
    ).toThrow();
  });
});

describe("rich-to-portable projections", () => {
  test("derives exact recipe and public rows for the portable executor", () => {
    const reviewedSource = source();
    const fixtureId = "fixture.portable.bundle";
    const richRecipe = {
      fixtureId,
      planDigest: digest("P"),
      classification: "effects",
      scenario: "allow",
      edgeIds: ["edge.portable.bundle"],
      implementationBranchIds: ["branch.portable.bundle"],
      enforcementBranchIds: ["enforcement.portable.bundle"],
      actionIds: ["cap.portable.bundle"],
      terminalObservedKey: "native-op:portableBundle",
      expectedObservation: {
        kind: "enforcement-branch",
        branchId: "enforcement.portable.bundle",
      },
      route: { surfaceObservedKeys: ["native-op:portableBundle"] },
      adapterProbe: null,
      publicSurfaceProbe: {
        kind: "public-surface-invocation",
        surfaceObservedKey: "native-op:portableBundle",
        command: [...nativeExecutor.command],
      },
      status: "fully-executable",
      residualReasons: [],
    };
    let richRecipes = {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
      profile: "ibex/capsec/1",
      target: target(),
      recipes: [richRecipe],
      summary: {
        requiredFixtures: 1,
        fullyExecutableFixtures: 1,
        internallyVerifiedFixtures: 0,
        adapterExecutableFixtures: 0,
        unresolvedFixtures: 0,
        byScenario: { allow: 1 },
        residualReasons: {},
      },
      recipeCatalogDigest: digest("A"),
    };
    richRecipes.recipeCatalogDigest = computeRecipeCatalogDigest(richRecipes);
    const scopeBinding = bindRichRecipeCatalogScope(richRecipes);
    richRecipes = scopeBinding.catalog;
    const recipes = derivePortableRecipeCatalogV2({
      richRecipeCatalog: richRecipes,
      target: target(),
      expectedFixtureIds: [fixtureId],
      scopeDigest: scopeBinding.scopeDigest,
      expandedEdgeIds: scopeBinding.expandedEdgeIds,
    });
    const recipeBytes = exactBytes(recipes);
    const publicSurface = derivePortablePublicSurfaceExecutionV2({
      richPublicSurfaceExecution: {
        publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
        profile: "ibex/capsec/1",
        sourceRevision: reviewedSource.sourceRevision,
        sourceTreeDigest: reviewedSource.sourceTreeDigest,
        target: target(),
        engine: {
          binaryDigest: reviewedSource.engine.runtimeComponentDigest,
        },
        executions: [
          {
            fixtureId,
            outcome: "passed",
            executor: nativeExecutor.executor,
          },
        ],
      },
      source: reviewedSource,
      richRecipeCatalog: richRecipes,
      recipeCatalog: recipes,
      recipeCatalogBytes: recipeBytes,
      expectedFixtureIds: [fixtureId],
    });
    expect(recipes.recipes[0].planDigest).toBe(
      portableRecipePlanDigest(recipes.recipes[0]),
    );
    expect(publicSurface.executions[0].executor).toBe(nativeExecutor.executor);
    expect(publicSurface.recipeCatalogRawContentDigest).toBe(
      rawContentDigest(recipeBytes),
    );
  });

  test("preserves internal recipes without projecting them as public executions", () => {
    const reviewedSource = source();
    const publicFixtureId = "fixture.portable.bundle";
    const internalFixtureId = "fixture.portable.bundle.internal";
    const publicRecipe = {
      fixtureId: publicFixtureId,
      planDigest: digest("P"),
      classification: "effects",
      scenario: "allow",
      edgeIds: ["edge.portable.bundle"],
      implementationBranchIds: ["branch.portable.bundle"],
      enforcementBranchIds: ["enforcement.portable.bundle"],
      actionIds: ["cap.portable.bundle"],
      terminalObservedKey: "native-op:portableBundle",
      expectedObservation: {
        kind: "enforcement-branch",
        branchId: "enforcement.portable.bundle",
      },
      route: { surfaceObservedKeys: ["native-op:portableBundle"] },
      adapterProbe: null,
      publicSurfaceProbe: {
        kind: "public-surface-invocation",
        surfaceObservedKey: "native-op:portableBundle",
        command: [...nativeExecutor.command],
      },
      status: "fully-executable",
      residualReasons: [],
    };
    const internalRecipe = {
      ...structuredClone(publicRecipe),
      fixtureId: internalFixtureId,
      scenario: "attribution-missing-deny",
      publicSurfaceProbe: null,
      internalInvariantProof: internalInvariantProofPlan(
        "attribution-missing-deny",
      ),
      status: "internally-verified",
      residualReasons: [
        "callback-invariant-attribution-missing-deny-probe-not-authored",
      ],
    };
    let richRecipes = {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
      profile: "ibex/capsec/1",
      target: target(),
      recipes: [publicRecipe, internalRecipe],
      summary: {
        requiredFixtures: 2,
        fullyExecutableFixtures: 1,
        internallyVerifiedFixtures: 1,
        adapterExecutableFixtures: 0,
        unresolvedFixtures: 0,
        byScenario: {
          allow: 1,
          "attribution-missing-deny": 1,
        },
        residualReasons: {
          "callback-invariant-attribution-missing-deny-probe-not-authored": 1,
        },
      },
      recipeCatalogDigest: digest("A"),
    };
    richRecipes.recipeCatalogDigest = computeRecipeCatalogDigest(richRecipes);
    const scopeBinding = bindRichRecipeCatalogScope(richRecipes);
    richRecipes = scopeBinding.catalog;
    const recipes = derivePortableRecipeCatalogV2({
      richRecipeCatalog: richRecipes,
      target: target(),
      expectedFixtureIds: [publicFixtureId, internalFixtureId],
      scopeDigest: scopeBinding.scopeDigest,
      expandedEdgeIds: scopeBinding.expandedEdgeIds,
    });
    const publicSurface = derivePortablePublicSurfaceExecutionV2({
      richPublicSurfaceExecution: {
        publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
        profile: "ibex/capsec/1",
        sourceRevision: reviewedSource.sourceRevision,
        sourceTreeDigest: reviewedSource.sourceTreeDigest,
        target: target(),
        engine: {
          binaryDigest: reviewedSource.engine.runtimeComponentDigest,
        },
        executions: [
          {
            fixtureId: publicFixtureId,
            outcome: "passed",
            executor: nativeExecutor.executor,
          },
        ],
      },
      source: reviewedSource,
      richRecipeCatalog: richRecipes,
      recipeCatalog: recipes,
      recipeCatalogBytes: exactBytes(recipes),
      expectedFixtureIds: [publicFixtureId, internalFixtureId],
    });
    expect(recipes.recipes).toEqual([
      expect.objectContaining({
        fixtureId: publicFixtureId,
        status: "fully-executable",
        executor: nativeExecutor.executor,
      }),
      expect.objectContaining({
        fixtureId: internalFixtureId,
        status: "internally-verified",
        executor: INTERNAL_INVARIANT_EXECUTOR,
      }),
    ]);
    expect(publicSurface.executions.map((row) => row.fixtureId)).toEqual([
      publicFixtureId,
    ]);
    expect(publicSurface.summary).toMatchObject({
      requiredFixtures: 2,
      executableFixtures: 1,
      internallyVerifiedFixtures: 1,
      executedFixtures: 1,
      missingFixtures: 1,
    });
  });

  test("refuses unknown commands and executor relabeling", () => {
    const reviewedSource = source();
    const fixtureId = "fixture.portable.executor";
    const richRecipe = {
      fixtureId,
      planDigest: digest("P"),
      classification: "effects",
      scenario: "allow",
      edgeIds: ["edge.portable.executor"],
      implementationBranchIds: ["branch.portable.executor"],
      enforcementBranchIds: ["enforcement.portable.executor"],
      actionIds: ["cap.portable.executor"],
      terminalObservedKey: "native-op:portableExecutor",
      expectedObservation: { kind: "enforcement-branch" },
      route: { surfaceObservedKeys: ["native-op:portableExecutor"] },
      adapterProbe: null,
      publicSurfaceProbe: {
        kind: "public-surface-invocation",
        surfaceObservedKey: "native-op:portableExecutor",
        command: [...nativeExecutor.command],
      },
      status: "fully-executable",
      residualReasons: [],
    };
    let richRecipes = {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
      profile: "ibex/capsec/1",
      target: target(),
      recipes: [richRecipe],
      summary: {
        requiredFixtures: 1,
        fullyExecutableFixtures: 1,
        internallyVerifiedFixtures: 0,
        adapterExecutableFixtures: 0,
        unresolvedFixtures: 0,
        byScenario: { allow: 1 },
        residualReasons: {},
      },
      recipeCatalogDigest: digest("A"),
    };
    richRecipes.recipeCatalogDigest = computeRecipeCatalogDigest(richRecipes);
    const scopeBinding = bindRichRecipeCatalogScope(richRecipes);
    richRecipes = scopeBinding.catalog;
    const recipes = derivePortableRecipeCatalogV2({
      richRecipeCatalog: richRecipes,
      target: target(),
      expectedFixtureIds: [fixtureId],
      scopeDigest: scopeBinding.scopeDigest,
      expandedEdgeIds: scopeBinding.expandedEdgeIds,
    });
    const recipeBytes = exactBytes(recipes);
    expect(() =>
      derivePortablePublicSurfaceExecutionV2({
        richPublicSurfaceExecution: {
          publicSurfaceExecutionSchema:
            "ibex/capsec-public-surface-executions/1",
          profile: "ibex/capsec/1",
          sourceRevision: reviewedSource.sourceRevision,
          sourceTreeDigest: reviewedSource.sourceTreeDigest,
          target: target(),
          engine: {
            binaryDigest: reviewedSource.engine.runtimeComponentDigest,
          },
          executions: [
            { fixtureId, outcome: "passed", executor: "borrowed-harness" },
          ],
        },
        source: reviewedSource,
        richRecipeCatalog: richRecipes,
        recipeCatalog: recipes,
        recipeCatalogBytes: recipeBytes,
        expectedFixtureIds: [fixtureId],
      }),
    ).toThrow(/executor differs/u);

    richRecipes.recipes[0].publicSurfaceProbe.command = [
      "cargo",
      "test",
      "unreviewed",
    ];
    richRecipes.recipeCatalogDigest = computeRecipeCatalogDigest(richRecipes);
    expect(() =>
      derivePortableRecipeCatalogV2({
        richRecipeCatalog: richRecipes,
        target: target(),
        expectedFixtureIds: [fixtureId],
        scopeDigest: scopeBinding.scopeDigest,
        expandedEdgeIds: scopeBinding.expandedEdgeIds,
      }),
    ).toThrow(/no reviewed executor/u);
  });

  test("derives canonical v4 observations from the validated rich proof projection", () => {
    const reviewedSource = source();
    const key = {
      surfaceId: "surface.native.portable",
      output: "result",
      alias: "portable",
      mode: "all",
      sourceKind: "native-op",
      returnVariant: "default",
      contextId: "javascript.package-call-loaded",
    };
    const richEvidence = {
      outputDispositionEvidenceSchema:
        "ibex/capsec-output-disposition-evidence/3",
      profile: "ibex/capsec/1",
      status: "verified",
      sourceRevision: reviewedSource.sourceRevision,
      sourceTreeDigest: reviewedSource.sourceTreeDigest,
      conformanceRunner: conformanceRunner(reviewedSource),
      target: target(),
      engine: {
        binaryDigest: reviewedSource.engine.runtimeComponentDigest,
      },
      observations: [
        {
          key,
          disposition: "non-path",
          proofKind: "compiled-runtime-return-record",
        },
      ],
    };
    const first = derivePortableOutputDispositionEvidenceV4({
      richOutputDispositionEvidence: richEvidence,
      source: reviewedSource,
    });
    const second = derivePortableOutputDispositionEvidenceV4({
      richOutputDispositionEvidence: clone(richEvidence),
      source: clone(reviewedSource),
    });
    expect(first).toEqual(second);
    expect(first.observations[0].key).toMatch(/^output\.[a-f0-9]{64}$/u);
    expect(first.observations[0].observationDigest).toBe(
      portableOutputDispositionObservationDigest(first.observations[0]),
    );

    const duplicate = clone(richEvidence);
    duplicate.observations.push(clone(duplicate.observations[0]));
    expect(() =>
      derivePortableOutputDispositionEvidenceV4({
        richOutputDispositionEvidence: duplicate,
        source: reviewedSource,
      }),
    ).toThrow(/sorted and unique/u);
  });
});
