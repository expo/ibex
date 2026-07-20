// @ref LLP 0035#reports-and-advertisements — portable publication is joined
// to detached per-process mapping, command, output, and source authority.
// @ref LLP 0035#kill-rules — v1 path/digest identities are never grandfathered
// or coerced into the Phase-2 contract.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  commandAttemptDigest,
  mappedEngineExecutionEvidenceDigest,
  portableConformanceDigest,
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
import { computeDomainDigest, parseJsonStrict } from "./capsec-contract.mjs";
import { conformanceRunnerBindingDigest } from "./capsec-conformance-runner-binding.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const schemasDir = path.join(repoRoot, "schemas");
const clone = (value) => structuredClone(value);
const digest = (character) => `sha256-${character.repeat(43)}`;

const readJson = (filePath) =>
  parseJsonStrict(fs.readFileSync(filePath), path.relative(repoRoot, filePath));
const portableVectors = readJson(
  path.join(
    schemasDir,
    "vectors",
    "portable-engine-provenance-v1.valid.json",
  ),
);
const basePortableEngine = portableVectors.documents.portableIdentity;
const baseMappedEngine = portableVectors.documents.mappedInstance;

function exactBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function parseBytes(bytes, label = "test artifact") {
  return parseJsonStrict(bytes, label);
}

function withSelfDigest(value, field, digestFunction) {
  value[field] = digest("A");
  value[field] = digestFunction(value);
  return value;
}

function defaultTarget() {
  return {
    triple: "aarch64-apple-darwin",
    features: [
      "hermes-frame-attribution",
      "native-compartments",
      "native-lockdown",
    ],
  };
}

function buildFixture({
  target = defaultTarget(),
  authorityTarget = target,
  engine = basePortableEngine,
  authorityEngine = engine,
  authorityFamily = "macos",
  fixtureId = "fixture.portable-engine-example",
  fixtureIds = null,
  mutateMapped = null,
} = {}) {
  target = clone(target);
  authorityTarget = clone(authorityTarget);
  engine = clone(engine);
  authorityEngine = clone(authorityEngine);
  const requiredFixtureIds = fixtureIds
    ? [...fixtureIds].sort()
    : [fixtureId];
  if (requiredFixtureIds.length === 0) {
    throw new Error("test fixture requires at least one fixture ID");
  }
  const sourceRevision = "a".repeat(40);
  const sourceTreeDigest = digest("A");
  const conformanceRunner = {
    sourceRevision,
    sourceTreeDigest,
    artifactId: engine.artifactId,
    buildConsumptionDigest: digest("M"),
    postLinkSetDigest: digest("Q"),
    verificationDigest: digest("U"),
    testExecutableDigest: `sha256-${"e".repeat(64)}`,
  };
  const authorityConformanceRunner = {
    ...clone(conformanceRunner),
    artifactId: authorityEngine.artifactId,
  };
  const executor = "ibex-exact-fixture-evidence-pilot";

  const targetCells = {
    targetCellSchema: "ibex/capsec-target-cells/1",
    profile: "ibex/capsec/1",
    cells: [
      {
        edgeId: "edge.portable-engine-example",
        target: clone(target),
        disposition: "enforced",
        implementationBranchIds: ["branch.portable-engine-example"],
        fixtures: requiredFixtureIds,
        rationale: "Exact fixture evidence is required.",
      },
    ],
  };
  const targetCellsBytes = exactBytes(targetCells);

  const recipes = requiredFixtureIds.map((requiredFixtureId) => {
    const recipe = {
      fixtureId: requiredFixtureId,
      status: "fully-executable",
      executor,
      planDigest: digest("A"),
    };
    recipe.planDigest = portableRecipePlanDigest(recipe);
    return recipe;
  });
  const recipeCatalog = withSelfDigest(
    {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/2",
      profile: "ibex/capsec/1",
      target: clone(target),
      recipes,
      summary: {
        requiredFixtures: requiredFixtureIds.length,
        fullyExecutableFixtures: requiredFixtureIds.length,
        unresolvedFixtures: 0,
      },
      recipeCatalogDigest: digest("A"),
    },
    "recipeCatalogDigest",
    portableRecipeCatalogDigest,
  );
  const recipeCatalogBytes = exactBytes(recipeCatalog);
  const recipeCatalogRawContentDigest = rawContentDigest(recipeCatalogBytes);

  const publicExecutions = requiredFixtureIds.map((requiredFixtureId) => {
    const execution = {
      fixtureId: requiredFixtureId,
      outcome: "passed",
      executor,
      evidenceDigest: digest("A"),
    };
    execution.evidenceDigest =
      portablePublicSurfaceExecutionEvidenceDigest(execution);
    return execution;
  });
  const publicSurfaceExecution = withSelfDigest(
    {
      publicSurfaceExecutionSchema:
        "ibex/capsec-public-surface-executions/2",
      profile: "ibex/capsec/1",
      sourceRevision,
      sourceTreeDigest,
      target: clone(target),
      engine: clone(engine),
      recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
      recipeCatalogRawContentDigest,
      summary: {
        requiredFixtures: requiredFixtureIds.length,
        executableFixtures: requiredFixtureIds.length,
        residualFixtures: 0,
        executedFixtures: requiredFixtureIds.length,
        passedFixtures: requiredFixtureIds.length,
        failedFixtures: 0,
        missingFixtures: 0,
      },
      executions: publicExecutions,
      publicSurfaceExecutionDigest: digest("A"),
    },
    "publicSurfaceExecutionDigest",
    portablePublicSurfaceExecutionDigest,
  );
  const publicSurfaceExecutionBytes = exactBytes(publicSurfaceExecution);
  const publicSurfaceExecutionRawContentDigest = rawContentDigest(
    publicSurfaceExecutionBytes,
  );

  const outputObservation = {
    key: "output.fixture",
    disposition: "non-path",
    proofKind: "compiled-runtime-return-record",
    observationDigest: digest("A"),
  };
  outputObservation.observationDigest =
    portableOutputDispositionObservationDigest(outputObservation);
  const outputDispositionEvidence = {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/4",
    profile: "ibex/capsec/1",
    status: "verified",
    sourceRevision,
    sourceTreeDigest,
    conformanceRunner: clone(conformanceRunner),
    target: clone(target),
    engine: clone(engine),
    summary: { observations: 1 },
    observations: [outputObservation],
  };
  const outputDispositionEvidenceBytes = exactBytes(outputDispositionEvidence);
  const outputDispositionEvidenceRawContentDigest = rawContentDigest(
    outputDispositionEvidenceBytes,
  );

  const portableBindings = {
    sourceRevision,
    sourceTreeDigest,
    conformanceRunner: clone(conformanceRunner),
    engine: clone(engine),
    target: clone(target),
    vocabularyDigest: digest("Q"),
    registryDigest: digest("U"),
    implementationManifestDigest: digest("Y"),
    fixtureCatalogDigest: digest("c"),
    targetCellsRawContentDigest: rawContentDigest(targetCellsBytes),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    recipeCatalogRawContentDigest,
    publicSurfaceExecutionDigest:
      publicSurfaceExecution.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest,
    outputDispositionEvidenceRawContentDigest,
  };
  const bindingDigest = portableExecutionBindingDigest(portableBindings);

  const fixtureArtifacts = requiredFixtureIds.map((requiredFixtureId) => {
    const artifact = withSelfDigest(
      {
        fixtureEvidenceSchema: "ibex/capsec-portable-fixture-evidence/1",
        profile: "ibex/capsec/1",
        sourceRevision,
        sourceTreeDigest,
        target: clone(target),
        engine: clone(engine),
        fixtureId: requiredFixtureId,
        outcome: "passed",
        executor,
        bindingDigest,
        artifactDigest: digest("A"),
      },
      "artifactDigest",
      portableFixtureEvidenceDigest,
    );
    const bytes = exactBytes(artifact);
    return {
      artifact,
      bytes,
      rawContentDigest: rawContentDigest(bytes),
    };
  });
  const fixtureArtifact = fixtureArtifacts[0].artifact;

  const mappedEngine = clone(baseMappedEngine);
  mappedEngine.portable = clone(engine);
  mappedEngine.before.digest = engine.runtimeComponentDigest;
  mappedEngine.after.digest = engine.runtimeComponentDigest;
  mappedEngine.processArchitecture = target.triple.split("-")[0];
  mutateMapped?.(mappedEngine);
  mappedEngine.observationDigest = computeDomainDigest(
    "ibex.mapped-engine-instance-identity.v1",
    mappedEngine,
    ["observationDigest"],
  );
  const evidence = withSelfDigest(
    {
      mappedEngineExecutionEvidenceSchema:
        "ibex/capsec-mapped-engine-execution-evidence/1",
      profile: "ibex/capsec/1",
      authorityClass: "same-runner-authoritative",
      sourceRevision,
      sourceTreeDigest,
      target: clone(target),
      phaseId: "fixture-evidence",
      commandId: "exact-fixture-evidence",
      commandIdentityDigest: digest("E"),
      fixtureIds: requiredFixtureIds,
      outputDigests: fixtureArtifacts.map(
        (fixture) => fixture.rawContentDigest,
      ),
      engine: clone(engine),
      mappedEngine,
      evidenceDigest: digest("A"),
    },
    "evidenceDigest",
    mappedEngineExecutionEvidenceDigest,
  );
  const mappedEvidenceBytes = exactBytes(evidence);
  const mappedEvidenceRawContentDigest = rawContentDigest(mappedEvidenceBytes);

  const attempt = withSelfDigest(
    {
      schema: "ibex/capsec-command-attempt/1",
      attemptId: "attempt-000001",
      commandId: evidence.commandId,
      commandIdentity: evidence.commandIdentityDigest,
      phase: evidence.phaseId,
      displayedInvocation: ["ibex", "--fixture-evidence"],
      declaredInputs: [
        {
          name: "conformanceRunner",
          digest: conformanceRunnerBindingDigest(conformanceRunner),
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
      stdout: {
        bytes: 0,
        digest: digest("4"),
        tail: "",
        truncated: false,
      },
      stderr: {
        bytes: 0,
        digest: digest("4"),
        tail: "",
        truncated: false,
      },
      outputs: [
        ...fixtureArtifacts.map((fixture, index) => ({
          path:
            fixtureArtifacts.length === 1
              ? "/runner/evidence/fixture.json"
              : `/runner/evidence/fixture-${index + 1}.json`,
          bytes: fixture.bytes.byteLength,
          digest: fixture.rawContentDigest,
        })),
        {
          path: "/runner/evidence/mapped-engine.json",
          bytes: mappedEvidenceBytes.byteLength,
          digest: mappedEvidenceRawContentDigest,
        },
      ],
      attemptDigest: digest("A"),
    },
    "attemptDigest",
    commandAttemptDigest,
  );
  const commandAttemptBytes = exactBytes(attempt);
  const evidenceReference = {
    evidenceDigest: evidence.evidenceDigest,
    rawContentDigest: mappedEvidenceRawContentDigest,
    attemptDigest: attempt.attemptDigest,
    attemptRawContentDigest: rawContentDigest(commandAttemptBytes),
  };

  const report = withSelfDigest(
    {
      conformanceSchema: "ibex/capsec-conformance/2",
      profile: "ibex/capsec/1",
      status: "conformant",
      bindings: {
        ...clone(portableBindings),
        mappedEngineExecutionEvidence: [evidenceReference],
      },
      summary: {
        cells: 1,
        conformantCells: 1,
        incompleteCells: 0,
        requiredFixtures: requiredFixtureIds.length,
        passedFixtures: requiredFixtureIds.length,
        missingFixtures: 0,
        failedFixtures: 0,
      },
      executions: fixtureArtifacts.map((fixture) => ({
        fixtureId: fixture.artifact.fixtureId,
        outcome: "passed",
        executor,
        artifactDigest: fixture.artifact.artifactDigest,
        rawContentDigest: fixture.rawContentDigest,
        bindingDigest,
        mappedEngineExecutionEvidenceDigest: evidence.evidenceDigest,
      })),
      cells: [
        {
          edgeId: "edge.portable-engine-example",
          implementationBranchIds: ["branch.portable-engine-example"],
          enforcementBranchIds: ["branch.portable-engine-example"],
          status: "conformant",
          requiredFixtures: requiredFixtureIds,
          passedFixtures: requiredFixtureIds,
          missingFixtures: [],
          failedFixtures: [],
        },
      ],
      conformanceDigest: digest("A"),
    },
    "conformanceDigest",
    portableConformanceDigest,
  );
  const reportBytes = exactBytes(report);

  const authority = {
    portablePromotionAuthoritySchema:
      "ibex/capsec-portable-promotion-authority/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest,
    targets: [
      {
        family: authorityFamily,
        target: clone(authorityTarget),
        engine: clone(authorityEngine),
        conformanceRunner: authorityConformanceRunner,
        vocabularyDigest: report.bindings.vocabularyDigest,
        registryDigest: report.bindings.registryDigest,
        implementationManifestDigest:
          report.bindings.implementationManifestDigest,
        fixtureCatalogDigest: report.bindings.fixtureCatalogDigest,
        targetCellsRawContentDigest:
          report.bindings.targetCellsRawContentDigest,
        recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
        recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          publicSurfaceExecution.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  const authorityBytes = exactBytes(authority);

  const attestations = {
    targetAttestationSchema: "ibex/capsec-target-attestations/2",
    profile: "ibex/capsec/1",
    attestations: [
      {
        target: clone(target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision,
        sourceTreeDigest,
        portableArtifactId: engine.artifactId,
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
        recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          publicSurfaceExecution.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  const advertisements = {
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/2",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: report.bindings.targetCellsRawContentDigest,
    advertisements: [
      {
        target: clone(target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision,
        sourceTreeDigest,
        engine: clone(engine),
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        vocabularyDigest: report.bindings.vocabularyDigest,
        registryDigest: report.bindings.registryDigest,
        implementationManifestDigest:
          report.bindings.implementationManifestDigest,
        fixtureCatalogDigest: report.bindings.fixtureCatalogDigest,
        recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
        recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          publicSurfaceExecution.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest,
      },
    ],
  };

  const input = {
    authorityBytes,
    reportBytes,
    attestationCatalogBytes: exactBytes(attestations),
    advertisementCatalogBytes: exactBytes(advertisements),
    targetCellsBytes,
    recipeCatalogBytes,
    publicSurfaceExecutionBytes,
    outputDispositionEvidenceBytes,
    processes: [
      {
        mappedEvidenceBytes,
        commandAttemptBytes,
        outputArtifactBytes: fixtureArtifacts.map((fixture) => fixture.bytes),
      },
    ],
  };
  return {
    advertisements,
    attempt,
    authority,
    bindingDigest,
    conformanceRunner,
    evidence,
    fixtureArtifact,
    fixtureArtifacts,
    input,
    outputDispositionEvidence,
    publicSurfaceExecution,
    recipeCatalog,
    report,
    target,
  };
}

function mutateJsonBytes(bytes, mutation) {
  const value = parseBytes(bytes);
  mutation(value);
  return exactBytes(value);
}

function rewriteAttemptReferenceChain(input, mutateAttempt) {
  const rewritten = clone(input);
  const attempt = parseBytes(
    rewritten.processes[0].commandAttemptBytes,
    "supervisor attempt",
  );
  mutateAttempt(attempt);
  attempt.attemptDigest = commandAttemptDigest(attempt);
  const attemptBytes = exactBytes(attempt);

  const report = parseBytes(rewritten.reportBytes, "report");
  const reference = report.bindings.mappedEngineExecutionEvidence[0];
  reference.attemptDigest = attempt.attemptDigest;
  reference.attemptRawContentDigest = rawContentDigest(attemptBytes);
  report.conformanceDigest = portableConformanceDigest(report);
  const reportBytes = exactBytes(report);
  const reportRawContentDigest = rawContentDigest(reportBytes);

  const attestations = parseBytes(
    rewritten.attestationCatalogBytes,
    "attestations",
  );
  attestations.attestations[0].conformanceDigest = report.conformanceDigest;
  attestations.attestations[0].reportRawContentDigest =
    reportRawContentDigest;
  attestations.attestations[0].mappedEngineExecutionEvidence = [
    clone(reference),
  ];
  const advertisements = parseBytes(
    rewritten.advertisementCatalogBytes,
    "advertisements",
  );
  advertisements.advertisements[0].conformanceDigest =
    report.conformanceDigest;
  advertisements.advertisements[0].reportRawContentDigest =
    reportRawContentDigest;
  advertisements.advertisements[0].mappedEngineExecutionEvidence = [
    clone(reference),
  ];

  rewritten.processes[0].commandAttemptBytes = attemptBytes;
  rewritten.reportBytes = reportBytes;
  rewritten.attestationCatalogBytes = exactBytes(attestations);
  rewritten.advertisementCatalogBytes = exactBytes(advertisements);
  return rewritten;
}

function rewriteFixtureProcessChain(input, mutateFixture) {
  const rewritten = clone(input);
  const fixture = parseBytes(
    rewritten.processes[0].outputArtifactBytes[0],
    "fixture artifact",
  );
  mutateFixture(fixture);
  fixture.artifactDigest = portableFixtureEvidenceDigest(fixture);
  const fixtureBytes = exactBytes(fixture);
  const fixtureRawDigest = rawContentDigest(fixtureBytes);

  const evidence = parseBytes(
    rewritten.processes[0].mappedEvidenceBytes,
    "mapped evidence",
  );
  evidence.outputDigests = [fixtureRawDigest];
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  const evidenceBytes = exactBytes(evidence);
  const evidenceRawDigest = rawContentDigest(evidenceBytes);

  const attempt = parseBytes(
    rewritten.processes[0].commandAttemptBytes,
    "supervisor attempt",
  );
  attempt.outputs[0].bytes = fixtureBytes.byteLength;
  attempt.outputs[0].digest = fixtureRawDigest;
  attempt.outputs[1].bytes = evidenceBytes.byteLength;
  attempt.outputs[1].digest = evidenceRawDigest;
  attempt.attemptDigest = commandAttemptDigest(attempt);
  const attemptBytes = exactBytes(attempt);
  const evidenceReference = {
    evidenceDigest: evidence.evidenceDigest,
    rawContentDigest: evidenceRawDigest,
    attemptDigest: attempt.attemptDigest,
    attemptRawContentDigest: rawContentDigest(attemptBytes),
  };

  const report = parseBytes(rewritten.reportBytes, "report");
  report.bindings.mappedEngineExecutionEvidence = [evidenceReference];
  report.executions[0].artifactDigest = fixture.artifactDigest;
  report.executions[0].rawContentDigest = fixtureRawDigest;
  report.executions[0].bindingDigest = fixture.bindingDigest;
  report.executions[0].mappedEngineExecutionEvidenceDigest =
    evidence.evidenceDigest;
  report.conformanceDigest = portableConformanceDigest(report);
  const reportBytes = exactBytes(report);
  const reportRawDigest = rawContentDigest(reportBytes);

  const attestations = parseBytes(
    rewritten.attestationCatalogBytes,
    "attestations",
  );
  attestations.attestations[0].conformanceDigest = report.conformanceDigest;
  attestations.attestations[0].reportRawContentDigest = reportRawDigest;
  attestations.attestations[0].mappedEngineExecutionEvidence = [
    clone(evidenceReference),
  ];
  const advertisements = parseBytes(
    rewritten.advertisementCatalogBytes,
    "advertisements",
  );
  advertisements.advertisements[0].conformanceDigest =
    report.conformanceDigest;
  advertisements.advertisements[0].reportRawContentDigest = reportRawDigest;
  advertisements.advertisements[0].mappedEngineExecutionEvidence = [
    clone(evidenceReference),
  ];

  rewritten.reportBytes = reportBytes;
  rewritten.attestationCatalogBytes = exactBytes(attestations);
  rewritten.advertisementCatalogBytes = exactBytes(advertisements);
  rewritten.processes[0].mappedEvidenceBytes = evidenceBytes;
  rewritten.processes[0].commandAttemptBytes = attemptBytes;
  rewritten.processes[0].outputArtifactBytes = [fixtureBytes];
  return rewritten;
}

function orphanFirstExecutionFromMappedEvidence(input) {
  const rewritten = clone(input);
  const retainedFixtureBytes = rewritten.processes[0].outputArtifactBytes[1];
  const retainedFixture = parseBytes(
    retainedFixtureBytes,
    "retained fixture artifact",
  );
  const retainedRawDigest = rawContentDigest(retainedFixtureBytes);

  const evidence = parseBytes(
    rewritten.processes[0].mappedEvidenceBytes,
    "mapped evidence",
  );
  evidence.fixtureIds = [retainedFixture.fixtureId];
  evidence.outputDigests = [retainedRawDigest];
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  const evidenceBytes = exactBytes(evidence);
  const evidenceRawDigest = rawContentDigest(evidenceBytes);

  const attempt = parseBytes(
    rewritten.processes[0].commandAttemptBytes,
    "supervisor attempt",
  );
  const retainedOutput = attempt.outputs.find(
    (output) => output.digest === retainedRawDigest,
  );
  const mappedOutput = attempt.outputs.at(-1);
  mappedOutput.bytes = evidenceBytes.byteLength;
  mappedOutput.digest = evidenceRawDigest;
  attempt.outputs = [retainedOutput, mappedOutput];
  attempt.attemptDigest = commandAttemptDigest(attempt);
  const attemptBytes = exactBytes(attempt);
  const evidenceReference = {
    evidenceDigest: evidence.evidenceDigest,
    rawContentDigest: evidenceRawDigest,
    attemptDigest: attempt.attemptDigest,
    attemptRawContentDigest: rawContentDigest(attemptBytes),
  };

  const report = parseBytes(rewritten.reportBytes, "report");
  report.bindings.mappedEngineExecutionEvidence = [evidenceReference];
  report.executions[0].mappedEngineExecutionEvidenceDigest = digest("I");
  report.executions[1].mappedEngineExecutionEvidenceDigest =
    evidence.evidenceDigest;
  report.conformanceDigest = portableConformanceDigest(report);
  const reportBytes = exactBytes(report);
  const reportRawDigest = rawContentDigest(reportBytes);

  const attestations = parseBytes(
    rewritten.attestationCatalogBytes,
    "attestations",
  );
  attestations.attestations[0].conformanceDigest = report.conformanceDigest;
  attestations.attestations[0].reportRawContentDigest = reportRawDigest;
  attestations.attestations[0].mappedEngineExecutionEvidence = [
    clone(evidenceReference),
  ];
  const advertisements = parseBytes(
    rewritten.advertisementCatalogBytes,
    "advertisements",
  );
  advertisements.advertisements[0].conformanceDigest =
    report.conformanceDigest;
  advertisements.advertisements[0].reportRawContentDigest = reportRawDigest;
  advertisements.advertisements[0].mappedEngineExecutionEvidence = [
    clone(evidenceReference),
  ];

  rewritten.reportBytes = reportBytes;
  rewritten.attestationCatalogBytes = exactBytes(attestations);
  rewritten.advertisementCatalogBytes = exactBytes(advertisements);
  rewritten.processes[0] = {
    mappedEvidenceBytes: evidenceBytes,
    commandAttemptBytes: attemptBytes,
    outputArtifactBytes: [retainedFixtureBytes],
  };
  return rewritten;
}

function expectRefused(input, pattern = undefined) {
  const operation = () => validatePortablePromotionV2(input);
  if (pattern) expect(operation).toThrow(pattern);
  else expect(operation).toThrow();
}

describe("additive Phase-2 portable-engine promotion contract", () => {
  test("strict-validates and joins the complete future promotion input", () => {
    const fixture = buildFixture();
    const result = validatePortablePromotionV2(fixture.input);
    expect(result.report).toEqual(fixture.report);
    expect(result.processes[0].attempt).toEqual(fixture.attempt);
    expect(result.processes[0].evidence).toEqual(fixture.evidence);
    expect(fixture.target.features).not.toEqual(
      fixture.evidence.engine.target.structuralFeatures,
    );
  });

  test("freezes the related fixture, mapped-evidence, command, and report digests", () => {
    const fixture = buildFixture();
    expect(fixture.recipeCatalog.recipes[0].planDigest).toBe(
      "sha256-AMAXq34h0aUY0aaIrQVdhWXNWXK4z66W7mrdwz3nq3c",
    );
    expect(fixture.recipeCatalog.recipeCatalogDigest).toBe(
      "sha256-tbcBW_HOoa9BBGh0otxvItVlhwbVan6HxQdyKJ2vVvQ",
    );
    expect(fixture.publicSurfaceExecution.executions[0].evidenceDigest).toBe(
      "sha256-MxU1J_ukMETJyQtjbNH9Ke4t4V29VNSZ81SYHkvwB88",
    );
    expect(
      fixture.publicSurfaceExecution.publicSurfaceExecutionDigest,
    ).toBe("sha256-UWZrlFMFN8hI5P1BDl2BvZodPuJwcu4KBmOXUnTo0Jw");
    expect(
      fixture.outputDispositionEvidence.observations[0].observationDigest,
    ).toBe("sha256-BnNTBOX_xO0eTu79WUDCocXEKeZOHJYpsGkxcGaIhH4");
    expect(fixture.bindingDigest).toBe(
      "sha256-6D-I0B_DbuFhQ_I09cV3HGuSBnwEbG5lnDW6cX0Gwqw",
    );
    expect(fixture.fixtureArtifact.artifactDigest).toBe(
      "sha256-ZQKNUCrH8FrKnPx3oLuoNpMNI1FCflycXJlfrKT71AI",
    );
    expect(fixture.evidence.evidenceDigest).toBe(
      "sha256-56xJxLAN68R70Wjx5ChJwtsRskMhhFq-WwNe-C_bTec",
    );
    expect(fixture.attempt.attemptDigest).toBe(
      "sha256-pZWLxGhydDKU2DcVM2FJAbZhh_xRiSQFA_48K1kVgw8",
    );
    expect(fixture.report.conformanceDigest).toBe(
      "sha256-65piFYyHRlKALchW-JE_y_IvxhQJagMxL-Y7Xl3RiyE",
    );
    expect(fixture.evidence.outputDigests).toEqual([
      fixture.report.executions[0].rawContentDigest,
    ]);
    expect(fixture.evidence.outputDigests).not.toContain(
      rawContentDigest(fixture.input.processes[0].mappedEvidenceBytes),
    );
  });

  test("recomputes the complete acyclic portable execution binding", () => {
    const input = rewriteFixtureProcessChain(buildFixture().input, (artifact) => {
      artifact.bindingDigest = digest("I");
    });
    expectRefused(
      input,
      /report execution differs from its detached fixture artifact/u,
    );
  });

  test("the execution binding covers every upstream identity and excludes downstream attempts", () => {
    const fixture = buildFixture();
    const baseline = fixture.bindingDigest;
    const mutations = [
      (bindings) => {
        bindings.sourceRevision = "b".repeat(40);
      },
      (bindings) => {
        bindings.sourceTreeDigest = digest("I");
      },
      (bindings) => {
        bindings.target.features.push("substituted-feature");
        bindings.target.features.sort();
      },
      (bindings) => {
        bindings.engine.artifactId = digest("I");
      },
      (bindings) => {
        bindings.vocabularyDigest = digest("I");
      },
      (bindings) => {
        bindings.registryDigest = digest("I");
      },
      (bindings) => {
        bindings.implementationManifestDigest = digest("I");
      },
      (bindings) => {
        bindings.fixtureCatalogDigest = digest("I");
      },
      (bindings) => {
        bindings.targetCellsRawContentDigest = digest("I");
      },
      (bindings) => {
        bindings.recipeCatalogDigest = digest("I");
      },
      (bindings) => {
        bindings.recipeCatalogRawContentDigest = digest("I");
      },
      (bindings) => {
        bindings.publicSurfaceExecutionDigest = digest("I");
      },
      (bindings) => {
        bindings.publicSurfaceExecutionRawContentDigest = digest("I");
      },
      (bindings) => {
        bindings.outputDispositionEvidenceRawContentDigest = digest("I");
      },
    ];
    for (const mutate of mutations) {
      const bindings = clone(fixture.report.bindings);
      mutate(bindings);
      expect(portableExecutionBindingDigest(bindings)).not.toBe(baseline);
    }

    const downstreamOnly = clone(fixture.report.bindings);
    downstreamOnly.mappedEngineExecutionEvidence[0].attemptDigest = digest("I");
    expect(portableExecutionBindingDigest(downstreamOnly)).toBe(baseline);
  });

  test("requires detached mapped evidence and binds the finalized supervisor attempt", () => {
    const fixture = buildFixture();
    const absent = clone(fixture.input);
    absent.processes = [];
    expectRefused(absent, /requires detached mapped evidence/u);

    const missingRunnerInput = rewriteAttemptReferenceChain(
      fixture.input,
      (attempt) => {
        attempt.declaredInputs = attempt.declaredInputs.filter(
          (input) => input.name !== "conformanceRunner",
        );
      },
    );
    expectRefused(missingRunnerInput, /lacks the exact conformance-runner/u);

    const substitutedRunnerInput = rewriteAttemptReferenceChain(
      fixture.input,
      (attempt) => {
        attempt.declaredInputs.find(
          (input) => input.name === "conformanceRunner",
        ).digest = digest("I");
      },
    );
    expectRefused(
      substitutedRunnerInput,
      /lacks the exact conformance-runner/u,
    );

    const commandMismatch = clone(fixture.input);
    commandMismatch.processes[0].commandAttemptBytes = mutateJsonBytes(
      commandMismatch.processes[0].commandAttemptBytes,
      (attempt) => {
        attempt.commandIdentity = digest("I");
        attempt.attemptDigest = commandAttemptDigest(attempt);
      },
    );
    expectRefused(commandMismatch, /command binding differs/u);

    const attemptEnvelopeMismatch = clone(fixture.input);
    attemptEnvelopeMismatch.processes[0].commandAttemptBytes = mutateJsonBytes(
      attemptEnvelopeMismatch.processes[0].commandAttemptBytes,
      (attempt) => {
        attempt.attemptId = "attempt-000002";
        attempt.attemptDigest = commandAttemptDigest(attempt);
      },
    );
    expectRefused(attemptEnvelopeMismatch, /finalized supervisor attempt/u);

    const outputMismatch = clone(fixture.input);
    outputMismatch.processes[0].commandAttemptBytes = mutateJsonBytes(
      outputMismatch.processes[0].commandAttemptBytes,
      (attempt) => {
        attempt.outputs[0].digest = digest("I");
        attempt.attemptDigest = commandAttemptDigest(attempt);
      },
    );
    const changedAttempt = parseBytes(
      outputMismatch.processes[0].commandAttemptBytes,
      "changed supervisor attempt",
    );
    outputMismatch.reportBytes = mutateJsonBytes(
      outputMismatch.reportBytes,
      (report) => {
        report.bindings.mappedEngineExecutionEvidence[0].attemptDigest =
          changedAttempt.attemptDigest;
        report.bindings.mappedEngineExecutionEvidence[0].attemptRawContentDigest =
          rawContentDigest(outputMismatch.processes[0].commandAttemptBytes);
        report.conformanceDigest = portableConformanceDigest(report);
      },
    );
    expectRefused(outputMismatch, /outputDigests differ/u);

    const missingOutputBytes = clone(fixture.input);
    missingOutputBytes.processes[0].outputArtifactBytes = [];
    expectRefused(missingOutputBytes, /artifact membership differs/u);
  });

  test("rejects an orphan report execution when another mapped process is complete", () => {
    const fixture = buildFixture({
      fixtureIds: [
        "fixture.portable-engine-alpha",
        "fixture.portable-engine-beta",
      ],
    });
    const input = orphanFirstExecutionFromMappedEvidence(fixture.input);
    expectRefused(input, /report execution references unbound mapped-engine evidence/u);
  });

  test("joins report execution raw and semantic digests to exact output bytes", () => {
    const rawMismatch = clone(buildFixture().input);
    rawMismatch.processes[0].outputArtifactBytes[0] = mutateJsonBytes(
      rawMismatch.processes[0].outputArtifactBytes[0],
      (artifact) => {
        artifact.executor = "substituted-executor";
      },
    );
    expectRefused(rawMismatch, /do not match one exact supervisor output row/u);

    const semanticMismatch = clone(buildFixture().input);
    semanticMismatch.reportBytes = mutateJsonBytes(
      semanticMismatch.reportBytes,
      (report) => {
        report.executions[0].artifactDigest = digest("I");
        report.conformanceDigest = portableConformanceDigest(report);
      },
    );
    expectRefused(semanticMismatch, /differs from its detached fixture artifact/u);
  });

  test("refuses every incomplete or non-passing report shape", () => {
    const cases = [
      (report) => {
        report.status = "incomplete";
      },
      (report) => {
        report.summary.missingFixtures = 1;
      },
      (report) => {
        report.summary.failedFixtures = 1;
      },
      (report) => {
        report.summary.passedFixtures = 0;
      },
      (report) => {
        report.cells[0].status = "incomplete";
        report.cells[0].passedFixtures = [];
        report.cells[0].missingFixtures = [report.cells[0].requiredFixtures[0]];
      },
    ];
    for (const mutation of cases) {
      const input = clone(buildFixture().input);
      input.reportBytes = mutateJsonBytes(input.reportBytes, (report) => {
        mutation(report);
        report.conformanceDigest = portableConformanceDigest(report);
      });
      expectRefused(input);
    }
  });

  test("joins target cells and every independent raw promotion artifact", () => {
    const targetCells = clone(buildFixture().input);
    targetCells.targetCellsBytes = mutateJsonBytes(
      targetCells.targetCellsBytes,
      (catalog) => {
        catalog.cells[0].rationale = "Substituted target cell bytes.";
      },
    );
    expectRefused(targetCells, /target-cell raw bytes differ/u);

    for (const field of [
      "recipeCatalogBytes",
      "publicSurfaceExecutionBytes",
      "outputDispositionEvidenceBytes",
    ]) {
      const input = clone(buildFixture().input);
      input[field] = mutateJsonBytes(input[field], (artifact) => {
        artifact.profile = "ibex/capsec/substituted";
      });
      expectRefused(input);
    }

    const advertisedCells = clone(buildFixture().input);
    advertisedCells.advertisementCatalogBytes = mutateJsonBytes(
      advertisedCells.advertisementCatalogBytes,
      (advertisements) => {
        advertisements.targetCellsRawContentDigest = digest("I");
      },
    );
    expectRefused(advertisedCells, /target-cell raw bytes differ/u);
  });

  test("strict-validates and recomputes recipe, public, and output semantics", () => {
    const unknownNestedRecipe = clone(buildFixture().input);
    unknownNestedRecipe.recipeCatalogBytes = mutateJsonBytes(
      unknownNestedRecipe.recipeCatalogBytes,
      (catalog) => {
        catalog.recipes[0].adapterProbe = {};
      },
    );
    expectRefused(unknownNestedRecipe, /recipe catalog schema invalid/u);

    const missingPublicEvidence = clone(buildFixture().input);
    missingPublicEvidence.publicSurfaceExecutionBytes = mutateJsonBytes(
      missingPublicEvidence.publicSurfaceExecutionBytes,
      (artifact) => {
        delete artifact.executions[0].evidenceDigest;
      },
    );
    expectRefused(
      missingPublicEvidence,
      /public-surface execution schema invalid/u,
    );

    const oldOutputObservation = clone(buildFixture().input);
    oldOutputObservation.outputDispositionEvidenceBytes = mutateJsonBytes(
      oldOutputObservation.outputDispositionEvidenceBytes,
      (artifact) => {
        artifact.observations[0] = {
          fixtureId: "fixture.portable-engine-example",
          disposition: "portable",
        };
      },
    );
    expectRefused(
      oldOutputObservation,
      /output-disposition evidence schema invalid/u,
    );

    const invalidPlanDigest = clone(buildFixture().input);
    invalidPlanDigest.recipeCatalogBytes = mutateJsonBytes(
      invalidPlanDigest.recipeCatalogBytes,
      (catalog) => {
        catalog.recipes[0].planDigest = digest("I");
        catalog.recipeCatalogDigest = portableRecipeCatalogDigest(catalog);
      },
    );
    expectRefused(invalidPlanDigest, /fully executable/u);

    const invalidExecutionDigest = clone(buildFixture().input);
    invalidExecutionDigest.publicSurfaceExecutionBytes = mutateJsonBytes(
      invalidExecutionDigest.publicSurfaceExecutionBytes,
      (artifact) => {
        artifact.executions[0].evidenceDigest = digest("I");
        artifact.publicSurfaceExecutionDigest =
          portablePublicSurfaceExecutionDigest(artifact);
      },
    );
    expectRefused(invalidExecutionDigest, /every required fixture passed/u);

    const invalidObservationDigest = clone(buildFixture().input);
    invalidObservationDigest.outputDispositionEvidenceBytes = mutateJsonBytes(
      invalidObservationDigest.outputDispositionEvidenceBytes,
      (artifact) => {
        artifact.observations[0].observationDigest = digest("I");
      },
    );
    expectRefused(invalidObservationDigest, /invalid semantic digests/u);

    const missingRunnerBinding = clone(buildFixture().input);
    missingRunnerBinding.outputDispositionEvidenceBytes = mutateJsonBytes(
      missingRunnerBinding.outputDispositionEvidenceBytes,
      (artifact) => {
        delete artifact.conformanceRunner;
      },
    );
    expectRefused(
      missingRunnerBinding,
      /output-disposition evidence schema invalid/u,
    );

    const pathBearingRunner = clone(buildFixture().input);
    pathBearingRunner.outputDispositionEvidenceBytes = mutateJsonBytes(
      pathBearingRunner.outputDispositionEvidenceBytes,
      (artifact) => {
        artifact.conformanceRunner.testExecutablePath =
          "/runner/target/debug/deps/ibex";
      },
    );
    expectRefused(
      pathBearingRunner,
      /output-disposition evidence schema invalid/u,
    );
  });

  test("rejects coherent target and portable-identity substitutions against independent authority", () => {
    const changedTarget = defaultTarget();
    changedTarget.features = [
      ...changedTarget.features,
      "substituted-security-feature",
    ].sort();
    const targetSubstitution = buildFixture({
      target: changedTarget,
      authorityTarget: defaultTarget(),
    });
    expectRefused(
      targetSubstitution.input,
      /no unique independently derived target authority/u,
    );

    const changedEngine = clone(basePortableEngine);
    changedEngine.artifactId = digest("I");
    const engineSubstitution = buildFixture({
      engine: changedEngine,
      authorityEngine: basePortableEngine,
    });
    expectRefused(
      engineSubstitution.input,
      /differs from independently derived source, target, engine/u,
    );
  });

  test("dispatches an exact target family and rejects lookalike triples", () => {
    const target = defaultTarget();
    target.triple = "aarch64-apple-darwin-extra";
    const engine = clone(basePortableEngine);
    engine.target.triple = target.triple;
    const fixture = buildFixture({
      target,
      authorityTarget: target,
      engine,
      authorityEngine: engine,
      authorityFamily: "macos",
    });
    expectRefused(fixture.input, /unsupported or ambiguous target family/u);

    const wrongFamily = buildFixture({ authorityFamily: "linux" });
    expectRefused(wrongFamily.input, /wrong exact target-family dispatch/u);
  });

  test("recursively rejects mixed-case and encoded local identity in portable authority", () => {
    for (const localValue of [
      "FiLe%3A%2F%2F%2FUsers%2Fsomeone%2Flibhermes.dylib",
      "0XDEADBEEF",
      "0%58DEADBEEF",
    ]) {
      const engine = clone(basePortableEngine);
      engine.target.structuralFeatures = [
        ...engine.target.structuralFeatures,
        localValue,
      ].sort();
      const fixture = buildFixture({
        engine,
        authorityEngine: engine,
      });
      expectRefused(fixture.input, /host-local path, URI, address/u);
    }
  });

  test("treats ASLR and local object identity as per-process evidence only", () => {
    const first = buildFixture();
    const second = buildFixture({
      mutateMapped(mapped) {
        mapped.canonicalLocalRuntimePath =
          "/another/runner/store/payload/lib/libhermes.dylib";
        mapped.localObject.volume = "dev:99";
        mapped.localObject.file = "inode:9001";
        mapped.before.object = clone(mapped.localObject);
        mapped.after.object = clone(mapped.localObject);
        mapped.mappingProof.platformObservation.mappedObject = clone(
          mapped.localObject,
        );
        mapped.mappingProof.platformObservation.regionStart = "0x200000000";
        mapped.mappingProof.platformObservation.regionEnd = "0x200100000";
      },
    });
    expect(() => validatePortablePromotionV2(first.input)).not.toThrow();
    expect(() => validatePortablePromotionV2(second.input)).not.toThrow();
    expect(second.evidence.engine).toEqual(first.evidence.engine);
    expect(second.evidence.evidenceDigest).not.toBe(first.evidence.evidenceDigest);
    expect(second.report.conformanceDigest).not.toBe(
      first.report.conformanceDigest,
    );
  });

  test("uses CapSec stable IDs rather than the looser portable grammar", () => {
    const fixture = buildFixture({ fixtureId: "Fixture.Uppercase" });
    expectRefused(fixture.input, /schema invalid/u);
  });

  test("unknown and missing fields fail through the sole production entry point", () => {
    const duplicateReportField = clone(buildFixture().input);
    duplicateReportField.reportBytes = Buffer.from(
      Buffer.from(duplicateReportField.reportBytes)
        .toString("utf8")
        .replace(
          '  "profile": "ibex/capsec/1",',
          '  "profile": "ibex/capsec/1",\n  "profile": "ibex/capsec/1",',
        ),
      "utf8",
    );
    expectRefused(duplicateReportField, /duplicate JSON object key/u);

    const unknownReport = clone(buildFixture().input);
    unknownReport.reportBytes = mutateJsonBytes(
      unknownReport.reportBytes,
      (report) => {
        report.unreviewed = true;
      },
    );
    expectRefused(unknownReport, /report schema invalid/u);

    const missingEvidence = clone(buildFixture().input);
    missingEvidence.processes[0].mappedEvidenceBytes = mutateJsonBytes(
      missingEvidence.processes[0].mappedEvidenceBytes,
      (evidence) => {
        delete evidence.commandId;
      },
    );
    expectRefused(missingEvidence, /evidence schema invalid/u);

    const unknownAttempt = clone(buildFixture().input);
    unknownAttempt.processes[0].commandAttemptBytes = mutateJsonBytes(
      unknownAttempt.processes[0].commandAttemptBytes,
      (attempt) => {
        attempt.unreviewed = true;
      },
    );
    expectRefused(unknownAttempt, /attempt schema invalid/u);

    const unknownAuthority = clone(buildFixture().input);
    unknownAuthority.authorityBytes = mutateJsonBytes(
      unknownAuthority.authorityBytes,
      (authority) => {
        authority.unreviewed = true;
      },
    );
    expectRefused(unknownAuthority, /authority schema invalid/u);

    const missingAttestationField = clone(buildFixture().input);
    missingAttestationField.attestationCatalogBytes = mutateJsonBytes(
      missingAttestationField.attestationCatalogBytes,
      (catalog) => {
        delete catalog.attestations[0].portableArtifactId;
      },
    );
    expectRefused(missingAttestationField, /attestations schema invalid/u);

    const missingInput = clone(buildFixture().input);
    delete missingInput.authorityBytes;
    expectRefused(missingInput, /unknown or missing fields/u);
  });

  test("does not coerce the old combined path/digest identity into v2", () => {
    const oldCombinedIdentity = {
      engineArtifactPath: "/tmp/hermesvm.framework/hermesvm",
      kind: "hermes",
      binaryDigest: digest("I"),
      object: { platform: "macos", volume: "dev:1", file: "inode:2" },
      targetArchitecture: "aarch64",
      structuralFeatures: ["framework"],
    };
    const input = clone(buildFixture().input);
    input.reportBytes = mutateJsonBytes(input.reportBytes, (report) => {
      report.bindings.engine = oldCombinedIdentity;
      report.conformanceDigest = portableConformanceDigest(report);
    });
    expectRefused(input, /report schema invalid/u);
  });

  test("valid future documents leave current promotion authority closed", () => {
    const fixture = buildFixture();
    expect(() => validatePortablePromotionV2(fixture.input)).not.toThrow();
    const currentAttestations = readJson(
      path.join(repoRoot, "capsec", "conformance", "target-attestations.json"),
    );
    const currentAdvertisements = readJson(
      path.join(repoRoot, "capsec", "generated", "target-advertisements.json"),
    );
    const trustPolicy = readJson(
      path.join(schemasDir, "portable-engine-provenance-trust-policy-v1.json"),
    );
    expect(currentAttestations.targetAttestationSchema).toBe(
      "ibex/capsec-target-attestations/1",
    );
    expect(currentAttestations.attestations).toEqual([]);
    expect(currentAdvertisements.targetAdvertisementSchema).toBe(
      "ibex/capsec-target-advertisements/1",
    );
    expect(currentAdvertisements.advertisements).toEqual([]);
    expect(trustPolicy.portableArtifactAcceptanceEnabled).toBe(false);
  });
});
