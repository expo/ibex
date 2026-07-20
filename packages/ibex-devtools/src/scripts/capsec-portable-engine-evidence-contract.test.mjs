// @ref LLP 0035#reports-and-advertisements — publication identity is portable
// while mapped paths, objects, and ASLR addresses remain detached per process.
// @ref LLP 0035#kill-rules — v1 path/digest identities are never grandfathered
// or coerced into the Phase-2 contract.

import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertPortablePublicationLocality,
  mappedEngineExecutionEvidenceDigest,
  portableConformanceDigest,
  rawContentDigest,
  validateMappedEngineExecutionEvidence,
  validatePortableConformanceReportV2,
  validatePortablePromotionJoin,
} from "./capsec-portable-engine-evidence-contract.mjs";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const schemasDir = path.join(repoRoot, "schemas");

const readJson = (filePath) =>
  parseJsonStrict(fs.readFileSync(filePath), path.relative(repoRoot, filePath));
const clone = (value) => structuredClone(value);
const digest = (character) => `sha256-${character.repeat(43)}`;

const portableVectors = readJson(
  path.join(
    schemasDir,
    "vectors",
    "portable-engine-provenance-v1.valid.json",
  ),
);
const portableEngine = portableVectors.documents.portableIdentity;
const mappedEngine = portableVectors.documents.mappedInstance;

const futureSchemaFiles = [
  "portable-engine-common-v1.schema.json",
  "portable-engine-artifact-identity-v1.schema.json",
  "mapped-engine-instance-identity-v1.schema.json",
  "capsec-portable-engine-evidence-common-v1.schema.json",
  "capsec-mapped-engine-execution-evidence-v1.schema.json",
  "capsec-conformance-report-v2.schema.json",
  "capsec-target-attestations-v2.schema.json",
  "capsec-target-advertisements-v2.schema.json",
];

function futureValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, validateSchema: true });
  for (const name of futureSchemaFiles) {
    ajv.addSchema(readJson(path.join(schemasDir, name)));
  }
  const get = (name) => {
    const validate = ajv.getSchema(`https://ibex.dev/schemas/${name}`);
    if (!validate) throw new Error(`future schema did not compile: ${name}`);
    return validate;
  };
  return {
    evidence: get("capsec-mapped-engine-execution-evidence-v1.schema.json"),
    report: get("capsec-conformance-report-v2.schema.json"),
    attestations: get("capsec-target-attestations-v2.schema.json"),
    advertisements: get("capsec-target-advertisements-v2.schema.json"),
  };
}

function exactBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function buildFixture() {
  const target = {
    triple: "aarch64-apple-darwin",
    // These are CapSec security properties. They intentionally differ from
    // portableEngine.target.structuralFeatures (framework/package shape).
    features: [
      "hermes-frame-attribution",
      "native-compartments",
      "native-lockdown",
    ],
  };
  const fixtureId = "fixture.portable-engine-example";
  const evidence = {
    mappedEngineExecutionEvidenceSchema:
      "ibex/capsec-mapped-engine-execution-evidence/1",
    profile: "ibex/capsec/1",
    authorityClass: "same-runner-authoritative",
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: digest("A"),
    target,
    phaseId: "fixture-evidence",
    commandId: "exact-fixture-evidence",
    commandIdentityDigest: digest("E"),
    fixtureIds: [fixtureId],
    outputDigests: [digest("I")],
    engine: clone(portableEngine),
    mappedEngine: clone(mappedEngine),
    evidenceDigest: digest("M"),
  };
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  const evidenceBytes = exactBytes(evidence);
  const evidenceReference = {
    evidenceDigest: evidence.evidenceDigest,
    rawContentDigest: rawContentDigest(evidenceBytes),
  };
  const report = {
    conformanceSchema: "ibex/capsec-conformance/2",
    profile: "ibex/capsec/1",
    status: "conformant",
    bindings: {
      sourceRevision: evidence.sourceRevision,
      sourceTreeDigest: evidence.sourceTreeDigest,
      engine: clone(portableEngine),
      target: clone(target),
      vocabularyDigest: digest("Q"),
      registryDigest: digest("U"),
      implementationManifestDigest: digest("Y"),
      fixtureCatalogDigest: digest("c"),
      recipeCatalogDigest: digest("g"),
      publicSurfaceExecutionDigest: digest("k"),
      outputDispositionEvidenceRawContentDigest: digest("o"),
      mappedEngineExecutionEvidence: [evidenceReference],
    },
    summary: {
      cells: 1,
      conformantCells: 1,
      incompleteCells: 0,
      requiredFixtures: 1,
      passedFixtures: 1,
      missingFixtures: 0,
      failedFixtures: 0,
    },
    executions: [
      {
        fixtureId,
        outcome: "passed",
        executor: "ibex-exact-fixture-evidence-pilot",
        artifactDigest: digest("s"),
        rawContentDigest: digest("w"),
        bindingDigest: digest("0"),
        mappedEngineExecutionEvidenceDigest: evidence.evidenceDigest,
      },
    ],
    cells: [
      {
        edgeId: "edge.portable-engine-example",
        implementationBranchIds: ["branch.portable-engine-example"],
        enforcementBranchIds: ["branch.portable-engine-example"],
        status: "conformant",
        requiredFixtures: [fixtureId],
        passedFixtures: [fixtureId],
        missingFixtures: [],
        failedFixtures: [],
      },
    ],
    conformanceDigest: digest("4"),
  };
  report.conformanceDigest = portableConformanceDigest(report);
  const reportBytes = exactBytes(report);
  const attestations = {
    targetAttestationSchema: "ibex/capsec-target-attestations/2",
    profile: "ibex/capsec/1",
    attestations: [
      {
        target: clone(target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision: evidence.sourceRevision,
        sourceTreeDigest: evidence.sourceTreeDigest,
        portableArtifactId: portableEngine.artifactId,
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        recipeCatalogDigest: report.bindings.recipeCatalogDigest,
        recipeCatalogRawContentDigest: digest("8"),
        publicSurfaceExecutionDigest:
          report.bindings.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest: digest("A"),
        outputDispositionEvidenceRawContentDigest:
          report.bindings.outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  const advertisements = {
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/2",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: digest("E"),
    advertisements: [
      {
        target: clone(target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision: evidence.sourceRevision,
        sourceTreeDigest: evidence.sourceTreeDigest,
        engine: clone(portableEngine),
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        vocabularyDigest: report.bindings.vocabularyDigest,
        registryDigest: report.bindings.registryDigest,
        implementationManifestDigest:
          report.bindings.implementationManifestDigest,
        fixtureCatalogDigest: report.bindings.fixtureCatalogDigest,
        recipeCatalogDigest: report.bindings.recipeCatalogDigest,
        recipeCatalogRawContentDigest:
          attestations.attestations[0].recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          report.bindings.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          attestations.attestations[0].publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          report.bindings.outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  return {
    target,
    evidence,
    evidenceBytes,
    evidenceReference,
    report,
    reportBytes,
    attestations,
    advertisements,
  };
}

function expectValid(validate, value) {
  expect(validate(value), JSON.stringify(validate.errors, null, 2)).toBe(true);
}

function expectInvalid(validate, value) {
  expect(validate(value), "unexpectedly accepted a future contract mutation").toBe(
    false,
  );
}

function refreshMappedAndEvidenceDigests(evidence) {
  evidence.mappedEngine.observationDigest = computeDomainDigest(
    "ibex.mapped-engine-instance-identity.v1",
    evidence.mappedEngine,
    ["observationDigest"],
  );
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  return evidence;
}

function refreshReportDigest(report) {
  report.conformanceDigest = portableConformanceDigest(report);
  return report;
}

describe("additive Phase-2 portable-engine evidence contracts", () => {
  test("compile as exact additive schemas and accept the joined future documents", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    expectValid(validators.evidence, fixture.evidence);
    expectValid(validators.report, fixture.report);
    expectValid(validators.attestations, fixture.attestations);
    expectValid(validators.advertisements, fixture.advertisements);
    const postExecutionEnvelopeShape = clone(fixture.evidence);
    postExecutionEnvelopeShape.commandEvidenceDigest =
      postExecutionEnvelopeShape.commandIdentityDigest;
    delete postExecutionEnvelopeShape.commandIdentityDigest;
    expectInvalid(validators.evidence, postExecutionEnvelopeShape);
    expect(() =>
      validateMappedEngineExecutionEvidence(fixture.evidence),
    ).not.toThrow();
    expect(() =>
      validatePortableConformanceReportV2(fixture.report, {
        detachedEvidence: [
          { bytes: fixture.evidenceBytes, evidence: fixture.evidence },
        ],
      }),
    ).not.toThrow();
    expect(() =>
      validatePortablePromotionJoin({
        report: fixture.report,
        reportBytes: fixture.reportBytes,
        attestations: fixture.attestations,
        advertisements: fixture.advertisements,
      }),
    ).not.toThrow();
  });

  test("freeze the new digest domains and self-excluding projections", () => {
    const fixture = buildFixture();
    expect(fixture.evidence.evidenceDigest).toBe(
      "sha256-tB4i31hrjfEnsLVCacveH2OpEdbo6QkHp7zaaJMiz3s",
    );
    expect(fixture.report.conformanceDigest).toBe(
      "sha256-WWQT0w_nYzrv2EJ04YUIc2OuTVhjwbFvPCnYQf6eZHE",
    );
    expect(fixture.evidence.outputDigests).not.toContain(
      rawContentDigest(fixture.evidenceBytes),
    );

    const changedEvidence = clone(fixture.evidence);
    changedEvidence.commandId = "another-engine-command";
    expect(mappedEngineExecutionEvidenceDigest(changedEvidence)).not.toBe(
      fixture.evidence.evidenceDigest,
    );
    const changedReport = clone(fixture.report);
    changedReport.summary.passedFixtures = 0;
    expect(portableConformanceDigest(changedReport)).not.toBe(
      fixture.report.conformanceDigest,
    );
  });

  test("does not equate CapSec security features with package structural features", () => {
    const fixture = buildFixture();
    expect(fixture.target.features).not.toEqual(
      fixture.evidence.engine.target.structuralFeatures,
    );
    expect(() =>
      validateMappedEngineExecutionEvidence(fixture.evidence),
    ).not.toThrow();
  });

  test("treats ASLR and object/path observations as per-process evidence only", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    const secondProcess = clone(fixture.evidence);
    secondProcess.mappedEngine.canonicalLocalRuntimePath =
      "/another/runner/store/payload/lib/libhermes.dylib";
    secondProcess.mappedEngine.localObject.volume = "dev:99";
    secondProcess.mappedEngine.localObject.file = "inode:9001";
    secondProcess.mappedEngine.before.object = clone(
      secondProcess.mappedEngine.localObject,
    );
    secondProcess.mappedEngine.after.object = clone(
      secondProcess.mappedEngine.localObject,
    );
    secondProcess.mappedEngine.mappingProof.platformObservation.mappedObject =
      clone(secondProcess.mappedEngine.localObject);
    secondProcess.mappedEngine.mappingProof.platformObservation.regionStart =
      "0x200000000";
    secondProcess.mappedEngine.mappingProof.platformObservation.regionEnd =
      "0x200100000";
    refreshMappedAndEvidenceDigests(secondProcess);

    expectValid(validators.evidence, secondProcess);
    expect(() => validateMappedEngineExecutionEvidence(secondProcess)).not.toThrow();
    expect(secondProcess.engine).toEqual(fixture.evidence.engine);
    expect(secondProcess.evidenceDigest).not.toBe(fixture.evidence.evidenceDigest);
    expect(secondProcess.mappedEngine.observationDigest).not.toBe(
      fixture.evidence.mappedEngine.observationDigest,
    );
  });

  test("rejects portable-to-mapped substitutions even when every digest is refreshed", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    const substituted = clone(fixture.evidence);
    substituted.mappedEngine.portable.artifactId = digest("I");
    refreshMappedAndEvidenceDigests(substituted);
    expectValid(validators.evidence, substituted);
    expect(() => validateMappedEngineExecutionEvidence(substituted)).toThrow(
      /complete portable engine identity/u,
    );

    const changedBytes = clone(fixture.evidence);
    changedBytes.mappedEngine.after.digest =
      `sha256-${"6".repeat(64)}`;
    refreshMappedAndEvidenceDigests(changedBytes);
    expectValid(validators.evidence, changedBytes);
    expect(() => validateMappedEngineExecutionEvidence(changedBytes)).toThrow(
      /portable runtime component/u,
    );

    const staleMappedDigest = clone(fixture.evidence);
    staleMappedDigest.mappedEngine.mappingProof.platformObservation.regionStart =
      "0x300000000";
    staleMappedDigest.evidenceDigest =
      mappedEngineExecutionEvidenceDigest(staleMappedDigest);
    expectValid(validators.evidence, staleMappedDigest);
    expect(() => validateMappedEngineExecutionEvidence(staleMappedDigest)).toThrow(
      /instance observation digest mismatch/u,
    );
  });

  test("rejects missing, substituted, or misbound detached process evidence", () => {
    const fixture = buildFixture();
    expect(() =>
      validatePortableConformanceReportV2(fixture.report, {
        detachedEvidence: [],
      }),
    ).toThrow(/membership differs/u);

    const wrongBytes = Buffer.from(fixture.evidenceBytes);
    wrongBytes[wrongBytes.length - 2] ^= 1;
    expect(() =>
      validatePortableConformanceReportV2(fixture.report, {
        detachedEvidence: [{ bytes: wrongBytes }],
      }),
    ).toThrow();

    const wrongPortable = clone(fixture.evidence);
    wrongPortable.engine.artifactId = digest("M");
    wrongPortable.mappedEngine.portable = clone(wrongPortable.engine);
    refreshMappedAndEvidenceDigests(wrongPortable);
    const wrongPortableBytes = exactBytes(wrongPortable);
    const report = clone(fixture.report);
    report.bindings.mappedEngineExecutionEvidence = [
      {
        evidenceDigest: wrongPortable.evidenceDigest,
        rawContentDigest: rawContentDigest(wrongPortableBytes),
      },
    ];
    report.executions[0].mappedEngineExecutionEvidenceDigest =
      wrongPortable.evidenceDigest;
    refreshReportDigest(report);
    expect(() =>
      validatePortableConformanceReportV2(report, {
        detachedEvidence: [{ bytes: wrongPortableBytes }],
      }),
    ).toThrow(/portable bindings/u);

    const unknownReference = clone(fixture.report);
    unknownReference.executions[0].mappedEngineExecutionEvidenceDigest =
      digest("Q");
    refreshReportDigest(unknownReference);
    expect(() => validatePortableConformanceReportV2(unknownReference)).toThrow(
      /unknown mapped-engine evidence/u,
    );

    const unsortedReferences = clone(fixture.report);
    unsortedReferences.bindings.mappedEngineExecutionEvidence.push({
      evidenceDigest: digest("A"),
      rawContentDigest: digest("E"),
    });
    refreshReportDigest(unsortedReferences);
    expect(() => validatePortableConformanceReportV2(unsortedReferences)).toThrow(
      /not canonically ordered/u,
    );

    const repeatedSemanticReference = clone(fixture.report);
    repeatedSemanticReference.bindings.mappedEngineExecutionEvidence.push({
      evidenceDigest: fixture.evidence.evidenceDigest,
      rawContentDigest: digest("E"),
    });
    repeatedSemanticReference.bindings.mappedEngineExecutionEvidence.sort(
      (left, right) =>
        canonicalJson([left.evidenceDigest, left.rawContentDigest]) <
        canonicalJson([right.evidenceDigest, right.rawContentDigest])
          ? -1
          : 1,
    );
    refreshReportDigest(repeatedSemanticReference);
    expect(() =>
      validatePortableConformanceReportV2(repeatedSemanticReference),
    ).toThrow(/repeats an evidence digest/u);
  });

  test("report, attestation, and advertisement recursively exclude local identity", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    for (const value of [
      fixture.report,
      fixture.attestations,
      fixture.advertisements,
    ]) {
      expect(() => assertPortablePublicationLocality(value)).not.toThrow();
    }

    const reportWithOldPath = clone(fixture.report);
    reportWithOldPath.bindings.engine.engineArtifactPath = "/Users/runner/hermes";
    expectInvalid(validators.report, reportWithOldPath);
    expect(() => assertPortablePublicationLocality(reportWithOldPath)).toThrow(
      /mapped\/local engine field/u,
    );

    const reportWithAddress = clone(fixture.report);
    reportWithAddress.executions[0].executor = "0x100000000";
    refreshReportDigest(reportWithAddress);
    expectValid(validators.report, reportWithAddress);
    expect(() => assertPortablePublicationLocality(reportWithAddress)).toThrow(
      /host-local path, address/u,
    );

    const attestationWithOldDigest = clone(fixture.attestations);
    attestationWithOldDigest.attestations[0].engineBinaryDigest = digest("U");
    expectInvalid(validators.attestations, attestationWithOldDigest);
    expect(() =>
      assertPortablePublicationLocality(attestationWithOldDigest),
    ).toThrow(/mapped\/local engine field/u);

    const advertisementWithMapping = clone(fixture.advertisements);
    advertisementWithMapping.advertisements[0].mappedEngine = clone(mappedEngine);
    expectInvalid(validators.advertisements, advertisementWithMapping);
    expect(() =>
      assertPortablePublicationLocality(advertisementWithMapping),
    ).toThrow(/mapped\/local engine field/u);
  });

  test("does not coerce the v1 combined path/digest identity into v2", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    const oldCombinedIdentity = {
      engineArtifactPath:
        "/repo/ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
      kind: "hermes",
      binaryDigest: digest("Y"),
      object: { platform: "apple", volume: "dev:1", file: "ino:2" },
      targetArchitecture: "aarch64",
      structuralFeatures: fixture.target.features,
    };
    const oldReportShape = clone(fixture.report);
    oldReportShape.bindings.engine = oldCombinedIdentity;
    expectInvalid(validators.report, oldReportShape);

    const renamed = {
      artifactKind: oldCombinedIdentity.kind,
      runtimeComponentDigest: `sha256-${"5".repeat(64)}`,
      target: {
        triple: fixture.target.triple,
        structuralFeatures: oldCombinedIdentity.structuralFeatures,
      },
    };
    const renamedReportShape = clone(fixture.report);
    renamedReportShape.bindings.engine = renamed;
    expectInvalid(validators.report, renamedReportShape);
  });

  test("promotion joins fail on portable or detached-evidence substitution", () => {
    const fixture = buildFixture();
    const changedReportBytes = Buffer.from(fixture.reportBytes);
    changedReportBytes[changedReportBytes.length - 2] ^= 1;
    expect(() =>
      validatePortablePromotionJoin({
        report: fixture.report,
        reportBytes: changedReportBytes,
        attestations: fixture.attestations,
        advertisements: fixture.advertisements,
      }),
    ).toThrow();

    const changedAttestation = clone(fixture.attestations);
    changedAttestation.attestations[0].portableArtifactId = digest("Y");
    expect(() =>
      validatePortablePromotionJoin({
        report: fixture.report,
        reportBytes: fixture.reportBytes,
        attestations: changedAttestation,
        advertisements: fixture.advertisements,
      }),
    ).toThrow(/attestation differs/u);

    const changedAdvertisement = clone(fixture.advertisements);
    changedAdvertisement.advertisements[0].engine.target.structuralFeatures = [
      ...fixture.target.features,
    ];
    expect(() =>
      validatePortablePromotionJoin({
        report: fixture.report,
        reportBytes: fixture.reportBytes,
        attestations: fixture.attestations,
        advertisements: changedAdvertisement,
      }),
    ).toThrow(/advertisement differs/u);

    const changedEvidenceReference = clone(fixture.advertisements);
    changedEvidenceReference.advertisements[0].mappedEngineExecutionEvidence[0]
      .rawContentDigest = digest("c");
    expect(() =>
      validatePortablePromotionJoin({
        report: fixture.report,
        reportBytes: fixture.reportBytes,
        attestations: fixture.attestations,
        advertisements: changedEvidenceReference,
      }),
    ).toThrow(/advertisement differs/u);
  });

  test("valid future documents do not authorize current promotion", () => {
    const validators = futureValidators();
    const fixture = buildFixture();
    expectValid(validators.report, fixture.report);
    expectValid(validators.attestations, fixture.attestations);
    expectValid(validators.advertisements, fixture.advertisements);

    const currentAttestations = readJson(
      path.join(repoRoot, "capsec", "conformance", "target-attestations.json"),
    );
    const currentAdvertisements = readJson(
      path.join(repoRoot, "capsec", "generated", "target-advertisements.json"),
    );
    const trustPolicy = readJson(
      path.join(
        schemasDir,
        "portable-engine-provenance-trust-policy-v1.json",
      ),
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
