// Additive Phase-2 contract helpers. These validate frozen future evidence
// shapes; they are intentionally not called by the live v1 conformance runner.
//
// @ref LLP 0035#runtime-identity-split — portable publication identity and
// per-process mapped identity are different authority layers.
// @ref LLP 0035#reports-and-advertisements — reports and advertisements carry
// only the portable engine while detached execution evidence retains mapping.
// @ref LLP 0032#authority-boundary — portable engine equality does not turn a
// diagnostic or cross-runner record into promotion authority.

import { createHash } from "node:crypto";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

export const MAPPED_ENGINE_EXECUTION_EVIDENCE_SCHEMA =
  "ibex/capsec-mapped-engine-execution-evidence/1";
export const MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN =
  "ibex:capsec:mapped-engine-execution-evidence:1";
export const PORTABLE_CONFORMANCE_SCHEMA = "ibex/capsec-conformance/2";
export const PORTABLE_CONFORMANCE_DOMAIN = "ibex:capsec:conformance:2";
export const PORTABLE_TARGET_ATTESTATIONS_SCHEMA =
  "ibex/capsec-target-attestations/2";
export const PORTABLE_TARGET_ADVERTISEMENTS_SCHEMA =
  "ibex/capsec-target-advertisements/2";

const FORBIDDEN_PUBLICATION_KEYS = new Set([
  "after",
  "before",
  "binaryDigest",
  "canonicalLocalRuntimePath",
  "engineArtifactPath",
  "engineBinaryDigest",
  "localObject",
  "mappedEngine",
  "mappedObject",
  "mappingProof",
  "object",
  "observationDigest",
  "processArchitecture",
  "regionEnd",
  "regionStart",
  "targetArchitecture",
]);

const LOCAL_STRING_PATTERNS = [
  /^\//u,
  /^[A-Za-z]:[\\/]/u,
  /^\\\\/u,
  /^file:\/\//u,
  /^0x[0-9a-f]+$/u,
  /^(?:dev|file|ino|inode|volume):/u,
];

const compareUtf8 = (left, right) =>
  Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertCanonicalScalarSet(values, label) {
  invariant(Array.isArray(values), `${label} must be an array`);
  const canonical = [...new Set(values)].sort(compareUtf8);
  invariant(
    same(values, canonical),
    `${label} must be a canonically ordered unique set`,
  );
}

function assertCanonicalEvidenceReferences(references, label) {
  invariant(Array.isArray(references) && references.length > 0, `${label} is empty`);
  const canonical = [...references].sort((left, right) =>
    compareUtf8(
      canonicalJson([left.evidenceDigest, left.rawContentDigest]),
      canonicalJson([right.evidenceDigest, right.rawContentDigest]),
    ),
  );
  invariant(same(references, canonical), `${label} is not canonically ordered`);
  invariant(
    new Set(references.map((reference) => reference.evidenceDigest)).size ===
      references.length,
    `${label} repeats an evidence digest`,
  );
  invariant(
    new Set(references.map((reference) => reference.rawContentDigest)).size ===
      references.length,
    `${label} repeats a raw-content digest`,
  );
}

export function rawContentDigest(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64url")}`;
}

export function mappedEngineExecutionEvidenceDigest(evidence) {
  return computeDomainDigest(
    MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN,
    evidence,
    ["evidenceDigest"],
  );
}

export function portableConformanceDigest(report) {
  return computeDomainDigest(PORTABLE_CONFORMANCE_DOMAIN, report, [
    "conformanceDigest",
  ]);
}

/**
 * Publication documents may contain digests of local evidence, but never the
 * local observation itself or a textual path/address smuggled through a field
 * whose JSON schema merely says "string".
 */
export function assertPortablePublicationLocality(value, label = "$") {
  if (typeof value === "string") {
    invariant(
      !LOCAL_STRING_PATTERNS.some((pattern) => pattern.test(value)),
      `${label} contains a host-local path, address, or object identity`,
    );
    return value;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertPortablePublicationLocality(item, `${label}[${index}]`),
    );
    return value;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      invariant(
        !FORBIDDEN_PUBLICATION_KEYS.has(key),
        `${label}.${key} is a mapped/local engine field`,
      );
      assertPortablePublicationLocality(child, `${label}.${key}`);
    }
  }
  return value;
}

export function validateMappedEngineExecutionEvidence(evidence) {
  invariant(
    evidence?.mappedEngineExecutionEvidenceSchema ===
      MAPPED_ENGINE_EXECUTION_EVIDENCE_SCHEMA,
    "mapped-engine execution evidence has the wrong schema",
  );
  invariant(
    evidence.authorityClass === "same-runner-authoritative",
    "mapped-engine execution evidence is not same-runner authoritative",
  );
  assertCanonicalScalarSet(evidence.target?.features, "target.features");
  assertCanonicalScalarSet(
    evidence.engine?.target?.structuralFeatures,
    "engine.target.structuralFeatures",
  );
  assertCanonicalScalarSet(evidence.fixtureIds, "fixtureIds");
  assertCanonicalScalarSet(evidence.outputDigests, "outputDigests");

  const mapped = evidence.mappedEngine;
  invariant(
    same(mapped?.portable, evidence.engine),
    "mapped engine does not carry the complete portable engine identity",
  );
  invariant(
    evidence.target?.triple === evidence.engine?.target?.triple,
    "CapSec target triple does not match the portable engine target",
  );
  invariant(
    same(mapped?.before?.object, mapped?.localObject) &&
      same(mapped?.after?.object, mapped?.localObject),
    "mapped before/after observations do not identify the retained local object",
  );
  invariant(
    mapped?.before?.digest === evidence.engine?.runtimeComponentDigest &&
      mapped?.after?.digest === evidence.engine?.runtimeComponentDigest,
    "mapped before/after bytes do not match the portable runtime component",
  );
  invariant(
    mapped?.before?.size === mapped?.after?.size,
    "mapped runtime size changed during the process evidence interval",
  );
  invariant(
    mapped?.processArchitecture === evidence.engine?.target?.triple.split("-")[0],
    "mapped process architecture does not match the portable engine target",
  );
  invariant(
    mapped?.observationDigest ===
      computeDomainDigest("ibex.mapped-engine-instance-identity.v1", mapped, [
        "observationDigest",
      ]),
    "mapped-engine instance observation digest mismatch",
  );

  const proof = mapped?.mappingProof;
  const observation = proof?.platformObservation;
  if (evidence.target.triple.includes("-apple-")) {
    invariant(
      proof?.class === "macos-proc-pid-region-path-info" &&
        observation?.platform === "macos" &&
        same(observation.mappedObject, mapped.localObject),
      "Apple evidence does not contain the admitted mapped-region object proof",
    );
  } else if (evidence.target.triple.includes("-windows-")) {
    invariant(
      proof?.class === "windows-locked-module-closure" &&
        observation?.platform === "windows" &&
        same(observation.runtimeModule?.object, mapped.localObject),
      "Windows evidence does not contain the admitted locked-module proof",
    );
  } else {
    invariant(
      proof?.class === "linux-proc-self-maps" &&
        observation?.platform === "linux" &&
        same(observation.mappedObject, mapped.localObject),
      "Unix evidence does not contain the admitted mapped-region object proof",
    );
  }

  invariant(
    evidence.evidenceDigest === mappedEngineExecutionEvidenceDigest(evidence),
    "mapped-engine execution evidence digest mismatch",
  );
  return evidence;
}

function parsedDetachedEvidence(record, label) {
  invariant(
    record && (Buffer.isBuffer(record.bytes) || record.bytes instanceof Uint8Array),
    `${label} has no exact raw bytes`,
  );
  const parsed = parseJsonStrict(record.bytes, label);
  if (record.evidence !== undefined) {
    invariant(
      same(parsed, record.evidence),
      `${label} parsed bytes differ from its supplied evidence value`,
    );
  }
  return parsed;
}

export function validatePortableConformanceReportV2(
  report,
  { detachedEvidence = null } = {},
) {
  invariant(
    report?.conformanceSchema === PORTABLE_CONFORMANCE_SCHEMA,
    "portable conformance report has the wrong schema",
  );
  assertPortablePublicationLocality(report, "report");
  assertCanonicalScalarSet(report.bindings?.target?.features, "report target.features");
  assertCanonicalScalarSet(
    report.bindings?.engine?.target?.structuralFeatures,
    "report engine.target.structuralFeatures",
  );
  invariant(
    report.bindings?.target?.triple === report.bindings?.engine?.target?.triple,
    "report target triple does not match the portable engine target",
  );
  const references = report.bindings.mappedEngineExecutionEvidence;
  assertCanonicalEvidenceReferences(
    references,
    "report bindings.mappedEngineExecutionEvidence",
  );
  const referenceByEvidenceDigest = new Map(
    references.map((reference) => [reference.evidenceDigest, reference]),
  );
  for (const execution of report.executions) {
    invariant(
      referenceByEvidenceDigest.has(
        execution.mappedEngineExecutionEvidenceDigest,
      ),
      `${execution.fixtureId}: report execution names unknown mapped-engine evidence`,
    );
  }
  invariant(
    report.conformanceDigest === portableConformanceDigest(report),
    "portable conformance report digest mismatch",
  );

  if (detachedEvidence !== null) {
    invariant(
      Array.isArray(detachedEvidence),
      "detached mapped-engine evidence must be an exact array",
    );
    invariant(
      detachedEvidence.length === references.length,
      "detached mapped-engine evidence membership differs from the report",
    );
    const evidenceByDigest = new Map();
    for (const [index, record] of detachedEvidence.entries()) {
      const evidence = parsedDetachedEvidence(
        record,
        `detached mapped-engine evidence ${index}`,
      );
      validateMappedEngineExecutionEvidence(evidence);
      invariant(
        !evidenceByDigest.has(evidence.evidenceDigest),
        "detached mapped-engine evidence repeats a semantic digest",
      );
      evidenceByDigest.set(evidence.evidenceDigest, { evidence, record });
    }
    for (const reference of references) {
      const joined = evidenceByDigest.get(reference.evidenceDigest);
      invariant(joined, "report references missing detached mapped-engine evidence");
      invariant(
        rawContentDigest(joined.record.bytes) === reference.rawContentDigest,
        "detached mapped-engine evidence raw-content digest mismatch",
      );
      const evidence = joined.evidence;
      invariant(
        evidence.sourceRevision === report.bindings.sourceRevision &&
          evidence.sourceTreeDigest === report.bindings.sourceTreeDigest &&
          same(evidence.target, report.bindings.target) &&
          same(evidence.engine, report.bindings.engine),
        "detached mapped-engine evidence differs from the report's portable bindings",
      );
    }
    for (const execution of report.executions) {
      const evidence = evidenceByDigest.get(
        execution.mappedEngineExecutionEvidenceDigest,
      )?.evidence;
      invariant(
        evidence?.fixtureIds.includes(execution.fixtureId),
        `${execution.fixtureId}: mapped-engine process evidence does not name the fixture`,
      );
    }
  }
  return report;
}

export function validatePortablePromotionJoin({
  report,
  reportBytes,
  attestations,
  advertisements,
}) {
  validatePortableConformanceReportV2(report);
  invariant(
    Buffer.isBuffer(reportBytes) || reportBytes instanceof Uint8Array,
    "portable promotion join has no exact report bytes",
  );
  invariant(
    same(parseJsonStrict(reportBytes, "portable conformance report"), report),
    "portable conformance report bytes differ from the supplied report value",
  );
  assertPortablePublicationLocality(attestations, "attestations");
  assertPortablePublicationLocality(advertisements, "advertisements");
  invariant(
    attestations?.targetAttestationSchema ===
      PORTABLE_TARGET_ATTESTATIONS_SCHEMA,
    "portable target attestation catalog has the wrong schema",
  );
  invariant(
    advertisements?.targetAdvertisementSchema ===
      PORTABLE_TARGET_ADVERTISEMENTS_SCHEMA,
    "portable target advertisement catalog has the wrong schema",
  );
  const targetKey = canonicalJson(report.bindings.target);
  const matchingAttestations = attestations.attestations.filter(
    (attestation) => canonicalJson(attestation.target) === targetKey,
  );
  const matchingAdvertisements = advertisements.advertisements.filter(
    (advertisement) => canonicalJson(advertisement.target) === targetKey,
  );
  invariant(
    matchingAttestations.length === 1 && matchingAdvertisements.length === 1,
    "portable promotion join requires one exact-target attestation and advertisement",
  );
  const [attestation] = matchingAttestations;
  const [advertisement] = matchingAdvertisements;
  const exactReportRawContentDigest = rawContentDigest(reportBytes);
  const bindings = report.bindings;

  invariant(
    same(attestation.target, bindings.target) &&
      attestation.conformanceDigest === report.conformanceDigest &&
      attestation.reportRawContentDigest === exactReportRawContentDigest &&
      attestation.sourceRevision === bindings.sourceRevision &&
      attestation.sourceTreeDigest === bindings.sourceTreeDigest &&
      attestation.portableArtifactId === bindings.engine.artifactId &&
      same(
        attestation.mappedEngineExecutionEvidence,
        bindings.mappedEngineExecutionEvidence,
      ) &&
      attestation.recipeCatalogDigest === bindings.recipeCatalogDigest &&
      attestation.publicSurfaceExecutionDigest ===
        bindings.publicSurfaceExecutionDigest &&
      attestation.outputDispositionEvidenceRawContentDigest ===
        bindings.outputDispositionEvidenceRawContentDigest,
    "portable target attestation differs from the report",
  );

  invariant(
    same(advertisement.target, bindings.target) &&
      advertisement.conformanceDigest === report.conformanceDigest &&
      advertisement.reportRawContentDigest === exactReportRawContentDigest &&
      advertisement.sourceRevision === bindings.sourceRevision &&
      advertisement.sourceTreeDigest === bindings.sourceTreeDigest &&
      same(advertisement.engine, bindings.engine) &&
      same(
        advertisement.mappedEngineExecutionEvidence,
        bindings.mappedEngineExecutionEvidence,
      ) &&
      advertisement.vocabularyDigest === bindings.vocabularyDigest &&
      advertisement.registryDigest === bindings.registryDigest &&
      advertisement.implementationManifestDigest ===
        bindings.implementationManifestDigest &&
      advertisement.fixtureCatalogDigest === bindings.fixtureCatalogDigest &&
      advertisement.recipeCatalogDigest === bindings.recipeCatalogDigest &&
      advertisement.recipeCatalogRawContentDigest ===
        attestation.recipeCatalogRawContentDigest &&
      advertisement.publicSurfaceExecutionDigest ===
        bindings.publicSurfaceExecutionDigest &&
      advertisement.publicSurfaceExecutionRawContentDigest ===
        attestation.publicSurfaceExecutionRawContentDigest &&
      advertisement.outputDispositionEvidenceRawContentDigest ===
        bindings.outputDispositionEvidenceRawContentDigest,
    "portable target advertisement differs from the report and attestation",
  );
  return { attestation, advertisement };
}
