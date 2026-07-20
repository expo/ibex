/**
 * Build and validate the LLP 0026 restricted-profile exact-target report.
 *
 * Each per-edge execution carries exactly one observation and a deterministic
 * fixture ID derived from `(edgeId, evidenceKind)`. Broad command success
 * never synthesizes a per-edge pass.
 *
 * @ref LLP 0026#8-generated-authority-and-conformance — target reports bind
 * every projected edge to fixture-specific executed evidence.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";

import {
  canonicalJson,
  capsecRoot,
  parseJsonStrict,
  readJsonStrict,
  repoRoot,
} from "./capsec-contract.mjs";

const reportSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-target-report.schema.json",
);
const fixturePlanSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-fixture-plan.schema.json",
);

const requiredByDisposition = new Map([
  ["reachable", ["live-invocation"]],
  ["structurally-absent", ["live-reachability", "source-install"]],
  ["trusted-control-plane", ["control-plane-negative"]],
]);

export function taggedDigest(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

function reportDigest(report) {
  const payload = structuredClone(report);
  delete payload.reportDigest;
  return taggedDigest(Buffer.concat([
    Buffer.from("ibex:restricted-profile-conformance:1\0", "utf8"),
    Buffer.from(canonicalJson(payload), "utf8"),
  ]));
}

function schemaValidator(schemaPath) {
  return new Ajv2020({ strict: true, allErrors: true }).compile(
    readJsonStrict(schemaPath),
  );
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    throw new Error(`${label} violates schema: ${JSON.stringify(validate.errors)}`);
  }
}

function assertSortedUnique(values, label) {
  const sorted = [...values].sort();
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} contains duplicates`);
  }
  if (values.some((value, index) => value !== sorted[index])) {
    throw new Error(`${label} must be sorted`);
  }
}

export function validateRestrictedFixturePlan(fixturePlan) {
  assertSchema(
    schemaValidator(fixturePlanSchemaPath),
    fixturePlan,
    "restricted fixture plan",
  );
  const actual = new Map();
  for (const row of fixturePlan.evidenceKinds) {
    const key = `${row.disposition}\0${row.id}`;
    if (actual.has(key)) throw new Error(`duplicate restricted evidence plan row ${key}`);
    actual.set(key, row);
  }
  for (const [disposition, kinds] of requiredByDisposition) {
    for (const kind of kinds) {
      if (!actual.has(`${disposition}\0${kind}`)) {
        throw new Error(`restricted fixture plan omits ${disposition}/${kind}`);
      }
    }
  }
  if (actual.size !== 4) {
    throw new Error("restricted fixture plan contains an unrecognized evidence kind");
  }
  assertSortedUnique(
    fixturePlan.globalCorpora.map((row) => row.id),
    "restricted global corpus IDs",
  );
}

function validateBindings(bindings, rawAuthorities) {
  const expected = {
    definitionRawContentDigest: taggedDigest(rawAuthorities.definition),
    projectionRawContentDigest: taggedDigest(rawAuthorities.projection),
    coverageRawContentDigest: taggedDigest(rawAuthorities.coverage),
    implementationManifestRawContentDigest: taggedDigest(rawAuthorities.implementationManifest),
    fixturePlanRawContentDigest: taggedDigest(rawAuthorities.fixturePlan),
    reportSchemaRawContentDigest: taggedDigest(rawAuthorities.reportSchema),
  };
  for (const [field, digest] of Object.entries(expected)) {
    if (bindings[field] !== digest) {
      throw new Error(`restricted report ${field} does not bind exact authority bytes`);
    }
  }
  if (
    canonicalJson(bindings.target.features)
      !== canonicalJson(bindings.engine.structuralFeatures)
  ) {
    throw new Error("restricted report target and engine features differ");
  }
}

function observationIdentity(edge) {
  return `${edge.surface.kind}:${edge.surface.name}`;
}

function deriveRestrictedTargetReport({
  projection,
  coverage,
  implementationManifest,
  fixturePlan,
  bindings,
  executions,
  globalCorpora,
  independentReview,
  rawAuthorities,
}) {
  validateRestrictedFixturePlan(fixturePlan);
  validateBindings(bindings, rawAuthorities);
  const coverageById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const implementationIds = new Set(
    implementationManifest.surfaces.map((surface) => surface.edgeId),
  );
  const projectedIds = projection.rows.map((row) => row[0]);
  assertSortedUnique(projectedIds, "restricted report projection rows");
  if (
    projectedIds.length !== coverageById.size
    || projectedIds.some((edgeId) => !coverageById.has(edgeId) || !implementationIds.has(edgeId))
  ) {
    throw new Error("restricted report projection does not join coverage and implementation");
  }

  assertSortedUnique(executions.map((row) => row.executionId), "restricted execution IDs");
  const executionById = new Map(executions.map((row) => [row.executionId, row]));
  const observations = new Map();
  for (const execution of executions) {
    if (execution.engineBinaryDigest !== bindings.engine.binaryDigest) {
      throw new Error(`restricted execution ${execution.executionId} used a different engine`);
    }
    const localKeys = [];
    for (const observation of execution.observations) {
      const edge = coverageById.get(observation.edgeId);
      if (!edge) throw new Error(`restricted observation names unknown edge ${observation.edgeId}`);
      if (observation.observedIdentity !== observationIdentity(edge)) {
        throw new Error(`restricted observation identity drift for ${observation.edgeId}`);
      }
      const key = `${observation.edgeId}\0${observation.kind}`;
      const expectedFixtureId = `restricted.${observation.kind}.${observation.edgeId}`;
      if (execution.fixtureId !== expectedFixtureId) {
        throw new Error(
          `restricted observation fixture mismatch: expected ${expectedFixtureId}`,
        );
      }
      localKeys.push(key);
      if (observations.has(key)) {
        throw new Error(`duplicate restricted per-edge observation ${key}`);
      }
      observations.set(key, { execution, observation });
    }
    if (execution.observations.length > 1) {
      throw new Error(
        `restricted execution ${execution.executionId} combines multiple per-edge observations`,
      );
    }
    assertSortedUnique(localKeys, `restricted observations in ${execution.executionId}`);
  }

  const rows = projection.rows.map(([edgeId, disposition]) => {
    const requiredEvidenceKinds = [...requiredByDisposition.get(disposition)].sort();
    const passedEvidenceKinds = [];
    const failedEvidenceKinds = [];
    const executionIds = new Set();
    for (const kind of requiredEvidenceKinds) {
      const evidence = observations.get(`${edgeId}\0${kind}`);
      if (!evidence) continue;
      executionIds.add(evidence.execution.executionId);
      const passed = evidence.execution.outcome === "passed"
        && evidence.execution.exitCode === 0
        && evidence.observation.outcome === "passed";
      (passed ? passedEvidenceKinds : failedEvidenceKinds).push(kind);
    }
    const missingEvidenceKinds = requiredEvidenceKinds.filter(
      (kind) => !passedEvidenceKinds.includes(kind) && !failedEvidenceKinds.includes(kind),
    );
    const status = passedEvidenceKinds.length === requiredEvidenceKinds.length
      ? "conformant"
      : "incomplete";
    return {
      edgeId,
      disposition,
      requiredEvidenceKinds,
      passedEvidenceKinds: passedEvidenceKinds.sort(),
      failedEvidenceKinds: failedEvidenceKinds.sort(),
      missingEvidenceKinds,
      executionIds: [...executionIds].sort(),
      status,
    };
  });

  const plannedCorpora = fixturePlan.globalCorpora.map((row) => row.id);
  assertSortedUnique(globalCorpora.map((row) => row.id), "restricted report corpus IDs");
  if (canonicalJson(plannedCorpora) !== canonicalJson(globalCorpora.map((row) => row.id))) {
    throw new Error("restricted report global corpus set differs from the fixture plan");
  }
  for (const corpus of globalCorpora) {
    assertSortedUnique(corpus.executionIds, `restricted corpus ${corpus.id} executions`);
    if (corpus.executionIds.some((id) => !executionById.has(id))) {
      throw new Error(`restricted corpus ${corpus.id} names unknown execution`);
    }
    if (
      corpus.status === "passed"
      && (corpus.executionIds.length === 0
        || corpus.executionIds.some((id) => {
          const execution = executionById.get(id);
          return execution.outcome !== "passed" || execution.fixtureId !== corpus.id;
        }))
    ) {
      throw new Error(`restricted corpus ${corpus.id} has no passing execution`);
    }
  }

  const summary = {
    total: rows.length,
    conformant: rows.filter((row) => row.status === "conformant").length,
    incomplete: rows.filter((row) => row.status === "incomplete").length,
    reachable: rows.filter((row) => row.disposition === "reachable").length,
    structurallyAbsent: rows.filter((row) => row.disposition === "structurally-absent").length,
    trustedControlPlane: rows.filter((row) => row.disposition === "trusted-control-plane").length,
    passedObservations: rows.reduce((sum, row) => sum + row.passedEvidenceKinds.length, 0),
    missingObservations: rows.reduce((sum, row) => sum + row.missingEvidenceKinds.length, 0),
    failedObservations: rows.reduce((sum, row) => sum + row.failedEvidenceKinds.length, 0),
  };
  const conformant = summary.conformant === summary.total
    && globalCorpora.every((row) => row.status === "passed")
    && independentReview.status === "clear"
    && independentReview.artifactDigest !== null
    && independentReview.unresolvedCritical === 0
    && independentReview.unresolvedHigh === 0;
  const report = {
    reportSchema: "ibex/restricted-profile-target-report/1",
    profile: projection.profile,
    status: conformant ? "conformant" : "incomplete",
    bindings,
    summary,
    executions,
    rows,
    globalCorpora,
    independentReview,
  };
  report.reportDigest = reportDigest(report);
  return report;
}

export function buildRestrictedTargetReport(inputs) {
  const report = deriveRestrictedTargetReport(inputs);
  validateRestrictedTargetReport(report, inputs);
  return report;
}

export function validateRestrictedTargetReport(report, authorities) {
  assertSchema(
    schemaValidator(reportSchemaPath),
    report,
    "restricted target report",
  );
  if (report.reportDigest !== reportDigest(report)) {
    throw new Error("restricted target report digest mismatch");
  }
  validateBindings(report.bindings, authorities.rawAuthorities);
  const rebuilt = deriveRestrictedTargetReport({
    ...authorities,
    bindings: report.bindings,
    executions: report.executions,
    globalCorpora: report.globalCorpora,
    independentReview: report.independentReview,
  });
  if (canonicalJson(rebuilt) !== canonicalJson(report)) {
    throw new Error("restricted target report is not derivable from its evidence");
  }
}

export function loadRestrictedReportAuthorities() {
  const paths = {
    definition: path.join(capsecRoot, "registry/restricted-exact-profile-definition.json"),
    projection: path.join(capsecRoot, "generated/restricted-exact-profile-projection.json"),
    coverage: path.join(capsecRoot, "registry/coverage-edges.json"),
    implementationManifest: path.join(capsecRoot, "generated/implementation-manifest.json"),
    fixturePlan: path.join(capsecRoot, "registry/restricted-exact-fixture-plan.json"),
    reportSchema: reportSchemaPath,
  };
  return {
    projection: readJsonStrict(paths.projection),
    coverage: readJsonStrict(paths.coverage),
    implementationManifest: readJsonStrict(paths.implementationManifest),
    fixturePlan: readJsonStrict(paths.fixturePlan),
    rawAuthorities: Object.fromEntries(
      Object.entries(paths).map(([name, file]) => [name, fs.readFileSync(file)]),
    ),
  };
}

export function deriveRestrictedTargetAdvertisements({
  targetAttestations,
  authorities,
}) {
  const advertisements = [];
  const targetKeys = [];
  for (const attestation of targetAttestations.attestations) {
    const targetKey = `${attestation.target.triple}\0${attestation.target.features.join("\0")}`;
    targetKeys.push(targetKey);
    const absolute = path.resolve(repoRoot, attestation.reportPath);
    const conformanceRoot = `${path.resolve(capsecRoot, "conformance")}${path.sep}`;
    if (!absolute.startsWith(conformanceRoot)) {
      throw new Error("restricted report path escapes capsec/conformance");
    }
    let stat;
    try {
      stat = fs.lstatSync(absolute);
    } catch {
      throw new Error("restricted attested report is unavailable");
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error("restricted attested report must be a regular non-symlink file");
    }
    const rawReport = fs.readFileSync(absolute);
    if (taggedDigest(rawReport) !== attestation.reportRawContentDigest) {
      throw new Error("restricted attestation report raw-content digest mismatch");
    }
    const report = parseJsonStrict(rawReport, attestation.reportPath);
    validateRestrictedTargetReport(report, authorities);
    if (report.status !== "conformant") {
      throw new Error("restricted attestation names an incomplete report");
    }
    const expected = {
      reportDigest: report.reportDigest,
      sourceRevision: report.bindings.sourceRevision,
      sourceTreeDigest: report.bindings.sourceTreeDigest,
      engineBinaryDigest: report.bindings.engine.binaryDigest,
      projectionRawContentDigest: report.bindings.projectionRawContentDigest,
      fixturePlanRawContentDigest: report.bindings.fixturePlanRawContentDigest,
      independentReviewArtifactDigest: report.independentReview.artifactDigest,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (attestation[field] !== value) {
        throw new Error(`restricted attestation ${field} mismatch`);
      }
    }
    if (canonicalJson(attestation.target) !== canonicalJson(report.bindings.target)) {
      throw new Error("restricted attestation target mismatch");
    }
    const git = (...args) => execFileSync("git", args, { cwd: repoRoot });
    let sourceTree;
    try {
      sourceTree = git("rev-parse", `${attestation.sourceRevision}^{tree}`);
    } catch {
      throw new Error("restricted attestation source revision is unavailable");
    }
    if (taggedDigest(sourceTree) !== attestation.sourceTreeDigest) {
      throw new Error("restricted attestation source tree digest mismatch");
    }
    const revisionAuthorities = {
      "capsec/registry/restricted-exact-profile-definition.json":
        authorities.rawAuthorities.definition,
      "capsec/generated/restricted-exact-profile-projection.json":
        authorities.rawAuthorities.projection,
      "capsec/registry/coverage-edges.json": authorities.rawAuthorities.coverage,
      "capsec/generated/implementation-manifest.json":
        authorities.rawAuthorities.implementationManifest,
      "capsec/registry/restricted-exact-fixture-plan.json":
        authorities.rawAuthorities.fixturePlan,
      "capsec/schema/restricted-profile-target-report.schema.json":
        authorities.rawAuthorities.reportSchema,
    };
    for (const [relativePath, currentBytes] of Object.entries(revisionAuthorities)) {
      let revisionBytes;
      try {
        revisionBytes = git("show", `${attestation.sourceRevision}:${relativePath}`);
      } catch {
        throw new Error(`restricted source revision omits authority ${relativePath}`);
      }
      if (!revisionBytes.equals(currentBytes)) {
        throw new Error(`restricted authority changed after report: ${relativePath}`);
      }
    }
    if (!authorities.projection.candidateTargets.some(
      (target) => canonicalJson(target) === canonicalJson(attestation.target),
    )) {
      throw new Error("restricted attestation names a non-candidate target");
    }
    advertisements.push({
      target: attestation.target,
      reportDigest: attestation.reportDigest,
      reportRawContentDigest: attestation.reportRawContentDigest,
      sourceRevision: attestation.sourceRevision,
      sourceTreeDigest: attestation.sourceTreeDigest,
      engineBinaryDigest: attestation.engineBinaryDigest,
      projectionRawContentDigest: attestation.projectionRawContentDigest,
      fixturePlanRawContentDigest: attestation.fixturePlanRawContentDigest,
    });
  }
  assertSortedUnique(targetKeys, "restricted attested target identities");
  return advertisements;
}
