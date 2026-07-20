/**
 * Build and validate the LLP 0033 restricted-profile exact-target report.
 *
 * Each per-edge execution carries exactly one observation and a deterministic
 * fixture ID derived from `(edgeId, evidenceKind)`. Broad command success
 * never synthesizes a per-edge pass.
 *
 * @ref LLP 0033#8-generated-authority-and-conformance — target reports bind
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
import { validateRestrictedExactAbsenceRouteGraph } from "./generate-restricted-exact-absence-route-graph.mjs";

const reportSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-target-report.schema.json",
);
const fixturePlanSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-fixture-plan.schema.json",
);
const absenceProbePlanSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-absence-probe-plan.schema.json",
);
const absenceRouteGraphSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-absence-route-graph.schema.json",
);

const requiredByDisposition = new Map([
  ["reachable", ["live-invocation"]],
  ["structurally-absent", ["live-reachability", "source-install"]],
  ["trusted-control-plane", ["control-plane-negative"]],
]);
const schemaValidators = new Map();
const routeGraphsByRawDigest = new Map();
const validatedRouteGraphsByImplementation = new WeakMap();

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

export function restrictedReportPathForTarget(target) {
  if (
    target === null
    || typeof target !== "object"
    || Array.isArray(target)
    || typeof target.triple !== "string"
    || !/^[a-z0-9_]+(?:-[a-z0-9_]+)+$/u.test(target.triple)
  ) {
    throw new Error("restricted report target triple is malformed");
  }
  return `capsec/conformance/restricted-exact-${target.triple}-report.json`;
}

function validateIndependentReviewArtifact(independentReview, reviewedState) {
  if (independentReview.status === "pending") {
    if (independentReview.artifactDigest !== null) {
      throw new Error("pending restricted review cannot name an artifact");
    }
    return;
  }
  if (independentReview.artifactDigest === null) {
    throw new Error("settled restricted review omits its raw artifact digest");
  }
  const reviewRoot = path.join(capsecRoot, "conformance/reviews");
  const candidates = fs.readdirSync(reviewRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => path.join(reviewRoot, entry.name))
    .filter((candidate) => {
      const stat = fs.lstatSync(candidate);
      return stat.isFile() && !stat.isSymbolicLink()
        && taggedDigest(fs.readFileSync(candidate)) === independentReview.artifactDigest;
    });
  if (candidates.length !== 1) {
    throw new Error("restricted review raw digest does not reopen exactly one artifact");
  }
  const rawReview = fs.readFileSync(candidates[0]);
  const review = parseJsonStrict(rawReview, path.relative(repoRoot, candidates[0]));
  if (
    review.kind !== "ibex-llp-0033-independent-security-review"
    || review.independent !== true
    || !["clear", "fail"].includes(review.verdict)
    || !Number.isSafeInteger(review.unresolvedCritical)
    || !Number.isSafeInteger(review.unresolvedHigh)
    || review.unresolvedCritical < 0
    || review.unresolvedHigh < 0
    || !Array.isArray(review.findings)
    || typeof review.reviewedCommit !== "string"
    || !/^([0-9a-f]{40})$/.test(review.reviewedCommit)
    || typeof review.reviewedReportDigest !== "string"
    || typeof review.reviewedReportRawContentDigest !== "string"
    || review.reviewedEvidenceRawContentDigests === null
    || typeof review.reviewedEvidenceRawContentDigests !== "object"
    || Array.isArray(review.reviewedEvidenceRawContentDigests)
  ) {
    throw new Error("restricted independent review artifact is malformed");
  }
  const validSeverities = new Set(["critical", "high", "medium", "low"]);
  const validFindingStatuses = new Set(["resolved", "unresolved"]);
  if (review.findings.some((finding) => (
    finding === null
    || typeof finding !== "object"
    || Array.isArray(finding)
    || !validSeverities.has(finding.severity)
    || !validFindingStatuses.has(finding.status)
    || typeof finding.title !== "string"
    || finding.title.length === 0
    || !Array.isArray(finding.evidence)
    || finding.evidence.length === 0
    || finding.evidence.some((row) => typeof row !== "string" || row.length === 0)
    || typeof finding.recommendation !== "string"
    || finding.recommendation.length === 0
  ))) {
    throw new Error("restricted independent review findings are malformed");
  }
  const countedCritical = review.findings.filter(
    (finding) => finding.status === "unresolved" && finding.severity === "critical",
  ).length;
  const countedHigh = review.findings.filter(
    (finding) => finding.status === "unresolved" && finding.severity === "high",
  ).length;
  if (
    countedCritical !== review.unresolvedCritical
    || countedHigh !== review.unresolvedHigh
  ) {
    throw new Error("restricted review unresolved counts do not match findings");
  }
  const expectedStatus = review.verdict === "clear" ? "clear" : "failed";
  if (
    independentReview.status !== expectedStatus
    || independentReview.unresolvedCritical !== review.unresolvedCritical
    || independentReview.unresolvedHigh !== review.unresolvedHigh
    || (review.verdict === "clear"
      && (review.unresolvedCritical !== 0 || review.unresolvedHigh !== 0))
    || (review.verdict === "fail"
      && review.unresolvedCritical === 0 && review.unresolvedHigh === 0)
  ) {
    throw new Error("restricted review summary does not match its artifact verdict");
  }
  const reportPath = restrictedReportPathForTarget(reviewedState.bindings.target);
  let reviewedReportRaw;
  try {
    reviewedReportRaw = execFileSync(
      "git",
      ["show", `${review.reviewedCommit}:${reportPath}`],
      { cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 },
    );
  } catch {
    throw new Error("restricted review commit does not contain its reviewed report");
  }
  const reviewedReport = parseJsonStrict(reviewedReportRaw, reportPath);
  if (
    taggedDigest(reviewedReportRaw) !== review.reviewedReportRawContentDigest
    || reviewedReport.reportDigest !== review.reviewedReportDigest
    || reviewedReport.reportDigest !== reportDigest(reviewedReport)
  ) {
    throw new Error("restricted review does not bind its historical report bytes");
  }
  const evidenceRoot = path.join(capsecRoot, "conformance/evidence/restricted-exact");
  const reviewedEvidence = Object.entries(review.reviewedEvidenceRawContentDigests);
  if (
    reviewedEvidence.length !== 4
    || !["absence-", "control-", "global-corpora-", "reachable-"].every(
      (prefix) => reviewedEvidence.some(([name]) => name.startsWith(prefix)),
    )
  ) {
    throw new Error("restricted review does not bind the four evidence families");
  }
  for (const [name, digest] of reviewedEvidence) {
    if (path.basename(name) !== name || typeof digest !== "string") {
      throw new Error("restricted review evidence binding is malformed");
    }
    const artifactPath = path.join(evidenceRoot, name);
    const stat = fs.lstatSync(artifactPath);
    if (!stat.isFile() || stat.isSymbolicLink()
      || taggedDigest(fs.readFileSync(artifactPath)) !== digest) {
      throw new Error(`restricted review evidence binding drifted: ${name}`);
    }
  }
  if (review.verdict === "clear") {
    const currentFixturePlan = readJsonStrict(path.join(
      capsecRoot,
      "registry/restricted-exact-fixture-plan.json",
    ));
    if (
      typeof review.reviewedProbePlanRawContentDigest !== "string"
      || review.reviewedProbePlanRawContentDigest
        !== currentFixturePlan.absenceProbePlan.rawContentDigest
      || typeof review.reviewedRouteGraphRawContentDigest !== "string"
      || review.reviewedRouteGraphRawContentDigest
        !== currentFixturePlan.absenceRouteGraph.rawContentDigest
    ) {
      throw new Error("clear restricted review does not bind the current probe plan and route graph");
    }
    for (const field of ["bindings", "executions", "globalCorpora", "rows", "summary"]) {
      if (canonicalJson(reviewedReport[field]) !== canonicalJson(reviewedState[field])) {
        throw new Error(`clear restricted review covered different ${field}`);
      }
    }
  }
}

function schemaValidator(schemaPath) {
  let validate = schemaValidators.get(schemaPath);
  if (!validate) {
    validate = new Ajv2020({ strict: true, allErrors: true }).compile(
      readJsonStrict(schemaPath),
    );
    schemaValidators.set(schemaPath, validate);
  }
  return validate;
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

export function validateRestrictedFixturePlan(fixturePlan, sourceBytes = {}) {
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
  const probePlanPath = path.resolve(repoRoot, fixturePlan.absenceProbePlan.path);
  const generatedRoot = `${path.resolve(capsecRoot, "generated")}${path.sep}`;
  if (!probePlanPath.startsWith(generatedRoot)) {
    throw new Error("restricted absence probe plan path escapes capsec/generated");
  }
  let rawProbePlan;
  if (sourceBytes.absenceProbePlan === undefined) {
    const stat = fs.lstatSync(probePlanPath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error("restricted absence probe plan must be a regular non-symlink file");
    }
    rawProbePlan = fs.readFileSync(probePlanPath);
  } else {
    rawProbePlan = sourceBytes.absenceProbePlan;
    if (!Buffer.isBuffer(rawProbePlan)) {
      throw new Error("restricted historical absence probe plan must be bytes");
    }
  }
  if (taggedDigest(rawProbePlan) !== fixturePlan.absenceProbePlan.rawContentDigest) {
    throw new Error("restricted absence probe plan raw-content digest mismatch");
  }
  const probePlan = parseJsonStrict(rawProbePlan, fixturePlan.absenceProbePlan.path);
  assertSchema(
    schemaValidator(absenceProbePlanSchemaPath),
    probePlan,
    "restricted absence probe plan",
  );
  assertSortedUnique(
    probePlan.edges.map((row) => row.edgeId),
    "restricted absence probe-plan edge IDs",
  );
  const sourceProbeIds = probePlan.edges.flatMap((row) => row.sourceInstall.map((probe) => probe.probeId));
  const liveProbeIds = probePlan.edges.flatMap((row) => row.liveReachability.map((probe) => probe.probeId));
  assertSortedUnique([...sourceProbeIds].sort(), "restricted source-install probe IDs");
  assertSortedUnique([...liveProbeIds].sort(), "restricted live-reachability probe IDs");
  if (
    probePlan.counts.edges !== probePlan.edges.length
    || probePlan.counts.sourceInstallProbes !== sourceProbeIds.length
    || probePlan.counts.liveReachabilityProbes !== liveProbeIds.length
  ) {
    throw new Error("restricted absence probe-plan counts drifted");
  }
  const routeGraphPath = path.resolve(repoRoot, fixturePlan.absenceRouteGraph.path);
  if (!routeGraphPath.startsWith(generatedRoot)) {
    throw new Error("restricted absence route graph path escapes capsec/generated");
  }
  let rawRouteGraph;
  if (sourceBytes.absenceRouteGraph === undefined) {
    const routeGraphStat = fs.lstatSync(routeGraphPath);
    if (!routeGraphStat.isFile() || routeGraphStat.isSymbolicLink()) {
      throw new Error("restricted absence route graph must be a regular non-symlink file");
    }
    rawRouteGraph = fs.readFileSync(routeGraphPath);
  } else {
    rawRouteGraph = sourceBytes.absenceRouteGraph;
    if (!Buffer.isBuffer(rawRouteGraph)) {
      throw new Error("restricted historical absence route graph must be bytes");
    }
  }
  if (taggedDigest(rawRouteGraph) !== fixturePlan.absenceRouteGraph.rawContentDigest) {
    throw new Error("restricted absence route graph raw-content digest mismatch");
  }
  let routeGraph = routeGraphsByRawDigest.get(fixturePlan.absenceRouteGraph.rawContentDigest);
  if (!routeGraph) {
    routeGraph = parseJsonStrict(rawRouteGraph, fixturePlan.absenceRouteGraph.path);
    assertSchema(
      schemaValidator(absenceRouteGraphSchemaPath),
      routeGraph,
      "restricted absence route graph",
    );
    routeGraphsByRawDigest.set(fixturePlan.absenceRouteGraph.rawContentDigest, routeGraph);
  }
  if (
    routeGraph.authorityDigests.probePlan !== fixturePlan.absenceProbePlan.rawContentDigest
    || routeGraph.counts.edges !== probePlan.counts.edges
    || routeGraph.counts.routes !== probePlan.counts.sourceInstallProbes
  ) {
    throw new Error("restricted absence route graph does not bind the probe plan");
  }
  return probePlan;
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
  const absenceProbePlan = validateRestrictedFixturePlan(fixturePlan);
  const graphDigest = fixturePlan.absenceRouteGraph.rawContentDigest;
  const absenceRouteGraph = routeGraphsByRawDigest.get(graphDigest);
  if (!absenceRouteGraph) {
    throw new Error("restricted absence route graph was not reopened");
  }
  const validatedForImplementation = validatedRouteGraphsByImplementation
    .get(implementationManifest) ?? new Set();
  if (!validatedForImplementation.has(graphDigest)) {
    validateRestrictedExactAbsenceRouteGraph(absenceRouteGraph, {
      probePlan: absenceProbePlan,
      implementationManifest,
    });
    validatedForImplementation.add(graphDigest);
    validatedRouteGraphsByImplementation.set(
      implementationManifest,
      validatedForImplementation,
    );
  }
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
  const absentIds = projection.rows
    .filter((row) => row[1] === "structurally-absent")
    .map((row) => row[0]);
  if (
    absenceProbePlan.profile !== projection.profile
    || canonicalJson(absenceProbePlan.edges.map((row) => row.edgeId))
      !== canonicalJson(absentIds)
    || absenceProbePlan.projectionRawContentDigest !== taggedDigest(rawAuthorities.projection)
    || absenceProbePlan.coverageRawContentDigest !== taggedDigest(rawAuthorities.coverage)
    || absenceProbePlan.implementationManifestRawContentDigest
      !== taggedDigest(rawAuthorities.implementationManifest)
    || absenceRouteGraph.profile !== projection.profile
    || absenceRouteGraph.authorityDigests.projection !== taggedDigest(rawAuthorities.projection)
    || absenceRouteGraph.authorityDigests.coverage !== taggedDigest(rawAuthorities.coverage)
    || absenceRouteGraph.authorityDigests.implementationManifest
      !== taggedDigest(rawAuthorities.implementationManifest)
  ) {
    throw new Error("restricted absence authorities do not bind the report inputs");
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
  validateIndependentReviewArtifact(independentReview, {
    bindings,
    executions,
    globalCorpora,
    rows,
    summary,
  });
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
