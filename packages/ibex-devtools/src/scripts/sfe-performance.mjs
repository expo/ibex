import { createHash } from 'node:crypto';

export const SFE_PERFORMANCE_BUDGET_SCHEMA = 'ibex/sfe-performance-budgets/1';
export const SFE_PERFORMANCE_MEASUREMENT_SCHEMA = 'ibex/sfe-performance-measurement/1';
export const SFE_PERFORMANCE_GATE_SCHEMA = 'ibex/sfe-performance-gate/1';
export const SFE_PERFORMANCE_REPORT_SCHEMA = 'ibex/sfe-performance-report/1';
export const SFE_PERFORMANCE_ARTIFACT_INSPECTION_SCHEMA =
  'ibex/sfe-performance-artifact-inspection/1';
export const SFE_STARTUP_PROTOCOL = 'fresh-process-os-cache-uncontrolled-v1';
export const SFE_RELEASE_TARGETS = Object.freeze([
  'aarch64-apple-darwin',
  'x86_64-unknown-linux-gnu',
]);
export const SFE_TARGET_MINIMUM_PLATFORMS = Object.freeze({
  'aarch64-apple-darwin': 'macos-14.0-arm64',
  'x86_64-unknown-linux-gnu': 'linux-glibc-2.35-x86-64-v1',
});

const MAXIMUM_KEYS = Object.freeze([
  'helloHbcExecutableBytes',
  'largeGraphHbcExecutableBytes',
  'helloFactoryTableExecutableBytes',
  'helloHbcFreshProcessMedianMs',
  'helloHbcRelocatedCopyAndLaunchMedianMs',
  'largeGraphHbcFreshProcessMedianMs',
  'inspectionFreshProcessMedianMs',
  'helloFactoryTableFreshProcessMedianMs',
  'dynamicDependenciesPerExecutable',
]);
const BYTE_MAXIMUM_KEYS = new Set([
  'helloHbcExecutableBytes',
  'largeGraphHbcExecutableBytes',
  'helloFactoryTableExecutableBytes',
]);
const FIXTURE_CONSTRAINT_KEYS = Object.freeze([
  'helloHbcMaximumRecords',
  'largeGraphHbcMinimumRecords',
  'helloFactoryTableMaximumRecords',
]);
const INSPECTION_KEYS = Object.freeze([
  'schema',
  'target',
  'minimumPlatform',
  'provenanceKind',
  'runtimeAdmissionState',
  'recordCount',
  'carrierCount',
  'carrierEncoding',
  'catalogDigest',
  'catalogSequence',
  'compilerIdentity',
  'environmentProfileDigest',
  'stubContractDigest',
  'stubCoreDigest',
  'producerId',
  'policyTargetProfile',
  'authorityComplete',
  'stubCoreConsistencyState',
  'platformSignatureState',
]);

const PROFILE_TO_MAXIMUM = Object.freeze({
  helloHbcFreshProcess: 'helloHbcFreshProcessMedianMs',
  helloHbcRelocatedCopyAndLaunch: 'helloHbcRelocatedCopyAndLaunchMedianMs',
  largeGraphHbcFreshProcess: 'largeGraphHbcFreshProcessMedianMs',
  inspectionFreshProcess: 'inspectionFreshProcessMedianMs',
  helloFactoryTableFreshProcess: 'helloFactoryTableFreshProcessMedianMs',
});

const ARTIFACT_TO_MAXIMUM = Object.freeze({
  helloHbc: 'helloHbcExecutableBytes',
  largeGraphHbc: 'largeGraphHbcExecutableBytes',
  helloFactoryTable: 'helloFactoryTableExecutableBytes',
});

const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const GIT_OBJECT_PATTERN = /^[a-f0-9]{40,64}$/u;

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function positiveFinite(value, label) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} must be a positive finite number`);
  }
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function digestOrNull(value, label) {
  if (value !== null && !DIGEST_PATTERN.test(value ?? '')) {
    throw new Error(`${label} must be null or a sha256 base64url digest`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} must contain exactly: ${wanted.join(', ')}`);
  }
}

export function sha256Digest(bytes) {
  return `sha256-${createHash('sha256').update(bytes).digest('base64url')}`;
}

export function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function summarizeSamples(samples, label = 'samples') {
  if (!Array.isArray(samples) || samples.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  const sorted = samples.map((value, index) => {
    if (!Number.isFinite(value) || value < 0) {
      throw new Error(`${label}[${index}] must be a non-negative finite number`);
    }
    return value;
  }).sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  const medianMs = sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
  const percentile95Index = Math.max(0, Math.ceil(sorted.length * 0.95) - 1);
  return {
    samples: sorted.length,
    minimumMs: sorted[0],
    medianMs,
    percentile95Ms: sorted[percentile95Index],
    maximumMs: sorted.at(-1),
  };
}

// @ref LLP 0029#7-phases-gates-and-the-author-decision-register — phase 7
// accepts measurements only against numeric budgets fixed before sampling.
export function validateSfePerformanceBudgets(budgets) {
  object(budgets, 'budgets');
  if (budgets.schema !== SFE_PERFORMANCE_BUDGET_SCHEMA) {
    throw new Error(`unsupported SFE performance budget schema ${budgets.schema}`);
  }
  if (budgets.status !== 'accepted') {
    throw new Error('SFE performance budgets must have status "accepted" before measurement');
  }
  const approval = object(budgets.approval, 'budgets.approval');
  nonEmptyString(approval.approvedBy, 'budgets.approval.approvedBy');
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(approval.approvedAt ?? '')) {
    throw new Error('budgets.approval.approvedAt must be an ISO date');
  }
  nonEmptyString(approval.rationale, 'budgets.approval.rationale');
  exactKeys(budgets.targets, SFE_RELEASE_TARGETS, 'budgets.targets');

  for (const target of SFE_RELEASE_TARGETS) {
    const row = object(budgets.targets[target], `budgets.targets.${target}`);
    if (!Number.isInteger(row.minimumSamples) || row.minimumSamples < 5) {
      throw new Error(`budgets.targets.${target}.minimumSamples must be an integer >= 5`);
    }
    if (row.startupProtocol !== SFE_STARTUP_PROTOCOL) {
      throw new Error(
        `budgets.targets.${target}.startupProtocol must be ${SFE_STARTUP_PROTOCOL}`,
      );
    }
    if (row.factoryTableDisposition !== 'undecided-pending-measurement') {
      throw new Error(
        `budgets.targets.${target}.factoryTableDisposition must preserve the pre-measurement decision state`,
      );
    }
    exactKeys(
      row.fixtureConstraints,
      FIXTURE_CONSTRAINT_KEYS,
      `budgets.targets.${target}.fixtureConstraints`,
    );
    for (const key of FIXTURE_CONSTRAINT_KEYS) {
      positiveInteger(
        row.fixtureConstraints[key],
        `budgets.targets.${target}.fixtureConstraints.${key}`,
      );
    }
    if (
      row.fixtureConstraints.largeGraphHbcMinimumRecords
      <= row.fixtureConstraints.helloHbcMaximumRecords
    ) {
      throw new Error(
        `budgets.targets.${target}.fixtureConstraints must distinguish the large graph from hello`,
      );
    }
    exactKeys(row.maximums, MAXIMUM_KEYS, `budgets.targets.${target}.maximums`);
    for (const key of MAXIMUM_KEYS) {
      if (key === 'dynamicDependenciesPerExecutable') {
        nonNegativeInteger(row.maximums[key], `budgets.targets.${target}.maximums.${key}`);
      } else if (BYTE_MAXIMUM_KEYS.has(key)) {
        positiveInteger(row.maximums[key], `budgets.targets.${target}.maximums.${key}`);
      } else {
        positiveFinite(row.maximums[key], `budgets.targets.${target}.maximums.${key}`);
      }
    }
  }
  return budgets;
}

function validateInspectionProjection(inspection, label) {
  exactKeys(inspection, INSPECTION_KEYS, label);
  if (inspection.schema !== SFE_PERFORMANCE_ARTIFACT_INSPECTION_SCHEMA) {
    throw new Error(`${label}.schema is unsupported`);
  }
  if (!SFE_RELEASE_TARGETS.includes(inspection.target)) {
    throw new Error(`${label}.target is not a v1 release tuple`);
  }
  nonEmptyString(inspection.minimumPlatform, `${label}.minimumPlatform`);
  nonEmptyString(inspection.provenanceKind, `${label}.provenanceKind`);
  nonEmptyString(inspection.runtimeAdmissionState, `${label}.runtimeAdmissionState`);
  positiveInteger(inspection.recordCount, `${label}.recordCount`);
  positiveInteger(inspection.carrierCount, `${label}.carrierCount`);
  nonEmptyString(inspection.carrierEncoding, `${label}.carrierEncoding`);
  digestOrNull(inspection.catalogDigest, `${label}.catalogDigest`);
  if (inspection.catalogSequence !== null) {
    positiveInteger(inspection.catalogSequence, `${label}.catalogSequence`);
  }
  digestOrNull(inspection.compilerIdentity, `${label}.compilerIdentity`);
  digestOrNull(
    inspection.environmentProfileDigest,
    `${label}.environmentProfileDigest`,
  );
  if (!DIGEST_PATTERN.test(inspection.stubContractDigest ?? '')) {
    throw new Error(`${label}.stubContractDigest must be a sha256 base64url digest`);
  }
  digestOrNull(inspection.stubCoreDigest, `${label}.stubCoreDigest`);
  nonEmptyString(inspection.producerId, `${label}.producerId`);
  nonEmptyString(inspection.policyTargetProfile, `${label}.policyTargetProfile`);
  if (typeof inspection.authorityComplete !== 'boolean') {
    throw new Error(`${label}.authorityComplete must be boolean`);
  }
  nonEmptyString(
    inspection.stubCoreConsistencyState,
    `${label}.stubCoreConsistencyState`,
  );
  nonEmptyString(inspection.platformSignatureState, `${label}.platformSignatureState`);
}

export function projectSfePerformanceArtifactInspection(inspection) {
  object(inspection, 'executable inspection');
  if (inspection.schema !== 'ibex/executable-inspection/3') {
    throw new Error('performance artifacts require admitted executable inspection v2');
  }
  const releasePlan = inspection.provenance?.compilePlan;
  const developmentProducer = inspection.provenance?.producerId;
  return {
    schema: SFE_PERFORMANCE_ARTIFACT_INSPECTION_SCHEMA,
    target: inspection.target?.triple,
    minimumPlatform: inspection.target?.minimumPlatform,
    provenanceKind: inspection.provenanceKind,
    runtimeAdmissionState: inspection.runtimeAdmission?.state,
    recordCount: inspection.runtimeAdmission?.recordCount,
    carrierCount: inspection.runtimeAdmission?.carrierCount,
    carrierEncoding: releasePlan?.carrierEncoding
      ?? (developmentProducer === 'ibex-sfe-dev-pack'
        ? 'javascript-factory-table'
        : 'unknown'),
    catalogDigest: releasePlan?.catalogDigest ?? null,
    catalogSequence: inspection.provenance?.catalogSequence ?? null,
    compilerIdentity: releasePlan?.compilerIdentity ?? null,
    environmentProfileDigest: releasePlan?.environmentProfileDigest ?? null,
    stubContractDigest: inspection.envelopeConsistency?.stubContractDigest,
    stubCoreDigest: inspection.stubCoreConsistency?.digest ?? null,
    producerId: inspection.provenance?.producerIdentity ?? developmentProducer,
    policyTargetProfile: inspection.authorityBundle?.policy?.targetProfile?.profile,
    authorityComplete: inspection.authorityBundle?.complete,
    stubCoreConsistencyState: inspection.stubCoreConsistency?.state,
    platformSignatureState: inspection.platformSignature?.state,
  };
}

// @ref LLP 0029#7-phases-gates-and-the-author-decision-register — performance
// evidence must measure real release HBC envelopes and a separately admitted
// diagnostic factory-table artifact, not arbitrary marker-printing binaries.
export function validateSfePerformanceArtifactInspections({
  target,
  fixtureConstraints,
  inspections,
}) {
  if (!SFE_RELEASE_TARGETS.includes(target)) {
    throw new Error(`inspection target ${target} is not a v1 release tuple`);
  }
  exactKeys(inspections, Object.keys(ARTIFACT_TO_MAXIMUM), 'artifact inspections');
  for (const [name, inspection] of Object.entries(inspections)) {
    validateInspectionProjection(inspection, `artifact inspections.${name}`);
    if (inspection.target !== target) {
      throw new Error(`artifact inspections.${name} has the wrong target`);
    }
    if (inspection.runtimeAdmissionState !== 'inner-contracts-admitted') {
      throw new Error(`artifact inspections.${name} failed inner admission`);
    }
    const expectedSignatureState = target === 'aarch64-apple-darwin'
      ? 'valid'
      : 'not-applicable';
    if (inspection.platformSignatureState !== expectedSignatureState) {
      throw new Error(`artifact inspections.${name} has the wrong platform signature state`);
    }
  }

  const hello = inspections.helloHbc;
  const large = inspections.largeGraphHbc;
  for (const [name, inspection] of [['helloHbc', hello], ['largeGraphHbc', large]]) {
    if (
      inspection.minimumPlatform !== SFE_TARGET_MINIMUM_PLATFORMS[target]
      || inspection.provenanceKind !== 'release-v1'
      || inspection.carrierEncoding !== 'hermes-bytecode'
      || inspection.policyTargetProfile !== 'sfe-v1'
      || inspection.authorityComplete !== true
      || inspection.stubCoreConsistencyState !== 'consistent'
      || inspection.catalogDigest === null
      || inspection.catalogSequence === null
      || inspection.compilerIdentity === null
      || inspection.environmentProfileDigest === null
      || inspection.stubCoreDigest === null
    ) {
      throw new Error(`artifact inspections.${name} is not an admitted v1 release HBC envelope`);
    }
  }
  for (const key of [
    'catalogDigest',
    'catalogSequence',
    'compilerIdentity',
    'environmentProfileDigest',
    'stubContractDigest',
    'stubCoreDigest',
    'producerId',
  ]) {
    if (hello[key] !== large[key]) {
      throw new Error(`release HBC artifact inspections disagree on ${key}`);
    }
  }

  const factory = inspections.helloFactoryTable;
  if (
    factory.minimumPlatform !== 'diagnostic-host-unpinned'
    || factory.provenanceKind !== 'development-or-unknown'
    || factory.carrierEncoding !== 'javascript-factory-table'
    || factory.catalogDigest !== null
    || factory.catalogSequence !== null
    || factory.compilerIdentity !== null
    || factory.environmentProfileDigest !== null
    || factory.stubCoreDigest !== null
    || factory.producerId !== 'ibex-sfe-dev-pack'
    || factory.policyTargetProfile !== 'sfe-dev-v1'
    || factory.authorityComplete !== false
    || factory.stubCoreConsistencyState !== 'unavailable'
  ) {
    throw new Error('artifact inspections.helloFactoryTable is not the diagnostic factory-table lane');
  }

  object(fixtureConstraints, 'fixtureConstraints');
  if (hello.recordCount > fixtureConstraints.helloHbcMaximumRecords) {
    throw new Error('hello HBC fixture exceeds its precommitted record-count bound');
  }
  if (large.recordCount < fixtureConstraints.largeGraphHbcMinimumRecords) {
    throw new Error('large-graph HBC fixture is below its precommitted record-count bound');
  }
  if (factory.recordCount > fixtureConstraints.helloFactoryTableMaximumRecords) {
    throw new Error('factory-table hello fixture exceeds its precommitted record-count bound');
  }
  return inspections;
}

function validateProfile(profile, label, minimumSamples) {
  object(profile, label);
  const derived = summarizeSamples(profile.samplesMs, `${label}.samplesMs`);
  if (derived.samples < minimumSamples) {
    throw new Error(`${label} requires at least ${minimumSamples} samples`);
  }
  for (const key of ['minimumMs', 'medianMs', 'percentile95Ms', 'maximumMs']) {
    if (profile[key] !== derived[key]) {
      throw new Error(`${label}.${key} does not match its raw samples`);
    }
  }
  if (profile.samples !== derived.samples) {
    throw new Error(`${label}.samples does not match its raw samples`);
  }
  return derived;
}

function validateArtifact(artifact, label) {
  object(artifact, label);
  nonEmptyString(artifact.fileName, `${label}.fileName`);
  if (!DIGEST_PATTERN.test(artifact.digest ?? '')) {
    throw new Error(`${label}.digest must be a sha256 base64url digest`);
  }
  positiveInteger(artifact.bytes, `${label}.bytes`);
  const audit = object(artifact.dynamicDependencies, `${label}.dynamicDependencies`);
  nonEmptyString(audit.tool, `${label}.dynamicDependencies.tool`);
  if (!Array.isArray(audit.entries) || audit.entries.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${label}.dynamicDependencies.entries must be a string array`);
  }
  nonNegativeInteger(audit.count, `${label}.dynamicDependencies.count`);
  if (audit.count !== audit.entries.length) {
    throw new Error(`${label}.dynamicDependencies.count must match entries.length`);
  }
  validateInspectionProjection(artifact.inspection, `${label}.inspection`);
}

function validateMeasurement(budgets, measurement, budgetDigest) {
  object(measurement, 'measurement');
  if (measurement.schema !== SFE_PERFORMANCE_MEASUREMENT_SCHEMA) {
    throw new Error(`unsupported SFE performance measurement schema ${measurement.schema}`);
  }
  if (!SFE_RELEASE_TARGETS.includes(measurement.target)) {
    throw new Error(`measurement target ${measurement.target} is not a v1 release tuple`);
  }
  const binding = object(measurement.budgetBinding, 'measurement.budgetBinding');
  if (!DIGEST_PATTERN.test(binding.sha256 ?? '') || binding.sha256 !== budgetDigest) {
    throw new Error('measurement is not bound to the supplied budget bytes');
  }
  nonEmptyString(binding.repositoryPath, 'measurement.budgetBinding.repositoryPath');
  if (!GIT_OBJECT_PATTERN.test(binding.gitBlob ?? '')) {
    throw new Error('measurement.budgetBinding.gitBlob must be a Git object id');
  }
  const revision = object(measurement.releaseRevision, 'measurement.releaseRevision');
  if (!GIT_OBJECT_PATTERN.test(revision.gitCommit ?? '')) {
    throw new Error('measurement.releaseRevision.gitCommit must be a Git commit id');
  }
  if (revision.trackedTreeClean !== true) {
    throw new Error('performance evidence requires a clean tracked source tree');
  }

  const budget = budgets.targets[measurement.target];
  const conditions = object(measurement.measurementConditions, 'measurement.measurementConditions');
  if (
    conditions.startupProtocol !== budget.startupProtocol
    || conditions.freshProcessPerSample !== true
    || conditions.osPageCacheEviction !== 'not-attempted'
    || conditions.relocatedProfileIncludesCopy !== true
  ) {
    throw new Error('measurement conditions do not implement the fixed startup protocol');
  }
  if (conditions.hostContentionObserved !== false) {
    throw new Error('contended SFE performance evidence cannot satisfy the gate');
  }

  exactKeys(measurement.artifacts, Object.keys(ARTIFACT_TO_MAXIMUM), 'measurement.artifacts');
  for (const name of Object.keys(ARTIFACT_TO_MAXIMUM)) {
    validateArtifact(measurement.artifacts[name], `measurement.artifacts.${name}`);
  }
  validateSfePerformanceArtifactInspections({
    target: measurement.target,
    fixtureConstraints: budget.fixtureConstraints,
    inspections: Object.fromEntries(
      Object.entries(measurement.artifacts).map(([name, artifact]) => [
        name,
        artifact.inspection,
      ]),
    ),
  });
  exactKeys(measurement.profiles, Object.keys(PROFILE_TO_MAXIMUM), 'measurement.profiles');
  const profiles = {};
  for (const name of Object.keys(PROFILE_TO_MAXIMUM)) {
    profiles[name] = validateProfile(
      measurement.profiles[name],
      `measurement.profiles.${name}`,
      budget.minimumSamples,
    );
  }
  return { budget, profiles };
}

// @ref LLP 0047#8-milestone-5--distribution-and-usability — both release
// tuples need a recorded, fail-loud size/startup/inspection gate.
export function evaluateSfePerformance({ budgets, measurement, budgetDigest }) {
  validateSfePerformanceBudgets(budgets);
  if (!DIGEST_PATTERN.test(budgetDigest ?? '')) {
    throw new Error('budgetDigest must be a sha256 base64url digest');
  }
  const { budget, profiles } = validateMeasurement(budgets, measurement, budgetDigest);
  const actuals = {
    helloHbcExecutableBytes: measurement.artifacts.helloHbc.bytes,
    largeGraphHbcExecutableBytes: measurement.artifacts.largeGraphHbc.bytes,
    helloFactoryTableExecutableBytes: measurement.artifacts.helloFactoryTable.bytes,
    helloHbcFreshProcessMedianMs: profiles.helloHbcFreshProcess.medianMs,
    helloHbcRelocatedCopyAndLaunchMedianMs:
      profiles.helloHbcRelocatedCopyAndLaunch.medianMs,
    largeGraphHbcFreshProcessMedianMs: profiles.largeGraphHbcFreshProcess.medianMs,
    inspectionFreshProcessMedianMs: profiles.inspectionFreshProcess.medianMs,
    helloFactoryTableFreshProcessMedianMs:
      profiles.helloFactoryTableFreshProcess.medianMs,
    dynamicDependenciesPerExecutable: Math.max(
      ...Object.values(measurement.artifacts).map(
        (artifact) => artifact.dynamicDependencies.count,
      ),
    ),
  };
  const failures = [];
  for (const key of MAXIMUM_KEYS) {
    if (actuals[key] > budget.maximums[key]) failures.push(key);
  }
  return {
    schema: SFE_PERFORMANCE_GATE_SCHEMA,
    target: measurement.target,
    budgetBinding: measurement.budgetBinding,
    startupProtocol: budget.startupProtocol,
    factoryTableDisposition: budget.factoryTableDisposition,
    minimumSamples: budget.minimumSamples,
    maximums: budget.maximums,
    actuals,
    passed: failures.length === 0,
    failures,
  };
}
