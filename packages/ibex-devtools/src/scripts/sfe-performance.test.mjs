import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  SFE_PERFORMANCE_ARTIFACT_INSPECTION_SCHEMA,
  SFE_PERFORMANCE_BUDGET_SCHEMA,
  SFE_PERFORMANCE_MEASUREMENT_SCHEMA,
  SFE_STARTUP_PROTOCOL,
  canonicalJson,
  evaluateSfePerformance,
  projectSfePerformanceArtifactInspection,
  sha256Digest,
  summarizeSamples,
  validateSfePerformanceBudgets,
} from './sfe-performance.mjs';

const TARGETS = ['aarch64-apple-darwin', 'x86_64-unknown-linux-gnu'];

function budgetRow(scale = 1) {
  return {
    minimumSamples: 5,
    startupProtocol: SFE_STARTUP_PROTOCOL,
    factoryTableDisposition: 'undecided-pending-measurement',
    fixtureConstraints: {
      helloHbcMaximumRecords: 5,
      largeGraphHbcMinimumRecords: 40,
      helloFactoryTableMaximumRecords: 5,
    },
    maximums: {
      helloHbcExecutableBytes: 100 * scale,
      largeGraphHbcExecutableBytes: 200 * scale,
      helloFactoryTableExecutableBytes: 120 * scale,
      helloHbcFreshProcessMedianMs: 10 * scale,
      helloHbcRelocatedCopyAndLaunchMedianMs: 20 * scale,
      largeGraphHbcFreshProcessMedianMs: 30 * scale,
      inspectionFreshProcessMedianMs: 40 * scale,
      helloFactoryTableFreshProcessMedianMs: 15 * scale,
      dynamicDependenciesPerExecutable: 3,
    },
  };
}

function budgets() {
  return {
    schema: SFE_PERFORMANCE_BUDGET_SCHEMA,
    status: 'accepted',
    approval: {
      approvedBy: 'release author',
      approvedAt: '2026-08-02',
      rationale: 'Thresholds accepted before collecting release measurements.',
    },
    targets: Object.fromEntries(TARGETS.map((target) => [target, budgetRow()])),
  };
}

function profile(medianMs) {
  const samplesMs = [medianMs - 2, medianMs - 1, medianMs, medianMs + 1, medianMs + 2];
  return { samplesMs, ...summarizeSamples(samplesMs) };
}

function inspection(kind, recordCount) {
  const release = kind !== 'factory';
  return {
    schema: SFE_PERFORMANCE_ARTIFACT_INSPECTION_SCHEMA,
    target: TARGETS[0],
    minimumPlatform: release ? 'macos-14.0-arm64' : 'diagnostic-host-unpinned',
    provenanceKind: release ? 'release-v1' : 'development-or-unknown',
    runtimeAdmissionState: 'inner-contracts-admitted',
    recordCount,
    carrierCount: recordCount,
    carrierEncoding: release ? 'hermes-bytecode' : 'javascript-factory-table',
    catalogDigest: release ? `sha256-${'C'.repeat(43)}` : null,
    catalogSequence: release ? 1 : null,
    compilerIdentity: release ? `sha256-${'I'.repeat(43)}` : null,
    environmentProfileDigest: release ? `sha256-${'E'.repeat(43)}` : null,
    stubContractDigest: `sha256-${(release ? 'S' : 'D').repeat(43)}`,
    stubCoreDigest: release ? `sha256-${'R'.repeat(43)}` : null,
    producerId: release ? 'ibex-compile/0.1.0' : 'ibex-sfe-dev-pack',
    policyTargetProfile: release ? 'sfe-v1' : 'sfe-dev-v1',
    authorityComplete: release,
    stubCoreConsistencyState: release ? 'consistent' : 'unavailable',
    platformSignatureState: 'valid',
  };
}

function artifact(fileName, bytes, inspectionKind, recordCount, dependencyCount = 2) {
  return {
    fileName,
    digest: `sha256-${'A'.repeat(43)}`,
    bytes,
    dynamicDependencies: {
      tool: 'fixture',
      entries: Array.from({ length: dependencyCount }, (_, index) => `lib${index}`),
      count: dependencyCount,
    },
    inspection: inspection(inspectionKind, recordCount),
  };
}

function fixture() {
  const acceptedBudgets = budgets();
  const budgetDigest = sha256Digest(canonicalJson(acceptedBudgets));
  return {
    acceptedBudgets,
    budgetDigest,
    measurement: {
      schema: SFE_PERFORMANCE_MEASUREMENT_SCHEMA,
      target: TARGETS[0],
      budgetBinding: {
        repositoryPath: 'config/sfe-performance-budgets.json',
        gitBlob: 'a'.repeat(40),
        sha256: budgetDigest,
      },
      releaseRevision: { gitCommit: 'b'.repeat(40), trackedTreeClean: true },
      measurementConditions: {
        startupProtocol: SFE_STARTUP_PROTOCOL,
        freshProcessPerSample: true,
        osPageCacheEviction: 'not-attempted',
        relocatedProfileIncludesCopy: true,
        hostContentionObserved: false,
      },
      artifacts: {
        helloHbc: artifact('hello-hbc', 90, 'hello', 2),
        largeGraphHbc: artifact('large-graph-hbc', 190, 'large', 40),
        helloFactoryTable: artifact('hello-factory-table', 110, 'factory', 3),
      },
      profiles: {
        helloHbcFreshProcess: profile(9),
        helloHbcRelocatedCopyAndLaunch: profile(19),
        largeGraphHbcFreshProcess: profile(29),
        inspectionFreshProcess: profile(39),
        helloFactoryTableFreshProcess: profile(14),
      },
    },
  };
}

test('accepts every release measurement row inside precommitted maximums', () => {
  const { acceptedBudgets, measurement, budgetDigest } = fixture();
  const gate = evaluateSfePerformance({
    budgets: acceptedBudgets,
    measurement,
    budgetDigest,
  });
  assert.equal(gate.passed, true);
  assert.deepEqual(gate.failures, []);
  assert.equal(gate.actuals.dynamicDependenciesPerExecutable, 2);
  assert.equal(gate.factoryTableDisposition, 'undecided-pending-measurement');
});

test('accepts the exact Linux baseline with non-applicable platform signatures', () => {
  const value = fixture();
  value.measurement.target = TARGETS[1];
  for (const [name, artifactValue] of Object.entries(value.measurement.artifacts)) {
    artifactValue.inspection.target = TARGETS[1];
    artifactValue.inspection.minimumPlatform = name === 'helloFactoryTable'
      ? 'diagnostic-host-unpinned'
      : 'linux-glibc-2.35-x86-64-v1';
    artifactValue.inspection.platformSignatureState = 'not-applicable';
  }
  const gate = evaluateSfePerformance({
    budgets: value.acceptedBudgets,
    measurement: value.measurement,
    budgetDigest: value.budgetDigest,
  });
  assert.equal(gate.passed, true);
});

test('projects release and diagnostic inspection reports into bounded evidence', () => {
  const releaseExpected = inspection('hello', 2);
  const release = {
    schema: 'ibex/executable-inspection/3',
    target: {
      triple: releaseExpected.target,
      minimumPlatform: releaseExpected.minimumPlatform,
    },
    provenanceKind: releaseExpected.provenanceKind,
    runtimeAdmission: {
      state: releaseExpected.runtimeAdmissionState,
      recordCount: releaseExpected.recordCount,
      carrierCount: releaseExpected.carrierCount,
    },
    provenance: {
      catalogSequence: releaseExpected.catalogSequence,
      producerIdentity: releaseExpected.producerId,
      compilePlan: {
        carrierEncoding: releaseExpected.carrierEncoding,
        catalogDigest: releaseExpected.catalogDigest,
        compilerIdentity: releaseExpected.compilerIdentity,
        environmentProfileDigest: releaseExpected.environmentProfileDigest,
      },
    },
    envelopeConsistency: { stubContractDigest: releaseExpected.stubContractDigest },
    stubCoreConsistency: {
      state: releaseExpected.stubCoreConsistencyState,
      digest: releaseExpected.stubCoreDigest,
    },
    authorityBundle: {
      complete: releaseExpected.authorityComplete,
      policy: { targetProfile: { profile: releaseExpected.policyTargetProfile } },
    },
    platformSignature: { state: releaseExpected.platformSignatureState },
  };
  assert.deepEqual(projectSfePerformanceArtifactInspection(release), releaseExpected);

  const factoryExpected = inspection('factory', 3);
  const factory = {
    ...release,
    target: {
      triple: factoryExpected.target,
      minimumPlatform: factoryExpected.minimumPlatform,
    },
    provenanceKind: factoryExpected.provenanceKind,
    runtimeAdmission: {
      state: factoryExpected.runtimeAdmissionState,
      recordCount: factoryExpected.recordCount,
      carrierCount: factoryExpected.carrierCount,
    },
    provenance: {
      producerId: factoryExpected.producerId,
    },
    envelopeConsistency: { stubContractDigest: factoryExpected.stubContractDigest },
    stubCoreConsistency: { state: factoryExpected.stubCoreConsistencyState },
    authorityBundle: {
      complete: factoryExpected.authorityComplete,
      policy: { targetProfile: { profile: factoryExpected.policyTargetProfile } },
    },
  };
  assert.deepEqual(projectSfePerformanceArtifactInspection(factory), factoryExpected);
});

test('reports every value beyond its named maximum', () => {
  const { acceptedBudgets, measurement, budgetDigest } = fixture();
  for (const artifactValue of Object.values(measurement.artifacts)) {
    artifactValue.bytes *= 2;
    artifactValue.dynamicDependencies.entries.push('lib3', 'lib4');
    artifactValue.dynamicDependencies.count = 4;
  }
  for (const [name, value] of Object.entries(measurement.profiles)) {
    const multiplier = name === 'helloHbcRelocatedCopyAndLaunch' ? 2 : 5;
    const samplesMs = value.samplesMs.map((sample) => sample * multiplier);
    measurement.profiles[name] = { samplesMs, ...summarizeSamples(samplesMs) };
  }
  const gate = evaluateSfePerformance({
    budgets: acceptedBudgets,
    measurement,
    budgetDigest,
  });
  assert.equal(gate.passed, false);
  assert.deepEqual(gate.failures, Object.keys(budgetRow().maximums));
});

test('refuses draft, incomplete, or single-tuple budgets before sampling', () => {
  const value = budgets();
  value.status = 'draft';
  assert.throws(() => validateSfePerformanceBudgets(value), /status "accepted"/u);
  value.status = 'accepted';
  delete value.targets[TARGETS[1]];
  assert.throws(() => validateSfePerformanceBudgets(value), /must contain exactly/u);
});

test('refuses budget drift, low sample counts, contention, and summary drift', () => {
  const first = fixture();
  assert.throws(
    () => evaluateSfePerformance({
      budgets: first.acceptedBudgets,
      measurement: first.measurement,
      budgetDigest: `sha256-${'Z'.repeat(43)}`,
    }),
    /not bound/u,
  );

  const second = fixture();
  second.measurement.profiles.helloHbcFreshProcess.samplesMs.pop();
  const shortened = second.measurement.profiles.helloHbcFreshProcess.samplesMs;
  second.measurement.profiles.helloHbcFreshProcess = {
    samplesMs: shortened,
    ...summarizeSamples(shortened),
  };
  assert.throws(
    () => evaluateSfePerformance({
      budgets: second.acceptedBudgets,
      measurement: second.measurement,
      budgetDigest: second.budgetDigest,
    }),
    /at least 5 samples/u,
  );

  const third = fixture();
  third.measurement.measurementConditions.hostContentionObserved = true;
  assert.throws(
    () => evaluateSfePerformance({
      budgets: third.acceptedBudgets,
      measurement: third.measurement,
      budgetDigest: third.budgetDigest,
    }),
    /contended/u,
  );

  const fourth = fixture();
  fourth.measurement.profiles.inspectionFreshProcess.medianMs += 1;
  assert.throws(
    () => evaluateSfePerformance({
      budgets: fourth.acceptedBudgets,
      measurement: fourth.measurement,
      budgetDigest: fourth.budgetDigest,
    }),
    /does not match its raw samples/u,
  );
});

test('accepts the committed two-tuple release budget document', () => {
  const budgetPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../../../config/sfe-performance-budgets.json',
  );
  const bytes = readFileSync(budgetPath, 'utf8');
  const budgets = JSON.parse(bytes);
  validateSfePerformanceBudgets(budgets);
  assert.equal(canonicalJson(budgets), bytes);
  assert.equal(budgets.status, 'accepted');
  assert.equal(
    budgets.targets['aarch64-apple-darwin'].factoryTableDisposition,
    'undecided-pending-measurement',
  );
});

test('refuses substituted release families, undersized graphs, and release factory inputs', () => {
  const family = fixture();
  family.measurement.artifacts.largeGraphHbc.inspection.catalogDigest =
    `sha256-${'X'.repeat(43)}`;
  assert.throws(
    () => evaluateSfePerformance({
      budgets: family.acceptedBudgets,
      measurement: family.measurement,
      budgetDigest: family.budgetDigest,
    }),
    /disagree on catalogDigest/u,
  );

  const graph = fixture();
  graph.measurement.artifacts.largeGraphHbc.inspection.recordCount = 39;
  assert.throws(
    () => evaluateSfePerformance({
      budgets: graph.acceptedBudgets,
      measurement: graph.measurement,
      budgetDigest: graph.budgetDigest,
    }),
    /below its precommitted record-count bound/u,
  );

  const factory = fixture();
  factory.measurement.artifacts.helloFactoryTable.inspection = inspection('hello', 2);
  assert.throws(
    () => evaluateSfePerformance({
      budgets: factory.acceptedBudgets,
      measurement: factory.measurement,
      budgetDigest: factory.budgetDigest,
    }),
    /not the diagnostic factory-table lane/u,
  );
});
