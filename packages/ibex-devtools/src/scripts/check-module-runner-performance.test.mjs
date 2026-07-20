import assert from 'node:assert/strict';
import test from 'node:test';

import {
  evaluateModuleRunnerPerformance,
  MODULE_RUNNER_PERFORMANCE_BUDGET,
} from './check-module-runner-performance.mjs';

function loaderBaseline(scale = 1) {
  const summary = (medianMs) => ({ medianMs: medianMs * scale });
  return {
    schema: 'ibex/module-loader-performance-baseline/2',
    platform: { os: 'linux', arch: 'x64' },
    graphModules: 40,
    measurementConditions: {
      moduleRunnerDefaultFeatureEnabled: scale !== 1,
      usableForPerformanceBudget: true,
    },
    ibexBinaryBytes: 100 * scale,
    compile: { cleanBuildSeconds: 10 * scale },
    profiles: {
      directSourceMjs: { cold: summary(20), warm: summary(10) },
      preparedRolldownMjs: { cold: summary(40), warm: summary(30) },
    },
  };
}

function nativeBaseline(scale = 1) {
  return {
    schema: 'ibex/module-runner-performance-baseline/1',
    platform: { os: 'linux', arch: 'x86_64' },
    dependencyModules: 40,
    profiles: {
      authenticatedSource: {
        cold: { medianMs: 20 * scale },
        warm: { medianMs: 10 * scale },
      },
      authenticatedPrepared: {
        cold: { medianMs: 40 * scale },
        warm: { medianMs: 30 * scale },
      },
    },
  };
}

function microBaseline(scale = 1) {
  return {
    schema: 'ibex/module-runner-micro-performance-baseline/1',
    platform: { os: 'linux', arch: 'x86_64' },
    measurementConditions: {
      iterations: 20_000,
      requireDependencyModules: 40,
      warmupSamplesExcluded: 2,
    },
    profiles: {
      checkedCellSetterNamespace: { samples: 5, medianMs: 10 * scale },
      plainProperty: { samples: 5, medianMs: 1 },
      coldRequireEsm: { samples: 5, medianMs: 20 * scale },
    },
  };
}

test('accepts native and build ratios inside the explicit Phase-0 envelopes', () => {
  const report = evaluateModuleRunnerPerformance({
    legacy: loaderBaseline(1),
    current: loaderBaseline(1.2),
    native: nativeBaseline(1.2),
    micro: microBaseline(1.2),
  });
  assert.equal(report.passed, true);
  assert.equal(report.advertised, true);
  assert.deepEqual(report.budgets, MODULE_RUNNER_PERFORMANCE_BUDGET);
  assert.equal(report.ratios.sourceCold, 1.2);
});

test('fails each ratio beyond its named envelope', () => {
  const report = evaluateModuleRunnerPerformance({
    legacy: loaderBaseline(1),
    current: loaderBaseline(2),
    native: nativeBaseline(3),
    micro: microBaseline(3),
  });
  assert.equal(report.passed, false);
  assert.deepEqual(report.failures, [
    'sourceCold',
    'sourceWarm',
    'preparedCold',
    'preparedWarm',
    'checkedCellSetterNamespace',
    'coldRequireEsm',
    'binarySize',
    'cleanBuild',
  ]);
});

test('accepts only the exact unadvertised Windows evidence shape', () => {
  const report = evaluateModuleRunnerPerformance({
    legacy: {},
    current: {},
    native: {
      schema: 'ibex/module-runner-unavailability/1',
      platform: { os: 'windows', arch: 'x86_64' },
      status: 'unadvertised',
      reason: 'patched native module ABI unavailable',
    },
  });
  assert.equal(report.passed, true);
  assert.equal(report.advertised, false);
  assert.throws(() =>
    evaluateModuleRunnerPerformance({
      legacy: {},
      current: {},
      native: {
        schema: 'ibex/module-runner-unavailability/1',
        platform: { os: 'linux', arch: 'x86_64' },
        status: 'unadvertised',
      },
    }),
  );
  assert.throws(() =>
    evaluateModuleRunnerPerformance({
      legacy: {},
      current: {},
      native: {
        schema: 'ibex/module-runner-unavailability/1',
        platform: { os: 'windows', arch: 'aarch64' },
        status: 'unadvertised',
        reason: 'patched native module ABI unavailable',
      },
    }),
  );
});

test('rejects cross-host evidence and advertised-target drift', () => {
  const legacy = loaderBaseline(1);
  const current = loaderBaseline(1.2);
  current.platform = { os: 'darwin', arch: 'arm64' };
  assert.throws(
    () => evaluateModuleRunnerPerformance({
      legacy,
      current,
      native: nativeBaseline(1),
      micro: microBaseline(1),
    }),
    /same exact host target/,
  );
  assert.throws(
    () => evaluateModuleRunnerPerformance({
      legacy,
      current: loaderBaseline(1.2),
      native: {
        ...nativeBaseline(1),
        platform: { os: 'windows', arch: 'x86_64' },
      },
      micro: microBaseline(1),
    }),
    /not advertised/,
  );
});
