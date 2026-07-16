import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// @ref LLP 0026#performance-and-platform-gates — enforce the accepted
// same-host runtime, binary-size, and clean-build envelopes fail-loudly.
export const MODULE_RUNNER_PERFORMANCE_BUDGET = Object.freeze({
  runtimeRatio: 1.25,
  binarySizeRatio: 1.25,
  cleanBuildRatio: 1.5,
});

function finitePositive(value, label) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} must be a positive finite number`);
  }
  return value;
}

function ratio(actual, baseline, label) {
  return finitePositive(actual, `${label}.actual`) /
    finitePositive(baseline, `${label}.baseline`);
}

function canonicalTarget(platform, label) {
  const aliases = new Map([
    ['darwin/arm64', 'macos/aarch64'],
    ['linux/x64', 'linux/x86_64'],
    ['linux/x86_64', 'linux/x86_64'],
    ['macos/aarch64', 'macos/aarch64'],
    ['win32/x64', 'windows/x86_64'],
    ['windows/x86_64', 'windows/x86_64'],
  ]);
  const target = aliases.get(`${platform?.os}/${platform?.arch}`);
  if (!target) throw new Error(`${label} has an unsupported platform tuple`);
  return target;
}

export function evaluateModuleRunnerPerformance({ legacy, current, native }) {
  if (native.schema === 'ibex/module-runner-unavailability/1') {
    if (
      native.status !== 'unadvertised'
      || canonicalTarget(native.platform, 'native unavailability') !== 'windows/x86_64'
      || typeof native.reason !== 'string'
      || native.reason.length < 20
    ) {
      throw new Error('only the exact Windows row may report native-runner unavailability');
    }
    return {
      schema: 'ibex/module-runner-performance-gate/1',
      platform: native.platform,
      advertised: false,
      passed: true,
      reason: native.reason,
    };
  }

  if (native.schema !== 'ibex/module-runner-performance-baseline/1') {
    throw new Error(`unsupported native performance schema ${native.schema}`);
  }
  if (legacy.schema !== 'ibex/module-loader-performance-baseline/2' ||
      current.schema !== 'ibex/module-loader-performance-baseline/2') {
    throw new Error('compatibility baselines must use module-loader baseline schema v2');
  }
  if (legacy.measurementConditions?.moduleRunnerDefaultFeatureEnabled !== false) {
    throw new Error('legacy report must be collected without default features');
  }
  if (current.measurementConditions?.moduleRunnerDefaultFeatureEnabled !== true) {
    throw new Error('current report must be collected with default features');
  }
  if (
    legacy.measurementConditions?.usableForPerformanceBudget !== true
    || current.measurementConditions?.usableForPerformanceBudget !== true
  ) {
    throw new Error('contended performance reports cannot satisfy the gate');
  }
  if (legacy.graphModules !== 40 || current.graphModules !== 40 || native.dependencyModules !== 40) {
    throw new Error('performance reports must cover the same 40-module graph');
  }
  const nativeTarget = canonicalTarget(native.platform, 'native report');
  if (!['macos/aarch64', 'linux/x86_64'].includes(nativeTarget)) {
    throw new Error(`native performance evidence is not advertised for ${nativeTarget}`);
  }
  if (
    canonicalTarget(legacy.platform, 'legacy report') !== nativeTarget
    || canonicalTarget(current.platform, 'current report') !== nativeTarget
  ) {
    throw new Error('performance reports must come from the same exact host target');
  }

  const ratios = {
    sourceCold: ratio(
      native.profiles?.authenticatedSource?.cold?.medianMs,
      legacy.profiles?.directSourceMjs?.cold?.medianMs,
      'sourceCold',
    ),
    sourceWarm: ratio(
      native.profiles?.authenticatedSource?.warm?.medianMs,
      legacy.profiles?.directSourceMjs?.warm?.medianMs,
      'sourceWarm',
    ),
    preparedCold: ratio(
      native.profiles?.authenticatedPrepared?.cold?.medianMs,
      legacy.profiles?.preparedRolldownMjs?.cold?.medianMs,
      'preparedCold',
    ),
    preparedWarm: ratio(
      native.profiles?.authenticatedPrepared?.warm?.medianMs,
      legacy.profiles?.preparedRolldownMjs?.warm?.medianMs,
      'preparedWarm',
    ),
    binarySize: ratio(current.ibexBinaryBytes, legacy.ibexBinaryBytes, 'binarySize'),
    cleanBuild: ratio(
      current.compile?.cleanBuildSeconds,
      legacy.compile?.cleanBuildSeconds,
      'cleanBuild',
    ),
  };
  const failures = [];
  for (const name of ['sourceCold', 'sourceWarm', 'preparedCold', 'preparedWarm']) {
    if (ratios[name] > MODULE_RUNNER_PERFORMANCE_BUDGET.runtimeRatio) failures.push(name);
  }
  if (ratios.binarySize > MODULE_RUNNER_PERFORMANCE_BUDGET.binarySizeRatio) {
    failures.push('binarySize');
  }
  if (ratios.cleanBuild > MODULE_RUNNER_PERFORMANCE_BUDGET.cleanBuildRatio) {
    failures.push('cleanBuild');
  }

  return {
    schema: 'ibex/module-runner-performance-gate/1',
    platform: native.platform,
    advertised: true,
    budgets: MODULE_RUNNER_PERFORMANCE_BUDGET,
    ratios,
    passed: failures.length === 0,
    failures,
  };
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return resolve(process.argv[index + 1]);
}

if (import.meta.main) {
  const legacyPath = argument('--legacy');
  const currentPath = argument('--current');
  const nativePath = argument('--native');
  const outputPath = argument('--write');
  const report = evaluateModuleRunnerPerformance({
    legacy: JSON.parse(readFileSync(legacyPath, 'utf8')),
    current: JSON.parse(readFileSync(currentPath, 'utf8')),
    native: JSON.parse(readFileSync(nativePath, 'utf8')),
  });
  writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) {
    throw new Error(`module-runner performance budget failed: ${report.failures.join(', ')}`);
  }
}
