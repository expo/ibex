#!/usr/bin/env node
/** Execute the predeclared 20-case test262 sample through generated factories. */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runtimeSource } from './run-module-runner-spike.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const marker = 'MODULE_RUNNER_SPIKE|';

function parseArgs(argv) {
  const options = {
    artifacts: path.join(repoRoot, 'tests/fixtures/module-runner-spike/test262-artifacts.json'),
    hermes: process.env.IBEX_HERMES_BIN || '',
    writeReport: '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--artifacts') options.artifacts = argv[++index] || '';
    else if (arg === '--hermes') options.hermes = argv[++index] || '';
    else if (arg === '--write-report') options.writeReport = argv[++index] || '';
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.hermes) throw new Error('--hermes /path/to/real/hermes is required');
  return options;
}

function harnessSource() {
  return `
function Test262Error(message) {
  this.name = "Test262Error";
  this.message = String(message || "Test262 assertion failed");
}
Test262Error.prototype = Object.create(Error.prototype);
Test262Error.prototype.constructor = Test262Error;
var assert = {
  sameValue: function (actual, expected, message) {
    var same = actual === expected ? (actual !== 0 || 1 / actual === 1 / expected) : (actual !== actual && expected !== expected);
    if (!same) throw new Test262Error((message ? message + ": " : "") + "Expected SameValue");
  }
};
var __test262Done = false;
function $DONE(error) {
  if (error) throw error instanceof Error ? error : new Test262Error(error);
  if (__test262Done) throw new Test262Error("$DONE called twice");
  __test262Done = true;
}
`;
}

function runCase(hermes, testCase) {
  if (testCase.producerError) {
    return { ok: false, stage: 'producer', error: testCase.producerError };
  }
  const fixture = {
    id: testCase.id,
    entry: 'entry.js',
    expected: { stdout: [] },
    modules: [testCase.artifact],
  };
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ibex-test262-spike-'));
  const script = path.join(directory, 'case.js');
  try {
    writeFileSync(script, harnessSource() + runtimeSource(fixture));
    const result = spawnSync(hermes, [script], { encoding: 'utf8', timeout: 30_000 });
    if (result.error) return { ok: false, stage: 'hermes', error: result.error.message };
    if (result.status !== 0) {
      return { ok: false, stage: 'hermes', error: `exit ${result.status}: ${result.stderr.trim()}` };
    }
    const line = result.stdout.split(/\r?\n/u).find((value) => value.startsWith(marker));
    if (!line) return { ok: false, stage: 'hermes', error: 'no completion marker' };
    const outcome = JSON.parse(line.slice(marker.length));
    return outcome.ok
      ? { ok: true, stage: 'hermes' }
      : { ok: false, stage: 'hermes', error: `${outcome.errorName}: ${outcome.message}` };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const bundle = JSON.parse(readFileSync(options.artifacts, 'utf8'));
  if (bundle.schema !== 'ibex/module-runner-test262-artifacts/1') {
    throw new Error(`unexpected artifact schema: ${bundle.schema}`);
  }
  const results = bundle.cases.map((testCase) => ({
    id: testCase.id,
    suite: testCase.suite,
    upstreamPath: testCase.upstreamPath,
    expectedDivergence: testCase.expectedDivergence,
    ...runCase(options.hermes, testCase),
  }));
  const passed = results.filter((result) => result.ok).length;
  const minimum = bundle.minimumPassRate.numerator;
  const versionResult = spawnSync(options.hermes, ['-version'], { encoding: 'utf8' });
  if (versionResult.status !== 0) throw new Error(`Hermes version probe failed: ${versionResult.stderr}`);
  const report = {
    schema: 'ibex/module-runner-test262-spike-report/1',
    upstream: bundle.upstream,
    transformFingerprint: bundle.transformFingerprint,
    hermes: {
      binaryName: path.basename(options.hermes),
      versionOutput: versionResult.stdout.trim(),
      platform: { os: process.platform, arch: process.arch, release: os.release() },
    },
    threshold: bundle.minimumPassRate,
    total: results.length,
    passed,
    thresholdMet: results.length === bundle.minimumPassRate.denominator && passed >= minimum,
    expectedDivergences: bundle.expectedDivergences,
    results,
  };
  for (const result of results) {
    console.log(`  ${result.ok ? 'ok  ' : 'FAIL'} ${result.id}${result.ok ? ' [real Hermes]' : ` (${result.stage}: ${result.error})`}`);
  }
  console.log(
    `module-runner test262 spike: ${passed}/${results.length} passed; threshold ${minimum}/${bundle.minimumPassRate.denominator} (${report.thresholdMet ? 'met' : 'NOT MET'}), real Hermes: ${options.hermes}`,
  );
  if (options.writeReport) writeFileSync(options.writeReport, `${JSON.stringify(report, null, 2)}\n`);
  if (!report.thresholdMet) process.exit(1);
}

main();
