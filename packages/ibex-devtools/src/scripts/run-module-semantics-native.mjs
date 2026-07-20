#!/usr/bin/env node

/**
 * Execute LLP 0028's first transform tranche through the real native module
 * runner in both source and prepared profiles.
 *
 * @ref LLP 0028#5-conformance-gates-telemetry-and-rollout — semantic output
 * alone is insufficient; successful rows require an execution receipt bound
 * to the loaded engine and physical carrier.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  moduleSemanticsMarker,
  moduleTransformCorpus,
} from './module-semantics-corpus.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const ibexIndex = process.argv.indexOf('--ibex');
assert.ok(ibexIndex !== -1 && process.argv[ibexIndex + 1], 'usage: --ibex PATH');
const ibex = path.resolve(process.argv[ibexIndex + 1]);
const filterIndex = process.argv.indexOf('--filter');
const filter = filterIndex === -1 ? null : process.argv[filterIndex + 1];
assert.ok(filterIndex === -1 || filter, '--filter requires a fixture id');
const profileIndex = process.argv.indexOf('--profile');
const profileFilter = profileIndex === -1 ? null : process.argv[profileIndex + 1];
assert.ok(
  profileFilter === null || profileFilter === 'source' || profileFilter === 'prepared',
  '--profile must be source or prepared',
);
const profiles = profileFilter ? [profileFilter] : ['source', 'prepared'];
const receiptPrefix = 'IBEX_NATIVE_MODULE_EXECUTION_RECEIPT ';

const identity = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'runtime-identity.json'), 'utf8'),
);
assert.equal(
  process.versions.node,
  String(identity.versions.node),
  'the module-semantics oracle must use the runtime-identity Node version',
);
assert.ok(moduleTransformCorpus.length > 0, 'transform corpus must not be empty');
const selectedCorpus = filter
  ? moduleTransformCorpus.filter((fixture) => fixture.id === filter)
  : moduleTransformCorpus;
assert.ok(selectedCorpus.length > 0, `no transform fixture matched ${filter}`);

function writeProject(root, fixture) {
  for (const [relative, contents] of Object.entries(fixture.files)) {
    const output = path.join(root, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, contents);
  }
}

function entryFor(fixture, runtime) {
  return typeof fixture.entry === 'string' ? fixture.entry : fixture.entry[runtime];
}

function markerLines(stdout) {
  return stdout.split(/\r?\n/u).filter((line) => line.startsWith(moduleSemanticsMarker));
}

function spawn(command, args, cwd, env = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  return result;
}

function validateReceipt(fixture, profile, stderr) {
  const lines = stderr.split(/\r?\n/u).filter((line) => line.startsWith(receiptPrefix));
  assert.equal(
    lines.length,
    1,
    `${fixture.id}/${profile} must emit exactly one native receipt:\n${stderr}`,
  );
  const receipt = JSON.parse(lines[0].slice(receiptPrefix.length));
  assert.equal(receipt.schema, 'ibex/native-module-execution-receipt/1');
  assert.equal(receipt.profile, profile);
  assert.match(receipt.entrySourceId, /^ibex-source-id-v1:/u);
  assert.match(receipt.loadedHermesDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
  assert.ok(receipt.records.length > 0);
  for (const record of receipt.records) {
    assert.match(record.sourceId, /^ibex-source-id-v1:/u);
    assert.match(record.semanticDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
    assert.match(record.transformFingerprintDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
    assert.match(record.producerBinaryDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
    assert.equal(
      record.carrierKind,
      profile === 'source' ? 'inline-source' : 'prepared-carrier',
    );
  }
}

let passed = 0;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-module-transform-native-'));
try {
  for (const fixture of selectedCorpus) {
    const project = path.join(root, fixture.id);
    const home = path.join(project, '.home');
    fs.mkdirSync(home, { recursive: true });
    writeProject(project, fixture);

    const oracle = spawn(process.execPath, [entryFor(fixture, 'node')], project);
    assert.equal(oracle.status, 0, `${fixture.id} Node oracle failed:\n${oracle.stderr}`);
    assert.deepEqual(
      markerLines(oracle.stdout),
      fixture.oracle,
      `${fixture.id} Node oracle drifted`,
    );

    for (const profile of profiles) {
      const env = { ...process.env };
      delete env.EXACT_COMPAT_TEST;
      delete env.IBEX_COMPAT_LOADER_TEST;
      delete env.IBEX_POLICY;
      delete env.EXACT_POLICY;
      env.HOME = home;
      env.XDG_CACHE_HOME = path.join(home, 'cache');
      env.IBEX_SKIP_AGENT_SKILLS_SYNC = '1';
      env.IBEX_TEST_NATIVE_RUNNER_PROFILE = profile;
      const result = spawn(
        ibex,
        ['--project-root', project, 'run', entryFor(fixture, 'ibex')],
        project,
        env,
      );
      if (fixture.native?.outcome === 'error') {
        assert.notEqual(result.status, 0, `${fixture.id}/${profile} unexpectedly succeeded`);
        if (!result.stderr.includes(fixture.native.stderrIncludes)) {
          process.stderr.write(`--- ${fixture.id}/${profile} native stderr ---\n${result.stderr}`);
          throw new Error(`${fixture.id}/${profile} error drifted:\n${result.stderr}`);
        }
        assert.ok(
          !result.stderr.includes(receiptPrefix),
          `${fixture.id}/${profile} emitted a receipt after producer failure`,
        );
      } else {
        assert.equal(
          result.status,
          0,
          `${fixture.id}/${profile} failed:\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
        );
        assert.deepEqual(
          markerLines(result.stdout),
          fixture.oracle,
          `${fixture.id}/${profile} behavior diverged`,
        );
        validateReceipt(fixture, profile, result.stderr);
      }
      passed += 1;
    }
  }
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

const total = selectedCorpus.length * profiles.length;
assert.equal(passed, total);
console.log(`module-semantics native: ${passed}/${total} fixtures ok`);
