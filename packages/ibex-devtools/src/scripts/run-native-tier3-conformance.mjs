#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  asyncGeneratorCorpus,
  forOfScopingCorpus,
} from './hermes-compat-corpus.mjs';
import { buildLegacyRequiredTelemetryReport } from './legacy-required-telemetry.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const mapping = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'config/llp0019-native-tier3-corpus.json'), 'utf8'),
);
const targetMatrix = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'config/llp0019-hermes-target-matrix.json'), 'utf8'),
);
const ibexIndex = process.argv.indexOf('--ibex');
assert.ok(ibexIndex !== -1 && process.argv[ibexIndex + 1], 'usage: --ibex PATH');
const ibex = path.resolve(process.argv[ibexIndex + 1]);
const telemetryIndex = process.argv.indexOf('--write-telemetry');
const telemetryPath = telemetryIndex === -1 ? null : process.argv[telemetryIndex + 1];
assert.ok(telemetryIndex === -1 || telemetryPath, '--write-telemetry requires a path');
const telemetryPrefix = 'IBEX_LEGACY_REQUIRED_EVENT ';
const telemetryEvents = [];

const corpusIds = [
  ...forOfScopingCorpus.map(({ id }) => `for-of:${id}`),
  ...asyncGeneratorCorpus.map(({ id }) => `async-generator:${id}`),
].sort();
const mappedIds = mapping.cases.map(({ kind, id }) => `${kind}:${id}`).sort();
assert.deepEqual(mappedIds, corpusIds, 'native disposition mapping must cover the exact corpus');
assert.deepEqual(mapping.profiles, ['source', 'prepared']);
assert.equal(targetMatrix.schema, 'ibex/llp0019-hermes-target-matrix/1');
assert.deepEqual(targetMatrix.profiles, mapping.profiles);

const byId = new Map(forOfScopingCorpus.map((fixture) => [fixture.id, fixture]));
const passing = mapping.cases.filter((row) => row.disposition === 'pass');
assert.ok(passing.length > 0, 'native corpus must contain at least one passing row');
assert.ok(
  passing.every((row) => row.kind === 'for-of'),
  'async generators require a typed quarantine until their native pass lands',
);

function nodeOracle(source) {
  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', `globalThis.print = console.log;\n${source}`],
    { encoding: 'utf8', timeout: 30_000 },
  );
  assert.equal(result.status, 0, `Node oracle failed:\n${result.stderr}`);
  const lines = result.stdout.trim().split(/\r?\n/u).filter(Boolean);
  assert.equal(lines.length, 1, `Node oracle must print exactly one result: ${result.stdout}`);
  return lines[0];
}

function runFixture(root, fixture, profile) {
  const project = path.join(root, `${fixture.namespace}-${fixture.id}-${profile}`);
  // The authenticated cache root must be disjoint from every JavaScript-
  // mounted project root. Keep fixture homes as siblings, never descendants.
  const home = path.join(root, '.homes', `${fixture.namespace}-${fixture.id}-${profile}`);
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  // `--project-root` is the authenticated launcher input. Keeping this
  // package-less avoids asking the resolver to stamp npm package metadata on
  // the root principal; the corpus is intentionally only a module evaluator
  // conformance surface.
  const entryName = `entry.${fixture.extension ?? 'mjs'}`;
  fs.writeFileSync(path.join(project, entryName), fixture.source);

  const env = { ...process.env };
  delete env.EXACT_COMPAT_TEST;
  delete env.IBEX_COMPAT_LOADER_TEST;
  delete env.IBEX_POLICY;
  delete env.EXACT_POLICY;
  env.HOME = home;
  env.XDG_CACHE_HOME = path.join(home, 'cache');
  env.IBEX_SKIP_AGENT_SKILLS_SYNC = '1';
  env.IBEX_TEST_NATIVE_RUNNER_PROFILE = profile;
  const result = spawnSync(
    ibex,
    ['--project-root', project, 'run', entryName],
    { cwd: project, env, encoding: 'utf8', timeout: 120_000 },
  );
  if (fixture.disposition === 'quarantine') {
    assert.notEqual(
      result.status,
      0,
      `${fixture.id}/${profile} silently executed a quarantined syntax family`,
    );
    assert.match(
      result.stderr,
      new RegExp(`native module-runner conformance quarantine: ${fixture.stableCode}:`, 'u'),
      `${fixture.id}/${profile} did not emit its stable quarantine code:\n${result.stderr}`,
    );
    assert.ok(
      result.stderr.includes(fixture.reason),
      `${fixture.id}/${profile} did not emit reason ${fixture.reason}:\n${result.stderr}`,
    );
    assert.ok(
      !result.stderr.includes('IBEX_NATIVE_MODULE_EXECUTION_RECEIPT '),
      `${fixture.id}/${profile} emitted an execution receipt after quarantine`,
    );
    const eventLines = result.stderr
      .split(/\r?\n/u)
      .filter((line) => line.startsWith(telemetryPrefix));
    assert.equal(
      eventLines.length,
      1,
      `${fixture.id}/${profile} must emit one typed LegacyRequired event:\n${result.stderr}`,
    );
    const event = JSON.parse(eventLines[0].slice(telemetryPrefix.length));
    assert.equal(event.schema, 'ibex/legacy-required-telemetry-event/1');
    assert.equal(event.code, fixture.stableCode);
    assert.equal(event.shape, fixture.reason);
    assert.match(event.moduleSourceId, /^ibex-source-id-v1:/u);
    assert.ok(event.originalSourceSite.line > 0);
    assert.ok(event.originalSourceSite.column > 0);
    assert.equal(event.runtimeVersion, '0.1.0');
    telemetryEvents.push(event);
    return;
  }
  assert.equal(
    result.status,
    0,
    `${fixture.id}/${profile} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  // The native product path always uses LLP 0034's default ES6 block-scoping
  // mode. `rawHermesCaptureLast` belongs only to the explicit legacy rollback
  // exercised by the standalone Hermes/loader compatibility gates.
  // @ref LLP 0034#compatibility-transform-transition
  const expected = fixture.expectedOutput ?? nodeOracle(fixture.source);
  assert.ok(expected, `${fixture.id} has no engine-truth oracle`);
  assert.ok(
    result.stdout.split(/\r?\n/u).includes(expected),
    `${fixture.id}/${profile} did not match the oracle ${expected}:\n${result.stdout}`,
  );
  const prefix = 'IBEX_NATIVE_MODULE_EXECUTION_RECEIPT ';
  const receiptLines = result.stderr
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(prefix));
  assert.equal(
    receiptLines.length,
    1,
    `${fixture.id}/${profile} must emit exactly one native execution receipt:\n${result.stderr}`,
  );
  const receipt = JSON.parse(receiptLines[0].slice(prefix.length));
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

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-native-tier3-'));
let passed = 0;
try {
  for (const row of passing) {
    const fixture = byId.get(row.id);
    assert.ok(fixture, `missing for-of fixture ${row.id}`);
    for (const profile of mapping.profiles) {
      runFixture(
        root,
        { ...fixture, id: row.id, namespace: 'corpus', disposition: 'pass' },
        profile,
      );
      passed += 1;
    }
  }
  for (const row of targetMatrix.rows) {
    if (row.disposition === 'blocked-on-decision') continue;
    assert.ok(
      row.disposition === 'pass' || row.disposition === 'quarantine',
      `unknown target-matrix disposition ${row.disposition}`,
    );
    for (const profile of targetMatrix.profiles) {
      runFixture(root, { ...row, namespace: 'matrix' }, profile);
      passed += 1;
    }
  }
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

const runnableMatrixRows = targetMatrix.rows.filter(
  ({ disposition }) => disposition !== 'blocked-on-decision',
);
const blockedMatrixRows = targetMatrix.rows.filter(
  ({ disposition }) => disposition === 'blocked-on-decision',
);
const total =
  passing.length * mapping.profiles.length +
  runnableMatrixRows.length * targetMatrix.profiles.length;
assert.equal(passed, total);
if (telemetryPath) {
  const modules = [
    ...passing.map((row) => {
      const fixture = byId.get(row.id);
      return {
        sourceId: `corpus:${row.id}`,
        fileName: `entry.${fixture.extension ?? 'mjs'}`,
        source: fixture.source,
      };
    }),
    ...runnableMatrixRows.map((row) => ({
      sourceId: `matrix:${row.id}`,
      fileName: `entry.${row.extension ?? 'mjs'}`,
      source: row.source,
    })),
  ];
  const report = buildLegacyRequiredTelemetryReport({
    populationId: 'ibex-native-tier3-controlled-fixtures',
    boundary: 'Only the checked Ibex native Tier-3 and Hermes-target fixture population; this is not released-user field usage.',
    modules,
    events: telemetryEvents,
    executions: total,
  });
  fs.mkdirSync(path.dirname(path.resolve(telemetryPath)), { recursive: true });
  fs.writeFileSync(path.resolve(telemetryPath), `${JSON.stringify(report, null, 2)}\n`);
}
console.log(
  `hermes-compat native: ${passed}/${total} fixtures ok; ` +
    `${blockedMatrixRows.length} target-matrix row blocked on author decision`,
);
