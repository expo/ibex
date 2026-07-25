#!/usr/bin/env node
/**
 * Run LLP 0026's Phase-0 module-semantics corpus against the pinned Node
 * oracle and the current real Ibex/Hermes compatibility path.
 *
 * Usage:
 *   node@24.13.1 run-module-semantics-baseline.mjs --ibex /path/to/ibex
 *   node@24.13.1 run-module-semantics-baseline.mjs --ibex /path/to/ibex --write-baseline
 *
 * @ref LLP 0026#compatibility-contract-and-conformance-corpus — wrong oracle
 * versions, zero cases, missing binaries, and silent runtime skips fail loud.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  moduleSemanticsCorpus,
  moduleSemanticsMarker,
} from './module-semantics-corpus.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const baselinePath = path.join(
  repoRoot,
  'tests/fixtures/module-semantics/current-loader-baseline.json',
);

function parseArgs(argv) {
  const options = { ibex: '', writeBaseline: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--ibex') {
      options.ibex = argv[++index] || '';
    } else if (arg === '--write-baseline') {
      options.writeBaseline = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!options.ibex) {
    throw new Error('--ibex /path/to/ibex is required; the Hermes path may not be skipped');
  }
  return options;
}

function pinnedNodeVersion() {
  const identity = JSON.parse(readFileSync(path.join(repoRoot, 'runtime-identity.json'), 'utf8'));
  return String(identity?.versions?.node || '');
}

function writeProject(root, fixture) {
  for (const [relative, contents] of Object.entries(fixture.files)) {
    const output = path.join(root, relative);
    mkdirSync(path.dirname(output), { recursive: true });
    writeFileSync(output, contents);
  }
}

function entryFor(fixture, runtime) {
  return typeof fixture.entry === 'string' ? fixture.entry : fixture.entry[runtime];
}

function markerLines(stdout) {
  return stdout
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(moduleSemanticsMarker));
}

function run(command, args, cwd, env = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 60_000,
  });
  if (result.error) {
    throw result.error;
  }
  return {
    status: result.status,
    signal: result.signal,
    lines: markerLines(result.stdout || ''),
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function stableObservation(result) {
  return {
    status: result.status,
    signal: result.signal,
    lines: result.lines,
  };
}

function readBaseline() {
  return JSON.parse(readFileSync(baselinePath, 'utf8'));
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const expectedNode = pinnedNodeVersion();
  const actualNode = process.versions.node;
  if (actualNode !== expectedNode) {
    throw new Error(
      `wrong Node oracle: runtime-identity.json pins ${expectedNode}, runner is ${actualNode}`,
    );
  }
  if (moduleSemanticsCorpus.length === 0) {
    throw new Error('module-semantics corpus is empty');
  }

  const observations = {};
  let passed = 0;
  for (const fixture of moduleSemanticsCorpus) {
    const root = mkdtempSync(path.join(os.tmpdir(), `ibex-module-semantics-${fixture.id}-`));
    try {
      writeProject(root, fixture);
      const node = run(process.execPath, [entryFor(fixture, 'node')], root);
      const ibex = run(
        options.ibex,
        ['capsec', 'audit', entryFor(fixture, 'ibex')],
        root,
        {
          EXACT_COMPAT_TEST: '1',
          IBEX_COMPAT_LOADER_TEST: '1',
          IBEX_SKIP_AGENT_SKILLS_SYNC: '1',
        },
      );

      const failures = [];
      if (node.status !== 0) {
        failures.push(`Node oracle exited ${node.status}: ${node.stderr.trim()}`);
      }
      if (JSON.stringify(node.lines) !== JSON.stringify(fixture.oracle)) {
        failures.push(`Node oracle lines ${JSON.stringify(node.lines)} != ${JSON.stringify(fixture.oracle)}`);
      }
      if (ibex.status === null) {
        failures.push(`Ibex terminated by ${ibex.signal || 'unknown signal'}: ${ibex.stderr.trim()}`);
      }
      const currentIbex = fixture.currentIbex || { outcome: 'marker' };
      if (currentIbex.outcome === 'error') {
        if (ibex.status === 0) {
          failures.push(`Ibex unexpectedly succeeded; expected named current-path error containing ${JSON.stringify(currentIbex.stderrIncludes)}`);
        }
        if (!ibex.stderr.includes(currentIbex.stderrIncludes)) {
          failures.push(`Ibex error did not contain ${JSON.stringify(currentIbex.stderrIncludes)}: ${ibex.stderr.trim()}`);
        }
      } else {
        if (ibex.status !== 0) {
          failures.push(`Ibex exited ${ibex.status}: ${ibex.stderr.trim()}`);
        }
        if (ibex.lines.length === 0) {
          failures.push(`Ibex emitted no ${moduleSemanticsMarker} observation: ${ibex.stderr.trim()}`);
        }
      }

      observations[fixture.id] = {
        category: fixture.category,
        node: stableObservation(node),
        ibex: stableObservation(ibex),
      };
      const ok = failures.length === 0;
      if (ok) passed += 1;
      console.log(`${ok ? 'ok  ' : 'FAIL'} ${fixture.id}`);
      for (const failure of failures) console.log(`     - ${failure}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  const generated = {
    schema: 'ibex/module-semantics-current-loader-baseline/1',
    oracle: { name: 'node', version: actualNode },
    fixtureCount: moduleSemanticsCorpus.length,
    observations,
  };

  if (options.writeBaseline) {
    mkdirSync(path.dirname(baselinePath), { recursive: true });
    writeFileSync(baselinePath, `${JSON.stringify(generated, null, 2)}\n`);
  } else {
    const baseline = readBaseline();
    if (JSON.stringify(generated) !== JSON.stringify(baseline)) {
      for (const [fixtureId, actual] of Object.entries(generated.observations)) {
        const expected = baseline.observations?.[fixtureId];
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
          console.error(
            `module-semantics baseline delta ${fixtureId}: expected ${JSON.stringify(expected)}; actual ${JSON.stringify(actual)}`,
          );
        }
      }
      console.error(
        'module-semantics baseline drifted; inspect the semantic delta and rerun with --write-baseline only when intentional',
      );
      process.exitCode = 1;
    }
  }

  console.log(`module-semantics baseline: ${passed}/${moduleSemanticsCorpus.length} fixtures produced Node+Hermes observations`);
  if (passed !== moduleSemanticsCorpus.length) process.exitCode = 1;
}

main();
