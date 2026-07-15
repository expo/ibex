#!/usr/bin/env node
/**
 * Reproducible Phase-0 timing harness for the shipped module-loader paths.
 * Results are diagnostic baselines, not default-switch budgets.
 *
 * @ref LLP 0026#phase-0-baseline-the-current-contract — measure direct source,
 * SWC-selected source, cold transform, warm cache, startup, and binary size
 * before the experimental runner changes the evaluator.
 */

import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const marker = 'MODULE_BASELINE|';

function parseArgs(argv) {
  const options = { ibex: '', samples: 5, write: '', cleanBuildSeconds: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--ibex') options.ibex = argv[++index] || '';
    else if (arg === '--samples') options.samples = Number(argv[++index]);
    else if (arg === '--write') options.write = argv[++index] || '';
    else if (arg === '--clean-build-seconds') {
      options.cleanBuildSeconds = Number(argv[++index]);
    }
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.ibex) throw new Error('--ibex /path/to/ibex is required');
  if (!Number.isInteger(options.samples) || options.samples < 3) {
    throw new Error('--samples must be an integer >= 3');
  }
  if (
    options.cleanBuildSeconds !== null
    && (!Number.isFinite(options.cleanBuildSeconds) || options.cleanBuildSeconds <= 0)
  ) {
    throw new Error('--clean-build-seconds must be a positive number');
  }
  return options;
}

function createGraph(root, extension, count = 40) {
  mkdirSync(root, { recursive: true });
  for (let index = count - 1; index >= 0; index -= 1) {
    const next = index + 1 < count ? `import { value as next } from './m${index + 1}.${extension}';` : 'const next = 0;';
    const type = extension === 'ts' ? ': number' : '';
    writeFileSync(
      path.join(root, `m${index}.${extension}`),
      `${next}\nexport const value${type} = next + 1;\n`,
    );
  }
  writeFileSync(
    path.join(root, 'entry.js'),
    `var result = require('./m0.${extension}');\nconsole.log('${marker}' + result.value);\n`,
  );
}

function runIbex(ibex, project, home) {
  const started = performance.now();
  const result = spawnSync(ibex, ['capsec', 'audit', 'entry.js'], {
    cwd: project,
    env: {
      ...process.env,
      HOME: home,
      EXACT_COMPAT_TEST: '1',
      IBEX_SKIP_AGENT_SKILLS_SYNC: '1',
    },
    encoding: 'utf8',
    timeout: 120_000,
  });
  const elapsedMs = performance.now() - started;
  if (result.error) throw result.error;
  if (result.status !== 0 || !result.stdout.split(/\r?\n/u).includes(`${marker}40`)) {
    throw new Error(
      `Ibex graph run failed (status ${result.status})\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  return elapsedMs;
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  return {
    samples: values.length,
    minMs: Number(sorted[0].toFixed(3)),
    medianMs: Number(sorted[Math.floor(sorted.length / 2)].toFixed(3)),
    meanMs: Number(mean.toFixed(3)),
    maxMs: Number(sorted.at(-1).toFixed(3)),
  };
}

function measureProfile(options, extension) {
  const project = mkdtempSync(path.join(os.tmpdir(), `ibex-module-baseline-${extension}-`));
  createGraph(project, extension);
  const cold = [];
  const warm = [];
  try {
    for (let sample = 0; sample < options.samples; sample += 1) {
      const coldHome = mkdtempSync(path.join(os.tmpdir(), `ibex-module-cold-${extension}-`));
      try {
        cold.push(runIbex(options.ibex, project, coldHome));
      } finally {
        rmSync(coldHome, { recursive: true, force: true });
      }
    }
    const warmHome = mkdtempSync(path.join(os.tmpdir(), `ibex-module-warm-${extension}-`));
    try {
      runIbex(options.ibex, project, warmHome);
      for (let sample = 0; sample < options.samples; sample += 1) {
        warm.push(runIbex(options.ibex, project, warmHome));
      }
    } finally {
      rmSync(warmHome, { recursive: true, force: true });
    }
  } finally {
    rmSync(project, { recursive: true, force: true });
  }
  return { cold: summarize(cold), warm: summarize(warm) };
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, { cwd: repoRoot, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const identity = JSON.parse(readFileSync(path.join(repoRoot, 'runtime-identity.json'), 'utf8'));
  const report = {
    schema: 'ibex/module-loader-performance-baseline/1',
    runtimeIdentity: identity,
    platform: {
      os: process.platform,
      arch: process.arch,
      release: os.release(),
      cpu: os.cpus()[0]?.model || 'unknown',
    },
    revision: commandOutput('git', ['rev-parse', 'HEAD']),
    rustc: commandOutput('rustc', ['--version']),
    ibexBinaryBytes: statSync(options.ibex).size,
    graphModules: 40,
    profiles: {
      directSourceMjs: measureProfile(options, 'mjs'),
      swcSelectedTs: measureProfile(options, 'ts'),
    },
    compile: {
      cleanBuildSeconds: options.cleanBuildSeconds,
      note: options.cleanBuildSeconds === null
        ? 'Populate from a clean CARGO_TARGET_DIR build on each supported desktop target; runtime timing never fabricates compile data.'
        : 'Measured with /usr/bin/time -p, a fresh CARGO_TARGET_DIR, cargo build --release --bin ibex, and matching authenticated Hermes compiler/headers/framework inputs.',
    },
  };
  const rendered = `${JSON.stringify(report, null, 2)}\n`;
  if (options.write) {
    const output = path.resolve(options.write);
    mkdirSync(path.dirname(output), { recursive: true });
    writeFileSync(output, rendered);
  }
  process.stdout.write(rendered);
}

main();
