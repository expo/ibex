#!/usr/bin/env node
/** Build Ibex in a fresh target directory and collect the Phase-0 loader report. */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');

function parseArgs(argv) {
  const options = {
    samples: 5,
    write: '',
    targetDir: '',
    expectOs: '',
    expectArch: '',
    hostContentionObserved: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--samples') options.samples = Number(argv[++index]);
    else if (arg === '--write') options.write = argv[++index] || '';
    else if (arg === '--target-dir') options.targetDir = argv[++index] || '';
    else if (arg === '--expect-os') options.expectOs = argv[++index] || '';
    else if (arg === '--expect-arch') options.expectArch = argv[++index] || '';
    else if (arg === '--host-contention-observed') options.hostContentionObserved = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.write) throw new Error('--write /path/to/report.json is required');
  if (!Number.isInteger(options.samples) || options.samples < 3) {
    throw new Error('--samples must be an integer >= 3');
  }
  if (options.expectOs && options.expectOs !== process.platform) {
    throw new Error(`expected OS ${options.expectOs}, got ${process.platform}`);
  }
  if (options.expectArch && options.expectArch !== process.arch) {
    throw new Error(`expected architecture ${options.expectArch}, got ${process.arch}`);
  }
  return options;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: process.env,
    stdio: 'inherit',
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited with status ${result.status}`);
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const ownsTarget = !options.targetDir;
  const targetDir = options.targetDir
    ? path.resolve(options.targetDir)
    : mkdtempSync(path.join(os.tmpdir(), 'ibex-module-baseline-build-'));
  try {
    const started = performance.now();
    run('cargo', ['build', '--release', '--bin', 'ibex'], {
      env: { ...process.env, CARGO_TARGET_DIR: targetDir },
    });
    const cleanBuildSeconds = (performance.now() - started) / 1000;
    const binary = path.join(targetDir, 'release', process.platform === 'win32' ? 'ibex.exe' : 'ibex');
    if (!statSync(binary).isFile()) throw new Error(`release binary missing: ${binary}`);

    const benchmarkArgs = [
      path.join(scriptDir, 'benchmark-module-loader-baseline.mjs'),
      '--ibex',
      binary,
      '--samples',
      String(options.samples),
      '--clean-build-seconds',
      cleanBuildSeconds.toFixed(3),
      '--write',
      path.resolve(options.write),
    ];
    if (options.hostContentionObserved) benchmarkArgs.push('--host-contention-observed');
    run(process.execPath, benchmarkArgs);
  } finally {
    if (ownsTarget) rmSync(targetDir, { recursive: true, force: true });
  }
}

main();
