#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import {
  SFE_PERFORMANCE_MEASUREMENT_SCHEMA,
  SFE_PERFORMANCE_REPORT_SCHEMA,
  SFE_RELEASE_TARGETS,
  evaluateSfePerformance,
  projectSfePerformanceArtifactInspection,
  sha256Digest,
  summarizeSamples,
  validateSfePerformanceArtifactInspections,
  validateSfePerformanceBudgets,
} from './sfe-performance.mjs';

function parseArgs(argv) {
  const options = {
    budgets: '',
    ibex: '',
    helloHbc: '',
    largeGraphHbc: '',
    helloFactoryTable: '',
    helloOutput: '',
    largeGraphOutput: '',
    factoryTableOutput: '',
    target: '',
    samples: null,
    write: '',
    hostContentionObserved: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const next = () => argv[++index] || '';
    if (argument === '--budgets') options.budgets = next();
    else if (argument === '--ibex') options.ibex = next();
    else if (argument === '--hello-hbc') options.helloHbc = next();
    else if (argument === '--large-graph-hbc') options.largeGraphHbc = next();
    else if (argument === '--hello-factory-table') options.helloFactoryTable = next();
    else if (argument === '--hello-output') options.helloOutput = next();
    else if (argument === '--large-graph-output') options.largeGraphOutput = next();
    else if (argument === '--factory-table-output') options.factoryTableOutput = next();
    else if (argument === '--target') options.target = next();
    else if (argument === '--samples') options.samples = Number(next());
    else if (argument === '--write') options.write = next();
    else if (argument === '--host-contention-observed') {
      options.hostContentionObserved = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  const required = [
    ['--budgets', 'budgets'],
    ['--ibex', 'ibex'],
    ['--hello-hbc', 'helloHbc'],
    ['--large-graph-hbc', 'largeGraphHbc'],
    ['--hello-factory-table', 'helloFactoryTable'],
    ['--hello-output', 'helloOutput'],
    ['--large-graph-output', 'largeGraphOutput'],
    ['--factory-table-output', 'factoryTableOutput'],
    ['--target', 'target'],
    ['--write', 'write'],
  ];
  for (const [flag, key] of required) {
    if (!options[key]) throw new Error(`${flag} is required`);
  }
  if (!SFE_RELEASE_TARGETS.includes(options.target)) {
    throw new Error(`--target must be one of: ${SFE_RELEASE_TARGETS.join(', ')}`);
  }
  if (
    options.samples !== null
    && (!Number.isInteger(options.samples) || options.samples < 5)
  ) {
    throw new Error('--samples must be an integer >= 5');
  }
  return options;
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: options.timeout ?? 120_000,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.signal) {
    throw new Error(`${commandName} ${args.join(' ')} terminated by ${result.signal}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `${commandName} ${args.join(' ')} exited ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

function optionalCommand(commandName, args) {
  const result = spawnSync(commandName, args, {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

function requireExecutable(filePath, label) {
  const resolved = realpathSync(path.resolve(filePath));
  const stats = statSync(resolved);
  if (!stats.isFile()) throw new Error(`${label} must be a regular file`);
  if ((stats.mode & 0o111) === 0) throw new Error(`${label} must be executable`);
  return resolved;
}

function hostTarget() {
  if (process.platform === 'darwin' && process.arch === 'arm64') {
    return 'aarch64-apple-darwin';
  }
  if (process.platform === 'linux' && process.arch === 'x64') {
    return 'x86_64-unknown-linux-gnu';
  }
  return null;
}

function repositoryIdentity(budgetPath) {
  const repoRoot = command('git', ['rev-parse', '--show-toplevel']);
  const root = realpathSync(repoRoot);
  const resolvedBudget = realpathSync(path.resolve(budgetPath));
  const relativeBudget = path.relative(root, resolvedBudget);
  if (
    relativeBudget === ''
    || relativeBudget === '..'
    || relativeBudget.startsWith(`..${path.sep}`)
    || path.isAbsolute(relativeBudget)
  ) {
    throw new Error('--budgets must name a file inside the current Git repository');
  }
  const gitPath = relativeBudget.split(path.sep).join('/');
  command('git', ['ls-files', '--error-unmatch', '--', gitPath], { cwd: root });
  const headBytes = command('git', ['show', `HEAD:${gitPath}`], { cwd: root });
  const workingBytes = readFileSync(resolvedBudget, 'utf8');
  if (`${headBytes}\n` !== workingBytes) {
    throw new Error('the performance budget file must exactly match its committed HEAD blob');
  }
  const trackedStatus = command(
    'git',
    ['status', '--porcelain', '--untracked-files=no'],
    { cwd: root },
  );
  if (trackedStatus !== '') {
    throw new Error('official SFE performance measurement requires a clean tracked source tree');
  }
  return {
    root,
    budgetPath: resolvedBudget,
    repositoryPath: gitPath,
    gitBlob: command('git', ['rev-parse', `HEAD:${gitPath}`], { cwd: root }),
    gitCommit: command('git', ['rev-parse', 'HEAD'], { cwd: root }),
    budgetBytes: workingBytes,
  };
}

function runAndVerify(executable, expectedOutput) {
  const result = spawnSync(executable, [], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    throw new Error(
      `${path.basename(executable)} failed during performance sampling: status=${result.status} signal=${result.signal}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  if (!result.stdout.includes(expectedOutput)) {
    throw new Error(
      `${path.basename(executable)} did not emit required marker ${JSON.stringify(expectedOutput)}`,
    );
  }
}

function measureFreshProcess(executable, expectedOutput, samples) {
  const samplesMs = [];
  for (let sample = 0; sample < samples; sample += 1) {
    const startedAt = performance.now();
    runAndVerify(executable, expectedOutput);
    samplesMs.push(performance.now() - startedAt);
  }
  return { samplesMs, ...summarizeSamples(samplesMs) };
}

function measureRelocatedCopyAndLaunch(executable, expectedOutput, samples) {
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'ibex-sfe-performance-'));
  const samplesMs = [];
  try {
    for (let sample = 0; sample < samples; sample += 1) {
      const destination = path.join(temporaryRoot, `sample-${sample}`);
      const startedAt = performance.now();
      copyFileSync(executable, destination);
      chmodSync(destination, statSync(executable).mode);
      runAndVerify(destination, expectedOutput);
      samplesMs.push(performance.now() - startedAt);
    }
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
  return { samplesMs, ...summarizeSamples(samplesMs) };
}

function measureInspection(ibex, executable, samples) {
  const samplesMs = [];
  for (let sample = 0; sample < samples; sample += 1) {
    const startedAt = performance.now();
    const output = command(ibex, ['inspect-executable', executable]);
    samplesMs.push(performance.now() - startedAt);
    const inspection = JSON.parse(output);
    if (inspection.schema !== 'ibex/executable-inspection/3') {
      throw new Error('inspection performance profile requires admitted inspection schema v2');
    }
    if (inspection.stubCoreConsistency?.state !== 'consistent') {
      throw new Error('inspection performance profile requires a consistent outer stub core');
    }
  }
  return { samplesMs, ...summarizeSamples(samplesMs) };
}

function inspectExecutable(ibex, executable) {
  const inspection = JSON.parse(command(ibex, ['inspect-executable', executable]));
  return inspection;
}

function dynamicDependencies(executable, target) {
  if (target === 'aarch64-apple-darwin') {
    const lines = command('otool', ['-L', executable]).split('\n').slice(1);
    const entries = lines
      .map((line) => line.trim().split(/\s+/u)[0])
      .filter(Boolean)
      .sort();
    return { tool: 'otool -L', entries, count: entries.length };
  }
  const result = spawnSync('ldd', [executable], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  const combined = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  if (combined.includes('not a dynamic executable')) {
    return { tool: 'ldd', entries: [], count: 0 };
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`ldd failed for ${executable}: ${combined}`);
  }
  if (combined.includes('not found')) {
    throw new Error(`ldd reported an unresolved dependency for ${executable}: ${combined}`);
  }
  const entries = result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const arrow = line.indexOf(' => ');
      return arrow >= 0 ? line.slice(0, arrow) : line.split(/\s+/u)[0];
    })
    .sort();
  return { tool: 'ldd', entries, count: entries.length };
}

function fileDigest(filePath) {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return `sha256-${hash.digest('base64url')}`;
}

function artifactRecord(executable, target, inspection) {
  return {
    fileName: path.basename(executable),
    digest: fileDigest(executable),
    bytes: statSync(executable).size,
    dynamicDependencies: dynamicDependencies(executable, target),
    inspection,
  };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (hostTarget() !== options.target) {
    throw new Error(
      `--target ${options.target} does not match this physical host (${hostTarget() ?? 'unsupported'})`,
    );
  }
  const repository = repositoryIdentity(options.budgets);
  const canonicalBudgets = JSON.parse(repository.budgetBytes);
  validateSfePerformanceBudgets(canonicalBudgets);
  if (`${JSON.stringify(canonicalBudgets, null, 2)}\n` !== repository.budgetBytes) {
    throw new Error('the committed performance budget must use canonical two-space JSON');
  }
  const targetBudget = canonicalBudgets.targets[options.target];
  const samples = options.samples ?? targetBudget.minimumSamples;
  if (samples < targetBudget.minimumSamples) {
    throw new Error(
      `--samples ${samples} is below the precommitted minimum ${targetBudget.minimumSamples}`,
    );
  }

  const ibex = requireExecutable(options.ibex, '--ibex');
  const helloHbc = requireExecutable(options.helloHbc, '--hello-hbc');
  const largeGraphHbc = requireExecutable(options.largeGraphHbc, '--large-graph-hbc');
  const helloFactoryTable = requireExecutable(
    options.helloFactoryTable,
    '--hello-factory-table',
  );
  const artifactInspections = {
    helloHbc: projectSfePerformanceArtifactInspection(
      inspectExecutable(ibex, helloHbc),
    ),
    largeGraphHbc: projectSfePerformanceArtifactInspection(
      inspectExecutable(ibex, largeGraphHbc),
    ),
    helloFactoryTable: projectSfePerformanceArtifactInspection(
      inspectExecutable(ibex, helloFactoryTable),
    ),
  };
  validateSfePerformanceArtifactInspections({
    target: options.target,
    fixtureConstraints: targetBudget.fixtureConstraints,
    inspections: artifactInspections,
  });
  const budgetDigest = sha256Digest(repository.budgetBytes);
  const measurement = {
    schema: SFE_PERFORMANCE_MEASUREMENT_SCHEMA,
    target: options.target,
    budgetBinding: {
      repositoryPath: repository.repositoryPath,
      gitBlob: repository.gitBlob,
      sha256: budgetDigest,
    },
    releaseRevision: {
      gitCommit: repository.gitCommit,
      trackedTreeClean: true,
    },
    host: {
      platform: process.platform,
      architecture: process.arch,
      release: os.release(),
      cpu: os.cpus()[0]?.model ?? 'unknown',
    },
    toolchain: {
      ibexVersion: optionalCommand(ibex, ['--version']),
      rustcVersion: optionalCommand('rustc', ['--version']),
      xcodeVersion: process.platform === 'darwin'
        ? optionalCommand('xcodebuild', ['-version'])
        : null,
    },
    measurementConditions: {
      startupProtocol: targetBudget.startupProtocol,
      freshProcessPerSample: true,
      osPageCacheEviction: 'not-attempted',
      relocatedProfileIncludesCopy: true,
      hostContentionObserved: options.hostContentionObserved,
      note: 'Each timing starts a new process. No OS page-cache eviction is attempted; the relocated profile includes copying to a unique path inside the timer.',
    },
    artifacts: {
      helloHbc: artifactRecord(
        helloHbc,
        options.target,
        artifactInspections.helloHbc,
      ),
      largeGraphHbc: artifactRecord(
        largeGraphHbc,
        options.target,
        artifactInspections.largeGraphHbc,
      ),
      helloFactoryTable: artifactRecord(
        helloFactoryTable,
        options.target,
        artifactInspections.helloFactoryTable,
      ),
    },
    profiles: {
      helloHbcFreshProcess: measureFreshProcess(
        helloHbc,
        options.helloOutput,
        samples,
      ),
      helloHbcRelocatedCopyAndLaunch: measureRelocatedCopyAndLaunch(
        helloHbc,
        options.helloOutput,
        samples,
      ),
      largeGraphHbcFreshProcess: measureFreshProcess(
        largeGraphHbc,
        options.largeGraphOutput,
        samples,
      ),
      inspectionFreshProcess: measureInspection(ibex, helloHbc, samples),
      helloFactoryTableFreshProcess: measureFreshProcess(
        helloFactoryTable,
        options.factoryTableOutput,
        samples,
      ),
    },
  };
  let gate;
  try {
    gate = evaluateSfePerformance({
      budgets: canonicalBudgets,
      measurement,
      budgetDigest,
    });
  } catch (error) {
    gate = {
      schema: 'ibex/sfe-performance-gate-error/1',
      target: options.target,
      passed: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
  const report = {
    schema: SFE_PERFORMANCE_REPORT_SCHEMA,
    measurement,
    gate,
  };
  const output = path.resolve(options.write);
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!gate.passed) {
    const reason = gate.failures?.join(', ') || gate.error || 'unknown failure';
    throw new Error(`SFE performance gate failed: ${reason}`);
  }
}

main();
