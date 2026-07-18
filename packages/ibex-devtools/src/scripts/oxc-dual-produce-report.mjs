#!/usr/bin/env node
/**
 * Compare pre- and post-rotation Oxc module producer artifacts without ever
 * loading both into a production runtime.
 *
 * @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation —
 * the one-shot migration evidence uses a precommitted semantic projection,
 * source-map invariants, and independent real-Hermes executions.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SourceMap } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');

export const REPORT_SCHEMA = 'ibex/oxc-old-new-dual-produce-report/1';
export const OLD_REVISION = '9329a9123a10e379d6253afb6a90a33de5de928e';
export const OLD_FINGERPRINT =
  'ibex-module-runner-spike/2+oxc-0.121.0+module-goal+hermes-abi-draft-1';
export const NEW_FINGERPRINT =
  'ibex-module-runner-spike/3+config/sha256-TsgKoBzPAzyrKCqTwoDAcYVMCdgauOPwoxi0SEoqlv8';

const SEMANTIC_FIELDS = Object.freeze([
  'bundle.schema',
  'bundle.manifestSchema',
  'fixture.id',
  'fixture.entry',
  'fixture.expected',
  'fixture.tags',
  'module.fixtureId',
  'module.sourceName',
  'module.dialect',
  'module.sourceIntegrity',
  'module.staticEdges',
  'module.dynamicEdges',
  'module.exportDescriptors',
  'module.hasTopLevelAwait',
  'module.hermesCompatPasses',
]);

const ALLOWED_DIFFERENCE_TYPES = Object.freeze([
  'transform-fingerprint-rotation',
  'factory-spelling-or-formatting',
  'source-map-layout-or-precision',
]);

const DISPOSITIONED_OLD_MAP_DEFECTS = Object.freeze([
  Object.freeze({
    fixtureId: 'hermes-for-of-capture',
    sourceName: 'entry.js',
    generatedLine: 16,
    generatedColumn: 0,
    originalLine: 8,
    originalColumn: 0,
    embeddedSourceLineCount: 7,
    defect: 'original-line-out-of-range',
  }),
]);

const PRODUCER_INPUT_PATHS = Object.freeze([
  'Cargo.lock',
  'Cargo.toml',
  'build.rs',
  'examples/module_runner_spike.rs',
  'rust-toolchain.toml',
  'src/module_loader/artifact.rs',
  'src/module_loader/commonjs_lexer.rs',
  'src/module_loader/producer_spike.rs',
  'src/module_loader/transform_config_generated.rs',
  'config/module-transform.json',
]);

const BASE64_VLQ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const VLQ_INDEX = new Map([...BASE64_VLQ].map((character, index) => [character, index]));

function parseArgs(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (!name.startsWith('--')) throw new Error(`unexpected argument: ${name}`);
    const value = argv[++index];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    if (options.has(name)) throw new Error(`duplicate argument: ${name}`);
    options.set(name, value);
  }
  const required = [
    '--old-artifacts',
    '--new-artifacts',
    '--old-producer',
    '--new-producer',
    '--old-root',
    '--new-root',
    '--old-manifest',
    '--new-manifest',
    '--hermes',
    '--contract',
    '--output-dir',
  ];
  for (const name of required) {
    if (!options.has(name)) throw new Error(`${name} is required`);
  }
  return Object.fromEntries([...options].map(([name, value]) => [name.slice(2), path.resolve(value)]));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function renderedJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function digestBytes(bytes) {
  return `sha256-${crypto.createHash('sha256').update(bytes).digest('base64url')}`;
}

function digestFile(filename) {
  return digestBytes(fs.readFileSync(filename));
}

function hexDigest(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function readJson(filename, label) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    throw new Error(`${label} is not readable JSON: ${error.message}`);
  }
  return parsed;
}

function readToolchain(root) {
  const source = fs.readFileSync(path.join(root, 'rust-toolchain.toml'), 'utf8');
  const channel = source.match(/^channel\s*=\s*"([^"]+)"/mu)?.[1];
  if (!channel) throw new Error(`${root}: rust-toolchain.toml has no channel`);
  return channel;
}

function lockPackages(root) {
  const lockfile = fs.readFileSync(path.join(root, 'Cargo.lock'), 'utf8');
  const packages = [];
  for (const block of lockfile.split('[[package]]').slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/mu)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/mu)?.[1];
    const source = block.match(/^source\s*=\s*"([^"]+)"/mu)?.[1];
    const checksum = block.match(/^checksum\s*=\s*"([^"]+)"/mu)?.[1];
    if (name?.startsWith('oxc_')) packages.push({ name, version, source, checksum });
  }
  packages.sort((left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version));
  if (packages.length === 0) throw new Error(`${root}: lockfile has no Oxc packages`);
  return packages;
}

function treeDigest(root, relativePaths) {
  const rows = [];
  for (const relativePath of [...relativePaths].sort()) {
    const filename = path.join(root, relativePath);
    if (!fs.existsSync(filename)) continue;
    const metadata = fs.lstatSync(filename);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`${filename}: producer input must be an owned regular file`);
    }
    rows.push({ path: relativePath, digest: digestFile(filename), bytes: metadata.size });
  }
  return { paths: rows, digest: digestBytes(canonicalJson(rows)) };
}

function listRegularFiles(root) {
  const output = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const filename = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`${filename}: fixture tree contains a symlink`);
      if (entry.isDirectory()) visit(filename);
      else if (entry.isFile()) output.push(filename);
      else throw new Error(`${filename}: fixture tree contains a non-regular entry`);
    }
  };
  visit(root);
  return output;
}

function manifestTree(manifestPath) {
  const root = path.dirname(manifestPath);
  const files = [manifestPath, ...listRegularFiles(path.join(root, 'sources'))]
    .map((filename) => ({
      path: path.relative(root, filename).split(path.sep).join('/'),
      digest: digestFile(filename),
      bytes: fs.statSync(filename).size,
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return { files, digest: digestBytes(canonicalJson(files)) };
}

function decodeVlq(segment, cursor) {
  let value = 0;
  let shift = 0;
  while (cursor.index < segment.length) {
    const character = segment[cursor.index++];
    const digit = VLQ_INDEX.get(character);
    if (digit === undefined) throw new Error(`invalid base64 VLQ character ${JSON.stringify(character)}`);
    value += (digit & 31) << shift;
    if ((digit & 32) === 0) return (value & 1) === 1 ? -(value >> 1) : value >> 1;
    shift += 5;
    if (shift > 30) throw new Error('base64 VLQ value exceeds the supported range');
  }
  throw new Error('truncated base64 VLQ value');
}

export function decodeMappings(sourceMap) {
  const segments = [];
  let sourceIndex = 0;
  let originalLine = 0;
  let originalColumn = 0;
  let nameIndex = 0;
  const lines = String(sourceMap.mappings ?? '').split(';');
  for (let generatedLine = 0; generatedLine < lines.length; generatedLine += 1) {
    let generatedColumn = 0;
    for (const encoded of lines[generatedLine].split(',')) {
      if (!encoded) continue;
      const cursor = { index: 0 };
      generatedColumn += decodeVlq(encoded, cursor);
      const row = { generatedLine: generatedLine + 1, generatedColumn };
      if (cursor.index < encoded.length) {
        sourceIndex += decodeVlq(encoded, cursor);
        originalLine += decodeVlq(encoded, cursor);
        originalColumn += decodeVlq(encoded, cursor);
        Object.assign(row, {
          sourceIndex,
          source: sourceMap.sources?.[sourceIndex],
          originalLine: originalLine + 1,
          originalColumn,
        });
        if (cursor.index < encoded.length) {
          nameIndex += decodeVlq(encoded, cursor);
          row.nameIndex = nameIndex;
          row.name = sourceMap.names?.[nameIndex];
        }
      }
      if (cursor.index !== encoded.length) throw new Error(`unconsumed VLQ data in ${encoded}`);
      segments.push(row);
    }
  }
  return segments;
}

export function semanticProjection(bundle) {
  return {
    schema: bundle.schema,
    manifestSchema: bundle.manifestSchema,
    fixtures: bundle.fixtures?.map((fixture) => ({
      id: fixture.id,
      entry: fixture.entry,
      expected: fixture.expected,
      tags: fixture.tags,
      modules: fixture.modules?.map((module) => ({
        fixtureId: module.fixtureId,
        sourceName: module.sourceName,
        dialect: module.dialect,
        sourceIntegrity: module.sourceIntegrity,
        staticEdges: module.staticEdges,
        dynamicEdges: module.dynamicEdges,
        exportDescriptors: module.exportDescriptors,
        hasTopLevelAwait: module.hasTopLevelAwait,
        hermesCompatPasses: module.hermesCompatPasses,
      })),
    })),
  };
}

function validateMap(fixture, module) {
  const sourceMap = module.sourceMap;
  assert.equal(sourceMap.version, 3, `${fixture.id}/${module.sourceName}: source-map version`);
  assert.equal(sourceMap.file, `${module.sourceName}.factory.js`, `${fixture.id}/${module.sourceName}: map filename`);
  assert.deepEqual(sourceMap.sources, [module.sourceName], `${fixture.id}/${module.sourceName}: map source identity`);
  assert.equal(sourceMap.sourcesContent?.length, 1, `${fixture.id}/${module.sourceName}: embedded source count`);
  assert.equal(sourceMap.x_ibex_composed, true, `${fixture.id}/${module.sourceName}: composed marker`);
  assert.equal(
    module.sourceIntegrity,
    `sha256-${crypto.createHash('sha256').update(sourceMap.sourcesContent[0]).digest('base64')}`,
    `${fixture.id}/${module.sourceName}: source integrity`,
  );
  assert.equal(
    sourceMap.x_ibex_factory_lines,
    module.factorySource.trimEnd().split('\n').length,
    `${fixture.id}/${module.sourceName}: factory line count`,
  );

  const decodedSegments = decodeMappings(sourceMap);
  const invariantDefects = [];
  if (sourceMap.mappings.length > 0) {
    assert.ok(decodedSegments.length > 0, `${fixture.id}/${module.sourceName}: non-empty source map has no segments`);
  } else {
    assert.equal(decodedSegments.length, 0, `${fixture.id}/${module.sourceName}: empty map decoded segments`);
  }
  let previous = null;
  const sourceLines = sourceMap.sourcesContent[0].split('\n');
  for (const segment of decodedSegments) {
    if (previous) {
      assert.ok(
        segment.generatedLine > previous.generatedLine ||
          (segment.generatedLine === previous.generatedLine && segment.generatedColumn >= previous.generatedColumn),
        `${fixture.id}/${module.sourceName}: generated mappings are not monotonic`,
      );
    }
    previous = segment;
    if (segment.originalLine !== undefined) {
      assert.equal(segment.sourceIndex, 0, `${fixture.id}/${module.sourceName}: mapped source index`);
      if (segment.originalLine < 1 || segment.originalLine > sourceLines.length) {
        invariantDefects.push({
          fixtureId: fixture.id,
          sourceName: module.sourceName,
          generatedLine: segment.generatedLine,
          generatedColumn: segment.generatedColumn,
          originalLine: segment.originalLine,
          originalColumn: segment.originalColumn,
          embeddedSourceLineCount: sourceLines.length,
          defect: 'original-line-out-of-range',
        });
      }
      assert.ok(segment.originalColumn >= 0, `${fixture.id}/${module.sourceName}: original column is negative`);
    }
  }

  let sourceLineOracle = null;
  if (fixture.expected?.sourceLine !== undefined && module.sourceName === fixture.entry) {
    const generatedLine = module.factorySource.split('\n').findIndex((line) => line.includes('throw new Error'));
    assert.ok(generatedLine >= 0, `${fixture.id}: generated throw site is absent`);
    const entry = new SourceMap(sourceMap).findEntry(generatedLine, 0);
    const observedLine = entry.originalLine + 1;
    assert.equal(observedLine, fixture.expected.sourceLine, `${fixture.id}: source-line oracle`);
    sourceLineOracle = {
      generatedLine: generatedLine + 1,
      expectedOriginalLine: fixture.expected.sourceLine,
      observedOriginalLine: observedLine,
    };
  }

  return {
    metadata: {
      version: sourceMap.version,
      file: sourceMap.file,
      names: sourceMap.names,
      sources: sourceMap.sources,
      sourcesContent: sourceMap.sourcesContent,
      composed: sourceMap.x_ibex_composed,
      factoryLines: sourceMap.x_ibex_factory_lines,
    },
    rawMappingsDigest: digestBytes(sourceMap.mappings),
    decodedSegments,
    decodedSegmentsDigest: digestBytes(canonicalJson(decodedSegments)),
    sourceLineOracle,
    invariantDefects,
  };
}

function validateBundle(bundle, expectedFingerprint, label) {
  assert.equal(bundle.schema, 'ibex/module-runner-spike-artifacts/1', `${label}: bundle schema`);
  assert.equal(bundle.manifestSchema, 'ibex/module-runner-spike-manifest/1', `${label}: manifest schema`);
  assert.equal(bundle.transformFingerprint, expectedFingerprint, `${label}: bundle transform fingerprint`);
  assert.ok(Array.isArray(bundle.fixtures) && bundle.fixtures.length > 0, `${label}: empty fixture bundle`);
  const moduleRows = [];
  const invariantDefects = [];
  const seenFixtures = new Set();
  for (const fixture of bundle.fixtures) {
    assert.ok(!seenFixtures.has(fixture.id), `${label}: duplicate fixture ${fixture.id}`);
    seenFixtures.add(fixture.id);
    assert.ok(fixture.modules.some((module) => module.sourceName === fixture.entry), `${label}/${fixture.id}: missing entry`);
    const seenModules = new Set();
    for (const module of fixture.modules) {
      assert.ok(!seenModules.has(module.sourceName), `${label}/${fixture.id}: duplicate module ${module.sourceName}`);
      seenModules.add(module.sourceName);
      assert.equal(module.fixtureId, fixture.id, `${label}/${fixture.id}: module fixture identity`);
      assert.equal(module.transformFingerprint, expectedFingerprint, `${label}/${fixture.id}/${module.sourceName}: fingerprint`);
      const sourceMap = validateMap(fixture, module);
      invariantDefects.push(...sourceMap.invariantDefects);
      moduleRows.push({
        fixtureId: fixture.id,
        sourceName: module.sourceName,
        factoryDigest: digestBytes(module.factorySource),
        sourceMap,
      });
    }
  }
  return { moduleRows, invariantDefects };
}

function runHermes(bundlePath, hermesPath) {
  const runner = path.join(repoRoot, 'packages/ibex-devtools/src/scripts/run-module-runner-spike.mjs');
  const result = spawnSync(process.execPath, [runner, '--artifacts', bundlePath, '--hermes', hermesPath], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  const outcomes = result.stdout
    .split(/\r?\n/u)
    .map((line) => line.match(/^\s+ok\s+(.+) \[real Hermes\]$/u)?.[1])
    .filter(Boolean);
  const summary = result.stdout.split(/\r?\n/u).find((line) => line.startsWith('module-runner spike:')) ?? null;
  if (result.status !== 0) {
    throw new Error(`real-Hermes bundle run failed (${result.status}):\n${result.stdout}\n${result.stderr}`);
  }
  return {
    exitCode: result.status,
    passedFixtureIds: outcomes,
    summary,
    stdoutDigest: digestBytes(result.stdout),
    stderrDigest: digestBytes(result.stderr),
  };
}

function hermesIdentity(hermesPath) {
  const result = spawnSync(hermesPath, ['-version'], { encoding: 'utf8', timeout: 30_000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Hermes version probe failed: ${result.stderr}`);
  return {
    binaryDigest: digestFile(hermesPath),
    versionOutput: `${result.stdout}${result.stderr}`.trim(),
  };
}

function gitRevision(root) {
  const result = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 || !/^[0-9a-f]{40}\n?$/u.test(result.stdout)) {
    throw new Error(`${root}: cannot resolve source revision: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function contractSection(source) {
  const startMarker = '## Precommitted comparison contract';
  const endMarker = '<!-- END PRECOMMITTED COMPARISON CONTRACT -->';
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  if (start < 0 || end < start) throw new Error('comparison contract markers are missing or inverted');
  return `${source.slice(start, end).trimEnd()}\n`;
}

function dispositionSection(source) {
  const startMarker = '## Execution finding and disposition';
  const endMarker = '<!-- END EXECUTION FINDING AND DISPOSITION -->';
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  if (start < 0 || end < start) throw new Error('comparison disposition markers are missing or inverted');
  return `${source.slice(start, end).trimEnd()}\n`;
}

function compareModules(oldRows, newRows) {
  assert.equal(oldRows.length, newRows.length, 'module count changed');
  const differences = [];
  for (let index = 0; index < oldRows.length; index += 1) {
    const oldRow = oldRows[index];
    const newRow = newRows[index];
    assert.equal(`${oldRow.fixtureId}/${oldRow.sourceName}`, `${newRow.fixtureId}/${newRow.sourceName}`, 'module order changed');
    const factoryChanged = oldRow.factoryDigest !== newRow.factoryDigest;
    const metadataChanged = canonicalJson(oldRow.sourceMap.metadata) !== canonicalJson(newRow.sourceMap.metadata);
    const rawMappingsChanged = oldRow.sourceMap.rawMappingsDigest !== newRow.sourceMap.rawMappingsDigest;
    const decodedSegmentsChanged =
      oldRow.sourceMap.decodedSegmentsDigest !== newRow.sourceMap.decodedSegmentsDigest;
    if (factoryChanged || metadataChanged || rawMappingsChanged || decodedSegmentsChanged) {
      differences.push({
        fixtureId: oldRow.fixtureId,
        sourceName: oldRow.sourceName,
        factoryChanged,
        oldFactoryDigest: oldRow.factoryDigest,
        newFactoryDigest: newRow.factoryDigest,
        sourceMapMetadataChanged: metadataChanged,
        rawMappingsChanged,
        oldRawMappingsDigest: oldRow.sourceMap.rawMappingsDigest,
        newRawMappingsDigest: newRow.sourceMap.rawMappingsDigest,
        decodedSegmentsChanged,
        oldDecodedSegmentsDigest: oldRow.sourceMap.decodedSegmentsDigest,
        newDecodedSegmentsDigest: newRow.sourceMap.decodedSegmentsDigest,
      });
    }
  }
  return differences;
}

function producerIdentity(root, binaryPath, revision) {
  const sourceTree = treeDigest(root, PRODUCER_INPUT_PATHS);
  return {
    revision,
    rustToolchain: readToolchain(root),
    oxcLockPackages: lockPackages(root),
    producerSourceTreeDigest: sourceTree.digest,
    producerSourcePaths: sourceTree.paths,
    producerBinaryDigest: digestFile(binaryPath),
  };
}

export function buildReport(options) {
  const oldBundle = readJson(options['old-artifacts'], 'old artifact bundle');
  const newBundle = readJson(options['new-artifacts'], 'new artifact bundle');
  const oldManifestTree = manifestTree(options['old-manifest']);
  const newManifestTree = manifestTree(options['new-manifest']);
  assert.equal(oldManifestTree.digest, newManifestTree.digest, 'old and new fixture trees differ');

  const oldValidation = validateBundle(oldBundle, OLD_FINGERPRINT, 'old producer');
  const newValidation = validateBundle(newBundle, NEW_FINGERPRINT, 'new producer');
  assert.equal(
    canonicalJson(oldValidation.invariantDefects),
    canonicalJson(DISPOSITIONED_OLD_MAP_DEFECTS),
    'old producer source-map defects differ from the dispositioned baseline',
  );
  assert.deepEqual(newValidation.invariantDefects, [], 'new producer has source-map invariant defects');
  const oldRows = oldValidation.moduleRows;
  const newRows = newValidation.moduleRows;
  const oldProjection = semanticProjection(oldBundle);
  const newProjection = semanticProjection(newBundle);
  const oldProjectionJson = canonicalJson(oldProjection);
  const newProjectionJson = canonicalJson(newProjection);
  assert.equal(oldProjectionJson, newProjectionJson, 'semantic projection changed across the pin rotation');

  const oldHermes = runHermes(options['old-artifacts'], options.hermes);
  const newHermes = runHermes(options['new-artifacts'], options.hermes);
  assert.deepEqual(oldHermes.passedFixtureIds, newHermes.passedFixtureIds, 'real-Hermes fixture outcomes differ');
  assert.equal(oldHermes.passedFixtureIds.length, oldBundle.fixtures.length, 'old bundle did not pass every fixture');
  assert.equal(newHermes.passedFixtureIds.length, newBundle.fixtures.length, 'new bundle did not pass every fixture');

  const differences = compareModules(oldRows, newRows);
  const sourceMapDifferences = differences.filter(
    (row) => row.sourceMapMetadataChanged || row.rawMappingsChanged || row.decodedSegmentsChanged,
  );
  const factoryDifferences = differences.filter((row) => row.factoryChanged);
  const issueSource = fs.readFileSync(options.contract, 'utf8');
  const contractBytes = contractSection(issueSource);
  const dispositionBytes = dispositionSection(issueSource);
  const report = {
    schema: REPORT_SCHEMA,
    status: 'pass-with-dispositioned-old-baseline-defect',
    contract: {
      issuePath: path.relative(options['new-root'], options.contract).split(path.sep).join('/'),
      issueDigest: digestBytes(contractBytes),
      semanticFields: SEMANTIC_FIELDS,
      allowedDifferenceTypes: ALLOWED_DIFFERENCE_TYPES,
      oldRevision: OLD_REVISION,
      oldFingerprint: OLD_FINGERPRINT,
      newFingerprint: NEW_FINGERPRINT,
      dispositionDigest: digestBytes(dispositionBytes),
      precommittedContractSatisfied: false,
      precommittedContractFailure: 'old-side-source-map-invariant',
    },
    environment: {
      platform: process.platform,
      architecture: process.arch,
      nodeVersion: process.version,
      hermes: hermesIdentity(options.hermes),
    },
    fixtureInputs: {
      manifestAndSourceTreeDigest: oldManifestTree.digest,
      files: oldManifestTree.files,
    },
    producers: {
      old: producerIdentity(options['old-root'], options['old-producer'], OLD_REVISION),
      new: producerIdentity(
        options['new-root'],
        options['new-producer'],
        gitRevision(options['new-root']),
      ),
    },
    artifacts: {
      old: {
        bundleDigest: digestFile(options['old-artifacts']),
        transformFingerprint: oldBundle.transformFingerprint,
        sourceMaps: oldRows,
        realHermes: oldHermes,
      },
      new: {
        bundleDigest: digestFile(options['new-artifacts']),
        transformFingerprint: newBundle.transformFingerprint,
        sourceMaps: newRows,
        realHermes: newHermes,
      },
    },
    comparison: {
      semanticProjectionDigest: digestBytes(oldProjectionJson),
      semanticProjectionEqual: true,
      oldSourceMapInvariantDefects: oldValidation.invariantDefects,
      newSourceMapInvariantDefects: newValidation.invariantDefects,
      oldBaselineDefectsExactlyDispositioned: true,
      transformFingerprintRotated: oldBundle.transformFingerprint !== newBundle.transformFingerprint,
      factoryDifferenceCount: factoryDifferences.length,
      sourceMapDifferenceCount: sourceMapDifferences.length,
      differences,
      realHermesOutcomesEqual: true,
      allOldFixturesPassed: true,
      allNewFixturesPassed: true,
    },
  };
  return report;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const report = buildReport(options);
  const rendered = renderedJson(report);
  const filename = path.join(options['output-dir'], `0028-oxc-dual-produce-${hexDigest(rendered)}.json`);
  fs.mkdirSync(options['output-dir'], { recursive: true });
  fs.writeFileSync(filename, rendered, { flag: 'wx', mode: 0o644 });
  console.log(filename);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
