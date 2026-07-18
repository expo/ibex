#!/usr/bin/env bun

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(scriptDir, '../../../..');
export const manifestPath = path.join(
  repoRoot,
  'config/oxc-retirement-manifest.json',
);
const implementationManifestPath = path.join(
  repoRoot,
  'capsec/generated/implementation-manifest.json',
);
const cargoLockPath = path.join(repoRoot, 'Cargo.lock');

const namedSourceNeedles = Object.freeze([
  Object.freeze({
    category: 'symbol',
    identity: 'TransformEngine',
    file: 'src/module_loader/transpile.rs',
    needle: 'enum TransformEngine',
    disposition: 'retire',
    expectedState: 'present',
  }),
  Object.freeze({
    category: 'symbol',
    identity: 'transpile_to_cjs',
    file: 'src/module_loader/transpile.rs',
    needle: 'pub fn transpile_to_cjs',
    disposition: 'retire',
    expectedState: 'present',
  }),
  Object.freeze({
    category: 'symbol',
    identity: 'transpile_esm_to_script',
    file: 'src/bin/ibex/runtime.rs',
    needle: 'fn transpile_esm_to_script',
    disposition: 'retire',
    expectedState: 'present',
  }),
  ...[
    ['in-process-swc-v2', 'src/module_loader/transpile.rs'],
    ['loader-transpile-v14-content-addressed', 'src/module_loader/mod.rs'],
    ['transpile-tool-directory-v1', 'src/module_loader/mod.rs'],
    ['subprocess-transpile-toolchain-v2', 'src/module_loader/mod.rs'],
    ['subprocess-transpile-script', 'src/module_loader/mod.rs'],
    ['in-process-transpile-engine', 'src/module_loader/mod.rs'],
  ].map(([identity, file]) =>
    Object.freeze({
      category: 'cache-namespace',
      identity,
      file,
      needle: identity,
      disposition: 'retire',
      expectedState: 'present',
    }),
  ),
  Object.freeze({
    category: 'cache-namespace',
    identity: 'in-process-oxc-0.121.0-v1',
    file: 'src/module_loader/transpile.rs',
    needle: 'in-process-oxc-0.121.0-v1',
    disposition: 'migrate',
    expectedState: 'absent',
  }),
  ...[
    ['IBEX_RUNTIME_TRANSFORM', 'src/module_loader/transpile.rs'],
    ['EXACT_RUNTIME_TRANSFORM', 'src/module_loader/transpile.rs'],
    ['EXACT_TRANSPILE_SCRIPT', 'src/module_loader/mod.rs'],
    ['IBEX_LEGACY_MODULE_LOADER', 'src/bin/ibex/runtime.rs'],
    ['IBEX_COMPAT_LOADER_TEST', 'src/bin/ibex/runtime.rs'],
    ['IBEX_TRANSPILE_CACHE_MAX_BYTES', 'src/module_loader/mod.rs'],
    ['IBEX_TEST_TRANSPILE_INPUT_BARRIER', 'src/module_loader/mod.rs'],
  ].map(([identity, file]) =>
    Object.freeze({
      category: 'environment-contract',
      identity,
      file,
      needle: identity,
      disposition: 'retire',
      expectedState: 'present',
    }),
  ),
]);

// Every runtime reader and environment producer for the split selectors has a
// named lifecycle disposition. Keep generated/tooling classifications out of
// this list: they account for the contract but do not consume or produce it.
const compatSelectorInventory = Object.freeze([
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'producer',
    identity: 'compat-runner',
    file: 'src/bin/ibex/compat/runner.rs',
    needle: 'cmd.env("EXACT_COMPAT_TEST", "1");',
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'producer',
    identity: 'module-semantics-baseline',
    file: 'packages/ibex-devtools/src/scripts/run-module-semantics-baseline.mjs',
    needle: "EXACT_COMPAT_TEST: '1'",
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'producer',
    identity: 'hermes-compat-loader',
    file: 'packages/ibex-devtools/src/scripts/run-hermes-compat-loader.mjs',
    needle: "EXACT_COMPAT_TEST: '1'",
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'producer',
    identity: 'bootstrap-loader-tests',
    file: 'tests/bootstrap_loader.rs',
    needle: '.env("EXACT_COMPAT_TEST", "1")',
    expectedOccurrences: 2,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'producer',
    identity: 'llp0013-compartment-tests',
    file: 'tests/llp0013_compartments.rs',
    needle: '.env("EXACT_COMPAT_TEST", "1")',
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'reader',
    identity: 'runtime-polyfill-reapply',
    file: 'src/bin/ibex/runtime.rs',
    needle: 'std::env::var_os("EXACT_COMPAT_TEST").is_some()',
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'reader',
    identity: 'bootstrap-compat-polyfills',
    file: 'src/engine/bootstrap/compat-polyfills.js',
    needle: "globalThis.process.env.EXACT_COMPAT_TEST === '1'",
    expectedOccurrences: 2,
    disposition: 'retain',
  }),
  Object.freeze({
    selector: 'EXACT_COMPAT_TEST',
    semantic: 'fixture-fidelity',
    role: 'reader',
    identity: 'process-fixture-identity',
    file: 'packages/ibex-runtime-js/src/node/process.ts',
    needle: 'return !!(env && env.EXACT_COMPAT_TEST);',
    expectedOccurrences: 1,
    disposition: 'retain',
  }),
  ...[
    'packages/ibex-runtime-js/src/fetch/Headers.ts',
    'packages/ibex-runtime-js/src/fetch/Request.ts',
    'packages/ibex-runtime-js/src/fetch/Response.ts',
    'packages/ibex-runtime-js/src/fetch/body.ts',
    'packages/ibex-runtime-js/src/fetch/fetch.ts',
    'packages/ibex-runtime-js/src/streams/ReadableStream.ts',
  ].map((file) =>
    Object.freeze({
      selector: 'EXACT_COMPAT_TEST',
      semantic: 'fixture-fidelity',
      role: 'reader',
      identity: file.replace(/^packages\/ibex-runtime-js\/src\//u, ''),
      file,
      needle: "readRuntimeEnv('EXACT_COMPAT_TEST') === '1'",
      expectedOccurrences: 1,
      disposition: 'retain',
    }),
  ),
  Object.freeze({
    selector: 'IBEX_COMPAT_LOADER_TEST',
    semantic: 'loader-selection',
    role: 'reader',
    identity: 'runtime-preparation-bypass',
    file: 'src/bin/ibex/runtime.rs',
    needle: 'std::env::var_os("IBEX_COMPAT_LOADER_TEST").is_some()',
    expectedOccurrences: 1,
    disposition: 'retire',
  }),
  Object.freeze({
    selector: 'IBEX_COMPAT_LOADER_TEST',
    semantic: 'loader-selection',
    role: 'producer',
    identity: 'compat-runner',
    file: 'src/bin/ibex/compat/runner.rs',
    needle: 'cmd.env("IBEX_COMPAT_LOADER_TEST", "1");',
    expectedOccurrences: 1,
    disposition: 'retire',
  }),
  Object.freeze({
    selector: 'IBEX_COMPAT_LOADER_TEST',
    semantic: 'loader-selection',
    role: 'producer',
    identity: 'module-loader-benchmark',
    file: 'packages/ibex-devtools/src/scripts/benchmark-module-loader-baseline.mjs',
    needle: "env.IBEX_COMPAT_LOADER_TEST = '1'",
    expectedOccurrences: 1,
    disposition: 'retire',
  }),
  ...[
    'packages/ibex-devtools/src/scripts/run-module-semantics-baseline.mjs',
    'packages/ibex-devtools/src/scripts/run-hermes-compat-loader.mjs',
  ].map((file) =>
    Object.freeze({
      selector: 'IBEX_COMPAT_LOADER_TEST',
      semantic: 'loader-selection',
      role: 'producer',
      identity: path.basename(file),
      file,
      needle: "IBEX_COMPAT_LOADER_TEST: '1'",
      expectedOccurrences: 1,
      disposition: 'retire',
    }),
  ),
  Object.freeze({
    selector: 'IBEX_COMPAT_LOADER_TEST',
    semantic: 'loader-selection',
    role: 'producer',
    identity: 'bootstrap-loader-tests',
    file: 'tests/bootstrap_loader.rs',
    needle: '.env("IBEX_COMPAT_LOADER_TEST", "1")',
    expectedOccurrences: 2,
    disposition: 'retire',
  }),
  Object.freeze({
    selector: 'IBEX_COMPAT_LOADER_TEST',
    semantic: 'loader-selection',
    role: 'producer',
    identity: 'llp0013-compartment-tests',
    file: 'tests/llp0013_compartments.rs',
    needle: '.env("IBEX_COMPAT_LOADER_TEST", "1")',
    expectedOccurrences: 1,
    disposition: 'retire',
  }),
]);

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function exactSet(actual, expected, label) {
  assert.deepEqual(sortedUnique(actual), sortedUnique(expected), label);
}

function countOccurrences(source, needle) {
  let count = 0;
  let cursor = 0;
  while (true) {
    const index = source.indexOf(needle, cursor);
    if (index === -1) return count;
    count += 1;
    cursor = index + needle.length;
  }
}

export function assertCompatSelectorInventory(
  entries,
  readSource = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8'),
) {
  const seen = new Set();
  const rolesBySelector = new Map();
  for (const entry of entries) {
    assert.ok(entry.role === 'producer' || entry.role === 'reader');
    const expectedSemantic =
      entry.selector === 'EXACT_COMPAT_TEST'
        ? 'fixture-fidelity'
        : entry.selector === 'IBEX_COMPAT_LOADER_TEST'
          ? 'loader-selection'
          : null;
    assert.equal(entry.semantic, expectedSemantic, `${entry.identity} selector semantic`);
    assert.equal(
      entry.disposition,
      entry.selector === 'EXACT_COMPAT_TEST' ? 'retain' : 'retire',
      `${entry.identity} selector disposition`,
    );
    const inventoryIdentity = `${entry.selector}:${entry.role}:${entry.identity}`;
    assert.ok(!seen.has(inventoryIdentity), `duplicate selector entry ${inventoryIdentity}`);
    seen.add(inventoryIdentity);
    const roles = rolesBySelector.get(entry.selector) ?? new Set();
    roles.add(entry.role);
    rolesBySelector.set(entry.selector, roles);
    assert.equal(
      countOccurrences(readSource(entry.file), entry.needle),
      entry.expectedOccurrences,
      `${inventoryIdentity} occurrence count drifted in ${entry.file}`,
    );
  }
  assert.deepEqual(
    [...rolesBySelector.entries()].map(([selector, roles]) => [selector, [...roles].sort()]),
    [
      ['EXACT_COMPAT_TEST', ['producer', 'reader']],
      ['IBEX_COMPAT_LOADER_TEST', ['producer', 'reader']],
    ],
    'both split selectors require explicit producers and readers',
  );
}

export function swcSurfaceInventory(implementationManifest, expectedBaseCount = 5) {
  const rows = implementationManifest.surfaces.filter((surface) =>
    /^surface\.loader\..*\.swc\.[a-z0-9]+$/u.test(surface.edgeId),
  );
  assert.equal(
    rows.length,
    expectedBaseCount,
    `expected ${expectedBaseCount} base SWC loader surfaces`,
  );
  const surfaceIds = sortedUnique(
    rows.flatMap((surface) => [surface.edgeId, surface.branchId]),
  );
  assert.equal(
    surfaceIds.length,
    expectedBaseCount * 2,
    `expected ${expectedBaseCount} base and ${expectedBaseCount} .main SWC IDs`,
  );
  for (const row of rows) {
    assert.equal(row.branchId, `${row.edgeId}.main`);
  }
  return {
    surfaceIds,
    symbolRefs: sortedUnique(rows.flatMap((surface) => surface.sourceRefs)),
  };
}

function cargoMetadata(profileArgs) {
  const stdout = execFileSync(
    'cargo',
    ['metadata', '--locked', '--format-version', '1', ...profileArgs],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'inherit'],
    },
  );
  return JSON.parse(stdout);
}

function swcNamesFromMetadata(metadata) {
  return sortedUnique(
    metadata.packages
      .map((pkg) => pkg.name)
      .filter((name) => name.startsWith('swc_')),
  );
}

function swcNamesFromLockfile(source) {
  return sortedUnique(
    [...source.matchAll(/^name = "(swc_[^"]+)"$/gmu)].map((match) => match[1]),
  );
}

// @ref LLP 0028#4-reachability-inventory-and-retirement-matrix — the gate is
// prefix-based even though the frozen inventory carries exact current names.
export function assertSwcDependencyPrefixGate({
  mode,
  expectedNames,
  profileNames,
  lockfileNames,
}) {
  assert.ok(mode === 'inventory' || mode === 'forbid-prefix');
  for (const [profile, names] of Object.entries(profileNames)) {
    if (mode === 'inventory') {
      exactSet(names, expectedNames, `${profile} SWC dependency inventory drifted`);
    } else {
      assert.deepEqual(names, [], `${profile} resolves forbidden swc_* packages`);
    }
  }
  if (mode === 'inventory') {
    assert.ok(expectedNames.length > 0, 'inventory mode requires existing SWC crates');
    exactSet(lockfileNames, expectedNames, 'Cargo.lock SWC dependency inventory drifted');
  } else {
    assert.deepEqual(lockfileNames, [], 'Cargo.lock contains forbidden swc_* packages');
  }
}

function buildFrozenManifest() {
  const implementationManifest = JSON.parse(
    fs.readFileSync(implementationManifestPath, 'utf8'),
  );
  const capsec = swcSurfaceInventory(implementationManifest);
  const cargoProfiles = [
    { name: 'default', cargoMetadataArgs: [] },
    { name: 'no-default-features', cargoMetadataArgs: ['--no-default-features'] },
  ];
  const profileNames = Object.fromEntries(
    cargoProfiles.map((profile) => [
      profile.name,
      swcNamesFromMetadata(cargoMetadata(profile.cargoMetadataArgs)),
    ]),
  );
  exactSet(
    profileNames.default,
    profileNames['no-default-features'],
    'retained profiles must freeze one SWC crate inventory',
  );
  return {
    retirementManifestSchema: 'ibex/oxc-retirement-manifest/1',
    llp: '0028',
    frozenOn: '2026-07-17',
    phase: 'inventory',
    provenance: {
      capsecSurfaceInventory: 'capsec/generated/implementation-manifest.json#surfaces',
      capsecSymbolTable: 'capsec/generated/implementation-manifest.json#surfaces[*].sourceRefs',
      dependencyGraph: 'cargo metadata --locked --format-version 1',
      lockfile: 'Cargo.lock',
    },
    surfaceInventory: {
      expectedState: 'present',
      exactIds: capsec.surfaceIds,
      implementationSymbolRefs: capsec.symbolRefs,
    },
    sourceNeedles: namedSourceNeedles,
    compatSelectorInventory,
    dependencyGate: {
      mode: 'inventory',
      rejectedNamePrefix: 'swc_',
      cargoProfiles,
      exactCurrentNames: profileNames.default,
    },
  };
}

function validateFrozenManifest(manifest) {
  assert.equal(manifest.retirementManifestSchema, 'ibex/oxc-retirement-manifest/1');
  assert.equal(manifest.llp, '0028');
  assert.equal(manifest.dependencyGate.rejectedNamePrefix, 'swc_');
  assert.deepEqual(
    manifest.sourceNeedles,
    namedSourceNeedles,
    'generated retirement source inventory drifted',
  );
  assert.deepEqual(
    manifest.compatSelectorInventory,
    compatSelectorInventory,
    'generated compat selector inventory drifted',
  );
  assertCompatSelectorInventory(manifest.compatSelectorInventory);

  const frozenIds = manifest.surfaceInventory.exactIds;
  assert.equal(new Set(frozenIds).size, 10, 'retirement manifest must freeze ten exact IDs');
  const frozenBaseIds = frozenIds.filter((id) => !id.endsWith('.main'));
  assert.equal(frozenBaseIds.length, 5, 'retirement manifest must freeze five base IDs');
  exactSet(
    frozenIds,
    frozenBaseIds.flatMap((id) => [id, `${id}.main`]),
    'every base surface must have its exact .main variant',
  );

  const implementationManifest = JSON.parse(
    fs.readFileSync(implementationManifestPath, 'utf8'),
  );
  const expectedBaseCount = manifest.surfaceInventory.expectedState === 'present' ? 5 : 0;
  const current = swcSurfaceInventory(implementationManifest, expectedBaseCount);
  if (manifest.surfaceInventory.expectedState === 'present') {
    exactSet(current.surfaceIds, frozenIds, 'frozen CapSec SWC surface inventory drifted');
    exactSet(
      current.symbolRefs,
      manifest.surfaceInventory.implementationSymbolRefs,
      'frozen CapSec SWC symbol table drifted',
    );
  } else {
    assert.equal(manifest.surfaceInventory.expectedState, 'absent');
    assert.deepEqual(current.surfaceIds, [], 'retired CapSec SWC surfaces remain');
  }

  const seenNeedles = new Set();
  for (const entry of manifest.sourceNeedles) {
    const identity = `${entry.category}:${entry.identity}`;
    assert.ok(!seenNeedles.has(identity), `duplicate retirement needle ${identity}`);
    seenNeedles.add(identity);
    assert.ok(entry.disposition === 'retire' || entry.disposition === 'migrate');
    const sourcePath = path.join(repoRoot, entry.file);
    const present = fs.existsSync(sourcePath)
      && fs.readFileSync(sourcePath, 'utf8').includes(entry.needle);
    assert.equal(
      present,
      entry.expectedState === 'present',
      `${identity} expected ${entry.expectedState} at ${entry.file}`,
    );
  }

  const profileNames = Object.fromEntries(
    manifest.dependencyGate.cargoProfiles.map((profile) => [
      profile.name,
      swcNamesFromMetadata(cargoMetadata(profile.cargoMetadataArgs)),
    ]),
  );
  assertSwcDependencyPrefixGate({
    mode: manifest.dependencyGate.mode,
    expectedNames: manifest.dependencyGate.exactCurrentNames,
    profileNames,
    lockfileNames: swcNamesFromLockfile(fs.readFileSync(cargoLockPath, 'utf8')),
  });
}

function render(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  assert.notEqual(write, check, 'pass exactly one of --write or --check');
  if (write) {
    const rendered = render(buildFrozenManifest());
    fs.writeFileSync(manifestPath, rendered, 'utf8');
    console.log(`Wrote ${path.relative(repoRoot, manifestPath)}`);
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  validateFrozenManifest(manifest);
  console.log('Oxc retirement manifest and swc_* prefix gates are current.');
}

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  main();
}
