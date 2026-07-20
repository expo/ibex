#!/usr/bin/env bun

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const repoRoot = path.resolve(scriptDir, '../../../..');
const configPath = path.join(repoRoot, 'config/module-transform.json');
const schemaPath = path.join(
  repoRoot,
  'schemas/module-transform-configuration-v1.schema.json',
);
const cargoManifestPath = path.join(repoRoot, 'Cargo.toml');
const cargoLockPath = path.join(repoRoot, 'Cargo.lock');
const receiptPath = path.join(
  repoRoot,
  'vendored-generated/module-transform-configuration.generated.json',
);
const rustPath = path.join(repoRoot, 'src/module_loader/transform_config_generated.rs');

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function base64UrlSha256(parts) {
  const hash = crypto.createHash('sha256');
  for (const part of parts) hash.update(part);
  return `sha256-${hash.digest('base64url')}`;
}

function domainDigest(domain, value) {
  return base64UrlSha256([domain, Buffer.from([0]), canonicalJson(value)]);
}

function contentDigest(value) {
  return base64UrlSha256([canonicalJson(value)]);
}

export function effectiveTransformConfigDigest(config, lockedSetDigest) {
  return domainDigest('ibex:module-transform-effective-config:1', {
    authored: config,
    lockedSetDigest,
  });
}

export function transformOptionDigests(config) {
  return {
    module: contentDigest({ goal: 'module', options: config.options }),
    commonJs: contentDigest({ goal: 'commonjs', options: config.options }),
    json: contentDigest({ goal: 'json', options: config.options }),
    moduleOutput: contentDigest({
      codegen: config.options.codegen,
      factory: config.options.factories.module,
    }),
    commonJsOutput: contentDigest({
      codegen: config.options.codegen,
      factory: config.options.factories.commonJs,
    }),
    jsonOutput: contentDigest({
      codegen: config.options.codegen,
      factory: config.options.factories.json,
    }),
  };
}

function cargoMetadata() {
  return JSON.parse(
    execFileSync('cargo', ['metadata', '--locked', '--format-version', '1'], {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'inherit'],
    }),
  );
}

function lockPackageKey(pkg) {
  return `${pkg.name}\u0000${pkg.version}\u0000${pkg.source ?? ''}`;
}

function resolvedOxcClosure(config, metadata, cargoLock) {
  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const nodesById = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const roots = Object.entries(config.oxc.directPackages).map(([name, version]) => {
    const candidates = metadata.packages.filter(
      (pkg) => pkg.name === name && pkg.version === version,
    );
    assert.equal(candidates.length, 1, `expected one resolved ${name}@${version}`);
    return candidates[0].id;
  });
  const reachable = new Set();
  const queue = [...roots];
  while (queue.length > 0) {
    const id = queue.pop();
    if (reachable.has(id)) continue;
    reachable.add(id);
    const node = nodesById.get(id);
    assert.ok(node, `cargo metadata has no resolve node for ${id}`);
    queue.push(...node.deps.map((dependency) => dependency.pkg));
  }

  const lockPackages = new Map(
    cargoLock.package.map((pkg) => [lockPackageKey(pkg), pkg]),
  );
  return [...reachable]
    .map((id) => {
      const pkg = packagesById.get(id);
      assert.ok(pkg, `cargo metadata has no package ${id}`);
      const source = pkg.source ?? null;
      const locked = lockPackages.get(
        lockPackageKey({ name: pkg.name, version: pkg.version, source }),
      );
      assert.ok(locked, `Cargo.lock has no exact package row for ${pkg.name}@${pkg.version}`);
      return {
        name: pkg.name,
        version: pkg.version,
        source,
        checksum: locked.checksum ?? null,
      };
    })
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

function readInputs() {
  const Ajv2020 = require('ajv/dist/2020.js').default;
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.ok(validate(config), JSON.stringify(validate.errors, null, 2));

  const cargoManifest = Bun.TOML.parse(fs.readFileSync(cargoManifestPath, 'utf8'));
  for (const [name, version] of Object.entries(config.oxc.directPackages)) {
    assert.equal(
      cargoManifest.dependencies[name],
      `=${version}`,
      `${name} must be exact-pinned to the authored transform configuration`,
    );
  }
  const cargoLock = Bun.TOML.parse(fs.readFileSync(cargoLockPath, 'utf8'));
  return { config, cargoLock };
}

function buildOutputs() {
  const { config, cargoLock } = readInputs();
  const lockedPackages = resolvedOxcClosure(config, cargoMetadata(), cargoLock);
  const lockedSetDigest = domainDigest('ibex:oxc-locked-set:1', lockedPackages);
  const authoredConfigDigest = domainDigest(
    'ibex:module-transform-authored-config:1',
    config,
  );
  const transformConfigDigest = effectiveTransformConfigDigest(config, lockedSetDigest);
  const optionDigests = transformOptionDigests(config);
  const receipt = {
    generatedTransformConfigurationSchema: 'ibex/generated-module-transform-configuration/1',
    authoredConfigDigest,
    lockedSetDigest,
    transformConfigDigest,
    cacheTag: `module-transform-${transformConfigDigest}`,
    authored: config,
    lockedPackages,
    optionDigests,
  };
  return { config, receipt };
}

function rustString(value) {
  return JSON.stringify(value);
}

function renderRust(config, receipt) {
  const values = {
    TRANSFORM_CONFIGURATION_SCHEMA: config.transformConfigurationSchema,
    TRANSFORM_CONFIGURATION_DIGEST: receipt.transformConfigDigest,
    TRANSFORM_CACHE_TAG: receipt.cacheTag,
    SPIKE_TRANSFORM_FINGERPRINT: `ibex-module-runner-spike/3+config/${receipt.transformConfigDigest}`,
    PRODUCER_ID: config.producer,
    OXC_LOCKED_SET_DIGEST: receipt.lockedSetDigest,
    PARSER_VERSION_IDENTITY: `oxc-locked-set/${receipt.lockedSetDigest}`,
    ECMASCRIPT_TARGET: config.ecmascriptTarget,
    HERMES_TARGET: config.hermesTarget,
    HANDWRITTEN_PASS_VERSION: config.handwrittenPassVersion,
    TRANSFORM_VERSION_IDENTITY: `${config.handwrittenPassVersion}+config/${receipt.transformConfigDigest}`,
    MODULE_RUNNER_ABI: config.moduleRunnerAbi,
    HERMES_COMPAT_VERSION: config.hermesCompatVersion,
    COMMONJS_DETECTOR: config.commonJsDetector.name,
    COMMONJS_DETECTOR_VERSION: config.commonJsDetector.version,
    OXC_MODULE_MODE: config.options.oxc.module,
    OXC_TYPESCRIPT_MODE: config.options.oxc.typescript,
    OXC_JSX_RUNTIME: config.options.oxc.jsx.runtime,
    CODEGEN_SOURCE_MAP: config.options.codegen.sourceMap,
    MODULE_OPTIONS_DIGEST: receipt.optionDigests.module,
    COMMONJS_OPTIONS_DIGEST: receipt.optionDigests.commonJs,
    JSON_OPTIONS_DIGEST: receipt.optionDigests.json,
    MODULE_OUTPUT_OPTIONS_DIGEST: receipt.optionDigests.moduleOutput,
    COMMONJS_OUTPUT_OPTIONS_DIGEST: receipt.optionDigests.commonJsOutput,
    JSON_OUTPUT_OPTIONS_DIGEST: receipt.optionDigests.jsonOutput,
  };
  const constants = Object.entries(values)
    .map(([name, value]) => {
      const prefix = `pub const ${name}: &str = `;
      const literal = rustString(value);
      return `${prefix}${literal};`.length > 100
        ? `${prefix.trimEnd()}\n    ${literal};`
        : `${prefix}${literal};`;
    })
    .join('\n');
  return `// @generated by bun run generate:module-transform-config; do not edit.\n// @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation — generated constants bind runtime identity to the reviewed pin set\n#![allow(dead_code)]\n${constants}\npub const OXC_JSX_ENABLED: bool = ${config.options.oxc.jsx.enabled};\npub const OXC_DECORATORS: bool = ${config.options.oxc.decorators};\npub const CODEGEN_MINIFY: bool = ${config.options.codegen.minify};\n`;
}

function writeOrCheck(file, rendered, check) {
  if (check) {
    assert.equal(fs.readFileSync(file, 'utf8'), rendered, `${path.relative(repoRoot, file)} is stale`);
  } else {
    fs.writeFileSync(file, rendered, 'utf8');
    console.log(`Wrote ${path.relative(repoRoot, file)}`);
  }
}

function main() {
  const check = process.argv.includes('--check');
  const write = process.argv.includes('--write');
  assert.notEqual(check, write, 'pass exactly one of --check or --write');
  const { config, receipt } = buildOutputs();
  writeOrCheck(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, check);
  writeOrCheck(rustPath, renderRust(config, receipt), check);
  if (check) console.log('Module transform configuration is current.');
}

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  main();
}
