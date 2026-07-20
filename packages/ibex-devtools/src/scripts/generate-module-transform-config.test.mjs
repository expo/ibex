import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  effectiveTransformConfigDigest,
  transformOptionDigests,
} from './generate-module-transform-config.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const config = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'config/module-transform.json'), 'utf8'),
);

function clone(value) {
  return structuredClone(value);
}

test('every output-changing phase rotates the effective transform identity', () => {
  const lockedSet = 'sha256-current-locked-set';
  const current = effectiveTransformConfigDigest(config, lockedSet);
  const mutations = [
    (next) => { next.ecmascriptTarget = 'es2023'; },
    (next) => { next.hermesTarget = 'hermes-syntax-abi-next'; },
    (next) => { next.handwrittenPassVersion = 'handwritten-next'; },
    (next) => { next.moduleRunnerAbi = 'module-runner-next'; },
    (next) => { next.hermesCompatVersion = 'hermes-compat-next'; },
    (next) => { next.commonJsDetector.version = 'next'; },
    (next) => { next.options.oxc.jsx.runtime = 'automatic'; },
    (next) => { next.options.codegen.minify = true; },
    (next) => { next.options.factories.module = 'factory-next'; },
  ];
  for (const mutate of mutations) {
    const next = clone(config);
    mutate(next);
    assert.notEqual(effectiveTransformConfigDigest(next, lockedSet), current);
  }
  assert.notEqual(
    effectiveTransformConfigDigest(config, 'sha256-next-locked-set'),
    current,
  );
});

test('goal-specific option digests rotate without aliasing other goals', () => {
  const current = transformOptionDigests(config);
  const next = clone(config);
  next.options.factories.commonJs = 'commonjs-wrapper-next';
  const rotated = transformOptionDigests(next);
  assert.notEqual(rotated.commonJs, current.commonJs);
  assert.notEqual(rotated.commonJsOutput, current.commonJsOutput);
  assert.equal(rotated.moduleOutput, current.moduleOutput);
  assert.equal(rotated.jsonOutput, current.jsonOutput);
});
