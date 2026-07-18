import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalJson,
  decodeMappings,
  semanticProjection,
} from './oxc-dual-produce-report.mjs';

test('semantic projection excludes producer identity and generated layout', () => {
  const bundle = {
    schema: 'bundle',
    manifestSchema: 'manifest',
    transformFingerprint: 'producer-a',
    fixtures: [
      {
        id: 'fixture',
        entry: 'entry.js',
        expected: { stdout: ['42'] },
        tags: ['semantic'],
        modules: [
          {
            fixtureId: 'fixture',
            sourceName: 'entry.js',
            dialect: 'JS',
            sourceIntegrity: 'sha256-source',
            transformFingerprint: 'producer-a',
            staticEdges: [],
            dynamicEdges: [],
            exportDescriptors: [],
            hasTopLevelAwait: false,
            hermesCompatPasses: [],
            factorySource: 'old spelling',
            sourceMap: { mappings: 'AAAA' },
          },
        ],
      },
    ],
  };
  const rotated = structuredClone(bundle);
  rotated.transformFingerprint = 'producer-b';
  rotated.fixtures[0].modules[0].transformFingerprint = 'producer-b';
  rotated.fixtures[0].modules[0].factorySource = 'new spelling';
  rotated.fixtures[0].modules[0].sourceMap.mappings = 'AACA';
  assert.equal(canonicalJson(semanticProjection(bundle)), canonicalJson(semanticProjection(rotated)));

  rotated.fixtures[0].modules[0].hasTopLevelAwait = true;
  assert.notEqual(canonicalJson(semanticProjection(bundle)), canonicalJson(semanticProjection(rotated)));
});

test('source-map decoder expands stateful base64 VLQ segments', () => {
  assert.deepEqual(
    decodeMappings({ mappings: 'AAAA;AACA', sources: ['entry.js'], names: [] }),
    [
      {
        generatedLine: 1,
        generatedColumn: 0,
        sourceIndex: 0,
        source: 'entry.js',
        originalLine: 1,
        originalColumn: 0,
      },
      {
        generatedLine: 2,
        generatedColumn: 0,
        sourceIndex: 0,
        source: 'entry.js',
        originalLine: 2,
        originalColumn: 0,
      },
    ],
  );
  assert.throws(() => decodeMappings({ mappings: 'A!', sources: ['entry.js'] }), /invalid base64 VLQ/u);
});

test('canonical report JSON is stable across object insertion order', () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), canonicalJson({ a: { b: 3, y: 2 }, z: 1 }));
});
