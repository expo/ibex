import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const inventory = JSON.parse(
  readFileSync(
    path.join(repoRoot, 'tests/fixtures/module-semantics/current-path-inventory.json'),
    'utf8',
  ),
);

const required = new Set([
  'direct-source',
  'swc-lowered',
  'scanner-lowered',
  'prepared-rolldown',
  'entry-tla',
  'per-package-chunks',
  'integrity-manifest',
  'hermes-bytecode',
]);

test('module-loader path inventory is complete and source-backed', () => {
  assert.equal(inventory.schema, 'ibex/module-loader-current-path-inventory/1');
  assert.equal(inventory.paths.length, required.size);
  for (const entry of inventory.paths) {
    assert.ok(required.delete(entry.id), `unexpected or duplicate path ${entry.id}`);
    assert.ok(entry.description.length > 20, `${entry.id} needs a useful description`);
    assert.ok(entry.evidence.length > 0, `${entry.id} needs source evidence`);
    for (const evidence of entry.evidence) {
      const source = readFileSync(path.join(repoRoot, evidence.file), 'utf8');
      assert.ok(
        source.includes(evidence.needle),
        `${entry.id} evidence drifted: ${evidence.file} lacks ${JSON.stringify(evidence.needle)}`,
      );
    }
  }
  assert.deepEqual([...required], []);
});
