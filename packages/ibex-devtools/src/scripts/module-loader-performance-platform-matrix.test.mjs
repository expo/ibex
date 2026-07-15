import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const matrix = JSON.parse(
  readFileSync(
    path.join(repoRoot, 'tests/fixtures/module-semantics/performance-platform-matrix.json'),
    'utf8',
  ),
);

test('desktop loader-performance matrix cannot hide missing native evidence', () => {
  assert.equal(matrix.schema, 'ibex/module-loader-performance-platform-matrix/1');
  assert.deepEqual(
    matrix.targets.map((target) => target.id),
    ['macos-arm64', 'linux-x64', 'windows-x64'],
  );
  for (const target of matrix.targets) {
    assert.ok(target.note.length > 40, `${target.id} needs an honest status note`);
    if (target.collectionWorkflow) {
      assert.ok(
        existsSync(path.join(repoRoot, target.collectionWorkflow)),
        `${target.id} names missing workflow ${target.collectionWorkflow}`,
      );
    }
    if (target.runtimeEvidence) {
      assert.ok(
        existsSync(path.join(repoRoot, target.runtimeEvidence)),
        `${target.id} names missing evidence ${target.runtimeEvidence}`,
      );
    } else {
      assert.notEqual(target.status, 'complete', `${target.id} cannot complete without evidence`);
    }
  }
});
