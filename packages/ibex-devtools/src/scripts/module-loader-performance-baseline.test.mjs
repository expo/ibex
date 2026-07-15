import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const report = JSON.parse(
  readFileSync(
    path.join(repoRoot, 'tests/fixtures/module-semantics/performance-macos-arm64.json'),
    'utf8',
  ),
);

function assertSummary(summary, label) {
  assert.ok(Number.isInteger(summary.samples) && summary.samples >= 3, `${label} sample count`);
  for (const field of ['minMs', 'medianMs', 'meanMs', 'maxMs']) {
    assert.ok(Number.isFinite(summary[field]) && summary[field] > 0, `${label}.${field}`);
  }
  assert.ok(summary.minMs <= summary.medianMs, `${label} median below minimum`);
  assert.ok(summary.medianMs <= summary.maxMs, `${label} median above maximum`);
}

test('macOS module-loader performance baseline is explicit and non-vacuous', () => {
  assert.equal(report.schema, 'ibex/module-loader-performance-baseline/2');
  assert.equal(report.platform.os, 'darwin');
  assert.equal(report.platform.arch, 'arm64');
  assert.equal(report.graphModules, 40);
  assert.ok(report.ibexBinaryBytes > 0);

  const conditions = report.measurementConditions;
  assert.equal(typeof conditions.hostContentionObserved, 'boolean');
  assert.equal(
    conditions.usableForPerformanceBudget,
    !conditions.hostContentionObserved,
    'contended measurements must never be presented as budget evidence',
  );
  assert.equal(conditions.preparedProfileRequiresDigestVerifiedBundleArtifact, true);
  assert.equal(conditions.transpileProfilesRequireDigestVerifiedCacheArtifact, true);

  for (const profile of [
    'directSourceMjs',
    'swcSelectedTs',
    'scannerSelectedJs',
    'preparedRolldownMjs',
  ]) {
    assert.ok(report.profiles[profile], `missing ${profile}`);
    assertSummary(report.profiles[profile].cold, `${profile}.cold`);
    assertSummary(report.profiles[profile].warm, `${profile}.warm`);
  }
  assert.ok(report.compile.cleanBuildSeconds > 0);
});
