#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { forOfScopingCorpus } from './hermes-compat-corpus.mjs';
import { moduleSemanticsCorpus } from './module-semantics-corpus.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');

test('every accumulated scanner repair has one source-owned fixture family', () => {
  const coverage = JSON.parse(readFileSync(
    path.join(repoRoot, 'tests/fixtures/module-semantics/scanner-regression-coverage.json'),
    'utf8',
  ));
  assert.equal(coverage.schema, 'ibex/module-semantics-scanner-regression-coverage/1');
  const moduleIds = new Set(moduleSemanticsCorpus.map((fixture) => fixture.id));
  const hermesCompatIds = new Set(forOfScopingCorpus.map((fixture) => fixture.id));
  const familiesByIssue = new Map(coverage.families.map((family) => [family.issue, family]));
  assert.deepEqual([...familiesByIssue.keys()].sort(), [...coverage.requiredIssues].sort());
  for (const issue of coverage.requiredIssues) {
    const family = familiesByIssue.get(issue);
    assert.ok(family.fixtureIds.length > 0, `${issue}: fixture family is empty`);
    const ownerIds = family.owner === 'module-semantics' ? moduleIds : hermesCompatIds;
    assert.ok(
      family.owner === 'module-semantics' || family.owner === 'llp0019-hermes-compat',
      `${issue}: unknown source owner ${family.owner}`,
    );
    for (const fixtureId of family.fixtureIds) {
      assert.ok(ownerIds.has(fixtureId), `${issue}: ${fixtureId} missing from ${family.owner}`);
    }
  }
});
