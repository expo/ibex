#!/usr/bin/env node
/**
 * Materialize the predeclared LLP 0026 test262 spike sample from an exact
 * checkout. The generated manifest keeps executable bodies small while
 * binding each one to its complete upstream source by SHA-256.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const upstreamCommit = 'f2d1435644797268dca1f7988cad5a4e89ccd8d2';
const minimumPassRate = { numerator: 18, denominator: 20, percent: 90 };
const selectedPaths = Object.freeze([
  'test/language/module-code/eval-this.js',
  'test/language/module-code/eval-export-cls-semi.js',
  'test/language/module-code/eval-export-dflt-cls-anon-semi.js',
  'test/language/module-code/eval-export-dflt-cls-named-semi.js',
  'test/language/module-code/eval-export-dflt-fun-anon-semi.js',
  'test/language/module-code/eval-export-dflt-fun-named-semi.js',
  'test/language/module-code/eval-export-fun-semi.js',
  'test/language/module-code/eval-gtbndng-local-bndng-const.js',
  'test/language/module-code/eval-gtbndng-local-bndng-let.js',
  'test/language/module-code/eval-gtbndng-local-bndng-var.js',
  'test/language/module-code/top-level-await/await-expr-resolution.js',
  'test/language/module-code/top-level-await/await-void-expr.js',
  'test/language/module-code/top-level-await/if-await-expr.js',
  'test/language/module-code/top-level-await/await-awaits-thenables.js',
  'test/language/module-code/top-level-await/await-awaits-thenable-not-callable.js',
  'test/language/module-code/top-level-await/await-expr-func-expression.js',
  'test/language/module-code/top-level-await/await-expr-regexp.js',
  'test/language/module-code/top-level-await/new-await-parens.js',
  'test/language/module-code/top-level-await/await-expr-new-expr.js',
  'test/language/module-code/top-level-await/await-expr-reject-throws.js',
]);

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function executableBody(source, upstreamPath) {
  const frontmatterEnd = source.indexOf('---*/');
  if (frontmatterEnd < 0) throw new Error(`${upstreamPath}: test262 frontmatter terminator missing`);
  return source.slice(frontmatterEnd + '---*/'.length).replace(/^\s+/u, '').replace(/\s*$/u, '\n');
}

function main() {
  const checkout = process.argv[2];
  const output = process.argv[3];
  if (!checkout || !output || process.argv.length !== 4) {
    throw new Error('usage: generate-module-runner-test262-subset.mjs TEST262_CHECKOUT OUTPUT');
  }
  const head = readFileSync(path.join(checkout, '.git/HEAD'), 'utf8').trim();
  if (!head.includes(upstreamCommit)) {
    // Detached checkout is required so regeneration cannot silently follow a
    // moving branch. Worktrees may store HEAD elsewhere, so the caller can
    // still prove the revision by checking out this exact commit first.
    throw new Error(`test262 checkout must be detached at ${upstreamCommit}; .git/HEAD=${head}`);
  }
  const cases = selectedPaths.map((upstreamPath) => {
    const completeSource = readFileSync(path.join(checkout, upstreamPath), 'utf8');
    const source = executableBody(completeSource, upstreamPath);
    return {
      id: upstreamPath.slice('test/language/module-code/'.length).replace(/\.js$/u, ''),
      suite: upstreamPath.includes('/top-level-await/') ? 'top-level-await' : 'module-code',
      upstreamPath,
      upstreamFileSha256: sha256(completeSource),
      executableBodySha256: sha256(source),
      source,
      expectedDivergence: null,
    };
  });
  const manifest = {
    schema: 'ibex/module-runner-test262-subset/1',
    upstream: {
      repository: 'https://github.com/tc39/test262',
      commit: upstreamCommit,
      license: 'BSD-3-Clause',
    },
    minimumPassRate,
    expectedDivergences: [],
    cases,
  };
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
}

main();
