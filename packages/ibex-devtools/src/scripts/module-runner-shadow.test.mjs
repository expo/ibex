import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

import { extractImportSpecifiersDetailed } from './import-grants.mjs';
import { moduleSemanticsCorpus } from './module-semantics-corpus.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');

// @ref LLP 0026#phase-2-synchronous-esm-graph — compare the authenticated
// producer's checked graph shape with the exact legacy scanner without
// evaluating either application graph or duplicating its side effects.
function legacyTransform() {
  const loaderPath = path.join(repoRoot, 'src/engine/bootstrap/module-loader.js');
  const source = readFileSync(loaderPath, 'utf8');
  const close = /\}\)\(\);\s*$/u;
  assert.match(source, close, 'bootstrap loader must retain its closing IIFE boundary');
  const instrumented = source.replace(
    close,
    'globalThis.__moduleRunnerShadowTransform = transformEsmToCjs;\n})();\n',
  );
  const sandbox = {
    console,
    Promise,
    Symbol,
    __exactPinProcessStreams() {},
    __exactModuleResolve(specifier) {
      return JSON.stringify({ error: `shadow probe must not resolve ${specifier}` });
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(instrumented, sandbox, { filename: loaderPath });
  assert.equal(typeof sandbox.__moduleRunnerShadowTransform, 'function');
  return sandbox.__moduleRunnerShadowTransform;
}

function normalizedTrace(specifiers) {
  return [...new Set(specifiers)].sort().map((specifier) => `import:${specifier}`);
}

function transformedTrace(transform, source, label) {
  const transformed = transform(source);
  const parsed = extractImportSpecifiersDetailed(transformed);
  assert.equal(parsed.parseable, true, `${label}: legacy output must remain parseable`);
  const scannerImports = [...transformed.matchAll(
    /\b__exactStaticImport\(("(?:\\.|[^"\\])*")\)/gu,
  )].map((match) => JSON.parse(match[1]));
  return normalizedTrace([...parsed.specifiers, ...scannerImports]);
}

test('legacy scanner and authenticated producer have the same static-edge effect trace', () => {
  const transform = legacyTransform();
  const checked = JSON.parse(readFileSync(
    path.join(repoRoot, 'tests/fixtures/module-runner-spike/canonical-artifacts.json'),
    'utf8',
  ));
  let comparedModules = 0;
  const comparedFixtures = new Set();
  for (const fixture of checked.fixtures) {
    for (const module of fixture.modules) {
      const source = module.sourceMap?.sourcesContent?.[0];
      if (
        module.dialect !== 'JS'
        || module.hasTopLevelAwait
        || module.dynamicEdges.length !== 0
        || typeof source !== 'string'
      ) {
        continue;
      }
      const producerTrace = normalizedTrace(
        module.staticEdges.map((edge) => edge.specifier),
      );
      assert.deepEqual(
        transformedTrace(transform, source, `${fixture.id}/${module.sourceName}`),
        producerTrace,
        `${fixture.id}/${module.sourceName}: legacy scanner and runner graph disagree`,
      );
      comparedModules += 1;
      comparedFixtures.add(fixture.id);
    }
  }
  assert.ok(comparedModules >= 10, `shadow corpus compared only ${comparedModules} modules`);
  assert.ok(comparedFixtures.size >= 5, `shadow corpus covered only ${comparedFixtures.size} fixtures`);
});

test('historical scanner repairs remain zero-divergence Oxc migration oracles', () => {
  const transform = legacyTransform();
  const repairs = moduleSemanticsCorpus.filter(
    (fixture) => fixture.category === 'scanner-regressions',
  );
  assert.deepEqual(
    repairs.map((fixture) => fixture.id),
    [
      'scanner-eng-22514-comments',
      'scanner-eng-22520-strings',
      'scanner-eng-22528-regex-template',
    ],
  );
  for (const fixture of repairs) {
    for (const [name, source] of Object.entries(fixture.files)) {
      if (!name.endsWith('.mjs')) continue;
      const runner = extractImportSpecifiersDetailed(source);
      assert.equal(runner.parseable, true, `${fixture.id}/${name}: Oxc parse failed`);
      assert.deepEqual(
        transformedTrace(transform, source, `${fixture.id}/${name}`),
        normalizedTrace(runner.specifiers),
        `${fixture.id}/${name}: repaired scanner knowledge diverged from Oxc`,
      );
    }
  }
});
