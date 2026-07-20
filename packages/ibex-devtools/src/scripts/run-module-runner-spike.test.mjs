import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { runtimeSource } from './run-module-runner-spike.mjs';

test('site-bearing and legacy dynamic imports select the specifier argument', async () => {
  const bundle = JSON.parse(
    fs.readFileSync(
      new URL('../../../../tests/fixtures/module-runner-spike/canonical-artifacts.json', import.meta.url),
      'utf8',
    ),
  );
  const fixture = bundle.fixtures.find((candidate) => candidate.id === 'dynamic-import');
  assert.ok(fixture, 'checked-in dynamic-import fixture must exist');

  const priorPrint = globalThis.print;
  try {
    const call = 'dynamicImport(-1, 24, 42, 0, "./dep.js")';
    const variants = [
      fixture,
      ...[
        'dynamicImport("./dep.js")',
        'dynamicImport(0, "./dep.js")',
      ].map((replacement) => {
        const legacy = structuredClone(fixture);
        const entry = legacy.modules.find((module) => module.sourceName === legacy.entry);
        assert.ok(entry.factorySource.includes(call));
        entry.factorySource = entry.factorySource.replace(call, replacement);
        return legacy;
      }),
    ];
    for (const variant of variants) {
      const output = [];
      globalThis.print = (value) => output.push(String(value));
      Function(runtimeSource(variant))();
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(output, [
        'dynamic:7',
        'MODULE_RUNNER_SPIKE|{"ok":true}',
      ]);
    }
  } finally {
    if (priorPrint === undefined) delete globalThis.print;
    else globalThis.print = priorPrint;
  }
});
