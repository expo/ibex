// Regression coverage for ENG-24233: manifest builtin implementation fan-out.
//
// A package authorizes the public builtin it imports, not every private builtin
// dependency used while that trusted shim initializes. The exemption must not
// become a detached-require escape: it is active only while the exact native
// resolver record with kind="builtin" is synchronously evaluating.

import { expect, test } from 'bun:test';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const loaderSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'module-loader.js'),
  'utf8',
);

const outerSource = [
  "var util = require('node:util');",
  'module.exports = {',
  '  value: util.value,',
  '  leakedRequire: require,',
  '  leakedModuleRequire: module.require,',
  "  terminal: function() { return globalThis.__exactReadFile('/secret'); }",
  '};',
].join('\n');

const records: Record<string, Record<string, unknown>> = {
  'node:outer': { id: 'node:outer', kind: 'builtin', source: outerSource },
  'node:util': {
    id: 'node:util',
    kind: 'builtin',
    source: "module.exports = { value: 'INTERNAL' };",
  },
  'node:secret': {
    id: 'node:secret',
    kind: 'builtin',
    source: "module.exports = { value: 'SECRET' };",
  },
  // A package-controlled record whose id looks builtin-like must not receive
  // the exemption. Trust comes only from the native resolver's exact kind.
  'node:forged-looking-package': {
    id: 'node:forged-looking-package',
    kind: 'cjs',
    path: '/app/node_modules/evil-pkg/index.js',
    pkgName: 'evil-pkg',
    pkgVersion: '1.0.0',
    pkgRoot: '/app/node_modules/evil-pkg',
    source: "module.exports = require('node:util');",
  },
};

function makeHarness() {
  const checked: Array<{ hint: number; specifier: string }> = [];
  const internallyResolved: string[] = [];
  let terminalCalls = 0;
  const packageAllowed = new Set(['node:outer', 'node:forged-looking-package']);
  const sandbox: any = {};
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.Symbol = Symbol;
  sandbox.Promise = Promise;
  sandbox.__exactPinProcessStreams = function () {};
  sandbox.__exactCheckImport = function (hint: number, specifier: string) {
    checked.push({ hint, specifier });
    return packageAllowed.has(specifier);
  };
  sandbox.__exactReadFile = function () {
    terminalCalls += 1;
    throw new Error('CAPABILITY-DENIED');
  };
  sandbox.__exactModuleResolve = function (specifier: string) {
    const record = records[specifier];
    return JSON.stringify(
      record ?? { error: `Module not found: ${specifier}` },
    );
  };
  sandbox.__exactResolveManifestBuiltinInternal = function (specifier: string) {
    internallyResolved.push(specifier);
    const record = records[specifier];
    return JSON.stringify(
      record?.kind === 'builtin'
        ? record
        : { error: `Not a manifest builtin: ${specifier}` },
    );
  };
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  return {
    checked,
    internallyResolved,
    internalResolverReachable:
      typeof sandbox.__exactResolveManifestBuiltinInternal === 'function',
    get terminalCalls() {
      return terminalCalls;
    },
    require: sandbox.require.bind(sandbox) as (specifier: string) => any,
  };
}

test('manifest builtin initialization can load its authored private dependency', () => {
  const harness = makeHarness();
  const outer = harness.require('node:outer');
  expect(outer.value).toBe('INTERNAL');
  expect(harness.checked.map((row) => row.specifier)).toEqual(['node:outer']);
  expect(harness.internallyResolved).toEqual(['node:util']);
  expect(harness.internalResolverReachable).toBe(false);
});

test('a package cannot spell the dependency or reuse leaked builtin require closures', () => {
  const harness = makeHarness();
  const outer = harness.require('node:outer');

  expect(() => harness.require('node:util')).toThrow('Import denied');
  expect(() => outer.leakedRequire('node:util')).toThrow('Import denied');
  expect(() => outer.leakedModuleRequire('node:secret')).toThrow(
    'Import denied',
  );
  expect(
    harness.checked
      .filter((row) => row.specifier !== 'node:outer')
      .map((row) => row.specifier),
  ).toEqual(['node:util', 'node:util', 'node:secret']);
  expect(
    harness.checked
      .filter((row) => row.specifier !== 'node:outer')
      .map((row) => row.hint),
  ).toEqual([0, 0xfffffffe, 0xfffffffe]);
});

test('a builtin-looking package record cannot claim the initialization exemption', () => {
  const harness = makeHarness();
  expect(() => harness.require('node:forged-looking-package')).toThrow(
    'Import denied',
  );
  expect(harness.checked.map((row) => row.specifier)).toEqual([
    'node:forged-looking-package',
    'node:util',
  ]);
});

test('internal loading never suppresses terminal capability checks', () => {
  const harness = makeHarness();
  const outer = harness.require('node:outer');
  expect(() => outer.terminal()).toThrow('CAPABILITY-DENIED');
  expect(harness.terminalCalls).toBe(1);
});
