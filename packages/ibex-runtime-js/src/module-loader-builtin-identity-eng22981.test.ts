// Regression tests for ENG-22981 finding 1: builtin module identity.
//
// The native resolver emits one registry record per alias (`fs`, `node:fs`,
// `bun:fs`, and cross-name groups like `util`/`sys`) with `id` set to the raw
// specifier. The bootstrap loader used to cache by that `id`, so each alias
// re-evaluated the builtin and produced an independent module object with
// forked state (distinct EventEmitter classes, fs watch registries, http
// globalAgent) and double eval cost. The fix canonicalizes builtin cache keys
// on the resolved source text so every alias of one builtin shares a single
// instance, while distinct modules stay separate.
//
// The loader is the first bootstrap script and self-installs `globalThis.require`
// against native globals, so we drive it in a vm context with a mock resolver
// that mirrors the real one (aliases in a group return an identical source
// string; distinct modules return distinct sources).

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

const SRC_FS = [
  'var n = (globalThis.__fsEvals = (globalThis.__fsEvals || 0) + 1);',
  'function Emitter() {}',
  'module.exports = { Emitter: Emitter, evals: n };',
].join('\n');
const SRC_EVENTS = [
  'var n = (globalThis.__evEvals = (globalThis.__evEvals || 0) + 1);',
  'function EventEmitter() {}',
  'module.exports = { EventEmitter: EventEmitter, evals: n };',
].join('\n');
const SRC_UTIL = ['function inspect() {}', 'module.exports = { inspect: inspect };'].join('\n');

// Alias groups mirror modules.ts: every name in a group resolves to the SAME
// source text; distinct modules resolve to distinct source text.
const GROUPS: Record<string, { names: string[]; source: string }> = {
  node_fs: { names: ['fs', 'node:fs', 'bun:fs'], source: SRC_FS },
  node_events: { names: ['events', 'node:events'], source: SRC_EVENTS },
  node_util: { names: ['util', 'sys', 'node:util', 'node:sys'], source: SRC_UTIL },
};

function makeRequire(): (specifier: string) => any {
  const byName = new Map<string, string>();
  for (const group of Object.values(GROUPS)) {
    for (const name of group.names) byName.set(name, group.source);
  }
  const sandbox: any = {};
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.Symbol = Symbol;
  sandbox.Promise = Promise;
  sandbox.__exactPinProcessStreams = function () {};
  sandbox.__exactModuleResolve = function (specifier: string) {
    const source = byName.get(specifier);
    if (source === undefined) {
      return JSON.stringify({ error: 'Module not found: ' + specifier });
    }
    // Native resolver shape for a builtin: id is the raw specifier.
    return JSON.stringify({ id: specifier, kind: 'builtin', source });
  };
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  if (typeof sandbox.require !== 'function') {
    throw new Error('loader did not install globalThis.require');
  }
  return sandbox.require.bind(sandbox);
}

test("require('fs') === require('node:fs') === require('bun:fs')", () => {
  const require = makeRequire();
  const bare = require('fs');
  const node = require('node:fs');
  const bun = require('bun:fs');
  expect(bare).toBe(node);
  expect(bare).toBe(bun);
  // Shared class: instanceof across aliases must hold.
  expect(bare.Emitter).toBe(node.Emitter);
  expect(new node.Emitter() instanceof bare.Emitter).toBe(true);
});

test('a builtin is evaluated exactly once across all its aliases', () => {
  const require = makeRequire();
  require('fs');
  require('node:fs');
  require('bun:fs');
  // If the loader forked per alias this would be 3.
  expect(require('fs').evals).toBe(1);
});

test('cross-name aliases sharing one source share identity (util/sys)', () => {
  const require = makeRequire();
  expect(require('util')).toBe(require('sys'));
  expect(require('util')).toBe(require('node:util'));
});

test("require('events') === require('node:events') with a shared EventEmitter", () => {
  const require = makeRequire();
  const bare = require('events');
  const node = require('node:events');
  expect(bare).toBe(node);
  expect(bare.EventEmitter).toBe(node.EventEmitter);
});

test('distinct builtins are not collapsed', () => {
  const require = makeRequire();
  expect(require('fs')).not.toBe(require('events'));
});

test('authenticated sourceId, not a host path label, keys user module records', () => {
  const sandbox: any = {};
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.Symbol = Symbol;
  sandbox.Promise = Promise;
  sandbox.__exactPinProcessStreams = function () {};
  sandbox.__exactModuleResolve = function (specifier: string) {
    const sourceId =
      specifier === 'alias-a' || specifier === 'alias-a-second-spelling'
        ? 'source:shared'
        : `source:${specifier}`;
    return JSON.stringify({
      sourceId,
      id: '/host/private/shared-label.js',
      kind: 'cjs',
      path: '/host/private/shared-label.js',
      source: `module.exports = { specifier: ${JSON.stringify(specifier)} };`,
    });
  };
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });

  const first = sandbox.require('alias-a');
  const sameIdentity = sandbox.require('alias-a-second-spelling');
  const samePathDifferentIdentity = sandbox.require('alias-b');
  expect(first).toBe(sameIdentity);
  expect(first).not.toBe(samePathDifferentIdentity);
});
