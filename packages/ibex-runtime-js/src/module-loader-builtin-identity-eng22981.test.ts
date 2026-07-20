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
const SRC_STREAM = [
  'var n = (globalThis.__streamEvals = (globalThis.__streamEvals || 0) + 1);',
  'module.exports = { evals: n };',
].join('\n');
const SRC_UTIL = ['function inspect() {}', 'module.exports = { inspect: inspect };'].join('\n');
const SRC_DNS_PROMISES = [
  'var n = (globalThis.__dnsPromisesEvals = (globalThis.__dnsPromisesEvals || 0) + 1);',
  "module.exports = { manifestSource: 'node_dns_promises', evals: n };",
].join('\n');

// Alias groups mirror modules.ts: every name in a group resolves to the SAME
// source text; distinct modules resolve to distinct source text.
const GROUPS: Record<string, { names: string[]; source: string }> = {
  node_fs: { names: ['fs', 'node:fs', 'bun:fs'], source: SRC_FS },
  node_events: { names: ['events', 'node:events'], source: SRC_EVENTS },
  node_stream: { names: ['stream', 'node:stream'], source: SRC_STREAM },
  node_util: { names: ['util', 'sys', 'node:util', 'node:sys'], source: SRC_UTIL },
  node_dns_promises: {
    names: ['dns/promises', 'node:dns/promises'],
    source: SRC_DNS_PROMISES,
  },
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
  const boundRequire = sandbox.require.bind(sandbox);
  (boundRequire as any).sandbox = sandbox;
  return boundRequire;
}

function makeAuthenticatedReceiptHarness(
  records: Record<string, { source: string; sourceId: string }>,
) {
  const sandbox: any = {};
  const markerCalls: unknown[][] = [];
  const receipts: unknown[][] = [];
  let activeModuleId = 0;
  let expectedAlias: string | null = null;
  const resolve = function (specifier: string) {
    const record = records[specifier];
    if (!record) {
      return JSON.stringify({ error: 'Module not found: ' + specifier });
    }
    return JSON.stringify({
      schema: 'ibex/module-resolution/1',
      id: specifier,
      kind: 'builtin',
      source: record.source,
      sourceId: record.sourceId,
    });
  };
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.Symbol = Symbol;
  sandbox.Promise = Promise;
  sandbox.__exactPinProcessStreams = function () {};
  sandbox.__exactModuleResolve = resolve;
  sandbox.__exactModuleResolveMeta = resolve;
  sandbox.__exactCaptureSessionStaticImport = function () {
    return { resolve, resolveMeta: resolve };
  };
  sandbox.__exactSetActiveModuleId = function (...args: unknown[]) {
    const previous = activeModuleId;
    const next = args[0];
    activeModuleId =
      typeof next === 'number' && Number.isSafeInteger(next) && next >= 0
        ? next
        : 0;
    if (args.length === 4) {
      markerCalls.push([...args]);
      if (
        next === previous &&
        args[1] === records[String(args[2])]?.sourceId &&
        args[2] === expectedAlias &&
        args[3] === 'ibex-capsec-authenticated-builtin-source-complete-v1'
      ) {
        receipts.push([...args]);
      }
    }
    return previous;
  };
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  return {
    require: sandbox.require.bind(sandbox) as (specifier: string) => any,
    arm(alias: string) {
      expectedAlias = alias;
    },
    markerCalls,
    receipts,
  };
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

test('dns/promises aliases execute their declared manifest source', () => {
  const require = makeRequire();
  const bare = require('dns/promises');
  const node = require('node:dns/promises');

  expect(bare).toBe(node);
  expect(bare.manifestSource).toBe('node_dns_promises');
  expect(bare.evals).toBe(1);
});

test('authenticated builtin completion receipt requires one cold exact-alias body', () => {
  const dnsSourceId = 'ibex-source-id-v1:bm9kZV9kbnM';
  const harness = makeAuthenticatedReceiptHarness({
    'node:dns': {
      source: "module.exports = { loaded: 'node:dns' };",
      sourceId: dnsSourceId,
    },
  });
  harness.arm('node:dns');
  expect(harness.require('node:dns').loaded).toBe('node:dns');
  expect(harness.markerCalls).toEqual([
    [
      0,
      dnsSourceId,
      'node:dns',
      'ibex-capsec-authenticated-builtin-source-complete-v1',
    ],
  ]);
  expect(harness.receipts).toEqual(harness.markerCalls);

  expect(harness.require('node:dns').loaded).toBe('node:dns');
  expect(harness.markerCalls).toHaveLength(1);
  expect(harness.receipts).toHaveLength(1);
});

test('authenticated builtin completion receipt rejects throws and cached wrong aliases', () => {
  const sharedSourceId = 'ibex-source-id-v1:bm9kZV9kbnNfcHJvbWlzZXM';
  const aliasHarness = makeAuthenticatedReceiptHarness({
    'dns/promises': {
      source: "module.exports = { loaded: 'dns/promises' };",
      sourceId: sharedSourceId,
    },
    'node:dns/promises': {
      source: "module.exports = { loaded: 'dns/promises' };",
      sourceId: sharedSourceId,
    },
  });
  aliasHarness.arm('node:dns/promises');
  expect(aliasHarness.require('dns/promises').loaded).toBe('dns/promises');
  expect(aliasHarness.markerCalls).toHaveLength(1);
  expect(aliasHarness.markerCalls[0]?.[2]).toBe('dns/promises');
  expect(aliasHarness.receipts).toHaveLength(0);
  expect(aliasHarness.require('node:dns/promises').loaded).toBe('dns/promises');
  expect(aliasHarness.markerCalls).toHaveLength(1);
  expect(aliasHarness.receipts).toHaveLength(0);

  const throwingHarness = makeAuthenticatedReceiptHarness({
    'node:throwing': {
      source: "throw new Error('body failed before completion');",
      sourceId: 'ibex-source-id-v1:dGhyb3dpbmc',
    },
  });
  throwingHarness.arm('node:throwing');
  expect(() => throwingHarness.require('node:throwing')).toThrow(
    /body failed before completion/,
  );
  expect(throwingHarness.markerCalls).toHaveLength(0);
  expect(throwingHarness.receipts).toHaveLength(0);
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

test('an unrelated public require does not eagerly initialize stream compatibility', () => {
  const require = makeRequire();
  expect(() => require('internal/streams/not-declared')).toThrow();
  expect((require as any).sandbox.__streamEvals).toBeUndefined();
  require('events');
  expect((require as any).sandbox.__streamEvals).toBeUndefined();
  expect(require('stream').evals).toBe(1);
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
