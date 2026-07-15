// Regression tests for ENG-23007: require.resolve must resolve via the
// metadata-only ABI bridge and never load/transpile the module body.
//
// `require.resolve(specifier)` only needs the resolved path, but the bootstrap
// loader used to call `__exactModuleResolve`, whose native side reads the whole
// target off disk, transpiles it, JSON-escapes the entire body, and hands it to
// JS — for the loader to keep only `rec.path` and throw the source away. The fix
// adds a metadata-only bridge (`__exactModuleResolveMeta` ->
// `ex_host_module_resolve_meta`) and points both `require.resolve` paths at it,
// falling back to the full bridge only when the meta binding is unavailable.
//
// The loader is the first bootstrap script and self-installs
// `globalThis.require` against native globals, so we drive it in a vm context
// with mock resolvers and assert require.resolve routes to the metadata bridge.

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

const RESOLVED_PATH = '/virtual/pkg/broken.ts';
const TYPED_RESOLVED_PATH = '/project/pkg/broken.ts';
const RESOLVED_LOGICAL_PATH = {
  schema: 'ibex/logical-path/1',
  sessionHandle: 'mrs0000000000000001',
  virtualPath: TYPED_RESOLVED_PATH,
  logicalPath: {
    root: 'project',
    components: [
      { encoding: 'utf8', value: 'pkg' },
      { encoding: 'utf8', value: 'broken.ts' },
    ],
    hostBound: null,
  },
  bindingOwner: null,
};
// The specifier under test. The loader also resolves builtins during its own
// bootstrap, so assertions target this specifier rather than exact call lists.
const TARGET = './broken';

type Calls = { meta: string[]; full: string[] };

function makeSandbox(opts: { withMeta: boolean }): { sandbox: any; calls: Calls } {
  const calls: Calls = { meta: [], full: [] };
  const sandbox: any = {};
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.Symbol = Symbol;
  sandbox.Promise = Promise;
  sandbox.__exactPinProcessStreams = function () {};

  // Metadata-only bridge: returns the resolved path with NO `source` — it never
  // reads or transpiles the module body.
  if (opts.withMeta) {
    sandbox.__exactModuleResolveMeta = function (specifier: string) {
      calls.meta.push(specifier);
      return JSON.stringify({
        schema: 'ibex/module-resolution/1',
        id: '/private/host/pkg/broken.ts',
        kind: 'esm',
        path: RESOLVED_LOGICAL_PATH,
      });
    };
  }

  // Full resolver: reads + transpiles the body (the native side returns `source`).
  // The loader also drives this bridge for its own bootstrap builtins, so it must
  // stay benign for other specifiers; for OUR specifier under the meta config it
  // throws — as if the body had a syntax error that fails transpile — so a
  // regression that routes require.resolve('./broken') here fails loudly.
  sandbox.__exactModuleResolve = function (specifier: string) {
    calls.full.push(specifier);
    if (opts.withMeta && specifier === TARGET) {
      throw new Error('full resolver (load+transpile) must not run for require.resolve');
    }
    return JSON.stringify({
      id: specifier,
      kind: 'esm',
      path: RESOLVED_PATH,
      source: 'export const x = 1;',
    });
  };

  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  if (typeof sandbox.require !== 'function' || typeof sandbox.require.resolve !== 'function') {
    throw new Error('loader did not install globalThis.require.resolve');
  }
  return { sandbox, calls };
}

test('require.resolve uses the metadata-only bridge and never loads/transpiles the body', () => {
  const { sandbox, calls } = makeSandbox({ withMeta: true });
  const resolved = sandbox.require.resolve(TARGET);
  expect(resolved).toBe(TYPED_RESOLVED_PATH);
  expect(calls.meta).toContain(TARGET);
  // The full read+transpile bridge must be untouched by require.resolve for the
  // target. If the body had a syntax error, require.resolve still succeeds
  // (Node semantics) because resolution never parses the body.
  expect(calls.full).not.toContain(TARGET);
});

test('require.resolve falls back to the full bridge when the meta binding is absent', () => {
  const { sandbox, calls } = makeSandbox({ withMeta: false });
  const resolved = sandbox.require.resolve(TARGET);
  expect(resolved).toBe(RESOLVED_PATH);
  expect(calls.full).toContain(TARGET);
  // No meta binding was installed, so it can never have been consulted.
  expect(calls.meta).toEqual([]);
});
