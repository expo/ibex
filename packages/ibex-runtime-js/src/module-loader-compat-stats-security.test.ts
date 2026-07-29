// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
// — armed loader-lane proof is readable but cannot be forged by project code.

import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const repoRoot = path.resolve(import.meta.dir, '../../..');
const loaderSource = readFileSync(
  path.join(repoRoot, 'src/engine/bootstrap/module-loader.js'),
  'utf8',
);

test('armed compatibility-loader counters are live and immutable', () => {
  const builtinSource = 'module.exports = 42;';
  const resolve = (specifier: string) =>
    JSON.stringify(
      specifier === 'node:proof'
        ? {
            id: specifier,
            kind: 'builtin',
            source: builtinSource,
          }
        : { error: `Module not found: ${specifier}` },
    );
  const sandbox: Record<string, any> = {
    console,
    Promise,
    Symbol,
    __exactPinProcessStreams() {},
    __exactModuleResolve: resolve,
    __exactModuleResolveMeta: resolve,
    __exactCaptureSessionStaticImport() {
      return { resolve, resolveMeta: resolve };
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });

  const rootDescriptor = Object.getOwnPropertyDescriptor(
    sandbox,
    '__ibexCompatLoaderStats',
  );
  const stats = sandbox.__ibexCompatLoaderStats;
  expect(rootDescriptor).toMatchObject({
    writable: false,
    enumerable: false,
    configurable: false,
  });
  expect(Object.isFrozen(stats)).toBe(true);
  const sourceTransformsBefore = stats.sourceTransformCount;
  const dynamicCompilesBefore = stats.dynamicFunctionCompileCount;
  expect(Number.isSafeInteger(sourceTransformsBefore)).toBe(true);
  expect(Number.isSafeInteger(dynamicCompilesBefore)).toBe(true);

  expect(sandbox.require('node:proof')).toBe(42);
  expect(stats.sourceTransformCount).toBeGreaterThanOrEqual(
    sourceTransformsBefore,
  );
  expect(stats.dynamicFunctionCompileCount).toBe(dynamicCompilesBefore + 1);
  const sourceTransformsAfter = stats.sourceTransformCount;
  const dynamicCompilesAfter = stats.dynamicFunctionCompileCount;

  expect(() =>
    Object.defineProperty(stats, 'sourceTransformCount', { value: 999 }),
  ).toThrow();
  expect(() =>
    Object.defineProperty(sandbox, '__ibexCompatLoaderStats', {
      value: {
        sourceTransformCount: 999,
        dynamicFunctionCompileCount: 999,
      },
    }),
  ).toThrow();
  expect(stats.sourceTransformCount).toBe(sourceTransformsAfter);
  expect(stats.dynamicFunctionCompileCount).toBe(dynamicCompilesAfter);
});
