import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

function evaluateBuiltin(
  relativePath: string,
  wiredRequire: (specifier: string) => unknown,
): any {
  const filename = resolve(repoRoot, relativePath);
  const source = readFileSync(filename, 'utf8');
  const module = { exports: {} as any };
  const wrapper = new Function(
    'exports',
    'require',
    'module',
    '__filename',
    '__dirname',
    source,
  );
  wrapper(module.exports, wiredRequire, module, filename, dirname(filename));
  return module.exports;
}

describe('manifest builtin dependency window', () => {
  test('util captures assert during evaluation and never resolves it from an exported call', () => {
    let evaluating = true;
    let resolutions = 0;
    const assertModule = {
      _isDeepStrictEqual(left: unknown, right: unknown) {
        return JSON.stringify(left) === JSON.stringify(right);
      },
    };
    const util = evaluateBuiltin('src/builtins/util.js', (specifier) => {
      expect(evaluating).toBe(true);
      expect(specifier).toBe('assert');
      resolutions += 1;
      return assertModule;
    });
    evaluating = false;

    expect(resolutions).toBe(1);
    expect(util.isDeepStrictEqual({ ibex: [1] }, { ibex: [1] })).toBe(true);
    expect(resolutions).toBe(1);
  });

  test('timers captures timers/promises before exported accessors can escape', () => {
    let evaluating = true;
    let resolutions = 0;
    const promisesModule = {
      setTimeout() {},
      setImmediate() {},
    };
    const timers = evaluateBuiltin('src/builtins/timers.js', (specifier) => {
      expect(evaluating).toBe(true);
      expect(specifier).toBe('timers/promises');
      resolutions += 1;
      return promisesModule;
    });
    evaluating = false;

    expect(resolutions).toBe(1);
    expect(timers.promises).toBe(promisesModule);
    expect(timers.setTimeout[Symbol.for('nodejs.util.promisify.custom')]).toBe(
      promisesModule.setTimeout,
    );
    expect(timers.setImmediate[Symbol.for('nodejs.util.promisify.custom')]).toBe(
      promisesModule.setImmediate,
    );
    expect(resolutions).toBe(1);
  });
});
