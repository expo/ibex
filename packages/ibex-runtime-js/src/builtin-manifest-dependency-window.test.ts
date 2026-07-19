import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const nodeRequire = createRequire(import.meta.url);

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

  test('child_process captures exported-call dependencies during evaluation', () => {
    let evaluating = true;
    let fsResolutions = 0;
    let pathResolutions = 0;
    let streamResolutions = 0;
    const resolveCalls: string[][] = [];
    const fakeFs = {
      existsSync() {
        return false;
      },
    };
    const fakePath = {
      isAbsolute(value: unknown) {
        return String(value).startsWith('/');
      },
      resolve(...parts: string[]) {
        resolveCalls.push(parts);
        return '/project/captured-entry.js';
      },
    };
    const childProcess = evaluateBuiltin(
      'src/builtins/child-process.js',
      (specifier) => {
        if (specifier === 'fs') {
          expect(evaluating).toBe(true);
          fsResolutions += 1;
          return fakeFs;
        }
        if (specifier === 'path') {
          expect(evaluating).toBe(true);
          pathResolutions += 1;
          return fakePath;
        }
        if (specifier === 'stream') {
          expect(evaluating).toBe(true);
          streamResolutions += 1;
          return nodeRequire(specifier);
        }
        if (specifier === 'internal/child_process') return {};
        return nodeRequire(specifier);
      },
    );
    evaluating = false;

    let capturedArgs: string[] | null = null;
    childProcess.spawn = (_command: string, args: string[]) => {
      capturedArgs = args;
      return { channel: null };
    };
    childProcess.fork('./entry.js', [], {
      execPath: '/bin/node',
      execArgv: [],
    });

    expect(resolveCalls).toEqual([['./entry.js']]);
    expect(capturedArgs).toEqual(['/project/captured-entry.js']);
    expect(fsResolutions).toBe(1);
    expect(pathResolutions).toBe(1);
    expect(streamResolutions).toBe(1);
  });

  test('fs streams retain the module value without resolving fs after evaluation', () => {
    let evaluating = true;
    const resolutions: string[] = [];
    const fs = evaluateBuiltin('src/builtins/fs.js', (specifier) => {
      expect(evaluating).toBe(true);
      resolutions.push(specifier);
      return nodeRequire(specifier);
    });
    evaluating = false;
    const evaluationResolutionCount = resolutions.length;

    expect(() =>
      fs.createReadStream('/unused', { fd: 0, autoClose: false }),
    ).not.toThrow();
    expect(resolutions).toHaveLength(evaluationResolutionCount);

    expect(() =>
      fs.createWriteStream('/unused', { fd: 1, autoClose: false }),
    ).not.toThrow();
    expect(resolutions).toHaveLength(evaluationResolutionCount);
  });
});
