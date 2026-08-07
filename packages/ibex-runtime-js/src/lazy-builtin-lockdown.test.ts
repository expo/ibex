import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const builtinRoot = path.resolve(import.meta.dir, '../../../src/builtins');

describe('lazy builtins under primordial lockdown', () => {
  test('os installs function coercion methods as own properties', () => {
    const source = fs.readFileSync(path.join(builtinRoot, 'os.js'), 'utf8');
    const context = vm.createContext({ module: { exports: {} }, exports: {}, process: {} });
    vm.runInContext('Object.freeze(Object.prototype); Object.freeze(Function.prototype);', context);
    vm.runInContext(`"use strict";\n${source}`, context);

    const os = context.module.exports as { platform: unknown };
    expect(String(os.platform)).toBe('darwin');
    expect(Object.prototype.hasOwnProperty.call(os.platform, 'toString')).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(os.platform, 'valueOf')).toBe(true);
  });

  test('primordial-named compatibility methods use explicit own-property definitions', () => {
    for (const name of ['os.js', 'fs.js', 'stream.js', 'child-process.js']) {
      const source = fs.readFileSync(path.join(builtinRoot, name), 'utf8');
      expect(source).not.toMatch(/\b(?:fn|err|bytes)\.toString\s*=/u);
      expect(source).not.toMatch(/\bfn\.valueOf\s*=/u);
    }
  });
});
