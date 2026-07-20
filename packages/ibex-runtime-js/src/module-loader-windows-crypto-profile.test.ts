// Windows uses a reduced native crypto bridge, but the public Node builtin is
// still the shared crypto.js implementation. A historical loader shortcut
// replaced it with a tiny target-only object, bypassing validation, constants,
// portable prime/DH code, and explicit unsupported-operation errors.

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

test('Windows crypto resolves the authenticated shared builtin', () => {
  const sandbox: any = {
    console,
    process: { platform: 'win32' },
    Promise,
    Symbol,
    __exactPinProcessStreams() {},
    __exactModuleResolve(specifier: string) {
      if (specifier !== 'crypto' && specifier !== 'node:crypto') {
        return JSON.stringify({ error: `Module not found: ${specifier}` });
      }
      return JSON.stringify({
        id: specifier,
        kind: 'builtin',
        sourceId: 'builtin:crypto',
        source:
          'module.exports = {' +
          ' constants: { RSA_PKCS1_PSS_PADDING: 6 },' +
          ' checkPrimeSync: function () { return "shared-builtin"; }' +
          ' };',
      });
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });

  const crypto = sandbox.require('node:crypto');
  expect(crypto.constants.RSA_PKCS1_PSS_PADDING).toBe(6);
  expect(crypto.checkPrimeSync()).toBe('shared-builtin');
});
