// @ref LLP 0023#72-the-structured-result-and-its-error-classes — native
// resolver failures retain only their stable public code at the JS boundary.

import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..', '..');
const generatedKeysSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'import-grant-keys.generated.js'),
  'utf8',
);
const loaderSource = readFileSync(
  path.join(repoRoot, 'src', 'engine', 'bootstrap', 'module-loader.js'),
  'utf8',
);

function requireFailure(record: Record<string, unknown>) {
  const resolve = () => JSON.stringify(record);
  const sandbox: any = {
    console,
    Promise,
    Symbol,
    process: { env: {}, argv: [] },
    __exactPinProcessStreams() {},
    __exactModuleResolve: resolve,
    __exactModuleResolveMeta: resolve,
    __exactNativeModuleResolve: resolve,
    __exactNativeModuleResolveMeta: resolve,
    __exactCaptureSessionStaticImport() {
      return { resolve, resolveMeta: resolve };
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(generatedKeysSource, sandbox, {
    filename: 'import-grant-keys.generated.js',
  });
  vm.runInContext(loaderSource, sandbox, { filename: 'module-loader.js' });
  try {
    sandbox.require('/project/payload.node');
  } catch (error) {
    return error as Error & { code?: string };
  }
  throw new Error('resolver failure returned instead of throwing');
}

test('public module-resolution records preserve their stable error code', () => {
  const error = requireFailure({
    schema: 'ibex/module-resolution/1',
    error: 'Module resolution failed',
    errorCode: 'ERR_IBEX_MODULE_RESOLUTION',
  });
  expect(error.message).toBe('Module resolution failed');
  expect(error.code).toBe('ERR_IBEX_MODULE_RESOLUTION');
  expect(Object.getOwnPropertyDescriptor(error, 'code')).toEqual({
    value: 'ERR_IBEX_MODULE_RESOLUTION',
    writable: true,
    enumerable: true,
    configurable: true,
  });
});

test('unversioned and malformed resolver codes are not copied to Error', () => {
  const unversioned = requireFailure({
    error: 'Module resolution failed',
    errorCode: 'ERR_IBEX_MODULE_RESOLUTION',
  });
  const malformed = requireFailure({
    schema: 'ibex/module-resolution/1',
    error: 'Module resolution failed',
    errorCode: 'ERR_ibex/host-path',
  });
  const unknown = requireFailure({
    schema: 'ibex/module-resolution/1',
    error: 'Module resolution failed',
    errorCode: 'ERR_IBEX_UNKNOWN_BUT_WELL_FORMED',
  });
  expect(unversioned.code).toBeUndefined();
  expect(malformed.code).toBeUndefined();
  expect(unknown.code).toBeUndefined();
});
