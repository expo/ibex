import { expect, test } from 'bun:test';

test('bootstrap compatibility controls are fixed, closed, and captured once', async () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, '__exactCompatModes');
  const priorSetEnv = Object.getOwnPropertyDescriptor(globalThis, '__exactSetEnv');
  try {
    Object.defineProperty(globalThis, '__exactSetEnv', {
      value: () => undefined,
      configurable: true,
    });
    const modes = ['bun', 'fixture', 'fixture:bun'];
    Object.defineProperty(globalThis, '__exactCompatModes', {
      value: modes,
      writable: true,
      configurable: true,
    });
    const valid = await import('./host-inputs.ts?bootstrap-control-valid');

    modes.length = 0;
    delete (globalThis as { __exactCompatModes?: unknown }).__exactCompatModes;
    expect(valid.readBootstrapCompatibilityControl('EXACT_COMPAT_BUN')).toBe('1');
    expect(valid.readBootstrapCompatibilityControl('EXACT_COMPAT_TEST')).toBe('1');
    expect(valid.readBootstrapCompatibilityControl('EXACT_TEST_SECTION')).toBe('bun');
    expect(valid.readBootstrapCompatibilityControl('HOST_SECRET')).toBeUndefined();
    expect(valid.isBootstrapCompatibilityControlFixed('EXACT_COMPAT_BUN')).toBe(true);
    expect(valid.isBootstrapCompatibilityControlFixed('EXACT_COMPAT_TEST')).toBe(true);
    expect(valid.isBootstrapCompatibilityControlFixed('EXACT_TEST_SECTION')).toBe(true);
    expect(valid.isBootstrapCompatibilityControlFixed('HOST_SECRET')).toBe(false);

    Object.defineProperty(globalThis, '__exactCompatModes', {
      value: ['fixture:bun'],
      writable: true,
      configurable: true,
    });
    const invalid = await import('./host-inputs.ts?bootstrap-control-invalid');
    expect(invalid.readBootstrapCompatibilityControl('EXACT_COMPAT_TEST')).toBeUndefined();
    expect(invalid.readBootstrapCompatibilityControl('EXACT_TEST_SECTION')).toBeUndefined();
    expect(invalid.isBootstrapCompatibilityControlFixed('EXACT_COMPAT_TEST')).toBe(true);

    Object.defineProperty(globalThis, '__exactCompatModes', {
      value: null,
      writable: true,
      configurable: true,
    });
    const missing = await import('./host-inputs.ts?bootstrap-control-missing');
    expect(missing.readBootstrapCompatibilityControl('EXACT_COMPAT_BUN')).toBeUndefined();
    expect(missing.isBootstrapCompatibilityControlFixed('EXACT_COMPAT_BUN')).toBe(true);

    delete (globalThis as { __exactSetEnv?: unknown }).__exactSetEnv;
    Object.defineProperty(globalThis, '__exactCompatModes', {
      value: [],
      writable: true,
      configurable: true,
    });
    const unarmed = await import('./host-inputs.ts?bootstrap-control-unarmed');
    expect(unarmed.isBootstrapCompatibilityControlFixed('EXACT_COMPAT_TEST')).toBe(false);
  } finally {
    if (prior) Object.defineProperty(globalThis, '__exactCompatModes', prior);
    else delete (globalThis as { __exactCompatModes?: unknown }).__exactCompatModes;
    if (priorSetEnv) Object.defineProperty(globalThis, '__exactSetEnv', priorSetEnv);
    else delete (globalThis as { __exactSetEnv?: unknown }).__exactSetEnv;
  }
});

test('armed false compatibility cannot fall through in runtime or raw bootstrap consumers', () => {
  const headersUrl = new URL(
    '../fetch/Headers.ts?bootstrap-fixed-false-subprocess',
    import.meta.url,
  ).href;
  const processUrl = new URL(
    '../node/process.ts?bootstrap-fixed-false-process-identity',
    import.meta.url,
  ).href;
  const compatPolyfillsUrl = new URL(
    '../../../../src/engine/bootstrap/compat-polyfills.js?bootstrap-fixed-false-raw',
    import.meta.url,
  ).href;
  const probe = Bun.spawnSync({
    cmd: [
      process.execPath,
      '-e',
      `
Object.defineProperty(globalThis, '__exactSetEnv', { value() {}, configurable: true });
Object.defineProperty(globalThis, '__exactCompatModes', { value: [], configurable: true });
const fallbackReads = [];
Object.defineProperty(globalThis, '__exactHostEnv', {
  configurable: true,
  value: new Proxy(
    { EXACT_COMPAT_TEST: '1', EXACT_TEST_SECTION: 'bun' },
    { get(target, key) { fallbackReads.push(String(key)); return target[key]; } },
  ),
});
const { Headers } = await import(${JSON.stringify(headersUrl)});
const rows = Array.from(new Headers({ z: '2', 'set-cookie': 'v=1', a: '1' }).entries());
const expected = [['a', '1'], ['set-cookie', 'v=1'], ['z', '2']];
if (JSON.stringify(rows) !== JSON.stringify(expected)) throw new Error(JSON.stringify(rows));
const { process: isolatedProcess } = await import(${JSON.stringify(processUrl)});
for (const key of ['bun', 'v8', 'uv', 'openssl', 'modules']) {
  if (Object.prototype.hasOwnProperty.call(isolatedProcess.versions, key)) {
    throw new Error('mutable fallback changed process identity: ' + key);
  }
}
if (fallbackReads.length !== 0) throw new Error('mutable fallback reads: ' + fallbackReads.join(','));

globalThis.process.env.EXACT_COMPAT_TEST = '1';
globalThis.process.env.EXACT_TEST_SECTION = 'bun';
const required = [];
Object.defineProperty(globalThis, '__exactRequire', {
  configurable: true,
  value(id) {
    required.push(id);
    return require(id);
  },
});
delete globalThis.ok;
delete globalThis.failed;
delete globalThis.badly;
await import(${JSON.stringify(compatPolyfillsUrl)});
if (typeof globalThis.ok === 'function' || typeof globalThis.failed === 'function' || typeof globalThis.badly === 'function') {
  throw new Error('raw compat bootstrap installed fixture globals from mutable environment');
}
if (required.includes('bun:test')) {
  throw new Error('raw compat bootstrap loaded bun:test from mutable environment');
}
`,
    ],
    stdout: 'pipe',
    stderr: 'pipe',
  });
  expect(new TextDecoder().decode(probe.stderr)).toBe('');
  expect(probe.exitCode).toBe(0);
});
