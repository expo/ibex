// ENG-22976 — the process.env proxy let native values shadow JS writes and
// deletes: the get trap consulted native first (so a write never won), set()
// only persisted into a cache that ownKeys/toJSON re-cloned away, and delete
// re-fetched the host value on the next read (so deletes silently failed).
// These tests drive createEnvProxy against a stubbed native env to prove that
// writes and deletes now stick while native still overrides the seeded default.
// Run with: bun test.

import { afterEach, expect, test } from 'bun:test';
import { createEnvProxy } from './process.ts';

const g = globalThis as Record<string, any>;

function stubNativeEnv(env: Record<string, string>): void {
  g.__exactGetAllEnv = () => ({ ...env });
  g.__exactGetEnv = (key: string) => (Object.prototype.hasOwnProperty.call(env, key) ? env[key] : undefined);
}

afterEach(() => {
  delete g.__exactGetAllEnv;
  delete g.__exactGetEnv;
  delete g.__exactSetEnv;
  delete g.__exactGetCwd;
  delete g.__exactSetCwd;
});

test('cwd retains its sealed bridge, reauthorizes every read, and propagates revocation', async () => {
  let authorized = true;
  let reads = 0;
  g.__exactGetCwd = () => {
    reads += 1;
    if (!authorized) {
      throw new Error('EACCES: cwd: filesystem policy denied');
    }
    return '/project/private';
  };
  const { process: isolatedProcess } = await import('./process.ts?cwd-reauthorization-test');

  expect(isolatedProcess.cwd()).toBe('/project/private');
  delete g.__exactGetCwd;
  authorized = false;
  expect(() => isolatedProcess.cwd()).toThrow(/filesystem policy denied/);
  expect(reads).toBe(2);
});

test('absolute chdir can mutate without implicitly observing cwd', async () => {
  let reads = 0;
  const writes: string[] = [];
  g.__exactGetCwd = () => {
    reads += 1;
    throw new Error('EACCES: cwd: filesystem policy denied');
  };
  g.__exactSetCwd = (path: string) => {
    writes.push(path);
  };
  const { process: isolatedProcess } = await import('./process.ts?cwd-mutate-without-observe-test');

  isolatedProcess.chdir('/project/allowed');
  expect(writes).toEqual(['/project/allowed']);
  expect(reads).toBe(0);
});

test('failed chdir does not perform an extra cwd observation while mapping the error', async () => {
  let reads = 0;
  let writes = 0;
  g.__exactGetCwd = () => {
    reads += 1;
    throw new Error('EACCES: cwd: filesystem policy denied');
  };
  g.__exactSetCwd = () => {
    writes += 1;
    throw new Error('EACCES: chdir: filesystem policy denied');
  };
  const { process: isolatedProcess } = await import('./process.ts?cwd-mutate-denial-test');

  expect(() => isolatedProcess.chdir('/project/denied')).toThrow(/EACCES/);
  expect(writes).toBe(1);
  expect(reads).toBe(0);
});

test('a JS write wins over a native value and survives an ownKeys refresh', () => {
  stubNativeEnv({ TZ: 'America/New_York', PATH: '/usr/bin' });
  const env = createEnvProxy();

  expect(env.TZ).toBe('America/New_York'); // native visible before any write
  env.TZ = 'UTC';
  expect(env.TZ).toBe('UTC'); // write wins over native

  // Object.keys() triggers refreshNativeCache(); the override must not be wiped.
  const keys = Object.keys(env);
  expect(keys).toContain('TZ');
  expect(env.TZ).toBe('UTC');
});

test('deleting a native-backed key sticks and does not resurrect', () => {
  stubNativeEnv({ HTTP_PROXY: 'http://host:8080', PATH: '/usr/bin' });
  const env = createEnvProxy();

  expect(env.HTTP_PROXY).toBe('http://host:8080');
  delete env.HTTP_PROXY;

  expect(env.HTTP_PROXY).toBeUndefined();
  expect('HTTP_PROXY' in env).toBe(false);
  expect(Object.keys(env)).not.toContain('HTTP_PROXY');

  // A refresh (ownKeys) must not bring the host value back.
  Object.keys(env);
  expect(env.HTTP_PROXY).toBeUndefined();
});

test('re-setting a deleted key brings it back', () => {
  stubNativeEnv({});
  const env = createEnvProxy();

  env.FOO = 'bar';
  delete env.FOO;
  expect(env.FOO).toBeUndefined();

  env.FOO = 'baz';
  expect(env.FOO).toBe('baz');
  expect('FOO' in env).toBe(true);
  expect(Object.keys(env)).toContain('FOO');
});

test('native still overrides the seeded NODE_ENV default, but an explicit write wins', () => {
  stubNativeEnv({ NODE_ENV: 'production' });
  const env = createEnvProxy();

  // Native promotes NODE_ENV to production for release builds.
  expect(env.NODE_ENV).toBe('production');

  // But an explicit JS assignment still wins over native.
  env.NODE_ENV = 'test';
  expect(env.NODE_ENV).toBe('test');
});

test('the seeded default applies when native provides nothing', () => {
  stubNativeEnv({});
  const env = createEnvProxy();
  expect(env.NODE_ENV).toBe('development');
});

test('native capability denials are fail-closed without aborting bootstrap reads', () => {
  g.__exactGetAllEnv = () => {
    throw new Error('Permission denied: env:read authority required');
  };
  g.__exactGetEnv = () => {
    throw new Error('Permission denied: env:read authority required');
  };
  const env = createEnvProxy();

  expect(env.PATH).toBeUndefined();
  expect(env.NODE_ENV).toBe('development');
  expect(Object.keys(env)).toEqual(['NODE_ENV']);
});

test('a cached native value is reauthorized after capability revocation', () => {
  let authorized = true;
  let scalarReads = 0;
  g.__exactGetAllEnv = () => ({ CALLBACK_SECRET: 'secret' });
  g.__exactGetEnv = () => {
    scalarReads += 1;
    if (!authorized) {
      throw new Error('Permission denied: env:read authority required');
    }
    return 'secret';
  };
  const env = createEnvProxy();

  expect(env.CALLBACK_SECRET).toBe('secret');
  authorized = false;
  expect(env.CALLBACK_SECRET).toBeUndefined();
  expect(scalarReads).toBe(2);
});

test('toJSON reflects writes and deletes with correct precedence', () => {
  stubNativeEnv({ TZ: 'America/New_York', PATH: '/usr/bin' });
  const env = createEnvProxy();

  env.TZ = 'UTC';
  delete env.PATH;

  const json = (env as any).toJSON();
  expect(json.TZ).toBe('UTC');
  expect('PATH' in json).toBe(false);
});

test('the armed bridge keeps an empty base and isolates one shared facade by principal', () => {
  let principal = 'package-a';
  const overlays = new Map<string, Record<string, string>>();
  const readable = new Set(['package-a', 'package-b']);
  const writable = new Set(['package-a', 'package-b']);
  const currentOverlay = () => overlays.get(principal) ?? {};

  g.__exactGetEnv = (key: string) => {
    if (!readable.has(principal)) {
      throw new Error('Permission denied: env:read authority required');
    }
    return currentOverlay()[key];
  };
  g.__exactGetAllEnv = () => {
    if (!readable.has(principal)) return {};
    return { ...currentOverlay() };
  };
  g.__exactSetEnv = (key: string, value: string | undefined) => {
    if (!writable.has(principal)) {
      throw new Error('Permission denied: env:write authority required');
    }
    const next = { ...currentOverlay() };
    if (value === undefined) delete next[key];
    else next[key] = value;
    overlays.set(principal, next);
  };

  const env = createEnvProxy();
  expect((env as any).__exactEnvProxy).toBe(true);
  expect(Object.keys(env)).toEqual([]);
  expect(env.NODE_ENV).toBeUndefined();
  expect(() => Object.preventExtensions(env)).toThrow(TypeError);
  expect(() => Object.setPrototypeOf(env, null)).toThrow(TypeError);
  expect(Object.isExtensible(env)).toBe(true);
  expect(Object.getPrototypeOf(env)).toBe(Object.prototype);

  env.API_TOKEN = 'a-secret';
  expect(env.API_TOKEN).toBe('a-secret');

  principal = 'package-b';
  expect(env.API_TOKEN).toBeUndefined();
  expect(Object.keys(env)).toEqual([]);
  env.API_TOKEN = 'b-secret';
  expect(env.API_TOKEN).toBe('b-secret');

  principal = 'package-a';
  expect(env.API_TOKEN).toBe('a-secret');
  delete env.API_TOKEN;
  expect(env.API_TOKEN).toBeUndefined();

  principal = 'package-b';
  expect(env.API_TOKEN).toBe('b-secret');
});

test('armed env:write and env:read stay independent', () => {
  let canRead = false;
  let canWrite = true;
  let stored: string | undefined;
  g.__exactGetAllEnv = () => (canRead && stored !== undefined ? { API_TOKEN: stored } : {});
  g.__exactGetEnv = () => {
    if (!canRead) {
      throw new Error('Permission denied: env:read authority required');
    }
    return stored;
  };
  g.__exactSetEnv = (_key: string, value: string | undefined) => {
    if (!canWrite) {
      throw new Error('Permission denied: env:write authority required');
    }
    stored = value;
  };

  const env = createEnvProxy();
  env.API_TOKEN = 'write-only-value';
  expect(env.API_TOKEN).toBeUndefined();
  expect(Object.keys(env)).toEqual([]);

  canRead = true;
  expect(env.API_TOKEN).toBe('write-only-value');
  expect(Object.keys(env)).toEqual(['API_TOKEN']);

  canWrite = false;
  expect(() => {
    env.API_TOKEN = 'denied-replacement';
  }).toThrow(/env:write authority required/);
  expect(env.API_TOKEN).toBe('write-only-value');
});
