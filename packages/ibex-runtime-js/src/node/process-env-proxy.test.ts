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

test('toJSON reflects writes and deletes with correct precedence', () => {
  stubNativeEnv({ TZ: 'America/New_York', PATH: '/usr/bin' });
  const env = createEnvProxy();

  env.TZ = 'UTC';
  delete env.PATH;

  const json = (env as any).toJSON();
  expect(json.TZ).toBe('UTC');
  expect('PATH' in json).toBe(false);
});
