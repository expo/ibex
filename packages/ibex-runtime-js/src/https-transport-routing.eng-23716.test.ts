// ENG-23716 — https transport selection on Windows. Requests carrying
// socket-transport options (ca, rejectUnauthorized, cert/key, servername, ...)
// must route through http.request -> Agent.createConnection -> tls.connect
// even on the default agent; only option-free requests may take the
// WinHTTP-backed fetch fast path. The old predicate's
// `|| options.agent === globalAgent` disjunct sent default-agent requests to
// fetch regardless, silently dropping the options (WinHTTP error 12175).
// Run with: bun test.

import { expect, test, describe, beforeEach, afterEach } from 'bun:test';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const httpMod = require('node:http');
const https = require('../../../src/builtins/https.js');

const realPlatform = process.platform;
const realHttpRequest = httpMod.request;
const realFetch = globalThis.fetch;

function setPlatform(platform: string) {
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
}

describe('https transport routing (ENG-23716)', () => {
  let httpRequestCalls: any[];

  beforeEach(() => {
    httpRequestCalls = [];
    // https.js captured the node:http module object at load; patching the
    // shared module object is visible to it.
    httpMod.request = (...args: any[]) => {
      httpRequestCalls.push(args);
      return { end: () => {}, on: () => {}, setTimeout: () => {} };
    };
    // The fetch path only invokes fetch on req.end(); presence is what the
    // predicate checks.
    (globalThis as any).fetch = () => new Promise(() => {});
    setPlatform('win32');
  });

  afterEach(() => {
    httpMod.request = realHttpRequest;
    (globalThis as any).fetch = realFetch;
    setPlatform(realPlatform);
  });

  test('win32: ca option on the default agent takes the socket path', () => {
    https.request({ hostname: 'localhost', port: 4443, ca: ['CERT'] }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: rejectUnauthorized=false on the default agent takes the socket path', () => {
    https.request({ hostname: 'localhost', port: 4443, rejectUnauthorized: false }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: explicit globalAgent with socket options takes the socket path', () => {
    https.request(
      { hostname: 'localhost', port: 4443, agent: https.globalAgent, servername: 'x.test' },
      () => {},
    );
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: option-free request keeps the WinHTTP fetch fast path', () => {
    const req = https.request({ hostname: 'example.com' }, () => {});
    expect(httpRequestCalls.length).toBe(0);
    // Fetch-path request object, not the http.request stub.
    expect(req.writable).toBe(true);
    req.destroy();
  });

  test('non-win32: ca option takes the socket path', () => {
    setPlatform('darwin');
    https.request({ hostname: 'localhost', port: 4443, ca: ['CERT'] }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('non-win32: option-free request also takes the socket path (fetch path is Windows-only)', () => {
    setPlatform('darwin');
    https.request({ hostname: 'example.com' }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });
});
