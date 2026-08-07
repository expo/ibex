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
const nodeHttp = require('node:http');

const realPlatform = process.platform;
const realHttpRequest = httpMod.request;
const realFetch = globalThis.fetch;

function setPlatform(platform: string) {
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
}

describe('https transport routing (ENG-23716)', () => {
  test('does not forward adapter-materialized primordial properties under lockdown', () => {
    const modulePath = require.resolve('../../../src/builtins/https.js');
    const prototypeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'toString')!;
    const httpDescriptor = Object.getOwnPropertyDescriptor(nodeHttp, 'toString');
    try {
      Object.defineProperty(nodeHttp, 'toString', {
        value: Object.prototype.toString,
        writable: false,
        enumerable: false,
        configurable: true,
      });
      Object.defineProperty(Object.prototype, 'toString', {
        ...prototypeDescriptor,
        writable: false,
      });
      delete (require as any).cache[modulePath];
      const lockedDownHttps = require(modulePath);
      expect(Object.hasOwn(lockedDownHttps, 'toString')).toBe(false);
    } finally {
      Object.defineProperty(Object.prototype, 'toString', prototypeDescriptor);
      if (httpDescriptor === undefined) delete nodeHttp.toString;
      else Object.defineProperty(nodeHttp, 'toString', httpDescriptor);
      delete (require as any).cache[modulePath];
    }
  });

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

  test('win32: agent constructed with ca, option-free request takes the socket path (ENG-23728)', () => {
    const pinned = new https.Agent({ ca: ['CERT'] });
    https.request({ hostname: 'localhost', port: 4443, agent: pinned }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: agent constructed with rejectUnauthorized=false, option-free request takes the socket path (ENG-23728)', () => {
    const lax = new https.Agent({ rejectUnauthorized: false });
    https.request({ hostname: 'localhost', port: 4443, agent: lax }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: agent constructed without socket options keeps the WinHTTP fetch fast path (ENG-23728)', () => {
    const plain = new https.Agent({ keepAlive: true, maxSockets: 4 });
    const req = https.request({ hostname: 'example.com', agent: plain }, () => {});
    expect(httpRequestCalls.length).toBe(0);
    req.destroy();
  });

  test('win32: an overridden custom-agent createConnection takes the socket path', () => {
    const custom = new https.Agent({ keepAlive: true });
    const inherited = custom.createConnection;
    custom.createConnection = function (this: any, ...args: any[]) {
      return inherited.apply(this, args);
    };
    https.request({ hostname: 'localhost', port: 4443, agent: custom }, () => {});
    expect(httpRequestCalls.length).toBe(1);
  });

  test('win32: request createConnection takes the socket path', () => {
    https.request(
      { hostname: 'localhost', port: 4443, createConnection: () => ({}) },
      () => {},
    );
    expect(httpRequestCalls.length).toBe(1);
  });

  test.each([
    ['auth', { auth: 'alice:secret' }],
    ['timeout', { timeout: 50 }],
    ['signal', { signal: new AbortController().signal }],
    ['array headers', { headers: [['X-Test', 'one']] }],
  ])('win32: %s forces the option-preserving socket path', (_name, extra) => {
    https.request({ hostname: 'localhost', port: 4443, ...extra }, () => {});
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
