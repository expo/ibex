import { test, expect, afterAll } from 'bun:test';

// Regression tests for ENG-22960 (src/builtins/net.js):
//   1. Received data must not be retained forever in _readBuffer once a chunk
//      has been delivered to a flowing ('data') consumer, and read() must not
//      double-deliver bytes already emitted as 'data'.
//   2. A failed connect must destroy the socket, so 'error' is followed by
//      'close'(hadError=true) and socket.destroyed becomes true (Node parity).
//
// The builtin references native host functions as free globals and captures
// `_hasTcp = typeof __exactTcpConnect === 'function'` at load time, so the
// mocks are installed before the module is required. __exactTcpConnect throws
// to drive the terminal connect-failure path without touching the network.

const prevConnect = (globalThis as any).__exactTcpConnect;
const prevClose = (globalThis as any).__exactTcpClose;
const prevRead = (globalThis as any).__exactTcpRead;

(globalThis as any).__exactTcpConnect = function () {
  throw new Error('connect failed for 10.0.0.1:80');
};
(globalThis as any).__exactTcpClose = function () {};
(globalThis as any).__exactTcpRead = function () {
  return Buffer.alloc(0);
};

// eslint-disable-next-line @typescript-eslint/no-var-requires
const net = require('../../../src/builtins/net.js');

afterAll(() => {
  (globalThis as any).__exactTcpConnect = prevConnect;
  (globalThis as any).__exactTcpClose = prevClose;
  (globalThis as any).__exactTcpRead = prevRead;
});

// error/close/lookup all resolve together (close is scheduled on the tick after
// error), so attach every listener synchronously and settle on the terminal
// 'close'.
function collectUntilClose(s: any) {
  const seen: { error: any; close: boolean | undefined; lookup: any[] } = {
    error: null,
    close: undefined,
    lookup: [],
  };
  return new Promise<typeof seen>((resolve) => {
    s.on('error', (e: any) => {
      seen.error = e;
    });
    s.on('lookup', (...a: any[]) => {
      seen.lookup.push(a);
    });
    s.on('close', (hadError: boolean) => {
      seen.close = hadError;
      resolve(seen);
    });
  });
}

test('flowing socket does not retain received data and read() does not double-deliver', () => {
  const s = new net.Socket();
  const received: Buffer[] = [];
  s.on('data', (c: Buffer) => received.push(c)); // attaching 'data' => flowing
  for (let i = 0; i < 50; i++) s.push(Buffer.from('chunk' + i));
  expect(Buffer.concat(received).length).toBeGreaterThan(0);
  expect(s._readBufferLength).toBe(0); // nothing retained
  expect(s._readBuffer.length).toBe(0);
  expect(s.read()).toBe(null); // already-emitted bytes are not re-delivered
});

test('paused socket (no data listener) buffers for read()', () => {
  const s = new net.Socket();
  s.push(Buffer.from('abc'));
  s.push(Buffer.from('def'));
  expect(s._readBufferLength).toBe(6);
  const out = s.read();
  expect(Buffer.isBuffer(out)).toBe(true);
  expect(out.toString()).toBe('abcdef');
  expect(s._readBufferLength).toBe(0);
});

test('flowing socket with setEncoding delivers strings and retains nothing', () => {
  const s = new net.Socket();
  s.setEncoding('utf8');
  const received: string[] = [];
  s.on('data', (c: string) => received.push(c));
  s.push(Buffer.from('hello '));
  s.push(Buffer.from('world'));
  expect(received.join('')).toBe('hello world');
  expect(s._readBufferLength).toBe(0);
});

test('connect that never routes: error then close(hadError=true) and destroyed=true', async () => {
  const s = net.connect({ port: 80, host: '10.0.0.1' });
  const seen = await collectUntilClose(s);
  expect(seen.error).toBeInstanceOf(Error);
  expect(seen.close).toBe(true);
  expect(s.destroyed).toBe(true);
});

test('blockList rejection destroys the socket and emits close(true)', async () => {
  const s = net.connect({ port: 80, host: '10.0.0.1', blockList: { check: () => true } });
  const seen = await collectUntilClose(s);
  expect(seen.error.code).toBe('ERR_IP_BLOCKED');
  expect(seen.close).toBe(true);
  expect(s.destroyed).toBe(true);
});

test('DNS lookup failure emits lookup(err), error, then close(true), destroyed=true', async () => {
  const s = net.connect({
    port: 80,
    host: 'example.invalid',
    lookup: (_host: string, _opts: any, cb: Function) => cb(new Error('EAI_AGAIN')),
  });
  const seen = await collectUntilClose(s);
  expect(seen.error).toBeInstanceOf(Error);
  expect(seen.close).toBe(true);
  expect(s.destroyed).toBe(true);
  expect(seen.lookup.length).toBe(1);
  expect(seen.lookup[0][0]).toBeInstanceOf(Error);
});
