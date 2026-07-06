// Regression tests for ENG-23034 (src/builtins/net.js):
//   1. Read-side highWaterMark backpressure: the native poll loop must stop
//      draining the kernel buffer into _readBuffer once it reaches
//      readableHighWaterMark and nobody is flowing, and resume once read()
//      drains it back under the watermark.
//   2. Bytes buffered before the first 'data' listener attaches (e.g. an
//      accepted connection whose consumer does an async step before
//      `sock.on('data', ...)`) must be flushed to that listener, not
//      stranded.
//   3. The StringDecoder's EOF-flush trailing chunk must be delivered
//      exactly once (routed through the same flowing/paused branch as every
//      other chunk), not appended to _readBuffer AND emitted as 'data'.
//   4. 'connect'/'ready' must not fire after _drainWriteQueue() destroys the
//      socket synchronously (e.g. an immediately-failed queued write).
//   5. A second connect() while one is still in flight must be rejected
//      (ERR_SOCKET_CONNECTING), not silently start a second native connect.
//
// net.js captures `_hasTcp`/`_hasAsyncTcpConnect` as free globals at load
// time, so the relevant __exact* stubs (forcing the synchronous connect
// path) are installed before the first require. Individual per-call
// behavior is reassigned per test via beforeEach.

import { test, expect, describe, beforeEach } from 'bun:test';

const g = globalThis as any;

g.__exactTcpConnect = () => 1;
g.__exactTcpConnectStart = undefined;
g.__exactTcpConnectPoll = undefined;
g.__exactTcpRead = () => Buffer.alloc(0);
g.__exactTcpWrite = () => 0;
g.__exactTcpClose = () => {};

// eslint-disable-next-line @typescript-eslint/no-var-requires
const net = require('../../../src/builtins/net.js');

beforeEach(() => {
  g.__exactTcpConnect = () => 1;
  g.__exactTcpRead = () => Buffer.alloc(0);
  g.__exactTcpWrite = () => 0;
  g.__exactTcpClose = () => {};
});

describe('read-side backpressure (ENG-23034 #1)', () => {
  test('poll loop stops draining past readableHighWaterMark; read() resumes it', async () => {
    let reads = 0;
    const CHUNK = Buffer.alloc(4096, 0x41);
    g.__exactTcpRead = () => {
      reads++;
      return CHUNK; // always more data available (never signals EAGAIN)
    };
    const s = new net.Socket({ _handle: 777001, readableHighWaterMark: 8192 });
    try {
      await new Promise((r) => setTimeout(r, 50));
      // Exactly 2 chunks (4096 * 2 = 8192) then the loop gates at the watermark.
      expect(s._readBufferLength).toBe(8192);
      expect(s._readBackpressured).toBe(true);
      const readsAtGate = reads;

      await new Promise((r) => setTimeout(r, 50));
      expect(reads).toBe(readsAtGate); // no further kernel reads while gated
      expect(s._readBufferLength).toBe(8192); // buffer did not grow past the watermark

      const chunk = s.read();
      expect(Buffer.isBuffer(chunk)).toBe(true);
      expect(chunk.length).toBe(8192);
      expect(s._readBufferLength).toBe(0);
      expect(s._readBackpressured).toBe(false);

      await new Promise((r) => setTimeout(r, 50));
      expect(s._readBufferLength).toBe(8192); // polling resumed and refilled
    } finally {
      s.destroy();
    }
  });
});

describe('pre-listener buffered bytes are flushed, not stranded (ENG-23034 #2)', () => {
  test('bytes read before the first data listener attaches are delivered on attach', async () => {
    let calls = 0;
    g.__exactTcpRead = () => {
      calls++;
      return calls === 1 ? Buffer.from('HELLO') : Buffer.alloc(0);
    };
    const s = new net.Socket({ _handle: 777002 });
    try {
      await new Promise((r) => setTimeout(r, 40));
      expect(s._readBufferLength).toBe(5); // buffered; no listener yet

      const received: Buffer[] = [];
      s.on('data', (c: Buffer) => received.push(c));

      await new Promise((r) => setTimeout(r, 10)); // let the scheduled flush run
      expect(Buffer.concat(received).toString()).toBe('HELLO');
      expect(s._readBufferLength).toBe(0);
    } finally {
      s.destroy();
    }
  });
});

describe('EOF decoder trailing chunk delivered exactly once (ENG-23034 #3)', () => {
  test('flowing consumer sees the flushed trailing chunk once; nothing left in _readBuffer', () => {
    const s = new net.Socket();
    s.setEncoding('utf8');
    const chunks: string[] = [];
    s.on('data', (c: string) => chunks.push(c));
    // '€' is E2 82 AC in utf-8; deliver only the first two bytes then EOF so
    // the StringDecoder has an incomplete trailing sequence to flush.
    s.push(Buffer.from([0xe2, 0x82]));
    s.push(null);
    expect(chunks.length).toBe(1);
    expect(s._readBufferLength).toBe(0); // not also retained
    expect(s.read()).toBe(null); // a later read() must not re-deliver it
  });
});

describe('connect() suppresses connect/ready after a destroy from the write-queue drain (ENG-23034 #4)', () => {
  test('an immediately-failing queued write destroys the socket before connect finishes', async () => {
    g.__exactTcpConnect = () => 999;
    g.__exactTcpWrite = () => {
      throw new Error('write failed');
    };
    const s = net.connect({ port: 12345, host: '127.0.0.1' });
    s.write(Buffer.alloc(64, 1));

    const seenEvents: string[] = [];
    s.on('connect', () => seenEvents.push('connect'));
    s.on('ready', () => seenEvents.push('ready'));
    s.on('error', () => seenEvents.push('error'));

    const hadError: any = await new Promise((resolve) => {
      s.on('close', (err: boolean) => resolve(err));
    });
    expect(hadError).toBe(true);
    expect(seenEvents).not.toContain('connect');
    expect(seenEvents).not.toContain('ready');
    expect(seenEvents[0]).toBe('error');
    expect(s.destroyed).toBe(true);
  });
});

describe('overlapping connect() calls are rejected (ENG-23034 #5)', () => {
  test('calling connect() again while one is in flight throws ERR_SOCKET_CONNECTING', () => {
    g.__exactTcpConnect = () => 1000;
    const s = net.connect({ port: 555, host: '127.0.0.1' });
    try {
      expect(s.connecting).toBe(true);
      let caught: any = null;
      try {
        s.connect({ port: 556, host: '127.0.0.1' });
      } catch (e) {
        caught = e;
      }
      expect(caught).not.toBeNull();
      expect(caught.code).toBe('ERR_SOCKET_CONNECTING');
    } finally {
      s.destroy();
    }
  });
});
