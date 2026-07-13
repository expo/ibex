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
import { EventEmitter } from 'events';

const g = globalThis as any;
let currentNetPrincipal = 1;
let nextNetOwnerToken = 1;
const netOwnerTokens = new Map<number, number>();

g.__exactNetOwner = (action: string, token?: number) => {
  if (action === 'new') {
    const id = nextNetOwnerToken++;
    netOwnerTokens.set(id, currentNetPrincipal);
    return id;
  }
  if (token == null || netOwnerTokens.get(token) !== currentNetPrincipal) {
    throw new Error('net owner denied');
  }
  if (action === 'close') netOwnerTokens.delete(token);
};

g.__exactTcpConnect = () => 1;
g.__exactTcpConnectStart = undefined;
g.__exactTcpConnectPoll = undefined;
g.__exactTcpRead = () => Buffer.alloc(0);
g.__exactTcpWrite = () => 0;
g.__exactTcpClose = () => {};
g.__exactTcpListen = () => 1;
g.__exactTcpAccept = () => -1;
g.__exactTcpLocalAddr = () => JSON.stringify({ address: '127.0.0.1', port: 0, family: 'IPv4' });

// eslint-disable-next-line @typescript-eslint/no-var-requires
const net = require('../../../src/builtins/net.js');

beforeEach(() => {
  currentNetPrincipal = 1;
  g.__exactTcpConnect = () => 1;
  g.__exactTcpRead = () => Buffer.alloc(0);
  g.__exactTcpWrite = () => 0;
  g.__exactTcpClose = () => {};
  g.__exactTcpListen = () => 1;
  g.__exactTcpAccept = () => -1;
  g.__exactTcpLocalAddr = () => JSON.stringify({ address: '127.0.0.1', port: 0, family: 'IPv4' });
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

describe('native selector ownership survives rejected close attempts', () => {
  test('Socket keeps its private handle and lifecycle open for the owner retry', () => {
    const handle = 777003;
    const attempts: number[] = [];
    let deny = true;
    g.__exactTcpClose = (id: number) => {
      attempts.push(id);
      if (deny) throw new Error('wrong principal');
    };

    const socket = new net.Socket({ _handle: handle });
    try {
      expect(() => { socket._handle = null; }).toThrow('private');
      expect(() => { socket._handle._exactHandle = 1; }).toThrow('private');
      expect(() => { socket.destroyed = true; }).toThrow('private');

      expect(() => socket.destroy()).toThrow('wrong principal');
      expect(socket.destroyed).toBe(false);
      expect(socket._handle._exactHandle).toBe(handle);

      deny = false;
      expect(() => socket.destroy()).not.toThrow();
      expect(socket.destroyed).toBe(true);
      expect(socket._handle).toBeNull();
      expect(attempts).toEqual([handle, handle]);
    } finally {
      deny = false;
      if (!socket.destroyed) socket.destroy();
    }
  });

  test('Server rejects selector replacement and closes only after native ownership succeeds', async () => {
    const handle = 777004;
    const attempts: number[] = [];
    let deny = false;
    g.__exactTcpListen = () => handle;
    g.__exactTcpAccept = () => -1;
    g.__exactTcpClose = (id: number) => {
      attempts.push(id);
      if (deny) throw new Error('wrong principal');
    };

    const server = net.createServer();
    try {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      expect(server.listening).toBe(true);
      expect(server._handle._exactHandle).toBe(handle);
      expect(() => { server._handle = null; }).toThrow('not publicly mutable');
      expect(() => { server._handle._exactHandle = 1; }).toThrow('private');

      deny = true;
      expect(() => server.close()).toThrow('wrong principal');
      expect(server.listening).toBe(true);
      expect(server._handle._exactHandle).toBe(handle);

      deny = false;
      const closed = new Promise<void>((resolve) => server.once('close', resolve));
      expect(() => server.close()).not.toThrow();
      await closed;
      expect(server.listening).toBe(false);
      expect(server._handle).toBeNull();
      expect(attempts).toEqual([handle, handle]);
    } finally {
      deny = false;
      if (server.listening) server.close();
    }
  });
});

describe('retained Socket authority cannot be laundered through queued writes', () => {
  test('foreign write/end/drain leave state untouched and owner continuation sends only owner bytes', async () => {
    const writes: string[] = [];
    let hijackedDrains = 0;
    const originalDrain = net.Socket.prototype._drainWriteQueue;
    g.__exactTcpConnect = () => 777005;
    g.__exactTcpRead = () => '';
    g.__exactTcpWrite = (_handle: number, data: Uint8Array) => {
      writes.push(Buffer.from(data).toString());
      return data.byteLength;
    };

    const socket = new net.Socket();
    try {
      socket.connect({ port: 12346, host: '127.0.0.1' });

      // Even replacing the public/internal-looking prototype slot cannot
      // interpose on the module-private continuation captured by net.js.
      net.Socket.prototype._drainWriteQueue = function () {
        hijackedDrains++;
      };

      currentNetPrincipal = 2;
      expect(() => socket.write('foreign')).toThrow('net owner denied');
      expect(() => socket.end('foreign-end')).toThrow('net owner denied');
      expect(() => originalDrain.call(socket)).toThrow('net owner denied');
      expect(() => socket._handle).toThrow('net owner denied');
      expect(() => socket._writeQueue).toThrow('net owner denied');

      currentNetPrincipal = 1;
      expect(socket.writableEnded).toBe(false);
      expect(socket.bufferSize).toBe(0);
      expect(socket.write('owner')).toBe(true);

      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('connect did not complete')), 1000);
        socket.once('connect', () => {
          clearTimeout(timer);
          setTimeout(resolve, 10);
        });
      });

      expect(writes).toEqual(['owner']);
      expect(hijackedDrains).toBe(0);
      expect(socket.bufferSize).toBe(0);
    } finally {
      currentNetPrincipal = 1;
      net.Socket.prototype._drainWriteQueue = originalDrain;
      if (!socket.destroyed) socket.destroy();
    }
  });

  test('foreign fields and caller-owned options cannot retarget a deferred connect', async () => {
    const connects: Array<[string, number, unknown, unknown]> = [];
    g.__exactTcpConnect = (host: string, port: number, localAddress: unknown, localPort: unknown) => {
      connects.push([host, port, localAddress, localPort]);
      return 777006;
    };
    const socket = new net.Socket();
    socket.on('error', () => {});
    const connected = new Promise<void>((resolve) => socket.once('connect', resolve));
    const options = { host: '127.0.0.1', port: 43111 };
    try {
      socket.connect(options);

      currentNetPrincipal = 2;
      expect(() => { socket._requestedAddress = '169.254.169.254'; }).toThrow('net owner denied');
      expect(() => { socket._requestedPort = 80; }).toThrow('net owner denied');
      expect(() => socket._requestedAddress).toThrow('net owner denied');
      options.host = '169.254.169.254';
      options.port = 80;

      currentNetPrincipal = 1;
      // Compatibility projections are not the deferred operation's target.
      socket._requestedAddress = '192.0.2.1';
      socket._requestedPort = 9;
      await connected;
      expect(connects).toEqual([['127.0.0.1', 43111, null, null]]);
    } finally {
      currentNetPrincipal = 1;
      if (!socket.destroyed) socket.destroy();
    }
  });

  test('saved EventEmitter methods and inbound buffers reject foreign disclosure, then owner retry succeeds', async () => {
    const socket = new net.Socket();
    try {
      socket.push(Buffer.from('owner-secret'));
      const foreignListener = () => {
        throw new Error('foreign listener ran');
      };

      currentNetPrincipal = 2;
      expect(() => EventEmitter.prototype.on.call(socket, 'data', foreignListener)).toThrow('net owner denied');
      expect(() => EventEmitter.prototype.once.call(socket, 'data', foreignListener)).toThrow('net owner denied');
      expect(() => EventEmitter.prototype.listeners.call(socket, 'data')).toThrow('net owner denied');
      expect(() => EventEmitter.prototype.emit.call(socket, 'data', Buffer.from('stolen'))).toThrow('net owner denied');
      expect(() => socket.on).toThrow('net owner denied');
      expect(() => { socket.emit = foreignListener; }).toThrow('net owner denied');
      expect(() => socket._events).toThrow('net owner denied');
      expect(() => socket._readBuffer).toThrow('net owner denied');
      expect(() => socket._readBufferLength).toThrow('net owner denied');
      expect(() => socket.read()).toThrow('net owner denied');
      expect(() => { socket._readBuffer = [Buffer.from('poison')]; }).toThrow('net owner denied');

      currentNetPrincipal = 1;
      const received: Buffer[] = [];
      socket.on('data', (chunk: Buffer) => received.push(Buffer.from(chunk)));
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      expect(Buffer.concat(received).toString()).toBe('owner-secret');
      expect(socket._readBufferLength).toBe(0);
    } finally {
      currentNetPrincipal = 1;
      if (!socket.destroyed) socket.destroy();
    }
  });
});
