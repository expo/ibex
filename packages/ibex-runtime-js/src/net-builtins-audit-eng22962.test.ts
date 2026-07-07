// ENG-22962 — regression coverage for correctness/perf bugs in the network
// builtins (tls/dgram/ws). Each builtin talks to native host functions
// (__exactUdp*, __exactTcp*, ...) which we stub here so the pure-JS logic can be
// exercised and checked against expected behavior. Run with: bun test.
//
// Finding #5 (fully-synchronous dns.lookup/resolve*/reverse) landed as the async
// native DNS bridge (ENG-22995): the native side runs the resolver off-thread
// and resolves a Promise on the event loop. The native non-blocking behavior is
// verified in `ibex self-test`; the JS wiring here (async-preferred, sync
// fallback, error mapping) is covered by the `dns async native bridge` block.

import { expect, test, describe, beforeEach, afterEach } from 'bun:test';
import { createRequire } from 'module';

const g = globalThis as Record<string, any>;
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// dgram — finding #2 (send callback misparse) and #3 (unref kills reception)
// ---------------------------------------------------------------------------
describe('dgram send/unref (ENG-22962 #2, #3)', () => {
  let dgram: any;
  let sendCalls: any[];
  let recvQueue: any[];
  let openSockets: any[];

  function track(s: any) { openSockets.push(s); return s; }

  beforeEach(() => {
    sendCalls = [];
    recvQueue = [];
    openSockets = [];
    let nextHandle = 1;
    g.__exactUdpSocket = () => nextHandle++;
    g.__exactUdpBind = () => JSON.stringify({ address: '0.0.0.0', port: 41999, family: 'IPv4' });
    g.__exactUdpSend = (...args: any[]) => { sendCalls.push(args); };
    g.__exactUdpRecv = () => (recvQueue.length ? recvQueue.shift() : null);
    g.__exactUdpClose = () => {};
    g.__exactUdpAddress = () => JSON.stringify({ address: '0.0.0.0', port: 41999, family: 'IPv4' });
    dgram = require('../../../src/builtins/dgram.js');
  });

  // Close any sockets that a (possibly failing) test left polling, so a leaked
  // recv poll can't consume another test's queued datagram via the shared stub.
  afterEach(() => {
    for (const s of openSockets) { try { s.close(); } catch {} }
  });

  test('send(msg, port, cb) on an unconnected socket: cb fires, address is a string (not the cb)', async () => {
    const socket = track(dgram.createSocket('udp4'));
    const cbResult: any = await new Promise((resolve, reject) => {
      socket.on('error', reject);
      socket.send(Buffer.from('hi'), 41234, (err: any, bytes: number) => resolve({ err, bytes }));
    });
    expect(cbResult.err).toBeNull();
    expect(cbResult.bytes).toBe(2);
    // __exactUdpSend(handle, data, port, address): address slot must be a string,
    // not the callback function; port slot must be the numeric port.
    expect(sendCalls.length).toBe(1);
    const [, , port, address] = sendCalls[0];
    expect(port).toBe(41234);
    expect(typeof address).toBe('string');
    expect(address).toBe('127.0.0.1');
    socket.close();
  });

  test('send(msg, offset, length, port, cb) unconnected (full form + trailing cb): cb fires', async () => {
    const socket = track(dgram.createSocket('udp4'));
    const buf = Buffer.from('hello world');
    const cbResult: any = await new Promise((resolve, reject) => {
      socket.on('error', reject);
      socket.send(buf, 0, 5, 41234, (err: any, bytes: number) => resolve({ err, bytes }));
    });
    expect(cbResult.err).toBeNull();
    const [, , port, address] = sendCalls[0];
    expect(port).toBe(41234);
    expect(typeof address).toBe('string');
    socket.close();
  });

  test('unref() does NOT stop reception; ref() after unref() keeps working', async () => {
    const socket = track(dgram.createSocket('udp4'));
    await new Promise<void>((resolve) => socket.bind(0, () => resolve()));

    // The core fix: unref() must not clear the poll timer / stop receiving.
    expect(socket._pollTimer).not.toBeNull();
    expect(socket._receiving).toBe(true);
    socket.unref();
    expect(socket._unrefed).toBe(true);
    expect(socket._pollTimer).not.toBeNull(); // was: null (reception permanently killed)
    expect(socket._receiving).toBe(true);
    socket.ref();
    expect(socket._unrefed).toBe(false);

    // Functional proof: a datagram enqueued after unref() is still delivered.
    const got: any = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no message delivered after unref()')), 1000);
      socket.once('message', (msg: Buffer, rinfo: any) => { clearTimeout(timer); resolve({ msg, rinfo }); });
      recvQueue.push({ data: Buffer.from('ping'), address: '10.0.0.1', family: 'IPv4', port: 5353, size: 4 });
    });
    expect(Buffer.from(got.msg).toString()).toBe('ping');
    socket.close();
  });
});

// ---------------------------------------------------------------------------
// ws — finding #4 (O(n^2) buffering / per-byte parse / per-byte encode)
// ---------------------------------------------------------------------------
describe('ws incoming/outgoing framing (ENG-22962 #4)', () => {
  let WS: any;
  let writes: Uint8Array[];

  function stubTcp() {
    writes = [];
    g.__exactTcpListen = () => 1;
    g.__exactTcpAccept = () => null;
    g.__exactTcpRead = () => ''; // no inbound data via the poll; we feed frames manually
    g.__exactTcpWrite = (_h: any, data: any) => {
      writes.push(data instanceof Uint8Array ? data : Uint8Array.from(typeof data === 'string'
        ? Array.from(data as string).map((c) => (c as string).charCodeAt(0))
        : data));
    };
    g.__exactTcpClose = () => {};
    g.__exactHashSync = () => '00';
  }

  // Build a masked client->server frame (clients always mask).
  function buildClientFrame(opcode: number, payload: Uint8Array, fin = true): Uint8Array {
    const mask = [0x12, 0x34, 0x56, 0x78];
    const len = payload.length;
    const header: number[] = [];
    header.push((fin ? 0x80 : 0) | (opcode & 0x0f));
    if (len < 126) header.push(0x80 | len);
    else if (len < 65536) header.push(0x80 | 126, (len >>> 8) & 0xff, len & 0xff);
    else header.push(0x80 | 127, 0, 0, 0, 0, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
    header.push(...mask);
    const out = new Uint8Array(header.length + len);
    out.set(header, 0);
    for (let i = 0; i < len; i++) out[header.length + i] = payload[i] ^ mask[i & 3];
    return out;
  }

  function newConn() {
    const ws = new WS.WebSocket(1, { url: '/' });
    return ws;
  }

  function shutdown(ws: any) {
    ws._readyState = WS.WebSocket.CLOSED;
    if (ws._pollTimer) { clearTimeout(ws._pollTimer); ws._pollTimer = null; }
  }

  beforeEach(() => {
    stubTcp();
    WS = require('../../../src/builtins/ws.js');
  });

  test('single small masked text frame delivers the exact message', () => {
    const ws = newConn();
    const messages: any[] = [];
    ws.on('message', (data: any, isBinary: boolean) => messages.push({ data, isBinary }));
    const frame = buildClientFrame(0x1, new TextEncoder().encode('hello ünïcode'));
    ws._appendData(frame);
    ws._processBuffer();
    expect(messages.length).toBe(1);
    expect(messages[0].data).toBe('hello ünïcode');
    shutdown(ws);
  });

  test('large binary frame appended across many chunks reassembles byte-exact', () => {
    const ws = newConn();
    ws.binaryType = 'arraybuffer';
    const received: any[] = [];
    ws.on('message', (data: any) => received.push(data));

    const N = 1024 * 1024; // 1 MiB single message
    const payload = new Uint8Array(N);
    for (let i = 0; i < N; i++) payload[i] = (i * 31 + 7) & 0xff;
    const frame = buildClientFrame(0x2, payload);

    // Simulate the transport delivering the frame in 64 KiB reads.
    const CHUNK = 65536;
    for (let off = 0; off < frame.length; off += CHUNK) {
      ws._appendData(frame.subarray(off, Math.min(off + CHUNK, frame.length)));
    }
    ws._processBuffer();

    expect(received.length).toBe(1);
    const got = new Uint8Array(received[0]);
    expect(got.length).toBe(N);
    // Spot-check a scattering of bytes (full compare would be slow but this is exact enough).
    for (const idx of [0, 1, 255, 65535, 65536, 500000, N - 1]) {
      expect(got[idx]).toBe(payload[idx]);
    }
    shutdown(ws);
  });

  test('fragmented text message (fin=0 + continuation) reassembles into one message', () => {
    const ws = newConn();
    const messages: any[] = [];
    ws.on('message', (data: any) => messages.push(data));
    const part1 = new TextEncoder().encode('Hello, ');
    const part2 = new TextEncoder().encode('world!');
    ws._appendData(buildClientFrame(0x1, part1, false)); // text, not final
    ws._appendData(buildClientFrame(0x0, part2, true));  // continuation, final
    ws._processBuffer();
    expect(messages.length).toBe(1);
    expect(messages[0]).toBe('Hello, world!');
    shutdown(ws);
  });

  test('two back-to-back frames in one buffer both deliver', () => {
    const ws = newConn();
    const messages: any[] = [];
    ws.on('message', (data: any) => messages.push(data));
    const a = buildClientFrame(0x1, new TextEncoder().encode('one'));
    const b = buildClientFrame(0x1, new TextEncoder().encode('two'));
    const both = new Uint8Array(a.length + b.length);
    both.set(a, 0); both.set(b, a.length);
    ws._appendData(both);
    ws._processBuffer();
    expect(messages).toEqual(['one', 'two']);
    shutdown(ws);
  });

  test('outgoing frame: send(Uint8Array) encodes a correct unmasked binary frame', () => {
    const ws = newConn();
    const payload = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252]);
    ws.send(payload);
    expect(writes.length).toBe(1);
    const frame = writes[0];
    expect(frame[0] & 0x0f).toBe(0x2); // binary opcode
    expect((frame[0] & 0x80) !== 0).toBe(true); // fin
    expect(frame[1] & 0x80).toBe(0); // server->client is NOT masked
    expect(frame[1] & 0x7f).toBe(payload.length); // small-length inline
    const body = frame.subarray(2);
    expect(Array.from(body)).toEqual(Array.from(payload));
    shutdown(ws);
  });

  test('outgoing frame: 200-byte payload uses the 16-bit extended length header', () => {
    const ws = newConn();
    const payload = new Uint8Array(200).fill(0xab);
    ws.send(payload);
    const frame = writes[0];
    expect(frame[1] & 0x7f).toBe(126); // extended-16 marker
    const declared = (frame[2] << 8) | frame[3];
    expect(declared).toBe(200);
    expect(Array.from(frame.subarray(4))).toEqual(Array.from(payload));
    shutdown(ws);
  });
});

// ---------------------------------------------------------------------------
// tls — finding #1 (secureConnection emitted twice / on handshake failure)
//
// The buggy duplicate emit lives inside the net.createServer connection
// callback closure, which we can only reach by intercepting net.createServer.
// bun's real net.Server does not surface that callback via emit('connection'),
// so we patch net.createServer to capture the tls connection callback and hand
// it a minimal fake server + raw socket. This must run before tls.js is first
// required (tls.js binds `net` at load).
// ---------------------------------------------------------------------------
const _net = require('net');
let _capturedConnListener: ((rawSocket: any) => void) | null = null;
_net.createServer = function (opts: any, cb: any) {
  _capturedConnListener = typeof opts === 'function' ? opts : cb;
  const listeners: Record<string, Function[]> = {};
  const s: any = {
    on(ev: string, fn: Function) { (listeners[ev] = listeners[ev] || []).push(fn); return s; },
    once(ev: string, fn: Function) { return s.on(ev, fn); },
    removeListener() { return s; },
    emit(ev: string, ...args: any[]) { (listeners[ev] || []).slice().forEach((fn) => fn(...args)); return true; },
    listen() { return s; },
    close(cb2: any) { if (typeof cb2 === 'function') cb2(); return s; },
    address() { return { port: 0 }; },
    ref() { return s; },
    unref() { return s; },
  };
  return s;
};

describe('tls server secureConnection (ENG-22962 #1)', () => {
  let tls: any;

  beforeEach(() => {
    _capturedConnListener = null;
    tls = require('../../../src/builtins/tls.js');
  });

  function fakeRawSocket() {
    return { remoteAddress: '127.0.0.1', remotePort: 44321, remoteFamily: 'IPv4', destroy() {} };
  }

  test('successful handshake emits secureConnection exactly once', () => {
    const server = tls.createServer({}, () => {});
    let secureCount = 0;
    let errCount = 0;
    server.on('secureConnection', () => { secureCount++; });
    server.on('tlsClientError', () => { errCount++; });
    // Simulate the client having already queued a successful server-side handshake.
    server._pendingTlsHandshakes.push({
      ok: true,
      clientOptions: {},
      cipher: 'TLS_AES_128_GCM_SHA256',
      serverError: null,
    });
    // Deliver the raw TCP connection through the captured net connection callback.
    expect(typeof _capturedConnListener).toBe('function');
    _capturedConnListener!(fakeRawSocket());
    expect(secureCount).toBe(1); // was: 2 (duplicate emit at the connection callback)
    expect(errCount).toBe(0);
  });

  test('failed handshake emits tlsClientError and NOT secureConnection', () => {
    const server = tls.createServer({}, () => {});
    let secureCount = 0;
    let errCount = 0;
    server.on('secureConnection', () => { secureCount++; });
    server.on('tlsClientError', () => { errCount++; });
    server._pendingTlsHandshakes.push({
      ok: false,
      clientOptions: {},
      cipher: null,
      serverError: new Error('no shared cipher'),
    });
    _capturedConnListener!(fakeRawSocket());
    expect(errCount).toBe(1);
    expect(secureCount).toBe(0); // was: 1 (secureConnection wrongly emitted for the destroyed socket)
  });
});

// ---------------------------------------------------------------------------
// dns — finding #5 (async native DNS bridge, ENG-22995)
//
// dns.js now prefers the non-blocking host functions (__exactDns*Async, which
// return Promises) and only falls back to the blocking __exactDns* calls when
// the async ones are absent. These stubs exercise that JS wiring: the async
// path is preferred, the callback is delivered asynchronously, results/errors
// map correctly, and the sync path still works as a fallback.
// ---------------------------------------------------------------------------
describe('dns async native bridge (ENG-22995 / #5)', () => {
  const dnsPath = require.resolve('../../../src/builtins/dns.js');
  const dnsGlobals = [
    '__exactDnsLookup', '__exactDnsLookupAsync',
    '__exactDnsResolve', '__exactDnsResolveAsync',
    '__exactDnsReverse', '__exactDnsReverseAsync',
  ];

  let asyncCalls: any[];
  let syncCalls: any[];

  // dns.js captures `typeof __exactDns*` into module-level flags at load time,
  // so each test installs its stubs first, then loads a fresh module instance.
  function loadFreshDns() {
    delete (require as any).cache[dnsPath];
    return require('../../../src/builtins/dns.js');
  }

  function clearDnsGlobals() {
    for (const k of dnsGlobals) delete g[k];
  }

  beforeEach(() => {
    asyncCalls = [];
    syncCalls = [];
    clearDnsGlobals();
  });

  afterEach(() => {
    clearDnsGlobals();
    delete (require as any).cache[dnsPath];
  });

  test('lookup prefers the async host function and never calls the blocking one', async () => {
    g.__exactDnsLookup = (...a: any[]) => { syncCalls.push(a); return JSON.stringify([{ address: '9.9.9.9', family: 4 }]); };
    g.__exactDnsLookupAsync = (...a: any[]) => { asyncCalls.push(a); return Promise.resolve(JSON.stringify([{ address: '1.2.3.4', family: 4 }])); };
    const dns = loadFreshDns();
    const res: any = await new Promise((resolve) => {
      dns.lookup('example.com', { family: 4 }, (err: any, address: string, family: number) => resolve({ err, address, family }));
    });
    expect(res.err).toBeNull();
    expect(res.address).toBe('1.2.3.4');
    expect(res.family).toBe(4);
    expect(asyncCalls.length).toBe(1);
    expect(syncCalls.length).toBe(0); // the blocking host function is never called
  });

  test('lookup callback is asynchronous — dispatch does not block the caller', async () => {
    g.__exactDnsLookupAsync = () => Promise.resolve(JSON.stringify([{ address: '1.2.3.4', family: 4 }]));
    const dns = loadFreshDns();
    let synchronousReturn = false;
    const firedBeforeReturn = await new Promise<boolean>((resolve) => {
      dns.lookup('example.com', () => resolve(synchronousReturn === false));
      // If lookup blocked and invoked the callback inline, this would run late.
      synchronousReturn = true;
    });
    // The callback must NOT have fired before the synchronous code after the call.
    expect(firedBeforeReturn).toBe(false);
  });

  test('lookup { all: true } returns the full record array', async () => {
    g.__exactDnsLookupAsync = () => Promise.resolve(JSON.stringify([
      { address: '1.2.3.4', family: 4 },
      { address: '5.6.7.8', family: 4 },
    ]));
    const dns = loadFreshDns();
    const res: any = await new Promise((resolve) => {
      dns.lookup('example.com', { all: true }, (err: any, results: any) => resolve({ err, results }));
    });
    expect(res.err).toBeNull();
    expect(res.results).toEqual([
      { address: '1.2.3.4', family: 4 },
      { address: '5.6.7.8', family: 4 },
    ]);
  });

  test('setDefaultResultOrder affects lookup result ordering', async () => {
    g.__exactDnsLookupAsync = () => Promise.resolve(JSON.stringify([
      { address: '2001:db8::1', family: 6 },
      { address: '1.2.3.4', family: 4 },
    ]));
    const dns = loadFreshDns();
    dns.setDefaultResultOrder('ipv4first');
    const res: any = await new Promise((resolve) => {
      dns.lookup('example.com', (err: any, address: string, family: number) => resolve({ err, address, family }));
    });
    expect(res.err).toBeNull();
    expect(res).toMatchObject({ address: '1.2.3.4', family: 4 });
  });

  test('lookup maps an empty async result to ENOTFOUND', async () => {
    g.__exactDnsLookupAsync = () => Promise.resolve('[]');
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.lookup('nope.invalid', (e: any) => resolve(e));
    });
    expect(err).toBeTruthy();
    expect(err.code).toBe('ENOTFOUND');
    expect(err.hostname).toBe('nope.invalid');
  });

  test('lookup maps an async rejection to ENOTFOUND', async () => {
    g.__exactDnsLookupAsync = () => Promise.reject(new Error('resolver down'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.lookup('nope.invalid', (e: any) => resolve(e));
    });
    expect(err).toBeTruthy();
    expect(err.code).toBe('ENOTFOUND');
  });

  test('resolveMx prefers the async resolver and returns records', async () => {
    g.__exactDnsResolve = (...a: any[]) => { syncCalls.push(a); return '[]'; };
    g.__exactDnsResolveAsync = (...a: any[]) => { asyncCalls.push(a); return Promise.resolve(JSON.stringify([{ priority: 10, exchange: 'mail.example.com' }])); };
    const dns = loadFreshDns();
    const recs: any = await new Promise((resolve, reject) => {
      dns.resolveMx('example.com', (err: any, r: any) => (err ? reject(err) : resolve(r)));
    });
    expect(recs).toEqual([{ priority: 10, exchange: 'mail.example.com' }]);
    expect(asyncCalls.length).toBe(1);
    expect(asyncCalls[0][1]).toBe('MX');
    expect(syncCalls.length).toBe(0);
  });

  test('resolve async rejection maps to a queryXxx ENOTFOUND error', async () => {
    g.__exactDnsResolve = () => '[]';
    g.__exactDnsResolveAsync = () => Promise.reject(new Error('SERVFAIL'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveTxt('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ENOTFOUND');
    expect(String(err.message)).toContain('queryTXT');
    expect(String(err.message)).toContain('SERVFAIL');
  });

  test('resolve empty record sets map to ENODATA', async () => {
    g.__exactDnsResolveAsync = () => Promise.resolve('[]');
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveTxt('example.com', (e: any) => resolve(e));
    });
    expect(err).toBeTruthy();
    expect(err.code).toBe('ENODATA');
    expect(err.syscall).toBe('queryTXT');
  });

  test('lookupService fails honestly when reverse lookup is unavailable', async () => {
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.lookupService('127.0.0.1', 22, (e: any) => resolve(e));
    });
    expect(err).toBeTruthy();
    expect(err.code).toBe('ENOTSUP');
    expect(err.syscall).toBe('getnameinfo');
  });

  test('lookupService uses reverse lookup and maps known service names', async () => {
    g.__exactDnsReverseAsync = () => Promise.resolve(JSON.stringify(['localhost']));
    const dns = loadFreshDns();
    const res: any = await new Promise((resolve) => {
      dns.lookupService('127.0.0.1', 22, (err: any, hostname: string, service: string) => resolve({ err, hostname, service }));
    });
    expect(res.err).toBeNull();
    expect(res.hostname).toBe('localhost');
    expect(res.service).toBe('ssh');
  });

  test('reverse prefers the async resolver and returns hostnames', async () => {
    g.__exactDnsReverse = (...a: any[]) => { syncCalls.push(a); return '[]'; };
    g.__exactDnsReverseAsync = (...a: any[]) => { asyncCalls.push(a); return Promise.resolve(JSON.stringify(['host.example.com'])); };
    const dns = loadFreshDns();
    const names: any = await new Promise((resolve, reject) => {
      dns.reverse('1.2.3.4', (err: any, r: any) => (err ? reject(err) : resolve(r)));
    });
    expect(names).toEqual(['host.example.com']);
    expect(asyncCalls.length).toBe(1);
    expect(syncCalls.length).toBe(0);
  });

  test('dns.promises.lookup rides the async path', async () => {
    g.__exactDnsLookupAsync = () => Promise.resolve(JSON.stringify([{ address: '1.2.3.4', family: 4 }]));
    const dns = loadFreshDns();
    const r: any = await dns.promises.lookup('example.com', { family: 4 });
    expect(r).toEqual({ address: '1.2.3.4', family: 4 });
  });

  test('falls back to the synchronous host function when the async one is absent', async () => {
    g.__exactDnsLookup = (...a: any[]) => { syncCalls.push(a); return JSON.stringify([{ address: '5.6.7.8', family: 4 }]); };
    // No __exactDnsLookupAsync installed.
    const dns = loadFreshDns();
    const res: any = await new Promise((resolve) => {
      dns.lookup('example.com', { family: 4 }, (err: any, address: string) => resolve({ err, address }));
    });
    expect(res.err).toBeNull();
    expect(res.address).toBe('5.6.7.8');
    expect(syncCalls.length).toBe(1); // fell back to the blocking host function
  });
});
