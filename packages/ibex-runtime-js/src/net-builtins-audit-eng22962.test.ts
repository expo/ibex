// ENG-22962 — regression coverage for correctness/perf bugs in the network
// builtins (tls/dgram/ws). Each builtin talks to native host functions
// (__exactUdp*, __exactTcp*, ...) which we stub here so the pure-JS logic can be
// exercised and checked against expected behavior. Run with: bun test.
//
// Finding #5 (fully-synchronous dns.lookup/resolve*/reverse) is NOT covered here:
// making those calls non-blocking requires a new async native DNS bridge and is
// tracked as a native follow-up — it cannot be fixed or verified in pure JS.

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
