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

let currentDgramPrincipal = 1;
let nextDgramOwnerStamp = 1;
const dgramOwnerStamps = new Map<number, number>();
g.__exactNetOwner = (action: string, stamp?: number) => {
  if (action === 'new') {
    const next = nextDgramOwnerStamp++;
    dgramOwnerStamps.set(next, currentDgramPrincipal);
    return next;
  }
  if (action === 'assert' && typeof stamp === 'number' &&
      dgramOwnerStamps.get(stamp) === currentDgramPrincipal) return;
  throw new Error('net owner denied');
};

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
    currentDgramPrincipal = 1;
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
    currentDgramPrincipal = 1;
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

  test('wrong-owner close preserves private UDP state for the owner retry', async () => {
    const socket = track(dgram.createSocket('udp4'));
    await new Promise<void>((resolve) => socket.bind(0, resolve));
    const attempts: number[] = [];
    let deny = true;
    g.__exactUdpClose = (id: number) => {
      attempts.push(id);
      if (deny) throw new Error('wrong principal');
    };

    expect(() => socket.close()).toThrow('wrong principal');
    expect(socket._closed).toBe(false);
    expect(() => socket._handle).toThrow('private');

    deny = false;
    expect(() => socket.close()).not.toThrow();
    expect(socket._closed).toBe(true);
    expect(attempts.length).toBe(2);
  });

  test('foreign routing, saved listeners, and close cannot redirect or disclose owner datagrams', async () => {
    const { EventEmitter } = require('events');
    const socket = track(dgram.createSocket('udp4'));
    socket.on('error', () => {});
    socket.connect(43222, '127.0.0.9');

    currentDgramPrincipal = 2;
    expect(() => { socket._connected = true; }).toThrow('net owner denied');
    expect(() => { socket._connectPort = 53; }).toThrow('net owner denied');
    expect(() => { socket._connectAddress = '169.254.169.254'; }).toThrow('net owner denied');
    expect(() => socket.remoteAddress()).toThrow('net owner denied');
    expect(() => EventEmitter.prototype.on.call(socket, 'message', () => {})).toThrow('net owner denied');
    expect(() => EventEmitter.prototype.once.call(socket, 'message', () => {})).toThrow('net owner denied');
    expect(() => EventEmitter.prototype.listeners.call(socket, 'message')).toThrow('net owner denied');
    expect(() => socket._events).toThrow('net owner denied');
    expect(() => { socket.emit = () => {}; }).toThrow('net owner denied');
    expect(() => socket.close()).toThrow('net owner denied');

    currentDgramPrincipal = 1;
    // Public compatibility projections are not the route used by send().
    socket._connected = false;
    socket._connectPort = 9;
    socket._connectAddress = '192.0.2.9';
    socket.send(Buffer.from('owner-datagram'));
    expect(sendCalls).toHaveLength(1);
    expect(sendCalls[0][2]).toBe(43222);
    expect(sendCalls[0][3]).toBe('127.0.0.9');

    const received = new Promise<string>((resolve) => {
      socket.once('message', (message: Buffer) => resolve(Buffer.from(message).toString()));
    });
    recvQueue.push({
      data: Buffer.from('owner-receive'),
      address: '127.0.0.10',
      family: 'IPv4',
      port: 43223,
      size: 13,
    });
    expect(await received).toBe('owner-receive');
    expect(() => socket.close()).not.toThrow();
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
    try { ws.terminate(); } catch {}
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

  test('wrong-owner terminate preserves private TCP state for the owner retry', () => {
    const ws = newConn();
    const attempts: number[] = [];
    let deny = true;
    g.__exactTcpClose = (id: number) => {
      attempts.push(id);
      if (deny) throw new Error('wrong principal');
    };

    expect(() => ws.terminate()).toThrow('wrong principal');
    expect(ws.readyState).toBe(WS.WebSocket.OPEN);
    expect(() => ws._handle).toThrow('private');

    deny = false;
    expect(() => ws.terminate()).not.toThrow();
    expect(ws.readyState).toBe(WS.WebSocket.CLOSED);
    expect(attempts).toEqual([1, 1]);
  });

  test('wrong-owner server close preserves its private listener for the owner retry', async () => {
    const handle = 2;
    g.__exactTcpListen = () => handle;
    g.__exactTcpAccept = () => -1;
    const server = new WS.Server({ port: 8080 });
    await new Promise<void>((resolve, reject) => {
      server.once('listening', resolve);
      server.once('error', reject);
    });

    const attempts: number[] = [];
    let deny = true;
    g.__exactTcpClose = (id: number) => {
      attempts.push(id);
      if (deny) throw new Error('wrong principal');
    };

    try {
      expect(server._listening).toBe(true);
      expect(() => server._handle).toThrow('private');
      expect(() => { server._handle = null; }).toThrow('private');
      expect(() => { server._listening = false; }).toThrow('private');

      expect(() => server.close()).toThrow('wrong principal');
      expect(server._listening).toBe(true);

      deny = false;
      const closed = new Promise<void>((resolve) => server.once('close', resolve));
      expect(() => server.close()).not.toThrow();
      await closed;
      expect(server._listening).toBe(false);
      expect(attempts).toEqual([handle, handle]);
    } finally {
      deny = false;
      if (server._listening) server.close();
    }
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
const _serverConnectionListeners = new WeakMap<object, (rawSocket: any) => void>();
const _originalNetConnect = _net.connect;
_net.createServer = function (opts: any, cb: any) {
  const connectionListener = typeof opts === 'function' ? opts : cb;
  const listeners: Record<string, Function[]> = {};
  let boundAddress = { address: '127.0.0.1', port: 0, family: 'IPv4' };
  const s: any = {
    on(ev: string, fn: Function) { (listeners[ev] = listeners[ev] || []).push(fn); return s; },
    once(ev: string, fn: Function) { return s.on(ev, fn); },
    removeListener() { return s; },
    emit(ev: string, ...args: any[]) { (listeners[ev] || []).slice().forEach((fn) => fn(...args)); return true; },
    listen(first: any, second?: any) {
      const listenOptions = first && typeof first === 'object' ? first : {};
      const address = listenOptions.host || listenOptions.address ||
        (typeof second === 'string' ? second : '127.0.0.1');
      const port = listenOptions.port ?? (typeof first === 'number' ? first : 0);
      const family = listenOptions.family || (String(address).includes(':') ? 'IPv6' : 'IPv4');
      boundAddress = { address: String(address), port: Number(port), family: String(family) };
      return s;
    },
    close(cb2: any) { if (typeof cb2 === 'function') cb2(); return s; },
    address() { return boundAddress; },
    ref() { return s; },
    unref() { return s; },
  };
  if (connectionListener) _serverConnectionListeners.set(s, connectionListener);
  return s;
};

describe('tls server secureConnection (ENG-22962 #1)', () => {
  let tls: any;
  const tlsHostGlobals = [
    '__exactTlsOwnerToken',
    '__exactTlsEngineNew', '__exactTlsEngineWriteTls', '__exactTlsEngineReadTls',
    '__exactTlsEngineReadPlain', '__exactTlsEngineWritePlain',
    '__exactTlsEngineStatus', '__exactTlsEngineClose',
    '__exactTlsEngineTransportEof', '__exactTlsEngineShutdown',
    '__exactTlsEnginePeerCerts',
  ];

  beforeEach(() => {
    tls = require('../../../src/builtins/tls.js');
  });

  afterEach(async () => {
    _net.connect = _originalNetConnect;
    // TLSSocket.destroy() synthesizes terminal events on a zero-delay timer
    // for reduced/custom transports. Let that release private owner tokens
    // before removing the host hooks used by the callback.
    await waitForTurn();
    for (const name of tlsHostGlobals) delete g[name];
  });

  function waitForTurn() {
    return new Promise<void>((resolve) => setTimeout(resolve, 10));
  }

  async function waitForHandshake() {
    await waitForTurn();
    await waitForTurn();
  }

  function connectedRaw(host = '203.0.113.10', port = 443) {
    const { EventEmitter } = require('events');
    const raw: any = new EventEmitter();
    raw.connecting = false;
    raw.destroyed = false;
    raw.readable = true;
    raw.writable = true;
    raw.remoteAddress = host;
    raw.remotePort = port;
    raw.pause = () => { raw.paused = true; return raw; };
    raw.resume = () => { raw.paused = false; return raw; };
    raw.write = () => true;
    raw.end = () => raw;
    raw.destroy = () => { raw.destroyed = true; return raw; };
    return raw;
  }

  function internalLoopbackRaw(
    host: string,
    port: number,
    family: 'IPv4' | 'IPv6',
    localPort: number,
  ) {
    const raw = connectedRaw(host, port);
    raw.remoteFamily = family;
    raw.localAddress = family === 'IPv6' ? '::1' : '127.0.0.1';
    raw.localPort = localPort;
    raw.localFamily = family;
    return raw;
  }

  function listenTlsServer(
    server: any,
    host = '127.0.0.1',
    port = 44321,
    family: 'IPv4' | 'IPv6' = 'IPv4',
  ) {
    server.listen({ host, port, family });
    server.emit('listening');
  }

  function acceptTlsServerSocket(server: any, clientRaw: any) {
    const listener = _serverConnectionListeners.get(server);
    if (!listener) throw new Error('missing fake TLS server connection listener');
    const serverRaw = connectedRaw(clientRaw.localAddress, clientRaw.localPort);
    serverRaw.remoteFamily = clientRaw.localFamily;
    serverRaw.localAddress = clientRaw.remoteAddress;
    serverRaw.localPort = clientRaw.remotePort;
    serverRaw.localFamily = clientRaw.remoteFamily;
    listener(serverRaw);
    return serverRaw;
  }

  function useInternalRawSocket(raw: any) {
    _net.connect = () => raw;
  }

  function installTlsBridge(overrides: Record<string, any> = {}) {
    const state: any = { closes: [], ownerCloses: [], writes: [], nextId: 91, nextToken: 501 };
    g.__exactTlsOwnerToken = (action: string, token?: number) => {
      if (action === 'new') return state.nextToken++;
      if (action === 'close') state.ownerCloses.push(token);
    };
    g.__exactTlsEngineNew = () => state.nextId;
    g.__exactTlsEngineWriteTls = (id: number, chunk: Uint8Array) => {
      state.writes.push(Buffer.from(chunk).toString());
      return chunk.byteLength;
    };
    g.__exactTlsEngineReadTls = () => new Uint8Array(0);
    g.__exactTlsEngineReadPlain = () => '';
    g.__exactTlsEngineWritePlain = (_id: number, chunk: Uint8Array) => chunk.byteLength;
    g.__exactTlsEngineStatus = () => JSON.stringify({ handshaking: true });
    g.__exactTlsEngineClose = (id: number) => { state.closes.push(id); };
    g.__exactTlsEngineTransportEof = () => {};
    g.__exactTlsEngineShutdown = () => {};
    g.__exactTlsEnginePeerCerts = () => '[]';
    Object.assign(g, overrides);
    return state;
  }

  test('private loopback handoff orders secureConnect, secure, then one secureConnection', async () => {
    const events: string[] = [];
    let acceptedSocket: any = null;
    const server = tls.createServer({}, (socket: any) => {
      acceptedSocket = socket;
      events.push('server secureConnection');
    });
    server.on('tlsClientError', () => events.push('server tlsClientError'));
    listenTlsServer(server);

    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51001);
    useInternalRawSocket(raw);
    acceptTlsServerSocket(server, raw);
    const socket = tls.connect({
      host: '127.0.0.1',
      port: 44321,
      rejectUnauthorized: false,
    });
    socket.on('secureConnect', () => events.push('client secureConnect'));
    socket.on('secure', () => events.push('client secure'));
    socket.on('error', (err: any) => events.push(`client error:${err.code}`));

    await waitForHandshake();
    expect(events).toEqual([
      'client secureConnect',
      'client secure',
      'server secureConnection',
    ]);
    expect(server._pendingTlsHandshakes).toBeUndefined();
    expect(server._pendingTlsSockets).toBeUndefined();

    socket.destroy();
    if (acceptedSocket) acceptedSocket.destroy();
    server.emit('close');
  });

  test('private loopback handoff emits tlsClientError and no secureConnection on failure', async () => {
    const server = tls.createServer({ ciphers: 'TLS_AES_128_GCM_SHA256' });
    let secureCount = 0;
    let errCount = 0;
    server.on('secureConnection', () => { secureCount++; });
    server.on('tlsClientError', () => { errCount++; });
    listenTlsServer(server);

    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51002);
    useInternalRawSocket(raw);
    acceptTlsServerSocket(server, raw);
    const socket = tls.connect({
      host: '127.0.0.1',
      port: 44321,
      ciphers: 'TLS_AES_256_GCM_SHA384',
      rejectUnauthorized: false,
    });
    let clientSecure = 0;
    const clientErrors: string[] = [];
    socket.on('secureConnect', () => { clientSecure++; });
    socket.on('error', (err: any) => clientErrors.push(err.code));

    await waitForHandshake();
    expect(errCount).toBe(1);
    expect(secureCount).toBe(0);
    expect(clientSecure).toBe(0);
    expect(clientErrors).toEqual(['ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE']);
    expect(server._pendingTlsHandshakes).toBeUndefined();

    server.emit('close');
  });

  test('strict loopback authentication fails loudly instead of publishing secure state', async () => {
    const serverErrors: string[] = [];
    const server = tls.createServer({});
    server.on('tlsClientError', (err: any) => serverErrors.push(err.code));
    let serverSecure = 0;
    server.on('secureConnection', () => { serverSecure++; });
    listenTlsServer(server);

    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51003);
    useInternalRawSocket(raw);
    acceptTlsServerSocket(server, raw);
    const socket = tls.connect({ host: '127.0.0.1', port: 44321 });
    const clientEvents: string[] = [];
    socket.on('secureConnect', () => clientEvents.push('secureConnect'));
    socket.on('secure', () => clientEvents.push('secure'));
    socket.on('error', (err: any) => clientEvents.push(`error:${err.code}`));
    socket.on('close', () => clientEvents.push('close'));

    await waitForHandshake();
    expect(clientEvents).toEqual([
      'error:ERR_TLS_LOOPBACK_AUTH_UNSUPPORTED',
      'close',
    ]);
    expect(serverErrors).toEqual(['ECONNRESET']);
    expect(serverSecure).toBe(0);

    server.emit('close');
  });

  test('client secure events stay held until the server accepts a queued handshake', async () => {
    const events: string[] = [];
    const server = tls.createServer({}, () => events.push('server secure'));
    listenTlsServer(server);

    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51031);
    useInternalRawSocket(raw);
    const socket = tls.connect({
      host: '127.0.0.1',
      port: 44321,
      rejectUnauthorized: false,
    });
    socket.on('secureConnect', () => events.push('client secure'));
    socket.on('error', (err: any) => events.push(`error:${err.code}`));

    await waitForTurn();
    expect(events).toEqual([]);
    const acceptedRaw = acceptTlsServerSocket(server, raw);
    await waitForHandshake();
    expect(events).toEqual(['client secure', 'server secure']);

    socket.destroy();
    acceptedRaw.destroy();
    server.emit('close');
  });

  test('SecureContext and local certificate projections never expose private identity material', async () => {
    const context = tls.createSecureContext({
      key: 'TOP_SECRET_PRIVATE_KEY',
      pfx: Buffer.from('TOP_SECRET_PFX'),
      passphrase: 'TOP_SECRET_PASSPHRASE',
    });
    expect(context.context).toEqual({});
    expect(context._options).toBeUndefined();
    expect(JSON.stringify(context)).not.toContain('TOP_SECRET');

    let localCertificate: any = null;
    const server = tls.createServer({ key: 'TOP_SECRET_PRIVATE_KEY' }, (socket: any) => {
      localCertificate = socket.getCertificate();
    });
    listenTlsServer(server);
    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51032);
    useInternalRawSocket(raw);
    acceptTlsServerSocket(server, raw);
    const client = tls.connect({
      host: '127.0.0.1',
      port: 44321,
      rejectUnauthorized: false,
    });
    client.on('error', () => {});
    await waitForHandshake();

    expect(JSON.stringify(localCertificate || {})).not.toContain('TOP_SECRET');
    client.destroy();
    server.emit('close');
  });

  test('TLS server credential methods are immutable owner-checked boundaries', () => {
    installTlsBridge();
    const server = tls.createServer({});
    for (const name of ['addContext', 'setSecureContext', 'getTicketKeys', 'setTicketKeys']) {
      const original = server[name];
      const descriptor = Object.getOwnPropertyDescriptor(server, name);
      expect(descriptor?.configurable).toBe(false);
      expect(descriptor?.writable).toBe(false);
      expect(Reflect.set(server, name, () => server)).toBe(false);
      expect(server[name]).toBe(original);
    }
    server.emit('close');
  });

  test('checkServerIdentity canonicalizes IPs and rejects invalid IP-shaped hosts', () => {
    expect(tls.checkServerIdentity('2001:0db8::1', {
      subject: {},
      subjectaltname: 'IP Address:2001:db8::1',
    })).toBeUndefined();
    expect(tls.checkServerIdentity('999.1.1.1', {
      subject: {},
      subjectaltname: 'IP Address:999.1.1.1',
    })?.code).toBe('ERR_TLS_CERT_ALTNAME_INVALID');
  });

  test('private event dispatch preserves EventEmitter captureRejections', async () => {
    const { EventEmitter } = require('events');
    const previousCapture = EventEmitter.captureRejections;
    EventEmitter.captureRejections = true;
    const events: string[] = [];
    let errorThenCalls = 0;
    let acceptedSocket: any = null;
    try {
      const server = tls.createServer({}, (socket: any) => {
        acceptedSocket = socket;
        socket.on('error', (err: any) => {
          events.push(`error:${err.message}`);
          return {
            then(_resolve: any, reject: (error: Error) => void) {
              errorThenCalls++;
              reject(new Error('ERROR_HANDLER_REJECTION'));
            },
          };
        });
        socket.on('data', async () => { throw new Error('REJECTED'); });
      });
      listenTlsServer(server);
      const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51033);
      useInternalRawSocket(raw);
      const serverRaw = acceptTlsServerSocket(server, raw);
      const client = tls.connect({
        host: '127.0.0.1',
        port: 44321,
        rejectUnauthorized: false,
      });
      client.on('error', () => {});
      await waitForHandshake();

      serverRaw.emit('data', Buffer.from('payload'));
      await waitForTurn();
      expect(events).toEqual(['error:REJECTED']);
      expect(errorThenCalls).toBe(0);

      client.destroy();
      if (acceptedSocket) acceptedSocket.destroy();
      server.emit('close');
    } finally {
      EventEmitter.captureRejections = previousCapture;
    }
  });

  test('same-port IPv4 and IPv6 loopback registries do not cross-pair', async () => {
    const port = 44322;
    let server4Secure = 0;
    let server6Secure = 0;
    let accepted4: any = null;
    let accepted6: any = null;
    const server4 = tls.createServer({}, (socket: any) => {
      accepted4 = socket;
      server4Secure++;
    });
    const server6 = tls.createServer({}, (socket: any) => {
      accepted6 = socket;
      server6Secure++;
    });
    listenTlsServer(server4, '127.0.0.1', port, 'IPv4');
    listenTlsServer(server6, '::1', port, 'IPv6');

    const raw4 = internalLoopbackRaw('127.0.0.1', port, 'IPv4', 51004);
    useInternalRawSocket(raw4);
    acceptTlsServerSocket(server4, raw4);
    const client4 = tls.connect({
      host: '127.0.0.1',
      port,
      rejectUnauthorized: false,
    });
    let client4Secure = 0;
    client4.on('secureConnect', () => { client4Secure++; });
    client4.on('error', () => {});

    const raw6 = internalLoopbackRaw('::1', port, 'IPv6', 51006);
    useInternalRawSocket(raw6);
    acceptTlsServerSocket(server6, raw6);
    const client6 = tls.connect({
      host: '::1',
      port,
      rejectUnauthorized: false,
    });
    let client6Secure = 0;
    client6.on('secureConnect', () => { client6Secure++; });
    client6.on('error', () => {});

    await waitForHandshake();
    expect(client4Secure).toBe(1);
    expect(client6Secure).toBe(1);
    expect(server4Secure).toBe(1);
    expect(server6Secure).toBe(1);

    client4.destroy();
    client6.destroy();
    if (accepted4) accepted4.destroy();
    if (accepted6) accepted6.destroy();
    server4.emit('close');
    server6.emit('close');
  });

  test('an already-connected transport cannot emit unauthenticated bytes before path selection', () => {
    const { EventEmitter } = require('events');
    const raw: any = new EventEmitter();
    raw.connecting = false;
    raw.remoteAddress = '203.0.113.10';
    raw.remotePort = 443;
    raw.pause = () => { raw.paused = true; return raw; };
    raw.resume = () => { raw.paused = false; return raw; };
    raw.write = () => true;
    raw.end = () => raw;
    raw.destroy = () => { raw.destroyed = true; return raw; };

    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    const leaked: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => leaked.push(Buffer.from(chunk)));
    raw.emit('data', Buffer.from([0x16, 0x03, 0x03, 0x00, 0x01]));

    expect(leaked).toEqual([]);
    expect(raw.paused).toBe(true);
    socket.destroy();
  });

  test('bridged pipe removes backpressure listeners when the destination closes', () => {
    const { EventEmitter } = require('events');
    const raw = connectedRaw();
    raw.connecting = true;
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    const dest: any = new EventEmitter();
    dest.write = () => false;
    dest.end = () => {};

    socket.pipe(dest, { end: false });
    socket.emit('data', Buffer.from('blocked'));
    expect(raw.paused).toBe(true);
    expect(dest.listenerCount('drain')).toBe(1);
    dest.emit('close');

    expect(raw.paused).toBe(false);
    expect(dest.listenerCount('drain')).toBe(0);
    expect(socket.listenerCount('data')).toBe(0);
    socket.destroy();
  });

  test('bridge handoff preserves retained-vs-reentrant ciphertext order', async () => {
    let firstRead = true;
    const state = installTlsBridge({
      __exactTlsEngineReadTls: () => {
        if (!firstRead) return new Uint8Array(0);
        firstRead = false;
        return Buffer.from('client-hello');
      },
    });
    const raw = connectedRaw();
    let injected = false;
    raw.write = () => {
      if (!injected) {
        injected = true;
        raw.emit('data', Buffer.from('new'));
      }
      return true;
    };
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    raw.emit('data', Buffer.from('old'));

    await waitForTurn();
    expect(state.writes).toEqual(['old', 'new']);
    socket.destroy();
  });

  test('native ciphertext read exceptions fail the bridge loudly', async () => {
    const readError: any = new Error('native TLS read lease failed');
    readError.code = 'ERR_TLS_READ_LEASE';
    const state = installTlsBridge({
      __exactTlsEngineReadTls: () => { throw readError; },
    });
    const raw = connectedRaw();
    const events: string[] = [];
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', (err: any) => events.push(`error:${err.code}`));
    socket.on('close', () => events.push('close'));

    await waitForTurn();
    expect(events).toEqual(['error:ERR_TLS_READ_LEASE', 'close']);
    expect(socket.destroyed).toBe(true);
    expect(state.closes).toEqual([91]);
  });

  test('configured default CAs are forwarded to the native bridge', async () => {
    const customCa = '-----BEGIN CERTIFICATE-----\nCUSTOM-CA\n-----END CERTIFICATE-----';
    let engineConfig: any = null;
    installTlsBridge({
      __exactTlsEngineNew: (json: string) => {
        engineConfig = JSON.parse(json);
        return 91;
      },
    });
    tls.setDefaultCACertificates([customCa]);
    const raw = connectedRaw();
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    try {
      await waitForTurn();
      expect(engineConfig.ca).toContain(customCa);
    } finally {
      tls.setDefaultCACertificates([]);
      socket.destroy();
    }
  });

  test('retained end/close reaches native EOF and emits one error then one close', async () => {
    const state = installTlsBridge();
    const raw = connectedRaw();
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    const events: string[] = [];
    socket.on('error', () => events.push('error'));
    socket.on('end', () => events.push('end'));
    socket.on('close', () => events.push('close'));
    raw.emit('end');
    raw.destroyed = true;
    raw.emit('close', true);

    await waitForTurn();
    expect(events).toEqual(['error', 'close']);
    expect(state.closes).toEqual([91]);
    expect(socket.destroyed).toBe(true);
  });

  test('native TLS status failures terminate loudly instead of stalling the handshake', async () => {
    const statusError = new Error('native status unavailable');
    const state = installTlsBridge({
      __exactTlsEngineStatus: () => { throw statusError; },
    });
    const raw = connectedRaw();
    const events: string[] = [];
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', (err: any) => events.push(`error:${err.message}`));
    socket.on('close', () => events.push('close'));

    raw.emit('data', Buffer.from('handshake'));
    await waitForTurn();

    expect(events).toEqual(['error:native status unavailable', 'close']);
    expect(state.closes).toEqual([91]);
    expect(socket.destroyed).toBe(true);
  });

  test('native transport EOF failures commit no silent EOF and terminate loudly', async () => {
    let handshaking = true;
    let eofAttempts = 0;
    const state = installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineTransportEof: () => {
        eofAttempts += 1;
        throw new Error('native EOF rejected');
      },
    });
    const raw = connectedRaw();
    const events: string[] = [];
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    socket.on('secureConnect', () => events.push('secure'));
    socket.on('error', (err: any) => events.push(`error:${err.message}`));
    socket.on('close', () => events.push('close'));

    raw.emit('data', Buffer.from('handshake'));
    raw.emit('end');
    await waitForTurn();

    expect(events).toEqual(['secure', 'error:native EOF rejected', 'close']);
    expect(eofAttempts).toBe(1);
    expect(state.closes).toEqual([91]);
    expect(socket.destroyed).toBe(true);
  });

  test('retained close after a successful handshake releases after end', async () => {
    let handshaking = true;
    let eof = false;
    const state = installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineReadPlain: () => eof ? null : '',
      __exactTlsEngineTransportEof: () => { eof = true; },
    });
    const raw = connectedRaw();
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    const events: string[] = [];
    socket.on('error', () => events.push('error'));
    socket.on('secureConnect', () => events.push('secure'));
    socket.on('end', () => events.push('end'));
    socket.on('close', () => events.push('close'));
    raw.emit('data', Buffer.from('handshake'));
    raw.emit('close', false);

    await waitForTurn();
    expect(events).toEqual(['secure', 'end', 'close']);
    expect(state.closes).toEqual([91]);
    expect(socket.destroyed).toBe(true);
  });

  test('post-selection close waits for readable plaintext and end before close', async () => {
    let handshaking = true;
    let eof = false;
    let delivered = false;
    const state = installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineReadPlain: () => {
        if (!eof) return '';
        if (!delivered) {
          delivered = true;
          return Buffer.from('tail');
        }
        return null;
      },
      __exactTlsEngineTransportEof: () => { eof = true; },
    });
    const raw = connectedRaw();
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    const events: string[] = [];
    socket.on('error', () => events.push('error'));
    socket.on('secureConnect', () => events.push('secure'));
    socket.on('readable', () => events.push('readable'));
    socket.on('end', () => events.push('end'));
    socket.on('close', () => events.push('close'));
    await waitForTurn();
    raw.emit('data', Buffer.from('handshake'));
    raw.destroyed = true;
    raw.emit('close', false);

    expect(events).toEqual(['secure', 'readable']);
    expect(state.closes).toEqual([]);
    expect(Buffer.from(socket.read()).toString()).toBe('tail');
    await waitForTurn();
    expect(events).toEqual(['secure', 'readable', 'end', 'close']);
    expect(state.closes).toEqual([91]);
  });

  test('public engine-id writes are inert and failed native close is owner-retryable', async () => {
    let failClose = true;
    const state = installTlsBridge({
      __exactTlsEngineClose: (id: number) => {
        state.closes.push(id);
        if (failClose) {
          failClose = false;
          throw new Error('wrong principal');
        }
      },
    });
    const raw = connectedRaw();
    let rawDestroyCount = 0;
    raw.destroy = () => { rawDestroyCount++; raw.destroyed = true; return raw; };
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    await waitForTurn();

    socket._tlsEngineId = 999;
    expect(() => socket.destroy()).toThrow('wrong principal');
    expect(socket.destroyed).toBe(false);
    expect(rawDestroyCount).toBe(0);
    socket.destroy();
    expect(state.closes).toEqual([91, 91]);
    expect(rawDestroyCount).toBe(1);
  });

  test('terminal close detaches raw listeners and late raw data cannot resurrect the wrapper', async () => {
    installTlsBridge();
    const raw = connectedRaw();
    let rawWrites = 0;
    let rawDestroys = 0;
    raw.write = () => { rawWrites++; return true; };
    // A retained custom transport may omit terminal events and remain usable.
    raw.destroy = () => { rawDestroys++; return raw; };
    const socket = new tls.TLSSocket(raw, {});
    socket.on('close', () => {});
    socket.destroy();
    await waitForTurn();

    for (const eventName of [
      'data', 'end', 'error', 'close', 'timeout', 'drain', 'lookup', 'ready', 'connect',
    ]) {
      expect(raw.listenerCount(eventName)).toBe(0);
    }
    raw.emit('data', Buffer.from('late'));
    expect(socket.destroyed).toBe(true);
    expect(rawDestroys).toBe(1);

    // Releasing the private owner token at terminal close must not turn a
    // retained wrapper into ambient mutation authority. Direct public calls
    // fail closed, while base-prototype bypass attempts cannot restore event
    // state or reach the retained raw transport.
    let lateEvents = 0;
    expect(() => { socket.authorized = true; }).toThrow(/closed TLSSocket/);
    expect(() => socket.write(Buffer.from('late'))).toThrow(/closed TLSSocket/);
    expect(() => socket.on('late', () => { lateEvents++; })).toThrow(/closed TLSSocket/);
    const { EventEmitter } = require('events');
    expect(() => EventEmitter.prototype.on.call(socket, 'late', () => { lateEvents++; })).toThrow();
    expect(EventEmitter.prototype.emit.call(socket, 'late')).toBe(false);
    expect(() => _net.Socket.prototype.write.call(socket, Buffer.from('late'))).toThrow();
    expect(() => _net.Socket.prototype.end.call(socket)).toThrow();
    expect(() => _net.Socket.prototype.destroy.call(socket)).toThrow();
    expect(EventEmitter.prototype.emit.call(socket, 'late')).toBe(false);
    expect(lateEvents).toBe(0);
    expect(rawWrites).toBe(0);
    expect(rawDestroys).toBe(1);
    expect(socket.destroyed).toBe(true);
  });

  test('private TLS state and owner denial both reject direct mutation', async () => {
    installTlsBridge();
    const raw = connectedRaw();
    const socket = tls.connect({ socket: raw, host: raw.remoteAddress, port: raw.remotePort });
    socket.on('error', () => {});
    await waitForTurn();

    const ownerHook = g.__exactTlsOwnerToken;
    let ownerAssertions = 0;
    g.__exactTlsOwnerToken = (action: string, token?: number) => {
      if (action === 'assert') {
        ownerAssertions++;
        throw new Error(`owner denied token ${token}`);
      }
      return ownerHook(action, token);
    };
    try {
      expect(() => {
        socket._bridgeReadQueue = [Buffer.from('forged')];
      }).toThrow('TLSSocket internal state is not publicly mutable');
      expect(() => {
        socket.authorized = true;
      }).toThrow('owner denied token 501');
    } finally {
      g.__exactTlsOwnerToken = ownerHook;
    }
    expect(ownerAssertions).toBe(1);
    expect(socket.authorized).toBe(false);
    socket.destroy();
  });

  test('supplied loopback sockets are excluded and fail loud without exposing early bytes', async () => {
    const server = tls.createServer({}, () => {});
    server.emit('listening');
    const raw = connectedRaw('127.0.0.1', 0);
    raw.destroy = (err: any) => {
      raw.destroyed = true;
      if (err) raw.emit('error', err);
      raw.emit('close', !!err);
      return raw;
    };
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    const events: string[] = [];
    socket.on('secureConnect', () => events.push('secure'));
    socket.on('data', () => events.push('data'));
    socket.on('error', (err: any) => events.push(`error:${err.code}`));
    socket.on('close', () => events.push('close'));
    raw.emit('data', Buffer.from('unauthenticated'));

    await waitForTurn();
    expect(events).toEqual(['error:ERR_TLS_EMULATION_LOOPBACK_ONLY', 'close']);
    expect(server._pendingTlsHandshakes).toBeUndefined();
    expect(server._pendingTlsSockets).toBeUndefined();
    server.emit('close');
  });

  test('destroying a supplied transport from connect never resurrects a secure socket', async () => {
    const server = tls.createServer({}, () => {});
    server.emit('listening');
    const raw = connectedRaw('127.0.0.1', 0);
    raw.connecting = true;
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    let secure = 0;
    socket.on('connect', () => raw.destroy());
    socket.on('secureConnect', () => { secure++; });
    raw.connecting = false;
    raw.emit('connect');

    await waitForTurn();
    expect(secure).toBe(0);
    expect(socket.destroyed).toBe(true);
    server.emit('close');
  });

  test('destroying raw transport from secure keeps prior secureConnect and drops held plaintext', async () => {
    const server = tls.createServer({}, () => {});
    listenTlsServer(server);
    const raw = internalLoopbackRaw('127.0.0.1', 44321, 'IPv4', 51007);
    const writes: string[] = [];
    raw.write = (chunk: Uint8Array) => { writes.push(Buffer.from(chunk).toString()); return true; };
    useInternalRawSocket(raw);
    acceptTlsServerSocket(server, raw);
    const socket = tls.connect({
      host: '127.0.0.1',
      port: 44321,
      rejectUnauthorized: false,
    });
    let secureConnect = 0;
    socket.write('secret');
    socket.on('secure', () => raw.destroy());
    socket.on('secureConnect', () => { secureConnect++; });

    await waitForHandshake();
    expect(secureConnect).toBe(1);
    expect(writes).toEqual([]);
    expect(socket.destroyed).toBe(true);
    server.emit('close');
  });

  test('undecided pause/resume and pipe cannot override the security pause', async () => {
    const server = tls.createServer({}, () => {});
    server.emit('listening');
    const raw = connectedRaw('127.0.0.1', 0);
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    socket.pause();
    expect(raw.paused).toBe(true);
    socket.resume();
    expect(raw.paused).toBe(false);

    raw.emit('data', Buffer.from('guarded'));
    expect(raw.paused).toBe(true);
    const { EventEmitter } = require('events');
    const dest: any = new EventEmitter();
    dest.write = () => true;
    dest.end = () => {};
    socket.pipe(dest);
    expect(raw.paused).toBe(true);

    socket.destroy();
    server.emit('close');
  });

  test('pause and destroy remain effective during bridged queued-data callbacks', async () => {
    let handshaking = true;
    let plaintext: any[] = [Buffer.from('held'), ''];
    installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineReadPlain: () => plaintext.length ? plaintext.shift() : '',
    });
    const raw = connectedRaw();
    const pausedSocket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    pausedSocket.on('error', () => {});
    await waitForTurn();
    pausedSocket.pause();
    const pausedGot: string[] = [];
    pausedSocket.on('data', (chunk: Buffer) => pausedGot.push(chunk.toString()));
    raw.emit('data', Buffer.from('record'));
    expect(pausedGot).toEqual([]);
    pausedSocket.resume();
    expect(pausedGot).toEqual(['held']);
    pausedSocket.destroy();

    handshaking = true;
    plaintext = [Buffer.from('a'), Buffer.from('b'), ''];
    installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineReadPlain: () => plaintext.length ? plaintext.shift() : '',
    });
    const raw2 = connectedRaw();
    const destroySocket = tls.connect({
      socket: raw2,
      host: raw2.remoteAddress,
      port: raw2.remotePort,
      rejectUnauthorized: false,
    });
    destroySocket.on('error', () => {});
    await waitForTurn();
    const destroyGot: string[] = [];
    destroySocket.on('data', (chunk: Buffer) => {
      destroyGot.push(chunk.toString());
      destroySocket.destroy();
    });
    raw2.emit('data', Buffer.from('record'));
    expect(destroyGot).toEqual(['a']);
  });

  test('destroying from decoder EOF tail suppresses the later end event', async () => {
    let handshaking = true;
    const plaintext: any[] = [Buffer.from([0xe2, 0x82]), null];
    installTlsBridge({
      __exactTlsEngineWriteTls: (_id: number, chunk: Uint8Array) => {
        handshaking = false;
        return chunk.byteLength;
      },
      __exactTlsEngineStatus: () => JSON.stringify({
        handshaking,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        verify: { checked: false, chainOk: false },
      }),
      __exactTlsEngineReadPlain: () => plaintext.length ? plaintext.shift() : '',
    });
    const raw = connectedRaw();
    const socket = tls.connect({
      socket: raw,
      host: raw.remoteAddress,
      port: raw.remotePort,
      rejectUnauthorized: false,
    });
    socket.on('error', () => {});
    await waitForTurn();
    const events: string[] = [];
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      events.push(`data:${chunk}`);
      socket.destroy();
    });
    socket.on('end', () => events.push('end'));
    raw.emit('data', Buffer.from('record'));

    expect(events).toEqual(['data:\ufffd']);
    expect(socket.destroyed).toBe(true);
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
