/**
 * End-to-end regression tests for the native WebSocket bridge (ENG-23469).
 *
 * Unlike the fake-bridge unit tests in this directory, these spawn the real
 * ibex binary and drive a live loopback connection: a builtin-`ws` echo/
 * command server and a global WebSocket client inside one ibex process, so
 * the platform native (NSURLSession on macOS, libcurl on Linux, WinHTTP on
 * Windows) and the JSI bridge are actually exercised.
 *
 * Covered regressions:
 * - empty sends ('' / Uint8Array(0) / ArrayBuffer(0)) transmit real frames
 *   (the bridge dropped empty typed-array payloads; Linux/Windows natives
 *   dropped every zero-length payload),
 * - text frames with an embedded NUL arrive full-length (macOS used strlen),
 * - a 100KB text message arrives as ONE string message event (Linux
 *   surfaced each curl chunk as a separate, mis-typed message),
 * - server close code/reason surface in the CloseEvent (Linux reported
 *   1000/'' unconditionally),
 * - client close() fires the close event (Linux never invoked close_cb).
 *
 * Skips when the ibex binary has not been built (matches the repo's
 * hermes-gated test convention); build with `cargo build` or point IBEX_BIN
 * at a binary.
 *
 * Run with: bun test packages/ibex-runtime-js/src/websocket
 */
import { expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

const repoRoot = path.resolve(import.meta.dir, '../../../..');
const ibexBin = process.env.IBEX_BIN
  ? path.resolve(process.env.IBEX_BIN)
  : path.join(repoRoot, 'target', 'debug', 'ibex');
const haveIbex = existsSync(ibexBin);

// The fixture runs entirely inside one ibex process. It prints PASS/FAIL per
// check plus a final RESULT line and exits nonzero on any failure. The
// embedded-NUL payload is spelled \u0000 so it survives as a source escape.
const fixtureSource = String.raw`
'use strict';
const { WebSocketServer } = require('ws');

let failures = 0;
function report(name, ok, detail) {
  if (!ok) failures += 1;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ' — ' + detail : ''));
}
function fatal(msg) {
  console.log('FATAL ' + msg);
  console.log('RESULT: FAIL');
  process.exit(1);
}
const overallTimeout = setTimeout(() => fatal('overall timeout (20s)'), 20000);

const server = new WebSocketServer({ host: '127.0.0.1', port: 0 }, () => {
  const addr = server.address();
  const port = typeof addr === 'object' ? addr.port : addr;
  run(port).catch((err) => fatal('client error: ' + ((err && err.stack) || err)));
});

server.on('connection', (sock) => {
  sock.on('message', (data, isBinary) => {
    if (!isBinary) {
      const text = String(data);
      if (text === 'cmd:nul') return void sock.send('a\u0000b');
      if (text === 'cmd:big') return void sock.send('x'.repeat(100000));
      if (text === 'cmd:close') return void sock.close(4001, 'bye');
      sock.send(JSON.stringify({ kind: 'string', len: text.length, value: text.slice(0, 32) }));
    } else {
      const len = data && typeof data.byteLength === 'number'
        ? data.byteLength
        : (Array.isArray(data) ? data.reduce((n, c) => n + c.byteLength, 0) : -1);
      sock.send(JSON.stringify({ kind: 'binary', len }));
    }
  });
});

function connect(port) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket('ws://127.0.0.1:' + port + '/');
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error('connect failed: ' + (e && e.message)));
  });
}

function nextMessage(ws, ms = 5000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timed out waiting for message')), ms);
    ws.onmessage = (ev) => {
      clearTimeout(t);
      ws.onmessage = null;
      resolve(ev.data);
    };
  });
}

async function run(port) {
  const ws = await connect(port);

  ws.send('hello');
  let reply = JSON.parse(await nextMessage(ws));
  report('text round-trip', reply.kind === 'string' && reply.len === 5 && reply.value === 'hello', JSON.stringify(reply));

  ws.send('');
  reply = JSON.parse(await nextMessage(ws));
  report('empty string send observed by server', reply.kind === 'string' && reply.len === 0, JSON.stringify(reply));

  ws.send(new Uint8Array(0));
  reply = JSON.parse(await nextMessage(ws));
  report('empty Uint8Array send observed by server', reply.kind === 'binary' && reply.len === 0, JSON.stringify(reply));

  ws.send(new ArrayBuffer(0));
  reply = JSON.parse(await nextMessage(ws));
  report('empty ArrayBuffer send observed by server', reply.kind === 'binary' && reply.len === 0, JSON.stringify(reply));

  ws.send('cmd:nul');
  const nulMsg = await nextMessage(ws);
  report(
    'NUL-embedded text arrives full-length',
    typeof nulMsg === 'string' && nulMsg.length === 3 && nulMsg === 'a\u0000b',
    'len=' + (typeof nulMsg === 'string' ? nulMsg.length : '?')
  );

  ws.send('cmd:big');
  const bigMsg = await nextMessage(ws);
  report(
    '100KB text arrives as one string message',
    typeof bigMsg === 'string' && bigMsg.length === 100000,
    'type=' + typeof bigMsg + ' len=' + (typeof bigMsg === 'string' ? bigMsg.length : '?')
  );

  const closeEvt = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timed out waiting for close')), 5000);
    ws.onclose = (ev) => { clearTimeout(t); resolve(ev); };
    ws.send('cmd:close');
  });
  report(
    'server close code/reason surfaced',
    closeEvt.code === 4001 && closeEvt.reason === 'bye',
    'code=' + closeEvt.code + ' reason=' + JSON.stringify(closeEvt.reason)
  );

  const ws2 = await connect(port);
  const closeEvt2 = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('client close never fired onclose')), 5000);
    ws2.onclose = (ev) => { clearTimeout(t); resolve(ev); };
    ws2.close(1000, 'done');
  });
  report(
    'client close() fires close event',
    ws2.readyState === 3,
    'code=' + closeEvt2.code + ' wasClean=' + closeEvt2.wasClean + ' readyState=' + ws2.readyState
  );

  clearTimeout(overallTimeout);
  server.close();
  console.log('RESULT: ' + (failures === 0 ? 'PASS' : 'FAIL'));
  process.exit(failures === 0 ? 0 : 1);
}
`;

test.skipIf(!haveIbex)(
  'native WebSocket bridge: empty frames, NUL text, large messages, close semantics (live loopback)',
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'ibex-ws-e2e-'));
    const fixturePath = path.join(dir, 'ws-e2e.js');
    try {
      await writeFile(fixturePath, fixtureSource);
      const proc = Bun.spawn([ibexBin, fixturePath], {
        cwd: repoRoot,
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const killTimer = setTimeout(() => proc.kill(), 45000);
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);
      clearTimeout(killTimer);
      const detail = `exit=${exitCode}\nstdout:\n${stdout}\nstderr:\n${stderr}`;
      expect(stdout, detail).toContain('RESULT: PASS');
      expect(stdout, detail).not.toContain('FAIL ');
      expect(exitCode, detail).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
  60000
);
