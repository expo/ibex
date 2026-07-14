// Live-loopback fixture for the native WebSocket bridge e2e test
// (ENG-23469). Runs entirely inside one ibex process: a builtin-`ws`
// echo/command server plus a real global WebSocket client. Prints PASS/FAIL
// per check and a final RESULT line; exits nonzero on any failure.
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
    const url = 'ws://127.0.0.1:' + port + '/';
    const canonicalUrl = new URL(url).href;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (error) {
      reject(new Error(
        'connect construction failed for ' + url +
        ' (canonical ' + canonicalUrl + '): ' + error
      ));
      return;
    }
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

  // Empty sends must transmit real frames (WHATWG); the server's message
  // handler observing them is the assertion.
  ws.send('');
  reply = JSON.parse(await nextMessage(ws));
  report('empty string send observed by server', reply.kind === 'string' && reply.len === 0, JSON.stringify(reply));

  ws.send(new Uint8Array(0));
  reply = JSON.parse(await nextMessage(ws));
  report('empty Uint8Array send observed by server', reply.kind === 'binary' && reply.len === 0, JSON.stringify(reply));

  ws.send(new ArrayBuffer(0));
  reply = JSON.parse(await nextMessage(ws));
  report('empty ArrayBuffer send observed by server', reply.kind === 'binary' && reply.len === 0, JSON.stringify(reply));

  // U+0000 is valid inside a text frame; the macOS bridge used strlen.
  ws.send('cmd:nul');
  const nulMsg = await nextMessage(ws);
  report(
    'NUL-embedded text arrives full-length',
    typeof nulMsg === 'string' && nulMsg.length === 3 && nulMsg === 'a\u0000b',
    'len=' + (typeof nulMsg === 'string' ? nulMsg.length : '?')
  );

  // Fragmented/chunked delivery must still surface exactly one message.
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

  // Stop listening, then connect to the now-closed loopback port. Native
  // backends report a failed handshake as error followed by close(1006). The
  // bridge must deduplicate terminal callbacks without letting error consume
  // the following close and strand readyState at CONNECTING.
  await new Promise((resolve) => server.close(resolve));
  const failedEvents = [];
  const failed = new WebSocket('ws://127.0.0.1:' + port + '/');
  const failedClose = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(
      'failed handshake never delivered close; events=' + failedEvents.join(','))), 5000);
    failed.onerror = () => failedEvents.push('error');
    failed.onclose = (ev) => {
      clearTimeout(t);
      failedEvents.push('close');
      resolve(ev);
    };
  });
  report(
    'failed handshake delivers error then close',
    failedEvents.join(',') === 'error,close' &&
      failedClose.code === 1006 &&
      failed.readyState === 3,
    'events=' + failedEvents.join(',') +
      ' code=' + failedClose.code +
      ' readyState=' + failed.readyState
  );

  clearTimeout(overallTimeout);
  console.log('RESULT: ' + (failures === 0 ? 'PASS' : 'FAIL'));
  process.exit(failures === 0 ? 0 : 1);
}
