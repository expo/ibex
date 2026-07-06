//! End-to-end regression tests for the Node-compat networking builtins
//! (http.js / ws.js), driving the real `ibex` binary over loopback TCP.
//!
//! ENG-23126 pinned three findings:
//!   * http server: a request body consumed via 'readable' + read() hung
//!     forever once the body crossed the readable highWaterMark, because
//!     read() never resumed the socket that _pushBodyChunk paused.
//!   * http client: the response socket ran in flowing mode with push()'s
//!     backpressure signal discarded, so a slow consumer buffered the whole
//!     response in memory.
//!   * ws server: no maxPayload cap — an untrusted peer could OOM the process
//!     with an unbounded fragment stream or a huge declared frame length.
//!
//! Run with: `scripts/run-tests.sh --scope test node_net`
//! (or `cargo test --test node_net_builtins`).

use serde_json::Value;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

async fn run_script(script: &str, secs: u64) -> Value {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-e").arg(script);

    let output = timeout(Duration::from_secs(secs), cmd.output())
        .await
        .expect("ibex process timed out (harness-level; the script watchdog should fire first)")
        .expect("failed to spawn or read ibex process output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ibex should exit 0: status={:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
    let json = stdout.trim_end().lines().last().unwrap_or("");
    serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("last stdout line should be JSON ({e}): {stdout}"))
}

#[tokio::test]
async fn node_net_http_server_readable_read_drains_body_past_highwatermark() {
    // Streams a 512 KiB request body (8 x 64 KiB writes, spaced out so the
    // server sees multiple socket reads) into a handler that consumes only via
    // 'readable' + read(). The first buffered chunk hits the 64 KiB
    // highWaterMark (getDefaultHighWaterMark()) and pauses the socket; before
    // the fix nothing ever resumed it, so 'end' never fired and this script
    // died on its watchdog. A second request over the same keep-alive
    // connection then proves the socket is not left stranded paused when the
    // final body bytes arrive in the same chunk that crossed the mark.
    let script = r#"
var http = require('http');
var TOTAL = 512 * 1024;
var server = http.createServer(function(req, res) {
  if (req.method === 'GET') {
    res.end('second-ok');
    return;
  }
  var received = 0;
  req.on('readable', function() {
    var chunk;
    while ((chunk = req.read()) !== null) received += chunk.length;
  });
  req.on('end', function() {
    res.end('got:' + received);
  });
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  var agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  var reqOut = http.request(
    { host: '127.0.0.1', port: port, method: 'POST', path: '/', agent: agent },
    function(res) {
      var body = '';
      res.on('data', function(d) { body += d; });
      res.on('end', function() {
        http.get(
          { host: '127.0.0.1', port: port, path: '/', agent: agent },
          function(res2) {
            var body2 = '';
            res2.on('data', function(d) { body2 += d; });
            res2.on('end', function() {
              console.log(JSON.stringify({ body: body, body2: body2 }));
              server.close();
              process.exit(0);
            });
          }
        ).on('error', function(err) {
          console.log(JSON.stringify({ error: 'second request: ' + String(err) }));
          process.exit(0);
        });
      });
    }
  );
  reqOut.on('error', function(err) {
    console.log(JSON.stringify({ error: String(err) }));
    process.exit(0);
  });
  var chunk = Buffer.alloc(64 * 1024, 120);
  var sent = 0;
  (function writeNext() {
    if (sent >= TOTAL) { reqOut.end(); return; }
    sent += chunk.length;
    reqOut.write(chunk);
    setTimeout(writeNext, 5);
  })();
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: request hung (read() never resumed the paused socket)' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not error or hang: {parsed}"
    );
    assert_eq!(
        parsed["body"],
        Value::String("got:524288".to_string()),
        "server should see the full body via readable/read(): {parsed}"
    );
    assert_eq!(
        parsed["body2"],
        Value::String("second-ok".to_string()),
        "a keep-alive request after the drained body should not hang on a stranded paused socket: {parsed}"
    );
}

#[tokio::test]
async fn node_net_http_client_response_slow_consumer_pauses_socket() {
    // The server streams a 1 MiB response while the client leaves the
    // response unconsumed (paused mode). With backpressure the socket is
    // paused once the readable buffer crosses the highWaterMark, keeping the
    // buffered bytes bounded far below the full 1 MiB; before the fix the
    // socket kept flowing and the whole response piled up in the buffer.
    // Afterwards the consumer drains everything to prove the socket resumes.
    let script = r#"
var http = require('http');
var TOTAL = 1024 * 1024;
var server = http.createServer(function(req, res) {
  res.writeHead(200, { 'Content-Length': String(TOTAL) });
  var chunk = Buffer.alloc(64 * 1024, 97);
  var sent = 0;
  (function writeNext() {
    while (sent < TOTAL) {
      sent += chunk.length;
      if (sent >= TOTAL) { res.end(chunk); return; }
      if (!res.write(chunk)) { res.once('drain', writeNext); return; }
    }
  })();
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  http.get({ host: '127.0.0.1', port: port, path: '/' }, function(res) {
    var checks = 0;
    function sample() {
      checks++;
      var paused = !!(res.socket && res.socket._paused === true);
      var buffered = res._readableState ? res._readableState.length : -1;
      if ((paused && buffered > 0) || checks > 100) {
        finish(paused, buffered);
        return;
      }
      setTimeout(sample, 50);
    }
    function finish(paused, buffered) {
      var received = 0;
      res.on('data', function(d) { received += d.length; });
      res.on('end', function() {
        console.log(JSON.stringify({ paused: paused, buffered: buffered, received: received }));
        server.close();
        process.exit(0);
      });
    }
    setTimeout(sample, 100);
  }).on('error', function(err) {
    console.log(JSON.stringify({ error: String(err) }));
    process.exit(0);
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: response never completed' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not error or hang: {parsed}"
    );
    assert_eq!(
        parsed["paused"],
        Value::Bool(true),
        "slow consumer should pause the response socket: {parsed}"
    );
    let buffered = parsed["buffered"].as_i64().unwrap_or(-1);
    assert!(
        buffered > 0 && buffered <= 256 * 1024,
        "readable buffer should stay bounded near the highWaterMark, not hold the whole 1 MiB response: {parsed}"
    );
    assert_eq!(
        parsed["received"].as_i64(),
        Some(1024 * 1024),
        "draining after the pause should still deliver the complete body (socket resumed): {parsed}"
    );
}

#[tokio::test]
async fn node_net_ws_server_closes_oversized_fragmented_message_with_1009() {
    // A raw TCP client performs the ws handshake, delivers one small complete
    // message (proving normal delivery still works under the cap), then
    // streams fin=0 + continuation fragments whose total crosses the server's
    // 64 KiB maxPayload. The server must stop accumulating and close 1009
    // instead of buffering fragments forever.
    let script = r#"
var WebSocketServer = require('ws').Server;
var net = require('net');
var wss = new WebSocketServer({ port: 0, host: '127.0.0.1', maxPayload: 64 * 1024 });
var messages = 0;
wss.on('connection', function(ws) {
  ws.on('error', function() {});
  ws.on('message', function() { messages++; });
  ws.on('close', function(code, reason) {
    console.log(JSON.stringify({ closeCode: code, messages: messages }));
    wss.close();
    process.exit(0);
  });
});
wss.on('listening', function() {
  var port = wss.address().port;
  var sock = net.connect(port, '127.0.0.1', function() {
    sock.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
  });
  sock.on('error', function() {});
  var sentFrames = false;
  sock.on('data', function() {
    if (sentFrames) return;
    sentFrames = true;
    // Masked client frame with a zero masking key (payload passes through
    // the unmask XOR unchanged). 126-style 16-bit extended length.
    function frame(opcode, fin, payloadLen) {
      var header = Buffer.from([
        (fin ? 0x80 : 0x00) | opcode,
        0x80 | 126,
        (payloadLen >> 8) & 0xFF,
        payloadLen & 0xFF,
        0, 0, 0, 0
      ]);
      return Buffer.concat([header, Buffer.alloc(payloadLen, 97)]);
    }
    // One well-formed message first: must still be delivered.
    sock.write(frame(0x1, true, 512));
    // Then a fragmented message that never sets FIN: 16 KiB text fragment
    // plus continuations; the 4th continuation pushes the total past 64 KiB.
    sock.write(frame(0x1, false, 16384));
    for (var i = 0; i < 8; i++) {
      sock.write(frame(0x0, false, 16384));
    }
  });
});
wss.on('error', function(err) {
  console.log(JSON.stringify({ error: String(err) }));
  process.exit(0);
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: server never closed the oversized fragment stream' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not error or hang: {parsed}"
    );
    assert_eq!(
        parsed["closeCode"].as_i64(),
        Some(1009),
        "oversized fragmented message should close with 1009: {parsed}"
    );
    assert_eq!(
        parsed["messages"].as_i64(),
        Some(1),
        "the small message should be delivered; the oversized one must not: {parsed}"
    );
}

#[tokio::test]
async fn node_net_ws_server_closes_oversized_declared_frame_with_1009() {
    // The client sends only a frame HEADER declaring a 2^32-byte payload (the
    // 64-bit length's high 32 bits set) and no payload bytes. The server must
    // reject on the declared length alone — before the fix _appendData would
    // grow the receive buffer toward the declared length until OOM.
    let script = r#"
var WebSocketServer = require('ws').Server;
var net = require('net');
var wss = new WebSocketServer({ port: 0, host: '127.0.0.1', maxPayload: 64 * 1024 });
var messages = 0;
wss.on('connection', function(ws) {
  ws.on('error', function() {});
  ws.on('message', function() { messages++; });
  ws.on('close', function(code, reason) {
    console.log(JSON.stringify({ closeCode: code, messages: messages }));
    wss.close();
    process.exit(0);
  });
});
wss.on('listening', function() {
  var port = wss.address().port;
  var sock = net.connect(port, '127.0.0.1', function() {
    sock.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
  });
  sock.on('error', function() {});
  var sentFrames = false;
  sock.on('data', function() {
    if (sentFrames) return;
    sentFrames = true;
    // Masked binary frame, 64-bit length path (127) declaring 2^32 bytes,
    // zero masking key, no payload bytes ever sent.
    sock.write(Buffer.from([
      0x82,
      0x80 | 127,
      0, 0, 0, 1, 0, 0, 0, 0,
      0, 0, 0, 0
    ]));
  });
});
wss.on('error', function(err) {
  console.log(JSON.stringify({ error: String(err) }));
  process.exit(0);
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: server never rejected the oversized declared frame' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not error or hang: {parsed}"
    );
    assert_eq!(
        parsed["closeCode"].as_i64(),
        Some(1009),
        "oversized declared frame length should close with 1009 before buffering: {parsed}"
    );
    assert_eq!(
        parsed["messages"].as_i64(),
        Some(0),
        "no message should be delivered: {parsed}"
    );
}
