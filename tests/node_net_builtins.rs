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
    let dir = tempfile::tempdir().expect("create script tempdir");
    let entry = dir.path().join("app.js");
    std::fs::write(&entry, script).expect("write script fixture");
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec").arg("audit").arg(&entry);

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

#[tokio::test]
async fn node_net_blocklist_uses_numeric_range_and_subnet_matching() {
    let script = r#"
var net = require('net');
var bl = new net.BlockList();
bl.addRange('1.0.0.0', '10.0.0.0');
bl.addSubnet('192.168.0.0', 16);
bl.addSubnet('2001:db8::', 32, 'ipv6');
console.log(JSON.stringify({
  range: bl.check('9.0.0.0'),
  rangeFalse: bl.check('100.0.0.0'),
  subnet: bl.check('192.168.9.1'),
  subnetFalse: bl.check('192.169.0.1'),
  ipv6Subnet: bl.check('2001:db8::1', 'ipv6')
}));
"#;

    // Foreground audit performs a full bundle/authentication pass before the
    // fixture starts, so leave headroom beyond production's old startup time.
    let parsed = run_script(script, 45).await;
    assert_eq!(parsed["range"], Value::Bool(true), "IPv4 range: {parsed}");
    assert_eq!(
        parsed["rangeFalse"],
        Value::Bool(false),
        "IPv4 range false positive: {parsed}"
    );
    assert_eq!(parsed["subnet"], Value::Bool(true), "IPv4 subnet: {parsed}");
    assert_eq!(
        parsed["subnetFalse"],
        Value::Bool(false),
        "IPv4 subnet false positive: {parsed}"
    );
    assert_eq!(
        parsed["ipv6Subnet"],
        Value::Bool(true),
        "IPv6 subnet: {parsed}"
    );
}

#[tokio::test]
async fn node_net_read_size_returns_null_until_enough_data_or_eof() {
    let script = r#"
var net = require('net');
var server = net.createServer(function(sock) {
  sock.write('hello');
  setTimeout(function() { sock.end(); }, 200);
});
server.listen(0, '127.0.0.1', function() {
  var client = net.connect(server.address().port, '127.0.0.1');
  var firstWasNull = false;
  var exact = '';
  client.on('readable', function() {
    if (!firstWasNull) {
      firstWasNull = client.read(100) === null;
      var chunk = client.read(5);
      if (chunk) exact += chunk.toString();
      return;
    }
    var rest = client.read(100);
    if (rest) exact += rest.toString();
  });
  client.on('end', function() {
    console.log(JSON.stringify({ firstWasNull: firstWasNull, exact: exact }));
    server.close();
    process.exit(0);
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: read test hung' }));
  process.exit(0);
}, 10000);
"#;

    let parsed = run_script(script, 20).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang: {parsed}"
    );
    assert_eq!(
        parsed["firstWasNull"],
        Value::Bool(true),
        "read(100) should return null on short buffered data before EOF: {parsed}"
    );
    assert_eq!(
        parsed["exact"],
        Value::String("hello".to_string()),
        "short read must not consume data: {parsed}"
    );
}

#[tokio::test]
async fn node_net_destroy_error_is_deferred_until_next_tick() {
    let script = r#"
var net = require('net');
var s = new net.Socket();
var events = [];
var watchdog = setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: close did not fire', events: events }));
  process.exit(0);
}, 10000);
s.destroy(new Error('boom'));
s.on('error', function(err) { events.push('error:' + err.message); });
s.on('close', function(hadErr) {
  events.push('close:' + hadErr);
  clearTimeout(watchdog);
  console.log(JSON.stringify({ events: events }));
  process.exit(0);
});
"#;

    let parsed = run_script(script, 20).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang: {parsed}"
    );
    let events = parsed["events"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        events.first(),
        Some(&Value::String("error:boom".to_string())),
        "error should be observable by a listener attached after destroy(): {parsed}"
    );
    assert_eq!(
        events.get(1),
        Some(&Value::String("close:true".to_string())),
        "close should follow the deferred error: {parsed}"
    );
}

#[tokio::test]
async fn node_net_second_end_callback_after_finish_reports_already_finished() {
    let script = r#"
var net = require('net');
var server = net.createServer(function(sock) { sock.resume(); });
server.listen(0, '127.0.0.1', function() {
  var client = net.connect(server.address().port, '127.0.0.1', function() {
    client.end();
  });
  client.on('finish', function() {
    client.end(function(err) {
      console.log(JSON.stringify({ code: err && err.code }));
      client.destroy();
      server.close();
      process.exit(0);
    });
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: second end callback did not fire' }));
  process.exit(0);
}, 10000);
"#;

    let parsed = run_script(script, 20).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang: {parsed}"
    );
    assert_eq!(
        parsed["code"],
        Value::String("ERR_STREAM_ALREADY_FINISHED".to_string()),
        "second end(cb) after finish should report ERR_STREAM_ALREADY_FINISHED: {parsed}"
    );
}

#[tokio::test]
async fn node_http_socket_mode_write_after_end_and_invalid_content_length_are_observable() {
    let script = r#"
var http = require('http');
var net = require('net');
var phase = 'write-after-end';
var results = {};

function runWriteAfterEnd(next) {
  var server = http.createServer(function(req, res) {
    var events = [];
    res.on('error', function(err) { events.push('error:' + err.code); });
    res.end('ok');
    var sync = true;
    var ret = res.write('late', function(err) {
      events.push('callback:' + (err && err.code) + ':sync=' + sync);
    });
    sync = false;
    setTimeout(function() {
      results.writeAfterEnd = { ret: ret, events: events };
      server.close(next);
    }, 50);
  });
  server.listen(0, '127.0.0.1', function() {
    http.get({ host: '127.0.0.1', port: server.address().port }, function(res) {
      res.resume();
    }).on('error', function() {});
  });
}

function runInvalidContentLength(next) {
  var server = http.createServer(function(req, res) {
    results.invalidContentLengthRequest = true;
    res.end('bad');
  });
  server.on('clientError', function(err, socket) {
    results.invalidContentLength = err.code;
    socket.destroy();
  });
  server.listen(0, '127.0.0.1', function() {
    var sock = net.connect(server.address().port, '127.0.0.1', function() {
      sock.write('POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\nbody');
    });
    sock.on('data', function() {});
    sock.on('close', function() {
      setTimeout(function() { server.close(next); }, 20);
    });
  });
}

runWriteAfterEnd(function() {
  runInvalidContentLength(function() {
    console.log(JSON.stringify(results));
    process.exit(0);
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: http socket-mode test hung', phase: phase, results: results }));
  process.exit(0);
}, 15000);
"#;

    let parsed = run_script(script, 30).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang: {parsed}"
    );
    assert_eq!(
        parsed["writeAfterEnd"]["ret"],
        Value::Bool(false),
        "write after end should return false: {parsed}"
    );
    let events = parsed["writeAfterEnd"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        events
            .iter()
            .any(|e| e == "callback:ERR_STREAM_WRITE_AFTER_END:sync=false"),
        "write-after-end callback should be async with ERR_STREAM_WRITE_AFTER_END: {parsed}"
    );
    assert!(
        events
            .iter()
            .any(|e| e == "error:ERR_STREAM_WRITE_AFTER_END"),
        "write-after-end should emit an error event: {parsed}"
    );
    assert_eq!(
        parsed["invalidContentLength"],
        Value::String("HPE_INVALID_CONTENT_LENGTH".to_string()),
        "invalid request Content-Length should emit clientError: {parsed}"
    );
    assert_eq!(
        parsed["invalidContentLengthRequest"],
        Value::Null,
        "invalid Content-Length must not emit a request: {parsed}"
    );
}

#[tokio::test]
async fn node_http_upgrade_preserves_connection_accounting_and_listen_path() {
    let script = r#"
var fs = require('fs');
var http = require('http');
var net = require('net');
var os = require('os');
var path = require('path');
var results = {};

function runUpgrade(next) {
  var server = http.createServer();
  server.on('upgrade', function(req, socket, head) {
    socket.end('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n');
  });
  server.listen(0, '127.0.0.1', function() {
    var sock = net.connect(server.address().port, '127.0.0.1', function() {
      sock.write('GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n');
    });
    sock.on('data', function() { sock.end(); });
    sock.on('close', function() {
      server.getConnections(function(err, countBeforeClose) {
        results.upgradeConnections = countBeforeClose;
        var done = false;
        server.close(function() {
          if (done) return;
          done = true;
          results.upgradeClose = true;
          next();
        });
        setTimeout(function() {
          if (!done) {
            done = true;
            results.upgradeClose = false;
            next();
          }
        }, 500);
      });
    });
  });
}

function runListenPath(next) {
  var sockPath = path.join(os.tmpdir(), 'ibex-http-listen-' + process.pid + '-' + Date.now() + '.sock');
  try { fs.unlinkSync(sockPath); } catch (e) {}
  var server = http.createServer(function(req, res) { res.end('ok'); });
  server.maxConnections = 3;
  server.listen({ path: sockPath }, function() {
    results.listenPathAddress = server.address();
    results.maxConnections = server.maxConnections;
    http.get({ socketPath: sockPath, path: '/' }, function(res) {
      var body = '';
      res.on('data', function(d) { body += d; });
      res.on('end', function() {
        results.listenPathBody = body;
        server.close(function() {
          try { fs.unlinkSync(sockPath); } catch (e) {}
          next();
        });
      });
    }).on('error', function(err) {
      results.listenPathError = err.code || err.message;
      server.close(next);
    });
  });
}

runUpgrade(function() {
  runListenPath(function() {
    console.log(JSON.stringify(results));
    process.exit(0);
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: upgrade/listen path test hung', results: results }));
  process.exit(0);
}, 15000);
"#;

    let parsed = run_script(script, 30).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang: {parsed}"
    );
    assert_eq!(
        parsed["upgradeConnections"].as_i64(),
        Some(0),
        "upgraded socket should decrement net.Server connection accounting after close: {parsed}"
    );
    assert_eq!(
        parsed["upgradeClose"],
        Value::Bool(true),
        "server.close callback should fire after upgraded socket closes: {parsed}"
    );
    assert!(
        parsed["listenPathAddress"]
            .as_str()
            .map(|s| s.ends_with(".sock"))
            .unwrap_or(false),
        "listen({{path}}) should bind a Unix socket and address() should return the path: {parsed}"
    );
    assert_eq!(
        parsed["maxConnections"].as_i64(),
        Some(3),
        "http maxConnections should proxy to net server: {parsed}"
    );
    assert_eq!(
        parsed["listenPathBody"],
        Value::String("ok".to_string()),
        "HTTP over listen({{path}}) should work: {parsed}"
    );
}

#[tokio::test]
async fn node_net_set_keep_alive_accepts_initial_delay() {
    // ENG-23456 finding 3: setKeepAlive(enable, initialDelay) used to drop
    // initialDelay because the host function was arity-2 (the `.length >= 3`
    // branch was dead). The native side is now arity-3 and applies
    // TCP_KEEPIDLE/TCP_KEEPALIVE; end-to-end this asserts the full call path
    // (ms -> seconds -> native) works on a live socket and data still flows.
    // The actual setsockopt effect is not observable from JS, so the idle
    // value itself is verified by code review, not here.
    let script = r#"
var net = require('net');
var watchdog = setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog' }));
  process.exit(1);
}, 20000);
var server = net.createServer(function(sock) {
  sock.end('pong');
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  var client = net.connect(port, '127.0.0.1', function() {
    var r1 = client.setKeepAlive(true, 1200);   // 1.2s -> 1s idle
    var r2 = client.setKeepAlive(true, 250);    // sub-second rounds up, not to 0
    var r3 = client.setKeepAlive(false);
    var chunks = [];
    client.on('data', function(c) { chunks.push(c); });
    client.on('end', function() {
      clearTimeout(watchdog);
      server.close();
      console.log(JSON.stringify({
        error: null,
        chained: r1 === client && r2 === client && r3 === client,
        data: Buffer.concat(chunks).toString()
      }));
    });
  });
});
"#;
    let parsed = run_script(script, 60).await;
    assert_eq!(parsed["error"], Value::Null, "no watchdog/error: {parsed}");
    assert_eq!(
        parsed["chained"],
        Value::Bool(true),
        "setKeepAlive returns the socket: {parsed}"
    );
    assert_eq!(
        parsed["data"], "pong",
        "socket still exchanges data after keepalive calls: {parsed}"
    );
}
