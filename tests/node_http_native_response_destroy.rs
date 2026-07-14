//! ENG-23146: the Node `http` bridge's native-mode (`__exactHttpServe`)
//! ServerResponse destroy path must ABORT the host response stream via
//! `__exactHttpRespondAbort`, never terminate it cleanly (or not at all).
//!
//! Before the fix, `ServerResponse.prototype.destroy` made no host call in
//! native mode: a `res.destroy()` mid-stream left the host response pipe open
//! (client hung until a host timeout), and older snapshots funnelled into a
//! clean `__exactHttpRespondEnd`, which makes hyper write a valid chunked
//! terminator over a TRUNCATED body that validates as complete on the client.
//! Real Node semantics (verified against node): mid-stream destroy => client
//! sees `aborted`/ECONNRESET, never a clean `end`; destroy after `end()` =>
//! clean complete body.
//!
//! These tests drive the real `ibex` binary. `http.Server` prefers the
//! net-socket transport when `net.createServer` exists, so the scripts null it
//! out around server construction to force the native `__exactHttpServe`
//! transport (the `serve({fetch})` host path from ENG-23114), then restore it
//! for the loopback client.
//!
//! Only compiled with the `host-http-server` feature: without it
//! `ex_host_http_serve` is a weak stub and native mode cannot listen.
//! Run with: `scripts/run-tests.sh --features host-http-server --scope test node_http_native`
#![cfg(feature = "host-http-server")]

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

/// Shared scaffold: starts a native-mode http server with `handler_js` as the
/// request listener body, issues one GET to `path`, and reports what the
/// client observed: ordered events, body, status, and whether the transfer
/// finished cleanly (`end` before `close`).
fn scenario_script(handler_js: &str, path: &str) -> String {
    format!(
        r#"
var net = require('net');
var http = require('http');
var savedCreateServer = net.createServer;
net.createServer = null;
var server = http.createServer(function(req, res) {{
{handler_js}
}});
net.createServer = savedCreateServer;
if (server._netServer) {{
  console.log(JSON.stringify({{ error: 'setup: expected native transport, got net socket transport' }}));
  process.exit(0);
}}
server.listen(0, '127.0.0.1', function() {{
  var port = server.address().port;
  var events = [];
  var body = '';
  var status = 0;
  function finish() {{
    console.log(JSON.stringify({{
      native: !!server._useNative,
      events: events,
      body: body,
      status: status
    }}));
    process.exit(0);
  }}
  var req = http.request({{ host: '127.0.0.1', port: port, path: '{path}' }}, function(res) {{
    status = res.statusCode;
    res.on('data', function(d) {{ body += d; }});
    res.on('aborted', function() {{ events.push('res-aborted'); }});
    res.on('error', function(e) {{ events.push('res-error:' + (e.code || e.message)); }});
    res.on('end', function() {{ events.push('res-end'); }});
    res.on('close', function() {{ events.push('res-close'); setTimeout(finish, 50); }});
  }});
  req.on('error', function(e) {{ events.push('req-error:' + (e.code || e.message)); setTimeout(finish, 50); }});
  req.end();
}});
setTimeout(function() {{
  console.log(JSON.stringify({{ error: 'watchdog: client never observed a response outcome (response pipe leaked?)' }}));
  process.exit(0);
}}, 20000);
"#
    )
}

fn events(parsed: &Value) -> Vec<String> {
    parsed["events"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn native_response_destroy_midstream_breaks_the_transfer() {
    // Handler streams a partial chunked body, then destroys the response.
    // The client must observe a broken transfer (abort/error/close without a
    // clean 'end'), never a truncated body that validates as complete — and
    // never hang on a leaked response pipe (the pre-fix behavior).
    let script = scenario_script(
        r#"  res.writeHead(200);
  res.write('partial-body-then-destroy');
  setTimeout(function() { res.destroy(new Error('boom')); }, 30);"#,
        "/midstream",
    );

    let parsed = run_script(&script, 40).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang or fail setup: {parsed}"
    );
    assert_eq!(
        parsed["native"],
        Value::Bool(true),
        "server should be on the native __exactHttpServe transport: {parsed}"
    );
    let evs = events(&parsed);
    assert!(
        !evs.iter().any(|e| e == "res-end"),
        "a destroyed mid-stream response must not deliver a clean 'end' (truncated body \
         validated as complete): {parsed}"
    );
    assert!(
        evs.iter().any(|e| e == "res-aborted"
            || e.starts_with("res-error:")
            || e.starts_with("req-error:")),
        "client should observe the broken transfer as an abort/error: {parsed}"
    );
}

#[tokio::test]
async fn native_response_destroy_after_end_stays_clean() {
    // destroy() after end() completed must NOT abort: the client already was
    // promised the full response and must receive it with a clean 'end'.
    let script = scenario_script(
        r#"  res.end('complete-body');
  res.destroy();"#,
        "/after-end",
    );

    let parsed = run_script(&script, 40).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "script should not hang or fail setup: {parsed}"
    );
    let evs = events(&parsed);
    assert!(
        evs.iter().any(|e| e == "res-end"),
        "destroy after end() must keep the clean transfer: {parsed}"
    );
    assert!(
        !evs.iter().any(|e| e == "res-aborted"
            || e.starts_with("res-error:")
            || e.starts_with("req-error:")),
        "destroy after end() must not surface a client error: {parsed}"
    );
    assert_eq!(
        parsed["body"],
        Value::String("complete-body".to_string()),
        "client should receive the full body: {parsed}"
    );
    assert_eq!(parsed["status"], Value::from(200), "status: {parsed}");
}

#[tokio::test]
async fn native_response_destroy_before_headers_unblocks_the_client() {
    // destroy() before any write: RespondAbort drops the still-pending host
    // responder, so hyper answers promptly (500 from the dropped-responder
    // branch) instead of parking the client until the request timeout. (Real
    // Node resets the connection; the host primitive surfaces a synthesized
    // 500 — the load-bearing assertions are "no hang" and "no handler-authored
    // success".)
    let script = scenario_script(
        r#"  res.destroy(new Error('rejected before headers'));"#,
        "/pre-headers",
    );

    let parsed = run_script(&script, 40).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "client must not park until the host request timeout: {parsed}"
    );
    let evs = events(&parsed);
    let errored = evs
        .iter()
        .any(|e| e == "res-aborted" || e.starts_with("res-error:") || e.starts_with("req-error:"));
    let synthesized_error_status = parsed["status"] == 500;
    assert!(
        errored || synthesized_error_status,
        "pre-header destroy should surface as a connection error or a synthesized 5xx, \
         never a success: {parsed}"
    );
}

#[tokio::test]
async fn native_request_destroy_aborts_the_paired_response() {
    // Native-mode requests do not have a real net.Socket, so req.destroy() must
    // still find the paired ServerResponse and drive its abort path. Before
    // ENG-23294 the response pipe stayed parked until the host request timeout.
    let script = scenario_script(
        r#"  res.writeHead(200);
  res.write('partial-before-req-destroy');
  setTimeout(function() { req.destroy(); }, 30);"#,
        "/req-destroy",
    );

    let parsed = run_script(&script, 40).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "client must not hang on a leaked native response pipe: {parsed}"
    );
    assert_eq!(
        parsed["native"],
        Value::Bool(true),
        "server should be on the native __exactHttpServe transport: {parsed}"
    );
    let evs = events(&parsed);
    assert!(
        !evs.iter().any(|e| e == "res-end"),
        "req.destroy() must not let the paired native response finish cleanly: {parsed}"
    );
    assert!(
        evs.iter().any(|e| e == "res-aborted"
            || e.starts_with("res-error:")
            || e.starts_with("req-error:")),
        "client should observe req.destroy() as a broken transfer: {parsed}"
    );
}
