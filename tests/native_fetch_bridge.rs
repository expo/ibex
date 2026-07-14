//! End-to-end regression tests for the native fetch bridge
//! (`hermes_runtime_fetch.cc` + the per-platform `native_fetch_*` backends),
//! driving the real `ibex` binary against an in-process loopback HTTP server.
//!
//! ENG-23471 pinned four cross-platform contract findings:
//!   * header values containing interior HTAB (legal per WHATWG fetch /
//!     RFC 9110) were rejected by the native `c <= 0x1f` check;
//!   * the Linux libcurl backend set CURLOPT_POSTFIELDS for body-less
//!     requests, stamping `Content-Length: 0` and a default form
//!     `Content-Type` onto every GET;
//!   * the Linux backend hardcoded statusText to "OK" for every status;
//!   * every request spawned its own detached OS thread (now a bounded pool),
//!     so a large Promise.all created hundreds of native threads.
//!
//! Run with: `scripts/run-tests.sh --scope test native_fetch_`
//! (or `cargo test --test native_fetch_bridge`).

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
async fn native_fetch_header_value_allows_interior_htab() {
    // Per WHATWG fetch / RFC 9110 a field value may contain interior HTAB;
    // Node/undici and browsers accept `a\tb`. The native bridge used to throw
    // "__nativeFetch: invalid header value" for any byte <= 0x1f.
    let script = r#"
var http = require('http');
var server = http.createServer(function(req, res) {
  res.end(JSON.stringify({ tab: req.headers['x-tab'] || null }));
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  fetch('http://127.0.0.1:' + port + '/', { headers: { 'X-Tab': 'a\tb' } })
    .then(function(res) { return res.json(); })
    .then(function(echo) {
      console.log(JSON.stringify(echo));
      process.exit(0);
    })
    .catch(function(e) {
      console.log(JSON.stringify({ error: String(e) }));
      process.exit(0);
    });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: fetch never completed' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "fetch with interior-HTAB header value should succeed: {parsed}"
    );
    assert_eq!(
        parsed["tab"],
        Value::String("a\tb".to_string()),
        "server should receive the header value byte-for-byte: {parsed}"
    );
}

#[tokio::test]
async fn native_fetch_get_sends_no_body_framing_headers() {
    // A body-less GET must not advertise a body: no Content-Length and no
    // Content-Type. The Linux libcurl backend used to set CURLOPT_POSTFIELDS
    // unconditionally, which switched curl's internal method to POST and
    // stamped `Content-Length: 0` + `Content-Type:
    // application/x-www-form-urlencoded` onto every GET (macOS/Windows never
    // sent them).
    let script = r#"
var http = require('http');
var server = http.createServer(function(req, res) {
  res.end(JSON.stringify({
    method: req.method,
    cl: req.headers['content-length'] || null,
    ct: req.headers['content-type'] || null
  }));
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  fetch('http://127.0.0.1:' + port + '/')
    .then(function(res) { return res.json(); })
    .then(function(echo) {
      console.log(JSON.stringify(echo));
      process.exit(0);
    })
    .catch(function(e) {
      console.log(JSON.stringify({ error: String(e) }));
      process.exit(0);
    });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: fetch never completed' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(parsed["error"], Value::Null, "GET should succeed: {parsed}");
    assert_eq!(parsed["method"], Value::String("GET".to_string()));
    assert_eq!(
        parsed["cl"],
        Value::Null,
        "a body-less GET must not send Content-Length: {parsed}"
    );
    assert_eq!(
        parsed["ct"],
        Value::Null,
        "a body-less GET must not send a default Content-Type: {parsed}"
    );
}

#[tokio::test]
async fn native_fetch_status_text_reports_reason_phrase() {
    // statusText must reflect the response status, not a hardcoded "OK". The
    // exact casing is platform-dependent (macOS uses NSURLSession's localized
    // string, "not found"; Linux/Windows surface the server's raw reason
    // phrase, "Not Found"), so compare case-insensitively.
    let script = r#"
var http = require('http');
var server = http.createServer(function(req, res) {
  res.statusCode = 404;
  res.end('nope');
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  fetch('http://127.0.0.1:' + port + '/missing')
    .then(function(res) {
      console.log(JSON.stringify({ status: res.status, statusText: res.statusText }));
      process.exit(0);
    })
    .catch(function(e) {
      console.log(JSON.stringify({ error: String(e) }));
      process.exit(0);
    });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: fetch never completed' }));
  process.exit(0);
}, 30000);
"#;

    let parsed = run_script(script, 60).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "fetch should succeed: {parsed}"
    );
    assert_eq!(parsed["status"], Value::Number(404.into()));
    let status_text = parsed["statusText"].as_str().unwrap_or_default();
    assert_eq!(
        status_text.to_lowercase(),
        "not found",
        "statusText should reflect the 404 reason phrase, not 'OK': {parsed}"
    );
}

#[tokio::test]
async fn native_fetch_many_concurrent_requests_complete() {
    // 40 concurrent fetches (past the 16-worker cap of the bounded pool on
    // Linux) must all complete with the right bodies — excess work queues
    // rather than being dropped, deadlocking, or spawning 40 native threads.
    let script = r#"
var http = require('http');
var urlProbe = [
  new URL('http://127.0.0.1/repeat-a').href,
  new URL('http://127.0.0.1/repeat-b').href
];
var server = http.createServer(function(req, res) {
  res.end('id:' + req.url.slice(1));
});
server.listen(0, '127.0.0.1', function() {
  var port = server.address().port;
  var jobs = [];
  for (var i = 0; i < 40; i++) {
    (function(id) {
      var target = 'http://127.0.0.1:' + port + '/' + id;
      jobs.push(
        fetch(target)
          .then(function(res) { return res.text(); })
          .then(function(text) { return text === 'id:' + id; })
      );
    })(i);
  }
  Promise.all(jobs).then(function(results) {
    var ok = 0;
    for (var j = 0; j < results.length; j++) { if (results[j]) ok++; }
    console.log(JSON.stringify({ ok: ok, total: results.length, urlProbe: urlProbe }));
    process.exit(0);
  }).catch(function(e) {
    console.log(JSON.stringify({ error: String(e && e.stack || e) }));
    process.exit(0);
  });
});
setTimeout(function() {
  console.log(JSON.stringify({ error: 'watchdog: concurrent fetches never completed' }));
  process.exit(0);
}, 45000);
"#;

    let parsed = run_script(script, 90).await;
    assert_eq!(
        parsed["error"],
        Value::Null,
        "concurrent fetches should all succeed: {parsed}"
    );
    assert_eq!(
        parsed["ok"],
        Value::Number(40.into()),
        "all 40 bodies should match: {parsed}"
    );
    assert_eq!(parsed["total"], Value::Number(40.into()));
    assert_eq!(
        parsed["urlProbe"],
        serde_json::json!(["http://127.0.0.1/repeat-a", "http://127.0.0.1/repeat-b"]),
        "ambient URL parsing must remain independent across constructions: {parsed}"
    );
}
