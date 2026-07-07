//! End-to-end regression tests for the Node-compat `tls` builtin, driving the
//! real `ibex` binary over loopback TCP (ENG-23448).
//!
//! The tls builtin is a loopback-only emulation — it performs no wire
//! cryptography. See LLP 0004 ("The tls builtin is a loopback-only emulation")
//! for the design; these tests pin the Node-facing contract, which was
//! verified against real Node v25.9.0 as the oracle.
//!
//! Run with: `scripts/run-tests.sh --scope test node_tls`
//! (or `cargo test --test node_tls_builtins`).

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
async fn tls_socket_prototype_chain_extends_net_socket() {
    // ENG-23448 finding 3: setPrototypeOf was applied to the constructor only,
    // so `new tls.TLSSocket(sock) instanceof net.Socket` was false and none of
    // the Socket API resolved. Node: instanceof is true and read()/on() exist.
    // The 'data' listener check pins the shadowing guard: the inherited
    // net.Socket.prototype.on hook schedules a read-buffer flush that would
    // throw on the wrapper's missing state if it were not shadowed by the
    // plain EventEmitter method.
    let script = r#"
var tls = require('tls');
var net = require('net');
var out = {};
var raw = new net.Socket();
var ts = new tls.TLSSocket(raw);
out.instanceofSocket = ts instanceof net.Socket;
out.hasRead = typeof ts.read;
out.hasClose = typeof ts.close;
out.hasOn = typeof ts.on;
out.emitWorks = false;
ts.on('data', function () {});
ts.on('ping', function (v) { out.emitWorks = v === 42; });
ts.emit('ping', 42);
setTimeout(function () {
  // Survived the tick where a non-shadowed inherited on('data') hook would
  // have thrown while flushing a read buffer the wrapper does not have.
  out.readReturns = String(ts.read());
  ts.destroy();
  raw.destroy();
  console.log(JSON.stringify(out));
  process.exit(0);
}, 50);
"#;
    let v = run_script(script, 20).await;
    assert_eq!(v["instanceofSocket"], true, "TLSSocket must extend net.Socket: {v}");
    assert_eq!(v["hasRead"], "function", "{v}");
    assert_eq!(v["hasClose"], "function", "{v}");
    assert_eq!(v["hasOn"], "function", "{v}");
    assert_eq!(v["emitWorks"], true, "{v}");
    assert_eq!(v["readReturns"], "null", "read() on an idle wrapper returns null: {v}");
}

#[tokio::test]
async fn tls_renegotiate_matches_node_contract() {
    // ENG-23448 finding 4: the stub claimed success unconditionally. Node
    // v25.9.0 oracle: TLSv1.3 -> false + cb(ERR_SSL_WRONG_SSL_VERSION);
    // TLSv1.2 self-initiated renegotiate succeeds even after
    // disableRenegotiation() (the disabled flag only errors the socket whose
    // peer renegotiates); destroyed socket -> undefined without callback;
    // non-object options / non-function callback -> throw ERR_INVALID_ARG_TYPE.
    let script = r#"
var tls = require('tls');
var net = require('net');
var out = {};

// Default protocol is TLSv1.3.
var s13 = new tls.TLSSocket(new net.Socket());
out.protocol13 = s13.getProtocol();
s13.disableRenegotiation();
var ret13 = s13.renegotiate({}, function (err) {
  out.tls13 = { ret: ret13, cbErr: err ? err.code : null, reason: err ? err.reason : null };
  next();
});

function next() {
  var s12 = new tls.TLSSocket(new net.Socket(), { maxVersion: 'TLSv1.2' });
  out.protocol12 = s12.getProtocol();
  s12.disableRenegotiation();
  var ret12 = s12.renegotiate({}, function (err) {
    out.tls12_disabled_self = { ret: ret12, cbErr: err ? err.code : null };
    finish(s12);
  });
}

function finish(s12) {
  var sd = new tls.TLSSocket(new net.Socket());
  sd.destroy();
  out.destroyed = { ret: String(sd.renegotiate({}, function () { out.destroyedCbFired = true; })) };
  try { s12.renegotiate(function () {}); out.fnAsOptions = 'no throw'; }
  catch (e) { out.fnAsOptions = e.code; }
  try { s12.renegotiate({}, 'not a function'); out.badCallback = 'no throw'; }
  catch (e) { out.badCallback = e.code; }
  setTimeout(function () {
    console.log(JSON.stringify(out));
    process.exit(0);
  }, 50);
}
"#;
    let v = run_script(script, 20).await;
    assert_eq!(v["protocol13"], "TLSv1.3", "{v}");
    assert_eq!(v["tls13"]["ret"], false, "TLSv1.3 renegotiate returns false: {v}");
    assert_eq!(v["tls13"]["cbErr"], "ERR_SSL_WRONG_SSL_VERSION", "{v}");
    assert_eq!(v["tls13"]["reason"], "wrong ssl version", "{v}");
    assert_eq!(v["protocol12"], "TLSv1.2", "{v}");
    assert_eq!(
        v["tls12_disabled_self"]["ret"], true,
        "self-initiated renegotiate succeeds on TLSv1.2 even when disabled (Node v25 contract): {v}"
    );
    assert_eq!(v["tls12_disabled_self"]["cbErr"], Value::Null, "{v}");
    assert_eq!(v["destroyed"]["ret"], "undefined", "{v}");
    assert!(v.get("destroyedCbFired").is_none(), "destroyed socket must not invoke callback: {v}");
    assert_eq!(v["fnAsOptions"], "ERR_INVALID_ARG_TYPE", "{v}");
    assert_eq!(v["badCallback"], "ERR_INVALID_ARG_TYPE", "{v}");
}
