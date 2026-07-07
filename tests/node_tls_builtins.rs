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

/// Self-signed localhost certificate (SAN: DNS:localhost, IP:127.0.0.1),
/// valid until 2046, used purely as in-process emulation fixture material.
const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIICyTCCAbGgAwIBAgIJAIhNqBAfSjJ0MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0yNjA3MDcwNzEzNTNaFw00NjA3MDIwNzEzNTNaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANqsn3OtDKJkvUqU+orW99gvf7iB7d8fj6/D0x4LhK5cBFZV/0y0XekyMKVp
6AyuhaPqJ52TWk8/U1PP8V1yQBzd7ure0UIfTIG6enGkIkuFaCDaWtdboFsyPc7h
IoT6xoIda7UPBvOu6g/8eOkhQ0mmXuehXwEr9iq0c0ETEbrjyUDxkfc4gqjRcv/R
tmQIuqRwwF7wiCogX2HRrN+NDvVpvdrtG+Ed38vYjra9mYUQY0YojXZObaZjGAAD
8SexhNnqLrNaFB+HZMtqbnnSongfhYE37p71Xtvx2ndynvAnMe9PV40DRmNWDzAu
Zfty7FNbkESG8Q3G4pkhb5iZ1zkCAwEAAaMeMBwwGgYDVR0RBBMwEYIJbG9jYWxo
b3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQAXXGuxy2BNZMmkf2LkoZtE2wH6
TOjuYdtQvIbf18ml6L6hUJDiAfnrefXcS40bAcg0r6YEZOa4Mcahd5CMRPm5a1x1
9yLyK8V5roFT6NYD0n9gMtmIrnOLSsQQSCxE33nT6+lYyELgCG9eiRKvgNBuDSPf
OaLPFE5C0v6yLhGBGwPv3dYMDH8iTnPS9pbEr6ZMbECBjtMt2jczm50rb2rn5VLB
/dMltnA7CViKGs+n2w2UK+mJKBZlXgCPqksAX0kW9waxQkkR75WzAEC10Q9Iqfb+
q/LkAWk7EoJDWScZbk7joFDnAI4D7Wk3maELFKYf8TiPxfZOXPfAg3JnE/Tr
-----END CERTIFICATE-----";

const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDarJ9zrQyiZL1K
lPqK1vfYL3+4ge3fH4+vw9MeC4SuXARWVf9MtF3pMjClaegMroWj6iedk1pPP1NT
z/FdckAc3e7q3tFCH0yBunpxpCJLhWgg2lrXW6BbMj3O4SKE+saCHWu1DwbzruoP
/HjpIUNJpl7noV8BK/YqtHNBExG648lA8ZH3OIKo0XL/0bZkCLqkcMBe8IgqIF9h
0azfjQ71ab3a7RvhHd/L2I62vZmFEGNGKI12Tm2mYxgAA/EnsYTZ6i6zWhQfh2TL
am550qJ4H4WBN+6e9V7b8dp3cp7wJzHvT1eNA0ZjVg8wLmX7cuxTW5BEhvENxuKZ
IW+Ymdc5AgMBAAECggEBAJppDIr9Jg/BvNxeSHAjjY0tNS3PKW3FdouxZnEvxvfr
5/Ai94xtTGbvVuRm3UGfNqThIiols76Dw85J5nCKzXTUzfExd2gOe9KbH/0A3mqf
gEC6jyzE+X2MA5MC7IIkJmoYZkbKnqkR2RuCtso//6iQ/zDmhRRpu4C6PSw1T+67
vaTa9r3m05d+26m0Ioz92e0B5vazQYcjgALetFRiTA0s848yYYMkS5CJYdgcii/K
TWmEB36hODB/fMihBYOkB1t4K/sb6yYrpKa3UFBDm+m0/qeVlVzFCL46HBVbD/ma
IPL9VebNACr/LVDM9jQ1KALpvGxJiTwOcRYO5m1IdbUCgYEA9l5YoyxumsYqDjOO
AUeBsphjnGwMPtnDSR5DZDb0ml8AbsFV7/UyAcy/HR9HGVNcvIHBXGb1utcWeREK
zoL9oLyDq0AWMdoyF3twMhS4BUo/gdo2yNXAXX0+kO4iCPhjnwH/OKbM7hyK5436
uT5Ysiih9pAT7+2GcGuvlsU+y5MCgYEA4zkc7/XKY88wrZx8jUrFoBp1FcimHhiz
kQD225z4MwESb/mqjStpf5WZyCWKz/C10Z5MAJSIwrtuNBbxOVINkwfsM1dXNf7o
XPij08+h3juPvotqYZ9lDA/IcfBYgXOsK8GdaFWlxMYY7+1sVR+YlfaEKnayYWwQ
EZZyJgciiYMCgYA/EoRKsfNW+GiH3jb6qN3RZSYLQ7YW2RUfwPmrzE3uv2eS8zgX
CITW5R4ATKOdHjRdpjJkf49lV+9O60gC+pIH9nsW+n80IBI25MkiaR97azi6+6yO
2fo3dPrxi6V2+nA2owI99KX+R5xgD38isY1vfuuH/fa8s+h5G3iGdtTOtQKBgQC8
cK4l93J8qeSV5pSI3PzelXKKuVfC1/t7gxA2+4v/SKFQyf5+iwU4MQpTKYdggiFX
kW84f/aXgLeZbXlqbzkguc5SmdmSxy9Pg0jirWxxkHXasWZtRbKYeTJkA85ytUqR
E0YGtBkBAsTFneJdChISNFpRmRTApM0CuQE7tmkXHwKBgQDqVxs4pHPIzjUZwMPU
q4pcdaX/M45Em54lA86I4ebWsNcRlStP+XNeu/nhiXl1j/hCHZEKEc1pKWHTPXcC
Md/fFsEQi8gONn+RDAEJjd+CR+EchO6UjciR+fZtUMeqhqM6Eq4td8d7t3t7/93v
GZp+REcWUDv3rRhch2XhCaD5Hw==
-----END PRIVATE KEY-----";

/// Prefix a script with `KEY`/`CERT` consts holding the fixture PEMs.
fn with_fixture_pems(script: &str) -> String {
    format!(
        "var CERT = {};\nvar KEY = {};\n{}",
        serde_json::to_string(TEST_CERT).unwrap(),
        serde_json::to_string(TEST_KEY).unwrap(),
        script
    )
}

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

#[tokio::test]
async fn tls_reject_unauthorized_false_still_reports_verification_result() {
    // ENG-23448 finding 2: rejectUnauthorized:false used to force
    // authorized=true and clear authorizationError. Node v25.9.0 oracle for a
    // self-signed in-process server: secureConnect fires, but
    // authorized=false with authorizationError='DEPTH_ZERO_SELF_SIGNED_CERT'.
    // The strict default (rejectUnauthorized unset => true) must still abort
    // with the same code.
    let script = r#"
var tls = require('tls');
var out = {};
var watchdog = setTimeout(function () {
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}, 10000);

var server = tls.createServer({ key: KEY, cert: CERT }, function () {});
server.listen(0, '127.0.0.1', function () {
  var port = server.address().port;
  var lax = tls.connect({ port: port, host: '127.0.0.1', rejectUnauthorized: false }, function () {
    out.lax = {
      secureConnect: true,
      authorized: lax.authorized,
      authorizationError: lax.authorizationError
    };
    lax.destroy();
    var strict = tls.connect({ port: port, host: '127.0.0.1' }, function () {
      out.strict = { secureConnect: true, authorized: strict.authorized };
      done();
    });
    strict.on('error', function (e) {
      out.strict = { error: e.code || e.message };
      done();
    });
  });
  lax.on('error', function (e) {
    out.lax = { error: e.code || e.message };
    done();
  });
  function done() {
    clearTimeout(watchdog);
    server.close(function () {
      console.log(JSON.stringify(out));
      process.exit(0);
    });
  }
});
"#;
    let v = run_script(&with_fixture_pems(script), 30).await;
    assert_eq!(v["lax"]["secureConnect"], true, "{v}");
    assert_eq!(
        v["lax"]["authorized"], false,
        "rejectUnauthorized:false must not fabricate authorized=true: {v}"
    );
    assert_eq!(v["lax"]["authorizationError"], "DEPTH_ZERO_SELF_SIGNED_CERT", "{v}");
    assert_eq!(v["strict"]["error"], "DEPTH_ZERO_SELF_SIGNED_CERT", "{v}");
}
