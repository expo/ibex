//! End-to-end regression tests for the Node-compat `tls` builtin, driving the
//! real `ibex` binary over loopback TCP (ENG-23448, ENG-23492, ENG-23526).
//!
//! Two client paths are covered (see LLP 0004, "The tls builtin"): the
//! in-process loopback emulation (no wire cryptography) and the native TLS
//! bridge, which performs REAL wire TLS — pinned here hermetically against an
//! in-process rustls server. The Node-facing contract in both cases was
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

#[cfg(target_os = "windows")]
#[tokio::test]
async fn node_tls_windows_native_bridge_host_functions_install_and_engine_starts() {
    // ENG-23526: synchronous native-bridge smoke, kept as a fast Windows
    // sanity check. The timer-driven oracle tests below run on Windows too
    // since ENG-23639/ENG-23705 (console output now survives process.exit).
    let script = r#"
require('tls');
var required = [
  '__exactTlsEngineNew',
  '__exactTlsEngineWriteTls',
  '__exactTlsEngineReadTls',
  '__exactTlsEngineReadPlain',
  '__exactTlsEngineWritePlain',
  '__exactTlsEngineStatus',
  '__exactTlsEnginePeerCerts',
  '__exactTlsEngineTransportEof',
  '__exactTlsEngineShutdown',
  '__exactTlsEngineClose',
  '__exactTcpConnect',
  '__exactTcpRead',
  '__exactTcpWrite'
];
var types = {};
for (var i = 0; i < required.length; i++) {
  types[required[i]] = typeof globalThis[required[i]];
}
var id = __exactTlsEngineNew(JSON.stringify({
  host: 'localhost',
  servername: 'localhost',
  alpn: ['http/1.1']
}));
var status = JSON.parse(__exactTlsEngineStatus(id));
var hello = __exactTlsEngineReadTls(id, 32);
var out = {
  types: types,
  idType: typeof id,
  handshaking: status.handshaking,
  tlsBytes: hello && hello.byteLength || 0
};
__exactTlsEngineClose(id);
console.log(JSON.stringify(out));
"#;
    let v = run_script(script, 5).await;
    for name in [
        "__exactTlsEngineNew",
        "__exactTlsEngineWriteTls",
        "__exactTlsEngineReadTls",
        "__exactTlsEngineReadPlain",
        "__exactTlsEngineWritePlain",
        "__exactTlsEngineStatus",
        "__exactTlsEnginePeerCerts",
        "__exactTlsEngineTransportEof",
        "__exactTlsEngineShutdown",
        "__exactTlsEngineClose",
        "__exactTcpConnect",
        "__exactTcpRead",
        "__exactTcpWrite",
    ] {
        assert_eq!(v["types"][name], "function", "{name}: {v}");
    }
    assert_eq!(v["idType"], "number", "{v}");
    assert_eq!(v["handshaking"], true, "{v}");
    assert!(
        v["tlsBytes"].as_u64().unwrap_or(0) > 0,
        "engine should emit initial TLS bytes: {v}"
    );
}

#[tokio::test]
async fn node_tls_socket_prototype_chain_extends_net_socket() {
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
    assert_eq!(
        v["instanceofSocket"], true,
        "TLSSocket must extend net.Socket: {v}"
    );
    assert_eq!(v["hasRead"], "function", "{v}");
    assert_eq!(v["hasClose"], "function", "{v}");
    assert_eq!(v["hasOn"], "function", "{v}");
    assert_eq!(v["emitWorks"], true, "{v}");
    assert_eq!(
        v["readReturns"], "null",
        "read() on an idle wrapper returns null: {v}"
    );
}

#[tokio::test]
async fn node_tls_renegotiate_matches_node_contract() {
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
    assert_eq!(
        v["tls13"]["ret"], false,
        "TLSv1.3 renegotiate returns false: {v}"
    );
    assert_eq!(v["tls13"]["cbErr"], "ERR_SSL_WRONG_SSL_VERSION", "{v}");
    assert_eq!(v["tls13"]["reason"], "wrong ssl version", "{v}");
    assert_eq!(v["protocol12"], "TLSv1.2", "{v}");
    assert_eq!(
        v["tls12_disabled_self"]["ret"], true,
        "self-initiated renegotiate succeeds on TLSv1.2 even when disabled (Node v25 contract): {v}"
    );
    assert_eq!(v["tls12_disabled_self"]["cbErr"], Value::Null, "{v}");
    assert_eq!(v["destroyed"]["ret"], "undefined", "{v}");
    assert!(
        v.get("destroyedCbFired").is_none(),
        "destroyed socket must not invoke callback: {v}"
    );
    assert_eq!(v["fnAsOptions"], "ERR_INVALID_ARG_TYPE", "{v}");
    assert_eq!(v["badCallback"], "ERR_INVALID_ARG_TYPE", "{v}");
}

#[tokio::test]
async fn node_tls_reject_unauthorized_false_still_reports_verification_result() {
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
    assert_eq!(
        v["lax"]["authorizationError"], "DEPTH_ZERO_SELF_SIGNED_CERT",
        "{v}"
    );
    assert_eq!(v["strict"]["error"], "DEPTH_ZERO_SELF_SIGNED_CERT", "{v}");
}

#[tokio::test]
async fn node_tls_connect_to_non_tls_peer_errors_and_never_reports_secure() {
    // ENG-23448 pinned "never fabricate secureConnect against a peer that is
    // not an in-process tls.Server". Since ENG-23492 the out-of-process path
    // performs REAL TLS through the native bridge, so the honest failure for
    // a plaintext-speaking peer is a wire-level TLS error. Node v25.9.0
    // oracle for a peer that answers the ClientHello with plaintext:
    // ERR_SSL_WRONG_VERSION_NUMBER, no secureConnect, exactly one error.
    // 'localhost' is the variant that pre-ENG-23448 fabricated full success.
    // @ref LLP 0004#the-tls-builtin — out-of-process peers use the native bridge
    let script = r#"
var tls = require('tls');
var net = require('net');
var out = {};
var watchdog = setTimeout(function () {
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}, 10000);

var plain = net.createServer(function (sock) {
  // Answer the ClientHello with plaintext HTTP, like a misconfigured server.
  sock.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nnot tls');
});
plain.listen(0, '127.0.0.1', function () {
  var port = plain.address().port;

  function attempt(host, label, next) {
    var events = [];
    var sock = tls.connect(port, host, function () { events.push('secureConnect'); });
    sock.on('error', function (e) { events.push('error:' + (e.code || e.message)); });
    sock.on('close', function () {
      out[label] = { events: events, destroyed: sock.destroyed, authorized: sock.authorized };
      next();
    });
  }

  attempt('localhost', 'byHostname', function () {
    attempt('127.0.0.1', 'byIp', function () {
      clearTimeout(watchdog);
      plain.close(function () {
        console.log(JSON.stringify(out));
        process.exit(0);
      });
    });
  });
});
"#;
    let v = run_script(script, 30).await;
    for label in ["byHostname", "byIp"] {
        let events = v[label]["events"]
            .as_array()
            .unwrap_or_else(|| panic!("{v}"));
        assert_eq!(
            events,
            &vec![Value::String("error:ERR_SSL_WRONG_VERSION_NUMBER".into())],
            "{label}: exactly one wire-level TLS error, never secureConnect: {v}"
        );
        assert_eq!(v[label]["destroyed"], true, "{label}: {v}");
        assert_eq!(v[label]["authorized"], false, "{label}: {v}");
    }
}

// ============================================================
// Native TLS bridge (ENG-23492/ENG-23526): real wire TLS against an in-process rustls
// server over loopback — hermetic (no network), same crypto stack the bridge
// itself uses. The fixture cert is self-signed for localhost/127.0.0.1, so
// `ca: [CERT]` exercises the trusted path and omitting it exercises the
// DEPTH_ZERO_SELF_SIGNED_CERT verdicts (all oracle-pinned on Node v25.9.0).
// ============================================================

mod tls_bridge_support {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    fn server_config() -> Arc<rustls::ServerConfig> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut super::TEST_CERT.as_bytes())
            .collect::<Result<_, _>>()
            .expect("fixture cert parses");
        let key = rustls_pemfile::private_key(&mut super::TEST_KEY.as_bytes())
            .expect("fixture key parses")
            .expect("fixture key present");
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config builds");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Spawn a real TLS server on 127.0.0.1: reads until a blank line (or
    /// LF for raw-socket clients), responds with a fixed HTTP/1.1 200, sends
    /// close_notify. Serves connections until the process exits (test
    /// scoped). Returns the bound port.
    pub fn spawn_tls_http_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let config = server_config();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let config = config.clone();
                std::thread::spawn(move || {
                    let mut conn = match rustls::ServerConnection::new(config) {
                        Ok(conn) => conn,
                        Err(_) => return,
                    };
                    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                    let mut received = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match tls.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                received.extend_from_slice(&buf[..n]);
                                if received.windows(4).any(|w| w == b"\r\n\r\n")
                                    || received.contains(&b'\n')
                                {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let body = b"ok-over-real-tls";
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(head.as_bytes());
                    let _ = tls.write_all(body);
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        port
    }
}

#[tokio::test]
async fn node_tls_bridge_real_handshake_with_ca_authorizes_and_moves_data() {
    // Trusted path: the self-signed fixture passed as `ca` must authorize
    // (Node v25.9.0 oracle: authorized=true), negotiate ALPN, expose the REAL
    // peer certificate fields parsed from the wire DER, and round-trip
    // application data over the encrypted socket.
    let port = tls_bridge_support::spawn_tls_http_server();
    let script = format!(
        r#"
var tls = require('tls');
var out = {{}};
var watchdog = setTimeout(function () {{
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}}, 10000);
var sock = tls.connect({{
  port: {port},
  host: '127.0.0.1',
  servername: 'localhost',
  ca: [CERT],
  ALPNProtocols: ['http/1.1']
}}, function () {{
  out.secureConnect = true;
  out.authorized = sock.authorized;
  out.authorizationError = sock.authorizationError;
  out.alpn = sock.alpnProtocol;
  out.protocol = sock.getProtocol();
  out.cipherName = sock.getCipher().name;
  var cert = sock.getPeerCertificate();
  out.subjectCN = cert.subject && cert.subject.CN;
  out.issuerCN = cert.issuer && cert.issuer.CN;
  out.altnames = cert.subjectaltname;
  out.validTo = cert.valid_to;
  out.fingerprint256Shape = /^([0-9A-F]{{2}}:){{31}}[0-9A-F]{{2}}$/.test(cert.fingerprint256 || '');
  out.hasRawDer = !!(cert.raw && cert.raw.length > 0);
  var body = '';
  sock.on('data', function (chunk) {{ body += chunk.toString(); }});
  sock.on('end', function () {{
    out.status = body.split('\r\n')[0];
    out.gotBody = body.indexOf('ok-over-real-tls') !== -1;
    clearTimeout(watchdog);
    console.log(JSON.stringify(out));
    process.exit(0);
  }});
  sock.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
}});
sock.on('error', function (e) {{
  out.error = (e.code || '') + ':' + e.message;
  clearTimeout(watchdog);
  console.log(JSON.stringify(out));
  process.exit(1);
}});
"#
    );
    let v = run_script(&with_fixture_pems(&script), 30).await;
    assert_eq!(v["secureConnect"], true, "{v}");
    assert_eq!(v["authorized"], true, "real chain + ca must authorize: {v}");
    assert_eq!(v["authorizationError"], Value::Null, "{v}");
    assert_eq!(v["alpn"], "http/1.1", "{v}");
    assert_eq!(v["protocol"], "TLSv1.3", "{v}");
    assert_eq!(v["subjectCN"], "localhost", "{v}");
    assert_eq!(v["issuerCN"], "localhost", "{v}");
    assert_eq!(v["altnames"], "DNS:localhost, IP Address:127.0.0.1", "{v}");
    assert_eq!(
        v["validTo"], "Jul  2 07:13:53 2046 GMT",
        "OpenSSL/Node cert time format from the real DER: {v}"
    );
    assert_eq!(v["fingerprint256Shape"], true, "{v}");
    assert_eq!(v["hasRawDer"], true, "{v}");
    assert_eq!(v["status"], "HTTP/1.1 200 OK", "{v}");
    assert_eq!(v["gotBody"], true, "application data over real TLS: {v}");
}

#[tokio::test]
async fn node_tls_bridge_selfsigned_verdicts_match_node() {
    // Untrusted (default roots) against the self-signed fixture. Node
    // v25.9.0 oracle: rejectUnauthorized:false -> secureConnect with
    // authorized=false / authorizationError='DEPTH_ZERO_SELF_SIGNED_CERT';
    // default -> abort with the same code and never secureConnect.
    let port = tls_bridge_support::spawn_tls_http_server();
    let script = format!(
        r#"
var tls = require('tls');
var out = {{}};
var watchdog = setTimeout(function () {{
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}}, 10000);
var lax = tls.connect({{ port: {port}, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false }}, function () {{
  out.lax = {{
    secureConnect: true,
    authorized: lax.authorized,
    authorizationError: lax.authorizationError,
    peerCN: (lax.getPeerCertificate().subject || {{}}).CN
  }};
  lax.destroy();
  var strictEvents = [];
  var strict = tls.connect({{ port: {port}, host: '127.0.0.1', servername: 'localhost' }}, function () {{
    strictEvents.push('secureConnect');
  }});
  strict.on('error', function (e) {{ strictEvents.push('error:' + (e.code || e.message)); }});
  strict.on('close', function () {{
    out.strict = {{ events: strictEvents, authorized: strict.authorized }};
    clearTimeout(watchdog);
    console.log(JSON.stringify(out));
    process.exit(0);
  }});
}});
lax.on('error', function (e) {{
  out.laxError = (e.code || '') + ':' + e.message;
  clearTimeout(watchdog);
  console.log(JSON.stringify(out));
  process.exit(1);
}});
"#
    );
    let v = run_script(&with_fixture_pems(&script), 30).await;
    assert_eq!(v["lax"]["secureConnect"], true, "{v}");
    assert_eq!(v["lax"]["authorized"], false, "{v}");
    assert_eq!(
        v["lax"]["authorizationError"], "DEPTH_ZERO_SELF_SIGNED_CERT",
        "{v}"
    );
    assert_eq!(v["lax"]["peerCN"], "localhost", "{v}");
    let strict_events = v["strict"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(
        strict_events,
        &vec![Value::String("error:DEPTH_ZERO_SELF_SIGNED_CERT".into())],
        "strict default must abort with the oracle code and never secureConnect: {v}"
    );
    assert_eq!(v["strict"]["authorized"], false, "{v}");
}

#[tokio::test]
async fn node_tls_bridge_hostname_mismatch_matches_node_shape() {
    // Chain trusted via ca but servername does not match the cert SANs.
    // Node v25.9.0 oracle: ERR_TLS_CERT_ALTNAME_INVALID with reason/host
    // properties and the exact message shape (the JS checkServerIdentity
    // path, fed by the REAL wire chain).
    let port = tls_bridge_support::spawn_tls_http_server();
    let script = format!(
        r#"
var tls = require('tls');
var out = {{}};
var watchdog = setTimeout(function () {{
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}}, 10000);
var events = [];
var sock = tls.connect({{ port: {port}, host: '127.0.0.1', servername: 'wrong.example.test', ca: [CERT] }}, function () {{
  events.push('secureConnect');
}});
sock.on('error', function (e) {{
  events.push('error');
  out.code = e.code;
  out.reason = e.reason;
  out.host = e.host;
  out.message = String(e.message).slice(0, 140);
}});
sock.on('close', function () {{
  out.events = events;
  out.authorized = sock.authorized;
  clearTimeout(watchdog);
  console.log(JSON.stringify(out));
  process.exit(0);
}});
"#
    );
    let v = run_script(&with_fixture_pems(&script), 30).await;
    assert_eq!(
        v["events"],
        serde_json::json!(["error"]),
        "hostname mismatch aborts before secureConnect: {v}"
    );
    assert_eq!(v["code"], "ERR_TLS_CERT_ALTNAME_INVALID", "{v}");
    assert_eq!(v["host"], "wrong.example.test", "{v}");
    assert_eq!(
        v["reason"],
        "Host: wrong.example.test. is not in the cert's altnames: DNS:localhost, IP Address:127.0.0.1",
        "{v}"
    );
    assert_eq!(v["authorized"], false, "{v}");
}

#[tokio::test]
async fn node_tls_bridge_https_get_roundtrip() {
    // https client over the bridged socket: URL + ca option, status and body
    // must come back through the real TLS connection. Also covers the
    // write-hold path (http.js writes the request on 'connect', before the
    // handshake finishes).
    let port = tls_bridge_support::spawn_tls_http_server();
    let script = format!(
        r#"
var https = require('https');
var out = {{}};
var watchdog = setTimeout(function () {{
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}}, 10000);
https.get('https://localhost:{port}/', {{ ca: [CERT] }}, function (res) {{
  out.status = res.statusCode;
  var body = '';
  res.on('data', function (chunk) {{ body += chunk; }});
  res.on('end', function () {{
    out.body = body;
    clearTimeout(watchdog);
    console.log(JSON.stringify(out));
    process.exit(0);
  }});
}}).on('error', function (e) {{
  out.error = (e.code || '') + ':' + e.message;
  clearTimeout(watchdog);
  console.log(JSON.stringify(out));
  process.exit(1);
}});
"#
    );
    let v = run_script(&with_fixture_pems(&script), 30).await;
    assert_eq!(v["status"], 200, "{v}");
    assert_eq!(v["body"], "ok-over-real-tls", "{v}");
}

#[tokio::test]
async fn node_tls_in_process_server_emulation_still_works_end_to_end() {
    // ENG-23448 finding 1 control: the supported loopback path — an
    // in-process tls.Server — must keep working after the fail-loud change:
    // server 'secureConnection', client 'secureConnect', negotiated cipher,
    // and application data round-tripping over the emulated socket pair.
    let script = r#"
var tls = require('tls');
var out = {};
var watchdog = setTimeout(function () {
  out.watchdog = 'fired';
  console.log(JSON.stringify(out));
  process.exit(1);
}, 10000);

var server = tls.createServer({ key: KEY, cert: CERT }, function (ssock) {
  ssock.on('data', function (d) { ssock.write('pong:' + d); });
});
server.on('secureConnection', function () { out.secureConnection = true; });
server.listen(0, '127.0.0.1', function () {
  var port = server.address().port;
  var sock = tls.connect({ port: port, host: '127.0.0.1', rejectUnauthorized: false }, function () {
    out.secureConnect = true;
    out.cipher = (sock.getCipher() || {}).name;
    sock.on('data', function (d) {
      out.echo = String(d);
      clearTimeout(watchdog);
      sock.destroy();
      server.close(function () {
        console.log(JSON.stringify(out));
        process.exit(0);
      });
    });
    sock.write('ping');
  });
  sock.on('error', function (e) {
    out.clientError = e.code || e.message;
    console.log(JSON.stringify(out));
    process.exit(1);
  });
});
"#;
    let v = run_script(&with_fixture_pems(script), 30).await;
    assert_eq!(v["secureConnection"], true, "{v}");
    assert_eq!(v["secureConnect"], true, "{v}");
    assert_eq!(v["cipher"], "TLS_AES_256_GCM_SHA384", "{v}");
    assert_eq!(v["echo"], "pong:ping", "{v}");
}
