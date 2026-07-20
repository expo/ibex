//! ENG-23506: the DEFAULT (native, no setServers) resolver path must preserve
//! resolver rcodes and timeout detail as Node-compatible dns error codes
//! instead of flattening every failure to ENOTFOUND.
//!
//! libresolv's res_query/res_nsend can never report SERVFAIL/REFUSED (they
//! skip such servers and eventually fail with a generic timeout), so the
//! native side sends the query on its own UDP socket and inspects the rcode
//! (src/engine/hermes_runtime_dns.cc). These tests drive the real `ibex`
//! binary against a loopback mock DNS server via the `IBEX_DNS_SERVER`
//! override — no public network involved — and assert the codes Node v25
//! produces for the same scenarios: ESERVFAIL, EREFUSED, ENOTFOUND (NXDOMAIN),
//! ENODATA (NOERROR/empty), ETIMEOUT (no response), plus a successful TXT
//! answer to prove normal resolution still parses.
//! Windows installs a separate system-resolver backend and does not compile
//! `hermes_runtime_dns.cc`, so this POSIX fixture override does not apply there.
//!
//! Run with: `cargo test --test native_dns_rcode`.

#![cfg(not(windows))]

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ibex-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[derive(Clone, Copy)]
enum MockMode {
    Rcode(u8),
    Timeout,
    TxtAnswer,
}

/// Minimal loopback mock DNS server: echoes each query back as a response with
/// the configured rcode (optionally with one TXT answer record), or stays
/// silent for the timeout scenario. Runs on a background thread until the
/// socket is dropped/test exits.
fn start_mock_dns_server(mode: MockMode) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mock DNS server");
    let port = socket.local_addr().expect("mock server addr").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf) {
            if len < 12 {
                continue;
            }
            match mode {
                MockMode::Timeout => continue,
                MockMode::Rcode(rcode) => {
                    let mut resp = buf[..len].to_vec();
                    let flags: u16 = 0x8180 | u16::from(rcode); // QR|RD|RA + rcode
                    resp[2..4].copy_from_slice(&flags.to_be_bytes());
                    resp[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT 0
                    let _ = socket.send_to(&resp, peer);
                }
                MockMode::TxtAnswer => {
                    let mut resp = buf[..len].to_vec();
                    resp[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT 1
                    let txt = b"eng-23506";
                    resp.extend_from_slice(&0xc00cu16.to_be_bytes()); // name ptr -> question
                    resp.extend_from_slice(&16u16.to_be_bytes()); // TXT
                    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
                    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    resp.extend_from_slice(&((txt.len() as u16) + 1).to_be_bytes());
                    resp.push(txt.len() as u8);
                    resp.extend_from_slice(txt);
                    let _ = socket.send_to(&resp, peer);
                }
            }
        }
    });
    port
}

const RCODE_PROBE_JS: &str = r#"var dns = require('dns');
dns.resolveTxt('rcode-fidelity.test', function(err, records) {
  if (err) {
    console.log('dns-rcode: code=' + err.code + ' syscall=' + err.syscall +
      ' hostname=' + err.hostname);
  } else {
    console.log('dns-rcode: ok ' + JSON.stringify(records));
  }
});
"#;

fn run_probe(mode: MockMode) -> String {
    let port = start_mock_dns_server(mode);
    let dir = unique_dir("dns-rcode");
    let script = dir.join("probe.js");
    std::fs::write(&script, RCODE_PROBE_JS).expect("write script");

    let out = Command::new(IBEX)
        .args(["capsec", "audit", "probe.js"])
        .current_dir(&dir)
        // Point the DEFAULT native resolver path at the loopback mock server;
        // keep the resolver timing tight so the timeout scenario stays fast.
        .env("IBEX_DNS_SERVER", format!("127.0.0.1:{port}"))
        .env("RES_OPTIONS", "timeout:1 attempts:1")
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("dns-rcode:"))
        .unwrap_or_else(|| {
            panic!("no dns-rcode line in output\nstdout:\n{stdout}\nstderr:\n{stderr}")
        })
        .to_string();
    let _ = std::fs::remove_dir_all(&dir);
    line
}

#[test]
fn dns_default_path_servfail_maps_to_eservfail() {
    let line = run_probe(MockMode::Rcode(2));
    assert_eq!(
        line,
        "dns-rcode: code=ESERVFAIL syscall=queryTXT hostname=rcode-fidelity.test"
    );
}

#[test]
fn dns_default_path_refused_maps_to_erefused() {
    let line = run_probe(MockMode::Rcode(5));
    assert_eq!(
        line,
        "dns-rcode: code=EREFUSED syscall=queryTXT hostname=rcode-fidelity.test"
    );
}

#[test]
fn dns_default_path_nxdomain_maps_to_enotfound() {
    let line = run_probe(MockMode::Rcode(3));
    assert_eq!(
        line,
        "dns-rcode: code=ENOTFOUND syscall=queryTXT hostname=rcode-fidelity.test"
    );
}

#[test]
fn dns_default_path_noerror_empty_maps_to_enodata() {
    let line = run_probe(MockMode::Rcode(0));
    assert_eq!(
        line,
        "dns-rcode: code=ENODATA syscall=queryTXT hostname=rcode-fidelity.test"
    );
}

#[test]
fn dns_default_path_unresponsive_server_maps_to_etimeout() {
    let line = run_probe(MockMode::Timeout);
    assert_eq!(
        line,
        "dns-rcode: code=ETIMEOUT syscall=queryTXT hostname=rcode-fidelity.test"
    );
}

#[test]
fn dns_default_path_txt_answer_still_resolves() {
    let line = run_probe(MockMode::TxtAnswer);
    assert_eq!(line, "dns-rcode: ok [[\"eng-23506\"]]");
}

#[test]
fn dns_get_servers_uses_native_resolver_configuration_without_fs_access() {
    let port = start_mock_dns_server(MockMode::TxtAnswer);
    let dir = unique_dir("dns-get-servers");
    std::fs::write(
        dir.join("probe.js"),
        "console.log(JSON.stringify(require('dns').getServers()));\n",
    )
    .expect("write getServers probe");
    let output = Command::new(IBEX)
        .args(["capsec", "audit", "probe.js"])
        .current_dir(&dir)
        .env("IBEX_DNS_SERVER", format!("127.0.0.1:{port}"))
        .output()
        .expect("run getServers probe");
    assert!(
        output.status.success(),
        "getServers probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!(r#"["127.0.0.1:{port}"]"#)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
