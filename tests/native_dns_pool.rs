//! ENG-23022 regression: the async native DNS worker pool must not spuriously
//! reject concurrent lookups once more than `kMaxWorkers` are in flight.
//!
//! `Promise.all` runs every executor synchronously, so a fan-out over many hosts
//! issues all `DnsWorkerPool::enqueue` calls in one JS tick — before any worker
//! thread returns from `getaddrinfo`. The old `idle_ == 0 && total_ >= kMaxWorkers`
//! early-reject fired before the queue-full check, so the 9th+ concurrent lookup
//! rejected with "DNS worker pool exhausted", which `dns.*` maps to a spurious
//! `getaddrinfo ENOTFOUND` for a perfectly resolvable host. This drives the real
//! `ibex` binary (real worker pool, real resolver) and asserts every lookup in a
//! 16-wide fan-out resolves.
//!
//! Run with: `cargo test --test native_dns_pool`.

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

// 16 concurrent localhost lookups (2x kMaxWorkers = 8). Counts resolves vs.
// rejections independent of the resolved address so the assertion holds wherever
// `localhost` resolves, and reports the reject codes on failure.
const DNS_FANOUT_JS: &str = r#"var dns = require('dns');
var N = 16;
var hosts = [];
for (var i = 0; i < N; i++) hosts.push('localhost');
Promise.all(hosts.map(function (h) {
  return dns.promises.lookup(h, { family: 4 }).then(
    function () { return 'ok'; },
    function (e) { return 'err:' + (e && e.code); });
})).then(function (results) {
  var ok = 0, bad = [];
  for (var i = 0; i < results.length; i++) {
    if (results[i] === 'ok') ok++; else bad.push(results[i]);
  }
  console.log('dns-fanout: total=' + results.length + ' ok=' + ok + ' bad=[' + bad.join(',') + ']');
});
"#;

#[test]
fn dns_worker_pool_does_not_spuriously_reject_concurrent_lookups() {
    let dir = unique_dir("dns-fanout");
    let script = dir.join("fanout.js");
    std::fs::write(&script, DNS_FANOUT_JS).expect("write script");

    let out = Command::new(IBEX)
        .args(["run", "fanout.js"])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stdout.contains("dns-fanout: total=16 ok=16 bad=[]"),
        "all 16 concurrent localhost lookups must resolve; a pool-exhaustion \
         ENOTFOUND would show up as ok<16:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
