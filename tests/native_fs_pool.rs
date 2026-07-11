//! ENG-23497: the callback/promise fs API must perform its I/O off the JS
//! thread. The "async" fs API used to run every syscall synchronously on the
//! JS thread and merely defer the callback, so a large `fs.readFile` starved
//! timers, sockets, and all other JS until the read completed. These tests
//! drive the real `ibex` binary (real FsWorkerPool, real syscalls) and assert:
//!
//! 1. timers keep firing while a large readFile is in flight (starvation),
//! 2. an in-flight async fs op keeps the event loop alive (keepalive), and
//! 3. `process.exit(0)` after pool use exits promptly — the pool is an
//!    immortal heap singleton, so no static-destructor deadlock on Linux
//!    (glibc deadlocks exit() when a function-local static pool destroys a
//!    condvar with parked waiters; see ENG-23471/ENG-23498), and
//! 4. a 16-wide concurrent fan-out (2x kMaxWorkers = 8) all succeeds.
//!
//! Run with: `cargo test --test native_fs_pool`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ibex-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// A 64 MiB file is large enough that the old sync-on-JS-thread readFile
// blocked the loop for a long, easily-detectable stretch (hundreds of ms even
// from page cache in a release build; seconds in debug), while staying cheap
// to create. The interval ticks every 5ms; with the worker-pool path at least
// a few ticks MUST land strictly between readFile dispatch and its callback.
// The old deferred-sync path delivers exactly zero ticks in that window (the
// read runs synchronously inside the deferred callback slot).
const STARVATION_JS: &str = r#"var fs = require('fs');
var file = process.argv[2] || 'big.bin';
var ticks = 0;
var iv = setInterval(function () { ticks++; }, 5);
var t0 = Date.now();
fs.readFile(file, function (err, data) {
  clearInterval(iv);
  if (err) {
    console.log('fs-starvation: err=' + err.code);
    return;
  }
  console.log('fs-starvation: bytes=' + data.length + ' durMs=' + (Date.now() - t0) + ' ticksDuringRead=' + ticks);
});
"#;

#[test]
fn timers_keep_firing_during_large_readfile() {
    let dir = unique_dir("fs-starvation");
    let script = dir.join("starve.js");
    std::fs::write(&script, STARVATION_JS).expect("write script");
    let big = dir.join("big.bin");
    std::fs::write(&big, vec![0xA5u8; 64 * 1024 * 1024]).expect("write 64MiB file");

    let out = Command::new(IBEX)
        .args(["run", "starve.js", big.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let line = stdout
        .lines()
        .find(|l| l.starts_with("fs-starvation:"))
        .unwrap_or_else(|| panic!("no fs-starvation line:\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    assert!(
        line.contains("bytes=67108864"),
        "readFile must deliver the full file: {line}\nstderr:\n{stderr}"
    );
    let ticks: u64 = line
        .split("ticksDuringRead=")
        .nth(1)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("unparseable line: {line}"));
    // Deliberately loose bound: any tick strictly during the read proves the
    // I/O left the JS thread (the sync path yields exactly 0). Requiring >= 1
    // keeps this robust on fast disks where the whole read takes ~10ms.
    assert!(
        ticks >= 1,
        "expected interval ticks to fire during readFile (got {ticks}); \
         0 ticks means the read blocked the JS thread: {line}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// No timers, no other referenced work: if pending_fs_ops were not counted as
// referenced work the process would exit before the worker delivers the
// completion and the marker line would never print.
const KEEPALIVE_JS: &str = r#"var fs = require('fs');
fs.readFile(process.argv[2] || 'small.txt', 'utf8', function (err, data) {
  console.log('fs-keepalive: ' + (err ? 'err=' + err.code : 'data=' + data));
});
"#;

#[test]
fn inflight_async_fs_op_keeps_event_loop_alive() {
    let dir = unique_dir("fs-keepalive");
    let script = dir.join("keepalive.js");
    std::fs::write(&script, KEEPALIVE_JS).expect("write script");
    let small = dir.join("small.txt");
    std::fs::write(&small, "alive").expect("write small file");

    let out = Command::new(IBEX)
        .args(["run", "keepalive.js", small.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("fs-keepalive: data=alive"),
        "readFile completion must be delivered before exit:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// After the pool has spawned workers (parked in cv_.wait), process.exit(0)
// must terminate promptly. A function-local by-value static pool deadlocks
// glibc's static destructors on Linux (ENG-23471); the immortal heap
// singleton must not.
const EXIT_SAFETY_JS: &str = r#"var fs = require('fs');
fs.readFile(process.argv[2] || 'small.txt', function (err) {
  console.log('fs-exit: read-done err=' + (err ? err.code : 'null'));
  process.exit(0);
});
"#;

#[test]
fn process_exit_after_pool_use_terminates_promptly() {
    let dir = unique_dir("fs-exit");
    let script = dir.join("exit.js");
    std::fs::write(&script, EXIT_SAFETY_JS).expect("write script");
    let small = dir.join("small.txt");
    std::fs::write(&small, "bye").expect("write small file");

    let start = Instant::now();
    let mut child = Command::new(IBEX)
        .args(["run", "exit.js", small.to_str().unwrap()])
        .current_dir(&dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn ibex binary");

    // Poll for exit with a hard 30s bound instead of blocking forever on a
    // deadlocked exit().
    let deadline = Duration::from_secs(30);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if start.elapsed() > deadline => {
                let _ = child.kill();
                panic!("process.exit(0) did not terminate within {deadline:?} — exit() deadlock");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    assert!(
        status.success(),
        "process.exit(0) must yield exit code 0, got {status:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// 16 concurrent readFiles (2x kMaxWorkers = 8) issued in one JS tick: excess
// work must queue, not reject (same discipline as the DNS pool after
// ENG-23022).
const FANOUT_JS: &str = r#"var fs = require('fs');
var file = process.argv[2] || 'small.txt';
var N = 16;
var work = [];
for (var i = 0; i < N; i++) {
  work.push(fs.promises.readFile(file, 'utf8').then(
    function (d) { return d === 'fanout' ? 'ok' : 'bad-content'; },
    function (e) { return 'err:' + (e && e.code); }));
}
Promise.all(work).then(function (results) {
  var ok = 0, bad = [];
  for (var i = 0; i < results.length; i++) {
    if (results[i] === 'ok') ok++; else bad.push(results[i]);
  }
  console.log('fs-fanout: total=' + results.length + ' ok=' + ok + ' bad=[' + bad.join(',') + ']');
});
"#;

#[test]
fn fs_worker_pool_handles_concurrent_fanout() {
    let dir = unique_dir("fs-fanout");
    let script = dir.join("fanout.js");
    std::fs::write(&script, FANOUT_JS).expect("write script");
    let small = dir.join("small.txt");
    std::fs::write(&small, "fanout").expect("write small file");

    let out = Command::new(IBEX)
        .args(["run", "fanout.js", small.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("fs-fanout: total=16 ok=16 bad=[]"),
        "all 16 concurrent readFiles must resolve:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

const PATH_OPS_JS: &str = r#"var fs = require('fs');
var os = require('os');
var path = require('path');

function callbackOp(fn) {
  return new Promise(function(resolve, reject) {
    fn(function(err, value) {
      if (err) reject(err);
      else resolve(value);
    });
  });
}

(async function() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-pathops-'));
  var child = path.join(root, 'child');
  var src = path.join(child, 'src.txt');
  var copy = path.join(child, 'copy.txt');
  var renamed = path.join(child, 'renamed.txt');
  await fs.promises.mkdir(child);
  fs.writeFileSync(src, 'abcdef');
  await fs.promises.copyFile(src, copy);
  var entries = await fs.promises.readdir(child);
  var statfs = await fs.promises.statfs(child);
  await callbackOp(function(done) { fs.rename(copy, renamed, done); });
  var real = await fs.promises.realpath(renamed);
  var expectedReal = fs.realpathSync(renamed);
  await callbackOp(function(done) { fs.truncate(renamed, 3, done); });
  await callbackOp(function(done) { fs.utimes(renamed, 1, 2, done); });
  var content = fs.readFileSync(renamed, 'utf8');
  await fs.promises.unlink(renamed);
  await fs.promises.unlink(src);
  await fs.promises.rmdir(child);
  fs.rmSync(root, { recursive: true, force: true });
  console.log('fs-pathops: ' + JSON.stringify({
    entries: entries,
    realOk: real === expectedReal,
    statfsOk: Number(statfs.bsize) > 0,
    content: content
  }));
})().catch(function(err) {
  console.log('fs-pathops: err=' + (err && (err.stack || err.message || err)));
  process.exitCode = 1;
});
"#;

#[test]
fn fs_worker_pool_handles_path_metadata_ops() {
    let dir = unique_dir("fs-pathops");
    let script = dir.join("pathops.js");
    std::fs::write(&script, PATH_OPS_JS).expect("write script");

    let out = Command::new(IBEX)
        .args(["run", "pathops.js"])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "path op script should exit successfully:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(
            r#"fs-pathops: {"entries":["copy.txt","src.txt"],"realOk":true,"statfsOk":true,"content":"abc"}"#
        ),
        "path metadata ops should complete through async fs APIs:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Node-shaped error contract straight through the async path: errno/code/
// syscall/path identical to the sync path (oracle: real Node v25).
const ERROR_SHAPE_JS: &str = r#"var fs = require('fs');
var missing = process.argv[2] + '/definitely-missing';
fs.readFile(missing, function (err) {
  console.log('fs-errshape: code=' + err.code + ' errno=' + err.errno +
      ' syscall=' + err.syscall + ' pathOk=' + (err.path === missing) +
      ' msgOk=' + (err.message === "ENOENT: no such file or directory, open '" + missing + "'"));
});
"#;

#[test]
fn async_readfile_errors_keep_node_shape() {
    let dir = unique_dir("fs-errshape");
    let script = dir.join("errshape.js");
    std::fs::write(&script, ERROR_SHAPE_JS).expect("write script");

    let out = Command::new(IBEX)
        .args(["run", "errshape.js", dir.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("failed to spawn ibex binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("fs-errshape: code=ENOENT errno=-2 syscall=open pathOk=true msgOk=true"),
        "async readFile error must keep Node shape:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Every fd-form async native duplicates the descriptor before dispatch. A
// close issued immediately afterwards may revoke/close the public descriptor,
// but must not redirect the in-flight operation onto a reused fd number.
#[test]
fn inflight_fd_read_is_pinned_across_async_close() {
    let dir = unique_dir("fs-fd-close-race");
    let script = dir.join("race.js");
    std::fs::write(
        &script,
        r#"var fs = require('fs');
var fd = fs.openSync('payload.txt', 'r');
var buf = Buffer.alloc(6);
fs.read(fd, buf, 0, 6, 0, function(err, n) {
  console.log('fd-close-race: ' + (err ? err.code : n + ':' + buf.toString()));
});
fs.close(fd, function(err) { if (err) console.log('close-error:' + err.code); });
"#,
    )
    .expect("write race script");
    std::fs::write(dir.join("payload.txt"), "pinned").expect("write payload");
    let out = Command::new(IBEX)
        .args(["run", "race.js"])
        .current_dir(&dir)
        .output()
        .expect("run close race");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("fd-close-race: 6:pinned"),
        "in-flight read must retain its open file description:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn queue_rejection_releases_owned_fds_and_rolls_back_close() {
    let dir = unique_dir("fs-queue-reject");
    let script = dir.join("reject.js");
    std::fs::write(
        &script,
        r#"var fs = require('fs');
(async function() {
  fs.writeFileSync('payload.txt', 'alive');
  var fd = fs.openSync('payload.txt', 'r');
  var before = fs.readdirSync('/dev/fd').length;
  var rejected = await Promise.all(Array.from({length: 100}, function(_, i) {
    var op = i % 2 ? fs.promises.fstat(fd) : fs.promises.fchmod(fd, 0o600);
    return op.then(function() { return false; }, function() { return true; });
  }));
  var closeRejected = await fs.promises.close(fd).then(function() { return false; }, function() { return true; });
  var byte = Buffer.alloc(1); fs.readSync(fd, byte, 0, 1, 0);
  var openRejected = await fs.promises.open('must-not-exist.txt', 'w').then(function() { return false; }, function() { return true; });
  var after = fs.readdirSync('/dev/fd').length;
  fs.closeSync(fd);
  console.log('fs-queue-reject: rejected=' + rejected.filter(Boolean).length +
    ' close=' + closeRejected + ' open=' + openRejected + ' byte=' + byte.toString() +
    ' created=' + fs.existsSync('must-not-exist.txt') + ' fdDelta=' + (after - before));
})().catch(function(e) { console.log('fs-queue-reject: error=' + (e.stack || e)); process.exitCode = 1; });
"#,
    )
    .expect("write rejection script");
    let out = Command::new(IBEX)
        .args(["run", "reject.js"])
        .env("IBEX_TEST_FS_WORKER_MAX_QUEUE", "0")
        .current_dir(&dir)
        .output()
        .expect("run queue rejection test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("rejected=100 close=true open=true byte=a created=false fdDelta=0"),
        "queue rejection must release duplicates and restore close authority:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn large_typed_readdir_stays_within_worker_queue_bound() {
    let dir = unique_dir("fs-large-readdir");
    let entries = dir.join("entries");
    std::fs::create_dir(&entries).expect("create entries dir");
    for i in 0..1500 {
        std::fs::write(entries.join(format!("entry-{i}")), "").expect("write entry");
    }
    std::fs::write(
        dir.join("large-readdir.js"),
        r#"var fs = require('fs');
fs.promises.readdir('entries', {withFileTypes:true}).then(function(items) {
  console.log('large-readdir: count=' + items.length + ' files=' + items.filter(function(x) { return x.isFile(); }).length);
}, function(err) { console.log('large-readdir: error=' + (err.code || err)); process.exitCode = 1; });
"#,
    )
    .expect("write large readdir script");
    let out = Command::new(IBEX)
        .args(["run", "large-readdir.js"])
        .current_dir(&dir)
        .output()
        .expect("run large readdir");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("large-readdir: count=1500 files=1500"),
        "bounded traversal must not overflow the 1024-job queue:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
