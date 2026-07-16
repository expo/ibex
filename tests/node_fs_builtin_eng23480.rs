//! End-to-end tests for the fs builtin correctness fixes from ENG-23480,
//! driving the real `ibex` binary. Every expectation here was oracle-checked
//! against real Node (v25) on macOS:
//!
//!   * globSync: exclude-function semantics (true = exclude, previously
//!     inverted), directories as match candidates, excluded-directory
//!     subtree pruning, Dirent args with withFileTypes.
//!   * cpSync: preserveTimestamps actually preserves mtime; source file mode
//!     always preserved; a FIFO source raises ERR_FS_CP_FIFO_PIPE for a
//!     direct copy and is skipped during a recursive tree copy (previously:
//!     infinite recursion / stack overflow).
//!   * createReadStream({autoClose:false}) still opens eagerly and emits
//!     'open'/'ready'.
//!   * WriteStream destroy() during the deferred open: no 'open'/'ready'
//!     after 'close', fd closed.
//!   * fs.watch with persistent:false still delivers events, and does not
//!     keep the event loop alive.
//!   * watchFile({bigint:true}): curr/prev keep isFile() etc.
//!   * rmSync recursive: ENOTEMPTY only for a verifiably non-empty target,
//!     genuine EACCES surfaces (previously every darwin EACCES was rewritten).
//!   * fs.promises.appendFile / FileHandle.appendFile resolve undefined;
//!     fs.promises.readFile honors options.signal.
//!   * lutimesSync / lchmodSync accept Buffer/URL paths.
//!
//! Run with: `scripts/run-tests.sh --scope test eng23480_fs`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

struct AppRun {
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("ibex-fs23480-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_text(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write test file");
}

fn run_app(tag: &str, app: &str, timeout: Duration) -> AppRun {
    let dir = unique_dir(tag);
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("create isolated home");
    write_text(&dir.join("app.js"), app);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        // The runtime's bundle cache is intentionally persistent, but this
        // fresh-process contract must not inherit cache-pruning latency from
        // unrelated tests or the developer's machine.
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ibex binary");

    let mut out = child.stdout.take().expect("stdout pipe");
    let mut err = child.stderr.take().expect("stderr pipe");
    let out_thread = thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_thread = thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }

    AppRun {
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
        timed_out,
    }
}

fn assert_lines(run: &AppRun, expected: &[&str]) {
    assert!(
        !run.timed_out,
        "app timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    for line in expected {
        assert!(
            run.stdout.lines().any(|l| l == *line),
            "missing line {:?}\nstdout:\n{}\nstderr:\n{}",
            line,
            run.stdout,
            run.stderr
        );
    }
}

#[test]
fn eng23480_fs_glob_exclude_semantics_and_directories() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-glob-'));
fs.writeFileSync(path.join(d, 'a.txt'), 'a');
fs.writeFileSync(path.join(d, 'b.txt'), 'b');
fs.mkdirSync(path.join(d, 'subdir'));
fs.writeFileSync(path.join(d, 'subdir', 'f.txt'), 's');
console.log('exclude-fn|' + fs.globSync('*.txt', { cwd: d, exclude: function(n) { return n === 'a.txt'; } }).sort().join(','));
console.log('exclude-arr|' + fs.globSync('*.txt', { cwd: d, exclude: ['a.txt'] }).sort().join(','));
console.log('star|' + fs.globSync('*', { cwd: d }).sort().join(','));
console.log('prune|' + fs.globSync('**', { cwd: d, exclude: function(n) { return n === 'subdir'; } }).sort().join(','));
console.log('wft|' + fs.globSync('*', { cwd: d, withFileTypes: true, exclude: function(de) { return de.name === 'a.txt'; } }).map(function(de){ return de.name + (de.isDirectory() ? '/' : ''); }).sort().join(','));
fs.rmSync(d, { recursive: true, force: true });
"#;
    let run = run_app("glob", app, Duration::from_secs(30));
    assert_lines(
        &run,
        &[
            "exclude-fn|b.txt",
            "exclude-arr|b.txt",
            "star|a.txt,b.txt,subdir",
            "prune|a.txt,b.txt",
            "wft|b.txt,subdir/",
        ],
    );
}

#[cfg(unix)]
#[test]
fn eng23480_fs_cp_sync_timestamps_mode_and_special_files() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var cp = require('child_process');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-cp-'));
var src = path.join(d, 'src'); var dst = path.join(d, 'dst');
fs.mkdirSync(src);
fs.writeFileSync(path.join(src, 'f.txt'), 'hello');
fs.chmodSync(path.join(src, 'f.txt'), 0o604);
var old = new Date(Date.now() - 86400000);
fs.utimesSync(path.join(src, 'f.txt'), old, old);
fs.cpSync(src, dst, { recursive: true, preserveTimestamps: true });
var s = fs.statSync(path.join(src, 'f.txt')), t = fs.statSync(path.join(dst, 'f.txt'));
console.log('mtime-preserved|' + (Math.abs(s.mtimeMs - t.mtimeMs) < 1000));
console.log('mode-ts|' + (t.mode & 0o777).toString(8));
console.log('content|' + fs.readFileSync(path.join(dst, 'f.txt'), 'utf8'));
fs.rmSync(dst, { recursive: true });
fs.cpSync(src, dst, { recursive: true });
console.log('mode|' + (fs.statSync(path.join(dst, 'f.txt')).mode & 0o777).toString(8));
cp.execSync('mkfifo ' + JSON.stringify(path.join(src, 'pipe')));
fs.rmSync(dst, { recursive: true });
// Previously this recursed to stack overflow on the FIFO (ENG-23480 #3).
fs.cpSync(src, dst, { recursive: true });
console.log('fifo-skipped|' + fs.readdirSync(dst).sort().join(','));
try {
  fs.cpSync(path.join(src, 'pipe'), path.join(d, 'pipe2'));
  console.log('direct-fifo|no-throw');
} catch (e) {
  console.log('direct-fifo|' + e.code);
}
fs.rmSync(d, { recursive: true, force: true });
"#;
    let run = run_app("cp", app, Duration::from_secs(30));
    assert_lines(
        &run,
        &[
            "mtime-preserved|true",
            "mode-ts|604",
            "content|hello",
            "mode|604",
            "fifo-skipped|f.txt",
            "direct-fifo|ERR_FS_CP_FIFO_PIPE",
        ],
    );
}

#[test]
fn eng23480_fs_streams_deferred_open_contracts() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-st-'));
var f = path.join(d, 'r.txt');
fs.writeFileSync(f, 'data');
var rs = fs.createReadStream(f, { autoClose: false });
var gotOpen = false, gotReady = false, finished = false;
var timer = setTimeout(function() { if (!finished) { console.log('read-open-eager|timeout'); part2(); } }, 3000);
rs.on('open', function(fd) { gotOpen = typeof fd === 'number'; check(); });
rs.on('ready', function() { gotReady = true; check(); });
function check() {
  if (gotOpen && gotReady && !finished) {
    finished = true;
    clearTimeout(timer);
    console.log('read-open-eager|true');
    fs.closeSync(rs.fd);
    part2();
  }
}
function part2() {
  var ws = fs.createWriteStream(path.join(d, 'w.txt'));
  var events = [];
  ws.on('open', function() { events.push('open'); });
  ws.on('ready', function() { events.push('ready'); });
  ws.on('close', function() { events.push('close'); });
  ws.write('x');
  ws.destroy();
  setTimeout(function() {
    var closeIdx = events.indexOf('close');
    var openIdx = events.indexOf('open');
    console.log('ws-no-open-after-close|' + (openIdx === -1 || (closeIdx !== -1 && openIdx < closeIdx)));
    fs.rmSync(d, { recursive: true, force: true });
  }, 300);
}
"#;
    let run = run_app("streams", app, Duration::from_secs(30));
    assert_lines(
        &run,
        &["read-open-eager|true", "ws-no-open-after-close|true"],
    );
}

#[test]
fn eng23480_fs_watch_persistent_false_delivers_events_and_bigint_watchfile() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-w-'));
var f = path.join(d, 'watched.txt');
fs.writeFileSync(f, 'v0');
var got = false;
var watcher = fs.watch(f, { persistent: false }, function() { got = true; });
var keepAlive = setTimeout(function() {}, 5000);
setTimeout(function() { fs.writeFileSync(f, 'v1-changed-content'); }, 100);
setTimeout(function() {
  console.log('persistent-false-event|' + got);
  watcher.close();
  var f2 = path.join(d, 'big.txt');
  fs.writeFileSync(f2, 'x');
  var saw = null;
  fs.watchFile(f2, { bigint: true, interval: 50 }, function(curr, prev) {
    if (saw === null) saw = curr.isFile() && prev.isFile() && typeof curr.mtimeMs === 'bigint';
  });
  setTimeout(function() { fs.writeFileSync(f2, 'xy'); }, 100);
  setTimeout(function() {
    console.log('watchfile-bigint|' + saw);
    fs.unwatchFile(f2);
    clearTimeout(keepAlive);
    fs.rmSync(d, { recursive: true, force: true });
  }, 1200);
}, 900);
"#;
    let run = run_app("watch", app, Duration::from_secs(30));
    assert_lines(
        &run,
        &["persistent-false-event|true", "watchfile-bigint|true"],
    );
}

#[test]
fn eng23480_fs_watch_persistent_false_does_not_hold_event_loop() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-ue-'));
var f = path.join(d, 'x.txt');
fs.writeFileSync(f, 'x');
fs.watch(f, { persistent: false }, function() {});
console.log('created-watcher|true');
"#;
    // Cold bundling can consume most of 15 seconds on debug CI runners. Give
    // startup independent headroom; a referenced watcher still runs forever
    // and is deterministically killed at this deadline.
    let run = run_app("unref-exit", app, Duration::from_secs(30));
    assert_lines(&run, &["created-watcher|true"]);
}

#[cfg(unix)]
#[test]
fn eng23480_fs_rm_recursive_error_codes_match_node() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-rm-'));
// Target dir itself read-only (cannot be emptied): Node reports ENOTEMPTY.
var p = path.join(d, 'ro');
fs.mkdirSync(p);
fs.writeFileSync(path.join(p, 'inner.txt'), 'z');
fs.chmodSync(p, 0o555);
try { fs.rmSync(p, { recursive: true }); console.log('nonempty|no-throw'); }
catch (e) { console.log('nonempty|' + e.code); }
fs.chmodSync(p, 0o755);
// Read-only parent (dir emptied, final rmdir fails): the real EACCES must
// surface instead of being rewritten to ENOTEMPTY (ENG-23480 #12).
var parent = path.join(d, 'parent'), sub = path.join(parent, 'sub');
fs.mkdirSync(sub, { recursive: true });
fs.writeFileSync(path.join(sub, 'f.txt'), 'x');
fs.chmodSync(parent, 0o555);
try { fs.rmSync(sub, { recursive: true }); console.log('perm|no-throw'); }
catch (e) { console.log('perm|' + e.code); }
fs.chmodSync(parent, 0o755);
fs.rmSync(d, { recursive: true, force: true });
"#;
    let run = run_app("rm", app, Duration::from_secs(30));
    // Root can delete regardless of permission bits; both probes throw only
    // for regular users. CI and dev machines run unprivileged.
    assert_lines(&run, &["nonempty|ENOTEMPTY", "perm|EACCES"]);
}

#[test]
fn eng23480_fs_promises_contracts_and_l_path_conversion() {
    let app = r#"
var fs = require('fs');
var os = require('os');
var path = require('path');
var d = fs.mkdtempSync(path.join(os.tmpdir(), 'eng23480-m-'));
var f = path.join(d, 'x.txt');
fs.writeFileSync(f, 'abc');
var old = new Date(Date.now() - 3600000);
fs.lutimesSync(new URL('file://' + f), old, old);
console.log('lutimes-url|' + (Math.abs(fs.lstatSync(f).mtimeMs - old.getTime()) < 1000));
fs.lchmodSync(Buffer.from(f), 0o600);
console.log('lchmod-buffer|' + (fs.lstatSync(f).mode & 0o777).toString(8));
fs.promises.appendFile(f, 'more').then(function(v) {
  console.log('promises-appendfile|' + (v === undefined ? 'undefined' : v));
  return fs.promises.open(f, 'a');
}).then(function(fh) {
  return fh.appendFile('x').then(function(v2) {
    console.log('filehandle-appendfile|' + (v2 === undefined ? 'undefined' : v2));
    return fh.close();
  });
}).then(function() {
  var c = new AbortController();
  c.abort();
  return fs.promises.readFile(f, { signal: c.signal }).then(
    function() { console.log('readfile-signal|resolved'); },
    function(err) { console.log('readfile-signal|' + err.code); });
}).then(function() {
  return fs.promises.readFile(f, { signal: 42 }).then(
    function() { console.log('readfile-badsignal|resolved'); },
    function(err) { console.log('readfile-badsignal|' + err.code); });
}).then(function() {
  return fs.promises.readFile(f, 'utf8').then(function(data) {
    console.log('readfile-normal|' + data);
  });
}).then(function() {
  fs.rmSync(d, { recursive: true, force: true });
}).catch(function(e) {
  console.log('FAIL|' + (e && (e.message || e)));
});
"#;
    let run = run_app("promises", app, Duration::from_secs(30));
    assert_lines(
        &run,
        &[
            "lutimes-url|true",
            "lchmod-buffer|600",
            "promises-appendfile|undefined",
            "filehandle-appendfile|undefined",
            "readfile-signal|ABORT_ERR",
            "readfile-badsignal|ERR_INVALID_ARG_TYPE",
            "readfile-normal|abcmorex",
        ],
    );
}
