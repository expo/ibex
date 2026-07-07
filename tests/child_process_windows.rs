//! Windows-only coverage for the native async child_process bridge.

#![cfg(windows)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
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
        std::env::temp_dir().join(format!("ibex-win-cp-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write test file");
}

fn run_app_in(dir: &Path, app: &str, timeout: Duration) -> AppRun {
    static RUN_APP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = RUN_APP_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("lock Windows child_process app runner");

    write_text(&dir.join("app.js"), app);
    let mut child = Command::new(IBEX)
        .arg("run")
        .arg("app.js")
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("IBEX_NO_BYTECODE", "1")
        .env("BUN_INSTALL_CACHE_DIR", dir.join(".bun-cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex binary");

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

fn run_app(tag: &str, app: &str, timeout: Duration) -> AppRun {
    let dir = unique_dir(tag);
    run_app_in(&dir, app, timeout)
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split('|').find_map(|kv| kv.strip_prefix(key))
}

fn result_line<'a>(run: &'a AppRun) -> &'a str {
    assert!(
        !run.timed_out,
        "app timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    run.stdout
        .lines()
        .find(|line| line.starts_with("RESULT|"))
        .unwrap_or_else(|| {
            panic!(
                "missing RESULT line\nstdout:\n{}\nstderr:\n{}",
                run.stdout, run.stderr
            )
        })
}

#[test]
fn win32_async_spawn_does_not_block_event_loop() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('cmd.exe', ['/d', '/c', 'ping -n 3 127.0.0.1 >NUL & echo DONE'], {
  stdio: ['ignore', 'pipe', 'pipe']
});
let timerFired = false;
let out = '';
c.stdout.on('data', function (d) { out += d; });
setTimeout(function () {
  timerFired = true;
}, 100);
c.on('close', function (code) {
  console.log('RESULT|code=' + code + '|timer=' + timerFired + '|out=' + out.trim());
});
"#;
    let run = run_app("nonblocking", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(field(line, "code="), Some("0"), "child failed: {line}");
    assert_eq!(
        field(line, "timer="),
        Some("true"),
        "event loop was blocked until the child exited: {line}"
    );
    assert_eq!(
        field(line, "out="),
        Some("DONE"),
        "stdout was not captured: {line}"
    );
}

#[test]
fn win32_spawn_stdin_write_reaches_live_child() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('cmd.exe', ['/d', '/v:on', '/c', 'set /p line=& echo ECHO:!line!'], {
  stdio: ['pipe', 'pipe', 'pipe']
});
let out = '';
c.stdout.on('data', function (d) { out += d; });
setTimeout(function () {
  c.stdin.write('hello\r\n');
  c.stdin.end();
}, 100);
c.on('close', function (code) {
  console.log('RESULT|code=' + code + '|out=' + out.trim());
});
"#;
    let run = run_app("stdin", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(field(line, "code="), Some("0"), "child failed: {line}");
    assert_eq!(
        field(line, "out="),
        Some("ECHO:hello"),
        "stdin write missed live child: {line}"
    );
}

#[test]
fn win32_spawn_kill_reaches_live_child() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('ping.exe', ['-n', '10', '127.0.0.1'], {
  stdio: ['ignore', 'ignore', 'ignore']
});
setTimeout(function () {
  console.log('RESULT|kill=' + c.kill());
}, 100);
c.on('close', function (code, signal) {
  console.log('RESULT2|code=' + code + '|signal=' + signal);
});
"#;
    let run = run_app("kill", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "kill="),
        Some("true"),
        "kill() did not reach child: {line}"
    );
    assert!(
        run.stdout.contains("RESULT2|code=1|signal=null"),
        "killed child did not close with TerminateProcess exit code\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn win32_fork_ipc_still_fails_loudly() {
    let dir = unique_dir("ipc");
    write_text(&dir.join("child.js"), "process.exit(0);\n");
    let app = r#"
const cp = require('child_process');
try {
  cp.fork(__dirname + '/child.js');
  console.log('RESULT|code=NO_THROW');
} catch (err) {
  console.log('RESULT|code=' + err.code);
}
"#;
    let run = run_app_in(&dir, app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "code="),
        Some("ENOTSUP"),
        "fork/IPC must fail explicitly: {line}"
    );
}
