//! Positional vectored fs I/O contract tests driving the real `ibex` binary
//! (ENG-23467): Node's `fs.readvSync`/`fs.writevSync` with a numeric position
//! must NOT move the fd's current file offset — libuv uses preadv/pwritev.
//! The native bridge previously did lseek+readv/writev, so a positional
//! vectored op permanently moved the cursor and corrupted a following
//! sequential read/write. These behaviors were oracle-checked against real
//! Node (v22) before landing.
//!
//! Run with: `scripts/run-tests.sh --scope test node_fs_vectored_positional`.

use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

/// Run a JS expression under `ibex -p` and return the last stdout line.
async fn eval(js: &str) -> String {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(js);
    let output = timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex -p timed out")
        .expect("failed to spawn or read ibex process output");
    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .lines()
        .last()
        .unwrap_or("")
        .to_string()
}

/// A positional writevSync must not move the fd cursor: after
/// `writevSync(fd, [ABCD], 0)` the cursor is still 0, so a plain `writeSync`
/// overwrites from the start ("XYCD"). The lseek+writev bug left the cursor
/// at 4, producing "ABCDXY". (Node oracle: "XYCD".)
#[tokio::test]
async fn vectored_positional_writev_does_not_move_cursor() {
    let js = r#"(function(){
      var fs = require('fs'); var os = require('os'); var path = require('path');
      var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-writev-'));
      var file = path.join(dir, 'f');
      var fd = fs.openSync(file, 'w');
      var written = fs.writevSync(fd, [Buffer.from('ABCD')], 0);
      fs.writeSync(fd, 'XY');
      fs.closeSync(fd);
      var out = fs.readFileSync(file, 'utf8');
      fs.rmSync(dir, { recursive: true, force: true });
      return JSON.stringify({ written: written, content: out });
    })()"#;
    assert_eq!(eval(js).await, r#"{"written":4,"content":"XYCD"}"#);
}

/// A positional readvSync must not move the fd cursor: reading 2 bytes
/// sequentially, then 4 bytes positionally at 0, then 2 more sequentially
/// must yield "AB", "ABCD", "CD". The lseek+readv bug made the final read
/// return "EF". (Node oracle: {"first":"AB","n":4,"vec":"ABCD","next":"CD"}.)
#[tokio::test]
async fn vectored_positional_readv_does_not_move_cursor() {
    let js = r#"(function(){
      var fs = require('fs'); var os = require('os'); var path = require('path');
      var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-readv-'));
      var file = path.join(dir, 'f');
      fs.writeFileSync(file, 'ABCDEF');
      var fd = fs.openSync(file, 'r');
      var first = Buffer.alloc(2); fs.readSync(fd, first, 0, 2, null);
      var vec = Buffer.alloc(4);
      var n = fs.readvSync(fd, [vec], 0);
      var next = Buffer.alloc(2); fs.readSync(fd, next, 0, 2, null);
      fs.closeSync(fd);
      fs.rmSync(dir, { recursive: true, force: true });
      return JSON.stringify({ first: first.toString(), n: n, vec: vec.toString(), next: next.toString() });
    })()"#;
    assert_eq!(
        eval(js).await,
        r#"{"first":"AB","n":4,"vec":"ABCD","next":"CD"}"#
    );
}

/// readvSync/writevSync at a nonzero numeric position must actually read
/// from / write at that offset (preadv/pwritev honor the offset argument).
#[tokio::test]
async fn vectored_io_honors_nonzero_position() {
    let js = r#"(function(){
      var fs = require('fs'); var os = require('os'); var path = require('path');
      var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-vecpos-'));
      var file = path.join(dir, 'f');
      fs.writeFileSync(file, 'ABCDEF');
      var fd = fs.openSync(file, 'r+');
      var buf = Buffer.alloc(2);
      var n = fs.readvSync(fd, [buf], 3);
      fs.writevSync(fd, [Buffer.from('zz')], 1);
      fs.closeSync(fd);
      var out = fs.readFileSync(file, 'utf8');
      fs.rmSync(dir, { recursive: true, force: true });
      return JSON.stringify({ n: n, read: buf.toString(), content: out });
    })()"#;
    assert_eq!(eval(js).await, r#"{"n":2,"read":"DE","content":"AzzDEF"}"#);
}

/// Vectored reads/writes without a position keep sequential semantics: the
/// cursor advances by the bytes transferred, matching Node.
#[tokio::test]
async fn unpositioned_vectored_io_advances_cursor() {
    let js = r#"(function(){
      var fs = require('fs'); var os = require('os'); var path = require('path');
      var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ibex-vecseq-'));
      var file = path.join(dir, 'f');
      fs.writeFileSync(file, 'ABCDEF');
      var fd = fs.openSync(file, 'r');
      var a = Buffer.alloc(2); var b = Buffer.alloc(2);
      fs.readvSync(fd, [a]);
      fs.readvSync(fd, [b]);
      fs.closeSync(fd);
      fs.rmSync(dir, { recursive: true, force: true });
      return JSON.stringify({ a: a.toString(), b: b.toString() });
    })()"#;
    assert_eq!(eval(js).await, r#"{"a":"AB","b":"CD"}"#);
}
