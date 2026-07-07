// ENG-22965 — regression coverage for correctness bugs in the process-management
// builtins (child-process kill() signal map, process.chdir path normalization,
// cluster.fork silent default). The builtins talk to native host functions
// (__exactSpawnKill, __exactSetCwd, ...) which we stub / bypass here so the
// pure-JS logic can be exercised. Node's os.constants.signals is used as the
// oracle for the Darwin signal numbers. Run with: bun test.
//
// Findings #2 (spawnSync/execSync maxBuffer enforced post-hoc, counted in UTF-16
// chars, child never killed) and #3 (binary stdio corrupted across the native
// string boundary) are intentionally NOT covered here: both are rooted in the
// native (Rust/C++) spawn bridge — the JS layer always hands native a 256MB
// maxBuffer and cannot kill/truncate mid-stream in a synchronous spawn, and
// non-UTF-8 bytes are already lost to UTF-8 decoding before JS receives them.
// They are tracked as separate native follow-ups.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import os from 'os';

const g = globalThis as Record<string, any>;
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Finding #1 — ChildProcess.kill mapped signal names via a Linux-numbered table
// on Darwin (SIGUSR1 -> 10 = SIGBUS, killing the child), was truncated to 15
// entries, and its reverse map misreported exit signals.
// ---------------------------------------------------------------------------
describe('child-process kill() signal mapping (ENG-22965 #1)', () => {
  const cp = require('../../../src/builtins/child-process.js');
  const signals = os.constants.signals as Record<string, number>;

  function makeChild() {
    const child = Object.create(cp.ChildProcess.prototype);
    child._exited = false;
    child._handle = 7;
    child.killed = false;
    return child;
  }

  function captureKill(name?: string) {
    let sent: any = null;
    g.__exactSpawnKill = (_handle: number, sig: number) => { sent = sig; return true; };
    makeChild().kill(name as any);
    return sent;
  }

  test('kill(name) sends the Darwin number Node uses, for every os.constants signal', () => {
    for (const name of Object.keys(signals)) {
      let sent: any = null;
      g.__exactSpawnKill = (_h: number, sig: number) => { sent = sig; return true; };
      const child = makeChild();
      expect(() => child.kill(name)).not.toThrow();
      expect(sent).toBe(signals[name]);
    }
  });

  test('the previously-mismapped signals now use platform numbers (one Linux table was applied everywhere)', () => {
    // child-process.js selects its signal table by process.platform at load
    // time (ENG-23032), and this suite runs on both darwin and linux hosts
    // (CI Preflight is ubuntu — ENG-23319). The original ENG-22965 defect was
    // the Linux-numbered table applied on Darwin, so the regression bites in
    // the darwin branch (30/31/10, not 10/12/7); on linux the platform-correct
    // numbers coincide with the old table for USR1/USR2 and BUS is 7.
    const linux = process.platform === 'linux';
    expect(captureKill('SIGUSR1')).toBe(linux ? 10 : 30); // darwin 30; Linux-on-Darwin bug sent 10 (== Darwin SIGBUS)
    expect(captureKill('SIGUSR2')).toBe(linux ? 12 : 31);
    expect(captureKill('SIGBUS')).toBe(linux ? 7 : 10);
  });

  test('signals beyond the old 15-entry map are accepted, not ERR_UNKNOWN_SIGNAL', () => {
    for (const name of ['SIGCHLD', 'SIGCONT', 'SIGSTOP', 'SIGWINCH']) {
      let sent: any = null;
      g.__exactSpawnKill = (_h: number, sig: number) => { sent = sig; return true; };
      const child = makeChild();
      expect(() => child.kill(name)).not.toThrow();
      expect(sent).toBe(signals[name]);
    }
  });

  test('kill() default is SIGTERM (15); kill(0) sends 0; unknown signal throws', () => {
    expect(captureKill()).toBe(15);
    expect(captureKill(0 as any)).toBe(0);
    let err: any;
    try { makeChild().kill('SIGNOTREAL' as any); } catch (e) { err = e; }
    expect(err && err.code).toBe('ERR_UNKNOWN_SIGNAL');
  });
});

// ---------------------------------------------------------------------------
// Finding #4 — process.chdir string-concatenated cwd + '/' + path without
// collapsing '.' / '..', so chdir('..') from /data/app returned /data/app/..
// ---------------------------------------------------------------------------
describe('process.chdir path normalization (ENG-22965 #4)', () => {
  test('collapses ., .. and duplicate slashes for absolute and relative chdir', () => {
    // Swap globalThis.process for an inheriting stub so requiring process.js
    // (which mutates globalThis.process) can't corrupt Bun's real process.
    const realProcess = g.process;
    const stub: any = Object.create(realProcess);
    g.process = stub;
    try {
      const proc = require('../../../src/builtins/process.js');

      // absolute inputs get normalized
      proc.chdir('/data/app');
      expect(proc.cwd()).toBe('/data/app');
      proc.chdir('/data/app/../lib');
      expect(proc.cwd()).toBe('/data/lib');
      proc.chdir('/a/b/c/../../d');
      expect(proc.cwd()).toBe('/a/d');
      proc.chdir('/foo/./bar//baz');
      expect(proc.cwd()).toBe('/foo/bar/baz');
      proc.chdir('/x/../../y'); // over-pop past root stays at root
      expect(proc.cwd()).toBe('/y');

      // relative inputs resolve against the current (builtin) cwd, then collapse
      proc.chdir('/start/here');
      expect(proc.cwd()).toBe('/start/here');
      proc.chdir('sub');
      expect(proc.cwd()).toBe('/start/here/sub');
      proc.chdir('..'); // the core bug: must be /start/here, not /start/here/sub/..
      expect(proc.cwd()).toBe('/start/here');
      proc.chdir('../sibling');
      expect(proc.cwd()).toBe('/start/sibling');
    } finally {
      g.process = realProcess;
    }
  });
});

// ---------------------------------------------------------------------------
// Finding #5 — cluster.fork hardcoded silent:true, ignoring cluster.settings
// and Node's silent:false default, so worker output never reached the parent.
// ---------------------------------------------------------------------------
describe('cluster.fork silent default (ENG-22965 #5)', () => {
  test('silent defaults to false and honors cluster.settings.silent', () => {
    // cluster.js does require('child_process') (Bun builtin). Patch its .fork on
    // the shared cached instance to capture options without spawning.
    const cpMod: any = require('child_process');
    const origFork = cpMod.fork;
    let forkOpts: any = null;
    const fakeChild = { on() {}, once() {}, unref() {}, connected: false };
    cpMod.fork = (_exec: any, _args: any, options: any) => { forkOpts = options; return fakeChild; };
    try {
      const cluster = require('../../../src/builtins/cluster.js');

      cluster.settings = {}; // Node default: silent false
      cluster.fork();
      expect(forkOpts.silent).toBe(false);

      cluster.settings = { silent: true };
      cluster.fork();
      expect(forkOpts.silent).toBe(true);

      cluster.settings = { silent: false };
      cluster.fork();
      expect(forkOpts.silent).toBe(false);
    } finally {
      cpMod.fork = origFork;
    }
  });
});
