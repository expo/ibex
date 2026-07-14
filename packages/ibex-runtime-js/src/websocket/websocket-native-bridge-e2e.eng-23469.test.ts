/**
 * End-to-end regression tests for the native WebSocket bridge (ENG-23469).
 *
 * Unlike the fake-bridge unit tests in this directory, this spawns the real
 * ibex binary on websocket-native-bridge-e2e.eng-23469.fixture.js, which
 * drives a live loopback connection (builtin-`ws` echo/command server plus a
 * global WebSocket client in one ibex process), so the platform native
 * (NSURLSession on macOS, libcurl on Linux, WinHTTP on Windows) and the JSI
 * bridge are actually exercised.
 *
 * Covered regressions:
 * - empty sends ('' / Uint8Array(0) / ArrayBuffer(0)) transmit real frames
 *   (the bridge dropped empty typed-array payloads; Linux/Windows natives
 *   dropped every zero-length payload),
 * - text frames with an embedded NUL arrive full-length (macOS used strlen),
 * - a 100KB text message arrives as ONE string message event (Linux
 *   surfaced each curl chunk as a separate, mis-typed message),
 * - server close code/reason surface in the CloseEvent (Linux reported
 *   1000/'' unconditionally),
 * - client close() fires the close event (Linux never invoked close_cb),
 * - failed handshakes deliver error followed by close instead of consuming
 *   the terminal close while deduplicating native callbacks.
 *
 * Skips when the ibex binary has not been built (matches the repo's
 * hermes-gated test convention); build with `cargo build` or point IBEX_BIN
 * at a binary.
 *
 * Run with: bun test packages/ibex-runtime-js/src/websocket
 */
import { expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import * as path from 'node:path';

const repoRoot = path.resolve(import.meta.dir, '../../../..');
const ibexBin = process.env.IBEX_BIN
  ? path.resolve(process.env.IBEX_BIN)
  : path.join(repoRoot, 'target', 'debug', 'ibex');
const haveIbex = existsSync(ibexBin);
const fixturePath = path.join(
  import.meta.dir,
  'websocket-native-bridge-e2e.eng-23469.fixture.js'
);

test.skipIf(!haveIbex)(
  'native WebSocket bridge: frames, messages, close and failure semantics (live loopback)',
  async () => {
    // This fixture intentionally exercises a live package and loopback socket
    // without producing a durable policy. Run it in the explicitly diagnostic
    // foreground audit posture; production defaults remain fail-closed.
    const proc = Bun.spawn([ibexBin, 'capsec', 'audit', fixturePath], {
      cwd: repoRoot,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const killTimer = setTimeout(() => proc.kill(), 45000);
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    clearTimeout(killTimer);
    const detail = `exit=${exitCode}\nstdout:\n${stdout}\nstderr:\n${stderr}`;
    expect(stdout, detail).toContain('RESULT: PASS');
    expect(stdout, detail).not.toContain('FAIL ');
    expect(exitCode, detail).toBe(0);
  },
  60000
);
