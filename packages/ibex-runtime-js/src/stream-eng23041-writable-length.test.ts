// Regression test for ENG-23041 (src/builtins/stream.js):
//
// Writable's non-_writev flush path (`_flushWriteQueue`'s `runNext` fallback)
// decrements `writableLength` per item as each write's callback fires (so the
// batch total is already fully subtracted by the time the batch finishes).
// `cleanup()` used to *also* subtract the batch's `totalLen` unconditionally,
// double-subtracting `writableLength` for that path (the `_writev` path has no
// per-item decrement, so cleanup()'s subtraction is correct only there).
// Clamped-to-0, this self-heals when the batch is the only outstanding data,
// but under-reports when a write arrives concurrently during the flush: it
// lands in a fresh `_writeQueue` (bumping `writableLength`) while the
// in-flight batch is still draining, and the erroneous double-subtraction can
// make `maybeEmitDrain()` fire a premature 'drain' while that write is still
// genuinely buffered.
//
// Repro (from the ticket): cork(); write(a /*10B*/); write(b /*10B*/); with an
// async _write and no _writev; during the flush a concurrent write(c /*10B*/)
// arrives. Once a+b finish, real buffered = 10B (c), which (with
// highWaterMark=5) is still >= the watermark, so 'drain' must NOT fire yet.
//
// This drives write completion manually (capturing each _write's callback
// instead of auto-resolving it) so the exact moment batch [a,b]'s cleanup()
// runs -- but before c's own flush completes -- is observed deterministically,
// with no timing races.
//
// NB: requiring src/builtins/stream.js runs its module-level
// _patchProcessWritableStdio(), which replaces the prototype of the live
// process.stdout/stderr with this module's own Writable.prototype. Under bun
// (unlike the Hermes runtime this builtin targets), process.stdout/stderr are
// already fully-functional native streams, and that prototype swap corrupts
// their internal construct/destroy state, crashing later stdout/stderr writes
// (TypeError: stream._construct is not a function, from bun's real
// internal:streams/destroy). This is pre-existing (reproduces on an unmodified
// checkout) and unrelated to this fix; filed separately as ENG-23043. Swap in
// throwaway stand-ins for the duration of the require() so the patch lands on
// those instead of the real streams, then restore the originals via a plain
// data-property redefinition (bypassing the accessor the patch installs, so
// restoring does not re-trigger it on the real objects).
import { test, expect } from 'bun:test';

const realStdout = process.stdout;
const realStderr = process.stderr;
Object.defineProperty(process, 'stdout', { value: {}, writable: true, configurable: true, enumerable: true });
Object.defineProperty(process, 'stderr', { value: {}, writable: true, configurable: true, enumerable: true });
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Writable } = require('../../../src/builtins/stream.js');
Object.defineProperty(process, 'stdout', { value: realStdout, writable: true, configurable: true, enumerable: true });
Object.defineProperty(process, 'stderr', { value: realStderr, writable: true, configurable: true, enumerable: true });

test('a concurrent write during an async non-writev flush is not double-subtracted / does not fire a premature drain', () => {
  const pendingCallbacks: Array<(err?: Error) => void> = [];
  const writeCalls: Buffer[] = [];
  const w = new Writable({
    highWaterMark: 5,
    write(chunk: Buffer, _encoding: string, callback: (err?: Error) => void) {
      writeCalls.push(chunk);
      // Don't resolve yet -- the test drives completion order explicitly.
      pendingCallbacks.push(callback);
    },
  });
  let drainCount = 0;
  w.on('drain', () => drainCount++);

  w.cork();
  w.write(Buffer.alloc(10, 1)); // a
  w.write(Buffer.alloc(10, 2)); // b
  w.uncork(); // starts the flush of [a, b] (no _writev -> runNext path); a's _write is dispatched synchronously

  expect(writeCalls.length).toBe(1); // only a dispatched so far; runNext awaits its callback before dispatching b

  // A concurrent write arrives mid-flush (state.writing/bufferProcessing are
  // still true) and must land in a fresh _writeQueue.
  w.write(Buffer.alloc(10, 3)); // c
  expect(w.writableLength).toBe(30); // 20 in-flight (a+b) + 10 buffered (c)

  const aCb = pendingCallbacks.shift()!;
  aCb();
  expect(writeCalls.length).toBe(2); // b now dispatched
  expect(w.writableLength).toBe(20); // a's 10 subtracted; b(10) + c(10) still outstanding

  // Completing b finishes the batch: cleanup() runs synchronously and (bug-free)
  // must not double-subtract totalLen, and must not let maybeEmitDrain() fire
  // 'drain' while c (10B, >= the 5B high-water mark) is still buffered.
  const bCb = pendingCallbacks.shift()!;
  bCb();
  expect(writeCalls.length).toBe(3); // cleanup() synchronously kicked off c's own flush
  expect(w.writableLength).toBe(10); // exactly c's outstanding length -- not 0 (double-subtracted), not 20
  expect(drainCount).toBe(0); // must not have fired -- c is still buffered and >= highWaterMark

  // Finally complete c's write -- everything has now genuinely drained.
  const cCb = pendingCallbacks.shift()!;
  cCb();
  expect(w.writableLength).toBe(0);
  expect(drainCount).toBe(1);
  expect(pendingCallbacks.length).toBe(0);
});
