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
import { test, expect } from 'bun:test';

const realStdout = process.stdout;
const realStderr = process.stderr;
const realStdoutProto = Object.getPrototypeOf(realStdout);
const realStderrProto = Object.getPrototypeOf(realStderr);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Writable } = require('../../../src/builtins/stream.js');

test('requiring the stream builtin does not corrupt Bun real stdio streams', () => {
  expect(process.stdout).toBe(realStdout);
  expect(process.stderr).toBe(realStderr);
  expect(Object.getPrototypeOf(process.stdout)).toBe(realStdoutProto);
  expect(Object.getPrototypeOf(process.stderr)).toBe(realStderrProto);
  expect(Object.getPrototypeOf(process.stdout)).not.toBe(Writable.prototype);
  expect(Object.getPrototypeOf(process.stderr)).not.toBe(Writable.prototype);
  process.stdout.write('');
  process.stderr.write('');
});

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
