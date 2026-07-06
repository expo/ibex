// ENG-23135 — regression coverage for stream.Writable stranding buffered write
// callbacks on error/destroy (src/builtins/stream.js).
//
// With an async _write, a write queued behind an in-flight write was stranded
// whenever the stream errored or was destroyed before the queue flushed:
// afterWrite's error path only called the failing write's own callback,
// _drainPendingEnd early-returned (queue non-empty), autoDestroy destroyed the
// stream, and nothing ever errored `_writeQueue` afterward (write() on a
// destroyed stream early-returns; _flushWriteQueue only runs from
// construct-resume/afterWrite-success/cleanup-success/uncork). The queued
// write's callback never fired — hanging promisified writes — and
// writableLength kept its bytes forever. Node guarantees every buffered write
// callback is invoked with the error (errorBuffer in
// internal/streams/writable.js) and its bytes released.
//
// Oracle values (cb errors + writableLength === 0) captured from REAL Node
// v25.9.0 with `node -e ...` for each scenario below.
//
// Like stream-eng23041-writable-length.test.ts, these tests capture each
// _write's completion callback instead of auto-resolving it, so error timing
// is driven deterministically.
//
import { test, expect } from 'bun:test';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Writable } = require('../../../src/builtins/stream.js');

const tick = () => new Promise<void>((r) => setTimeout(r, 10));

test('a write queued behind an erroring in-flight write gets its callback errored and its bytes released', async () => {
  const pending: Array<(err?: Error) => void> = [];
  const w = new Writable({
    highWaterMark: 4,
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) {
      pending.push(cb);
    },
  });
  w.on('error', () => {});

  let cbA: any = 'never';
  let cbB: any = 'never';
  w.write(Buffer.from('aaaa'), (e: any) => { cbA = e ? e.message : 'null'; });
  w.write(Buffer.from('bbbb'), (e: any) => { cbB = e ? e.message : 'null'; });
  expect(pending.length).toBe(1); // A in flight, B queued
  expect(w.writableLength).toBe(8);

  pending[0](new Error('boom'));
  await tick();

  expect(cbA).toBe('boom');
  expect(cbB).toBe('boom'); // was 'never': stranded forever
  expect(w.writableLength).toBe(0); // was 4: phantom bytes
});

test('a promisified queued write settles (rejects) instead of hanging when the in-flight write errors', async () => {
  const pending: Array<(err?: Error) => void> = [];
  const w = new Writable({
    highWaterMark: 4,
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) {
      pending.push(cb);
    },
  });
  w.on('error', () => {});

  w.write(Buffer.from('aaaa'), () => {});
  const settled = new Promise<string>((resolve) => {
    w.write(Buffer.from('bbbb'), (e: any) => resolve(e ? 'rejected:' + e.message : 'ok'));
    pending[0](new Error('boom'));
    // Guard: fail fast (rather than the suite's full timeout) if still stranded.
    setTimeout(() => resolve('hung'), 250);
  });
  expect(await settled).toBe('rejected:boom');
});

test('destroy() with corked/buffered writes errors every buffered callback with ERR_STREAM_DESTROYED', async () => {
  const w = new Writable({
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) { cb(); },
  });
  w.on('error', () => {});

  let cbErr: any = 'never';
  w.cork();
  w.write(Buffer.from('aaaa'), (e: any) => { cbErr = e ? e.code || e.message : 'null'; });
  expect(w.writableLength).toBe(4);
  w.destroy();
  await tick();

  expect(cbErr).toBe('ERR_STREAM_DESTROYED'); // was 'never'
  expect(w.writableLength).toBe(0); // was 4
});

test('destroy(err) with buffered writes propagates the destroy error to buffered callbacks', async () => {
  const w = new Writable({
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) { cb(); },
  });
  w.on('error', () => {});

  let cbErr: any = 'never';
  w.cork();
  w.write(Buffer.from('aaaa'), (e: any) => { cbErr = e ? e.message : 'null'; });
  w.destroy(new Error('boom'));
  await tick();

  expect(cbErr).toBe('boom'); // Node: state.errored ?? ERR_STREAM_DESTROYED
  expect(w.writableLength).toBe(0);
});

test('batch flush error: unattempted batch items and writes queued during the flush are all errored, length fully released', async () => {
  const pending: Array<(err?: Error) => void> = [];
  const w = new Writable({
    highWaterMark: 4,
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) {
      pending.push(cb);
    },
  });
  w.on('error', () => {});

  const results: Record<string, any> = { a: 'never', b: 'never', c: 'never', d: 'never' };
  w.cork();
  w.write(Buffer.from('aaaa'), (e: any) => { results.a = e ? e.message : 'null'; });
  w.write(Buffer.from('bbbb'), (e: any) => { results.b = e ? e.message : 'null'; });
  w.write(Buffer.from('cccc'), (e: any) => { results.c = e ? e.message : 'null'; });
  w.uncork(); // batch [a,b,c] flushes via the runNext path (no _writev)
  // A write landing in the fresh _writeQueue while the batch is mid-flush:
  w.write(Buffer.from('dddd'), (e: any) => { results.d = e ? e.message : 'null'; });
  expect(w.writableLength).toBe(16);

  pending[0](); // a completes ok
  pending[1](new Error('boom')); // b errors mid-batch
  await tick();

  // Node oracle: a=null b=boom c=boom d=boom, writableLength=0.
  expect(results.a).toBe('null'); // completed before the error; NOT re-invoked
  expect(results.b).toBe('boom');
  expect(results.c).toBe('boom'); // unattempted batch item
  expect(results.d).toBe('boom'); // was 'never': stranded in the fresh queue
  expect(w.writableLength).toBe(0); // was 8: c (unattempted) + d (stranded)
});

test('successful writes are unaffected: callbacks fire once with null and length drains to 0', async () => {
  const pending: Array<(err?: Error) => void> = [];
  const w = new Writable({
    highWaterMark: 4,
    write(_chunk: Buffer, _enc: string, cb: (err?: Error) => void) {
      pending.push(cb);
    },
  });

  const calls: string[] = [];
  w.write(Buffer.from('aaaa'), (e: any) => calls.push('a:' + (e ? e.message : 'null')));
  w.write(Buffer.from('bbbb'), (e: any) => calls.push('b:' + (e ? e.message : 'null')));
  pending[0]();
  await tick();
  pending[1]();
  await tick();

  expect(calls).toEqual(['a:null', 'b:null']);
  expect(w.writableLength).toBe(0);
});
