// ENG-23482 — regression coverage for stream.js Node-contract gaps
// (src/builtins/stream.js): Transform cb(null,null) prematurely ending the
// readable side, destroy-error handling (silent swallow without an 'error'
// listener, inverted ERR_STREAM_DESTROYED preference in _flushWriteQueue),
// resume/push/unshift/from/finished/toWeb/fromWeb contract gaps, and pipe
// backpressure clobbering a destination's own `size` property.
//
// Oracle values captured from REAL Node v25.9.0 (scratchpad oracle run,
// 2026-07-07) for every scenario below.
//
import { test, expect } from 'bun:test';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Readable, Writable, Transform, finished } = require('../../../src/builtins/stream.js');

const tick = (ms = 10) => new Promise<void>((r) => setTimeout(r, ms));

// #1 — Transform cb(null, null) must be a no-op skip, not EOF.
test('Transform callback(null, null) skips the chunk without ending the readable side', async () => {
  const t = new Transform({
    transform(_c: unknown, _e: string, cb: (err?: Error | null, data?: unknown) => void) {
      cb(null, null);
    },
  });
  let ended = false;
  const chunks: unknown[] = [];
  t.on('end', () => { ended = true; });
  t.on('data', (c: unknown) => chunks.push(c));
  t.write('a');
  t.write('b');
  await tick(30);
  expect(ended).toBe(false); // was true after the first chunk (push(null) EOF)
  expect(chunks.length).toBe(0);
  t.end();
  await tick(30);
  expect(ended).toBe(true); // stream still ends normally on end()
});

test('Transform callback(null, chunk) still forwards chunks', async () => {
  const t = new Transform({
    transform(c: Buffer, _e: string, cb: (err?: Error | null, data?: unknown) => void) {
      cb(null, c.toString().toUpperCase());
    },
  });
  const chunks: string[] = [];
  t.on('data', (c: Buffer) => chunks.push(c.toString()));
  t.write('a');
  t.write('b');
  t.end();
  await tick(30);
  expect(chunks).toEqual(['A', 'B']);
});

// #3 — destroy(err) with no 'error' listener must not be swallowed: the
// unhandled 'error' routes through process 'uncaughtException' (Node crashes
// the process; under this harness the registered handler observes it).
test('destroy(err) with no error listener surfaces via uncaughtException instead of silence', async () => {
  let caught: Error | null = null;
  const handler = (e: Error) => { caught = e; };
  process.on('uncaughtException', handler);
  try {
    const r = new Readable({ read() {} });
    r.destroy(new Error('boom-eng23482'));
    await tick(30);
  } finally {
    process.removeListener('uncaughtException', handler);
  }
  expect(caught && (caught as Error).message).toBe('boom-eng23482');
});

test('destroy(err) with an error listener emits to it (no uncaughtException)', async () => {
  let caught: Error | null = null;
  let emitted: Error | null = null;
  const handler = (e: Error) => { caught = e; };
  process.on('uncaughtException', handler);
  try {
    const r = new Readable({ read() {} });
    r.on('error', (e: Error) => { emitted = e; });
    r.destroy(new Error('boom'));
    await tick(30);
  } finally {
    process.removeListener('uncaughtException', handler);
  }
  expect(emitted && (emitted as Error).message).toBe('boom');
  expect(caught).toBe(null);
});

// #4 — a write queued behind an in-flight write at destroy(err) time must get
// the explicit destroy error, not a synthetic ERR_STREAM_DESTROYED.
test('queued write callback receives the explicit destroy error after the in-flight write completes', async () => {
  const pending: Array<(err?: Error) => void> = [];
  const w = new Writable({
    highWaterMark: 4,
    write(_c: Buffer, _e: string, cb: (err?: Error) => void) { pending.push(cb); },
  });
  w.on('error', () => {});
  let cbB: string = 'never';
  w.write(Buffer.from('aaaa'), () => {});
  w.write(Buffer.from('bbbb'), (e: any) => { cbB = e ? `${e.code || 'nocode'}:${e.message}` : 'null'; });
  w.destroy(new Error('boom'));
  pending[0](); // complete the in-flight write successfully
  await tick(30);
  expect(cbB).toBe('nocode:boom'); // was ERR_STREAM_DESTROYED:...
});

// #5 — 'resume' fires on the first transition from the initial (null) state.
test("resume() from the initial flowing=null state emits 'resume'", async () => {
  const r = new Readable({ read() {} });
  let resumed = 0;
  r.on('resume', () => resumed++);
  r.resume();
  await tick(30);
  expect(resumed).toBe(1);
});

// #6 — non-objectMode push of a non-string/Buffer/Uint8Array raises
// ERR_INVALID_ARG_TYPE via errorOrDestroy (Node: ret false, destroyed).
test('push(42) in non-objectMode errors the stream with ERR_INVALID_ARG_TYPE', async () => {
  const r = new Readable({ read() {} });
  let errCode: string | null = null;
  r.on('error', (e: any) => { errCode = e.code; });
  const ret = r.push(42);
  await tick(30);
  expect(ret).toBe(false);
  expect(errCode).toBe('ERR_INVALID_ARG_TYPE');
  expect(r.destroyed).toBe(true);
});

test('push accepts string/Buffer/Uint8Array in non-objectMode and anything in objectMode', async () => {
  const r = new Readable({ read() {} });
  r.on('error', () => { throw new Error('unexpected error'); });
  expect(() => r.push('str')).not.toThrow();
  expect(() => r.push(Buffer.from('b'))).not.toThrow();
  expect(() => r.push(new Uint8Array([1]))).not.toThrow();
  const o = new Readable({ objectMode: true, read() {} });
  o.on('error', () => { throw new Error('unexpected error'); });
  expect(() => o.push(42)).not.toThrow();
  expect(() => o.push({ a: 1 })).not.toThrow();
  await tick(5);
});

// #7 — unshift after 'end' has been emitted raises
// ERR_STREAM_UNSHIFT_AFTER_END_EVENT instead of silently buffering.
test("unshift() after 'end' raises ERR_STREAM_UNSHIFT_AFTER_END_EVENT", async () => {
  const r = new Readable({ read() {} });
  let errCode: string | null = null;
  r.on('error', (e: any) => { errCode = e.code; });
  r.push('x');
  r.push(null);
  let unshiftRet: unknown = 'not-called';
  r.on('end', () => {
    unshiftRet = r.unshift(Buffer.from('y'));
  });
  r.resume();
  await tick(50);
  expect(unshiftRet).toBe(false);
  expect(errCode).toBe('ERR_STREAM_UNSHIFT_AFTER_END_EVENT');
});

test('unshift() between push(null) and the end event stays legal', async () => {
  const r = new Readable({ read() {} });
  r.on('error', (e: Error) => { throw e; });
  r.push('b');
  r.push(null);
  const first = r.read();
  expect(first.toString()).toBe('b');
  r.unshift(Buffer.from('a')); // put back before 'end' has emitted
  expect(r.read().toString()).toBe('a');
  await tick(20);
});

// #8 — Readable.from(asyncIterable) must not start the generator until the
// first read.
test('Readable.from(asyncGenerator) is lazy: generator body runs only on first read', async () => {
  let started = false;
  async function* g() {
    started = true;
    yield 1;
    yield 2;
  }
  const r = Readable.from(g());
  await tick(30);
  expect(started).toBe(false); // was true: pumped eagerly at from() time
  const got: number[] = [];
  r.on('data', (v: number) => got.push(v));
  await tick(30);
  expect(started).toBe(true);
  expect(got).toEqual([1, 2]);
});

// #9 — finished() defers its callback even for already-settled streams.
test('finished() on an already-finished stream invokes the callback asynchronously', async () => {
  const w = new Writable({ write(_c: unknown, _e: string, cb: () => void) { cb(); } });
  w.end();
  await tick(30);
  let sync = true;
  const settled = new Promise<boolean>((resolve) => {
    finished(w, () => resolve(sync));
  });
  sync = false;
  expect(await settled).toBe(false); // Node: always deferred via nextTick
});

test('finished() on an already-destroyed (premature) stream defers ERR_STREAM_PREMATURE_CLOSE', async () => {
  const w = new Writable({ write(_c: unknown, _e: string, cb: () => void) { cb(); } });
  w.destroy();
  await tick(30);
  let sync = true;
  const settled = new Promise<{ sync: boolean; code: string | undefined }>((resolve) => {
    finished(w, (err: any) => resolve({ sync, code: err && err.code }));
  });
  sync = false;
  const out = await settled;
  expect(out.sync).toBe(false);
  expect(out.code).toBe('ERR_STREAM_PREMATURE_CLOSE');
});

test('finished() on an already-errored stream defers the error delivery', async () => {
  const w = new Writable({ write(_c: unknown, _e: string, cb: () => void) { cb(); } });
  w.on('error', () => {});
  w.destroy(new Error('boom'));
  await tick(30);
  let sync = true;
  const settled = new Promise<{ sync: boolean; msg: string | undefined }>((resolve) => {
    finished(w, (err: any) => resolve({ sync, msg: err && err.message }));
  });
  sync = false;
  const out = await settled;
  expect(out.sync).toBe(false);
  expect(out.msg).toBe('boom');
});

// #10 — a _write/_transform callback invoked twice raises ERR_MULTIPLE_CALLBACK.
test('write callback called twice raises ERR_MULTIPLE_CALLBACK', async () => {
  const w = new Writable({
    write(_c: unknown, _e: string, cb: () => void) { cb(); cb(); },
  });
  let errCode: string | null = null;
  w.on('error', (e: any) => { errCode = e.code; });
  w.write('a');
  await tick(30);
  expect(errCode).toBe('ERR_MULTIPLE_CALLBACK');
  expect(w.destroyed).toBe(true);
});

test('transform callback called twice raises ERR_MULTIPLE_CALLBACK', async () => {
  const t = new Transform({
    transform(c: unknown, _e: string, cb: (err?: Error | null, data?: unknown) => void) {
      cb(null, c);
      cb(null, c);
    },
  });
  let errCode: string | null = null;
  t.on('error', (e: any) => { errCode = e.code; });
  t.resume();
  t.write('a');
  await tick(30);
  expect(errCode).toBe('ERR_MULTIPLE_CALLBACK');
});

// #11 — emitClose: false suppresses only the event; closed still flips.
test('closed becomes true after destroy with emitClose:false (writable and readable)', async () => {
  const w = new Writable({ emitClose: false, write(_c: unknown, _e: string, cb: () => void) { cb(); } });
  let wClose = false;
  w.on('close', () => { wClose = true; });
  w.destroy();
  const r = new Readable({ emitClose: false, read() {} });
  let rClose = false;
  r.on('close', () => { rClose = true; });
  r.destroy();
  await tick(30);
  expect(w.closed).toBe(true); // was false forever
  expect(wClose).toBe(false); // event still suppressed
  expect(r.closed).toBe(true);
  expect(rClose).toBe(false);
});

// #12 — fromWeb is pull-based (no eager unbounded buffering) and cancels the
// web reader on destroy; toWeb respects desiredSize.
test('Readable.fromWeb does not pump without demand and cancels the reader on destroy', async () => {
  let pulls = 0;
  let cancelled: string | null = null;
  const ws = new ReadableStream({
    pull(c) { pulls++; c.enqueue(new Uint8Array([pulls])); },
    cancel(reason) { cancelled = String(reason); },
  }, { highWaterMark: 0 });
  const r = Readable.fromWeb(ws);
  r.on('error', () => {});
  await tick(30);
  const pullsBeforeRead = pulls;
  r.destroy(new Error('stop'));
  await tick(30);
  expect(pullsBeforeRead).toBe(0); // was: pumped the whole stream eagerly
  expect(cancelled).toContain('stop'); // was: source never cancelled
});

test('Readable.fromWeb delivers data on demand and ends', async () => {
  const ws = new ReadableStream({
    start(c) {
      c.enqueue(new Uint8Array([1]));
      c.enqueue(new Uint8Array([2]));
      c.close();
    },
  });
  const r = Readable.fromWeb(ws);
  const got: number[] = [];
  let ended = false;
  r.on('data', (c: Uint8Array) => got.push(c[0]));
  r.on('end', () => { ended = true; });
  await tick(50);
  expect(got).toEqual([1, 2]);
  expect(ended).toBe(true);
});

test('Readable.toWeb applies backpressure instead of draining an unconsumed source unboundedly', async () => {
  let pushed = 0;
  const r = new Readable({
    highWaterMark: 16,
    read() {
      pushed++;
      this.push('x'.repeat(64));
    },
  });
  Readable.toWeb(r); // no consumer attached
  await tick(50);
  expect(pushed).toBeLessThan(8); // Node oracle: 2 pushes; eager version drains forever
});

test('Readable.toWeb still delivers all chunks to a consumer', async () => {
  const r = Readable.from(['a', 'b', 'c']);
  const ws = Readable.toWeb(r);
  const reader = ws.getReader();
  const out: string[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out.push(typeof value === 'string' ? value : Buffer.from(value).toString());
  }
  expect(out).toEqual(['a', 'b', 'c']);
});

// #13 — pipe backpressure bookkeeping must not clobber a destination's own
// `size` property.
test("pipe backpressure keeps the destination's own size property intact", async () => {
  const pending: Array<() => void> = [];
  const src = new Readable({ read() {} });
  const dest = new Writable({
    highWaterMark: 1,
    write(_c: unknown, _e: string, cb: () => void) { pending.push(cb); },
  });
  (dest as any).size = 5;
  src.pipe(dest);
  src.push('aaaa');
  src.push('bbbb');
  await tick(20);
  while (pending.length) pending.shift()!(); // drain
  await tick(30);
  expect((dest as any).size).toBe(5); // was: replaced by shim getter, then delete'd
  src.destroy();
  dest.destroy();
});
