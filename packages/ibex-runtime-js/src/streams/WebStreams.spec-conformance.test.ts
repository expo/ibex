// ENG-23472 — WHATWG Streams spec-conformance fixes, oracle-checked against
// real Node (v25): cancel() on errored/locked ReadableStreams, tee() cancel
// composition, ReadableStream.from(syncIterable) forwarding return(),
// WritableStream erroring on a throwing/invalid size(), writer.ready resolving
// when close() is requested under backpressure, controller.error() waiting for
// the in-flight sink.write to settle, byobRequest.respond(0) while readable,
// and the TransformStream readable side defaulting to highWaterMark 0.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { ReadableStream, CountQueuingStrategy } from './ReadableStream.ts';
import { WritableStream } from './WritableStream.ts';
import { TransformStream } from './TransformStream.ts';

const tick = () => new Promise((r) => setTimeout(r, 0));

// ---------------------------------------------------------------------------
// 1. ReadableStream.cancel() on errored / locked streams
// ---------------------------------------------------------------------------

test('cancel() on an errored stream rejects with the stored error', async () => {
  const boom = new Error('boom');
  const rs = new ReadableStream({ start(c) { c.error(boom); } });
  expect(await rs.cancel().then(() => 'resolved', (e) => e)).toBe(boom);
});

test('reader.cancel() on an errored stream rejects with the stored error', async () => {
  const boom = new Error('boom');
  const rs = new ReadableStream({ start(c) { c.error(boom); } });
  const reader = rs.getReader();
  expect(await reader.cancel().then(() => 'resolved', (e) => e)).toBe(boom);
});

test('cancel() on a locked stream returns a rejected promise, not a sync throw', async () => {
  const rs = new ReadableStream();
  rs.getReader();
  let p!: Promise<void>;
  expect(() => { p = rs.cancel(); }).not.toThrow();
  expect(await p.then(() => 'resolved', (e) => e.constructor.name)).toBe('TypeError');
});

test('cancel() on a closed stream still resolves', async () => {
  const rs = new ReadableStream({ start(c) { c.close(); } });
  expect(await rs.cancel().then(() => 'resolved', () => 'rejected')).toBe('resolved');
});

// ---------------------------------------------------------------------------
// 2. tee() cancel composition
// ---------------------------------------------------------------------------

test('tee(): both branch cancels reject when the source cancel rejects, with composite reason', async () => {
  const sourceError = new Error('x');
  let sourceReason: any;
  const rs = new ReadableStream({
    cancel(reason: any) {
      sourceReason = reason;
      // Pre-handle: the stream only attaches internal (tracker-invisible)
      // handlers to this promise, which the userland rejection-tracking
      // polyfill would otherwise report as an unhandled rejection when
      // another test file in the same process has installed it.
      const p = Promise.reject(sourceError);
      p.catch(() => {});
      return p;
    },
  });
  const [a, b] = rs.tee();
  const pa = a.cancel('ra').then(() => 'resolved', (e: any) => e);
  const pb = b.cancel('rb').then(() => 'resolved', (e: any) => e);
  expect(await pa).toBe(sourceError);
  expect(await pb).toBe(sourceError);
  expect(sourceReason).toEqual(['ra', 'rb']);
});

test('tee(): first branch cancel stays pending until the second branch cancels', async () => {
  let sourceReason: any = 'not-called';
  const rs = new ReadableStream({ cancel(reason: any) { sourceReason = reason; } });
  const [a, b] = rs.tee();
  const pa = a.cancel();
  const settled = await Promise.race([
    pa.then(() => 'settled', () => 'settled'),
    tick().then(() => 'pending'),
  ]);
  expect(settled).toBe('pending');
  expect(sourceReason).toBe('not-called');
  await b.cancel();
  await pa;
  expect(sourceReason).toEqual([undefined, undefined]);
});

test('tee() of a byte stream: composite reason keeps undefined slots', async () => {
  let sourceReason: any = 'not-called';
  const rs = new ReadableStream({
    type: 'bytes',
    cancel(reason: any) { sourceReason = reason; },
  } as any);
  const [a, b] = rs.tee();
  const pa = a.cancel('ra');
  await b.cancel();
  await pa;
  expect(sourceReason).toEqual(['ra', undefined]);
});

// ---------------------------------------------------------------------------
// 3. ReadableStream.from(syncIterable) forwards return() on cancel
// ---------------------------------------------------------------------------

test('from(sync generator): cancel calls return() so finally blocks run', async () => {
  let finallyRan = false;
  function* gen() {
    try {
      yield 1;
      yield 2;
    } finally {
      finallyRan = true;
    }
  }
  const rs = ReadableStream.from(gen());
  const reader = rs.getReader();
  expect((await reader.read()).value).toBe(1);
  await reader.cancel('done');
  expect(finallyRan).toBe(true);
});

test('from(sync iterable without return) cancels cleanly', async () => {
  const rs = ReadableStream.from([1, 2, 3]);
  const reader = rs.getReader();
  expect((await reader.read()).value).toBe(1);
  await reader.cancel();
});

// ---------------------------------------------------------------------------
// 4. WritableStream: throwing/invalid size() errors the whole stream
// ---------------------------------------------------------------------------

test('throwing size() errors the stream: ready and later writes reject', async () => {
  const sizeError = new Error('bad size');
  const ws = new WritableStream({}, { size() { throw sizeError; } });
  const writer = ws.getWriter();
  expect(await writer.write('x').then(() => 'resolved', (e: any) => e)).toBe(sizeError);
  expect(await writer.ready.then(() => 'resolved', (e: any) => e)).toBe(sizeError);
  expect(await writer.write('y').then(() => 'resolved', (e: any) => e)).toBe(sizeError);
});

test('invalid size() return errors the stream with a RangeError', async () => {
  const ws = new WritableStream({}, { size() { return -1; } });
  const writer = ws.getWriter();
  const writeErr = await writer.write('x').then(() => undefined, (e: any) => e);
  expect(writeErr).toBeInstanceOf(RangeError);
  const readyErr = await writer.ready.then(() => undefined, (e: any) => e);
  expect(readyErr).toBe(writeErr);
});

// ---------------------------------------------------------------------------
// 5. writer.ready resolves when close() is requested under backpressure
// ---------------------------------------------------------------------------

test('close() under permanent backpressure (HWM 0) resolves writer.ready', async () => {
  const ws = new WritableStream({}, new CountQueuingStrategy({ highWaterMark: 0 }));
  const writer = ws.getWriter();
  const closePromise = writer.close();
  const out = await Promise.race([
    writer.ready.then(() => 'resolved', () => 'rejected'),
    tick().then(() => 'timeout'),
  ]);
  expect(out).toBe('resolved');
  await closePromise;
});

// ---------------------------------------------------------------------------
// 6. controller.error() waits for the in-flight sink.write to settle
// ---------------------------------------------------------------------------

test('controller.error() mid-write: a fulfilling sink.write still resolves write()', async () => {
  const ctlError = new Error('ctl-err');
  let resolveWrite!: () => void;
  let ctl: any;
  const ws = new WritableStream({
    start(c: any) { ctl = c; },
    write() { return new Promise<void>((r) => { resolveWrite = r; }); },
  });
  const writer = ws.getWriter();
  const writePromise = writer.write('a');
  await tick();
  ctl.error(ctlError);
  await tick();
  // The write is still in flight; the stream must not have finished erroring.
  resolveWrite();
  expect(await writePromise.then(() => 'resolved', (e: any) => e)).toBe('resolved');
  expect(await writer.closed.then(() => 'resolved', (e: any) => e)).toBe(ctlError);
});

test('controller.error() mid-write: a rejecting sink.write rejects write() with its own error', async () => {
  let rejectWrite!: (e: any) => void;
  let ctl: any;
  const ws = new WritableStream({
    start(c: any) { ctl = c; },
    write() { return new Promise<void>((_, rj) => { rejectWrite = rj; }); },
  });
  const writer = ws.getWriter();
  const writePromise = writer.write('a');
  await tick();
  ctl.error(new Error('ctl-err'));
  await tick();
  const writeError = new Error('write-err');
  rejectWrite(writeError);
  expect(await writePromise.then(() => 'resolved', (e: any) => e)).toBe(writeError);
});

test('transformer calling controller.error() during transform() does not reject that write()', async () => {
  const tErr = new Error('t-err');
  const ts = new TransformStream({
    transform(_chunk: any, controller: any) {
      controller.error(tErr);
      return Promise.resolve();
    },
  });
  const writer = ts.writable.getWriter();
  const reader = ts.readable.getReader();
  const readPromise = reader.read().then(() => 'resolved', (e: any) => e);
  expect(await writer.write('a').then(() => 'resolved', (e: any) => e)).toBe('resolved');
  expect(await readPromise).toBe(tErr);
});

// ---------------------------------------------------------------------------
// 7. byobRequest.respond(0) while readable throws TypeError
// ---------------------------------------------------------------------------

test('respond(0) while the stream is readable throws TypeError', async () => {
  let ctl: any;
  const rs = new ReadableStream({ type: 'bytes', start(c: any) { ctl = c; } } as any);
  const reader = rs.getReader({ mode: 'byob' });
  const readPromise = reader.read(new Uint8Array(4));
  readPromise.catch(() => {});
  await tick();
  expect(() => ctl.byobRequest.respond(0)).toThrow(TypeError);
  // A valid respond still works afterwards.
  ctl.byobRequest.view.set([7], 0);
  ctl.byobRequest.respond(1);
  const result = await readPromise;
  expect(result.done).toBe(false);
  expect((result.value as Uint8Array)[0]).toBe(7);
});

test('respond(0) after close() with a pending BYOB read resolves the read as done', async () => {
  let ctl: any;
  const rs = new ReadableStream({ type: 'bytes', start(c: any) { ctl = c; } } as any);
  const reader = rs.getReader({ mode: 'byob' });
  const readPromise = reader.read(new Uint8Array(4));
  await tick();
  ctl.close();
  expect(() => ctl.byobRequest.respond(0)).not.toThrow();
  expect((await readPromise).done).toBe(true);
});

// ---------------------------------------------------------------------------
// 8. TransformStream readable side defaults to highWaterMark 0
// ---------------------------------------------------------------------------

test('readableStrategy without highWaterMark defaults the readable HWM to 0', () => {
  let desired: number | null | undefined;
  new TransformStream(
    { start(c: any) { desired = c.desiredSize; } },
    undefined,
    { size: () => 1 }
  );
  expect(desired).toBe(0);
});

test('no readableStrategy still defaults the readable HWM to 0', () => {
  let desired: number | null | undefined;
  new TransformStream({ start(c: any) { desired = c.desiredSize; } });
  expect(desired).toBe(0);
});

test('explicit readable highWaterMark is respected', () => {
  let desired: number | null | undefined;
  new TransformStream(
    { start(c: any) { desired = c.desiredSize; } },
    undefined,
    { highWaterMark: 2 }
  );
  expect(desired).toBe(2);
});
