// ENG-22973 — WritableStream.abort() rejected the in-flight write request and
// ran sink.abort() immediately, racing a still-executing sink.write(). Per
// WritableStreamAbort/FinishErroring the abort algorithm must wait for the
// in-flight write to settle, a write whose sink.write() succeeds must resolve,
// and a second concurrent abort() must return the first abort's promise.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { WritableStream } from './WritableStream.ts';

const flushMicrotasks = () => new Promise((r) => setTimeout(r, 0));

test('abort defers sink.abort until the in-flight write resolves', async () => {
  const events: string[] = [];
  let releaseWrite!: () => void;

  const sink = {
    write() {
      events.push('write-start');
      return new Promise<void>((resolve) => {
        releaseWrite = () => {
          events.push('write-end');
          resolve();
        };
      });
    },
    abort() {
      events.push('abort');
    },
  };

  const ws = new WritableStream(sink, { highWaterMark: 4 });
  const writer = ws.getWriter();
  await flushMicrotasks(); // let start() settle

  const writePromise = writer.write('a');
  await flushMicrotasks();
  expect(events).toEqual(['write-start']); // sink.write is in flight

  const abortPromise = writer.abort('boom');
  // A concurrent abort returns the SAME pending promise (not undefined).
  const abortPromise2 = writer.abort('again');
  expect(abortPromise2).toBe(abortPromise);

  // sink.abort must NOT run while the write is still in flight.
  await flushMicrotasks();
  expect(events).toEqual(['write-start']);

  // Let the slow write flush successfully.
  releaseWrite();

  // The write resolves — its bytes were written — rather than rejecting.
  await expect(writePromise).resolves.toBeUndefined();
  await expect(abortPromise).resolves.toBeUndefined();

  // sink.abort ran only after the write finished.
  expect(events).toEqual(['write-start', 'write-end', 'abort']);
});

test('abort with no in-flight write runs sink.abort and rejects closed', async () => {
  const events: string[] = [];
  const sink = {
    abort(reason: any) {
      events.push('abort:' + reason);
    },
  };
  const ws = new WritableStream(sink);
  const writer = ws.getWriter();
  await flushMicrotasks();

  const closed = writer.closed;
  await expect(writer.abort('bye')).resolves.toBeUndefined();
  expect(events).toEqual(['abort:bye']);
  await expect(closed).rejects.toBe('bye');
});

test('abort on a closed stream resolves without error', async () => {
  const ws = new WritableStream({});
  const writer = ws.getWriter();
  await flushMicrotasks();
  await writer.close();
  await expect(writer.abort('late')).resolves.toBeUndefined();
});
