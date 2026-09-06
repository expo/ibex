// Regression coverage for the embedded HTTP request-body lifecycle. The host
// adapter may expose an EOF read one job before reader.closed settles; releasing
// in that interval produces a spurious "Reader was released" rejection.
// Run with: bun test src/fetch/body-reader-release.test.ts

import { describe, expect, test } from 'bun:test';

import {
  normalizeReadableStreamBody,
  readableStreamToUint8Array,
} from './body.ts';

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function createDelayedClosedReader() {
  let closedSettled = false;
  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = () => {
      closedSettled = true;
      resolve();
    };
  });
  const lifecycleRejections: Error[] = [];
  let releaseCount = 0;

  const reader = {
    closed,
    read() {
      return Promise.resolve({ done: true, value: undefined });
    },
    cancel() {
      resolveClosed();
      return Promise.resolve();
    },
    releaseLock() {
      releaseCount += 1;
      if (!closedSettled) {
        // Model the embedded reader's internal closed-promise rejection. The
        // real runtime reports this through its unhandled-rejection hook.
        lifecycleRejections.push(new TypeError('Reader was released'));
      }
    },
  };

  return {
    stream: { getReader: () => reader } as unknown as ReadableStream<Uint8Array>,
    resolveClosed,
    lifecycleRejections,
    releaseCount: () => releaseCount,
  };
}

describe('body reader release ordering', () => {
  test('buffering delayed EOF waits for reader.closed before releasing', async () => {
    const source = createDelayedClosedReader();

    expect(await readableStreamToUint8Array(source.stream)).toEqual(new Uint8Array(0));
    expect(source.releaseCount()).toBe(0);
    expect(source.lifecycleRejections).toEqual([]);

    source.resolveClosed();
    await tick();

    expect(source.releaseCount()).toBe(1);
    expect(source.lifecycleRejections).toEqual([]);
  });

  test('normalizing delayed EOF releases the source reader exactly once', async () => {
    const source = createDelayedClosedReader();
    const normalized = normalizeReadableStreamBody(source.stream);
    const reader = normalized.getReader();

    expect(await reader.read()).toEqual({ done: true, value: undefined });
    expect(source.releaseCount()).toBe(0);
    expect(source.lifecycleRejections).toEqual([]);

    source.resolveClosed();
    await tick();
    await tick();

    expect(source.releaseCount()).toBe(1);
    expect(source.lifecycleRejections).toEqual([]);
  });
});
