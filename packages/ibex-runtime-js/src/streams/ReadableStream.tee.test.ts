// ENG-23040 #3 — a default (non-byte) ReadableStream's tee() cloned branch 2's
// chunk via structuredClone instead of aliasing the same reference. Per the
// WHATWG spec (ReadableStreamDefaultTee), both branches of a *default* tee
// observe the same chunk reference — cloning is only spec'd for byte-stream
// tee. The bug broke chunk identity for non-primitive values and added an
// O(n) copy per chunk. Run with: bun test.

import { expect, test, describe } from 'bun:test';
import { ReadableStream } from './ReadableStream.ts';

function streamOf<T>(items: T[]): ReadableStream<T> {
  return new ReadableStream<T>({
    start(controller) {
      for (const item of items) {
        controller.enqueue(item);
      }
      controller.close();
    },
  });
}

describe('ReadableStream.tee() (default, non-byte stream)', () => {
  test('both branches observe the exact same chunk reference for object values', async () => {
    const [a, b] = streamOf([{ n: 1 }]).tee();
    const va = (await a.getReader().read()).value;
    const vb = (await b.getReader().read()).value;

    // Chrome/Node: va === vb, and mutating one is visible on the other —
    // default tee does not clone.
    expect(va).toBe(vb);
    (va as { n: number }).n = 42;
    expect((vb as { n: number }).n).toBe(42);
  });

  test('both branches observe the exact same typed-array reference', async () => {
    const chunk = new Uint8Array([1, 2, 3]);
    const [a, b] = streamOf([chunk]).tee();
    const va = (await a.getReader().read()).value;
    const vb = (await b.getReader().read()).value;

    expect(va).toBe(chunk);
    expect(vb).toBe(chunk);
  });

  test('primitive values are still delivered correctly to both branches', async () => {
    const [a, b] = streamOf([1, 2, 3]).tee();
    const readAll = async (s: ReadableStream<number>) => {
      const out: number[] = [];
      const reader = s.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        out.push(value);
      }
      return out;
    };
    expect(await readAll(a)).toEqual([1, 2, 3]);
    expect(await readAll(b)).toEqual([1, 2, 3]);
  });
});
