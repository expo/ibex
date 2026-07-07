// ENG-22977 — Blob must snapshot its parts at construction and never hand out
// its internal backing store. Previously convertToBytes stored live views over
// the caller's memory and #concatenateBytes returned this.#parts[0] directly,
// so (a) mutating a source array after construction changed the Blob and
// (b) mutating the array returned from bytes()/_getBytes() corrupted the
// "immutable" Blob.
//
// Run with: bun test.

import { expect, test } from 'bun:test';
import { Blob } from './Blob';
import { File } from './File';

test('mutating a source Uint8Array after construction does not change the Blob', async () => {
  const u = new Uint8Array([1, 2, 3]);
  const b = new Blob([u]);
  u[0] = 9;

  expect(Array.from(await b.bytes())).toEqual([1, 2, 3]);
  expect(await b.text()).toBe(String.fromCharCode(1, 2, 3));
});

test('a Blob snapshots only the viewed region of an offset view', async () => {
  const backing = new Uint8Array([0, 1, 2, 3, 4, 5]);
  const view = new Uint8Array(backing.buffer, 2, 3); // [2, 3, 4]
  const b = new Blob([view]);

  backing[2] = 99; // mutate the source region after construction

  expect(Array.from(await b.bytes())).toEqual([2, 3, 4]);
});

test('mutating a source ArrayBuffer after construction does not change the Blob', async () => {
  const ab = new Uint8Array([1, 2, 3]).buffer;
  const b = new Blob([ab]);
  new Uint8Array(ab)[0] = 9;

  expect(Array.from(await b.bytes())).toEqual([1, 2, 3]);
});

test('bytes() returns a fresh copy each call; mutating it cannot corrupt the Blob', async () => {
  const b = new Blob([new Uint8Array([1, 2, 3])]);

  const first = await b.bytes();
  first[0] = 0;

  const second = await b.bytes();
  expect(Array.from(second)).toEqual([1, 2, 3]);
  expect(first).not.toBe(second);
});

test('_getBytes() returns a fresh copy for single-part Blobs', () => {
  const b = new Blob([new Uint8Array([1, 2, 3])]);

  const a1 = (b as unknown as { _getBytes(): Uint8Array })._getBytes();
  a1[0] = 42;

  const a2 = (b as unknown as { _getBytes(): Uint8Array })._getBytes();
  expect(Array.from(a2)).toEqual([1, 2, 3]);
});

test('arrayBuffer() is independent of the source and of the Blob', async () => {
  const u = new Uint8Array([1, 2, 3]);
  const b = new Blob([u]);
  u[0] = 9;

  const ab = await b.arrayBuffer();
  expect(Array.from(new Uint8Array(ab))).toEqual([1, 2, 3]);
  new Uint8Array(ab)[0] = 0;
  expect(Array.from(await b.bytes())).toEqual([1, 2, 3]);
});

test('Blob-first import order leaves File constructible', async () => {
  const f = new File([new Uint8Array([4, 5])], 'blob-first.bin', {
    type: 'application/octet-stream',
    lastModified: 123,
  });

  expect(f).toBeInstanceOf(Blob);
  expect(f.name).toBe('blob-first.bin');
  expect(f.lastModified).toBe(123);
  expect(Array.from(await f.bytes())).toEqual([4, 5]);
});
