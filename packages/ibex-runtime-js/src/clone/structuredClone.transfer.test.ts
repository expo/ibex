// ENG-22977 — structured-clone / transfer semantics.
//
// (1) Views over one ArrayBuffer previously each cloned to their own private
//     buffer at offset 0, so aliasing between views of the same source buffer
//     was silently lost. Per StructuredSerialize, sibling views must share one
//     cloned buffer with preserved byte offsets.
// (4) Transferring an ArrayBuffer must truly detach the source (subsequent
//     construction / slice throws), not merely shadow byteLength.
//
// Run with: bun test.

import { expect, test } from 'bun:test';
import { structuredClone } from './structuredClone';
import { Blob } from '../blob/Blob';
import { File } from '../blob/File';

test('sibling views over one buffer clone into a single shared buffer with offsets preserved', () => {
  const buf = new ArrayBuffer(16);
  const whole = new Uint8Array(buf); // offset 0, length 16
  const tail = new Uint8Array(buf, 8, 8); // offset 8, length 8

  const cloned = structuredClone({ buf, whole, tail }) as {
    buf: ArrayBuffer;
    whole: Uint8Array;
    tail: Uint8Array;
  };

  // All three must reference the ONE cloned buffer.
  expect(cloned.whole.buffer).toBe(cloned.buf);
  expect(cloned.tail.buffer).toBe(cloned.buf);
  expect(cloned.whole.buffer).toBe(cloned.tail.buffer);

  // Offsets/lengths preserved; the whole buffer is cloned.
  expect(cloned.buf.byteLength).toBe(16);
  expect(cloned.whole.byteOffset).toBe(0);
  expect(cloned.tail.byteOffset).toBe(8);
  expect(cloned.tail.length).toBe(8);

  // Aliasing survives: writing through one cloned view is visible through the
  // overlapping cloned view.
  cloned.whole[8] = 42;
  expect(cloned.tail[0]).toBe(42);
});

test('a DataView and a TypedArray over one buffer share the cloned buffer', () => {
  const buf = new ArrayBuffer(8);
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf, 4, 4);

  const cloned = structuredClone({ bytes, view }) as {
    bytes: Uint8Array;
    view: DataView;
  };

  expect(cloned.view.buffer).toBe(cloned.bytes.buffer);
  expect(cloned.view.byteOffset).toBe(4);

  cloned.bytes[4] = 7;
  expect(cloned.view.getUint8(0)).toBe(7);
});

test('a standalone offset view clones its entire underlying buffer', () => {
  const buf = new ArrayBuffer(16);
  const v = new Uint8Array(buf, 8, 4);

  const clone = structuredClone(v);

  expect(clone.buffer.byteLength).toBe(16);
  expect(clone.byteOffset).toBe(8);
  expect(clone.length).toBe(4);
  // Independent of the source.
  expect(clone.buffer).not.toBe(buf);
});

test('transferring an ArrayBuffer moves the data and detaches the source', () => {
  const buf = new ArrayBuffer(16);
  new Uint8Array(buf).fill(7);

  const clone = structuredClone(buf, { transfer: [buf] }) as ArrayBuffer;

  expect(clone.byteLength).toBe(16);
  expect(new Uint8Array(clone)[0]).toBe(7);

  // Source is detached: byteLength collapses to 0 in every engine, and on
  // engines with ArrayBuffer.prototype.transfer the internal slot is really
  // cleared so construction / slice throw (instead of yielding a zombie buffer).
  expect(buf.byteLength).toBe(0);
  if (typeof (ArrayBuffer.prototype as unknown as { transfer?: unknown }).transfer === 'function') {
    expect(() => new Uint8Array(buf)).toThrow();
    expect(() => buf.slice(0)).toThrow();
  }
});

test('Blob and File clones preserve Ibex constructors and data', async () => {
  const blob = new Blob([new Uint8Array([1, 2, 3])], { type: 'image/png' });
  const file = new File([new Uint8Array([4, 5])], 'clone.bin', {
    type: 'application/octet-stream',
    lastModified: 321,
  });

  const blobClone = structuredClone(blob);
  const fileClone = structuredClone(file);

  expect(blobClone).toBeInstanceOf(Blob);
  expect(blobClone.type).toBe('image/png');
  expect(Array.from(await blobClone.bytes())).toEqual([1, 2, 3]);

  expect(fileClone).toBeInstanceOf(File);
  expect(fileClone).toBeInstanceOf(Blob);
  expect(fileClone.name).toBe('clone.bin');
  expect(fileClone.type).toBe('application/octet-stream');
  expect(fileClone.lastModified).toBe(321);
  expect(Array.from(await fileClone.bytes())).toEqual([4, 5]);
});
