// ENG-23040 #4 — CompressionStream/DecompressionStream mishandled non-Uint8Array
// BufferSource chunks. `chunk instanceof Uint8Array ? chunk : new
// Uint8Array(chunk)` is only correct for Uint8Array/ArrayBuffer:
//   - A multi-byte typed-array view (Uint16Array, Float64Array, ...) fed to
//     `new Uint8Array(typedArray)` gets element-wise *value* converted (each
//     element truncated to a byte) instead of byte-for-byte reinterpreted.
//   - A DataView isn't array-like, so `new Uint8Array(dataView)` silently
//     produces an empty array.
//   - CompressionStream's `write()` guard additionally read `chunk.length`,
//     which is `undefined` on ArrayBuffer/DataView, so `undefined > 0` is
//     false and those chunks were dropped before ever reaching the buffer.
//
// These tests stub the native compress/decompress bridges to capture exactly
// the bytes the fix hands them, independent of the real codec. Run:
// bun test src/compression/compression-audit-eng23040.test.ts

import { expect, test, describe } from 'bun:test';
import { CompressionStream } from './CompressionStream';
import { DecompressionStream } from './DecompressionStream';

const g = globalThis as Record<string, any>;

describe('CompressionStream BufferSource chunk normalization', () => {
  test('a multi-byte typed-array view (Uint16Array) is reinterpreted byte-for-byte, not value-converted', async () => {
    let captured: Uint8Array | null = null;
    g.__exactDeflateSync = (input: Uint8Array) => {
      captured = input;
      return new Uint8Array([0xaa]);
    };

    const view = new Uint16Array([0x0102, 0x0304]);
    const expectedBytes = Array.from(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));

    const cs = new CompressionStream('deflate');
    const writer = cs.writable.getWriter();
    await writer.write(view as unknown as Uint8Array);
    await writer.close();

    expect(captured).not.toBeNull();
    // 4 raw bytes, not the old buggy 2-byte element-wise truncation ([2, 4]).
    expect((captured as unknown as Uint8Array).length).toBe(4);
    expect(Array.from(captured as unknown as Uint8Array)).toEqual(expectedBytes);
  });

  test('a raw ArrayBuffer chunk is not silently dropped', async () => {
    let captured: Uint8Array | null = null;
    g.__exactDeflateSync = (input: Uint8Array) => {
      captured = input;
      return new Uint8Array([0xaa]);
    };

    const buffer = new Uint8Array([9, 8, 7, 6]).buffer;

    const cs = new CompressionStream('deflate');
    const writer = cs.writable.getWriter();
    await writer.write(buffer as unknown as Uint8Array);
    await writer.close();

    expect(captured).not.toBeNull();
    expect(Array.from(captured as unknown as Uint8Array)).toEqual([9, 8, 7, 6]);
  });

  test('a DataView chunk is reinterpreted byte-for-byte, not silently emptied', async () => {
    let captured: Uint8Array | null = null;
    g.__exactDeflateSync = (input: Uint8Array) => {
      captured = input;
      return new Uint8Array([0xaa]);
    };

    const buffer = new ArrayBuffer(3);
    new Uint8Array(buffer).set([1, 2, 3]);
    const view = new DataView(buffer);

    const cs = new CompressionStream('deflate');
    const writer = cs.writable.getWriter();
    await writer.write(view as unknown as Uint8Array);
    await writer.close();

    expect(captured).not.toBeNull();
    expect(Array.from(captured as unknown as Uint8Array)).toEqual([1, 2, 3]);
  });
});

describe('DecompressionStream BufferSource chunk normalization', () => {
  test('a multi-byte typed-array view (Uint16Array) is reinterpreted byte-for-byte, not value-converted', async () => {
    let captured: Uint8Array | null = null;
    g.__exactInflateSync = (input: Uint8Array) => {
      captured = input;
      return new Uint8Array(0);
    };

    const view = new Uint16Array([0x0102, 0x0304]);
    const expectedBytes = Array.from(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));

    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    await writer.write(view as unknown as Uint8Array);
    await writer.close();

    expect(captured).not.toBeNull();
    expect((captured as unknown as Uint8Array).length).toBe(4);
    expect(Array.from(captured as unknown as Uint8Array)).toEqual(expectedBytes);
  });

  test('a DataView chunk is reinterpreted byte-for-byte, not silently emptied', async () => {
    let captured: Uint8Array | null = null;
    g.__exactInflateSync = (input: Uint8Array) => {
      captured = input;
      return new Uint8Array(0);
    };

    const buffer = new ArrayBuffer(3);
    new Uint8Array(buffer).set([4, 5, 6]);
    const view = new DataView(buffer);

    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    await writer.write(view as unknown as Uint8Array);
    await writer.close();

    expect(captured).not.toBeNull();
    expect(Array.from(captured as unknown as Uint8Array)).toEqual([4, 5, 6]);
  });
});
