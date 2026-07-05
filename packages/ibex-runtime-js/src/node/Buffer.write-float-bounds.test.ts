// ENG-22976 — writeDoubleBE/LE and writeFloatBE/LE previously had no offset
// bounds check and constructed a DataView that spanned to the end of the
// underlying ArrayBuffer rather than the Buffer view. A write on a too-short
// view (e.g. `big.subarray(0, 4).writeDoubleLE(...)`) silently corrupted the
// adjacent/pooled sibling bytes instead of throwing ERR_BUFFER_OUT_OF_BOUNDS.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { Buffer } from './Buffer.ts';

test('writeDouble/writeFloat throw ERR_BUFFER_OUT_OF_BOUNDS on a too-small buffer', () => {
  for (const method of ['writeDoubleBE', 'writeDoubleLE'] as const) {
    const buf = Buffer.alloc(4);
    expect(() => (buf as any)[method](1.5, 0)).toThrow(
      expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS' }),
    );
  }
  for (const method of ['writeFloatBE', 'writeFloatLE'] as const) {
    const buf = Buffer.alloc(2);
    expect(() => (buf as any)[method](1.5, 0)).toThrow(
      expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS' }),
    );
  }
});

test('writeDoubleLE on a short subarray does not corrupt sibling bytes', () => {
  const big = Buffer.alloc(8); // all zero
  const view = big.subarray(0, 4); // length 4, byteOffset 0, shares the 8-byte backing store

  expect(() => view.writeDoubleLE(1.5, 0)).toThrow(
    expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS' }),
  );

  // The 8-byte write must not have landed: bytes 4..7 stay zero.
  for (let i = 0; i < 8; i++) {
    expect(big[i]).toBe(0);
  }
});

test('writeFloatLE on a short subarray does not corrupt sibling bytes', () => {
  const big = Buffer.alloc(8);
  const view = big.subarray(0, 2); // only 2 bytes, needs 4

  expect(() => view.writeFloatLE(1.5, 0)).toThrow(
    expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS' }),
  );

  for (let i = 0; i < 8; i++) {
    expect(big[i]).toBe(0);
  }
});

test('an out-of-range (but positive) offset throws ERR_OUT_OF_RANGE', () => {
  const buf = Buffer.alloc(10);
  // offset 5 leaves only 5 bytes, but a double needs 8.
  let err: any;
  try {
    buf.writeDoubleLE(1.5, 5);
  } catch (e) {
    err = e;
  }
  expect(err).toBeDefined();
  expect(['ERR_OUT_OF_RANGE', 'ERR_BUFFER_OUT_OF_BOUNDS']).toContain(err.code);
});

test('valid writeDouble/writeFloat still round-trip and return the next offset', () => {
  const buf = Buffer.alloc(16);

  expect(buf.writeDoubleBE(1.5, 0)).toBe(8);
  expect(buf.readDoubleBE(0)).toBe(1.5);

  expect(buf.writeDoubleLE(-2.25, 8)).toBe(16);
  expect(buf.readDoubleLE(8)).toBe(-2.25);

  const fbuf = Buffer.alloc(8);
  expect(fbuf.writeFloatLE(0.5, 4)).toBe(8);
  expect(fbuf.readFloatLE(4)).toBe(0.5);
});

test('writing into a view with a non-zero byteOffset stays inside the view', () => {
  const big = Buffer.alloc(16);
  const view = big.subarray(8, 16); // length 8, byteOffset 8

  expect(view.writeDoubleLE(3.5, 0)).toBe(8);
  // Bytes before the view are untouched.
  for (let i = 0; i < 8; i++) {
    expect(big[i]).toBe(0);
  }
  expect(big.readDoubleLE(8)).toBe(3.5);
});
