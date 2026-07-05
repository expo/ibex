// ENG-22977 — markDetachedArrayBuffer must truly detach the buffer, not merely
// shadow byteLength with an own property. On engines that expose
// ArrayBuffer.prototype.transfer (ES2024) the internal [[ArrayBufferData]] slot
// is cleared so TypedArray/DataView construction and slice throw TypeError; on
// engines without it we fall back to zero-fill + WeakSet + byteLength shadow.
//
// Run with: bun test.

import { expect, test } from 'bun:test';
import { markDetachedArrayBuffer, isDetachedArrayBuffer } from './arraybuffer-detach';

const hasNativeTransfer =
  typeof (ArrayBuffer.prototype as unknown as { transfer?: unknown }).transfer === 'function';

test('a marked buffer reports as detached and byteLength collapses to 0', () => {
  const buf = new ArrayBuffer(32);
  new Uint8Array(buf).fill(9);

  markDetachedArrayBuffer(buf);

  expect(isDetachedArrayBuffer(buf)).toBe(true);
  expect(buf.byteLength).toBe(0);
});

test('on engines with ArrayBuffer.prototype.transfer the detach is real (throws)', () => {
  if (!hasNativeTransfer) {
    return; // fallback path can only best-effort shadow; nothing stronger to assert
  }

  const buf = new ArrayBuffer(16);
  markDetachedArrayBuffer(buf);

  expect(() => new Uint8Array(buf)).toThrow();
  expect(() => new DataView(buf)).toThrow();
  expect(() => buf.slice(0)).toThrow();
});
