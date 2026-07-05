// ENG-22973 — atob() returned `String.fromCharCode(...result)`, spreading one
// argument per decoded byte. Engines cap call arguments (~64-125K), so atob
// threw RangeError on valid base64 above ~100KB (e.g. data: URLs embedding
// images/wasm). Decoding must be chunked.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { atob, btoa } from './base64.ts';

test('atob round-trips a large payload without RangeError', () => {
  // ~300KB of binary → ~400KB of base64, well past the argument-count limit.
  const size = 300_000;
  let binary = '';
  for (let i = 0; i < size; i++) {
    binary += String.fromCharCode(i % 256);
  }

  const encoded = btoa(binary);
  let decoded: string;
  expect(() => {
    decoded = atob(encoded);
  }).not.toThrow();

  expect(decoded!.length).toBe(size);
  // Spot-check the boundaries and an interior chunk edge (8192-byte chunks).
  expect(decoded!.charCodeAt(0)).toBe(0);
  expect(decoded!.charCodeAt(8192)).toBe(8192 % 256);
  expect(decoded!.charCodeAt(size - 1)).toBe((size - 1) % 256);
});

test('atob still decodes small inputs correctly', () => {
  expect(atob(btoa('hello world'))).toBe('hello world');
  expect(atob('aGVsbG8=')).toBe('hello');
});
