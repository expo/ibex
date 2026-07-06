// ENG-22964 — src/builtins/buffer.js: the utf8/latin1/ascii/base64 decode paths,
// Buffer.concat and BufferProto.copy were rewritten off per-byte
// String.fromCharCode / index loops onto native TextDecoder + typed-array ops, and
// the hex decoder was moved off parseInt (which accepted whitespace/signs and
// half-valid pairs) onto a Node-compatible nibble scan. These tests pin the
// observable behavior against the runtime's own Buffer (Node/Bun) as an oracle.
//
// Run with: bun test packages/ibex-runtime-js/src/node/builtin-buffer.hotpaths.test.ts

import { expect, test } from 'bun:test';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
// The builtin under test (CommonJS source shipped to the Ibex runtime).
const Bx = require('../../../../src/builtins/buffer.js').Buffer as any;
// Oracle: the host runtime's Node-compatible Buffer.
const Oracle = require('buffer').Buffer as any;

function randBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i++) a[i] = (Math.random() * 256) | 0;
  return a;
}

function sameBytes(a: ArrayLike<number>, b: ArrayLike<number>): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Finding 2: hex decoding must reject what Node rejects (no parseInt slop).
// ---------------------------------------------------------------------------
test('hex decode stops at the first invalid nibble (matches Node)', () => {
  // The exact cases called out in the ticket.
  expect(Array.from(Bx.from('a1bg', 'hex'))).toEqual([0xa1]); // was <a1 0b>
  expect(Array.from(Bx.from('1 23', 'hex'))).toEqual([]); // was <01 23>

  // Signs / whitespace / partial pairs are rejected exactly like Node.
  const cases = [
    '', 'a', 'ab', 'abc', 'abcd', 'A1B2', 'deadBEEF',
    '+1', '-1', ' 1', '1 ', '0x41', 'zz', 'a1zz', 'ffgg', '  ', '\t0', '00\n',
    'gg00', '1', '123', '12345', 'FfEe', '６１', // fullwidth digits (non-ascii)
  ];
  for (const s of cases) {
    expect(Array.from(Bx.from(s, 'hex'))).toEqual(Array.from(Oracle.from(s, 'hex')));
  }
});

test('hex decode fuzz vs Node oracle (valid + mangled strings)', () => {
  const hexish = '0123456789abcdefABCDEF g+-\t \n';
  let mism = 0;
  for (let t = 0; t < 4000; t++) {
    const len = (Math.random() * 12) | 0;
    let s = '';
    for (let i = 0; i < len; i++) s += hexish[(Math.random() * hexish.length) | 0];
    if (!sameBytes(Bx.from(s, 'hex'), Oracle.from(s, 'hex'))) mism++;
  }
  expect(mism).toBe(0);
});

// ---------------------------------------------------------------------------
// Finding 1: perf rewrites must preserve exact bytes/strings.
// ---------------------------------------------------------------------------
test('utf8 decode of valid input matches Node (fast path), incl. BOM/emoji/large', () => {
  const fixed = [
    '', 'hello', 'héllo wörld', 'ünïcödé', '你好，世界', '😀🚀🧪',
    '﻿with bom', 'tab\tnl\n\0null', 'a'.repeat(70000), '🎉'.repeat(30000),
  ];
  for (const s of fixed) {
    const bytes = Array.from(Oracle.from(s, 'utf8'));
    expect(Bx.from(bytes).toString('utf8')).toBe(Oracle.from(bytes).toString('utf8'));
  }
  // Random valid utf8 built from random code points.
  for (let t = 0; t < 2000; t++) {
    let s = '';
    const n = (Math.random() * 40) | 0;
    for (let i = 0; i < n; i++) {
      const cp = (Math.random() * 0x10ffff) | 0;
      if (cp >= 0xd800 && cp <= 0xdfff) continue; // skip lone surrogates
      s += String.fromCodePoint(cp);
    }
    const bytes = Array.from(Oracle.from(s, 'utf8'));
    expect(Bx.from(bytes).toString('utf8')).toBe(Oracle.from(bytes).toString('utf8'));
  }
});

test('utf8 decode never throws on malformed bytes and returns a string', () => {
  // The lenient fallback loop still owns malformed input; it must not throw.
  for (let t = 0; t < 5000; t++) {
    const out = Bx.from(randBytes((Math.random() * 8) | 0)).toString('utf8');
    expect(typeof out).toBe('string');
  }
});

test('latin1/binary/ascii/base64/base64url decode match Node (incl. > chunk size)', () => {
  const encs = ['latin1', 'binary', 'ascii', 'base64', 'base64url'];
  for (let t = 0; t < 3000; t++) {
    const bytes = Array.from(randBytes((Math.random() * 40) | 0));
    for (const e of encs) {
      expect(Bx.from(bytes).toString(e)).toBe(Oracle.from(bytes).toString(e));
    }
  }
  // Exercise the chunked fromCharCode path (> BINARY_STRING_CHUNK === 0x2000).
  const big = Array.from(randBytes(70000));
  for (const e of encs) {
    expect(Bx.from(big).toString(e)).toBe(Oracle.from(big).toString(e));
  }
});

// ---------------------------------------------------------------------------
// ENG-23038 finding #4: hex/ucs2 toString() moved off a per-byte/per-unit
// `+=` loop (table lookup + join for hex; scratch array + chunked
// fromCharCode.apply for ucs2/utf16le) -- these pin the byte-exact output
// against the runtime's own Buffer, including across the chunk-size boundary.
// ---------------------------------------------------------------------------
test('hex/ucs2/utf16le toString match Node (incl. > chunk size, odd-length ucs2)', () => {
  const encs = ['hex', 'ucs2', 'utf16le'];
  for (let t = 0; t < 3000; t++) {
    const bytes = Array.from(randBytes((Math.random() * 40) | 0));
    for (const e of encs) {
      expect(Bx.from(bytes).toString(e)).toBe(Oracle.from(bytes).toString(e));
    }
  }
  // An odd byte length truncates the trailing incomplete code unit for
  // ucs2/utf16le (Node does the same); hex is unaffected by parity.
  for (const len of [1, 3, 5, 7]) {
    const bytes = Array.from(randBytes(len));
    for (const e of encs) {
      expect(Bx.from(bytes).toString(e)).toBe(Oracle.from(bytes).toString(e));
    }
  }
  // Exercise the chunked fromCharCode path (> BINARY_STRING_CHUNK === 0x2000)
  // for both the byte-table hex path and the code-unit ucs2/utf16le path.
  const big = Array.from(randBytes(70000));
  for (const e of encs) {
    expect(Bx.from(big).toString(e)).toBe(Oracle.from(big).toString(e));
  }
  // All 256 byte values individually, to pin the HEX_BYTE_TABLE contents.
  const allBytes = Array.from({ length: 256 }, (_, i) => i);
  expect(Bx.from(allBytes).toString('hex')).toBe(Oracle.from(allBytes).toString('hex'));
});

test('Buffer.concat matches Node (default length, truncated, and over-length)', () => {
  let mism = 0;
  for (let t = 0; t < 4000; t++) {
    const k = (Math.random() * 5) | 0;
    const parts: number[][] = [];
    for (let i = 0; i < k; i++) parts.push(Array.from(randBytes((Math.random() * 12) | 0)));
    const totMode = Math.random();
    const tot = totMode < 0.34 ? undefined : (Math.random() * 30) | 0;
    const bx = Bx.concat(parts.map((p) => Bx.from(p)), tot);
    const or = Oracle.concat(parts.map((p) => Oracle.from(p)), tot);
    if (!sameBytes(bx, or)) mism++;
  }
  expect(mism).toBe(0);
  // Large concat exercises result.set on sizeable inputs.
  const a = randBytes(50000), b = randBytes(50000);
  expect(sameBytes(Bx.concat([Bx.from(a), Bx.from(b)]), Oracle.concat([Oracle.from(a), Oracle.from(b)]))).toBe(true);
});

test('BufferProto.copy matches Node, including overlapping self-copies', () => {
  let mism = 0;
  for (let t = 0; t < 5000; t++) {
    const len = 1 + ((Math.random() * 16) | 0);
    const src = Array.from(randBytes(len));
    const bx = Bx.from(src), or = Oracle.from(src);
    const ts = (Math.random() * len) | 0;
    const ss = (Math.random() * len) | 0;
    const se = ss + ((Math.random() * (len - ss + 1)) | 0);
    const br = bx.copy(bx, ts, ss, se); // self-copy → overlap
    const nr = or.copy(or, ts, ss, se);
    if (br !== nr || !sameBytes(bx, or)) mism++;
  }
  expect(mism).toBe(0);
  // Copy between distinct buffers, large.
  const srcBig = randBytes(40000);
  const dbx = Bx.alloc(40000), dor = Oracle.alloc(40000);
  Bx.from(srcBig).copy(dbx, 5, 3, 39000);
  Oracle.from(srcBig).copy(dor, 5, 3, 39000);
  expect(sameBytes(dbx, dor)).toBe(true);
});
