// ENG-22972 — regression coverage for two correctness bugs in the TextEncoder /
// TextEncoderStream implementation:
//
//   3. TextEncoderStream encoded each chunk independently with no pending
//      high-surrogate state, so a surrogate pair split across a chunk boundary
//      (writer.write('\uD83D'); writer.write('\uDE00')) emitted two U+FFFD
//      instead of one emoji. Fix: carry a trailing high surrogate to the next
//      chunk and flush an unpaired one at end-of-stream.
//   4. TextEncoder.encodeInto substituted U+FFFD (and mis-counted `read`) when a
//      valid surrogate pair did not fit as 4 bytes. Per the Encoding spec and
//      V8/Node native behavior, encodeInto must stop *before* a code point that
//      does not fit so callers can grow the buffer and resume. Fix: break.
//
// Run: bun test.

import { expect, test, describe } from 'bun:test';
import { TextEncoder } from './TextEncoder';
import { TextEncoderStream } from './TextEncoderStream';

const EMOJI = '\u{1F600}';          // U+1F600, UTF-8 = f0 9f 98 80, UTF-16 = D83D DE00
const EMOJI_BYTES = [0xf0, 0x9f, 0x98, 0x80];
const FFFD_BYTES = [0xef, 0xbf, 0xbd];

function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

async function runEncoderStream(inputChunks: string[]): Promise<Uint8Array> {
  const tes = new TextEncoderStream();
  const writer = tes.writable.getWriter();
  const reader = (tes.readable as ReadableStream<Uint8Array>).getReader();
  const readAll = (async () => {
    const parts: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    return parts;
  })();
  for (const chunk of inputChunks) {
    await writer.write(chunk);
  }
  await writer.close();
  return concat(await readAll);
}

describe('TextEncoder.encodeInto boundary handling (ENG-22972 #4)', () => {
  test('a surrogate pair that fits as 4 bytes is written whole', () => {
    const dest = new Uint8Array(4);
    const r = new TextEncoder().encodeInto(EMOJI, dest);
    expect(r).toEqual({ read: 2, written: 4 });
    expect(Array.from(dest)).toEqual(EMOJI_BYTES);
  });

  test('a surrogate pair that does NOT fit stops before it (nothing written)', () => {
    // Was: wrote U+FFFD (3 bytes) and returned read:1, then reprocessed the low
    // surrogate as a second lone surrogate -> corruption.
    const dest = new Uint8Array(3);
    const r = new TextEncoder().encodeInto(EMOJI, dest);
    expect(r).toEqual({ read: 0, written: 0 });
    expect(Array.from(dest)).toEqual([0, 0, 0]);
  });

  test('stops before the pair after emitting preceding characters', () => {
    const dest = new Uint8Array(4); // 'a' fits, emoji (4 bytes) does not
    const r = new TextEncoder().encodeInto('a' + EMOJI, dest);
    expect(r).toEqual({ read: 1, written: 1 });
    expect(Array.from(dest)).toEqual([0x61, 0, 0, 0]);
  });

  test('resize-and-continue: caller can resume from read with no corruption', () => {
    const source = 'a' + EMOJI + 'b';
    const enc = new TextEncoder();
    // First pass into a 4-byte buffer: 'a' fits, emoji does not.
    const buf1 = new Uint8Array(4);
    const r1 = enc.encodeInto(source, buf1);
    expect(r1).toEqual({ read: 1, written: 1 });
    // Grow and continue from the unread remainder.
    const buf2 = new Uint8Array(16);
    const r2 = enc.encodeInto(source.slice(r1.read), buf2);
    const combined = concat([buf1.subarray(0, r1.written), buf2.subarray(0, r2.written)]);
    expect(combined).toEqual(enc.encode(source));
    expect(new TextDecoder().decode(combined)).toBe('a' + EMOJI + 'b');
  });

  test('a lone surrogate that does not fit also stops (no partial write)', () => {
    const dest = new Uint8Array(2); // lone surrogate -> U+FFFD needs 3 bytes
    const r = new TextEncoder().encodeInto('\uD83D', dest);
    expect(r).toEqual({ read: 0, written: 0 });
    expect(Array.from(dest)).toEqual([0, 0]);
  });
});

describe('TextEncoderStream surrogate carry-over (ENG-22972 #3)', () => {
  test('surrogate pair split across two chunks encodes as one code point', async () => {
    // Was: two U+FFFD (6 bytes). Now: the emoji's 4 UTF-8 bytes.
    const out = await runEncoderStream(['\uD83D', '\uDE00']);
    expect(Array.from(out)).toEqual(EMOJI_BYTES);
  });

  test('pair fully within a single chunk still encodes correctly', async () => {
    const out = await runEncoderStream([EMOJI]);
    expect(Array.from(out)).toEqual(EMOJI_BYTES);
  });

  test('unpaired high surrogate at end of stream flushes as U+FFFD', async () => {
    const out = await runEncoderStream(['ab', '\uD83D']);
    expect(Array.from(out)).toEqual([0x61, 0x62, ...FFFD_BYTES]);
  });

  test('high surrogate followed by a non-low code unit yields U+FFFD then the char', async () => {
    const out = await runEncoderStream(['\uD83D', 'A']);
    expect(Array.from(out)).toEqual([...FFFD_BYTES, 0x41]);
  });

  test('multiple split pairs across many chunks round-trip', async () => {
    const full = 'x' + EMOJI + 'y' + EMOJI + 'z';
    // Split every UTF-16 code unit into its own chunk (maximally adversarial).
    const chunks = Array.from(full);
    // Array.from splits by code point, so re-split surrogate pairs into units:
    const unitChunks: string[] = [];
    for (let i = 0; i < full.length; i++) unitChunks.push(full[i]);
    const out = await runEncoderStream(unitChunks);
    expect(new TextDecoder().decode(out)).toBe(full);
    expect(out).toEqual(new TextEncoder().encode(full));
    void chunks;
  });
});
