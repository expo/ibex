// ENG-22972 — regression coverage for two correctness/perf bugs in the Web
// Compression API implementation:
//
//   1. DecompressionStream decoded each write() chunk independently (passing
//      only the latest chunk to the stateless one-shot inflate bridge and
//      marking the stream finished after the first chunk). A mid-stream deflate
//      chunk is headerless and cannot decode alone, so any payload delivered in
//      2+ chunks — the normal network case — errored. The brotli path had the
//      same bug. Fix: accumulate all input and decode the full stream once when
//      the writable side closes.
//   2. Both streams' appendInput reallocated and copied the entire accumulated
//      buffer on every write (O(n^2)). Fix: buffer chunks in a list and
//      concatenate exactly once.
//
// The streams talk to native host bridges (__exactInflateSync / __exactDeflateSync
// and the brotli pair). Here we stub those with Node's zlib as the byte
// primitive (its truncation error message "unexpected end of file" matches the
// native bridge), then round-trip data through the JS stream classes. Run: bun test.

import { expect, test, describe } from 'bun:test';
import * as zlib from 'node:zlib';
import { CompressionStream } from './CompressionStream';
import { DecompressionStream } from './DecompressionStream';

const g = globalThis as Record<string, any>;

const toBuf = (input: Uint8Array): Buffer =>
  Buffer.from(input.buffer, input.byteOffset, input.byteLength);

// mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw deflate
g.__exactDeflateSync = (input: Uint8Array, _level: number, mode: number): Uint8Array => {
  const buf = toBuf(input);
  if (mode === 1) return new Uint8Array(zlib.gzipSync(buf));
  if (mode === 2) return new Uint8Array(zlib.deflateRawSync(buf));
  return new Uint8Array(zlib.deflateSync(buf));
};
// mode: 0 = deflate, 1 = gzip (auto-detect), 2 = raw. Throws "unexpected end of
// file" on truncated input, exactly like the native bridge.
g.__exactInflateSync = (input: Uint8Array, mode: number, _strict?: boolean): Uint8Array => {
  const buf = toBuf(input);
  if (mode === 1) return new Uint8Array(zlib.gunzipSync(buf));
  if (mode === 2) return new Uint8Array(zlib.inflateRawSync(buf));
  return new Uint8Array(zlib.inflateSync(buf));
};
g.__exactBrotliCompressSync = (input: Uint8Array): Uint8Array =>
  new Uint8Array(zlib.brotliCompressSync(toBuf(input)));
g.__exactBrotliDecompressSync = (input: Uint8Array, _strict?: boolean): Uint8Array =>
  new Uint8Array(zlib.brotliDecompressSync(toBuf(input)));

function splitIntoChunks(bytes: Uint8Array, parts: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  const size = Math.max(1, Math.ceil(bytes.length / parts));
  for (let i = 0; i < bytes.length; i += size) {
    chunks.push(bytes.subarray(i, Math.min(i + size, bytes.length)));
  }
  return chunks.length > 0 ? chunks : [new Uint8Array(0)];
}

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

// Write every input chunk and collect every output chunk, reading concurrently
// with writing to avoid any backpressure deadlock.
async function runTransform(
  transform: { writable: WritableStream<Uint8Array>; readable: ReadableStream<Uint8Array> },
  inputChunks: Uint8Array[]
): Promise<Uint8Array> {
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();
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

const FORMATS = ['gzip', 'deflate', 'deflate-raw', 'brotli'] as const;

// A payload big enough to be split across several chunks of compressed bytes.
const SAMPLE = new TextEncoder().encode(
  'The quick brown fox jumps over the lazy dog. '.repeat(64) + '\u{1F600}中あ'
);

function nodeCompress(format: string, data: Uint8Array): Uint8Array {
  const buf = toBuf(data);
  switch (format) {
    case 'gzip': return new Uint8Array(zlib.gzipSync(buf));
    case 'deflate': return new Uint8Array(zlib.deflateSync(buf));
    case 'deflate-raw': return new Uint8Array(zlib.deflateRawSync(buf));
    case 'brotli': return new Uint8Array(zlib.brotliCompressSync(buf));
    default: throw new Error('unknown format');
  }
}

describe('DecompressionStream multi-chunk decode (ENG-22972 #1)', () => {
  for (const format of FORMATS) {
    test(`${format}: compressed payload split into 5 chunks decodes correctly`, async () => {
      const compressed = nodeCompress(format, SAMPLE);
      // The whole point: the compressed stream is delivered in multiple chunks,
      // none of which is independently decodable. (Was: errored on chunk 2.)
      const chunks = splitIntoChunks(compressed, 5);
      expect(chunks.length).toBeGreaterThan(1);
      const ds = new DecompressionStream(format);
      const out = await runTransform(ds, chunks);
      expect(out).toEqual(SAMPLE);
    });

    test(`${format}: single-chunk payload still decodes correctly`, async () => {
      const compressed = nodeCompress(format, SAMPLE);
      const ds = new DecompressionStream(format);
      const out = await runTransform(ds, [compressed]);
      expect(out).toEqual(SAMPLE);
    });
  }

  test('truncated stream errors the readable with a TypeError (incomplete data)', async () => {
    const compressed = nodeCompress('gzip', SAMPLE);
    const truncated = compressed.subarray(0, compressed.length - 4);
    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    for (const chunk of splitIntoChunks(truncated, 3)) {
      await writer.write(chunk);
    }
    await writer.close();
    await expect(reader.read()).rejects.toThrow(/incomplete data/i);
  });
});

describe('CompressionStream <-> DecompressionStream round trip', () => {
  for (const format of FORMATS) {
    test(`${format}: many small input chunks compress then decompress back (ENG-22972 #2)`, async () => {
      // 200 tiny chunks exercise the chunk-list buffering path (the old O(n^2)
      // realloc-per-write pattern) without a quadratic blow-up.
      const inputChunks: Uint8Array[] = [];
      for (let i = 0; i < 200; i++) inputChunks.push(SAMPLE.subarray(0, 8));
      const original = concat(inputChunks);

      const cs = new CompressionStream(format);
      const compressed = await runTransform(cs, inputChunks);
      expect(compressed.length).toBeGreaterThan(0);

      const ds = new DecompressionStream(format);
      const restored = await runTransform(ds, splitIntoChunks(compressed, 4));
      expect(restored).toEqual(original);
    });
  }

  test('empty input compresses to a valid stream that decompresses to empty', async () => {
    const cs = new CompressionStream('gzip');
    const compressed = await runTransform(cs, []);
    const ds = new DecompressionStream('gzip');
    const restored = await runTransform(ds, [compressed]);
    expect(restored).toEqual(new Uint8Array(0));
  });
});
