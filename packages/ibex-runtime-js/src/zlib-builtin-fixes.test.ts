// ENG-22967 — regression coverage for correctness bugs in the zlib builtin
// (`src/builtins/zlib.js`).
//
// Covered here (behavioral bugs, checked against Node's own zlib as the oracle):
//   #1  Transform-stream flush() was destructive: on an encoder it compressed
//       everything buffered so far into a complete Z_FINISH-terminated member,
//       marked the stream flushed, and cleared its buffer — so any data written
//       *after* flush() was silently dropped:
//           gz.write('hello');
//           gz.flush(() => gz.end('world'));   // 'world' was lost
//       The fix defers all (de)compression to _final, so the full input
//       round-trips as one valid stream and nothing is dropped.
//   #2  zstd* silently emitted raw zlib-deflate output labelled as zstd (no
//       native zstd backend is registered), and the empty-input special case
//       produced a real zstd frame the inflate fallback couldn't parse. The fix
//       surfaces ENOSYS on every zstd entry point instead of wrong-format bytes.
//
// zlib.js talks to native host hooks (__exactDeflateSync/__exactInflateSync); we
// back them with Node's own zlib before requiring the builtin. We deliberately
// DO NOT stub __exactZstd*Sync so #2 can assert the ENOSYS behavior.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import * as nodeZlib from 'node:zlib';

const g = globalThis as Record<string, any>;

// --- Node-backed stubs for zlib.js's native codec hooks.
//     mode: 0 = zlib-deflate, 1 = gzip, 2 = raw-deflate. ---
g.__exactDeflateSync = (bytes: Uint8Array, level: number, mode: number, dict?: Uint8Array) => {
  const opts: nodeZlib.ZlibOptions = {};
  if (typeof level === 'number' && level !== -1) opts.level = level;
  if (dict) opts.dictionary = Buffer.from(dict);
  let out: Buffer;
  if (mode === 1) out = nodeZlib.gzipSync(bytes, opts);
  else if (mode === 2) out = nodeZlib.deflateRawSync(bytes, opts);
  else out = nodeZlib.deflateSync(bytes, opts);
  return new Uint8Array(out);
};
g.__exactInflateSync = (
  bytes: Uint8Array, mode: number, _lenient: boolean, flags: number, dict?: Uint8Array
) => {
  const opts: nodeZlib.ZlibOptions = {};
  if (dict) opts.dictionary = Buffer.from(dict);
  let out: Buffer;
  if (mode === 1) out = nodeZlib.gunzipSync(bytes, opts);
  else if (mode === 2) out = nodeZlib.inflateRawSync(bytes, opts);
  else out = nodeZlib.inflateSync(bytes, opts);
  const u8 = new Uint8Array(out);
  // flags bit 1 (value 2) = returnConsumed -> [output, bytesConsumed]
  if ((flags & 2) === 2) return [u8, bytes.length];
  return u8;
};

const require = createRequire(import.meta.url);
const zlib = require('../../../src/builtins/zlib.js');

function collect(stream: any): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (d: Uint8Array) => chunks.push(Buffer.from(d)));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

describe('flush() is non-destructive (ENG-22967 #1)', () => {
  test('createGzip: data written after flush() is not dropped', async () => {
    const gz = zlib.createGzip();
    const done = collect(gz);
    gz.write('hello');
    gz.flush(() => gz.end('world'));
    const compressed = await done;
    // Real Node gunzip must recover the FULL input as one valid stream.
    expect(nodeZlib.gunzipSync(compressed).toString()).toBe('helloworld');
  });

  test('createDeflate: post-flush writes survive as one valid zlib stream', async () => {
    // deflate can't be decoded as concatenated members, so this fails unless
    // the fix produces a single stream over the whole input.
    const df = zlib.createDeflate();
    const done = collect(df);
    df.write('hello');
    df.flush(() => df.end('world'));
    const compressed = await done;
    expect(nodeZlib.inflateSync(compressed).toString()).toBe('helloworld');
  });

  test('createGzip: basic round-trip still works', async () => {
    const gz = zlib.createGzip();
    const done = collect(gz);
    gz.end('the quick brown fox jumps over the lazy dog');
    expect(nodeZlib.gunzipSync(await done).toString()).toBe(
      'the quick brown fox jumps over the lazy dog');
  });

  test('createGunzip: decodes full input across an intermediate flush()', async () => {
    const src = 'streaming-body-split-across-a-flush-boundary';
    const gzBytes = nodeZlib.gzipSync(Buffer.from(src));
    const mid = Math.floor(gzBytes.length / 2);
    const gunzip = zlib.createGunzip();
    const done = collect(gunzip);
    gunzip.write(gzBytes.subarray(0, mid));
    gunzip.flush(() => {
      gunzip.write(gzBytes.subarray(mid));
      gunzip.end();
    });
    expect((await done).toString()).toBe(src);
  });
});

describe('zstd surfaces ENOSYS with no native backend (ENG-22967 #2)', () => {
  function catchCode(fn: () => unknown): string | undefined {
    try { fn(); } catch (e: any) { return e && e.code; }
    return '__DID_NOT_THROW__';
  }

  test('zstdCompressSync throws ENOSYS instead of emitting deflate', () => {
    expect(catchCode(() => zlib.zstdCompressSync(Buffer.from('payload')))).toBe('ENOSYS');
  });

  test('zstdCompressSync empty input throws ENOSYS (no half-broken frame)', () => {
    expect(catchCode(() => zlib.zstdCompressSync(Buffer.alloc(0)))).toBe('ENOSYS');
  });

  test('zstdDecompressSync throws ENOSYS', () => {
    expect(catchCode(() => zlib.zstdDecompressSync(Buffer.from([1, 2, 3])))).toBe('ENOSYS');
  });

  test('async zstdCompress reports ENOSYS via callback', async () => {
    const err = await new Promise<any>((resolve) =>
      zlib.zstdCompress(Buffer.from('x'), (e: any) => resolve(e)));
    expect(err && err.code).toBe('ENOSYS');
  });

  test('createZstdCompress stream emits an ENOSYS error', async () => {
    const s = zlib.createZstdCompress();
    const err = await new Promise<any>((resolve) => {
      s.on('error', resolve);
      s.end('x');
    });
    expect(err && err.code).toBe('ENOSYS');
  });

  test('createZstdDecompress stream emits an ENOSYS error', async () => {
    const s = zlib.createZstdDecompress();
    const err = await new Promise<any>((resolve) => {
      s.on('error', resolve);
      s.end(Buffer.from([0x28, 0xb5, 0x2f, 0xfd]));
    });
    expect(err && err.code).toBe('ENOSYS');
  });
});
