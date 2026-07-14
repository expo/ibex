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

import { afterEach, beforeEach, expect, test, describe } from 'bun:test';
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
  if ((flags & 1) === 1) opts.finishFlush = nodeZlib.constants.Z_SYNC_FLUSH;
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
const ibexStream = require('../../../src/builtins/stream.js');
const IbexEventEmitter = require('../../../src/builtins/events.js');

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

describe('zlib stream parity fixes (ENG-23478)', () => {
  test('a user Buffer with a control-lookalike property remains ordinary data', async () => {
    const input: any = Buffer.from('caller-owned payload must be compressed');
    input.__ibexZlibControl = { type: 'flush', kind: zlib.constants.Z_FINISH };
    const stream = zlib.createDeflate();
    const done = collect(stream);
    stream.end(input);
    expect(nodeZlib.inflateSync(await done).toString()).toBe(input.toString());
  });

  test('params() changes the compression level used for subsequently-ended data', async () => {
    const input = Buffer.from('abc123\n'.repeat(4096));
    const stream = zlib.createDeflate({ level: 0 });
    const done = collect(stream);
    await new Promise<void>((resolve, reject) => {
      stream.params(9, 0, (err: any) => err ? reject(err) : resolve());
    });
    stream.end(input);
    const actual = await done;
    const levelNine = nodeZlib.deflateSync(input, { level: 9 });
    const levelZero = nodeZlib.deflateSync(input, { level: 0 });
    expect(actual.length).toBe(levelNine.length);
    expect(actual.length).toBeLessThan(levelZero.length);
  });

  test('decoder streams enforce maxOutputLength', async () => {
    const compressed = nodeZlib.deflateSync(Buffer.alloc(10_000, 65));
    const stream = zlib.createInflate({ maxOutputLength: 100 });
    const err = await new Promise<any>((resolve) => {
      stream.on('error', resolve);
      stream.end(compressed);
    });
    expect(err && err.code).toBe('ERR_BUFFER_TOO_LARGE');
  });

  test('brotli passes a native pre-allocation budget and normalizes overflow', async () => {
    const originalBrotli = g.__exactBrotliDecompressSync;
    const budgets: number[] = [];
    g.__exactBrotliDecompressSync = (
      bytes: Uint8Array,
      _strict: boolean,
      flags: number,
      maxOutputLength: number,
    ) => {
      budgets.push(maxOutputLength);
      if (maxOutputLength < 10) {
        throw new Error(`zlib output exceeds maxOutputLength of ${maxOutputLength} bytes`);
      }
      const output = new Uint8Array(10);
      return (flags & 2) === 2 ? [output, bytes.length] : output;
    };

    try {
      let overflow: any;
      try {
        zlib.brotliDecompressSync(Buffer.from([1]), { maxOutputLength: 9 });
      } catch (error) {
        overflow = error;
      }
      expect(overflow && overflow.code).toBe('ERR_BUFFER_TOO_LARGE');
      expect(zlib.brotliDecompressSync(Buffer.from([1]), {
        maxOutputLength: 10,
      }).length).toBe(10);
      const streamOverflow = await new Promise<any>((resolve) => {
        const stream = zlib.createBrotliDecompress({ maxOutputLength: 9 });
        stream.on('error', resolve);
        stream.end(Buffer.from([1]));
      });
      expect(streamOverflow && streamOverflow.code).toBe('ERR_BUFFER_TOO_LARGE');
      expect(budgets).toEqual([9, 10, 9]);
    } finally {
      if (originalBrotli === undefined) delete g.__exactBrotliDecompressSync;
      else g.__exactBrotliDecompressSync = originalBrotli;
    }
  });

  test('decoder streams honor finishFlush: Z_SYNC_FLUSH for truncated deflate', async () => {
    const compressed = nodeZlib.deflateSync(Buffer.from('prefix that survives truncation'));
    const stream = zlib.createInflate({ finishFlush: zlib.constants.Z_SYNC_FLUSH });
    const done = collect(stream);
    stream.end(compressed.subarray(0, -6));
    expect((await done).toString()).toContain('prefix');
  });

  test('gunzip streams reject a truncated later gzip member instead of returning partial data', async () => {
    const member = nodeZlib.gzipSync(Buffer.from('hello'));
    const stream = zlib.createGunzip();
    const err = await new Promise<any>((resolve) => {
      stream.on('error', resolve);
      stream.end(Buffer.concat([member, member.subarray(0, 8)]));
    });
    expect(err).toBeTruthy();
    expect(err.code).toMatch(/^Z_/);
  });

  test('one-shot multi-member budgeting uses a running output total', () => {
    const originalInflate = g.__exactInflateSync;
    const budgets: number[] = [];
    g.__exactInflateSync = (
      bytes: Uint8Array,
      _mode: number,
      _strict: boolean,
      _flags: number,
      _dictionary: unknown,
      maxOutputLength: number,
    ) => {
      budgets.push(maxOutputLength);
      return [new Uint8Array([65]), 1];
    };

    try {
      const memberCount = 2048;
      const result = zlib.gunzipSync(Buffer.alloc(memberCount, 1), {
        maxOutputLength: memberCount,
      });
      expect(result.length).toBe(memberCount);
      expect(budgets.length).toBe(memberCount);
      expect(budgets[0]).toBe(memberCount);
      expect(budgets[memberCount - 1]).toBe(1);
    } finally {
      g.__exactInflateSync = originalInflate;
    }
  });
});

describe('preset dictionary round-trips (ENG-24282)', () => {
  test('wrapped and raw codecs round-trip dictionaries in one-shot and fallback streams', async () => {
    const dictionary = Buffer.from(
      'shared-dictionary:alpha-beta-gamma-delta:0123456789',
    );
    const input = Buffer.from(
      Array.from({ length: 64 }, (_, index) =>
        `${dictionary.toString()}:record-${index % 7}\n`).join(''),
    );

    const wrapped = zlib.deflateSync(input, { dictionary });
    const raw = zlib.deflateRawSync(input, { dictionary });
    expect(zlib.inflateSync(wrapped, { dictionary }).equals(input)).toBe(true);
    expect(zlib.inflateRawSync(raw, { dictionary }).equals(input)).toBe(true);

    // Force the JS-only stream path used by Bun and reduced-profile harnesses.
    // The real stateful native dictionary path is covered by node_zlib_builtin.
    const nativeHookNames = [
      '__exactZlibCreate',
      '__exactZlibWrite',
      '__exactZlibParams',
      '__exactZlibCheckOwner',
      '__exactZlibClose',
    ];
    const nativeHooks = new Map<string, unknown>();
    for (const name of nativeHookNames) {
      nativeHooks.set(name, g[name]);
      delete g[name];
    }

    async function streamRoundTrip(rawMode: boolean): Promise<boolean> {
      const encoder = rawMode
        ? zlib.createDeflateRaw({ dictionary })
        : zlib.createDeflate({ dictionary });
      const encoded = collect(encoder);
      encoder.write(input.subarray(0, 97));
      encoder.end(input.subarray(97));
      const compressed = await encoded;

      const decoder = rawMode
        ? zlib.createInflateRaw({ dictionary })
        : zlib.createInflate({ dictionary });
      const decoded = collect(decoder);
      const split = Math.max(1, Math.floor(compressed.length / 2));
      decoder.write(compressed.subarray(0, split));
      decoder.end(compressed.subarray(split));
      return (await decoded).equals(input);
    }

    try {
      expect(await streamRoundTrip(false)).toBe(true);
      expect(await streamRoundTrip(true)).toBe(true);
    } finally {
      for (const name of nativeHookNames) {
        const original = nativeHooks.get(name);
        if (original === undefined) delete g[name];
        else g[name] = original;
      }
    }
  });
});

describe('incremental native zlib stream path (ENG-23505)', () => {
  let originalCheckOwner: unknown;

  type NativeOperation =
    | { type: 'write'; text: string; flush: number; final: boolean }
    | { type: 'params'; level: number; strategy: number }
    | { type: 'close' };

  function installNativeRecorder(id: number) {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;
    const operations: NativeOperation[] = [];

    g.__exactZlibCreate = () => id;
    g.__exactZlibWrite = (
      actualId: number,
      bytes: Uint8Array,
      flush: number,
      final: boolean,
    ) => {
      expect(actualId).toBe(id);
      operations.push({
        type: 'write',
        text: Buffer.from(bytes).toString(),
        flush,
        final,
      });
      return new Uint8Array(bytes);
    };
    g.__exactZlibParams = (
      actualId: number,
      level: number,
      strategy: number,
    ) => {
      expect(actualId).toBe(id);
      operations.push({ type: 'params', level, strategy });
      return new Uint8Array(0);
    };
    g.__exactZlibClose = (actualId: number) => {
      expect(actualId).toBe(id);
      operations.push({ type: 'close' });
    };

    return {
      operations,
      restore() {
        if (originalCreate === undefined) delete g.__exactZlibCreate;
        else g.__exactZlibCreate = originalCreate;
        if (originalWrite === undefined) delete g.__exactZlibWrite;
        else g.__exactZlibWrite = originalWrite;
        if (originalParams === undefined) delete g.__exactZlibParams;
        else g.__exactZlibParams = originalParams;
        if (originalClose === undefined) delete g.__exactZlibClose;
        else g.__exactZlibClose = originalClose;
      },
    };
  }

  beforeEach(() => {
    originalCheckOwner = g.__exactZlibCheckOwner;
    g.__exactZlibCheckOwner = () => {};
  });

  afterEach(() => {
    if (originalCheckOwner === undefined) delete g.__exactZlibCheckOwner;
    else g.__exactZlibCheckOwner = originalCheckOwner;
  });

  test('options.flush emits output and applies its flush mode to every data write', async () => {
    const recorder = installNativeRecorder(80);
    try {
      const stream = zlib.createDeflate({ flush: zlib.constants.Z_SYNC_FLUSH });
      const emitted: Buffer[] = [];
      stream.on('data', (chunk: Uint8Array) => emitted.push(Buffer.from(chunk)));
      const ended = new Promise<void>((resolve, reject) => {
        stream.on('end', resolve);
        stream.on('error', reject);
      });

      await new Promise<void>((resolve, reject) => {
        stream.write('alpha', (err: any) => err ? reject(err) : resolve());
      });
      expect(Buffer.concat(emitted).toString()).toBe('alpha');

      await new Promise<void>((resolve, reject) => {
        stream.write('beta', (err: any) => err ? reject(err) : resolve());
      });
      expect(Buffer.concat(emitted).toString()).toBe('alphabeta');

      stream.end('omega');
      await ended;
      expect(Buffer.concat(emitted).toString()).toBe('alphabetaomega');
      expect(recorder.operations).toEqual([
        { type: 'write', text: 'alpha', flush: zlib.constants.Z_SYNC_FLUSH, final: false },
        { type: 'write', text: 'beta', flush: zlib.constants.Z_SYNC_FLUSH, final: false },
        { type: 'write', text: 'omega', flush: zlib.constants.Z_SYNC_FLUSH, final: false },
        { type: 'write', text: '', flush: zlib.constants.Z_FINISH, final: true },
        { type: 'close' },
      ]);
    } finally {
      recorder.restore();
    }
  });

  test('flush() and params() remain ordered behind an already queued write', async () => {
    const recorder = installNativeRecorder(81);
    try {
      const stream = zlib.createDeflate({ level: 0 });
      const done = collect(stream);
      const callbackOrder: string[] = [];

      stream.cork();
      stream.write('pending', (err: any) => {
        if (err) throw err;
        callbackOrder.push('write');
      });
      const flushed = new Promise<void>((resolve, reject) => {
        stream.flush(zlib.constants.Z_SYNC_FLUSH, (err: any) => {
          if (err) { reject(err); return; }
          callbackOrder.push('flush');
          resolve();
        });
      });
      const paramsChanged = new Promise<void>((resolve, reject) => {
        stream.params(9, zlib.constants.Z_DEFAULT_STRATEGY, (err: any) => {
          if (err) { reject(err); return; }
          callbackOrder.push('params');
          resolve();
        });
      });

      expect(recorder.operations).toEqual([]);
      stream.uncork();
      await flushed;
      await paramsChanged;
      stream.end('tail');

      expect((await done).toString()).toBe('pendingtail');
      expect(callbackOrder).toEqual(['write', 'flush', 'params']);
      expect(recorder.operations).toEqual([
        { type: 'write', text: 'pending', flush: zlib.constants.Z_NO_FLUSH, final: false },
        { type: 'write', text: '', flush: zlib.constants.Z_SYNC_FLUSH, final: false },
        { type: 'params', level: 9, strategy: zlib.constants.Z_DEFAULT_STRATEGY },
        { type: 'write', text: 'tail', flush: zlib.constants.Z_NO_FLUSH, final: false },
        { type: 'write', text: '', flush: zlib.constants.Z_FINISH, final: true },
        { type: 'close' },
      ]);
    } finally {
      recorder.restore();
    }
  });

  test('flush() after end is an asynchronous no-op', async () => {
    const recorder = installNativeRecorder(82);
    try {
      const stream = zlib.createDeflate();
      const done = collect(stream);
      stream.end('payload');
      expect((await done).toString()).toBe('payload');
      const beforeFlush = recorder.operations.slice();

      let synchronous = true;
      let callbackCalled = false;
      const returned = stream.flush((err: any) => {
        callbackCalled = true;
        expect(err).toBeUndefined();
        expect(synchronous).toBe(false);
      });
      synchronous = false;
      expect(returned).toBe(stream);
      await new Promise<void>((resolve) => process.nextTick(resolve));

      expect(callbackCalled).toBe(true);
      expect(recorder.operations).toEqual(beforeFlush);
    } finally {
      recorder.restore();
    }
  });

  test('deflate streams write each chunk through the stateful native codec', async () => {
    const originalDeflateSync = g.__exactDeflateSync;
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;

    let oneShotCalls = 0;
    let nextId = 1;
    const writes: Array<{ id: number; text: string; flush: number; final: boolean }> = [];
    const closed: number[] = [];

    g.__exactDeflateSync = (...args: any[]) => {
      oneShotCalls += 1;
      return originalDeflateSync(...args);
    };
    g.__exactZlibCreate = () => nextId++;
    g.__exactZlibWrite = (id: number, bytes: Uint8Array, flush: number, final: boolean) => {
      writes.push({ id, text: Buffer.from(bytes).toString(), flush, final });
      return new Uint8Array(bytes);
    };
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibClose = (id: number) => { closed.push(id); };

    try {
      const stream = zlib.createDeflate();
      const done = collect(stream);
      stream.write('alpha');
      stream.write(Buffer.from('beta'));
      stream.end('omega');

      expect((await done).toString()).toBe('alphabetaomega');
      expect(oneShotCalls).toBe(0);
      expect(writes.map((w) => [w.text, w.flush, w.final])).toEqual([
        ['alpha', zlib.constants.Z_NO_FLUSH, false],
        ['beta', zlib.constants.Z_NO_FLUSH, false],
        ['omega', zlib.constants.Z_NO_FLUSH, false],
        ['', zlib.constants.Z_FINISH, true],
      ]);
      expect(closed).toEqual([1]);
    } finally {
      g.__exactDeflateSync = originalDeflateSync;
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('decoder writes pass the remaining output budget into native code', async () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;
    const budgets: number[] = [];

    g.__exactZlibCreate = () => 40;
    g.__exactZlibWrite = (
      _id: number,
      bytes: Uint8Array,
      _flush: number,
      _final: boolean,
      _lenient: boolean,
      maxOutputLength: number,
    ) => {
      budgets.push(maxOutputLength);
      return new Uint8Array(bytes);
    };
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibClose = () => {};

    try {
      const stream = zlib.createInflate({ maxOutputLength: 50 });
      const done = collect(stream);
      stream.write(Buffer.alloc(20, 1));
      stream.end(Buffer.alloc(10, 2));

      expect((await done).length).toBe(30);
      expect(budgets).toEqual([50, 30, 20]);
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('a writable guessed native id cannot redirect stream operations', async () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;
    const observedIds: number[] = [];
    const closed: number[] = [];

    g.__exactZlibCreate = () => 41;
    g.__exactZlibWrite = (id: number, bytes: Uint8Array) => {
      observedIds.push(id);
      return new Uint8Array(bytes);
    };
    g.__exactZlibParams = (id: number) => {
      observedIds.push(id);
      return new Uint8Array(0);
    };
    g.__exactZlibClose = (id: number) => { closed.push(id); };

    try {
      const stream: any = zlib.createDeflate();
      expect(Object.prototype.hasOwnProperty.call(stream, '_nativeId')).toBe(false);
      // The old bridge trusted this public writable property as the native
      // registry key. It is deliberately inert now; the real id is private.
      stream._nativeId = 999;
      const done = collect(stream);
      await new Promise<void>((resolve, reject) => {
        stream.params(6, 0, (err: any) => err ? reject(err) : resolve());
      });
      stream.end('owner-bound');

      expect((await done).toString()).toBe('owner-bound');
      expect(observedIds.length).toBeGreaterThan(0);
      expect(observedIds.every((id) => id === 41)).toBe(true);
      expect(closed).toEqual([41]);
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('a failed native close retains the private id for an owner retry', () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;
    const closeAttempts: number[] = [];

    g.__exactZlibCreate = () => 73;
    g.__exactZlibWrite = (_id: number, bytes: Uint8Array) => new Uint8Array(bytes);
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibClose = (id: number) => {
      closeAttempts.push(id);
      if (closeAttempts.length === 1) throw new Error('wrong principal');
    };

    try {
      const stream = zlib.createDeflate();
      stream.write('owner-bound');

      expect(() => stream.reset()).toThrow('wrong principal');
      expect(() => stream.reset()).not.toThrow();
      expect(closeAttempts).toEqual([73, 73]);
      stream.destroy();
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('a cleanup failure during final flush does not mask the codec error', async () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalClose = g.__exactZlibClose;
    const closeAttempts: number[] = [];

    g.__exactZlibCreate = () => 74;
    g.__exactZlibWrite = (
      _id: number,
      bytes: Uint8Array,
      _flush: number,
      final: boolean,
    ) => {
      if (final) throw new Error('codec operation failed');
      return new Uint8Array(bytes);
    };
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibClose = (id: number) => {
      closeAttempts.push(id);
      if (closeAttempts.length === 1) throw new Error('cleanup failed');
    };

    try {
      const stream = zlib.createDeflate();
      const err = await new Promise<any>((resolve) => {
        stream.on('error', resolve);
        stream.end('payload');
      });

      expect(err && err.message).toBe('codec operation failed');
      expect(closeAttempts).toEqual([74, 74]);
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('wrong-principal destroy is rejected before Transform state mutates', () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalCheckOwner = g.__exactZlibCheckOwner;
    const originalClose = g.__exactZlibClose;
    const closeAttempts: number[] = [];
    let principal = 'owner';

    g.__exactZlibCreate = () => 75;
    g.__exactZlibWrite = (_id: number, bytes: Uint8Array) => new Uint8Array(bytes);
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibCheckOwner = () => {
      if (principal !== 'owner') throw new Error('wrong principal');
    };
    g.__exactZlibClose = (id: number) => {
      if (principal !== 'owner') throw new Error('wrong principal');
      closeAttempts.push(id);
    };

    try {
      const stream = zlib.createDeflate();
      stream.write('owner-bound');
      principal = 'foreign';
      expect(() => stream.destroy()).toThrow('wrong principal');
      principal = 'owner';
      expect(stream.destroyed).toBe(false);
      expect(closeAttempts).toEqual([]);

      expect(() => stream.destroy()).not.toThrow();
      expect(stream.destroyed).toBe(true);
      expect(closeAttempts).toEqual([75]);
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalCheckOwner === undefined) delete g.__exactZlibCheckOwner;
      else g.__exactZlibCheckOwner = originalCheckOwner;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
    }
  });

  test('owner projections remain sealed after native close', () => {
    const originalCreate = g.__exactZlibCreate;
    const originalWrite = g.__exactZlibWrite;
    const originalParams = g.__exactZlibParams;
    const originalCheckOwner = g.__exactZlibCheckOwner;
    const originalClose = g.__exactZlibClose;
    const originalNetOwner = g.__exactNetOwner;
    let principal = 'owner';
    let createCount = 0;
    const leaked: string[] = [];

    g.__exactNetOwner = (action: string, stamp?: number) => {
      if (action === 'new') return 913;
      if (action !== 'assert' || stamp !== 913 || principal !== 'owner') {
        throw new Error('wrong principal');
      }
    };
    g.__exactZlibCreate = () => {
      createCount++;
      return 76;
    };
    g.__exactZlibWrite = (_id: number, bytes: Uint8Array) => new Uint8Array(bytes);
    g.__exactZlibParams = () => new Uint8Array(0);
    g.__exactZlibCheckOwner = () => {};
    g.__exactZlibClose = () => {};

    try {
      const stream = zlib.createDeflate();
      const originalSync = stream._syncFn;
      stream._closeNativeStream();

      const injected = (chunk: Uint8Array) => {
        leaked.push(Buffer.from(chunk).toString());
        return chunk;
      };
      principal = 'foreign';
      expect(() => { stream._syncFn = injected; }).toThrow('wrong principal');
      expect(() => { stream._transform = injected; }).toThrow('wrong principal');
      expect(() => Object.defineProperty(stream, '_syncFn', { value: injected }))
        .toThrow();
      expect(() => stream.on('data', injected)).toThrow('wrong principal');
      expect(() => stream.reset()).toThrow('wrong principal');
      expect(createCount).toBe(1);

      principal = 'owner';
      expect(stream._syncFn).toBe(originalSync);
      stream._processChunk(Buffer.from('owner-secret'));
      expect(leaked).toEqual([]);
      stream.destroy();
    } finally {
      if (originalCreate === undefined) delete g.__exactZlibCreate;
      else g.__exactZlibCreate = originalCreate;
      if (originalWrite === undefined) delete g.__exactZlibWrite;
      else g.__exactZlibWrite = originalWrite;
      if (originalParams === undefined) delete g.__exactZlibParams;
      else g.__exactZlibParams = originalParams;
      if (originalCheckOwner === undefined) delete g.__exactZlibCheckOwner;
      else g.__exactZlibCheckOwner = originalCheckOwner;
      if (originalClose === undefined) delete g.__exactZlibClose;
      else g.__exactZlibClose = originalClose;
      if (originalNetOwner === undefined) delete g.__exactNetOwner;
      else g.__exactNetOwner = originalNetOwner;
    }
  });
});

describe('retained stream owner guard', () => {
  test('saved base-prototype methods reject before queue or lifecycle mutation', () => {
    let principal = 'owner';
    const stream = new ibexStream.Transform({}, () => {
      if (principal !== 'owner') throw new Error('wrong principal');
    });
    stream._transform = (chunk: Uint8Array, _encoding: string, callback: Function) => {
      callback(null, chunk);
    };

    const before = {
      destroyed: stream.destroyed,
      ended: stream.writableEnded,
      length: stream.writableLength,
      queued: stream._writeQueue.length,
      ending: stream._writableState.ending,
    };

    principal = 'foreign';
    expect(() => ibexStream.Writable.prototype.write.call(stream, Buffer.from('evil')))
      .toThrow('wrong principal');
    expect(() => ibexStream.Writable.prototype.end.call(stream))
      .toThrow('wrong principal');
    expect(() => ibexStream.Writable.prototype._flushWriteQueue.call(stream))
      .toThrow('wrong principal');
    expect(() => ibexStream.Transform.prototype._write.call(
      stream,
      Buffer.from('evil'),
      'buffer',
      () => {},
    )).toThrow('wrong principal');
    expect(() => ibexStream.Stream.prototype.destroy.call(stream))
      .toThrow('wrong principal');

    principal = 'owner';
    expect({
      destroyed: stream.destroyed,
      ended: stream.writableEnded,
      length: stream.writableLength,
      queued: stream._writeQueue.length,
      ending: stream._writableState.ending,
    }).toEqual(before);

    stream.destroy();
  });

  test('listener and continuation injection cannot observe later owner plaintext', async () => {
    let principal = 'owner';
    const leaked: string[] = [];
    const stream = new ibexStream.Transform({}, () => {
      if (principal !== 'owner') throw new Error('wrong principal');
    });
    stream._transform = (chunk: Uint8Array, _encoding: string, callback: Function) => {
      callback(null, chunk);
    };

    const foreignTransform = (chunk: Uint8Array, _encoding: string, callback: Function) => {
      leaked.push(Buffer.from(chunk).toString());
      callback(null, chunk);
    };
    const foreignListener = (chunk: Uint8Array) => {
      leaked.push(Buffer.from(chunk).toString());
    };

    principal = 'foreign';
    expect(() => ibexStream.Readable.prototype.on.call(stream, 'data', foreignListener))
      .toThrow('wrong principal');
    expect(() => IbexEventEmitter.prototype.on.call(stream, 'data', foreignListener))
      .toThrow('wrong principal');
    expect(() => ibexStream.Readable.prototype.read.call(stream))
      .toThrow('wrong principal');
    expect(() => stream._readableState).toThrow('wrong principal');
    expect(() => { stream._transform = foreignTransform; }).toThrow('wrong principal');
    expect(() => Object.defineProperty(stream, '_transform', { value: foreignTransform }))
      .toThrow();
    expect(() => { stream.emit = foreignListener; }).toThrow('wrong principal');
    expect(() => { stream.push = foreignListener; }).toThrow('wrong principal');

    principal = 'owner';
    const chunks: Buffer[] = [];
    const output = new Promise<Buffer>((resolve, reject) => {
      stream.on('data', (chunk: Uint8Array) => chunks.push(Buffer.from(chunk)));
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
    });
    stream.end(Buffer.from('owner-secret'));

    expect((await output).toString()).toBe('owner-secret');
    expect(leaked).toEqual([]);
  });
});
