// ENG-23136 — Buffer & fs builtins: omitted-offset bounds-check bypass,
// Buffer.from(ArrayBuffer) copy-vs-share, web hex decoder parseInt slop,
// write/fill offset validation, fd-based writeSync EINTR handling, and the
// EFBIG errno map gap.
//
// Files under test:
//   - src/builtins/buffer.js           (validateOffset, BufferProto.write)
//   - packages/ibex-runtime-js/src/node/Buffer.ts (from(ArrayBuffer), hex,
//     write, fill)
//   - src/builtins/fs.js               (_writeAllSync EINTR retry, EFBIG errno)
//
// Oracle: the host runtime's Node-compatible Buffer, same pattern as
// builtin-buffer.hotpaths.test.ts / eng23038-buffer-offset-url-querystring.test.ts.
//
// Run with: bun test packages/ibex-runtime-js/src/eng23136-buffer-fs-fixes.test.ts

import { expect, test, describe, beforeAll, afterAll } from 'bun:test';
import { createRequire } from 'module';
import * as nodeFs from 'node:fs';
import * as os from 'node:os';
import * as nodePath from 'node:path';
import { Buffer as WebBuffer } from './node/Buffer';

const require = createRequire(import.meta.url);
const Bx = require('../../../src/builtins/buffer.js').Buffer as any;
const Oracle = require('buffer').Buffer as any;

// Runs `fn` against both implementations and asserts identical outcome shape:
// either both return (deep-equal bytes / equal primitives) or both throw with
// the same err.code.
function agreeWithOracle(label: string, fn: (B: any) => unknown) {
  let bxThrew: any = null;
  let orThrew: any = null;
  let bxResult: unknown;
  let orResult: unknown;
  try {
    bxResult = fn(Bx);
  } catch (e) {
    bxThrew = e;
  }
  try {
    orResult = fn(Oracle);
  } catch (e) {
    orThrew = e;
  }
  if (orThrew) {
    expect(`${label}: threw=${bxThrew !== null} code=${bxThrew?.code}`)
      .toBe(`${label}: threw=true code=${orThrew.code}`);
  } else {
    expect(bxThrew).toBeNull();
    if (orResult instanceof Uint8Array) {
      expect(Array.from(bxResult as Uint8Array)).toEqual(Array.from(orResult));
    } else {
      expect(bxResult).toEqual(orResult);
    }
  }
}

// ---------------------------------------------------------------------------
// M1 — builtins validateOffset: omitted offset must hit the bounds check
// ---------------------------------------------------------------------------
describe('builtins buffer.js: omitted offset bounds check (ENG-23136 M1)', () => {
  test('readUInt32LE() on a 2-byte buffer throws like Node (was: silent OOB read)', () => {
    agreeWithOracle('readUInt32LE()', (B) => B.alloc(2).readUInt32LE());
    agreeWithOracle('readUInt32BE()', (B) => B.alloc(2).readUInt32BE());
    agreeWithOracle('readUInt16LE()', (B) => B.alloc(1).readUInt16LE());
    agreeWithOracle('readDoubleLE()', (B) => B.alloc(4).readDoubleLE());
    agreeWithOracle('readBigUInt64LE()', (B) => B.alloc(4).readBigUInt64LE());
  });

  test('omitted and explicit-0 offsets behave identically (was: asymmetric)', () => {
    let omitted: any = null;
    let explicit: any = null;
    try { Bx.alloc(2).readUInt32LE(); } catch (e) { omitted = e; }
    try { Bx.alloc(2).readUInt32LE(0); } catch (e) { explicit = e; }
    expect(omitted).not.toBeNull();
    expect(explicit).not.toBeNull();
    expect(omitted.code).toBe(explicit.code);
  });

  test('writeUInt32LE(x) on a 2-byte buffer throws and does not report a fake full write', () => {
    agreeWithOracle('writeUInt32LE(0xdeadbeef)', (B) => B.alloc(2).writeUInt32LE(0xdeadbeef));
    const buf = Bx.alloc(2);
    try { buf.writeUInt32LE(0xdeadbeef); } catch { /* expected */ }
    // No partial mutation: the low bytes must not have been written.
    expect(Array.from(buf)).toEqual([0, 0]);
  });

  test('writeBigUInt64LE(1n) on a 4-byte buffer throws without partial mutation', () => {
    agreeWithOracle('writeBigUInt64LE(1n)', (B) => B.alloc(4).writeBigUInt64LE(1n));
    const buf = Bx.alloc(4);
    buf.fill(0xaa);
    try { buf.writeBigUInt64LE(0x1122334455667788n); } catch { /* expected */ }
    // Pre-3c512fb behavior restored: no low-word write before the throw.
    expect(Array.from(buf)).toEqual([0xaa, 0xaa, 0xaa, 0xaa]);
  });

  test('omitted offset still works on buffers that are large enough', () => {
    agreeWithOracle('readUInt32LE() ok', (B) => B.from([1, 2, 3, 4]).readUInt32LE());
    const buf = Bx.alloc(4);
    expect(buf.writeUInt32LE(0x01020304)).toBe(4);
    expect(Array.from(buf)).toEqual([4, 3, 2, 1]);
    const big = Bx.alloc(8);
    expect(big.writeBigUInt64LE(1n)).toBe(8);
    expect(big.readBigUInt64LE()).toBe(1n);
  });
});

// ---------------------------------------------------------------------------
// L1 — builtins Buffer#write: fractional/NaN/out-of-range offsets must throw
// ---------------------------------------------------------------------------
describe('builtins buffer.js: write offset/length validation (ENG-23136 L1)', () => {
  test('invalid offsets throw exactly where Node throws', () => {
    agreeWithOracle("write('abc', 1.5)", (B) => B.alloc(8).write('abc', 1.5));
    agreeWithOracle("write('x', NaN)", (B) => B.alloc(8).write('x', NaN));
    agreeWithOracle("write('x', Infinity)", (B) => B.alloc(8).write('x', Infinity));
    agreeWithOracle("write('data', 999)", (B) => B.alloc(8).write('data', 999));
    agreeWithOracle("write('x', -1)", (B) => B.alloc(8).write('x', -1));
    agreeWithOracle("write('x', null)", (B) => B.alloc(8).write('x', null));
  });

  test('invalid lengths throw exactly where Node throws', () => {
    agreeWithOracle("write('abc', 0, NaN)", (B) => B.alloc(8).write('abc', 0, NaN));
    agreeWithOracle("write('abc', 0, 1.5)", (B) => B.alloc(8).write('abc', 0, 1.5));
    agreeWithOracle("write('abc', 0, -1)", (B) => B.alloc(8).write('abc', 0, -1));
    agreeWithOracle("write('abcdef', 0, 99)", (B) => B.alloc(4).write('abcdef', 0, 99));
  });

  test('valid writes still work, including arg-shuffle overloads', () => {
    agreeWithOracle("write('abc')", (B) => {
      const b = B.alloc(8);
      const n = b.write('abc');
      return [n, ...Array.from(b)];
    });
    agreeWithOracle("write('abc', 2)", (B) => {
      const b = B.alloc(8);
      const n = b.write('abc', 2);
      return [n, ...Array.from(b)];
    });
    agreeWithOracle("write('abcdef', 2, 3)", (B) => {
      const b = B.alloc(8);
      const n = b.write('abcdef', 2, 3);
      return [n, ...Array.from(b)];
    });
    agreeWithOracle("write('6162', 'hex')", (B) => {
      const b = B.alloc(4);
      const n = b.write('6162', 'hex');
      return [n, ...Array.from(b)];
    });
    agreeWithOracle("write('abc', 1, 'ascii')", (B) => {
      const b = B.alloc(8);
      const n = b.write('abc', 1, 'ascii');
      return [n, ...Array.from(b)];
    });
    // Truncation at the end of the buffer still returns the written count.
    agreeWithOracle("write('abcdef', 6)", (B) => {
      const b = B.alloc(8);
      const n = b.write('abcdef', 6);
      return [n, ...Array.from(b)];
    });
  });
});

// ---------------------------------------------------------------------------
// M2 — web Buffer.from(ArrayBuffer) must share memory, not copy
// ---------------------------------------------------------------------------
describe('web Buffer.ts: Buffer.from(ArrayBuffer) shares memory (ENG-23136 M2)', () => {
  test('writes through the Buffer are visible in the ArrayBuffer', () => {
    const ab = new ArrayBuffer(8);
    const buf = WebBuffer.from(ab, 1, 4);
    expect(buf.length).toBe(4);
    expect(buf.byteOffset).toBe(1);
    expect(buf.buffer).toBe(ab);
    buf[0] = 42;
    buf.writeUInt16LE(0xbeef, 2);
    const raw = new Uint8Array(ab);
    expect(raw[1]).toBe(42);
    expect(raw[3]).toBe(0xef);
    expect(raw[4]).toBe(0xbe);
  });

  test('writes into the ArrayBuffer are visible through the Buffer (wasm-style)', () => {
    const ab = new ArrayBuffer(8);
    const buf = WebBuffer.from(ab);
    new Uint8Array(ab)[5] = 0x77;
    expect(buf[5]).toBe(0x77);
  });

  test('byteOffset/length defaults cover the whole ArrayBuffer', () => {
    const ab = new ArrayBuffer(6);
    new Uint8Array(ab).set([1, 2, 3, 4, 5, 6]);
    expect(Array.from(WebBuffer.from(ab))).toEqual([1, 2, 3, 4, 5, 6]);
    expect(Array.from(WebBuffer.from(ab, 4))).toEqual([5, 6]);
  });

  test('result is a Buffer (prototype methods work on the shared view)', () => {
    const ab = new ArrayBuffer(4);
    const buf = WebBuffer.from(ab, 0, 4);
    expect(buf instanceof WebBuffer).toBe(true);
    buf.writeUInt32LE(0x01020304, 0);
    expect(buf.readUInt32LE(0)).toBe(0x01020304);
    expect(new Uint8Array(ab)[0]).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// M3 — web hex decoder: nibble scan, no parseInt slop
// ---------------------------------------------------------------------------
describe('web Buffer.ts: hex decode matches Node (ENG-23136 M3)', () => {
  test('ticket cases: stops at first invalid pair, no fabricated bytes', () => {
    expect(Array.from(WebBuffer.from('a1bg', 'hex'))).toEqual([0xa1]); // was <a1 0b>
    expect(Array.from(WebBuffer.from('1 23', 'hex'))).toEqual([]); // was <01 23>
    expect(Array.from(WebBuffer.from('abc', 'hex'))).toEqual([0xab]); // half-pair dropped
  });

  test('rejects signs/whitespace/half pairs exactly like Node', () => {
    const cases = [
      '', 'a', 'ab', 'abc', 'abcd', 'A1B2', 'deadBEEF',
      '+1', '-1', ' 1', '1 ', '0x41', 'zz', 'a1zz', 'ffgg', '  ', '\t0', '00\n',
      'gg00', '1', '123', '12345', 'FfEe', '６１',
    ];
    for (const s of cases) {
      expect(Array.from(WebBuffer.from(s, 'hex')))
        .toEqual(Array.from(Oracle.from(s, 'hex')));
    }
  });

  test('fuzz vs Node oracle', () => {
    const hexish = '0123456789abcdefABCDEF g+-\t \n';
    let mism = 0;
    for (let t = 0; t < 2000; t++) {
      const len = (Math.random() * 12) | 0;
      let s = '';
      for (let i = 0; i < len; i++) s += hexish[(Math.random() * hexish.length) | 0];
      const a = Array.from(WebBuffer.from(s, 'hex'));
      const b = Array.from(Oracle.from(s, 'hex'));
      if (a.length !== b.length || a.some((v, i) => v !== b[i])) mism++;
    }
    expect(mism).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// L1 (web) — write/fill offset validation
// ---------------------------------------------------------------------------
describe('web Buffer.ts: write/fill offset validation (ENG-23136 L1)', () => {
  test('write: NaN/fractional/out-of-range offsets throw ERR_OUT_OF_RANGE', () => {
    expect(() => WebBuffer.alloc(8).write('abc', 1.5)).toThrow(RangeError);
    expect(() => WebBuffer.alloc(8).write('x', NaN)).toThrow(RangeError);
    expect(() => WebBuffer.alloc(8).write('data', 999)).toThrow(RangeError);
    expect(() => WebBuffer.alloc(8).write('x', -1)).toThrow(RangeError);
    try {
      WebBuffer.alloc(8).write('data', 999);
      throw new Error('unreachable');
    } catch (e: any) {
      expect(e.code).toBe('ERR_OUT_OF_RANGE');
    }
  });

  test('write: invalid length throws; valid length clamps to remaining', () => {
    expect(() => WebBuffer.alloc(8).write('abc', 0, NaN as any)).toThrow(RangeError);
    expect(() => WebBuffer.alloc(8).write('abc', 0, 1.5 as any)).toThrow(RangeError);
    expect(() => WebBuffer.alloc(8).write('abc', 0, -1 as any)).toThrow(RangeError);
    const b = WebBuffer.alloc(8);
    expect(b.write('abcdef', 6)).toBe(2); // truncated at end of buffer
    expect(b.write('abc', 2, 2)).toBe(2);
  });

  test('write: still returns byte counts Node returns for valid input', () => {
    const pairs: Array<[number, number[]]> = [];
    for (const B of [WebBuffer as any, Oracle]) {
      const b = B.alloc(8);
      const n = b.write('abcdef', 2, 3);
      pairs.push([n, Array.from(b)]);
    }
    expect(pairs[0]).toEqual(pairs[1]);
  });

  // Oracle values captured from real Node v25.9.0 via `node -e` (bun's own
  // Buffer deviates from Node on fractional fill offsets, so the live-oracle
  // comparison used elsewhere in this file can't be used here).
  test('fill: negative/fractional/NaN offset and out-of-range end throw like Node', () => {
    const throwing: Array<[string, () => unknown]> = [
      ['fill(1, -1)', () => WebBuffer.alloc(4).fill(1, -1)],
      ['fill(1, 1.5)', () => WebBuffer.alloc(4).fill(1, 1.5)],
      ['fill(1, NaN)', () => WebBuffer.alloc(4).fill(1, NaN)],
      ['fill(1, 0, 5)', () => WebBuffer.alloc(4).fill(1, 0, 5)],
      ['fill(1, 0, -1)', () => WebBuffer.alloc(4).fill(1, 0, -1)],
      ['fill(1, 0, 2.5)', () => WebBuffer.alloc(4).fill(1, 0, 2.5)],
    ];
    for (const [label, fn] of throwing) {
      let caught: any = null;
      try { fn(); } catch (e) { caught = e; }
      expect(`${label}: code=${caught?.code}`).toBe(`${label}: code=ERR_OUT_OF_RANGE`);
    }
    // Node treats offset beyond length (end defaulted) as a no-op, not error.
    expect(Array.from(WebBuffer.alloc(4).fill(1, 10))).toEqual([0, 0, 0, 0]);
    // Normal fills unchanged.
    expect(Array.from(WebBuffer.alloc(4).fill(7))).toEqual([7, 7, 7, 7]);
    expect(Array.from(WebBuffer.alloc(4).fill(7, 1, 3))).toEqual([0, 7, 7, 0]);
    expect(Array.from(WebBuffer.alloc(5).fill('ab', 1))).toEqual([0, 97, 98, 97, 98]);
  });
});

// ---------------------------------------------------------------------------
// M4/L2 — fs.js: _writeAllSync EINTR retry + EFBIG errno on partial writes
// ---------------------------------------------------------------------------
describe('fs.js: fd write EINTR retry and EFBIG errno (ENG-23136 M4/L2)', () => {
  const g = globalThis as Record<string, any>;
  let fs: any;
  let dir: string;
  const realFsWrite = (fd: number, bytes: Uint8Array, pos: number) =>
    nodeFs.writeSync(fd, bytes, 0, bytes.length, pos === -1 ? null : pos);

  beforeAll(() => {
    // Node-backed stubs for the fs.js native host hooks (same pattern as
    // fs-builtin-fixes.test.ts).
    g.__exactEnsureFs = () => {};
    g.__exactFsOpen = (p: string, flags: number, mode: number) => nodeFs.openSync(p, flags, mode);
    g.__exactFsClose = (fd: number) => nodeFs.closeSync(fd);
    g.__exactFsWrite = realFsWrite;
    fs = require('../../../src/builtins/fs.js');
    dir = nodeFs.mkdtempSync(nodePath.join(os.tmpdir(), 'eng23136-'));
  });

  afterAll(() => {
    g.__exactFsWrite = realFsWrite;
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch {}
  });

  function eintrError(): Error {
    const err: any = new Error('EINTR: interrupted system call, write');
    err.code = 'EINTR';
    return err;
  }

  test('a transient EINTR from the write hook is retried, not fatal', () => {
    const p = nodePath.join(dir, 'eintr-once.txt');
    let calls = 0;
    g.__exactFsWrite = (fd: number, bytes: Uint8Array, pos: number) => {
      calls++;
      if (calls === 1) throw eintrError();
      return realFsWrite(fd, bytes, pos);
    };
    try {
      const fd = nodeFs.openSync(p, 'w');
      fs.writeFileSync(fd, 'hello eintr'); // was: spurious throw + partial write
      nodeFs.closeSync(fd);
    } finally {
      g.__exactFsWrite = realFsWrite;
    }
    expect(calls).toBeGreaterThan(1);
    expect(nodeFs.readFileSync(p, 'utf8')).toBe('hello eintr');
  });

  test('EINTR after a partial write resumes at the right offset', () => {
    const p = nodePath.join(dir, 'eintr-partial.txt');
    const payload = 'abcdefghij';
    let calls = 0;
    g.__exactFsWrite = (fd: number, bytes: Uint8Array, pos: number) => {
      calls++;
      if (calls === 1) return realFsWrite(fd, bytes.subarray(0, 4), pos); // short write
      if (calls === 2) throw eintrError(); // signal between retries
      return realFsWrite(fd, bytes, pos);
    };
    try {
      const fd = nodeFs.openSync(p, 'w');
      fs.writeFileSync(fd, payload);
      nodeFs.closeSync(fd);
    } finally {
      g.__exactFsWrite = realFsWrite;
    }
    expect(calls).toBe(3);
    expect(nodeFs.readFileSync(p, 'utf8')).toBe(payload); // no dropped/duplicated bytes
  });

  test('non-EINTR errors still propagate', () => {
    const p = nodePath.join(dir, 'real-error.txt');
    g.__exactFsWrite = () => {
      const err: any = new Error('EBADF: bad file descriptor, write');
      err.code = 'EBADF';
      throw err;
    };
    try {
      const fd = nodeFs.openSync(p, 'w');
      expect(() => fs.writeFileSync(fd, 'x')).toThrow(/EBADF/);
      nodeFs.closeSync(fd);
    } finally {
      g.__exactFsWrite = realFsWrite;
    }
  });

  test('partial-write UNKNOWN coerces to EFBIG with numeric errno -27 (was NaN)', () => {
    const p = nodePath.join(dir, 'efbig.txt');
    let calls = 0;
    g.__exactFsWrite = (fd: number, bytes: Uint8Array, pos: number) => {
      calls++;
      if (calls === 1) return realFsWrite(fd, bytes.subarray(0, 2), pos); // progress
      throw new Error('UNKNOWN: unknown error, write'); // RLIMIT_FSIZE-style abort
    };
    let caught: any = null;
    try {
      const fd = nodeFs.openSync(p, 'w');
      try {
        fs.writeFileSync(fd, 'abcdef');
      } catch (e) {
        caught = e;
      }
      nodeFs.closeSync(fd);
    } finally {
      g.__exactFsWrite = realFsWrite;
    }
    expect(caught).not.toBeNull();
    expect(caught.code).toBe('EFBIG');
    expect(caught.errno).toBe(-27); // Node: -27; was NaN before the map fix
    expect(Number.isNaN(caught.errno)).toBe(false);
  });
});
