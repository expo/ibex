// ENG-22984 — regression coverage for six spec-divergence bugs in the web
// polyfills under src/polyfills/. Each polyfill installs itself only when the
// engine lacks a native implementation (`if (typeof X !== 'function')`), and the
// Bun test engine *has* native versions of all six APIs. To exercise OUR code we
// temporarily remove the native implementation, install the polyfill, capture /
// test it, then restore the native implementation in afterAll. Expected values
// are the exact spec results (the same runtime whose native impls we replace).
//
// Findings covered:
//   1. ArrayBuffer.prototype.resize was a silent no-op while advertising
//      resizable:true — now every buffer reports non-resizable and resize throws.
//   2. Array.prototype.with / toSpliced skipped ToIntegerOrInfinity truncation.
//   3. Iterator.prototype.take / drop rejected Infinity and fractional limits.
//   4. Set methods iterated a set-like via Symbol.iterator/forEach instead of
//      keys() (misreads a Map), and never validated keys is callable.
//   5. Intl.PluralRules returned 'other' for negative integers.
//   6. Intl.Segmenter re-segmented the whole input on every containing() call.

import { expect, test, describe, beforeAll, afterAll } from 'bun:test';
import { installArrayPolyfills } from './array';
import { installArrayBufferPolyfills } from './arraybuffer';
import { installIteratorPolyfills } from './iterator';
import { installSetPolyfills } from './set';
import { installIntlPolyfills } from './intl';

function drain(it: any): any[] {
  const out: any[] = [];
  while (true) {
    const r = it.next();
    if (r.done) break;
    out.push(r.value);
  }
  return out;
}

function makeIter(arr: any[]): any {
  let i = 0;
  return {
    next() {
      return i < arr.length ? { value: arr[i++], done: false } : { value: undefined, done: true };
    },
    [Symbol.iterator]() {
      return this;
    },
  };
}

// ---------------------------------------------------------------------------
// Finding 1: ArrayBuffer.prototype.resize
// ---------------------------------------------------------------------------
describe('ENG-22984 #1 ArrayBuffer resize is no longer a silent no-op', () => {
  let origAB: any;
  let dResize: any;
  let dResizable: any;
  let dMaxByteLength: any;

  beforeAll(() => {
    origAB = globalThis.ArrayBuffer;
    dResize = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resize');
    dResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable');
    dMaxByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'maxByteLength');
    delete (ArrayBuffer.prototype as any).resize;
    delete (ArrayBuffer.prototype as any).resizable;
    delete (ArrayBuffer.prototype as any).maxByteLength;
    installArrayBufferPolyfills();
  });

  afterAll(() => {
    const proto = origAB.prototype;
    if (dResize) Object.defineProperty(proto, 'resize', dResize);
    else delete (proto as any).resize;
    if (dResizable) Object.defineProperty(proto, 'resizable', dResizable);
    else delete (proto as any).resizable;
    if (dMaxByteLength) Object.defineProperty(proto, 'maxByteLength', dMaxByteLength);
    else delete (proto as any).maxByteLength;
    (globalThis as any).ArrayBuffer = origAB;
  });

  test('resizable reports false and maxByteLength equals byteLength', () => {
    const b = new ArrayBuffer(4, { maxByteLength: 64 });
    expect((b as any).resizable).toBe(false);
    expect((b as any).maxByteLength).toBe(4);
  });

  test('resize() throws instead of silently succeeding while nothing grows', () => {
    const b = new ArrayBuffer(4, { maxByteLength: 64 });
    expect(() => (b as any).resize(64)).toThrow(TypeError);
    // The core regression: it must NOT have appeared to succeed with a stale length.
    expect(b.byteLength).toBe(4);
    expect(new Uint8Array(b).length).toBe(4);
  });

  test('constructor still rejects a maxByteLength smaller than the length', () => {
    expect(() => new ArrayBuffer(8, { maxByteLength: 4 })).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// Finding 2: Array.prototype.with / toSpliced
// ---------------------------------------------------------------------------
describe('ENG-22984 #2 Array.with/toSpliced apply ToIntegerOrInfinity', () => {
  let dWith: any;
  let dToSpliced: any;

  beforeAll(() => {
    dWith = Object.getOwnPropertyDescriptor(Array.prototype, 'with');
    dToSpliced = Object.getOwnPropertyDescriptor(Array.prototype, 'toSpliced');
    delete (Array.prototype as any).with;
    delete (Array.prototype as any).toSpliced;
    installArrayPolyfills();
  });

  afterAll(() => {
    if (dWith) Object.defineProperty(Array.prototype, 'with', dWith);
    if (dToSpliced) Object.defineProperty(Array.prototype, 'toSpliced', dToSpliced);
  });

  test('with truncates a fractional index', () => {
    expect(['a', 'b', 'c'].with(1.5, 'X')).toEqual(['a', 'X', 'c']);
  });

  test('with truncates NaN to 0', () => {
    expect(['a', 'b', 'c'].with(NaN, 'X')).toEqual(['X', 'b', 'c']);
  });

  test('with truncates a negative fractional index toward zero', () => {
    expect(['a', 'b', 'c'].with(-1.5, 'X')).toEqual(['a', 'b', 'X']);
  });

  test('toSpliced truncates a fractional start (no undefined holes)', () => {
    const r = ['a', 'b', 'c'].toSpliced(1.5, 0, 'X');
    expect(r).toEqual(['a', 'X', 'b', 'c']);
    expect(r.includes(undefined as any)).toBe(false);
  });

  test('toSpliced truncates a fractional deleteCount', () => {
    expect(['a', 'b', 'c'].toSpliced(1, 1.9, 'X')).toEqual(['a', 'X', 'c']);
  });

  test('toSpliced with -Infinity start clamps to 0', () => {
    expect(['a', 'b', 'c'].toSpliced(-Infinity, 1, 'X')).toEqual(['X', 'b', 'c']);
  });
});

// ---------------------------------------------------------------------------
// Finding 3: Iterator.prototype.take / drop
// ---------------------------------------------------------------------------
describe('ENG-22984 #3 Iterator.take/drop accept Infinity and fractions', () => {
  let dTake: any;
  let dDrop: any;
  let polyTake: any;
  let polyDrop: any;
  let IterProto: any;

  beforeAll(() => {
    IterProto = (globalThis as any).Iterator.prototype;
    dTake = Object.getOwnPropertyDescriptor(IterProto, 'take');
    dDrop = Object.getOwnPropertyDescriptor(IterProto, 'drop');
    delete IterProto.take;
    delete IterProto.drop;
    installIteratorPolyfills();
    polyTake = IterProto.take;
    polyDrop = IterProto.drop;
  });

  afterAll(() => {
    if (dTake) Object.defineProperty(IterProto, 'take', dTake);
    if (dDrop) Object.defineProperty(IterProto, 'drop', dDrop);
  });

  test('take(Infinity) is the "no limit" idiom and yields everything', () => {
    expect(drain(polyTake.call(makeIter([1, 2, 3, 4, 5]), Infinity))).toEqual([1, 2, 3, 4, 5]);
  });

  test('take truncates a fractional limit', () => {
    expect(drain(polyTake.call(makeIter([1, 2, 3, 4, 5]), 2.9))).toEqual([1, 2]);
  });

  test('take still rejects negatives and NaN', () => {
    expect(() => polyTake.call(makeIter([1]), -1)).toThrow(RangeError);
    expect(() => polyTake.call(makeIter([1]), NaN)).toThrow(RangeError);
  });

  test('drop(Infinity) drops everything', () => {
    expect(drain(polyDrop.call(makeIter([1, 2, 3, 4, 5]), Infinity))).toEqual([]);
  });

  test('drop truncates a fractional count', () => {
    expect(drain(polyDrop.call(makeIter([1, 2, 3, 4, 5]), 1.9))).toEqual([2, 3, 4, 5]);
  });
});

// ---------------------------------------------------------------------------
// Finding 4: Set methods iterate set-like keys(), not Symbol.iterator
// ---------------------------------------------------------------------------
describe('ENG-22984 #4 Set methods read a set-like via keys()', () => {
  const methods = [
    'union',
    'intersection',
    'difference',
    'symmetricDifference',
    'isSubsetOf',
    'isSupersetOf',
    'isDisjointFrom',
  ];
  const saved: Record<string, any> = {};

  beforeAll(() => {
    for (const m of methods) {
      saved[m] = Object.getOwnPropertyDescriptor(Set.prototype, m);
      delete (Set.prototype as any)[m];
    }
    installSetPolyfills();
  });

  afterAll(() => {
    for (const m of methods) {
      if (saved[m]) Object.defineProperty(Set.prototype, m, saved[m]);
      else delete (Set.prototype as any)[m];
    }
  });

  test('union with a Map reads keys, not [key,value] pairs', () => {
    const r = new Set([1]).union(new Map([[2, 'b'], [3, 'c']]));
    expect([...r].sort()).toEqual([1, 2, 3]);
  });

  test('intersection (this larger) reads a Map by keys', () => {
    const r = new Set([1, 2, 3, 4]).intersection(new Map([[2, 'b'], [5, 'e']]));
    expect([...r]).toEqual([2]);
  });

  test('symmetricDifference reads a Map by keys', () => {
    const r = new Set([1, 2]).symmetricDifference(new Map([[2, 'b'], [3, 'c']]));
    expect([...r].sort()).toEqual([1, 3]);
  });

  test('isSupersetOf reads a Map by keys', () => {
    expect(new Set([1, 2, 3]).isSupersetOf(new Map([[1, 'a'], [2, 'b']]))).toBe(true);
    expect(new Set([1, 2, 3]).isSupersetOf(new Map([[1, 'a'], [9, 'z']]))).toBe(false);
  });

  test('requireSetLike rejects an argument without a keys() method', () => {
    const noKeys = { size: 1, has: () => true };
    expect(() => new Set([1]).union(noKeys as any)).toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------
// Finding 5: Intl.PluralRules and negative integers
// ---------------------------------------------------------------------------
describe('ENG-22984 #5 Intl.PluralRules handles negative integers', () => {
  let dPR: any;

  beforeAll(() => {
    dPR = Object.getOwnPropertyDescriptor(Intl, 'PluralRules');
    delete (Intl as any).PluralRules;
    installIntlPolyfills();
  });

  afterAll(() => {
    if (dPR) Object.defineProperty(Intl, 'PluralRules', dPR);
  });

  test('English: -1 is "one", 1 is "one", -2 and 1.5 are "other"', () => {
    const pr = new Intl.PluralRules('en');
    expect(pr.select(-1)).toBe('one');
    expect(pr.select(1)).toBe('one');
    expect(pr.select(-2)).toBe('other');
    expect(pr.select(1.5)).toBe('other');
  });

  test('de/it/nl/sv/es/tr: select(-1) is "one"', () => {
    for (const loc of ['de', 'it', 'nl', 'sv', 'es', 'tr']) {
      expect(new Intl.PluralRules(loc).select(-1)).toBe('one');
    }
  });
});

// ---------------------------------------------------------------------------
// Finding 6: Intl.Segmenter caches segmentation
// ---------------------------------------------------------------------------
describe('ENG-22984 #6 Intl.Segmenter caches segmentation', () => {
  let dSeg: any;

  beforeAll(() => {
    dSeg = Object.getOwnPropertyDescriptor(Intl, 'Segmenter');
    delete (Intl as any).Segmenter;
    installIntlPolyfills();
  });

  afterAll(() => {
    if (dSeg) Object.defineProperty(Intl, 'Segmenter', dSeg);
  });

  test('repeated containing() returns the same memoized segment (no re-segmentation)', () => {
    const segs = new Intl.Segmenter('en', { granularity: 'grapheme' }).segment('abcdef');
    const a = segs.containing(2);
    const b = segs.containing(2);
    expect(a).toBeDefined();
    // Object identity proves the segment array is cached rather than rebuilt.
    expect(a).toBe(b);
  });

  test('containing() locates the correct segment across the string', () => {
    const segs = new Intl.Segmenter('en', { granularity: 'grapheme' }).segment('hello');
    expect(segs.containing(0).segment).toBe('h');
    expect(segs.containing(4).segment).toBe('o');
    expect(segs.containing(2).index).toBe(2);
  });

  test('binary search handles a multi-code-unit grapheme (surrogate pair)', () => {
    const segs = new Intl.Segmenter('en', { granularity: 'grapheme' }).segment('a\u{1F600}b');
    expect(segs.containing(0).segment).toBe('a');
    expect(segs.containing(1).segment).toBe('\u{1F600}');
    expect(segs.containing(2).segment).toBe('\u{1F600}');
    expect(segs.containing(3).segment).toBe('b');
  });
});
